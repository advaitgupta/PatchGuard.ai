"""FastAPI application — complete production-ready API.

Provides REST endpoints for:
  - Health check
  - Services, components, dependencies
  - Vulnerabilities (CRUD + live ingestion)
  - Analysis (full pipeline execution)
  - Upgrade plan (ranked, explainable)
  - Approvals (human-in-the-loop)
  - Reports (JSON, CSV, executive summary)
  - Dependency graph (vis.js JSON)
  - Live CVE/KEV/EPSS enrichment
  - Agent pipeline trace
  - AI-powered explanations and queries (Gemini LLM)
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import date, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.agents.orchestrator import Orchestrator, PipelineResult
from app.config import get_settings
from app.core.graph_engine import DependencyGraph
from app.loaders import (
    load_approvals,
    load_dependencies,
    load_internal_docs,
    load_services,
    load_vulnerabilities,
    get_docs_for_service,
    save_approval,
    save_vulnerabilities,
)
from app.models import ApprovalRecord, Vulnerability
from app.services.cve_provider import (
    enrich_vulnerabilities,
    fetch_kev_catalog,
    fetch_recent_cves,
    parse_kev_entry,
    parse_nvd_cve,
)
from app.services.report_service import (
    generate_csv_report,
    generate_executive_summary_text,
    generate_json_report,
)

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

BASE_DIR = Path(__file__).resolve().parent
settings = get_settings()

# ──────────────────────────── App Setup ────────────────────────────

app = FastAPI(
    title=settings.app_title,
    version=settings.app_version,
    description="Agentic AI platform for business-aware software upgrade prioritization",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# ──────────────── Cached pipeline result ──────────────────

_cached_result: PipelineResult | None = None

# Tracks (cve_id, service) pairs that have been resolved (completed or rejected)
# so they are filtered from all plan/summary views
_resolved_items: set[tuple[str, str]] = set()


def _run_pipeline() -> PipelineResult:
    """Run the full orchestration pipeline (cached for demo speed)."""
    global _cached_result
    services = load_services()
    deps = load_dependencies()
    vulns = load_vulnerabilities()
    orch = Orchestrator(services, deps, vulns)
    _cached_result = orch.run()
    return _cached_result


def _get_result() -> PipelineResult:
    global _cached_result
    if _cached_result is None:
        return _run_pipeline()
    return _cached_result


def _get_active_plan(result: PipelineResult) -> list:
    """Return plan items that have NOT been resolved yet.
    
    An item is resolved if:
    1. It's in the memory _resolved_items set (manual fix).
    2. It has an execution record with status 'COMPLETED'.
    3. It has been REJECTED by an approver (hides from view, but risk remains).
    """
    from app.services.execution_state import get_all_executions
    completed_keys = { (ex['cve_id'], ex['service']) 
                       for ex in get_all_executions() 
                       if ex['status'] == 'completed' }
    
    # Load latest approvals to check for rejections
    approvals = load_approvals()
    rejected_keys = { (a['cve_id'], a['service']) 
                      for a in approvals 
                      if a.get('decision') == 'rejected' }

    return [
        p for p in result.plan
        if (p.cve_id, p.service) not in _resolved_items 
        and (p.cve_id, p.service) not in completed_keys
        and (p.cve_id, p.service) not in rejected_keys
    ]



# ──────────────────────── Health ────────────────────────

@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": settings.app_version}


# ──────────────────────── Services ────────────────────────

@app.get("/api/services")
def get_services() -> list[dict]:
    services = load_services()
    return [s.model_dump() for s in services]


@app.get("/api/services/{service_name}")
def get_service_detail(service_name: str) -> dict:
    services = load_services()
    svc = next((s for s in services if s.name == service_name), None)
    if not svc:
        raise HTTPException(404, f"Service '{service_name}' not found")
    deps = load_dependencies()
    graph = DependencyGraph(services, deps)
    br = graph.blast_radius(service_name)
    result = _get_result()
    svc_findings = [p.to_dict() for p in result.plan if p.service == service_name]
    return {
        "service": svc.model_dump(),
        "blast_radius": {
            "downstream_count": br.downstream_count,
            "downstream_services": br.downstream_services,
            "critical_path_count": br.critical_path_count,
            "hub_score": br.hub_score,
        },
        "dependencies_out": graph.direct_dependencies(service_name),
        "dependencies_in": graph.direct_dependents(service_name),
        "open_findings": svc_findings,
        "internal_docs": get_docs_for_service(service_name),
    }


# ──────────────────── Internal Documentation ────────────────────

@app.get("/api/internal-docs")
def get_internal_docs(service: str | None = None, doc_type: str | None = None) -> list[dict]:
    """Internal documentation: incident reports, change logs, runbooks."""
    docs = load_internal_docs()
    if service:
        docs = [d for d in docs if d.get("service") == service]
    if doc_type:
        docs = [d for d in docs if d.get("type") == doc_type]
    return docs


# ──────────────────── Dependencies ────────────────────

@app.get("/api/dependencies")
def get_dependencies() -> list[dict]:
    return [d.model_dump() for d in load_dependencies()]


@app.get("/api/graph")
def get_graph_data() -> dict:
    """Return dependency graph in vis-network JSON format."""
    services = load_services()
    deps = load_dependencies()
    graph = DependencyGraph(services, deps)
    return graph.to_vis_json()


# ────────────────── Asset Inventory ──────────────────

@app.get("/api/asset-inventory")
def get_asset_inventory() -> list[dict]:
    services = load_services()
    return [{
        "service": s.name,
        "tier": s.tier,
        "components": s.components,
        "owner_team": s.owner.team,
        "internet_facing": s.internet_facing,
    } for s in services]


# ──────────────────── Vulnerabilities ────────────────────

@app.get("/api/vulnerabilities")
def get_vulnerabilities(kev_only: bool = False, severity_min: float = 0.0) -> list[dict]:
    vulns = load_vulnerabilities()
    if kev_only:
        vulns = [v for v in vulns if v.kev]
    if severity_min > 0:
        vulns = [v for v in vulns if v.cvss >= severity_min]
    return [v.model_dump(mode="json") for v in vulns]


@app.post("/api/vulnerabilities")
def add_vulnerability(vulnerability: Vulnerability) -> dict:
    existing = load_vulnerabilities()
    if any(v.cve_id == vulnerability.cve_id for v in existing):
        raise HTTPException(status_code=409, detail="Vulnerability already exists")
    existing.append(vulnerability)
    save_vulnerabilities(existing)
    # Invalidate pipeline cache
    global _cached_result
    _cached_result = None
    return {"message": "Vulnerability added", "cve_id": vulnerability.cve_id}


@app.post("/api/vulnerabilities/ingest")
def ingest_vulnerabilities(payload: dict) -> dict:
    """Batch ingest vulnerability records."""
    records = payload.get("records", [])
    source = payload.get("source", "manual")
    existing = load_vulnerabilities()
    existing_ids = {v.cve_id for v in existing}
    added = 0
    for rec in records:
        vuln = Vulnerability(**rec)
        if vuln.cve_id not in existing_ids:
            existing.append(vuln)
            existing_ids.add(vuln.cve_id)
            added += 1
    save_vulnerabilities(existing)
    global _cached_result
    _cached_result = None
    return {"message": f"Ingested {added} new vulnerabilities from {source}", "added": added}


# ──────────────────── Analysis ────────────────────

@app.post("/api/analysis/run")
def run_analysis() -> dict:
    """Execute the full multi-agent analysis pipeline."""
    result = _run_pipeline()
    
    # Record history for trend analysis
    from app.services.analytics import record_analysis_run
    
    critical_count = sum(1 for p in result.plan if p.risk_level == "critical")
    high_count = sum(1 for p in result.plan if p.risk_level == "high")
    medium_count = sum(1 for p in result.plan if p.risk_level == "medium")
    low_count = sum(1 for p in result.plan if p.risk_level == "low")
    avg_score = sum(p.final_score for p in result.plan) / max(1, len(result.plan))
    services_affected = len(set(p.service for p in result.plan))
    
    # Calculate daily cost of delay (simplified sum)
    from app.services.analytics import estimate_cost_of_delay
    from app.loaders import load_services, load_vulnerabilities
    services = {s.name: s for s in load_services()}
    vulns = {v.cve_id: v for v in load_vulnerabilities()}
    
    total_cost_delay = 0
    for p in result.plan:
        svc = services.get(p.service)
        vuln = vulns.get(p.cve_id)
        if svc and vuln:
            cost = estimate_cost_of_delay(
                tier=svc.tier,
                exploit_maturity=vuln.exploit_maturity,
                regulatory_scope=svc.regulatory_scope,
                internet_facing=svc.internet_facing,
                kev=vuln.kev,
                cvss=vuln.cvss,
            )
            total_cost_delay += cost["total_daily"]
            p.cost_of_delay_daily = cost["total_daily"] # Add to plan item dynamically
            
    top_cve = result.plan[0].cve_id if result.plan else ""
    top_service = result.plan[0].service if result.plan else ""
    
    record_analysis_run(
        findings_count=len(result.findings),
        plan_count=len(result.plan),
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        avg_score=avg_score,
        kev_count=sum(1 for v in vulns.values() if v.kev),
        services_affected=services_affected,
        total_services=len(services),
        pipeline_ms=result.total_duration_ms,
        top_cve=top_cve,
        top_service=top_service,
        cost_of_delay_daily=total_cost_delay,
    )
    
    return {
        "status": "complete",
        "findings_count": len(result.findings),
        "plan_count": len(result.plan),
        "duration_ms": round(result.total_duration_ms, 1),
        "agent_steps": [s.to_dict() for s in result.steps],
        "executive_summary": result.executive_summary,
        "cost_of_delay_daily": total_cost_delay,
    }

# ──────────────────── Analytics Endpoints ────────────────────

@app.get("/api/analytics/trend")
def get_risk_trend() -> dict:
    from app.services.analytics import get_trend_data
    return get_trend_data()


@app.get("/api/analytics/batches")
def get_batch_windows() -> dict:
    from app.services.analytics import compute_batch_windows
    result = _get_result()
    return compute_batch_windows([p.to_dict() for p in result.plan])


@app.get("/api/analysis/latest")
def get_analysis() -> dict:
    result = _get_result()
    findings = []
    for f in result.findings:
        findings.append({
            "cve_id": f.cve_id,
            "service": f.service_name,
            "component": f.component,
            "final_score": f.score.final_score,
            "severity_score": f.score.severity_score,
            "exploitability_score": f.score.exploitability_score,
            "business_impact_score": f.score.business_impact_score,
            "blast_radius_score": f.score.blast_radius_score,
            "match_confidence": f.match_confidence,
            "rationale": f.score.rationale,
            "cvss_only_rank": f.cvss_only_rank,
            "business_rank": f.business_rank,
        })
    return {
        "findings": findings,
        "agent_steps": [s.to_dict() for s in result.steps],
        "total_duration_ms": round(result.total_duration_ms, 1),
    }


# ──────────────────── Plan ────────────────────

@app.get("/api/plan")
def get_plan() -> list[dict]:
    result = _get_result()
    return [p.to_dict() for p in _get_active_plan(result)]


@app.get("/api/plan/{rank}")
def get_plan_item(rank: int) -> dict:
    result = _get_result()
    item = next((p for p in result.plan if p.priority_rank == rank), None)
    if not item:
        raise HTTPException(404, f"Plan item rank {rank} not found")
    return item.to_dict()


# ──────────────────── Approvals ────────────────────

@app.get("/api/approvals")
def get_approvals() -> list[dict]:
    return load_approvals()


@app.post("/api/approvals/{cve_id}/{service_name}")
def approve_plan_item(cve_id: str, service_name: str, body: dict) -> dict:
    """Submit approval decision for a plan item."""
    decision = body.get("decision", "approved")
    approver = body.get("approver", "unknown@harborview.example")
    comment = body.get("comment", "")

    record = {
        "cve_id": cve_id,
        "service": service_name,
        "approver_email": approver,
        "decision": decision,
        "comment": comment,
        "timestamp": datetime.utcnow().isoformat(),
    }
    save_approval(record)

    # Update cached plan if available
    result = _get_result()
    for p in result.plan:
        if p.cve_id == cve_id and p.service == service_name:
            p.approval_status = decision

    return {"message": f"Approval recorded: {decision}", "record": record}


# ──────────────────── Reports ────────────────────

@app.get("/api/reports/executive-summary")
def get_executive_summary() -> dict:
    result = _get_result()
    return result.executive_summary


@app.get("/api/reports/export.json")
def export_json() -> PlainTextResponse:
    import json as _json
    result = _get_result()
    active_plan = _get_active_plan(result)
    from app.services.execution_state import get_all_executions
    executions = get_all_executions()
    
    # Enrich findings with live status
    analysis = []
    for f in result.findings:
        status = "active"
        if (f.cve_id, f.service_name) in _resolved_items:
            status = "resolved"
        
        # Check for rejection in approval records
        plan_item = next((p for p in result.plan if p.cve_id == f.cve_id and p.service == f.service_name), None)
        if plan_item and plan_item.approval_status == "rejected":
            status = "rejected"
            
        analysis.append({
            "cve_id": f.cve_id,
            "service": f.service_name,
            "component": f.component,
            "final_score": f.score.final_score,
            "risk_level": plan_item.risk_level if plan_item else "unknown",
            "status": status,
            "rationale": f.score.rationale,
        })
        
    plan_dicts = [p.to_dict() for p in active_plan]
    resolved_list = [{"cve_id": k[0], "service": k[1], "status": "resolved"} for k in _resolved_items]
    
    # Include Rejections in the resolved list for the report audit trail
    for p in result.plan:
        if p.approval_status == "rejected":
             resolved_list.append({"cve_id": p.cve_id, "service": p.service, "status": "rejected"})

    report_obj = {
        "metadata": {
            "title": "Harborview Risk-Aware Upgrade Report",
            "generated_at": datetime.utcnow().isoformat(),
            "summary": result.executive_summary,
            "stats": {
                "active_upgrades": len(plan_dicts),
                "resolved_or_rejected": len(resolved_list),
                "total_vulnerabilities": len(result.findings),
                "daily_cost_of_delay": sum(p.cost_of_delay_daily for p in result.plan 
                                         if (p.cve_id, p.service) not in _resolved_items 
                                         and (p.cve_id, p.service) not in { (ex['cve_id'], ex['service']) for ex in executions if ex['status'] == 'completed' })
            }
        },

        "prioritized_plan": plan_dicts,
        "full_vulnerability_inventory": analysis,
        "execution_audit_trail": executions,
        "resolved_items": resolved_list
    }
    
    return PlainTextResponse(
        _json.dumps(report_obj, indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=harborview_risk_report.json"},
    )



@app.get("/api/reports/export.csv")
def export_csv() -> PlainTextResponse:
    result = _get_result()
    active_plan = _get_active_plan(result)
    plan_dicts = [p.to_dict() for p in active_plan]
    
    from app.services.execution_state import get_all_executions
    executions = { (ex['cve_id'], ex['service']): ex['status'] for ex in get_all_executions() }
    
    for d in plan_dicts:
        key = (d["cve_id"], d["service"])
        d["live_execution_status"] = executions.get(key, "not_started")
        d["approval_status"] = d.get("approval_status", "pending")

    # Add Resolved/Rejected Items to CSV for completeness
    for f in result.findings:
        key = (f.cve_id, f.service_name)
        # If it's not in the active plan, it must be resolved or rejected
        if not any(p.cve_id == f.cve_id and p.service == f.service_name for p in active_plan):
            plan_item = next((p for p in result.plan if p.cve_id == f.cve_id and p.service == f.service_name), None)
            status = "resolved" if key in _resolved_items else "rejected"
            plan_dicts.append({
                "priority_rank": "-",
                "service": f.service_name,
                "cve_id": f.cve_id,
                "component": f.component,
                "final_score": f.score.final_score,
                "risk_level": plan_item.risk_level if plan_item else "-",
                "owner_team": plan_item.owner_team if plan_item else "-",
                "recommended_window": "-",
                "target_date": "-",
                "approval_status": plan_item.approval_status if plan_item else status,
                "live_execution_status": status
            })

    csv_content = generate_csv_report(plan_dicts)
    return PlainTextResponse(csv_content, media_type="text/csv",
                            headers={"Content-Disposition": "attachment; filename=harborview_upgrade_plan.csv"})



@app.get("/api/reports/executive-summary.txt")
def export_executive_text() -> PlainTextResponse:
    result = _get_result()
    active_plan = _get_active_plan(result)
    text = generate_executive_summary_text(result.executive_summary)
    
    # Add Live counts
    rejected_count = sum(1 for p in result.plan if p.approval_status == "rejected")
    resolved_count = len(_resolved_items)
    
    text += f"\n\n{'='*60}\n  LIVE ORCHESTRATION STATUS\n{'='*60}\n"
    text += f"  Total Active Vulnerabilities: {len(active_plan)}\n"
    text += f"  Total Patched/Resolved:      {resolved_count}\n"
    text += f"  Total Rejected/Dismissed:    {rejected_count}\n"
    
    if resolved_count > 0:
        text += f"\n  RESOLVED ITEMS:\n"
        for cve_id, service in _resolved_items:
            text += f"    - {cve_id} in {service} (SUCCESS)\n"

    # Filter by Rejections for executive summary audit
    approvals = load_approvals()
    approval_map = { (a['cve_id'], a['service']): a for a in approvals }

    if any(p.approval_status == "rejected" for p in result.plan):
        text += f"\n{'='*60}\n  RISK ACCEPTANCE / REJECTED UPGRADES\n{'='*60}\n"
        for p in result.plan:
            key = (p.cve_id, p.service)
            if key in approval_map and approval_map[key].get('decision') == 'rejected':
                comment = approval_map[key].get('comment', 'No comment')
                text += f"    - {p.cve_id} in {p.service} (REJECTED: {comment})\n"

    
    # Add Cost of Delay Sync
    # Sum for everything NOT fixed
    completed_keys = { (ex['cve_id'], ex['service']) for ex in get_all_executions() if ex['status'] == 'completed' }
    total_cod = sum(p.cost_of_delay_daily for p in result.plan 
                    if (p.cve_id, p.service) not in _resolved_items 
                    and (p.cve_id, p.service) not in completed_keys)
    
    text += f"\n{'='*60}\n  FINANCIAL RISK IMPACT\n{'='*60}\n"
    text += f"  Current Daily Cost of Delay: ${total_cod:,.2f}\n"
    text += "  (Note: Includes rejected but remediated items as risk persists)\n"

    
    return PlainTextResponse(text, media_type="text/plain",
                            headers={"Content-Disposition": "attachment; filename=harborview_executive_summary.txt"})

    return PlainTextResponse(text)


# ──────────────── Live Feed Endpoints ────────────────

@app.get("/api/feeds/kev")
async def get_live_kev() -> dict:
    """Fetch live CISA KEV catalog."""
    entries = await fetch_kev_catalog()
    parsed = [parse_kev_entry(e) for e in entries[:50]]
    return {"count": len(entries), "entries": parsed}


@app.get("/api/feeds/enrich")
async def enrich_current_vulns() -> dict:
    """Enrich current vulnerability set with live KEV/EPSS data."""
    vulns = load_vulnerabilities()
    cve_ids = [v.cve_id for v in vulns]
    enrichment = await enrich_vulnerabilities(cve_ids)
    return {"enriched": len(enrichment), "data": enrichment}


# ──────────────── Comparison (CVSS-only vs Business-Aware) ────────────────

@app.get("/api/comparison")
def get_ranking_comparison() -> list[dict]:
    """Compare CVSS-only ranking vs business-aware ranking."""
    result = _get_result()
    comparison = []
    for p in result.plan:
        comparison.append({
            "cve_id": p.cve_id,
            "service": p.service,
            "component": p.component,
            "cvss_only_rank": p.cvss_only_rank,
            "business_rank": p.priority_rank,
            "rank_change": (p.cvss_only_rank or 0) - p.priority_rank,
            "final_score": p.final_score,
            "risk_level": p.risk_level,
        })
    return comparison


# ──────────────── AI / LLM Endpoints (Gemini) ────────────────

@app.get("/api/ai/status")
def ai_status() -> dict:
    """Check if AI/LLM features are available."""
    from app.services.llm_service import is_configured
    return {"ai_enabled": is_configured(), "model": "gemini-2.0-flash"}


@app.post("/api/ai/explain/{rank}")
async def ai_explain(rank: int) -> dict:
    """Generate an AI-powered explanation for a specific plan item."""
    from app.services.llm_service import generate_ai_explanation, is_configured
    if not is_configured():
        raise HTTPException(503, "GEMINI_API_KEY not configured")
    result = _get_result()
    item = next((p for p in result.plan if p.priority_rank == rank), None)
    if not item:
        raise HTTPException(404, f"Plan item rank {rank} not found")
    explanation = await generate_ai_explanation(item.to_dict())
    return {"rank": rank, "cve_id": item.cve_id, "service": item.service, "ai_explanation": explanation}


@app.post("/api/ai/query")
async def ai_query(body: dict) -> dict:
    """Ask a natural language question about the risk analysis."""
    from app.services.llm_service import query_risk_data, is_configured
    if not is_configured():
        raise HTTPException(503, "GEMINI_API_KEY not configured")
    question = body.get("question", "")
    if not question:
        raise HTTPException(400, "Question is required")
    result = _get_result()
    services = load_services()
    context = {
        "plan": [p.to_dict() for p in result.plan],
        "services": [s.model_dump() for s in services],
        "executive_summary": result.executive_summary,
        "vuln_count": len(load_vulnerabilities()),
    }
    answer = await query_risk_data(question, context)
    return {"question": question, "answer": answer, "ai_generated": True}


@app.post("/api/ai/summary")
async def ai_summary() -> dict:
    """Generate an AI-written executive summary."""
    from app.services.llm_service import generate_ai_summary, is_configured
    if not is_configured():
        raise HTTPException(503, "GEMINI_API_KEY not configured")
    result = _get_result()
    context = {
        "plan": [p.to_dict() for p in result.plan],
        "vuln_count": len(load_vulnerabilities()),
    }
    summary = await generate_ai_summary(context)
    return {"ai_summary": summary, "ai_generated": True}


# ──────────────── Autonomous Agent Endpoints ────────────────

@app.post("/api/agents/triage/{cve_id}/{service_name}")
async def run_triage_agent(cve_id: str, service_name: str) -> dict:
    """Run the autonomous Vulnerability Triage Agent.
    
    The agent uses Gemini + tools to autonomously:
    1. Look up the CVE details
    2. Check the service's tier and regulatory exposure  
    3. Analyze blast radius via dependency graph
    4. Review past incidents
    5. Make a priority decision with reasoning
    """
    from app.agents.gemini_agent import run_vulnerability_triage_agent
    from app.services.llm_service import is_configured
    if not is_configured():
        raise HTTPException(503, "GEMINI_API_KEY not configured")
    result = await run_vulnerability_triage_agent(cve_id, service_name)
    return result.to_dict()


@app.post("/api/agents/remediate/{cve_id}/{service_name}")
async def run_remediation_agent(cve_id: str, service_name: str) -> dict:
    """Run the autonomous Remediation Agent.
    
    When a patch is APPROVED, this agent autonomously:
    1. Checks service details and runbooks
    2. Generates a remediation script
    3. Executes the patch (simulated)
    4. Verifies health checks
    5. Reports results
    """
    from app.agents.gemini_agent import run_remediation_agent as _run_remediation
    from app.services.llm_service import is_configured
    if not is_configured():
        raise HTTPException(503, "GEMINI_API_KEY not configured")
    
    # Find the plan item to get component details
    result = _get_result()
    item = next((p for p in result.plan if p.cve_id == cve_id and p.service == service_name), None)
    if not item:
        raise HTTPException(404, f"No plan item for {cve_id} in {service_name}")
    
    agent_result = await _run_remediation(
        cve_id=cve_id,
        service_name=service_name,
        component=item.component,
        current_version=getattr(item, 'current_version', None) or "unknown",
        target_version=item.patch_version or "latest",
    )
    return agent_result.to_dict()


@app.post("/api/agents/blast-radius/{service_name}")
async def run_blast_radius_agent(service_name: str) -> dict:
    """Run the autonomous Blast Radius Agent.
    
    Analyzes the full impact if a service goes down or a patch fails.
    """
    from app.agents.gemini_agent import run_blast_radius_agent as _run_br
    from app.services.llm_service import is_configured
    if not is_configured():
        raise HTTPException(503, "GEMINI_API_KEY not configured")
    result = await _run_br(service_name)
    return result.to_dict()


# ──────────────── Auto-Remediation on Approval ────────────────

@app.post("/api/approvals/{cve_id}/{service_name}/auto-remediate")
async def approve_and_remediate(cve_id: str, service_name: str, body: dict) -> dict:
    """Approve a patch AND trigger autonomous remediation.
    
    This is the full agentic flow:
    1. Record the approval
    2. Launch the Remediation Agent
    3. Agent autonomously generates and executes the patch
    4. Returns full execution trace
    """
    from app.agents.gemini_agent import run_remediation_agent as _run_remediation
    from app.services.llm_service import is_configured
    
    # Step 1: Record approval
    approver = body.get("approver", "unknown@harborview.example")
    record = {
        "cve_id": cve_id,
        "service": service_name,
        "approver_email": approver,
        "decision": "approved",
        "comment": body.get("comment", "Auto-remediation triggered"),
        "timestamp": datetime.utcnow().isoformat(),
        "auto_remediate": True,
    }
    save_approval(record)
    
    # Update plan status
    result = _get_result()
    item = next((p for p in result.plan if p.cve_id == cve_id and p.service == service_name), None)
    if not item:
        raise HTTPException(404, f"No plan item for {cve_id} in {service_name}")
    item.approval_status = "approved"
    
    # Step 2: Launch autonomous remediation
    if is_configured():
        agent_result = await _run_remediation(
            cve_id=cve_id,
            service_name=service_name,
            component=item.component,
            current_version=getattr(item, 'current_version', None) or "unknown",
            target_version=item.patch_version or "latest",
        )
        return {
            "approval": record,
            "remediation": agent_result.to_dict(),
            "status": "remediation_complete",
        }
    else:
        return {
            "approval": record,
            "status": "approved_pending_remediation",
            "message": "Approved but GEMINI_API_KEY not set for autonomous remediation",
        }


# ──────────────────────── Dashboard ────────────────────────

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    result = _get_result()
    services = load_services()
    vulns = load_vulnerabilities()
    approvals = load_approvals()

    # Build approval status lookup
    approval_lookup: dict[str, str] = {}
    for a in approvals:
        key = f"{a.get('cve_id')}:{a.get('service')}"
        approval_lookup[key] = a.get("decision", "pending")

    # Get analytics — use ACTIVE (unresolved) plan items only
    from app.services.analytics import get_trend_data, compute_batch_windows
    trend = get_trend_data()
    active_plan = _get_active_plan(result)
    batches = compute_batch_windows([p.to_dict() for p in active_plan])

    # Recalculate cost of delay from ACTIVE items only — computed fresh each page load
    from app.services.analytics import estimate_cost_of_delay
    services_map = {s.name: s for s in services}
    vulns_map = {v.cve_id: v for v in vulns}

    total_cost_delay = 0
    
    # We calculate cost for ANYTHING that isn't actually patched (COMPLETED)
    # Even if it's hidden (REJECTED), the risk still exists!
    from app.services.execution_state import get_all_executions
    completed_keys = { (ex['cve_id'], ex['service']) 
                       for ex in get_all_executions() 
                       if ex['status'] == 'completed' }
    
    for p in result.plan:
        if (p.cve_id, p.service) in _resolved_items or (p.cve_id, p.service) in completed_keys:
            continue
            
        # Use cached value if already computed by run_analysis()
        item_cost = getattr(p, 'cost_of_delay_daily', 0) or 0
        if not item_cost:
            svc = services_map.get(p.service)
            vuln = vulns_map.get(p.cve_id)
            if svc and vuln:
                cost = estimate_cost_of_delay(
                    tier=svc.tier,
                    exploit_maturity=vuln.exploit_maturity,
                    regulatory_scope=svc.regulatory_scope,
                    internet_facing=svc.internet_facing,
                    kev=vuln.kev,
                    cvss=vuln.cvss,
                )
                item_cost = cost["total_daily"]
                p.cost_of_delay_daily = item_cost
        total_cost_delay += item_cost


    summary = {
        "service_count": len(services),
        "vuln_count": len(vulns) - len(_resolved_items),
        "finding_count": len(result.findings) - len(_resolved_items),
        "plan_count": len(active_plan),
        "kev_count": sum(1 for v in vulns if v.kev and (v.cve_id, '') not in _resolved_items),
        "critical_count": sum(1 for p in active_plan if p.risk_level == "critical"),
        "high_count": sum(1 for p in active_plan if p.risk_level == "high"),
        "approval_pending": sum(1 for p in active_plan if p.approval_status == "pending"),
        "tier1_services": sum(1 for s in services if s.tier == "tier_1"),
        "avg_score": round(sum(p.final_score for p in active_plan) / len(active_plan), 1) if active_plan else 0,
        "pipeline_ms": round(result.total_duration_ms, 1),
        "cost_of_delay_daily": total_cost_delay,
    }

    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "summary": summary,
            "plan": [p.to_dict() for p in active_plan],
            "steps": [s.to_dict() for s in result.steps],
            "executive_summary": result.executive_summary,
            "services": [s.model_dump() for s in services],
            "approval_lookup": approval_lookup,
            "ai_enabled": bool(os.environ.get("GEMINI_API_KEY", "")),
            "trend": trend,
            "batches": batches,
        },
    )


# ──────────────────── Resolved Items API ────────────────────

@app.post("/api/resolved")
async def mark_resolved(request: Request) -> dict:
    """Mark a (cve_id, service) pair as resolved — removes it from plan/summary.
    Body: {cve_id, service}
    """
    global _resolved_items
    body = await request.json()
    key = (body["cve_id"], body["service"])
    _resolved_items.add(key)
    return {"status": "resolved", "cve_id": body["cve_id"], "service": body["service"],
            "resolved_count": len(_resolved_items)}


@app.delete("/api/resolved")
async def unmark_resolved(request: Request) -> dict:
    """Unmark a (cve_id, service) pair — restores it to the active plan."""
    global _resolved_items
    body = await request.json()
    key = (body["cve_id"], body["service"])
    _resolved_items.discard(key)
    return {"status": "unresolved", "cve_id": body["cve_id"], "service": body["service"]}


@app.get("/api/resolved")
def list_resolved() -> list[dict]:
    """List all resolved (cve_id, service) pairs."""
    return [{"cve_id": k[0], "service": k[1]} for k in _resolved_items]


@app.post("/api/resolved/reset")
def reset_resolved() -> dict:
    """Clear all resolved items (restore full plan)."""
    global _resolved_items
    _resolved_items.clear()
    return {"status": "reset"}



# ═══════════════════════════════════════════════════════════════════
#  AGENTIC EXECUTION ENDPOINTS
# ═══════════════════════════════════════════════════════════════════

from app.agents.execution_agent import start_remediation
from app.services.execution_state import get_all_executions, get_execution_record
from app.services.notification_service import get_notifications, clear_notifications
from app.services.change_control_service import record_approval as cc_approve, record_rejection as cc_reject


@app.post("/api/execution/start")
async def api_start_execution(request: Request) -> dict:
    """Start autonomous remediation for a plan item.
    
    Body: {cve_id, service, component, patch_version, previous_version,
           autonomy_level, scenario}
    scenario: "success" or "failure" (to demo rollback)
    """
    body = await request.json()
    result = await start_remediation(
        cve_id=body["cve_id"],
        service=body["service"],
        component=body["component"],
        patch_version=body["patch_version"],
        previous_version=body.get("previous_version", ""),
        autonomy_level=body.get("autonomy_level", "supervised"),
        scenario=body.get("scenario", "success"),
    )
    return result


@app.get("/api/execution/list")
async def api_list_executions() -> list[dict]:
    """List all execution records."""
    return get_all_executions()


@app.get("/api/execution/{execution_id}")
async def api_get_execution(execution_id: str) -> dict:
    """Get full details of a specific execution."""
    record = get_execution_record(execution_id)
    if not record:
        raise HTTPException(status_code=404, detail="Execution not found")
    return record.to_dict()


@app.post("/api/execution/{execution_id}/approve")
async def api_approve_execution(execution_id: str, request: Request) -> dict:
    """Approve a pending execution."""
    body = await request.json()
    result = cc_approve(execution_id, body.get("approver", "admin"), 
                        body.get("comment", "Approved"))
    return result


@app.post("/api/execution/{execution_id}/reject")
async def api_reject_execution(execution_id: str, request: Request) -> dict:
    """Reject a pending execution."""
    body = await request.json()
    result = cc_reject(execution_id, body.get("approver", "admin"), 
                       body.get("comment", "Rejected"))
    return result


@app.get("/api/notifications")
async def api_notifications() -> list[dict]:
    """Get recent agent notifications."""
    return get_notifications()


@app.post("/api/notifications/clear")
async def api_clear_notifications() -> dict:
    """Clear all notifications."""
    clear_notifications()
    return {"status": "cleared"}


@app.post("/api/execution/reset")
async def api_reset_executions() -> dict:
    """Reset all execution state (for demo reset)."""
    global _resolved_items
    from app.services.execution_state import STATE_FILE
    from app.loaders import APPROVALS_FILE
    
    # Delete persistent data
    for f in [STATE_FILE, APPROVALS_FILE]:
        if f.exists():
            f.unlink()
            
    clear_notifications()
    _resolved_items.clear()  # Restore full plan on demo reset
    return {"status": "reset"}

