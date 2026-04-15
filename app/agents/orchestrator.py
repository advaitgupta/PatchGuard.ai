"""Multi-agent orchestrator for the full analysis pipeline.

Implements six agents that run sequentially:
  1. Vulnerability Ingestion Agent  – loads & normalizes vuln data
  2. Asset & Dependency Context Agent – builds service/component graph
  3. Risk Reasoning Agent – scores every finding
  4. Upgrade Planning Agent – ranks and schedules upgrades
  5. Governance Agent – enforces approval policies
  6. Explanation Agent – generates human-readable rationale

Each agent produces a traceable step log for audit/demo purposes.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Any

from app.config import get_settings
from app.core.explainer import Explanation, generate_executive_summary, generate_explanation
from app.core.graph_engine import DependencyGraph
from app.core.matching import MatchingEngine, VulnMatch
from app.core.policy import PolicyDecision, evaluate_policy
from app.core.scoring import ScoreBreakdown, compute_priority_score, cvss_only_score
from app.models import DependencyEdge, Service, Vulnerability

logger = logging.getLogger(__name__)


@dataclass
class AgentStep:
    """One traceable step in the pipeline."""
    agent_name: str
    action: str
    detail: str
    duration_ms: float
    items_processed: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent_name,
            "action": self.action,
            "detail": self.detail,
            "duration_ms": round(self.duration_ms, 1),
            "items_processed": self.items_processed,
        }


@dataclass
class AnalysisFinding:
    """One scored vulnerability-service pair."""
    cve_id: str
    service_name: str
    component: str
    score: ScoreBreakdown
    match_confidence: str
    cvss_only_rank: int | None = None
    business_rank: int | None = None


@dataclass
class PlanItem:
    """One entry in the upgrade plan."""
    priority_rank: int
    service: str
    component: str
    cve_id: str
    final_score: float
    risk_level: str
    severity_score: float
    exploitability_score: float
    business_impact_score: float
    blast_radius_score: float
    owner_team: str
    owner_email: str
    approval_required: bool
    approval_status: str
    approver_role: str
    policy_reasons: list[str]
    recommended_window: str
    target_date: str
    rollback_complexity: str
    prechecks: list[str]
    execution_steps: list[str]
    rollback_steps: list[str]
    postchecks: list[str]
    downstream_impact: list[str]
    explanation: dict[str, Any]
    rationale: list[str]
    match_confidence: str
    patch_version: str
    cvss_only_rank: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class PipelineResult:
    """Full output of the orchestration pipeline."""
    steps: list[AgentStep] = field(default_factory=list)
    matches: list[VulnMatch] = field(default_factory=list)
    findings: list[AnalysisFinding] = field(default_factory=list)
    plan: list[PlanItem] = field(default_factory=list)
    executive_summary: dict[str, str] = field(default_factory=dict)
    total_duration_ms: float = 0.0


class Orchestrator:
    """Multi-agent pipeline orchestrator."""

    def __init__(
        self,
        services: list[Service],
        dependencies: list[DependencyEdge],
        vulnerabilities: list[Vulnerability],
    ) -> None:
        self.services = services
        self.dependencies = dependencies
        self.vulnerabilities = vulnerabilities
        self._svc_map = {s.name: s for s in services}
        self._vuln_map = {v.cve_id: v for v in vulnerabilities}

    def run(self) -> PipelineResult:
        """Execute the full multi-agent pipeline."""
        result = PipelineResult()
        t_start = time.perf_counter()

        # ── Agent 1: Ingestion ──
        t = time.perf_counter()
        vulns = self.vulnerabilities
        result.steps.append(AgentStep(
            agent_name="Vulnerability Ingestion Agent",
            action="Loaded & normalized vulnerability records",
            detail=f"{len(vulns)} vulnerabilities from demo/live feeds",
            duration_ms=(time.perf_counter() - t) * 1000,
            items_processed=len(vulns),
        ))

        # ── Agent 2: Asset & Context ──
        t = time.perf_counter()
        graph = DependencyGraph(self.services, self.dependencies)
        matching = MatchingEngine(services=self.services)
        matches = matching.match(vulns)
        result.matches = matches
        result.steps.append(AgentStep(
            agent_name="Asset & Dependency Context Agent",
            action="Built dependency graph and matched vulnerabilities to services",
            detail=f"{graph.graph.number_of_nodes()} services, {graph.graph.number_of_edges()} edges, {len(matches)} matches",
            duration_ms=(time.perf_counter() - t) * 1000,
            items_processed=len(matches),
        ))

        # ── Agent 3: Risk Reasoning ──
        t = time.perf_counter()
        findings: list[AnalysisFinding] = []
        seen: set[tuple[str, str]] = set()
        for m in matches:
            key = (m.cve_id, m.service_name)
            if key in seen:
                continue
            seen.add(key)
            vuln = self._vuln_map.get(m.cve_id)
            svc = self._svc_map.get(m.service_name)
            if not vuln or not svc:
                continue
            score = compute_priority_score(vuln, svc, graph)
            findings.append(AnalysisFinding(
                cve_id=m.cve_id,
                service_name=m.service_name,
                component=m.component_name,
                score=score,
                match_confidence=m.confidence,
            ))
        # Sort by final score descending
        findings.sort(key=lambda f: f.score.final_score, reverse=True)

        # Compute CVSS-only ranks for comparison
        cvss_ranked = sorted(findings, key=lambda f: self._vuln_map[f.cve_id].cvss, reverse=True)
        for i, f in enumerate(cvss_ranked, 1):
            f.cvss_only_rank = i
        for i, f in enumerate(findings, 1):
            f.business_rank = i

        result.findings = findings
        result.steps.append(AgentStep(
            agent_name="Risk Reasoning Agent",
            action="Computed business-aware risk scores for all matches",
            detail=f"{len(findings)} scored findings, top score = {findings[0].score.final_score:.1f}" if findings else "No findings",
            duration_ms=(time.perf_counter() - t) * 1000,
            items_processed=len(findings),
        ))

        # ── Agent 4: Upgrade Planning ──
        t = time.perf_counter()
        plan: list[PlanItem] = []
        today = date.today()
        for rank, finding in enumerate(findings, 1):
            vuln = self._vuln_map[finding.cve_id]
            svc = self._svc_map[finding.service_name]
            mw = svc.maintenance_window

            # Find next window date
            target_weekday = [
                "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"
            ].index(mw.day_of_week.lower())
            d = today + timedelta(days=rank)
            while d.weekday() != target_weekday:
                d += timedelta(days=1)

            window_str = f"{mw.day_of_week.title()} {mw.start_hour_24:02d}:00–{(mw.start_hour_24 + mw.duration_hours) % 24:02d}:00"
            downstream = graph.all_downstream(svc.name)

            prechecks = self._build_prechecks(svc, vuln)
            exec_steps = self._build_execution_steps(svc, vuln)
            rollback = self._build_rollback_steps(svc, vuln)
            postchecks = self._build_postchecks(svc, vuln, downstream)

            # Explanation
            explanation = generate_explanation(vuln, svc, finding.score, graph, rank)

            # Policy
            policy = evaluate_policy(svc, vuln, finding.score.final_score, d)

            plan.append(PlanItem(
                priority_rank=rank,
                service=svc.name,
                component=finding.component,
                cve_id=finding.cve_id,
                final_score=finding.score.final_score,
                risk_level=policy.risk_level,
                severity_score=finding.score.severity_score,
                exploitability_score=finding.score.exploitability_score,
                business_impact_score=finding.score.business_impact_score,
                blast_radius_score=finding.score.blast_radius_score,
                owner_team=svc.owner.team,
                owner_email=svc.owner.email,
                approval_required=policy.approval_required,
                approval_status="pending" if policy.approval_required else "auto-approved",
                approver_role=policy.approver_role,
                policy_reasons=policy.reasons,
                recommended_window=window_str,
                target_date=d.isoformat(),
                rollback_complexity=svc.rollback_complexity,
                prechecks=prechecks,
                execution_steps=exec_steps,
                rollback_steps=rollback,
                postchecks=postchecks,
                downstream_impact=downstream,
                explanation=explanation.to_dict(),
                rationale=finding.score.rationale,
                match_confidence=finding.match_confidence,
                patch_version=vuln.patch_version,
                cvss_only_rank=finding.cvss_only_rank,
            ))

        result.plan = plan
        result.steps.append(AgentStep(
            agent_name="Upgrade Planning Agent",
            action="Generated ranked upgrade plan with scheduling",
            detail=f"{len(plan)} plan items generated",
            duration_ms=(time.perf_counter() - t) * 1000,
            items_processed=len(plan),
        ))

        # ── Agent 5: Governance ──
        t = time.perf_counter()
        approval_count = sum(1 for p in plan if p.approval_required)
        result.steps.append(AgentStep(
            agent_name="Governance Agent",
            action="Evaluated approval policies and compliance constraints",
            detail=f"{approval_count}/{len(plan)} items require human approval",
            duration_ms=(time.perf_counter() - t) * 1000,
            items_processed=len(plan),
        ))

        # ── Agent 6: Explanation ──
        t = time.perf_counter()
        if findings:
            kev_count = sum(1 for f in findings if self._vuln_map[f.cve_id].kev)
            critical_count = sum(1 for f in findings if f.score.final_score >= 70)
            svc_at_risk = len({f.service_name for f in findings})
            avg_score = sum(f.score.final_score for f in findings) / len(findings)
            result.executive_summary = generate_executive_summary(
                total_vulns=len(vulns),
                kev_count=kev_count,
                critical_count=critical_count,
                services_at_risk=svc_at_risk,
                top_service=findings[0].service_name,
                top_cve=findings[0].cve_id,
                avg_score=avg_score,
            )
        result.steps.append(AgentStep(
            agent_name="Explanation Agent",
            action="Generated human-readable explanations and executive summary",
            detail="Explanations attached to all plan items",
            duration_ms=(time.perf_counter() - t) * 1000,
            items_processed=len(plan),
        ))

        result.total_duration_ms = (time.perf_counter() - t_start) * 1000
        return result

    # ─────────────── helpers ───────────────
    def _build_prechecks(self, svc: Service, vuln: Vulnerability) -> list[str]:
        steps = [
            f"Verify {vuln.component} current version in {svc.name} environment",
            f"Run {svc.name} integration test suite",
            "Create database/config backup or snapshot",
        ]
        if svc.tier == "tier_1":
            steps.append("Notify on-call engineering team")
        if svc.rollback_complexity == "high":
            steps.append("Prepare validated rollback procedure and test in staging")
        return steps

    def _build_execution_steps(self, svc: Service, vuln: Vulnerability) -> list[str]:
        steps = [
            f"Update {vuln.component} to version {vuln.patch_version}",
            "Deploy updated container/package to staging",
            "Run smoke tests against staging",
            "Deploy to production with canary (10% traffic)",
            "Monitor error rates and latency for 15 minutes",
            "Complete full production rollout",
        ]
        return steps

    def _build_rollback_steps(self, svc: Service, vuln: Vulnerability) -> list[str]:
        steps = [
            f"Revert {vuln.component} to previous version",
            f"Restore prior container image / package in {svc.name}",
            "Run smoke tests to confirm rollback success",
        ]
        if "payment" in svc.name.lower() or "payment" in svc.business_function.lower():
            steps.append("Verify transaction processing pipeline integrity")
        if "auth" in svc.name.lower():
            steps.append("Verify authentication flow and session management")
        steps.append(f"Validate within {svc.maintenance_window.duration_hours}h maintenance window")
        return steps

    def _build_postchecks(self, svc: Service, vuln: Vulnerability, downstream: list[str]) -> list[str]:
        steps = [
            f"Confirm {vuln.component} version is {vuln.patch_version}",
            "Run full integration test suite",
            "Monitor error rate, latency, and business KPIs for 30 minutes",
        ]
        if downstream:
            steps.append(f"Validate connectivity to downstream services: {', '.join(downstream[:4])}")
        return steps
