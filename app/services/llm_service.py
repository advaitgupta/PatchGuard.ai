"""Gemini LLM service for AI-powered explanations and natural language queries.

Provides:
  - Rich, contextual explanation generation for upgrade recommendations
  - Natural language Q&A over the risk analysis data
  - AI-generated executive summaries
  - Advisory summarization
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

import google.generativeai as genai

logger = logging.getLogger(__name__)

# ──────────────── Configuration ────────────────

_model = None

def _get_model():
    """Lazy-init the Gemini model."""
    global _model
    if _model is None:
        api_key = os.environ.get("GEMINI_API_KEY", "")
        if not api_key:
            raise RuntimeError("GEMINI_API_KEY environment variable not set")
        genai.configure(api_key=api_key)
        _model = genai.GenerativeModel(
            model_name="gemini-3.1-pro-preview",
            generation_config={
                "temperature": 0.7,
                "top_p": 0.9,
                "max_output_tokens": 15000,
            },
            system_instruction=(
                "You are an expert cybersecurity risk analyst working at Harborview Financial Services, "
                "a mid-sized financial company. You help security teams and engineering managers understand "
                "vulnerability risks and make informed upgrade decisions. "
                "Be concise, data-driven, and focus on actionable insights. "
                "Always explain technical risks in business terms. "
                "Use the specific data provided — never make up CVE details or scores."
            ),
        )
    return _model


def is_configured() -> bool:
    """Check if Gemini API key is available."""
    return bool(os.environ.get("GEMINI_API_KEY", ""))


# ──────────────── AI Explanation ────────────────

async def generate_ai_explanation(plan_item: dict[str, Any]) -> dict[str, str]:
    """Generate a rich AI explanation for a single upgrade recommendation."""
    model = _get_model()

    # Load relevant internal docs
    from app.loaders import get_docs_for_component, get_docs_for_service
    component_docs = get_docs_for_component(plan_item.get('component', ''))
    service_docs = get_docs_for_service(plan_item.get('service', ''))
    all_docs = component_docs + [d for d in service_docs if d not in component_docs]
    docs_text = ""
    if all_docs:
        docs_text = "\nINTERNAL DOCUMENTATION (incidents, change logs, runbooks):\n"
        for doc in all_docs[:5]:
            docs_text += f"  [{doc.get('type','doc').upper()}] {doc.get('date','')} - {doc.get('title','')}: {doc.get('summary','')}\n"

    prompt = f"""Analyze this software upgrade recommendation and provide an expert security assessment.

VULNERABILITY DETAILS:
- CVE: {plan_item.get('cve_id')}
- Component: {plan_item.get('component')}
- Service: {plan_item.get('service')}
- Risk Score: {plan_item.get('final_score', 0):.1f}/100
- Risk Level: {plan_item.get('risk_level')}
- Severity Score: {plan_item.get('severity_score', 0):.1f}/100
- Exploitability Score: {plan_item.get('exploitability_score', 0):.1f}/100
- Business Impact Score: {plan_item.get('business_impact_score', 0):.1f}/100
- Blast Radius Score: {plan_item.get('blast_radius_score', 0):.1f}/100

CONTEXT:
- Owner: {plan_item.get('owner_team')}
- Maintenance Window: {plan_item.get('recommended_window')}
- Rollback Complexity: {plan_item.get('rollback_complexity')}
- Downstream Services Impacted: {', '.join(plan_item.get('downstream_impact', [])) or 'None'}
- Approval Required: {plan_item.get('approval_required')}
- Patch Version: {plan_item.get('patch_version')}
- Priority Rank: #{plan_item.get('priority_rank')}
- CVSS-Only Rank: #{plan_item.get('cvss_only_rank', 'N/A')}
{docs_text}
Existing rationale: {json.dumps(plan_item.get('rationale', []))}

Provide your analysis in this JSON format:
{{
  "risk_assessment": "2-3 sentence expert assessment of the actual risk this poses to Harborview. Reference any relevant past incidents or internal documentation.",
  "business_impact": "1-2 sentences on how this could affect business operations, customers, or revenue",
  "recommended_action": "Specific, actionable recommendation with timing urgency",
  "key_concern": "The single most important thing the decision-maker should know",
  "rank_justification": "Why this is ranked #{plan_item.get('priority_rank')} vs CVSS-only rank #{plan_item.get('cvss_only_rank', 'N/A')} — explain the business reasoning"
}}

Return ONLY the JSON, no other text."""

    try:
        response = model.generate_content(prompt)
        text = response.text.strip()
        # Clean up markdown code fences if present
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()
        result = json.loads(text)
        result["ai_generated"] = True
        return result
    except json.JSONDecodeError:
        # If JSON parsing fails, return the raw text
        return {
            "risk_assessment": response.text if 'response' in dir() else "AI analysis unavailable",
            "ai_generated": True,
            "parse_error": True,
        }
    except Exception as exc:
        logger.error("Gemini explanation failed: %s", exc)
        return {"error": str(exc), "ai_generated": False}


# ──────────────── Natural Language Query ────────────────

async def query_risk_data(question: str, context: dict[str, Any]) -> str:
    """Answer a natural language question about the risk analysis."""
    model = _get_model()

    # Build context summary
    plan_summary = []
    for item in context.get("plan", [])[:15]:
        plan_summary.append(
            f"  #{item.get('priority_rank')}: {item.get('cve_id')} in {item.get('service')} "
            f"({item.get('component')}) — score {item.get('final_score', 0):.1f}, "
            f"risk={item.get('risk_level')}, approval={'required' if item.get('approval_required') else 'auto'}"
        )

    services_summary = []
    for svc in context.get("services", []):
        services_summary.append(
            f"  {svc.get('name')}: {svc.get('tier')}, "
            f"{'internet-facing' if svc.get('internet_facing') else 'internal'}, "
            f"owner={svc.get('owner', {}).get('team', 'unknown')}"
        )

    exec_summary = context.get("executive_summary", {})

    # Load internal docs for context
    from app.loaders import load_internal_docs
    docs = load_internal_docs()
    docs_text = "\nINTERNAL DOCUMENTATION (recent incidents, change logs, runbooks):\n"
    for doc in docs[:8]:
        docs_text += f"  [{doc.get('type','doc').upper()}] {doc.get('service','')} - {doc.get('title','')}: {doc.get('summary','')[:120]}\n"

    prompt = f"""You are a cybersecurity risk analyst at Harborview Financial Services.
Answer the following question based on the current risk analysis data and internal documentation.

EXECUTIVE SUMMARY:
{exec_summary.get('headline', 'N/A')}
{exec_summary.get('risk_posture', 'N/A')}

CURRENT UPGRADE PLAN (top 15):
{chr(10).join(plan_summary)}

SERVICES:
{chr(10).join(services_summary)}
{docs_text}
QUESTION: {question}

Provide a clear, concise, data-driven answer. Reference specific CVEs, services, scores, 
and internal documentation (incidents, runbooks) when relevant.
Keep your answer to 3-5 sentences unless the question requires more detail."""

    try:
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as exc:
        logger.error("Gemini query failed: %s", exc)
        return f"AI query failed: {exc}"


# ──────────────── AI Executive Summary ────────────────

async def generate_ai_summary(context: dict[str, Any]) -> str:
    """Generate an AI-written executive summary of the risk posture."""
    model = _get_model()

    plan = context.get("plan", [])
    critical_items = [i for i in plan if i.get("risk_level") == "critical"]
    kev_items = [i for i in plan if "KEV" in " ".join(i.get("rationale", []))]

    prompt = f"""Write a concise executive risk summary for Harborview Financial Services leadership.

KEY METRICS:
- Total vulnerabilities assessed: {context.get('vuln_count', 0)}
- Total findings mapped to services: {len(plan)}
- Critical findings: {len(critical_items)}
- Services at risk: {len(set(i.get('service') for i in plan))}
- Pending approvals: {sum(1 for i in plan if i.get('approval_status') == 'pending')}

TOP 5 PRIORITIES:
{chr(10).join(f"  {i+1}. {item.get('cve_id')} in {item.get('service')} (score: {item.get('final_score', 0):.1f}, {item.get('risk_level')})" for i, item in enumerate(plan[:5]))}

Write 4-5 sentences covering:
1. Current risk posture (how serious is this?)
2. Most urgent action needed
3. Key business systems at risk
4. Recommended next steps

Be direct and executive-friendly. No technical jargon."""

    try:
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as exc:
        logger.error("Gemini summary failed: %s", exc)
        return f"AI summary generation failed: {exc}"
