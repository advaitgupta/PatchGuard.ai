"""Report generation service — JSON, CSV, and executive summary exports."""
from __future__ import annotations

import csv
import io
import json
from typing import Any


def generate_json_report(plan: list[dict[str, Any]], analysis: list[dict[str, Any]]) -> str:
    """Full JSON export of analysis and plan."""
    report = {
        "report_type": "risk_upgrade_orchestrator_full_export",
        "generated_by": "Harborview Risk-Aware Upgrade Orchestrator",
        "analysis_findings": analysis,
        "upgrade_plan": plan,
        "total_findings": len(analysis),
        "total_planned": len(plan),
    }
    return json.dumps(report, indent=2, default=str)


def generate_csv_report(plan: list[dict[str, Any]]) -> str:
    """CSV export of the ranked upgrade plan."""
    if not plan:
        return ""
    output = io.StringIO()
    fieldnames = [
        "priority_rank", "service", "component", "cve_id",
        "final_score", "risk_level", "owner_team",
        "approval_required", "approval_status",
        "recommended_window", "rollback_complexity",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for item in plan:
        writer.writerow({
            "priority_rank": item.get("priority_rank", ""),
            "service": item.get("service", ""),
            "component": item.get("component", ""),
            "cve_id": item.get("cve_id", ""),
            "final_score": item.get("final_score", ""),
            "risk_level": item.get("risk_level", ""),
            "owner_team": item.get("owner_team", ""),
            "approval_required": item.get("approval_required", ""),
            "approval_status": item.get("approval_status", "pending"),
            "recommended_window": item.get("recommended_window", ""),
            "rollback_complexity": item.get("rollback_complexity", ""),
        })
    return output.getvalue()


def generate_executive_summary_text(summary: dict[str, str]) -> str:
    """Render executive summary as formatted text."""
    lines = [
        "═" * 60,
        "  EXECUTIVE RISK SUMMARY",
        "  Harborview Financial Services",
        "═" * 60,
        "",
        f"  {summary.get('headline', '')}",
        "",
        f"  TOP PRIORITY: {summary.get('top_priority', '')}",
        "",
        f"  RISK POSTURE: {summary.get('risk_posture', '')}",
        "",
        f"  RECOMMENDATION: {summary.get('recommendation', '')}",
        "",
        "═" * 60,
    ]
    return "\n".join(lines)
