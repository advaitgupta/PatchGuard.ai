"""Analysis history and risk trend tracking.

Stores results of each pipeline run and provides trend analysis
to show whether the organization's risk posture is improving or degrading.
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

DATA_DIR = Path(__file__).resolve().parent.parent / "demo_data"
HISTORY_FILE = DATA_DIR / "analysis_history.json"


def _load_history() -> list[dict]:
    if HISTORY_FILE.exists():
        with HISTORY_FILE.open("r", encoding="utf-8") as f:
            return json.load(f)
    return []


def _save_history(history: list[dict]) -> None:
    with HISTORY_FILE.open("w", encoding="utf-8") as f:
        json.dump(history, f, indent=2, default=str)


def record_analysis_run(
    findings_count: int,
    plan_count: int,
    critical_count: int,
    high_count: int,
    medium_count: int,
    low_count: int,
    avg_score: float,
    kev_count: int,
    services_affected: int,
    total_services: int,
    pipeline_ms: float,
    top_cve: str = "",
    top_service: str = "",
    cost_of_delay_daily: float = 0.0,
) -> dict:
    """Record a snapshot of the current analysis run."""
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "findings_count": findings_count,
        "plan_count": plan_count,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "avg_score": round(avg_score, 1),
        "kev_count": kev_count,
        "services_affected": services_affected,
        "total_services": total_services,
        "pipeline_ms": round(pipeline_ms, 1),
        "top_cve": top_cve,
        "top_service": top_service,
        "cost_of_delay_daily": round(cost_of_delay_daily, 2),
    }
    history = _load_history()
    history.append(entry)
    # Keep last 100 runs
    if len(history) > 100:
        history = history[-100:]
    _save_history(history)
    return entry


def get_trend_data() -> dict[str, Any]:
    """Compute risk trend from historical runs."""
    history = _load_history()
    if len(history) < 2:
        return {
            "trend": "insufficient_data",
            "runs": history,
            "message": "Need at least 2 analysis runs to compute trend",
        }

    latest = history[-1]
    baseline = history[0]  # Compare against oldest baseline

    # Calculate deltas (latest vs baseline)
    score_delta = latest["avg_score"] - baseline["avg_score"]
    critical_delta = latest["critical_count"] - baseline["critical_count"]
    findings_delta = latest["findings_count"] - baseline["findings_count"]
    cost_delta = latest.get("cost_of_delay_daily", 0) - baseline.get("cost_of_delay_daily", 0)

    # Determine trend direction
    if score_delta < -3:
        direction = "improving"
        assessment = f"Risk posture improving — avg score {baseline['avg_score']}→{latest['avg_score']} ({abs(score_delta):.1f}↓), {abs(critical_delta)} fewer critical findings since baseline"
    elif score_delta > 3:
        direction = "degrading"
        assessment = f"Risk posture degrading — avg score {baseline['avg_score']}→{latest['avg_score']} ({score_delta:.1f}↑)"
    else:
        direction = "stable"
        assessment = "Risk posture is stable across recent runs"

    return {
        "trend": direction,
        "assessment": assessment,
        "latest": latest,
        "baseline": baseline,
        "deltas": {
            "avg_score": round(score_delta, 1),
            "critical_count": critical_delta,
            "findings_count": findings_delta,
            "cost_of_delay": round(cost_delta, 0),
        },
        "total_runs": len(history),
        "runs": history[-10:],  # Last 10 runs for charting
    }


# ──────────── Cost-of-Delay Estimation ────────────

# Revenue-at-risk multipliers based on service tier and exposure
_DAILY_REVENUE_AT_RISK = {
    "tier_1": 150_000,  # $150K/day for tier-1 services
    "tier_2": 45_000,   # $45K/day for tier-2
    "tier_3": 8_000,    # $8K/day for tier-3
}

_EXPLOIT_LIKELIHOOD_MULTIPLIER = {
    "active": 0.85,    # Active exploit = 85% chance of impact
    "poc": 0.25,       # PoC exists = 25%
    "none": 0.05,      # No known exploit = 5%
    "unknown": 0.10,   # Unknown = 10%
}

_REGULATORY_FINE_DAILY = {
    "PCI-DSS": 5_000,   # $5K/day per PCI violation
    "SOX": 10_000,       # $10K/day per SOX violation
    "FFIEC": 3_000,      # $3K/day
    "GLBA": 2_500,       # $2.5K/day
    "BSA/AML": 8_000,    # $8K/day
    "SOC2": 1_500,       # $1.5K/day
}


def estimate_cost_of_delay(
    tier: str,
    exploit_maturity: str,
    regulatory_scope: list[str],
    internet_facing: bool,
    kev: bool,
    cvss: float,
) -> dict[str, float]:
    """Estimate the daily cost of NOT patching a vulnerability.

    Returns cost breakdown: revenue risk, regulatory exposure, reputational.
    """
    base_revenue_risk = _DAILY_REVENUE_AT_RISK.get(tier, 8_000)

    # Adjust by exploit likelihood
    exploit_mult = _EXPLOIT_LIKELIHOOD_MULTIPLIER.get(exploit_maturity, 0.10)
    if kev:
        exploit_mult = max(exploit_mult, 0.80)  # KEV = high likelihood

    # Internet-facing increases exposure
    exposure_mult = 1.5 if internet_facing else 1.0

    # CVSS severity multiplier (0-10 range → 0.3-1.0)
    severity_mult = max(0.3, cvss / 10.0)

    revenue_at_risk = base_revenue_risk * exploit_mult * exposure_mult * severity_mult

    # Regulatory fines
    regulatory_daily = sum(_REGULATORY_FINE_DAILY.get(r, 0) for r in regulatory_scope)
    regulatory_risk = regulatory_daily * exploit_mult * severity_mult

    # Reputational cost (simplified)
    reputational = revenue_at_risk * 0.3 if internet_facing else revenue_at_risk * 0.1

    total_daily = revenue_at_risk + regulatory_risk + reputational

    return {
        "total_daily": round(total_daily, 2),
        "revenue_at_risk": round(revenue_at_risk, 2),
        "regulatory_exposure": round(regulatory_risk, 2),
        "reputational_cost": round(reputational, 2),
        "annual_projection": round(total_daily * 365, 2),
        "30_day_cost": round(total_daily * 30, 2),
    }


# ──────────── Batch Window Optimization ────────────

def compute_batch_windows(plan: list[dict]) -> list[dict]:
    """Group upgrade plan items by service and maintenance window for batch execution.

    This minimizes the number of maintenance windows needed and reduces
    total downtime for the organization.
    """
    # Group by service
    by_service: dict[str, list[dict]] = {}
    for item in plan:
        svc = item.get("service", "Unknown")
        by_service.setdefault(svc, []).append(item)

    batches = []
    for service, items in by_service.items():
        if not items:
            continue
        window = items[0].get("recommended_window", "TBD")
        total_risk = sum(i.get("final_score", 0) for i in items)
        cves = [i.get("cve_id", "") for i in items]
        components = list(set(i.get("component", "") for i in items))
        max_risk = max(i.get("risk_level", "low") for i in items)

        batches.append({
            "service": service,
            "window": window,
            "item_count": len(items),
            "cves": cves,
            "components": components,
            "total_risk_score": round(total_risk, 1),
            "max_risk_level": max_risk,
            "estimated_duration_hours": min(len(items) * 0.5 + 1, 4),  # Cap at 4 hours
            "windows_saved": max(0, len(items) - 1),
        })

    # Sort by total risk
    batches.sort(key=lambda b: b["total_risk_score"], reverse=True)

    total_saved_windows = sum(b["windows_saved"] for b in batches)

    return {
        "batches": batches,
        "total_services": len(batches),
        "total_upgrades": sum(b["item_count"] for b in batches),
        "windows_saved": total_saved_windows,
        "downtime_reduction_pct": round(
            total_saved_windows / max(1, sum(b["item_count"] for b in batches)) * 100, 1
        ),
    }
