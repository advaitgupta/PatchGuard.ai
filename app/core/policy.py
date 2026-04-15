"""Governance and policy engine.

Enforces approval rules, change-freeze windows, and compliance constraints.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any

from app.config import get_settings
from app.models import Service, Vulnerability


@dataclass
class PolicyDecision:
    """Approval / governance decision for one plan item."""
    approval_required: bool
    reasons: list[str]
    risk_level: str           # "critical" | "high" | "medium" | "low"
    approver_role: str        # e.g. "Engineering Manager", "CISO"
    blocked: bool = False     # True if within freeze window
    block_reason: str = ""


# Hard-coded freeze windows for demo
FREEZE_WINDOWS: list[tuple[date, date, str]] = [
    # Example: quarter-end freeze
    # (date(2026, 3, 28), date(2026, 4, 2), "Quarter-end change freeze"),
]


def _is_in_freeze(target_date: date) -> tuple[bool, str]:
    for start, end, reason in FREEZE_WINDOWS:
        if start <= target_date <= end:
            return True, reason
    return False, ""


def evaluate_policy(
    service: Service,
    vuln: Vulnerability,
    final_score: float,
    target_date: date | None = None,
) -> PolicyDecision:
    """Evaluate governance policy for a proposed upgrade."""
    cfg = get_settings()
    reasons: list[str] = []
    approval_required = False

    # Tier-1 always requires approval
    if cfg.approval.tier1_always_approve and service.tier == "tier_1":
        approval_required = True
        reasons.append("Tier-1 service requires manager approval")

    # High rollback complexity
    if cfg.approval.high_rollback_approve and service.rollback_complexity == "high":
        approval_required = True
        reasons.append("High rollback complexity requires approval")

    # Score threshold
    if final_score >= cfg.approval.score_threshold:
        approval_required = True
        reasons.append(f"Risk score {final_score:.1f} exceeds threshold ({cfg.approval.score_threshold})")

    # Payment services
    if cfg.approval.payment_services_approve:
        if "payment" in service.name.lower() or "payment" in service.business_function.lower():
            approval_required = True
            reasons.append("Payment-related service requires approval")

    # Auth services
    if cfg.approval.auth_services_approve:
        name_lower = service.name.lower()
        if "auth" in name_lower or "iam" in name_lower or "identity" in name_lower:
            approval_required = True
            reasons.append("Authentication/identity service requires approval")

    # Risk level
    if final_score >= 70:
        risk_level = "critical"
    elif final_score >= 50:
        risk_level = "high"
    elif final_score >= 30:
        risk_level = "medium"
    else:
        risk_level = "low"

    # Approver role
    if risk_level == "critical":
        approver_role = "CISO / VP Engineering"
    elif service.tier == "tier_1":
        approver_role = "Engineering Manager"
    else:
        approver_role = "Team Lead"

    # Freeze window check
    blocked = False
    block_reason = ""
    if target_date:
        blocked, block_reason = _is_in_freeze(target_date)

    return PolicyDecision(
        approval_required=approval_required,
        reasons=reasons,
        risk_level=risk_level,
        approver_role=approver_role,
        blocked=blocked,
        block_reason=block_reason,
    )
