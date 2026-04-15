"""Business-aware risk scoring engine.

Computes a composite priority score from:
 - Severity (CVSS)
 - Exploitability (EPSS + KEV + internet exposure)
 - Business impact (tier + customer-facing + regulatory scope)
 - Blast radius (dependency graph)
 - Upgrade complexity penalty
 - Maintenance window penalty

All sub-scores are normalized to 0-100 before weighting.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.config import ScoringWeights, get_settings
from app.core.graph_engine import DependencyGraph
from app.models import Service, Vulnerability


@dataclass
class ScoreBreakdown:
    """Transparent, auditable sub-score breakdown for one finding."""
    severity_score: float
    exploitability_score: float
    business_impact_score: float
    blast_radius_score: float
    exposure_score: float
    complexity_penalty: float
    maintenance_penalty: float
    final_score: float
    rationale: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity_score": self.severity_score,
            "exploitability_score": self.exploitability_score,
            "business_impact_score": self.business_impact_score,
            "blast_radius_score": self.blast_radius_score,
            "exposure_score": self.exposure_score,
            "complexity_penalty": self.complexity_penalty,
            "maintenance_penalty": self.maintenance_penalty,
            "final_score": self.final_score,
            "rationale": self.rationale,
        }


def _severity(vuln: Vulnerability) -> float:
    """CVSS 0-10 → 0-100."""
    return round(vuln.cvss * 10, 2)


def _exploitability(vuln: Vulnerability, internet_facing: bool) -> float:
    """Combine EPSS probability, KEV flag, and network exposure."""
    cfg = get_settings()
    score = vuln.epss * 100
    if vuln.kev:
        score += cfg.kev_bonus
    if internet_facing:
        score += cfg.internet_exposure_bonus
    # Exploit maturity bonus
    maturity = getattr(vuln, "exploit_maturity", None)
    if maturity == "active":
        score += 15
    elif maturity == "poc":
        score += 8
    return min(100.0, round(score, 2))


def _business_impact(service: Service) -> float:
    """Business impact from tier, customer-facing flag, and regulatory scope."""
    cfg = get_settings()
    base = cfg.tier_impact.get(service.tier, 30)
    if service.internet_facing:
        base += cfg.customer_facing_bonus
    if hasattr(service, "regulatory_scope") and service.regulatory_scope:
        base += cfg.regulatory_bonus
    return min(100.0, float(base))


def _exposure(vuln: Vulnerability, service: Service) -> float:
    """Combined exposure score (patch availability, internet facing, etc.)."""
    score = 0.0
    if not vuln.patch_available:
        score += 30   # no patch = more urgent
    if service.internet_facing:
        score += 35
    if vuln.kev:
        score += 25
    if vuln.epss > 0.3:
        score += 10
    return min(100.0, round(score, 2))


def _complexity(service: Service) -> float:
    """Upgrade complexity / disruption difficulty."""
    cfg = get_settings()
    return float(cfg.rollback_complexity_score.get(service.rollback_complexity, 35))


def _maintenance_penalty(service: Service, days_to_window: int = 3) -> float:
    """Penalty if next maintenance window is far away."""
    # Normalize: if window is >14 days away → high penalty
    return min(100.0, float(days_to_window * 5))


def compute_priority_score(
    vuln: Vulnerability,
    service: Service,
    graph: DependencyGraph,
    days_to_window: int = 3,
) -> ScoreBreakdown:
    """Compute composite priority score with full breakdown."""
    cfg = get_settings()
    w = cfg.scoring

    severity = _severity(vuln)
    exploitability = _exploitability(vuln, service.internet_facing)
    business_impact = _business_impact(service)
    blast_radius = graph.blast_radius_score(service.name)
    exposure = _exposure(vuln, service)
    complexity = _complexity(service)
    maint_pen = _maintenance_penalty(service, days_to_window)

    # Weighted composite
    positive = (
        w.severity * severity
        + w.exploitability * exploitability
        + w.business_impact * business_impact
        + w.blast_radius * blast_radius
        + w.exposure * exposure
    )
    penalty = w.complexity_penalty * complexity + w.maintenance_penalty * maint_pen
    final = round(max(0.0, positive - penalty), 2)

    # Build rationale
    rationale: list[str] = []
    if severity >= 80:
        rationale.append(f"Critical severity (CVSS {vuln.cvss}/10).")
    elif severity >= 60:
        rationale.append(f"High severity (CVSS {vuln.cvss}/10).")
    if vuln.kev:
        rationale.append("Vulnerability is in CISA Known Exploited Vulnerabilities catalog.")
    if vuln.epss >= 0.15:
        rationale.append(f"High exploit probability (EPSS {vuln.epss:.0%}).")
    if service.tier == "tier_1":
        rationale.append(f"{service.name} is a Tier-1 mission-critical service.")
    if service.internet_facing:
        rationale.append("Service is internet-facing, increasing attack surface.")
    br = graph.blast_radius(service.name)
    if br.downstream_count > 0:
        rationale.append(
            f"Blast radius: {br.downstream_count} downstream services affected "
            f"({', '.join(br.downstream_services[:4])}"
            f"{'…' if br.downstream_count > 4 else ''})."
        )
    if service.rollback_complexity == "high":
        rationale.append("Rollback is operationally complex — tighter scheduling needed.")
    if not vuln.patch_available:
        rationale.append("No vendor patch currently available — mitigation only.")

    return ScoreBreakdown(
        severity_score=severity,
        exploitability_score=exploitability,
        business_impact_score=business_impact,
        blast_radius_score=blast_radius,
        exposure_score=exposure,
        complexity_penalty=complexity,
        maintenance_penalty=maint_pen,
        final_score=final,
        rationale=rationale,
    )


def cvss_only_score(vuln: Vulnerability) -> float:
    """Baseline: rank by CVSS alone (for comparison)."""
    return round(vuln.cvss * 10, 2)
