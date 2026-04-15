"""Explanation layer for upgrade recommendations.

Generates human-readable, judge-friendly explanations covering:
  - Technical risk reasoning
  - Business justification
  - Operational context
  - Executive summary
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.core.graph_engine import DependencyGraph
from app.core.scoring import ScoreBreakdown
from app.models import Service, Vulnerability


@dataclass
class Explanation:
    """Structured explanation for a single upgrade recommendation."""
    summary: str
    technical_reason: str
    business_reason: str
    operational_reason: str
    risk_factors: list[str]
    mitigating_factors: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "technical_reason": self.technical_reason,
            "business_reason": self.business_reason,
            "operational_reason": self.operational_reason,
            "risk_factors": self.risk_factors,
            "mitigating_factors": self.mitigating_factors,
        }


def generate_explanation(
    vuln: Vulnerability,
    service: Service,
    score: ScoreBreakdown,
    graph: DependencyGraph,
    rank: int,
) -> Explanation:
    """Generate a multi-faceted explanation for one recommendation."""

    br = graph.blast_radius(service.name)

    # ---- Summary
    urgency = "critical" if score.final_score >= 70 else "high" if score.final_score >= 50 else "moderate"
    summary = (
        f"Priority #{rank}: Upgrade {vuln.component} in {service.name} "
        f"({urgency} urgency, score {score.final_score:.1f}/100)."
    )

    # ---- Technical
    tech_parts: list[str] = []
    if vuln.cvss >= 9.0:
        tech_parts.append(f"Critical CVSS score of {vuln.cvss}")
    elif vuln.cvss >= 7.0:
        tech_parts.append(f"High CVSS score of {vuln.cvss}")
    else:
        tech_parts.append(f"CVSS score of {vuln.cvss}")

    if vuln.kev:
        tech_parts.append("listed in CISA Known Exploited Vulnerabilities")
    if vuln.epss >= 0.15:
        tech_parts.append(f"EPSS indicates {vuln.epss:.0%} exploitation probability")
    if vuln.patch_available:
        tech_parts.append(f"vendor patch available (→ {vuln.patch_version})")
    else:
        tech_parts.append("no vendor patch available — mitigation required")

    technical_reason = "; ".join(tech_parts) + "."

    # ---- Business
    biz_parts: list[str] = []
    biz_parts.append(f"{service.name} is a {service.tier.replace('_', ' ')} service")
    biz_parts.append(f"supporting {service.business_function}")
    if service.internet_facing:
        biz_parts.append("exposed to the internet")
    if br.downstream_count > 0:
        biz_parts.append(
            f"with {br.downstream_count} downstream dependent service(s): "
            + ", ".join(br.downstream_services[:5])
        )
    business_reason = "; ".join(biz_parts) + "."

    # ---- Operational
    op_parts: list[str] = []
    op_parts.append(f"Rollback complexity is {service.rollback_complexity}")
    mw = service.maintenance_window
    op_parts.append(f"maintenance window: {mw.day_of_week.title()} {mw.start_hour_24:02d}:00 ({mw.duration_hours}h)")
    op_parts.append(f"owned by {service.owner.team} ({service.owner.lead})")
    if br.downstream_count > 3:
        op_parts.append("large blast radius requires careful scheduling")
    operational_reason = "; ".join(op_parts) + "."

    # ---- Risk / mitigating factors
    risk_factors: list[str] = []
    mitigating: list[str] = []

    if vuln.kev:
        risk_factors.append("Active exploitation in the wild (KEV)")
    if vuln.cvss >= 9.0:
        risk_factors.append("Critical severity")
    if service.internet_facing:
        risk_factors.append("Internet-facing attack surface")
    if br.downstream_count >= 3:
        risk_factors.append(f"Large blast radius ({br.downstream_count} services)")
    if service.rollback_complexity == "high":
        risk_factors.append("Complex rollback procedure")

    if vuln.patch_available:
        mitigating.append("Vendor patch available")
    if service.rollback_complexity == "low":
        mitigating.append("Easy rollback")
    if not service.internet_facing:
        mitigating.append("Not directly internet-accessible")
    if br.downstream_count == 0:
        mitigating.append("No downstream dependencies impacted")

    return Explanation(
        summary=summary,
        technical_reason=technical_reason,
        business_reason=business_reason,
        operational_reason=operational_reason,
        risk_factors=risk_factors,
        mitigating_factors=mitigating,
    )


def generate_executive_summary(
    total_vulns: int,
    kev_count: int,
    critical_count: int,
    services_at_risk: int,
    top_service: str,
    top_cve: str,
    avg_score: float,
) -> dict[str, str]:
    """Generate an executive-level summary for reporting."""
    return {
        "headline": (
            f"Current assessment identifies {total_vulns} vulnerabilities across "
            f"{services_at_risk} services. {kev_count} are actively exploited in the wild."
        ),
        "top_priority": (
            f"Highest-priority action: address {top_cve} in {top_service}."
        ),
        "risk_posture": (
            f"{critical_count} findings exceed the critical threshold. "
            f"Average risk score is {avg_score:.1f}/100."
        ),
        "recommendation": (
            "Immediate attention required for Tier-1 services with known-exploited "
            "vulnerabilities. Recommend executing the top 5 upgrades in the next "
            "available maintenance windows with full approval workflow."
        ),
    }
