from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from app.models import DependencyEdge, RiskFinding, Service, Vulnerability


TIER_IMPACT = {
    "tier_1": 35,
    "tier_2": 22,
    "tier_3": 12,
}

ROLLBACK_PENALTY = {
    "low": 0,
    "medium": 8,
    "high": 16,
}

DEPENDENCY_CRITICALITY_WEIGHT = {
    "low": 1,
    "medium": 2,
    "high": 4,
}


@dataclass
class RiskContext:
    services: list[Service]
    dependencies: list[DependencyEdge]
    vulnerabilities: list[Vulnerability]


class RiskEngine:
    def __init__(self, context: RiskContext) -> None:
        self.context = context
        self.graph = nx.DiGraph()
        for service in context.services:
            self.graph.add_node(service.name)
        for edge in context.dependencies:
            self.graph.add_edge(
                edge.consumer,
                edge.provider,
                dependency_type=edge.dependency_type,
                criticality=edge.criticality,
            )
        self._service_map = {s.name: s for s in context.services}

    def affected_services(self, component: str) -> list[Service]:
        return [s for s in self.context.services if component in s.components]

    def blast_radius(self, service_name: str) -> int:
        # Reverse graph descendants = downstream consumers impacted if this service changes or fails.
        reverse_graph = self.graph.reverse(copy=True)
        return len(nx.descendants(reverse_graph, service_name))

    def downstream_services(self, service_name: str) -> list[str]:
        reverse_graph = self.graph.reverse(copy=True)
        return sorted(nx.descendants(reverse_graph, service_name))

    def edge_risk_weight(self, service_name: str) -> int:
        reverse_graph = self.graph.reverse(copy=True)
        total = 0
        for downstream in nx.descendants(reverse_graph, service_name):
            if self.graph.has_edge(downstream, service_name):
                criticality = self.graph[downstream][service_name].get("criticality", "medium")
                total += DEPENDENCY_CRITICALITY_WEIGHT[criticality]
        return total

    def compute_findings(self) -> list[RiskFinding]:
        findings: list[RiskFinding] = []
        for vuln in self.context.vulnerabilities:
            for service in self.affected_services(vuln.component):
                severity_score = vuln.cvss * 10
                exploit_score = vuln.epss * 100 + (25 if vuln.kev else 0)
                business_impact = TIER_IMPACT[service.tier] + (12 if service.internet_facing else 0)
                blast_radius = self.blast_radius(service.name)
                dependency_weight = self.edge_risk_weight(service.name)
                operational_penalty = ROLLBACK_PENALTY[service.rollback_complexity]
                risk_score = round(
                    severity_score
                    + exploit_score
                    + business_impact
                    + (blast_radius * 6)
                    + dependency_weight
                    - operational_penalty,
                    1,
                )

                rationale = [
                    f"CVSS contributes {severity_score:.1f} points.",
                    f"Exploitability contributes {exploit_score:.1f} points.",
                    f"Business criticality contributes {business_impact} points.",
                    f"Blast radius affects {blast_radius} downstream services.",
                ]
                if vuln.kev:
                    rationale.append("Vulnerability is in the known-exploited bucket.")
                if service.internet_facing:
                    rationale.append("Service is internet-facing, increasing urgency.")
                if service.rollback_complexity == "high":
                    rationale.append("Rollback is operationally complex, requiring tighter planning.")

                findings.append(
                    RiskFinding(
                        cve_id=vuln.cve_id,
                        service=service.name,
                        component=vuln.component,
                        risk_score=risk_score,
                        blast_radius=blast_radius,
                        business_impact=business_impact,
                        exploit_score=round(exploit_score, 1),
                        severity_score=round(severity_score, 1),
                        operational_penalty=round(operational_penalty, 1),
                        recommended_action=f"Upgrade {vuln.component} to {vuln.patch_version}",
                        owner_team=service.owner.team,
                        rationale=rationale,
                    )
                )
        findings.sort(key=lambda f: f.risk_score, reverse=True)
        return findings
