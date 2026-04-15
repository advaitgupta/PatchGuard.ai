"""Service dependency graph engine powered by NetworkX.

Responsibilities:
- Build a directed dependency graph of enterprise services
- Compute downstream/upstream impact (blast radius)
- Identify critical paths and hub services
- Serialize graph data for frontend visualization
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import networkx as nx

from app.models import DependencyEdge, Service

CRITICALITY_WEIGHT = {"low": 1, "medium": 2, "high": 4}


@dataclass
class BlastRadiusResult:
    """Compact blast-radius report for a single service."""
    service_name: str
    downstream_count: int
    downstream_services: list[str]
    critical_path_count: int
    weighted_impact: float
    hub_score: float


class DependencyGraph:
    """Directed graph where an edge (A → B) means A *depends on* B."""

    def __init__(self, services: list[Service], edges: list[DependencyEdge]) -> None:
        self.graph = nx.DiGraph()
        self._service_map: dict[str, Service] = {}
        for svc in services:
            self.graph.add_node(svc.name, tier=svc.tier, internet_facing=svc.internet_facing)
            self._service_map[svc.name] = svc
        for edge in edges:
            if edge.consumer in self._service_map and edge.provider in self._service_map:
                self.graph.add_edge(
                    edge.consumer,
                    edge.provider,
                    dependency_type=edge.dependency_type,
                    criticality=edge.criticality,
                    critical_path=edge.criticality == "high",
                )

    # ------------------------------------------------------------------ queries
    def direct_dependents(self, service_name: str) -> list[str]:
        """Services that directly depend on *service_name*."""
        return sorted(self.graph.predecessors(service_name))

    def direct_dependencies(self, service_name: str) -> list[str]:
        """Services that *service_name* directly depends on."""
        return sorted(self.graph.successors(service_name))

    def all_downstream(self, service_name: str) -> list[str]:
        """Transitive closure: all services impacted if *service_name* fails.

        If A→B (A depends on B), and B goes down, A breaks.
        So "downstream impact of B" = all predecessors of B (transitively).
        """
        return sorted(nx.ancestors(self.graph, service_name))

    def all_upstream(self, service_name: str) -> list[str]:
        """All services that *service_name* transitively depends on."""
        return sorted(nx.descendants(self.graph, service_name))

    def blast_radius(self, service_name: str) -> BlastRadiusResult:
        """Compute blast radius when patching/changing a service."""
        downstream = self.all_downstream(service_name)
        # Critical-path edges count
        critical = 0
        for pred in self.graph.predecessors(service_name):
            edata = self.graph[pred][service_name]
            if edata.get("critical_path"):
                critical += 1
        # Weighted impact: sum of criticality weights of incoming edges
        weighted = 0.0
        for pred in self.graph.predecessors(service_name):
            crit = self.graph[pred][service_name].get("criticality", "medium")
            weighted += CRITICALITY_WEIGHT.get(crit, 2)
        # Add transitive downstream weights
        for d in downstream:
            for pred in self.graph.predecessors(d):
                if pred == service_name or pred in downstream:
                    crit = self.graph[pred][d].get("criticality", "medium")
                    weighted += CRITICALITY_WEIGHT.get(crit, 2) * 0.5
        # Hub score: betweenness centrality
        try:
            centrality = nx.betweenness_centrality(self.graph)
            hub_score = round(centrality.get(service_name, 0.0), 4)
        except Exception:
            hub_score = 0.0

        return BlastRadiusResult(
            service_name=service_name,
            downstream_count=len(downstream),
            downstream_services=downstream,
            critical_path_count=critical,
            weighted_impact=round(weighted, 2),
            hub_score=hub_score,
        )

    def blast_radius_score(self, service_name: str) -> float:
        """Normalized 0-100 blast radius score."""
        br = self.blast_radius(service_name)
        # Base: 8 pts per downstream, bonus for critical paths and hub
        raw = (br.downstream_count * 8) + (br.critical_path_count * 12) + (br.hub_score * 80)
        return min(100.0, round(raw, 2))

    def detect_cycles(self) -> list[list[str]]:
        """Return any cycles in the dependency graph (for warnings)."""
        try:
            return list(nx.simple_cycles(self.graph))
        except Exception:
            return []

    def get_hub_services(self, top_n: int = 5) -> list[tuple[str, float]]:
        """Return the top-N services by betweenness centrality (hubs)."""
        centrality = nx.betweenness_centrality(self.graph)
        ranked = sorted(centrality.items(), key=lambda x: x[1], reverse=True)
        return ranked[:top_n]

    # ----------------------------------------------------------- serialization
    def to_vis_json(self) -> dict[str, Any]:
        """Serialize graph for vis-network frontend visualization."""
        nodes = []
        for name, data in self.graph.nodes(data=True):
            svc = self._service_map.get(name)
            tier = data.get("tier", "tier_3")
            color_map = {"tier_1": "#ef4444", "tier_2": "#f59e0b", "tier_3": "#22c55e"}
            nodes.append({
                "id": name,
                "label": name,
                "color": color_map.get(tier, "#64748b"),
                "tier": tier,
                "internet_facing": data.get("internet_facing", False),
                "owner": svc.owner.team if svc else "",
                "shape": "dot",
                "size": 22 + (8 if tier == "tier_1" else 4 if tier == "tier_2" else 0),
                "font": {"color": "#e2e8f0", "size": 12},
            })
        edges = []
        for u, v, data in self.graph.edges(data=True):
            edges.append({
                "from": u,
                "to": v,
                "arrows": "to",
                "color": {
                    "color": "#ef4444" if data.get("criticality") == "high"
                             else "#f59e0b" if data.get("criticality") == "medium"
                             else "#64748b",
                    "opacity": 0.7,
                },
                "dashes": data.get("dependency_type") in ("notification", "analytics"),
                "label": data.get("dependency_type", ""),
                "font": {"color": "#94a3b8", "size": 9},
                "smooth": {"type": "curvedCW", "roundness": 0.15},
            })
        return {"nodes": nodes, "edges": edges}
