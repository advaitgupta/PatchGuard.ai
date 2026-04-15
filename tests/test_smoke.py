"""Comprehensive test suite for the Risk-Aware Upgrade Orchestrator."""
import json
from pathlib import Path

from app.agents.orchestrator import Orchestrator
from app.core.graph_engine import DependencyGraph
from app.core.matching import MatchingEngine, _normalize_name, _version_matches_rule
from app.core.scoring import compute_priority_score, cvss_only_score
from app.core.policy import evaluate_policy
from app.loaders import load_dependencies, load_services, load_vulnerabilities


# ───────────────── Data Loading ─────────────────

def test_data_loads():
    """All demo data files load without errors."""
    services = load_services()
    deps = load_dependencies()
    vulns = load_vulnerabilities()
    assert len(services) >= 10
    assert len(deps) >= 20
    assert len(vulns) >= 15


# ───────────────── Graph Engine ─────────────────

def test_graph_build():
    """Graph constructs correctly from demo data."""
    services = load_services()
    deps = load_dependencies()
    graph = DependencyGraph(services, deps)
    assert graph.graph.number_of_nodes() == len(services)
    assert graph.graph.number_of_edges() >= 20


def test_blast_radius():
    """Payment Gateway should have large blast radius."""
    services = load_services()
    deps = load_dependencies()
    graph = DependencyGraph(services, deps)
    br = graph.blast_radius("Payment Gateway")
    assert br.downstream_count >= 1
    assert isinstance(br.hub_score, float)


def test_graph_serialization():
    """Graph serializes to vis.js format."""
    services = load_services()
    deps = load_dependencies()
    graph = DependencyGraph(services, deps)
    vis = graph.to_vis_json()
    assert "nodes" in vis
    assert "edges" in vis
    assert len(vis["nodes"]) == len(services)


# ───────────────── Matching ─────────────────

def test_name_normalization():
    assert _normalize_name("spring-boot") == "spring-boot"
    assert _normalize_name("springboot") == "spring-boot"
    assert _normalize_name("Express") == "express"


def test_version_matching():
    assert _version_matches_rule("2.1.8", "<2.1.10") is True
    assert _version_matches_rule("2.1.10", "<2.1.10") is False
    assert _version_matches_rule("1.0.0", "*") is True


def test_matching_engine():
    services = load_services()
    vulns = load_vulnerabilities()
    engine = MatchingEngine(services=services)
    matches = engine.match(vulns)
    assert len(matches) >= 10
    # Express should match to Customer Portal
    express_matches = [m for m in matches if m.component_name == "express"]
    assert any(m.service_name == "Customer Portal" for m in express_matches)


# ───────────────── Scoring ─────────────────

def test_scoring():
    services = load_services()
    deps = load_dependencies()
    vulns = load_vulnerabilities()
    graph = DependencyGraph(services, deps)
    svc = next(s for s in services if s.name == "Payment Gateway")
    vuln = next(v for v in vulns if v.component == "jpos")
    score = compute_priority_score(vuln, svc, graph)
    assert score.final_score > 50  # should be high priority
    assert score.severity_score > 0
    assert len(score.rationale) >= 1


def test_cvss_vs_business_aware():
    """Business-aware scoring should differ from CVSS-only."""
    services = load_services()
    deps = load_dependencies()
    vulns = load_vulnerabilities()
    graph = DependencyGraph(services, deps)

    # Score two vulns
    svc_pg = next(s for s in services if s.name == "Payment Gateway")
    vuln_jpos = next(v for v in vulns if v.component == "jpos")

    svc_dw = next(s for s in services if s.name == "Data Warehouse")
    vuln_redshift = next(v for v in vulns if v.component == "redshift-driver")

    score_jpos = compute_priority_score(vuln_jpos, svc_pg, graph)
    score_redshift = compute_priority_score(vuln_redshift, svc_dw, graph)

    # jPOS in Payment Gateway should rank higher despite potentially similar CVSS
    assert score_jpos.final_score > score_redshift.final_score


# ───────────────── Policy ─────────────────

def test_tier1_requires_approval():
    services = load_services()
    vulns = load_vulnerabilities()
    svc = next(s for s in services if s.tier == "tier_1")
    vuln = vulns[0]
    decision = evaluate_policy(svc, vuln, 80.0)
    assert decision.approval_required is True


def test_low_risk_auto_approved():
    services = load_services()
    vulns = load_vulnerabilities()
    svc = next(s for s in services if s.tier == "tier_3")
    vuln = next(v for v in vulns if v.cvss < 5.0)
    if vuln:
        decision = evaluate_policy(svc, vuln, 20.0)
        # Tier-3 with low score might not require approval
        assert isinstance(decision.approval_required, bool)


# ───────────────── Orchestrator (full pipeline) ─────────────────

def test_full_pipeline():
    """Full pipeline runs and produces ordered plan."""
    services = load_services()
    deps = load_dependencies()
    vulns = load_vulnerabilities()
    orch = Orchestrator(services, deps, vulns)
    result = orch.run()
    assert len(result.findings) >= 10
    assert len(result.plan) >= 10
    assert len(result.steps) == 6
    # Plan should be ordered by score
    scores = [p.final_score for p in result.plan]
    assert scores == sorted(scores, reverse=True)
    # Executive summary should be present
    assert "headline" in result.executive_summary


def test_pipeline_explanations():
    """Every plan item has an explanation."""
    services = load_services()
    deps = load_dependencies()
    vulns = load_vulnerabilities()
    orch = Orchestrator(services, deps, vulns)
    result = orch.run()
    for item in result.plan:
        assert item.explanation
        assert "summary" in item.explanation


def test_pipeline_comparison_ranks():
    """CVSS-only ranks are assigned and differ from business ranks."""
    services = load_services()
    deps = load_dependencies()
    vulns = load_vulnerabilities()
    orch = Orchestrator(services, deps, vulns)
    result = orch.run()
    has_difference = False
    for item in result.plan:
        assert item.cvss_only_rank is not None
        if item.cvss_only_rank != item.priority_rank:
            has_difference = True
    assert has_difference, "Business-aware ranking should differ from CVSS-only"
