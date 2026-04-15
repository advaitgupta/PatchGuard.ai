"""Central configuration for the Risk-Aware Upgrade Orchestrator."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ScoringWeights:
    """Weights for the composite risk-priority formula (should sum to ~1.0)."""
    severity: float = 0.30
    exploitability: float = 0.25
    business_impact: float = 0.20
    blast_radius: float = 0.15
    exposure: float = 0.10
    # Penalty weights (subtracted)
    complexity_penalty: float = 0.08
    maintenance_penalty: float = 0.05


@dataclass(frozen=True)
class ApprovalPolicy:
    """Rules that force human-in-the-loop approval."""
    tier1_always_approve: bool = True
    high_rollback_approve: bool = True
    score_threshold: float = 65.0          # final score >= this → approval required
    payment_services_approve: bool = True  # any service with "payment" in name
    auth_services_approve: bool = True     # any service with "auth" or "iam" in name


@dataclass(frozen=True)
class FeedURLs:
    """Public vulnerability intelligence feed endpoints."""
    nvd_cve: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    cisa_kev: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    epss: str = "https://api.first.org/data/v1/epss"


@dataclass
class Settings:
    """Application-wide settings."""
    app_title: str = "Risk-Aware Software Upgrade Orchestrator"
    app_version: str = "1.0.0"
    debug: bool = True
    # Database (SQLite for hackathon)
    database_url: str = "sqlite:///orchestrator.db"
    # Scoring
    scoring: ScoringWeights = field(default_factory=ScoringWeights)
    # Approval
    approval: ApprovalPolicy = field(default_factory=ApprovalPolicy)
    # Feeds
    feeds: FeedURLs = field(default_factory=FeedURLs)
    # Feature flags
    enable_live_feeds: bool = True
    enable_llm_explanations: bool = False
    # Tier mappings
    tier_impact: dict[str, int] = field(default_factory=lambda: {
        "tier_1": 95,
        "tier_2": 60,
        "tier_3": 30,
    })
    rollback_complexity_score: dict[str, int] = field(default_factory=lambda: {
        "low": 10,
        "medium": 35,
        "high": 70,
    })
    # KEV / internet exposure bonuses (added to exploitability)
    kev_bonus: int = 25
    internet_exposure_bonus: int = 15
    customer_facing_bonus: int = 12
    regulatory_bonus: int = 10


def get_settings() -> Settings:
    """Return settings (reads env overrides where applicable)."""
    return Settings(
        debug=os.getenv("DEBUG", "true").lower() == "true",
        enable_live_feeds=os.getenv("ENABLE_LIVE_FEEDS", "true").lower() == "true",
    )
