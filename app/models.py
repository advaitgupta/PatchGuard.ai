"""Pydantic data models for the Risk-Aware Upgrade Orchestrator.

Covers: services, components, vulnerabilities, dependencies,
risk findings, upgrade plans, approvals, and audit events.
"""
from __future__ import annotations

from datetime import date, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


# ───────────────────────── Service & Infra ─────────────────────────

class Owner(BaseModel):
    team: str
    lead: str
    email: str


class MaintenanceWindow(BaseModel):
    day_of_week: str
    start_hour_24: int = Field(ge=0, le=23)
    duration_hours: int = Field(ge=1, le=24)


class Service(BaseModel):
    name: str
    tier: Literal["tier_1", "tier_2", "tier_3"]
    internet_facing: bool = False
    business_function: str
    owner: Owner
    maintenance_window: MaintenanceWindow
    rollback_complexity: Literal["low", "medium", "high"]
    components: list[str]
    customer_facing: bool = False
    regulatory_scope: list[str] = Field(default_factory=list)
    hosting_type: str = "hybrid"
    environment: str = "prod"


class Component(BaseModel):
    component_id: str
    name: str
    version: str
    package_type: str = "unknown"   # npm, pypi, maven, container, etc.
    supplier: str = ""
    is_direct_dependency: bool = True


class ServiceComponent(BaseModel):
    service_id: str
    component_id: str
    usage_type: str = "runtime"     # runtime, build, transitive
    exposed_to_internet: bool = False


# ───────────────────────── Vulnerability ──────────────────────────

class Vulnerability(BaseModel):
    cve_id: str
    component: str
    cvss: float = Field(ge=0.0, le=10.0)
    epss: float = Field(ge=0.0, le=1.0)
    kev: bool = False
    summary: str
    patch_version: str
    published_date: date
    patch_available: bool = True
    exploit_maturity: str = "unknown"          # unknown, none, poc, active
    affected_versions_rule: str = ""           # e.g. "<2.1.10"
    severity_label: str = ""                   # critical, high, medium, low
    vendor_source: str = ""
    reference_urls: list[str] = Field(default_factory=list)


# ───────────────────────── Dependencies ───────────────────────────

class DependencyEdge(BaseModel):
    consumer: str
    provider: str
    dependency_type: Literal["data", "functional", "auth", "notification", "analytics"]
    criticality: Literal["low", "medium", "high"]


# ───────────────────────── Analysis & Planning ────────────────────

class RiskFinding(BaseModel):
    cve_id: str
    service: str
    component: str
    risk_score: float
    blast_radius: int
    business_impact: int
    exploit_score: float
    severity_score: float
    operational_penalty: float
    recommended_action: str
    owner_team: str
    rationale: list[str]


class PlannedChange(BaseModel):
    priority_rank: int
    target_date: date
    service: str
    component: str
    cve_id: str
    risk_score: float
    owner_team: str
    approval_required: bool
    planned_window: str
    rollback_plan: str
    downstream_impact: list[str]
    validation_steps: list[str]


# ───────────────────────── Approval ───────────────────────────────

class ApprovalRecord(BaseModel):
    plan_id: str
    cve_id: str
    service: str
    approver_email: str
    approver_name: str = ""
    decision: Literal["approved", "rejected", "deferred"]
    comment: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ───────────────────────── Audit ──────────────────────────────────

class AuditEvent(BaseModel):
    actor: str
    action_type: str
    entity_type: str
    entity_id: str
    detail: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
