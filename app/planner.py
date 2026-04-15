from __future__ import annotations

from datetime import date, timedelta

from app.models import PlannedChange, RiskFinding, Service
from app.risk_engine import RiskEngine


class Planner:
    def __init__(self, services: list[Service], risk_engine: RiskEngine) -> None:
        self.services = {s.name: s for s in services}
        self.risk_engine = risk_engine

    def _next_window_date(self, service_name: str, start_date: date) -> date:
        service = self.services[service_name]
        target_weekday = [
            "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"
        ].index(service.maintenance_window.day_of_week.lower())
        d = start_date
        while d.weekday() != target_weekday:
            d += timedelta(days=1)
        return d

    def _approval_required(self, service: Service, finding: RiskFinding) -> bool:
        return service.tier == "tier_1" or finding.risk_score >= 160 or service.rollback_complexity == "high"

    def build_plan(self, findings: list[RiskFinding], start_date: date | None = None) -> list[PlannedChange]:
        today = start_date or date.today()
        plan: list[PlannedChange] = []

        for idx, finding in enumerate(findings, start=1):
            service = self.services[finding.service]
            slot_date = self._next_window_date(finding.service, today + timedelta(days=idx - 1))
            window = service.maintenance_window
            downstream_impact = self.risk_engine.downstream_services(finding.service)
            rollback_plan = (
                f"Revert {finding.component}, restore prior container or package version, "
                f"run smoke tests, and validate auth/transaction telemetry within {window.duration_hours}h window."
            )
            validation_steps = [
                "Run pre-deployment backup or snapshot.",
                "Execute smoke tests for the upgraded service.",
                "Validate top 3 upstream and downstream integrations.",
                "Monitor error rate, latency, and business KPIs for 30 minutes.",
            ]
            plan.append(
                PlannedChange(
                    priority_rank=idx,
                    target_date=slot_date,
                    service=finding.service,
                    component=finding.component,
                    cve_id=finding.cve_id,
                    risk_score=finding.risk_score,
                    owner_team=service.owner.team,
                    approval_required=self._approval_required(service, finding),
                    planned_window=f"{window.day_of_week.title()} {window.start_hour_24:02d}:00 for {window.duration_hours}h",
                    rollback_plan=rollback_plan,
                    downstream_impact=downstream_impact,
                    validation_steps=validation_steps,
                )
            )
        return plan
