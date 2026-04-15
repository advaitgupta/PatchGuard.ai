"""Data loaders for JSON-backed demo/synthetic data.

Supports: services, dependencies, vulnerabilities, components, and
maintenance windows.  Also provides save-back for dynamic ingestion.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.models import Component, DependencyEdge, Service, ServiceComponent, Vulnerability

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "demo_data"
APPROVALS_FILE = DATA_DIR / "approvals.json"



def _load_json(filename: str) -> Any:
    filepath = DATA_DIR / filename
    if not filepath.exists():
        return []
    with filepath.open("r", encoding="utf-8") as f:
        return json.load(f)


def _save_json(filename: str, data: Any) -> None:
    with (DATA_DIR / filename).open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


# ───────────────── Services ─────────────────

def load_services() -> list[Service]:
    return [Service(**item) for item in _load_json("services.json")]


# ───────────────── Dependencies ─────────────────

def load_dependencies() -> list[DependencyEdge]:
    return [DependencyEdge(**item) for item in _load_json("dependencies.json")]


# ───────────────── Vulnerabilities ─────────────────

def load_vulnerabilities() -> list[Vulnerability]:
    return [Vulnerability(**item) for item in _load_json("vulnerabilities.json")]


def save_vulnerabilities(vulnerabilities: list[Vulnerability]) -> None:
    payload = [v.model_dump(mode="json") for v in vulnerabilities]
    _save_json("vulnerabilities.json", payload)


# ───────────────── Components (rich) ─────────────────

def load_components() -> list[Component]:
    return [Component(**item) for item in _load_json("components.json")]


# ───────────────── Service-Component mappings ─────────────────

def load_service_components() -> list[ServiceComponent]:
    return [ServiceComponent(**item) for item in _load_json("service_components.json")]


# ───────────────── Approvals (persisted as JSON) ─────────────────

def load_approvals() -> list[dict]:
    return _load_json("approvals.json")


def save_approval(record: dict) -> None:
    existing = load_approvals()
    existing.append(record)
    _save_json("approvals.json", existing)


# ───────────────── Internal Documentation ─────────────────

def load_internal_docs() -> list[dict]:
    """Load internal documentation: incident reports, change logs, runbooks."""
    return _load_json("internal_docs.json")


def get_docs_for_service(service_name: str) -> list[dict]:
    """Get internal docs filtered by service name."""
    docs = load_internal_docs()
    return [d for d in docs if d.get("service") == service_name]


def get_docs_for_component(component_name: str) -> list[dict]:
    """Get internal docs filtered by component."""
    docs = load_internal_docs()
    return [d for d in docs if d.get("related_component") == component_name]
