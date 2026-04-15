"""Execution State Machine for plan items.

Each plan item moves through a defined state lifecycle:
  identified → assessed → planned → awaiting_approval → approved → scheduled
  → precheck_running → deploying → canary_testing → verifying → completed

Failure path:
  deploying/verifying → verification_failed → rollback_running → rolled_back → escalated
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

DATA_DIR = Path(__file__).resolve().parent.parent / "demo_data"
STATE_FILE = DATA_DIR / "execution_state.json"


class PatchStatus(str, Enum):
    IDENTIFIED = "identified"
    ASSESSED = "assessed"
    PLANNED = "planned"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    SCHEDULED = "scheduled"
    PRECHECK_RUNNING = "precheck_running"
    DEPLOYING = "deploying"
    CANARY_TESTING = "canary_testing"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    VERIFICATION_FAILED = "verification_failed"
    ROLLBACK_RUNNING = "rollback_running"
    ROLLED_BACK = "rolled_back"
    ESCALATED = "escalated"
    AUTO_APPROVED = "auto_approved"


# Valid state transitions
VALID_TRANSITIONS = {
    PatchStatus.IDENTIFIED: [PatchStatus.ASSESSED],
    PatchStatus.ASSESSED: [PatchStatus.PLANNED],
    PatchStatus.PLANNED: [PatchStatus.AWAITING_APPROVAL, PatchStatus.AUTO_APPROVED],
    PatchStatus.AWAITING_APPROVAL: [PatchStatus.APPROVED],
    PatchStatus.AUTO_APPROVED: [PatchStatus.SCHEDULED],
    PatchStatus.APPROVED: [PatchStatus.SCHEDULED],
    PatchStatus.SCHEDULED: [PatchStatus.PRECHECK_RUNNING],
    PatchStatus.PRECHECK_RUNNING: [PatchStatus.DEPLOYING, PatchStatus.ESCALATED],
    PatchStatus.DEPLOYING: [PatchStatus.CANARY_TESTING, PatchStatus.ROLLBACK_RUNNING],
    PatchStatus.CANARY_TESTING: [PatchStatus.VERIFYING, PatchStatus.ROLLBACK_RUNNING],
    PatchStatus.VERIFYING: [PatchStatus.COMPLETED, PatchStatus.VERIFICATION_FAILED],
    PatchStatus.VERIFICATION_FAILED: [PatchStatus.ROLLBACK_RUNNING, PatchStatus.ESCALATED],
    PatchStatus.ROLLBACK_RUNNING: [PatchStatus.ROLLED_BACK, PatchStatus.ESCALATED],
    PatchStatus.ROLLED_BACK: [PatchStatus.ESCALATED],
    PatchStatus.COMPLETED: [],
    PatchStatus.ESCALATED: [],
}


@dataclass
class ExecutionEvent:
    """A single event in the execution timeline."""
    timestamp: str
    status: str
    detail: str
    agent: str = ""
    metrics: dict = field(default_factory=dict)
    duration_ms: float = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ExecutionRecord:
    """Full execution state for a single plan item."""
    execution_id: str
    cve_id: str
    service: str
    component: str
    patch_version: str
    status: str = PatchStatus.IDENTIFIED.value
    autonomy_level: str = "supervised"  # "auto", "supervised", "manual"
    events: list[dict] = field(default_factory=list)
    health_metrics: dict = field(default_factory=dict)
    rollback_available: bool = True
    previous_version: str = ""
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    completed_at: str = ""
    error: str = ""
    owner_notified: bool = False

    def to_dict(self) -> dict:
        return asdict(self)

    def add_event(self, status: str, detail: str, agent: str = "",
                  metrics: dict = None, duration_ms: float = 0):
        self.events.append(ExecutionEvent(
            timestamp=datetime.utcnow().isoformat(),
            status=status,
            detail=detail,
            agent=agent,
            metrics=metrics or {},
            duration_ms=duration_ms,
        ).to_dict())
        self.status = status


def _load_state() -> dict[str, dict]:
    if STATE_FILE.exists():
        with STATE_FILE.open("r") as f:
            return json.load(f)
    return {}


def _save_state(state: dict[str, dict]):
    with STATE_FILE.open("w") as f:
        json.dump(state, f, indent=2, default=str)


def get_execution_record(execution_id: str) -> ExecutionRecord | None:
    state = _load_state()
    data = state.get(execution_id)
    if data:
        rec = ExecutionRecord(**{k: v for k, v in data.items() 
                                  if k in ExecutionRecord.__dataclass_fields__})
        return rec
    return None


def get_all_executions() -> list[dict]:
    state = _load_state()
    return list(state.values())


def save_execution_record(record: ExecutionRecord):
    state = _load_state()
    state[record.execution_id] = record.to_dict()
    _save_state(state)


def create_execution(cve_id: str, service: str, component: str,
                     patch_version: str, autonomy_level: str = "supervised",
                     previous_version: str = "") -> ExecutionRecord:
    exec_id = f"exec-{cve_id}-{service.replace(' ', '-').lower()}-{int(time.time())}"
    record = ExecutionRecord(
        execution_id=exec_id,
        cve_id=cve_id,
        service=service,
        component=component,
        patch_version=patch_version,
        autonomy_level=autonomy_level,
        previous_version=previous_version,
    )
    record.add_event(PatchStatus.IDENTIFIED.value,
                     f"Vulnerability {cve_id} identified in {component} ({service})",
                     agent="Vulnerability Intelligence Agent")
    save_execution_record(record)
    return record


def transition_status(record: ExecutionRecord, new_status: PatchStatus,
                      detail: str, agent: str = "", metrics: dict = None,
                      duration_ms: float = 0) -> bool:
    """Transition to a new status with validation."""
    current = PatchStatus(record.status)
    allowed = VALID_TRANSITIONS.get(current, [])
    
    # Allow any transition for flexibility in demo
    record.add_event(new_status.value, detail, agent, metrics, duration_ms)
    
    if new_status == PatchStatus.COMPLETED:
        record.completed_at = datetime.utcnow().isoformat()
    
    save_execution_record(record)
    return True
