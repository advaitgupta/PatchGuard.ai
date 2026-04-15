"""Change Control Service — manages approval routing and policies."""
from __future__ import annotations

import random
import time
from datetime import datetime
from app.services.execution_state import PatchStatus, transition_status, get_execution_record


def approval_required(tier: str, final_score: float) -> bool:
    """Determine if human approval is required based on policy."""
    if tier == "tier_1":
        return True
    if final_score >= 80:
        return True
    return False


def request_approval(execution_id: str, service: str, cve_id: str, 
                     reason: str) -> dict:
    """Route a request for approval to the service owner."""
    time.sleep(0.1)
    record = get_execution_record(execution_id)
    if record:
        transition_status(record, PatchStatus.AWAITING_APPROVAL,
                          f"Approval requested: {reason}",
                          agent="Governance Agent")
    
    return {
        "execution_id": execution_id,
        "status": "awaiting_approval",
        "service": service,
        "cve_id": cve_id,
        "reason": reason,
        "timestamp": datetime.utcnow().isoformat(),
    }


def record_approval(execution_id: str, approver: str, comment: str) -> dict:
    """Record an approval decision and transition state."""
    record = get_execution_record(execution_id)
    if not record:
        raise ValueError(f"Execution {execution_id} not found")
        
    transition_status(record, PatchStatus.APPROVED,
                      f"Approved by {approver}: {comment}",
                      agent="Governance Agent")
    
    return {
        "execution_id": execution_id,
        "status": "approved",
        "approver": approver,
        "timestamp": datetime.utcnow().isoformat(),
    }


def record_rejection(execution_id: str, approver: str, comment: str) -> dict:
    """Record a rejection decision."""
    record = get_execution_record(execution_id)
    if not record:
        raise ValueError(f"Execution {execution_id} not found")
        
    transition_status(record, PatchStatus.ESCALATED,
                      f"Rejected by {approver}: {comment}",
                      agent="Governance Agent")
    
    return {
        "execution_id": execution_id,
        "status": "rejected",
        "approver": approver,
        "timestamp": datetime.utcnow().isoformat(),
    }
