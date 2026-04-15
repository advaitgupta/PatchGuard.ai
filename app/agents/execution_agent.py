"""Autonomous Execution Agent — the closed-loop remediation orchestrator.

This is the heart of the agentic system. It:
  1. Observes approved/auto-approved plan items
  2. Reasons about execution order and policy
  3. Executes patching through tools (stage → precheck → canary → full rollout)
  4. Verifies outcomes via health checks
  5. Rolls back and escalates on failure
  6. Notifies owners throughout

The agent uses bounded autonomy:
  - Low-risk (tier_3, score < 60): auto-execute without approval
  - Medium-risk: execute after approval
  - High-risk (tier_1): execute after approval with extended canary
"""
from __future__ import annotations

import logging
import time
from datetime import datetime
from typing import Any

from app.services.execution_state import (
    PatchStatus, ExecutionRecord, create_execution,
    get_execution_record, get_all_executions, save_execution_record,
    transition_status,
)
from app.services.execution_service import (
    prepare_execution_context, stage_patch_artifact,
    execute_canary_rollout, execute_full_rollout, create_change_record,
)
from app.services.verification_service import (
    run_prechecks, check_service_health, run_postchecks, check_error_budget,
)
from app.services.rollback_service import (
    rollback_to_previous_version, restore_previous_config, verify_rollback_health,
)
from app.services.notification_service import notify_owner, notify_escalation
from app.services.change_control_service import approval_required

logger = logging.getLogger(__name__)


async def execute_single_remediation(record: ExecutionRecord,
                                 scenario: str = "success") -> dict:
    """Execute a single remediation workflow end-to-end using a Reasoning Agent.
    
    This replaces the hardcoded state machine with a live ReAct loop.
    """
    from app.agents.gemini_agent import run_remediation_agent as _run_agent
    
    timeline = []
    
    def log_step(step: str, detail: str, agent: str, metrics: dict = None,
                 duration_ms: float = 0):
        entry = {
            "step": step,
            "detail": detail,
            "agent": agent,
            "timestamp": datetime.utcnow().isoformat(),
            "metrics": metrics or {},
            "duration_ms": duration_ms,
        }
        timeline.append(entry)
        logger.info(f"[{agent}] {step}: {detail}")

    try:
        # Initial Assessment (Simulated as first thought)
        transition_status(record, PatchStatus.ASSESSED,
                          f"Risk assessment complete for {record.cve_id}",
                          agent="Risk Prioritization Agent")
        log_step("assessed", f"Vulnerability {record.cve_id} matched to {record.service}", 
                 "Risk Prioritization Agent")

        # Start the live reasoning agent
        transition_status(record, PatchStatus.PLANNED,
                          "Reasoning Agent initialized for remediation planning",
                          agent="Remediation Agent")
        
        # We run the agent. The agent will call tools (precheck, canary, etc.)
        # and we capture its entire thought process for the timeline.
        agent_result = await _run_agent(
            cve_id=record.cve_id,
            service_name=record.service,
            component=record.component,
            current_version=record.previous_version or "unknown",
            target_version=record.patch_version or "latest",
            scenario=scenario
        )

        
        # Map Agent thoughts into our timeline for display
        for thought in agent_result.thoughts:
            step_name = thought.tool_name if thought.step_type == "act" else thought.step_type
            log_step(
                step_name,
                thought.content,
                "Remediation Agent",
                metrics={
                    "tool": thought.tool_name,
                    "input": thought.tool_input,
                    "output": thought.tool_output
                } if thought.tool_name else {},
                duration_ms=thought.duration_ms
            )

        # Final decision by agent
        if "remediated" in agent_result.final_answer.lower() or "success" in agent_result.final_answer.lower():
            transition_status(record, PatchStatus.COMPLETED,
                              agent_result.final_answer,
                              agent="Remediation Agent")
            return {"status": "completed", "timeline": timeline}
        elif "rolled back" in agent_result.final_answer.lower() or "failure" in agent_result.final_answer.lower():
            transition_status(record, PatchStatus.ROLLED_BACK,
                              agent_result.final_answer,
                              agent="Remediation Agent")
            return {"status": "rolled_back", "timeline": timeline}
        else:
            transition_status(record, PatchStatus.ESCALATED,
                              agent_result.final_answer,
                              agent="Remediation Agent")
            return {"status": "escalated", "timeline": timeline}

    except Exception as exc:
        logger.error(f"Reasoning loop failed: {exc}")
        transition_status(record, PatchStatus.ESCALATED, f"Error: {exc}", agent="System")
        return {"status": "failed", "error": str(exc), "timeline": timeline}


async def start_remediation(cve_id: str, service: str, component: str,
                      patch_version: str, previous_version: str = "",
                      autonomy_level: str = "supervised",
                      scenario: str = "success") -> dict:
    """Entry point: create execution record and run the Reasoning-Based Agent."""
    record = create_execution(
        cve_id=cve_id,
        service=service,
        component=component,
        patch_version=patch_version,
        autonomy_level=autonomy_level,
        previous_version=previous_version,
    )
    
    result = await execute_single_remediation(record, scenario=scenario)
    result["execution_id"] = record.execution_id
    result["record"] = get_execution_record(record.execution_id).to_dict()
    
    return result
