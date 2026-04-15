"""Notification Service — alerts and escalations to service owners."""
from __future__ import annotations

from datetime import datetime
from typing import Any

# In-memory notification log (in production: Slack, PagerDuty, email, etc.)
_notifications: list[dict] = []


def notify_owner(service: str, message: str, severity: str = "info",
                 execution_id: str = "", channel: str = "slack") -> dict:
    """Send notification to the service owner."""
    notif = {
        "id": f"notif-{len(_notifications)+1}",
        "service": service,
        "message": message,
        "severity": severity,
        "execution_id": execution_id,
        "channel": channel,
        "timestamp": datetime.utcnow().isoformat(),
        "acknowledged": False,
    }
    _notifications.append(notif)
    return notif


def notify_escalation(service: str, execution_id: str, reason: str,
                      evidence: dict = None) -> dict:
    """Escalate to on-call engineer with evidence."""
    notif = {
        "id": f"notif-{len(_notifications)+1}",
        "service": service,
        "type": "escalation",
        "message": f"🚨 ESCALATION: {reason}",
        "severity": "critical",
        "execution_id": execution_id,
        "evidence": evidence or {},
        "channel": "pagerduty",
        "timestamp": datetime.utcnow().isoformat(),
        "acknowledged": False,
    }
    _notifications.append(notif)
    return notif


def get_notifications(limit: int = 50) -> list[dict]:
    """Get recent notifications."""
    return list(reversed(_notifications[-limit:]))


def clear_notifications():
    """Clear all notifications."""
    _notifications.clear()
