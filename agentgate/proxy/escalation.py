"""Cross-system escalation detection.

Tracks sequences of tool calls within a session and blocks dangerous
patterns. For example, an agent that reads sensitive data (DynamoDB/S3)
and then tries to send it externally (SES) is blocked — even though
each individual action is allowed by IAM.

This is layered on top of per-call IAM permission checks in routes.py.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class EscalationRule:
    """Defines a dangerous cross-system pattern.

    If any action from trigger_actions has been seen in the session history,
    then any action in blocked_actions will be blocked.

    Attributes:
        name: unique identifier for the rule (e.g. "data_exfiltration").
        description: human-readable explanation of why this pattern is dangerous.
        trigger_actions: AWS actions that activate this rule when seen in history.
        blocked_actions: AWS actions that are blocked once a trigger has fired.
        severity: HIGH, MEDIUM, or LOW.
    """

    name: str
    description: str
    trigger_actions: list[str]
    blocked_actions: list[str]
    severity: str = "HIGH"


@dataclass
class EscalationResult:
    """Outcome of an escalation check.

    Attributes:
        blocked: whether the action was blocked.
        rule_name: which rule triggered the block.
        reason: human-readable explanation.
    """

    blocked: bool
    rule_name: str
    reason: str


class SessionTracker:
    """Tracks tool call history per session.

    A session is identified by a key (typically "user_arn:agent_id").
    The tracker records which AWS actions have been performed in each
    session so escalation rules can check for dangerous sequences.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, list[str]] = {}

    def record(self, session_key: str, action: str) -> None:
        """Add an action to the session history."""
        if session_key not in self._sessions:
            self._sessions[session_key] = []
        self._sessions[session_key].append(action)

    def get_history(self, session_key: str) -> list[str]:
        """Get the list of past actions for a session."""
        return list(self._sessions.get(session_key, []))

    def clear(self, session_key: str) -> None:
        """Reset a session's history."""
        self._sessions.pop(session_key, None)

    def clear_all(self) -> None:
        """Reset all session histories."""
        self._sessions.clear()


def check_escalation(
    history: list[str],
    next_action: str,
    rules: list[EscalationRule],
) -> EscalationResult | None:
    """Check if performing next_action would violate an escalation rule.

    Compares the session history against each rule. If a trigger action
    has already been seen AND the next action is in the blocked list,
    the action is blocked.

    Args:
        history: list of AWS actions already performed in this session.
        next_action: the AWS action about to be performed.
        rules: escalation rules to check against.

    Returns:
        EscalationResult if the action should be blocked, None if it's safe.
    """
    for rule in rules:
        # Check if any trigger action was already performed in this session
        triggered_action = None
        for past_action in history:
            if past_action in rule.trigger_actions:
                triggered_action = past_action
                break

        # If triggered, check if the next action is in the blocked list
        if triggered_action and next_action in rule.blocked_actions:
            return EscalationResult(
                blocked=True,
                rule_name=rule.name,
                reason=(
                    f"Cross-system escalation blocked by rule '{rule.name}': "
                    f"{rule.description}. "
                    f"Trigger action '{triggered_action}' was followed by "
                    f"blocked action '{next_action}'."
                ),
            )

    return None


# Default rules for the demo — covers the primary attack scenario from the paper
DEFAULT_ESCALATION_RULES = [
    EscalationRule(
        name="data_exfiltration",
        description="Reading data then sending it externally",
        trigger_actions=["dynamodb:Query", "dynamodb:Scan", "s3:GetObject"],
        blocked_actions=["ses:SendEmail"],
        severity="HIGH",
    ),
]
