"""
Data models for the permission engine.

These are the core types that flow through the evaluation chain:
- PolicyEntry: one parsed action+resource pair from an IAM statement
- PolicyLists: aggregated allow/deny entries
- IdentityPolicies: raw policy data before parsing
- Decision/EvaluationResult: the output of can_do()
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Decision(Enum):
    """Outcome of an IAM permission evaluation."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    IMPLICIT_DENY = "IMPLICIT_DENY"


@dataclass
class PolicyEntry:
    """One action+resource pair extracted from a parsed IAM statement."""

    action: str
    resource: str

    def __post_init__(self) -> None:
        if not self.action:
            raise ValueError("action must not be empty")
        if not self.resource:
            raise ValueError("resource must not be empty")


@dataclass
class PolicyLists:
    """Aggregated allow and deny lists from parsed IAM policies."""

    allows: list[PolicyEntry] = field(default_factory=list)
    denies: list[PolicyEntry] = field(default_factory=list)

    def merge(self, other: "PolicyLists") -> None:
        """Merge another PolicyLists into this one."""
        self.allows.extend(other.allows)
        self.denies.extend(other.denies)


@dataclass
class IdentityPolicies:
    """Raw policy data for a single IAM identity (before parsing).

    Attributes:
        inline_policies: list of raw policy documents (dicts) attached directly to the identity.
        managed_policies: list of raw policy documents (dicts) from attached managed policies.
        permission_boundary: optional raw policy document for the permission boundary.
        scps: list of raw SCP policy documents from the org chain.
    """

    inline_policies: list[dict[str, Any]] = field(default_factory=list)
    managed_policies: list[dict[str, Any]] = field(default_factory=list)
    permission_boundary: Optional[dict[str, Any]] = None
    scps: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class EvaluationResult:
    """The final output of can_do().

    Attributes:
        decision: ALLOW, DENY, or IMPLICIT_DENY.
        reason: human-readable explanation of why this decision was made.
        action: the AWS action that was evaluated.
        resource: the AWS resource ARN that was evaluated.
        user_arn: the IAM identity that was evaluated.
    """

    decision: Decision
    reason: str
    action: str
    resource: str
    user_arn: str
