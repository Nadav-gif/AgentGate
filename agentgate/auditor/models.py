"""Data models for the permission auditor output.

These are the structured types that the CrewAI agents produce:
- Finding: one security issue detected by the analysis
- SecurityReport: the final output combining all findings with a risk score
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class Finding:
    """A single security finding from the audit analysis.

    Attributes:
        severity: HIGH, MEDIUM, or LOW.
        category: what type of finding (e.g. "unused_permission", "denial_spike").
        user_arn: the IAM identity this finding relates to (agent role or user).
        description: human-readable explanation of the issue.
        recommendation: what to do about it.
    """

    severity: str
    category: str
    user_arn: str
    description: str
    recommendation: str


@dataclass
class SecurityReport:
    """Final output of the permission auditor crew.

    Attributes:
        risk_score: overall risk from 1 (low) to 10 (critical).
        findings: list of individual security findings.
        summary: high-level narrative of the analysis.
        generated_at: ISO timestamp of when the report was created.
    """

    risk_score: int
    findings: list[Finding] = field(default_factory=list)
    summary: str = ""
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
