"""CrewAI tools for querying audit logs and IAM policy data.

These tools are the interface between the CrewAI agents and our data.
Each tool wraps a query against the audit SQLite database or the
policy fetcher, returning JSON strings that the LLM agents can parse.

Tools are constructed with dependency injection — they receive references
to the AuditLogger and PolicyFetcherProtocol at creation time.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from agentgate.permission_engine.policy_fetcher import PolicyFetcherProtocol
from agentgate.proxy.audit import AuditLogger

logger = logging.getLogger(__name__)


# --- Input schemas (tell the LLM what arguments each tool accepts) ---


class QueryAuditLogInput(BaseModel):
    """Input for querying the audit log."""

    user_arn: str = Field(default="", description="Filter by user ARN. Empty string means all users.")
    decision: str = Field(default="", description="Filter by decision: ALLOW, DENY, or IMPLICIT_DENY. Empty means all.")
    limit: int = Field(default=100, description="Maximum number of entries to return.")


class GetDeniedRequestsInput(BaseModel):
    """Input for querying denied requests."""

    limit: int = Field(default=100, description="Maximum number of denied entries to return.")


class GetAgentRolePoliciesInput(BaseModel):
    """Input for fetching an agent role's IAM policies."""

    role_arn: str = Field(description="The ARN of the agent role to fetch policies for.")


class GetAccessSummaryInput(BaseModel):
    """Input for getting an access summary."""

    limit: int = Field(default=200, description="Maximum number of audit entries to summarize.")


# --- Tools ---


class QueryAuditLogTool(BaseTool):
    """Query the audit log with optional filters.

    Returns a JSON list of audit entries, each with: timestamp, user_arn,
    agent_id, tool_name, aws_action, resource, decision, reason.
    """

    name: str = "query_audit_log"
    description: str = (
        "Query the permission audit log database. "
        "Can filter by user_arn and/or decision (ALLOW/DENY/IMPLICIT_DENY). "
        "Returns a JSON list of audit entries showing what the agent tried to do."
    )
    args_schema: type[BaseModel] = QueryAuditLogInput

    # Injected dependency — not an LLM argument
    _audit: AuditLogger

    def __init__(self, audit: AuditLogger, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._audit = audit

    def _run(self, user_arn: str = "", decision: str = "", limit: int = 100) -> str:
        if user_arn:
            entries = self._audit.get_by_user(user_arn, limit=limit)
        else:
            entries = self._audit.get_recent(limit=limit)

        if decision:
            entries = [e for e in entries if e["decision"] == decision.upper()]

        return json.dumps(entries, indent=2)


class GetDeniedRequestsTool(BaseTool):
    """Get all denied requests from the audit log.

    Convenience tool that returns only DENY and IMPLICIT_DENY entries.
    Useful for detecting agents probing capabilities they shouldn't have.
    """

    name: str = "get_denied_requests"
    description: str = (
        "Get all denied requests from the audit log. "
        "Returns entries where the agent was blocked (DENY or IMPLICIT_DENY). "
        "Useful for detecting suspicious access attempts or misconfigured permissions."
    )
    args_schema: type[BaseModel] = GetDeniedRequestsInput

    _audit: AuditLogger

    def __init__(self, audit: AuditLogger, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._audit = audit

    def _run(self, limit: int = 100) -> str:
        entries = self._audit.get_recent(limit=limit)
        denied = [e for e in entries if e["decision"] in ("DENY", "IMPLICIT_DENY")]
        return json.dumps(denied, indent=2)


class GetAgentRolePoliciesTool(BaseTool):
    """Fetch the IAM policies attached to an agent role.

    Returns the raw policy documents so the agent can see exactly what
    permissions the agent role has been granted. This is the "what's allowed"
    side of the privilege creep comparison.
    """

    name: str = "get_agent_role_policies"
    description: str = (
        "Fetch the IAM policies for an agent role ARN. "
        "Returns the raw policy documents showing what AWS actions the agent role is allowed to perform. "
        "Use this to compare granted permissions against actual usage from audit logs."
    )
    args_schema: type[BaseModel] = GetAgentRolePoliciesInput

    _fetcher: PolicyFetcherProtocol

    def __init__(self, fetcher: PolicyFetcherProtocol, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._fetcher = fetcher

    def _run(self, role_arn: str) -> str:
        policies = self._fetcher.get_identity_policies(role_arn)

        result = {
            "role_arn": role_arn,
            "inline_policies": policies.inline_policies,
            "managed_policies": policies.managed_policies,
            "permission_boundary": policies.permission_boundary,
        }
        return json.dumps(result, indent=2)


class GetAccessSummaryTool(BaseTool):
    """Aggregate audit log data into a usage summary.

    Groups entries by (agent_id, aws_action) and counts how many times each
    action was used and how many were allowed vs denied. Gives agents a
    high-level view of what the agent actually does without processing raw rows.
    """

    name: str = "get_access_summary"
    description: str = (
        "Get a summary of agent access patterns from the audit log. "
        "Groups by agent_id and aws_action, showing total count, allow count, and deny count. "
        "Use this to see which AWS actions the agent actually uses vs. which are never called."
    )
    args_schema: type[BaseModel] = GetAccessSummaryInput

    _audit: AuditLogger

    def __init__(self, audit: AuditLogger, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._audit = audit

    def _run(self, limit: int = 200) -> str:
        entries = self._audit.get_recent(limit=limit)

        # Group by (agent_id, aws_action) with counts
        summary: dict[str, dict[str, Any]] = {}
        for entry in entries:
            key = f"{entry['agent_id']}|{entry['aws_action']}"
            if key not in summary:
                summary[key] = {
                    "agent_id": entry["agent_id"],
                    "aws_action": entry["aws_action"],
                    "total": 0,
                    "allowed": 0,
                    "denied": 0,
                    "resources": [],
                }
            summary[key]["total"] += 1
            if entry["decision"] == "ALLOW":
                summary[key]["allowed"] += 1
            else:
                summary[key]["denied"] += 1
            resource = entry["resource"]
            if resource not in summary[key]["resources"]:
                summary[key]["resources"].append(resource)

        return json.dumps(list(summary.values()), indent=2)
