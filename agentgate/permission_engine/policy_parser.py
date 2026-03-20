"""
Pure-function policy parser.

Parses IAM policy documents into PolicyEntry lists and provides
wildcard matching for actions and resources.
"""

from __future__ import annotations

import fnmatch
import logging
from typing import Any

from agentgate.permission_engine.models import PolicyEntry, PolicyLists

logger = logging.getLogger(__name__)

ALL_AWS_ACTIONS: list[str] | None = None  # lazy-loaded for NotAction


def _ensure_list(value: str | list[str]) -> list[str]:
    """IAM policy Actions/Resources can be a string or list. normalize to always be a list."""
    if isinstance(value, str):
        return [value]
    return list(value)


def action_matches(pattern: str, action: str) -> bool:
    """Check if an IAM action pattern matches a specific action. Case-insensitive.

    Supports wildcards: 's3:Get*' matches 's3:GetObject', '*' matches everything.
    """
    return fnmatch.fnmatch(action.lower(), pattern.lower())


def resource_matches(pattern: str, resource: str) -> bool:
    """Check if an IAM resource pattern matches a specific resource ARN.

    Supports wildcards: 'arn:aws:s3:::my-bucket/*' matches 'arn:aws:s3:::my-bucket/key'.
    """
    if pattern == "*":
        return True
    return fnmatch.fnmatch(resource, pattern)


def get_matching_resources(action: str, resource: str, entries: list[PolicyEntry]) -> list[PolicyEntry]:
    """Return all entries that match both the given action AND resource."""
    matches = []
    for entry in entries:
        if action_matches(entry.action, action) and resource_matches(entry.resource, resource):
            matches.append(entry)
    return matches


def parse_statement(statement: dict[str, Any]) -> tuple[list[PolicyEntry], list[PolicyEntry]]:
    """Parse one IAM policy statement into (allow_entries, deny_entries).

    Handles Action/NotAction and Resource fields. Returns new lists (no mutation).
    """
    effect = statement.get("Effect", "")
    resources = _ensure_list(statement.get("Resource", ["*"]))

    # Determine actions — either Action or NotAction
    if "Action" in statement:
        actions = _ensure_list(statement["Action"])
    elif "NotAction" in statement:
        not_actions = _ensure_list(statement["NotAction"])
        actions = _expand_not_action(not_actions)
    else:
        return [], []

    entries = [PolicyEntry(action=a, resource=r) for a in actions for r in resources]

    if effect == "Allow":
        return entries, []
    elif effect == "Deny":
        return [], entries
    else:
        logger.warning("Unknown Effect %r in statement, skipping", effect)
        return [], []


def _expand_not_action(not_actions: list[str]) -> list[str]:
    """Expand NotAction by returning all known AWS actions that DON'T match the patterns."""
    from agentgate.permission_engine.aws_actions import get_all_actions

    all_actions = get_all_actions()
    return [a for a in all_actions if not any(action_matches(pattern, a) for pattern in not_actions)]


def parse_policy_document(document: dict[str, Any]) -> PolicyLists:
    """Parse all statements in a policy document into aggregated PolicyLists."""
    result = PolicyLists()
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        allows, denies = parse_statement(stmt)
        result.allows.extend(allows)
        result.denies.extend(denies)

    return result


def intersect_with_boundary(allow_list: list[PolicyEntry], boundary_lists: PolicyLists) -> list[PolicyEntry]:
    """Restrict allow_list to only entries also allowed by the permission boundary.

    An entry is kept only if at least one boundary allow entry matches its action and resource.
    """
    return [
        entry
        for entry in allow_list
        if any(
            action_matches(b.action, entry.action) and resource_matches(b.resource, entry.resource)
            for b in boundary_lists.allows
        )
    ]
