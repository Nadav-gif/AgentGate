"""
Policy fetcher — protocol + AWS implementation for retrieving IAM policies.

The Protocol allows dependency injection of a fake fetcher in tests.
The AwsPolicyFetcher is the real implementation using boto3.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Protocol, runtime_checkable

from agentgate.permission_engine.cache import PolicyCache
from agentgate.permission_engine.models import IdentityPolicies

logger = logging.getLogger(__name__)


@runtime_checkable
class PolicyFetcherProtocol(Protocol):
    """Interface for fetching IAM policies for an identity."""

    def get_identity_policies(self, identity_arn: str) -> IdentityPolicies: ...


def _parse_arn(arn: str) -> tuple[str, str, str]:
    """Parse an IAM ARN into (account_id, identity_type, identity_name).

    Example: 'arn:aws:iam::123456789012:user/alice' -> ('123456789012', 'user', 'alice')
    """
    parts = arn.split(":")
    if len(parts) < 6:
        raise ValueError(f"Invalid ARN format: {arn}")
    account_id = parts[4]
    resource = parts[5]
    if "/" in resource:
        identity_type, identity_name = resource.split("/", 1)
    else:
        identity_type = resource
        identity_name = ""
    return account_id, identity_type, identity_name


class AwsPolicyFetcher:
    """Fetches IAM policies from AWS using boto3.

    Parses the identity ARN to determine whether it's a user or role,
    then fetches inline policies, managed policies, and permission boundaries.
    """

    def __init__(self, session: Any, cache: PolicyCache | None = None) -> None:
        self._iam = session.client("iam")
        self._orgs: Any = None
        self._session = session
        self._cache = cache or PolicyCache()

    def get_identity_policies(self, identity_arn: str) -> IdentityPolicies:
        """Fetch all policies for the given IAM identity ARN."""
        _, identity_type, identity_name = _parse_arn(identity_arn)

        if identity_type == "user":
            return self._fetch_user_policies(identity_name)
        elif identity_type == "role":
            return self._fetch_role_policies(identity_name)
        else:
            raise ValueError(f"Unsupported identity type: {identity_type}")

    def _fetch_user_policies(self, username: str) -> IdentityPolicies:
        """Fetch inline policies, managed policies, and boundary for a user."""
        result = IdentityPolicies()

        # Inline policies
        inline_names = self._iam.list_user_policies(UserName=username)["PolicyNames"]
        for name in inline_names:
            cache_key = f"inline:user:{username}:{name}"
            doc = self._cache.get(cache_key)
            if doc is None:
                resp = self._iam.get_user_policy(UserName=username, PolicyName=name)
                doc = resp["PolicyDocument"]
                if isinstance(doc, str):
                    doc = json.loads(doc)
                self._cache.set(cache_key, doc)
            result.inline_policies.append(doc)

        # Managed policies
        attached = self._iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
        for policy in attached:
            doc = self._fetch_managed_policy(policy["PolicyArn"])
            result.managed_policies.append(doc)

        # Permission boundary
        try:
            user_info = self._iam.get_user(UserName=username)["User"]
            boundary_arn = user_info.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn")
            if boundary_arn:
                result.permission_boundary = self._fetch_managed_policy(boundary_arn)
        except Exception:
            logger.debug("Could not fetch permission boundary for user %s", username)

        # Group policies
        groups = self._iam.list_groups_for_user(UserName=username)["Groups"]
        for group in groups:
            group_name = group["GroupName"]
            # Group inline policies
            group_inline_names = self._iam.list_group_policies(GroupName=group_name)["PolicyNames"]
            for name in group_inline_names:
                cache_key = f"inline:group:{group_name}:{name}"
                doc = self._cache.get(cache_key)
                if doc is None:
                    resp = self._iam.get_group_policy(GroupName=group_name, PolicyName=name)
                    doc = resp["PolicyDocument"]
                    if isinstance(doc, str):
                        doc = json.loads(doc)
                    self._cache.set(cache_key, doc)
                result.inline_policies.append(doc)

            # Group managed policies
            group_attached = self._iam.list_attached_group_policies(GroupName=group_name)["AttachedPolicies"]
            for policy in group_attached:
                doc = self._fetch_managed_policy(policy["PolicyArn"])
                result.managed_policies.append(doc)

        return result

    def _fetch_role_policies(self, role_name: str) -> IdentityPolicies:
        """Fetch inline policies, managed policies, and boundary for a role."""
        result = IdentityPolicies()

        # Inline policies
        inline_names = self._iam.list_role_policies(RoleName=role_name)["PolicyNames"]
        for name in inline_names:
            cache_key = f"inline:role:{role_name}:{name}"
            doc = self._cache.get(cache_key)
            if doc is None:
                resp = self._iam.get_role_policy(RoleName=role_name, PolicyName=name)
                doc = resp["PolicyDocument"]
                if isinstance(doc, str):
                    doc = json.loads(doc)
                self._cache.set(cache_key, doc)
            result.inline_policies.append(doc)

        # Managed policies
        attached = self._iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
        for policy in attached:
            doc = self._fetch_managed_policy(policy["PolicyArn"])
            result.managed_policies.append(doc)

        # Permission boundary
        try:
            role_info = self._iam.get_role(RoleName=role_name)["Role"]
            boundary_arn = role_info.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn")
            if boundary_arn:
                result.permission_boundary = self._fetch_managed_policy(boundary_arn)
        except Exception:
            logger.debug("Could not fetch permission boundary for role %s", role_name)

        return result

    def _fetch_managed_policy(self, policy_arn: str) -> dict[str, Any]:
        """Fetch and cache a managed policy document by ARN."""
        cache_key = f"managed:{policy_arn}"
        doc = self._cache.get(cache_key)
        if doc is not None:
            return doc

        policy = self._iam.get_policy(PolicyArn=policy_arn)["Policy"]
        version_id = policy["DefaultVersionId"]
        version = self._iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
        doc = version["PolicyVersion"]["Document"]
        if isinstance(doc, str):
            doc = json.loads(doc)
        self._cache.set(cache_key, doc)
        return doc
