"""Dependency injection — shared objects for the FastAPI app.

All the components from previous phases are wired together here.
The create_dependencies() function builds everything, and the
individual get_*() functions are used as FastAPI dependencies in routes.
"""

from __future__ import annotations

from dataclasses import dataclass

from agentgate.action_mapping.config_loader import MappingConfig
from agentgate.mock_aws.base import MockServiceRegistry
from agentgate.permission_engine.models import IdentityPolicies
from agentgate.permission_engine.policy_fetcher import PolicyFetcherProtocol
from agentgate.proxy.audit import AuditLogger
from agentgate.proxy.auth import ApiKeyAuthenticator


class FakePolicyFetcher:
    """Returns pre-configured policies for demo/testing.

    Maps user ARNs to their IdentityPolicies. If a user isn't in the
    mapping, returns empty policies (which means implicit deny for everything).
    """

    def __init__(self, policies: dict[str, IdentityPolicies] | None = None) -> None:
        self._policies = policies or {}

    def get_identity_policies(self, identity_arn: str) -> IdentityPolicies:
        return self._policies.get(identity_arn, IdentityPolicies())


@dataclass
class AppDependencies:
    """Container for all shared objects the app needs."""

    authenticator: ApiKeyAuthenticator
    config: MappingConfig
    registry: MockServiceRegistry
    fetcher: PolicyFetcherProtocol
    audit: AuditLogger


# Global instance — set by create_dependencies(), accessed by route handlers
_deps: AppDependencies | None = None


def init_dependencies(deps: AppDependencies) -> None:
    """Initialize the global dependencies. Called once at app startup."""
    global _deps
    _deps = deps


def get_deps() -> AppDependencies:
    """Get the global dependencies. Used as a FastAPI dependency."""
    if _deps is None:
        raise RuntimeError("Dependencies not initialized — call init_dependencies() first")
    return _deps
