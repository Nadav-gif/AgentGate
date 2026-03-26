"""API key authentication — maps keys to IAM identities."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import HTTPException

from agentgate.proxy.models import UserContext

logger = logging.getLogger(__name__)


class ApiKeyAuthenticator:
    """Validates API keys and resolves them to user identities.

    The key-to-identity mapping is loaded from a dict (in production,
    this could come from a database or secrets manager).
    """

    def __init__(self, api_keys: dict[str, dict[str, Any]]) -> None:
        """Initialize with a mapping of API key -> user info.

        Expected format:
            {
                "abc123": {"user_arn": "arn:aws:iam::123456789012:user/alice", "agent_id": "agent-1"},
            }
        """
        self._api_keys = api_keys

    def authenticate(self, api_key: str) -> UserContext:
        """Look up an API key and return the associated user context.

        Raises:
            HTTPException(401): if the key is missing or invalid.
        """
        if not api_key:
            logger.warning("Request with missing API key")
            raise HTTPException(status_code=401, detail="Missing API key")

        user_info = self._api_keys.get(api_key)
        if user_info is None:
            logger.warning("Request with invalid API key")
            raise HTTPException(status_code=401, detail="Invalid API key")

        context = UserContext(
            user_arn=user_info["user_arn"],
            agent_id=user_info.get("agent_id", "unknown"),
        )
        logger.info("Authenticated %s (agent: %s)", context.user_arn, context.agent_id)
        return context
