"""Base pattern for mock AWS services — registry and dispatch."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Handler signature: (resource: str, params: dict) -> MockResponse
HandlerFunc = Callable[[str, dict[str, Any]], "MockResponse"]


@dataclass
class MockResponse:
    """Standard response from a mock AWS service."""

    success: bool
    response: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class MockServiceRegistry:
    """Routes AWS actions to the appropriate mock handler.

    Usage:
        registry = MockServiceRegistry()
        registry.register("s3:GetObject", my_handler_func)
        result = registry.handle("s3:GetObject", "arn:aws:s3:::bucket/key", {"Bucket": "b", "Key": "k"})
    """

    def __init__(self) -> None:
        self._handlers: dict[str, HandlerFunc] = {}

    def register(self, action: str, handler: HandlerFunc) -> None:
        """Register a handler for an AWS action."""
        self._handlers[action] = handler
        logger.debug("Registered mock handler for %s", action)

    def handle(self, action: str, resource: str, params: dict[str, Any]) -> MockResponse:
        """Dispatch an AWS action to the registered mock handler.

        Returns an error MockResponse if no handler is registered.
        """
        handler = self._handlers.get(action)
        if handler is None:
            return MockResponse(success=False, error=f"No mock handler registered for action: {action}")

        logger.info("Mock handling %s on %s", action, resource)
        return handler(resource, params)

    @property
    def registered_actions(self) -> list[str]:
        """List all actions that have registered handlers."""
        return list(self._handlers.keys())
