"""Mock SES service — email sending simulation."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from agentgate.mock_aws.base import MockResponse, MockServiceRegistry

logger = logging.getLogger(__name__)


class MockSES:
    """Mock SES that validates email parameters and returns a fake MessageId.

    Keeps a log of sent emails for test verification.
    """

    def __init__(self) -> None:
        self._sent_emails: list[dict[str, Any]] = []

    def register(self, registry: MockServiceRegistry) -> None:
        """Register all SES handlers with the service registry."""
        registry.register("ses:SendEmail", self.send_email)

    def send_email(self, resource: str, params: dict[str, Any]) -> MockResponse:
        """Simulate sending an email via SES.

        Params:
            Source: sender email address
            Destination: dict with ToAddresses list
            Message: dict with Subject and Body
        """
        source = params.get("Source", "")
        if not source:
            return MockResponse(success=False, error="Missing required parameter: Source")

        destination = params.get("Destination")
        if not destination or not isinstance(destination, dict):
            return MockResponse(success=False, error="Missing required parameter: Destination")

        to_addresses = destination.get("ToAddresses", [])
        if not to_addresses:
            return MockResponse(success=False, error="Destination must include at least one ToAddresses")

        message = params.get("Message")
        if not message or not isinstance(message, dict):
            return MockResponse(success=False, error="Missing required parameter: Message")

        message_id = str(uuid.uuid4())

        self._sent_emails.append({
            "MessageId": message_id,
            "Source": source,
            "Destination": destination,
            "Message": message,
        })

        logger.info("Mock SES sent email from %s to %s", source, to_addresses)

        return MockResponse(
            success=True,
            response={
                "MessageId": message_id,
            },
        )

    @property
    def sent_emails(self) -> list[dict[str, Any]]:
        """Access the log of sent emails (for test assertions)."""
        return list(self._sent_emails)
