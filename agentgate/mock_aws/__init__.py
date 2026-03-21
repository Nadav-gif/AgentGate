"""Mock AWS services for development and demo — not used in production."""

from agentgate.mock_aws.base import MockResponse, MockServiceRegistry
from agentgate.mock_aws.dynamodb import MockDynamoDB
from agentgate.mock_aws.s3 import MockS3
from agentgate.mock_aws.ses import MockSES


def create_default_registry() -> MockServiceRegistry:
    """Create a registry with all mock services registered."""
    registry = MockServiceRegistry()
    MockS3().register(registry)
    MockDynamoDB().register(registry)
    MockSES().register(registry)
    return registry


__all__ = [
    "MockDynamoDB",
    "MockResponse",
    "MockS3",
    "MockSES",
    "MockServiceRegistry",
    "create_default_registry",
]
