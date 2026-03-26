"""Shared test fixtures for proxy tests.

Creates a fully configured test app with:
- Two API keys (alice = allowed S3+DynamoDB, bob = only DynamoDB)
- Action mapping config with S3 and DynamoDB tools
- Mock S3 and DynamoDB with pre-seeded data
- FakePolicyFetcher with pre-configured IAM policies
"""

import pytest
from fastapi.testclient import TestClient

from agentgate.action_mapping.config_loader import load_config_from_dict
from agentgate.mock_aws.base import MockServiceRegistry
from agentgate.mock_aws.dynamodb import MockDynamoDB
from agentgate.mock_aws.s3 import MockS3
from agentgate.mock_aws.ses import MockSES
from agentgate.permission_engine.models import IdentityPolicies
from agentgate.proxy.app import create_app
from agentgate.proxy.audit import AuditLogger
from agentgate.proxy.auth import ApiKeyAuthenticator
from agentgate.proxy.dependencies import AppDependencies, FakePolicyFetcher

ALICE_ARN = "arn:aws:iam::123456789012:user/alice"
BOB_ARN = "arn:aws:iam::123456789012:user/bob"


def _allow_policy(action, resource="*"):
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": action, "Resource": resource}],
    }


def _deny_policy(action, resource="*"):
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": action, "Resource": resource}],
    }


@pytest.fixture
def test_app(tmp_path):
    """Create a fully configured test app."""

    # API keys
    authenticator = ApiKeyAuthenticator({
        "alice-key": {"user_arn": ALICE_ARN, "agent_id": "agent-alice"},
        "bob-key": {"user_arn": BOB_ARN, "agent_id": "agent-bob"},
    })

    # Action mapping config
    config = load_config_from_dict({
        "version": "1",
        "account_id": "123456789012",
        "region": "us-east-1",
        "tools": {
            "read_file": {
                "aws_actions": [{"action": "s3:GetObject", "resource": "arn:aws:s3:::{bucket}/{key}"}],
                "required_args": ["bucket", "key"],
            },
            "write_file": {
                "aws_actions": [{"action": "s3:PutObject", "resource": "arn:aws:s3:::{bucket}/{key}"}],
                "required_args": ["bucket", "key"],
            },
            "query_database": {
                "aws_actions": [
                    {"action": "dynamodb:Query", "resource": "arn:aws:dynamodb:{region}:{account_id}:table/{table}"}
                ],
                "required_args": ["table"],
            },
            "send_email": {
                "aws_actions": [{"action": "ses:SendEmail", "resource": "*"}],
            },
        },
    })

    # Mock services with seeded data
    registry = MockServiceRegistry()

    mock_s3 = MockS3()
    mock_s3.seed("reports", "q4.csv", "revenue,cost\n1000,500")
    mock_s3.register(registry)

    mock_dynamo = MockDynamoDB()
    mock_dynamo.seed("employees", [
        {"dept": {"S": "engineering"}, "name": {"S": "Alice"}, "salary": {"N": "120000"}},
        {"dept": {"S": "sales"}, "name": {"S": "Bob"}, "salary": {"N": "95000"}},
    ])
    mock_dynamo.register(registry)

    mock_ses = MockSES()
    mock_ses.register(registry)

    # Policy fetcher — alice gets S3+DynamoDB, bob gets only DynamoDB
    fetcher = FakePolicyFetcher({
        ALICE_ARN: IdentityPolicies(inline_policies=[
            _allow_policy(["s3:GetObject", "s3:PutObject"]),
            _allow_policy("dynamodb:Query"),
        ]),
        BOB_ARN: IdentityPolicies(inline_policies=[
            _allow_policy("dynamodb:Query"),
            _deny_policy("s3:*"),
        ]),
    })

    # Audit logger — use temp directory so tests don't pollute
    audit = AuditLogger(db_path=str(tmp_path / "test_audit.db"))

    deps = AppDependencies(
        authenticator=authenticator,
        config=config,
        registry=registry,
        fetcher=fetcher,
        audit=audit,
    )

    app = create_app(deps)
    return TestClient(app), deps
