"""Production server entry point.

Reads configuration from environment variables and starts the FastAPI proxy.
Supports two modes:

  AGENTGATE_MODE=mock  — FakePolicyFetcher with hardcoded policies (default)
  AGENTGATE_MODE=real  — AwsPolicyFetcher with real AWS IAM via boto3

Usage:
  uvicorn agentgate.proxy.server:app --host 0.0.0.0 --port 8000

Required env vars for real mode:
  AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION
  AGENTGATE_API_KEYS  — JSON mapping of API keys to user info
  AGENTGATE_AGENT_ROLE_ARN — ARN of the agent role (for auditor)

Optional:
  AGENTGATE_MODE — "mock" (default) or "real"
"""

from __future__ import annotations

import json
import logging
import os
import tempfile

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
from agentgate.proxy.escalation import DEFAULT_ESCALATION_RULES

logger = logging.getLogger(__name__)


def _tool_mapping_config() -> dict:
    """Standard tool-to-AWS-action mapping."""
    return {
        "version": "1",
        "account_id": os.getenv("AWS_ACCOUNT_ID", "123456789012"),
        "region": os.getenv("AWS_DEFAULT_REGION", "us-east-1"),
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
    }


def _mock_services() -> MockServiceRegistry:
    """Set up mock AWS services with seeded demo data."""
    registry = MockServiceRegistry()

    mock_s3 = MockS3()
    mock_s3.seed("reports", "q4.csv", "revenue,cost\n1000,500\n2000,800")
    mock_s3.register(registry)

    mock_dynamo = MockDynamoDB()
    mock_dynamo.seed("employees", [
        {"dept": {"S": "engineering"}, "name": {"S": "Alice"}, "salary": {"N": "120000"}},
        {"dept": {"S": "sales"}, "name": {"S": "Bob"}, "salary": {"N": "95000"}},
    ])
    mock_dynamo.register(registry)

    mock_ses = MockSES()
    mock_ses.register(registry)

    return registry


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


def _create_mock_deps() -> AppDependencies:
    """Create dependencies with hardcoded policies for demo/testing."""
    account_id = os.getenv("AWS_ACCOUNT_ID", "123456789012")
    alice_arn = f"arn:aws:iam::{account_id}:user/agentgate-alice"
    bob_arn = f"arn:aws:iam::{account_id}:user/agentgate-bob"
    role_arn = f"arn:aws:iam::{account_id}:role/agentgate-agent-role"

    api_keys_json = os.getenv("AGENTGATE_API_KEYS")
    if api_keys_json:
        api_keys = json.loads(api_keys_json)
    else:
        api_keys = {
            "alice-key": {"user_arn": alice_arn, "agent_id": "agent-alice"},
            "bob-key": {"user_arn": bob_arn, "agent_id": "agent-bob"},
        }

    agent_role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"], "Resource": "*"},
            {"Effect": "Allow", "Action": ["dynamodb:Query", "dynamodb:Scan"], "Resource": "*"},
            {"Effect": "Allow", "Action": "ses:SendEmail", "Resource": "*"},
            {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": "*"},
        ],
    }

    fetcher = FakePolicyFetcher({
        alice_arn: IdentityPolicies(inline_policies=[
            _allow_policy(["s3:GetObject", "s3:PutObject"]),
            _allow_policy("dynamodb:Query"),
            _allow_policy("ses:SendEmail"),
        ]),
        bob_arn: IdentityPolicies(inline_policies=[
            _allow_policy("dynamodb:Query"),
            _deny_policy("s3:*"),
        ]),
        role_arn: IdentityPolicies(inline_policies=[agent_role_policy]),
    })

    db_path = os.getenv("AGENTGATE_AUDIT_DB", os.path.join(tempfile.gettempdir(), "agentgate_audit.db"))

    return AppDependencies(
        authenticator=ApiKeyAuthenticator(api_keys),
        config=load_config_from_dict(_tool_mapping_config()),
        registry=_mock_services(),
        fetcher=fetcher,
        audit=AuditLogger(db_path=db_path),
        escalation_rules=list(DEFAULT_ESCALATION_RULES),
    )


def _create_real_deps() -> AppDependencies:
    """Create dependencies with real AWS IAM policy fetching.

    Requires AWS credentials in environment variables.
    Mock services are still used for execution.
    """
    import boto3

    from agentgate.permission_engine.policy_fetcher import AwsPolicyFetcher

    api_keys_json = os.getenv("AGENTGATE_API_KEYS")
    if not api_keys_json:
        raise RuntimeError("AGENTGATE_API_KEYS env var is required in real mode")
    api_keys = json.loads(api_keys_json)

    session = boto3.Session()
    fetcher = AwsPolicyFetcher(session=session)

    db_path = os.getenv("AGENTGATE_AUDIT_DB", os.path.join(tempfile.gettempdir(), "agentgate_audit.db"))

    return AppDependencies(
        authenticator=ApiKeyAuthenticator(api_keys),
        config=load_config_from_dict(_tool_mapping_config()),
        registry=_mock_services(),
        fetcher=fetcher,
        audit=AuditLogger(db_path=db_path),
        escalation_rules=list(DEFAULT_ESCALATION_RULES),
    )


def create_production_app():
    """Create the FastAPI app based on AGENTGATE_MODE env var."""
    mode = os.getenv("AGENTGATE_MODE", "mock")
    logger.info("Starting AgentGate proxy in %s mode", mode)

    if mode == "real":
        deps = _create_real_deps()
    else:
        deps = _create_mock_deps()

    return create_app(deps)


# Module-level app instance for uvicorn
app = create_production_app()
