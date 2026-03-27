"""Shared test fixtures for auditor tests.

Creates:
- An AuditLogger with pre-seeded decision history
- A FakePolicyFetcher with an agent role that has more permissions than it uses
- This simulates the privilege creep scenario from the project paper
"""

import pytest

from agentgate.permission_engine.models import IdentityPolicies
from agentgate.proxy.audit import AuditLogger
from agentgate.proxy.dependencies import FakePolicyFetcher

# The agent role — has broad permissions (S3, DynamoDB, SES, Lambda)
AGENT_ROLE_ARN = "arn:aws:iam::123456789012:role/agent-service-role"

# Users who interact through the agent
ALICE_ARN = "arn:aws:iam::123456789012:user/alice"
BOB_ARN = "arn:aws:iam::123456789012:user/bob"


def _agent_role_policy():
    """The agent role's IAM policy — intentionally over-provisioned.

    The role can do S3 read/write/delete, DynamoDB query/scan, SES send,
    and Lambda invoke. But from the audit logs, only S3 read, DynamoDB query,
    and SES send are actually used. The rest is privilege creep.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:DeleteObject",
                ],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": [
                    "dynamodb:Query",
                    "dynamodb:Scan",
                ],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": "ses:SendEmail",
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": "lambda:InvokeFunction",
                "Resource": "*",
            },
        ],
    }


def _seed_audit_log(audit: AuditLogger) -> None:
    """Populate the audit log with realistic decision history.

    Simulates a scenario where:
    - alice reads S3 files frequently (allowed)
    - alice queries DynamoDB (allowed)
    - bob queries DynamoDB (allowed)
    - bob tries to read S3 but is denied (user lacks permission)
    - alice sends one email (allowed)
    - Nobody ever uses s3:PutObject, s3:DeleteObject, dynamodb:Scan, or lambda:InvokeFunction
      → these are unused agent permissions (privilege creep)
    """
    # Alice reads S3 — 5 times (the most common action)
    for i in range(5):
        audit.log_decision(
            user_arn=ALICE_ARN,
            agent_id="agent-alice",
            tool_name="read_file",
            aws_action="s3:GetObject",
            resource=f"arn:aws:s3:::reports/file{i}.csv",
            decision="ALLOW",
            reason="Allowed by inline policy",
        )

    # Alice queries DynamoDB — 3 times
    for _ in range(3):
        audit.log_decision(
            user_arn=ALICE_ARN,
            agent_id="agent-alice",
            tool_name="query_database",
            aws_action="dynamodb:Query",
            resource="arn:aws:dynamodb:us-east-1:123456789012:table/employees",
            decision="ALLOW",
            reason="Allowed by inline policy",
        )

    # Bob queries DynamoDB — 2 times
    for _ in range(2):
        audit.log_decision(
            user_arn=BOB_ARN,
            agent_id="agent-bob",
            tool_name="query_database",
            aws_action="dynamodb:Query",
            resource="arn:aws:dynamodb:us-east-1:123456789012:table/employees",
            decision="ALLOW",
            reason="Allowed by inline policy",
        )

    # Bob tries to read S3 — denied 3 times (user policy blocks it)
    for _ in range(3):
        audit.log_decision(
            user_arn=BOB_ARN,
            agent_id="agent-bob",
            tool_name="read_file",
            aws_action="s3:GetObject",
            resource="arn:aws:s3:::reports/q4.csv",
            decision="DENY",
            reason="Explicitly denied by inline policy",
        )

    # Alice sends one email
    audit.log_decision(
        user_arn=ALICE_ARN,
        agent_id="agent-alice",
        tool_name="send_email",
        aws_action="ses:SendEmail",
        resource="*",
        decision="ALLOW",
        reason="Allowed by inline policy",
    )


@pytest.fixture
def audit_logger(tmp_path):
    """Create an AuditLogger pre-seeded with test data."""
    audit = AuditLogger(db_path=str(tmp_path / "test_audit.db"))
    _seed_audit_log(audit)
    return audit


@pytest.fixture
def policy_fetcher():
    """Create a FakePolicyFetcher with the agent role's over-provisioned policy."""
    return FakePolicyFetcher({
        AGENT_ROLE_ARN: IdentityPolicies(inline_policies=[_agent_role_policy()]),
    })
