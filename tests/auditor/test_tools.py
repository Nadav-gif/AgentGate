"""Tests for auditor tools — verify they correctly query audit data and policies."""

import json

from tests.auditor.conftest import AGENT_ROLE_ARN, ALICE_ARN, BOB_ARN

from agentgate.auditor.tools import (
    GetAccessSummaryTool,
    GetAgentRolePoliciesTool,
    GetDeniedRequestsTool,
    QueryAuditLogTool,
)


class TestQueryAuditLogTool:
    """Tests for QueryAuditLogTool — the general-purpose audit log query."""

    def test_returns_all_entries(self, audit_logger):
        tool = QueryAuditLogTool(audit=audit_logger)
        result = json.loads(tool._run())
        # Seeded data: 5 S3 reads + 3 alice dynamo + 2 bob dynamo + 3 bob denied + 1 email = 14
        assert len(result) == 14

    def test_filter_by_user(self, audit_logger):
        tool = QueryAuditLogTool(audit=audit_logger)
        result = json.loads(tool._run(user_arn=ALICE_ARN))
        assert all(entry["user_arn"] == ALICE_ARN for entry in result)
        # Alice: 5 S3 reads + 3 dynamo + 1 email = 9
        assert len(result) == 9

    def test_filter_by_decision(self, audit_logger):
        tool = QueryAuditLogTool(audit=audit_logger)
        result = json.loads(tool._run(decision="DENY"))
        assert all(entry["decision"] == "DENY" for entry in result)
        # Bob's 3 denied S3 reads
        assert len(result) == 3

    def test_filter_by_user_and_decision(self, audit_logger):
        tool = QueryAuditLogTool(audit=audit_logger)
        result = json.loads(tool._run(user_arn=BOB_ARN, decision="ALLOW"))
        assert all(entry["user_arn"] == BOB_ARN for entry in result)
        assert all(entry["decision"] == "ALLOW" for entry in result)
        # Bob's 2 allowed dynamo queries
        assert len(result) == 2

    def test_limit(self, audit_logger):
        tool = QueryAuditLogTool(audit=audit_logger)
        result = json.loads(tool._run(limit=3))
        assert len(result) == 3

    def test_entry_has_expected_fields(self, audit_logger):
        tool = QueryAuditLogTool(audit=audit_logger)
        result = json.loads(tool._run(limit=1))
        entry = result[0]
        assert "timestamp" in entry
        assert "user_arn" in entry
        assert "agent_id" in entry
        assert "tool_name" in entry
        assert "aws_action" in entry
        assert "resource" in entry
        assert "decision" in entry
        assert "reason" in entry


class TestGetDeniedRequestsTool:
    """Tests for GetDeniedRequestsTool — convenience filter for denied entries."""

    def test_returns_only_denied(self, audit_logger):
        tool = GetDeniedRequestsTool(audit=audit_logger)
        result = json.loads(tool._run())
        assert len(result) == 3
        assert all(entry["decision"] in ("DENY", "IMPLICIT_DENY") for entry in result)

    def test_denied_entries_are_bob(self, audit_logger):
        tool = GetDeniedRequestsTool(audit=audit_logger)
        result = json.loads(tool._run())
        assert all(entry["user_arn"] == BOB_ARN for entry in result)

    def test_limit(self, audit_logger):
        tool = GetDeniedRequestsTool(audit=audit_logger)
        result = json.loads(tool._run(limit=1))
        # limit applies to get_recent before filtering, but we have 14 entries
        # so limit=1 gets only 1 recent entry which may or may not be denied
        assert len(result) <= 1

    def test_empty_when_no_denials(self, tmp_path):
        """Empty audit log → no denied entries."""
        from agentgate.proxy.audit import AuditLogger

        audit = AuditLogger(db_path=str(tmp_path / "empty.db"))
        audit.log_decision("arn:user", "agent", "tool", "s3:Get", "*", "ALLOW", "ok")
        tool = GetDeniedRequestsTool(audit=audit)
        result = json.loads(tool._run())
        assert result == []


class TestGetAgentRolePoliciesTool:
    """Tests for GetAgentRolePoliciesTool — fetches the agent role's IAM policies."""

    def test_returns_role_policies(self, policy_fetcher):
        tool = GetAgentRolePoliciesTool(fetcher=policy_fetcher)
        result = json.loads(tool._run(role_arn=AGENT_ROLE_ARN))
        assert result["role_arn"] == AGENT_ROLE_ARN
        assert len(result["inline_policies"]) == 1

    def test_policy_contains_expected_actions(self, policy_fetcher):
        tool = GetAgentRolePoliciesTool(fetcher=policy_fetcher)
        result = json.loads(tool._run(role_arn=AGENT_ROLE_ARN))
        policy = result["inline_policies"][0]
        # Flatten all actions from all statements
        all_actions = []
        for stmt in policy["Statement"]:
            actions = stmt["Action"]
            if isinstance(actions, str):
                actions = [actions]
            all_actions.extend(actions)
        assert "s3:GetObject" in all_actions
        assert "s3:DeleteObject" in all_actions
        assert "lambda:InvokeFunction" in all_actions

    def test_unknown_role_returns_empty(self, policy_fetcher):
        tool = GetAgentRolePoliciesTool(fetcher=policy_fetcher)
        result = json.loads(tool._run(role_arn="arn:aws:iam::999999999999:role/unknown"))
        assert result["inline_policies"] == []
        assert result["managed_policies"] == []

    def test_includes_boundary_field(self, policy_fetcher):
        tool = GetAgentRolePoliciesTool(fetcher=policy_fetcher)
        result = json.loads(tool._run(role_arn=AGENT_ROLE_ARN))
        assert "permission_boundary" in result


class TestGetAccessSummaryTool:
    """Tests for GetAccessSummaryTool — aggregated usage statistics."""

    def test_summary_groups_by_agent_and_action(self, audit_logger):
        tool = GetAccessSummaryTool(audit=audit_logger)
        result = json.loads(tool._run())
        # Should have groups for: agent-alice/s3:GetObject, agent-alice/dynamodb:Query,
        # agent-bob/dynamodb:Query, agent-bob/s3:GetObject, agent-alice/ses:SendEmail
        assert len(result) == 5

    def test_summary_counts_correct(self, audit_logger):
        tool = GetAccessSummaryTool(audit=audit_logger)
        result = json.loads(tool._run())
        # Find alice's S3 reads
        alice_s3 = [r for r in result if r["agent_id"] == "agent-alice" and r["aws_action"] == "s3:GetObject"]
        assert len(alice_s3) == 1
        assert alice_s3[0]["total"] == 5
        assert alice_s3[0]["allowed"] == 5
        assert alice_s3[0]["denied"] == 0

    def test_summary_tracks_denied(self, audit_logger):
        tool = GetAccessSummaryTool(audit=audit_logger)
        result = json.loads(tool._run())
        # Find bob's denied S3 reads
        bob_s3 = [r for r in result if r["agent_id"] == "agent-bob" and r["aws_action"] == "s3:GetObject"]
        assert len(bob_s3) == 1
        assert bob_s3[0]["denied"] == 3
        assert bob_s3[0]["allowed"] == 0

    def test_summary_tracks_resources(self, audit_logger):
        tool = GetAccessSummaryTool(audit=audit_logger)
        result = json.loads(tool._run())
        # Alice read 5 different S3 files
        alice_s3 = [r for r in result if r["agent_id"] == "agent-alice" and r["aws_action"] == "s3:GetObject"]
        assert len(alice_s3[0]["resources"]) == 5

    def test_summary_with_limit(self, audit_logger):
        tool = GetAccessSummaryTool(audit=audit_logger)
        # With limit=3 we only get the 3 most recent entries
        result = json.loads(tool._run(limit=3))
        total = sum(r["total"] for r in result)
        assert total == 3
