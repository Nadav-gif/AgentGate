"""Tests for audit logging — verify decisions are recorded in SQLite."""


class TestAuditLogging:
    def test_allowed_action_logged(self, test_app):
        client, deps = test_app
        client.post(
            "/execute-tool",
            json={"tool_name": "query_database", "tool_args": {"table": "employees"}},
            headers={"X-API-Key": "alice-key"},
        )
        entries = deps.audit.get_recent(limit=10)
        assert len(entries) >= 1
        latest = entries[0]
        assert latest["user_arn"] == "arn:aws:iam::123456789012:user/alice"
        assert latest["agent_id"] == "agent-alice"
        assert latest["tool_name"] == "query_database"
        assert latest["aws_action"] == "dynamodb:Query"
        assert latest["decision"] == "ALLOW"

    def test_denied_action_logged(self, test_app):
        client, deps = test_app
        client.post(
            "/execute-tool",
            json={"tool_name": "read_file", "tool_args": {"bucket": "b", "key": "k"}},
            headers={"X-API-Key": "bob-key"},
        )
        entries = deps.audit.get_recent(limit=10)
        assert len(entries) >= 1
        latest = entries[0]
        assert latest["user_arn"] == "arn:aws:iam::123456789012:user/bob"
        assert latest["decision"] == "DENY"

    def test_multiple_actions_logged(self, test_app):
        """Multiple tool calls → multiple audit entries."""
        client, deps = test_app
        client.post(
            "/execute-tool",
            json={"tool_name": "query_database", "tool_args": {"table": "employees"}},
            headers={"X-API-Key": "alice-key"},
        )
        client.post(
            "/execute-tool",
            json={"tool_name": "read_file", "tool_args": {"bucket": "reports", "key": "q4.csv"}},
            headers={"X-API-Key": "alice-key"},
        )
        entries = deps.audit.get_recent(limit=10)
        assert len(entries) >= 2

    def test_query_by_user(self, test_app):
        client, deps = test_app
        # Alice makes a request
        client.post(
            "/execute-tool",
            json={"tool_name": "query_database", "tool_args": {"table": "employees"}},
            headers={"X-API-Key": "alice-key"},
        )
        # Bob makes a request
        client.post(
            "/execute-tool",
            json={"tool_name": "query_database", "tool_args": {"table": "employees"}},
            headers={"X-API-Key": "bob-key"},
        )
        alice_entries = deps.audit.get_by_user("arn:aws:iam::123456789012:user/alice")
        bob_entries = deps.audit.get_by_user("arn:aws:iam::123456789012:user/bob")
        assert len(alice_entries) >= 1
        assert len(bob_entries) >= 1
        assert all(e["user_arn"].endswith("alice") for e in alice_entries)
        assert all(e["user_arn"].endswith("bob") for e in bob_entries)
