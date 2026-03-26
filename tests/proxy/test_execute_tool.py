"""Tests for the /execute-tool endpoint — the full pipeline."""


class TestAllowedActions:
    def test_alice_reads_s3(self, test_app):
        """Alice has S3 read permission → should succeed and return file contents."""
        client, _ = test_app
        resp = client.post(
            "/execute-tool",
            json={"tool_name": "read_file", "tool_args": {"bucket": "reports", "key": "q4.csv"}},
            headers={"X-API-Key": "alice-key"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "allowed"
        assert body["tool_name"] == "read_file"
        assert len(body["results"]) == 1
        assert body["results"][0]["action"] == "s3:GetObject"
        assert body["results"][0]["response"]["Body"] == "revenue,cost\n1000,500"

    def test_alice_queries_dynamodb(self, test_app):
        """Alice has DynamoDB query permission → should succeed."""
        client, _ = test_app
        resp = client.post(
            "/execute-tool",
            json={"tool_name": "query_database", "tool_args": {"table": "employees"}},
            headers={"X-API-Key": "alice-key"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "allowed"
        assert body["results"][0]["response"]["Count"] == 2

    def test_bob_queries_dynamodb(self, test_app):
        """Bob has DynamoDB query permission → should succeed."""
        client, _ = test_app
        resp = client.post(
            "/execute-tool",
            json={"tool_name": "query_database", "tool_args": {"table": "employees"}},
            headers={"X-API-Key": "bob-key"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "allowed"


class TestDeniedActions:
    def test_bob_denied_s3_read(self, test_app):
        """Bob has explicit S3 deny → should get 403."""
        client, _ = test_app
        resp = client.post(
            "/execute-tool",
            json={"tool_name": "read_file", "tool_args": {"bucket": "reports", "key": "q4.csv"}},
            headers={"X-API-Key": "bob-key"},
        )
        assert resp.status_code == 403
        body = resp.json()["detail"]
        assert body["status"] == "denied"
        assert body["denied_action"] == "s3:GetObject"
        assert "deny" in body["reason"].lower() or "Deny" in body["reason"]

    def test_bob_denied_s3_write(self, test_app):
        """Bob has explicit S3 deny → write should also be denied."""
        client, _ = test_app
        resp = client.post(
            "/execute-tool",
            json={"tool_name": "write_file", "tool_args": {"bucket": "reports", "key": "new.csv"}},
            headers={"X-API-Key": "bob-key"},
        )
        assert resp.status_code == 403

    def test_alice_denied_unknown_tool(self, test_app):
        """Unknown tool → should get 400."""
        client, _ = test_app
        resp = client.post(
            "/execute-tool",
            json={"tool_name": "hack_mainframe", "tool_args": {}},
            headers={"X-API-Key": "alice-key"},
        )
        assert resp.status_code == 400

    def test_missing_required_args(self, test_app):
        """Missing required tool arguments → should get 400."""
        client, _ = test_app
        resp = client.post(
            "/execute-tool",
            json={"tool_name": "read_file", "tool_args": {"bucket": "reports"}},
            headers={"X-API-Key": "alice-key"},
        )
        assert resp.status_code == 400


class TestImplicitDeny:
    def test_alice_no_ses_permission(self, test_app):
        """Alice has no SES policy → implicit deny."""
        client, _ = test_app
        resp = client.post(
            "/execute-tool",
            json={"tool_name": "send_email", "tool_args": {}},
            headers={"X-API-Key": "alice-key"},
        )
        assert resp.status_code == 403
        body = resp.json()["detail"]
        assert body["decision"] == "IMPLICIT_DENY"
