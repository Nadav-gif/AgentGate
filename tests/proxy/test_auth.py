"""Tests for API key authentication."""


class TestAuthentication:
    def test_valid_key(self, test_app):
        client, _ = test_app
        resp = client.post(
            "/execute-tool",
            json={"tool_name": "query_database", "tool_args": {"table": "employees"}},
            headers={"X-API-Key": "alice-key"},
        )
        # Should not be 401
        assert resp.status_code != 401

    def test_missing_key(self, test_app):
        client, _ = test_app
        resp = client.post(
            "/execute-tool",
            json={"tool_name": "query_database", "tool_args": {"table": "employees"}},
        )
        assert resp.status_code == 422  # FastAPI validation error — header is required

    def test_invalid_key(self, test_app):
        client, _ = test_app
        resp = client.post(
            "/execute-tool",
            json={"tool_name": "query_database", "tool_args": {"table": "employees"}},
            headers={"X-API-Key": "wrong-key"},
        )
        assert resp.status_code == 401

    def test_empty_key(self, test_app):
        client, _ = test_app
        resp = client.post(
            "/execute-tool",
            json={"tool_name": "query_database", "tool_args": {"table": "employees"}},
            headers={"X-API-Key": ""},
        )
        assert resp.status_code == 401
