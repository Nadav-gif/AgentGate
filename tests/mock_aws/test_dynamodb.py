"""Tests for the mock DynamoDB service."""

from agentgate.mock_aws.base import MockServiceRegistry
from agentgate.mock_aws.dynamodb import MockDynamoDB


class TestMockDynamoDBPutItem:
    def test_put_item(self):
        db = MockDynamoDB()
        db.create_table("users")
        resp = db.put_item("", {
            "TableName": "users",
            "Item": {"id": {"S": "1"}, "name": {"S": "Alice"}},
        })
        assert resp.success is True

    def test_put_to_nonexistent_table(self):
        db = MockDynamoDB()
        resp = db.put_item("", {
            "TableName": "nope",
            "Item": {"id": {"S": "1"}},
        })
        assert resp.success is False
        assert "ResourceNotFoundException" in resp.error

    def test_put_missing_item(self):
        db = MockDynamoDB()
        db.create_table("users")
        resp = db.put_item("", {"TableName": "users"})
        assert resp.success is False
        assert "Missing" in resp.error

    def test_put_missing_table_name(self):
        db = MockDynamoDB()
        resp = db.put_item("", {"Item": {"id": {"S": "1"}}})
        assert resp.success is False


class TestMockDynamoDBQuery:
    def test_query_all(self):
        db = MockDynamoDB()
        db.seed("employees", [
            {"dept": {"S": "engineering"}, "name": {"S": "Alice"}},
            {"dept": {"S": "sales"}, "name": {"S": "Bob"}},
        ])
        resp = db.query("", {"TableName": "employees"})
        assert resp.success is True
        assert resp.response["Count"] == 2
        assert len(resp.response["Items"]) == 2

    def test_query_with_filter(self):
        db = MockDynamoDB()
        db.seed("employees", [
            {"dept": {"S": "engineering"}, "name": {"S": "Alice"}},
            {"dept": {"S": "sales"}, "name": {"S": "Bob"}},
            {"dept": {"S": "engineering"}, "name": {"S": "Charlie"}},
        ])
        resp = db.query("", {
            "TableName": "employees",
            "KeyConditionExpression": "dept = :d",
            "ExpressionAttributeValues": {":d": {"S": "engineering"}},
        })
        assert resp.success is True
        assert resp.response["Count"] == 2
        assert resp.response["ScannedCount"] == 3

    def test_query_nonexistent_table(self):
        db = MockDynamoDB()
        resp = db.query("", {"TableName": "nope"})
        assert resp.success is False
        assert "ResourceNotFoundException" in resp.error

    def test_query_missing_table_name(self):
        db = MockDynamoDB()
        resp = db.query("", {})
        assert resp.success is False

    def test_query_no_matches(self):
        db = MockDynamoDB()
        db.seed("employees", [
            {"dept": {"S": "sales"}, "name": {"S": "Bob"}},
        ])
        resp = db.query("", {
            "TableName": "employees",
            "ExpressionAttributeValues": {":d": {"S": "engineering"}},
        })
        assert resp.success is True
        assert resp.response["Count"] == 0


class TestMockDynamoDBSeed:
    def test_seed_creates_table(self):
        db = MockDynamoDB()
        db.seed("new-table", [{"id": {"S": "1"}}])
        resp = db.query("", {"TableName": "new-table"})
        assert resp.success is True
        assert resp.response["Count"] == 1

    def test_seed_appends(self):
        db = MockDynamoDB()
        db.seed("t", [{"id": {"S": "1"}}])
        db.seed("t", [{"id": {"S": "2"}}])
        resp = db.query("", {"TableName": "t"})
        assert resp.response["Count"] == 2


class TestMockDynamoDBRegistry:
    def test_registers_with_registry(self):
        registry = MockServiceRegistry()
        db = MockDynamoDB()
        db.register(registry)
        assert "dynamodb:Query" in registry.registered_actions
        assert "dynamodb:PutItem" in registry.registered_actions
