"""Tests for the mock S3 service."""

from agentgate.mock_aws.base import MockServiceRegistry
from agentgate.mock_aws.s3 import MockS3


class TestMockS3PutAndGet:
    def test_put_then_get(self):
        s3 = MockS3()
        put_resp = s3.put_object("", {"Bucket": "my-bucket", "Key": "file.txt", "Body": "hello world"})
        assert put_resp.success is True
        assert "ETag" in put_resp.response

        get_resp = s3.get_object("", {"Bucket": "my-bucket", "Key": "file.txt"})
        assert get_resp.success is True
        assert get_resp.response["Body"] == "hello world"
        assert get_resp.response["ContentLength"] == 11
        assert get_resp.response["ContentType"] == "application/octet-stream"
        assert "ETag" in get_resp.response
        assert "LastModified" in get_resp.response

    def test_put_with_content_type(self):
        s3 = MockS3()
        s3.put_object("", {"Bucket": "b", "Key": "k", "Body": "{}", "ContentType": "application/json"})
        resp = s3.get_object("", {"Bucket": "b", "Key": "k"})
        assert resp.response["ContentType"] == "application/json"

    def test_put_overwrites(self):
        s3 = MockS3()
        s3.put_object("", {"Bucket": "b", "Key": "k", "Body": "old"})
        s3.put_object("", {"Bucket": "b", "Key": "k", "Body": "new"})
        resp = s3.get_object("", {"Bucket": "b", "Key": "k"})
        assert resp.response["Body"] == "new"


class TestMockS3GetErrors:
    def test_get_nonexistent_key(self):
        s3 = MockS3()
        resp = s3.get_object("", {"Bucket": "b", "Key": "missing"})
        assert resp.success is False
        assert "NoSuchKey" in resp.error

    def test_get_missing_params(self):
        s3 = MockS3()
        resp = s3.get_object("", {})
        assert resp.success is False
        assert "Missing" in resp.error


class TestMockS3Delete:
    def test_delete_existing(self):
        s3 = MockS3()
        s3.put_object("", {"Bucket": "b", "Key": "k", "Body": "data"})
        resp = s3.delete_object("", {"Bucket": "b", "Key": "k"})
        assert resp.success is True

        # Verify it's gone
        get_resp = s3.get_object("", {"Bucket": "b", "Key": "k"})
        assert get_resp.success is False

    def test_delete_nonexistent_succeeds(self):
        s3 = MockS3()
        resp = s3.delete_object("", {"Bucket": "b", "Key": "nope"})
        assert resp.success is True

    def test_delete_missing_params(self):
        s3 = MockS3()
        resp = s3.delete_object("", {})
        assert resp.success is False


class TestMockS3Seed:
    def test_seed_and_read(self):
        s3 = MockS3()
        s3.seed("reports", "q4.csv", "col1,col2\n1,2", content_type="text/csv")
        resp = s3.get_object("", {"Bucket": "reports", "Key": "q4.csv"})
        assert resp.success is True
        assert resp.response["Body"] == "col1,col2\n1,2"
        assert resp.response["ContentType"] == "text/csv"


class TestMockS3Registry:
    def test_registers_with_registry(self):
        registry = MockServiceRegistry()
        s3 = MockS3()
        s3.register(registry)
        assert "s3:GetObject" in registry.registered_actions
        assert "s3:PutObject" in registry.registered_actions
        assert "s3:DeleteObject" in registry.registered_actions

    def test_dispatch_through_registry(self):
        registry = MockServiceRegistry()
        s3 = MockS3()
        s3.register(registry)
        s3.seed("b", "k", "data")

        resp = registry.handle("s3:GetObject", "arn:aws:s3:::b/k", {"Bucket": "b", "Key": "k"})
        assert resp.success is True
        assert resp.response["Body"] == "data"
