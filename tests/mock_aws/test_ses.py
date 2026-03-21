"""Tests for the mock SES service."""

from agentgate.mock_aws.base import MockServiceRegistry
from agentgate.mock_aws.ses import MockSES


class TestMockSESSendEmail:
    def test_send_email_success(self):
        ses = MockSES()
        resp = ses.send_email("", {
            "Source": "sender@example.com",
            "Destination": {"ToAddresses": ["recipient@example.com"]},
            "Message": {
                "Subject": {"Data": "Test Subject"},
                "Body": {"Text": {"Data": "Hello!"}},
            },
        })
        assert resp.success is True
        assert "MessageId" in resp.response
        assert len(resp.response["MessageId"]) > 0

    def test_email_logged(self):
        ses = MockSES()
        ses.send_email("", {
            "Source": "a@b.com",
            "Destination": {"ToAddresses": ["c@d.com"]},
            "Message": {"Subject": {"Data": "Hi"}},
        })
        assert len(ses.sent_emails) == 1
        assert ses.sent_emails[0]["Source"] == "a@b.com"

    def test_multiple_emails_logged(self):
        ses = MockSES()
        for i in range(3):
            ses.send_email("", {
                "Source": f"sender{i}@test.com",
                "Destination": {"ToAddresses": ["r@test.com"]},
                "Message": {"Subject": {"Data": f"Email {i}"}},
            })
        assert len(ses.sent_emails) == 3


class TestMockSESValidation:
    def test_missing_source(self):
        ses = MockSES()
        resp = ses.send_email("", {
            "Destination": {"ToAddresses": ["r@test.com"]},
            "Message": {"Subject": {"Data": "Hi"}},
        })
        assert resp.success is False
        assert "Source" in resp.error

    def test_missing_destination(self):
        ses = MockSES()
        resp = ses.send_email("", {
            "Source": "s@test.com",
            "Message": {"Subject": {"Data": "Hi"}},
        })
        assert resp.success is False
        assert "Destination" in resp.error

    def test_empty_to_addresses(self):
        ses = MockSES()
        resp = ses.send_email("", {
            "Source": "s@test.com",
            "Destination": {"ToAddresses": []},
            "Message": {"Subject": {"Data": "Hi"}},
        })
        assert resp.success is False
        assert "ToAddresses" in resp.error

    def test_missing_message(self):
        ses = MockSES()
        resp = ses.send_email("", {
            "Source": "s@test.com",
            "Destination": {"ToAddresses": ["r@test.com"]},
        })
        assert resp.success is False
        assert "Message" in resp.error


class TestMockSESRegistry:
    def test_registers_with_registry(self):
        registry = MockServiceRegistry()
        ses = MockSES()
        ses.register(registry)
        assert "ses:SendEmail" in registry.registered_actions

    def test_dispatch_through_registry(self):
        registry = MockServiceRegistry()
        ses = MockSES()
        ses.register(registry)

        resp = registry.handle("ses:SendEmail", "*", {
            "Source": "s@test.com",
            "Destination": {"ToAddresses": ["r@test.com"]},
            "Message": {"Subject": {"Data": "Hi"}},
        })
        assert resp.success is True
