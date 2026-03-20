"""Tests for permission engine data models."""

import pytest

from agentgate.permission_engine.models import (
    Decision,
    EvaluationResult,
    IdentityPolicies,
    PolicyEntry,
    PolicyLists,
)


class TestDecision:
    def test_enum_values(self):
        assert Decision.ALLOW.value == "ALLOW"
        assert Decision.DENY.value == "DENY"
        assert Decision.IMPLICIT_DENY.value == "IMPLICIT_DENY"

    def test_all_members(self):
        assert set(Decision) == {Decision.ALLOW, Decision.DENY, Decision.IMPLICIT_DENY}


class TestPolicyEntry:
    def test_construction(self):
        entry = PolicyEntry(action="s3:GetObject", resource="arn:aws:s3:::my-bucket/*")
        assert entry.action == "s3:GetObject"
        assert entry.resource == "arn:aws:s3:::my-bucket/*"

    def test_empty_action_rejected(self):
        with pytest.raises(ValueError, match="action must not be empty"):
            PolicyEntry(action="", resource="*")

    def test_empty_resource_rejected(self):
        with pytest.raises(ValueError, match="resource must not be empty"):
            PolicyEntry(action="s3:GetObject", resource="")

    def test_equality(self):
        a = PolicyEntry(action="s3:GetObject", resource="*")
        b = PolicyEntry(action="s3:GetObject", resource="*")
        assert a == b

class TestPolicyLists:
    def test_default_empty(self):
        pl = PolicyLists()
        assert pl.allows == []
        assert pl.denies == []

    def test_merge(self):
        a = PolicyLists(allows=[PolicyEntry("s3:GetObject", "*")])
        b = PolicyLists(
            allows=[PolicyEntry("s3:PutObject", "*")],
            denies=[PolicyEntry("s3:DeleteObject", "*")],
        )
        a.merge(b)
        assert len(a.allows) == 2
        assert len(a.denies) == 1


class TestIdentityPolicies:
    def test_default_empty(self):
        ip = IdentityPolicies()
        assert ip.inline_policies == []
        assert ip.managed_policies == []
        assert ip.permission_boundary is None
        assert ip.scps == []

    def test_with_data(self):
        doc = {"Version": "2012-10-17", "Statement": []}
        ip = IdentityPolicies(inline_policies=[doc], permission_boundary=doc)
        assert len(ip.inline_policies) == 1
        assert ip.permission_boundary is not None


class TestEvaluationResult:
    def test_construction(self):
        result = EvaluationResult(
            decision=Decision.ALLOW,
            reason="Allowed by policy",
            action="s3:GetObject",
            resource="arn:aws:s3:::bucket/key",
            user_arn="arn:aws:iam::123456789012:user/alice",
        )
        assert result.decision == Decision.ALLOW
        assert result.reason == "Allowed by policy"
        assert result.action == "s3:GetObject"
