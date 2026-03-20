"""Tests for the can_do() evaluator using a fake policy fetcher."""

from agentgate.permission_engine.evaluator import can_do
from agentgate.permission_engine.models import Decision, IdentityPolicies


class FakePolicyFetcher:
    """Returns pre-built policy data — no AWS dependency."""

    def __init__(self, policies: IdentityPolicies | None = None):
        self._policies = policies or IdentityPolicies()

    def get_identity_policies(self, identity_arn: str) -> IdentityPolicies:
        return self._policies


USER_ARN = "arn:aws:iam::123456789012:user/alice"


def _allow_policy(action: str, resource: str = "*") -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": action, "Resource": resource}],
    }


def _deny_policy(action: str, resource: str = "*") -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": action, "Resource": resource}],
    }


class TestCanDoBasic:
    def test_allow_simple(self):
        fetcher = FakePolicyFetcher(IdentityPolicies(inline_policies=[_allow_policy("s3:GetObject")]))
        result = can_do(USER_ARN, "s3:GetObject", "arn:aws:s3:::bucket/key", fetcher)
        assert result.decision == Decision.ALLOW

    def test_implicit_deny_no_policies(self):
        fetcher = FakePolicyFetcher()
        result = can_do(USER_ARN, "s3:GetObject", "arn:aws:s3:::bucket/key", fetcher)
        assert result.decision == Decision.IMPLICIT_DENY

    def test_implicit_deny_wrong_action(self):
        fetcher = FakePolicyFetcher(IdentityPolicies(inline_policies=[_allow_policy("ec2:DescribeInstances")]))
        result = can_do(USER_ARN, "s3:GetObject", "arn:aws:s3:::bucket/key", fetcher)
        assert result.decision == Decision.IMPLICIT_DENY

    def test_explicit_deny_overrides_allow(self):
        policies = IdentityPolicies(
            inline_policies=[_allow_policy("s3:*")],
            managed_policies=[_deny_policy("s3:DeleteObject")],
        )
        fetcher = FakePolicyFetcher(policies)
        result = can_do(USER_ARN, "s3:DeleteObject", "arn:aws:s3:::bucket/key", fetcher)
        assert result.decision == Decision.DENY

    def test_wildcard_action_allows(self):
        fetcher = FakePolicyFetcher(IdentityPolicies(inline_policies=[_allow_policy("s3:*")]))
        result = can_do(USER_ARN, "s3:PutObject", "arn:aws:s3:::bucket/key", fetcher)
        assert result.decision == Decision.ALLOW

    def test_result_includes_context(self):
        fetcher = FakePolicyFetcher(IdentityPolicies(inline_policies=[_allow_policy("s3:GetObject")]))
        result = can_do(USER_ARN, "s3:GetObject", "arn:aws:s3:::bucket/key", fetcher)
        assert result.user_arn == USER_ARN
        assert result.action == "s3:GetObject"
        assert result.resource == "arn:aws:s3:::bucket/key"


class TestCanDoResourceScoping:
    def test_resource_match(self):
        fetcher = FakePolicyFetcher(
            IdentityPolicies(inline_policies=[_allow_policy("s3:GetObject", "arn:aws:s3:::my-bucket/*")])
        )
        result = can_do(USER_ARN, "s3:GetObject", "arn:aws:s3:::my-bucket/key.txt", fetcher)
        assert result.decision == Decision.ALLOW

    def test_resource_no_match(self):
        fetcher = FakePolicyFetcher(
            IdentityPolicies(inline_policies=[_allow_policy("s3:GetObject", "arn:aws:s3:::my-bucket/*")])
        )
        result = can_do(USER_ARN, "s3:GetObject", "arn:aws:s3:::other-bucket/key.txt", fetcher)
        assert result.decision == Decision.IMPLICIT_DENY


class TestCanDoPermissionBoundary:
    def test_boundary_restricts(self):
        policies = IdentityPolicies(
            inline_policies=[_allow_policy("s3:*")],
            permission_boundary=_allow_policy("s3:GetObject"),
        )
        fetcher = FakePolicyFetcher(policies)
        # GetObject is in boundary → allowed
        result = can_do(USER_ARN, "s3:GetObject", "*", fetcher)
        assert result.decision == Decision.ALLOW
        # PutObject is NOT in boundary → implicit deny
        result = can_do(USER_ARN, "s3:PutObject", "*", fetcher)
        assert result.decision == Decision.IMPLICIT_DENY

    def test_no_boundary_no_restriction(self):
        policies = IdentityPolicies(inline_policies=[_allow_policy("s3:*")])
        fetcher = FakePolicyFetcher(policies)
        result = can_do(USER_ARN, "s3:PutObject", "*", fetcher)
        assert result.decision == Decision.ALLOW


class TestCanDoSCPs:
    def test_scp_allows(self):
        policies = IdentityPolicies(
            inline_policies=[_allow_policy("s3:GetObject")],
            scps=[_allow_policy("*")],
        )
        fetcher = FakePolicyFetcher(policies)
        result = can_do(USER_ARN, "s3:GetObject", "*", fetcher)
        assert result.decision == Decision.ALLOW

    def test_scp_implicit_deny(self):
        policies = IdentityPolicies(
            inline_policies=[_allow_policy("s3:GetObject")],
            scps=[_allow_policy("ec2:*")],  # SCP only allows EC2
        )
        fetcher = FakePolicyFetcher(policies)
        result = can_do(USER_ARN, "s3:GetObject", "*", fetcher)
        assert result.decision == Decision.IMPLICIT_DENY

    def test_scp_explicit_deny(self):
        policies = IdentityPolicies(
            inline_policies=[_allow_policy("s3:*")],
            scps=[
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Action": "*", "Resource": "*"},
                        {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"},
                    ],
                }
            ],
        )
        fetcher = FakePolicyFetcher(policies)
        result = can_do(USER_ARN, "s3:DeleteObject", "*", fetcher)
        assert result.decision == Decision.DENY


class TestCanDoMultiplePolicies:
    def test_combined_inline_and_managed(self):
        policies = IdentityPolicies(
            inline_policies=[_allow_policy("s3:GetObject")],
            managed_policies=[_allow_policy("s3:PutObject")],
        )
        fetcher = FakePolicyFetcher(policies)
        assert can_do(USER_ARN, "s3:GetObject", "*", fetcher).decision == Decision.ALLOW
        assert can_do(USER_ARN, "s3:PutObject", "*", fetcher).decision == Decision.ALLOW
        assert can_do(USER_ARN, "s3:DeleteObject", "*", fetcher).decision == Decision.IMPLICIT_DENY
