"""Integration tests using moto to mock AWS IAM.

These tests create real IAM resources in a mocked AWS environment
and run the full can_do() evaluation chain.
"""

import json

import boto3
import pytest
from moto import mock_aws

from agentgate.permission_engine.evaluator import can_do
from agentgate.permission_engine.models import Decision
from agentgate.permission_engine.policy_fetcher import AwsPolicyFetcher

ACCOUNT_ID = "123456789012"


@pytest.fixture
def aws_session():
    """Create a moto-mocked boto3 session."""
    with mock_aws():
        session = boto3.Session(
            aws_access_key_id="testing",
            aws_secret_access_key="testing",
            region_name="us-east-1",
        )
        yield session


def _create_user(iam, username: str) -> str:
    """Create an IAM user and return its ARN."""
    resp = iam.create_user(UserName=username)
    return resp["User"]["Arn"]


def _attach_inline_policy(iam, username: str, policy_name: str, document: dict) -> None:
    """Attach an inline policy to a user."""
    iam.put_user_policy(
        UserName=username,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(document),
    )


def _create_managed_policy(iam, policy_name: str, document: dict) -> str:
    """Create a managed policy and return its ARN."""
    resp = iam.create_policy(
        PolicyName=policy_name,
        PolicyDocument=json.dumps(document),
    )
    return resp["Policy"]["Arn"]


class TestIntegrationUserInlinePolicy:
    def test_allow_with_inline_policy(self, aws_session):
        iam = aws_session.client("iam")
        user_arn = _create_user(iam, "alice")
        _attach_inline_policy(iam, "alice", "s3-read", {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        })

        fetcher = AwsPolicyFetcher(aws_session)
        result = can_do(user_arn, "s3:GetObject", "arn:aws:s3:::bucket/key", fetcher)
        assert result.decision == Decision.ALLOW

    def test_deny_not_in_policy(self, aws_session):
        iam = aws_session.client("iam")
        user_arn = _create_user(iam, "bob")
        _attach_inline_policy(iam, "bob", "ec2-only", {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}],
        })

        fetcher = AwsPolicyFetcher(aws_session)
        result = can_do(user_arn, "s3:GetObject", "arn:aws:s3:::bucket/key", fetcher)
        assert result.decision == Decision.IMPLICIT_DENY


class TestIntegrationManagedPolicy:
    def test_allow_with_managed_policy(self, aws_session):
        iam = aws_session.client("iam")
        user_arn = _create_user(iam, "charlie")
        policy_arn = _create_managed_policy(iam, "s3-full", {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
        })
        iam.attach_user_policy(UserName="charlie", PolicyArn=policy_arn)

        fetcher = AwsPolicyFetcher(aws_session)
        result = can_do(user_arn, "s3:PutObject", "arn:aws:s3:::bucket/key", fetcher)
        assert result.decision == Decision.ALLOW


class TestIntegrationExplicitDeny:
    def test_deny_overrides_allow(self, aws_session):
        iam = aws_session.client("iam")
        user_arn = _create_user(iam, "dave")
        _attach_inline_policy(iam, "dave", "allow-s3", {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
        })
        _attach_inline_policy(iam, "dave", "deny-delete", {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"}],
        })

        fetcher = AwsPolicyFetcher(aws_session)
        result = can_do(user_arn, "s3:DeleteObject", "arn:aws:s3:::bucket/key", fetcher)
        assert result.decision == Decision.DENY

        # Other S3 actions still allowed
        result = can_do(user_arn, "s3:GetObject", "arn:aws:s3:::bucket/key", fetcher)
        assert result.decision == Decision.ALLOW


class TestIntegrationGroupPolicy:
    def test_group_policy_grants_access(self, aws_session):
        iam = aws_session.client("iam")
        user_arn = _create_user(iam, "eve")

        # Create group with policy
        iam.create_group(GroupName="developers")
        iam.put_group_policy(
            GroupName="developers",
            PolicyName="dev-policy",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
            }),
        )
        iam.add_user_to_group(GroupName="developers", UserName="eve")

        fetcher = AwsPolicyFetcher(aws_session)
        result = can_do(user_arn, "s3:GetObject", "arn:aws:s3:::bucket/key", fetcher)
        assert result.decision == Decision.ALLOW


class TestIntegrationPermissionBoundary:
    @pytest.mark.skip(reason="moto does not support PermissionsBoundary on get_user — tested via unit tests with FakePolicyFetcher")
    def test_boundary_restricts_permissions(self, aws_session):
        iam = aws_session.client("iam")

        # Create boundary policy that only allows S3 read
        boundary_arn = _create_managed_policy(iam, "s3-read-boundary", {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        })

        # Create user with boundary
        iam.create_user(UserName="frank", PermissionsBoundary=boundary_arn)
        user_arn = f"arn:aws:iam::{ACCOUNT_ID}:user/frank"

        # Give user full S3 access
        _attach_inline_policy(iam, "frank", "s3-full", {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
        })

        fetcher = AwsPolicyFetcher(aws_session)

        # GetObject is within boundary → allowed
        result = can_do(user_arn, "s3:GetObject", "arn:aws:s3:::bucket/key", fetcher)
        assert result.decision == Decision.ALLOW

        # PutObject is outside boundary → implicit deny
        result = can_do(user_arn, "s3:PutObject", "arn:aws:s3:::bucket/key", fetcher)
        assert result.decision == Decision.IMPLICIT_DENY


class TestIntegrationRolePolicy:
    def test_role_inline_policy(self, aws_session):
        iam = aws_session.client("iam")

        iam.create_role(
            RoleName="lambda-role",
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
            }),
        )
        iam.put_role_policy(
            RoleName="lambda-role",
            PolicyName="s3-access",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
            }),
        )
        role_arn = f"arn:aws:iam::{ACCOUNT_ID}:role/lambda-role"

        fetcher = AwsPolicyFetcher(aws_session)
        result = can_do(role_arn, "s3:GetObject", "arn:aws:s3:::bucket/key", fetcher)
        assert result.decision == Decision.ALLOW

        result = can_do(role_arn, "ec2:DescribeInstances", "*", fetcher)
        assert result.decision == Decision.IMPLICIT_DENY
