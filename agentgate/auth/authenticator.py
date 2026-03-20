"""
AWS session creation and validation.

Provides helpers to create boto3 sessions, assume roles, and validate
that a session is working by calling GetCallerIdentity.
"""

from __future__ import annotations

import logging
from typing import Any

import boto3

logger = logging.getLogger(__name__)


class AuthenticationError(Exception):
    """Raised when AWS authentication fails."""


def create_session(
    profile_name: str | None = None,
    aws_access_key_id: str | None = None,
    aws_secret_access_key: str | None = None,
    region_name: str = "us-east-1",
) -> boto3.Session:
    """Create a boto3 session from a profile or explicit credentials.

    Args:
        profile_name: AWS CLI profile name.
        aws_access_key_id: explicit access key (ignored if profile_name is set).
        aws_secret_access_key: explicit secret key.
        region_name: AWS region.

    Returns:
        A configured boto3.Session.

    Raises:
        AuthenticationError: if session creation fails.
    """
    try:
        if profile_name:
            return boto3.Session(profile_name=profile_name, region_name=region_name)
        elif aws_access_key_id and aws_secret_access_key:
            return boto3.Session(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region_name=region_name,
            )
        else:
            # Default credential chain
            return boto3.Session(region_name=region_name)
    except Exception as e:
        raise AuthenticationError(f"Failed to create session: {e}") from e


def assume_role(session: boto3.Session, role_arn: str, session_name: str = "AgentGateSession") -> boto3.Session:
    """Assume an IAM role and return a new session with temporary credentials.

    Args:
        session: existing session with permission to call sts:AssumeRole.
        role_arn: ARN of the role to assume.
        session_name: name for the assumed role session.

    Returns:
        A new boto3.Session using the assumed role's temporary credentials.

    Raises:
        AuthenticationError: if role assumption fails.
    """
    try:
        sts = session.client("sts")
        response = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
        creds = response["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=session.region_name,
        )
    except Exception as e:
        raise AuthenticationError(f"Failed to assume role {role_arn}: {e}") from e


def validate_session(session: boto3.Session) -> dict[str, Any]:
    """Validate a session by calling GetCallerIdentity.

    Returns:
        Dict with 'arn', 'account', and 'user_id' keys.

    Raises:
        AuthenticationError: if the session is invalid.
    """
    try:
        sts = session.client("sts")
        response = sts.get_caller_identity()
        return {
            "arn": response["Arn"],
            "account": response["Account"],
            "user_id": response["UserId"],
        }
    except Exception as e:
        raise AuthenticationError(f"Session validation failed: {e}") from e
