"""AWS IAM setup for real-mode testing.

Creates the IAM users and policies needed to run the attack simulator
against real AWS. Also provides teardown to clean up afterward.

Usage:
  python -m agentgate.simulator.aws_setup --action create --profile my-profile
  python -m agentgate.simulator.aws_setup --action teardown --profile my-profile

This creates:
  - IAM user "agentgate-alice" with S3 read, DynamoDB query, SES send
  - IAM user "agentgate-bob" with DynamoDB query only, explicit deny on S3
  - IAM role "agentgate-agent-role" with broad permissions (intentionally
    over-provisioned to demonstrate privilege creep detection)
"""

from __future__ import annotations

import json
import logging

logger = logging.getLogger(__name__)

# Prefix all IAM resources to avoid conflicts
PREFIX = "agentgate-"

ALICE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": "*",
        },
        {
            "Effect": "Allow",
            "Action": "dynamodb:Query",
            "Resource": "*",
        },
        {
            "Effect": "Allow",
            "Action": "ses:SendEmail",
            "Resource": "*",
        },
    ],
}

BOB_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "dynamodb:Query",
            "Resource": "*",
        },
        {
            "Effect": "Deny",
            "Action": "s3:*",
            "Resource": "*",
        },
    ],
}

AGENT_ROLE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject",
            ],
            "Resource": "*",
        },
        {
            "Effect": "Allow",
            "Action": [
                "dynamodb:Query",
                "dynamodb:Scan",
            ],
            "Resource": "*",
        },
        {
            "Effect": "Allow",
            "Action": "ses:SendEmail",
            "Resource": "*",
        },
        {
            "Effect": "Allow",
            "Action": "lambda:InvokeFunction",
            "Resource": "*",
        },
    ],
}

# Trust policy that allows the current account to assume the agent role
ROLE_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        },
    ],
}


def create_resources(profile: str = "default") -> dict:
    """Create IAM users and role for the simulator.

    Returns a dict with the ARNs of the created resources.
    """
    import boto3

    session = boto3.Session(profile_name=profile)
    iam = session.client("iam")
    results = {}

    # Create alice
    print(f"Creating IAM user {PREFIX}alice...")
    try:
        resp = iam.create_user(UserName=f"{PREFIX}alice")
        results["alice_arn"] = resp["User"]["Arn"]
    except iam.exceptions.EntityAlreadyExistsException:
        resp = iam.get_user(UserName=f"{PREFIX}alice")
        results["alice_arn"] = resp["User"]["Arn"]
        print(f"  Already exists: {results['alice_arn']}")

    iam.put_user_policy(
        UserName=f"{PREFIX}alice",
        PolicyName=f"{PREFIX}alice-policy",
        PolicyDocument=json.dumps(ALICE_POLICY),
    )
    print(f"  Policy attached: {results.get('alice_arn', 'OK')}")

    # Create bob
    print(f"Creating IAM user {PREFIX}bob...")
    try:
        resp = iam.create_user(UserName=f"{PREFIX}bob")
        results["bob_arn"] = resp["User"]["Arn"]
    except iam.exceptions.EntityAlreadyExistsException:
        resp = iam.get_user(UserName=f"{PREFIX}bob")
        results["bob_arn"] = resp["User"]["Arn"]
        print(f"  Already exists: {results['bob_arn']}")

    iam.put_user_policy(
        UserName=f"{PREFIX}bob",
        PolicyName=f"{PREFIX}bob-policy",
        PolicyDocument=json.dumps(BOB_POLICY),
    )
    print(f"  Policy attached: {results.get('bob_arn', 'OK')}")

    # Create agent role
    print(f"Creating IAM role {PREFIX}agent-role...")
    try:
        resp = iam.create_role(
            RoleName=f"{PREFIX}agent-role",
            AssumeRolePolicyDocument=json.dumps(ROLE_TRUST_POLICY),
            Description="AgentGate demo — over-provisioned agent role for privilege creep testing",
        )
        results["role_arn"] = resp["Role"]["Arn"]
    except iam.exceptions.EntityAlreadyExistsException:
        resp = iam.get_role(RoleName=f"{PREFIX}agent-role")
        results["role_arn"] = resp["Role"]["Arn"]
        print(f"  Already exists: {results['role_arn']}")

    iam.put_role_policy(
        RoleName=f"{PREFIX}agent-role",
        PolicyName=f"{PREFIX}agent-role-policy",
        PolicyDocument=json.dumps(AGENT_ROLE_POLICY),
    )
    print(f"  Policy attached: {results.get('role_arn', 'OK')}")

    print("\nIAM resources created successfully!")
    print(f"  Alice ARN: {results.get('alice_arn')}")
    print(f"  Bob ARN:   {results.get('bob_arn')}")
    print(f"  Role ARN:  {results.get('role_arn')}")

    print("\nTo run the simulator in real mode, update the ARNs in runner.py")
    print("to match the ARNs above (account ID will differ from the mock default).")

    return results


def teardown_resources(profile: str = "default") -> None:
    """Remove all IAM resources created by create_resources."""
    import boto3

    session = boto3.Session(profile_name=profile)
    iam = session.client("iam")

    # Delete user policies and users
    for username in [f"{PREFIX}alice", f"{PREFIX}bob"]:
        print(f"Deleting IAM user {username}...")
        try:
            # Delete inline policies first
            policies = iam.list_user_policies(UserName=username)
            for policy_name in policies["PolicyNames"]:
                iam.delete_user_policy(UserName=username, PolicyName=policy_name)
            iam.delete_user(UserName=username)
            print(f"  Deleted: {username}")
        except iam.exceptions.NoSuchEntityException:
            print(f"  Not found: {username}")

    # Delete role policy and role
    role_name = f"{PREFIX}agent-role"
    print(f"Deleting IAM role {role_name}...")
    try:
        policies = iam.list_role_policies(RoleName=role_name)
        for policy_name in policies["PolicyNames"]:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam.delete_role(RoleName=role_name)
        print(f"  Deleted: {role_name}")
    except iam.exceptions.NoSuchEntityException:
        print(f"  Not found: {role_name}")

    print("\nAll AgentGate IAM resources removed.")


def main() -> None:
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="AgentGate AWS IAM Setup")
    parser.add_argument(
        "--action",
        choices=["create", "teardown"],
        required=True,
        help="create = set up IAM resources, teardown = remove them",
    )
    parser.add_argument(
        "--profile",
        default="default",
        help="AWS profile name",
    )
    args = parser.parse_args()

    if args.action == "create":
        create_resources(profile=args.profile)
    else:
        teardown_resources(profile=args.profile)


if __name__ == "__main__":
    main()
