"""
AWS actions registry for NotAction expansion and action validation.

The full list is loaded lazily to avoid startup cost when not needed.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# A representative subset of common AWS actions. In production, this would be
# the full list (~15,000+ actions) loaded from a data file or AWS API.
# For now, we include enough to make NotAction tests meaningful.
_ALL_ACTIONS: list[str] | None = None

_COMMON_ACTIONS = [
    # S3
    "s3:GetObject",
    "s3:PutObject",
    "s3:DeleteObject",
    "s3:ListBucket",
    "s3:ListAllMyBuckets",
    "s3:GetBucketLocation",
    "s3:GetBucketPolicy",
    "s3:PutBucketPolicy",
    "s3:DeleteBucket",
    "s3:CreateBucket",
    # EC2
    "ec2:DescribeInstances",
    "ec2:RunInstances",
    "ec2:StartInstances",
    "ec2:StopInstances",
    "ec2:TerminateInstances",
    "ec2:DescribeSecurityGroups",
    "ec2:AuthorizeSecurityGroupIngress",
    "ec2:CreateSecurityGroup",
    "ec2:DeleteSecurityGroup",
    # IAM
    "iam:CreateUser",
    "iam:DeleteUser",
    "iam:GetUser",
    "iam:ListUsers",
    "iam:AttachUserPolicy",
    "iam:DetachUserPolicy",
    "iam:CreateRole",
    "iam:DeleteRole",
    "iam:GetRole",
    "iam:ListRoles",
    "iam:AttachRolePolicy",
    "iam:DetachRolePolicy",
    "iam:CreatePolicy",
    "iam:DeletePolicy",
    "iam:GetPolicy",
    "iam:ListPolicies",
    "iam:PutUserPolicy",
    "iam:GetUserPolicy",
    "iam:DeleteUserPolicy",
    # STS
    "sts:AssumeRole",
    "sts:GetCallerIdentity",
    "sts:GetSessionToken",
    # Lambda
    "lambda:CreateFunction",
    "lambda:DeleteFunction",
    "lambda:InvokeFunction",
    "lambda:GetFunction",
    "lambda:ListFunctions",
    "lambda:UpdateFunctionCode",
    # DynamoDB
    "dynamodb:GetItem",
    "dynamodb:PutItem",
    "dynamodb:DeleteItem",
    "dynamodb:Query",
    "dynamodb:Scan",
    "dynamodb:CreateTable",
    "dynamodb:DeleteTable",
    "dynamodb:ListTables",
    # SNS
    "sns:Publish",
    "sns:Subscribe",
    "sns:CreateTopic",
    "sns:DeleteTopic",
    "sns:ListTopics",
    # SQS
    "sqs:SendMessage",
    "sqs:ReceiveMessage",
    "sqs:DeleteMessage",
    "sqs:CreateQueue",
    "sqs:DeleteQueue",
    "sqs:ListQueues",
    # CloudWatch
    "cloudwatch:PutMetricData",
    "cloudwatch:GetMetricData",
    "cloudwatch:ListMetrics",
    "logs:CreateLogGroup",
    "logs:PutLogEvents",
    "logs:DescribeLogGroups",
]


def get_all_actions() -> list[str]:
    """Return the full list of known AWS actions (loaded lazily)."""
    global _ALL_ACTIONS
    if _ALL_ACTIONS is None:
        _ALL_ACTIONS = list(_COMMON_ACTIONS)
    return _ALL_ACTIONS


def validate_action(action: str) -> bool:
    """Check if an action string looks like a valid AWS action (service:ActionName)."""
    if not action or ":" not in action:
        return False
    service, action_name = action.split(":", 1)
    if not service or not action_name:
        return False
    # Wildcards are valid in policies
    if "*" in action:
        return True
    # Check against known actions
    return action in get_all_actions()
