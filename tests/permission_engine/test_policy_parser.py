"""TDD tests for the policy parser — written BEFORE the implementation."""

import pytest

from agentgate.permission_engine.models import PolicyEntry, PolicyLists
from agentgate.permission_engine.policy_parser import (
    action_matches,
    get_matching_resources,
    intersect_with_boundary,
    parse_policy_document,
    parse_statement,
    resource_matches,
)


class TestActionMatches:
    def test_exact_match(self):
        assert action_matches("s3:GetObject", "s3:GetObject") is True

    def test_case_insensitive(self):
        assert action_matches("s3:getobject", "s3:GetObject") is True
        assert action_matches("S3:GETOBJECT", "s3:GetObject") is True

    def test_wildcard_suffix(self):
        assert action_matches("s3:Get*", "s3:GetObject") is True
        assert action_matches("s3:Get*", "s3:GetBucketPolicy") is True

    def test_wildcard_no_match(self):
        assert action_matches("s3:Get*", "s3:PutObject") is False

    def test_full_wildcard(self):
        assert action_matches("*", "s3:GetObject") is True

    def test_service_wildcard(self):
        assert action_matches("s3:*", "s3:GetObject") is True
        assert action_matches("s3:*", "ec2:DescribeInstances") is False

    def test_no_match(self):
        assert action_matches("ec2:DescribeInstances", "s3:GetObject") is False


class TestResourceMatches:
    def test_exact_match(self):
        arn = "arn:aws:s3:::my-bucket/key.txt"
        assert resource_matches(arn, arn) is True

    def test_wildcard_all(self):
        assert resource_matches("*", "arn:aws:s3:::my-bucket/key.txt") is True

    def test_wildcard_suffix(self):
        assert resource_matches("arn:aws:s3:::my-bucket/*", "arn:aws:s3:::my-bucket/key.txt") is True

    def test_no_match(self):
        assert resource_matches("arn:aws:s3:::other-bucket/*", "arn:aws:s3:::my-bucket/key.txt") is False


class TestParseStatement:
    def test_allow_statement(self):
        stmt = {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::my-bucket/*",
        }
        allows, denies = parse_statement(stmt)
        assert len(allows) == 1
        assert len(denies) == 0
        assert allows[0].action == "s3:GetObject"
        assert allows[0].resource == "arn:aws:s3:::my-bucket/*"

    def test_deny_statement(self):
        stmt = {
            "Effect": "Deny",
            "Action": "s3:DeleteObject",
            "Resource": "*",
        }
        allows, denies = parse_statement(stmt)
        assert len(allows) == 0
        assert len(denies) == 1

    def test_multiple_actions_and_resources(self):
        stmt = {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": ["arn:aws:s3:::bucket-a/*", "arn:aws:s3:::bucket-b/*"],
        }
        allows, denies = parse_statement(stmt)
        # 2 actions × 2 resources = 4 entries
        assert len(allows) == 4
        assert len(denies) == 0

    def test_no_action_returns_empty(self):
        stmt = {"Effect": "Allow", "Resource": "*"}
        allows, denies = parse_statement(stmt)
        assert allows == []
        assert denies == []

    def test_unknown_effect_returns_empty(self):
        stmt = {"Effect": "Maybe", "Action": "s3:GetObject", "Resource": "*"}
        allows, denies = parse_statement(stmt)
        assert allows == []
        assert denies == []

    def test_default_resource_is_wildcard(self):
        stmt = {"Effect": "Allow", "Action": "s3:GetObject"}
        allows, _ = parse_statement(stmt)
        assert len(allows) == 1
        assert allows[0].resource == "*"


class TestParsePolicyDocument:
    def test_single_statement(self):
        doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
            ],
        }
        result = parse_policy_document(doc)
        assert len(result.allows) == 1
        assert len(result.denies) == 0

    def test_multiple_statements(self):
        doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
                {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"},
            ],
        }
        result = parse_policy_document(doc)
        assert len(result.allows) == 1
        assert len(result.denies) == 1

    def test_empty_statement_list(self):
        doc = {"Version": "2012-10-17", "Statement": []}
        result = parse_policy_document(doc)
        assert result.allows == []
        assert result.denies == []

    def test_single_statement_not_in_list(self):
        """Some AWS policies have Statement as a dict, not a list."""
        doc = {
            "Version": "2012-10-17",
            "Statement": {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
        }
        result = parse_policy_document(doc)
        assert len(result.allows) > 0


class TestGetMatchingResources:
    def test_finds_match(self):
        entries = [
            PolicyEntry(action="s3:GetObject", resource="arn:aws:s3:::my-bucket/*"),
            PolicyEntry(action="s3:PutObject", resource="*"),
        ]
        matches = get_matching_resources("s3:GetObject", "arn:aws:s3:::my-bucket/key.txt", entries)
        assert len(matches) == 1
        assert matches[0].action == "s3:GetObject"

    def test_no_match(self):
        entries = [PolicyEntry(action="ec2:DescribeInstances", resource="*")]
        matches = get_matching_resources("s3:GetObject", "arn:aws:s3:::bucket/key", entries)
        assert matches == []

    def test_wildcard_action_match(self):
        entries = [PolicyEntry(action="s3:*", resource="*")]
        matches = get_matching_resources("s3:GetObject", "arn:aws:s3:::bucket/key", entries)
        assert len(matches) == 1

    def test_multiple_matches(self):
        entries = [
            PolicyEntry(action="s3:*", resource="*"),
            PolicyEntry(action="s3:GetObject", resource="*"),
        ]
        matches = get_matching_resources("s3:GetObject", "arn:aws:s3:::bucket/key", entries)
        assert len(matches) == 2


class TestIntersectWithBoundary:
    def test_keeps_matching(self):
        allows = [PolicyEntry(action="s3:GetObject", resource="*")]
        boundary = PolicyLists(allows=[PolicyEntry(action="s3:*", resource="*")])
        result = intersect_with_boundary(allows, boundary)
        assert len(result) == 1

    def test_removes_non_matching(self):
        allows = [
            PolicyEntry(action="s3:GetObject", resource="*"),
            PolicyEntry(action="ec2:DescribeInstances", resource="*"),
        ]
        boundary = PolicyLists(allows=[PolicyEntry(action="s3:*", resource="*")])
        result = intersect_with_boundary(allows, boundary)
        assert len(result) == 1
        assert result[0].action == "s3:GetObject"

    def test_empty_boundary_removes_all(self):
        allows = [PolicyEntry(action="s3:GetObject", resource="*")]
        boundary = PolicyLists()
        result = intersect_with_boundary(allows, boundary)
        assert result == []

    def test_resource_restriction(self):
        allows = [PolicyEntry(action="s3:GetObject", resource="arn:aws:s3:::any-bucket/*")]
        boundary = PolicyLists(allows=[PolicyEntry(action="s3:*", resource="arn:aws:s3:::specific-bucket/*")])
        result = intersect_with_boundary(allows, boundary)
        assert result == []
