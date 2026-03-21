"""Tests for the action resolver."""

import pytest

from agentgate.action_mapping.config_loader import load_config_from_dict
from agentgate.action_mapping.resolver import ResolutionError, resolve


def _config_with_tools(tools_dict):
    """Build a config with the given tools."""
    return load_config_from_dict({
        "version": "1",
        "account_id": "123456789012",
        "region": "us-east-1",
        "tools": tools_dict,
    })


class TestResolveBasic:
    def test_simple_resolution(self):
        config = _config_with_tools({
            "read_file": {
                "aws_actions": [{"action": "s3:GetObject", "resource": "arn:aws:s3:::{bucket}/{key}"}],
                "required_args": ["bucket", "key"],
            }
        })
        result = resolve(config, "read_file", {"bucket": "my-bucket", "key": "data.csv"})
        assert len(result) == 1
        assert result[0].action == "s3:GetObject"
        assert result[0].resource == "arn:aws:s3:::my-bucket/data.csv"

    def test_config_level_placeholders(self):
        config = _config_with_tools({
            "query_db": {
                "aws_actions": [
                    {"action": "dynamodb:Query", "resource": "arn:aws:dynamodb:{region}:{account_id}:table/{table}"}
                ],
                "required_args": ["table"],
            }
        })
        result = resolve(config, "query_db", {"table": "users"})
        assert result[0].resource == "arn:aws:dynamodb:us-east-1:123456789012:table/users"

    def test_multiple_aws_actions(self):
        config = _config_with_tools({
            "copy_file": {
                "aws_actions": [
                    {"action": "s3:GetObject", "resource": "arn:aws:s3:::{src_bucket}/{src_key}"},
                    {"action": "s3:PutObject", "resource": "arn:aws:s3:::{dst_bucket}/{dst_key}"},
                ],
                "required_args": ["src_bucket", "src_key", "dst_bucket", "dst_key"],
            }
        })
        result = resolve(
            config, "copy_file",
            {"src_bucket": "source", "src_key": "a.txt", "dst_bucket": "dest", "dst_key": "b.txt"},
        )
        assert len(result) == 2
        assert result[0].action == "s3:GetObject"
        assert result[0].resource == "arn:aws:s3:::source/a.txt"
        assert result[1].action == "s3:PutObject"
        assert result[1].resource == "arn:aws:s3:::dest/b.txt"

    def test_no_placeholders(self):
        config = _config_with_tools({
            "list_buckets": {
                "aws_actions": [{"action": "s3:ListAllMyBuckets", "resource": "*"}],
            }
        })
        result = resolve(config, "list_buckets", {})
        assert result[0].action == "s3:ListAllMyBuckets"
        assert result[0].resource == "*"

    def test_extra_args_ignored(self):
        config = _config_with_tools({
            "read_file": {
                "aws_actions": [{"action": "s3:GetObject", "resource": "arn:aws:s3:::{bucket}/{key}"}],
                "required_args": ["bucket", "key"],
            }
        })
        result = resolve(config, "read_file", {"bucket": "b", "key": "k", "extra": "ignored"})
        assert result[0].resource == "arn:aws:s3:::b/k"


class TestResolveErrors:
    def test_unknown_tool(self):
        config = _config_with_tools({
            "read_file": {
                "aws_actions": [{"action": "s3:GetObject", "resource": "*"}],
            }
        })
        with pytest.raises(ResolutionError, match="Unknown tool"):
            resolve(config, "nonexistent_tool", {})

    def test_missing_required_arg(self):
        config = _config_with_tools({
            "read_file": {
                "aws_actions": [{"action": "s3:GetObject", "resource": "arn:aws:s3:::{bucket}/{key}"}],
                "required_args": ["bucket", "key"],
            }
        })
        with pytest.raises(ResolutionError, match="missing required arguments"):
            resolve(config, "read_file", {"bucket": "my-bucket"})

    def test_missing_placeholder_value(self):
        config = _config_with_tools({
            "read_file": {
                "aws_actions": [{"action": "s3:GetObject", "resource": "arn:aws:s3:::{bucket}/{key}"}],
                # No required_args — so validation passes, but placeholder filling fails
            }
        })
        with pytest.raises(ResolutionError, match="placeholder"):
            resolve(config, "read_file", {})


class TestResolveEndToEnd:
    """Test with the example config file to verify real-world usage."""

    def test_query_database(self):
        import os
        from agentgate.action_mapping.config_loader import load_config

        config_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "agentgate", "action_mapping", "example_config.yaml"
        )
        config = load_config(config_path)

        result = resolve(config, "query_database", {"table": "hr-salaries"})
        assert len(result) == 1
        assert result[0].action == "dynamodb:Query"
        assert result[0].resource == "arn:aws:dynamodb:us-east-1:123456789012:table/hr-salaries"

    def test_copy_file(self):
        import os
        from agentgate.action_mapping.config_loader import load_config

        config_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "agentgate", "action_mapping", "example_config.yaml"
        )
        config = load_config(config_path)

        result = resolve(
            config, "copy_file",
            {"source_bucket": "src", "source_key": "a.txt", "dest_bucket": "dst", "dest_key": "b.txt"},
        )
        assert len(result) == 2
        assert result[0].action == "s3:GetObject"
        assert result[0].resource == "arn:aws:s3:::src/a.txt"
        assert result[1].action == "s3:PutObject"
        assert result[1].resource == "arn:aws:s3:::dst/b.txt"
