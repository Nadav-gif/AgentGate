"""Tests for the config loader and validator."""

import pytest

from agentgate.action_mapping.config_loader import ConfigError, load_config, load_config_from_dict


def _minimal_config(**overrides):
    """Build a minimal valid config dict, with optional overrides."""
    base = {
        "version": "1",
        "account_id": "123456789012",
        "region": "us-east-1",
        "tools": {
            "read_file": {
                "description": "Read from S3",
                "aws_actions": [{"action": "s3:GetObject", "resource": "arn:aws:s3:::{bucket}/{key}"}],
                "required_args": ["bucket", "key"],
            }
        },
    }
    base.update(overrides)
    return base


class TestLoadConfigFromDict:
    def test_valid_config(self):
        config = load_config_from_dict(_minimal_config())
        assert config.version == "1"
        assert config.account_id == "123456789012"
        assert config.region == "us-east-1"
        assert "read_file" in config.tools

    def test_tool_parsed_correctly(self):
        config = load_config_from_dict(_minimal_config())
        tool = config.tools["read_file"]
        assert tool.name == "read_file"
        assert tool.description == "Read from S3"
        assert len(tool.aws_actions) == 1
        assert tool.aws_actions[0].action == "s3:GetObject"
        assert tool.aws_actions[0].resource == "arn:aws:s3:::{bucket}/{key}"
        assert tool.required_args == ["bucket", "key"]

    def test_multiple_tools(self):
        raw = _minimal_config()
        raw["tools"]["write_file"] = {
            "aws_actions": [{"action": "s3:PutObject", "resource": "*"}],
        }
        config = load_config_from_dict(raw)
        assert len(config.tools) == 2

    def test_multiple_aws_actions(self):
        raw = _minimal_config()
        raw["tools"]["copy_file"] = {
            "aws_actions": [
                {"action": "s3:GetObject", "resource": "arn:aws:s3:::{src}"},
                {"action": "s3:PutObject", "resource": "arn:aws:s3:::{dst}"},
            ],
            "required_args": ["src", "dst"],
        }
        config = load_config_from_dict(raw)
        assert len(config.tools["copy_file"].aws_actions) == 2

    def test_optional_fields_default(self):
        raw = {
            "version": "1",
            "tools": {
                "simple": {
                    "aws_actions": [{"action": "s3:ListAllMyBuckets", "resource": "*"}],
                }
            },
        }
        config = load_config_from_dict(raw)
        assert config.account_id == ""
        assert config.region == ""
        tool = config.tools["simple"]
        assert tool.description == ""
        assert tool.required_args == []


class TestConfigValidation:
    def test_missing_version(self):
        raw = _minimal_config()
        del raw["version"]
        with pytest.raises(ConfigError, match="version"):
            load_config_from_dict(raw)

    def test_missing_tools(self):
        raw = _minimal_config()
        del raw["tools"]
        with pytest.raises(ConfigError, match="tools"):
            load_config_from_dict(raw)

    def test_empty_tools(self):
        raw = _minimal_config(tools={})
        with pytest.raises(ConfigError, match="tools"):
            load_config_from_dict(raw)

    def test_tool_missing_aws_actions(self):
        raw = _minimal_config()
        raw["tools"]["bad"] = {"description": "no actions"}
        with pytest.raises(ConfigError, match="aws_actions"):
            load_config_from_dict(raw)

    def test_aws_action_missing_action_field(self):
        raw = _minimal_config()
        raw["tools"]["bad"] = {"aws_actions": [{"resource": "*"}]}
        with pytest.raises(ConfigError, match="action"):
            load_config_from_dict(raw)

    def test_aws_action_missing_resource_field(self):
        raw = _minimal_config()
        raw["tools"]["bad"] = {"aws_actions": [{"action": "s3:GetObject"}]}
        with pytest.raises(ConfigError, match="resource"):
            load_config_from_dict(raw)

    def test_not_a_dict(self):
        with pytest.raises(ConfigError, match="mapping"):
            load_config_from_dict("not a dict")  # type: ignore


class TestLoadConfigFromFile:
    def test_load_example_config(self):
        import os

        config_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "agentgate", "action_mapping", "example_config.yaml"
        )
        config = load_config(config_path)
        assert config.version == "1"
        assert "query_database" in config.tools
        assert "read_file" in config.tools
        assert "copy_file" in config.tools

    def test_file_not_found(self):
        with pytest.raises(ConfigError, match="not found"):
            load_config("/nonexistent/path.yaml")

    def test_invalid_yaml(self, tmp_path):
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("{{invalid yaml")
        with pytest.raises(ConfigError, match="Invalid YAML"):
            load_config(bad_file)
