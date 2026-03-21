"""Load and validate tool-to-AWS action mapping configuration from YAML files."""

import logging
from pathlib import Path
from typing import Any

import yaml

from agentgate.action_mapping.models import AwsActionMapping, MappingConfig, ToolMapping

logger = logging.getLogger(__name__)


class ConfigError(Exception):
    """Raised when the mapping configuration is invalid."""


def load_config(path: str | Path) -> MappingConfig:
    """Load and validate a mapping config from a YAML file.

    Args:
        path: path to the YAML config file.

    Returns:
        A validated MappingConfig.

    Raises:
        ConfigError: if the file is missing, malformed, or fails validation.
    """
    path = Path(path)
    if not path.exists():
        raise ConfigError(f"Config file not found: {path}")

    try:
        with open(path) as f:
            raw = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ConfigError(f"Invalid YAML in {path}: {e}") from e

    if not isinstance(raw, dict):
        raise ConfigError(f"Config must be a YAML mapping, got {type(raw).__name__}")

    return _parse_config(raw)


def load_config_from_dict(raw: dict[str, Any]) -> MappingConfig:
    """Load and validate a mapping config from a dict (useful for tests)."""
    if not isinstance(raw, dict):
        raise ConfigError(f"Config must be a mapping, got {type(raw).__name__}")
    return _parse_config(raw)


def _parse_config(raw: dict[str, Any]) -> MappingConfig:
    """Parse and validate raw config dict into a MappingConfig."""
    # Required top-level fields
    version = raw.get("version")
    if not version:
        raise ConfigError("Missing required field: 'version'")

    account_id = raw.get("account_id", "")
    region = raw.get("region", "")

    raw_tools = raw.get("tools")
    if not isinstance(raw_tools, dict) or not raw_tools:
        raise ConfigError("'tools' must be a non-empty mapping")

    tools: dict[str, ToolMapping] = {}
    for tool_name, tool_data in raw_tools.items():
        tools[tool_name] = _parse_tool(tool_name, tool_data)

    config = MappingConfig(version=version, account_id=account_id, region=region, tools=tools)
    logger.info("Loaded mapping config with %d tools", len(tools))
    return config


def _parse_tool(name: str, data: Any) -> ToolMapping:
    """Parse and validate a single tool mapping entry."""
    if not isinstance(data, dict):
        raise ConfigError(f"Tool '{name}' must be a mapping, got {type(data).__name__}")

    description = data.get("description", "")

    raw_actions = data.get("aws_actions")
    if not isinstance(raw_actions, list) or not raw_actions:
        raise ConfigError(f"Tool '{name}' must have a non-empty 'aws_actions' list")

    aws_actions: list[AwsActionMapping] = []
    for i, entry in enumerate(raw_actions):
        if not isinstance(entry, dict):
            raise ConfigError(f"Tool '{name}' aws_actions[{i}] must be a mapping")
        action = entry.get("action")
        resource = entry.get("resource")
        if not action:
            raise ConfigError(f"Tool '{name}' aws_actions[{i}] missing 'action'")
        if not resource:
            raise ConfigError(f"Tool '{name}' aws_actions[{i}] missing 'resource'")
        aws_actions.append(AwsActionMapping(action=action, resource=resource))

    required_args = data.get("required_args", [])
    if not isinstance(required_args, list):
        raise ConfigError(f"Tool '{name}' 'required_args' must be a list")

    return ToolMapping(name=name, description=description, aws_actions=aws_actions, required_args=required_args)
