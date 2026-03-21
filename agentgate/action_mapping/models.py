"""Data models for action mapping configuration."""

from dataclasses import dataclass, field


@dataclass
class AwsActionMapping:
    """One AWS action + resource template pair from a tool mapping."""

    action: str
    resource: str


@dataclass
class ToolMapping:
    """Maps a single agent tool to its AWS actions and required arguments."""

    name: str
    description: str
    aws_actions: list[AwsActionMapping]
    required_args: list[str] = field(default_factory=list)


@dataclass
class ResolvedAction:
    """A fully resolved AWS action + resource ARN (placeholders filled in)."""

    action: str
    resource: str


@dataclass
class MappingConfig:
    """Top-level configuration holding all tool mappings and defaults."""

    version: str
    account_id: str
    region: str
    tools: dict[str, ToolMapping]
