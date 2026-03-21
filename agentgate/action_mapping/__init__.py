"""Action mapping — translates agent tool calls to AWS actions + resource ARNs."""

from agentgate.action_mapping.config_loader import ConfigError, load_config, load_config_from_dict
from agentgate.action_mapping.models import MappingConfig, ResolvedAction
from agentgate.action_mapping.resolver import ResolutionError, resolve

__all__ = [
    "ConfigError",
    "MappingConfig",
    "ResolvedAction",
    "ResolutionError",
    "load_config",
    "load_config_from_dict",
    "resolve",
]
