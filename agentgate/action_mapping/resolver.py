"""Action resolver — translates agent tool calls into AWS actions + resource ARNs."""

import logging
import re

from agentgate.action_mapping.models import MappingConfig, ResolvedAction

logger = logging.getLogger(__name__)


class ResolutionError(Exception):
    """Raised when a tool call cannot be resolved to AWS actions."""


def resolve(config: MappingConfig, tool_name: str, tool_args: dict[str, str]) -> list[ResolvedAction]:
    """Resolve a tool call to a list of AWS action + resource pairs.

    Args:
        config: the loaded mapping configuration.
        tool_name: name of the agent tool being called.
        tool_args: arguments the agent passed to the tool.

    Returns:
        List of ResolvedAction (one per AWS action the tool maps to).

    Raises:
        ResolutionError: if the tool is unknown, required args are missing,
            or placeholders can't be filled.
    """
    tool = config.tools.get(tool_name)
    if tool is None:
        raise ResolutionError(f"Unknown tool: '{tool_name}'")

    # Check required arguments
    missing = [arg for arg in tool.required_args if arg not in tool_args]
    if missing:
        raise ResolutionError(f"Tool '{tool_name}' missing required arguments: {missing}")

    # Build the placeholder context: tool args + config-level defaults
    context = {"account_id": config.account_id, "region": config.region}
    context.update(tool_args)

    resolved: list[ResolvedAction] = []
    for mapping in tool.aws_actions:
        resource = _fill_placeholders(mapping.resource, context, tool_name)
        resolved.append(ResolvedAction(action=mapping.action, resource=resource))

    logger.info(
        "Resolved tool '%s' to %d AWS action(s)",
        tool_name,
        len(resolved),
        extra={"tool_name": tool_name},
    )
    return resolved


def _fill_placeholders(template: str, context: dict[str, str], tool_name: str) -> str:
    """Replace {placeholders} in a resource template with values from context.

    Raises:
        ResolutionError: if a placeholder has no matching value in context.
    """
    def replacer(match: re.Match) -> str:
        key = match.group(1)
        if key not in context:
            raise ResolutionError(
                f"Tool '{tool_name}' resource template has placeholder '{{{key}}}' "
                f"but no value was provided"
            )
        return context[key]

    return re.sub(r"\{(\w+)\}", replacer, template)
