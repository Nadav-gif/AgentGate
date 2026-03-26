"""Pydantic models for proxy request/response validation."""

from pydantic import BaseModel, Field


class ToolExecutionRequest(BaseModel):
    """What the agent sends to /execute-tool."""

    tool_name: str = Field(..., description="Name of the tool to execute (must match a tool in the mapping config)")
    tool_args: dict[str, str] = Field(default_factory=dict, description="Arguments to pass to the tool")


class ActionResult(BaseModel):
    """Result of executing one AWS action via the mock service."""

    action: str
    resource: str
    response: dict


class ToolExecutionResponse(BaseModel):
    """Returned when the tool call is allowed and executed."""

    status: str = "allowed"
    tool_name: str
    results: list[ActionResult]


class ToolDeniedResponse(BaseModel):
    """Returned when the tool call is denied by the permission engine."""

    status: str = "denied"
    tool_name: str
    denied_action: str
    resource: str
    decision: str
    reason: str


class UserContext(BaseModel):
    """Identity information extracted from the API key."""

    user_arn: str
    agent_id: str
