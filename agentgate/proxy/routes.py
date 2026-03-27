"""Route handlers for the permission proxy."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Header, HTTPException

from agentgate.action_mapping.resolver import ResolutionError, resolve
from agentgate.permission_engine.evaluator import can_do
from agentgate.permission_engine.models import Decision
from agentgate.proxy.dependencies import AppDependencies, get_deps
from agentgate.proxy.escalation import check_escalation
from agentgate.proxy.models import (
    ActionResult,
    ToolDeniedResponse,
    ToolExecutionRequest,
    ToolExecutionResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# Maps tool argument names to AWS-style parameter names that mock services expect
_ARG_TO_AWS_PARAM = {
    "bucket": "Bucket",
    "key": "Key",
    "table": "TableName",
    "body": "Body",
    "content_type": "ContentType",
    "source": "Source",
    "function_name": "FunctionName",
}


def _build_aws_params(tool_args: dict[str, str]) -> dict[str, str]:
    """Convert tool argument names to AWS-style parameter names for mock services."""
    params = {}
    for arg_name, value in tool_args.items():
        aws_name = _ARG_TO_AWS_PARAM.get(arg_name, arg_name)
        params[aws_name] = value
    return params


@router.post("/execute-tool")
def execute_tool(
    request: ToolExecutionRequest,
    x_api_key: str = Header(..., alias="X-API-Key"),
    deps: AppDependencies = Depends(get_deps),
) -> ToolExecutionResponse | ToolDeniedResponse:
    """The core endpoint: receive a tool call, check permissions, execute or deny.

    Flow:
    1. Authenticate the API key → get user context
    2. Resolve tool call → AWS action(s) + resource(s)
    3. Check each action with the permission engine (IAM)
    4. Check cross-system escalation rules (session history)
    5. If any denied → return 403 with reason
    6. If all allowed → execute via mock service → return results
    7. Log everything to audit database
    """
    # Step 1: Authenticate
    user = deps.authenticator.authenticate(x_api_key)
    session_key = f"{user.user_arn}:{user.agent_id}"

    # Step 2: Resolve tool call to AWS actions
    try:
        resolved_actions = resolve(deps.config, request.tool_name, request.tool_args)
    except ResolutionError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    # Step 3: Check IAM permissions for each resolved action
    for action in resolved_actions:
        result = can_do(user.user_arn, action.action, action.resource, deps.fetcher)

        # Log every IAM decision
        deps.audit.log_decision(
            user_arn=user.user_arn,
            agent_id=user.agent_id,
            tool_name=request.tool_name,
            aws_action=action.action,
            resource=action.resource,
            decision=result.decision.value,
            reason=result.reason,
        )

        if result.decision != Decision.ALLOW:
            raise HTTPException(
                status_code=403,
                detail=ToolDeniedResponse(
                    tool_name=request.tool_name,
                    denied_action=action.action,
                    resource=action.resource,
                    decision=result.decision.value,
                    reason=result.reason,
                ).model_dump(),
            )

    # Step 4: Check cross-system escalation rules
    history = deps.session_tracker.get_history(session_key)
    for action in resolved_actions:
        esc_result = check_escalation(history, action.action, deps.escalation_rules)
        if esc_result is not None:
            # Log the escalation block
            deps.audit.log_decision(
                user_arn=user.user_arn,
                agent_id=user.agent_id,
                tool_name=request.tool_name,
                aws_action=action.action,
                resource=action.resource,
                decision="DENY",
                reason=esc_result.reason,
            )
            raise HTTPException(
                status_code=403,
                detail=ToolDeniedResponse(
                    tool_name=request.tool_name,
                    denied_action=action.action,
                    resource=action.resource,
                    decision="DENY",
                    reason=esc_result.reason,
                ).model_dump(),
            )

    # Step 5: All checks passed — execute via mock services
    results: list[ActionResult] = []
    for action in resolved_actions:
        aws_params = _build_aws_params(request.tool_args)
        mock_response = deps.registry.handle(action.action, action.resource, aws_params)
        results.append(ActionResult(
            action=action.action,
            resource=action.resource,
            response=mock_response.response if mock_response.success else {"error": mock_response.error},
        ))

    # Step 6: Record actions in session history (only after successful execution)
    for action in resolved_actions:
        deps.session_tracker.record(session_key, action.action)

    return ToolExecutionResponse(
        tool_name=request.tool_name,
        results=results,
    )
