"""
The main permission evaluator — can_do() answers "is this action allowed?"

Evaluation order follows the real AWS IAM logic:
1. Parse all identity policies into allow/deny lists
2. Explicit deny → DENY
3. SCP evaluation → must allow, any deny blocks
4. Permission boundary → intersect with allows
5. Remaining allows → ALLOW
6. Otherwise → IMPLICIT_DENY
"""

from __future__ import annotations

import logging

from agentgate.permission_engine.models import Decision, EvaluationResult, PolicyLists
from agentgate.permission_engine.policy_fetcher import PolicyFetcherProtocol
from agentgate.permission_engine.policy_parser import (
    get_matching_resources,
    parse_policy_document,
)

logger = logging.getLogger(__name__)


def can_do(user_arn: str, action: str, resource: str, fetcher: PolicyFetcherProtocol) -> EvaluationResult:
    """Evaluate whether an IAM identity can perform an action on a resource.

    Args:
        user_arn: ARN of the IAM user or role.
        action: AWS action (e.g., 's3:GetObject').
        resource: AWS resource ARN.
        fetcher: a PolicyFetcherProtocol implementation for retrieving policies.

    Returns:
        EvaluationResult with decision, reason, and context.
    """
    identity_policies = fetcher.get_identity_policies(user_arn)

    # Step 1: Parse all policy documents into a single PolicyLists
    combined = PolicyLists()
    for doc in identity_policies.inline_policies + identity_policies.managed_policies:
        combined.merge(parse_policy_document(doc))

    # Step 2: Check explicit deny
    deny_matches = get_matching_resources(action, resource, combined.denies)
    if deny_matches:
        reason = f"Explicit deny: {deny_matches[0].action} on {deny_matches[0].resource}"
        logger.info(
            "Permission DENIED",
            extra={"user_arn": user_arn, "action": action, "resource": resource, "decision": "DENY", "reason": reason},
        )
        return EvaluationResult(
            decision=Decision.DENY,
            reason=reason,
            action=action,
            resource=resource,
            user_arn=user_arn,
        )

    # Step 3: SCP evaluation (if available)
    if identity_policies.scps:
        scp_allowed = False
        for scp_doc in identity_policies.scps:
            scp_lists = parse_policy_document(scp_doc)
            # SCP deny takes precedence
            scp_deny_matches = get_matching_resources(action, resource, scp_lists.denies)
            if scp_deny_matches:
                reason = f"SCP explicit deny: {scp_deny_matches[0].action} on {scp_deny_matches[0].resource}"
                logger.info(
                    "Permission DENIED by SCP",
                    extra={
                        "user_arn": user_arn,
                        "action": action,
                        "resource": resource,
                        "decision": "DENY",
                        "reason": reason,
                    },
                )
                return EvaluationResult(
                    decision=Decision.DENY,
                    reason=reason,
                    action=action,
                    resource=resource,
                    user_arn=user_arn,
                )
            # SCP must explicitly allow
            if get_matching_resources(action, resource, scp_lists.allows):
                scp_allowed = True

        if not scp_allowed:
            reason = "No SCP allows this action"
            logger.info(
                "Permission IMPLICIT_DENY by SCP",
                extra={
                    "user_arn": user_arn,
                    "action": action,
                    "resource": resource,
                    "decision": "IMPLICIT_DENY",
                    "reason": reason,
                },
            )
            return EvaluationResult(
                decision=Decision.IMPLICIT_DENY,
                reason=reason,
                action=action,
                resource=resource,
                user_arn=user_arn,
            )

    # Step 4: Check allows
    allow_matches = get_matching_resources(action, resource, combined.allows)

    # Step 5: Permission boundary — the boundary must also allow this action+resource
    if allow_matches and identity_policies.permission_boundary:
        boundary_lists = parse_policy_document(identity_policies.permission_boundary)
        boundary_matches = get_matching_resources(action, resource, boundary_lists.allows)
        if not boundary_matches:
            reason = "Permission boundary does not allow this action"
            logger.info(
                "Permission IMPLICIT_DENY by boundary",
                extra={
                    "user_arn": user_arn,
                    "action": action,
                    "resource": resource,
                    "decision": "IMPLICIT_DENY",
                    "reason": reason,
                },
            )
            return EvaluationResult(
                decision=Decision.IMPLICIT_DENY,
                reason=reason,
                action=action,
                resource=resource,
                user_arn=user_arn,
            )

    # Step 6: Check allows
    if allow_matches:
        reason = f"Allowed by: {allow_matches[0].action} on {allow_matches[0].resource}"
        logger.info(
            "Permission ALLOWED",
            extra={
                "user_arn": user_arn,
                "action": action,
                "resource": resource,
                "decision": "ALLOW",
                "reason": reason,
            },
        )
        return EvaluationResult(
            decision=Decision.ALLOW,
            reason=reason,
            action=action,
            resource=resource,
            user_arn=user_arn,
        )

    # Step 6: Implicit deny
    reason = "No policy grants this permission"
    logger.info(
        "Permission IMPLICIT_DENY",
        extra={
            "user_arn": user_arn,
            "action": action,
            "resource": resource,
            "decision": "IMPLICIT_DENY",
            "reason": reason,
        },
    )
    return EvaluationResult(
        decision=Decision.IMPLICIT_DENY,
        reason=reason,
        action=action,
        resource=resource,
        user_arn=user_arn,
    )
