"""CrewAI agent definitions for the permission auditor.

Three specialized agents that work together to detect privilege creep:

1. Log Analyzer — reads audit logs, finds access patterns and anomalies
2. Privilege Creep Detector — compares agent role permissions vs actual usage
3. Recommendation Agent — synthesizes findings into an actionable report
"""

from __future__ import annotations

from crewai import Agent
from crewai.tools import BaseTool


def create_log_analyzer(tools: list[BaseTool], llm: str | None = None) -> Agent:
    """Create the log analyzer agent.

    This agent reads audit logs from the proxy and identifies patterns:
    - Which AWS actions are being called, by whom, how often
    - Denial spikes (could indicate probing of agent capabilities)
    - Unusual resource access patterns
    """
    kwargs: dict = {
        "role": "Security Log Analyst",
        "goal": (
            "Analyze the permission proxy audit logs to identify access patterns and anomalies. "
            "Focus on: which AWS actions the agent actually performs, how often each action is used, "
            "which requests get denied and why, and any unusual patterns like denial spikes "
            "or sudden access to new resources."
        ),
        "backstory": (
            "You are a security analyst specializing in AI agent behavior monitoring. "
            "You review audit logs from AgentGate, a permission proxy that sits between "
            "AI agents and AWS services. Every tool call the agent makes is logged with "
            "the AWS action, the resource, and whether it was allowed or denied. "
            "Your job is to spot anomalies that could indicate security problems."
        ),
        "tools": tools,
        "verbose": False,
        "allow_delegation": False,
    }
    if llm is not None:
        kwargs["llm"] = llm
    return Agent(**kwargs)


def create_privilege_creep_detector(tools: list[BaseTool], llm: str | None = None) -> Agent:
    """Create the privilege creep detector agent.

    This agent compares what the agent role CAN do (IAM policies) against
    what it ACTUALLY does (audit logs). The gap is privilege creep —
    permissions that exist on the role but are never used by any user
    through the proxy. These are unnecessary attack surface.
    """
    kwargs: dict = {
        "role": "Privilege Creep Detector",
        "goal": (
            "Compare the agent role's granted IAM permissions against actual usage from audit logs. "
            "Identify permissions that are granted to the agent role but never exercised through the proxy. "
            "These unused permissions are unnecessary attack surface — if the agent is compromised, "
            "the attacker gets access to everything the role allows, including unused permissions."
        ),
        "backstory": (
            "You are a cloud security specialist focused on the principle of least privilege. "
            "AI agents accumulate permissions over time as new features are added, but old "
            "permissions are never revoked. You cross-reference the agent role's IAM policies "
            "with the proxy's audit logs to find permissions that can safely be removed."
        ),
        "tools": tools,
        "verbose": False,
        "allow_delegation": False,
    }
    if llm is not None:
        kwargs["llm"] = llm
    return Agent(**kwargs)


def create_recommendation_agent(llm: str | None = None) -> Agent:
    """Create the recommendation agent.

    This agent receives findings from the other two agents and synthesizes
    them into an actionable security report with risk score, findings,
    and specific recommendations for reducing the agent's blast radius.

    It has no tools — it works purely from the context provided by the
    log analyzer and privilege creep detector.
    """
    kwargs: dict = {
        "role": "Security Advisor",
        "goal": (
            "Synthesize the findings from the log analysis and privilege creep detection "
            "into an actionable security report. Assign a risk score from 1-10, list the "
            "top findings ranked by severity, and provide specific recommendations for "
            "reducing the agent role's blast radius (which permissions to revoke, which "
            "access patterns to investigate)."
        ),
        "backstory": (
            "You are a senior security advisor who reviews findings from security analysts "
            "and produces executive-level reports. You translate technical findings into "
            "clear recommendations. Your reports help teams decide which agent permissions "
            "to revoke and which access patterns need investigation."
        ),
        "tools": [],
        "verbose": False,
        "allow_delegation": False,
    }
    if llm is not None:
        kwargs["llm"] = llm
    return Agent(**kwargs)
