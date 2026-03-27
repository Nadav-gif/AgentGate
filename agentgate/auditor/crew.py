"""CrewAI crew orchestration for the permission auditor.

This is the entry point for running the audit. It wires together the tools,
agents, and tasks, then kicks off the crew in sequential mode:

1. Log Analyzer runs first — queries audit logs, finds patterns
2. Privilege Creep Detector runs second — compares policies vs usage
3. Recommendation Agent runs last — gets both outputs, produces report

Usage:
    report = run_audit(audit_logger, policy_fetcher, agent_role_arn)
"""

from __future__ import annotations

import json
import logging

from crewai import Crew, Process

from agentgate.auditor.agents import (
    create_log_analyzer,
    create_privilege_creep_detector,
    create_recommendation_agent,
)
from agentgate.auditor.models import Finding, SecurityReport
from agentgate.auditor.tasks import (
    create_log_analysis_task,
    create_privilege_creep_task,
    create_recommendation_task,
)
from agentgate.auditor.tools import (
    GetAccessSummaryTool,
    GetAgentRolePoliciesTool,
    GetDeniedRequestsTool,
    QueryAuditLogTool,
)
from agentgate.permission_engine.policy_fetcher import PolicyFetcherProtocol
from agentgate.proxy.audit import AuditLogger

logger = logging.getLogger(__name__)


def _parse_report(raw_output: str) -> SecurityReport:
    """Parse the crew's raw output into a SecurityReport.

    The recommendation agent returns JSON, but LLM output can be messy.
    This does best-effort parsing with sensible defaults.
    """
    try:
        # Try to extract JSON from the output (LLMs sometimes wrap in markdown)
        text = raw_output.strip()
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()

        data = json.loads(text)

        findings = []
        for f in data.get("findings", []):
            findings.append(Finding(
                severity=f.get("severity", "MEDIUM"),
                category=f.get("category", "unknown"),
                user_arn=f.get("user_arn", ""),
                description=f.get("description", ""),
                recommendation=f.get("recommendation", ""),
            ))

        return SecurityReport(
            risk_score=int(data.get("risk_score", 5)),
            findings=findings,
            summary=data.get("summary", ""),
        )
    except (json.JSONDecodeError, KeyError, ValueError):
        logger.warning("Could not parse crew output as JSON, returning raw output as summary")
        return SecurityReport(
            risk_score=5,
            findings=[],
            summary=raw_output,
        )


def build_crew(
    audit: AuditLogger,
    fetcher: PolicyFetcherProtocol,
    agent_role_arn: str,
    llm: str | None = None,
) -> Crew:
    """Build the auditor crew with all tools, agents, and tasks wired together.

    Args:
        audit: the audit logger to query for decision history.
        fetcher: policy fetcher to pull the agent role's IAM permissions.
        agent_role_arn: the ARN of the agent role to analyze.
        llm: optional LLM model string (e.g. "openai/gpt-4o"). If None, uses CrewAI default.

    Returns:
        A configured Crew ready to kick off.
    """
    # Step 1: Create tools with injected dependencies
    query_audit_tool = QueryAuditLogTool(audit=audit)
    denied_tool = GetDeniedRequestsTool(audit=audit)
    summary_tool = GetAccessSummaryTool(audit=audit)
    policies_tool = GetAgentRolePoliciesTool(fetcher=fetcher)

    # Step 2: Create agents with their tools
    log_analyzer = create_log_analyzer(
        tools=[query_audit_tool, denied_tool, summary_tool],
        llm=llm,
    )
    privilege_detector = create_privilege_creep_detector(
        tools=[policies_tool, summary_tool],
        llm=llm,
    )
    recommender = create_recommendation_agent(llm=llm)

    # Step 3: Create tasks (sequential — each depends on the previous)
    log_task = create_log_analysis_task(log_analyzer, agent_role_arn)
    creep_task = create_privilege_creep_task(privilege_detector, agent_role_arn, log_task)
    rec_task = create_recommendation_task(recommender, agent_role_arn, log_task, creep_task)

    # Step 4: Assemble the crew
    return Crew(
        agents=[log_analyzer, privilege_detector, recommender],
        tasks=[log_task, creep_task, rec_task],
        process=Process.sequential,
        verbose=False,
    )


def run_audit(
    audit: AuditLogger,
    fetcher: PolicyFetcherProtocol,
    agent_role_arn: str,
    llm: str | None = None,
) -> SecurityReport:
    """Run the full permission audit and return a security report.

    This is the main entry point. It builds the crew, kicks it off,
    and parses the output into a SecurityReport.

    Args:
        audit: the audit logger to query for decision history.
        fetcher: policy fetcher to pull the agent role's IAM permissions.
        agent_role_arn: the ARN of the agent role to analyze.
        llm: optional LLM model string. If None, uses CrewAI default.

    Returns:
        A SecurityReport with risk score, findings, and recommendations.
    """
    logger.info("Starting permission audit for %s", agent_role_arn)

    crew = build_crew(audit, fetcher, agent_role_arn, llm=llm)
    result = crew.kickoff()

    report = _parse_report(result.raw)
    logger.info("Audit complete — risk score: %d, findings: %d", report.risk_score, len(report.findings))
    return report
