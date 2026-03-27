"""CrewAI task definitions for the permission auditor.

Each task is a specific instruction for one agent. Tasks run sequentially:
1. Log analysis — produces access pattern findings
2. Privilege creep detection — produces unused permission findings
3. Recommendation — consumes both, produces final SecurityReport
"""

from __future__ import annotations

from crewai import Agent, Task


def create_log_analysis_task(agent: Agent, agent_role_arn: str) -> Task:
    """Create the log analysis task.

    Instructs the log analyzer to query the audit log and find anomalies.
    """
    return Task(
        description=(
            f"Analyze the audit logs for the agent role '{agent_role_arn}'. "
            "Use the query_audit_log and get_denied_requests tools to examine "
            "the proxy's decision history. Then use get_access_summary for an "
            "overview of access patterns.\n\n"
            "Identify:\n"
            "1. Which AWS actions the agent actually performs and how frequently\n"
            "2. Any denied request spikes (could indicate someone probing the agent)\n"
            "3. Unusual resource access patterns (new resources never seen before)\n"
            "4. Users whose requests are frequently denied\n\n"
            "Return your findings as a structured list with severity (HIGH/MEDIUM/LOW), "
            "a description of each finding, and what it means for security."
        ),
        expected_output=(
            "A structured analysis containing:\n"
            "- List of all AWS actions used by the agent with frequencies\n"
            "- Any anomalies detected (denial spikes, unusual access)\n"
            "- Each finding with severity level and description"
        ),
        agent=agent,
    )


def create_privilege_creep_task(
    agent: Agent,
    agent_role_arn: str,
    log_analysis_task: Task,
) -> Task:
    """Create the privilege creep detection task.

    Instructs the detector to compare granted permissions vs actual usage.
    Receives the log analysis as context so it knows what actions are actually used.
    """
    return Task(
        description=(
            f"Detect privilege creep for the agent role '{agent_role_arn}'.\n\n"
            "Step 1: Use get_agent_role_policies to fetch the agent role's IAM policies. "
            "This shows every AWS action the agent is allowed to perform.\n\n"
            "Step 2: Use get_access_summary to see which actions the agent actually uses.\n\n"
            "Step 3: Compare the two. Any permission in the IAM policy that never appears "
            "in the audit logs is an unused permission — privilege creep. These are "
            "unnecessary attack surface.\n\n"
            "For each unused permission, explain:\n"
            "- What the permission allows (e.g., 's3:DeleteObject lets the agent delete S3 files')\n"
            "- Why it's a risk (if the agent is compromised, this permission is available to attackers)\n"
            "- Recommendation: revoke it to reduce blast radius"
        ),
        expected_output=(
            "A structured list of:\n"
            "- All permissions granted to the agent role\n"
            "- Which permissions are actively used (with evidence from audit logs)\n"
            "- Which permissions are unused (privilege creep)\n"
            "- For each unused permission: severity, risk description, and recommendation"
        ),
        agent=agent,
        context=[log_analysis_task],
    )


def create_recommendation_task(
    agent: Agent,
    agent_role_arn: str,
    log_analysis_task: Task,
    privilege_creep_task: Task,
) -> Task:
    """Create the recommendation task.

    Synthesizes findings from both previous tasks into a final report.
    Uses output_json to return structured data matching SecurityReport.
    """
    return Task(
        description=(
            "Based on the log analysis and privilege creep findings, generate a "
            f"security report for the agent role '{agent_role_arn}'.\n\n"
            "Your report must include:\n"
            "1. risk_score: An integer from 1 (low risk) to 10 (critical). Base this on:\n"
            "   - Number of unused permissions (more = higher risk)\n"
            "   - Severity of unused permissions (write/delete > read)\n"
            "   - Any anomalies detected in access patterns\n"
            "2. findings: A list of findings, each with:\n"
            "   - severity: HIGH, MEDIUM, or LOW\n"
            "   - category: 'unused_permission', 'denial_spike', 'anomalous_access', etc.\n"
            "   - user_arn: the relevant identity\n"
            "   - description: what the issue is\n"
            "   - recommendation: what to do about it\n"
            "3. summary: A brief narrative summarizing the overall security posture\n\n"
            "Format your response as a JSON object with keys: "
            "risk_score, findings, summary."
        ),
        expected_output=(
            "A JSON object with:\n"
            '- "risk_score": integer 1-10\n'
            '- "findings": list of objects with severity, category, user_arn, description, recommendation\n'
            '- "summary": string with overall assessment'
        ),
        agent=agent,
        context=[log_analysis_task, privilege_creep_task],
    )
