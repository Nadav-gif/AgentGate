"""Integration tests for the auditor crew — verify wiring and configuration.

These tests verify that the crew is correctly assembled:
- Tools are attached to the right agents
- Tasks have correct context dependencies
- The crew is configured with sequential process
- The report parser handles various output formats

We do NOT call real LLMs here. The tests validate the data pipeline
(tools work with real data) and the structural wiring (agents, tasks, crew).

A fake OPENAI_API_KEY is set because CrewAI validates its presence when
constructing Agent objects, even though no LLM calls are made in these tests.
"""

import json
import os

import pytest
from crewai import Process

from tests.auditor.conftest import AGENT_ROLE_ARN


@pytest.fixture(autouse=True)
def _fake_openai_key(monkeypatch):
    """Set a fake API key so CrewAI can construct Agent objects without error."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-fake-key-for-testing")

from agentgate.auditor.agents import (
    create_log_analyzer,
    create_privilege_creep_detector,
    create_recommendation_agent,
)
from agentgate.auditor.crew import _parse_report, build_crew
from agentgate.auditor.models import Finding, SecurityReport
from agentgate.auditor.tools import (
    GetAccessSummaryTool,
    GetAgentRolePoliciesTool,
    GetDeniedRequestsTool,
    QueryAuditLogTool,
)


class TestCrewWiring:
    """Verify the crew is assembled correctly."""

    def test_crew_has_three_agents(self, audit_logger, policy_fetcher):
        crew = build_crew(audit_logger, policy_fetcher, AGENT_ROLE_ARN)
        assert len(crew.agents) == 3

    def test_crew_has_three_tasks(self, audit_logger, policy_fetcher):
        crew = build_crew(audit_logger, policy_fetcher, AGENT_ROLE_ARN)
        assert len(crew.tasks) == 3

    def test_crew_uses_sequential_process(self, audit_logger, policy_fetcher):
        crew = build_crew(audit_logger, policy_fetcher, AGENT_ROLE_ARN)
        assert crew.process == Process.sequential

    def test_log_analyzer_has_three_tools(self, audit_logger, policy_fetcher):
        crew = build_crew(audit_logger, policy_fetcher, AGENT_ROLE_ARN)
        log_analyzer = crew.agents[0]
        assert log_analyzer.role == "Security Log Analyst"
        assert len(log_analyzer.tools) == 3
        tool_names = {t.name for t in log_analyzer.tools}
        assert tool_names == {"query_audit_log", "get_denied_requests", "get_access_summary"}

    def test_privilege_detector_has_two_tools(self, audit_logger, policy_fetcher):
        crew = build_crew(audit_logger, policy_fetcher, AGENT_ROLE_ARN)
        detector = crew.agents[1]
        assert detector.role == "Privilege Creep Detector"
        assert len(detector.tools) == 2
        tool_names = {t.name for t in detector.tools}
        assert tool_names == {"get_agent_role_policies", "get_access_summary"}

    def test_recommendation_agent_has_no_tools(self, audit_logger, policy_fetcher):
        crew = build_crew(audit_logger, policy_fetcher, AGENT_ROLE_ARN)
        recommender = crew.agents[2]
        assert recommender.role == "Security Advisor"
        assert len(recommender.tools) == 0

    def test_recommendation_task_depends_on_both_previous(self, audit_logger, policy_fetcher):
        crew = build_crew(audit_logger, policy_fetcher, AGENT_ROLE_ARN)
        rec_task = crew.tasks[2]
        # The recommendation task should have context from both previous tasks
        assert len(rec_task.context) == 2

    def test_privilege_creep_task_depends_on_log_analysis(self, audit_logger, policy_fetcher):
        crew = build_crew(audit_logger, policy_fetcher, AGENT_ROLE_ARN)
        creep_task = crew.tasks[1]
        assert len(creep_task.context) == 1


class TestAgentCreation:
    """Verify agents are created with correct attributes."""

    def test_log_analyzer_attributes(self, audit_logger):
        tools = [
            QueryAuditLogTool(audit=audit_logger),
            GetDeniedRequestsTool(audit=audit_logger),
            GetAccessSummaryTool(audit=audit_logger),
        ]
        agent = create_log_analyzer(tools)
        assert agent.role == "Security Log Analyst"
        assert agent.allow_delegation is False
        assert len(agent.tools) == 3

    def test_privilege_detector_attributes(self, audit_logger, policy_fetcher):
        tools = [
            GetAgentRolePoliciesTool(fetcher=policy_fetcher),
            GetAccessSummaryTool(audit=audit_logger),
        ]
        agent = create_privilege_creep_detector(tools)
        assert agent.role == "Privilege Creep Detector"
        assert agent.allow_delegation is False
        assert len(agent.tools) == 2

    def test_recommendation_agent_attributes(self):
        agent = create_recommendation_agent()
        assert agent.role == "Security Advisor"
        assert agent.allow_delegation is False
        assert len(agent.tools) == 0

    def test_custom_llm_passed_through(self, audit_logger):
        tools = [QueryAuditLogTool(audit=audit_logger)]
        agent = create_log_analyzer(tools, llm="openai/gpt-4o-mini")
        # CrewAI converts the string to an LLM object at construction time
        assert agent.llm is not None


class TestReportParsing:
    """Verify _parse_report handles various output formats."""

    def test_parse_valid_json(self):
        raw = json.dumps({
            "risk_score": 7,
            "findings": [
                {
                    "severity": "HIGH",
                    "category": "unused_permission",
                    "user_arn": AGENT_ROLE_ARN,
                    "description": "s3:DeleteObject never used",
                    "recommendation": "Revoke s3:DeleteObject",
                },
            ],
            "summary": "Agent role has unused permissions.",
        })
        report = _parse_report(raw)
        assert report.risk_score == 7
        assert len(report.findings) == 1
        assert report.findings[0].severity == "HIGH"
        assert report.findings[0].category == "unused_permission"
        assert report.summary == "Agent role has unused permissions."

    def test_parse_json_in_markdown_block(self):
        raw = '```json\n{"risk_score": 3, "findings": [], "summary": "Low risk."}\n```'
        report = _parse_report(raw)
        assert report.risk_score == 3
        assert report.summary == "Low risk."

    def test_parse_json_in_generic_code_block(self):
        raw = '```\n{"risk_score": 5, "findings": [], "summary": "Moderate."}\n```'
        report = _parse_report(raw)
        assert report.risk_score == 5

    def test_parse_invalid_json_returns_raw_as_summary(self):
        raw = "This is not JSON, just a plain text response from the LLM."
        report = _parse_report(raw)
        assert report.risk_score == 5  # default
        assert report.findings == []
        assert report.summary == raw

    def test_parse_partial_json_uses_defaults(self):
        raw = json.dumps({"risk_score": 8})
        report = _parse_report(raw)
        assert report.risk_score == 8
        assert report.findings == []
        assert report.summary == ""

    def test_parse_findings_with_missing_fields(self):
        raw = json.dumps({
            "risk_score": 6,
            "findings": [{"severity": "LOW", "description": "minor issue"}],
            "summary": "ok",
        })
        report = _parse_report(raw)
        assert len(report.findings) == 1
        assert report.findings[0].severity == "LOW"
        assert report.findings[0].category == "unknown"  # default
        assert report.findings[0].user_arn == ""  # default


class TestModels:
    """Verify the data models work correctly."""

    def test_finding_creation(self):
        f = Finding(
            severity="HIGH",
            category="unused_permission",
            user_arn=AGENT_ROLE_ARN,
            description="test",
            recommendation="fix it",
        )
        assert f.severity == "HIGH"
        assert f.category == "unused_permission"

    def test_security_report_defaults(self):
        report = SecurityReport(risk_score=5)
        assert report.risk_score == 5
        assert report.findings == []
        assert report.summary == ""
        assert report.generated_at  # should have a timestamp

    def test_security_report_with_findings(self):
        findings = [
            Finding("HIGH", "unused_permission", AGENT_ROLE_ARN, "desc", "rec"),
            Finding("LOW", "denial_spike", AGENT_ROLE_ARN, "desc2", "rec2"),
        ]
        report = SecurityReport(risk_score=7, findings=findings, summary="Bad")
        assert len(report.findings) == 2
        assert report.risk_score == 7
