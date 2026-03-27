"""Tests for attack simulator scenarios.

Runs each scenario in mock mode and verifies AgentGate
correctly catches all three attack types.
"""

from agentgate.simulator.runner import create_mock_app
from agentgate.simulator.scenarios import (
    scenario_a_authorization_bypass,
    scenario_b_privilege_creep,
    scenario_c_cross_system_escalation,
)


class TestScenarioA:
    """Authorization bypass — restricted user blocked from S3 access."""

    def test_scenario_passes(self):
        client, deps = create_mock_app()
        result = scenario_a_authorization_bypass(client, deps)
        assert result.passed is True
        assert result.name == "Scenario A: Authorization Bypass"

    def test_bob_dynamodb_allowed(self):
        client, deps = create_mock_app()
        result = scenario_a_authorization_bypass(client, deps)
        step = result.steps[0]
        assert step.passed is True
        assert step.actual == "ALLOW"

    def test_bob_s3_denied(self):
        client, deps = create_mock_app()
        result = scenario_a_authorization_bypass(client, deps)
        step = result.steps[1]
        assert step.passed is True
        assert step.actual == "DENY"
        assert step.status_code == 403

    def test_alice_s3_allowed(self):
        client, deps = create_mock_app()
        result = scenario_a_authorization_bypass(client, deps)
        step = result.steps[2]
        assert step.passed is True
        assert step.actual == "ALLOW"

    def test_has_three_steps(self):
        client, deps = create_mock_app()
        result = scenario_a_authorization_bypass(client, deps)
        assert len(result.steps) == 3


class TestScenarioB:
    """Privilege creep detection — unused agent permissions identified."""

    def test_scenario_passes(self):
        client, deps = create_mock_app()
        result = scenario_b_privilege_creep(client, deps)
        assert result.passed is True

    def test_normal_usage_allowed(self):
        client, deps = create_mock_app()
        result = scenario_b_privilege_creep(client, deps)
        # First 3 steps are normal usage — should all pass
        for step in result.steps[:3]:
            assert step.passed is True
            assert step.actual == "ALLOW"

    def test_unused_permissions_detected(self):
        client, deps = create_mock_app()
        result = scenario_b_privilege_creep(client, deps)
        creep_step = result.steps[3]
        assert creep_step.passed is True
        assert creep_step.actual == "CREEP_DETECTED"
        # Should mention specific unused permissions
        assert "s3:DeleteObject" in creep_step.detail
        assert "lambda:InvokeFunction" in creep_step.detail

    def test_has_four_steps(self):
        client, deps = create_mock_app()
        result = scenario_b_privilege_creep(client, deps)
        assert len(result.steps) == 4


class TestScenarioC:
    """Cross-system escalation — read-then-send blocked."""

    def test_scenario_passes(self):
        client, deps = create_mock_app()
        result = scenario_c_cross_system_escalation(client, deps)
        assert result.passed is True

    def test_email_alone_allowed(self):
        client, deps = create_mock_app()
        result = scenario_c_cross_system_escalation(client, deps)
        step = result.steps[0]
        assert step.passed is True
        assert step.actual == "ALLOW"

    def test_read_allowed(self):
        client, deps = create_mock_app()
        result = scenario_c_cross_system_escalation(client, deps)
        step = result.steps[1]
        assert step.passed is True
        assert step.actual == "ALLOW"

    def test_send_after_read_blocked(self):
        client, deps = create_mock_app()
        result = scenario_c_cross_system_escalation(client, deps)
        step = result.steps[2]
        assert step.passed is True
        assert step.actual == "DENY"
        assert step.status_code == 403
        assert "escalation" in step.detail.lower()

    def test_has_three_steps(self):
        client, deps = create_mock_app()
        result = scenario_c_cross_system_escalation(client, deps)
        assert len(result.steps) == 3


class TestRunner:
    """Test the runner's mock mode end-to-end."""

    def test_all_scenarios_pass_in_mock_mode(self):
        from agentgate.simulator.runner import run

        results = run(mode="mock")
        assert all(r.passed for r in results)
        assert len(results) == 3
