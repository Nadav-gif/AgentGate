"""Data models for the attack simulator output."""

from dataclasses import dataclass, field


@dataclass
class StepResult:
    """Outcome of one step in an attack scenario.

    Attributes:
        description: what the step does (e.g. "Bob reads S3 file").
        expected: what should happen ("ALLOW" or "DENY").
        actual: what actually happened.
        status_code: HTTP status code from the proxy.
        passed: whether the outcome matched the expectation.
        detail: additional info (denial reason, response data, etc.).
    """

    description: str
    expected: str
    actual: str
    status_code: int
    passed: bool
    detail: str = ""


@dataclass
class ScenarioResult:
    """Outcome of a full attack scenario.

    Attributes:
        name: scenario identifier (e.g. "Authorization Bypass").
        description: what the scenario demonstrates.
        passed: whether AgentGate correctly handled all steps.
        steps: individual step outcomes.
    """

    name: str
    description: str
    passed: bool = True
    steps: list[StepResult] = field(default_factory=list)

    def add_step(self, step: StepResult) -> None:
        """Add a step result and update overall pass/fail."""
        self.steps.append(step)
        if not step.passed:
            self.passed = False
