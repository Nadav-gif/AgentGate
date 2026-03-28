"""Simulator runner — sets up the proxy and runs attack scenarios.

Three modes:
  mock  — FakePolicyFetcher with hardcoded policies (no AWS needed)
  real  — AwsPolicyFetcher with real AWS IAM, in-process via TestClient
  live  — real HTTP requests to a deployed proxy (Docker/Azure)

Usage:
  python -m agentgate.simulator --mode mock
  python -m agentgate.simulator --mode real --profile agentgate
  python -m agentgate.simulator --mode live --url http://localhost:8000
"""

from __future__ import annotations

import sys
import tempfile

from fastapi.testclient import TestClient

from agentgate.action_mapping.config_loader import load_config_from_dict
from agentgate.mock_aws.base import MockServiceRegistry
from agentgate.mock_aws.dynamodb import MockDynamoDB
from agentgate.mock_aws.s3 import MockS3
from agentgate.mock_aws.ses import MockSES
from agentgate.permission_engine.models import IdentityPolicies
from agentgate.proxy.app import create_app
from agentgate.proxy.audit import AuditLogger
from agentgate.proxy.auth import ApiKeyAuthenticator
from agentgate.proxy.dependencies import AppDependencies, FakePolicyFetcher
from agentgate.proxy.escalation import DEFAULT_ESCALATION_RULES
from agentgate.simulator.models import ScenarioResult
from agentgate.simulator.scenarios import (
    scenario_a_authorization_bypass,
    scenario_b_privilege_creep,
    scenario_c_cross_system_escalation,
)

# --- Constants ---

ALICE_ARN = "arn:aws:iam::123456789012:user/alice"
BOB_ARN = "arn:aws:iam::123456789012:user/bob"
AGENT_ROLE_ARN = "arn:aws:iam::123456789012:role/agent-service-role"


# --- Shared config ---


def _tool_mapping_config() -> dict:
    """Tool-to-AWS-action mapping used by both modes."""
    return {
        "version": "1",
        "account_id": "123456789012",
        "region": "us-east-1",
        "tools": {
            "read_file": {
                "aws_actions": [{"action": "s3:GetObject", "resource": "arn:aws:s3:::{bucket}/{key}"}],
                "required_args": ["bucket", "key"],
            },
            "write_file": {
                "aws_actions": [{"action": "s3:PutObject", "resource": "arn:aws:s3:::{bucket}/{key}"}],
                "required_args": ["bucket", "key"],
            },
            "query_database": {
                "aws_actions": [
                    {"action": "dynamodb:Query", "resource": "arn:aws:dynamodb:{region}:{account_id}:table/{table}"}
                ],
                "required_args": ["table"],
            },
            "send_email": {
                "aws_actions": [{"action": "ses:SendEmail", "resource": "*"}],
            },
        },
    }


def _api_keys() -> dict:
    """API key -> user mapping used by both modes."""
    return {
        "alice-key": {"user_arn": ALICE_ARN, "agent_id": "agent-alice"},
        "bob-key": {"user_arn": BOB_ARN, "agent_id": "agent-bob"},
    }


def _mock_services() -> MockServiceRegistry:
    """Set up mock AWS services with seeded test data."""
    registry = MockServiceRegistry()

    mock_s3 = MockS3()
    mock_s3.seed("reports", "q4.csv", "revenue,cost\n1000,500\n2000,800")
    mock_s3.register(registry)

    mock_dynamo = MockDynamoDB()
    mock_dynamo.seed("employees", [
        {"dept": {"S": "engineering"}, "name": {"S": "Alice"}, "salary": {"N": "120000"}},
        {"dept": {"S": "sales"}, "name": {"S": "Bob"}, "salary": {"N": "95000"}},
    ])
    mock_dynamo.register(registry)

    mock_ses = MockSES()
    mock_ses.register(registry)

    return registry


def _agent_role_policy() -> dict:
    """The agent role's IAM policy -- intentionally over-provisioned."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": ["dynamodb:Query", "dynamodb:Scan"],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": "ses:SendEmail",
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": "lambda:InvokeFunction",
                "Resource": "*",
            },
        ],
    }


# --- Mock mode ---


def _allow_policy(action, resource="*"):
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": action, "Resource": resource}],
    }


def _deny_policy(action, resource="*"):
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": action, "Resource": resource}],
    }


def create_mock_app() -> tuple[TestClient, AppDependencies]:
    """Create a fully configured proxy in mock mode.

    Uses FakePolicyFetcher with hardcoded IAM policies. No AWS needed.
    """
    fetcher = FakePolicyFetcher({
        # Alice: can read S3, query DynamoDB, send email
        ALICE_ARN: IdentityPolicies(inline_policies=[
            _allow_policy(["s3:GetObject", "s3:PutObject"]),
            _allow_policy("dynamodb:Query"),
            _allow_policy("ses:SendEmail"),
        ]),
        # Bob: can only query DynamoDB, explicitly denied S3
        BOB_ARN: IdentityPolicies(inline_policies=[
            _allow_policy("dynamodb:Query"),
            _deny_policy("s3:*"),
        ]),
        # Agent role: over-provisioned (for privilege creep detection)
        AGENT_ROLE_ARN: IdentityPolicies(inline_policies=[_agent_role_policy()]),
    })

    tmp_dir = tempfile.mkdtemp()
    deps = AppDependencies(
        authenticator=ApiKeyAuthenticator(_api_keys()),
        config=load_config_from_dict(_tool_mapping_config()),
        registry=_mock_services(),
        fetcher=fetcher,
        audit=AuditLogger(db_path=f"{tmp_dir}/simulator_audit.db"),
        escalation_rules=list(DEFAULT_ESCALATION_RULES),
    )

    app = create_app(deps)
    return TestClient(app), deps


# --- Real mode ---


def create_real_app(profile: str = "default") -> tuple[TestClient, AppDependencies]:
    """Create a proxy that checks permissions against real AWS IAM.

    Uses AwsPolicyFetcher with boto3 to pull actual IAM policies.
    Mock services are still used for execution (we don't want to
    actually send emails or delete S3 files during a demo).

    Requires:
    - AWS credentials configured (via profile, env vars, or IAM role)
    - IAM users alice and bob created with appropriate policies
    - See aws_setup.py for setup instructions
    """
    import boto3

    from agentgate.permission_engine.policy_fetcher import AwsPolicyFetcher

    session = boto3.Session(profile_name=profile)
    fetcher = AwsPolicyFetcher(session=session)

    tmp_dir = tempfile.mkdtemp()
    deps = AppDependencies(
        authenticator=ApiKeyAuthenticator(_api_keys()),
        config=load_config_from_dict(_tool_mapping_config()),
        registry=_mock_services(),
        fetcher=fetcher,
        audit=AuditLogger(db_path=f"{tmp_dir}/simulator_audit.db"),
        escalation_rules=list(DEFAULT_ESCALATION_RULES),
    )

    app = create_app(deps)
    return TestClient(app), deps


# --- Live mode ---


class LiveClient:
    """HTTP client that mimics TestClient's interface for live deployments.

    Makes real HTTP requests to a deployed proxy using httpx.
    """

    def __init__(self, base_url: str) -> None:
        import httpx

        self._base_url = base_url.rstrip("/")
        self._client = httpx.Client(base_url=self._base_url, timeout=30.0)

    def post(self, path: str, json: dict | None = None, headers: dict | None = None):
        return self._client.post(path, json=json, headers=headers)


# --- Report printing ---


def print_report(results: list[ScenarioResult]) -> None:
    """Print a formatted report of all scenario results."""
    all_passed = all(r.passed for r in results)

    print("\n" + "=" * 70)
    print("  AgentGate Attack Simulator -- Results")
    print("=" * 70)

    for scenario in results:
        status = "PASS" if scenario.passed else "FAIL"
        print(f"\n  [{status}] {scenario.name}")
        print(f"  {scenario.description}")
        print()

        for i, step in enumerate(scenario.steps, 1):
            icon = "+" if step.passed else "X"
            print(f"    {i}. [{icon}] {step.description}")
            print(f"       Expected: {step.expected}  |  Actual: {step.actual}  |  HTTP: {step.status_code}")
            if step.detail:
                # Truncate long details
                detail = step.detail if len(step.detail) <= 100 else step.detail[:97] + "..."
                print(f"       Detail: {detail}")

    print("\n" + "-" * 70)
    total = sum(len(s.steps) for s in results)
    passed = sum(1 for s in results for step in s.steps if step.passed)
    print(f"  Total steps: {total}  |  Passed: {passed}  |  Failed: {total - passed}")
    print(f"  Overall: {'ALL SCENARIOS PASSED' if all_passed else 'SOME SCENARIOS FAILED'}")
    print("-" * 70 + "\n")


# --- Main ---


def run(mode: str = "mock", profile: str = "default", url: str = "") -> list[ScenarioResult]:
    """Run all attack scenarios and return results.

    Args:
        mode: "mock", "real", or "live".
        profile: AWS profile name (only used in real mode).
        url: base URL of the deployed proxy (only used in live mode).
    """
    print(f"\nStarting AgentGate Attack Simulator (mode={mode})...\n")

    if mode == "live":
        if not url:
            print("ERROR: --url is required for live mode")
            sys.exit(1)
        client = LiveClient(url)
        # In live mode, deps is None — scenarios that need deps will skip
        deps = None
    elif mode == "real":
        client, deps = create_real_app(profile=profile)
    else:
        client, deps = create_mock_app()

    results = [
        scenario_a_authorization_bypass(client, deps),
        scenario_c_cross_system_escalation(client, deps),
    ]

    # Scenario B (privilege creep) requires access to deps for auditor tools.
    # In live mode we skip it since we can't access the server's internals.
    if deps is not None:
        results.insert(1, scenario_b_privilege_creep(client, deps))
    else:
        print("  [SKIP] Scenario B: Privilege Creep Detection (requires local deps, not available in live mode)\n")

    print_report(results)

    if deps is not None:
        deps.audit.close()
    return results


def main() -> None:
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="AgentGate Attack Simulator")
    parser.add_argument(
        "--mode",
        choices=["mock", "real", "live"],
        default="mock",
        help="mock = hardcoded policies, real = AWS IAM in-process, live = HTTP to deployed proxy",
    )
    parser.add_argument(
        "--profile",
        default="default",
        help="AWS profile name (only used with --mode real)",
    )
    parser.add_argument(
        "--url",
        default="",
        help="Base URL of deployed proxy (only used with --mode live, e.g. http://localhost:8000)",
    )
    args = parser.parse_args()

    results = run(mode=args.mode, profile=args.profile, url=args.url)
    sys.exit(0 if all(r.passed for r in results) else 1)
