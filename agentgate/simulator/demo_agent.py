"""Demo AI agent — shows what an agent looks like from the user's perspective.

This simulates an AI agent that receives a user task and makes tool calls
through the AgentGate proxy. The proxy checks whether the USER who launched
the agent has permission for each action.

Usage:
  # Bob's agent tries to read S3 (will be blocked):
  python -m agentgate.simulator.demo_agent --user bob --task "read the Q4 report"

  # Alice's agent does the same (will succeed):
  python -m agentgate.simulator.demo_agent --user alice --task "read the Q4 report"
"""

from __future__ import annotations

import json
import sys

import httpx

# API keys map users to their IAM identity — this is how AgentGate knows
# which user launched the agent. The agent includes this key in every request.
USER_API_KEYS = {
    "alice": "alice-key",
    "bob": "bob-key",
}

DEFAULT_URL = "http://localhost:8000"


def agent_execute(base_url: str, api_key: str, tool_name: str, tool_args: dict) -> dict:
    """Make a tool call through the AgentGate proxy."""
    resp = httpx.post(
        f"{base_url}/execute-tool",
        json={"tool_name": tool_name, "tool_args": tool_args},
        headers={"X-API-Key": api_key},
        timeout=10.0,
    )
    return {"status_code": resp.status_code, "body": resp.json()}


def run_agent(user: str, task: str, base_url: str = DEFAULT_URL) -> None:
    """Simulate an AI agent reasoning about a task and making tool calls."""
    api_key = USER_API_KEYS.get(user)
    if not api_key:
        print(f"Unknown user: {user}")
        sys.exit(1)

    print(f"\n{'=' * 60}")
    print(f"  AI Agent started by: {user}")
    print(f"  Task: \"{task}\"")
    print(f"  Proxy: {base_url}")
    print(f"{'=' * 60}\n")

    # The agent "reasons" about the task and decides what tools to call
    if "report" in task.lower() or "read" in task.lower():
        print("[Agent] I need to read the Q4 report from S3.\n")

        print("[Agent] Calling tool: read_file(bucket='reports', key='q4.csv')")
        print(f"[Agent] Sending request to AgentGate proxy with {user}'s API key...\n")

        result = agent_execute(base_url, api_key, "read_file", {
            "bucket": "reports",
            "key": "q4.csv",
        })

        if result["status_code"] == 200:
            print(f"[Proxy] Status: 200 ALLOWED")
            data = result["body"].get("results", [{}])[0].get("response", {})
            print(f"[Proxy] Response: {json.dumps(data, indent=2)[:200]}")
            print(f"\n[Agent] Got the report data. Task complete.")
        else:
            detail = result["body"].get("detail", {})
            reason = detail.get("reason", "Unknown")
            print(f"[Proxy] Status: 403 DENIED")
            print(f"[Proxy] Reason: {reason}")
            print(f"\n[Agent] I was blocked from reading the file.")
            print(f"[Agent] AgentGate checked {user}'s IAM permissions and denied the request.")

    elif "email" in task.lower() or "send" in task.lower():
        print("[Agent] I need to query the database first, then send the results by email.\n")

        # Step 1: Query DynamoDB
        print("[Agent] Step 1: Calling tool: query_database(table='employees')")
        result = agent_execute(base_url, api_key, "query_database", {"table": "employees"})

        if result["status_code"] == 200:
            print(f"[Proxy] Status: 200 ALLOWED\n")
        else:
            print(f"[Proxy] Status: 403 DENIED\n")
            return

        # Step 2: Send email (should be blocked by escalation)
        print("[Agent] Step 2: Calling tool: send_email()")
        result = agent_execute(base_url, api_key, "send_email", {
            "Source": "agent@company.com",
            "Destination": "external@partner.com",
            "Message": "Employee data attached",
        })

        if result["status_code"] == 200:
            print(f"[Proxy] Status: 200 ALLOWED")
            print(f"\n[Agent] Email sent. Task complete.")
        else:
            detail = result["body"].get("detail", {})
            reason = detail.get("reason", "Unknown")
            print(f"[Proxy] Status: 403 DENIED")
            print(f"[Proxy] Reason: {reason}")
            print(f"\n[Agent] I was blocked from sending the email.")
            print(f"[Agent] AgentGate detected a dangerous cross-system pattern.")

    print()


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Demo AI Agent")
    parser.add_argument("--user", required=True, choices=["alice", "bob"])
    parser.add_argument("--task", required=True)
    parser.add_argument("--url", default=DEFAULT_URL)
    args = parser.parse_args()

    run_agent(args.user, args.task, args.url)


if __name__ == "__main__":
    main()
