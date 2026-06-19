# AgentGate

AgentGate (`agentgate`) is a security gateway that sits between your AI agents and AWS. It makes sure an AI agent can **never do more than the actual user who asked it to** — checking every action against that user's real AWS IAM permissions, in real time, before it runs.

The problem it solves is simple but serious. In normal cloud security every action is tied to a person: you log in, the cloud checks *your* permissions, and *you* show up in the audit log. AI agents break this. An agent runs with **its own** credentials — usually broad ones, because the same agent serves a whole team. So when a junior employee asks an agent to "pull the revenue report," the agent reads it with the *agent's* wide permissions, not the employee's narrow ones. The employee just saw data they were never allowed to see, and the audit log only shows the agent. Security researchers call this the **confused-deputy problem**.

AgentGate closes that gap. Every tool call an agent makes is intercepted and evaluated against the **requesting user's** IAM policies (including explicit denies, Organization SCPs, and permission boundaries). If the user couldn't do it themselves, the agent can't do it on their behalf — and every decision is logged back to the real user.

```
   User → AI Agent ──tool call + user's API key──▶  ┌──────────────────────────────┐
                                                    │          AgentGate           │
                                                    │  1. Who is the user?         │
                                                    │  2. What AWS action is this? │ ──▶ AWS IAM
                                                    │  3. Is the USER allowed?     │     (real perms)
                                                    │  4. Allow → run | Deny → 403 │
                                                    │  5. Log it to the audit trail│
                                                    └──────────────────────────────┘
```

## Features

1. **User-permission enforcement (the proxy)**:
   - Intercepts every agent tool call and checks it against the *user's* AWS IAM permissions before it runs — not the agent's.
   - Re-implements the real AWS IAM decision logic: explicit `Deny`, Organization SCPs, permission boundaries, and identity policies.
   - Answers the question: *"This user could not read the `hr-salaries` table themselves — should the agent be allowed to do it for them?"* (No.)

2. **Cross-system escalation detection**:
   - Tracks the *sequence* of actions inside a single user session and blocks dangerous chains, even when each individual step is allowed.
   - Example: reading sensitive data and then emailing it externally in the same session is blocked as data exfiltration.
   - Answers questions such as: *"The agent read the customer database and is now trying to send an external email — is this an exfiltration attempt?"*

3. **Privilege-creep auditor (multi-agent)**:
   - A background system (built with CrewAI) that compares what the agent role is *allowed* to do against what it has *actually* done, and recommends which unused permissions to revoke.
   - Produces a security report with a risk score and concrete recommendations.
   - Answers questions such as: *"The agent role can delete S3 objects but never has — should we remove that permission to shrink the blast radius?"*

4. **Full audit trail**:
   - Every decision is written to a database with the real user, the agent, the tool, the AWS action and resource, the result, and the reason — so the audit log always traces back to the person who initiated the request.

## How it works

When an agent makes a tool call, AgentGate runs it through this pipeline:

1. **Authenticate** — the request carries the user's API key, which maps to that user's IAM identity (ARN). AgentGate now knows *who* is really behind the request.
2. **Resolve** — the tool call (e.g. `read_file(bucket="reports", key="q4.csv")`) is translated into the AWS action and resource it needs (`s3:GetObject` on `arn:aws:s3:::reports/q4.csv`).
3. **Check permissions** — AgentGate evaluates whether *that user* is allowed to perform *that action* on *that resource*, using their real IAM policies.
4. **Check for escalation** — the action is checked against the session history for dangerous cross-system patterns.
5. **Enforce** — if anything is denied, the agent gets back an HTTP `403` with a clear reason. If everything passes, the action runs.
6. **Audit** — the decision is logged with full attribution.

## Installation

To install `agentgate`, clone the repository and install the dependencies:

```bash
git clone https://github.com/Nadav-gif/AgentGate.git
cd AgentGate
pip install -e ".[dev]"
```

## Quick demo (no AWS account needed)

The fastest way to see AgentGate work is the built-in attack simulator. It spins up the gateway with example users and runs the three attack scenarios, showing what gets allowed and what gets blocked:

```bash
python -m agentgate.simulator --mode mock
```

You'll see a report where a restricted user is blocked from reading S3 (while an allowed user succeeds), the auditor flags unused agent permissions, and a read-then-email exfiltration chain is blocked.

## Running it as a service (Docker)

This is how you deploy AgentGate as a running server that your agents talk to.

**1. Configure it.** Copy the example environment file and edit it:

```bash
cp .env.example .env
```

In `.env` you set the mode and the user→identity mapping:

```bash
# "mock" = demo policies, no AWS needed.  "real" = check against your live AWS IAM.
AGENTGATE_MODE=mock

# Which API key belongs to which AWS user. This is how AgentGate knows
# who is really behind each agent request.
AGENTGATE_API_KEYS={"alice-key": {"user_arn": "arn:aws:iam::123456789012:user/alice", "agent_id": "agent-1"}}
```

**2. Start it.**

```bash
docker compose up --build
```

The gateway is now live at `http://localhost:8000`. That's it — it's ready to receive tool calls.

**3. Send a tool call.** Each request includes the user's API key in the `X-API-Key` header. AgentGate checks *that user's* permissions:

```bash
# alice is allowed to read S3 → 200 OK, returns the data
curl -X POST http://localhost:8000/execute-tool \
  -H "X-API-Key: alice-key" \
  -H "Content-Type: application/json" \
  -d '{"tool_name": "read_file", "tool_args": {"bucket": "reports", "key": "q4.csv"}}'

# a user whose IAM policy denies S3 → 403, with the reason, even though the agent could do it
```

A denied response tells you exactly why:

```json
{
  "status": "denied",
  "denied_action": "s3:GetObject",
  "resource": "arn:aws:s3:::reports/q4.csv",
  "decision": "DENY",
  "reason": "Explicit deny: s3:* on *"
}
```

## Using it with your AI agent

In production you don't call AgentGate with `curl` — your agent does. The pattern is: **wrap each agent tool so that instead of calling AWS directly, it calls AgentGate with the user's API key.** AgentGate then enforces that user's permissions on every call.

```python
import httpx

AGENTGATE_URL = "http://localhost:8000"

def make_tool(user_api_key: str):
    """Give the agent a tool that routes through AgentGate under a specific user."""
    def read_file(bucket: str, key: str) -> dict:
        resp = httpx.post(
            f"{AGENTGATE_URL}/execute-tool",
            headers={"X-API-Key": user_api_key},          # who the user really is
            json={"tool_name": "read_file",
                  "tool_args": {"bucket": bucket, "key": key}},
        )
        if resp.status_code == 403:
            return {"error": resp.json()["detail"]["reason"]}   # the user wasn't allowed
        return resp.json()["results"][0]["response"]
    return read_file

# When Alice launches the agent, build its tools with Alice's key.
# Now anything the agent tries is checked against Alice's real AWS permissions.
read_file = make_tool("alice-key")
```

There's also a narrated demo agent you can run to watch this happen end-to-end (start the server first):

```bash
python -m agentgate.simulator.demo_agent --user bob   --task "read the Q4 report"   # blocked
python -m agentgate.simulator.demo_agent --user alice --task "read the Q4 report"   # succeeds
```

## Using your real AWS IAM (production mode)

To enforce against your **real** IAM policies instead of demo ones, set `AGENTGATE_MODE=real` and provide AWS credentials in `.env`:

```bash
AGENTGATE_MODE=real
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=us-east-1
AGENTGATE_API_KEYS={"alice-key": {"user_arn": "arn:aws:iam::<your-account>:user/alice", "agent_id": "agent-1"}}
```

In real mode AgentGate pulls each user's actual inline, managed, group, and boundary policies (and SCPs) from AWS and evaluates against them. The identity used to run AgentGate needs `iam:List*` and `iam:Get*` permissions so it can read those policies (and the `organizations:*` read permissions if you want SCPs included).

> The gateway and its permission enforcement are real. The execution backend in this build uses lightweight in-memory mock AWS services (S3, DynamoDB, SES) so you can run a full demo without touching real infrastructure — in a real deployment you would point the execution step at your actual AWS services.

There's a helper that creates the example IAM users and an (intentionally over-permissioned) agent role in your account so you can try real mode, and tears them down afterward:

```bash
python -m agentgate.simulator.aws_setup --action create   --profile <aws-profile>
python -m agentgate.simulator           --mode real        --profile <aws-profile>
python -m agentgate.simulator.aws_setup --action teardown  --profile <aws-profile>
```

## Available tools

Agent tool calls are mapped to AWS actions in `agentgate/action_mapping/example_config.yaml`. Out of the box:

| Tool | AWS action | Arguments |
|---|---|---|
| `read_file` | `s3:GetObject` | `bucket`, `key` |
| `write_file` | `s3:PutObject` | `bucket`, `key` |
| `delete_file` | `s3:DeleteObject` | `bucket`, `key` |
| `list_bucket` | `s3:ListBucket` | `bucket` |
| `query_database` | `dynamodb:Query` | `table` |
| `scan_table` | `dynamodb:Scan` | `table` |
| `send_email` | `ses:SendEmail` | — |
| `invoke_lambda` | `lambda:InvokeFunction` | `function_name` |

You can add your own tools by editing that config file — no code changes needed.

## Running the privilege-creep audit

The auditor reviews the audit logs against the agent role's granted permissions and reports what can be safely revoked:

```python
from agentgate.auditor.crew import run_audit

report = run_audit(audit_logger, policy_fetcher, agent_role_arn)
print(report.risk_score, report.summary)
for finding in report.findings:
    print(finding.severity, finding.recommendation)
```

The auditor uses an LLM through CrewAI, so configure your LLM provider (per the [CrewAI docs](https://docs.crewai.com/)) before running a live audit.

## Configuration reference

| Variable | Default | Description |
|---|---|---|
| `AGENTGATE_MODE` | `mock` | `mock` (demo policies) or `real` (your live AWS IAM). |
| `AGENTGATE_API_KEYS` | demo keys | JSON mapping of API key → `{ user_arn, agent_id }`. |
| `AGENTGATE_AGENT_ROLE_ARN` | — | The agent role the auditor analyzes. |
| `AGENTGATE_AUDIT_DB` | `/tmp/agentgate_audit.db` | Where the audit log is stored. |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_DEFAULT_REGION` | — | Required for `real` mode. |

> `.env` is gitignored — never commit real credentials.

## Development

```bash
pip install -e ".[dev]"
pytest          # run the test suite
ruff check .    # lint
```

The project is organized into clear components — the permission engine (`permission_engine/`), the proxy (`proxy/`), the action mapping (`action_mapping/`), the multi-agent auditor (`auditor/`), the mock AWS services (`mock_aws/`), and the attack simulator (`simulator/`) — each fully unit-tested with no real AWS calls.
