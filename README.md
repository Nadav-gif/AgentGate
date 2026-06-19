# AgentGate

**Runtime permission enforcement proxy for AI agents accessing AWS services.**

AgentGate sits between an AI agent and the cloud services it calls. On every tool
call it answers one question:

> *"Does the **user** who initiated this request have permission to perform this
> action — according to their own AWS IAM policies?"*

The agent's own (typically broad) role becomes irrelevant. What matters is the
requesting user's effective permissions, resolved in real time from their actual
IAM policies, permission boundaries, and SCPs.

**Core principle — user-ceiling enforcement: an agent can never do more than the
user could do themselves.**

---

## Why this exists

Traditional cloud IAM ties every action to an *identity*: a human authenticates,
gets a session, and every action is checked against *their* permissions and logged
under *their* name.

AI agents break this model. An agent runs with **its own** credentials, not the
user's — and those credentials are deliberately broad because one agent serves a
whole team. When a restricted user asks the agent to do something, the service
checks the *agent's* permissions, not the user's. This is the classic
**confused-deputy problem**, and it enables three attack patterns:

| Attack | What happens | How AgentGate stops it |
|---|---|---|
| **Authorization bypass** | A restricted user reads data they have no direct access to, *through* the agent. | Every call is evaluated against the **user's** IAM policies, not the agent's. The user's permissions are the ceiling. |
| **Privilege creep** | The agent role accumulates permissions over months; nobody revokes the unused ones, inflating the blast radius. | A CrewAI multi-agent auditor diffs **granted** vs **actually-used** permissions and recommends what to revoke. |
| **Cross-system escalation** | The agent reads sensitive data and then exfiltrates it (e.g. emails it out) in a single session. Each step is individually allowed. | Session-level tracking blocks dangerous **sequences** (read-then-send-external) on top of per-call checks. |

---

## Architecture

```
                                  ┌─────────────────────────────────────────┐
   Agent (CrewAI / any client)    │              AgentGate proxy             │
   POST /execute-tool ───────────▶│                                          │
   X-API-Key: <user key>          │  1. Auth        API key → user IAM ARN   │
   { tool_name, tool_args }       │  2. Resolve     tool → AWS action+ARN    │
                                  │  3. Permission  can_do(user, action)     │──▶ AWS IAM (real mode)
                                  │  4. Escalation  session-sequence rules   │     or hardcoded (mock mode)
                                  │  5. Enforce     DENY → HTTP 403          │
                                  │  6. Execute     mock S3 / DynamoDB / SES │
                                  │  7. Audit       SQLite, full attribution │
                                  └─────────────────────────────────────────┘
```

### Components

| Module | Role |
|---|---|
| `agentgate/proxy/` | **Permission proxy** (FastAPI). The runtime enforcement layer and `POST /execute-tool` endpoint. |
| `agentgate/permission_engine/` | **Permission engine.** `can_do()` reproduces the real AWS IAM evaluation order: explicit deny → SCPs → permission boundary → identity policies. Includes a TTL cache and a pluggable policy fetcher. |
| `agentgate/auditor/` | **Permission auditor.** A 3-agent CrewAI crew (Log Analyzer → Privilege Creep Detector → Recommendation Agent) that produces a security report. |
| `agentgate/action_mapping/` | Translates an agent tool call (e.g. `query_database(table="hr")`) into an AWS action + resource ARN. |
| `agentgate/proxy/escalation.py` | Session tracking + cross-system escalation rules. |
| `agentgate/mock_aws/` | In-memory mock S3 / DynamoDB / SES so the agent has something to execute against in a demo. |
| `agentgate/simulator/` | Attack simulator that runs all three scenarios end-to-end. |

---

## How a request is evaluated

The permission engine's `can_do(user_arn, action, resource)` follows the real AWS
IAM decision order:

1. **Explicit `Deny`** in any identity policy → **DENY** (wins over everything).
2. **SCPs** (if the account is in an Organization): any SCP deny blocks; the action
   must be explicitly allowed by an SCP.
3. **Permission boundary** (if set): an allow must *also* be permitted by the boundary.
4. A matching **`Allow`** → **ALLOW**.
5. Otherwise → **IMPLICIT_DENY**.

Every decision returns a human-readable reason and is written to the audit log with
full attribution (which user, which agent, which tool, which AWS action/resource,
the decision, and why).

---

## Quick start

### Requirements
- Python 3.10+
- (Optional) Docker, for containerized deployment
- (Optional) An AWS account, only for "real" mode

### Install

```bash
git clone <your-repo-url> AgentGate
cd AgentGate
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

### Run the attack simulator (no AWS needed)

The fastest way to see AgentGate work. This runs all three attack scenarios against
an in-process proxy using hardcoded demo policies and prints a pass/fail report:

```bash
python -m agentgate.simulator --mode mock
```

Expected output (abridged):

```
  [PASS] Scenario A: Authorization Bypass
    1. [+] Bob queries DynamoDB (has permission)       Expected: ALLOW | Actual: ALLOW | HTTP: 200
    2. [+] Bob reads S3 file (policy denies s3:*)       Expected: DENY  | Actual: DENY  | HTTP: 403
    3. [+] Alice reads same S3 file (has permission)    Expected: ALLOW | Actual: ALLOW | HTTP: 200

  [PASS] Scenario B: Privilege Creep Detection
    ... Agent role has 7 granted permissions. 2 used, 5 unused ...

  [PASS] Scenario C: Cross-System Escalation
    3. [+] Alice sends email after reading data (blocked — escalation)  Expected: DENY | HTTP: 403
```

### Run the server

```bash
uvicorn agentgate.proxy.server:app --host 0.0.0.0 --port 8000
```

The mode is controlled by the `AGENTGATE_MODE` environment variable
(`mock` by default, `real` for live AWS IAM).

### Try a tool call

The demo ships with two users mapped to API keys: `alice-key` and `bob-key`.

```bash
# Alice can read S3 — ALLOWED
curl -s -X POST http://localhost:8000/execute-tool \
  -H "X-API-Key: alice-key" \
  -H "Content-Type: application/json" \
  -d '{"tool_name": "read_file", "tool_args": {"bucket": "reports", "key": "q4.csv"}}'

# Bob is denied S3 by his IAM policy — 403 DENIED, even though the agent role allows it
curl -s -X POST http://localhost:8000/execute-tool \
  -H "X-API-Key: bob-key" \
  -H "Content-Type: application/json" \
  -d '{"tool_name": "read_file", "tool_args": {"bucket": "reports", "key": "q4.csv"}}'
```

### Demo agent (narrated)

Shows the same thing from the agent's point of view (requires the server running):

```bash
python -m agentgate.simulator.demo_agent --user bob   --task "read the Q4 report"   # blocked
python -m agentgate.simulator.demo_agent --user alice --task "read the Q4 report"   # succeeds
```

---

## HTTP API

### `POST /execute-tool`
Authenticate, resolve the tool call to AWS action(s), check permissions + escalation
rules, and execute if allowed.

**Headers:** `X-API-Key: <key>`

**Request body:**
```json
{
  "tool_name": "read_file",
  "tool_args": { "bucket": "reports", "key": "q4.csv" }
}
```

**Allowed response (200):**
```json
{
  "status": "allowed",
  "tool_name": "read_file",
  "results": [{ "action": "s3:GetObject", "resource": "arn:aws:s3:::reports/q4.csv", "response": { "...": "..." } }]
}
```

**Denied response (403):**
```json
{
  "status": "denied",
  "tool_name": "read_file",
  "denied_action": "s3:GetObject",
  "resource": "arn:aws:s3:::reports/q4.csv",
  "decision": "DENY",
  "reason": "Explicit deny: s3:* on *"
}
```

### `POST /reset-sessions`
Clears all session-tracking state (used by the simulator between scenarios).

### Built-in tools

Tool calls are mapped to AWS actions via `agentgate/action_mapping/example_config.yaml`:

| Tool | AWS action | Required args |
|---|---|---|
| `read_file` | `s3:GetObject` | `bucket`, `key` |
| `write_file` | `s3:PutObject` | `bucket`, `key` |
| `delete_file` | `s3:DeleteObject` | `bucket`, `key` |
| `list_bucket` | `s3:ListBucket` | `bucket` |
| `query_database` | `dynamodb:Query` | `table` |
| `scan_table` | `dynamodb:Scan` | `table` |
| `send_email` | `ses:SendEmail` | — |
| `invoke_lambda` | `lambda:InvokeFunction` | `function_name` |
| `copy_file` | `s3:GetObject` + `s3:PutObject` | `source_*`, `dest_*` |

---

## Running modes

| Mode | Policy source | Use case |
|---|---|---|
| `mock` | Hardcoded `FakePolicyFetcher` policies | Demos and tests — **no AWS account needed**. |
| `real` | `AwsPolicyFetcher` via boto3 against live IAM | Validate against real IAM users/roles. |
| `live` | Real HTTP requests to a deployed proxy | Test a running Docker/Azure deployment. |

```bash
python -m agentgate.simulator --mode mock
python -m agentgate.simulator --mode real --profile <aws-profile>
python -m agentgate.simulator --mode live --url http://localhost:8000
```

### Real AWS mode

Create the demo IAM users and over-provisioned agent role, run, then tear down:

```bash
python -m agentgate.simulator.aws_setup --action create   --profile <aws-profile>
python -m agentgate.simulator           --mode real        --profile <aws-profile>
python -m agentgate.simulator.aws_setup --action teardown  --profile <aws-profile>
```

---

## Permission auditor (CrewAI)

A background multi-agent system that detects privilege creep. Three agents run
sequentially:

1. **Log Analyzer** — reads the proxy's audit logs and finds access patterns and
   denial spikes.
2. **Privilege Creep Detector** — pulls the agent role's IAM policies and
   cross-references *granted* permissions against *actually-used* ones from the logs.
3. **Recommendation Agent** — synthesizes a `SecurityReport` with a risk score
   (1–10), findings, and specific revocation recommendations.

```python
from agentgate.auditor.crew import run_audit

report = run_audit(audit_logger, policy_fetcher, agent_role_arn)
print(report.risk_score, report.findings, report.summary)
```

> The auditor's three agents use an LLM via CrewAI. Configure your LLM provider per
> the [CrewAI docs](https://docs.crewai.com/) (e.g. set the relevant API key) before
> running a live audit. The privilege-creep *detection logic* itself is also exercised
> directly (without an LLM) in Scenario B of the simulator.

---

## Docker

```bash
cp .env.example .env        # then edit .env
docker compose up --build
```

The proxy is served on port `8000`. `AGENTGATE_MODE` (and, for real mode, AWS
credentials and `AGENTGATE_API_KEYS`) are read from `.env`. The container is
deployable to Azure Container Instances / App Service.

### Configuration (environment variables)

| Variable | Default | Description |
|---|---|---|
| `AGENTGATE_MODE` | `mock` | `mock` or `real`. |
| `AGENTGATE_API_KEYS` | demo keys | JSON mapping of API key → `{user_arn, agent_id}`. |
| `AGENTGATE_AGENT_ROLE_ARN` | — | Agent role ARN analyzed by the auditor. |
| `AGENTGATE_AUDIT_DB` | `/tmp/agentgate_audit.db` | SQLite audit-log path. |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_DEFAULT_REGION` / `AWS_ACCOUNT_ID` | — | Required for `real` mode. |

> **Note:** `.env` is gitignored — never commit real credentials.

---

## Development

```bash
pip install -e ".[dev]"
pytest                 # run the test suite (220+ tests)
pytest --cov           # with coverage
ruff check .           # lint
```

The codebase uses Protocol-based dependency injection throughout, so every component
is tested in isolation with fakes (no AWS calls in the test suite).

---

## Project layout

```
agentgate/
├── proxy/              # FastAPI app, routes, auth, audit, escalation, server entry point
├── permission_engine/  # can_do(), policy parser/fetcher, cache, models
├── auditor/            # CrewAI agents, tasks, tools, crew orchestration
├── action_mapping/     # tool → AWS action/resource resolver + YAML config
├── mock_aws/           # in-memory S3 / DynamoDB / SES
└── simulator/          # attack scenarios, runner (mock/real/live), demo agent, AWS setup
tests/                  # mirrored test package
Dockerfile, docker-compose.yml, .env.example
```

---

## Status & scope

This is a research/educational project demonstrating a runtime permission-enforcement
pattern for AI agents. The mock AWS services and static API-key auth are demo
conveniences — in production these would be replaced by real AWS services and a
proper secrets store. The permission engine itself implements the real AWS IAM
evaluation chain and works against live IAM in `real` mode.
