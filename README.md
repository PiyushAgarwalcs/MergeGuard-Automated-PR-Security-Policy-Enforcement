# MergeGuard

[![CI](https://github.com/PiyushAgarwalcs/MergeGuard-Automated-PR-Security-Policy-Enforcement/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/PiyushAgarwalcs/MergeGuard-Automated-PR-Security-Policy-Enforcement/actions/workflows/ci.yml)
[![Python 3.11](https://img.shields.io/badge/python-3.11-3776AB?logo=python&logoColor=white)](https://www.python.org/downloads/release/python-3110/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**A multi-agent pull request review and deployment gate.**

MergeGuard coordinates five specialist agents to analyze pull requests, apply risk-based deployment policy, and publish an audit report. Deterministic tools perform checks and enforce critical security outcomes; agents coordinate the review and hand off decisions through Band.

## Review workflow

```mermaid
flowchart TD
    PR["Developer opens or updates a pull request"] --> GH["GitHub pull_request event"]
    GH --> WH["FastAPI webhook<br/>HMAC-SHA256 verification"]
    WH --> VALID{"Valid signature<br/>and base branch is main?"}
    VALID -->|No| IGNORE["Ignore event or reject request"]
    VALID -->|Yes| ROOM["Create Band room<br/>add agents and on-call engineer"]

    subgraph REVIEW["MergeGuard review · Band agent hand-offs"]
        direction LR
        SCAN["ScanAgent<br/>Lint · tests · dependency audit"] --> SCAN_RESULT{"Scan verdict"}
        SCAN_RESULT -->|PASS / WARN| SECURITY["SecurityAgent<br/>Vulnerability and secrets scan"]
        SCAN_RESULT -->|BLOCK| ENGINEER["On-call engineer<br/>APPROVE / REJECT"]
        SECURITY --> SEVERITY{"Highest finding"}
        SEVERITY -->|LOW / MED / HIGH| RISK["RiskAgent<br/>Weighted score · 0–100"]
        SEVERITY -->|CRITICAL| BLOCK["Post critical finding<br/>and block deployment"]
        BLOCK --> ENGINEER
        RISK --> SCORE{"Risk score"}
        SCORE -->|"< 71 · PASS"| DEPLOY["DeployAgent<br/>Only after approval"]
        SCORE -->|"≥ 71 · ESCALATE"| ENGINEER
        ENGINEER -->|APPROVE| DEPLOY
        ENGINEER -->|REJECT| REPORT["ReportAgent<br/>Assemble audit trail"]
        DEPLOY --> ACTIONS["Trigger GitHub Actions<br/>workflow_dispatch"]
        ACTIONS --> REPORT
    end

    ROOM --> SCAN
    REPORT --> AUDIT["Post audit summary<br/>to the pull request"]

    classDef scan fill:#DBEAFE,stroke:#2563EB,color:#172554,stroke-width:2px;
    classDef security fill:#FCE7F3,stroke:#DB2777,color:#500724,stroke-width:2px;
    classDef risk fill:#FEF3C7,stroke:#D97706,color:#451A03,stroke-width:2px;
    classDef deploy fill:#DCFCE7,stroke:#16A34A,color:#052E16,stroke-width:2px;
    classDef report fill:#EDE9FE,stroke:#7C3AED,color:#2E1065,stroke-width:2px;
    classDef human fill:#FFE4E6,stroke:#E11D48,color:#4C0519,stroke-width:2px;
    classDef system fill:#E2E8F0,stroke:#475569,color:#0F172A;
    classDef decision fill:#FFFFFF,stroke:#64748B,color:#0F172A;
    classDef blocked fill:#FEE2E2,stroke:#DC2626,color:#450A0A,stroke-width:2px;

    class SCAN scan;
    class SECURITY security;
    class RISK risk;
    class DEPLOY deploy;
    class REPORT report;
    class ENGINEER human;
    class GH,WH,ROOM,ACTIONS,AUDIT,PR,IGNORE system;
    class VALID,SCAN_RESULT,SEVERITY,SCORE decision;
    class BLOCK blocked;
```

Each agent has its own color in the diagram: **Scan** blue, **Security** pink, **Risk** amber, **Deploy** green, and **Report** purple. The on-call engineer is shown in red.

### Agent responsibilities

| Agent | Responsibility | Key outcome |
|---|---|---|
| **ScanAgent** | Runs static analysis, tests, and dependency auditing. | Passes findings onward or blocks the review. |
| **SecurityAgent** | Scans the pull request diff for vulnerabilities and secrets. | Critical findings create a PR comment and block deployment. |
| **RiskAgent** | Scores risk from change characteristics and upstream warnings. | Scores below 71 pass; scores of 71 or higher require human review. |
| **DeployAgent** | Triggers the configured GitHub Actions deployment workflow. | Runs only after the review is approved. |
| **ReportAgent** | Collects review and deployment outcomes. | Publishes the final audit summary. |

For detailed decision branches, risk weights, and deployment topology, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Design principles

- **Deterministic enforcement:** security scanning, risk scoring, deployment triggering, and report assembly are implemented as tools rather than relying solely on model-generated decisions.
- **Fail closed on critical findings:** a critical security finding blocks deployment and is surfaced on the pull request.
- **Human approval for elevated risk:** high risk scores and blocked reviews route to the on-call engineer for an in-chat decision.
- **Traceable outcomes:** the final report summarizes review and deployment results.

## Technology

| Component | Technology |
|---|---|
| Agent coordination | Band (`band-sdk[langgraph]`) |
| Agent runtime | LangGraph ReAct agents |
| Model providers | Featherless or AIMLAPI (OpenAI-compatible APIs) |
| Webhook service | FastAPI with HMAC-SHA256 verification |
| Review and deployment integration | GitHub API and GitHub Actions |
| Packaging and deployment | Docker; Railway configuration is included |
| Quality checks | pytest, Ruff, Black, mypy, GitHub Actions |

## Getting started

### Requirements

- Python 3.11
- GitHub credentials with the permissions needed to read pull requests, write comments, and dispatch the configured workflow
- Band agent credentials and a supported model-provider API key

### Install

Create and activate a virtual environment, then install dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

On macOS or Linux:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Set the required values in `.env`. At minimum, configure the Band service and agent credentials, model-provider credentials, `GITHUB_TOKEN`, `TARGET_REPO`, and `GITHUB_WEBHOOK_SECRET`. Set `DEPLOY_WORKFLOW_FILE` to the workflow file in the target repository.

Do not commit `.env` or real credentials.

### Run locally

Start the webhook and agent runtime in separate terminals:

```bash
python -m webhook.main
```

```bash
python -m run_all_agents
```

The webhook listens on port `8000` by default. Configure a GitHub pull-request webhook to reach `/webhook`, using the same secret as `GITHUB_WEBHOOK_SECRET`.

### Run checks

```bash
ruff check .
black --check .
mypy shared/ tools/ webhook/ agents/ --ignore-missing-imports
pytest tests/ -q
```

## Deployment

The repository includes a Dockerfile, a Docker Compose configuration, and a GitHub Actions workflow for CI and deployment. The documented Railway layout uses a public `webhook` service (`python -m webhook.main`) and an `agents` service (`python -m run_all_agents`). Configure the required environment variables and deployment secrets in the hosting and GitHub environments before enabling live webhooks or deployment triggers.

## Repository layout

```text
agents/              Five specialist agents
tools/               Scanning, risk, GitHub, deployment, and reporting tools
shared/              Agent runtime wiring, schemas, and shared helpers
webhook/             Webhook verification, parsing, and Band room initiation
tests/               Unit tests and pull-request fixtures
run_all_agents.py    Runs all five agents in one process
ARCHITECTURE.md      Pipeline details, risk weights, and deployment topology
```
