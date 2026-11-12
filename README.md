# MergeGuard

**Build status**<br>
[![CI](https://github.com/PiyushAgarwalcs/MergeGuard-Automated-PR-Security-Policy-Enforcement/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/PiyushAgarwalcs/MergeGuard-Automated-PR-Security-Policy-Enforcement/actions/workflows/ci.yml)
[![PR Validation](https://github.com/PiyushAgarwalcs/MergeGuard-Automated-PR-Security-Policy-Enforcement/actions/workflows/pr-validation.yml/badge.svg?branch=main)](https://github.com/PiyushAgarwalcs/MergeGuard-Automated-PR-Security-Policy-Enforcement/actions/workflows/pr-validation.yml)
[![Deployment](https://github.com/PiyushAgarwalcs/MergeGuard-Automated-PR-Security-Policy-Enforcement/actions/workflows/deploy.yml/badge.svg?branch=main)](https://github.com/PiyushAgarwalcs/MergeGuard-Automated-PR-Security-Policy-Enforcement/actions/workflows/deploy.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**Agents and models**<br>
[![Python 3.11](https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white)](https://www.python.org/downloads/release/python-3110/)
[![Band SDK](https://img.shields.io/badge/Band-SDK-734F96)](https://band.ai/)
[![LangGraph](https://img.shields.io/badge/LangGraph-agents-1C3C3C)](https://langchain-ai.github.io/langgraph/)
[![LangChain](https://img.shields.io/badge/LangChain-framework-1C3C3C)](https://python.langchain.com/)
[![LangChain OpenAI](https://img.shields.io/badge/LangChain-OpenAI%20integration-1C3C3C)](https://python.langchain.com/docs/integrations/chat/openai/)
[![Featherless AI](https://img.shields.io/badge/Featherless-AI-6C47FF)](https://featherless.ai/)
[![AIMLAPI](https://img.shields.io/badge/AIMLAPI-models-0B6E99)](https://aimlapi.com/)

**API and configuration**<br>
[![FastAPI](https://img.shields.io/badge/FastAPI-webhook-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Uvicorn](https://img.shields.io/badge/Uvicorn-ASGI-4051B5)](https://www.uvicorn.org/)
[![HTTPX](https://img.shields.io/badge/HTTPX-client-5A29E4)](https://www.python-httpx.org/)
[![PyGithub](https://img.shields.io/badge/PyGithub-GitHub_API-181717?logo=github&logoColor=white)](https://pygithub.readthedocs.io/)
[![Pydantic](https://img.shields.io/badge/Pydantic-validation-E92063)](https://docs.pydantic.dev/)
[![PyYAML](https://img.shields.io/badge/PyYAML-config-CC0000)](https://pyyaml.org/)
[![python-dotenv](https://img.shields.io/badge/python--dotenv-config-3776AB?logo=python&logoColor=white)](https://github.com/theskumar/python-dotenv)

**Infrastructure**<br>
[![GitHub Actions](https://img.shields.io/badge/GitHub-Actions-2088FF?logo=githubactions&logoColor=white)](https://docs.github.com/actions)
[![Docker](https://img.shields.io/badge/Docker-containers-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![Docker Compose](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![Railway](https://img.shields.io/badge/Railway-deployment-0B0D0E)](https://railway.com/)

**Quality checks**<br>
[![pytest](https://img.shields.io/badge/pytest-tests-0A9EDC?logo=pytest&logoColor=white)](https://docs.pytest.org/)
[![pytest-asyncio](https://img.shields.io/badge/pytest--asyncio-tests-0A9EDC)](https://pytest-asyncio.readthedocs.io/)
[![pip-audit](https://img.shields.io/badge/pip--audit-dependencies-2D6A4F)](https://github.com/pypa/pip-audit)
[![Ruff](https://img.shields.io/badge/Ruff-lint-D7FF64?logo=ruff&logoColor=black)](https://docs.astral.sh/ruff/)
[![Black](https://img.shields.io/badge/Black-format-000000?logo=python&logoColor=white)](https://black.readthedocs.io/)
[![mypy](https://img.shields.io/badge/mypy-types-2A6DB2)](https://mypy.readthedocs.io/)

**A multi-agent pull request review and deployment gate.**

MergeGuard coordinates five specialist agents to analyze pull requests, apply risk-based deployment policy, and publish an audit report. Deterministic tools enforce the review gates; pull-request tests, lint, and dependency audits run on an isolated GitHub Actions runner against the exact reviewed commit.

[Workflow](#review-workflow) · [Technology](#technology) · [Getting started](#getting-started) · [Deployment](#deployment)

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
        SCAN["ScanAgent<br/>Validate exact PR SHA in isolation"] --> SCAN_RESULT{"Ruff · tests · dependency audit"}
        SCAN_RESULT -->|PASS| SECURITY["SecurityAgent<br/>Pattern scan + structured LLM review"]
        SCAN_RESULT -->|BLOCK| ENGINEER["On-call engineer<br/>APPROVE / REJECT"]
        SECURITY --> SEVERITY{"Highest finding"}
        SEVERITY -->|LOW / MED / HIGH| RISK["RiskAgent<br/>Weighted score · 0–100"]
        SEVERITY -->|CRITICAL| BLOCK["Post critical finding<br/>and block deployment"]
        BLOCK --> ENGINEER
        RISK --> SCORE{"Risk score"}
        SCORE -->|"< 71 · PASS"| DEPLOY["DeployAgent<br/>Trusted workflow · pinned SHA"]
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
| **ScanAgent** | Dispatches Ruff, the PR test suite, and dependency auditing on an isolated runner. | Failed, stale, or unavailable validation blocks the automatic path. |
| **SecurityAgent** | Scans the exact PR diff with deterministic patterns and a structured LLM review. | Critical pattern findings block; LLM findings or scan errors require human review. |
| **RiskAgent** | Scores risk from change characteristics and upstream warnings. | Scores below 71 pass; scores of 71 or higher require human review. |
| **DeployAgent** | Dispatches the trusted deployment workflow from `main` with the reviewed SHA. | Runs only after approval and verifies the correlated workflow run. |
| **ReportAgent** | Collects review and deployment outcomes. | Reports the decision and only claims success for the verified run. |

For detailed decision branches, risk weights, and deployment topology, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Design principles

- **Deterministic enforcement:** security scanning, risk scoring, deployment triggering, and report assembly are implemented as tools rather than relying solely on model-generated decisions.
- **Fail closed:** critical findings, stale commits, and unavailable validation or metadata cannot pass automatically.
- **Untrusted code stays isolated:** PR tests and dependency installation run on an ephemeral GitHub-hosted runner with no workflow write permissions and no checkout credentials persisted to the workspace.
- **Human approval for elevated risk:** high risk scores and blocked reviews route to the on-call engineer for an in-chat decision.
- **Traceable outcomes:** the final report summarizes review and deployment results.

## Technology

| Area | Technologies |
|---|---|
| Language and agent orchestration | Python 3.11, Band SDK, LangGraph, LangChain Core, LangChain OpenAI |
| Model providers | Featherless AI and AIMLAPI |
| Webhook and HTTP | FastAPI, Uvicorn, HTTPX |
| GitHub integration | PyGithub, GitHub Actions |
| Validation and configuration | Pydantic, PyYAML, python-dotenv |
| Packaging and hosting | Docker, Docker Compose, Railway |
| Development and security checks | pytest, pytest-asyncio, pip-audit, Ruff, Black, mypy |

## Getting started

### Requirements

- Python 3.11
- GitHub credentials with the permissions needed to read pull requests, write comments, and dispatch the configured workflow
- Band agent credentials and a supported model-provider API key

### Install

Create and activate a virtual environment, then install runtime dependencies:

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

Set the required values in `.env`. At minimum, configure the Band service and agent credentials, model-provider credentials, `GITHUB_TOKEN`, `TARGET_REPO`, and `GITHUB_WEBHOOK_SECRET`. `PR_VALIDATION_REPO` identifies the repository that hosts this project's `pr-validation.yml` workflow; the GitHub token must be able to dispatch it. Set `DEPLOY_WORKFLOW_FILE` to the workflow file in the target repository.

Do not commit `.env` or real credentials.

In the validation-workflow repository, configure `TARGET_REPO` and `GH_PAT` as Actions secrets. `GH_PAT` needs read-only contents access to the target repository for checkout. The service's `GITHUB_TOKEN` needs permission to dispatch and inspect workflow runs in `PR_VALIDATION_REPO`. The validation job disables `GITHUB_TOKEN` permissions and does not persist checkout credentials.

The target's deployment workflow must accept `head_sha`, `pr_number`, and `request_id` as `workflow_dispatch` inputs, check out and deploy the artifact built from `head_sha`, and include the request ID and SHA in its run name. MergeGuard dispatches only the workflow version from trusted `main`; a target workflow that does not honor this contract is not treated as a verified deployment.

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
pip install -r requirements-dev.txt
python -m pytest tests/ -q
ruff check .
black --check .
mypy shared/ tools/ webhook/ agents/ --ignore-missing-imports
```

These are MergeGuard's own unit and quality checks. For local checks, install `requirements-dev.txt`; PR code is tested by the dispatched isolated workflow, not by running it inside the long-lived agent service.

## Deployment

The repository includes a Dockerfile, a two-service Docker Compose configuration, and GitHub Actions workflows for CI, isolated PR validation, and deployment. Docker Compose and the documented Railway layout both use a public `webhook` service (`python -m webhook.main`) and a single `agents` service (`python -m run_all_agents`). Configure the required environment variables and Actions secrets before enabling live webhooks or deployment triggers.

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
