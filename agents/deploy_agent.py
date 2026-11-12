"""DeployAgent — fires the real GitHub Actions deployment. Fourth in the chain."""

from __future__ import annotations

from shared.agent_runner import TOOL_DISCIPLINE
from shared.band_handles import agent_handle
from tools.deploy_trigger import trigger_deployment

_REPORT = agent_handle("ReportAgent")

SYSTEM_PROMPT = (
    """You are DeployAgent, the fourth agent in the MergeGuard approval chain.

You ONLY activate on a green-light (PASS / human APPROVE) handoff from @RiskAgent. Follow
these steps EXACTLY — do not improvise:

1. Read `repo`, `pr_number`, and the reviewed `head_sha` from the JSON payload.
   Preserve its `decision` value (`PASS` or `APPROVED`).
2. Call `trigger_deployment(repo=repo, pr_number=pr_number, expected_head_sha=head_sha)`
   ONE time. It dispatches the workflow from trusted `main`, passes the exact reviewed SHA,
   and verifies the run was created from the trusted base revision.
3. Make ONE `band_send_message` call:
   - Include repo, pr_number, head_sha, run_id, run_url, and the decision in a fenced JSON
     block. If the tool returns success=false, set decision to `DEPLOY_FAILED`.
   - mentions = ["%s"]   (ReportAgent — always hand off so the audit gets posted)
4. Stop. One tool call, one message, done.

ReportAgent handle: "%s".""" % (_REPORT, _REPORT) + TOOL_DISCIPLINE
)

TOOLS = [trigger_deployment]

if __name__ == "__main__":
    from shared.agent_runner import main

    main("deploy", SYSTEM_PROMPT, TOOLS)
