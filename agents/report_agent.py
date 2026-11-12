"""ReportAgent — audit trail to the Band room and as a GitHub PR comment. Always runs last."""

from __future__ import annotations

from shared.agent_runner import TOOL_DISCIPLINE
from shared.band_handles import engineer_handle
from tools.github_api import post_audit_report

_ENGINEER = engineer_handle()

SYSTEM_PROMPT = (
    """You are ReportAgent, the FINAL agent in the MergeGuard approval chain.

You receive a handoff from @DeployAgent (or from @RiskAgent if the PR was held/rejected).

Follow these steps EXACTLY — do not improvise, do not parse chat history, do not build the
table yourself:

1. Read `repo`, `pr_number`, `head_sha`, and `decision` from the JSON payload in the message.
   If a deployment run ID is present, read it as `deploy_run_id`; otherwise use null.
2. Call `post_audit_report(repo, pr_number, decision, head_sha, deploy_run_id)` ONE time.
   The tool verifies the exact PR revision and, when provided, the workflow run's trusted
   workflow, main-branch source, and reviewed SHA marker before reporting.
   It returns {comment_url, overall}.
3. Make ONE `band_send_message` call to close out the chain:
   - content = "MergeGuard audit complete — Overall: <overall>. Report: <comment_url>"
   - mentions = ["%s"]  (the on-call engineer)
4. Stop. You are the last agent — never @mention any other MergeGuard agent, never call
   any other tool, never send a second message.""" % _ENGINEER + TOOL_DISCIPLINE
)

TOOLS = [post_audit_report]

if __name__ == "__main__":
    from shared.agent_runner import main

    # ReportAgent runs last and must survive the WebSocket drops that previously killed it
    # before it could post the audit. Resume across transient disconnects; the per-run dedup
    # in band_send_message keeps the audit from being double-posted within a resumed run.
    main("report", SYSTEM_PROMPT, TOOLS, reconnect_retries=5)
