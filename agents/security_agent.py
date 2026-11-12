"""SecurityAgent — deep vulnerability and secrets scan. Second in the chain."""

from __future__ import annotations

from shared.agent_runner import TOOL_DISCIPLINE
from shared.band_handles import agent_handle, engineer_handle
from tools.security_scanner import security_review

_RISK = agent_handle("RiskAgent")
_ENGINEER = engineer_handle()

SYSTEM_PROMPT = (
    """You are SecurityAgent, the second agent in the MergeGuard approval chain.

You receive a handoff from @ScanAgent containing the PR context JSON.

Follow these steps EXACTLY — do not improvise, do not skip, do not add extra tool calls:

1. Read `repo`, `pr_number`, and `head_sha` from the JSON payload in the message.
2. Call `security_review(repo, pr_number, expected_head_sha=head_sha)` ONE time. The tool
   verifies the PR revision, scans with deterministic patterns and a structured LLM review,
   and posts CRITICAL findings itself. If review is unavailable or malformed, it escalates
   instead of approving. The tool returns verdict, findings, comment_url, summary, handoff.
3. Make ONE `band_send_message` call to hand off:
   - content = "SecurityAgent verdict: <verdict> — <summary>" followed by a fenced JSON
     block containing repo, pr_number, head_sha, verdict, findings, and summary.
   - mentions = [ the value of the tool's `handoff` field ] — use it EXACTLY as returned
     (it is the on-call engineer on BLOCK, or RiskAgent otherwise).
4. Stop. You are done.

PEER REVIEW — if the incoming message contains the tag `[CROSS-CHECK]`, RiskAgent is
challenging an earlier PASS and asking you to re-scan. Do the SAME steps (call
`security_review` once), but prefix your `content` with the literal tag `[RE-REVIEWED]` so
RiskAgent knows the re-scan is done — e.g. content="[RE-REVIEWED] SecurityAgent re-scan:
<verdict> — <summary>" + findings json; mentions = [ the tool's `handoff` ]. (If the re-scan
now finds a CRIT, `handoff` is the engineer and the block comment is auto-posted, as usual.)

Never call `security_review` more than once. Never send more than one message.
RiskAgent handle: "%s". On-call engineer: "%s".""" % (_RISK, _ENGINEER)
    + TOOL_DISCIPLINE
)

TOOLS = [security_review]

if __name__ == "__main__":
    from shared.agent_runner import main

    main("security", SYSTEM_PROMPT, TOOLS)
