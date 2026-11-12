"""LangChain tool: calculate a risk score (0–100) for a PR."""

from __future__ import annotations

import datetime
import re

from langchain_core.tools import tool

from shared.verdict import Verdict

# Weighted risk factors (additive, capped at 100)
_AUTH_FILES = re.compile(r"(?:auth|login|session|token|jwt|oauth|password)", re.I)
_PAYMENT_FILES = re.compile(r"(?:payment|billing|stripe|paypal|checkout|invoice)", re.I)


def _compute_risk(
    changed_files: list,
    additions: int,
    deletions: int,
    scan_verdict: str,
    security_verdict: str,
    upstream_warn_count: int,
) -> dict:
    """Pure scoring logic used by assess_risk."""
    factors: dict[str, int] = {}
    score = 0

    auth_touched = any(_AUTH_FILES.search(f) for f in changed_files)
    payment_touched = any(_PAYMENT_FILES.search(f) for f in changed_files)

    if auth_touched:
        factors["auth_file_touched"] = 30
        score += 30
    if payment_touched:
        factors["payment_file_touched"] = 40
        score += 40

    if datetime.datetime.now(datetime.timezone.utc).weekday() == 4:  # Friday
        factors["friday_deploy"] = 15
        score += 15

    diff_size = additions + deletions
    if diff_size > 500:
        factors["large_diff"] = 10
        score += 10

    warn_contribution = min(upstream_warn_count * 5, 20)
    if warn_contribution:
        factors["upstream_warns"] = warn_contribution
        score += warn_contribution

    score = min(score, 100)
    verdict = Verdict.ESCALATE if score >= 71 else Verdict.PASS

    reasons = [f"{k.replace('_', ' ')}: +{v}" for k, v in factors.items()]
    if not reasons:
        reasons = ["No major risk factors detected"]

    return {
        "verdict": verdict.value,
        "score": score,
        "factors": factors,
        "reasons": reasons,
    }


@tool
def assess_risk(
    repo: str,
    pr_number: int,
    expected_head_sha: str,
    scan_verdict: str,
    security_verdict: str,
) -> dict:
    """Score a PR's deployment risk in ONE deterministic call.

    RiskAgent should call THIS and nothing else. It fetches the PR's changed files + size
    itself (so the agent never has to dig them out of chat history), counts upstream WARNs
    from the two verdicts, computes the 0–100 score, and returns the exact next hand-off
    handle. Returns {score, verdict, factors, reasons, handoff} — DeployAgent on PASS, the
    on-call engineer on ESCALATE.

    Peer review: also returns `cross_check`. If the PR touches security-sensitive files
    (auth/payment) yet SecurityAgent only returned PASS/WARN, RiskAgent should NOT just trust
    it — `cross_check` is "challenge" and `challenge_handle` is SecurityAgent, so RiskAgent
    sends it back for a deeper re-scan (consensus required before deploy). Otherwise
    `cross_check` is "endorsed".
    """
    from shared.band_handles import agent_handle, engineer_handle
    from tools.github_api import _resolve_target, get_pr_metadata

    scan_status = str(scan_verdict).strip().upper()
    security_status = str(security_verdict).strip().upper()
    if scan_status not in {"PASS", "WARN"}:
        return _risk_escalation(
            f"ScanAgent verdict is not deployable: {scan_status or 'missing'}"
        )
    if security_status not in {"PASS", "WARN"}:
        return _risk_escalation(
            f"SecurityAgent verdict is not deployable: {security_status or 'missing'}"
        )

    try:
        repo, pr_number = _resolve_target(repo, pr_number)
    except ValueError as exc:
        return _risk_escalation(str(exc))

    meta = get_pr_metadata.invoke({"repo": repo, "pr_number": pr_number})
    if not isinstance(meta, dict) or "error" in meta:
        return _risk_escalation(
            meta.get("error", "Could not fetch PR metadata")
            if isinstance(meta, dict)
            else "Could not fetch PR metadata"
        )
    if not expected_head_sha or meta.get("head_sha") != expected_head_sha:
        return _risk_escalation(
            "PR head changed since the review started; restart validation"
        )

    changed_files = meta.get("changed_files", []) or []
    additions = int(meta.get("additions", 0) or 0)
    deletions = int(meta.get("deletions", 0) or 0)

    warns = sum(1 for v in (scan_status, security_status) if v == "WARN")
    result = _compute_risk(
        changed_files, additions, deletions, scan_verdict, security_verdict, warns
    )
    result["handoff"] = (
        agent_handle("DeployAgent")
        if result["verdict"] == Verdict.PASS.value
        else engineer_handle()
    )

    # Peer-review cross-check: a security-sensitive change that Security only PASSed/WARNed
    # warrants a second look — RiskAgent challenges SecurityAgent to re-scan (consensus gate).
    sensitive = any(
        _AUTH_FILES.search(f) or _PAYMENT_FILES.search(f) for f in changed_files
    )
    sv = security_status
    result["cross_check"] = (
        "challenge" if (sensitive and sv in ("PASS", "WARN")) else "endorsed"
    )
    result["challenge_handle"] = agent_handle("SecurityAgent")
    return result


def _risk_escalation(reason: str) -> dict:
    from shared.band_handles import agent_handle, engineer_handle

    return {
        "verdict": Verdict.ESCALATE.value,
        "score": 100,
        "factors": {},
        "reasons": [reason],
        "handoff": engineer_handle(),
        "cross_check": "endorsed",
        "challenge_handle": agent_handle("SecurityAgent"),
        "error": reason,
    }
