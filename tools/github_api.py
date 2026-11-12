"""LangChain tools for GitHub PR operations.

Every tool catches its own exceptions and returns a structured error instead of raising:
a tool that raises inside the Band LangGraph adapter aborts the agent's whole message
turn (the message is marked permanently failed), which silently breaks the approval chain.
Returning an error value keeps the agent alive and lets the LLM recover (retry with the
repo/pr_number from the opener, or proceed on the findings it already has).
"""

from __future__ import annotations

import os
from typing import Any

from langchain_core.tools import tool


def _gh() -> Any:
    from github import Github

    return Github(os.environ["GITHUB_TOKEN"])


def _err(exc: Exception) -> str:
    return f"{type(exc).__name__}: {exc}"[:300]


def _audit_overall(decision: str, blocked: bool, run: Any | None) -> str:
    if decision == "REJECTED":
        return "REJECTED"
    if decision == "DEPLOY_FAILED":
        return "DEPLOY_FAILED"
    if decision == "BLOCKED" or (blocked and decision != "APPROVED"):
        return "BLOCKED"
    if run is None:
        return "UNKNOWN"
    if run.status != "completed":
        return "DEPLOY_IN_PROGRESS"
    if run.conclusion == "success":
        return (
            "DEPLOYED_WITH_OVERRIDE"
            if blocked or decision == "APPROVED"
            else "DEPLOYED"
        )
    return "DEPLOY_FAILED"


def _normalize_repo(value: str) -> str:
    v = (value or "").strip().rstrip("/")
    for prefix in ("https://github.com/", "http://github.com/", "git@github.com:"):
        if v.startswith(prefix):
            v = v[len(prefix) :]
            break
    return (v[:-4] if v.endswith(".git") else v).lower()


def _resolve_target(repo: str, pr_number: Any) -> tuple[str, int]:
    """Validate identifiers; never substitute a different repository or pull request."""
    try:
        pr_int = int(pr_number)
    except (TypeError, ValueError):
        raise ValueError("Invalid pull request number") from None
    target = _normalize_repo(os.environ.get("TARGET_REPO", ""))
    supplied = _normalize_repo(repo)
    if not supplied or pr_int < 1:
        raise ValueError("Repository and positive pull request number are required")
    if not target:
        raise ValueError("TARGET_REPO is not configured")
    if supplied != target:
        raise ValueError("Repository does not match TARGET_REPO")
    return supplied, pr_int


@tool
def get_pr_metadata(repo: str, pr_number: int) -> dict:
    """Return PR metadata: title, author, branches, additions, deletions, changed files."""
    try:
        repo, pr_number = _resolve_target(repo, pr_number)
        pr = _gh().get_repo(repo).get_pull(int(pr_number))
        return {
            "title": pr.title,
            "author": pr.user.login,
            "base_branch": pr.base.ref,
            "head_branch": pr.head.ref,
            "head_sha": pr.head.sha,
            "additions": pr.additions,
            "deletions": pr.deletions,
            "changed_files": [f.filename for f in pr.get_files()],
        }
    except Exception as exc:  # noqa: BLE001 - must not crash the agent
        return {
            "error": _err(exc),
            "note": f"could not fetch metadata for {repo}#{pr_number}",
        }


@tool
def get_pr_diff(repo: str, pr_number: int) -> str:
    """Fetch the unified diff text for a pull request."""
    import httpx

    try:
        token = os.environ["GITHUB_TOKEN"]
        repo, pr_number = _resolve_target(repo, pr_number)
        pr = _gh().get_repo(repo).get_pull(int(pr_number))
        resp = httpx.get(
            pr.url,
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3.diff",
            },
            follow_redirects=True,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.text
    except Exception as exc:  # noqa: BLE001 - must not crash the agent
        return f"ERROR fetching diff for {repo}#{pr_number}: {_err(exc)}"


@tool
def get_pr_files(repo: str, pr_number: int) -> list:
    """List files changed in a PR with patch content."""
    try:
        repo, pr_number = _resolve_target(repo, pr_number)
        pr = _gh().get_repo(repo).get_pull(int(pr_number))
        return [
            {
                "filename": f.filename,
                "status": f.status,
                "additions": f.additions,
                "deletions": f.deletions,
                "patch": f.patch or "",
            }
            for f in pr.get_files()
        ]
    except Exception as exc:  # noqa: BLE001 - must not crash the agent
        return [
            {"error": _err(exc), "note": f"could not list files for {repo}#{pr_number}"}
        ]


@tool
def post_pr_comment(repo: str, pr_number: int, body: str) -> str:
    """Post a comment on a GitHub pull request. Returns the comment URL."""
    try:
        repo, pr_number = _resolve_target(repo, pr_number)
        pr = _gh().get_repo(repo).get_pull(int(pr_number))
        comment = pr.create_issue_comment(body)
        return comment.html_url
    except Exception as exc:  # noqa: BLE001 - must not crash the agent
        return f"ERROR posting comment to {repo}#{pr_number}: {_err(exc)}"


@tool
def post_audit_report(
    repo: str,
    pr_number: int,
    decision: str,
    expected_head_sha: str,
    deploy_run_id: int | None = None,
) -> dict:
    """Assemble and post the FINAL MergeGuard audit report for a PR — deterministically.

    A deployment is only reported as successful when the supplied run belongs to the configured
    deploy workflow and its unique run title contains the reviewed head SHA. Missing or
    inconsistent data is UNKNOWN.
    """
    try:
        repo, pr_number = _resolve_target(repo, pr_number)
        gh_repo = _gh().get_repo(repo)
        pr = gh_repo.get_pull(int(pr_number))
        if not expected_head_sha or pr.head.sha != expected_head_sha:
            return {
                "error": "PR head does not match reviewed SHA",
                "overall": "UNKNOWN",
            }

        blocked = any(
            f"<!-- mergeguard:blocked:{expected_head_sha} -->" in (comment.body or "")
            for comment in pr.get_issue_comments()
        )
        decision = decision.strip().upper()
        if decision not in {
            "PASS",
            "APPROVED",
            "REJECTED",
            "BLOCKED",
            "DEPLOY_FAILED",
        }:
            decision = "UNKNOWN"

        deploy_status = "NOT RUN"
        run = None
        if deploy_run_id:
            run = gh_repo.get_workflow_run(int(deploy_run_id))
            expected_workflow = gh_repo.get_workflow(
                os.environ.get("DEPLOY_WORKFLOW_FILE", "deploy.yml")
            )
            run_title = getattr(run, "display_title", "") or ""
            if (
                run.workflow_id != expected_workflow.id
                or run.event != "workflow_dispatch"
                or run.head_branch != "main"
                or expected_head_sha not in run_title
            ):
                return {
                    "error": "Deployment run does not match workflow and reviewed SHA",
                    "overall": "UNKNOWN",
                }
            deploy_status = run.conclusion or run.status or "UNKNOWN"

        overall = _audit_overall(decision, blocked, run)

        security_cell = (
            "Block marker found" if blocked else "No current-SHA block marker"
        )
        deploy_cell = deploy_status
        body = (
            "## 📋 MergeGuard — Audit Report\n\n"
            f"**PR #{pr_number}** — {pr.title} · by @{pr.user.login}\n\n"
            "| Stage | Result |\n"
            "|-------|--------|\n"
            f"| Review decision | {decision} |\n"
            f"| Security block marker | {security_cell} |\n"
            f"| Deployment workflow | {deploy_cell} |\n\n"
            f"### Overall: **{overall}**\n\n"
            f"Reviewed commit: `{expected_head_sha}`\n\n"
            "_Generated by MergeGuard ReportAgent._"
        )
        comment = pr.create_issue_comment(body)
        return {"comment_url": comment.html_url, "overall": overall}
    except Exception as exc:  # noqa: BLE001 - must not crash the agent
        return {"error": _err(exc), "overall": "UNKNOWN", "comment_url": ""}
