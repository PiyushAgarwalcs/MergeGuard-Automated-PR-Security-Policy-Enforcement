"""LangChain tool: trigger a GitHub Actions workflow and poll until completion."""

from __future__ import annotations

import os
import re
import time
import uuid
from datetime import datetime, timedelta, timezone

from langchain_core.tools import tool


def _normalize_repo(value: str) -> str:
    """Accept 'owner/repo' or a full GitHub URL and return 'owner/repo'."""
    v = (value or "").strip().rstrip("/")
    for prefix in ("https://github.com/", "http://github.com/", "git@github.com:"):
        if v.startswith(prefix):
            v = v[len(prefix) :]
            break
    if v.endswith(".git"):
        v = v[: -len(".git")]
    return v.lower()


@tool
def trigger_deployment(
    repo: str,
    pr_number: int,
    expected_head_sha: str,
) -> dict:
    """Dispatch the trusted base-branch workflow to deploy the reviewed commit.

    The workflow must accept head_sha, pr_number, and request_id inputs, then check out
    head_sha. Running the workflow from the PR branch would execute untrusted workflow code.
    """
    try:
        from github import Github

        token = os.environ["GITHUB_TOKEN"]
        target_repo = _normalize_repo(os.environ.get("TARGET_REPO") or "")
        requested_repo = _normalize_repo(repo or "")
        if not target_repo or requested_repo != target_repo:
            raise ValueError("Repository does not match TARGET_REPO")
        if pr_number < 1 or not re.fullmatch(r"[0-9a-f]{40}", expected_head_sha):
            raise ValueError("PR number and reviewed head SHA are required")

        wf_file = os.environ.get("DEPLOY_WORKFLOW_FILE", "deploy.yml")
        g = Github(token)
        r = g.get_repo(target_repo)
        pr = r.get_pull(pr_number)
        if pr.base.ref != "main":
            raise ValueError("Only PRs targeting main can be deployed")
        if pr.head.sha != expected_head_sha:
            return {
                "success": False,
                "run_id": None,
                "run_url": "",
                "status": "STALE",
                "error": "PR head changed since review; deployment not triggered",
            }

        wf = r.get_workflow(wf_file)
        request_id = uuid.uuid4().hex
        dispatched_at = datetime.now(timezone.utc) - timedelta(seconds=5)
        wf.create_dispatch(
            ref=pr.base.ref,
            inputs={
                "head_sha": expected_head_sha,
                "pr_number": str(pr_number),
                "request_id": request_id,
            },
        )
    except Exception as exc:  # noqa: BLE001 - never crash the agent
        return {
            "success": False,
            "run_id": None,
            "run_url": "",
            "status": "FAILED",
            "error": f"{type(exc).__name__}: {exc}"[:200],
        }

    run = _find_dispatched_run(r, wf.id, "main", dispatched_at, request_id, timeout=60)
    if not run:
        return {
            "success": False,
            "run_id": None,
            "run_url": "",
            "status": "FAILED",
            "error": "Run not found after dispatch",
        }
    run_title = getattr(run, "display_title", "") or ""
    if run.head_sha != pr.base.sha or expected_head_sha not in run_title:
        try:
            run.cancel()
        except Exception:
            pass
        return {
            "success": False,
            "run_id": run.id,
            "run_url": run.html_url,
            "status": "STALE",
            "error": "Dispatched run did not match the trusted base or reviewed SHA",
        }

    # Poll only briefly. The chain must not stall for minutes waiting on Actions — DeployAgent
    # confirms the deploy started, hands off to ReportAgent, and ReportAgent's audit reads the
    # final run conclusion. A fast echo deploy usually finishes inside this window anyway.
    result = _poll_run(r, run.id, timeout=60)
    result["run_id"] = run.id
    result["run_url"] = run.html_url
    result["head_sha"] = run.head_sha
    return result


def _find_dispatched_run(
    repo, workflow_id: int, branch: str, dispatched_at, request_id: str, timeout: int
):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            runs = list(repo.get_workflow_runs(workflow_id=workflow_id, branch=branch))
            for run in runs:
                if (
                    run.event == "workflow_dispatch"
                    and run.head_branch == branch
                    and run.created_at >= dispatched_at
                    and request_id in (getattr(run, "display_title", "") or "")
                ):
                    return run
        except Exception:
            pass
        time.sleep(2)
    return None


def _poll_run(repo, run_id: int, timeout: int) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            run = repo.get_workflow_run(run_id)
            if run.status == "completed":
                success = run.conclusion == "success"
                return {
                    "success": success,
                    "status": "READY" if success else "FAILED",
                    "error": "" if success else f"conclusion={run.conclusion}",
                }
        except Exception as exc:
            return {"success": False, "status": "FAILED", "error": str(exc)}
        time.sleep(5)
    # Still running — the dispatch succeeded, so this is a success for hand-off purposes.
    # ReportAgent's audit reads the actual conclusion from the run.
    return {"success": True, "status": "TRIGGERED", "error": ""}
