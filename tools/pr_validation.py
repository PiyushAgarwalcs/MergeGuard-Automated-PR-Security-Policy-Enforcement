"""Run PR tests and dependency audits in an isolated GitHub Actions runner."""

from __future__ import annotations

import os
import re
import time
import uuid
from urllib.parse import quote

import httpx
from langchain_core.tools import tool


def _normalize_repo(value: str) -> str:
    normalized = (value or "").strip().rstrip("/")
    for prefix in ("https://github.com/", "http://github.com/", "git@github.com:"):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :]
            break
    if normalized.endswith(".git"):
        normalized = normalized[:-4]
    return normalized.lower()


@tool
def validate_pr_commit(repo: str, pr_number: int, head_sha: str) -> dict:
    """Run tests and dependency auditing against the exact PR commit in GitHub Actions.

    The isolated workflow checks out the target repository without persisting credentials,
    then runs untrusted project code with no GitHub token or write permissions.
    """
    try:
        token = os.environ["GITHUB_TOKEN"]
        target_repo = _normalize_repo(os.environ["TARGET_REPO"])
        if not target_repo or _normalize_repo(repo) != target_repo:
            return {
                "ok": False,
                "status": "REJECTED",
                "error": "PR repository does not match TARGET_REPO",
            }
        if int(pr_number) < 1:
            return {"ok": False, "status": "REJECTED", "error": "Invalid PR number"}
        if not re.fullmatch(r"[0-9a-f]{40}", head_sha):
            return {"ok": False, "status": "REJECTED", "error": "Invalid PR head SHA"}

        from github import Github

        gh_repo = Github(token).get_repo(target_repo)
        pr = gh_repo.get_pull(int(pr_number))
        if pr.base.ref != "main":
            return {"ok": False, "status": "REJECTED", "error": "PR base is not main"}
        if pr.head.sha != head_sha:
            return {
                "ok": False,
                "status": "STALE",
                "error": "PR head changed; review and validation must restart",
            }

        validation_repo = os.environ.get(
            "PR_VALIDATION_REPO",
            "PiyushAgarwalcs/MergeGuard-Automated-PR-Security-Policy-Enforcement",
        )
        validation_ref = os.environ.get("PR_VALIDATION_REF", "main")
        workflow_file = os.environ.get(
            "PR_VALIDATION_WORKFLOW_FILE", "pr-validation.yml"
        )
        request_id = uuid.uuid4().hex
        workflow_repo = Github(token).get_repo(validation_repo)
        workflow = workflow_repo.get_workflow(workflow_file)
        workflow.create_dispatch(
            ref=validation_ref,
            inputs={
                "repository": target_repo,
                "pr_number": str(pr_number),
                "head_sha": head_sha,
                "request_id": request_id,
            },
        )

        api_url = f"https://api.github.com/repos/{validation_repo}/actions/workflows/{quote(workflow_file, safe='')}/runs"
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        deadline = time.monotonic() + 1500
        run: dict | None = None
        while time.monotonic() < deadline:
            response = httpx.get(
                api_url,
                headers=headers,
                params={
                    "event": "workflow_dispatch",
                    "branch": validation_ref,
                    "per_page": 20,
                },
                timeout=30,
            )
            response.raise_for_status()
            for candidate in response.json().get("workflow_runs", []):
                title = candidate.get("display_title") or candidate.get("name") or ""
                if request_id in title:
                    run = candidate
                    break
            if run and run.get("status") == "completed":
                conclusion = run.get("conclusion")
                return {
                    "ok": conclusion == "success",
                    "status": "PASS" if conclusion == "success" else "FAILED",
                    "run_id": run.get("id"),
                    "run_url": run.get("html_url", ""),
                    "conclusion": conclusion or "unknown",
                    "error": "" if conclusion == "success" else "PR validation failed",
                }
            time.sleep(5)

        return {
            "ok": False,
            "status": "TIMEOUT",
            "run_id": run.get("id") if run else None,
            "run_url": run.get("html_url", "") if run else "",
            "error": "PR validation did not complete before timeout",
        }
    except Exception as exc:  # noqa: BLE001 - validation errors must fail closed
        return {
            "ok": False,
            "status": "FAILED",
            "error": f"{type(exc).__name__}: {exc}"[:300],
        }
