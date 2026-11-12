"""Tests for tools/ — no network, no Band, no LLM credentials required."""

from __future__ import annotations

from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


# ── security_scanner ─────────────────────────────────────────────────────────


def test_security_scanner_flags_vuln_diff():
    from shared.verdict import Severity
    from tools.security_scanner import scan_diff_regex

    diff = (FIXTURES / "vuln_pr_diff.txt").read_text()
    findings = scan_diff_regex(diff)
    severities = {f.severity for f in findings}
    assert (
        Severity.CRIT in severities
    ), f"Expected CRIT finding in vuln diff, got: {[f.message for f in findings]}"


def test_security_scanner_passes_clean_diff():
    from shared.verdict import Severity
    from tools.security_scanner import scan_diff_regex

    diff = (FIXTURES / "clean_pr_diff.txt").read_text()
    findings = scan_diff_regex(diff)
    crit_findings = [f for f in findings if f.severity == Severity.CRIT]
    assert crit_findings == [], f"Unexpected CRIT in clean diff: {crit_findings}"


def test_security_review_blocks_and_autoposts(monkeypatch):
    """The deterministic review tool must auto-post the CRIT comment + escalate, with no
    dependence on the LLM. This locks the demo's hero visual."""
    import os

    os.environ.setdefault("BAND_USERNAME", "danny.ssd7")
    monkeypatch.setenv("TARGET_REPO", "x/y")
    from langchain_core.tools import tool

    import tools.github_api as gh

    posted: list[str] = []

    @tool
    def _meta(repo: str, pr_number: int) -> dict:
        """fake"""
        return {"head_sha": "a" * 40}

    @tool
    def _diff(repo: str, pr_number: int) -> str:
        """fake"""
        return (FIXTURES / "vuln_pr_diff.txt").read_text()

    @tool
    def _post(repo: str, pr_number: int, body: str) -> str:
        """fake"""
        posted.append(body)
        return "https://github.com/x/y/pull/1#comment-1"

    monkeypatch.setattr(gh, "get_pr_metadata", _meta)
    monkeypatch.setattr(gh, "get_pr_diff", _diff)
    monkeypatch.setattr(gh, "post_pr_comment", _post)

    from tools.security_scanner import security_review

    r = security_review.invoke(
        {"repo": "x/y", "pr_number": 1, "expected_head_sha": "a" * 40}
    )
    assert r["verdict"] == "BLOCK"
    assert len(posted) == 1, "must auto-post exactly one CRIT comment"
    assert r["handoff"].endswith("danny.ssd7"), "BLOCK escalates to the engineer"


def test_security_review_clean_routes_to_risk(monkeypatch):
    import os

    os.environ.setdefault("BAND_USERNAME", "danny.ssd7")
    monkeypatch.setenv("TARGET_REPO", "x/y")
    from langchain_core.tools import tool

    import tools.github_api as gh

    posted: list[str] = []

    @tool
    def _meta(repo: str, pr_number: int) -> dict:
        """fake"""
        return {"head_sha": "a" * 40}

    @tool
    def _diff(repo: str, pr_number: int) -> str:
        """fake"""
        return (FIXTURES / "clean_pr_diff.txt").read_text()

    @tool
    def _post(repo: str, pr_number: int, body: str) -> str:
        """fake"""
        posted.append(body)
        return "url"

    monkeypatch.setattr(gh, "get_pr_metadata", _meta)
    monkeypatch.setattr(gh, "get_pr_diff", _diff)
    monkeypatch.setattr(gh, "post_pr_comment", _post)

    import tools.security_scanner as scanner

    monkeypatch.setattr(scanner, "_llm_scan", lambda diff, agent_key: ([], ""))
    from tools.security_scanner import security_review

    r = security_review.invoke(
        {"repo": "x/y", "pr_number": 2, "expected_head_sha": "a" * 40}
    )
    assert r["verdict"] == "PASS"
    assert posted == [], "clean diff must NOT post a comment"
    assert "riskagent" in r["handoff"], "PASS hands off to RiskAgent"


def test_security_review_escalates_when_head_changed(monkeypatch):
    import os

    os.environ.setdefault("BAND_USERNAME", "danny.ssd7")
    monkeypatch.setenv("TARGET_REPO", "x/y")
    from langchain_core.tools import tool

    import tools.github_api as gh

    @tool
    def _meta(repo: str, pr_number: int) -> dict:
        """fake"""
        return {"head_sha": "b" * 40}

    monkeypatch.setattr(gh, "get_pr_metadata", _meta)
    from tools.security_scanner import security_review

    result = security_review.invoke(
        {"repo": "x/y", "pr_number": 2, "expected_head_sha": "a" * 40}
    )
    assert result["verdict"] == "ESCALATE"
    assert "head changed" in result["summary"]


def test_llm_security_review_parses_structured_findings(monkeypatch):
    class FakeLLM:
        def invoke(self, prompt):
            return type(
                "Response",
                (),
                {
                    "content": (
                        '{"findings":[{"file":"app.py","line":8,"severity":"HIGH",'
                        '"message":"Unsafe deserialization"}]}'
                    )
                },
            )()

    import shared.llm_factory as factory

    monkeypatch.setattr(factory, "build_llm", lambda agent_key: FakeLLM())
    from tools.security_scanner import _llm_scan

    findings, error = _llm_scan("diff", "security")
    assert error == ""
    assert len(findings) == 1
    assert findings[0].file == "app.py"
    assert findings[0].severity.value == "HIGH"


# ── risk_scorer ──────────────────────────────────────────────────────────────


def test_risk_scorer_auth_file_scores_high():
    from tools.risk_scorer import _compute_risk

    result = _compute_risk(["app/auth.py"], 100, 10, "PASS", "PASS", 0)
    assert result["score"] >= 30
    assert "auth_file_touched" in result["factors"]


def test_risk_scorer_payment_escalates():
    from tools.risk_scorer import _compute_risk

    result = _compute_risk(["app/billing.py"], 200, 50, "PASS", "PASS", 0)
    assert result["score"] >= 40
    assert result["verdict"] in ("PASS", "ESCALATE")


def test_risk_scorer_large_diff_adds_points():
    from tools.risk_scorer import _compute_risk

    result = _compute_risk(["app/utils.py"], 400, 200, "PASS", "PASS", 0)
    assert result["factors"].get("large_diff") == 10


def test_risk_scorer_score_capped_at_100():
    from tools.risk_scorer import _compute_risk

    result = _compute_risk(
        ["app/auth.py", "app/billing.py"], 600, 100, "WARN", "WARN", 4
    )
    assert result["score"] <= 100


def _mock_meta(monkeypatch, changed_files):
    """Point assess_risk's get_pr_metadata at a fake (no network)."""
    import os

    os.environ.setdefault("BAND_USERNAME", "danny.ssd7")
    monkeypatch.setenv("TARGET_REPO", "x/y")
    from langchain_core.tools import tool

    import tools.github_api as gh

    @tool
    def _meta(repo: str, pr_number: int) -> dict:
        """fake"""
        return {
            "changed_files": changed_files,
            "additions": 10,
            "deletions": 0,
            "head_sha": "a" * 40,
        }

    monkeypatch.setattr(gh, "get_pr_metadata", _meta)


def test_assess_risk_challenges_sensitive_passed_change(monkeypatch):
    """A security-sensitive change SecurityAgent only PASSed must trigger a peer-review
    challenge back to SecurityAgent (the agent-reviews-agent consensus gate)."""
    _mock_meta(monkeypatch, ["app/auth.py"])
    from tools.risk_scorer import assess_risk

    r = assess_risk.invoke(
        {
            "repo": "x/y",
            "pr_number": 1,
            "expected_head_sha": "a" * 40,
            "scan_verdict": "PASS",
            "security_verdict": "PASS",
        }
    )
    assert r["cross_check"] == "challenge"
    assert "securityagent" in r["challenge_handle"].lower()


def test_assess_risk_endorses_nonsensitive_change(monkeypatch):
    _mock_meta(monkeypatch, ["app/utils.py"])
    from tools.risk_scorer import assess_risk

    r = assess_risk.invoke(
        {
            "repo": "x/y",
            "pr_number": 2,
            "expected_head_sha": "a" * 40,
            "scan_verdict": "PASS",
            "security_verdict": "PASS",
        }
    )
    assert r["cross_check"] == "endorsed"


def test_assess_risk_escalates_when_metadata_is_unavailable(monkeypatch):
    _mock_meta(monkeypatch, [])
    from langchain_core.tools import tool

    import tools.github_api as gh

    @tool
    def _failed_meta(repo: str, pr_number: int) -> dict:
        """fake"""
        return {"error": "GitHub unavailable"}

    monkeypatch.setattr(gh, "get_pr_metadata", _failed_meta)
    from tools.risk_scorer import assess_risk

    result = assess_risk.invoke(
        {
            "repo": "x/y",
            "pr_number": 3,
            "expected_head_sha": "a" * 40,
            "scan_verdict": "PASS",
            "security_verdict": "PASS",
        }
    )
    assert result["verdict"] == "ESCALATE"
    assert result["handoff"].endswith("danny.ssd7")
    assert "error" in result


def test_assess_risk_never_overrides_upstream_block(monkeypatch):
    import os

    os.environ.setdefault("BAND_USERNAME", "danny.ssd7")
    from tools.risk_scorer import assess_risk

    result = assess_risk.invoke(
        {
            "repo": "x/y",
            "pr_number": 3,
            "expected_head_sha": "a" * 40,
            "scan_verdict": "BLOCK",
            "security_verdict": "PASS",
        }
    )
    assert result["verdict"] == "ESCALATE"
    assert result["handoff"].endswith("danny.ssd7")


def test_resolve_target_rejects_mismatched_repository(monkeypatch):
    import pytest

    from tools.github_api import _resolve_target

    monkeypatch.setenv("TARGET_REPO", "owner/target")
    with pytest.raises(ValueError, match="does not match"):
        _resolve_target("owner/other", 12)


def test_audit_never_claims_deployment_without_a_matching_run():
    from tools.github_api import _audit_overall

    assert _audit_overall("REJECTED", False, None) == "REJECTED"
    assert _audit_overall("PASS", False, None) == "UNKNOWN"
    success = type("Run", (), {"status": "completed", "conclusion": "success"})()
    assert _audit_overall("APPROVED", False, success) == "DEPLOYED_WITH_OVERRIDE"


def test_audit_rejects_run_without_reviewed_sha_marker(monkeypatch):
    from types import SimpleNamespace

    import tools.github_api as gh

    class FakePR:
        title = "test"
        user = SimpleNamespace(login="author")
        head = SimpleNamespace(sha="a" * 40)

        def get_issue_comments(self):
            return []

        def create_issue_comment(self, body):
            raise AssertionError("an unverified run must not be reported")

    class FakeRepo:
        def get_pull(self, number):
            return FakePR()

        def get_workflow_run(self, run_id):
            return SimpleNamespace(
                workflow_id=7,
                event="workflow_dispatch",
                head_branch="main",
                display_title="MergeGuard deploy missing-sha",
            )

        def get_workflow(self, workflow_file):
            return SimpleNamespace(id=7)

    class FakeGithub:
        def get_repo(self, repo):
            return FakeRepo()

    monkeypatch.setenv("TARGET_REPO", "owner/target")
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setattr(gh, "_gh", lambda: FakeGithub())
    result = gh.post_audit_report.invoke(
        {
            "repo": "owner/target",
            "pr_number": 3,
            "decision": "PASS",
            "expected_head_sha": "a" * 40,
            "deploy_run_id": 123,
        }
    )
    assert result["overall"] == "UNKNOWN"
    assert "reviewed SHA" in result["error"]


def test_validate_pr_commit_rejects_repository_outside_scope(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setenv("TARGET_REPO", "owner/target")
    from tools.pr_validation import validate_pr_commit

    result = validate_pr_commit.invoke(
        {
            "repo": "owner/other",
            "pr_number": 8,
            "head_sha": "a" * 40,
        }
    )
    assert result["ok"] is False
    assert result["status"] == "REJECTED"


def test_validate_pr_commit_stops_when_pr_head_changed(monkeypatch):
    import sys
    from types import SimpleNamespace

    class FakeRepo:
        def get_pull(self, number):
            return SimpleNamespace(
                base=SimpleNamespace(ref="main"),
                head=SimpleNamespace(sha="b" * 40),
            )

        def get_workflow(self, workflow_file):
            raise AssertionError("stale commits must not be dispatched")

    class FakeGithub:
        def __init__(self, token):
            pass

        def get_repo(self, repo):
            return FakeRepo()

    monkeypatch.setitem(sys.modules, "github", SimpleNamespace(Github=FakeGithub))
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setenv("TARGET_REPO", "owner/target")
    from tools.pr_validation import validate_pr_commit

    result = validate_pr_commit.invoke(
        {"repo": "owner/target", "pr_number": 8, "head_sha": "a" * 40}
    )
    assert result["status"] == "STALE"
    assert result["ok"] is False


def test_validate_pr_commit_returns_matching_actions_result(monkeypatch):
    import sys
    from types import SimpleNamespace

    import tools.pr_validation as validator

    dispatched = {}
    request_sha = "a" * 40

    class FakeWorkflow:
        def create_dispatch(self, ref, inputs):
            dispatched.update(inputs)

    class FakeRepo:
        def get_pull(self, number):
            return SimpleNamespace(
                base=SimpleNamespace(ref="main"),
                head=SimpleNamespace(sha=request_sha),
            )

        def get_workflow(self, workflow_file):
            return FakeWorkflow()

    class FakeGithub:
        def __init__(self, token):
            pass

        def get_repo(self, repo):
            return FakeRepo()

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {
                "workflow_runs": [
                    {
                        "display_title": (
                            f"MergeGuard PR validation {dispatched['request_id']}"
                        ),
                        "status": "completed",
                        "conclusion": "success",
                        "id": 123,
                        "html_url": "https://github.com/actions/runs/123",
                    }
                ]
            }

    monkeypatch.setitem(sys.modules, "github", SimpleNamespace(Github=FakeGithub))
    monkeypatch.setattr(validator.httpx, "get", lambda *args, **kwargs: FakeResponse())
    monkeypatch.setattr(validator.time, "sleep", lambda seconds: None)
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setenv("TARGET_REPO", "owner/target")
    monkeypatch.setenv("PR_VALIDATION_REPO", "owner/mergeguard")

    result = validator.validate_pr_commit.invoke(
        {"repo": "owner/target", "pr_number": 8, "head_sha": request_sha}
    )
    assert result["ok"] is True
    assert result["run_id"] == 123
    assert dispatched["head_sha"] == request_sha


def test_deploy_dispatch_uses_trusted_main_and_pinned_sha(monkeypatch):
    import sys
    from datetime import datetime, timedelta, timezone
    from types import SimpleNamespace

    dispatched = {}
    reviewed_sha = "a" * 40
    base_sha = "b" * 40

    class FakeWorkflow:
        id = 7

        def create_dispatch(self, ref, inputs):
            dispatched.update({"ref": ref, **inputs})

    class FakeRun:
        event = "workflow_dispatch"
        head_branch = "main"
        head_sha = base_sha
        created_at = datetime.now(timezone.utc) + timedelta(seconds=1)
        display_title = ""
        id = 123
        html_url = "https://github.com/actions/runs/123"
        status = "completed"
        conclusion = "success"

    run = FakeRun()

    class FakeRepo:
        def get_pull(self, number):
            return SimpleNamespace(
                base=SimpleNamespace(ref="main", sha=base_sha),
                head=SimpleNamespace(ref="feature", sha=reviewed_sha),
            )

        def get_workflow(self, workflow_file):
            return FakeWorkflow()

        def get_workflow_runs(self, workflow_id, branch):
            run.display_title = (
                f"MergeGuard deploy {dispatched['request_id']} {reviewed_sha}"
            )
            return [run]

        def get_workflow_run(self, run_id):
            return run

    class FakeGithub:
        def __init__(self, token):
            pass

        def get_repo(self, repo):
            return FakeRepo()

    monkeypatch.setitem(sys.modules, "github", SimpleNamespace(Github=FakeGithub))
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setenv("TARGET_REPO", "owner/target")
    from tools.deploy_trigger import trigger_deployment

    result = trigger_deployment.invoke(
        {
            "repo": "owner/target",
            "pr_number": 8,
            "expected_head_sha": reviewed_sha,
        }
    )
    assert result["success"] is True
    assert dispatched["ref"] == "main"
    assert dispatched["head_sha"] == reviewed_sha
    assert dispatched["pr_number"] == "8"
    assert dispatched["request_id"]


# ── webhook parser + verifier ─────────────────────────────────────────────────


def test_webhook_parser_accepts_main_pr():
    import json

    from webhook.parser import parse_pr_payload

    payload = json.loads((FIXTURES / "sample_pr_payload.json").read_text())
    pr = parse_pr_payload(payload)
    assert pr is not None
    assert pr.pr_number == 42
    assert pr.author == "contributor"


def test_webhook_parser_ignores_non_main():
    from webhook.parser import parse_pr_payload

    payload = {
        "action": "opened",
        "pull_request": {
            "number": 1,
            "title": "t",
            "user": {"login": "u"},
            "base": {"ref": "dev", "sha": "x"},
            "head": {"ref": "f", "sha": "y"},
            "diff_url": "",
            "additions": 0,
            "deletions": 0,
        },
        "repository": {"full_name": "o/r"},
    }
    assert parse_pr_payload(payload) is None


def test_webhook_verifier_accepts_valid_signature():
    import hashlib
    import hmac
    import os

    os.environ["GITHUB_WEBHOOK_SECRET"] = "test-secret"
    from webhook.verifier import verify_signature

    body = b'{"action":"opened"}'
    sig = "sha256=" + hmac.new(b"test-secret", body, hashlib.sha256).hexdigest()
    assert verify_signature(body, sig) is True


def test_webhook_verifier_rejects_bad_signature():
    import os

    os.environ["GITHUB_WEBHOOK_SECRET"] = "test-secret"
    from webhook.verifier import verify_signature

    assert verify_signature(b"body", "sha256=badhash") is False


# ── llm_factory: multi-key Featherless ────────────────────────────────────────


def test_featherless_key_pool_round_robin(monkeypatch):
    """A key pool spreads agents across keys so no single key is hit twice per run."""
    from shared.llm_factory import _resolve_api_key

    provider = {"api_key_env": "FEATHERLESS_API_KEY"}
    monkeypatch.delenv("FEATHERLESS_API_KEY_SCAN", raising=False)
    monkeypatch.setenv("FEATHERLESS_API_KEYS", "k1,k2,k3")
    # config agent order: scan, security, risk, deploy, report
    assert _resolve_api_key(provider, "scan") == "k1"
    assert _resolve_api_key(provider, "security") == "k2"
    assert _resolve_api_key(provider, "risk") == "k3"
    assert _resolve_api_key(provider, "deploy") == "k1"  # wraps


def test_featherless_per_agent_override(monkeypatch):
    from shared.llm_factory import _resolve_api_key

    provider = {"api_key_env": "FEATHERLESS_API_KEY"}
    monkeypatch.setenv("FEATHERLESS_API_KEY_SCAN", "special")
    assert _resolve_api_key(provider, "scan") == "special"
