"""Unit tests for dependency-light shared logic (no Band/LLM/network required)."""

from __future__ import annotations

from shared.context_schema import PRContext
from shared.verdict import SEVERITY_TO_VERDICT, Severity, Verdict


def test_severity_ranking_is_ordered():
    assert (
        Severity.LOW.rank < Severity.MED.rank < Severity.HIGH.rank < Severity.CRIT.rank
    )


def test_severity_to_verdict_mapping():
    assert SEVERITY_TO_VERDICT[Severity.LOW] is Verdict.PASS
    assert SEVERITY_TO_VERDICT[Severity.MED] is Verdict.PASS
    assert SEVERITY_TO_VERDICT[Severity.HIGH] is Verdict.WARN
    assert SEVERITY_TO_VERDICT[Severity.CRIT] is Verdict.BLOCK


def test_pr_context_diff_size():
    pr = PRContext(
        repo="o/r",
        pr_number=47,
        author="dan",
        head_branch="feat",
        additions=600,
        deletions=12,
    )
    assert pr.diff_size == 612
