"""Validated PR context and security findings shared by the webhook and tools."""

from __future__ import annotations

from pydantic import BaseModel, Field

from .verdict import Severity


class PRContext(BaseModel):
    """Extracted from the GitHub webhook; seeds the whole chain."""

    repo: str  # "owner/name"
    pr_number: int
    title: str = ""
    author: str
    base_branch: str = "main"
    head_branch: str
    head_sha: str = ""
    diff_url: str = ""
    changed_files: list[str] = Field(default_factory=list)
    additions: int = 0
    deletions: int = 0

    @property
    def diff_size(self) -> int:
        return self.additions + self.deletions


class Finding(BaseModel):
    """One issue located in the diff."""

    file: str
    line: int | None = None
    rule: str = ""
    message: str
    severity: Severity = Severity.LOW
