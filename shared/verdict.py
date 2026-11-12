"""Verdict and severity vocabularies shared across the agent chain."""

from __future__ import annotations

from enum import Enum


class Verdict(str, Enum):
    """A stage's decision in the approval chain."""

    PASS = "PASS"
    WARN = "WARN"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"


class Severity(str, Enum):
    """Security finding severity, ordered LOW < MED < HIGH < CRIT."""

    LOW = "LOW"
    MED = "MED"
    HIGH = "HIGH"
    CRIT = "CRIT"

    @property
    def rank(self) -> int:
        return {"LOW": 0, "MED": 1, "HIGH": 2, "CRIT": 3}[self.value]


# Maps a SecurityAgent severity to the verdict it should hand downstream.
SEVERITY_TO_VERDICT: dict[Severity, Verdict] = {
    Severity.LOW: Verdict.PASS,
    Severity.MED: Verdict.PASS,
    Severity.HIGH: Verdict.WARN,
    Severity.CRIT: Verdict.BLOCK,
}
