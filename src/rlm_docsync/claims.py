"""Simplified claim schema matching GS-S6 spec.

Defines ClaimResult and EvidenceRef -- the output side of a doc-sync
run.  These are intentionally minimal; the full GuardSpine product adds
compression, decision queues, and organizational policy on top.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ClaimStatus(Enum):
    """Outcome of inspecting a single claim."""

    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"


@dataclass(frozen=True)
class EvidenceRef:
    """A pointer to a piece of evidence found (or not found) in source."""

    source_type: str  # "code" | "markdown"
    path: str  # file path relative to repo root
    line: int = 0  # 0 means not applicable
    snippet: str = ""  # short excerpt (<=120 chars)
    matched: bool = False  # True if evidence confirms the claim


@dataclass
class ClaimResult:
    """Result of evaluating one claim from the manifest."""

    claim_id: str
    claim_text: str
    status: ClaimStatus = ClaimStatus.SKIP
    evidence: list[EvidenceRef] = field(default_factory=list)
    message: str = ""  # human-readable explanation

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "claim_text": self.claim_text,
            "status": self.status.value,
            "evidence": [
                {
                    "source_type": e.source_type,
                    "path": e.path,
                    "line": e.line,
                    "snippet": e.snippet,
                    "matched": e.matched,
                }
                for e in self.evidence
            ],
            "message": self.message,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ClaimResult:
        evidence = [
            EvidenceRef(
                source_type=e["source_type"],
                path=e["path"],
                line=e.get("line", 0),
                snippet=e.get("snippet", ""),
                matched=e.get("matched", False),
            )
            for e in data.get("evidence", [])
        ]
        return cls(
            claim_id=data["claim_id"],
            claim_text=data["claim_text"],
            status=ClaimStatus(data.get("status", "skip")),
            evidence=evidence,
            message=data.get("message", ""),
        )
