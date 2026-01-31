"""Simplified claim schema matching GS-S6 spec.

Defines ClaimResult and EvidenceRef -- the output side of a doc-sync
run.  These are intentionally minimal; the full GuardSpine product adds
compression, decision queues, and organizational policy on top.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


_MAX_SNIPPET_LEN = 120  # Maximum length for evidence snippets


class ClaimStatus(Enum):
    """Outcome of inspecting a single claim."""

    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"


@dataclass(frozen=True)
class EvidenceRef:
    """A pointer to a piece of evidence found (or not found) in source.

    Attributes:
        source_type: Origin adapter -- ``"code"`` or ``"markdown"``.
        path: File path relative to the repository root.
        line: 1-based line number where evidence was found (0 = N/A).
        snippet: Short excerpt of the matching line (max 120 chars).
        matched: ``True`` when the evidence confirms the associated claim.
    """

    source_type: str
    path: str
    line: int = 0
    snippet: str = ""
    matched: bool = False

    def __post_init__(self) -> None:
        if len(self.snippet) > _MAX_SNIPPET_LEN:
            object.__setattr__(
                self, "snippet", self.snippet[:_MAX_SNIPPET_LEN]
            )


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
        """Deserialize a ClaimResult from a dict.

        Validates required keys and field types to guard against
        malformed or maliciously crafted input.

        Raises:
            KeyError: if required keys (claim_id, claim_text) are missing.
            ValueError: if field values have unexpected types.
        """
        if not isinstance(data, dict):
            raise ValueError(
                f"ClaimResult.from_dict expects a dict, got {type(data).__name__}"
            )
        for key in ("claim_id", "claim_text"):
            if key not in data:
                raise KeyError(f"ClaimResult.from_dict: missing required key '{key}'")

        raw_evidence = data.get("evidence", [])
        if not isinstance(raw_evidence, list):
            raise ValueError("ClaimResult.from_dict: 'evidence' must be a list")

        evidence: list[EvidenceRef] = []
        for e in raw_evidence:
            if not isinstance(e, dict):
                raise ValueError(
                    "ClaimResult.from_dict: each evidence entry must be a dict"
                )
            snippet = str(e.get("snippet", ""))[:_MAX_SNIPPET_LEN]
            evidence.append(
                EvidenceRef(
                    source_type=str(e.get("source_type", "")),
                    path=str(e.get("path", "")),
                    line=int(e.get("line", 0)),
                    snippet=snippet,
                    matched=bool(e.get("matched", False)),
                )
            )

        status_raw = data.get("status", "skip")
        try:
            status = ClaimStatus(status_raw)
        except ValueError:
            status = ClaimStatus.SKIP

        return cls(
            claim_id=str(data["claim_id"]),
            claim_text=str(data["claim_text"]),
            status=status,
            evidence=evidence,
            message=str(data.get("message", "")),
        )
