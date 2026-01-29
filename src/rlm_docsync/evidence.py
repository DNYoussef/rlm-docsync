"""DocEvidencePack: the output artifact of a doc-sync run.

Each pack is a JSON document with a SHA-256 hash chain so that any
consumer can independently verify that no entries were tampered with
or reordered after the run completed.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .claims import ClaimResult


def _sha256(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass
class DocEvidencePack:
    """Immutable evidence pack produced by a doc-sync run."""

    manifest_hash: str  # SHA-256 of the manifest file content
    runner: str = "rlm-docsync"
    runner_version: str = "0.1.0"
    timestamp: str = ""
    results: list[ClaimResult] = field(default_factory=list)
    hash_chain: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = (
                datetime.now(timezone.utc)
                .isoformat(timespec="seconds")
            )

    # ------------------------------------------------------------------
    # Hash chain
    # ------------------------------------------------------------------

    def build_hash_chain(self) -> list[str]:
        """Compute the SHA-256 hash chain over all results.

        Each link is:  sha256(previous_hash | json(result))
        The first link uses the manifest_hash as its predecessor.
        """
        chain: list[str] = []
        prev = self.manifest_hash
        for result in self.results:
            entry_json = json.dumps(result.to_dict(), sort_keys=True)
            link = _sha256(f"{prev}|{entry_json}")
            chain.append(link)
            prev = link
        self.hash_chain = chain
        return chain

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_json(self, indent: int = 2) -> str:
        if not self.hash_chain:
            self.build_hash_chain()
        payload: dict[str, Any] = {
            "manifest_hash": self.manifest_hash,
            "runner": self.runner,
            "runner_version": self.runner_version,
            "timestamp": self.timestamp,
            "results": [r.to_dict() for r in self.results],
            "hash_chain": self.hash_chain,
        }
        return json.dumps(payload, indent=indent, sort_keys=False)

    @classmethod
    def from_json(cls, text: str) -> DocEvidencePack:
        data = json.loads(text)
        results = [ClaimResult.from_dict(r) for r in data.get("results", [])]
        pack = cls(
            manifest_hash=data["manifest_hash"],
            runner=data.get("runner", "rlm-docsync"),
            runner_version=data.get("runner_version", "0.1.0"),
            timestamp=data.get("timestamp", ""),
            results=results,
            hash_chain=data.get("hash_chain", []),
        )
        return pack

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self) -> tuple[bool, str]:
        """Verify the hash chain integrity.

        Returns (True, "ok") on success or (False, reason) on failure.
        """
        if len(self.hash_chain) != len(self.results):
            return False, (
                f"chain length ({len(self.hash_chain)}) != "
                f"results length ({len(self.results)})"
            )
        prev = self.manifest_hash
        for i, result in enumerate(self.results):
            entry_json = json.dumps(result.to_dict(), sort_keys=True)
            expected = _sha256(f"{prev}|{entry_json}")
            if i >= len(self.hash_chain):
                return False, f"chain too short at index {i}"
            if self.hash_chain[i] != expected:
                return False, (
                    f"hash mismatch at index {i}: "
                    f"expected {expected}, got {self.hash_chain[i]}"
                )
            prev = expected
        return True, "ok"
