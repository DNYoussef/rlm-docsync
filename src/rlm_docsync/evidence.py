"""DocEvidencePack: the output artifact of a doc-sync run.

Each pack is a JSON document with a SHA-256 hash chain so that any
consumer can independently verify that no entries were tampered with
or reordered after the run completed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .claims import ClaimResult
from .sanitization import _sha256_text as _sha256


@dataclass
class DocEvidencePack:
    """Immutable evidence pack produced by a doc-sync run."""

    manifest_hash: str  # SHA-256 of the manifest file content
    runner: str = "rlm-docsync"
    runner_version: str = "0.1.1"
    timestamp: str = ""
    #: Ordered list of :class:`ClaimResult` objects produced by the run.
    #: Each entry corresponds to one claim evaluated against source evidence.
    results: list[ClaimResult] = field(default_factory=list)
    #: Legacy chain view (list of chain_hash values), kept for compatibility.
    hash_chain: list[str] = field(default_factory=list)
    #: Canonical v0.2.x immutability proof.
    immutability_proof: dict[str, Any] = field(default_factory=dict)
    #: Optional sanitization attestation summary.
    sanitization: dict[str, Any] | None = None

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
        """Build canonical v0.2.x proof and update legacy hash_chain view."""
        links: list[dict[str, Any]] = []
        previous_hash = "genesis"

        for idx, result in enumerate(self.results):
            item_id = f"claim-{idx:04d}"
            content_type = "guardspine/rlm-docsync-claim"
            content = result.to_dict()
            content_json = json.dumps(content, sort_keys=True, separators=(",", ":"))
            content_hash = _sha256(content_json)
            chain_input = (
                f"{idx}|{item_id}|{content_type}|{content_hash}|{previous_hash}"
            )
            chain_hash = _sha256(chain_input)
            links.append({
                "sequence": idx,
                "item_id": item_id,
                "content_type": content_type,
                "content_hash": content_hash,
                "previous_hash": previous_hash,
                "chain_hash": chain_hash,
            })
            previous_hash = chain_hash

        concatenated = "".join(link["chain_hash"] for link in links)
        root_hash = _sha256(concatenated)
        self.immutability_proof = {"hash_chain": links, "root_hash": root_hash}
        self.hash_chain = [link["chain_hash"] for link in links]
        return self.hash_chain

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_json(self, indent: int = 2) -> str:
        if not self.hash_chain:
            self.build_hash_chain()
        items = []
        for idx, result in enumerate(self.results):
            item_content = result.to_dict()
            content_json = json.dumps(item_content, sort_keys=True, separators=(",", ":"))
            items.append({
                "item_id": f"claim-{idx:04d}",
                "sequence": idx,
                "content_type": "guardspine/rlm-docsync-claim",
                "content": item_content,
                "content_hash": _sha256(content_json),
            })
        payload: dict[str, Any] = {
            "version": "0.2.1" if self.sanitization else "0.2.0",
            "manifest_hash": self.manifest_hash,
            "runner": self.runner,
            "runner_version": self.runner_version,
            "timestamp": self.timestamp,
            "items": items,
            "immutability_proof": self.immutability_proof,
            "results": [r.to_dict() for r in self.results],
            "hash_chain": self.hash_chain,
        }
        if self.sanitization:
            payload["sanitization"] = self.sanitization
        return json.dumps(payload, indent=indent, sort_keys=False)

    @classmethod
    def from_json(cls, text: str) -> DocEvidencePack:
        data = json.loads(text)
        if data.get("results"):
            results = [ClaimResult.from_dict(r) for r in data.get("results", [])]
        else:
            # v0.2.x payload may only contain items; reconstruct results from item content.
            results = []
            for item in data.get("items", []):
                content = item.get("content", {})
                if isinstance(content, dict):
                    results.append(ClaimResult.from_dict(content))
        pack = cls(
            manifest_hash=data["manifest_hash"],
            runner=data.get("runner", "rlm-docsync"),
            runner_version=data.get("runner_version", "0.1.1"),
            timestamp=data.get("timestamp", ""),
            results=results,
            hash_chain=data.get("hash_chain", []),
            immutability_proof=data.get("immutability_proof", {}),
            sanitization=data.get("sanitization"),
        )
        if not pack.hash_chain and pack.immutability_proof.get("hash_chain"):
            pack.hash_chain = [
                link.get("chain_hash", "")
                for link in pack.immutability_proof.get("hash_chain", [])
            ]
        return pack

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self) -> tuple[bool, str]:
        """Verify the hash chain integrity.

        Returns (True, "ok") on success or (False, reason) on failure.
        """
        if not self.hash_chain:
            # Accept empty packs as valid; they serialize to an empty chain.
            if not self.results:
                return True, "ok"
            self.build_hash_chain()

        if len(self.hash_chain) != len(self.results):
            return False, (
                f"chain length ({len(self.hash_chain)}) != "
                f"results length ({len(self.results)})"
            )
        prev = "genesis"
        recomputed_links: list[dict[str, Any]] = []
        for i, result in enumerate(self.results):
            content = result.to_dict()
            content_json = json.dumps(content, sort_keys=True, separators=(",", ":"))
            item_id = f"claim-{i:04d}"
            content_type = "guardspine/rlm-docsync-claim"
            content_hash = _sha256(content_json)
            expected = _sha256(f"{i}|{item_id}|{content_type}|{content_hash}|{prev}")
            if i >= len(self.hash_chain):
                return False, f"chain too short at index {i}"
            if self.hash_chain[i] != expected:
                return False, (
                    f"hash mismatch at index {i}: "
                    f"expected {expected}, got {self.hash_chain[i]}"
                )
            prev = expected
            recomputed_links.append({
                "sequence": i,
                "item_id": item_id,
                "content_type": content_type,
                "content_hash": content_hash,
                "previous_hash": i == 0 and "genesis" or recomputed_links[-1]["chain_hash"],
                "chain_hash": expected,
            })

        if self.immutability_proof:
            proof = self.immutability_proof
            chain = proof.get("hash_chain", [])
            if len(chain) != len(recomputed_links):
                return False, "immutability_proof hash_chain length mismatch"
            for idx, link in enumerate(chain):
                if link.get("chain_hash") != recomputed_links[idx]["chain_hash"]:
                    return False, f"immutability_proof mismatch at index {idx}"
            expected_root = _sha256("".join(link["chain_hash"] for link in recomputed_links))
            if proof.get("root_hash") != expected_root:
                return False, "immutability_proof root_hash mismatch"
        return True, "ok"
