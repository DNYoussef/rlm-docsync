"""Load and validate guardspine.docs.yaml manifests.

Matches the GS-S2 DocManifest spec. Uses only stdlib (no PyYAML) --
callers must pass parsed dicts or use the included simple YAML subset
parser for trivial manifests.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class EvidenceSpec:
    """Where to look for evidence of a claim."""

    type: str  # "code" | "markdown"
    pattern: str  # regex or literal to search for
    scope: str = ""  # directory or file scope (empty = whole repo)


@dataclass(frozen=True)
class DocEntry:
    """A single document registered in the manifest."""

    path: str
    mode: str  # "spec-first" | "reality-first"
    claims: list[ClaimEntry] = field(default_factory=list)


@dataclass(frozen=True)
class ClaimEntry:
    """A claim declared in the manifest."""

    id: str
    text: str
    evidence: list[EvidenceSpec] = field(default_factory=list)


@dataclass(frozen=True)
class DocManifest:
    """Top-level manifest loaded from guardspine.docs.yaml."""

    version: str
    docs: list[DocEntry] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def _parse_evidence_spec(raw: dict[str, Any]) -> EvidenceSpec:
    return EvidenceSpec(
        type=str(raw.get("type", "code")),
        pattern=str(raw.get("pattern", "")),
        scope=str(raw.get("scope", "")),
    )


def _parse_claim_entry(raw: dict[str, Any]) -> ClaimEntry:
    evidence = [
        _parse_evidence_spec(e)
        for e in raw.get("evidence", [])
    ]
    return ClaimEntry(
        id=str(raw["id"]),
        text=str(raw["text"]),
        evidence=evidence,
    )


def _parse_doc_entry(raw: dict[str, Any]) -> DocEntry:
    claims = [_parse_claim_entry(c) for c in raw.get("claims", [])]
    return DocEntry(
        path=str(raw["path"]),
        mode=str(raw.get("mode", "spec-first")),
        claims=claims,
    )


def load_manifest_from_dict(data: dict[str, Any]) -> DocManifest:
    """Build a DocManifest from an already-parsed dict.

    This avoids a hard dependency on PyYAML.  Callers can parse YAML
    with any library they prefer and hand the resulting dict here.
    """
    version = str(data.get("version", "1.0"))
    docs = [_parse_doc_entry(d) for d in data.get("docs", [])]
    return DocManifest(version=version, docs=docs)


def load_manifest(path: str | Path) -> DocManifest:
    """Load a manifest from a JSON file.

    For YAML support, parse externally and call
    ``load_manifest_from_dict``.
    """
    text = Path(path).read_text(encoding="utf-8")
    data = json.loads(text)
    return load_manifest_from_dict(data)


def validate_manifest(manifest: DocManifest) -> list[str]:
    """Return a list of validation errors (empty means valid)."""
    errors: list[str] = []
    if not manifest.version:
        errors.append("manifest.version is required")
    if not manifest.docs:
        errors.append("manifest.docs must contain at least one entry")
    seen_ids: set[str] = set()
    for doc in manifest.docs:
        if not doc.path:
            errors.append("doc entry missing 'path'")
        if doc.mode not in ("spec-first", "reality-first"):
            errors.append(
                f"doc '{doc.path}': mode must be 'spec-first' or "
                f"'reality-first', got '{doc.mode}'"
            )
        for claim in doc.claims:
            if not claim.id:
                errors.append(f"doc '{doc.path}': claim missing 'id'")
            elif claim.id in seen_ids:
                errors.append(f"duplicate claim id: {claim.id}")
            else:
                seen_ids.add(claim.id)
            if not claim.text:
                errors.append(
                    f"doc '{doc.path}': claim '{claim.id}' missing 'text'"
                )
    return errors
