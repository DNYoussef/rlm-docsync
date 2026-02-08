"""DocSync runner interface and concrete NightlyRunner.

The runner iterates over a DocManifest, extracts claims, inspects
source via adapters, and produces DocEvidencePack artifacts.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Protocol

from .adapters.code import CodeAdapter
from .adapters.markdown import MarkdownAdapter
from .claims import ClaimResult, ClaimStatus, EvidenceRef
from .evidence import DocEvidencePack
from .manifest import DocManifest, ClaimEntry, EvidenceSpec
from .sanitization import _sha256_text

_ALLOWED_SANITIZATION_METHODS = {
    "deterministic_hmac",
    "provider_native",
    "entropy+hmac",
}
_ALLOWED_SANITIZATION_STATUSES = {"sanitized", "none", "partial", "error"}
_SALT_FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-f]{8,64}$")


class EvidenceSanitizer(Protocol):
    """Protocol for external sanitizers (e.g. PII-Shield)."""

    def sanitize_text(self, text: str, request: dict[str, Any]) -> dict[str, Any]: ...


class DocSyncRunner(ABC):
    """Abstract base for doc-sync runners."""

    @abstractmethod
    def run(self, manifest: DocManifest) -> list[DocEvidencePack]:
        """Execute sync and return one evidence pack per document."""
        ...


class NightlyRunner(DocSyncRunner):
    """Concrete runner that walks docs, extracts claims, inspects code."""

    def __init__(
        self,
        repo_root: str | Path,
        manifest_text: str = "",
        sanitizer: EvidenceSanitizer | None = None,
        sanitization_salt_fingerprint: str = "sha256:00000000",
    ) -> None:
        self.repo_root = Path(repo_root)
        self._manifest_text = manifest_text
        self._sanitizer = sanitizer
        self._sanitization_salt_fingerprint = _normalize_salt_fingerprint(
            sanitization_salt_fingerprint
        )
        self._code_adapter = CodeAdapter(self.repo_root)
        self._md_adapter = MarkdownAdapter(self.repo_root)

    def _manifest_hash(self) -> str:
        if self._manifest_text:
            return hashlib.sha256(
                self._manifest_text.encode("utf-8")
            ).hexdigest()
        return hashlib.sha256(b"").hexdigest()

    def _inspect_claim(
        self, claim: ClaimEntry
    ) -> ClaimResult:
        """Inspect a single claim against its evidence specs."""
        refs: list[EvidenceRef] = []
        for spec in claim.evidence:
            adapter_refs = self._inspect_evidence(spec)
            refs.extend(adapter_refs)

        any_matched = any(r.matched for r in refs)
        if not refs:
            status = ClaimStatus.SKIP
            message = "no evidence specs defined"
        elif any_matched:
            status = ClaimStatus.PASS
            message = f"{sum(r.matched for r in refs)}/{len(refs)} evidence found"
        else:
            status = ClaimStatus.FAIL
            message = "no matching evidence found"

        return ClaimResult(
            claim_id=claim.id,
            claim_text=claim.text,
            status=status,
            evidence=refs,
            message=message,
        )

    def _inspect_evidence(self, spec: EvidenceSpec) -> list[EvidenceRef]:
        """Dispatch to the appropriate adapter."""
        if spec.type == "code":
            return self._code_adapter.search(spec.pattern, spec.scope)
        elif spec.type == "markdown":
            return self._md_adapter.search(spec.pattern, spec.scope)
        return []

    def _sanitize_text(
        self,
        text: str,
        purpose: str,
        input_format: str = "text",
    ) -> tuple[str, dict[str, Any] | None]:
        if not self._sanitizer:
            return text, None
        try:
            result = self._sanitizer.sanitize_text(
                text,
                {
                    "purpose": purpose,
                    "input_format": input_format,
                    "include_findings": input_format in {"json", "diff"},
                },
            )
        except Exception as exc:
            print(f"WARNING: PII sanitizer call failed ({type(exc).__name__}: {exc}), using unsanitized text", file=sys.stderr)
            if bool(getattr(self._sanitizer, "fail_closed", False)):
                raise
            normalized = _normalize_sanitizer_result(
                text,
                {
                    "sanitized_text": text,
                    "changed": False,
                    "redaction_count": 0,
                    "redactions_by_type": {},
                    "engine_name": "pii-shield",
                    "engine_version": "unknown",
                    "method": "provider_native",
                    "status": "error",
                },
            )
            return text, normalized

        normalized = _normalize_sanitizer_result(text, result)
        return str(normalized["sanitized_text"]), normalized

    def _sanitize_results(
        self,
        results: list[ClaimResult],
    ) -> tuple[list[ClaimResult], dict[str, Any] | None]:
        if not self._sanitizer:
            return results, None

        raw_results = [result.to_dict() for result in results]
        raw_payload = json.dumps(
            raw_results,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        sanitized_text, stage = self._sanitize_text(
            raw_payload,
            purpose="docsync_pack",
            input_format="json",
        )

        summary: dict[str, Any] = {
            "engine_name": stage.get("engine_name", "pii-shield"),
            "engine_version": stage.get("engine_version", "unknown"),
            "method": stage.get("method", "provider_native"),
            "token_format": "[HIDDEN:<id>]",
            "salt_fingerprint": self._sanitization_salt_fingerprint,
            "redaction_count": int(max(stage.get("redaction_count", 0), 0)),
            "redactions_by_type": _merge_count_map({}, stage.get("redactions_by_type", {})),
            "input_hash": stage.get("input_hash"),
            "output_hash": stage.get("output_hash"),
            "applied_to": ["docsync_pack"],
            "status": stage.get("status", "none"),
        }

        if not stage.get("changed"):
            return results, summary

        try:
            parsed = json.loads(sanitized_text)
            if not isinstance(parsed, list):
                raise ValueError("sanitized payload root must be a list")
            if len(parsed) != len(results):
                raise ValueError(
                    "sanitized payload length changed "
                    f"(expected {len(results)}, got {len(parsed)})"
                )
            sanitized_results = [ClaimResult.from_dict(item) for item in parsed]
            return sanitized_results, summary
        except Exception as exc:
            print(f"WARNING: PII sanitizer returned invalid response, falling back to unsanitized data: {type(exc).__name__}", file=sys.stderr)
            summary["status"] = "partial"
            return results, summary

    def run(self, manifest: DocManifest) -> list[DocEvidencePack]:
        """Run sync across all docs in the manifest."""
        packs: list[DocEvidencePack] = []
        manifest_hash = self._manifest_hash()

        for doc in manifest.docs:
            results: list[ClaimResult] = []
            for claim in doc.claims:
                result = self._inspect_claim(claim)
                results.append(result)

            # H5: sanitize individual claim_text and message fields
            if self._sanitizer:
                for result in results:
                    if result.claim_text:
                        sanitized_ct, _ = self._sanitize_text(result.claim_text, purpose="claim_text")
                        result.claim_text = sanitized_ct
                    if result.message:
                        sanitized_msg, _ = self._sanitize_text(result.message, purpose="claim_message")
                        result.message = sanitized_msg

            sanitized_results, sanitization = self._sanitize_results(results)

            pack = DocEvidencePack(
                manifest_hash=manifest_hash,
                results=sanitized_results,
                sanitization=sanitization,
            )
            pack.build_hash_chain()
            packs.append(pack)

        return packs


def _merge_count_map(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, int]:
    merged: dict[str, int] = {}
    for source in (base or {}, extra or {}):
        for key, value in source.items():
            try:
                numeric = int(value)
            except Exception as exc:
                print(f"WARNING: non-numeric count for key '{key}': {type(exc).__name__}", file=sys.stderr)
                numeric = 0
            merged[str(key)] = merged.get(str(key), 0) + max(numeric, 0)
    return merged


def _coerce_method(value: Any) -> str:
    method = str(value or "provider_native")
    if method not in _ALLOWED_SANITIZATION_METHODS:
        return "provider_native"
    return method


def _coerce_status(value: Any, changed: bool) -> str:
    if value is None:
        return "sanitized" if changed else "none"
    status = str(value)
    if status not in _ALLOWED_SANITIZATION_STATUSES:
        return "sanitized" if changed else "none"
    return status


def _normalize_salt_fingerprint(value: str) -> str:
    candidate = (value or "").strip().lower()
    if _SALT_FINGERPRINT_RE.fullmatch(candidate):
        return candidate
    digest = hashlib.sha256((value or "pii-shield").encode("utf-8")).hexdigest()[:16]
    return f"sha256:{digest}"


def _normalize_sanitizer_result(text: str, raw_result: Any) -> dict[str, Any]:
    if isinstance(raw_result, dict):
        data = raw_result
    else:
        data = {
            "sanitized_text": getattr(raw_result, "sanitized_text", text),
            "changed": getattr(raw_result, "changed", None),
            "redaction_count": getattr(raw_result, "redaction_count", 0),
            "redactions_by_type": getattr(raw_result, "redactions_by_type", {}),
            "engine_name": getattr(raw_result, "engine_name", "pii-shield"),
            "engine_version": getattr(raw_result, "engine_version", "unknown"),
            "method": getattr(raw_result, "method", "provider_native"),
            "status": getattr(raw_result, "status", None),
            "input_hash": getattr(raw_result, "input_hash", None),
            "output_hash": getattr(raw_result, "output_hash", None),
        }

    sanitized_text = text  # fallback to original
    for key in ("sanitized_text", "sanitizedText", "output"):
        val = data.get(key)
        if val is not None:
            sanitized_text = val
            break
    sanitized_text = str(sanitized_text)
    changed = bool(data.get("changed", sanitized_text != text))

    redaction_count = data.get("redaction_count", data.get("redactionCount", 0))
    try:
        redaction_count = max(int(redaction_count), 0)
    except Exception as exc:
        print(f"WARNING: non-numeric redaction_count '{redaction_count}': {type(exc).__name__}", file=sys.stderr)
        redaction_count = 0

    redactions_by_type = data.get(
        "redactions_by_type",
        data.get("redactionsByType", {}),
    )
    clean_counts = _merge_count_map({}, redactions_by_type if isinstance(redactions_by_type, dict) else {})

    return {
        "sanitized_text": sanitized_text,
        "changed": changed,
        "redaction_count": redaction_count,
        "redactions_by_type": clean_counts,
        "engine_name": str(data.get("engine_name", data.get("engineName", "pii-shield"))),
        "engine_version": str(data.get("engine_version", data.get("engineVersion", "unknown"))),
        "method": _coerce_method(data.get("method")),
        "status": _coerce_status(data.get("status"), changed),
        "input_hash": data.get("input_hash", data.get("inputHash")) or _sha256_text(text),
        "output_hash": data.get("output_hash", data.get("outputHash")) or _sha256_text(sanitized_text),
    }
