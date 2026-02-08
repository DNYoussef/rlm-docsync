"""PII-Shield adapter for rlm-docsync."""

from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib import error as urllib_error
from urllib import request as urllib_request


class PIIShieldSanitizer:
    """Remote PII-Shield adapter with fail-open/fail-closed behavior."""

    def __init__(
        self,
        endpoint: str,
        api_key: str | None = None,
        timeout_seconds: float = 5.0,
        fail_closed: bool = False,
    ) -> None:
        self.endpoint = endpoint.strip()
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self.fail_closed = fail_closed

    def sanitize_text(self, text: str, options: dict[str, Any]) -> dict[str, Any]:
        """Sanitize text and return normalized metadata."""
        if not self.endpoint:
            if self.fail_closed:
                raise RuntimeError("PII-Shield endpoint is required in fail-closed mode")
            return self._passthrough_result(text, status="none")

        payload = {
            "text": text,
            "input_format": str(options.get("input_format", "text")),
            "purpose": str(options.get("purpose", "docsync_pack")),
            "deterministic": True,
            "preserve_line_numbers": True,
            "include_findings": bool(options.get("include_findings", False)),
        }

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        req = urllib_request.Request(
            self.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )

        try:
            with urllib_request.urlopen(req, timeout=self.timeout_seconds) as response:
                raw = response.read().decode("utf-8")
                body = json.loads(raw) if raw else {}
        except (urllib_error.URLError, urllib_error.HTTPError, TimeoutError, ValueError) as exc:
            if self.fail_closed:
                raise RuntimeError(f"PII-Shield request failed: {exc}") from exc
            return self._passthrough_result(text, status="error")

        if not isinstance(body, dict):
            if self.fail_closed:
                raise RuntimeError("PII-Shield response must be a JSON object")
            return self._passthrough_result(text, status="error")

        sanitized_text = (
            body.get("sanitized_text")
            or body.get("redacted_text")
            or body.get("text")
            or body.get("output")
            or text
        )
        sanitized_text = str(sanitized_text)

        changed = bool(body.get("changed", sanitized_text != text))
        redactions_by_type = _extract_redactions_by_type(body)

        redaction_count = body.get("redaction_count")
        if not isinstance(redaction_count, int):
            redaction_count = sum(redactions_by_type.values())
            if redaction_count == 0 and isinstance(body.get("redactions"), list):
                redaction_count = len(body["redactions"])

        return {
            "sanitized_text": sanitized_text,
            "changed": changed,
            "redaction_count": max(int(redaction_count), 0),
            "redactions_by_type": redactions_by_type,
            "engine_name": str(body.get("engine_name", "pii-shield")),
            "engine_version": str(
                body.get("engine_version")
                or body.get("version")
                or body.get("schema_version")
                or "unknown"
            ),
            "method": str(body.get("method", "provider_native")),
            "status": str(body.get("status", "sanitized" if changed else "none")),
            "input_hash": _sha256_text(text),
            "output_hash": _sha256_text(sanitized_text),
        }

    @staticmethod
    def _passthrough_result(text: str, status: str) -> dict[str, Any]:
        digest = _sha256_text(text)
        return {
            "sanitized_text": text,
            "changed": False,
            "redaction_count": 0,
            "redactions_by_type": {},
            "engine_name": "pii-shield",
            "engine_version": "unknown",
            "method": "provider_native",
            "status": status,
            "input_hash": digest,
            "output_hash": digest,
        }


def _sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _extract_redactions_by_type(body: dict[str, Any]) -> dict[str, int]:
    raw = body.get("redactions_by_type")
    if isinstance(raw, dict):
        clean: dict[str, int] = {}
        for key, value in raw.items():
            try:
                clean[str(key)] = max(int(value), 0)
            except Exception:
                continue
        return clean

    redactions = body.get("redactions")
    if not isinstance(redactions, list):
        return {}

    inferred: dict[str, int] = {}
    for item in redactions:
        label = "unknown"
        if isinstance(item, dict):
            label = str(
                item.get("type")
                or item.get("category")
                or item.get("label")
                or "unknown"
            )
        inferred[label] = inferred.get(label, 0) + 1
    return inferred
