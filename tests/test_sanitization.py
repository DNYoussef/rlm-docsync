"""Tests for PII-Shield sanitizer adapter."""

import json
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import unittest
from src.rlm_docsync.sanitization import PIIShieldSanitizer


class _FakeResponse:
    def __init__(self, body: dict[str, object]):
        self._raw = json.dumps(body).encode("utf-8")

    def read(self) -> bytes:
        return self._raw

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


class TestPIIShieldSanitizer(unittest.TestCase):
    def test_missing_endpoint_fail_open_passthrough(self):
        sanitizer = PIIShieldSanitizer(endpoint="", fail_closed=False)
        result = sanitizer.sanitize_text("abc", {"input_format": "text"})
        self.assertEqual(result["sanitized_text"], "abc")
        self.assertEqual(result["status"], "none")
        self.assertEqual(result["redaction_count"], 0)

    def test_missing_endpoint_fail_closed_raises(self):
        sanitizer = PIIShieldSanitizer(endpoint="", fail_closed=True)
        with self.assertRaises(RuntimeError):
            sanitizer.sanitize_text("abc", {"input_format": "text"})

    def test_remote_response_is_normalized(self):
        sanitizer = PIIShieldSanitizer(endpoint="https://example.test/sanitize")
        fake_body = {
            "sanitized_text": "token=[HIDDEN:a1b2c3]",
            "engine_version": "1.1.0",
            "redactions": [{"type": "api_key"}],
        }
        with patch("src.rlm_docsync.sanitization.urllib_request.urlopen", return_value=_FakeResponse(fake_body)):
            result = sanitizer.sanitize_text("token=SECRET123456", {"input_format": "text"})

        self.assertEqual(result["engine_name"], "pii-shield")
        self.assertEqual(result["engine_version"], "1.1.0")
        self.assertEqual(result["redaction_count"], 1)
        self.assertEqual(result["redactions_by_type"], {"api_key": 1})
        self.assertTrue(result["changed"])


    def test_empty_string_sanitized_text_not_bypassed(self):
        """C5: empty string from PII-Shield must NOT fall through to original."""
        sanitizer = PIIShieldSanitizer(endpoint="https://example.test/sanitize")
        fake_body = {
            "sanitized_text": "",
            "changed": True,
            "redaction_count": 1,
            "redactions_by_type": {"email": 1},
        }
        with patch("src.rlm_docsync.sanitization.urllib_request.urlopen", return_value=_FakeResponse(fake_body)):
            result = sanitizer.sanitize_text("user@example.com", {"input_format": "text"})

        self.assertEqual(result["sanitized_text"], "")
        self.assertTrue(result["changed"])

    def test_none_sanitized_text_falls_to_redacted_text(self):
        """C5: None sanitized_text should fall through to redacted_text."""
        sanitizer = PIIShieldSanitizer(endpoint="https://example.test/sanitize")
        fake_body = {
            "sanitized_text": None,
            "redacted_text": "safe",
            "changed": True,
            "redaction_count": 1,
        }
        with patch("src.rlm_docsync.sanitization.urllib_request.urlopen", return_value=_FakeResponse(fake_body)):
            result = sanitizer.sanitize_text("dangerous PII here", {"input_format": "text"})

        self.assertEqual(result["sanitized_text"], "safe")
        self.assertTrue(result["changed"])


if __name__ == "__main__":
    unittest.main()
