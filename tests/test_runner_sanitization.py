"""Tests for NightlyRunner sanitization integration."""

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import unittest
from src.rlm_docsync.manifest import load_manifest_from_dict
from src.rlm_docsync.runner import NightlyRunner


class _RedactingSanitizer:
    def sanitize_text(self, text: str, request: dict[str, object]) -> dict[str, object]:
        sanitized = text.replace("SECRET_KEY_1234567890", "[HIDDEN:a1b2c3]")
        return {
            "sanitized_text": sanitized,
            "changed": sanitized != text,
            "redaction_count": 1 if sanitized != text else 0,
            "redactions_by_type": {"api_key": 1 if sanitized != text else 0},
            "engine_name": "pii-shield",
            "engine_version": "1.1.0",
            "method": "provider_native",
            "status": "sanitized" if sanitized != text else "none",
        }


class _BrokenSanitizer:
    def sanitize_text(self, text: str, request: dict[str, object]) -> dict[str, object]:
        return {
            "sanitized_text": "{not-json",
            "changed": True,
            "redaction_count": 1,
            "redactions_by_type": {"api_key": 1},
            "engine_name": "pii-shield",
            "engine_version": "1.1.0",
            "method": "provider_native",
            "status": "sanitized",
        }


def _make_manifest() -> dict[str, object]:
    return {
        "version": "1.0",
        "docs": [
            {
                "path": "docs/arch.md",
                "mode": "spec-first",
                "claims": [
                    {
                        "id": "SEC-001",
                        "text": "Secrets must not be hardcoded",
                        "evidence": [
                            {
                                "type": "code",
                                "pattern": "SECRET_KEY_1234567890",
                                "scope": "src/",
                            }
                        ],
                    }
                ],
            }
        ],
    }


class TestRunnerSanitization(unittest.TestCase):
    def test_redaction_summary_and_bundle_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir(parents=True, exist_ok=True)
            (root / "src" / "app.py").write_text(
                'API_KEY = "SECRET_KEY_1234567890"\n',
                encoding="utf-8",
            )

            manifest = load_manifest_from_dict(_make_manifest())
            runner = NightlyRunner(
                repo_root=root,
                manifest_text=json.dumps(_make_manifest()),
                sanitizer=_RedactingSanitizer(),
                sanitization_salt_fingerprint="sha256:deadbeef",
            )

            packs = runner.run(manifest)
            self.assertEqual(len(packs), 1)
            pack = packs[0]
            self.assertIsNotNone(pack.sanitization)
            self.assertEqual(pack.sanitization["engine_name"], "pii-shield")
            self.assertEqual(pack.sanitization["salt_fingerprint"], "sha256:deadbeef")
            self.assertEqual(pack.sanitization["status"], "sanitized")
            self.assertGreaterEqual(pack.sanitization["redaction_count"], 1)
            self.assertIn("docsync_pack", pack.sanitization["applied_to"])
            self.assertIn("[HIDDEN:a1b2c3]", pack.results[0].evidence[0].snippet)

            payload = json.loads(pack.to_json())
            self.assertEqual(payload["version"], "0.2.1")
            ok, reason = pack.verify()
            self.assertTrue(ok, reason)

    def test_invalid_sanitizer_payload_degrades_to_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir(parents=True, exist_ok=True)
            (root / "src" / "app.py").write_text(
                'API_KEY = "SECRET_KEY_1234567890"\n',
                encoding="utf-8",
            )

            manifest = load_manifest_from_dict(_make_manifest())
            runner = NightlyRunner(
                repo_root=root,
                manifest_text=json.dumps(_make_manifest()),
                sanitizer=_BrokenSanitizer(),
                sanitization_salt_fingerprint="invalid fingerprint",
            )

            pack = runner.run(manifest)[0]
            self.assertEqual(pack.sanitization["status"], "partial")
            self.assertTrue(pack.sanitization["salt_fingerprint"].startswith("sha256:"))
            self.assertIn("SECRET_KEY_1234567890", pack.results[0].evidence[0].snippet)

            payload = json.loads(pack.to_json())
            self.assertEqual(payload["version"], "0.2.1")
            ok, reason = pack.verify()
            self.assertTrue(ok, reason)


if __name__ == "__main__":
    unittest.main()
