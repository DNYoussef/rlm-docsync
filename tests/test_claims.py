"""Tests for claims schema and evidence pack."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import unittest
from src.rlm_docsync.claims import ClaimResult, ClaimStatus, EvidenceRef
from src.rlm_docsync.evidence import DocEvidencePack


class TestClaimResult(unittest.TestCase):

    def test_roundtrip(self):
        result = ClaimResult(
            claim_id="T-001",
            claim_text="Test claim",
            status=ClaimStatus.PASS,
            evidence=[
                EvidenceRef(
                    source_type="code",
                    path="src/foo.py",
                    line=10,
                    snippet="some_func()",
                    matched=True,
                )
            ],
            message="found",
        )
        d = result.to_dict()
        restored = ClaimResult.from_dict(d)
        self.assertEqual(restored.claim_id, "T-001")
        self.assertEqual(restored.status, ClaimStatus.PASS)
        self.assertEqual(len(restored.evidence), 1)
        self.assertTrue(restored.evidence[0].matched)

    def test_default_status(self):
        result = ClaimResult(claim_id="X", claim_text="x")
        self.assertEqual(result.status, ClaimStatus.SKIP)


class TestDocEvidencePack(unittest.TestCase):

    def _make_pack(self) -> DocEvidencePack:
        results = [
            ClaimResult(
                claim_id="A-001",
                claim_text="Claim A",
                status=ClaimStatus.PASS,
                evidence=[
                    EvidenceRef(
                        source_type="code",
                        path="a.py",
                        line=1,
                        snippet="x",
                        matched=True,
                    )
                ],
                message="ok",
            ),
            ClaimResult(
                claim_id="A-002",
                claim_text="Claim B",
                status=ClaimStatus.FAIL,
                message="not found",
            ),
        ]
        pack = DocEvidencePack(
            manifest_hash="abc123",
            results=results,
        )
        pack.build_hash_chain()
        return pack

    def test_hash_chain_length(self):
        pack = self._make_pack()
        self.assertEqual(len(pack.hash_chain), 2)

    def test_verify_valid(self):
        pack = self._make_pack()
        ok, msg = pack.verify()
        self.assertTrue(ok)
        self.assertEqual(msg, "ok")

    def test_verify_tampered(self):
        pack = self._make_pack()
        pack.hash_chain[0] = "tampered"
        ok, msg = pack.verify()
        self.assertFalse(ok)
        self.assertIn("mismatch", msg)

    def test_json_roundtrip(self):
        pack = self._make_pack()
        json_str = pack.to_json()
        restored = DocEvidencePack.from_json(json_str)
        ok, msg = restored.verify()
        self.assertTrue(ok)
        self.assertEqual(len(restored.results), 2)

    def test_json_roundtrip_with_sanitization(self):
        pack = self._make_pack()
        pack.sanitization = {
            "engine_name": "pii-shield",
            "engine_version": "1.1.0",
            "method": "provider_native",
            "token_format": "[HIDDEN:<id>]",
            "salt_fingerprint": "sha256:deadbeef",
            "redaction_count": 1,
            "redactions_by_type": {"api_key": 1},
            "status": "sanitized",
            "applied_to": ["docsync_pack"],
        }
        raw = json.loads(pack.to_json())
        self.assertEqual(raw["version"], "0.2.1")

        restored = DocEvidencePack.from_json(json.dumps(raw))
        self.assertEqual(restored.sanitization["engine_name"], "pii-shield")
        ok, msg = restored.verify()
        self.assertTrue(ok)

    def test_empty_pack(self):
        pack = DocEvidencePack(manifest_hash="empty")
        pack.build_hash_chain()
        ok, msg = pack.verify()
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
