"""Tests for manifest loading and validation."""

import sys
from pathlib import Path

# Ensure src is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import unittest
from src.rlm_docsync.manifest import (
    DocManifest,
    DocEntry,
    ClaimEntry,
    EvidenceSpec,
    load_manifest_from_dict,
    validate_manifest,
)


class TestLoadManifest(unittest.TestCase):

    def test_minimal_manifest(self):
        data = {
            "version": "1.0",
            "docs": [
                {
                    "path": "docs/arch.md",
                    "mode": "spec-first",
                    "claims": [
                        {
                            "id": "A-001",
                            "text": "Some claim",
                            "evidence": [
                                {"type": "code", "pattern": "foo", "scope": "src/"}
                            ],
                        }
                    ],
                }
            ],
        }
        manifest = load_manifest_from_dict(data)
        self.assertEqual(manifest.version, "1.0")
        self.assertEqual(len(manifest.docs), 1)
        self.assertEqual(manifest.docs[0].path, "docs/arch.md")
        self.assertEqual(manifest.docs[0].mode, "spec-first")
        self.assertEqual(len(manifest.docs[0].claims), 1)
        self.assertEqual(manifest.docs[0].claims[0].id, "A-001")
        self.assertEqual(len(manifest.docs[0].claims[0].evidence), 1)

    def test_empty_docs(self):
        data = {"version": "1.0", "docs": []}
        manifest = load_manifest_from_dict(data)
        self.assertEqual(len(manifest.docs), 0)

    def test_defaults(self):
        data = {
            "docs": [
                {
                    "path": "readme.md",
                    "claims": [],
                }
            ]
        }
        manifest = load_manifest_from_dict(data)
        self.assertEqual(manifest.version, "1.0")
        self.assertEqual(manifest.docs[0].mode, "spec-first")


class TestValidateManifest(unittest.TestCase):

    def test_valid(self):
        manifest = DocManifest(
            version="1.0",
            docs=[
                DocEntry(
                    path="a.md",
                    mode="spec-first",
                    claims=[
                        ClaimEntry(id="C1", text="claim one"),
                    ],
                )
            ],
        )
        errors = validate_manifest(manifest)
        self.assertEqual(errors, [])

    def test_missing_version(self):
        manifest = DocManifest(version="", docs=[DocEntry(path="a.md", mode="spec-first")])
        errors = validate_manifest(manifest)
        self.assertIn("manifest.version is required", errors)

    def test_empty_docs(self):
        manifest = DocManifest(version="1.0", docs=[])
        errors = validate_manifest(manifest)
        self.assertIn("manifest.docs must contain at least one entry", errors)

    def test_bad_mode(self):
        manifest = DocManifest(
            version="1.0",
            docs=[DocEntry(path="a.md", mode="invalid")],
        )
        errors = validate_manifest(manifest)
        self.assertTrue(any("mode must be" in e for e in errors))

    def test_duplicate_claim_id(self):
        manifest = DocManifest(
            version="1.0",
            docs=[
                DocEntry(
                    path="a.md",
                    mode="spec-first",
                    claims=[
                        ClaimEntry(id="DUP", text="first"),
                        ClaimEntry(id="DUP", text="second"),
                    ],
                )
            ],
        )
        errors = validate_manifest(manifest)
        self.assertTrue(any("duplicate" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
