# rlm-docsync

**Self-updating documentation with proofs.**

rlm-docsync keeps your documentation in sync with your codebase by
extracting claims from docs, inspecting source code for evidence, and
producing cryptographically chained evidence packs that prove each claim
is (or is not) satisfied.

## How It Works

Every document is a list of **claims** about your system. rlm-docsync
reads a manifest (`guardspine.docs.yaml`), walks each document, extracts
claims, then inspects the codebase for evidence. The output is an
**evidence pack** -- a JSON file with SHA-256 hash chains that anyone
can independently verify.

### Two Modes

| Mode | Doc is... | Code is... | Output |
|------|-----------|------------|--------|
| **spec-first** | truth | inspected | Violations where code diverges from docs |
| **reality-first** | updated | truth | PRs that update docs to match code |

## Quick Start

```bash
pip install rlm-docsync

# Create a manifest (see examples/guardspine.docs.yaml)
docsync run --manifest guardspine.docs.yaml

# Verify an evidence pack
docsync verify --pack evidence-pack.json

# Optional: sanitize claims before bundle sealing
docsync run --manifest guardspine.docs.yaml \
  --pii-shield-enabled \
  --pii-shield-endpoint https://pii-shield.example/sanitize \
  --pii-shield-salt-fingerprint sha256:deadbeef
```

## Manifest Format

```yaml
version: "1.0"
docs:
  - path: docs/architecture.md
    mode: spec-first
    claims:
      - id: ARCH-001
        text: "All API endpoints require authentication"
        evidence:
          - type: code
            pattern: "@requires_auth"
            scope: "src/api/"
```

## Evidence Packs

Each run produces a JSON evidence pack containing:

- Manifest snapshot (hash of the manifest at run time)
- Per-claim results (pass, fail, skip) with evidence references
- SHA-256 hash chain linking every entry to its predecessor
- Timestamp and runner metadata
- Optional `sanitization` attestation block (GuardSpine v0.2.1 format)

Use `docsync verify --pack <file>` to validate the hash chain
independently.

## Scope

rlm-docsync does NOT include compression, decision queues,
organizational policy, or approval workflows. For enterprise features,
see GuardSpine.

## License

Apache 2.0. See [LICENSE](LICENSE).
