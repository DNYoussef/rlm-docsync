"""CLI entry point for rlm-docsync.

Commands:
    docsync run --manifest <path>    Run doc sync and produce evidence packs
    docsync verify --pack <path>     Verify an evidence pack hash chain

Uses argparse only (no click/typer dependency).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Adjust import path so the package is importable when run from repo root
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.rlm_docsync.manifest import load_manifest_from_dict, validate_manifest
from src.rlm_docsync.runner import NightlyRunner
from src.rlm_docsync.evidence import DocEvidencePack


def _cmd_run(args: argparse.Namespace) -> int:
    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        print(f"ERROR: manifest not found: {manifest_path}", file=sys.stderr)
        return 1

    raw_text = manifest_path.read_text(encoding="utf-8")

    # Support JSON first, then YAML if PyYAML is available.
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError:
        try:
            import yaml  # type: ignore

            parsed = yaml.safe_load(raw_text)
            if not isinstance(parsed, dict):
                raise ValueError("manifest root must be an object")
            data = parsed
        except Exception:
            print(
                "ERROR: manifest must be valid JSON or YAML",
                file=sys.stderr,
            )
            return 1

    manifest = load_manifest_from_dict(data)
    errors = validate_manifest(manifest)
    if errors:
        print("Manifest validation errors:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    repo_root = args.repo or str(Path.cwd())
    runner = NightlyRunner(repo_root=repo_root, manifest_text=raw_text)
    packs = runner.run(manifest)

    output_dir = Path(args.output) if args.output else Path.cwd()
    output_dir.mkdir(parents=True, exist_ok=True)

    for i, pack in enumerate(packs):
        filename = f"evidence-pack-{i}.json"
        out_path = output_dir / filename
        out_path.write_text(pack.to_json(), encoding="utf-8")
        print(f"Wrote {out_path}")

    total_pass = sum(
        1
        for pack in packs
        for r in pack.results
        if r.status.value == "pass"
    )
    total_fail = sum(
        1
        for pack in packs
        for r in pack.results
        if r.status.value == "fail"
    )
    total_skip = sum(
        1
        for pack in packs
        for r in pack.results
        if r.status.value == "skip"
    )
    print(f"\nResults: {total_pass} pass, {total_fail} fail, {total_skip} skip")
    return 1 if total_fail > 0 else 0


def _cmd_verify(args: argparse.Namespace) -> int:
    pack_path = Path(args.pack)
    if not pack_path.exists():
        print(f"ERROR: pack not found: {pack_path}", file=sys.stderr)
        return 1

    raw = pack_path.read_text(encoding="utf-8")
    pack = DocEvidencePack.from_json(raw)
    ok, message = pack.verify()

    if ok:
        print(f"VERIFIED: {message}")
        print(f"  {len(pack.results)} claims, chain intact")
        return 0
    else:
        print(f"FAILED: {message}", file=sys.stderr)
        return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="docsync",
        description="Self-updating documentation with proofs",
    )
    sub = parser.add_subparsers(dest="command")

    # -- run --
    run_parser = sub.add_parser("run", help="Run doc sync")
    run_parser.add_argument(
        "--manifest", required=True, help="Path to manifest file (JSON)"
    )
    run_parser.add_argument(
        "--repo", default="", help="Repository root (default: cwd)"
    )
    run_parser.add_argument(
        "--output", default="", help="Output directory for evidence packs"
    )

    # -- verify --
    verify_parser = sub.add_parser("verify", help="Verify evidence pack")
    verify_parser.add_argument(
        "--pack", required=True, help="Path to evidence pack JSON"
    )

    args = parser.parse_args(argv)
    if args.command == "run":
        return _cmd_run(args)
    elif args.command == "verify":
        return _cmd_verify(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
