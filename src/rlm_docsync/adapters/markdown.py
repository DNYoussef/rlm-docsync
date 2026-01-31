"""Markdown adapter: search documentation files for evidence.

Side effects:
    Reads files from the filesystem under the configured ``repo_root``.
    All I/O is read-only; no files are modified.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..claims import EvidenceRef

_MD_EXTENSIONS = {".md", ".markdown", ".rst", ".txt"}

#: Reject regex patterns longer than this to mitigate ReDoS.
_MAX_PATTERN_LEN = 1000


class MarkdownAdapter:
    """Search markdown/documentation files for evidence patterns."""

    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root

    def search(self, pattern: str, scope: str = "") -> list[EvidenceRef]:
        """Search doc files matching *pattern* under *scope*."""
        search_root = self.repo_root / scope if scope else self.repo_root
        if not search_root.exists():
            return []

        refs: list[EvidenceRef] = []
        if len(pattern) > _MAX_PATTERN_LEN:
            pattern = re.escape(pattern[:_MAX_PATTERN_LEN])
        try:
            compiled = re.compile(pattern)
        except re.error:
            compiled = re.compile(re.escape(pattern))

        for fpath in self._iter_md_files(search_root):
            rel = str(fpath.relative_to(self.repo_root)).replace("\\", "/")
            try:
                lines = fpath.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
            except OSError:
                continue
            for i, line in enumerate(lines, start=1):
                if compiled.search(line):
                    snippet = line.strip()[:120]
                    refs.append(EvidenceRef(
                        source_type="markdown",
                        path=rel,
                        line=i,
                        snippet=snippet,
                        matched=True,
                    ))

        return refs

    def _iter_md_files(self, root: Path):
        """Yield markdown files under *root* (filesystem read, no writes)."""
        if root.is_file():
            if root.suffix in _MD_EXTENSIONS:
                yield root
            return
        for p in root.rglob("*"):
            if p.is_file() and p.suffix in _MD_EXTENSIONS:
                yield p
