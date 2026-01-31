"""Code adapter: AST + grep for evidence in source files.

Side effects:
    Reads files from the filesystem under the configured ``repo_root``.
    All I/O is read-only; no files are modified.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from ..claims import EvidenceRef

_CODE_EXTENSIONS = {".py", ".js", ".ts", ".go", ".rs", ".java", ".c", ".h", ".cpp"}

#: Reject regex patterns longer than this to mitigate ReDoS.
_MAX_PATTERN_LEN = 1000


class CodeAdapter:
    """Search source code files for evidence patterns."""

    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root

    def search(self, pattern: str, scope: str = "") -> list[EvidenceRef]:
        """Search code files matching *pattern* under *scope*.

        Uses regex grep across all recognized source files.  For Python
        files, also attempts basic AST inspection for function/class
        names matching the pattern.
        """
        search_root = self.repo_root / scope if scope else self.repo_root
        if not search_root.exists():
            return []

        refs: list[EvidenceRef] = []
        if len(pattern) > _MAX_PATTERN_LEN:
            pattern = re.escape(pattern[:_MAX_PATTERN_LEN])
        try:
            compiled = re.compile(pattern)
        except re.error:
            # Treat as literal if not valid regex
            compiled = re.compile(re.escape(pattern))

        for fpath in self._iter_code_files(search_root):
            rel = str(fpath.relative_to(self.repo_root)).replace("\\", "/")
            try:
                lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for i, line in enumerate(lines, start=1):
                if compiled.search(line):
                    snippet = line.strip()[:120]
                    refs.append(EvidenceRef(
                        source_type="code",
                        path=rel,
                        line=i,
                        snippet=snippet,
                        matched=True,
                    ))

        # Also try AST for Python files (function/class name matching)
        if not refs:
            refs.extend(self._ast_search(search_root, compiled))

        return refs

    def _iter_code_files(self, root: Path):
        """Yield code files under *root* (filesystem read, no writes)."""
        if root.is_file():
            if root.suffix in _CODE_EXTENSIONS:
                yield root
            return
        for p in root.rglob("*"):
            if p.is_file() and p.suffix in _CODE_EXTENSIONS:
                yield p

    def _ast_search(self, root: Path, compiled: re.Pattern) -> list[EvidenceRef]:
        """Search Python AST for matching function/class names."""
        refs: list[EvidenceRef] = []
        for fpath in self._iter_code_files(root):
            if fpath.suffix != ".py":
                continue
            try:
                source = fpath.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source, filename=str(fpath))
            except (OSError, SyntaxError):
                continue
            rel = str(fpath.relative_to(self.repo_root)).replace("\\", "/")
            for node in ast.walk(tree):
                name = getattr(node, "name", None)
                if name and compiled.search(name):
                    refs.append(EvidenceRef(
                        source_type="code",
                        path=rel,
                        line=getattr(node, "lineno", 0),
                        snippet=f"def/class {name}",
                        matched=True,
                    ))
        return refs
