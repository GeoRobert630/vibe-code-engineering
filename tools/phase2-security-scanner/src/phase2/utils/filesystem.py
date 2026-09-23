"""Read-only, bounded filesystem traversal.

* Symlinks (files and directories) are never followed; they are recorded so the
  report can mention them.
* Every yielded path is verified to resolve inside the project root.
* Files above ``max_file_size`` are skipped and recorded.
* Binary files are detected (NUL byte in the first 8 KiB) and not decoded.
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path

from ..models import FileEntry

DEFAULT_EXCLUDED_DIRS = frozenset(
    {
        ".git", ".hg", ".svn",
        "node_modules", ".venv", "venv", ".tox", "__pycache__", ".mypy_cache",
        ".pytest_cache", ".ruff_cache", "vendor", ".terraform",
        "coverage", ".nyc_output", "target", ".gradle", ".cache", ".turbo",
    }
)
# Build output is excluded by default but can be included for secret scanning
# (``include_build_output``) because bundles are where client-side secret leaks show up.
BUILD_OUTPUT_DIRS = frozenset({"dist", "build", ".next", "out", ".output", ".nuxt", ".svelte-kit"})
DEFAULT_MAX_FILE_SIZE = 2 * 1024 * 1024
MAX_FILES = 200_000
MAX_LINE_LENGTH = 4000


@dataclass
class WalkResult:
    files: list[FileEntry] = field(default_factory=list)
    skipped_large: list[str] = field(default_factory=list)
    skipped_symlinks: list[str] = field(default_factory=list)
    excluded_dirs: list[str] = field(default_factory=list)
    truncated: bool = False


def to_rel(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def is_within(root: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def _matches_any(rel: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(rel + "/", p) for p in patterns)


def walk_project(
    root: Path,
    excluded_dirs: frozenset[str] | set[str] = DEFAULT_EXCLUDED_DIRS,
    exclude_globs: list[str] | None = None,
    include_build_output: bool = False,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
) -> WalkResult:
    root = root.resolve()
    result = WalkResult()
    exclude_globs = exclude_globs or []
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current = Path(dirpath)
        kept = []
        for d in sorted(dirnames):
            full = current / d
            rel = to_rel(root, full)
            is_junction = getattr(full, "is_junction", lambda: False)()
            if full.is_symlink() or is_junction or not is_within(root, full):
                # SR-09: Windows junctions are not reported as symlinks by os.walk.
                result.skipped_symlinks.append(rel)
                continue
            if d in excluded_dirs or _matches_any(rel, exclude_globs):
                result.excluded_dirs.append(rel)
                continue
            if d in BUILD_OUTPUT_DIRS and not include_build_output:
                result.excluded_dirs.append(rel)
                continue
            kept.append(d)
        dirnames[:] = kept
        in_build = any(part in BUILD_OUTPUT_DIRS for part in current.relative_to(root).parts)
        for name in sorted(filenames):
            full = current / name
            rel = to_rel(root, full)
            if _matches_any(rel, exclude_globs):
                continue
            try:
                if full.is_symlink():
                    result.skipped_symlinks.append(rel)
                    continue
                st = full.stat()
            except OSError:
                continue
            if not full.is_file():
                continue
            if not is_within(root, full):
                result.skipped_symlinks.append(rel)
                continue
            if st.st_size > max_file_size:
                result.skipped_large.append(rel)
                continue
            result.files.append(FileEntry(rel=rel, path=full, size=st.st_size, build_output=in_build))
            if len(result.files) >= MAX_FILES:
                result.truncated = True
                return result
    return result


def read_text(path: Path, max_bytes: int = DEFAULT_MAX_FILE_SIZE) -> str | None:
    """Return decoded text, or None for binary/unreadable files. Never follows symlinks."""
    try:
        if path.is_symlink():
            return None
        with open(path, "rb") as fh:
            data = fh.read(max_bytes + 1)
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    return data[:max_bytes].decode("utf-8", "replace")


def iter_lines(text: str):
    """Yield (line_number, line) with lines capped to MAX_LINE_LENGTH chars (regex DoS guard)."""
    for number, line in enumerate(text.splitlines(), start=1):
        yield number, line[:MAX_LINE_LENGTH]


def in_string_literal(line: str, pos: int) -> bool:
    """Heuristic: True when ``pos`` sits inside a '...' or "..." literal on this line.

    Used to skip rule matches inside documentation strings, test snippets and
    messages (e.g. a description mentioning ``app.run(debug=True)``).
    """
    quote = None
    i = 0
    while i < pos and i < len(line):
        ch = line[i]
        if ch == "\\":
            i += 2
            continue
        if quote is None and ch in "'\"":
            quote = ch
        elif ch == quote:
            quote = None
        i += 1
    if quote is None:
        return False
    # Only treat it as a string if the literal is closed later on the line; an
    # unbalanced quote (regex literal, apostrophe in JSX text) must not hide code.
    j = pos
    while j < len(line):
        if line[j] == "\\":
            j += 2
            continue
        if line[j] == quote:
            return True
        j += 1
    return False


def python_multiline_string_lines(text: str) -> set[int]:
    """Line numbers that continue a triple-quoted string (docstrings, long literals).

    The opening line is not included (it is handled by ``in_string_literal``);
    continuation lines and the closing line are.
    """
    inside: set[int] = set()
    delim: str | None = None
    for number, line in enumerate(text.splitlines(), start=1):
        if delim is not None:
            inside.add(number)
        pos = 0
        while True:
            if delim is None:
                idx = [i for i in (line.find('"""', pos), line.find("'''", pos)) if i >= 0]
                if not idx:
                    break
                start = min(idx)
                delim = line[start:start + 3]
                pos = start + 3
            else:
                end = line.find(delim, pos)
                if end < 0:
                    break
                delim = None
                pos = end + 3
    return inside


TEST_DIR_NAMES = frozenset({"test", "tests", "__tests__", "spec", "specs", "fixtures", "__fixtures__", "testdata", "mocks", "__mocks__", "examples", "example"})


def is_test_path(rel: str) -> bool:
    parts = rel.lower().split("/")
    if any(p in TEST_DIR_NAMES for p in parts[:-1]):
        return True
    name = parts[-1]
    return (
        name.startswith("test_")
        or name.endswith("_test.py")
        or ".test." in name
        or ".spec." in name
        or name == "conftest.py"
    )
