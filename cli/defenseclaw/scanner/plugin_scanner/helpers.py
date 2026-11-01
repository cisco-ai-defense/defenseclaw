# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Shared utilities for the plugin scanner.

Comment stripping, path detection, file collection, finding factory,
deduplication, and assessment computation.
"""

from __future__ import annotations

import io
import keyword
import os
import re
import stat
import tokenize
from datetime import datetime, timezone
from enum import Enum

from defenseclaw.scanner.plugin_scanner.rules import (
    BINARY_EXTENSIONS,
    DEPRIORITIZED_PATH_PATTERNS,
    TAXONOMY_MAP,
)
from defenseclaw.scanner.plugin_scanner.types import (
    Assessment,
    AssessmentCategory,
    Finding,
    ScanMetadata,
    ScanResult,
)

# ---------------------------------------------------------------------------
# Scanner name
# ---------------------------------------------------------------------------

SCANNER_NAME = "defenseclaw-plugin-scanner"

# ---------------------------------------------------------------------------
# Evidence helpers
# ---------------------------------------------------------------------------

MAX_EVIDENCE_LEN = 200
SECRET_REDACT_RE = re.compile(
    r"(?:AKIA|sk_live_|pk_live_|sk_test_|pk_test_|ghp_|gho_|ghu_|ghs_|ghr_|xox[bpors]-|AIza|eyJ)[A-Za-z0-9\-_+/=.]{6,}"
)


def sanitise_evidence(line: str, redact: bool = False) -> str:
    """Truncate and optionally redact a source line for use as evidence."""
    evidence = line.strip()
    if redact:
        evidence = SECRET_REDACT_RE.sub(lambda m: m.group(0)[:6] + "***REDACTED***", evidence)
    if len(evidence) > MAX_EVIDENCE_LEN:
        evidence = evidence[:MAX_EVIDENCE_LEN] + "\u2026"
    return evidence


# ---------------------------------------------------------------------------
# Comment / path helpers
# ---------------------------------------------------------------------------


def strip_comment(line: str) -> str:
    """Strip single-line comments from a line.

    Preserves strings containing "//". Avoids false-positive pattern
    matches on commented-out code.
    """
    in_string: str | None = None
    i = 0
    while i < len(line):
        ch = line[i]
        prev = line[i - 1] if i > 0 else ""

        if in_string:
            if ch == in_string and prev != "\\":
                in_string = None
            i += 1
            continue

        if ch in ('"', "'", "`"):
            in_string = ch
            i += 1
            continue

        if ch == "/" and i + 1 < len(line) and line[i + 1] == "/":
            return line[:i].rstrip()

        i += 1

    return line


def strip_hash_comment(line: str) -> str:
    """Strip a Python ``#`` comment from a line, ignoring ``#`` inside strings."""
    in_string: str | None = None
    for i, ch in enumerate(line):
        prev = line[i - 1] if i > 0 else ""
        if in_string:
            if ch == in_string and prev != "\\":
                in_string = None
        elif ch in ('"', "'"):
            in_string = ch
        elif ch == "#":
            return line[:i].rstrip()
    return line


# A ``/`` after one of these (or these words) starts a regex literal, not a
# division.
_JS_REGEX_AFTER = frozenset("(,=:[!&|?{};+-*%<>~^")
_JS_REGEX_WORDS = frozenset(
    {"return", "typeof", "case", "in", "of", "new", "delete", "void", "throw", "yield", "await"}
)


def js_call_view(content: str) -> tuple[list[str], list[tuple[int, ...]]]:
    """JavaScript/TypeScript lines with comments and the text of string,
    template and regex literals blanked (``${...}`` stays code), plus, per
    line, the lines opening the brackets still open where it starts.

    The JavaScript side of :meth:`PySource.openers` and ``PySource.calls``:
    a network word inside an error message is not a call, and a URL four
    lines into ``axios({`` belongs to that call (GAP-2068). Columns and
    line numbers match ``content.split("\n")``.
    """
    out = list(content)
    n = len(content)
    tmpl: list[int] = []  # per open template: brace depth in ``${}``, -1 in its text
    last = ""
    word = ""
    i = 0

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        ch = content[i]
        nxt = content[i + 1] if i + 1 < n else ""
        if tmpl and tmpl[-1] < 0:
            if ch == "`":
                tmpl.pop()
                last, word = "`", ""
                i += 1
            elif ch == "$" and nxt == "{":
                out[i] = " "
                tmpl[-1] = 0
                last, word = "{", ""
                i += 2
            else:
                step = 2 if ch == "\\" else 1
                blank(i, i + step)
                i += step
            continue
        if ch in "\"'":
            j = i + 1
            while j < n and content[j] not in (ch, "\n"):
                j += 2 if content[j] == "\\" else 1
            blank(i + 1, j)
            i = j + 1 if j < n and content[j] == ch else j
            last, word = ch, ""
            continue
        if ch == "`":
            tmpl.append(-1)
            i += 1
            continue
        if ch == "/" and nxt == "/":
            j = content.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
            continue
        if ch == "/" and nxt == "*":
            j = content.find("*/", i + 2)
            j = n if j < 0 else j + 2
            blank(i, j)
            i = j
            continue
        if ch == "/" and (not last or last in _JS_REGEX_AFTER or word in _JS_REGEX_WORDS):
            j, in_class = i + 1, False
            while j < n and content[j] != "\n":
                c = content[j]
                if c == "\\":
                    j += 2
                    continue
                if c == "/" and not in_class:
                    break
                in_class = (in_class or c == "[") and c != "]"
                j += 1
            if j < n and content[j] == "/":
                blank(i + 1, j)
                i = j + 1
                last, word = "a", ""
                continue
        if tmpl and ch == "{":
            tmpl[-1] += 1
        elif tmpl and ch == "}":
            if tmpl[-1] == 0:
                tmpl[-1] = -1
                i += 1
                continue
            tmpl[-1] -= 1
        if ch.isalnum() or ch in "_$":
            j = i
            while j < n and (content[j].isalnum() or content[j] in "_$"):
                j += 1
            word, last = content[i:j], "a"
            i = j
            continue
        if not ch.isspace():
            last, word = ch, ""
        i += 1

    lines = "".join(out).split("\n")
    openers: list[tuple[int, ...]] = []
    stack: list[int] = []
    for row, line in enumerate(lines):
        openers.append(tuple(stack))
        for c in line:
            if c in "([{":
                stack.append(row)
            elif c in ")]}" and stack:
                stack.pop()
    return lines, openers


# Write/append/delete calls on a path in Python source (GAP-2124). A
# cognitive file name counts as written only when the statement holding it,
# or a name it is assigned to, reaches one of these. ``fh.write(...)`` is
# left out: it takes content, not a path, and the ``open(p, "a")`` that made
# the handle already counts.
_PY_WRITE_METHODS = frozenset({"write_text", "write_bytes", "unlink", "rmdir", "rename", "touch"})
_PY_MODULE_WRITES = {
    "os": frozenset({"remove", "unlink", "rename", "replace", "truncate", "rmdir", "removedirs"}),
    # A copy onto a path overwrites it like a move does (GAP-2187).
    "shutil": frozenset({"move", "rmtree", "copy", "copy2", "copyfile", "copytree"}),
}
_PY_OPEN_FLAGS = frozenset({"O_WRONLY", "O_RDWR", "O_APPEND", "O_TRUNC", "O_CREAT"})
_PY_WRITE_MODE = re.compile(r"[rbtU]*[wax+][rbtU+]*")
_PY_MUTATORS = frozenset({"append", "extend", "add", "insert", "update", "setdefault"})
_PY_ASSIGN_OPS = frozenset({"=", "+=", "-=", "*=", "/=", "//=", "%=", "|=", "&=", "^=", ">>=", "<<=", "@=", "**="})


class _PyStmt:
    __slots__ = ("scope", "writes", "names", "targets")

    def __init__(self, scope: int) -> None:
        self.scope = scope
        self.writes = False
        self.names: set[str] = set()
        # (scope, name) pairs; scope -1 is module-wide (globals, attributes).
        self.targets: set[tuple[int, str]] = set()


class PySource:
    """One tokenize pass over a Python file: the two blanked views plus,
    on demand, the bracket and statement structure the call and write
    checks need (GAP-2068, GAP-2124)."""

    def __init__(self, toks: list, code: list[str], calls: list[str]) -> None:
        self.code = code
        self.calls = calls
        self._toks = toks
        self._openers: list[tuple[int, ...]] | None = None
        self._line_stmt: list[int] = []
        self._stmts: list[_PyStmt] = []

    def openers(self, line_idx: int) -> tuple[int, ...]:
        """Indexes of the lines whose brackets are still open at *line_idx*."""
        if self._openers is None:
            self._analyze()
        return self._openers[line_idx] if line_idx < len(self._openers) else ()

    def path_written(self, line_idx: int) -> bool:
        """True when the value on *line_idx* reaches a write/append/delete.

        Either its own statement writes (``Path(...).write_text``,
        ``open(p, "a")``, ``os.remove``), or it is assigned to a name (or
        returned from a function) that a writing statement later uses. A
        file name in a data list that is only compared against is not a
        write (GAP-2069).
        """
        if self._openers is None:
            self._analyze()
        if line_idx >= len(self._line_stmt) or self._line_stmt[line_idx] < 0:
            return False
        first = self._stmts[self._line_stmt[line_idx]]
        if first.writes:
            return True
        tainted: dict[str, set[int]] = {}
        for scope, name in first.targets:
            tainted.setdefault(name, set()).add(scope)
        seen = {id(first)}
        changed = bool(tainted)
        while changed:
            changed = False
            for st in self._stmts:
                if id(st) in seen:
                    continue
                if not any((scopes := tainted.get(n)) and (-1 in scopes or st.scope in scopes) for n in st.names):
                    continue
                if st.writes:
                    return True
                seen.add(id(st))
                for scope, name in st.targets:
                    tainted.setdefault(name, set()).add(scope)
                changed = True
        return False

    def _analyze(self) -> None:
        nrows = len(self.code)
        openers: list[tuple[int, ...]] = [()] * nrows
        line_stmt = [-1] * nrows
        stmts: list[_PyStmt] = []
        stack: list[int] = []
        funcs: list[tuple[int, int, str]] = []  # (indent, scope id, name)
        indent = 0
        row = 0
        cur: list = []
        for tok in self._toks:
            start_row = tok.start[0] - 1
            while row <= start_row and row < nrows:
                openers[row] = tuple(stack)
                row += 1
            if tok.type == tokenize.OP:
                if tok.string in "([{":
                    stack.append(start_row)
                elif tok.string in ")]}" and stack:
                    stack.pop()
            if tok.type == tokenize.INDENT:
                indent += 1
            elif tok.type == tokenize.DEDENT:
                indent -= 1
                while funcs and funcs[-1][0] >= indent:
                    funcs.pop()
            elif tok.type in (tokenize.NEWLINE, tokenize.ENDMARKER):
                if cur:
                    # A statement level with a def header ends that function
                    # (also after a one-line ``def f(): ...``).
                    while funcs and funcs[-1][0] >= indent:
                        funcs.pop()
                    st = _py_statement(cur, funcs)
                    for r in range(cur[0].start[0] - 1, min(cur[-1].end[0], nrows)):
                        line_stmt[r] = len(stmts)
                    stmts.append(st)
                    lead = [t.string for t in cur[:2]]
                    if lead[0] == "def" or lead == ["async", "def"]:
                        names = [t.string for t in cur if t.type == tokenize.NAME]
                        fname = names[names.index("def") + 1] if names.index("def") + 1 < len(names) else ""
                        funcs.append((indent, len(stmts) - 1, fname))
                cur = []
            elif tok.type not in (tokenize.NL, tokenize.COMMENT):
                cur.append(tok)
        self._openers, self._line_stmt, self._stmts = openers, line_stmt, stmts


def _string_value(tok_string: str) -> str:
    body = tok_string.lstrip("rRbBuUfF")
    if body[:3] in ('"""', "'''"):
        return body[3:-3]
    return body[1:-1]


def _py_statement(cur: list, funcs: list[tuple[int, int, str]]) -> _PyStmt:
    """Names, assignment targets and write calls of one logical line."""
    st = _PyStmt(funcs[-1][1] if funcs else -1)
    n = len(cur)

    def is_op(k: int, s: str) -> bool:
        return 0 <= k < n and cur[k].type == tokenize.OP and cur[k].string == s

    def add_target(k: int) -> None:
        name = cur[k].string
        if keyword.iskeyword(name):
            return
        st.targets.add((-1 if is_op(k - 1, ".") else st.scope, name))

    depth = 0
    assign_at: list[int] = []
    for k, tok in enumerate(cur):
        if tok.type == tokenize.OP:
            if tok.string in "([{":
                depth += 1
            elif tok.string in ")]}":
                depth -= 1
            elif depth == 0 and tok.string in _PY_ASSIGN_OPS:
                assign_at.append(k)
            continue
        if tok.type != tokenize.NAME or keyword.iskeyword(tok.string):
            continue
        name = tok.string
        st.names.add(name)
        if name in _PY_OPEN_FLAGS:
            st.writes = True
        elif is_op(k + 1, "(") and (
            (name in _PY_WRITE_METHODS and is_op(k - 1, "."))
            or (is_op(k - 1, ".") and k >= 2 and name in _PY_MODULE_WRITES.get(cur[k - 2].string, ()))
        ):
            st.writes = True
        elif name == "open" and is_op(k + 1, "("):
            level = 0
            for t in cur[k + 1 :]:
                if t.type == tokenize.OP and t.string in "([{":
                    level += 1
                elif t.type == tokenize.OP and t.string in ")]}":
                    level -= 1
                    if level == 0:
                        break
                elif t.type == tokenize.STRING and _PY_WRITE_MODE.fullmatch(_string_value(t.string)):
                    st.writes = True
                    break
        elif name in _PY_MUTATORS and is_op(k - 1, ".") and is_op(k + 1, "(") and k >= 2:
            if cur[k - 2].type == tokenize.NAME:
                add_target(k - 2)

    lead = cur[0].string
    if lead == "for" or (lead == "async" and n > 1 and cur[1].string == "for"):
        for k in range(1, n):
            if cur[k].type == tokenize.NAME and cur[k].string == "in":
                break
            if cur[k].type == tokenize.NAME:
                add_target(k)
    elif lead in ("with", "async"):
        for k in range(n - 1):
            if cur[k].type == tokenize.NAME and cur[k].string == "as" and cur[k + 1].type == tokenize.NAME:
                add_target(k + 1)
    elif lead in ("return", "yield"):
        if funcs and funcs[-1][2]:
            st.targets.add((-1, funcs[-1][2]))
    elif assign_at:
        depth = 0
        for k in range(assign_at[-1]):
            tok = cur[k]
            if tok.type == tokenize.OP:
                if tok.string in "([{":
                    depth += 1
                elif tok.string in ")]}":
                    depth -= 1
                elif depth == 0 and tok.string == ":":
                    break
            elif tok.type == tokenize.NAME and depth == 0 and not is_op(k + 1, "."):
                add_target(k)
    return st


def python_source(content: str) -> PySource | None:
    """Tokenize *content* once and return its :class:`PySource`, or None."""
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(content).readline))
    except (tokenize.TokenError, SyntaxError):
        return None
    string_types = {tokenize.STRING}
    if hasattr(tokenize, "FSTRING_MIDDLE"):
        string_types.add(tokenize.FSTRING_MIDDLE)
    doc_spans = []
    string_spans = []
    stmt_start = True
    for i, tok in enumerate(toks):
        if tok.type == tokenize.COMMENT:
            doc_spans.append(tok)
        elif tok.type in string_types:
            string_spans.append(tok)
            if tok.type == tokenize.STRING and stmt_start:
                # A bare string statement (docstring): strings up to NEWLINE.
                j = i + 1
                while j < len(toks) and toks[j].type in (tokenize.STRING, tokenize.NL, tokenize.COMMENT):
                    j += 1
                if j == len(toks) or toks[j].type in (tokenize.NEWLINE, tokenize.ENDMARKER):
                    doc_spans.extend(t for t in toks[i:j] if t.type == tokenize.STRING)
        if tok.type in (tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT):
            stmt_start = True
        elif tok.type not in (tokenize.NL, tokenize.COMMENT):
            stmt_start = False
    rows = content.split("\n")
    _blank_spans(rows, doc_spans)
    code = [r.rstrip() for r in rows]
    _blank_spans(rows, string_spans)
    return PySource(toks, code, [r.rstrip() for r in rows])


def _blank_spans(rows: list[str], spans) -> None:
    """Replace each token span in *rows* with spaces, keeping columns."""
    for tok in spans:
        (sr, sc), (er, ec) = tok.start, tok.end
        for r in range(sr - 1, min(er, len(rows))):
            row = rows[r]
            lo = sc if r == sr - 1 else 0
            hi = min(ec if r == er - 1 else len(row), len(row))
            if hi > lo:
                rows[r] = row[:lo] + " " * (hi - lo) + row[hi:]


def is_comment_line(line: str) -> bool:
    """Quick check if a raw line is a single-line comment."""
    stripped = line.lstrip()
    return stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*")


def is_test_path(rel_path: str) -> bool:
    return any(pat.search(rel_path) for pat in DEPRIORITIZED_PATH_PATTERNS)


def downgrade(severity: str) -> str:
    """Downgrade severity by one level (for test-path findings)."""
    mapping = {
        "CRITICAL": "HIGH",
        "HIGH": "MEDIUM",
        "MEDIUM": "LOW",
        "LOW": "INFO",
        "INFO": "INFO",
    }
    return mapping.get(severity, severity)


# ---------------------------------------------------------------------------
# File system helpers
# ---------------------------------------------------------------------------


# Directories that are always safe to skip (build artifacts, VCS, IDE config,
# and Python virtual environments).
# `dist/` was previously skipped unconditionally, but
# many npm plugins point `package.json.main` at `dist/index.js` and
# malicious shipped JavaScript can hide there while the source
# analyzer sees nothing. We no longer skip `dist/` so source rules
# apply to runtime entrypoints.
_SKIP_DIRS: frozenset[str] = frozenset(
    {
        "node_modules",
        "coverage",
        ".git",
        ".svn",
        ".hg",
        ".vscode",
        ".idea",
        ".tox",
        "__pycache__",
        ".mypy_cache",
        "venv",
        ".venv",
        "env",
    }
)

# Standard connector manifest directories.  These names are security
# sensitive: callers may special-case only exact, top-level entries and must
# still require a real directory rather than a symlink or Windows reparse
# point.
STANDARD_MANIFEST_DIRS: frozenset[str] = frozenset(
    {
        ".claude-plugin",
        ".codex-plugin",
        ".cursor-plugin",
    }
)


class PathLinkStatus(Enum):
    """Result of inspecting one directory entry without following it."""

    PLAIN = "plain"
    LINK_OR_REPARSE = "link_or_reparse"
    ERROR = "error"


def inspect_path_link(
    path: str | os.PathLike[str],
) -> tuple[PathLinkStatus, os.stat_result | None]:
    """Classify an entry, distinguishing inspection failure from a plain path."""
    try:
        info = os.lstat(path)
    except OSError:
        return PathLinkStatus.ERROR, None
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attributes = getattr(info, "st_file_attributes", 0)
    if stat.S_ISLNK(info.st_mode) or bool(attributes & reparse_flag):
        return PathLinkStatus.LINK_OR_REPARSE, info
    return PathLinkStatus.PLAIN, info


# Safety cap — high enough for any real plugin tree, low enough to bound cost.
_MAX_DEPTH = 20


def collect_files(
    directory: str,
    extensions: list[str],
    max_depth: int = _MAX_DEPTH,
    max_file_bytes: int = 2 * 1024 * 1024,
    _depth: int = 0,
    *,
    _scan_root: str | None = None,
    _seen_inodes: set[tuple[int, int]] | None = None,
    _symlink_escapes: list[str] | None = None,
    _depth_truncations: list[str] | None = None,
    _oversized_files: list[str] | None = None,
) -> list[str]:
    """Recursively collect files with given extensions.

    - Symlinked dirs/files that escape *scan_root* are skipped and recorded.
    - Inode tracking prevents symlink cycles.
    - Only known-benign directories are skipped; other dot-prefixed dirs are scanned.
    - Depth limit raised to 20; truncated directories are recorded.
    - Files exceeding *max_file_bytes* are skipped and recorded in *_oversized_files*
      without being read, preventing memory exhaustion from crafted large files.
    """
    if _scan_root is None:
        _scan_root = os.path.realpath(directory)
    if _seen_inodes is None:
        _seen_inodes = set()
        try:
            st_root = os.stat(_scan_root)
            _seen_inodes.add((st_root.st_dev, st_root.st_ino))
        except OSError:
            pass
    if _symlink_escapes is None:
        _symlink_escapes = []
    if _depth_truncations is None:
        _depth_truncations = []

    if _depth >= max_depth:
        _depth_truncations.append(directory)
        return []

    files: list[str] = []
    try:
        entries = os.listdir(directory)
    except OSError:
        return files

    for entry in entries:
        # Skip known-benign directories only; scan other dot-prefixed dirs
        if entry in _SKIP_DIRS:
            continue

        full_path = os.path.join(directory, entry)
        try:
            # --- Symlink containment ---
            # NOTE: There is a theoretical TOCTOU race between the link check
            # and os.path.realpath(): the symlink target could change between
            # the two calls. Acceptable for static plugin scanning where the
            # directory is not modified concurrently.
            link_status, entry_info = inspect_path_link(full_path)
            if link_status is PathLinkStatus.ERROR:
                continue
            if link_status is PathLinkStatus.LINK_OR_REPARSE and _depth == 0 and entry in STANDARD_MANIFEST_DIRS:
                # A standard manifest directory must never be represented by
                # a link, even when its target remains inside the scan root.
                continue
            if link_status is PathLinkStatus.LINK_OR_REPARSE:
                real = os.path.realpath(full_path)
                # Block symlinks that escape the scan root
                if not real.startswith(_scan_root + os.sep) and real != _scan_root:
                    _symlink_escapes.append(full_path)
                    continue

            is_directory = (
                stat.S_ISDIR(entry_info.st_mode)
                if link_status is PathLinkStatus.PLAIN and entry_info is not None
                else os.path.isdir(full_path)
            )
            if is_directory:
                try:
                    st_dir = os.stat(full_path)
                    dir_key = (st_dir.st_dev, st_dir.st_ino)
                except OSError:
                    continue
                if dir_key in _seen_inodes:
                    continue
                _seen_inodes.add(dir_key)
                nested = collect_files(
                    full_path,
                    extensions,
                    max_depth,
                    max_file_bytes,
                    _depth + 1,
                    _scan_root=_scan_root,
                    _seen_inodes=_seen_inodes,
                    _symlink_escapes=_symlink_escapes,
                    _depth_truncations=_depth_truncations,
                    _oversized_files=_oversized_files,
                )
                files.extend(nested)
            elif any(entry.endswith(ext) for ext in extensions):
                try:
                    st_file = os.stat(full_path)
                    file_key = (st_file.st_dev, st_file.st_ino)
                except OSError:
                    continue
                if file_key in _seen_inodes:
                    continue
                _seen_inodes.add(file_key)
                if max_file_bytes > 0:
                    try:
                        if os.path.getsize(full_path) > max_file_bytes:
                            if _oversized_files is not None:
                                _oversized_files.append(full_path)
                            continue
                    except OSError:
                        pass
                files.append(full_path)
        except OSError:
            continue

    return files


def audit_skipped_dirs_for_native(
    directory: str,
    max_depth: int = _MAX_DEPTH,
    _depth: int = 0,
    *,
    _scan_root: str | None = None,
    _in_skipped: bool = False,
) -> list[Finding]:
    """Flag native/binary payloads hidden under normally-skipped directories.

    F-1907: :func:`collect_files` (and the directory-structure scanner)
    blanket-skip ``node_modules``/``.git`` and the other ``_SKIP_DIRS``.
    That blind spot let a malicious plugin stash a native addon under one
    of them (e.g. a dependency loader in ``node_modules`` that ``require``s
    a ``.node``/``.so`` payload kept in ``.git``) and evade BOTH source and
    binary scanning.

    Rather than fully un-skipping those trees (which would explode cost and
    false positives on legitimate dependency source), this walks INTO each
    skipped directory and reports ONLY files whose extension is in
    :data:`BINARY_EXTENSIONS` (``.exe``/``.so``/``.dylib``/``.wasm``/``.dll``/
    ``.node``). A compiled native module never legitimately lives inside a
    VCS object store or build cache, so the signal is high and the
    false-positive surface tiny. Findings use a dedicated
    ``STRUCT-NATIVE-IN-SKIPDIR`` rule so the historical "skip VCS/cache dirs
    for ordinary structure checks" behaviour (and the
    ``STRUCT-BINARY``-based tests) is preserved.

    Symlinks are never followed (containment / cycle safety) and the same
    depth cap as the collector bounds traversal cost.
    """
    if _scan_root is None:
        _scan_root = os.path.realpath(directory)
    if _depth >= max_depth:
        return []

    findings: list[Finding] = []
    try:
        entries = os.listdir(directory)
    except OSError:
        return findings

    for entry in entries:
        full_path = os.path.join(directory, entry)
        try:
            link_status, entry_info = inspect_path_link(full_path)
            if link_status is not PathLinkStatus.PLAIN or entry_info is None:
                continue
            if stat.S_ISDIR(entry_info.st_mode):
                # Descend once we are inside (or entering) a skipped dir;
                # outside skipped dirs we only recurse looking for the next
                # skipped dir so we don't re-walk the entire source tree.
                entering_skipped = _in_skipped or entry in _SKIP_DIRS
                if not _in_skipped and entry not in _SKIP_DIRS:
                    # Keep hunting for a skipped dir nested deeper (e.g.
                    # ``a/b/node_modules``) without auditing ordinary files.
                    findings.extend(
                        audit_skipped_dirs_for_native(
                            full_path, max_depth, _depth + 1, _scan_root=_scan_root, _in_skipped=False
                        )
                    )
                    continue
                findings.extend(
                    audit_skipped_dirs_for_native(
                        full_path, max_depth, _depth + 1, _scan_root=_scan_root, _in_skipped=entering_skipped
                    )
                )
                continue
            if not _in_skipped:
                continue
            dot_idx = entry.rfind(".")
            ext = entry[dot_idx:] if dot_idx >= 0 else ""
            if ext in BINARY_EXTENSIONS:
                rel = full_path.replace(_scan_root + os.sep, "").replace(os.sep, "/")
                findings.append(
                    make_finding(
                        len(findings) + 1,
                        rule_id="STRUCT-NATIVE-IN-SKIPDIR",
                        severity="HIGH",
                        confidence=0.85,
                        title=f"Native payload hidden in skipped directory: {entry}",
                        evidence=f"File: {rel}",
                        description=(
                            f'Plugin hides a native/binary file "{entry}" inside a directory the scanner '
                            "normally skips (node_modules, .git, etc.). Stashing a native addon under a "
                            "skipped directory and loading it from a dependency is a known way to evade "
                            "both source and binary scanning (F-1907)."
                        ),
                        location=rel,
                        remediation=(
                            "Remove native binaries from node_modules/.git and other build/VCS directories. "
                            "Plugins should contain only auditable source code."
                        ),
                        tags=["supply-chain"],
                    )
                )
        except OSError:
            continue

    return findings


def resolve_entrypoint_files(directory: str, entrypoints: list[str] | None) -> list[str]:
    """Resolve declared manifest entrypoints to existing files in *directory*.

    ``package.json`` ``main``/``bin`` (and connector-manifest entrypoints)
    routinely point at extensionless launchers (e.g. ``bin/cli``) or files
    under directories that :func:`collect_files` skips (e.g. a ``main`` under
    ``node_modules``). Those runtime files must still be scanned, so callers
    use this to force-include the specific resolved files in source / LLM
    analysis regardless of extension allow-lists or ``_SKIP_DIRS``.

    Each entrypoint is treated as a path relative to the plugin directory.
    Resolved paths that escape the plugin root (via ``..`` or symlinks) are
    dropped for containment. Returned paths are anchored under *directory*
    (so callers can derive a stable relative path), de-duplicated by their
    real path.
    """
    if not entrypoints:
        return []

    scan_root = os.path.realpath(directory)
    resolved: list[str] = []
    seen_real: set[str] = set()

    for raw in entrypoints:
        if not isinstance(raw, str):
            continue
        rel = raw.strip()
        if not rel:
            continue
        # Strip a leading "./" and any leading separators so the entry can
        # never be interpreted as an absolute path that escapes the plugin.
        rel = rel.lstrip("/")
        candidate = os.path.join(directory, rel)
        try:
            real = os.path.realpath(candidate)
        except OSError:
            continue
        # Containment: resolved file must stay inside the plugin root.
        if real != scan_root and not real.startswith(scan_root + os.sep):
            continue
        try:
            if not os.path.isfile(candidate):
                continue
        except OSError:
            continue
        if real in seen_real:
            continue
        seen_real.add(real)
        resolved.append(candidate)

    return resolved


def check_lockfile_presence(directory: str) -> bool:
    for name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
        if os.path.isfile(os.path.join(directory, name)):
            return True
    return False


def dir_exists(path: str) -> bool:
    try:
        return os.path.isdir(path)
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Finding factory
# ---------------------------------------------------------------------------


def make_finding(
    id_num: int,
    *,
    rule_id: str,
    severity: str,
    confidence: float,
    title: str,
    description: str,
    evidence: str | None = None,
    location: str | None = None,
    remediation: str | None = None,
    tags: list[str] | None = None,
) -> Finding:
    return Finding(
        id=f"plugin-{id_num}",
        rule_id=rule_id,
        severity=severity,
        confidence=confidence,
        title=title,
        description=description,
        evidence=evidence,
        location=location,
        remediation=remediation,
        scanner=SCANNER_NAME,
        tags=tags or [],
        taxonomy=TAXONOMY_MAP.get(rule_id),
    )


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Merge multiple hits on the same rule into one finding with occurrence_count."""
    seen: dict[str, Finding] = {}
    out: list[Finding] = []

    for f in findings:
        key = f"{f.rule_id or ''}::{f.title}::{f.location or ''}"
        existing = seen.get(key)
        if existing is not None:
            existing.occurrence_count = (existing.occurrence_count or 1) + 1
            if SEVERITY_RANK.get(f.severity, 0) > SEVERITY_RANK.get(existing.severity, 0):
                existing.severity = f.severity
                existing.confidence = f.confidence
                existing.location = f.location
                existing.evidence = f.evidence
        else:
            from copy import copy

            c = copy(f)
            c.tags = list(f.tags)  # shallow copy list
            c.occurrence_count = 1
            seen[key] = c
            out.append(c)

    return out


# ---------------------------------------------------------------------------
# Assessment computation
# ---------------------------------------------------------------------------

_ASSESSMENT_CATEGORIES: list[dict[str, list[str] | str]] = [
    {
        "name": "permissions",
        "tags": [],
        "rule_ids": ["PERM-DANGEROUS", "PERM-WILDCARD", "PERM-NONE", "TOOL-PERM-DANGEROUS"],
    },
    {"name": "supply-chain", "tags": ["supply-chain"], "rule_ids": []},
    {"name": "credentials", "tags": ["credential-theft"], "rule_ids": []},
    {"name": "exfiltration", "tags": ["exfiltration"], "rule_ids": []},
    {
        "name": "code-execution",
        "tags": ["code-execution"],
        "rule_ids": ["SRC-EVAL", "SRC-NEW-FUNC", "SRC-CHILD-PROC", "SRC-EXEC", "SRC-DENO-RUN", "SRC-BUN-SPAWN"],
    },
    {"name": "obfuscation", "tags": ["obfuscation"], "rule_ids": []},
    {"name": "gateway-integrity", "tags": ["gateway-manipulation"], "rule_ids": []},
    {"name": "cognitive-tampering", "tags": ["cognitive-tampering"], "rule_ids": []},
]


def _category_status(findings: list[Finding]) -> str:
    if not findings:
        return "pass"
    max_sev = 0
    for f in findings:
        rank = SEVERITY_RANK.get(f.severity, 0)
        if rank > max_sev:
            max_sev = rank
    if max_sev >= 4:
        return "fail"
    if max_sev >= 3:
        return "warn"
    return "info"


_SEV_SORT_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def compute_assessment(findings: list[Finding]) -> Assessment:
    categories: list[AssessmentCategory] = []

    for cat in _ASSESSMENT_CATEGORIES:
        cat_tags: list[str] = cat["tags"]  # type: ignore[assignment]
        cat_rule_ids: list[str] = cat["rule_ids"]  # type: ignore[assignment]

        relevant = [
            f for f in findings if (f.rule_id or "") in cat_rule_ids or any(t in (f.tags or []) for t in cat_tags)
        ]
        status = _category_status(relevant)

        if not relevant:
            summary = "No issues detected."
        else:
            counts: dict[str, int] = {}
            for f in relevant:
                counts[f.severity] = counts.get(f.severity, 0) + 1
            parts = sorted(counts.items(), key=lambda x: _SEV_SORT_ORDER.get(x[0], 5))
            parts_str = ", ".join(f"{count} {sev}" for sev, count in parts)
            n = len(relevant)
            summary = f"{n} finding{'s' if n > 1 else ''}: {parts_str}."

        categories.append(
            AssessmentCategory(
                name=cat["name"],  # type: ignore[arg-type]
                status=status,
                summary=summary,
            )
        )

    has_critical = any(f.severity == "CRITICAL" for f in findings)
    has_high = any(f.severity == "HIGH" for f in findings)
    has_medium = any(f.severity == "MEDIUM" for f in findings)
    max_confidence = max((f.confidence or 0 for f in findings), default=0)

    if has_critical:
        verdict = "malicious"
        confidence = min(max_confidence, 0.95)
        n_crit = sum(1 for f in findings if f.severity == "CRITICAL")
        summary = f"Plugin has {n_crit} critical finding(s) indicating likely malicious behaviour."
    elif has_high:
        verdict = "suspicious"
        confidence = min(max_confidence, 0.85)
        n_high = sum(1 for f in findings if f.severity == "HIGH")
        summary = f"Plugin has {n_high} high-severity finding(s) requiring review."
    elif has_medium:
        verdict = "suspicious"
        confidence = min(max_confidence, 0.6)
        n_med = sum(1 for f in findings if f.severity == "MEDIUM")
        summary = f"Plugin has {n_med} medium-severity finding(s). Review recommended."
    elif findings:
        verdict = "benign"
        confidence = 0.8
        summary = "Plugin has only low/informational findings."
    else:
        verdict = "benign"
        confidence = 0.9
        summary = "No security issues detected."

    return Assessment(
        verdict=verdict,
        confidence=confidence,
        summary=summary,
        categories=categories,
    )


# ---------------------------------------------------------------------------
# Result builder
# ---------------------------------------------------------------------------


def build_result(
    target: str,
    findings: list[Finding],
    start_ms: float,
    metadata: ScanMetadata | None = None,
) -> ScanResult:
    import time

    elapsed_ms = time.time() * 1000 - start_ms
    return ScanResult(
        scanner=SCANNER_NAME,
        target=target,
        timestamp=datetime.now(timezone.utc).isoformat(),
        findings=findings,
        duration_ns=int(elapsed_ms * 1_000_000),
        metadata=metadata,
        assessment=compute_assessment(findings),
    )
