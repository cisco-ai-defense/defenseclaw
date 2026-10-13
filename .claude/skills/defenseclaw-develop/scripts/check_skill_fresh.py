#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Check that the defenseclaw-develop skill still matches the repository.

Run from the repository root:

    python3 .claude/skills/defenseclaw-develop/scripts/check_skill_fresh.py

For every backticked span in SKILL.md and reference/*.md the script verifies:

  * repo paths exist (a span or a token inside a command whose first path
    segment is a top-level repo entry; placeholders and globs are skipped),
  * make targets named after `make` are defined in the Makefile,
  * symbols written as `@sym:Name` are found by git grep outside the skill,
  * every alternative of a `go test -run` pattern matches a Test function in
    the named packages (a pattern that matches nothing passes vacuously).

It also enforces the size limits (SKILL.md 200 lines, checklist 340, other
reference files 300), the frontmatter name, that every reference file is
linked from SKILL.md, and the ID rules: requirement IDs are defined once, in
reference/checklist.md, and every ID cited anywhere is defined there.

Exit codes: 0 no drift, 1 drift, 2 the script could not run.
Standard library only, no network.
"""
from __future__ import annotations

import argparse
import os
import re
import shlex
import subprocess
import sys

SKILL_NAME = "defenseclaw-develop"
SKILL_REL = ".claude/skills/" + SKILL_NAME
SKILL_MAX_LINES = 200
REFERENCE_MAX_LINES = 300
CHECKLIST_MAX_LINES = 340
AREAS = ("CFG", "POL", "ID", "DEP", "REQ", "SBX", "SCN", "TST", "PERF", "OBS", "DOC", "SEC", "PKG", "PR")
ID_RE = re.compile(r"\b([MSO])-([A-Z]+)-(\d+)\b")
DEF_RE = re.compile(r"\*\*([MSO]-[A-Z]+-\d+)\*\*")
TEST_FUNC_RE = re.compile(r"^func (Test\w*)\(", re.M)
# Skill copies are excluded from symbol search so the skill cannot vouch for itself.
SYMBOL_EXCLUDES = (":(exclude).claude/skills/" + SKILL_NAME,
                   ":(exclude).agents/skills/" + SKILL_NAME)

SPAN_RE = re.compile(r"`([^`\n]+)`")
PATH_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.\-/]+$")
TARGET_RE = re.compile(r"^[a-z][a-z0-9_.\-]*$")
MAKE_RE = re.compile(r"(?:^|[\s;&|(])make\s+((?:[^\s;&|)]+\s*)+)")
ROOT_FILES = {
    "Makefile", "CONTRIBUTING.md", "AGENTS.md", "CHANGELOG.md", "SECURITY.md",
    "THIRD_PARTY_LICENSES.txt", "go.mod", "pyproject.toml", "uv.lock", "NOTICE",
}


_FOUND: set[str] | None = None


def preload_symbols(root: str, symbols: set[str]) -> None:
    """Find every symbol with one git grep (one process per symbol is too slow)."""
    global _FOUND
    _FOUND = set()
    if not symbols:
        return
    cmd = ["git", "grep", "-h", "-o", "-F", "-w"]
    for sym in sorted(symbols):
        cmd.extend(["-e", sym])
    cmd.append("--")
    cmd.append(".")
    cmd.extend(SYMBOL_EXCLUDES)
    try:
        out = subprocess.run(cmd, cwd=root, capture_output=True, text=True,
                             errors="replace").stdout
    except OSError:
        return
    _FOUND = set(out.split())


def git_grep(root: str, symbol: str) -> bool:
    if _FOUND is not None:
        return symbol in _FOUND
    cmd = ["git", "grep", "-q", "-F", "-w", "-e", symbol, "--", "."]
    cmd.extend(SYMBOL_EXCLUDES)
    try:
        return subprocess.run(cmd, cwd=root, capture_output=True).returncode == 0
    except OSError:
        return False


def makefile_targets(root: str) -> set[str]:
    targets: set[str] = set()
    try:
        with open(os.path.join(root, "Makefile"), encoding="utf-8") as fh:
            for line in fh:
                m = re.match(r"^([A-Za-z0-9_.\-]+(?:\s+[A-Za-z0-9_.\-]+)*)\s*:(?!=)", line)
                if m:
                    targets.update(m.group(1).split())
                if line.startswith(".PHONY"):
                    targets.update(re.findall(r"[A-Za-z0-9_.\-]+", line.split(":", 1)[-1]))
    except OSError:
        pass
    return targets


def spans_with_lines(path: str):
    """Yield (line_number, span_text) for backticked spans outside code fences."""
    fenced = False
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if line.lstrip().startswith("```"):
                fenced = not fenced
                continue
            if fenced:
                continue
            for m in SPAN_RE.finditer(line):
                yield n, m.group(1).strip()


def is_placeholder(text: str) -> bool:
    return any(c in text for c in "<>*{}$|") or "..." in text or text.startswith("~")


def check_path(root: str, tops: set[str], token: str, single: bool) -> str | None:
    token = token.rstrip(".,;:)")
    if token.startswith("./"):
        token = token[2:]
    if not token or is_placeholder(token) or not PATH_TOKEN_RE.match(token):
        return None
    first = token.split("/", 1)[0]
    if "/" not in token and token not in ROOT_FILES:
        return None
    if first not in tops and token not in ROOT_FILES:
        return None
    if os.path.exists(os.path.join(root, token)):
        return None
    return "path not found: " + token


def go_run_problems(root, span):
    """Flag `go test ... -run a|b` alternatives that match no Test function."""
    if not span.startswith("go test "):
        return []
    try:
        words = shlex.split(span.replace("\\|", "|"))
    except ValueError:
        return []
    pkgs = [w for w in words if w.startswith("./") and not is_placeholder(w.replace("...", ""))]
    pats = [words[i + 1] for i, w in enumerate(words[:-1]) if w == "-run"]
    if not pkgs or not pats:
        return []
    names: list[str] = []
    for pkg in pkgs:
        base = os.path.join(root, pkg[2:].replace("...", "").rstrip("/"))
        walk = pkg.endswith("...")
        dirs = [d for d, _, _ in os.walk(base)] if walk else [base]
        for d in dirs:
            if not os.path.isdir(d):
                continue
            for f in os.listdir(d):
                if f.endswith("_test.go"):
                    with open(os.path.join(d, f), encoding="utf-8", errors="replace") as fh:
                        names += TEST_FUNC_RE.findall(fh.read())
    out = []
    for pat in pats:
        if pat in ("^$",) or is_placeholder(pat.replace("|", "")):
            continue
        for alt in pat.split("|"):
            alt = alt.split("/")[0]
            try:
                rx = re.compile(alt)
            except re.error:
                continue
            if alt and not any(rx.search(n) for n in names):
                out.append("go test -run alternative matches no test: " + alt)
    return out


def check_span(root, tops, targets, span):
    problems: list[str] = []
    if span.startswith("@sym:"):
        sym = span[len("@sym:"):].strip()
        if sym and not is_placeholder(sym) and not git_grep(root, sym):
            problems.append("symbol not found: " + sym)
        return problems
    if " " not in span:
        msg = check_path(root, tops, span, True)
        return [msg] if msg else []
    # A command: check make targets and any repo paths inside it.
    problems.extend(go_run_problems(root, span))
    for m in MAKE_RE.finditer(span):
        for word in m.group(1).split():
            if "=" in word or word.startswith("-") or is_placeholder(word):
                break
            if not TARGET_RE.match(word):
                break
            if word not in targets:
                problems.append("make target not found: " + word)
    for token in span.split():
        msg = check_path(root, tops, token, False)
        if msg:
            problems.append(msg)
    return problems


def id_problems(files) -> list[str]:
    """IDs are defined once, in reference/checklist.md; every cited ID must exist."""
    out: list[str] = []
    defined: dict[str, int] = {}
    cited: list[tuple[str, int, str]] = []
    for label, path, _ in files:
        with open(path, encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                if label == "reference/checklist.md":
                    for m in DEF_RE.finditer(line):
                        if m.group(1) in defined:
                            out.append("%s:%d: ID defined twice: %s" % (label, n, m.group(1)))
                        defined[m.group(1)] = n
                elif re.match(r"^\| [MSO]-[A-Z]+-\d+ \|", line):
                    out.append("%s:%d: IDs are defined only in reference/checklist.md" % (label, n))
                for m in ID_RE.finditer(line):
                    cited.append((label, n, m.group(0)))
    for label, n, ident in cited:
        area = ident.split("-")[1]
        if area not in AREAS:
            out.append("%s:%d: unknown requirement area in %s" % (label, n, ident))
        elif ident not in defined:
            out.append("%s:%d: ID not defined in reference/checklist.md: %s" % (label, n, ident))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=".", help="repository root (default: cwd)")
    ap.add_argument("--skill", default=None,
                    help="skill directory (default: %s under the root)" % SKILL_REL)
    args = ap.parse_args()

    root = os.path.abspath(args.root)
    skill = os.path.abspath(args.skill or os.path.join(root, SKILL_REL))
    if not os.path.isfile(os.path.join(root, "Makefile")) or not os.path.isdir(
            os.path.join(root, ".git")) and not os.path.isfile(os.path.join(root, ".git")):
        print("check_skill_fresh: run from the repository root (Makefile and .git not found)",
              file=sys.stderr)
        return 2
    skill_md = os.path.join(skill, "SKILL.md")
    if not os.path.isfile(skill_md):
        print("check_skill_fresh: %s not found" % skill_md, file=sys.stderr)
        return 2

    ref_dir = os.path.join(skill, "reference")
    refs = sorted(f for f in os.listdir(ref_dir) if f.endswith(".md")) if os.path.isdir(ref_dir) else []
    files = [("SKILL.md", skill_md, SKILL_MAX_LINES)]
    files += [("reference/" + f, os.path.join(ref_dir, f),
               CHECKLIST_MAX_LINES if f == "checklist.md" else REFERENCE_MAX_LINES) for f in refs]

    syms: set[str] = set()
    for _, path, _ in files:
        with open(path, encoding="utf-8") as fh:
            syms.update(s.strip() for s in re.findall(r"`@sym:([^`\n]+)`", fh.read())
                        if s.strip() and not is_placeholder(s))
    preload_symbols(root, syms)

    tops = {e for e in os.listdir(root) if e != ".git"}
    targets = makefile_targets(root)
    drift: list[str] = []
    cache: dict[str, list[str]] = {}

    for label, path, limit in files:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        count = text.count("\n") + (0 if text.endswith("\n") or not text else 1)
        if count > limit:
            drift.append("%s: %d lines, limit is %d" % (label, count, limit))
        if label == "SKILL.md":
            if not re.search(r"^name:\s*%s\s*$" % SKILL_NAME, text, re.M):
                drift.append("SKILL.md: frontmatter name must be %s" % SKILL_NAME)
            if not re.search(r"^description:\s*\S", text, re.M):
                drift.append("SKILL.md: frontmatter description is missing")
            for f in refs:
                if "reference/" + f not in text:
                    drift.append("SKILL.md: reference/%s is not linked" % f)
        for n, span in spans_with_lines(path):
            if span not in cache:
                cache[span] = check_span(root, tops, targets, span)
            for problem in cache[span]:
                drift.append("%s:%d: %s (in `%s`)" % (label, n, problem, span[:70]))

    drift.extend(id_problems(files))

    if drift:
        print("defenseclaw-develop skill has drifted from the repository (%d problems):" % len(drift))
        for item in drift:
            print("  - " + item)
        print("Fix the citation or the rule. See %s/reference/maintenance.md." % SKILL_REL)
        return 1
    print("defenseclaw-develop skill is fresh: %d files checked." % len(files))
    return 0


if __name__ == "__main__":
    sys.exit(main())
