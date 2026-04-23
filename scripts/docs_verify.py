#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Strict docs-site accuracy checks.

This verifier intentionally checks code-derived facts that are easy to drift:
source footers, MDX component vocabulary, CLI example flags, HTTP routes, and
Make targets. It is complementary to docs-gen and dead-link checks.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs-site"
ALLOWED_COMPONENTS = {
    "Callout",
    "CodeBlock",
    "DocImage",
    "VideoEmbed",
    "IdeInstallLinks",
    "RelatedProjects",
}
STALE_PATTERNS = [
    ("18790", "stale gateway API port"),
    ("--enable-guardrails", "stale plural guardrail flag"),
]
ALLOWED_PLACEHOLDERS = {"http://", "https://", "mailto:"}


@dataclass
class Issue:
    path: Path
    message: str

    def __str__(self) -> str:
        try:
            rel = self.path.relative_to(ROOT)
        except ValueError:
            rel = self.path
        return f"{rel}: {self.message}"


@dataclass
class CommandSpec:
    flags: set[str]
    has_positionals: bool = False


def strip_fences(text: str) -> str:
    return re.sub(r"```[A-Za-z0-9_-]*\n.*?```", "", text, flags=re.S)


def mdx_files() -> list[Path]:
    return sorted(DOCS.rglob("*.mdx"))


def check_frontmatter(path: Path, text: str) -> list[Issue]:
    issues: list[Issue] = []
    if not text.startswith("---\n"):
        return [Issue(path, "missing YAML frontmatter")]
    end = text.find("\n---\n", 4)
    if end == -1:
        return [Issue(path, "unterminated YAML frontmatter")]
    fm = text[4:end]
    for key in ("title", "description", "order"):
        if not re.search(rf"^{key}:\s+.+$", fm, re.M):
            issues.append(Issue(path, f"frontmatter missing {key}"))
    desc = re.search(r'^description:\s+"?(.+?)"?$', fm, re.M)
    if desc:
        value = desc.group(1).strip()
        if len(value) > 140:
            issues.append(Issue(path, "frontmatter description exceeds 140 characters"))
        if value and value[-1] not in ".!?":
            issues.append(Issue(path, "frontmatter description must end with punctuation"))
    m = re.search(r"^order:\s+(.+)$", fm, re.M)
    if m:
        try:
            int(m.group(1).strip())
        except ValueError:
            issues.append(Issue(path, "frontmatter order must be an integer"))
    return issues


def check_code_fences(path: Path, text: str) -> list[Issue]:
    issues: list[Issue] = []
    in_fence = False
    for line in text.splitlines():
        if line.startswith("~~~"):
            issues.append(Issue(path, "use triple-backtick code fences instead of tilde fences"))
            continue
        if not line.startswith("```"):
            continue
        info = line[3:].strip()
        if in_fence:
            in_fence = False
            continue
        in_fence = True
        if not info:
            issues.append(Issue(path, "untagged fenced code block"))
        elif info == "sh":
            issues.append(Issue(path, "use bash code fences instead of sh"))
    return issues


def check_components(path: Path, text: str) -> list[Issue]:
    issues: list[Issue] = []
    body = strip_fences(text)
    for tag in sorted(set(re.findall(r"</?([A-Z][A-Za-z0-9]*)\b", body))):
        if tag not in ALLOWED_COMPONENTS:
            issues.append(Issue(path, f"unsupported MDX component or placeholder <{tag}>"))
    return issues


def _footer_refs(text: str) -> list[str]:
    m = re.search(r"<!-- generated-from:\s*(.*?)\s*-->\s*$", text.strip(), re.S)
    if not m:
        return []
    return [r.strip() for r in m.group(1).split(",") if r.strip()]


def check_generated_from(path: Path, text: str) -> list[Issue]:
    issues: list[Issue] = []
    refs = _footer_refs(text)
    if not refs:
        issues.append(Issue(path, "missing generated-from footer as last non-empty line"))
        return issues
    for ref in refs:
        clean = ref.split("::", 1)[0].strip()
        if clean != ref and not clean:
            issues.append(Issue(path, f"invalid generated-from ref {ref!r}"))
            continue
        if " " in clean and not clean.startswith("."):
            issues.append(Issue(path, f"generated-from ref must be an exact path or glob: {ref!r}"))
            continue
        if "*" in clean:
            if not list(ROOT.glob(clean)):
                issues.append(Issue(path, f"generated-from glob has no matches: {clean}"))
        elif clean.endswith("/"):
            if not (ROOT / clean).is_dir():
                issues.append(Issue(path, f"generated-from directory missing: {clean}"))
        elif not (ROOT / clean).exists():
            issues.append(Issue(path, f"generated-from path missing: {clean}"))
    return issues


def check_pinned(path: Path, text: str) -> list[Issue]:
    issues: list[Issue] = []
    for pat, msg in STALE_PATTERNS:
        if pat in text:
            issues.append(Issue(path, f"{msg}: {pat}"))
    return issues


def click_commands() -> dict[str, CommandSpec]:
    sys.path.insert(0, str(ROOT / "cli"))
    from defenseclaw.main import cli  # type: ignore

    out: dict[str, CommandSpec] = {}

    def walk(prefix: list[str], cmd) -> None:
        flags = {"--help"}
        for p in getattr(cmd, "params", []):
            if hasattr(p, "opts"):
                for opt in p.opts + p.secondary_opts:
                    if opt.startswith("--"):
                        flags.add(opt)
        if prefix == ["defenseclaw"]:
            flags.add("--version")
        has_positionals = any(p.__class__.__name__ == "Argument" for p in getattr(cmd, "params", []))
        out[" ".join(prefix)] = CommandSpec(flags=flags, has_positionals=has_positionals)
        for name, sub in getattr(cmd, "commands", {}).items():
            walk(prefix + [name], sub)

    walk(["defenseclaw"], cli)
    return out


def cobra_commands() -> dict[str, CommandSpec]:
    exe = ROOT / "bin" / "docgen-go"
    if exe.exists():
        proc = subprocess.run([str(exe)], cwd=ROOT, text=True, capture_output=True, check=True)
    else:
        proc = subprocess.run(["go", "run", "./cmd/docgen-go"], cwd=ROOT, text=True, capture_output=True, check=True)
    tree = json.loads(proc.stdout)
    out: dict[str, CommandSpec] = {}

    def walk(node: dict, inherited: set[str] | None = None) -> None:
        inherited = set(inherited or ())
        flags = {"--help", "--version"} if node["full_name"] == "defenseclaw-gateway" else {"--help"}
        for f in node.get("local_flags") or []:
            flags.add("--" + f["name"])
        for f in node.get("persistent_flags") or []:
            flags.add("--" + f["name"])
            inherited.add("--" + f["name"])
        flags |= inherited
        use = node.get("use") or ""
        out[node["full_name"]] = CommandSpec(
            flags=flags,
            has_positionals=("<" in use or "[" in use or " -- " in use),
        )
        for sub in node.get("subcommands") or []:
            walk(sub, inherited)

    walk(tree)
    return out


def _children(commands: dict[str, CommandSpec]) -> dict[str, set[str]]:
    child: dict[str, set[str]] = {k: set() for k in commands}
    for key in commands:
        parts = key.split()
        for i in range(1, len(parts)):
            parent = " ".join(parts[:i])
            child.setdefault(parent, set()).add(parts[i])
    return child


def bash_blocks(text: str) -> Iterable[str]:
    for m in re.finditer(r"```bash\n(.*?)```", text, re.S):
        yield m.group(1)


def _logical_lines(block: str) -> Iterable[str]:
    current = ""
    for raw in block.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "#" in line:
            line = line.split("#", 1)[0].rstrip()
        if line.endswith("\\"):
            current += line[:-1] + " "
            continue
        yield (current + line).strip()
        current = ""
    if current.strip():
        yield current.strip()


def check_cli_examples(path: Path, text: str, commands: dict[str, CommandSpec]) -> list[Issue]:
    issues: list[Issue] = []
    children = _children(commands)
    for block in bash_blocks(text):
        for line in _logical_lines(block):
            if not (line.startswith("defenseclaw ") or line.startswith("defenseclaw-gateway ")):
                continue
            before = re.split(r"\s*(?:\||&&|;)\s*", line, maxsplit=1)[0]
            if re.search(r"\[(?:OPTIONS|flags|--[A-Za-z0-9-]+|<[^>]+>)\]", before):
                continue
            try:
                parts = shlex.split(before)
            except ValueError:
                parts = before.split()
            if not parts:
                continue
            cmd = [parts[0]]
            i = 1
            unsupported_subcommand: str | None = None
            while i < len(parts):
                tok = parts[i]
                if tok.startswith("-") or tok.startswith("$"):
                    break
                key = " ".join(cmd)
                if tok in children.get(key, set()):
                    cmd.append(tok)
                    i += 1
                    continue
                if children.get(key) and not commands[key].has_positionals:
                    unsupported_subcommand = f"{key} {tok}"
                break
            if unsupported_subcommand:
                issues.append(Issue(path, f"unsupported CLI command in example: {unsupported_subcommand}"))
                continue
            key = " ".join(cmd)
            if key not in commands:
                issues.append(Issue(path, f"unsupported CLI command in example: {key}"))
                continue
            for tok in parts:
                if tok.startswith("--"):
                    flag = tok.split("=", 1)[0]
                    if flag not in commands[key].flags:
                        issues.append(Issue(path, f"unsupported flag {flag} on `{key}`"))
    return issues


def route_set() -> set[str]:
    routes: set[str] = set()
    for rel in ("internal/gateway/api.go", "internal/gateway/proxy.go"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        routes.update(re.findall(r'mux\.HandleFunc\("([^"]+)"', text))
    return routes


def check_routes(path: Path, text: str, routes: set[str]) -> list[Issue]:
    issues: list[Issue] = []
    body = strip_fences(text)
    for m in re.finditer(r"(?<![`A-Za-z0-9])((?:/api)?/v1/[A-Za-z0-9_./:-]+|/(?:health|status|alerts|policy/reload|config/patch|skills|mcps|tools/catalog)\b)", body):
        route = m.group(1).rstrip(".,)")
        norm = route.split("?", 1)[0]
        norm = re.sub(r":[^/]+", "", norm).rstrip("/")
        if norm and norm not in routes and route not in routes:
            issues.append(Issue(path, f"documented HTTP route not registered: {route}"))
    return issues


def make_targets() -> set[str]:
    text = (ROOT / "Makefile").read_text(encoding="utf-8")
    return {m.group(1) for m in re.finditer(r"^([A-Za-z0-9_.-]+):(?:\s|$)", text, re.M)}


def check_make_examples(path: Path, text: str, targets: set[str]) -> list[Issue]:
    issues: list[Issue] = []
    for block in bash_blocks(text):
        for line in _logical_lines(block):
            if line.startswith("make "):
                parts = line.split()
                if len(parts) > 1 and "=" not in parts[1] and parts[1] not in targets:
                    issues.append(Issue(path, f"documented Make target not found: {parts[1]}"))
    return issues


def run() -> int:
    issues: list[Issue] = []
    py_cmds = click_commands()
    go_cmds = cobra_commands()
    commands = {**py_cmds, **go_cmds}
    routes = route_set()
    targets = make_targets()
    for path in mdx_files():
        text = path.read_text(encoding="utf-8")
        issues.extend(check_frontmatter(path, text))
        issues.extend(check_code_fences(path, text))
        issues.extend(check_components(path, text))
        issues.extend(check_generated_from(path, text))
        issues.extend(check_pinned(path, text))
        issues.extend(check_cli_examples(path, text, commands))
        issues.extend(check_routes(path, text, routes))
        issues.extend(check_make_examples(path, text, targets))
    if issues:
        for issue in issues:
            print(issue)
        print(f"\ndocs-verify failed: {len(issues)} issue(s)", file=sys.stderr)
        return 1
    print(f"docs-verify: OK ({len(mdx_files())} MDX files)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.parse_args()
    os.chdir(ROOT)
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
