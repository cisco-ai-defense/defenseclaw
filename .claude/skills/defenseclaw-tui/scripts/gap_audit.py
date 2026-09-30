#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Show which CLI commands the TUI can reach, and which it can't.

Walks the Click tree under ``defenseclaw.main:cli`` and prints one row per
command path with three checks:

  palette  a command-palette row (``tui/registry_data.py`` GO_PARITY_REGISTRY)
           whose argv starts with this path
  tui      the path appears as a literal argv (tuple/list of strings, or a
           ``"defenseclaw ..."`` string) anywhere else in ``cli/defenseclaw/tui``
           (Setup WIZARD_COMMANDS, panel intents, follow-ups ...)
  json     the command has ``--json`` or ``-o/--output``/``--format`` so the TUI
           can load it quietly (``_communicate_captured`` + ``model.apply_json``)

The ``tui`` check is a static literal scan: argv built from variables at run
time is not seen, so treat a missing mark as "go and look", not as proof.

Examples (repository root, repo venv):

    .venv/bin/python .claude/skills/defenseclaw-tui/scripts/gap_audit.py
    .venv/bin/python .claude/skills/defenseclaw-tui/scripts/gap_audit.py --missing-only
    .venv/bin/python .claude/skills/defenseclaw-tui/scripts/gap_audit.py --prefix policy --groups
"""

from __future__ import annotations

import argparse
import ast
import sys
from collections.abc import Iterator
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
TUI_DIR = REPO_ROOT / "cli" / "defenseclaw" / "tui"
sys.path.insert(0, str(REPO_ROOT / "cli"))

JSON_OPTIONS = {"--json", "--output", "-o", "--format"}


def walk(group, prefix: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], object, bool]]:
    """Yield (path, command, is_group) for every command below ``group``."""

    import click

    for name in sorted(group.commands):
        command = group.commands[name]
        if getattr(command, "hidden", False):
            continue
        path = (*prefix, name)
        is_group = isinstance(command, click.Group)
        yield path, command, is_group
        if is_group:
            yield from walk(command, path)


def has_json(command) -> bool:
    for param in getattr(command, "params", ()):
        if set(getattr(param, "opts", ())) & JSON_OPTIONS:
            return True
    return False


def _leading_strings(node: ast.AST) -> tuple[str, ...]:
    """Leading string constants of a tuple/list literal, stopping at the first non-string."""

    out: list[str] = []
    for element in getattr(node, "elts", ()):
        if isinstance(element, ast.Constant) and isinstance(element.value, str):
            out.append(element.value)
        else:
            break
    return tuple(out)


def tui_literal_argvs(skip: set[Path]) -> set[tuple[str, ...]]:
    """Every literal argv-looking string sequence in the TUI source."""

    found: set[tuple[str, ...]] = set()
    for path in sorted(TUI_DIR.rglob("*.py")):
        if path in skip:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            words: tuple[str, ...] = ()
            if isinstance(node, (ast.Tuple, ast.List)):
                words = _leading_strings(node)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                if node.value.startswith("defenseclaw "):
                    words = tuple(node.value.split())
            if words and words[0] == "defenseclaw":
                words = words[1:]
            words = tuple(w for w in words if not w.startswith("-"))
            if words:
                found.add(words)
    return found


def covered(path: tuple[str, ...], argvs: set[tuple[str, ...]]) -> bool:
    return any(argv[: len(path)] == path for argv in argvs)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--missing-only", action="store_true", help="only rows with no palette row and no TUI argv")
    parser.add_argument("--groups", action="store_true", help="include group rows (default: leaf commands only)")
    parser.add_argument(
        "--prefix", default="", help='only paths starting with this, e.g. "policy" or "setup guardrail"'
    )
    args = parser.parse_args(argv)

    from defenseclaw.main import cli
    from defenseclaw.tui.registry_data import GO_PARITY_REGISTRY

    palette = {
        tuple(w for w in row[2] if not w.startswith("-")) for row in GO_PARITY_REGISTRY if row[1] == "defenseclaw"
    }
    literals = tui_literal_argvs(skip={TUI_DIR / "registry_data.py"})
    want = tuple(args.prefix.split())

    rows = []
    for path, command, is_group in walk(cli):
        if is_group and not args.groups:
            continue
        if want and path[: len(want)] != want:
            continue
        rows.append((" ".join(path), covered(path, palette), covered(path, literals), has_json(command)))

    shown = [r for r in rows if not (args.missing_only and (r[1] or r[2]))]
    width = max((len(r[0]) for r in shown), default=10)
    mark = {True: "yes", False: "-"}
    print(f"{'command':<{width}}  palette  tui  json")
    for name, in_palette, in_tui, json_ in shown:
        print(f"{name:<{width}}  {mark[in_palette]:<7}  {mark[in_tui]:<3}  {mark[json_]}")

    total = len(rows)
    print()
    print(
        f"{total} commands: palette {sum(r[1] for r in rows)}, tui argv {sum(r[2] for r in rows)}, "
        f"json {sum(r[3] for r in rows)}, unreachable (no palette, no tui) {sum(not (r[1] or r[2]) for r in rows)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
