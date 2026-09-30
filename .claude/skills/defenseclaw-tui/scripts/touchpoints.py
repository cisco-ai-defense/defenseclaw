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

"""List the per-panel if-chains a panel has to be wired into, and which ones it is.

Every panel renders into one shared surface, so adding or changing a panel
means touching a fixed set of functions in ``app.py`` (and ``hint_bar.py``).
This script finds each of them by name (AST, not line numbers) and reports
whether it mentions the panel:

  literal  the panel name or stem as a string (``"sandboxes"``, CLI command
           ``"sandbox"``) or a ``"sandboxes-..."`` button/control id
  ident    only an identifier containing the panel stem (``self.sandbox_model``)
  -        not wired

Examples (repository root, repo venv):

    .venv/bin/python .claude/skills/defenseclaw-tui/scripts/touchpoints.py sandboxes
    .venv/bin/python .claude/skills/defenseclaw-tui/scripts/touchpoints.py policies --stem policy
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
TUI_DIR = REPO_ROOT / "cli" / "defenseclaw" / "tui"

# (file relative to tui/, function or module-level name, what the touchpoint is for)
TOUCHPOINTS: tuple[tuple[str, str, str], ...] = (
    ("app.py", "PANELS", "tab, Ctrl+P jumper, hotkey, badge row"),
    ("app.py", "compose", 'button bar Horizontal(id="<panel>-controls")'),
    ("app.py", "_body_text", "body text + table columns/rows (pure, 2 s re-render)"),
    ("app.py", "_handle_active_panel_key", "panel key routing -> model.handle_key"),
    ("app.py", "_on_table_row_highlighted", "table cursor -> model cursor"),
    ("app.py", "_on_table_row_selected", "Enter/click on a row"),
    ("app.py", "_active_table_cursor", "cursor restore after re-render"),
    ("app.py", "_render_panel_control_visibility", "show/hide the panel's button bar"),
    ("app.py", "_render_panel_controls", "per-view button visibility (_sync_<panel>_controls)"),
    ("app.py", "_on_panel_control_pressed", "button id -> handler"),
    ("app.py", "_detail_text", "#detail-panel text for the selected row"),
    ("app.py", "action_switch_panel", "load/poll on first open"),
    ("app.py", "_panel_total_count", "tab badge count"),
    ("app.py", "_apply_config_snapshot", "config reload -> model.set_config"),
    ("app.py", "_handle_successful_command", "refresh after a successful CLI intent"),
    ("app.py", "_help_sections", "? overlay key sheet"),
    ("app.py", "_refresh_hint", "HintState.panel_view for per-view hints"),
    ("widgets/hint_bar.py", "hint_for", "HintEngine hint line"),
)


def _index(path: Path) -> dict[str, ast.AST]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            found.setdefault(node.name, node)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    found.setdefault(target.id, node)
    return found


def _evidence(node: ast.AST, panel: str, stems: tuple[str, ...]) -> tuple[str, int | None]:
    ident_line = None
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            value = child.value
            if value == panel or value in stems or value.startswith(f"{panel}-"):
                return "literal", child.lineno
        name = ""
        if isinstance(child, ast.Attribute):
            name = child.attr
        elif isinstance(child, ast.Name):
            name = child.id
        if name and ident_line is None and any(stem in name.lower() for stem in stems):
            ident_line = child.lineno
    if ident_line is not None:
        return "ident", ident_line
    return "-", None


def _stems(panel: str, extra: list[str]) -> tuple[str, ...]:
    stems = {panel, *extra}
    if panel.endswith("ies"):
        stems.add(panel[:-3] + "y")
    elif panel.endswith("es"):
        stems.add(panel[:-2])
    elif panel.endswith("s"):
        stems.add(panel[:-1])
    return tuple(sorted(s.lower() for s in stems if len(s) >= 3))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("panel", help="panel name as used in PANELS, e.g. sandboxes")
    parser.add_argument("--stem", action="append", default=[], help="extra identifier stem, e.g. policy")
    args = parser.parse_args(argv)

    stems = _stems(args.panel, args.stem)
    indexes: dict[str, dict[str, ast.AST]] = {}
    wired = 0
    rows = []
    for rel, name, purpose in TOUCHPOINTS:
        index = indexes.setdefault(rel, _index(TUI_DIR / rel))
        node = index.get(name)
        if node is None:
            rows.append(("?", f"{rel}:{name}", "(not found - renamed?)", purpose))
            continue
        kind, line = _evidence(node, args.panel, stems)
        wired += kind != "-"
        where = f"{rel}:{line}" if line else rel
        rows.append((kind, name, where, purpose))

    print(f"panel {args.panel!r} (identifier stems: {', '.join(stems)})")
    print(f"{'mark':<7}  {'touchpoint':<34}  {'where':<26}  purpose")
    for kind, name, where, purpose in rows:
        print(f"{kind:<7}  {name:<34}  {where:<26}  {purpose}")

    print()
    files = sorted(
        str(p.relative_to(TUI_DIR))
        for p in TUI_DIR.rglob("*.py")
        if any(stem in p.stem.lower() for stem in stems if stem != args.panel) or p.stem == args.panel
    )
    print(
        "panel files:", ", ".join(files) if files else "(none yet: model in services/<x>_state.py, mixin <x>_panel.py)"
    )
    print(f"{wired}/{len(TOUCHPOINTS)} touchpoints mention {args.panel!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
