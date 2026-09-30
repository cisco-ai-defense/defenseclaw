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

"""Print what the DefenseClaw TUI shows, as plain text, without a terminal.

Builds the fake-data app from ``cli/tests/tui/fixtures.py`` (nothing reads the
real home, gateway or SQLite), presses keys, and dumps the screen at each size.

Examples (run from the repository root with the repo's venv):

    .venv/bin/python .claude/skills/defenseclaw-tui/scripts/render.py --panel setup
    .venv/bin/python .claude/skills/defenseclaw-tui/scripts/render.py --keys 0 enter enter
    .venv/bin/python .claude/skills/defenseclaw-tui/scripts/render.py --size 80x24 --keys 0 c
    .venv/bin/python .claude/skills/defenseclaw-tui/scripts/render.py --keys : "text:policy list" enter
    .venv/bin/python .claude/skills/defenseclaw-tui/scripts/render.py --first-run
    .venv/bin/python .claude/skills/defenseclaw-tui/scripts/render.py --panel setup --size 80x24 --expect Setup
    .venv/bin/python .claude/skills/defenseclaw-tui/scripts/render.py --panel alerts --svg /tmp/alerts.svg

Keys use Textual names (``enter``, ``escape``, ``tab``, ``ctrl+p``, ``down``).
``text:<string>`` types each character of the string.

``--expect TEXT`` (repeatable) exits 1 when TEXT is missing from any rendered
size. ``--svg PATH`` also writes an SVG screenshot per size (``PATH`` gets a
``-80x24`` style suffix when more than one size is rendered).
"""

from __future__ import annotations

import argparse
import asyncio
import os
import shutil
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path[:0] = [str(REPO_ROOT / "cli"), str(REPO_ROOT / "cli" / "tests" / "tui")]


def _parse_size(value: str) -> tuple[int, int]:
    try:
        width, height = value.lower().split("x", 1)
        return int(width), int(height)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"size must look like 80x24, got {value!r}") from exc


def _stub_host_probes() -> None:
    """Keep renders hermetic: no agent discovery scan, no sandbox doctor."""

    from defenseclaw.inventory import agent_discovery

    empty = agent_discovery.AgentDiscovery(scanned_at="render", agents={}, cache_hit=True)
    agent_discovery.discover_agents = lambda *args, **kwargs: empty
    try:
        from defenseclaw.tui import sandbox_panel
        from defenseclaw.tui.panels.setup import sandbox_machine_check
    except ImportError:
        return
    sandbox_panel.probe_sandbox_machine = lambda: sandbox_machine_check(None, "not probed in renders")


def _build_app(args: argparse.Namespace, home: Path):
    from defenseclaw.tui.app import DefenseClawTUI

    if args.first_run:
        return DefenseClawTUI(first_run=True)

    import fixtures

    setup_config = None
    if args.setup_config == "default":
        from defenseclaw.config import default_config

        setup_config = default_config()
    app_home = Path(tempfile.mkdtemp(dir=home))
    return fixtures.snapshot_app(app_home, setup_config=setup_config)


def _svg_path(base: str, size: tuple[int, int], many: bool) -> Path:
    path = Path(base)
    if not many:
        return path
    return path.with_name(f"{path.stem}-{size[0]}x{size[1]}{path.suffix or '.svg'}")


async def _render(args: argparse.Namespace, size: tuple[int, int], home: Path, svg: Path | None = None) -> str:
    import fixtures

    app = _build_app(args, home)
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        if args.panel:
            app.action_switch_panel(args.panel)
            await pilot.pause()
        for key in args.keys:
            if key.startswith("text:"):
                await pilot.press(*key[len("text:") :])
            else:
                await pilot.press(key)
            await pilot.pause()
            await pilot.pause()
        await asyncio.sleep(args.wait)
        await pilot.pause()
        if svg is not None:
            svg.write_text(app.export_screenshot(), encoding="utf-8")
        return fixtures.screen_text(app)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--size",
        action="append",
        type=_parse_size,
        help="terminal size, repeatable (default: 80x24 and 120x40)",
    )
    parser.add_argument("--panel", help="switch to this panel first (see --list-panels)")
    parser.add_argument("--keys", nargs="*", default=[], help="keys to press, in order")
    parser.add_argument("--first-run", action="store_true", help="render the no-config first-run setup")
    parser.add_argument(
        "--setup-config",
        choices=("default", "empty"),
        default="default",
        help="Setup panel config: a full default config (default) or an empty one",
    )
    parser.add_argument("--wait", type=float, default=0.3, help="seconds to wait before the dump")
    parser.add_argument(
        "--expect",
        action="append",
        default=[],
        metavar="TEXT",
        help="exit 1 if TEXT is not on screen at every size (repeatable)",
    )
    parser.add_argument("--svg", metavar="PATH", help="also write an SVG screenshot (one per size)")
    parser.add_argument("--list-panels", action="store_true", help="print panel names and keys, then exit")
    args = parser.parse_args(argv)

    home = Path(tempfile.mkdtemp(prefix="dc-tui-render-"))
    try:
        return _main(args, home)
    finally:
        # Every run gets a fresh scratch home; don't leave them behind.
        shutil.rmtree(home, ignore_errors=True)


def _main(args: argparse.Namespace, home: Path) -> int:
    os.environ.setdefault("DEFENSECLAW_HOME", str(home))
    _stub_host_probes()

    if args.list_panels:
        from defenseclaw.tui.app import PANELS

        for name, key, label in PANELS:
            print(f"{key:>2}  {name:<12} {label}")
        return 0

    label = "first-run" if args.first_run else " ".join(filter(None, [args.panel or "", *args.keys])) or "start"
    sizes = args.size or [(80, 24), (120, 40)]
    missing: list[str] = []
    for size in sizes:
        svg = _svg_path(args.svg, size, len(sizes) > 1) if args.svg else None
        text = asyncio.run(_render(args, size, home, svg))
        print(f"===== {label} @ {size[0]}x{size[1]} =====")
        print(text.rstrip("\n"))
        print()
        if svg is not None:
            print(f"(svg written to {svg})")
        missing.extend(f"{size[0]}x{size[1]}: {want!r}" for want in args.expect if want not in text)
    if missing:
        print("EXPECT FAILED - not on screen:", *missing, sep="\n  ", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
