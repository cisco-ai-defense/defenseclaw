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

"""Run the fake-data DefenseClaw TUI interactively, for tmux and manual checks.

Same hermetic app as render.py (``cli/tests/tui/fixtures.py``, no host
discovery, no sandbox doctor), but it runs for real in your terminal so you can
press keys and click. HOME, DEFENSECLAW_HOME, CLAUDE_CONFIG_DIR and CODEX_HOME
all point into a fresh ``mktemp`` directory, so nothing touches your real
configs.

By default confirmed commands do NOT run: a fake executor prints the argv it
would have run (secrets fed over stdin show only as ``<stdin: N chars>``) and
exits 0, so follow-ups and refreshes still fire. ``--real-exec`` runs the real
CLI inside the scratch home instead.

Examples (repository root, repo venv):

    .venv/bin/python .claude/skills/defenseclaw-tui/scripts/demo.py
    .venv/bin/python .claude/skills/defenseclaw-tui/scripts/demo.py --panel setup
    .venv/bin/python .claude/skills/defenseclaw-tui/scripts/demo.py --first-run
    tmux new-session -d -s dc-tui -x 80 -y 24 \\
        '.venv/bin/python .claude/skills/defenseclaw-tui/scripts/demo.py --panel setup'
    tmux send-keys -t dc-tui Enter; tmux capture-pane -t dc-tui -p
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import render  # noqa: E402  (sets up sys.path for cli/ and cli/tests/tui)


def _isolate_home(root: Path) -> None:
    for var, sub in (
        ("HOME", "home"),
        ("DEFENSECLAW_HOME", "home/.defenseclaw"),
        ("CLAUDE_CONFIG_DIR", "home/.claude"),
        ("CODEX_HOME", "home/.codex"),
    ):
        path = root / sub
        path.mkdir(parents=True, exist_ok=True)
        os.environ[var] = str(path)
    if sys.platform == "win32":
        os.environ["USERPROFILE"] = os.environ["HOME"]


def _install_fake_executor(app) -> None:
    from defenseclaw.tui.executor import CommandEvent

    async def fake_run(binary, args, *, stdin_input=None, env_overrides=None):
        started = time.monotonic()
        argv = " ".join((binary, *args))
        yield CommandEvent("start", argv)
        yield CommandEvent("output", f"demo: would run: {argv}")
        if stdin_input is not None:
            yield CommandEvent("output", f"demo: <stdin: {len(stdin_input)} chars>")
        if env_overrides:
            yield CommandEvent("output", f"demo: env overrides: {', '.join(sorted(env_overrides))}")
        yield CommandEvent("done", exit_code=0, duration=time.monotonic() - started)

    app.executor.run = fake_run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--panel", help="switch to this panel first (render.py --list-panels)")
    parser.add_argument("--first-run", action="store_true", help="start in the no-config first-run setup")
    parser.add_argument(
        "--setup-config",
        choices=("default", "empty"),
        default="default",
        help="Setup panel config: a full default config (default) or an empty one",
    )
    parser.add_argument(
        "--keep-home",
        action="store_true",
        help="keep the scratch home after exit (to inspect what --real-exec wrote)",
    )
    parser.add_argument(
        "--real-exec",
        action="store_true",
        help="run confirmed commands for real (inside the scratch home) instead of echoing them",
    )
    args = parser.parse_args(argv)

    root = Path(tempfile.mkdtemp(prefix="dc-tui-demo-"))
    _isolate_home(root)
    render._stub_host_probes()

    app = render._build_app(args, root)
    if not args.real_exec:
        _install_fake_executor(app)
    if args.panel:
        app.call_after_refresh(app.action_switch_panel, args.panel)
    try:
        app.run()
    finally:
        if args.keep_home:
            print(f"scratch home kept: {root}")
        else:
            shutil.rmtree(root, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
