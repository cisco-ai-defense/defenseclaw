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

"""Python Textual TUI building blocks and launch entrypoint."""

from __future__ import annotations

import os
import subprocess
import sys

from defenseclaw.tui.models import CommandResult, HintState, ServiceStatus, StatusModel
from defenseclaw.tui.panels.first_run import decide_first_run_prompt, first_run_prompt_text
from defenseclaw.tui.theme import DEFAULT_TOKENS, TEXTUAL_CSS, ThemeTokens


def run_textual_tui() -> None:
    """Run the Python Textual TUI backend."""

    from defenseclaw import config
    from defenseclaw.tui.app import DefenseClawTUI

    try:
        cfg = config.load()
        first_run = False
    except Exception:
        cfg, first_run = _load_after_optional_first_run_prompt(config)
    DefenseClawTUI(config=cfg, first_run=first_run).run()


def _load_after_optional_first_run_prompt(config_module: object) -> tuple[object | None, bool]:
    """Run the canonical first-run wizard before falling back to embedded setup."""

    try:
        cfg_path = str(config_module.config_path())  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - prompt copy can fall back to the common path.
        cfg_path = "~/.defenseclaw/config.yaml"

    tty_ok = sys.stdin.isatty() and sys.stdout.isatty()
    skip = os.environ.get("DEFENSECLAW_TUI_SKIP_FIRST_RUN_PROMPT", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }
    answer: str | None = None
    if tty_ok and not skip:
        try:
            answer = input(first_run_prompt_text(cfg_path) + " ")
        except EOFError:
            tty_ok = False

    decision = decide_first_run_prompt(answer, skip=skip, tty_ok=tty_ok)
    if decision.message:
        print(decision.message, file=sys.stderr)
    if decision.outcome == "declined":
        return None, False
    if decision.should_spawn_init:
        try:
            result = subprocess.run(("defenseclaw", "init"), check=False)
        except OSError as exc:
            decision = decide_first_run_prompt(answer, skip=skip, tty_ok=tty_ok, spawn_error=exc)
            if decision.message:
                print(decision.message, file=sys.stderr)
            return None, True
        if result.returncode == 0:
            try:
                return config_module.load(), False  # type: ignore[attr-defined]
            except Exception as exc:  # noqa: BLE001 - embedded first-run remains the recovery path.
                print(f"defenseclaw init completed but config still could not load: {exc}", file=sys.stderr)
                return None, True
        print(f"defenseclaw init exited with {result.returncode}; opening embedded first-run setup.", file=sys.stderr)
        return None, True
    return None, True


__all__ = [
    "CommandResult",
    "DEFAULT_TOKENS",
    "HintState",
    "run_textual_tui",
    "ServiceStatus",
    "StatusModel",
    "TEXTUAL_CSS",
    "ThemeTokens",
]
