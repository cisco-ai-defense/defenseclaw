# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Optional live PTY smoke tests using coder/agent-tty."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]


def _agent_tty_enabled() -> bool:
    return os.environ.get("DEFENSECLAW_AGENT_TTY_TESTS") == "1"


def _agent_tty_command() -> list[str] | None:
    override = os.environ.get("DEFENSECLAW_AGENT_TTY_BIN")
    if override:
        return shlex.split(override)
    found = shutil.which("agent-tty")
    if found is None:
        return None
    return [found]


def _agent_tty(home: Path, *args: str) -> dict:
    if not args:
        raise AssertionError("agent-tty command is required")
    command = _agent_tty_command()
    if command is None:
        raise AssertionError("agent-tty is not installed")
    try:
        proc = subprocess.run(
            [*command, "--home", str(home), "--timeout-ms", "30000", args[0], "--json", *args[1:]],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=45,
        )
    except subprocess.TimeoutExpired as exc:
        raise AssertionError(f"agent-tty timed out while running {args[0]!r}") from exc
    if proc.returncode != 0:
        raise AssertionError(f"agent-tty failed: {proc.stderr or proc.stdout}")
    return json.loads(proc.stdout)


@pytest.mark.agent_tty
def test_agent_tty_launches_textual_backend_and_covers_core_workflows(tmp_path: Path) -> None:
    if not _agent_tty_enabled():
        pytest.skip("set DEFENSECLAW_AGENT_TTY_TESTS=1 to run live agent-tty smoke tests")
    if _agent_tty_command() is None:
        pytest.skip("agent-tty is not installed")

    home = tmp_path / "agent-tty"
    _agent_tty(home, "doctor")
    created = _agent_tty(home, "create", "--name", "defenseclaw-textual-smoke", "--", "/bin/bash")
    session_id = created["result"]["sessionId"]
    try:
        launch = f"cd {REPO_ROOT} && uv run defenseclaw tui --backend textual"
        _agent_tty(home, "run", session_id, launch, "--no-wait")
        _agent_tty(home, "wait", session_id, "--text", "Enterprise AI Governance")

        _agent_tty(home, "send-keys", session_id, "q")
        _agent_tty(home, "wait", session_id, "--text", "q is local close/no-op")
        snapshot = _agent_tty(home, "snapshot", session_id, "--format", "text")
        assert "q is local close/no-op" in snapshot["result"]["text"]

        _agent_tty(home, "send-keys", session_id, "2")
        _agent_tty(home, "wait", session_id, "--text", "Alerts")
        _agent_tty(home, "send-keys", session_id, "0")
        _agent_tty(home, "wait", session_id, "--text", "Setup Wizards")

        _agent_tty(home, "send-keys", session_id, ":")
        _agent_tty(home, "wait", session_id, "--text", "Category")
        _agent_tty(home, "type", session_id, "block skill alpha")
        _agent_tty(home, "send-keys", session_id, "Enter")
        _agent_tty(home, "wait", session_id, "--text", "Confirm Command")
        preview = _agent_tty(home, "snapshot", session_id, "--format", "text")
        assert "Origin" in preview["result"]["text"]
        assert "Risk" in preview["result"]["text"]
        assert "Restart" in preview["result"]["text"]
        _agent_tty(home, "send-keys", session_id, "Escape")
        _agent_tty(home, "wait", session_id, "--text", "Command cancelled")

        _agent_tty(home, "send-keys", session_id, "a")
        _agent_tty(home, "wait", session_id, "--text", "No commands run yet")
        _agent_tty(home, "send-keys", session_id, ":")
        _agent_tty(home, "wait", session_id, "--text", "Category")
        _agent_tty(home, "type", session_id, "defenseclaw version")
        _agent_tty(home, "send-keys", session_id, "Enter")
        _agent_tty(home, "wait", session_id, "--text", "exit ")

        _agent_tty(home, "send-keys", session_id, ":")
        _agent_tty(home, "wait", session_id, "--text", "Category")
        _agent_tty(home, "type", session_id, "defenseclaw doctor | cat")
        _agent_tty(home, "send-keys", session_id, "Enter")
        _agent_tty(home, "wait", session_id, "--text", "Shell operators are not allowed")

        snapshot = _agent_tty(home, "snapshot", session_id, "--format", "text")
        assert "Activity" in snapshot["result"]["text"]
        assert "Shell operators are not allowed" in snapshot["result"]["text"]
    finally:
        _agent_tty(home, "destroy", session_id)
