# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Doctor rows for what a rollback leaves in the agent settings (1.0.2)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from defenseclaw.commands import cmd_doctor
from defenseclaw.commands.cmd_doctor import _DoctorResult

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX hook scripts")


def _settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, data_dir: Path) -> Path:
    claude = tmp_path / "claude"
    claude.mkdir()
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(claude))
    script = data_dir / "hooks" / "claude-code-hook.sh"
    settings = {
        "hooks": {
            "UserPromptSubmit": [
                {"hooks": [{"type": "command", "command": f"{script} || {{ rc=$?; exit 2; }}"}]},
                {"hooks": [{"type": "command", "command": "/opt/operator/prompt-check.sh"}]},
            ]
        }
    }
    path = claude / "settings.json"
    path.write_text(json.dumps(settings), encoding="utf-8")
    return path


def _cfg(data_dir: Path, *active: str) -> SimpleNamespace:
    return SimpleNamespace(data_dir=str(data_dir), active_connectors=lambda: list(active))


def test_doctor_fails_on_hook_entries_of_a_connector_a_rollback_left(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # rel-1-0-1:GAP-0009: after a rollback Claude Code ran a DefenseClaw hook
    # script the restored data dir does not have and blocked every prompt.
    data_dir = tmp_path / "dc"
    path = _settings(tmp_path, monkeypatch, data_dir)
    r = _DoctorResult()

    cmd_doctor._check_orphaned_hook_entries(_cfg(data_dir, "codex"), "codex", r)

    (check,) = r.checks
    assert check["status"] == "fail" and check["label"] == "Orphaned hook entries [claudecode]"
    assert f"{path} has DefenseClaw hook entries for claudecode, which is not configured" in check["detail"]
    assert "does not exist" in check["detail"]
    assert check["remediation"] == "defenseclaw setup remove claudecode"


def test_doctor_names_entries_of_an_unconfigured_connector_whose_script_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_dir = tmp_path / "dc"
    _settings(tmp_path, monkeypatch, data_dir)
    (data_dir / "hooks").mkdir(parents=True)
    (data_dir / "hooks" / "claude-code-hook.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    r = _DoctorResult()

    cmd_doctor._check_orphaned_hook_entries(_cfg(data_dir, "codex"), "codex", r)

    (check,) = r.checks
    assert check["status"] == "warn" and check["remediation"] == "defenseclaw setup remove claudecode"


def test_doctor_is_silent_for_a_configured_connector_and_for_other_installs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_dir = tmp_path / "dc"
    _settings(tmp_path, monkeypatch, data_dir)
    r = _DoctorResult()
    cmd_doctor._check_orphaned_hook_entries(_cfg(data_dir, "claudecode"), "claudecode", r)
    # Entries that run another data dir's scripts are not this install's.
    cmd_doctor._check_orphaned_hook_entries(_cfg(tmp_path / "other"), "", r)
    assert r.checks == []


def _opencode_plugin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, data_dir: Path) -> Path:
    """Write DefenseClaw's OpenCode plugin of *data_dir* next to an operator plugin."""
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    config = tmp_path / "opencode"
    monkeypatch.setenv("OPENCODE_CONFIG_DIR", str(config))
    plugins = config / "plugins"
    plugins.mkdir(parents=True)
    (plugins / "operator.js").write_text("export const Operator = async () => ({});\n", encoding="utf-8")
    token = data_dir / "hooks" / ".hook-opencode.token"
    path = plugins / "defenseclaw.js"
    path.write_text(
        "// defenseclaw-managed-plugin v7\n"
        'const DC_API_ADDR = "127.0.0.1:18970";\n'
        f"const DC_TOKEN_FILE = {json.dumps(str(token))};\n",
        encoding="utf-8",
    )
    return path


def test_doctor_fails_on_the_opencode_plugin_a_rollback_left(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # rel-1-0-2:GAP-0001 (rel-1-0-1:GAP-0009) for a plugin-file connector:
    # after a rollback OpenCode's plugin read a credential the restored data
    # dir does not have and refused every tool call.
    data_dir = tmp_path / "dc"
    path = _opencode_plugin(tmp_path, monkeypatch, data_dir)
    r = _DoctorResult()

    cmd_doctor._check_orphaned_hook_entries(_cfg(data_dir, "codex"), "codex", r)

    (check,) = r.checks
    assert check["status"] == "fail" and check["label"] == "Orphaned hook entries [opencode]"
    assert f"{path} is the DefenseClaw plugin of opencode, which is not configured" in check["detail"]
    assert f"{data_dir / 'hooks' / '.hook-opencode.token'}, which does not exist" in check["detail"]
    assert check["remediation"] == "defenseclaw setup remove opencode"


def test_doctor_warns_on_an_unconfigured_opencode_plugin_whose_credential_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_dir = tmp_path / "dc"
    _opencode_plugin(tmp_path, monkeypatch, data_dir)
    (data_dir / "hooks").mkdir(parents=True)
    (data_dir / "hooks" / ".hook-opencode.token").write_text("0" * 64 + "\n", encoding="utf-8")
    r = _DoctorResult()

    cmd_doctor._check_orphaned_hook_entries(_cfg(data_dir, "codex"), "codex", r)

    (check,) = r.checks
    assert check["status"] == "warn" and check["remediation"] == "defenseclaw setup remove opencode"


def test_doctor_is_silent_for_a_configured_foreign_or_operator_opencode_plugin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_dir = tmp_path / "dc"
    path = _opencode_plugin(tmp_path, monkeypatch, data_dir)
    r = _DoctorResult()
    cmd_doctor._check_orphaned_hook_entries(_cfg(data_dir, "opencode"), "opencode", r)
    # Another data dir's plugin is not this install's.
    cmd_doctor._check_orphaned_hook_entries(_cfg(tmp_path / "other"), "", r)
    # Without DefenseClaw's ownership marker first it is the operator's file.
    path.write_text("// my plugin\n" + path.read_text(encoding="utf-8"), encoding="utf-8")
    cmd_doctor._check_orphaned_hook_entries(_cfg(data_dir), "", r)
    assert r.checks == []
