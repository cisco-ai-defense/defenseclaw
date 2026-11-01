# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""GAP-2632 residual: acp remove takes out the empty editor lock enterprise ACP setup keeps."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner
from defenseclaw.commands import cmd_acp
from defenseclaw.commands.cmd_acp import acp_cmd

from tests.helpers import cleanup_app, make_app_context


def _settings(monkeypatch, tmp_path: Path) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "AppData" / "Roaming"))
    if os.name == "nt":
        path = tmp_path / "AppData" / "Roaming" / "Zed" / "settings.json"
    else:
        path = tmp_path / ".config" / "zed" / "settings.json"
    path.parent.mkdir(parents=True)
    path.write_text('{"theme": "mine"}\n')
    return path


def test_remove_takes_out_an_empty_editor_lock_left_after_the_entry(tmp_path, monkeypatch):
    settings = _settings(monkeypatch, tmp_path)
    lock = Path(str(settings) + ".defenseclaw.lock")
    lock.write_bytes(b"")
    data = tmp_path / "data"
    data.mkdir()
    app, data_dir, db_path = make_app_context(str(data))
    try:
        result = CliRunner().invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
        assert result.exit_code == 0, result.output
        assert "Removed the empty DefenseClaw editor lock" in result.output
        assert not lock.exists()
        assert settings.read_text() == '{"theme": "mine"}\n'
    finally:
        cleanup_app(app, db_path, data_dir)


def test_editor_lock_with_content_or_a_remaining_entry_stays(tmp_path, monkeypatch):
    settings = _settings(monkeypatch, tmp_path)
    lock = Path(str(settings) + ".defenseclaw.lock")
    lock.write_bytes(b"x")
    assert not cmd_acp._remove_editor_setup_lock("zed", str(tmp_path / "data"))
    assert lock.exists()
    lock.write_bytes(b"")
    with patch.object(cmd_acp, "_managed_pairs", return_value={("zed", "kiro")}):
        assert not cmd_acp._remove_editor_setup_lock("zed", str(tmp_path / "data"))
    assert lock.exists()
