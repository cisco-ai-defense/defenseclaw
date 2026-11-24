# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""GAP-1938: doctor names a codex app-server that is older than DefenseClaw's Codex token.

A `codex app-server` daemon started before a DefenseClaw reinstall keeps the
credentials it started with, so Codex answered 401 until that process was
killed by hand (vendor behaviour, same on 1.0.10). Lead ruling 07:50Z
(option B, owner confirm list): doctor warns, naming the PID, when it
started and the restart command. It never stops the process, and install
does not change.
"""

import os
from types import SimpleNamespace

from defenseclaw.commands import cmd_doctor
from defenseclaw.commands.cmd_doctor import _DoctorResult


def _cfg(tmp_path, token_age_s):
    hooks = tmp_path / "hooks"
    hooks.mkdir(parents=True, exist_ok=True)
    token = hooks / ".hook-codex.token"
    token.write_text("a" * 64)
    written = 1_800_000_000.0 - token_age_s
    os.utime(token, (written, written))
    return SimpleNamespace(data_dir=str(tmp_path)), written


def _rows(result):
    return [row for row in result.checks if "app-server" in (row.get("label", "") + row.get("detail", ""))]


def test_an_app_server_older_than_the_codex_token_is_named(tmp_path, monkeypatch):
    cfg, written = _cfg(tmp_path, 600)
    monkeypatch.setattr(cmd_doctor, "_codex_app_server_processes", lambda: [(1076, written - 3600), (2044, written + 60)], raising=False)
    result = _DoctorResult()
    cmd_doctor._check_codex_app_server_age(cfg, result)
    rows = _rows(result)
    assert len(rows) == 1, result.checks
    row = rows[0]
    assert row["status"] == "warn"
    assert "1076" in row["detail"] and "2044" not in row["detail"]
    assert "codex app-server daemon restart" in (row.get("remediation", "") + row["detail"])
    assert "401" in row["detail"]


def test_no_row_when_every_app_server_is_newer_or_none_runs(tmp_path, monkeypatch):
    cfg, written = _cfg(tmp_path, 600)
    for processes in ([], [(2044, written + 60)]):
        monkeypatch.setattr(cmd_doctor, "_codex_app_server_processes", lambda processes=processes: processes, raising=False)
        result = _DoctorResult()
        cmd_doctor._check_codex_app_server_age(cfg, result)
        assert not _rows(result), result.checks


def test_no_row_without_a_codex_token(tmp_path, monkeypatch):
    monkeypatch.setattr(cmd_doctor, "_codex_app_server_processes", lambda: [(1076, 1.0)], raising=False)
    result = _DoctorResult()
    cmd_doctor._check_codex_app_server_age(SimpleNamespace(data_dir=str(tmp_path)), result)
    assert not _rows(result)
