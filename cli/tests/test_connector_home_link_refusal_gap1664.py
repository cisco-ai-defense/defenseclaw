# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""GAP-1664: setup refuses a connector home variable that goes through a link on Windows."""

from __future__ import annotations

import os

import pytest
from defenseclaw.commands import cmd_setup
from defenseclaw.file_permissions import UnsafePathError


def _fake_reject(linked: str):
    def reject(path: str) -> None:
        if os.path.abspath(path).startswith(os.path.abspath(linked)):
            raise UnsafePathError(f"refusing sensitive write through reparse point: {linked}")

    return reject


@pytest.mark.parametrize(
    ("connector", "variable"),
    [("codex", "CODEX_HOME"), ("claudecode", "CLAUDE_CONFIG_DIR"), ("copilot", "COPILOT_HOME"),
     ("hermes", "HERMES_HOME"), ("opencode", "OPENCODE_CONFIG_DIR")],
)
def test_windows_setup_refuses_a_connector_home_through_a_junction(monkeypatch, tmp_path, connector, variable):
    junction = tmp_path / "fc166junc"
    monkeypatch.setattr(cmd_setup, "_host_is_windows", lambda: True)
    monkeypatch.setenv(variable, str(junction))
    monkeypatch.setattr(cmd_setup, "reject_reparse_path", _fake_reject(str(junction)))
    monkeypatch.setattr(cmd_setup, "_gateway_lifecycle_executable", lambda: "")
    refusal = cmd_setup._agent_settings_refusal(object(), connector)
    assert f"{variable}={os.path.abspath(str(junction))}" in refusal
    assert "symbolic link or junction" in refusal
    assert "Setup changed nothing" in refusal


def test_windows_setup_keeps_a_real_connector_home_and_an_unset_one(monkeypatch, tmp_path):
    monkeypatch.setattr(cmd_setup, "_host_is_windows", lambda: True)
    monkeypatch.setattr(cmd_setup, "reject_reparse_path", _fake_reject(str(tmp_path / "linked")))
    monkeypatch.setattr(cmd_setup, "_gateway_lifecycle_executable", lambda: "")
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "real"))
    assert cmd_setup._agent_settings_refusal(object(), "codex") == ""
    monkeypatch.delenv("CODEX_HOME")
    assert cmd_setup._agent_settings_refusal(object(), "codex") == ""
    # A connector without a home variable is not checked.
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "linked"))
    assert cmd_setup._agent_settings_refusal(object(), "cursor") == ""


def test_posix_setup_does_not_refuse_a_symlinked_system_folder(monkeypatch, tmp_path):
    monkeypatch.setattr(cmd_setup, "_host_is_windows", lambda: False)
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "linked"))
    monkeypatch.setattr(cmd_setup, "reject_reparse_path", _fake_reject(str(tmp_path / "linked")))
    monkeypatch.setattr(cmd_setup, "_gateway_lifecycle_executable", lambda: "")
    assert cmd_setup._agent_settings_refusal(object(), "codex") == ""
