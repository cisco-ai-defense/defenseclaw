# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-2632: uninstall removes the guarded ACP editor entries `acp setup` wrote and keeps the rest."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import patch

from click.testing import CliRunner
from defenseclaw.commands import cmd_acp, cmd_config, cmd_uninstall
from defenseclaw.config import CURRENT_CONFIG_VERSION

from tests.helpers import cleanup_app, make_app_context
from tests.test_cmd_acp import _binary, _isolate_client_config, _zed_settings


def test_uninstall_removes_the_acp_editor_entry_setup_wrote(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    data = tmp_path / "data"
    data.mkdir()
    app, data_dir, db_path = make_app_context(str(data))
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "opencode")
    try:
        with patch("defenseclaw.commands.cmd_acp._agent_version", return_value="v"):
            result = CliRunner().invoke(
                cmd_acp.acp_cmd,
                ["setup", "--client", "zed", "--agent", "opencode", "--guard-binary", guard, "--agent-binary", agent],
                obj=app,
            )
        assert result.exit_code == 0, result.output
        settings = _zed_settings(tmp_path)
        document = json.loads(settings.read_text())
        document["agent_servers"]["Foreign"] = {"command": "other"}
        settings.write_text(json.dumps(document))
        lock = cmd_acp._contract_lock_path(data_dir, "zed", "opencode")
        assert lock.is_file()

        entries = cmd_uninstall._acp_editor_entries(app.cfg, (data_dir,))
        assert entries == (("zed", "opencode", str(cmd_acp._client_path("zed"))),)
        cmd_uninstall._remove_acp_editor_entries(SimpleNamespace(record_dirs=(data_dir,), acp_entries=entries))

        assert json.loads(settings.read_text())["agent_servers"] == {"Foreign": {"command": "other"}}
        assert not lock.exists()
        assert cmd_uninstall._acp_editor_entries(app.cfg, (data_dir,)) == ()
        app.cfg.deployment_mode = "managed_enterprise"
        assert cmd_uninstall._acp_editor_entries(app.cfg, (data_dir,)) == ()
    finally:
        cleanup_app(app, db_path, data_dir)


def test_uninstall_finds_and_removes_the_acp_editor_entry_in_a_moved_data_dir(tmp_path, monkeypatch):
    # GAP-0874: config.yaml names another data_dir than the install home. The
    # ownership records and contract locks acp setup wrote are in that folder,
    # so the plan read the install home, found no entry and left it installed.
    _isolate_client_config(monkeypatch, tmp_path)
    store = tmp_path / "state"
    store.mkdir()
    home = tmp_path / ".defenseclaw"
    home.mkdir()
    (home / "config.yaml").write_text(f"data_dir: {store}\nguardrail:\n  connector: hermes\n")
    app, data_dir, db_path = make_app_context(str(store))
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "opencode")
    try:
        with patch("defenseclaw.commands.cmd_acp._agent_version", return_value="v"):
            result = CliRunner().invoke(
                cmd_acp.acp_cmd,
                ["setup", "--client", "zed", "--agent", "opencode", "--guard-binary", guard, "--agent-binary", agent],
                obj=app,
            )
        assert result.exit_code == 0, result.output
        settings = _zed_settings(tmp_path)
        document = json.loads(settings.read_text())
        document["agent_servers"]["Foreign"] = {"command": "other"}
        settings.write_text(json.dumps(document))
        lock = cmd_acp._contract_lock_path(data_dir, "zed", "opencode")
        assert lock.is_file()

        with patch("defenseclaw.commands.cmd_uninstall.config_module.default_data_path", return_value=str(home)):
            plan = cmd_uninstall._build_plan(wipe_data=False, binaries=False, revert_openclaw=True, remove_plugin=True)
        assert plan.data_dir == str(home)
        assert plan.acp_entries == (("zed", "opencode", str(cmd_acp._client_path("zed"))),)
        cmd_uninstall._remove_acp_editor_entries(plan)

        assert json.loads(settings.read_text())["agent_servers"] == {"Foreign": {"command": "other"}}
        assert not lock.exists()
        with patch("defenseclaw.commands.cmd_uninstall.config_module.default_data_path", return_value=str(home)):
            again = cmd_uninstall._build_plan(wipe_data=False, binaries=False, revert_openclaw=True, remove_plugin=True)
        assert again.acp_entries == ()
    finally:
        cleanup_app(app, db_path, data_dir)


def test_uninstall_removes_the_acp_editor_entry_written_before_data_dir_moved(tmp_path, monkeypatch):
    # GAP-0874 review: `config set data_dir` leaves the ACP ownership record and
    # contract lock in the folder setup wrote them in. The plan reads the new
    # folder and that one, so an entry set up before the move is still removed
    # and an entry a foreign tool wrote stays.
    _isolate_client_config(monkeypatch, tmp_path)
    home = tmp_path / ".defenseclaw"
    home.mkdir()
    store = tmp_path / "state"
    store.mkdir()
    (home / "config.yaml").write_text(f"data_dir: {home}\nguardrail:\n  connector: hermes\n")
    app, data_dir, db_path = make_app_context(str(home))
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "opencode")
    try:
        with patch("defenseclaw.commands.cmd_acp._agent_version", return_value="v"):
            result = CliRunner().invoke(
                cmd_acp.acp_cmd,
                ["setup", "--client", "zed", "--agent", "opencode", "--guard-binary", guard, "--agent-binary", agent],
                obj=app,
            )
        assert result.exit_code == 0, result.output
        settings = _zed_settings(tmp_path)
        document = json.loads(settings.read_text())
        document["agent_servers"]["Foreign"] = {"command": "other"}
        settings.write_text(json.dumps(document))
        lock = cmd_acp._contract_lock_path(str(home), "zed", "opencode")
        assert lock.is_file()

        result = CliRunner().invoke(cmd_config.config_cmd, ["set", "data_dir", str(store)], obj=app)
        assert result.exit_code == 0, result.output
        assert not cmd_acp._owned_entry_records(str(store))

        with patch("defenseclaw.commands.cmd_uninstall.config_module.default_data_path", return_value=str(home)):
            plan = cmd_uninstall._build_plan(wipe_data=False, binaries=False, revert_openclaw=True, remove_plugin=True)
        assert plan.record_dirs == (str(store), str(home))
        assert plan.acp_entries == (("zed", "opencode", str(cmd_acp._client_path("zed"))),)
        cmd_uninstall._remove_acp_editor_entries(plan)

        assert json.loads(settings.read_text())["agent_servers"] == {"Foreign": {"command": "other"}}
        assert not lock.exists()
        assert not cmd_acp._owned_entry_records(str(home))
    finally:
        cleanup_app(app, db_path, data_dir)


def _setup_zed_opencode(app, tmp_path):
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "opencode")
    with patch("defenseclaw.commands.cmd_acp._agent_version", return_value="v"):
        result = CliRunner().invoke(
            cmd_acp.acp_cmd,
            ["setup", "--client", "zed", "--agent", "opencode", "--guard-binary", guard, "--agent-binary", agent],
            obj=app,
        )
    assert result.exit_code == 0, result.output


def _two_data_dir_moves(tmp_path, monkeypatch):
    """Install home, then setup in a first store, then a second move: the records stay in the first store.

    The list of earlier folders is only written by an unelevated account (an elevated process leaves no
    list for the user to read), and the Windows CI runner is elevated, so the move runs as the user.
    """
    monkeypatch.setattr(cmd_config.config_module, "_is_admin_process", lambda: False)
    home = tmp_path / ".defenseclaw"
    home.mkdir()
    first = tmp_path / "state-one"
    first.mkdir()
    second = tmp_path / "state-two"
    second.mkdir()
    (home / "config.yaml").write_text(
        f"config_version: {CURRENT_CONFIG_VERSION}\ndata_dir: {home}\nguardrail:\n  connector: hermes\n"
    )
    app_home, _, _ = make_app_context(str(home))
    app_first = None
    try:
        result = CliRunner().invoke(cmd_config.config_cmd, ["set", "data_dir", str(first)], obj=app_home)
        assert result.exit_code == 0, result.output
        app_first, first_dir, _ = make_app_context(str(first))
        _setup_zed_opencode(app_first, tmp_path)
        lock = cmd_acp._contract_lock_path(first_dir, "zed", "opencode")
        assert lock.is_file()
        result = CliRunner().invoke(cmd_config.config_cmd, ["set", "data_dir", str(second)], obj=app_first)
        assert result.exit_code == 0, result.output
    finally:
        app_home.store.close()
        if app_first is not None:
            app_first.store.close()
    return home, first, second, lock


def test_uninstall_removes_the_acp_editor_entry_written_two_data_dir_moves_ago(tmp_path, monkeypatch):
    # GAP-0874 review 3: the records of a setup stay in the folder it ran in, so a
    # second `config set data_dir` leaves them in a folder that is neither the
    # current one nor the install home. The install home lists that folder.
    _isolate_client_config(monkeypatch, tmp_path)
    home, first, second, lock = _two_data_dir_moves(tmp_path, monkeypatch)
    settings = _zed_settings(tmp_path)
    document = json.loads(settings.read_text())
    document["agent_servers"]["Foreign"] = {"command": "other"}
    settings.write_text(json.dumps(document))

    with patch("defenseclaw.commands.cmd_uninstall.config_module.default_data_path", return_value=str(home)):
        plan = cmd_uninstall._build_plan(wipe_data=False, binaries=False, revert_openclaw=True, remove_plugin=True)
    assert plan.record_dirs == (str(second), str(first), str(home))
    assert plan.acp_entries == (("zed", "opencode", str(cmd_acp._client_path("zed"))),)
    cmd_uninstall._remove_acp_editor_entries(plan)

    assert json.loads(settings.read_text())["agent_servers"] == {"Foreign": {"command": "other"}}
    assert not lock.exists()
    assert not cmd_acp._owned_entry_records(str(first))


def test_uninstall_keeps_an_edited_acp_editor_entry_in_an_earlier_data_dir(tmp_path, monkeypatch):
    # The list of earlier folders only says where to look: the ownership proof in
    # that folder still decides, so an entry the user changed stays.
    _isolate_client_config(monkeypatch, tmp_path)
    home, first, _second, lock = _two_data_dir_moves(tmp_path, monkeypatch)
    settings = _zed_settings(tmp_path)
    document = json.loads(settings.read_text())
    (name,) = document["agent_servers"]
    document["agent_servers"][name]["command"] = "edited-by-the-user"
    settings.write_text(json.dumps(document))

    with patch("defenseclaw.commands.cmd_uninstall.config_module.default_data_path", return_value=str(home)):
        plan = cmd_uninstall._build_plan(wipe_data=False, binaries=False, revert_openclaw=True, remove_plugin=True)
    assert plan.acp_entries == ()
    cmd_uninstall._remove_acp_editor_entries(plan)
    assert json.loads(settings.read_text())["agent_servers"][name]["command"] == "edited-by-the-user"
    assert lock.is_file()
