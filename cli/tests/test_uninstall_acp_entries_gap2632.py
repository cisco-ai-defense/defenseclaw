# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-2632: uninstall removes the guarded ACP editor entries `acp setup` wrote and keeps the rest."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import patch

from click.testing import CliRunner
from defenseclaw.commands import cmd_acp, cmd_uninstall

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

        entries = cmd_uninstall._acp_editor_entries(app.cfg, data_dir)
        assert entries == (("zed", "opencode", str(cmd_acp._client_path("zed"))),)
        cmd_uninstall._remove_acp_editor_entries(SimpleNamespace(records_dir=data_dir, acp_entries=entries))

        assert json.loads(settings.read_text())["agent_servers"] == {"Foreign": {"command": "other"}}
        assert not lock.exists()
        assert cmd_uninstall._acp_editor_entries(app.cfg, data_dir) == ()
        app.cfg.deployment_mode = "managed_enterprise"
        assert cmd_uninstall._acp_editor_entries(app.cfg, data_dir) == ()
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
