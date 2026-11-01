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
        cmd_uninstall._remove_acp_editor_entries(SimpleNamespace(data_dir=data_dir, acp_entries=entries))

        assert json.loads(settings.read_text())["agent_servers"] == {"Foreign": {"command": "other"}}
        assert not lock.exists()
        assert cmd_uninstall._acp_editor_entries(app.cfg, data_dir) == ()
        app.cfg.deployment_mode = "managed_enterprise"
        assert cmd_uninstall._acp_editor_entries(app.cfg, data_dir) == ()
    finally:
        cleanup_app(app, db_path, data_dir)
