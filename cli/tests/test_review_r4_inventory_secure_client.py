"""Focused regressions for inventory and Secure Client Python CLI behavior."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import patch

from click.testing import CliRunner
from defenseclaw.commands.cmd_agent import agent
from defenseclaw.commands.cmd_aibom import aibom
from defenseclaw.commands.cmd_alerts import alerts
from defenseclaw.config import default_config
from defenseclaw.inventory.claw_inventory import attach_ide_plugins, build_claw_aibom
from defenseclaw.models import Event

from tests.helpers import cleanup_app, make_app_context


def test_ide_page_cap_is_partial() -> None:
    inv = {"summary": {}}
    attach_ide_plugins(inv, {"plugins": [{}], "next_cursor": "more"})
    assert inv["summary"]["ide_plugins"]["count"] == 1
    assert inv["summary"]["ide_plugins"]["partial"] is True

def test_secure_client_aibom_skips_ide_gateway_and_output() -> None:
    app, tmp_dir, db_path = make_app_context()
    try:
        app.cfg.active_connectors = lambda: ["codex"]
        with patch("defenseclaw.commands.cmd_status._enterprise_profile", return_value="secure_client"), \
             patch("defenseclaw.commands.cmd_aibom._fetch_ide_plugins") as fetch, \
             patch("defenseclaw.commands.cmd_aibom._scan_one_connector",
                   return_value=({"connector": "codex"}, None)):
            result = CliRunner().invoke(aibom, ["scan", "--json"], obj=app, catch_exceptions=False)
        assert result.exit_code == 0, result.output
        assert json.loads(result.output) == {"connector": "codex"}
        fetch.assert_not_called()
    finally:
        cleanup_app(app, db_path, tmp_dir)

def test_secure_client_aibom_does_not_stamp_plugin_or_mcp_users() -> None:
    cfg = default_config()
    with patch("defenseclaw.commands.cmd_status._enterprise_profile", return_value="secure_client"), \
         patch("defenseclaw.inventory.claw_inventory._stamp_local_user") as stamp:
        build_claw_aibom(cfg, live=False, categories={"plugins", "mcp"})
        build_claw_aibom(cfg, live=True, categories=set(), connector="codex")
    stamp.assert_not_called()

def test_secure_client_agent_command_tree_hides_new_commands() -> None:
    app, tmp_dir, db_path = make_app_context()
    try:
        with patch("defenseclaw.commands.cmd_status._enterprise_profile", return_value="secure_client"):
            help_result = CliRunner().invoke(agent, ["--help"], obj=app)
            assert "ide-plugins" not in help_result.output
            assert "identities" not in help_result.output
            for name in ("ide-plugins", "identities"):
                result = CliRunner().invoke(agent, [name], obj=app)
                assert result.exit_code != 0
                assert "No such command" in result.output
            from defenseclaw.main import cli

            with patch("defenseclaw.config.load", return_value=app.cfg):
                root_help = CliRunner().invoke(cli, ["agent", "--help"])
            assert root_help.exit_code == 0, root_help.output
            assert "ide-plugins" not in root_help.output
            assert "identities" not in root_help.output
    finally:
        cleanup_app(app, db_path, tmp_dir)

def test_secure_client_alerts_omit_agent_facts_in_json_and_detail() -> None:
    app, tmp_dir, db_path = make_app_context()
    try:
        app.store.log_event(Event(action="scan", target="x", severity="HIGH",
                                  details="test alert", timestamp=datetime.now(timezone.utc)))
        def facts(_store, ids):
            return {id_: [("Session", "private-session")] for id_ in ids}
        with patch("defenseclaw.commands.cmd_status._enterprise_profile", return_value="secure_client"), \
             patch("defenseclaw.commands.cmd_alerts.alert_agent_facts", side_effect=facts) as lookup:
            json_result = CliRunner().invoke(alerts, ["--json"], obj=app, catch_exceptions=False)
            detail_result = CliRunner().invoke(alerts, ["--show", "1"], obj=app, catch_exceptions=False)
        assert json_result.exit_code == 0, json_result.output
        assert detail_result.exit_code == 0, detail_result.output
        assert "session_id" not in json_result.output
        assert "private-session" not in detail_result.output
        lookup.assert_not_called()
    finally:
        cleanup_app(app, db_path, tmp_dir)
