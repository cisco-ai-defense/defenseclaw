"""A setup that cannot reach OpenClaw's gateway leaves openclaw.json and the config as they were."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_setup

from tests.helpers import cleanup_app, make_app_context

pytestmark = pytest.mark.supported_connector_host

_JSON5 = (
    b"// a comment the user wrote\n"
    b"{\n"
    b"  /* block comment */\n"
    b"  gateway: { mode: 'local', port: 0x7077, }, // hex port\n"
    b"  plugins: { allow: ['other'], },\n"
    b"}\n"
)


def _seed(tmp_dir: str, app) -> str:
    path = os.path.join(tmp_dir, "openclaw.json")
    with open(path, "wb") as handle:
        handle.write(_JSON5)
    app.cfg.claw.config_file = path
    app.cfg.gateway.host = "127.0.0.1"
    return path


def _invoke(app, *args: str):
    with (
        patch.object(cmd_setup, "_ensure_connector_available"),
        patch.object(cmd_setup, "_windows_runtime_rollback", return_value=False),
        patch("time.sleep"),
    ):
        return CliRunner().invoke(cmd_setup.setup, ["openclaw", "--yes", *args], obj=app)


def test_gateway_down_fails_before_any_write_and_keeps_the_json5_bytes():
    app, tmp_dir, db_path = make_app_context()
    try:
        path = _seed(tmp_dir, app)
        before_connector = app.cfg.active_connector()
        with (
            patch.object(cmd_setup, "_openclaw_gateway_healthy", return_value=False) as probe,
            patch.object(cmd_setup, "_restart_openclaw_gateway", return_value=False),
            patch.object(cmd_setup, "_OPENCLAW_PRESETUP_WAIT_SECONDS", 0),
            patch.object(cmd_setup, "_restart_services") as restart_services,
            patch.object(cmd_setup, "_restart_defense_gateway") as restart_gateway,
            patch.object(cmd_setup, "_adopt_openclaw_gateway_token") as adopt_token,
            patch.object(cmd_setup, "setup_guardrail") as guardrail,
        ):
            result = _invoke(app)
        assert result.exit_code != 0, result.output
        assert "The OpenClaw gateway is not running" in result.output
        assert "No changes made" in result.output
        assert "restored" not in result.output.lower()
        # The port in openclaw.json (0x7077) is the one dialed.
        assert all(call.args[1] == 0x7077 for call in probe.call_args_list)
        with open(path, "rb") as handle:
            assert handle.read() == _JSON5
        assert app.cfg.active_connector() == before_connector
        for stub in (restart_services, restart_gateway, adopt_token, guardrail):
            stub.assert_not_called()
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_gateway_that_a_service_starts_lets_setup_continue():
    app, tmp_dir, db_path = make_app_context()
    try:
        _seed(tmp_dir, app)
        with (
            patch.object(cmd_setup, "_openclaw_gateway_healthy", side_effect=[False, False, True]),
            patch.object(cmd_setup, "_restart_openclaw_gateway", return_value=True) as service_start,
            patch.object(cmd_setup, "_adopt_openclaw_gateway_token"),
            patch.object(cmd_setup, "_write_picked_connector_hint"),
            patch.object(cmd_setup, "setup_guardrail") as guardrail,
        ):
            result = _invoke(app)
        assert result.exit_code == 0, result.output
        service_start.assert_called_once()
        guardrail.assert_called_once()
    finally:
        cleanup_app(app, db_path, tmp_dir)


@pytest.mark.parametrize("args", [(), ("--no-restart",)])
def test_running_gateway_and_no_restart_runs_are_not_held_up(args):
    app, tmp_dir, db_path = make_app_context()
    try:
        _seed(tmp_dir, app)
        healthy = args == ()
        with (
            patch.object(cmd_setup, "_openclaw_gateway_healthy", return_value=healthy) as probe,
            patch.object(cmd_setup, "_restart_openclaw_gateway") as service_start,
            patch.object(cmd_setup, "_adopt_openclaw_gateway_token"),
            patch.object(cmd_setup, "_write_picked_connector_hint"),
            patch.object(cmd_setup, "setup_guardrail") as guardrail,
        ):
            result = _invoke(app, *args)
        assert result.exit_code == 0, result.output
        service_start.assert_not_called()
        assert probe.call_count == (1 if healthy else 0)
        guardrail.assert_called_once()
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_remote_openclaw_gateway_is_not_probed_from_here():
    app, tmp_dir, db_path = make_app_context()
    try:
        _seed(tmp_dir, app)
        app.cfg.gateway.host = "gateway.example.net"
        with (
            patch.object(cmd_setup, "_openclaw_gateway_healthy") as probe,
            patch.object(cmd_setup, "_adopt_openclaw_gateway_token"),
            patch.object(cmd_setup, "_write_picked_connector_hint"),
            patch.object(cmd_setup, "setup_guardrail"),
        ):
            result = _invoke(app)
        assert result.exit_code == 0, result.output
        probe.assert_not_called()
    finally:
        cleanup_app(app, db_path, tmp_dir)


@pytest.mark.parametrize("guards_openclaw", [True, False])
def test_late_openclaw_outage_rollback_says_when_the_plugin_entries_stay(guards_openclaw):
    app, tmp_dir, db_path = make_app_context()
    try:
        app.cfg.claw.mode = "openclaw" if guards_openclaw else "codex"
        app.cfg.guardrail.connector = "openclaw" if guards_openclaw else "codex"
        app.cfg.guardrail.connectors = {}
        snapshot = cmd_setup._capture_setup_config_snapshot(app.cfg)
        cause = cmd_setup._OpenClawGatewayNotRunning("The OpenClaw gateway is not running.")
        with (
            patch.object(cmd_setup, "_restart_restored_connector_runtime"),
            pytest.raises(cmd_setup.click.ClickException) as raised,
        ):
            cmd_setup._rollback_failed_connector_application(app, snapshot, cause)
        text = raised.value.format_message()
        assert ("keeps the DefenseClaw plugin entries" in text) is guards_openclaw
        assert "rollback was incomplete" not in text
    finally:
        cleanup_app(app, db_path, tmp_dir)
