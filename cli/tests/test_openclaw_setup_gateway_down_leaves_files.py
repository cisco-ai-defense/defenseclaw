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


_LATE_REGISTERED = b'{"gateway":{"port":18773},"plugins":{"allow":["other","defenseclaw"]}}\n'


@pytest.mark.parametrize(
    "original",
    [
        b"// user comment\n{gateway:{mode:'local',port:0x4955},plugins:{allow:['other']}}\n",
        b'{"gateway":{"mode":"local","port":18773},"plugins":{"allow":["other"]}}\n',
        _JSON5,
    ],
    ids=["json5-comments-hex", "plain-json", "json5-block-comment"],
)
@pytest.mark.parametrize("guards_openclaw", [True, False])
def test_late_openclaw_outage_puts_back_the_saved_bytes(original, guards_openclaw):
    app, tmp_dir, db_path = make_app_context()
    try:
        path = os.path.join(tmp_dir, "openclaw.json")
        with open(path, "wb") as handle:
            handle.write(original)
        os.chmod(path, 0o640)
        app.cfg.claw.config_file = path
        app.cfg.gateway.host = "127.0.0.1"
        app.cfg.claw.mode = "openclaw" if guards_openclaw else ""
        app.cfg.guardrail.connector = app.cfg.claw.mode
        app.cfg.guardrail.connectors = {}
        calls = []

        def restart(*_args, **_kwargs):
            calls.append("restart")
            if len(calls) == 1:
                # DefenseClaw's gateway registered the plugin, then OpenClaw's went down.
                with open(path, "wb") as handle:
                    handle.write(_LATE_REGISTERED)
                cmd_setup._fail_if_restart_failed(["openclaw-gateway"])
            elif guards_openclaw:
                # The rollback restart on a configuration that guards OpenClaw registers it again.
                with open(path, "wb") as handle:
                    handle.write(_LATE_REGISTERED)

        with (
            patch.object(cmd_setup, "_restart_services", side_effect=restart),
            patch.object(cmd_setup, "_openclaw_gateway_healthy", return_value=True),
            patch.object(cmd_setup, "_adopt_openclaw_gateway_token"),
            patch.object(cmd_setup, "_write_picked_connector_hint"),
            patch.object(cmd_setup, "_ensure_connector_available"),
            patch.object(cmd_setup, "_maybe_bring_up_local_stack"),
            patch.object(cmd_setup, "_check_connector_version_supported_for_setup", return_value=True),
            patch.object(cmd_setup, "_windows_runtime_rollback", return_value=False),
        ):
            result = CliRunner().invoke(cmd_setup.setup, ["openclaw", "--mode", "action", "--yes"], obj=app)
        assert result.exit_code != 0, result.output
        assert len(calls) == 2, result.output
        with open(path, "rb") as handle:
            assert handle.read() == original
        assert os.stat(path).st_mode & 0o777 == 0o640
        assert "rollback was incomplete" not in result.output
        assert "keeps the DefenseClaw plugin entries" not in result.output
        assert not [name for name in os.listdir(tmp_dir) if name.startswith(".openclaw-restore-")]
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_restore_leaves_an_unchanged_file_alone():
    app, tmp_dir, db_path = make_app_context()
    try:
        path = os.path.join(tmp_dir, "openclaw.json")
        with open(path, "wb") as handle:
            handle.write(_JSON5)
        record = cmd_setup._capture_openclaw_config_record(path)
        before = os.stat(path)
        cmd_setup._restore_openclaw_config_record(record)
        after = os.stat(path)
        assert (after.st_ino, after.st_mtime_ns) == (before.st_ino, before.st_mtime_ns)
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_failed_restore_of_the_saved_bytes_is_reported_not_called_restored():
    app, tmp_dir, db_path = make_app_context()
    try:
        path = os.path.join(tmp_dir, "openclaw.json")
        with open(path, "wb") as handle:
            handle.write(_JSON5)
        app.cfg.claw.config_file = path
        app.cfg.claw.mode = "codex"
        app.cfg.guardrail.connector = "codex"
        app.cfg.guardrail.connectors = {}
        snapshot = cmd_setup._with_openclaw_config_record(cmd_setup._capture_setup_config_snapshot(app.cfg), path)
        with open(path, "wb") as handle:
            handle.write(_LATE_REGISTERED)
        cause = cmd_setup._OpenClawGatewayNotRunning("The OpenClaw gateway is not running.")
        with (
            patch.object(cmd_setup, "_restart_restored_connector_runtime"),
            patch.object(cmd_setup.os, "replace", side_effect=PermissionError("denied")),
            pytest.raises(cmd_setup.click.ClickException) as raised,
        ):
            cmd_setup._rollback_failed_connector_application(app, snapshot, cause)
        assert "rollback was incomplete: restore openclaw.json" in raised.value.format_message()
        assert not [name for name in os.listdir(tmp_dir) if name.startswith(".openclaw-restore-")]
    finally:
        cleanup_app(app, db_path, tmp_dir)
