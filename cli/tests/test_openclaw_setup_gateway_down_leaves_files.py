"""A setup that cannot reach OpenClaw's gateway leaves openclaw.json and the config as they were."""

from __future__ import annotations

import json
import os
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from defenseclaw import openclaw_json5
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
_SAVED_DURING_SETUP = (
    b'{"gateway":{"port":18773},"plugins":{"allow":["other","defenseclaw"]},"operatorNote":"saved while setup ran"}\n'
)


def _registered(original):
    """What DefenseClaw's registration makes of ``original``: the plugin added, the rest as it was."""
    config = openclaw_json5.loads(original.decode("utf-8")) if original else {}
    plugins = config.setdefault("plugins", {})
    plugins["allow"] = [*plugins.get("allow", []), "defenseclaw"]
    plugins.setdefault("entries", {})["defenseclaw"] = {"enabled": True}
    return (json.dumps(config, indent=2) + "\n").encode()


def _run_late_outage(tmp_dir, app, original, *, written=None, guards_openclaw=True):
    """Setup whose OpenClaw gateway goes down after DefenseClaw registered the plugin.

    ``original`` None means no openclaw.json before setup. ``written`` is what the
    registering restart leaves in the file. Returns (result, path, restart calls).
    """
    path = os.path.join(tmp_dir, "openclaw.json")
    if original is not None:
        with open(path, "wb") as handle:
            handle.write(original)
        os.chmod(path, 0o640)
    app.cfg.claw.config_file = path
    app.cfg.gateway.host = "127.0.0.1"
    app.cfg.claw.mode = "openclaw" if guards_openclaw else ""
    app.cfg.guardrail.connector = app.cfg.claw.mode
    app.cfg.guardrail.connectors = {}
    registered = _registered(original)
    calls = []

    def restart(*_args, **_kwargs):
        calls.append("restart")
        if len(calls) == 1:
            # DefenseClaw's gateway registered the plugin, then OpenClaw's went down.
            with open(path, "wb") as handle:
                handle.write(registered if written is None else written)
            cmd_setup._fail_if_restart_failed(["openclaw-gateway"])
        elif guards_openclaw:
            # The rollback restart on a configuration that guards OpenClaw registers it again.
            with open(path, "wb") as handle:
                handle.write(registered)

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
    assert not [name for name in os.listdir(tmp_dir) if name.startswith(".openclaw-restore-")]
    return result, path, calls


@pytest.mark.parametrize(
    "original",
    [
        b"// user comment\n{gateway:{mode:'local',port:0x4955},plugins:{allow:['other']}}\n",
        b'{"gateway":{"mode":"local","port":18773},"plugins":{"allow":["other"]}}\n',
        _JSON5,
        # Past 4 MiB: the Go connector reads such a file, so the rollback has to keep it too.
        b'{"gateway":{"port":18773},"plugins":{"allow":["other"]}}' + b" " * (4 * 1024 * 1024) + b"\n",
    ],
    ids=["json5-comments-hex", "plain-json", "json5-block-comment", "over-4-mib"],
)
@pytest.mark.parametrize("guards_openclaw", [True, False])
def test_late_openclaw_outage_puts_back_the_saved_bytes(original, guards_openclaw):
    app, tmp_dir, db_path = make_app_context()
    try:
        result, path, _ = _run_late_outage(tmp_dir, app, original, guards_openclaw=guards_openclaw)
        with open(path, "rb") as handle:
            assert handle.read() == original
        assert os.stat(path).st_mode & 0o777 == 0o640
        assert "rollback was incomplete" not in result.output
        assert "saved by OpenClaw or you" not in result.output
    finally:
        cleanup_app(app, db_path, tmp_dir)


@pytest.mark.parametrize("guards_openclaw", [True, False])
def test_late_openclaw_outage_deletes_a_file_setup_created(guards_openclaw):
    app, tmp_dir, db_path = make_app_context()
    try:
        result, path, _ = _run_late_outage(tmp_dir, app, None, guards_openclaw=guards_openclaw)
        assert not os.path.exists(path), result.output
        assert "rollback was incomplete" not in result.output
    finally:
        cleanup_app(app, db_path, tmp_dir)


_BASE = b'{"gateway":{"mode":"local","port":18773},"plugins":{"allow":["other"]}}\n'


@pytest.mark.parametrize(
    ("original", "written", "marker"),
    [
        (_BASE, _SAVED_DURING_SETUP, b"saved while setup ran"),
        # A file nobody had before setup, saved by someone with no DefenseClaw registration in it.
        (None, b'{"operatorNote":"saved while setup ran"}\n', b"saved while setup ran"),
        # A value that was already there was changed, not added.
        (_BASE, _LATE_REGISTERED.replace(b"18773", b"19999"), b"19999"),
        # Not JSON5 at all: not DefenseClaw's output.
        (_BASE, b"{ this is not json", b"this is not json"),
    ],
    ids=["new-key", "no-file-before", "changed-value", "unreadable"],
)
def test_a_save_made_during_setup_is_kept_and_reported(original, written, marker):
    app, tmp_dir, db_path = make_app_context()
    try:
        # The restored configuration does not guard OpenClaw, so nothing registers again.
        result, path, _ = _run_late_outage(tmp_dir, app, original, written=written, guards_openclaw=False)
        with open(path, "rb") as handle:
            assert marker in handle.read()
        assert "saved by OpenClaw or you while setup ran" in result.output
        assert "rollback was incomplete" not in result.output
    finally:
        cleanup_app(app, db_path, tmp_dir)


@pytest.mark.parametrize("make_unreadable", ["too-big", "directory"])
def test_a_config_that_cannot_be_copied_exactly_stops_setup_before_any_write(make_unreadable):
    app, tmp_dir, db_path = make_app_context()
    try:
        path = os.path.join(tmp_dir, "openclaw.json")
        before = b'{"gateway":{"port":18773}}' + b" " * 64
        if make_unreadable == "directory":
            os.mkdir(path)
        else:
            with open(path, "wb") as handle:
                handle.write(before)
        app.cfg.claw.config_file = path
        app.cfg.gateway.host = "127.0.0.1"
        before_connector = app.cfg.active_connector()
        with (
            patch.object(cmd_setup, "_OPENCLAW_CONFIG_MAX_BYTES", 16),
            patch.object(cmd_setup, "_openclaw_gateway_healthy", return_value=True),
            patch.object(cmd_setup, "_restart_services") as restart_services,
            patch.object(cmd_setup, "_adopt_openclaw_gateway_token") as adopt_token,
            patch.object(cmd_setup, "setup_guardrail") as guardrail,
        ):
            result = _invoke(app)
        assert result.exit_code != 0, result.output
        assert "cannot keep an exact copy" in result.output
        assert "No changes made" in result.output
        assert app.cfg.active_connector() == before_connector
        for stub in (restart_services, adopt_token, guardrail):
            stub.assert_not_called()
        if make_unreadable == "too-big":
            with open(path, "rb") as handle:
                assert handle.read() == before
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_content_registered_for_defenseclaw_alone_is_not_a_foreign_save():
    prior = b"// c\n{plugins:{allow:['other'],load:{paths:['/x']}},approvals:{}}\n"
    ours = (
        b'{"plugins":{"allow":["other","defenseclaw"],"entries":{"defenseclaw":{"enabled":true}},'
        b'"load":{"paths":["/x","/home/u/.openclaw/extensions/defenseclaw"]}},'
        b'"approvals":{"plugin":{"enabled":true,"mode":"session"}}}'
    )
    assert cmd_setup._openclaw_config_saved_by_others(prior, ours) is False
    created = (
        b'{"plugins":{"allow":["defenseclaw"],"entries":{"defenseclaw":{"enabled":true}},'
        b'"load":{"paths":["/home/u/.openclaw/extensions/defenseclaw"]}}}'
    )
    assert cmd_setup._openclaw_config_saved_by_others(None, created) is False
    # A file setup created holds the registration and nothing else; other content in it was saved by someone.
    assert cmd_setup._openclaw_config_saved_by_others(None, ours) is True
    assert cmd_setup._openclaw_config_saved_by_others(None, b'{"gateway":{"port":1}}') is True
    assert cmd_setup._openclaw_config_saved_by_others(prior, ours.replace(b'"allow":["other"', b'"allow":["x"')) is True


_OPERATOR_BASE = b'{"gateway":{"mode":"local","port":18773},"plugins":{"allow":["other"]}}\n'


@pytest.mark.parametrize(
    ("original", "change", "marker"),
    [
        (None, "new-note-in-a-file-setup-created", b'"operatorNote": "saved during setup"'),
        (_OPERATOR_BASE, "other-plugin-named-like-defenseclaw", b'"other-defenseclaw-plugin"'),
        (_OPERATOR_BASE, "operator-setting-in-the-defenseclaw-entry", b'"operatorChoice": "keep"'),
        (_OPERATOR_BASE, "changed-approval-setting", b'"mode": "always"'),
        (_OPERATOR_BASE, "removed-gateway-field", b'"port": 18773'),
        (_OPERATOR_BASE, "operator-load-path", b'"/opt/operator-plugins"'),
    ],
)
def test_nearby_saves_during_setup_are_kept_and_reported(original, change, marker):
    app, tmp_dir, db_path = make_app_context()
    try:
        content = json.loads(_registered(original))
        if change == "new-note-in-a-file-setup-created":
            content["operatorNote"] = "saved during setup"
        elif change == "other-plugin-named-like-defenseclaw":
            content["plugins"]["allow"].append("other-defenseclaw-plugin")
        elif change == "operator-setting-in-the-defenseclaw-entry":
            content["plugins"]["entries"]["defenseclaw"]["config"] = {"operatorChoice": "keep"}
        elif change == "changed-approval-setting":
            content["approvals"] = {"plugin": {"enabled": True, "mode": "always"}}
        elif change == "removed-gateway-field":
            del content["gateway"]["mode"]
        elif change == "operator-load-path":
            content["plugins"]["load"] = {"paths": ["/opt/operator-plugins"]}
        written = (json.dumps(content, indent=2) + "\n").encode()
        result, path, _ = _run_late_outage(tmp_dir, app, original, written=written, guards_openclaw=False)
        assert os.path.exists(path), result.output
        with open(path, "rb") as handle:
            after = handle.read()
        if change == "removed-gateway-field":
            assert "mode" not in json.loads(after)["gateway"], result.output
        else:
            assert marker in after, result.output
        assert "saved by OpenClaw or you while setup ran" in result.output
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_everything_the_registration_writes_is_put_back_with_the_saved_bytes():
    """Approvals block, conversation-hook grant and extension directory are setup own, next to operator content."""
    original = (
        b'// operator comment\n{gateway:{port:0x4955,timeout:1.0},plugins:{allow:["other"],'
        b'load:{paths:["/opt/operator-plugins"]}},approvals:{exec:{enabled:false}}}\n'
    )
    written = (
        json.dumps(
            {
                "gateway": {"port": 0x4955, "timeout": 1},
                "plugins": {
                    "allow": ["other", "defenseclaw"],
                    "entries": {"defenseclaw": {"enabled": True, "hooks": {"allowConversationAccess": True}}},
                    "load": {"paths": ["/opt/operator-plugins", "/home/u/.openclaw/extensions/defenseclaw"]},
                },
                "approvals": {"exec": {"enabled": False}, "plugin": {"enabled": True, "mode": "session"}},
            },
            indent=2,
        ).encode()
        + b"\n"
    )
    assert cmd_setup._openclaw_config_saved_by_others(original, written) is False
    app, tmp_dir, db_path = make_app_context()
    try:
        result, path, _ = _run_late_outage(tmp_dir, app, original, written=written, guards_openclaw=False)
        with open(path, "rb") as handle:
            assert handle.read() == original
        assert "saved by OpenClaw or you" not in result.output
    finally:
        cleanup_app(app, db_path, tmp_dir)


@pytest.mark.parametrize(
    ("prior", "written"),
    [
        # The approvals block setup wrote earlier is dropped again on an OpenClaw that rejects it.
        (
            b'{"plugins":{"allow":["other"]},"approvals":{"plugin":{"enabled":true,"mode":"session"}}}',
            b'{"plugins":{"allow":["other","defenseclaw"],"entries":{"defenseclaw":{"enabled":true}}}}',
        ),
        # An operator-set grant and an already registered plugin stay as they were.
        (
            b'{"plugins":{"allow":["defenseclaw"],"entries":{"defenseclaw":{"enabled":true,'
            b'"hooks":{"allowConversationAccess":false}}}}}',
            b'{"plugins":{"allow":["defenseclaw"],"entries":{"defenseclaw":{"enabled":true,'
            b'"hooks":{"allowConversationAccess":false}}}}}',
        ),
    ],
)
def test_registration_variants_are_not_foreign_saves(prior, written):
    assert cmd_setup._openclaw_config_saved_by_others(prior, written) is False


def test_a_changed_grant_or_boolean_is_a_foreign_save():
    prior = b'{"plugins":{"entries":{"defenseclaw":{"enabled":true,"hooks":{"allowConversationAccess":false}}}}}'
    flipped = prior.replace(b"false", b"true")
    assert cmd_setup._openclaw_config_saved_by_others(prior, flipped) is True
    # A 1 saved where the operator had true is a change, not the same value.
    assert (
        cmd_setup._openclaw_config_saved_by_others(b'{"flag":true}', b'{"flag":1,"plugins":{"allow":["defenseclaw"]}}')
        is True
    )


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
            handle.write(_registered(_JSON5))
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
