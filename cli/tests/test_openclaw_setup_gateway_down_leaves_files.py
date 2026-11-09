"""A setup that cannot reach OpenClaw's gateway leaves openclaw.json as it is and says so (GAP-0973)."""

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
    """What DefenseClaw's registration makes of ``original``: the plugin added (once), the rest as it was."""
    config = openclaw_json5.loads(original.decode("utf-8")) if original else {}
    plugins = config.setdefault("plugins", {})
    if "defenseclaw" not in plugins.get("allow", []):
        plugins["allow"] = [*plugins.get("allow", []), "defenseclaw"]
    plugins.setdefault("entries", {})["defenseclaw"] = {"enabled": True}
    return (json.dumps(config, indent=2) + "\n").encode()


def _run_late_outage(
    tmp_dir,
    app,
    original,
    *,
    written=None,
    guards_openclaw=True,
    saved_before_restart=None,
    gateway_fails=False,
    home=None,
    configured_copy=None,
):
    """Setup whose OpenClaw gateway goes down after DefenseClaw registered the plugin, through the real restart step.

    ``original`` None means no openclaw.json before setup. ``written`` is what OpenClaw's own
    restart then saved over the registration. ``saved_before_restart`` is a save that lands after
    setup took its mark and before DefenseClaw's gateway restarts; ``gateway_fails`` makes that
    restart fail before it registers anything. With ``home`` the registration writes
    ``<home>/.openclaw/openclaw.json`` (the Go writer's file) while the configuration names
    another path; ``configured_copy`` is a save an operator makes at the configured path during the run.
    Returns (result, path of the file the registration writes).
    """
    configured = os.path.join(tmp_dir, "openclaw.json")
    path = configured if home is None else os.path.join(home, ".openclaw", "openclaw.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if original is not None:
        with open(path, "wb") as handle:
            handle.write(original)
        os.chmod(path, 0o640)
    app.cfg.claw.config_file = configured
    app.cfg.gateway.host = "127.0.0.1"
    app.cfg.claw.mode = "openclaw" if guards_openclaw else ""
    app.cfg.guardrail.connector = app.cfg.claw.mode
    app.cfg.guardrail.connectors = {}
    restarts = []

    def save_before_restart(*_args, **_kwargs):
        if configured_copy is not None:
            with open(configured, "wb") as handle:
                handle.write(configured_copy)
        if saved_before_restart is not None:
            with open(path, "wb") as handle:
                handle.write(saved_before_restart)

    def defenseclaw_gateway(*_args, **_kwargs):
        restarts.append("restart")
        if len(restarts) == 1 and gateway_fails:
            return False
        if len(restarts) == 1 or guards_openclaw:
            # The first start registers the plugin; the rollback start does it again when the restored
            # configuration guards OpenClaw. The registration merges over what the file holds at that moment.
            current = open(path, "rb").read() if os.path.exists(path) else original
            with open(path, "wb") as handle:
                handle.write(_registered(current))
        return True

    def openclaw_is_down(*_args, **_kwargs):
        if written is not None:
            with open(path, "wb") as handle:
                handle.write(written)
        return False

    environment = {} if home is None else {"HOME": home, "USERPROFILE": home}
    with (
        patch.dict(os.environ, environment),
        patch.object(cmd_setup, "_restart_defense_gateway", side_effect=defenseclaw_gateway),
        patch.object(cmd_setup, "_restart_openclaw_gateway", return_value=True),
        patch.object(cmd_setup, "_check_openclaw_gateway", side_effect=openclaw_is_down),
        patch.object(cmd_setup, "_openclaw_gateway_healthy", return_value=True),
        patch.object(cmd_setup, "_adopt_openclaw_gateway_token", side_effect=save_before_restart),
        patch.object(cmd_setup, "_write_picked_connector_hint"),
        patch.object(cmd_setup, "_ensure_connector_available"),
        patch.object(cmd_setup, "_maybe_bring_up_local_stack"),
        patch.object(cmd_setup, "_check_connector_version_supported_for_setup", return_value=True),
        patch.object(cmd_setup, "_windows_runtime_rollback", return_value=False),
        patch("time.sleep"),
    ):
        result = CliRunner().invoke(cmd_setup.setup, ["openclaw", "--mode", "action", "--yes"], obj=app)
    assert result.exit_code != 0, result.output
    assert len(restarts) == 2, result.output
    assert not [name for name in os.listdir(os.path.dirname(path)) if name.startswith(".openclaw-restore-")]
    return result, path


def _assert_left_as_it_is(result, path):
    assert "Not restored" in result.output, result.output
    assert path in result.output, result.output
    assert "defenseclaw setup remove openclaw" in result.output, result.output
    assert "plugins.entries.defenseclaw" in result.output, result.output
    assert "rollback was incomplete" not in result.output, result.output


@pytest.mark.parametrize(
    "original",
    [
        b"// user comment\n{gateway:{mode:'local',port:0x4955},plugins:{allow:['other']}}\n",
        b'{"gateway":{"mode":"local","port":18773},"plugins":{"allow":["other"]}}\n',
        _JSON5,
        # Past 4 MiB: the Go connector reads such a file, so the message must not depend on its size.
        b'{"gateway":{"port":18773},"plugins":{"allow":["other"]}}' + b" " * (4 * 1024 * 1024) + b"\n",
        None,
    ],
    ids=["json5-comments-hex", "plain-json", "json5-block-comment", "over-4-mib", "no-file-before"],
)
@pytest.mark.parametrize("guards_openclaw", [True, False])
def test_late_openclaw_outage_leaves_the_file_as_the_registration_wrote_it_and_says_so(original, guards_openclaw):
    app, tmp_dir, db_path = make_app_context()
    try:
        result, path = _run_late_outage(tmp_dir, app, original, guards_openclaw=guards_openclaw)
        with open(path, "rb") as handle:
            assert handle.read() == _registered(original)
        _assert_left_as_it_is(result, path)
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
        # Not JSON5 at all.
        (_BASE, b"{ this is not json", b"this is not json"),
        # Bytes equal to what the registration wrote, saved by someone else: never swapped for the old copy.
        (_BASE, _registered(_BASE), b'"defenseclaw"'),
    ],
    ids=["new-key", "no-file-before", "changed-value", "unreadable", "copy-of-the-registration"],
)
def test_a_save_made_during_setup_is_never_overwritten(original, written, marker):
    app, tmp_dir, db_path = make_app_context()
    try:
        # The restored configuration does not guard OpenClaw, so nothing registers again.
        result, path = _run_late_outage(tmp_dir, app, original, written=written, guards_openclaw=False)
        with open(path, "rb") as handle:
            assert handle.read() == written
        assert marker in written
        assert "rollback was incomplete" not in result.output
        if written != _registered(original):
            _assert_left_as_it_is(result, path)
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_an_outside_save_before_the_restart_stays_in_the_file_the_registration_merges_over():
    outside = _OPERATOR_BASE.replace(b'"other"', b'"other", "mine"')
    app, tmp_dir, db_path = make_app_context()
    try:
        result, path = _run_late_outage(
            tmp_dir, app, _OPERATOR_BASE, saved_before_restart=outside, guards_openclaw=False
        )
        with open(path, "rb") as handle:
            assert handle.read() == _registered(outside), result.output
        _assert_left_as_it_is(result, path)
    finally:
        cleanup_app(app, db_path, tmp_dir)


@pytest.mark.parametrize("guards_openclaw", [True, False])
def test_a_save_at_the_configured_path_is_untouched_when_the_registration_writes_elsewhere(tmp_path, guards_openclaw):
    """The configuration names one path and the registration writes the account's OpenClaw home."""
    app, tmp_dir, db_path = make_app_context()
    try:
        home = str(tmp_path / "account")
        copy = _registered(_BASE)  # An operator saves bytes equal to the registration's output at the configured path.
        result, written_path = _run_late_outage(
            tmp_dir, app, _BASE, guards_openclaw=guards_openclaw, home=home, configured_copy=copy
        )
        assert written_path == os.path.join(home, ".openclaw", "openclaw.json")
        with open(written_path, "rb") as handle:
            assert handle.read() == _registered(_BASE)
        with open(os.path.join(tmp_dir, "openclaw.json"), "rb") as handle:
            assert handle.read() == copy
        _assert_left_as_it_is(result, written_path)
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_a_failed_setup_that_wrote_nothing_does_not_claim_it_did():
    """The restart fails before any registration: the file is byte for byte as it was and the message says nothing of it."""
    app, tmp_dir, db_path = make_app_context()
    try:
        result, path = _run_late_outage(tmp_dir, app, _JSON5, gateway_fails=True, guards_openclaw=False)
        with open(path, "rb") as handle:
            assert handle.read() == _JSON5
        assert "Not restored" not in result.output
        assert "defenseclaw setup remove openclaw" not in result.output
    finally:
        cleanup_app(app, db_path, tmp_dir)


_OPERATOR_BASE = b'{"gateway":{"mode":"local","port":18773},"plugins":{"allow":["other"]}}\n'
_WITH_APPROVAL = (
    b'{"plugins":{"allow":["other"]},'
    b'"approvals":{"plugin":{"enabled":true,"mode":"session"},"exec":{"enabled":false}}}\n'
)


@pytest.mark.parametrize(
    ("original", "change", "marker"),
    [
        (None, "new-note-in-a-file-setup-created", b'"operatorNote": "saved during setup"'),
        (_OPERATOR_BASE, "other-plugin-named-like-defenseclaw", b'"other-defenseclaw-plugin"'),
        (_OPERATOR_BASE, "operator-setting-in-the-defenseclaw-entry", b'"operatorChoice": "keep"'),
        (_OPERATOR_BASE, "changed-approval-setting", b'"mode": "always"'),
        (_OPERATOR_BASE, "removed-gateway-field", b'"port": 18773'),
        (_OPERATOR_BASE, "operator-load-path", b'"/opt/operator-plugins"'),
        (_OPERATOR_BASE, "operator-path-named-defenseclaw", b'"/opt/operator/defenseclaw"'),
        (_OPERATOR_BASE, "operator-path-object-named-defenseclaw", b'"/opt/operator/defenseclaw"'),
        (_WITH_APPROVAL, "operator-removed-approval-block", b'"exec"'),
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
        elif change == "operator-path-named-defenseclaw":
            content["plugins"]["load"] = {
                "paths": ["/home/u/.openclaw/extensions/defenseclaw", "/opt/operator/defenseclaw"]
            }
        elif change == "operator-path-object-named-defenseclaw":
            content["plugins"]["load"] = {
                "paths": ["/home/u/.openclaw/extensions/defenseclaw", {"operator": ["/opt/operator/defenseclaw"]}]
            }
        elif change == "operator-removed-approval-block":
            del content["approvals"]["plugin"]
        written = (json.dumps(content, indent=2) + "\n").encode()
        result, path = _run_late_outage(tmp_dir, app, original, written=written, guards_openclaw=False)
        assert os.path.exists(path), result.output
        with open(path, "rb") as handle:
            after = handle.read()
        if change == "removed-gateway-field":
            assert "mode" not in json.loads(after)["gateway"], result.output
        elif change == "operator-removed-approval-block":
            assert "plugin" not in json.loads(after)["approvals"], result.output
        else:
            assert marker in after, result.output
        assert "Not restored" in result.output
    finally:
        cleanup_app(app, db_path, tmp_dir)
