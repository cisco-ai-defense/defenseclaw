"""A setup that cannot reach OpenClaw's gateway leaves openclaw.json and the config as they were."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
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


def _publish_writer_receipt(data_dir, path, original, committed):
    """The record the Go registration leaves under the data dir once it has committed ``committed`` over ``original``."""
    folder = os.path.join(data_dir, "connector_backups", "openclaw")
    os.makedirs(folder, exist_ok=True)
    receipt = {
        "version": 1,
        "connector": "openclaw",
        "logical_name": "openclaw.json",
        "path": path,
        "existed": original is not None,
        "pristine_sha256": hashlib.sha256(original).hexdigest() if original is not None else "missing",
        "post_sha256": hashlib.sha256(committed).hexdigest(),
    }
    receipt_path = os.path.join(folder, "openclaw.json.json")
    with open(receipt_path, "w") as handle:
        json.dump(receipt, handle)
    return receipt_path


class _FakeGateway:
    """The gateway process: its generation, and the digest of the bytes it passed to its own last write."""

    def __init__(self):
        self.restarts = 0
        self.generation = None
        self.digest = None

    def start(self):
        self.restarts += 1
        self.generation = f"generation-{self.restarts}"
        self.digest = None

    def wrote(self, data):
        self.digest = hashlib.sha256(data).hexdigest()

    def report(self, _data_dir):
        return self.generation, self.digest


def _run_late_outage(
    tmp_dir,
    app,
    original,
    *,
    written=None,
    writer=None,
    guards_openclaw=True,
    saved_before_restart=None,
    gateway_fails=False,
):
    """Setup whose OpenClaw gateway goes down after DefenseClaw registered the plugin, through the real restart step.

    ``original`` None means no openclaw.json before setup. ``writer`` is what the
    registration committed (default: the plugin added and nothing else) and
    ``written`` what OpenClaw's own restart then saved over it. ``saved_before_restart``
    is a save that lands after setup took its copy and before DefenseClaw's gateway
    restarts; ``gateway_fails`` makes that restart fail before it registers anything.
    Returns (result, path).
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
    restarts = []
    gateway = _FakeGateway()

    def save_before_restart(*_args, **_kwargs):
        if saved_before_restart is not None:
            with open(path, "wb") as handle:
                handle.write(saved_before_restart)
            # Another registration published over that save, with a record of its own.
            _publish_writer_receipt(app.cfg.data_dir, path, original, saved_before_restart)

    def defenseclaw_gateway(*_args, **_kwargs):
        restarts.append("restart")
        gateway.start()
        if len(restarts) == 1 and gateway_fails:
            return False
        if len(restarts) == 1 or guards_openclaw:
            # The first start registers the plugin; the rollback start does it again when the restored
            # configuration guards OpenClaw.
            # The registration merges over what the file holds at that moment.
            current = open(path, "rb").read() if os.path.exists(path) else original
            committed = _registered(current) if writer is None else writer
            with open(path, "wb") as handle:
                handle.write(committed)
            gateway.wrote(committed)
            _publish_writer_receipt(app.cfg.data_dir, path, original, committed)
        return True

    def openclaw_is_down(*_args, **_kwargs):
        if written is not None:
            with open(path, "wb") as handle:
                handle.write(written)
        return False

    with (
        patch.object(cmd_setup, "_restart_defense_gateway", side_effect=defenseclaw_gateway),
        patch.object(cmd_setup, "_openclaw_gateway_write_report", side_effect=gateway.report),
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
    assert not [name for name in os.listdir(tmp_dir) if name.startswith(".openclaw-restore-")]
    return result, path


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
        result, path = _run_late_outage(tmp_dir, app, original, guards_openclaw=guards_openclaw)
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
        result, path = _run_late_outage(tmp_dir, app, None, guards_openclaw=guards_openclaw)
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
        result, path = _run_late_outage(tmp_dir, app, original, written=written, guards_openclaw=False)
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
    app, tmp_dir, db_path = make_app_context()
    try:
        result, path = _run_late_outage(tmp_dir, app, original, writer=written, guards_openclaw=False)
        with open(path, "rb") as handle:
            assert handle.read() == original
        assert "saved by OpenClaw or you" not in result.output
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
        snapshot = cmd_setup._with_openclaw_config_record(
            cmd_setup._capture_setup_config_snapshot(app.cfg), path, app.cfg.data_dir
        )
        _observed_registration(pathlib.Path(path), snapshot.openclaw_config, _registered(_JSON5))
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


_PRUNED_PRIOR = (
    b"// operator comment\n{plugins:{entries:{defenseclaw:{config:{mode:'action',"
    b"operatorNote:'note',agent:{id:'alice',extra:true}}}}}}\n"
)


def test_a_plugin_config_the_registration_pruned_to_the_schema_is_put_back():
    """The writer drops fields the bundled schema rejects; that is its output, not a save by someone else."""
    committed = {
        "plugins": {
            "allow": ["defenseclaw"],
            "entries": {"defenseclaw": {"config": {"mode": "action", "agent": {"id": "alice"}}, "enabled": True}},
            "load": {"paths": ["/home/u/.openclaw/extensions/defenseclaw"]},
        }
    }
    app, tmp_dir, db_path = make_app_context()
    try:
        result, path = _run_late_outage(
            tmp_dir, app, _PRUNED_PRIOR, writer=(json.dumps(committed, indent=2) + "\n").encode(), guards_openclaw=False
        )
        with open(path, "rb") as handle:
            assert handle.read() == _PRUNED_PRIOR
        assert "saved by OpenClaw or you" not in result.output
    finally:
        cleanup_app(app, db_path, tmp_dir)


def _observed_registration(path, record, committed):
    """What the setup command sees around a gateway restart that registers ``committed`` over the file."""
    gateway = _FakeGateway()
    with patch.object(cmd_setup, "_openclaw_gateway_write_report", side_effect=gateway.report):
        record.witness.before_restart()
        gateway.start()
        gateway.wrote(committed)
        path.write_bytes(committed)
        record.witness.after_restart()


def _registered_record(tmp_path, prior=_OPERATOR_BASE):
    """A record taken before setup, then this run's own gateway restart registering the plugin."""
    data_dir = str(tmp_path / "data")
    path = tmp_path / "openclaw.json"
    path.write_bytes(prior)
    record = cmd_setup._capture_openclaw_config_record(str(path), data_dir)
    _observed_registration(path, record, _registered(prior))
    receipt = _publish_writer_receipt(data_dir, record.path, prior, _registered(prior))
    return record, path, receipt


def test_restore_puts_back_the_saved_bytes_and_drops_the_record_of_the_rolled_back_registration(tmp_path):
    record, path, receipt = _registered_record(tmp_path)
    assert cmd_setup._restore_openclaw_config_record(record) == "restored"
    assert path.read_bytes() == _OPERATOR_BASE
    assert not os.path.exists(receipt)
    assert sorted(os.listdir(tmp_path)) == ["data", "openclaw.json"]


def test_restore_keeps_the_record_of_an_earlier_setup(tmp_path):
    record, path, receipt = _registered_record(tmp_path)
    with open(receipt) as handle:
        earlier = json.load(handle)
    earlier["pristine_sha256"] = hashlib.sha256(b"{}").hexdigest()
    with open(receipt, "w") as handle:
        json.dump(earlier, handle)
    assert cmd_setup._restore_openclaw_config_record(record) == "restored"
    assert os.path.exists(receipt)


def test_bytes_this_run_never_saw_its_own_restart_write_are_kept(tmp_path):
    """Whatever the file holds, a registration this run did not observe is not proof that the run wrote it."""
    data_dir = str(tmp_path / "data")
    path = tmp_path / "openclaw.json"
    path.write_bytes(_OPERATOR_BASE)
    record = cmd_setup._capture_openclaw_config_record(str(path), data_dir)
    path.write_bytes(_registered(_OPERATOR_BASE))
    _publish_writer_receipt(data_dir, record.path, _OPERATOR_BASE, _registered(_OPERATOR_BASE))
    assert cmd_setup._restore_openclaw_config_record(record) == "kept"
    assert path.read_bytes() == _registered(_OPERATOR_BASE)


def test_file_deleted_after_registration_stays_deleted(tmp_path):
    record, path, _ = _registered_record(tmp_path)
    path.unlink()  # The registration writer never deletes an existing file.
    assert cmd_setup._restore_openclaw_config_record(record) == "kept"
    assert not path.exists()


def test_save_written_into_the_file_while_it_is_replaced_is_given_back(tmp_path):
    record, path, _ = _registered_record(tmp_path)
    real_replace = os.replace
    done = []

    def save_then_replace(src, dst):
        if not done:
            done.append(True)
            path.write_bytes(b'{"operatorNote":"saved during restore"}\n')
        return real_replace(src, dst)

    with patch.object(cmd_setup.os, "replace", side_effect=save_then_replace):
        assert cmd_setup._restore_openclaw_config_record(record) == "kept"
    assert path.read_bytes() == b'{"operatorNote":"saved during restore"}\n'
    assert sorted(os.listdir(tmp_path)) == ["data", "openclaw.json"]


def test_save_that_replaces_the_file_before_the_final_check_is_kept(tmp_path):
    record, path, _ = _registered_record(tmp_path)
    real_link = os.link

    def save_then_link(src, dst, *args, **kwargs):
        newer = tmp_path / "saved.tmp"
        newer.write_bytes(b'{"operatorNote":"replaced during restore"}\n')
        os.replace(newer, path)
        return real_link(src, dst, *args, **kwargs)

    with patch.object(cmd_setup.os, "link", side_effect=save_then_link):
        assert cmd_setup._restore_openclaw_config_record(record) == "kept"
    assert path.read_bytes() == b'{"operatorNote":"replaced during restore"}\n'
    assert sorted(os.listdir(tmp_path)) == ["data", "openclaw.json"]


def test_file_a_setup_created_is_removed_only_while_it_is_the_bytes_this_run_wrote(tmp_path):
    data_dir = str(tmp_path / "data")
    path = tmp_path / "openclaw.json"
    record = cmd_setup._capture_openclaw_config_record(str(path), data_dir)
    _observed_registration(path, record, _registered(None))
    assert cmd_setup._restore_openclaw_config_record(record) == "restored"
    assert not path.exists()
    path.write_bytes(b'{"operatorNote":"mine"}\n')
    assert cmd_setup._restore_openclaw_config_record(record) == "kept"
    assert path.exists()


# The bytes another registration, or an earlier setup, left: byte for byte what a registration writes,
# and still not something this run wrote.
_EARLIER_PRISTINE = b"{\"gateway\":{\"port\":18773}}\n"
_EARLIER_COMMITTED = _registered(_EARLIER_PRISTINE)
_SAVED_BEFORE_SETUP = b"{\"operatorNote\":\"saved before this setup\"}\n"


@pytest.mark.parametrize("prior", [_SAVED_BEFORE_SETUP, _EARLIER_PRISTINE], ids=["other-prior", "same-prior"])
def test_a_save_that_looks_like_a_registration_is_never_overwritten(tmp_path, prior):
    """A file another registration (or an earlier setup) left, with its record, stays the run's loss of track."""
    path = tmp_path / "openclaw.json"
    data_dir = str(tmp_path / "data")
    path.write_bytes(prior)
    record = cmd_setup._capture_openclaw_config_record(str(path), data_dir)
    path.write_bytes(_EARLIER_COMMITTED)
    receipt = _publish_writer_receipt(data_dir, str(path), prior, _EARLIER_COMMITTED)
    # The run's own gateway restart then registers over it, or fails: neither gives the bytes back to the run.
    _observed_registration(path, record, _registered(_EARLIER_COMMITTED))
    assert cmd_setup._restore_openclaw_config_record(record) == "kept"
    assert path.read_bytes() == _registered(_EARLIER_COMMITTED)
    assert os.path.exists(receipt)


def test_a_run_publishes_nothing_for_the_restore_to_trust(tmp_path):
    path = tmp_path / "openclaw.json"
    path.write_bytes(_OPERATOR_BASE)
    cmd_setup._capture_openclaw_config_record(str(path), str(tmp_path / "data"))
    assert not (tmp_path / "data").exists()


def test_an_outside_save_and_a_registration_over_it_are_never_overwritten():
    """OpenClaw saves the file, another registration publishes over that save, then this run's restart fails."""
    outside = _registered(_SAVED_BEFORE_SETUP).replace(b'"allow"', b'"operatorNote": "saved by OpenClaw", "allow"')
    for guards_openclaw in (True, False):
        app, tmp_dir, db_path = make_app_context()
        try:
            result, path = _run_late_outage(
                tmp_dir,
                app,
                _SAVED_BEFORE_SETUP,
                saved_before_restart=outside,
                gateway_fails=True,
                guards_openclaw=guards_openclaw,
            )
            with open(path, "rb") as handle:
                after = handle.read()
            if guards_openclaw:
                # The rollback restart registers again on the configuration it restores; the save stays in the file.
                assert b'"operatorNote": "saved by OpenClaw"' in after, result.output
            else:
                assert after == outside, result.output
            assert "saved by OpenClaw or you while setup ran" in result.output
            assert "defenseclaw setup remove openclaw" in result.output
        finally:
            cleanup_app(app, db_path, tmp_dir)


def test_an_outside_save_before_the_restart_is_kept_even_when_the_restart_registers():
    """The registration merges over the save, so the saved copy from before setup would lose that change."""
    outside = _OPERATOR_BASE.replace(b'"other"', b'"other", "mine"')
    app, tmp_dir, db_path = make_app_context()
    try:
        result, path = _run_late_outage(
            tmp_dir, app, _OPERATOR_BASE, saved_before_restart=outside, guards_openclaw=False
        )
        with open(path, "rb") as handle:
            assert b'"mine"' in handle.read(), result.output
        assert "saved by OpenClaw or you while setup ran" in result.output
    finally:
        cleanup_app(app, db_path, tmp_dir)


@pytest.mark.parametrize("gateway_reports", ["nothing", "no-registration", "registration-then-save"])
def test_a_save_during_the_gateway_restart_is_kept_and_reported(gateway_reports):
    """A save that lands while the restart runs is never taken as the bytes this run wrote."""
    app, tmp_dir, db_path = make_app_context()
    try:
        path = os.path.join(tmp_dir, "openclaw.json")
        registered = _registered(_OPERATOR_BASE)
        content = json.loads(registered if gateway_reports == "registration-then-save" else _OPERATOR_BASE)
        content["operatorNote"] = "saved during restart"
        outside = (json.dumps(content) + "\n").encode()
        with open(path, "wb") as handle:
            handle.write(_OPERATOR_BASE)
        app.cfg.claw.config_file = path
        app.cfg.gateway.host = "127.0.0.1"
        app.cfg.claw.mode = ""
        app.cfg.guardrail.connector = ""
        app.cfg.guardrail.connectors = {}
        gateway = _FakeGateway()
        restarts = []

        def gateway_restart(*_args, **_kwargs):
            restarts.append("restart")
            if len(restarts) == 1:
                gateway.start()
                if gateway_reports == "registration-then-save":
                    with open(path, "wb") as handle:
                        handle.write(registered)
                    gateway.wrote(registered)
                with open(path, "wb") as handle:
                    handle.write(outside)
            return True

        report = (lambda _data_dir: (None, None)) if gateway_reports == "nothing" else gateway.report
        with (
            patch.object(cmd_setup, "_restart_defense_gateway", side_effect=gateway_restart),
            patch.object(cmd_setup, "_openclaw_gateway_write_report", side_effect=report),
            patch.object(cmd_setup, "_restart_openclaw_gateway", return_value=True),
            patch.object(cmd_setup, "_check_openclaw_gateway", return_value=False),
            patch.object(cmd_setup, "_openclaw_gateway_healthy", return_value=True),
            patch.object(cmd_setup, "_adopt_openclaw_gateway_token"),
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
        with open(path, "rb") as handle:
            assert handle.read() == outside, result.output
        assert "saved by OpenClaw or you while setup ran" in result.output
        assert "defenseclaw setup remove openclaw" in result.output
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_the_digest_comes_from_the_gateway_that_wrote_not_from_the_file(tmp_path):
    """The file holding the very bytes of a registration is not enough: the gateway has to have reported them."""
    path = tmp_path / "openclaw.json"
    path.write_bytes(_OPERATOR_BASE)
    record = cmd_setup._capture_openclaw_config_record(str(path), str(tmp_path / "data"))
    gateway = _FakeGateway()
    with patch.object(cmd_setup, "_openclaw_gateway_write_report", side_effect=gateway.report):
        record.witness.before_restart()
        gateway.start()  # The gateway starts and reports no write of its own.
        path.write_bytes(_registered(_OPERATOR_BASE))  # Something else registers the plugin meanwhile.
        record.witness.after_restart()
    assert cmd_setup._restore_openclaw_config_record(record) == "kept"
    assert path.read_bytes() == _registered(_OPERATOR_BASE)


def test_a_digest_from_the_gateway_that_was_already_running_is_not_this_runs_write(tmp_path):
    path = tmp_path / "openclaw.json"
    path.write_bytes(_OPERATOR_BASE)
    record = cmd_setup._capture_openclaw_config_record(str(path), str(tmp_path / "data"))
    digest = hashlib.sha256(_registered(_OPERATOR_BASE)).hexdigest()
    with patch.object(cmd_setup, "_openclaw_gateway_write_report", return_value=("started-earlier", digest)):
        record.witness.before_restart()
        path.write_bytes(_registered(_OPERATOR_BASE))
        record.witness.after_restart()
    assert cmd_setup._restore_openclaw_config_record(record) == "kept"
    assert path.read_bytes() == _registered(_OPERATOR_BASE)


@pytest.mark.parametrize(
    ("health", "expected"),
    [
        (None, (None, None)),
        ({"started_at": "t1"}, ("t1", None)),
        ({"started_at": "t1", "openclaw_config_write": {"sha256": "ab" * 32}}, ("t1", "ab" * 32)),
        ({"started_at": "t1", "openclaw_config_write": {"sha256": "short"}}, ("t1", None)),
        ({"started_at": 5, "openclaw_config_write": "x"}, (None, None)),
    ],
)
def test_the_gateway_write_report_reads_only_what_the_health_document_says(tmp_path, health, expected):
    with (
        patch.object(cmd_setup, "_gateway_api_config", return_value=object()),
        patch.object(cmd_setup, "_read_defense_gateway_health_once", return_value=health),
    ):
        assert cmd_setup._openclaw_gateway_write_report(str(tmp_path)) == expected
    assert cmd_setup._openclaw_gateway_write_report("") is None
