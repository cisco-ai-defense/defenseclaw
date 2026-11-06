"""Foreground gateway status on Windows and macOS uses public, PID-bound health."""

from __future__ import annotations

import json
import os
import socket
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner
from defenseclaw import file_permissions, gateway, logger
from defenseclaw.commands import cmd_doctor, cmd_status
from defenseclaw.doctor_gateway import ListenerEvidence, ProcessEvidence

from tests.helpers import cleanup_app, make_app_context


@pytest.fixture
def cfg(tmp_path: Path):
    data_dir = tmp_path / "home"
    data_dir.mkdir()
    return SimpleNamespace(
        data_dir=str(data_dir),
        deployment_mode="",
        gateway=SimpleNamespace(api_bind="127.0.0.1", api_port=18789),
    )


def _proof(
    platform: str,
    *,
    peer_sid: str = "S-1-5-21-1000",
    record_port: int = 18789,
    executable: str | None = None,
    listener_pids: tuple[int | None, ...] = (4242,),
    process_uid: int = 1000,
    own_uid: int = 1000,
    own_sid: str = "S-1-5-21-1000",
    record_host: str = "127.0.0.1",
    process_uids: tuple[int, ...] = (),
    resolved_addresses: tuple[str, ...] = (),
    alternate_closed: bool = True,
) -> tuple[ExitStack, MagicMock]:
    image = executable or (
        "C:\\DefenseClaw\\defenseclaw-gateway.exe" if platform == "win32" else "/opt/defenseclaw-gateway"
    )
    process = ProcessEvidence("ok", pid=4242, executable=image, start_identity="generation-1", uid=process_uid)
    evidence = MagicMock()
    evidence.process.return_value = process
    if process_uids:
        evidence.process.side_effect = [
            ProcessEvidence("ok", pid=4242, executable=image, start_identity="generation-1", uid=uid)
            for uid in process_uids
        ]
    listener = MagicMock(
        side_effect=[
            ListenerEvidence("missing") if pid is None else ListenerEvidence("ok", pid=pid) for pid in listener_pids
        ]
    )
    health = {"gateway": {"state": "running"}, "connectors": [{"name": "claudecode", "state": "running"}]}
    probe = MagicMock(return_value=(200, json.dumps(health)))
    stack = ExitStack()
    stack.enter_context(patch.object(cmd_doctor.sys, "platform", platform))
    stack.enter_context(patch.object(cmd_doctor, "GatewayEvidence", return_value=evidence))
    stack.enter_context(
        patch.object(
            cmd_doctor,
            "_managed_gateway_process_trust",
            return_value=cmd_doctor._GatewayTrust("missing", "no PID file"),
        )
    )
    stack.enter_context(patch.object(cmd_doctor, "_managed_gateway_listener_evidence", listener))
    if resolved_addresses:
        rows = [
            (
                socket.AF_INET6 if ":" in address else socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                (address, 18789, 0, 0) if ":" in address else (address, 18789),
            )
            for address in resolved_addresses
        ]
        stack.enter_context(patch.object(cmd_doctor.socket, "getaddrinfo", return_value=rows))
        stack.enter_context(
            patch.object(cmd_doctor, "_foreground_endpoint_closed", return_value=alternate_closed, create=True)
        )
    stack.enter_context(patch.object(cmd_doctor, "_gateway_port_holder", return_value="PID 4242 (defenseclaw-gateway)"))
    stack.enter_context(patch.object(cmd_doctor, "_foreground_current_uid", return_value=own_uid, create=True))
    stack.enter_context(patch.object(cmd_doctor, "windows_process_user_sid", return_value=peer_sid, create=True))
    stack.enter_context(patch.object(file_permissions, "_windows_current_user_sid", return_value=own_sid))
    stack.enter_context(patch.object(gateway, "resolve_trusted_gateway_binary", return_value=image))
    stack.enter_context(
        patch.object(
            logger, "_running_gateway_record", return_value={"pid": 4242, "host": record_host, "port": record_port}
        )
    )
    stack.enter_context(patch.object(cmd_doctor, "_http_probe", probe))
    return stack, probe


@pytest.mark.parametrize("platform", ["win32", "darwin"])
def test_foreground_gateway_status_uses_public_health_without_a_pid_file(cfg, platform: str) -> None:
    client = MagicMock()
    stack, probe = _proof(platform, listener_pids=(4242, 4242))
    with stack:
        assert not cmd_doctor._trusted_gateway_listener(cfg).trusted
        health = cmd_status._fetch_runtime_bound_health(client, cfg)
    assert health is not None
    assert health["pid"] == 4242
    assert health["connectors"][0]["state"] == "running"
    client.status.assert_not_called()
    assert probe.call_args.kwargs.get("headers") is None
    assert probe.call_args.kwargs["bound_peer"].pid == 4242


@pytest.mark.parametrize("platform", ["win32", "darwin"])
def test_foreground_gateway_holder_is_not_labeled_foreign_in_status(cfg, platform: str) -> None:
    stack, _ = _proof(platform, listener_pids=(4242, 4242))
    with stack:
        assert cmd_doctor._foreign_gateway_port_holder(cfg, status_only=True) == ""
        assert "PID 4242" in cmd_doctor._foreign_gateway_port_holder(cfg)


@pytest.mark.parametrize("platform", ["win32", "darwin"])
@pytest.mark.parametrize(
    ("bind", "record_host", "listener_pids"),
    [
        ("localhost", "127.0.0.1", (4242, None, 4242, None)),
        ("localhost", "::1", (None, 4242, None, 4242)),
        ("loopback.local", "127.0.0.1", (4242, None, 4242, None)),
    ],
)
def test_loopback_hostname_uses_recorded_numeric_endpoint(
    cfg, platform: str, bind: str, record_host: str, listener_pids: tuple[int | None, ...]
) -> None:
    cfg.gateway.api_bind = bind
    client = MagicMock()
    stack, probe = _proof(
        platform,
        listener_pids=listener_pids,
        record_host=record_host,
        resolved_addresses=("127.0.0.1", "::1"),
    )
    with (
        stack,
        patch.object(
            cmd_doctor, "_trusted_gateway_listener", return_value=cmd_doctor._GatewayTrust("missing", "no PID file")
        ),
    ):
        assert cmd_status._fetch_runtime_bound_health(client, cfg) is not None
    expected_url = "http://[::1]:18789/health" if record_host == "::1" else "http://127.0.0.1:18789/health"
    assert probe.call_args.args[0] == expected_url
    assert probe.call_args.kwargs.get("headers") is None
    client.status.assert_not_called()


@pytest.mark.parametrize("platform", ["win32", "darwin"])
def test_loopback_hostname_holder_is_not_labeled_foreign(cfg, platform: str) -> None:
    cfg.gateway.api_bind = "localhost"
    stack, _ = _proof(
        platform,
        listener_pids=(4242, None, 4242, None),
        resolved_addresses=("127.0.0.1", "::1"),
    )
    with (
        stack,
        patch.object(
            cmd_doctor, "_trusted_gateway_listener", return_value=cmd_doctor._GatewayTrust("missing", "no PID file")
        ),
    ):
        assert cmd_doctor._foreign_gateway_port_holder(cfg, status_only=True) == ""


@pytest.mark.parametrize("platform", ["win32", "darwin"])
@pytest.mark.parametrize("bind", ["localhost", "127.0.0.1"])
def test_unavailable_public_health_keeps_verified_foreground_owner_unverified(cfg, platform: str, bind: str) -> None:
    cfg.gateway.api_bind = bind
    details = (
        {"resolved_addresses": ("127.0.0.1", "::1"), "listener_pids": (4242, None, 4242, None)}
        if bind == "localhost"
        else {"listener_pids": (4242, 4242)}
    )
    stack, probe = _proof(platform, **details)
    probe.return_value = (0, "public health unavailable")
    with stack:
        assert cmd_doctor._foreground_gateway_status_health(cfg) is None
        assert cmd_doctor._foreign_gateway_port_holder(cfg, status_only=True) == ""
        assert "PID 4242" in cmd_doctor._foreign_gateway_port_holder(cfg)
    assert probe.call_count == 1
    assert probe.call_args.kwargs.get("headers") is None


@pytest.mark.parametrize("platform", ["win32", "darwin"])
@pytest.mark.parametrize(
    ("listener_pids", "alternate_closed"),
    [((4242, 4343), True), ((4242, None), False)],
)
def test_second_resolved_listener_is_not_foreground_gateway(
    cfg, platform: str, listener_pids: tuple[int | None, ...], alternate_closed: bool
) -> None:
    cfg.gateway.api_bind = "localhost"
    stack, probe = _proof(
        platform,
        listener_pids=listener_pids,
        resolved_addresses=("127.0.0.1", "::1"),
        alternate_closed=alternate_closed,
    )
    with stack:
        assert cmd_doctor._foreground_gateway_status_health(cfg) is None
    probe.assert_not_called()


@pytest.mark.parametrize("platform", ["win32", "darwin"])
def test_loopback_hostname_other_account_remains_untrusted(cfg, platform: str) -> None:
    cfg.gateway.api_bind = "localhost"
    changes = {"peer_sid": "S-1-5-21-2000"} if platform == "win32" else {"process_uid": 2000}
    stack, probe = _proof(
        platform,
        listener_pids=(4242, None),
        resolved_addresses=("127.0.0.1", "::1"),
        **changes,
    )
    with stack:
        assert cmd_doctor._foreground_gateway_status_health(cfg) is None
    probe.assert_not_called()


@pytest.mark.parametrize("platform", ["win32", "darwin"])
def test_hostname_with_nonloopback_resolution_stays_untrusted(cfg, platform: str) -> None:
    cfg.gateway.api_bind = "loopback.local"
    stack, probe = _proof(platform, resolved_addresses=("127.0.0.1", "192.0.2.1"))
    with stack:
        assert cmd_doctor._foreground_gateway_status_health(cfg) is None
    probe.assert_not_called()


@pytest.mark.parametrize(
    ("platform", "changes"),
    [
        ("win32", {"peer_sid": "S-1-5-21-2000"}),
        ("darwin", {"process_uid": 2000}),
    ],
)
def test_other_account_listener_remains_foreign_in_status(cfg, platform: str, changes: dict) -> None:
    stack, probe = _proof(platform, **changes)
    with stack:
        assert "PID 4242" in cmd_doctor._foreign_gateway_port_holder(cfg, status_only=True)
    probe.assert_not_called()


def test_status_renders_foreground_gateway_and_agents_from_public_health() -> None:
    app, tmp_dir, db_path = make_app_context()
    app.cfg.guardrail.connector = "claudecode"
    app.cfg.guardrail.enabled = True
    app.cfg.fleet.enabled = True
    health = {"gateway": {"state": "running"}, "connectors": [{"name": "claudecode", "state": "running"}]}
    client = MagicMock()
    try:
        with (
            patch.object(
                cmd_doctor, "_trusted_gateway_listener", return_value=cmd_doctor._GatewayTrust("missing", "no PID file")
            ),
            patch.object(cmd_doctor, "_foreground_gateway_status_health", return_value=(4242, health), create=True),
            patch.object(gateway, "OrchestratorClient", return_value=client),
        ):
            human = CliRunner().invoke(cmd_status.status, [], obj=app)
            machine = CliRunner().invoke(cmd_status.status, ["--json"], obj=app)
        assert human.exit_code == 0, human.output
        assert "Sidecar:      running (PID 4242" in human.output
        assert "Claude Code (claudecode)" in human.output
        assert "Fleet:" in human.output
        assert "unavailable without authenticated gateway status" in human.output
        assert "Fleet:        not configured" not in human.output
        assert machine.exit_code == 0, machine.output
        assert json.loads(machine.output)["sidecar"]["running"] is True
        assert json.loads(machine.output)["fleet"]["available"] is False
        client.status.assert_not_called()
        client._session.get.assert_not_called()
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_status_renders_unverified_foreground_owner_without_credentials() -> None:
    app, tmp_dir, db_path = make_app_context()
    app.cfg.guardrail.connector = "claudecode"
    app.cfg.guardrail.enabled = True
    app.cfg.fleet.enabled = True
    client = MagicMock()
    try:
        with (
            patch.object(
                cmd_doctor, "_trusted_gateway_listener", return_value=cmd_doctor._GatewayTrust("missing", "no PID file")
            ),
            patch.object(cmd_doctor, "_foreground_gateway_status_health", return_value=None),
            patch.object(cmd_doctor, "_foreground_gateway_status_owner", return_value=SimpleNamespace(pid=4242)),
            patch.object(cmd_doctor, "_gateway_port_holder", return_value="PID 4242 (defenseclaw-gateway)"),
            patch.object(cmd_status, "_live_gateway_pid", return_value=0),
            patch.object(gateway, "OrchestratorClient", return_value=client),
        ):
            human = CliRunner().invoke(cmd_status.status, [], obj=app)
            machine = CliRunner().invoke(cmd_status.status, ["--json"], obj=app)
        assert human.exit_code == 0, human.output
        assert "foreground gateway (PID 4242) owns the listener" in human.output
        assert "live state unverified" in human.output
        assert "port 18789 is held by" not in human.output
        assert machine.exit_code == 0, machine.output
        sidecar = json.loads(machine.output)["sidecar"]
        assert sidecar["running"] is None
        assert "foreground gateway (PID 4242) owns the listener" in sidecar["reason"]
        client.status.assert_not_called()
        client._session.get.assert_not_called()
    finally:
        cleanup_app(app, db_path, tmp_dir)


@pytest.mark.parametrize(
    ("platform", "changes"),
    [
        ("win32", {"peer_sid": "S-1-5-21-2000"}),
        ("win32", {"record_port": 18790}),
        ("darwin", {"record_port": 18790}),
        ("darwin", {"executable": "/opt/other-program"}),
        ("win32", {"listener_pids": (4242, 4343)}),
        ("darwin", {"process_uid": 2000}),
        ("darwin", {"process_uids": (1000, 2000)}),
        ("darwin", {"process_uid": 0, "own_uid": 0}),
        ("win32", {"peer_sid": "S-1-5-18", "own_sid": "S-1-5-18"}),
        ("win32", {"record_host": "127.0.0.2"}),
    ],
)
def test_unverified_foreground_listener_stays_untrusted(cfg, platform: str, changes: dict) -> None:
    client = MagicMock()
    stack, _ = _proof(platform, **changes)
    with stack:
        assert cmd_status._fetch_runtime_bound_health(client, cfg) is None
    client.status.assert_not_called()


@pytest.mark.parametrize("mode", ["managed", "secure_client"])
def test_foreground_display_proof_excludes_managed_profiles(cfg, mode: str) -> None:
    from defenseclaw.enforce import asset_lists

    if mode == "managed":
        cfg.deployment_mode = "managed_enterprise"
    with (
        patch.object(asset_lists, "is_secure_client", return_value=mode == "secure_client"),
        patch.object(cmd_doctor, "_managed_gateway_listener_evidence", side_effect=AssertionError("not queried")),
    ):
        assert cmd_doctor._foreground_gateway_status_health(cfg, platform_name="win32") is None


def test_private_runtime_record_can_follow_a_verified_listener_without_pid_file(tmp_path: Path) -> None:
    data_dir = tmp_path / "home"
    data_dir.mkdir()
    record = data_dir / "gateway-api.json"
    record.write_text(json.dumps({"pid": os.getpid(), "host": "127.0.0.1", "port": 18789}), encoding="utf-8")
    record.chmod(0o600)
    if os.name == "nt":
        pytest.skip("native Windows custody is covered by its ACL tests")
    assert not (data_dir / "gateway.pid").exists()
    assert logger._running_gateway_record(str(data_dir), "gateway-api.json") is None
    assert logger._running_gateway_record(str(data_dir), "gateway-api.json", expected_pid=os.getpid()) == {
        "pid": os.getpid(),
        "host": "127.0.0.1",
        "port": 18789,
    }
    assert logger._running_gateway_record(str(data_dir), "gateway-api.json", expected_pid=os.getpid() + 1) is None


@pytest.mark.skipif(os.name != "nt", reason="requires Windows process tokens")
def test_windows_process_sid_proof_reads_the_current_process() -> None:
    from defenseclaw.doctor_gateway import windows_process_user_sid

    assert windows_process_user_sid(os.getpid()) == file_permissions._windows_current_user_sid()
