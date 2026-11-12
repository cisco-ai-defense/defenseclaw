"""GAP-1260: the CLI sends no gateway token to another account's listener."""

from __future__ import annotations

import os
import stat
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest import mock

import pytest
import requests
from defenseclaw import gateway


def test_missing_gateway_pid_is_definitely_offline_before_a_setup_audit_send() -> None:
    from defenseclaw import config, upgrade_shim
    from defenseclaw.commands import cmd_doctor
    from defenseclaw.logger import _is_definite_preconnect_failure

    client = gateway.OrchestratorClient(host="127.0.0.1", port=18960, token="t" * 64)
    cfg = SimpleNamespace(gateway=SimpleNamespace(api_port=18960))
    for code, definite in (("missing", True), ("identity", False)):
        trust = SimpleNamespace(
            trusted=False,
            code=code,
            detail="the gateway is not running (PID file is missing)" if definite else "listener identity failed",
        )
        with (
            mock.patch.object(upgrade_shim, "managed_descriptor", return_value=None),
            mock.patch.object(gateway, "_managed_connected_verifier_spec", return_value=None),
            mock.patch.object(config, "load", return_value=cfg),
            mock.patch.object(gateway, "gateway_api_client_host", return_value="127.0.0.1"),
            mock.patch.object(cmd_doctor, "_trusted_gateway_listener", return_value=trust),
            mock.patch.object(requests.adapters.HTTPAdapter, "send", side_effect=AssertionError("token sent")),
        ):
            with pytest.raises(gateway.GatewayListenerNotOwnedError) as failure:
                client.status()
        assert _is_definite_preconnect_failure(failure.value) is definite


def test_cli_checks_connected_socket_before_sending_after_listener_replacement() -> None:
    received: list[str] = []

    class Peer(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            received.append(self.headers.get("Authorization", ""))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *_args) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Peer)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = gateway.OrchestratorClient(host="127.0.0.1", port=server.server_port, token="private-token")
        with (
            mock.patch.object(gateway, "_unproven_per_user_gateway_target", return_value=""),
            mock.patch.object(
                gateway,
                "_verify_connected_gateway_socket",
                side_effect=gateway.GatewayListenerNotOwnedError("connected peer is another account"),
                create=True,
            ) as verify,
        ):
            with pytest.raises(requests.ConnectionError):
                client.status()
            assert verify.called
        assert received == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_managed_cli_checks_service_peer_before_sending_to_a_foreign_listener(tmp_path) -> None:
    from defenseclaw import upgrade_shim

    received: list[str] = []

    class Peer(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            received.append(self.headers.get("Authorization", ""))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *_args) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Peer)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    binary = tmp_path / "defenseclaw-gateway"
    binary.write_text("#!/bin/sh\nexit 1\n", encoding="ascii")
    binary.chmod(0o700)
    descriptor = "/etc/defenseclaw/managed-runtime.json"
    try:
        client = gateway.OrchestratorClient(host="127.0.0.1", port=server.server_port, token="private-token")
        with (
            mock.patch.object(upgrade_shim, "managed_descriptor", return_value=descriptor),
            mock.patch.dict(gateway._MANAGED_GATEWAY_BINARIES, {descriptor: str(binary)}),
            mock.patch.object(gateway, "_trusted_connected_verifier_binary"),
            mock.patch.object(gateway.subprocess, "run", return_value=SimpleNamespace(returncode=1)) as verify,
        ):
            with pytest.raises(requests.ConnectionError, match="connected gateway"):
                client.status()
            assert verify.called
        assert received == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_mac_status_and_doctor_name_a_peer_listener_hidden_from_lsof() -> None:
    from defenseclaw.commands import cmd_doctor

    cfg = SimpleNamespace(gateway=SimpleNamespace(api_port=19081))
    with (
        mock.patch.object(cmd_doctor.sys, "platform", "darwin"),
        mock.patch.object(cmd_doctor, "_trusted_gateway_listener", return_value=cmd_doctor._GatewayTrust("missing", "")),
        mock.patch.object(cmd_doctor, "_gateway_port_holder", return_value=""),
        mock.patch.object(cmd_doctor, "_gateway_api_host", return_value="127.0.0.1"),
        mock.patch.object(
            gateway, "foreign_loopback_listener", return_value="127.0.0.1:19081 is held by a process of another account"
        ),
    ):
        holder = cmd_doctor._foreign_gateway_port_holder(cfg)
    assert "another account" in holder


def test_doctor_sidecar_root_listener_uses_root_remedy(monkeypatch) -> None:
    from defenseclaw.commands import cmd_doctor

    cfg = SimpleNamespace(gateway=SimpleNamespace(api_port=18970))
    monkeypatch.setattr(
        cmd_doctor, "_trusted_gateway_listener",
        lambda _cfg: cmd_doctor._GatewayTrust("root_gateway", "root listener", pid=4242),
    )
    monkeypatch.setattr(cmd_doctor, "_gateway_port_holder", lambda _cfg: "another account (uid 0)")
    holder = cmd_doctor._foreign_gateway_port_holder(cfg)
    assert holder == cmd_doctor.ROOT_GATEWAY_REASON
    detail = cmd_doctor._foreign_gateway_port_detail(cfg, holder)
    remedy = cmd_doctor._foreign_gateway_port_remediation(cfg, holder=holder)
    if sys.platform.startswith("win"):
        # GAP-0747: the Windows remedy is an elevated PowerShell prompt, never sudo.
        assert "elevated PowerShell prompt" in detail and "sudo" not in detail and remedy in detail
    else:
        assert "sudo env DEFENSECLAW_HOME=" in detail and remedy in detail
    assert "--api-port" not in detail


def test_doctor_names_visible_root_listener_from_trust_evidence(monkeypatch) -> None:
    from defenseclaw.commands import cmd_doctor

    cfg = SimpleNamespace(gateway=SimpleNamespace(api_port=18970), data_dir="/tmp/defenseclaw-account-home")
    monkeypatch.setattr(cmd_doctor.sys, "platform", "darwin")
    monkeypatch.setattr(cmd_doctor, "_gateway_port_holder", lambda _cfg: "PID 4242 (defenseclaw-gateway)")
    monkeypatch.setattr(
        cmd_doctor, "_trusted_gateway_listener",
        lambda _cfg: cmd_doctor._GatewayTrust("root_gateway", "root listener", pid=4242),
    )
    assert cmd_doctor._foreign_gateway_port_holder(cfg) == cmd_doctor.ROOT_GATEWAY_REASON

    monkeypatch.setattr(
        cmd_doctor, "_trusted_gateway_listener",
        lambda _cfg: cmd_doctor._GatewayTrust("trusted", "own listener", pid=4242),
    )
    assert cmd_doctor._foreign_gateway_port_holder(cfg) == ""


def test_doctor_names_unlisted_linux_root_listener_without_an_extra_probe(monkeypatch) -> None:
    from defenseclaw.commands import cmd_doctor

    cfg = SimpleNamespace(gateway=SimpleNamespace(api_port=18970), data_dir="/tmp/defenseclaw-account-home")
    monkeypatch.setattr(cmd_doctor.sys, "platform", "linux")
    monkeypatch.setattr(cmd_doctor, "_gateway_port_holder", lambda _cfg: "")
    monkeypatch.setattr(cmd_doctor, "_gateway_api_host", lambda _cfg: "127.0.0.1")
    monkeypatch.setattr(
        cmd_doctor, "_trusted_gateway_listener",
        lambda _cfg: pytest.fail("an unlisted listener must use the existing connected-peer diagnosis"),
    )
    monkeypatch.setattr(
        gateway, "foreign_loopback_listener",
        lambda *_args: cmd_doctor.ROOT_GATEWAY_REASON + " " + cmd_doctor._root_gateway_remedy(cfg),
    )
    assert cmd_doctor._foreign_gateway_port_holder(cfg) == cmd_doctor.ROOT_GATEWAY_REASON
    monkeypatch.setattr(gateway, "foreign_loopback_listener", lambda *_args: "")
    assert cmd_doctor._foreign_gateway_port_holder(cfg) == ""


_HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"


def _row(addr: str, uid: int) -> str:
    return f"   0: {addr}:4A10 00000000:0000 0A 00000000:00000000 00:00000000 00000000 {uid:5d}        0 4242 1\n"


@pytest.mark.parametrize(
    ("host", "tcp", "tcp6", "expected"),
    [
        ("127.0.0.1", _row("0100007F", 1009), "", "uid 1009"),
        ("::1", "", _row("00000000000000000000000001000000", 1009), "uid 1009"),
        ("127.0.0.1", _row("0100007F", 1000), "", ""),
        ("127.0.0.1", _row("0200007F", 1000) + _row("0100007F", 1009), "", "uid 1009"),
        ("127.0.0.1", _row("0200007F", 1009), "", ""),
        ("127.0.0.1", _row("0500000A", 1009), "", ""),
        ("127.0.0.1", "", "", ""),
    ],
)
def test_linux_listener_owner(tmp_path, host, tcp, tcp6, expected) -> None:
    (tmp_path / "tcp").write_text(_HEADER + tcp, encoding="ascii")
    (tmp_path / "tcp6").write_text(_HEADER + tcp6, encoding="ascii")
    with (
        mock.patch.object(gateway.sys, "platform", "linux"),
        mock.patch.object(gateway.os, "getuid", return_value=1000, create=True),
    ):
        problem = gateway._foreign_loopback_listener_uncached(18960, str(tmp_path), host=host)
    if expected:
        assert expected in problem
    else:
        assert problem == ""


def test_mac_listener_owner_checks_the_configured_address() -> None:
    from defenseclaw import doctor_gateway

    def lsof_result(args, **_kwargs):
        # This account owns 127.0.0.2:18960, while a peer answers on
        # 127.0.0.1:18960. A broad port query sees the wrong listener.
        if "-iTCP:18960" in args:
            return SimpleNamespace(returncode=0, stdout="42\n", stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="")

    with (
        mock.patch.object(gateway.sys, "platform", "darwin"),
        mock.patch.object(gateway.os, "getuid", return_value=1000, create=True),
        mock.patch.object(doctor_gateway, "trusted_lsof_path", return_value="/usr/sbin/lsof"),
        mock.patch("subprocess.run", side_effect=lsof_result) as lsof,
        mock.patch.object(gateway.socket, "create_connection") as connect,
    ):
        problem = gateway._foreign_loopback_listener_uncached(18960)
    assert "another account" in problem
    assert "-iTCP@127.0.0.1:18960" in lsof.call_args.args[0]
    connect.assert_called_once_with(("127.0.0.1", 18960), timeout=1)


def test_client_refuses_to_send_its_token_to_a_foreign_listener() -> None:
    client = gateway.OrchestratorClient(host="127.0.0.1", port=18960, token="t" * 64)
    with (
        mock.patch.object(
            gateway, "_unproven_per_user_gateway_target", return_value="held by another account"
        ) as check,
        mock.patch.object(requests.adapters.HTTPAdapter, "send", side_effect=AssertionError("token sent")),
    ):
        with pytest.raises(gateway.GatewayListenerNotOwnedError, match="held by another account"):
            client.status()
    check.assert_called_once_with("127.0.0.1", 18960)


def test_client_without_a_token_still_requires_listener_proof() -> None:
    client = gateway.OrchestratorClient(host="127.0.0.1", port=18960)
    with (
        mock.patch.object(gateway, "_unproven_per_user_gateway_target", return_value="listener not proven") as check,
        mock.patch.object(requests.adapters.HTTPAdapter, "send", side_effect=AssertionError("request sent")),
    ):
        with pytest.raises(gateway.GatewayListenerNotOwnedError, match="listener not proven"):
            client.health()
    check.assert_called_once_with("127.0.0.1", 18960)


def test_doctor_health_refuses_an_unverified_gateway_before_reading_its_decision() -> None:
    from defenseclaw.commands import cmd_doctor

    received: list[str] = []

    class Peer(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            received.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"audit_store":{"state":"replaced"}}')

        def log_message(self, *_args) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Peer)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        cfg = SimpleNamespace(gateway=SimpleNamespace(api_port=server.server_port))
        with (
            mock.patch.object(cmd_doctor, "_gateway_api_host", return_value="127.0.0.1"),
            mock.patch.object(
                cmd_doctor,
                "_trusted_gateway_listener",
                return_value=SimpleNamespace(trusted=False, detail="listener belongs to another account"),
            ),
        ):
            assert cmd_doctor._live_gateway_health(cfg) is None
        assert received == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_client_requires_positive_gateway_listener_proof_even_when_foreign_probe_is_empty() -> None:
    from defenseclaw import config, upgrade_shim
    from defenseclaw.commands import cmd_doctor

    client = gateway.OrchestratorClient(host="127.0.0.1", port=18960, token="t" * 64)
    cfg = SimpleNamespace(gateway=SimpleNamespace(api_port=18960))
    with (
        mock.patch.object(upgrade_shim, "managed_descriptor", return_value=None),
        mock.patch.object(config, "load", return_value=cfg),
        mock.patch.object(gateway, "gateway_api_client_host", return_value="127.0.0.1"),
        mock.patch.object(
            cmd_doctor,
            "_trusted_gateway_listener",
            return_value=SimpleNamespace(trusted=False, detail="listener not proven"),
        ),
        mock.patch.object(gateway, "foreign_loopback_listener", return_value=""),
        mock.patch.object(requests.adapters.HTTPAdapter, "send", side_effect=AssertionError("token sent")),
    ):
        with pytest.raises(gateway.GatewayListenerNotOwnedError, match="listener not proven"):
            client.status()


def test_client_rejects_a_token_bearing_request_to_a_changed_target() -> None:
    client = gateway.OrchestratorClient(host="127.0.0.1", port=18960, token="t" * 64)
    with (
        mock.patch.object(gateway, "_unproven_per_user_gateway_target", return_value=""),
        mock.patch.object(requests.adapters.HTTPAdapter, "send", side_effect=AssertionError("token sent")),
    ):
        with pytest.raises(gateway.GatewayListenerNotOwnedError, match="target changed"):
            client._session.post(
                "http://127.0.0.1:18961/otlp", headers={"Authorization": "Bearer secret"}, data=b"telemetry"
            )


@pytest.mark.parametrize(
    ("recorded_pid", "process_status", "expected"),
    [
        (0, "denied", "PID 13496, a process of another account"),
        (13496, "denied", ""),
        (0, "ok", ""),
    ],
)
def test_windows_listener_owner(tmp_path, recorded_pid, process_status, expected) -> None:
    """GAP-1343: on Windows another account's listener gets no token either."""
    from defenseclaw import doctor_gateway as evidence

    record = evidence.PIDRecord("ok", pid=recorded_pid) if recorded_pid else evidence.PIDRecord("missing")
    with (
        mock.patch.dict(os.environ, {"DEFENSECLAW_HOME": str(tmp_path)}),
        mock.patch.object(
            evidence, "_windows_listener_evidence", return_value=evidence.ListenerEvidence("ok", pid=13496)
        ),
        mock.patch.object(evidence, "read_pid_record", return_value=record) as read,
        mock.patch.object(evidence, "_windows_process_evidence", return_value=evidence.ProcessEvidence(process_status)),
    ):
        assert gateway._windows_foreign_listener("127.0.0.1", 19000) == expected
    read.assert_called_once_with(os.path.join(str(tmp_path), "gateway.pid"))


def test_saved_port_edit_keeps_the_running_listener_provable_until_restart(tmp_path, monkeypatch) -> None:
    """GAP-0441: `config set gateway.api_port` saved a port the gateway applies at restart.

    The audit fact goes to the running listener (its gateway-api.json bound to
    gateway.pid); the ownership check accepted only the saved port, so every
    such fact was refused before a byte was sent. The running listener is
    accepted with the same listener proof; any other port still is not.
    """
    import json
    import os

    from defenseclaw import config
    from defenseclaw.commands import cmd_doctor
    from defenseclaw.file_permissions import protect_private_file

    (tmp_path / "gateway.pid").write_text(str(os.getpid()), encoding="utf-8")
    record = tmp_path / "gateway-api.json"
    record.write_text(json.dumps({"pid": os.getpid(), "host": "127.0.0.1", "port": 19080}), encoding="utf-8")
    # The gateway publishes the record private to its account: 0600 on POSIX,
    # a protected owner-only DACL on Windows (GAP-2277).
    protect_private_file(record)
    cfg = SimpleNamespace(data_dir=str(tmp_path), gateway=SimpleNamespace(host="127.0.0.1", api_port=19082))
    proven: list[int] = []

    def trusted(_cfg, *, api_port=None, **_kwargs):
        proven.append(api_port)
        return SimpleNamespace(trusted=True, code="trusted", detail="")

    monkeypatch.setattr(gateway, "_managed_connected_verifier_spec", lambda: None)
    monkeypatch.setattr(config, "load", lambda **_kwargs: cfg)
    monkeypatch.setattr(gateway, "gateway_api_client_host", lambda _cfg: "127.0.0.1")
    monkeypatch.setattr(cmd_doctor, "_trusted_gateway_listener", trusted)

    assert gateway._unproven_per_user_gateway_target("127.0.0.1", 19080) == ""
    assert proven == [19080]
    assert gateway._unproven_per_user_gateway_target("127.0.0.1", 19082) == ""
    assert proven == [19080, 19082]
    assert "not the configured gateway endpoint" in gateway._unproven_per_user_gateway_target("127.0.0.1", 19081)
    # A descriptor of another process never vouches for a port.
    record.write_text(json.dumps({"pid": os.getpid() + 1, "host": "127.0.0.1", "port": 19080}), encoding="utf-8")
    protect_private_file(record)
    assert "not the configured gateway endpoint" in gateway._unproven_per_user_gateway_target("127.0.0.1", 19080)
    assert proven == [19080, 19082]


def test_a_running_listener_record_that_is_not_private_vouches_for_no_port(tmp_path, monkeypatch) -> None:
    """GAP-2277: only a record private to this account names the running listener."""
    import json
    import os

    from defenseclaw import config
    from defenseclaw.commands import cmd_doctor

    (tmp_path / "gateway.pid").write_text(str(os.getpid()), encoding="utf-8")
    record = tmp_path / "gateway-api.json"
    record.write_text(json.dumps({"pid": os.getpid(), "host": "127.0.0.1", "port": 19080}), encoding="utf-8")
    if os.name != "nt":
        record.chmod(0o644)
    cfg = SimpleNamespace(data_dir=str(tmp_path), gateway=SimpleNamespace(host="127.0.0.1", api_port=19082))
    monkeypatch.setattr(gateway, "_managed_connected_verifier_spec", lambda: None)
    monkeypatch.setattr(config, "load", lambda **_kwargs: cfg)
    monkeypatch.setattr(gateway, "gateway_api_client_host", lambda _cfg: "127.0.0.1")
    monkeypatch.setattr(
        cmd_doctor, "_trusted_gateway_listener", lambda *_a, **_k: SimpleNamespace(trusted=True, code="", detail="")
    )
    assert "not the configured gateway endpoint" in gateway._unproven_per_user_gateway_target("127.0.0.1", 19080)


def test_listener_proof_checks_the_named_running_port(monkeypatch) -> None:
    from defenseclaw.commands import cmd_doctor

    seen: list[int] = []
    process = SimpleNamespace(trusted=True)
    monkeypatch.setattr(cmd_doctor, "_gateway_api_host", lambda _cfg: "127.0.0.1")
    monkeypatch.setattr(cmd_doctor, "_managed_gateway_process_trust", lambda *_a, **_k: process)
    monkeypatch.setattr(
        cmd_doctor, "_managed_gateway_listener_evidence", lambda port, **_k: seen.append(port) or "listener"
    )
    monkeypatch.setattr(cmd_doctor, "_gateway_listener_trust", lambda proc, listener: cmd_doctor._GatewayTrust("unavailable", "stub"))
    cfg = SimpleNamespace(gateway=SimpleNamespace(api_port=19082))
    cmd_doctor._trusted_gateway_listener(cfg, evidence=object(), platform_name="linux", api_port=19080)
    cmd_doctor._trusted_gateway_listener(cfg, evidence=object(), platform_name="linux")
    assert seen == [19080, 19082]


@pytest.mark.skipif(os.name == "nt", reason="POSIX account semantics")
def test_root_listener_names_the_remedy_and_keeps_the_token_withheld(monkeypatch) -> None:
    from defenseclaw import upgrade_shim
    from defenseclaw.commands import cmd_doctor

    cfg = SimpleNamespace(data_dir="/tmp/defenseclaw-account-home")

    monkeypatch.setattr(upgrade_shim, "managed_descriptor", lambda: None)
    monkeypatch.setattr(
        gateway, "_foreign_loopback_listener_uncached", lambda port, *_a, **_k: "a process of another account"
    )
    monkeypatch.setattr(
        gateway, "_root_gateway_listener_reason",
        lambda port: cmd_doctor.ROOT_GATEWAY_REASON + " " + cmd_doctor._root_gateway_remedy(cfg) if port == 18970 else "",
    )
    problem = gateway.foreign_loopback_listener("127.0.0.1", 18970)
    assert cmd_doctor.ROOT_GATEWAY_REASON in problem
    assert "sudo env DEFENSECLAW_HOME=" in problem
    assert "--api-port" not in problem
    assert "another account" in gateway.foreign_loopback_listener("127.0.0.1", 18980)


@pytest.mark.skipif(os.name == "nt", reason="POSIX account semantics")
def test_root_listener_classification_requires_complete_home_and_endpoint_proof(monkeypatch) -> None:
    from defenseclaw import config
    from defenseclaw.commands import cmd_doctor
    from defenseclaw.enforce import asset_lists

    monkeypatch.setattr(config, "load", lambda **_kwargs: SimpleNamespace())
    monkeypatch.setattr(asset_lists, "is_secure_client", lambda _cfg: False)
    seen: list[int] = []

    def prove(code: str):
        def trust(_cfg, *, api_port=None, **_kwargs):
            seen.append(api_port)
            return SimpleNamespace(code=code, detail="root reason" if code == "root_gateway" else "")
        return trust

    for code, expected in (("root_gateway", "root reason"), ("trusted", ""), ("missing_listener", "")):
        monkeypatch.setattr(cmd_doctor, "_trusted_gateway_listener", prove(code))
        assert gateway._root_gateway_listener_reason(18970) == expected
    assert seen == [18970] * 3

    def unavailable(*_args, **_kwargs):
        raise RuntimeError("config does not load")

    monkeypatch.setattr(cmd_doctor, "_trusted_gateway_listener", unavailable)
    assert gateway._root_gateway_listener_reason(18970) == ""


@pytest.mark.skipif(os.name == "nt" or os.geteuid() == 0, reason="POSIX per-user root listener")
def test_trusted_listener_reclassifies_root_without_trusting_its_token(monkeypatch) -> None:
    from defenseclaw.commands import cmd_doctor
    from defenseclaw.enforce import asset_lists

    monkeypatch.setattr(asset_lists, "is_secure_client", lambda _cfg: False)
    monkeypatch.setattr(cmd_doctor, "_gateway_api_host", lambda _cfg: "127.0.0.1")
    monkeypatch.setattr(cmd_doctor, "_managed_gateway_listener_evidence", lambda *_a, **_k: object())
    record = SimpleNamespace(start_identity="kernel start", data_dir="/home/account/.defenseclaw")
    process = SimpleNamespace(uid=0)
    process_trust = cmd_doctor._GatewayTrust(
        "trusted", "same home", pid=4242, home_bound=True, record=record, process=process
    )
    monkeypatch.setattr(cmd_doctor, "_managed_gateway_process_trust", lambda *_a, **_k: process_trust)
    monkeypatch.setattr(cmd_doctor, "_gateway_listener_trust", lambda *_a, **_k: process_trust)
    cfg = SimpleNamespace(gateway=SimpleNamespace(api_port=18970), deployment_mode="")
    root = cmd_doctor._trusted_gateway_listener(cfg, evidence=object(), platform_name="linux")
    assert root.code == "root_gateway"
    assert not root.trusted
    assert "sudo env DEFENSECLAW_HOME=" in root.detail

    for name, changed in (
        ("own UID", dict(process=SimpleNamespace(uid=os.getuid()))),
        ("missing start identity", dict(record=SimpleNamespace(start_identity="", data_dir=record.data_dir))),
        ("different home", dict(home_bound=False)),
    ):
        process_trust = cmd_doctor._GatewayTrust(
            "trusted", name, pid=4242, home_bound=changed.get("home_bound", True),
            record=changed.get("record", record), process=changed.get("process", process),
        )
        got = cmd_doctor._trusted_gateway_listener(cfg, evidence=object(), platform_name="linux")
        assert got.code == "trusted" and got.trusted, name
    cfg.deployment_mode = "managed_enterprise"
    process_trust = cmd_doctor._GatewayTrust(
        "trusted", "managed", pid=4242, home_bound=True, record=record, process=process
    )
    got = cmd_doctor._trusted_gateway_listener(cfg, evidence=object(), platform_name="linux")
    assert got.trusted


@pytest.mark.skipif(not sys.platform.startswith("linux") or os.geteuid() == 0, reason="Linux per-user root diagnosis")
def test_linux_root_diagnosis_uses_bound_start_identity_when_executable_is_hidden(monkeypatch, tmp_path) -> None:
    from defenseclaw import doctor_gateway
    from defenseclaw.commands import cmd_doctor
    from defenseclaw.enforce import asset_lists

    monkeypatch.setattr(asset_lists, "is_secure_client", lambda _cfg: False)
    monkeypatch.setattr(cmd_doctor, "_process_uid", lambda _pid: 0)
    monkeypatch.setattr(cmd_doctor, "pid_alive", lambda _pid: True)
    monkeypatch.setattr(cmd_doctor, "_linux_root_process_identity_matches", lambda _record: True)
    monkeypatch.setattr(cmd_doctor, "_linux_root_listener_at", lambda _host, _port: True)
    home = str(tmp_path)
    cfg = SimpleNamespace(data_dir=home, deployment_mode="")
    record = doctor_gateway.PIDRecord(
        "ok", pid=4242, executable="/home/account/.local/bin/defenseclaw-gateway",
        data_dir=home, start_identity="kernel start",
    )
    def diagnose(row):
        unavailable = cmd_doctor._GatewayTrust("unavailable", "executable hidden", record=row)
        return cmd_doctor._linux_root_gateway_diagnosis(cfg, unavailable, "127.0.0.1", 18970, "linux")

    root = diagnose(record)
    assert root is not None and root.code == "root_gateway" and not root.trusted
    assert root.pid == 4242 and root.home_bound
    for changed in (
        dict(start_identity=""), dict(data_dir=str(tmp_path / "other")),
        dict(executable="/usr/bin/other"),
    ):
        row = doctor_gateway.PIDRecord(
            "ok", pid=4242, executable=changed.get("executable", record.executable),
            data_dir=changed.get("data_dir", home),
            start_identity=changed.get("start_identity", record.start_identity),
        )
        assert diagnose(row) is None
    monkeypatch.setattr(cmd_doctor, "_linux_root_listener_at", lambda _host, _port: False)
    assert diagnose(record) is None
    monkeypatch.setattr(cmd_doctor, "_linux_root_listener_at", lambda _host, _port: True)
    monkeypatch.setattr(cmd_doctor, "_process_uid", lambda _pid: os.getuid())
    assert diagnose(record) is None
    monkeypatch.setattr(cmd_doctor, "_process_uid", lambda _pid: 0)
    cfg.deployment_mode = "managed_enterprise"
    assert diagnose(record) is None


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux procfs identity")
def test_linux_hidden_executable_identity_uses_kernel_start_generation() -> None:
    from defenseclaw import doctor_gateway
    from defenseclaw.commands import cmd_doctor

    pid = os.getpid()
    with open(f"/proc/{pid}/stat", encoding="ascii") as stream:
        raw = stream.read()
    fields = raw[raw.rfind(")") + 1 :].split()
    with open(f"/proc/{pid}/comm", encoding="ascii") as stream:
        command = stream.read().strip()
    record = doctor_gateway.PIDRecord(
        "ok", pid=pid, executable=f"/opt/defenseclaw/{command}",
        start_identity=fields[19], data_dir="/home/account/.defenseclaw",
    )
    assert cmd_doctor._linux_root_process_identity_matches(record)
    stale = doctor_gateway.PIDRecord(
        "ok", pid=pid, executable=record.executable,
        start_identity="different", data_dir=record.data_dir,
    )
    assert not cmd_doctor._linux_root_process_identity_matches(stale)
@pytest.mark.skipif(os.name == "nt", reason="POSIX account semantics")
def test_doctor_binds_another_accounts_gateway_to_its_own_runtime_record(tmp_path, monkeypatch) -> None:
    """Without a socket table it may read, doctor binds the verified gateway of
    another account to the endpoint through the gateway's own private
    runtime record (gateway-api.json) and a listener that answers there.
    Anything less leaves the listener unproven.
    """
    import json
    import socket
    from types import SimpleNamespace

    from defenseclaw import doctor_gateway as evidence_module
    from defenseclaw.commands import cmd_doctor
    from defenseclaw.file_permissions import protect_private_file

    executable = "/Library/PrivilegedHelperTools/DefenseClawMacGatewayAdmin/uid-501/defenseclaw-gateway"
    pid = os.getpid()  # the records must name a live process
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    pid_file = tmp_path / "gateway.pid"
    pid_file.write_text(
        json.dumps(
            {"pid": pid, "executable": executable, "data_dir": str(tmp_path), "start_identity": "1793776207.630838"}
        ),
        encoding="utf-8",
    )
    protect_private_file(pid_file)
    record = tmp_path / "gateway-api.json"

    def publish(record_pid: int, record_port: int) -> None:
        record.write_text(json.dumps({"pid": record_pid, "host": "127.0.0.1", "port": record_port}), encoding="utf-8")
        protect_private_file(record)

    class Evidence(evidence_module.GatewayEvidence):
        def __init__(self, uid: int) -> None:
            super().__init__(platform_name="darwin")
            self.uid = uid

        def process(self, inspected_pid: int) -> evidence_module.ProcessEvidence:
            return evidence_module.ProcessEvidence(
                "ok",
                pid=inspected_pid,
                executable=executable,
                start_identity="1793776207.630838",
                uid=self.uid,
            )

    cfg = SimpleNamespace(data_dir=str(tmp_path), gateway=SimpleNamespace(api_bind="127.0.0.1", api_port=port))
    monkeypatch.setattr(cmd_doctor, "_gateway_api_host", lambda _cfg: "127.0.0.1")
    monkeypatch.setattr(
        cmd_doctor,
        "_managed_gateway_listener_evidence",
        lambda *_a, **_k: evidence_module.ListenerEvidence("missing", reason="no TCP listener"),
    )

    def prove(uid: int = 0) -> cmd_doctor._GatewayTrust:
        return cmd_doctor._trusted_gateway_listener(cfg, evidence=Evidence(uid), platform_name="darwin")

    try:
        publish(pid, port)
        trust = prove()
        assert (trust.code, trust.pid, trust.trusted) == ("root_gateway", pid, False)
        # This account's own gateway is listed by lsof: no listener means none.
        assert prove(os.getuid()).code == "missing_listener"
        # The record must name this port, and this process.
        publish(pid, port + 1)
        assert prove().code == "missing_listener"
        publish(pid + 1, port)
        assert prove().code == "missing_listener"
        # A record that is not private vouches for nothing.
        publish(pid, port)
        record.chmod(0o644)
        assert prove().code == "missing_listener"
        # And a gateway must answer there.
        protect_private_file(record)
        listener.close()
        assert prove().code == "missing_listener"
    finally:
        listener.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX account semantics")
@pytest.mark.parametrize(
    ("record_host", "target_host", "trusted"),
    [
        ("127.0.0.1", "127.0.0.1", True),
        ("127.0.0.1", "[127.0.0.1]", True),
        # localhost names no listener: it may resolve to the other loopback,
        # where another account can listen on the same port.
        ("localhost", "127.0.0.1", False),
        ("127.0.0.1", "localhost", False),
        ("localhost", "localhost", False),
        ("::1", "127.0.0.1", False),
        ("127.0.0.1", "::1", False),
        ("127.0.0.2", "127.0.0.1", False),
        ("[127.0.0.1]", "127.0.0.1", False),
        ("192.0.2.10", "192.0.2.10", False),
    ],
)
def test_doctor_probes_only_the_exact_ip_the_runtime_record_names(
    tmp_path, monkeypatch, record_host, target_host, trusted
) -> None:
    """PR #1426 review N2: the listener proof for another account's gateway
    connects to the IP literal gateway-api.json names, and only when the
    target is that same IP.
    """
    import json
    import socket
    from types import SimpleNamespace

    from defenseclaw import doctor_gateway as evidence_module
    from defenseclaw.commands import cmd_doctor
    from defenseclaw.file_permissions import protect_private_file

    executable = "/Library/PrivilegedHelperTools/DefenseClawMacGatewayAdmin/uid-501/defenseclaw-gateway"
    pid = os.getpid()
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    pid_file = tmp_path / "gateway.pid"
    pid_file.write_text(
        json.dumps(
            {"pid": pid, "executable": executable, "data_dir": str(tmp_path), "start_identity": "1793776207.630838"}
        ),
        encoding="utf-8",
    )
    protect_private_file(pid_file)
    record = tmp_path / "gateway-api.json"
    record.write_text(json.dumps({"pid": pid, "host": record_host, "port": port}), encoding="utf-8")
    protect_private_file(record)

    class Evidence(evidence_module.GatewayEvidence):
        def __init__(self) -> None:
            super().__init__(platform_name="darwin")

        def process(self, inspected_pid: int) -> evidence_module.ProcessEvidence:
            return evidence_module.ProcessEvidence(
                "ok", pid=inspected_pid, executable=executable, start_identity="1793776207.630838", uid=0
            )

    cfg = SimpleNamespace(data_dir=str(tmp_path), gateway=SimpleNamespace(api_bind=target_host, api_port=port))
    monkeypatch.setattr(cmd_doctor, "_gateway_api_host", lambda _cfg: target_host)
    monkeypatch.setattr(
        cmd_doctor,
        "_managed_gateway_listener_evidence",
        lambda *_a, **_k: evidence_module.ListenerEvidence("missing", reason="no TCP listener"),
    )
    probed: list[tuple] = []
    connect = socket.create_connection

    def recording_connect(address, *args, **kwargs):
        probed.append(tuple(address))
        return connect(address, *args, **kwargs)

    monkeypatch.setattr(cmd_doctor.socket, "create_connection", recording_connect)
    try:
        trust = cmd_doctor._trusted_gateway_listener(cfg, evidence=Evidence(), platform_name="darwin")
    finally:
        listener.close()
    other_account_probes = [address for address in probed if address[1] == port]
    if trusted:
        assert (trust.code, trust.pid, trust.trusted) == ("root_gateway", pid, False)
        assert other_account_probes == [("127.0.0.1", port)]
    else:
        assert trust.trusted is False
        assert other_account_probes == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX account semantics")
def test_runtime_record_is_read_only_when_this_account_or_root_owns_it(tmp_path, monkeypatch) -> None:
    """PR #1426 review N5: like read_pid_record for gateway.pid, a runtime
    record (gateway-api.json, gateway_running_token.json) counts only when
    this account or root wrote it.
    """
    import json

    from defenseclaw import logger
    from defenseclaw.file_permissions import protect_private_file

    pid = os.getpid()
    (tmp_path / "gateway.pid").write_text(str(pid), encoding="utf-8")
    record = tmp_path / "gateway-api.json"
    record.write_text(json.dumps({"pid": pid, "host": "127.0.0.1", "port": 18970}), encoding="utf-8")
    protect_private_file(record)
    real_stat = os.stat
    owner = {"uid": os.geteuid()}

    def stat_with_owner(path, *args, **kwargs):
        result = real_stat(path, *args, **kwargs)
        if os.fspath(path) != str(record):
            return result
        fields = list(result[:10])
        fields[stat.ST_UID] = owner["uid"]
        return os.stat_result(fields)

    monkeypatch.setattr(os, "stat", stat_with_owner)
    another_account = next(uid for uid in range(54321, 54400) if uid not in {0, os.geteuid(), os.getuid()})

    assert logger._running_gateway_record(str(tmp_path), "gateway-api.json") == {
        "pid": pid,
        "host": "127.0.0.1",
        "port": 18970,
    }
    owner["uid"] = 0
    assert logger._running_gateway_record(str(tmp_path), "gateway-api.json") is not None
    owner["uid"] = another_account
    assert logger._running_gateway_record(str(tmp_path), "gateway-api.json") is None
    assert logger._running_gateway_address(str(tmp_path)) is None
