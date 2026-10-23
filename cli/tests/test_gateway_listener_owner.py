"""GAP-1260: the CLI sends no gateway token to another account's listener."""

from __future__ import annotations

import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest import mock

import pytest
import requests
from defenseclaw import gateway


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
                gateway, "_verify_connected_gateway_socket",
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


def test_mac_status_and_doctor_name_a_peer_listener_hidden_from_lsof() -> None:
    from defenseclaw.commands import cmd_doctor

    cfg = SimpleNamespace(gateway=SimpleNamespace(api_port=19081))
    with (
        mock.patch.object(cmd_doctor.sys, "platform", "darwin"),
        mock.patch.object(cmd_doctor, "_gateway_port_holder", return_value=""),
        mock.patch.object(cmd_doctor, "_gateway_api_host", return_value="127.0.0.1"),
        mock.patch.object(gateway, "foreign_loopback_listener", return_value="127.0.0.1:19081 is held by a process of another account"),
    ):
        holder = cmd_doctor._foreign_gateway_port_holder(cfg)
    assert "another account" in holder

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
        mock.patch.object(gateway, "_unproven_per_user_gateway_target", return_value="held by another account") as check,
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


def test_client_requires_positive_gateway_listener_proof_even_when_foreign_probe_is_empty() -> None:
    from defenseclaw import config, upgrade_shim
    from defenseclaw.commands import cmd_doctor

    client = gateway.OrchestratorClient(host="127.0.0.1", port=18960, token="t" * 64)
    cfg = SimpleNamespace(gateway=SimpleNamespace(api_port=18960))
    with (
        mock.patch.object(upgrade_shim, "managed_descriptor", return_value=None),
        mock.patch.object(config, "load", return_value=cfg),
        mock.patch.object(gateway, "gateway_api_client_host", return_value="127.0.0.1"),
        mock.patch.object(cmd_doctor, "_trusted_gateway_listener", return_value=SimpleNamespace(trusted=False, detail="listener not proven")),
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
            client._session.post("http://127.0.0.1:18961/otlp", headers={"Authorization": "Bearer secret"}, data=b"telemetry")


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
        mock.patch.object(evidence, "_windows_listener_evidence", return_value=evidence.ListenerEvidence("ok", pid=13496)),
        mock.patch.object(evidence, "read_pid_record", return_value=record) as read,
        mock.patch.object(evidence, "_windows_process_evidence", return_value=evidence.ProcessEvidence(process_status)),
    ):
        assert gateway._windows_foreign_listener("127.0.0.1", 19000) == expected
    read.assert_called_once_with(os.path.join(str(tmp_path), "gateway.pid"))
