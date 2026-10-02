"""GAP-1260: the CLI sends no gateway token to another account's listener."""

from __future__ import annotations

import os
from unittest import mock

import pytest
import requests
from defenseclaw import gateway

_HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"


def _row(addr: str, uid: int) -> str:
    return f"   0: {addr}:4A10 00000000:0000 0A 00000000:00000000 00:00000000 00000000 {uid:5d}        0 4242 1\n"


@pytest.mark.parametrize(
    ("tcp", "tcp6", "expected"),
    [
        (_row("0100007F", 1009), "", "uid 1009"),
        ("", _row("00000000000000000000000001000000", 1009), "uid 1009"),
        (_row("0100007F", 1000), "", ""),
        (_row("0500000A", 1009), "", ""),
        ("", "", ""),
    ],
)
def test_linux_listener_owner(tmp_path, tcp, tcp6, expected) -> None:
    (tmp_path / "tcp").write_text(_HEADER + tcp, encoding="ascii")
    (tmp_path / "tcp6").write_text(_HEADER + tcp6, encoding="ascii")
    with mock.patch.object(gateway.sys, "platform", "linux"), mock.patch.object(gateway.os, "getuid", return_value=1000):
        problem = gateway._foreign_loopback_listener_uncached(18960, str(tmp_path))
    if expected:
        assert expected in problem
    else:
        assert problem == ""


def test_client_refuses_to_send_its_token_to_a_foreign_listener() -> None:
    client = gateway.OrchestratorClient(host="127.0.0.1", port=18960, token="t" * 64)
    with (
        mock.patch.object(gateway, "foreign_loopback_listener", return_value="held by another account") as check,
        mock.patch.object(requests.adapters.HTTPAdapter, "send", side_effect=AssertionError("token sent")),
    ):
        with pytest.raises(gateway.GatewayListenerNotOwnedError, match="held by another account"):
            client.status()
    check.assert_called_once_with("127.0.0.1", 18960)


def test_client_without_a_token_skips_the_check() -> None:
    client = gateway.OrchestratorClient(host="127.0.0.1", port=18960)
    response = requests.Response()
    response.status_code = 200
    response._content = b"{}"
    with (
        mock.patch.object(gateway, "foreign_loopback_listener", side_effect=AssertionError("checked")),
        mock.patch.object(requests.adapters.HTTPAdapter, "send", return_value=response),
    ):
        assert client.health() == {}


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
