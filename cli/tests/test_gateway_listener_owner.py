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


@pytest.mark.skipif(os.name == "nt", reason="per-user listener ownership is checked on Linux and macOS")
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
