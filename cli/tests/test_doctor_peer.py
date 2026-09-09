# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Replacement-race coverage for Doctor peer-bound credential probes."""

from __future__ import annotations

import http.server
import ipaddress
import os
import ssl
import threading
from pathlib import Path

import pytest
from defenseclaw.commands.cmd_doctor import _http_probe
from defenseclaw.doctor_peer import (
    PeerBindError,
    TrustedPeer,
    bind_connected_peer,
    linux_established_peer_pid_from_proc,
    loopback_bearer_requires_peer,
    lsof_established_peer_pid_from_output,
    lsof_tcp_selector,
    peer_bound_handlers,
    windows_established_peer_pid_from_rows,
)

_TOKEN = "peer-bind-token-must-not-render"


def test_trusted_peer_requires_positive_pid_and_start_identity() -> None:
    with pytest.raises(PeerBindError):
        TrustedPeer(pid=0, start_identity="start-1")
    with pytest.raises(PeerBindError):
        TrustedPeer(pid=4242, start_identity="  ")


def test_loopback_bearer_requires_peer_but_remote_and_non_bearer_do_not() -> None:
    assert loopback_bearer_requires_peer(
        "http://127.0.0.1:18790/status",
        {"Authorization": f"Bearer {_TOKEN}"},
    )
    assert loopback_bearer_requires_peer(
        "http://localhost:18790/status",
        {"Authorization": f"Bearer {_TOKEN}"},
    )
    assert not loopback_bearer_requires_peer(
        "http://127.0.0.1:18790/status",
        {"Authorization": f"Splunk {_TOKEN}"},
    )
    assert not loopback_bearer_requires_peer(
        "https://api.openai.com/v1/models",
        {"Authorization": f"Bearer {_TOKEN}"},
    )


def test_bind_connected_peer_rejects_pid_and_generation_mismatch() -> None:
    trusted = TrustedPeer(pid=4242, start_identity="start-1")
    with pytest.raises(PeerBindError, match="verified gateway process"):
        bind_connected_peer(
            object(),  # type: ignore[arg-type]
            trusted,
            peer_lookup=lambda _sock: 4243,
            process_lookup=lambda _pid: "start-1",
        )
    with pytest.raises(PeerBindError, match="verified gateway generation"):
        bind_connected_peer(
            object(),  # type: ignore[arg-type]
            trusted,
            peer_lookup=lambda _sock: 4242,
            process_lookup=lambda _pid: "start-2",
        )
    with pytest.raises(PeerBindError, match="start identity is unavailable"):
        bind_connected_peer(
            object(),  # type: ignore[arg-type]
            trusted,
            peer_lookup=lambda _sock: 4242,
            process_lookup=lambda _pid: "",
        )


def test_linux_established_peer_pid_from_fake_proc(tmp_path: Path) -> None:
    local_ip = ipaddress.ip_address("127.0.0.1")
    remote_ip = ipaddress.ip_address("127.0.0.1")
    local_port = 54321
    remote_port = 18790
    proc_root = tmp_path / "proc"
    net = proc_root / "net"
    net.mkdir(parents=True)
    (proc_root / "4242" / "fd").mkdir(parents=True)
    (proc_root / "9" / "fd").mkdir(parents=True)
    (net / "tcp").write_text(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        f"   0: 0100007F:{remote_port:04X} 0100007F:{local_port:04X} 01 00000000:00000000 00:00000000 00000000     0        0 99 1 0000000000000000 20 0 0 1 0\n",
        encoding="ascii",
    )
    os.symlink("socket:[99]", proc_root / "4242" / "fd" / "3")
    os.symlink("socket:[8]", proc_root / "9" / "fd" / "3")

    assert (
        linux_established_peer_pid_from_proc(
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            proc_root=str(proc_root),
        )
        == 4242
    )


def test_linux_tcp6_mapped_loopback_matches_ipv4_endpoints(tmp_path: Path) -> None:
    proc_root = tmp_path / "proc"
    (proc_root / "net").mkdir(parents=True)
    (proc_root / "4242" / "fd").mkdir(parents=True)
    (proc_root / "net" / "tcp").write_text(
        "  sl  local_address rem_address   st inode\n",
        encoding="ascii",
    )
    (proc_root / "net" / "tcp6").write_text(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 0000000000000000FFFF00000100007F:4966 "
        "0000000000000000FFFF00000100007F:D431 01 00000000:00000000 "
        "00:00000000 00000000     0        0 99 1 0000000000000000 20 0 0 1 0\n",
        encoding="ascii",
    )
    os.symlink("socket:[99]", proc_root / "4242" / "fd" / "3")

    assert (
        linux_established_peer_pid_from_proc(
            ipaddress.ip_address("127.0.0.1"),
            54321,
            ipaddress.ip_address("127.0.0.1"),
            18790,
            proc_root=str(proc_root),
        )
        == 4242
    )


def test_linux_established_peer_pid_fails_closed_when_missing(tmp_path: Path) -> None:
    proc_root = tmp_path / "proc"
    (proc_root / "net").mkdir(parents=True)
    (proc_root / "net" / "tcp").write_text(
        "  sl  local_address rem_address   st inode\n",
        encoding="ascii",
    )
    with pytest.raises(PeerBindError, match="ESTABLISHED"):
        linux_established_peer_pid_from_proc(
            ipaddress.ip_address("127.0.0.1"),
            1,
            ipaddress.ip_address("127.0.0.1"),
            2,
            proc_root=str(proc_root),
        )


def test_windows_established_rows_require_unique_owner() -> None:
    local_ip = ipaddress.ip_address("127.0.0.1")
    remote_ip = ipaddress.ip_address("127.0.0.1")
    rows = [
        (5, "127.0.0.1", 18790, "127.0.0.1", 54321, 4242),
        (2, "127.0.0.1", 18790, "0.0.0.0", 0, 7),
    ]
    assert (
        windows_established_peer_pid_from_rows(rows, local_ip, 54321, remote_ip, 18790)
        == 4242
    )
    with pytest.raises(PeerBindError, match="uniquely identified"):
        windows_established_peer_pid_from_rows(
            [
                (5, "127.0.0.1", 18790, "127.0.0.1", 54321, 4242),
                (5, "127.0.0.1", 18790, "127.0.0.1", 54321, 4243),
            ],
            local_ip,
            54321,
            remote_ip,
            18790,
        )


def test_lsof_tcp_selector_brackets_ipv6_literals() -> None:
    assert lsof_tcp_selector(ipaddress.ip_address("127.0.0.1"), 18790) == "-iTCP@127.0.0.1:18790"
    assert lsof_tcp_selector(ipaddress.ip_address("::1"), 18790) == "-iTCP@[::1]:18790"


def test_https_handler_forwards_ssl_context() -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    handler = peer_bound_handlers(
        TrustedPeer(pid=4242, start_identity="start-1"),
        ssl_context=context,
    )[1]
    captured: dict[str, object] = {}

    def fake_do_open(http_class, _req, **kwargs):
        captured["kwargs"] = kwargs
        captured["connection"] = http_class("127.0.0.1", 443, **kwargs)
        return object()

    handler.do_open = fake_do_open  # type: ignore[method-assign]
    assert handler.https_open(object()) is not None
    assert captured["kwargs"] == {"context": context}
    assert getattr(captured["connection"], "_context") is context


def test_lsof_established_output_selects_gateway_side() -> None:
    stdout = (
        "p111\n"
        "n127.0.0.1:54321->127.0.0.1:18790\n"
        "p4242\n"
        "n127.0.0.1:18790->127.0.0.1:54321\n"
    )
    assert (
        lsof_established_peer_pid_from_output(
            stdout,
            ipaddress.ip_address("127.0.0.1"),
            54321,
            ipaddress.ip_address("127.0.0.1"),
            18790,
        )
        == 4242
    )


class _RecordingHandler(http.server.BaseHTTPRequestHandler):
    received_authorization: list[str] = []

    def do_GET(self) -> None:
        self.received_authorization.append(self.headers.get("Authorization", ""))
        body = b'{"runtime":{"pid":4242}}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:
        return


def _serve() -> tuple[http.server.HTTPServer, threading.Thread]:
    _RecordingHandler.received_authorization = []
    server = http.server.HTTPServer(("127.0.0.1", 0), _RecordingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_http_probe_refuses_loopback_bearer_without_trusted_peer() -> None:
    server, thread = _serve()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/status"
        code, body = _http_probe(
            url,
            headers={"Authorization": f"Bearer {_TOKEN}"},
            timeout=2.0,
            bypass_proxy=True,
        )
        assert code == 0
        assert "before peer bind" in body
        assert _RecordingHandler.received_authorization == []
        assert _TOKEN not in body
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_http_probe_does_not_send_bearer_to_replaced_peer() -> None:
    server, thread = _serve()
    trusted = TrustedPeer(pid=4242, start_identity="start-1")
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/status"
        code, body = _http_probe(
            url,
            headers={"Authorization": f"Bearer {_TOKEN}"},
            timeout=2.0,
            bypass_proxy=True,
            trusted_peer=trusted,
            peer_lookup=lambda _sock: 9999,
            process_lookup=lambda _pid: "start-1",
        )
        assert code == 0
        assert "verified gateway process" in body
        assert _RecordingHandler.received_authorization == []
        assert _TOKEN not in body
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_http_probe_sends_bearer_only_after_matching_peer_bind() -> None:
    server, thread = _serve()
    trusted = TrustedPeer(pid=4242, start_identity="start-1")
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/status"
        code, body = _http_probe(
            url,
            headers={"Authorization": f"Bearer {_TOKEN}"},
            timeout=2.0,
            bypass_proxy=True,
            trusted_peer=trusted,
            peer_lookup=lambda _sock: 4242,
            process_lookup=lambda _pid: "start-1",
        )
        assert code == 200, body
        assert _RecordingHandler.received_authorization == [f"Bearer {_TOKEN}"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
