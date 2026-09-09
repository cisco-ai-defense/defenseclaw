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

"""Bind Doctor credential-bearing HTTP probes to the verified gateway peer.

Listener inspection plus a later urllib connect leaves an inspect-to-send
interval: a replacement process can accept the TCP connection and receive the
gateway bearer before authenticated runtime metadata rejects the response.

This module binds after TCP connect and before any request bytes are written.
The connected ESTABLISHED peer must be the inspected PID and start identity.
Failure is closed; the socket is dropped without an HTTP request.
"""

from __future__ import annotations

import ctypes
import http.client
import ipaddress
import os
import socket
import subprocess
import sys
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass

from defenseclaw.doctor_gateway import GatewayEvidence
from defenseclaw.file_permissions import trusted_system_subprocess_env

PeerLookup = Callable[[socket.socket], int]
ProcessLookup = Callable[[int], str]

_LINUX_TCP_ESTABLISHED = "01"
_WINDOWS_TCP_TABLE_OWNER_PID_CONNECTIONS = 4
_WINDOWS_MIB_TCP_STATE_ESTAB = 5
_MAX_PLATFORM_PID = 2_147_483_647


class PeerBindError(Exception):
    """Refuse to send credentials to a peer that is not the verified gateway."""


@dataclass(frozen=True)
class TrustedPeer:
    """Inspected gateway generation that must own the connected socket."""

    pid: int
    start_identity: str

    def __post_init__(self) -> None:
        if type(self.pid) is not int or self.pid <= 0 or self.pid > _MAX_PLATFORM_PID:
            raise PeerBindError("trusted gateway peer PID is invalid")
        identity = self.start_identity.strip()
        if not identity:
            raise PeerBindError("trusted gateway peer start identity is unavailable")
        object.__setattr__(self, "start_identity", identity)


def loopback_bearer_requires_peer(url: str, headers: dict | None) -> bool:
    """Return whether this request would send a loopback bearer credential."""
    if not _authorization_is_bearer(headers):
        return False
    try:
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
    except ValueError:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


def bind_connected_peer(
    sock: socket.socket,
    trusted: TrustedPeer,
    *,
    peer_lookup: PeerLookup | None = None,
    process_lookup: ProcessLookup | None = None,
) -> None:
    """Fail closed unless ``sock`` is owned by ``trusted`` right now."""
    if sock is None:
        raise PeerBindError("refusing to send credentials before the TCP peer exists")
    lookup = peer_lookup or connected_peer_pid
    try:
        peer_pid = lookup(sock)
    except PeerBindError:
        raise
    except OSError as exc:
        raise PeerBindError("connected gateway peer could not be identified") from exc
    if type(peer_pid) is not int or peer_pid <= 0 or peer_pid > _MAX_PLATFORM_PID:
        raise PeerBindError("connected gateway peer PID is invalid")
    if peer_pid != trusted.pid:
        raise PeerBindError("connected peer is not the verified gateway process")
    identity_lookup = process_lookup or process_start_identity
    try:
        start_identity = identity_lookup(peer_pid)
    except PeerBindError:
        raise
    except OSError as exc:
        raise PeerBindError("connected gateway peer start identity could not be queried") from exc
    if not isinstance(start_identity, str) or not start_identity.strip():
        raise PeerBindError("connected gateway peer start identity is unavailable")
    if start_identity.strip() != trusted.start_identity:
        raise PeerBindError("connected peer is not the verified gateway generation")


def connected_peer_pid(sock: socket.socket) -> int:
    """Return the PID that owns the ESTABLISHED remote endpoint of ``sock``."""
    platform_name = "win32" if os.name == "nt" else sys.platform
    if platform_name == "win32":
        return _windows_established_peer_pid(sock)
    if platform_name.startswith("linux"):
        return _linux_established_peer_pid(sock)
    return _lsof_established_peer_pid(sock)


def process_start_identity(pid: int) -> str:
    """Read the live start identity for one connected peer PID."""
    platform_name = "win32" if os.name == "nt" else sys.platform
    evidence = GatewayEvidence(platform_name=platform_name).process(pid)
    if evidence.status != "ok" or not evidence.start_identity.strip():
        raise PeerBindError("connected gateway peer start identity is unavailable")
    return evidence.start_identity.strip()


def socket_endpoints(
    sock: socket.socket,
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int, ipaddress.IPv4Address | ipaddress.IPv6Address, int]:
    """Return canonical (local_ip, local_port, remote_ip, remote_port)."""
    try:
        local = sock.getsockname()
        remote = sock.getpeername()
    except OSError as exc:
        raise PeerBindError("connected socket endpoints are unavailable") from exc
    return (
        _canonical_ip(local[0]),
        int(local[1]),
        _canonical_ip(remote[0]),
        int(remote[1]),
    )


def linux_established_peer_pid_from_proc(
    local_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    local_port: int,
    remote_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    remote_port: int,
    *,
    proc_root: str,
) -> int:
    """Resolve an ESTABLISHED Linux peer from a (possibly fake) proc tree."""
    local_ip = _canonical_ip(local_ip)
    remote_ip = _canonical_ip(remote_ip)
    matching_inodes: set[str] = set()
    table_found = False
    for table_name in ("tcp", "tcp6"):
        table_path = os.path.join(proc_root, "net", table_name)
        try:
            with open(table_path, encoding="ascii") as table:
                rows = table.readlines()[1:]
            table_found = True
        except FileNotFoundError:
            continue
        except (OSError, UnicodeError) as exc:
            raise PeerBindError("Linux connection table could not be read") from exc
        for row in rows:
            parsed = _linux_established_row(row, ipv6=table_name == "tcp6")
            if parsed is None:
                continue
            row_local_ip, row_local_port, row_remote_ip, row_remote_port, inode = parsed
            if (
                row_local_port == remote_port
                and row_remote_port == local_port
                and row_local_ip == remote_ip
                and row_remote_ip == local_ip
            ):
                matching_inodes.add(inode)
    if not table_found:
        raise PeerBindError("Linux connection tables are unavailable")
    if not matching_inodes:
        raise PeerBindError("connected gateway peer is not present in the ESTABLISHED table")
    return _linux_socket_inode_owner(matching_inodes, proc_root=proc_root)


def windows_established_peer_pid_from_rows(
    rows: list[tuple[int, str, int, str, int, int]],
    local_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    local_port: int,
    remote_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    remote_port: int,
) -> int:
    """Resolve an ESTABLISHED Windows peer from already-decoded table rows.

    Each row is ``(state, local_addr, local_port, remote_addr, remote_port, pid)``.
    """
    matching: set[int] = set()
    for state, row_local_addr, row_local_port, row_remote_addr, row_remote_port, pid in rows:
        if state != _WINDOWS_MIB_TCP_STATE_ESTAB:
            continue
        if type(pid) is not int or pid <= 0 or pid > _MAX_PLATFORM_PID:
            continue
        try:
            row_local_ip = ipaddress.ip_address(row_local_addr)
            row_remote_ip = ipaddress.ip_address(row_remote_addr)
        except ValueError:
            continue
        if (
            row_local_port == remote_port
            and row_remote_port == local_port
            and row_local_ip == remote_ip
            and row_remote_ip == local_ip
        ):
            matching.add(pid)
    if len(matching) != 1:
        raise PeerBindError("connected gateway peer could not be uniquely identified")
    return next(iter(matching))


def lsof_established_peer_pid_from_output(
    stdout: str,
    local_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    local_port: int,
    remote_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    remote_port: int,
) -> int:
    """Resolve an ESTABLISHED macOS/lsof peer from machine-readable output."""
    matching: set[int] = set()
    current_pid = 0
    for raw_line in stdout.splitlines():
        if raw_line.startswith("p"):
            try:
                current_pid = int(raw_line[1:])
            except ValueError:
                current_pid = 0
            continue
        if not raw_line.startswith("n") or current_pid <= 0:
            continue
        if _lsof_established_name_matches(
            raw_line[1:],
            local_ip,
            local_port,
            remote_ip,
            remote_port,
        ):
            matching.add(current_pid)
    if len(matching) != 1:
        raise PeerBindError("connected gateway peer could not be uniquely identified")
    return next(iter(matching))


class PeerBoundHTTPConnection(http.client.HTTPConnection):
    """HTTP connection that binds the TCP peer before writing a request."""

    def __init__(
        self,
        host: str,
        port: int | None = None,
        timeout: float = socket._GLOBAL_DEFAULT_TIMEOUT,
        source_address: tuple[str, int] | None = None,
        blocksize: int = 8192,
        *,
        trusted_peer: TrustedPeer,
        peer_lookup: PeerLookup | None = None,
        process_lookup: ProcessLookup | None = None,
    ) -> None:
        super().__init__(
            host,
            port,
            timeout=timeout,
            source_address=source_address,
            blocksize=blocksize,
        )
        self._trusted_peer = trusted_peer
        self._peer_lookup = peer_lookup
        self._process_lookup = process_lookup
        self._peer_bound = False

    def connect(self) -> None:
        super().connect()
        try:
            bind_connected_peer(
                self.sock,
                self._trusted_peer,
                peer_lookup=self._peer_lookup,
                process_lookup=self._process_lookup,
            )
        except Exception:
            self._close_unbound_socket()
            raise
        self._peer_bound = True

    def send(self, data) -> None:
        if self.sock is None:
            self.connect()
        if not self._peer_bound:
            self._close_unbound_socket()
            raise PeerBindError("refusing to send credentials before peer bind")
        super().send(data)

    def _close_unbound_socket(self) -> None:
        sock = self.sock
        self.sock = None
        self._peer_bound = False
        if sock is None:
            return
        try:
            sock.close()
        except OSError:
            pass


class PeerBoundHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that binds the TCP peer before request bytes."""

    def __init__(
        self,
        host: str,
        port: int | None = None,
        timeout: float = socket._GLOBAL_DEFAULT_TIMEOUT,
        source_address: tuple[str, int] | None = None,
        context=None,
        blocksize: int = 8192,
        *,
        trusted_peer: TrustedPeer,
        peer_lookup: PeerLookup | None = None,
        process_lookup: ProcessLookup | None = None,
    ) -> None:
        super().__init__(
            host,
            port,
            timeout=timeout,
            source_address=source_address,
            context=context,
            blocksize=blocksize,
        )
        self._trusted_peer = trusted_peer
        self._peer_lookup = peer_lookup
        self._process_lookup = process_lookup
        self._peer_bound = False

    def connect(self) -> None:
        super().connect()
        try:
            bind_connected_peer(
                self.sock,
                self._trusted_peer,
                peer_lookup=self._peer_lookup,
                process_lookup=self._process_lookup,
            )
        except Exception:
            self._close_unbound_socket()
            raise
        self._peer_bound = True

    def send(self, data) -> None:
        if self.sock is None:
            self.connect()
        if not self._peer_bound:
            self._close_unbound_socket()
            raise PeerBindError("refusing to send credentials before peer bind")
        super().send(data)

    def _close_unbound_socket(self) -> None:
        sock = self.sock
        self.sock = None
        self._peer_bound = False
        if sock is None:
            return
        try:
            sock.close()
        except OSError:
            pass


class _PeerBoundHTTPHandler(urllib.request.HTTPHandler):
    def __init__(
        self,
        trusted_peer: TrustedPeer,
        *,
        peer_lookup: PeerLookup | None = None,
        process_lookup: ProcessLookup | None = None,
    ) -> None:
        super().__init__()
        self._trusted_peer = trusted_peer
        self._peer_lookup = peer_lookup
        self._process_lookup = process_lookup

    def http_open(self, req):
        return self.do_open(self._connection, req)

    def _connection(self, *args, **kwargs):
        return PeerBoundHTTPConnection(
            *args,
            **kwargs,
            trusted_peer=self._trusted_peer,
            peer_lookup=self._peer_lookup,
            process_lookup=self._process_lookup,
        )


class _PeerBoundHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(
        self,
        trusted_peer: TrustedPeer,
        *,
        peer_lookup: PeerLookup | None = None,
        process_lookup: ProcessLookup | None = None,
        context=None,
    ) -> None:
        super().__init__(context=context)
        self._trusted_peer = trusted_peer
        self._peer_lookup = peer_lookup
        self._process_lookup = process_lookup

    def https_open(self, req):
        return self.do_open(self._connection, req, context=self._context)

    def _connection(self, *args, **kwargs):
        return PeerBoundHTTPSConnection(
            *args,
            **kwargs,
            trusted_peer=self._trusted_peer,
            peer_lookup=self._peer_lookup,
            process_lookup=self._process_lookup,
        )


def peer_bound_handlers(
    trusted_peer: TrustedPeer,
    *,
    peer_lookup: PeerLookup | None = None,
    process_lookup: ProcessLookup | None = None,
    ssl_context=None,
) -> list[urllib.request.BaseHandler]:
    """Return HTTP/HTTPS handlers that bind before writing credentials."""
    return [
        _PeerBoundHTTPHandler(
            trusted_peer,
            peer_lookup=peer_lookup,
            process_lookup=process_lookup,
        ),
        _PeerBoundHTTPSHandler(
            trusted_peer,
            peer_lookup=peer_lookup,
            process_lookup=process_lookup,
            context=ssl_context,
        ),
    ]


def _authorization_is_bearer(headers: dict | None) -> bool:
    for key, value in (headers or {}).items():
        if str(key).lower() == "authorization" and str(value).lower().startswith("bearer "):
            return True
    return False


def _canonical_ip(value: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as exc:
        raise PeerBindError("connected socket address is not an IP literal") from exc
    if parsed.version == 6 and parsed.ipv4_mapped is not None:
        return parsed.ipv4_mapped
    return parsed


def _linux_established_peer_pid(sock: socket.socket) -> int:
    local_ip, local_port, remote_ip, remote_port = socket_endpoints(sock)
    return linux_established_peer_pid_from_proc(
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        proc_root="/proc",
    )


_LinuxEndpoint = ipaddress.IPv4Address | ipaddress.IPv6Address


def _linux_established_row(
    row: str,
    *,
    ipv6: bool,
) -> tuple[_LinuxEndpoint, int, _LinuxEndpoint, int, str] | None:
    fields = row.split()
    if len(fields) < 10 or fields[3] != _LINUX_TCP_ESTABLISHED:
        return None
    try:
        local_ip, local_port = _linux_hex_endpoint(fields[1], ipv6=ipv6)
        remote_ip, remote_port = _linux_hex_endpoint(fields[2], ipv6=ipv6)
    except ValueError:
        return None
    inode = fields[9]
    if not inode.isdigit():
        return None
    return local_ip, local_port, remote_ip, remote_port, inode


def _linux_hex_endpoint(
    field: str,
    *,
    ipv6: bool,
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]:
    raw_address, separator, raw_port = field.rpartition(":")
    if not separator:
        raise ValueError("missing address/port separator")
    port = int(raw_port, 16)
    packed = bytes.fromhex(raw_address)
    if ipv6:
        network_bytes = b"".join(packed[index : index + 4][::-1] for index in range(0, len(packed), 4))
        return _canonical_ip(ipaddress.ip_address(network_bytes)), port
    return _canonical_ip(ipaddress.ip_address(packed[::-1])), port


def _linux_socket_inode_owner(inodes: set[str], *, proc_root: str) -> int:
    owners_by_inode: dict[str, set[int]] = {inode: set() for inode in inodes}
    try:
        process_entries = list(os.scandir(proc_root))
    except OSError as exc:
        raise PeerBindError("Linux process descriptors could not be enumerated") from exc
    for process_entry in process_entries:
        if not process_entry.name.isdigit():
            continue
        pid = int(process_entry.name)
        if not 0 < pid <= _MAX_PLATFORM_PID:
            continue
        try:
            descriptors = os.scandir(os.path.join(process_entry.path, "fd"))
        except OSError:
            continue
        with descriptors:
            for descriptor in descriptors:
                try:
                    target = os.readlink(descriptor.path)
                except OSError:
                    continue
                if target.startswith("socket:[") and target.endswith("]"):
                    inode = target[8:-1]
                    if inode in owners_by_inode:
                        owners_by_inode[inode].add(pid)
    if any(not owners for owners in owners_by_inode.values()):
        raise PeerBindError("connected gateway peer owner could not be resolved")
    if any(len(owners) > 1 for owners in owners_by_inode.values()):
        raise PeerBindError("connected gateway peer is ambiguously owned")
    owners = {next(iter(inode_owners)) for inode_owners in owners_by_inode.values()}
    if len(owners) != 1:
        raise PeerBindError("connected gateway peer is ambiguously owned")
    return next(iter(owners))


def _windows_established_peer_pid(sock: socket.socket) -> int:  # pragma: no cover - native Windows
    from ctypes import wintypes

    local_ip, local_port, remote_ip, remote_port = socket_endpoints(sock)
    iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
    get_table = iphlpapi.GetExtendedTcpTable
    get_table.argtypes = (
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.ULONG),
        wintypes.BOOL,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
    )
    get_table.restype = wintypes.DWORD
    error_insufficient_buffer = 122

    class TCP4Row(ctypes.Structure):
        _fields_ = [
            ("state", wintypes.DWORD),
            ("local_addr", wintypes.DWORD),
            ("local_port", wintypes.DWORD),
            ("remote_addr", wintypes.DWORD),
            ("remote_port", wintypes.DWORD),
            ("pid", wintypes.DWORD),
        ]

    class TCP6Row(ctypes.Structure):
        _fields_ = [
            ("local_addr", ctypes.c_ubyte * 16),
            ("local_scope", wintypes.DWORD),
            ("local_port", wintypes.DWORD),
            ("remote_addr", ctypes.c_ubyte * 16),
            ("remote_scope", wintypes.DWORD),
            ("remote_port", wintypes.DWORD),
            ("state", wintypes.DWORD),
            ("pid", wintypes.DWORD),
        ]

    family = socket.AF_INET if local_ip.version == 4 else socket.AF_INET6
    row_type = TCP4Row if family == socket.AF_INET else TCP6Row
    size = wintypes.ULONG(0)
    result = get_table(
        None,
        ctypes.byref(size),
        False,
        family,
        _WINDOWS_TCP_TABLE_OWNER_PID_CONNECTIONS,
        0,
    )
    if result not in (0, error_insufficient_buffer) or not size.value:
        raise PeerBindError("Windows connection table could not be queried")
    buffer = ctypes.create_string_buffer(size.value)
    result = get_table(
        buffer,
        ctypes.byref(size),
        False,
        family,
        _WINDOWS_TCP_TABLE_OWNER_PID_CONNECTIONS,
        0,
    )
    if result == error_insufficient_buffer and size.value > len(buffer):
        buffer = ctypes.create_string_buffer(size.value)
        result = get_table(
            buffer,
            ctypes.byref(size),
            False,
            family,
            _WINDOWS_TCP_TABLE_OWNER_PID_CONNECTIONS,
            0,
        )
    if result != 0:
        raise PeerBindError("Windows connection table could not be queried")
    count = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD)).contents.value
    offset = ctypes.sizeof(wintypes.DWORD)
    alignment = ctypes.alignment(row_type)
    offset = (offset + alignment - 1) & ~(alignment - 1)
    rows: list[tuple[int, str, int, str, int, int]] = []
    for index in range(count):
        row = row_type.from_buffer_copy(buffer, offset + index * ctypes.sizeof(row_type))
        try:
            if family == socket.AF_INET:
                local_packed = int(row.local_addr).to_bytes(4, byteorder=sys.byteorder)
                remote_packed = int(row.remote_addr).to_bytes(4, byteorder=sys.byteorder)
            else:
                local_packed = bytes(row.local_addr)
                remote_packed = bytes(row.remote_addr)
            rows.append(
                (
                    int(row.state),
                    socket.inet_ntop(family, local_packed),
                    socket.ntohs(row.local_port & 0xFFFF),
                    socket.inet_ntop(family, remote_packed),
                    socket.ntohs(row.remote_port & 0xFFFF),
                    int(row.pid),
                )
            )
        except (OSError, OverflowError, ValueError):
            continue
    return windows_established_peer_pid_from_rows(
        rows,
        local_ip,
        local_port,
        remote_ip,
        remote_port,
    )


def _lsof_established_peer_pid(sock: socket.socket) -> int:
    local_ip, local_port, remote_ip, remote_port = socket_endpoints(sock)
    lsof_path = trusted_lsof_path()
    if not lsof_path:
        raise PeerBindError("trusted lsof binary is unavailable")
    selector = lsof_tcp_selector(local_ip, local_port)
    try:
        proc = subprocess.run(
            [
                lsof_path,
                "-nP",
                "-a",
                selector,
                "-sTCP:ESTABLISHED",
                "-Fpn",
            ],
            capture_output=True,
            text=True,
            shell=False,
            stdin=subprocess.DEVNULL,
            env=trusted_system_subprocess_env(),
            timeout=2.0,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        raise PeerBindError("lsof connection inspection failed") from exc
    if proc.returncode not in {0, 1}:
        raise PeerBindError("lsof connection inspection failed")
    return lsof_established_peer_pid_from_output(
        proc.stdout,
        local_ip,
        local_port,
        remote_ip,
        remote_port,
    )


def lsof_tcp_selector(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    port: int,
) -> str:
    """Return an lsof ``-iTCP`` selector with IPv6 literals in brackets."""
    host = str(ip)
    if ip.version == 6:
        host = f"[{host}]"
    return f"-iTCP@{host}:{port}"


def _lsof_established_name_matches(
    endpoint: str,
    local_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    local_port: int,
    remote_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    remote_port: int,
) -> bool:
    name = endpoint.strip()
    if "->" not in name:
        return False
    left, right = name.split("->", 1)
    parsed_local = _lsof_endpoint(left)
    parsed_remote = _lsof_endpoint(right)
    if parsed_local is None or parsed_remote is None:
        return False
    return parsed_local == (remote_ip, remote_port) and parsed_remote == (local_ip, local_port)


def _lsof_endpoint(
    value: str,
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int] | None:
    address, separator, raw_port = value.strip().strip("[]").rpartition(":")
    if not separator:
        return None
    try:
        return ipaddress.ip_address(address.strip("[]")), int(raw_port)
    except ValueError:
        return None


def trusted_lsof_path() -> str:
    for candidate in ("/usr/sbin/lsof", "/usr/bin/lsof"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return ""
