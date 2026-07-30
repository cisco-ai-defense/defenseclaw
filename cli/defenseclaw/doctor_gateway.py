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

"""Injectable, native evidence collectors for Doctor gateway diagnostics.

This module deliberately returns small status objects rather than rendering
diagnostics.  Tests can inject a fake collector on any host, while the real
Windows collector uses read-only, least-privilege APIs and never reads process
memory or environment blocks.
"""

from __future__ import annotations

import ctypes
import ipaddress
import json
import ntpath
import os
import posixpath
import socket
import stat
import sys
from dataclasses import dataclass
from typing import Literal

from defenseclaw.file_permissions import (
    UnsafePathError,
    open_regular_file_no_follow,
    read_regular_file_no_follow,
)
from defenseclaw.safety import is_symlink

EvidenceStatus = Literal[
    "ok",
    "missing",
    "malformed",
    "denied",
    "ambiguous",
    "unavailable",
]
GATEWAY_PROCESS_NAMES = frozenset({"defenseclaw-gateway", "defenseclaw-gateway.exe"})
MAX_PLATFORM_PID = 2_147_483_647
_MAX_PID_RECORD_BYTES = 16 * 1024
_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


@dataclass(frozen=True)
class PIDRecord:
    status: EvidenceStatus
    pid: int = 0
    executable: str = ""
    start_identity: str = ""
    start_time: str = ""
    data_dir: str = ""
    reason: str = ""


@dataclass(frozen=True)
class ProcessEvidence:
    status: EvidenceStatus
    pid: int = 0
    executable: str = ""
    start_identity: str = ""
    reason: str = ""


@dataclass(frozen=True)
class ListenerEvidence:
    status: EvidenceStatus
    pid: int = 0
    reason: str = ""


def canonical_path(path: str) -> str:
    """Return a comparison-only canonical path without exposing it."""
    try:
        normalized = os.path.realpath(os.path.abspath(path))
    except (OSError, ValueError):
        return ""
    return os.path.normcase(os.path.normpath(normalized))


def paths_same(left: str, right: str) -> bool:
    """Compare path identity without misclassifying filesystem aliases.

    Existing objects use native file identity, which handles case-insensitive
    volumes, hard links, and symlink aliases. If exactly one path exists they
    cannot name the same current object. Lexical comparison is reserved for
    two missing paths, where no filesystem identity is available.
    """
    if not left or not right:
        return False
    try:
        left_exists = os.path.exists(left)
        right_exists = os.path.exists(right)
    except (OSError, ValueError):
        return False
    if left_exists and right_exists:
        try:
            return os.path.samefile(left, right)
        except (OSError, ValueError):
            return False
    if left_exists != right_exists:
        return False
    left_canonical = canonical_path(left)
    right_canonical = canonical_path(right)
    return bool(left_canonical) and left_canonical == right_canonical


def _pid_record_integrity_error(path: str, info: os.stat_result) -> str:
    """Return why a PID record is mutable by a different local principal."""
    if os.name == "nt":
        try:
            from defenseclaw.file_permissions import windows_acl_custody_write_error

            if file_problem := windows_acl_custody_write_error(
                path,
                allow_current_user=True,
                require_current_user_owner=True,
            ):
                return file_problem
            ancestor = os.path.dirname(os.path.abspath(path)) or os.curdir
            while ancestor:
                parent = os.path.dirname(ancestor)
                # A drive/share root cannot itself be renamed. The generic ACL
                # validator also treats harmless root-level create-child grants
                # as writes, so stop after validating every replaceable
                # ancestor below that immutable boundary.
                if not parent or parent == ancestor:
                    break
                if ancestor_problem := windows_acl_custody_write_error(
                    ancestor,
                    allow_current_user=True,
                ):
                    return f"PID file ancestor directory has unsafe ACLs ({ancestor_problem})"
                ancestor = parent
            return ""
        except OSError:
            return "PID file ACL could not be verified"
    geteuid = getattr(os, "geteuid", None)
    current_uid = geteuid() if callable(geteuid) else info.st_uid
    if info.st_uid != current_uid:
        return "PID file is not owned by the current user"
    if stat.S_IMODE(info.st_mode) & 0o022:
        return "PID file is writable by another local principal"
    if sys.platform == "darwin":
        from defenseclaw.file_permissions import darwin_acl_write_error

        if acl_problem := darwin_acl_write_error(path):
            return acl_problem

    # A protected leaf can still be replaced by renaming it from a writable
    # directory. Walk the POSIX custody chain; sticky root-owned/current-user
    # directories (for example /tmp) preserve ownership of existing children.
    current = os.path.realpath(os.path.dirname(os.path.abspath(path)) or os.curdir)
    while True:
        directory_info = os.lstat(current)
        if not stat.S_ISDIR(directory_info.st_mode):
            return "PID file ancestor is not a directory"
        if directory_info.st_uid not in {0, current_uid}:
            return "PID file ancestor directory is not owned by a trusted principal"
        mode = stat.S_IMODE(directory_info.st_mode)
        if mode & 0o022 and not mode & stat.S_ISVTX:
            return "PID file ancestor directory is writable by another local principal"
        if sys.platform == "darwin":
            from defenseclaw.file_permissions import darwin_acl_write_error

            if acl_problem := darwin_acl_write_error(current):
                return f"PID file ancestor directory has unsafe ACLs ({acl_problem})"
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return ""


def read_pid_record(path: str) -> PIDRecord:
    """Read a regular, non-link PID record from the configured data home."""
    try:
        if is_symlink(path):
            return PIDRecord("malformed", reason="PID file is a symbolic link or reparse point")
        info = os.lstat(path)
        if getattr(info, "st_file_attributes", 0) & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT:
            return PIDRecord("malformed", reason="PID file is a symbolic link or reparse point")
        if not stat.S_ISREG(info.st_mode):
            return PIDRecord("malformed", reason="PID file is not a regular file")
        if integrity_error := _pid_record_integrity_error(path, info):
            return PIDRecord("malformed", reason=integrity_error)
        raw_bytes = read_regular_file_no_follow(
            path,
            max_bytes=_MAX_PID_RECORD_BYTES,
            expected_stat=info,
        )
        current = os.lstat(path)
        if not os.path.samestat(info, current):
            return PIDRecord("unavailable", reason="PID file changed while it was being inspected")
    except FileNotFoundError:
        return PIDRecord("missing", reason="PID file is missing")
    except PermissionError:
        return PIDRecord("denied", reason="PID file access denied")
    except UnsafePathError as exc:
        if "exceeds" in str(exc):
            return PIDRecord("malformed", reason="PID file exceeds the inspection limit")
        if "non-file" in str(exc):
            return PIDRecord("malformed", reason="PID file is not a regular file")
        if "symlink" in str(exc) or "reparse" in str(exc):
            return PIDRecord("malformed", reason="PID file is a symbolic link or reparse point")
        return PIDRecord("unavailable", reason="PID file changed while it was being inspected")
    except OSError:
        return PIDRecord("unavailable", reason="PID file could not be inspected")

    return parse_pid_record_bytes(raw_bytes)


def parse_pid_record_bytes(raw_bytes: bytes) -> PIDRecord:
    """Parse bounded PID-record bytes already bound to trusted file evidence."""

    try:
        raw = raw_bytes.decode("utf-8")
    except UnicodeError:
        return PIDRecord("malformed", reason="PID file is not valid UTF-8")
    raw = raw.strip()
    if not raw:
        return PIDRecord("malformed", reason="PID file is empty")
    try:
        pid = int(raw)
        payload: dict[str, object] = {}
    except ValueError:
        try:
            decoded = json.loads(raw)
            if not isinstance(decoded, dict):
                raise ValueError
            payload = decoded
            raw_pid = payload.get("pid", 0)
            if type(raw_pid) is not int:
                raise ValueError
            pid = raw_pid
        except (json.JSONDecodeError, OverflowError, TypeError, ValueError):
            return PIDRecord("malformed", reason="PID file is malformed")
    if not 0 < pid <= MAX_PLATFORM_PID:
        return PIDRecord("malformed", reason="PID file contains an invalid PID")
    executable = payload.get("executable", "")
    start_identity = payload.get("start_identity", "")
    start_time = payload.get("start_time", "")
    data_dir = payload.get("data_dir", "")
    for field in (executable, data_dir):
        if isinstance(field, str) and "\x00" in field:
            return PIDRecord("malformed", reason="PID file contains an invalid path field")
    return PIDRecord(
        "ok",
        pid=pid,
        executable=executable if isinstance(executable, str) else "",
        start_identity=start_identity if isinstance(start_identity, str) else "",
        start_time=str(start_time) if isinstance(start_time, (str, int)) else "",
        data_dir=data_dir if isinstance(data_dir, str) else "",
    )


def pid_file_fingerprint_from_fd(fd: int) -> tuple[int, int, int, int, bytes] | None:
    """Fingerprint the exact regular PID-file object bound to ``fd``.

    Callers that hold an exclusive Windows mutation descriptor can compare and
    delete the same file object without reopening its pathname in between.
    """

    opened_info = os.fstat(fd)
    if (
        not stat.S_ISREG(opened_info.st_mode)
        or opened_info.st_size > _MAX_PID_RECORD_BYTES
        or getattr(opened_info, "st_file_attributes", 0) & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
    ):
        return None
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = _MAX_PID_RECORD_BYTES + 1
    while remaining:
        chunk = os.read(fd, min(64 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    current_info = os.fstat(fd)
    if len(raw) > _MAX_PID_RECORD_BYTES or len(raw) != opened_info.st_size:
        return None
    if (
        not os.path.samestat(opened_info, current_info)
        or opened_info.st_size != current_info.st_size
        or getattr(opened_info, "st_mtime_ns", 0) != getattr(current_info, "st_mtime_ns", 0)
    ):
        return None
    return (
        int(getattr(opened_info, "st_dev", 0)),
        int(getattr(opened_info, "st_ino", 0)),
        int(opened_info.st_size),
        int(getattr(opened_info, "st_mtime_ns", 0)),
        raw,
    )


def pid_file_fingerprint(path: str) -> tuple[int, int, int, int, bytes] | None:
    """Return a race-check fingerprint for a safe regular PID file."""
    try:
        if is_symlink(path):
            return None
        info = os.lstat(path)
        if getattr(info, "st_file_attributes", 0) & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT:
            return None
        if not stat.S_ISREG(info.st_mode):
            return None
        if _pid_record_integrity_error(path, info):
            return None
        fd = open_regular_file_no_follow(path)
        try:
            opened_info = os.fstat(fd)
            if not os.path.samestat(info, opened_info):
                return None
            fingerprint = pid_file_fingerprint_from_fd(fd)
        finally:
            os.close(fd)
    except OSError:
        return None
    return fingerprint


class GatewayEvidence:
    """OS evidence seam used by Doctor's cross-platform trust checks."""

    def __init__(self, *, platform_name: str | None = None) -> None:
        self.platform_name = platform_name or sys.platform

    def pid_record(self, path: str) -> PIDRecord:
        return read_pid_record(path)

    def process(self, pid: int) -> ProcessEvidence:
        if self.platform_name == "win32":
            return _windows_process_evidence(pid)
        if self.platform_name.startswith("linux"):
            return _linux_process_evidence(pid)
        if self.platform_name == "darwin":
            return _darwin_process_evidence(pid)
        return ProcessEvidence(
            "unavailable",
            pid=pid,
            reason="native process identity inspection is unavailable",
        )

    def listener(self, port: int, host: str = "") -> ListenerEvidence:
        if self.platform_name != "win32":
            return ListenerEvidence("unavailable", reason="native Windows listener inspection is unavailable")
        return _windows_listener_evidence(port, host=host)


def _linux_process_evidence(
    pid: int,
    *,
    proc_root: str = "/proc",
) -> ProcessEvidence:
    """Read the same executable/start identity used by the Go daemon."""
    if not 0 < pid <= MAX_PLATFORM_PID:
        return ProcessEvidence("missing", pid=pid, reason="invalid PID")
    process_root = os.path.join(proc_root, str(pid))
    try:
        executable = os.readlink(os.path.join(process_root, "exe"))
        with open(os.path.join(process_root, "stat"), encoding="utf-8") as stat_file:
            raw_stat = stat_file.read(1 << 20)
    except FileNotFoundError:
        return ProcessEvidence("missing", pid=pid, reason="recorded process does not exist")
    except PermissionError:
        return ProcessEvidence("denied", pid=pid, reason="process identity access denied")
    except (OSError, UnicodeError):
        return ProcessEvidence("unavailable", pid=pid, reason="process identity could not be queried")

    closing_paren = raw_stat.rfind(")")
    if closing_paren < 0:
        return ProcessEvidence("unavailable", pid=pid, reason="process start identity is malformed")
    fields = raw_stat[closing_paren + 1 :].split()
    # Fields 1 and 2 (pid + parenthesized comm) were removed. Field 22
    # therefore lands at zero-based tail index 19, matching Go.
    if len(fields) < 20:
        return ProcessEvidence("unavailable", pid=pid, reason="process start identity is incomplete")
    return ProcessEvidence(
        "ok",
        pid=pid,
        executable=executable,
        start_identity=fields[19],
    )


def _darwin_native_process_identity(pid: int) -> tuple[str, str]:
    """Return full executable path and microsecond start time via libproc."""
    import errno

    class _ProcBSDInfo(ctypes.Structure):
        _fields_ = [
            ("flags", ctypes.c_uint32),
            ("status", ctypes.c_uint32),
            ("xstatus", ctypes.c_uint32),
            ("pid", ctypes.c_uint32),
            ("ppid", ctypes.c_uint32),
            ("uid", ctypes.c_uint32),
            ("gid", ctypes.c_uint32),
            ("ruid", ctypes.c_uint32),
            ("rgid", ctypes.c_uint32),
            ("svuid", ctypes.c_uint32),
            ("svgid", ctypes.c_uint32),
            ("rfu_1", ctypes.c_uint32),
            ("comm", ctypes.c_char * 16),
            ("name", ctypes.c_char * 32),
            ("nfiles", ctypes.c_uint32),
            ("pgid", ctypes.c_uint32),
            ("pjobc", ctypes.c_uint32),
            ("e_tdev", ctypes.c_uint32),
            ("e_tpgid", ctypes.c_uint32),
            ("nice", ctypes.c_int32),
            ("start_tvsec", ctypes.c_uint64),
            ("start_tvusec", ctypes.c_uint64),
        ]

    libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    proc_pidpath = libproc.proc_pidpath
    proc_pidpath.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)
    proc_pidpath.restype = ctypes.c_int
    path_buffer = ctypes.create_string_buffer(4096)
    ctypes.set_errno(0)
    path_size = proc_pidpath(pid, path_buffer, len(path_buffer))
    if path_size <= 0:
        error = ctypes.get_errno()
        if error == errno.ESRCH:
            raise ProcessLookupError(pid)
        if error in {errno.EACCES, errno.EPERM}:
            raise PermissionError(pid)
        raise OSError(error, "proc_pidpath failed")

    proc_pidinfo = libproc.proc_pidinfo
    proc_pidinfo.argtypes = (
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_uint64,
        ctypes.c_void_p,
        ctypes.c_int,
    )
    proc_pidinfo.restype = ctypes.c_int
    info = _ProcBSDInfo()
    ctypes.set_errno(0)
    result = proc_pidinfo(
        pid,
        3,  # PROC_PIDTBSDINFO
        0,
        ctypes.byref(info),
        ctypes.sizeof(info),
    )
    if result != ctypes.sizeof(info):
        error = ctypes.get_errno()
        if error == errno.ESRCH:
            raise ProcessLookupError(pid)
        if error in {errno.EACCES, errno.EPERM}:
            raise PermissionError(pid)
        raise OSError(error, "proc_pidinfo failed")
    executable = os.fsdecode(path_buffer.value)
    if not executable or not info.start_tvsec:
        raise OSError("Darwin process identity is incomplete")
    return executable, f"{info.start_tvsec}.{info.start_tvusec:06d}"


def _darwin_process_evidence(pid: int) -> ProcessEvidence:
    """Read a full Darwin executable path and microsecond start identity."""
    if not 0 < pid <= MAX_PLATFORM_PID:
        return ProcessEvidence("missing", pid=pid, reason="invalid PID")
    try:
        executable, start_identity = _darwin_native_process_identity(pid)
    except ProcessLookupError:
        return ProcessEvidence("missing", pid=pid, reason="recorded process does not exist")
    except PermissionError:
        return ProcessEvidence("denied", pid=pid, reason="process identity access denied")
    except OSError:
        return ProcessEvidence("unavailable", pid=pid, reason="process identity could not be queried")
    return ProcessEvidence(
        "ok",
        pid=pid,
        executable=executable,
        start_identity=start_identity,
    )


def _windows_process_evidence(pid: int) -> ProcessEvidence:  # pragma: no cover - native Windows only
    from ctypes import wintypes

    if not 0 < pid <= MAX_PLATFORM_PID:
        return ProcessEvidence("missing", pid=pid, reason="invalid PID")
    query_limited = 0x1000
    still_active = 259
    error_access_denied = 5
    error_invalid_parameter = 87
    error_not_found = 1168
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    open_process = kernel32.OpenProcess
    open_process.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    open_process.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL

    handle = open_process(query_limited, False, pid)
    if not handle:
        error = ctypes.get_last_error()
        if error == error_access_denied:
            return ProcessEvidence("denied", pid=pid, reason="process inspection access denied")
        if error in {error_invalid_parameter, error_not_found}:
            return ProcessEvidence("missing", pid=pid, reason="recorded process does not exist")
        return ProcessEvidence("unavailable", pid=pid, reason="process identity could not be queried")
    try:
        get_exit_code = kernel32.GetExitCodeProcess
        get_exit_code.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
        get_exit_code.restype = wintypes.BOOL
        exit_code = wintypes.DWORD()
        if not get_exit_code(handle, ctypes.byref(exit_code)):
            return ProcessEvidence("unavailable", pid=pid, reason="process state could not be queried")
        if exit_code.value != still_active:
            return ProcessEvidence("missing", pid=pid, reason="recorded process has exited")

        query_image = kernel32.QueryFullProcessImageNameW
        query_image.argtypes = (
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
        )
        query_image.restype = wintypes.BOOL
        size = wintypes.DWORD(32_768)
        image = ctypes.create_unicode_buffer(size.value)
        if not query_image(handle, 0, image, ctypes.byref(size)):
            return ProcessEvidence("unavailable", pid=pid, reason="process executable could not be queried")

        class FILETIME(ctypes.Structure):
            _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

        get_times = kernel32.GetProcessTimes
        get_times.argtypes = tuple([wintypes.HANDLE] + [ctypes.POINTER(FILETIME)] * 4)
        get_times.restype = wintypes.BOOL
        creation, exit_time, kernel_time, user_time = FILETIME(), FILETIME(), FILETIME(), FILETIME()
        if not get_times(
            handle,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel_time),
            ctypes.byref(user_time),
        ):
            return ProcessEvidence("unavailable", pid=pid, reason="process start identity could not be queried")
        ticks_100ns = (creation.high << 32) | creation.low
        # Match golang.org/x/sys/windows.Filetime.Nanoseconds(), which is
        # what daemon.writePIDInfo persists through processStartIdentity.
        unix_epoch_100ns = 116_444_736_000_000_000
        return ProcessEvidence(
            "ok",
            pid=pid,
            executable=image.value,
            start_identity=str((ticks_100ns - unix_epoch_100ns) * 100),
        )
    finally:
        close_handle(handle)


def _listener_address_matches(local_address: str, target_host: str) -> bool:
    """Return whether a bound address can receive a connection to target."""
    if not target_host:
        return True
    try:
        local = ipaddress.ip_address(local_address)
        if target_host.strip("[]").casefold() == "localhost":
            return local.is_unspecified or local.is_loopback
        target = ipaddress.ip_address(target_host.strip("[]"))
    except ValueError:
        return False
    return local.version == target.version and (local.is_unspecified or local == target)


def _windows_listener_evidence(
    port: int,
    *,
    host: str = "",
) -> ListenerEvidence:  # pragma: no cover - native Windows only
    """Resolve a TCP listener owner with GetExtendedTcpTable (IPv4/IPv6)."""
    from ctypes import wintypes

    if not 1 <= port <= 65_535:
        return ListenerEvidence("unavailable", reason="configured API port is invalid")
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
    tcp_table_owner_pid_listener = 3
    error_insufficient_buffer = 122
    error_access_denied = 5

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

    target_host = host.strip("[]")
    families: tuple[tuple[int, type[ctypes.Structure]], ...] = (
        (socket.AF_INET, TCP4Row),
        (socket.AF_INET6, TCP6Row),
    )
    if target_host and target_host.casefold() != "localhost":
        try:
            target_version = ipaddress.ip_address(target_host).version
        except ValueError:
            return ListenerEvidence("unavailable", reason="configured API host is not an IP literal")
        family = socket.AF_INET if target_version == 4 else socket.AF_INET6
        row_type = TCP4Row if target_version == 4 else TCP6Row
        families = ((family, row_type),)

    matching_pids: set[int] = set()
    query_errors: list[EvidenceStatus] = []
    for family, row_type in families:
        size = wintypes.ULONG(0)
        result = get_table(None, ctypes.byref(size), False, family, tcp_table_owner_pid_listener, 0)
        if result not in (0, error_insufficient_buffer):
            if result == error_access_denied:
                query_errors.append("denied")
            else:
                query_errors.append("unavailable")
            continue
        if not size.value:
            continue
        buffer = ctypes.create_string_buffer(size.value)
        result = get_table(buffer, ctypes.byref(size), False, family, tcp_table_owner_pid_listener, 0)
        if result == error_insufficient_buffer and size.value > len(buffer):
            # The table can grow between the sizing and fill calls.
            buffer = ctypes.create_string_buffer(size.value)
            result = get_table(buffer, ctypes.byref(size), False, family, tcp_table_owner_pid_listener, 0)
        if result != 0:
            if result == error_access_denied:
                query_errors.append("denied")
            else:
                query_errors.append("unavailable")
            continue
        count = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD)).contents.value
        offset = ctypes.sizeof(wintypes.DWORD)
        # The table aligns its row array to the row's native alignment.
        alignment = ctypes.alignment(row_type)
        offset = (offset + alignment - 1) & ~(alignment - 1)
        for index in range(count):
            row = row_type.from_buffer_copy(buffer, offset + index * ctypes.sizeof(row_type))
            if socket.ntohs(row.local_port & 0xFFFF) != port:
                continue
            try:
                if family == socket.AF_INET:
                    packed = int(row.local_addr).to_bytes(4, byteorder=sys.byteorder)
                else:
                    packed = bytes(row.local_addr)
                local_address = socket.inet_ntop(family, packed)
            except (OSError, OverflowError, ValueError):
                continue
            if _listener_address_matches(local_address, host):
                matching_pids.add(int(row.pid))
    if len(matching_pids) == 1:
        return ListenerEvidence("ok", pid=next(iter(matching_pids)))
    if len(matching_pids) > 1:
        return ListenerEvidence(
            "ambiguous",
            reason="multiple processes own listeners for the configured API endpoint",
        )
    if query_errors:
        if "denied" in query_errors:
            return ListenerEvidence("denied", reason="listener ownership access denied")
        return ListenerEvidence("unavailable", reason="listener ownership could not be queried")
    return ListenerEvidence("missing", reason="no TCP listener on the configured API port")


def gateway_executable_name(path: str, *, platform_name: str | None = None) -> str:
    """Normalize a cross-platform executable basename for allowlist matching."""
    platform = (platform_name or ("win32" if os.name == "nt" else sys.platform)).lower()
    path_module = ntpath if platform in {"nt", "win32", "windows"} else posixpath
    return path_module.basename(path.strip()).lower()
