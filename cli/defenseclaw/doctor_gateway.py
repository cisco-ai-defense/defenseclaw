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
import subprocess
import sys
from dataclasses import dataclass
from typing import Literal

from defenseclaw.file_permissions import (
    UNSAFE_PATH_CHANGED,
    UNSAFE_PATH_EXCEEDS_LIMIT,
    UNSAFE_PATH_INSPECTION_FAILED,
    UNSAFE_PATH_NOT_ABSOLUTE,
    UNSAFE_PATH_NOT_REGULAR_FILE,
    UNSAFE_PATH_SYMLINK_OR_REPARSE,
    UNSAFE_PATH_UNKNOWN,
    UNSAFE_PATH_UNTRUSTED_CUSTODY,
    UnsafePathError,
    open_regular_file_no_follow,
    read_regular_file_no_follow,
    trusted_runtime_owner,
    trusted_system_subprocess_env,
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
WatchdogOwnershipStatus = Literal["held", "unlocked", "missing", "unsafe", "denied", "unavailable"]
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


@dataclass(frozen=True)
class WatchdogStateEvidence:
    status: EvidenceStatus
    state: str = ""
    reason: str = ""


@dataclass(frozen=True)
class WatchdogOwnershipEvidence:
    status: WatchdogOwnershipStatus
    source: str = ""
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


def _pid_record_integrity_error(path: str, info: os.stat_result) -> tuple[EvidenceStatus, str]:
    """Classify why a PID record may be mutable by a different principal.

    Returns ``("ok", "")`` when custody is proven safe. Otherwise the status
    distinguishes two situations Doctor must not conflate:

    ``denied``
        Custody was inspected and is positively untrusted -- foreign owner,
        group/world-writable leaf, a write-capable ACL, or a replaceable
        ancestor. The record is refused.

    ``unavailable``
        Custody could not be established at all. Network or container homes
        with UID mapping, an unreadable ancestor, or an ACL query failure land
        here. The record is still refused, but reporting it as ``malformed``
        would tell an operator their PID file is corrupt when it is not.

    ``malformed`` is reserved for records whose *contents* are bad, so a
    custody problem never masquerades as a parse failure.
    """
    if os.name == "nt":
        try:
            from defenseclaw.file_permissions import windows_acl_custody_write_error

            if file_problem := windows_acl_custody_write_error(
                path,
                allow_current_user=True,
                require_current_user_owner=True,
            ):
                return "denied", file_problem
            ancestor = os.path.dirname(os.path.abspath(path)) or os.curdir
            while ancestor:
                parent = os.path.dirname(ancestor)
                # A drive/share root cannot itself be renamed, so stop after
                # validating every replaceable ancestor below that boundary.
                if not parent or parent == ancestor:
                    break
                # Only rights that can rename, delete or re-ACL an existing
                # child matter on an ancestor. Create-child grants such as the
                # BUILTIN\\Users (CI)(AD)/(WD) entries a folder inherits from
                # an NTFS volume root cannot replace the record (GAP-2615).
                if ancestor_problem := windows_acl_custody_write_error(
                    ancestor,
                    allow_current_user=True,
                    ancestor_replace_only=True,
                ):
                    return (
                        "denied",
                        f"PID file ancestor directory has unsafe ACLs ({ancestor_problem})",
                    )
                ancestor = parent
            return "ok", ""
        except OSError:
            return "unavailable", "PID file ACL could not be verified"
    geteuid = getattr(os, "geteuid", None)
    current_uid = geteuid() if callable(geteuid) else info.st_uid
    # Root is a trusted writer of a user install (sudo gateway start).
    # A foreign non-root owner is still untrusted. Group/other-writable
    # leaves stay denied below so this does not widen the write set.
    if not trusted_runtime_owner(info.st_uid, current_uid=current_uid):
        return "denied", "PID file is not owned by a trusted principal"
    if stat.S_IMODE(info.st_mode) & 0o022:
        return "denied", "PID file is writable by another local principal"
    if sys.platform == "darwin":
        from defenseclaw.file_permissions import darwin_acl_write_error

        if acl_problem := darwin_acl_write_error(path):
            return "denied", acl_problem

    # A protected leaf can still be replaced by renaming it from a writable
    # directory. Walk the POSIX custody chain; sticky root-owned/current-user
    # directories (for example /tmp) preserve ownership of existing children.
    current = os.path.realpath(os.path.dirname(os.path.abspath(path)) or os.curdir)
    while True:
        try:
            directory_info = os.lstat(current)
        except OSError:
            # An ancestor we cannot stat is unproven custody, not proof of
            # tampering. Common on network homes and bind-mounted containers.
            return "unavailable", "PID file ancestor custody could not be verified"
        if not stat.S_ISDIR(directory_info.st_mode):
            return "denied", "PID file ancestor is not a directory"
        if directory_info.st_uid not in {0, current_uid}:
            # A foreign-owned ancestor is frequently a UID-mapped network or
            # container mount rather than an attacker, so this refusal is
            # reported as unverifiable custody instead of positive tampering.
            return (
                "unavailable",
                "PID file ancestor directory is not owned by a trusted principal",
            )
        mode = stat.S_IMODE(directory_info.st_mode)
        if mode & 0o022 and not mode & stat.S_ISVTX:
            return (
                "denied",
                "PID file ancestor directory is writable by another local principal",
            )
        if sys.platform == "darwin":
            from defenseclaw.file_permissions import darwin_acl_write_error

            if acl_problem := darwin_acl_write_error(current):
                return (
                    "denied",
                    f"PID file ancestor directory has unsafe ACLs ({acl_problem})",
                )
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return "ok", ""


_UNSAFE_PATH_PID_EVIDENCE: dict[str, tuple[EvidenceStatus, str]] = {
    UNSAFE_PATH_EXCEEDS_LIMIT: ("malformed", "PID file exceeds the inspection limit"),
    UNSAFE_PATH_NOT_REGULAR_FILE: ("malformed", "PID file is not a regular file"),
    UNSAFE_PATH_SYMLINK_OR_REPARSE: (
        "malformed",
        "PID file is a symbolic link or reparse point",
    ),
    UNSAFE_PATH_CHANGED: (
        "unavailable",
        "PID file changed while it was being inspected",
    ),
    UNSAFE_PATH_UNTRUSTED_CUSTODY: (
        "denied",
        "PID file custody is not trusted",
    ),
    UNSAFE_PATH_NOT_ABSOLUTE: ("malformed", "PID file path is not absolute"),
    UNSAFE_PATH_INSPECTION_FAILED: (
        "unavailable",
        "PID file could not be inspected",
    ),
}


def _pid_record_unsafe_path_evidence(exc: UnsafePathError) -> tuple[EvidenceStatus, str]:
    """Map a stable reader refusal code onto PID-record evidence."""
    return _UNSAFE_PATH_PID_EVIDENCE.get(
        getattr(exc, "code", UNSAFE_PATH_UNKNOWN),
        # An unrecognized code is treated as an unproven inspection failure
        # rather than a content verdict, keeping the refusal fail-closed
        # without asserting the record is corrupt.
        ("unavailable", "PID file could not be safely inspected"),
    )


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
        integrity_status, integrity_error = _pid_record_integrity_error(path, info)
        if integrity_status != "ok":
            return PIDRecord(integrity_status, reason=integrity_error)
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
        # Branch on the reader's stable code, never on its message text: these
        # statuses gate which lifecycle repairs Doctor will run, so a reworded
        # message must not be able to reclassify a refusal.
        status, reason = _pid_record_unsafe_path_evidence(exc)
        return PIDRecord(status, reason=reason)
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


def read_watchdog_pid_record(path: str, *, platform_name: str | None = None) -> PIDRecord:
    """Read watchdog.pid from one private, identity-bound Windows handle.

    Gateway PID diagnostics retain their established reader. This stricter
    reader is watchdog-specific because a held lifetime lock is meaningful
    only when the replaceable canonical publication has private custody too.
    """
    if (platform_name or sys.platform) != "win32":
        return read_pid_record(path)

    from defenseclaw.windows_acl import (
        WindowsAclError,
        assert_not_broadly_readable,
        assert_not_broadly_writable,
        assert_trusted_owner,
        capture_fd,
        open_regular_read_fd_shared_delete,
    )

    try:
        if is_symlink(path):
            return PIDRecord("malformed", reason="watchdog PID file is a symbolic link or reparse point")
        named_info = os.lstat(path)
        reparse_point = 0x400
        if getattr(named_info, "st_file_attributes", 0) & reparse_point:
            return PIDRecord("malformed", reason="watchdog PID file is a symbolic link or reparse point")
        if not stat.S_ISREG(named_info.st_mode):
            return PIDRecord("malformed", reason="watchdog PID file is not a regular file")
        fd = open_regular_read_fd_shared_delete(path)
        try:
            opened_info = os.fstat(fd)
            if not os.path.samestat(named_info, opened_info):
                return PIDRecord("unavailable", reason="watchdog PID file changed while it was inspected")
            security = capture_fd(fd)
            assert_trusted_owner(security)
            assert_not_broadly_readable(security)
            assert_not_broadly_writable(security)
            os.lseek(fd, 0, os.SEEK_SET)
            data = os.read(fd, 16_385)
        finally:
            os.close(fd)
    except FileNotFoundError:
        return PIDRecord("missing", reason="watchdog PID file is missing")
    except PermissionError:
        return PIDRecord("denied", reason="watchdog PID file access denied")
    except WindowsAclError as exc:
        code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
        if code in {2, 3}:
            return PIDRecord("missing", reason="watchdog PID file is missing")
        if code == 5:
            return PIDRecord("denied", reason="watchdog PID custody inspection access denied")
        message = str(exc).lower()
        if any(marker in message for marker in ("regular file", "reparse")):
            return PIDRecord("malformed", reason="watchdog PID file is not a private regular non-reparse file")
        if code is not None:
            return PIDRecord("unavailable", reason="watchdog PID file could not be inspected safely")
        return PIDRecord("malformed", reason="watchdog PID file owner or DACL is not private")
    except OSError:
        return PIDRecord("unavailable", reason="watchdog PID file could not be inspected safely")

    if len(data) > 16_384:
        return PIDRecord("malformed", reason="watchdog PID file exceeds the inspection limit")
    return parse_pid_record_bytes(data)


def read_watchdog_state(path: str) -> WatchdogStateEvidence:
    """Read the bounded, non-link last-known watchdog health state."""
    try:
        if is_symlink(path):
            return WatchdogStateEvidence("malformed", reason="state file is a symbolic link or reparse point")
        info = os.lstat(path)
        reparse_point = 0x400
        if getattr(info, "st_file_attributes", 0) & reparse_point:
            return WatchdogStateEvidence("malformed", reason="state file is a symbolic link or reparse point")
        if not stat.S_ISREG(info.st_mode):
            return WatchdogStateEvidence("malformed", reason="state file is not a regular file")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            opened_info = os.fstat(fd)
            if not os.path.samestat(info, opened_info):
                return WatchdogStateEvidence("unavailable", reason="state file changed while it was inspected")
            handle = os.fdopen(fd, encoding="utf-8")
            fd = -1
            with handle:
                raw = handle.read(65)
        finally:
            if fd >= 0:
                os.close(fd)
    except FileNotFoundError:
        return WatchdogStateEvidence("missing", reason="last-known state is missing")
    except PermissionError:
        return WatchdogStateEvidence("denied", reason="last-known state access denied")
    except (OSError, UnicodeError):
        return WatchdogStateEvidence("unavailable", reason="last-known state could not be inspected")

    if len(raw) > 64:
        return WatchdogStateEvidence("malformed", reason="last-known state exceeds the inspection limit")
    state = raw.strip().lower()
    if state not in {"healthy", "degraded", "down"}:
        return WatchdogStateEvidence("malformed", reason="last-known state is invalid")
    return WatchdogStateEvidence("ok", state=state)


def inspect_watchdog_ownership(
    stable_path: str,
    legacy_pid_path: str,
    *,
    platform_name: str | None = None,
) -> WatchdogOwnershipEvidence:
    """Probe the stable Windows ownership lock with bounded legacy fallback.

    The probe never writes file content. It attempts the exact lifetime byte
    lock and immediately releases it when available. A held stable lock is
    authoritative for current watchdogs; a held canonical PID lock is accepted
    only as compatibility evidence for an older watchdog publisher.
    """
    if (platform_name or sys.platform) != "win32":
        return WatchdogOwnershipEvidence(
            "unavailable",
            reason="native Windows watchdog ownership inspection is unavailable",
        )

    stable = _windows_watchdog_file_lock_evidence(stable_path, source="stable")
    if stable.status == "held":
        return stable
    if stable.status in {"unsafe", "denied", "unavailable"}:
        return stable

    legacy = _windows_watchdog_file_lock_evidence(legacy_pid_path, source="legacy")
    if legacy.status == "held":
        return legacy
    if legacy.status in {"unsafe", "denied", "unavailable"}:
        return legacy
    if stable.status == "unlocked":
        return stable
    if legacy.status == "unlocked":
        return legacy
    return WatchdogOwnershipEvidence("missing", reason="no watchdog ownership object exists")


def _windows_watchdog_file_lock_evidence(path: str, *, source: str) -> WatchdogOwnershipEvidence:
    """Inspect one private regular Windows lifecycle file and its lock byte."""
    import msvcrt
    from ctypes import wintypes

    from defenseclaw.windows_acl import (
        WindowsAclError,
        assert_not_broadly_readable,
        assert_not_broadly_writable,
        assert_trusted_owner,
        capture_fd,
        open_regular_read_fd_shared_delete,
    )

    try:
        fd = open_regular_read_fd_shared_delete(path)
    except WindowsAclError as exc:
        code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
        if code in {2, 3}:
            return WatchdogOwnershipEvidence("missing", source=source, reason="ownership file is missing")
        if code == 5:
            return WatchdogOwnershipEvidence("denied", source=source, reason="ownership file access denied")
        message = str(exc).lower()
        if any(marker in message for marker in ("regular file", "reparse", "owner", "dacl", "broad")):
            return WatchdogOwnershipEvidence("unsafe", source=source, reason="ownership file is unsafe")
        return WatchdogOwnershipEvidence(
            "unavailable",
            source=source,
            reason="ownership file could not be opened safely",
        )

    try:
        try:
            security = capture_fd(fd)
            assert_trusted_owner(security)
            assert_not_broadly_readable(security)
            assert_not_broadly_writable(security)
        except WindowsAclError as exc:
            code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
            if code == 5:
                return WatchdogOwnershipEvidence(
                    "denied",
                    source=source,
                    reason="ownership security inspection access denied",
                )
            return WatchdogOwnershipEvidence(
                "unsafe",
                source=source,
                reason="ownership file owner or DACL is not private",
            )

        class OVERLAPPED(ctypes.Structure):
            _fields_ = [
                ("Internal", ctypes.c_size_t),
                ("InternalHigh", ctypes.c_size_t),
                ("Offset", wintypes.DWORD),
                ("OffsetHigh", wintypes.DWORD),
                ("hEvent", wintypes.HANDLE),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        lock_file = kernel32.LockFileEx
        lock_file.argtypes = (
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(OVERLAPPED),
        )
        lock_file.restype = wintypes.BOOL
        unlock_file = kernel32.UnlockFileEx
        unlock_file.argtypes = (
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(OVERLAPPED),
        )
        unlock_file.restype = wintypes.BOOL

        overlapped = OVERLAPPED(OffsetHigh=0x4000_0000)
        handle = wintypes.HANDLE(msvcrt.get_osfhandle(fd))
        lock_exclusive = 0x00000002
        lock_fail_immediately = 0x00000001
        if not lock_file(
            handle,
            lock_exclusive | lock_fail_immediately,
            0,
            1,
            0,
            ctypes.byref(overlapped),
        ):
            error = ctypes.get_last_error()
            if error == 33:  # ERROR_LOCK_VIOLATION
                return WatchdogOwnershipEvidence("held", source=source, reason="ownership lock is held")
            if error == 5:  # ERROR_ACCESS_DENIED
                return WatchdogOwnershipEvidence(
                    "denied",
                    source=source,
                    reason="ownership lock access denied",
                )
            return WatchdogOwnershipEvidence(
                "unavailable",
                source=source,
                reason="ownership lock state could not be inspected",
            )
        if not unlock_file(handle, 0, 1, 0, ctypes.byref(overlapped)):
            return WatchdogOwnershipEvidence(
                "unavailable",
                source=source,
                reason="ownership probe lock could not be released",
            )
        return WatchdogOwnershipEvidence("unlocked", source=source, reason="ownership lock is not held")
    finally:
        os.close(fd)

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
        if _pid_record_integrity_error(path, info)[0] != "ok":
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

    def watchdog_pid_record(self, path: str) -> PIDRecord:
        return read_watchdog_pid_record(path, platform_name=self.platform_name)

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

    def connection_owner(
        self,
        pid: int,
        client: tuple[object, ...],
        server: tuple[object, ...],
    ) -> ListenerEvidence:
        """Report whether ``pid`` holds the server end of one connected socket.

        ``client`` and ``server`` are ``getsockname()`` and ``getpeername()``
        of a socket this process connected. ``ok`` carries the PID the kernel
        attributes the accepted server socket to. ``missing`` means ``pid``
        does not hold it yet, which is also the state before the server has
        accepted the connection, so callers poll within a short bound.
        """
        local = _socket_endpoint(server)
        remote = _socket_endpoint(client)
        if local is None or remote is None or not 0 < pid <= MAX_PLATFORM_PID:
            return ListenerEvidence("unavailable", reason="connected endpoint is not a TCP/IP endpoint")
        if self.platform_name == "win32":
            return _windows_connection_owner(local, remote)
        if self.platform_name.startswith("linux"):
            return _linux_connection_owner(pid, local, remote)
        if self.platform_name == "darwin":
            return _lsof_connection_owner(pid, local, remote)
        return ListenerEvidence("unavailable", reason="native connection ownership inspection is unavailable")

    def watchdog_state(self, path: str) -> WatchdogStateEvidence:
        return read_watchdog_state(path)

    def watchdog_ownership(self, stable_path: str, legacy_pid_path: str) -> WatchdogOwnershipEvidence:
        return inspect_watchdog_ownership(
            stable_path,
            legacy_pid_path,
            platform_name=self.platform_name,
        )


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


_WINDOWS_TCP_TABLE_OWNER_PID_LISTENER = 3
_WINDOWS_TCP_TABLE_OWNER_PID_CONNECTIONS = 4
_WINDOWS_MIB_TCP_STATE_ESTAB = 5
_WindowsTCPRow = tuple[int, str, int, str, int, int]


def _windows_tcp_owner_rows(
    family: int,
    table_class: int,
) -> tuple[EvidenceStatus, list[_WindowsTCPRow]]:  # pragma: no cover - native Windows only
    """Read one GetExtendedTcpTable owner-PID table for ``family``.

    Rows are ``(state, local address, local port, remote address, remote
    port, owner PID)`` with ports in host order.
    """
    from ctypes import wintypes

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

    row_type: type[ctypes.Structure] = TCP4Row if family == socket.AF_INET else TCP6Row
    size = wintypes.ULONG(0)
    result = get_table(None, ctypes.byref(size), False, family, table_class, 0)
    if result not in (0, error_insufficient_buffer):
        return ("denied" if result == error_access_denied else "unavailable"), []
    if not size.value:
        return "ok", []
    buffer = ctypes.create_string_buffer(size.value)
    result = get_table(buffer, ctypes.byref(size), False, family, table_class, 0)
    if result == error_insufficient_buffer and size.value > len(buffer):
        # The table can grow between the sizing and fill calls.
        buffer = ctypes.create_string_buffer(size.value)
        result = get_table(buffer, ctypes.byref(size), False, family, table_class, 0)
    if result != 0:
        return ("denied" if result == error_access_denied else "unavailable"), []
    count = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD)).contents.value
    offset = ctypes.sizeof(wintypes.DWORD)
    # The table aligns its row array to the row's native alignment.
    alignment = ctypes.alignment(row_type)
    offset = (offset + alignment - 1) & ~(alignment - 1)
    rows: list[_WindowsTCPRow] = []
    for index in range(count):
        row = row_type.from_buffer_copy(buffer, offset + index * ctypes.sizeof(row_type))
        try:
            if family == socket.AF_INET:
                local_packed = int(row.local_addr).to_bytes(4, byteorder=sys.byteorder)
                remote_packed = int(row.remote_addr).to_bytes(4, byteorder=sys.byteorder)
            else:
                local_packed = bytes(row.local_addr)
                remote_packed = bytes(row.remote_addr)
            local_address = socket.inet_ntop(family, local_packed)
            remote_address = socket.inet_ntop(family, remote_packed)
        except (OSError, OverflowError, ValueError):
            continue
        rows.append(
            (
                int(row.state),
                local_address,
                socket.ntohs(row.local_port & 0xFFFF),
                remote_address,
                socket.ntohs(row.remote_port & 0xFFFF),
                int(row.pid),
            )
        )
    return "ok", rows


def _windows_listener_evidence(
    port: int,
    *,
    host: str = "",
) -> ListenerEvidence:  # pragma: no cover - native Windows only
    """Resolve a TCP listener owner with GetExtendedTcpTable (IPv4/IPv6)."""
    if not 1 <= port <= 65_535:
        return ListenerEvidence("unavailable", reason="configured API port is invalid")
    target_host = host.strip("[]")
    families: tuple[int, ...] = (socket.AF_INET, socket.AF_INET6)
    if target_host and target_host.casefold() != "localhost":
        try:
            target_version = ipaddress.ip_address(target_host).version
        except ValueError:
            return ListenerEvidence("unavailable", reason="configured API host is not an IP literal")
        families = (socket.AF_INET if target_version == 4 else socket.AF_INET6,)

    matching_pids: set[int] = set()
    query_errors: list[EvidenceStatus] = []
    for family in families:
        status, rows = _windows_tcp_owner_rows(family, _WINDOWS_TCP_TABLE_OWNER_PID_LISTENER)
        if status != "ok":
            query_errors.append(status)
            continue
        for _state, local_address, local_port, _remote_address, _remote_port, pid in rows:
            if local_port == port and _listener_address_matches(local_address, host):
                matching_pids.add(pid)
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


_Endpoint = tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]


def _socket_endpoint(address: object) -> _Endpoint | None:
    """Normalize ``(host, port, ...)``; IPv4-mapped IPv6 compares as IPv4.

    A dual-stack listener accepts an IPv4 client on an IPv6 socket, so the
    two ends of one loopback connection can name the same address in either
    family.
    """
    if not isinstance(address, tuple) or len(address) < 2:
        return None
    host, port = address[0], address[1]
    if not isinstance(host, str) or type(port) is not int or not 1 <= port <= 65_535:
        return None
    try:
        ip = ipaddress.ip_address(host.strip("[]").split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip, port


def _linux_proc_net_endpoint(field: str) -> _Endpoint | None:
    """Decode one ``/proc/net/tcp*`` ``ADDRESS:PORT`` field."""
    raw_address, separator, raw_port = field.rpartition(":")
    try:
        packed = bytes.fromhex(raw_address)
        port = int(raw_port, 16)
    except ValueError:
        return None
    if not separator or len(packed) not in (4, 16):
        return None
    if sys.byteorder == "little":
        # The kernel prints each 32-bit address word in host byte order.
        packed = b"".join(packed[index : index + 4][::-1] for index in range(0, len(packed), 4))
    return _socket_endpoint((str(ipaddress.ip_address(packed)), port))


def _linux_connection_owner(
    pid: int,
    local: _Endpoint,
    remote: _Endpoint,
    *,
    proc_root: str = "/proc",
) -> ListenerEvidence:
    """Find the accepted socket for ``local``<-``remote`` among ``pid``'s descriptors."""
    inode = ""
    table_found = False
    for table_name in ("tcp", "tcp6"):
        try:
            with open(os.path.join(proc_root, "net", table_name), encoding="ascii") as table:
                rows = table.readlines()[1:]
        except FileNotFoundError:
            continue
        except (OSError, UnicodeError):
            return ListenerEvidence("unavailable", reason="Linux connection table could not be read")
        table_found = True
        for row in rows:
            fields = row.split()
            # State 01 is ESTABLISHED.
            if len(fields) < 10 or fields[3] != "01":
                continue
            if _linux_proc_net_endpoint(fields[1]) == local and _linux_proc_net_endpoint(fields[2]) == remote:
                inode = fields[9]
                break
        if inode:
            break
    if not table_found:
        return ListenerEvidence("unavailable", reason="Linux connection tables are unavailable")
    if not inode.isdigit() or inode == "0":
        # The kernel gives a queued connection a socket inode only on accept.
        return ListenerEvidence("missing", reason="the connected server socket is not held by a process yet")
    target = f"socket:[{inode}]"
    try:
        descriptors = os.scandir(os.path.join(proc_root, str(pid), "fd"))
    except PermissionError:
        return ListenerEvidence("denied", reason="gateway process descriptors are not readable")
    except OSError:
        return ListenerEvidence("unavailable", reason="gateway process descriptors are unavailable")
    with descriptors:
        for descriptor in descriptors:
            try:
                if os.readlink(descriptor.path) == target:
                    return ListenerEvidence("ok", pid=pid)
            except OSError:
                continue
    return ListenerEvidence("missing", reason="the gateway process does not hold the connected server socket")


def trusted_lsof_path() -> str:
    """Return a fixed system lsof path, never a PATH-resolved executable."""
    for candidate in ("/usr/sbin/lsof", "/usr/bin/lsof"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return ""


def _lsof_endpoint(text: str) -> _Endpoint | None:
    address, separator, port = text.strip().rpartition(":")
    if not separator or not port.isdigit():
        return None
    return _socket_endpoint((address, int(port)))


def _lsof_connection_owner(pid: int, local: _Endpoint, remote: _Endpoint) -> ListenerEvidence:
    """Ask a fixed-path ``lsof`` whether ``pid`` holds ``local``<-``remote``."""
    lsof_path = trusted_lsof_path()
    if not lsof_path:
        return ListenerEvidence("unavailable", reason="trusted lsof binary is unavailable")
    try:
        proc = subprocess.run(
            [
                lsof_path,
                "-nP",
                "-a",
                "-p",
                str(pid),
                f"-iTCP:{remote[1]}",
                "-sTCP:ESTABLISHED",
                "-Fn",
            ],
            capture_output=True,
            text=True,
            shell=False,
            stdin=subprocess.DEVNULL,
            env=trusted_system_subprocess_env(),
            timeout=2.0,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return ListenerEvidence("unavailable", reason="lsof connection inspection failed")
    if proc.returncode != 0:
        if proc.returncode == 1 and not proc.stdout.strip():
            return ListenerEvidence("missing", reason="the gateway process does not hold the connected server socket")
        return ListenerEvidence("unavailable", reason="lsof connection inspection failed")
    for line in proc.stdout.splitlines():
        if not line.startswith("n"):
            continue
        source, arrow, destination = line[1:].partition("->")
        if arrow and _lsof_endpoint(source) == local and _lsof_endpoint(destination) == remote:
            return ListenerEvidence("ok", pid=pid)
    return ListenerEvidence("missing", reason="the gateway process does not hold the connected server socket")


def _windows_connection_owner(
    local: _Endpoint,
    remote: _Endpoint,
) -> ListenerEvidence:  # pragma: no cover - native Windows only
    """Return the owner PID of the ESTABLISHED ``local``<-``remote`` row."""
    query_errors: list[EvidenceStatus] = []
    for family in (socket.AF_INET, socket.AF_INET6):
        status, rows = _windows_tcp_owner_rows(family, _WINDOWS_TCP_TABLE_OWNER_PID_CONNECTIONS)
        if status != "ok":
            query_errors.append(status)
            continue
        for state, local_address, local_port, remote_address, remote_port, pid in rows:
            if (
                state == _WINDOWS_MIB_TCP_STATE_ESTAB
                and _socket_endpoint((local_address, local_port)) == local
                and _socket_endpoint((remote_address, remote_port)) == remote
            ):
                if pid <= 0:
                    return ListenerEvidence("unavailable", reason="connected server socket has no owner PID")
                return ListenerEvidence("ok", pid=pid)
    if "denied" in query_errors:
        return ListenerEvidence("denied", reason="connection ownership access denied")
    if query_errors:
        return ListenerEvidence("unavailable", reason="connection ownership could not be queried")
    return ListenerEvidence("missing", reason="the connected server socket is not visible")


def gateway_executable_name(path: str, *, platform_name: str | None = None) -> str:
    """Normalize a cross-platform executable basename for allowlist matching."""
    platform = (platform_name or ("win32" if os.name == "nt" else sys.platform)).lower()
    path_module = ntpath if platform in {"nt", "win32", "windows"} else posixpath
    return path_module.basename(path.strip()).lower()
