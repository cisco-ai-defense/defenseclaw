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

"""Cross-platform file-permission helpers for secret-bearing writes."""

from __future__ import annotations

import contextlib
import os
import stat
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Callable
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import TextIO


class UnsafePathError(OSError):
    """Raised when a sensitive write would traverse a reparse point."""


MAX_DOTENV_BYTES = 1024 * 1024

_DOTENV_PROCESS_CONTROL_NAMES = frozenset(
    {
        "ALL_PROXY",
        "BASH_ENV",
        "CLAUDE_CONFIG_DIR",
        "CODEX_HOME",
        "COMSPEC",
        "CURL_CA_BUNDLE",
        "DEFENSECLAW_CONFIG",
        "DEFENSECLAW_CODEX_LOOPBACK_TRUST",
        "DEFENSECLAW_DATA_DIR",
        "DEFENSECLAW_DAEMON",
        "DEFENSECLAW_DEV",
        "DEFENSECLAW_DISABLE_AWS_HTTP1_SHIM",
        "DEFENSE" + "CLAW_DISABLE_REDACTION",
        "DEFENSECLAW_DUMP_RAW_SECRETS",
        "DEFENSECLAW_FAIL_MODE",
        "DEFENSECLAW_FORCE_AWS_HTTP1_SHIM",
        "DEFENSECLAW_GATEWAY_BIN",
        "DEFENSECLAW_HOME",
        "DEFENSECLAW_JSONL_DISABLE",
        "DEFENSECLAW_OPENSHELL_ALLOW_UNPINNED",
        "DEFENSECLAW_OTEL_TLS_INSECURE",
        "DEFENSECLAW_POLICY_VALIDATE_ALLOW_NO_OPA",
        "DEFENSECLAW_PREPAIR_TRUST_DEVICE_KEY",
        "DEFENSECLAW_REVEAL_PII",
        "DEFENSECLAW_SANDBOX_FORCE_REGEX_CLEANUP",
        "DEFENSECLAW_STRICT_AVAILABILITY",
        "DEFENSECLAW_TEST",
        "DEFENSECLAW_TOOL_INSPECT_FAIL_OPEN",
        "DEFENSECLAW_TRUSTED_PROXY_CIDRS",
        "DEFENSECLAW_UNGUARDED_CHATGPT_CODEX_RESPONSES",
        "DEFENSECLAW_UPGRADE_ALLOW_UNVERIFIED",
        "DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST",
        "ENV",
        "GIT_SSL_NO_VERIFY",
        "HOME",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "LOCPATH",
        "NO_PROXY",
        "NODE_EXTRA_CA_CERTS",
        "NODE_OPTIONS",
        "PATH",
        "PATHEXT",
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "WINDIR",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_RUNTIME_DIR",
        "XDG_STATE_HOME",
    }
)
_DOTENV_PROCESS_CONTROL_PREFIXES = ("DYLD_", "LD_")
_DOTENV_PROCESS_CONTROL_DEFENSECLAW_PREFIXES = ("DEFENSE" + "CLAW_ALLOW_",)


def dotenv_key_is_valid(key: str) -> bool:
    """Return whether *key* is one portable ASCII environment name."""
    return bool(
        key
        and key.isascii()
        and (key[0].isalpha() or key[0] == "_")
        and all(character.isalnum() or character == "_" for character in key)
    )


def dotenv_key_is_process_control(key: str) -> bool:
    """Return whether a dotenv key can redirect or inject a child process."""
    normalized = key.strip().upper()
    return normalized in _DOTENV_PROCESS_CONTROL_NAMES or normalized.startswith(
        _DOTENV_PROCESS_CONTROL_PREFIXES + _DOTENV_PROCESS_CONTROL_DEFENSECLAW_PREFIXES
    )


def _windows_extended_path(path: str | os.PathLike[str]) -> str:
    """Return an absolute Win32 path that is not limited by ``MAX_PATH``."""

    value = os.path.abspath(os.fspath(path))
    if value.startswith(("\\\\?\\", "\\\\.\\")):
        return value
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value


def _sync_directory(path: str | os.PathLike[str]) -> None:
    """Persist a directory-entry mutation where the platform supports it."""

    if os.name == "nt":
        # Windows replacements use MOVEFILE_WRITE_THROUGH below. Opening a
        # directory for FlushFileBuffers is filesystem/privilege dependent and
        # adds no stronger guarantee than that documented primitive.
        return
    fd = os.open(os.fspath(path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def replace_file_durable(source: str | os.PathLike[str], target: str | os.PathLike[str]) -> None:
    """Atomically replace *target* and durably commit the directory entry.

    ``os.replace`` provides name atomicity but does not request write-through
    on Windows. Installer migrations use the resulting file as a recovery
    boundary, so native Windows uses ``MoveFileExW`` with both
    ``MOVEFILE_REPLACE_EXISTING`` and ``MOVEFILE_WRITE_THROUGH``. POSIX uses a
    sibling rename followed by an fsync of the containing directory.
    """

    source_path = os.path.abspath(os.fspath(source))
    target_path = os.path.abspath(os.fspath(target))
    if os.path.normcase(os.path.dirname(source_path)) != os.path.normcase(os.path.dirname(target_path)):
        raise OSError("durable atomic replacement requires sibling paths")
    if os.name != "nt":
        os.replace(source_path, target_path)
        _sync_directory(os.path.dirname(target_path) or os.curdir)
        return

    import ctypes
    from ctypes import wintypes

    movefile_replace_existing = 0x00000001
    movefile_write_through = 0x00000008
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    move_file_ex = kernel32.MoveFileExW
    move_file_ex.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    move_file_ex.restype = wintypes.BOOL
    if not move_file_ex(
        _windows_extended_path(source_path),
        _windows_extended_path(target_path),
        movefile_replace_existing | movefile_write_through,
    ):
        raise ctypes.WinError(ctypes.get_last_error())


def delete_file_durable(path: str | os.PathLike[str]) -> None:
    """Durably remove one file without exposing a partially deleted name.

    On Windows, first write-through rename the file to a unique sibling. A
    crash can therefore leave only an inert tombstone, never the live legacy
    filename that a downgraded process would consume again. The tombstone is
    then unlinked immediately. We deliberately do not glob-delete tombstones
    on a later run: without a durable ownership record, a matching filename is
    not sufficient proof that DefenseClaw owns an artifact. POSIX unlinks and
    fsyncs the parent directory.
    """

    target = os.path.abspath(os.fspath(path))
    parent = os.path.dirname(target) or os.curdir
    if os.name != "nt":
        os.unlink(target)
        _sync_directory(parent)
        return
    tombstone = os.path.join(parent, f".{os.path.basename(target)}.deleted.{uuid.uuid4().hex}")
    replace_file_durable(target, tombstone)
    try:
        os.unlink(tombstone)
    except OSError as exc:
        raise OSError(f"removed live path but could not delete durable tombstone {tombstone}: {exc}") from exc


def reject_reparse_path(path: str | os.PathLike[str]) -> None:
    """Reject a leaf or Windows ancestor that redirects filesystem access."""
    target = os.path.abspath(os.fspath(path))
    _reject_reparse_chain(os.path.dirname(target) or os.curdir)
    _reject_reparse_path(target, allow_missing=True)


def make_private_directory(path: str | os.PathLike[str]) -> None:
    """Create or tighten one operator-private directory cross-platform."""
    target = os.path.abspath(os.fspath(path))
    _reject_reparse_chain(os.path.dirname(target) or os.curdir)
    _make_private_directories(target)
    _reject_reparse_path(target, allow_missing=False)
    _protect_private_directory(target)


def protect_private_file(path: str | os.PathLike[str]) -> None:
    """Tighten an existing regular file to POSIX 0600 or a private DACL."""
    target = os.path.abspath(os.fspath(path))
    fd = open_regular_file_no_follow(target)
    try:
        set_file_mode(fd, target, 0o600)
    finally:
        os.close(fd)


def open_regular_file_no_follow(
    path: str | os.PathLike[str],
    *,
    expected_stat: os.stat_result | None = None,
    _deny_write_sharing: bool = False,
) -> int:
    """Open one regular file without following a swapped symlink/reparse point.

    ``expected_stat`` lets a caller bind this open to an identity it inspected
    before entering the shared reader. This closes an A→B→A pathname swap in
    callers that perform custody checks before reading the file.
    """
    target = os.path.abspath(os.fspath(path))
    _reject_reparse_chain(os.path.dirname(target) or os.curdir)
    expected = _reject_reparse_path(target, allow_missing=False)
    assert expected is not None
    if expected_stat is not None and not os.path.samestat(expected_stat, expected):
        raise UnsafePathError(f"sensitive file changed before opening: {target}")
    if not stat.S_ISREG(expected.st_mode):
        raise UnsafePathError(f"refusing sensitive access to non-file: {target}")
    # Windows CRT text mode translates CRLF while ``fstat().st_size`` reports
    # the exact bytes on disk. Callers that bind security evidence to the
    # opened file size must therefore always receive a binary descriptor.
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    if os.name == "nt" and _deny_write_sharing:
        fd = _open_windows_stable_read_fd(target)
    else:
        fd = os.open(target, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise UnsafePathError(f"refusing sensitive access to non-file: {target}")
        if not os.path.samestat(expected, opened):
            raise UnsafePathError(f"sensitive file changed while opening: {target}")
    except Exception:
        os.close(fd)
        raise
    return fd


def _open_windows_stable_read_fd(path: str) -> int:
    """Open a binary CRT reader backed by an NT handle that denies writers."""
    import ctypes
    import msvcrt
    from ctypes import wintypes

    generic_read = 0x80000000
    file_share_read = 0x00000001
    file_share_delete = 0x00000004
    open_existing = 3
    file_flag_open_reparse_point = 0x00200000
    invalid_handle = ctypes.c_void_p(-1).value

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    handle = create_file(
        _windows_extended_path(path),
        generic_read,
        file_share_read | file_share_delete,
        None,
        open_existing,
        file_flag_open_reparse_point,
        None,
    )
    if handle == invalid_handle:
        raise ctypes.WinError(ctypes.get_last_error())
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    try:
        return msvcrt.open_osfhandle(handle, flags)
    except BaseException:
        close_handle(handle)
        raise


def _windows_file_stability_times(fd: int) -> tuple[int, int]:
    """Return handle-bound NT last-write and change times."""
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class _FileBasicInfo(ctypes.Structure):
        _fields_ = [
            ("creation_time", ctypes.c_longlong),
            ("last_access_time", ctypes.c_longlong),
            ("last_write_time", ctypes.c_longlong),
            ("change_time", ctypes.c_longlong),
            ("file_attributes", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_file_information = kernel32.GetFileInformationByHandleEx
    get_file_information.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    get_file_information.restype = wintypes.BOOL
    basic = _FileBasicInfo()
    file_basic_info = 0
    if not get_file_information(
        msvcrt.get_osfhandle(fd),
        file_basic_info,
        ctypes.byref(basic),
        ctypes.sizeof(basic),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    return basic.last_write_time, basic.change_time


def _file_stability_snapshot(fd: int) -> tuple[int, int, int, int, int]:
    """Capture metadata that changes when an open file is mutated in place."""
    opened = os.fstat(fd)
    native_modified = 0
    native_changed = 0
    if os.name == "nt":
        native_modified, native_changed = _windows_file_stability_times(fd)
    return (
        opened.st_size,
        opened.st_mtime_ns,
        opened.st_ctime_ns,
        native_modified,
        native_changed,
    )


def read_regular_file_no_follow(
    path: str | os.PathLike[str],
    *,
    max_bytes: int,
    expected_stat: os.stat_result | None = None,
) -> bytes:
    """Read one stable bounded file without following links or blocking on FIFOs."""
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    target = os.path.abspath(os.fspath(path))
    fd = open_regular_file_no_follow(
        target,
        expected_stat=expected_stat,
        _deny_write_sharing=True,
    )
    try:
        opened = os.fstat(fd)
        before = _file_stability_snapshot(fd)
        if before[0] > max_bytes:
            raise UnsafePathError(f"sensitive file exceeds {max_bytes}-byte read limit")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(fd, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        body = b"".join(chunks)
        after = _file_stability_snapshot(fd)
    finally:
        os.close(fd)
    if len(body) > max_bytes:
        raise UnsafePathError(f"sensitive file exceeds {max_bytes}-byte read limit")
    if before != after or len(body) != before[0]:
        raise UnsafePathError(f"sensitive file changed while reading: {target}")
    _reject_reparse_chain(os.path.dirname(target) or os.curdir)
    current = _reject_reparse_path(target, allow_missing=False)
    assert current is not None
    if not os.path.samestat(opened, current):
        raise UnsafePathError(f"sensitive file changed while reading: {target}")
    return body


def trusted_system_subprocess_env() -> dict[str, str]:
    """Return a minimal environment for fixed-path OS evidence commands."""
    allowed = (
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TZ",
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
    )
    return {name: os.environ[name] for name in allowed if name in os.environ}


def trusted_posix_executable_path(path: str | os.PathLike[str]) -> str:
    """Resolve an executable held only by root/current-user, non-writable paths."""
    if os.name == "nt":
        raise OSError("POSIX executable custody is unavailable on Windows")
    raw_path = os.fspath(path)
    if not os.path.isabs(raw_path):
        raise UnsafePathError("gateway executable path is not absolute")
    candidate = os.path.abspath(raw_path)
    resolved = os.path.realpath(candidate)
    try:
        info = os.lstat(resolved)
    except OSError as exc:
        raise UnsafePathError("gateway executable could not be inspected") from exc
    if not stat.S_ISREG(info.st_mode) or not os.access(resolved, os.X_OK):
        raise UnsafePathError("gateway executable is not an executable regular file")
    geteuid = getattr(os, "geteuid", None)
    current_uid = geteuid() if callable(geteuid) else info.st_uid
    if info.st_uid not in {0, current_uid} or stat.S_IMODE(info.st_mode) & 0o022:
        raise UnsafePathError("gateway executable is writable by an untrusted principal")
    if sys.platform == "darwin" and darwin_acl_write_error(resolved):
        raise UnsafePathError("gateway executable has a write-capable extended ACL")

    current = Path(resolved).parent
    while True:
        parent_info = os.lstat(current)
        if not stat.S_ISDIR(parent_info.st_mode):
            raise UnsafePathError("gateway executable ancestor is not a directory")
        if parent_info.st_uid not in {0, current_uid} or stat.S_IMODE(parent_info.st_mode) & 0o022:
            raise UnsafePathError("gateway executable ancestor is writable by an untrusted principal")
        if sys.platform == "darwin" and darwin_acl_write_error(current):
            raise UnsafePathError("gateway executable ancestor has a write-capable extended ACL")
        if current.parent == current:
            break
        current = current.parent
    return resolved


def _darwin_acl_output(path: str | os.PathLike[str]) -> tuple[str, str]:
    """Return ``(mode, ACL text)`` from a fixed-path Darwin inspection."""
    if sys.platform != "darwin":
        return "", ""
    try:
        result = subprocess.run(
            ["/bin/ls", "-lde", os.path.abspath(os.fspath(path))],
            capture_output=True,
            text=True,
            shell=False,
            stdin=subprocess.DEVNULL,
            env=trusted_system_subprocess_env(),
            timeout=2.0,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return "", ""
    if result.returncode != 0:
        return "", ""
    lines = result.stdout.splitlines()
    first_line = lines[0] if lines else ""
    mode_field = first_line.split(maxsplit=1)[0] if first_line else ""
    return mode_field, "\n".join(lines[1:])


def _darwin_acl_allows(acl_text: str, permissions: frozenset[str]) -> bool:
    for raw_line in acl_text.splitlines():
        line = raw_line.strip().lower()
        if " allow " not in f" {line} ":
            continue
        granted = line.rsplit(" allow ", 1)[-1]
        words = {word.strip() for word in granted.replace(":", ",").split(",")}
        if words & permissions:
            return True
    return False


def darwin_acl_confidentiality_error(path: str | os.PathLike[str]) -> str | None:
    """Return whether a Darwin ACL grants file-content read access."""
    if sys.platform != "darwin":
        return None
    mode_field, acl_text = _darwin_acl_output(path)
    if not mode_field:
        return "extended ACL could not be inspected"
    if not acl_text:
        return "extended ACL could not be interpreted" if "+" in mode_field else None
    read_permissions = frozenset({"read", "readattr", "readextattr"})
    return "extended ACL grants additional read access" if _darwin_acl_allows(acl_text, read_permissions) else None


def darwin_acl_write_error(path: str | os.PathLike[str]) -> str | None:
    """Return whether a Darwin ACL grants file-integrity-changing access."""
    if sys.platform != "darwin":
        return None
    mode_field, acl_text = _darwin_acl_output(path)
    if not mode_field:
        return "extended ACL could not be inspected"
    if not acl_text:
        return "extended ACL could not be interpreted" if "+" in mode_field else None
    write_permissions = frozenset(
        {
            "add_file",
            "add_subdirectory",
            "append",
            "chown",
            "delete",
            "delete_child",
            "write",
            "writeattr",
            "writeextattr",
            "writesecurity",
        }
    )
    return "extended ACL grants additional write access" if _darwin_acl_allows(acl_text, write_permissions) else None


def _clear_darwin_extended_acl(fd: int, path: str) -> None:
    """Remove a Darwin extended ACL and prove the path still names *fd*."""
    expected = os.fstat(fd)
    try:
        result = subprocess.run(
            ["/bin/chmod", "-N", f"/dev/fd/{fd}"],
            capture_output=True,
            text=True,
            shell=False,
            stdin=subprocess.DEVNULL,
            env=trusted_system_subprocess_env(),
            pass_fds=(fd,),
            timeout=2.0,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        raise OSError("could not clear the private file's extended ACL") from exc
    if result.returncode != 0:
        raise OSError("could not clear the private file's extended ACL")
    current = os.lstat(path)
    if not os.path.samestat(expected, current):
        raise UnsafePathError("sensitive file changed while clearing its extended ACL")


def set_file_mode(fd: int, path: str, mode: int, *, set_owner: bool = False) -> None:
    """Apply *mode* to the open file described by *fd* and *path*.

    POSIX uses the descriptor so the permission change cannot be redirected
    through a path race. Windows has no :func:`os.fchmod`, and its
    :func:`os.chmod` only toggles the read-only attribute; for owner-only
    modes, install a protected owner/SYSTEM DACL before secret bytes are
    written instead.

    The caller must keep *fd* open for the duration of this call. Windows CRT
    descriptors deny delete sharing, which keeps *path* bound to that file
    while ``SetFileSecurityW`` applies the DACL. ``set_owner`` is reserved for
    a DefenseClaw-managed path opened for creation or an authorized rewrite;
    operator-selected existing paths must leave it disabled.
    """
    if os.name == "nt":
        if mode & 0o077 == 0:
            _set_windows_owner_only_acl(path, set_owner=set_owner)
        else:
            os.chmod(path, mode)
        return

    fchmod = getattr(os, "fchmod", None)
    if fchmod is not None:
        fchmod(fd, mode)
    else:
        os.chmod(path, mode)
    if sys.platform == "darwin" and mode & 0o077 == 0:
        _clear_darwin_extended_acl(fd, path)
        if fchmod is not None:
            fchmod(fd, mode)


def atomic_write_text_secure(
    path: str,
    write: Callable[[TextIO], None],
    *,
    prefix: str,
) -> None:
    """Atomically replace a secret-bearing text file without widening access.

    A new parent directory is owner-only on POSIX, while an existing directory
    is never chmodded. The staging file is protected before ``write`` receives
    its stream, and every failure path closes and removes the staging file.
    """
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)

    target_mode = 0o600
    if os.name != "nt":
        try:
            existing_mode = stat.S_IMODE(os.stat(path).st_mode)
        except OSError:
            existing_mode = None
        if existing_mode is not None and existing_mode != 0o600:
            target_mode = existing_mode & 0o600
            if target_mode == 0o600 and existing_mode & 0o077 == 0o040:
                target_mode = 0o640
            elif target_mode == 0:
                target_mode = 0o600

    fd = -1
    tmp = ""
    try:
        fd, tmp = tempfile.mkstemp(prefix=prefix, suffix=".tmp", dir=directory)
        set_file_mode(fd, tmp, target_mode, set_owner=True)
        stream = os.fdopen(fd, "w")
        fd = -1
        with stream:
            write(stream)
            stream.flush()
            os.fsync(stream.fileno())
        replace_file_durable(tmp, path)
        tmp = ""
    finally:
        if fd != -1:
            with contextlib.suppress(OSError):
                os.close(fd)
        if tmp:
            with contextlib.suppress(OSError):
                os.unlink(tmp)


def copy_windows_dacl(source: str, destination: str) -> None:
    """Copy the Windows DACL from *source* to *destination*.

    Atomic replacement creates a new file, so Windows ACLs do not follow the
    old path automatically. This preserves an operator-hardened DACL (and also
    avoids tightening a deliberately shared non-secret file) across rewrite.
    """
    if os.name != "nt":
        raise OSError("Windows DACL copying is only available on Windows")

    import ctypes
    from ctypes import wintypes

    dacl_security_information = 0x00000004
    protected_dacl_security_information = 0x80000000
    error_insufficient_buffer = 122

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    get_file_security = advapi32.GetFileSecurityW
    get_file_security.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    get_file_security.restype = wintypes.BOOL

    get_descriptor_dacl = advapi32.GetSecurityDescriptorDacl
    get_descriptor_dacl.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.BOOL),
    ]
    get_descriptor_dacl.restype = wintypes.BOOL

    set_named_security_info = advapi32.SetNamedSecurityInfoW
    set_named_security_info.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
    ]
    set_named_security_info.restype = wintypes.DWORD

    needed = wintypes.DWORD()
    ctypes.set_last_error(0)
    found = get_file_security(
        source,
        dacl_security_information,
        None,
        0,
        ctypes.byref(needed),
    )
    error = ctypes.get_last_error()
    if not found and error != error_insufficient_buffer:
        raise ctypes.WinError(error)

    descriptor = ctypes.create_string_buffer(needed.value)
    if not get_file_security(
        source,
        dacl_security_information,
        descriptor,
        needed,
        ctypes.byref(needed),
    ):
        raise ctypes.WinError(ctypes.get_last_error())

    dacl_present = wintypes.BOOL()
    dacl = wintypes.LPVOID()
    dacl_defaulted = wintypes.BOOL()
    if not get_descriptor_dacl(
        descriptor,
        ctypes.byref(dacl_present),
        ctypes.byref(dacl),
        ctypes.byref(dacl_defaulted),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    if not dacl_present.value or not dacl.value:
        raise OSError(f"refusing to copy a missing or NULL Windows DACL: {source}")

    result = set_named_security_info(
        destination,
        1,  # SE_FILE_OBJECT
        dacl_security_information | protected_dacl_security_information,
        None,
        None,
        dacl,
        None,
    )
    if result:
        raise OSError(result, ctypes.FormatError(result), destination)
    if not _windows_dacl_is_protected(destination):
        raise OSError(f"copied Windows DACL remains inheritable: {destination}")


def _windows_dacl_is_protected(path: str | os.PathLike[str]) -> bool:
    """Return whether *path* has the ``SE_DACL_PROTECTED`` control bit."""

    if os.name != "nt":
        raise OSError("Windows DACL inspection is only available on Windows")

    import ctypes
    from ctypes import wintypes

    dacl_security_information = 0x00000004
    error_insufficient_buffer = 122
    se_dacl_protected = 0x1000

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    get_file_security = advapi32.GetFileSecurityW
    get_file_security.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    get_file_security.restype = wintypes.BOOL
    get_descriptor_control = advapi32.GetSecurityDescriptorControl
    get_descriptor_control.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    get_descriptor_control.restype = wintypes.BOOL

    needed = wintypes.DWORD()
    ctypes.set_last_error(0)
    found = get_file_security(
        os.fspath(path),
        dacl_security_information,
        None,
        0,
        ctypes.byref(needed),
    )
    error = ctypes.get_last_error()
    if not found and error != error_insufficient_buffer:
        raise ctypes.WinError(error)

    descriptor = ctypes.create_string_buffer(needed.value)
    if not get_file_security(
        os.fspath(path),
        dacl_security_information,
        descriptor,
        needed,
        ctypes.byref(needed),
    ):
        raise ctypes.WinError(ctypes.get_last_error())

    control = wintypes.WORD()
    revision = wintypes.DWORD()
    if not get_descriptor_control(
        descriptor,
        ctypes.byref(control),
        ctypes.byref(revision),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    return bool(control.value & se_dacl_protected)


def _windows_private_target_problem(path: str) -> str | None:
    try:
        problem = windows_acl_confidentiality_error(path)
    except OSError as exc:
        return f"ACL inspection failed: {exc}"
    if problem is not None:
        return problem
    try:
        required_access = _windows_acl_has_required_access(path)
    except OSError as exc:
        return f"ACL access verification failed: {exc}"
    if not required_access:
        return "owner/SYSTEM access missing"
    return None


def _verify_or_repair_windows_private_target(path: str) -> None:
    """Repair or remove a replaced private file whose DACL cannot be verified."""

    problem = _windows_private_target_problem(path)
    if problem is None:
        return

    repair_error: OSError | None = None
    try:
        _set_windows_owner_only_acl(path)
    except OSError as exc:
        repair_error = exc
    else:
        problem = _windows_private_target_problem(path)
        if problem is None:
            return

    cleanup_error: OSError | None = None
    try:
        os.unlink(path)
    except OSError as exc:
        cleanup_error = exc

    detail = problem
    if repair_error is not None:
        detail += f"; repair failed: {repair_error}"
    if cleanup_error is not None:
        detail += f"; cleanup failed: {cleanup_error}"
    raise OSError(f"private Windows DACL verification failed: {detail}")


def atomic_write_private(
    path: str | os.PathLike[str],
    write: Callable[[int], None],
    *,
    protect_parent: bool = True,
) -> None:
    """Atomically materialize a sensitive file with native protections.

    The random same-directory staging file is protected before ``write`` is
    called.  Existing safe Windows DACLs are copied to the replacement so an
    operator-hardened target is never widened. Unsafe inherited read or write
    grants are replaced by the canonical owner/SYSTEM policy instead.
    """
    target = os.path.abspath(os.fspath(path))
    parent = os.path.dirname(target) or os.curdir
    _reject_reparse_chain(parent)
    _make_private_directories(parent)
    with _hold_windows_directory(parent):
        _reject_reparse_chain(parent)
        if protect_parent:
            _protect_private_directory(parent)
        else:
            _validate_unmodified_parent(parent)
        _reject_reparse_path(target, allow_missing=True)

        fd = -1
        tmp = ""
        try:
            fd, tmp = tempfile.mkstemp(
                prefix=f".{os.path.basename(target)}.",
                suffix=".tmp",
                dir=parent,
            )
            set_file_mode(fd, tmp, 0o600, set_owner=True)
            write(fd)
            os.fsync(fd)
            os.close(fd)
            fd = -1

            _reject_reparse_chain(parent)
            _reject_reparse_path(target, allow_missing=True)
            if os.name == "nt" and os.path.exists(target):
                # Preserve an existing DACL only when it grants no untrusted
                # read or write access. A readable inherited DACL must not be
                # copied onto the new secret-bearing staging file.
                if windows_acl_confidentiality_error(target) is None and _windows_acl_has_required_access(target):
                    copy_windows_dacl(target, tmp)
            replace_file_durable(tmp, target)
            tmp = ""
            if os.name == "nt":
                _verify_or_repair_windows_private_target(target)
        finally:
            if fd != -1:
                with suppress(OSError):
                    os.close(fd)
            if tmp:
                with suppress(OSError):
                    os.unlink(tmp)


def atomic_write_private_bytes(path: str | os.PathLike[str], data: bytes, *, protect_parent: bool = True) -> None:
    """Convenience wrapper for a complete in-memory payload."""

    def _write(fd: int) -> None:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write while materializing private file")
            view = view[written:]

    atomic_write_private(path, _write, protect_parent=protect_parent)


def windows_acl_write_error(path: str | os.PathLike[str]) -> str | None:
    """Return why an untrusted SID can write *path*, or ``None`` when safe."""
    if os.name != "nt":
        return None
    try:
        owner_sid, null_dacl, entries = _windows_acl_snapshot(os.fspath(path))
    except OSError as exc:
        return f"cannot read Windows ACL ({exc})"
    if null_dacl:
        return "ACL grants write access to Everyone (null DACL)"

    try:
        current_sid = _windows_current_user_sid()
    except OSError:
        return "current user SID could not be resolved"
    if not current_sid:
        return "current user SID could not be resolved"
    if owner_sid != current_sid:
        return f"owner SID {owner_sid or '<unknown>'} is not the current user"

    trusted = {"S-1-3-4", "S-1-5-18", current_sid}  # OWNER RIGHTS, LocalSystem, current user
    write_mask = 0x10000000 | 0x40000000 | 0x000D0156
    for permissions, access_mode, inheritance, sid in entries:
        if access_mode not in (1, 2) or not permissions & write_mask:
            continue
        if sid in trusted:
            continue
        if sid == "S-1-3-0" and inheritance & 0x08:
            continue
        return f"ACL grants write access to untrusted SID {sid or '<unknown>'}"
    return None


def windows_acl_custody_write_error(
    path: str | os.PathLike[str],
    *,
    allow_current_user: bool,
    require_current_user_owner: bool = False,
) -> str | None:
    """Return why a path is outside trusted Windows write custody.

    Private credential files use :func:`windows_acl_write_error`, which
    deliberately requires current-user ownership. Executable and ancestor
    custody must also admit objects owned by Windows itself. This validator
    accepts only LocalSystem, BUILTIN\\Administrators, TrustedInstaller, and
    optionally the current user as owners or write-capable trustees. Runtime
    state can additionally require current-user ownership while still
    admitting Windows system controllers as write-capable trustees.
    """
    if os.name != "nt":
        return None
    try:
        owner_sid, null_dacl, entries = _windows_acl_snapshot(os.fspath(path))
    except OSError as exc:
        return f"cannot read Windows ACL ({exc})"
    if null_dacl:
        return "ACL grants write access to Everyone (null DACL)"

    current_sid = ""
    trust_current_user = allow_current_user or require_current_user_owner
    if trust_current_user:
        try:
            current_sid = _windows_current_user_sid()
        except OSError:
            return "current user SID could not be resolved"
        if not current_sid:
            return "current user SID could not be resolved"
    system_controllers = {
        "S-1-5-18",  # LocalSystem
        "S-1-5-32-544",  # BUILTIN\Administrators
        # NT SERVICE\TrustedInstaller
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
    }
    trusted_owners = set(system_controllers)
    if trust_current_user:
        trusted_owners.add(current_sid)
    if require_current_user_owner and owner_sid != current_sid:
        return f"owner SID {owner_sid or '<unknown>'} is not the current user"
    if not require_current_user_owner and owner_sid not in trusted_owners:
        return f"owner SID {owner_sid or '<unknown>'} is not a trusted custody principal"

    trusted_writers = system_controllers | {
        "S-1-3-4",  # OWNER RIGHTS, constrained by the owner check above
        owner_sid,
    }
    if trust_current_user:
        trusted_writers.add(current_sid)
    write_mask = 0x10000000 | 0x40000000 | 0x000D0156
    for permissions, access_mode, inheritance, sid in entries:
        if access_mode not in (1, 2) or not permissions & write_mask:
            continue
        if sid in trusted_writers:
            continue
        if sid == "S-1-3-0" and inheritance & 0x08:
            continue
        return f"ACL grants write access to untrusted SID {sid or '<unknown>'}"
    return None


def windows_acl_confidentiality_error(path: str | os.PathLike[str]) -> str | None:
    """Return why *path* does not have a private Windows DACL.

    ``windows_acl_write_error`` protects integrity, but a secret-bearing file
    can still be unsafe when another principal has read-only access.  This
    stricter validator accepts effective read/write grants only for the current
    owner, Owner Rights, and LocalSystem.  Inherit-only ACEs do not apply to the
    file itself and are therefore ignored.

    Non-Windows callers receive ``None`` so cross-platform permission checks can
    use this helper without importing Win32 APIs.
    """
    if os.name != "nt":
        return None
    try:
        owner_sid, null_dacl, entries = _windows_acl_snapshot(os.fspath(path))
    except OSError as exc:
        return f"cannot read Windows ACL ({exc})"
    if null_dacl:
        return "ACL grants read/write access to Everyone (null DACL)"

    try:
        current_sid = _windows_current_user_sid()
    except OSError:
        return "current user SID could not be resolved"
    if not current_sid:
        return "current user SID could not be resolved"
    if owner_sid != current_sid:
        return f"owner SID {owner_sid or '<unknown>'} is not the current user"

    trusted = {"S-1-3-4", "S-1-5-18", current_sid}  # OWNER RIGHTS, LocalSystem, current user
    # Content confidentiality depends on GENERIC_READ/GENERIC_ALL or
    # FILE_READ_DATA. Metadata-only rights such as READ_CONTROL and
    # FILE_READ_ATTRIBUTES do not reveal secret bytes.
    read_mask = 0x80000000 | 0x10000000 | 0x00000001
    write_mask = 0x10000000 | 0x40000000 | 0x000D0156
    inherit_only_ace = 0x08
    for permissions, access_mode, inheritance, sid in entries:
        if access_mode not in (1, 2) or inheritance & inherit_only_ace:
            continue
        if sid in trusted:
            continue
        if permissions & read_mask:
            return f"ACL grants read access to untrusted SID {sid or '<unknown>'}"
        if permissions & write_mask:
            return f"ACL grants write access to untrusted SID {sid or '<unknown>'}"
    if not _windows_acl_has_required_access(path):
        return "owner/SYSTEM effective access is missing"
    return None


def _protect_private_directory(path: str) -> None:
    if os.name != "nt":
        if os.stat(path).st_mode & 0o077:
            os.chmod(path, 0o700)
        return
    owner_sid, _null_dacl, _entries = _windows_acl_snapshot(path)
    if owner_sid != _windows_current_user_sid():
        raise OSError(f"refusing to protect foreign-owned directory: {path}")
    problem = windows_acl_write_error(path)
    if problem is not None or not _windows_acl_has_required_access(path):
        _set_windows_owner_only_acl(path)
        problem = windows_acl_write_error(path)
        if problem is not None:
            raise OSError(f"cannot protect private directory {path}: {problem}")
    else:
        # Freeze an already-safe inherited DACL without changing its ACEs.
        copy_windows_dacl(path, path)


def _validate_unmodified_parent(path: str) -> None:
    """Fail closed when an operator-selected parent is replaceable by others."""
    if os.name == "nt":
        problem = windows_acl_write_error(path)
        if problem is not None:
            raise OSError(f"unsafe export parent {path}: {problem}")
        return
    info = os.stat(path)
    writable_by_others = info.st_mode & 0o022
    sticky = info.st_mode & 0o1000
    if writable_by_others and not sticky:
        raise OSError(f"unsafe group/world-writable export parent: {path}")


def _make_private_directories(path: str) -> None:
    """Create missing Windows directories with the policy DACL at creation."""
    if os.name != "nt":
        os.makedirs(path, mode=0o700, exist_ok=True)
        return
    import ctypes
    from ctypes import wintypes

    missing: list[str] = []
    current = os.path.abspath(path)
    while not os.path.lexists(current):
        missing.append(current)
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    if not missing:
        return

    class _SecurityAttributes(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", wintypes.LPVOID),
            ("bInheritHandle", wintypes.BOOL),
        ]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    convert = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.DWORD),
    ]
    convert.restype = wintypes.BOOL
    create_directory = kernel32.CreateDirectoryW
    create_directory.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(_SecurityAttributes)]
    create_directory.restype = wintypes.BOOL
    local_free = kernel32.LocalFree
    local_free.argtypes = [wintypes.HLOCAL]
    local_free.restype = wintypes.HLOCAL

    descriptor = wintypes.LPVOID()
    sddl = _windows_private_directory_sddl()
    if not convert(sddl, 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
    try:
        for directory in reversed(missing):
            if not create_directory(directory, ctypes.byref(attributes)):
                error = ctypes.get_last_error()
                if error != 183:  # ERROR_ALREADY_EXISTS: validate the racing object below.
                    raise ctypes.WinError(error)
            _reject_reparse_path(directory, allow_missing=False)
            _protect_private_directory(directory)
    finally:
        local_free(descriptor)


def _windows_private_directory_sddl() -> str:
    """Build the creation descriptor for a current-user-owned directory."""
    owner_sid = _windows_current_user_sid()
    return f"O:{owner_sid}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)"


@contextmanager
def _hold_windows_directory(path: str):
    """Hold the parent without delete sharing so it cannot be swapped mid-write."""
    if os.name != "nt":
        yield
        return
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    handle = create_file(
        path,
        0x00000001 | 0x00000080,  # FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES
        0x00000001 | 0x00000002,  # FILE_SHARE_READ | FILE_SHARE_WRITE; deliberately no DELETE
        None,
        3,  # OPEN_EXISTING
        0x02000000 | 0x00200000,  # BACKUP_SEMANTICS | OPEN_REPARSE_POINT
        None,
    )
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        yield
    finally:
        close_handle(handle)


def _windows_acl_has_required_access(path: str | os.PathLike[str]) -> bool:
    owner_sid, null_dacl, entries = _windows_acl_snapshot(os.fspath(path))
    try:
        current_sid = _windows_current_user_sid()
    except OSError:
        return False
    if not current_sid or null_dacl or owner_sid != current_sid:
        return False
    allowed = {
        sid for permissions, access_mode, _inheritance, sid in entries if access_mode in (1, 2) and permissions != 0
    }
    denied = {sid for permissions, access_mode, _inheritance, sid in entries if access_mode == 3 and permissions != 0}
    required_owner_sids = {current_sid, "S-1-3-4"}
    return (
        "S-1-5-18" in allowed
        and "S-1-5-18" not in denied
        and bool(required_owner_sids & allowed)
        and not required_owner_sids & denied
    )


def _windows_current_user_sid() -> str:
    """Return the current process token user's SID string."""
    if os.name != "nt":
        raise OSError("Windows access tokens are unavailable on this platform")
    import ctypes
    from ctypes import wintypes

    token_query = 0x0008
    token_user_class = 1
    error_insufficient_buffer = 122
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_current_process = kernel32.GetCurrentProcess
    get_current_process.argtypes = []
    get_current_process.restype = wintypes.HANDLE
    open_process_token = advapi32.OpenProcessToken
    open_process_token.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    open_process_token.restype = wintypes.BOOL
    get_token_information = advapi32.GetTokenInformation
    get_token_information.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    get_token_information.restype = wintypes.BOOL
    sid_to_string = advapi32.ConvertSidToStringSidW
    sid_to_string.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    sid_to_string.restype = wintypes.BOOL
    local_free = kernel32.LocalFree
    local_free.argtypes = [wintypes.HLOCAL]
    local_free.restype = wintypes.HLOCAL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    token = wintypes.HANDLE()
    if not open_process_token(get_current_process(), token_query, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        needed = wintypes.DWORD()
        ctypes.set_last_error(0)
        get_token_information(token, token_user_class, None, 0, ctypes.byref(needed))
        if ctypes.get_last_error() != error_insufficient_buffer:
            raise ctypes.WinError(ctypes.get_last_error())
        buffer = ctypes.create_string_buffer(needed.value)
        if not get_token_information(token, token_user_class, buffer, needed, ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid_pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p)).contents.value
        value = wintypes.LPWSTR()
        if not sid_to_string(sid_pointer, ctypes.byref(value)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return value.value or ""
        finally:
            local_free(value)
    finally:
        close_handle(token)


def _reject_reparse_chain(path: str) -> None:
    current = Path(os.path.abspath(path))
    if os.name != "nt":
        # POSIX systems intentionally ship symlinked system ancestors (for
        # example macOS /tmp -> /private/tmp). The caller-owned leaf must not
        # itself be a symlink, while Windows requires checking every ancestor
        # because a junction is transparent to ordinary path operations.
        _reject_reparse_path(os.fspath(current), allow_missing=True)
        return
    while True:
        _reject_reparse_path(os.fspath(current), allow_missing=True)
        if current.parent == current:
            break
        current = current.parent


def _reject_reparse_path(path: str, *, allow_missing: bool) -> os.stat_result | None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        if allow_missing:
            return None
        raise
    if os.path.islink(path):
        raise UnsafePathError(f"refusing sensitive write through symlink: {path}")
    attributes = getattr(info, "st_file_attributes", 0)
    if attributes & 0x400:  # FILE_ATTRIBUTE_REPARSE_POINT
        raise UnsafePathError(f"refusing sensitive write through reparse point: {path}")
    return info


def _windows_acl_snapshot(path: str) -> tuple[str, bool, list[tuple[int, int, int, str]]]:
    """Read the owner SID and every DACL ACE using native Win32 APIs."""
    if os.name != "nt":
        raise OSError("Windows ACLs are unavailable on this platform")
    import ctypes
    from ctypes import wintypes

    class _Acl(ctypes.Structure):
        _fields_ = [
            ("AclRevision", wintypes.BYTE),
            ("Sbz1", wintypes.BYTE),
            ("AclSize", wintypes.WORD),
            ("AceCount", wintypes.WORD),
            ("Sbz2", wintypes.WORD),
        ]

    class _AceHeader(ctypes.Structure):
        _fields_ = [
            ("AceType", wintypes.BYTE),
            ("AceFlags", wintypes.BYTE),
            ("AceSize", wintypes.WORD),
        ]

    class _AccessAce(ctypes.Structure):
        _fields_ = [
            ("Header", _AceHeader),
            ("Mask", wintypes.DWORD),
            ("SidStart", wintypes.DWORD),
        ]

    access_allowed_ace_type = 0
    access_denied_ace_type = 1
    access_modes = {
        access_allowed_ace_type: 1,  # GRANT_ACCESS
        access_denied_ace_type: 3,  # DENY_ACCESS
    }

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_security = advapi32.GetNamedSecurityInfoW
    get_security.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    get_security.restype = wintypes.DWORD
    # GetExplicitEntriesFromAclW omits inherited ACEs. Setup deliberately
    # publishes its executable tree with inherited read/execute access, so
    # custody checks must enumerate the exact DACL instead.
    get_ace = advapi32.GetAce
    get_ace.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    get_ace.restype = wintypes.BOOL
    sid_to_string = advapi32.ConvertSidToStringSidW
    sid_to_string.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    sid_to_string.restype = wintypes.BOOL
    local_free = kernel32.LocalFree
    local_free.argtypes = [ctypes.c_void_p]
    local_free.restype = ctypes.c_void_p

    def _sid_string(sid: int | None) -> str:
        if not sid:
            return ""
        value = wintypes.LPWSTR()
        if not sid_to_string(ctypes.c_void_p(sid), ctypes.byref(value)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return value.value or ""
        finally:
            local_free(ctypes.cast(value, ctypes.c_void_p))

    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    result = get_security(
        path,
        1,
        0x00000001 | 0x00000004,
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if result:
        raise OSError(result, ctypes.FormatError(result), path)
    try:
        owner_sid = _sid_string(owner.value)
        if not dacl.value:
            return owner_sid, True, []
        acl = ctypes.cast(dacl, ctypes.POINTER(_Acl)).contents
        entries = []
        for index in range(acl.AceCount):
            ace_pointer = ctypes.c_void_p()
            if not get_ace(dacl, index, ctypes.byref(ace_pointer)):
                raise ctypes.WinError(ctypes.get_last_error())
            ace = ctypes.cast(ace_pointer, ctypes.POINTER(_AccessAce)).contents
            if ace.Header.AceSize < ctypes.sizeof(_AccessAce):
                raise OSError(f"invalid Windows DACL ACE size at index {index}: {path}")
            access_mode = access_modes.get(ace.Header.AceType)
            if access_mode is None:
                raise OSError(f"unsupported Windows DACL ACE type {ace.Header.AceType}: {path}")
            sid_pointer = ace_pointer.value + _AccessAce.SidStart.offset
            entries.append(
                (
                    int(ace.Mask),
                    access_mode,
                    int(ace.Header.AceFlags),
                    _sid_string(sid_pointer),
                )
            )
        return owner_sid, False, entries
    finally:
        if descriptor.value:
            local_free(descriptor)


def _set_windows_owner_only_acl(path: str, *, set_owner: bool = False) -> None:
    """Replace inherited access with the protected owner/SYSTEM policy DACL."""
    import ctypes
    from ctypes import wintypes

    sddl_revision_1 = 1
    dacl_security_information = 0x00000004
    # D:P protects the DACL from inheritance. OW is the Windows Owner Rights
    # SID; SY retains LocalSystem access required by the product policy.
    # Private directories must propagate the same policy to existing and new
    # descendants. Without OI/CI, Windows recalculates an existing child's
    # inherited ACL against a parent with no inheritable ACEs and can leave the
    # child with an empty DACL (the managed venv became inaccessible after init).
    inheritance = "OICI" if os.path.isdir(path) else ""
    owner_only_sddl = f"D:P(A;{inheritance};FA;;;SY)(A;{inheritance};FA;;;OW)"

    if set_owner:
        _set_windows_current_user_owner(path)

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    convert = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.DWORD),
    ]
    convert.restype = wintypes.BOOL

    set_file_security = advapi32.SetFileSecurityW
    set_file_security.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.LPVOID,
    ]
    set_file_security.restype = wintypes.BOOL

    local_free = kernel32.LocalFree
    local_free.argtypes = [wintypes.HLOCAL]
    local_free.restype = wintypes.HLOCAL

    descriptor = wintypes.LPVOID()
    if not convert(
        owner_only_sddl,
        sddl_revision_1,
        ctypes.byref(descriptor),
        None,
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not set_file_security(path, dacl_security_information, descriptor):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        local_free(descriptor)


def _set_windows_current_user_owner(path: str) -> None:
    """Assign a DefenseClaw-managed path to the current token user."""
    import ctypes
    from ctypes import wintypes

    se_file_object = 1
    owner_security_information = 0x00000001
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    convert = advapi32.ConvertStringSidToSidW
    convert.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.LPVOID)]
    convert.restype = wintypes.BOOL
    set_security = advapi32.SetNamedSecurityInfoW
    set_security.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
    ]
    set_security.restype = wintypes.DWORD
    local_free = ctypes.WinDLL("kernel32", use_last_error=True).LocalFree
    local_free.argtypes = [wintypes.HLOCAL]
    local_free.restype = wintypes.HLOCAL

    owner = wintypes.LPVOID()
    if not convert(_windows_current_user_sid(), ctypes.byref(owner)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        result = set_security(
            path,
            se_file_object,
            owner_security_information,
            owner,
            None,
            None,
            None,
        )
        if result:
            raise ctypes.WinError(result)
    finally:
        local_free(owner)
