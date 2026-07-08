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
import tempfile
from collections.abc import Callable
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import TextIO


class UnsafePathError(OSError):
    """Raised when a sensitive write would traverse a reparse point."""


def reject_reparse_path(path: str | os.PathLike[str]) -> None:
    """Reject a leaf or Windows ancestor that redirects filesystem access."""
    target = os.path.abspath(os.fspath(path))
    _reject_reparse_chain(os.path.dirname(target) or os.curdir)
    _reject_reparse_path(target, allow_missing=True)


def set_file_mode(fd: int, path: str, mode: int) -> None:
    """Apply *mode* to the open file described by *fd* and *path*.

    POSIX uses the descriptor so the permission change cannot be redirected
    through a path race. Windows has no :func:`os.fchmod`, and its
    :func:`os.chmod` only toggles the read-only attribute; for owner-only
    modes, install a protected owner/SYSTEM DACL before secret bytes are
    written instead.

    The caller must keep *fd* open for the duration of this call. Windows CRT
    descriptors deny delete sharing, which keeps *path* bound to that file
    while ``SetFileSecurityW`` applies the DACL.
    """
    if os.name == "nt":
        if mode & 0o077 == 0:
            _set_windows_owner_only_acl(path)
        else:
            os.chmod(path, mode)
        return

    fchmod = getattr(os, "fchmod", None)
    if fchmod is not None:
        fchmod(fd, mode)
    else:
        os.chmod(path, mode)


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
        set_file_mode(fd, tmp, target_mode)
        stream = os.fdopen(fd, "w")
        fd = -1
        with stream:
            write(stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
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


def atomic_write_private(
    path: str | os.PathLike[str],
    write: Callable[[int], None],
    *,
    protect_parent: bool = True,
) -> None:
    """Atomically materialize a sensitive file with native protections.

    The random same-directory staging file is protected before ``write`` is
    called.  Existing safe Windows DACLs are copied to the replacement so an
    operator-hardened target is never widened.  Unsafe inherited write grants
    are replaced by the canonical owner/SYSTEM policy instead.
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
            set_file_mode(fd, tmp, 0o600)
            write(fd)
            os.fsync(fd)
            os.close(fd)
            fd = -1

            _reject_reparse_chain(parent)
            _reject_reparse_path(target, allow_missing=True)
            if os.name == "nt" and os.path.exists(target):
                # Preserve an existing DACL only when it grants no untrusted
                # write-like access. A permissive inherited DACL must not be
                # copied onto the new protected staging file.
                if windows_acl_write_error(target) is None and _windows_acl_has_required_access(target):
                    copy_windows_dacl(target, tmp)
            os.replace(tmp, target)
            tmp = ""
            if os.name == "nt":
                problem = windows_acl_write_error(target)
                if problem is not None:
                    raise OSError(f"private Windows DACL verification failed: {problem}")
                if not _windows_acl_has_required_access(target):
                    raise OSError("private Windows DACL verification failed: owner/SYSTEM access missing")
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

    current_sid = _windows_current_user_sid()
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
    sddl = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)"
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
    current_sid = _windows_current_user_sid()
    if null_dacl or owner_sid != current_sid:
        return False
    allowed = {
        sid for permissions, access_mode, _inheritance, sid in entries if access_mode in (1, 2) and permissions != 0
    }
    denied = {
        sid
        for permissions, access_mode, _inheritance, sid in entries
        if access_mode == 3 and permissions != 0
    }
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


def _reject_reparse_path(path: str, *, allow_missing: bool) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        if allow_missing:
            return
        raise
    if os.path.islink(path):
        raise UnsafePathError(f"refusing sensitive write through symlink: {path}")
    attributes = getattr(info, "st_file_attributes", 0)
    if attributes & 0x400:  # FILE_ATTRIBUTE_REPARSE_POINT
        raise UnsafePathError(f"refusing sensitive write through reparse point: {path}")


def _windows_acl_snapshot(path: str) -> tuple[str, bool, list[tuple[int, int, int, str]]]:
    """Read the owner SID and explicit DACL entries using native Win32 APIs."""
    if os.name != "nt":
        raise OSError("Windows ACLs are unavailable on this platform")
    import ctypes
    from ctypes import wintypes

    class _TrusteeW(ctypes.Structure):
        pass

    _TrusteeW._fields_ = [
        ("pMultipleTrustee", ctypes.POINTER(_TrusteeW)),
        ("MultipleTrusteeOperation", wintypes.DWORD),
        ("TrusteeForm", wintypes.DWORD),
        ("TrusteeType", wintypes.DWORD),
        ("ptstrName", ctypes.c_void_p),
    ]

    class _ExplicitAccessW(ctypes.Structure):
        _fields_ = [
            ("grfAccessPermissions", wintypes.DWORD),
            ("grfAccessMode", wintypes.DWORD),
            ("grfInheritance", wintypes.DWORD),
            ("Trustee", _TrusteeW),
        ]

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
    get_entries = advapi32.GetExplicitEntriesFromAclW
    get_entries.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.ULONG),
        ctypes.POINTER(ctypes.POINTER(_ExplicitAccessW)),
    ]
    get_entries.restype = wintypes.DWORD
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
    entries_ptr = ctypes.POINTER(_ExplicitAccessW)()
    try:
        owner_sid = _sid_string(owner.value)
        if not dacl.value:
            return owner_sid, True, []
        count = wintypes.ULONG()
        result = get_entries(dacl, ctypes.byref(count), ctypes.byref(entries_ptr))
        if result:
            raise OSError(result, ctypes.FormatError(result), path)
        entries = []
        for index in range(count.value):
            entry = entries_ptr[index]
            sid = _sid_string(entry.Trustee.ptstrName) if entry.Trustee.TrusteeForm == 0 else ""
            entries.append((int(entry.grfAccessPermissions), int(entry.grfAccessMode), int(entry.grfInheritance), sid))
        return owner_sid, False, entries
    finally:
        if entries_ptr:
            local_free(ctypes.cast(entries_ptr, ctypes.c_void_p))
        if descriptor.value:
            local_free(descriptor)


def _set_windows_owner_only_acl(path: str) -> None:
    """Replace inherited access with the protected owner/SYSTEM policy DACL."""
    import ctypes
    from ctypes import wintypes

    sddl_revision_1 = 1
    dacl_security_information = 0x00000004
    # D:P protects the DACL from inheritance. OW is the Windows Owner Rights
    # SID; SY retains LocalSystem access required by the product policy.
    owner_only_sddl = "D:P(A;;FA;;;SY)(A;;FA;;;OW)"

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
