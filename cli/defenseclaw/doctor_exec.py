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

"""Bind Doctor/setup lifecycle execution to the inspected executable object.

Supported installation custody model
------------------------------------

POSIX (Linux/macOS)
  The executable and every ancestor directory must be owned by root or the
  current user and must not be group/world writable. Darwin extended ACLs
  must not grant write. The path must be a regular file (no symlink). After
  that pathname custody check, Doctor opens the file with ``O_RDONLY`` /
  ``O_NOFOLLOW`` and executes the held inode through ``/proc/self/fd/<n>``
  (Linux). Darwin ``/dev/fd/<n>`` is not executable, so macOS re-validates
  the held inode against the pathname (``os.path.samestat``) and fail-closes
  on swap, then execs by path. Do not switch Darwin to ``/dev/fd`` exec.

Windows
  Packaged installs must resolve to the sibling gateway under the install
  root. Non-packaged paths must pass the existing integrity ACL write check
  and must not be a reparse point. Doctor then opens the file with
  ``GENERIC_READ | GENERIC_EXECUTE``, ``FILE_SHARE_READ`` only (no write or
  delete sharing), and records the volume serial plus file index from that
  handle. Spawn refuses if the path's object identity has changed. Holding
  the handle without delete/write sharing prevents the inspected file from
  being replaced for the duration of the lifecycle call.

Failure is closed whenever the held identity cannot be established or no
longer matches. Callers keep explicit argv, ``shell=False``, and a bounded
environment; this module only changes *which object* those argv bytes exec.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from defenseclaw.file_permissions import (
    UnsafePathError,
    open_regular_file_no_follow,
    trusted_posix_executable_path,
)

Runner = Callable[..., subprocess.CompletedProcess]


class ExecBindError(Exception):
    """Refuse to spawn an executable whose object identity is not bound."""


@dataclass(frozen=True)
class ExecutableIdentity:
    """Stable identity of one opened executable object."""

    device: int
    inode: int
    size: int
    windows_volume: int = 0
    windows_index: int = 0


class BoundExecutable:
    """An executable inode/handle held across check-to-exec."""

    def __init__(self, path: str, fd: int, identity: ExecutableIdentity) -> None:
        self.path = path
        self._fd = fd
        self.identity = identity

    @property
    def fd(self) -> int:
        if self._fd < 0:
            raise ExecBindError("bound executable handle is already closed")
        return self._fd

    def close(self) -> None:
        fd = self._fd
        self._fd = -1
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass

    def __enter__(self) -> BoundExecutable:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def bind_trusted_executable(path: str, *, verify_custody: bool = True) -> BoundExecutable:
    """Open the custody-checked executable and hold that exact object.

    ``verify_custody=False`` is for callers that just completed a pathname
    custody check and only need the check-to-exec handle. The opened inode is
    still identity-pinned; ancestor ACL walks are not repeated.
    """
    if not path or not os.path.isabs(path):
        raise ExecBindError("lifecycle executable path is not absolute")
    verified = _verify_pathname_custody(path) if verify_custody else os.path.abspath(path)
    try:
        fd = _open_executable_object(verified)
    except (OSError, UnsafePathError) as exc:
        raise ExecBindError("lifecycle executable object could not be opened") from exc
    try:
        identity = executable_identity(fd)
        _verify_opened_identity(verified, fd, identity)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    return BoundExecutable(verified, fd, identity)


def revalidate_bound_executable(bound: BoundExecutable) -> None:
    """Fail closed if the held object is gone or no longer named by its path."""
    current = executable_identity(bound.fd)
    if current != bound.identity:
        raise ExecBindError("held executable object changed before spawn")
    if os.name == "nt":
        _assert_windows_path_still_bound(bound)
    elif not sys.platform.startswith("linux"):
        _assert_posix_path_still_bound(bound)


def run_bound_executable(
    bound: BoundExecutable,
    args: Sequence[str],
    *,
    runner: Runner = subprocess.run,
    capture_output: bool = True,
    text: bool = True,
    env: Mapping[str, str] | None = None,
    timeout: float | None = None,
    stdin=subprocess.DEVNULL,
    **kwargs: Any,
) -> subprocess.CompletedProcess:
    """Spawn ``args`` from the held executable object, not a later pathname."""
    if not args:
        raise ExecBindError("lifecycle argv is empty")
    revalidate_bound_executable(bound)
    if os.name == "nt":
        executable = bound.path
        extra: dict[str, Any] = {}
    elif sys.platform.startswith("linux"):
        executable = _posix_held_executable_path(bound.fd)
        extra = {"pass_fds": tuple(set(kwargs.pop("pass_fds", ())) | {bound.fd})}
    else:
        # Darwin /dev/fd/N is not executable. Revalidate already fail-closed
        # if the pathname no longer names the held inode; exec that path.
        executable = bound.path
        extra = {}
    argv = [bound.path, *list(args)]
    return runner(
        argv,
        executable=executable,
        capture_output=capture_output,
        text=text,
        shell=False,
        stdin=stdin,
        env=dict(env) if env is not None else None,
        timeout=timeout,
        **extra,
        **kwargs,
    )


def executable_identity(fd: int) -> ExecutableIdentity:
    """Return the identity of an already-open executable descriptor."""
    try:
        opened = os.fstat(fd)
    except OSError as exc:
        raise ExecBindError("lifecycle executable identity could not be read") from exc
    if not stat.S_ISREG(opened.st_mode):
        raise ExecBindError("lifecycle executable is not a regular file")
    volume = 0
    index = 0
    if os.name == "nt":
        volume, index = _windows_file_id(fd)
    return ExecutableIdentity(
        device=int(opened.st_dev),
        inode=int(opened.st_ino),
        size=int(opened.st_size),
        windows_volume=volume,
        windows_index=index,
    )


def _verify_pathname_custody(path: str) -> str:
    if os.name != "nt":
        try:
            return trusted_posix_executable_path(path)
        except (OSError, UnsafePathError) as exc:
            raise ExecBindError("lifecycle executable custody could not be verified") from exc
    from defenseclaw.file_permissions import windows_acl_write_error
    from defenseclaw.gateway import packaged_windows_gateway_path

    resolved = os.path.abspath(path)
    packaged = packaged_windows_gateway_path()
    if packaged:
        try:
            if os.path.samefile(resolved, packaged):
                return os.path.abspath(packaged)
        except OSError as exc:
            raise ExecBindError("packaged lifecycle executable could not be verified") from exc
    for candidate in (resolved, os.path.dirname(resolved)):
        if windows_acl_write_error(candidate) is not None:
            raise ExecBindError("lifecycle executable custody could not be verified")
    if not os.path.isfile(resolved):
        raise ExecBindError("lifecycle executable is not a regular file")
    return resolved


def _open_executable_object(path: str) -> int:
    if os.name == "nt":
        return _open_windows_executable(path)
    return open_regular_file_no_follow(path)


def _verify_opened_identity(path: str, fd: int, identity: ExecutableIdentity) -> None:
    try:
        path_stat = os.stat(path)
    except OSError as exc:
        raise ExecBindError("lifecycle executable path changed while opening") from exc
    if not stat.S_ISREG(path_stat.st_mode):
        raise ExecBindError("lifecycle executable is not a regular file")
    if os.name != "nt":
        if (int(path_stat.st_dev), int(path_stat.st_ino)) != (identity.device, identity.inode):
            raise ExecBindError("lifecycle executable path no longer names the opened object")
        return
    volume, index = _windows_path_file_id(path)
    if (volume, index) != (identity.windows_volume, identity.windows_index):
        raise ExecBindError("lifecycle executable path no longer names the opened object")


def _posix_held_executable_path(fd: int) -> str:
    held = f"/proc/self/fd/{fd}"
    if not os.path.exists(held):
        raise ExecBindError("handle-bound executable path is unavailable")
    return held


def _assert_posix_path_still_bound(bound: BoundExecutable) -> None:
    try:
        opened = os.fstat(bound.fd)
        current = os.stat(bound.path)
    except OSError as exc:
        raise ExecBindError("lifecycle executable path could not be revalidated") from exc
    if not os.path.samestat(opened, current):
        raise ExecBindError("lifecycle executable was replaced after it was bound")


def _assert_windows_path_still_bound(bound: BoundExecutable) -> None:
    volume, index = _windows_path_file_id(bound.path)
    if (volume, index) != (bound.identity.windows_volume, bound.identity.windows_index):
        raise ExecBindError("lifecycle executable was replaced after it was bound")


def _open_windows_executable(path: str) -> int:  # pragma: no cover - native Windows
    import ctypes
    import msvcrt
    from ctypes import wintypes

    from defenseclaw.file_permissions import UnsafePathError, reject_reparse_path

    try:
        reject_reparse_path(path)
    except (OSError, UnsafePathError) as exc:
        raise ExecBindError("lifecycle executable is a reparse point") from exc

    generic_read = 0x80000000
    generic_execute = 0x20000000
    file_share_read = 0x00000001
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
        generic_read | generic_execute,
        file_share_read,
        None,
        open_existing,
        file_flag_open_reparse_point,
        None,
    )
    if handle == invalid_handle:
        raise ExecBindError("lifecycle executable handle could not be opened")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    try:
        return msvcrt.open_osfhandle(handle, flags)
    except BaseException:
        close_handle(handle)
        raise


def _windows_file_id(fd: int) -> tuple[int, int]:
    if os.name != "nt":
        return 0, 0
    return _windows_handle_file_id(_osfhandle(fd))


def _windows_path_file_id(path: str) -> tuple[int, int]:
    if os.name != "nt":
        return 0, 0
    fd = _open_windows_executable(path)
    try:
        return _windows_file_id(fd)
    finally:
        os.close(fd)


def _osfhandle(fd: int) -> int:
    import msvcrt

    return int(msvcrt.get_osfhandle(fd))


def _windows_extended_path(path: str) -> str:
    value = os.path.abspath(path)
    if value.startswith(("\\\\?\\", "\\\\.\\")):
        return value
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value


def _windows_handle_file_id(handle: int) -> tuple[int, int]:  # pragma: no cover - native Windows
    import ctypes
    from ctypes import wintypes

    class _FileTime(ctypes.Structure):
        _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

    class _Info(ctypes.Structure):
        _fields_ = [
            ("file_attributes", wintypes.DWORD),
            ("creation_time", _FileTime),
            ("last_access_time", _FileTime),
            ("last_write_time", _FileTime),
            ("volume_serial_number", wintypes.DWORD),
            ("file_size_high", wintypes.DWORD),
            ("file_size_low", wintypes.DWORD),
            ("number_of_links", wintypes.DWORD),
            ("file_index_high", wintypes.DWORD),
            ("file_index_low", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_info = kernel32.GetFileInformationByHandle
    get_info.argtypes = [wintypes.HANDLE, ctypes.POINTER(_Info)]
    get_info.restype = wintypes.BOOL
    info = _Info()
    if not get_info(handle, ctypes.byref(info)):
        raise ExecBindError("lifecycle executable file identity could not be read")
    index = (int(info.file_index_high) << 32) | int(info.file_index_low)
    return int(info.volume_serial_number), index
