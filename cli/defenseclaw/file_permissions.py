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

import os


def set_file_mode(fd: int, path: str, mode: int) -> None:
    """Apply *mode* to the open file described by *fd* and *path*.

    POSIX uses the descriptor so the permission change cannot be redirected
    through a path race. Windows has no :func:`os.fchmod`, and its
    :func:`os.chmod` only toggles the read-only attribute; for owner-only
    modes, install a protected DACL before secret bytes are written instead.

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

    set_file_security = advapi32.SetFileSecurityW
    set_file_security.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.LPVOID,
    ]
    set_file_security.restype = wintypes.BOOL

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
    if not set_file_security(destination, dacl_security_information, descriptor):
        raise ctypes.WinError(ctypes.get_last_error())


def _set_windows_owner_only_acl(path: str) -> None:
    """Replace inherited access with a protected owner-full-control DACL."""
    import ctypes
    from ctypes import wintypes

    sddl_revision_1 = 1
    dacl_security_information = 0x00000004
    # D:P protects the DACL from inheritance. OW is the Windows Owner Rights
    # SID, and FA grants that owner full file access. No other ACE is present.
    owner_only_sddl = "D:P(A;;FA;;;OW)"

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
