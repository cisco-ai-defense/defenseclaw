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

"""Small, dependency-free Windows owner/DACL transaction primitives.

The observability-v8 activation path must not translate a Windows security
descriptor through POSIX mode bits.  That loses explicit and inherited ACEs
and can silently widen access when a staged file is renamed over the original.
This module keeps the authorization-relevant representation native:

* the exact owner SID bytes;
* the exact DACL bytes, including ACE order and inheritance flags; and
* the DACL protection bit.

Staged files are created with a protected copy of the desired DACL before any
payload is written.  Existing files are published with ``ReplaceFileW`` and no
"ignore ACL errors" flags, then the caller verifies the descriptor again.  A
new secret file receives a protected owner/SYSTEM/Administrators DACL.

The module deliberately has no pywin32 dependency.  Win32 bindings are loaded
only when an operation is invoked, which also lets POSIX tests inject a fake
API and exercise the transaction policy without pretending to be Windows.
"""

from __future__ import annotations

import ctypes
import ntpath
import os
import secrets
import shutil
import stat
import struct
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from typing import Any, Protocol

_ERROR_SUCCESS = 0
_SE_FILE_OBJECT = 1

_OWNER_SECURITY_INFORMATION = 0x00000001
_DACL_SECURITY_INFORMATION = 0x00000004
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000

_SE_DACL_PROTECTED = 0x1000

_READ_CONTROL = 0x00020000
_WRITE_DAC = 0x00040000
_WRITE_OWNER = 0x00080000
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_DELETE = 0x00010000

_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_FILE_SHARE_DELETE = 0x00000004
_CREATE_NEW = 1
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_NORMAL = 0x00000080
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_FLAG_WRITE_THROUGH = 0x80000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

_ACL_REVISION = 2
_ACCESS_ALLOWED_ACE_TYPE = 0
_ACCESS_DENIED_ACE_TYPE = 1
_OBJECT_INHERIT_ACE = 0x01
_CONTAINER_INHERIT_ACE = 0x02
_INHERIT_ONLY_ACE = 0x08

_FILE_WRITE_DATA = 0x00000002
_FILE_APPEND_DATA = 0x00000004
_FILE_WRITE_EA = 0x00000010
_FILE_DELETE_CHILD = 0x00000040
_FILE_WRITE_ATTRIBUTES = 0x00000100
_FILE_READ_ATTRIBUTES = 0x00000080
_WRITE_RIGHTS = (
    _FILE_WRITE_DATA
    | _FILE_APPEND_DATA
    | _FILE_WRITE_EA
    | _FILE_DELETE_CHILD
    | _FILE_WRITE_ATTRIBUTES
    | _DELETE
    | _WRITE_DAC
    | _WRITE_OWNER
    | _GENERIC_WRITE
    | 0x10000000  # GENERIC_ALL
)
_READ_RIGHTS = _GENERIC_READ | 0x10000000 | 0x00000001 | 0x00000008 | 0x00000080 | _READ_CONTROL

_BROAD_SIDS = frozenset(
    {
        "S-1-1-0",  # Everyone
        "S-1-5-7",  # Anonymous
        "S-1-5-11",  # Authenticated Users
        "S-1-5-32-545",  # BUILTIN\\Users
        "S-1-5-32-546",  # BUILTIN\\Guests
    }
)
_LOCAL_SYSTEM_SID = "S-1-5-18"
_BUILTIN_ADMINISTRATORS_SID = "S-1-5-32-544"
_TRUSTED_INSTALLER_SID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"


@dataclass(frozen=True)
class WindowsFileSecurity:
    """Authorization-relevant file security, safe to compare exactly."""

    owner: bytes = field(repr=False)
    dacl: bytes = field(repr=False)
    dacl_protected: bool

    def staging_copy(self) -> WindowsFileSecurity:
        """Protect a staged copy so its ACL cannot be widened by inheritance."""

        return WindowsFileSecurity(self.owner, self.dacl, True)


class _WindowsApi(Protocol):
    def open_path(self, path: str, *, access: int, directory: bool = False) -> int: ...

    def close_handle(self, handle: int) -> None: ...

    def _open_regular_reader_shared_delete(self, path: str) -> int: ...

    def open_exclusive_file(self, path: str) -> int: ...

    def open_directory_no_delete(self, path: str) -> int: ...

    def assert_real_directory(self, handle: int) -> None: ...

    def get_security(self, handle: int) -> WindowsFileSecurity: ...

    def set_security(self, handle: int, security: WindowsFileSecurity) -> None: ...

    def create_file(self, path: str, security: WindowsFileSecurity) -> int: ...

    def write_all(self, handle: int, payload: bytes) -> None: ...

    def flush(self, handle: int) -> None: ...

    def replace_file(self, target: str, replacement: str, backup: str) -> None: ...

    def move_file_no_replace(self, source: str, target: str) -> None: ...

    def replace_regular_file_by_handle(self, source: str, target: str) -> None: ...

    def delete_regular_file_by_handle(self, path: str) -> None: ...

    def private_security(self, owner: bytes, *, ace_flags: int = 0) -> WindowsFileSecurity: ...

    def trusted_owner_sids(self) -> frozenset[str]: ...


class WindowsAclError(OSError):
    """A native security operation was unavailable, unsafe, or failed."""


@dataclass(frozen=True)
class _HeldPhaseTwoMutatorLease:
    path: str
    handle: int


class _SecurityDescriptor(ctypes.Structure):
    _fields_ = [
        ("revision", ctypes.c_ubyte),
        ("sbz1", ctypes.c_ubyte),
        ("control", ctypes.c_ushort),
        ("owner", ctypes.c_void_p),
        ("group", ctypes.c_void_p),
        ("sacl", ctypes.c_void_p),
        ("dacl", ctypes.c_void_p),
    ]


class _FileTime(ctypes.Structure):
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]


class _ByHandleFileInformation(ctypes.Structure):
    _fields_ = [
        ("file_attributes", ctypes.c_uint32),
        ("creation_time", _FileTime),
        ("last_access_time", _FileTime),
        ("last_write_time", _FileTime),
        ("volume_serial_number", ctypes.c_uint32),
        ("file_size_high", ctypes.c_uint32),
        ("file_size_low", ctypes.c_uint32),
        ("number_of_links", ctypes.c_uint32),
        ("file_index_high", ctypes.c_uint32),
        ("file_index_low", ctypes.c_uint32),
    ]


class _FileRenameInformation(ctypes.Structure):
    _fields_ = [
        ("replace_if_exists", ctypes.c_ubyte),
        ("root_directory", ctypes.c_void_p),
        ("file_name_length", ctypes.c_uint32),
        ("file_name", ctypes.c_uint16 * 1),
    ]


_FILE_RENAME_INFO_CLASS = 3
_FILE_DISPOSITION_INFO_CLASS = 4


class _CtypesWindowsApi:
    def __init__(self) -> None:
        if os.name != "nt":
            raise WindowsAclError("Windows ACL APIs are unavailable on this platform")
        self._advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._bind()

    def _bind(self) -> None:
        void_p = ctypes.c_void_p
        dword = ctypes.c_ulong

        self._get_security_info = self._advapi32.GetSecurityInfo
        self._get_security_info.argtypes = [
            void_p,
            ctypes.c_int,
            dword,
            ctypes.POINTER(void_p),
            ctypes.POINTER(void_p),
            ctypes.POINTER(void_p),
            ctypes.POINTER(void_p),
            ctypes.POINTER(void_p),
        ]
        self._get_security_info.restype = dword

        self._set_security_info = self._advapi32.SetSecurityInfo
        self._set_security_info.argtypes = [void_p, ctypes.c_int, dword, void_p, void_p, void_p, void_p]
        self._set_security_info.restype = dword

        self._get_security_descriptor_control = self._advapi32.GetSecurityDescriptorControl
        self._get_security_descriptor_control.argtypes = [
            void_p,
            ctypes.POINTER(ctypes.c_ushort),
            ctypes.POINTER(dword),
        ]
        self._get_security_descriptor_control.restype = ctypes.c_int

        self._get_length_sid = self._advapi32.GetLengthSid
        self._get_length_sid.argtypes = [void_p]
        self._get_length_sid.restype = dword

        self._is_valid_sid = self._advapi32.IsValidSid
        self._is_valid_sid.argtypes = [void_p]
        self._is_valid_sid.restype = ctypes.c_int

        self._is_valid_acl = self._advapi32.IsValidAcl
        self._is_valid_acl.argtypes = [void_p]
        self._is_valid_acl.restype = ctypes.c_int

        self._initialize_security_descriptor = self._advapi32.InitializeSecurityDescriptor
        self._initialize_security_descriptor.argtypes = [void_p, dword]
        self._initialize_security_descriptor.restype = ctypes.c_int

        self._set_security_descriptor_owner = self._advapi32.SetSecurityDescriptorOwner
        self._set_security_descriptor_owner.argtypes = [void_p, void_p, ctypes.c_int]
        self._set_security_descriptor_owner.restype = ctypes.c_int

        self._set_security_descriptor_dacl = self._advapi32.SetSecurityDescriptorDacl
        self._set_security_descriptor_dacl.argtypes = [void_p, ctypes.c_int, void_p, ctypes.c_int]
        self._set_security_descriptor_dacl.restype = ctypes.c_int

        self._set_security_descriptor_control = self._advapi32.SetSecurityDescriptorControl
        self._set_security_descriptor_control.argtypes = [void_p, ctypes.c_ushort, ctypes.c_ushort]
        self._set_security_descriptor_control.restype = ctypes.c_int

        self._initialize_acl = self._advapi32.InitializeAcl
        self._initialize_acl.argtypes = [void_p, dword, dword]
        self._initialize_acl.restype = ctypes.c_int

        self._add_access_allowed_ace_ex = self._advapi32.AddAccessAllowedAceEx
        self._add_access_allowed_ace_ex.argtypes = [void_p, dword, dword, dword, void_p]
        self._add_access_allowed_ace_ex.restype = ctypes.c_int

        self._create_well_known_sid = self._advapi32.CreateWellKnownSid
        self._create_well_known_sid.argtypes = [ctypes.c_int, void_p, void_p, ctypes.POINTER(dword)]
        self._create_well_known_sid.restype = ctypes.c_int

        self._open_process_token = self._advapi32.OpenProcessToken
        self._open_process_token.argtypes = [void_p, dword, ctypes.POINTER(void_p)]
        self._open_process_token.restype = ctypes.c_int

        self._get_token_information = self._advapi32.GetTokenInformation
        self._get_token_information.argtypes = [void_p, ctypes.c_int, void_p, dword, ctypes.POINTER(dword)]
        self._get_token_information.restype = ctypes.c_int

        self._create_file = self._kernel32.CreateFileW
        self._create_file.argtypes = [
            ctypes.c_wchar_p,
            dword,
            dword,
            void_p,
            dword,
            dword,
            void_p,
        ]
        self._create_file.restype = void_p

        self._close_handle = self._kernel32.CloseHandle
        self._close_handle.argtypes = [void_p]
        self._close_handle.restype = ctypes.c_int

        self._local_free = self._kernel32.LocalFree
        self._local_free.argtypes = [void_p]
        self._local_free.restype = void_p

        self._write_file = self._kernel32.WriteFile
        self._write_file.argtypes = [void_p, void_p, dword, ctypes.POINTER(dword), void_p]
        self._write_file.restype = ctypes.c_int

        self._flush_file_buffers = self._kernel32.FlushFileBuffers
        self._flush_file_buffers.argtypes = [void_p]
        self._flush_file_buffers.restype = ctypes.c_int

        self._replace_file = self._kernel32.ReplaceFileW
        self._replace_file.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            dword,
            void_p,
            void_p,
        ]
        self._replace_file.restype = ctypes.c_int

        self._move_file = self._kernel32.MoveFileW
        self._move_file.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p]
        self._move_file.restype = ctypes.c_int

        self._get_file_information = self._kernel32.GetFileInformationByHandle
        self._get_file_information.argtypes = [
            void_p,
            ctypes.POINTER(_ByHandleFileInformation),
        ]
        self._get_file_information.restype = ctypes.c_int

        self._set_file_information = self._kernel32.SetFileInformationByHandle
        self._set_file_information.argtypes = [void_p, ctypes.c_int, void_p, dword]
        self._set_file_information.restype = ctypes.c_int

        self._get_current_process = self._kernel32.GetCurrentProcess
        self._get_current_process.argtypes = []
        self._get_current_process.restype = void_p

    @staticmethod
    def _raise_last_error(operation: str) -> None:
        error = ctypes.get_last_error()
        raise WindowsAclError(error, f"{operation} failed")

    @staticmethod
    def _raise_status(operation: str, status: int) -> None:
        raise WindowsAclError(status, f"{operation} failed")

    def open_path(self, path: str, *, access: int, directory: bool = False) -> int:
        flags = _FILE_FLAG_OPEN_REPARSE_POINT
        if directory:
            flags |= _FILE_FLAG_BACKUP_SEMANTICS
        handle = self._create_file(
            path,
            access,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
            None,
            _OPEN_EXISTING,
            flags,
            None,
        )
        if handle == _INVALID_HANDLE_VALUE:
            self._raise_last_error("CreateFileW")
        return int(handle)

    def open_exclusive_file(self, path: str) -> int:
        """Open an existing real file with a share-none lifetime lease."""

        handle = self._create_file(
            path,
            _GENERIC_READ | _GENERIC_WRITE | _READ_CONTROL,
            0,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        if handle == _INVALID_HANDLE_VALUE:
            self._raise_last_error("CreateFileW(exclusive lease)")
        return int(handle)

    def open_directory_no_delete(self, path: str) -> int:
        """Bind a directory while denying rename/delete sharing to peers."""

        handle = self._create_file(
            path,
            _FILE_READ_ATTRIBUTES,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_OPEN_REPARSE_POINT | _FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        if handle == _INVALID_HANDLE_VALUE:
            self._raise_last_error("CreateFileW(directory lifetime lease)")
        return int(handle)

    def _file_information(self, handle: int) -> _ByHandleFileInformation:
        information = _ByHandleFileInformation()
        if not self._get_file_information(handle, ctypes.byref(information)):
            self._raise_last_error("GetFileInformationByHandle")
        return information

    def assert_real_directory(self, handle: int) -> None:
        attributes = self._file_information(handle).file_attributes
        if not attributes & _FILE_ATTRIBUTE_DIRECTORY:
            raise WindowsAclError("Windows rollback ancestor is not a directory")
        if attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise WindowsAclError("Windows rollback ancestor is a reparse point")

    def close_handle(self, handle: int) -> None:
        if not self._close_handle(handle):
            self._raise_last_error("CloseHandle")

    def get_security(self, handle: int) -> WindowsFileSecurity:
        owner = ctypes.c_void_p()
        dacl = ctypes.c_void_p()
        descriptor = ctypes.c_void_p()
        status = self._get_security_info(
            handle,
            _SE_FILE_OBJECT,
            _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
            ctypes.byref(owner),
            None,
            ctypes.byref(dacl),
            None,
            ctypes.byref(descriptor),
        )
        if status != _ERROR_SUCCESS:
            self._raise_status("GetSecurityInfo", int(status))
        try:
            if not owner.value or not self._is_valid_sid(owner):
                raise WindowsAclError("file owner SID is absent or invalid")
            if not dacl.value:
                raise WindowsAclError("null DACL is unsafe and cannot be preserved")
            if not self._is_valid_acl(dacl):
                raise WindowsAclError("file DACL is invalid")
            owner_size = int(self._get_length_sid(owner))
            if owner_size <= 0:
                raise WindowsAclError("GetLengthSid returned zero for a valid owner SID")
            acl_size = ctypes.c_ushort.from_address(int(dacl.value) + 2).value
            if acl_size < 8:
                raise WindowsAclError("file DACL has an invalid size")
            control = ctypes.c_ushort()
            revision = ctypes.c_ulong()
            if not self._get_security_descriptor_control(descriptor, ctypes.byref(control), ctypes.byref(revision)):
                self._raise_last_error("GetSecurityDescriptorControl")
            return WindowsFileSecurity(
                owner=ctypes.string_at(owner, owner_size),
                dacl=ctypes.string_at(dacl, acl_size),
                dacl_protected=bool(control.value & _SE_DACL_PROTECTED),
            )
        finally:
            if descriptor.value:
                self._local_free(descriptor)

    def set_security(self, handle: int, security: WindowsFileSecurity) -> None:
        owner_buffer = ctypes.create_string_buffer(security.owner)
        dacl_buffer = ctypes.create_string_buffer(security.dacl)
        protection = (
            _PROTECTED_DACL_SECURITY_INFORMATION
            if security.dacl_protected
            else _UNPROTECTED_DACL_SECURITY_INFORMATION
        )
        status = self._set_security_info(
            handle,
            _SE_FILE_OBJECT,
            _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION | protection,
            owner_buffer,
            None,
            dacl_buffer,
            None,
        )
        if status != _ERROR_SUCCESS:
            self._raise_status("SetSecurityInfo", int(status))

    def _absolute_descriptor(self, security: WindowsFileSecurity):
        owner_buffer = ctypes.create_string_buffer(security.owner)
        dacl_buffer = ctypes.create_string_buffer(security.dacl)
        descriptor = _SecurityDescriptor()
        if not self._initialize_security_descriptor(ctypes.byref(descriptor), 1):
            self._raise_last_error("InitializeSecurityDescriptor")
        if not self._set_security_descriptor_owner(ctypes.byref(descriptor), owner_buffer, False):
            self._raise_last_error("SetSecurityDescriptorOwner")
        if not self._set_security_descriptor_dacl(ctypes.byref(descriptor), True, dacl_buffer, False):
            self._raise_last_error("SetSecurityDescriptorDacl")
        if not self._set_security_descriptor_control(
            ctypes.byref(descriptor),
            _SE_DACL_PROTECTED,
            _SE_DACL_PROTECTED if security.dacl_protected else 0,
        ):
            self._raise_last_error("SetSecurityDescriptorControl")
        return descriptor, owner_buffer, dacl_buffer

    def create_file(self, path: str, security: WindowsFileSecurity) -> int:
        descriptor, owner_buffer, dacl_buffer = self._absolute_descriptor(security)

        class _SecurityAttributes(ctypes.Structure):
            _fields_ = [
                ("nLength", ctypes.c_ulong),
                ("lpSecurityDescriptor", ctypes.c_void_p),
                ("bInheritHandle", ctypes.c_int),
            ]

        attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), ctypes.addressof(descriptor), False)
        handle = self._create_file(
            path,
            _GENERIC_READ | _GENERIC_WRITE | _READ_CONTROL | _WRITE_DAC | _WRITE_OWNER | _DELETE,
            _FILE_SHARE_READ,
            ctypes.byref(attributes),
            _CREATE_NEW,
            _FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_WRITE_THROUGH,
            None,
        )
        # Keep descriptor component buffers alive through CreateFileW.
        _ = owner_buffer, dacl_buffer
        if handle == _INVALID_HANDLE_VALUE:
            self._raise_last_error("CreateFileW(CREATE_NEW)")
        return int(handle)

    def write_all(self, handle: int, payload: bytes) -> None:
        offset = 0
        while offset < len(payload):
            chunk = payload[offset : offset + 1024 * 1024]
            buffer = ctypes.create_string_buffer(chunk)
            written = ctypes.c_ulong()
            if not self._write_file(handle, buffer, len(chunk), ctypes.byref(written), None):
                self._raise_last_error("WriteFile")
            if written.value <= 0:
                raise WindowsAclError("WriteFile made no progress")
            offset += int(written.value)

    def flush(self, handle: int) -> None:
        if not self._flush_file_buffers(handle):
            self._raise_last_error("FlushFileBuffers")

    def replace_file(self, target: str, replacement: str, backup: str) -> None:
        # Zero flags are intentional: ignoring ACL merge errors would violate
        # the activation transaction's core security invariant.
        if not self._replace_file(target, replacement, backup, 0, None, None):
            self._raise_last_error("ReplaceFileW")

    def move_file_no_replace(self, source: str, target: str) -> None:
        # MoveFileW fails when target already exists, giving new-file publish
        # the required create-if-absent behavior.
        if not self._move_file(source, target):
            self._raise_last_error("MoveFileW")

    def _open_regular_mutator(self, path: str) -> int:
        handle = self._create_file(
            path,
            _DELETE | _FILE_READ_ATTRIBUTES,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        if handle == _INVALID_HANDLE_VALUE:
            self._raise_last_error("CreateFileW(regular-file mutator)")
        try:
            attributes = self._file_information(int(handle)).file_attributes
            if attributes & (_FILE_ATTRIBUTE_DIRECTORY | _FILE_ATTRIBUTE_REPARSE_POINT):
                raise WindowsAclError("Windows rollback member is not a real regular file")
            return int(handle)
        except BaseException:
            self.close_handle(int(handle))
            raise

    def _open_regular_reader_shared_delete(self, path: str) -> int:
        """Open an exact regular-file claim without blocking later deletion."""

        handle = self._create_file(
            path,
            _GENERIC_READ,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        if handle == _INVALID_HANDLE_VALUE:
            self._raise_last_error("CreateFileW(shared-delete regular-file reader)")
        try:
            attributes = self._file_information(int(handle)).file_attributes
            if attributes & (_FILE_ATTRIBUTE_DIRECTORY | _FILE_ATTRIBUTE_REPARSE_POINT):
                raise WindowsAclError("Windows rollback claim is not a real regular file")
            return int(handle)
        except BaseException:
            self.close_handle(int(handle))
            raise

    def replace_regular_file_by_handle(self, source: str, target: str) -> None:
        """Rename the exact opened source over ``target`` atomically."""

        handle = self._open_regular_mutator(source)
        try:
            encoded_target = os.path.abspath(target).encode("utf-16-le")
            name_offset = _FileRenameInformation.file_name.offset
            # FILE_RENAME_INFO is variable-length, but Win32 still requires
            # the fixed structure (including FileName[1]/tail padding) plus
            # the path bytes. The zeroed surplus also supplies its wide NUL.
            buffer = ctypes.create_string_buffer(
                ctypes.sizeof(_FileRenameInformation) + len(encoded_target),
            )
            information = ctypes.cast(
                buffer,
                ctypes.POINTER(_FileRenameInformation),
            ).contents
            information.replace_if_exists = 1
            information.root_directory = None
            information.file_name_length = len(encoded_target)
            ctypes.memmove(
                ctypes.addressof(buffer) + name_offset,
                encoded_target,
                len(encoded_target),
            )
            if not self._set_file_information(
                handle,
                _FILE_RENAME_INFO_CLASS,
                buffer,
                len(buffer),
            ):
                self._raise_last_error("SetFileInformationByHandle(FileRenameInfo)")
        finally:
            self.close_handle(handle)

    def delete_regular_file_by_handle(self, path: str) -> None:
        """Delete the exact opened non-reparse file, never a later path swap."""

        handle = self._open_regular_mutator(path)
        try:
            delete = ctypes.c_ubyte(1)
            if not self._set_file_information(
                handle,
                _FILE_DISPOSITION_INFO_CLASS,
                ctypes.byref(delete),
                ctypes.sizeof(delete),
            ):
                self._raise_last_error("SetFileInformationByHandle(FileDispositionInfo)")
        finally:
            self.close_handle(handle)

    def _well_known_sid(self, sid_type: int) -> bytes:
        size = ctypes.c_ulong(68)
        buffer = ctypes.create_string_buffer(size.value)
        if not self._create_well_known_sid(sid_type, None, buffer, ctypes.byref(size)):
            self._raise_last_error("CreateWellKnownSid")
        return bytes(buffer.raw[: size.value])

    def private_security(self, owner: bytes, *, ace_flags: int = 0) -> WindowsFileSecurity:
        sid_values: list[bytes] = [owner, self._well_known_sid(22), self._well_known_sid(26)]
        unique: list[bytes] = []
        for sid in sid_values:
            if sid not in unique:
                unique.append(sid)
        acl_size = 8 + sum(8 + len(sid) for sid in unique)
        acl = ctypes.create_string_buffer(acl_size)
        if not self._initialize_acl(acl, acl_size, _ACL_REVISION):
            self._raise_last_error("InitializeAcl")
        sid_buffers: list[ctypes.Array[ctypes.c_char]] = []
        for sid in unique:
            sid_buffer = ctypes.create_string_buffer(sid)
            sid_buffers.append(sid_buffer)
            if not self._add_access_allowed_ace_ex(
                acl,
                _ACL_REVISION,
                ace_flags,
                0x001F01FF,
                sid_buffer,
            ):
                self._raise_last_error("AddAccessAllowedAceEx")
        _ = sid_buffers
        return WindowsFileSecurity(owner=owner, dacl=bytes(acl.raw), dacl_protected=True)

    def trusted_owner_sids(self) -> frozenset[str]:
        token = ctypes.c_void_p()
        if not self._open_process_token(self._get_current_process(), 0x0008, ctypes.byref(token)):
            self._raise_last_error("OpenProcessToken")
        try:
            required = ctypes.c_ulong()
            self._get_token_information(token, 1, None, 0, ctypes.byref(required))
            if required.value == 0:
                raise WindowsAclError("GetTokenInformation returned no TOKEN_USER size")
            buffer = ctypes.create_string_buffer(required.value)
            if not self._get_token_information(token, 1, buffer, required, ctypes.byref(required)):
                self._raise_last_error("GetTokenInformation")
            sid_pointer = ctypes.c_void_p.from_buffer(buffer).value
            if not sid_pointer or not self._is_valid_sid(sid_pointer):
                raise WindowsAclError("process token user SID is invalid")
            size = int(self._get_length_sid(sid_pointer))
            current = _sid_string(ctypes.string_at(sid_pointer, size))
        finally:
            self.close_handle(int(token.value))
        return frozenset(
            {
                current,
                _LOCAL_SYSTEM_SID,
                _BUILTIN_ADMINISTRATORS_SID,
                _TRUSTED_INSTALLER_SID,
            }
        )


_api: _WindowsApi | None = None


def _get_api() -> _WindowsApi:
    global _api
    if _api is None:
        _api = _CtypesWindowsApi()
    return _api


def open_regular_read_fd_shared_delete(path: str) -> int:
    """Return a CRT read descriptor backed by a delete-sharing Win32 handle.

    ``open_osfhandle`` transfers ownership of the native handle to the CRT
    descriptor.  After a successful conversion callers must use ``os.close``;
    if conversion fails, this function closes the still-native handle itself.
    """

    if os.name != "nt":
        raise WindowsAclError("shared-delete CRT handles require Windows")
    import msvcrt

    api = _get_api()
    handle = api._open_regular_reader_shared_delete(path)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOINHERIT", 0)
    )
    try:
        return msvcrt.open_osfhandle(handle, flags)
    except BaseException:
        api.close_handle(handle)
        raise


def capture_fd(fd: int) -> WindowsFileSecurity:
    """Capture owner/DACL from the exact CRT descriptor already read."""

    if os.name != "nt":
        raise WindowsAclError("CRT handle conversion is unavailable on this platform")
    import msvcrt

    return _get_api().get_security(msvcrt.get_osfhandle(fd))


def capture_path(path: str, *, directory: bool = False) -> WindowsFileSecurity:
    api = _get_api()
    handle = api.open_path(path, access=_READ_CONTROL, directory=directory)
    try:
        return api.get_security(handle)
    finally:
        api.close_handle(handle)


def apply_path(path: str, security: WindowsFileSecurity, *, directory: bool = False) -> None:
    api = _get_api()
    handle = api.open_path(
        path,
        access=_READ_CONTROL | _WRITE_DAC | _WRITE_OWNER,
        directory=directory,
    )
    try:
        api.set_security(handle, security)
        actual = api.get_security(handle)
        if actual != security:
            raise WindowsAclError("owner or DACL did not match after SetSecurityInfo")
    finally:
        api.close_handle(handle)


def write_new_file(path: str, payload: bytes, security: WindowsFileSecurity) -> None:
    """Create, secure, write, flush, and verify a never-before-existing file."""

    api = _get_api()
    staged_security = security.staging_copy()
    handle = api.create_file(path, staged_security)
    try:
        # CreateFileW applied the protected descriptor before this first byte.
        if api.get_security(handle) != staged_security:
            raise WindowsAclError("new file owner or DACL does not match before write")
        api.write_all(handle, payload)
        api.flush(handle)
        if api.get_security(handle) != staged_security:
            raise WindowsAclError("new file owner or DACL changed while writing")
    finally:
        api.close_handle(handle)


def replace_file(target: str, replacement: str, backup: str) -> None:
    _get_api().replace_file(target, replacement, backup)


def move_file_no_replace(source: str, target: str) -> None:
    _get_api().move_file_no_replace(source, target)


def _windows_directory_prefixes(path: str) -> tuple[str, ...]:
    """Return volume-rooted prefixes for one absolute Windows directory."""

    absolute = ntpath.normpath(path)
    drive, tail = ntpath.splitdrive(absolute)
    if not drive or not tail.startswith(("\\", "/")):
        raise WindowsAclError("Windows directory lease requires an absolute path")
    root = drive + "\\"
    prefixes = [root]
    current = root
    for part in (part for part in tail.replace("/", "\\").split("\\") if part):
        current = ntpath.join(current, part)
        prefixes.append(current)
    return tuple(prefixes)


@contextmanager
def hold_directory(path: str) -> Iterator[None]:
    """Hold one real directory open without ``FILE_SHARE_DELETE``."""

    if os.name != "nt":
        raise WindowsAclError("Windows directory leases require Windows")
    api = _get_api()
    handle = api.open_directory_no_delete(path)
    try:
        api.assert_real_directory(handle)
        yield
    finally:
        api.close_handle(handle)


@contextmanager
def hold_directory_chain(path: str) -> Iterator[None]:
    """Prevent every absolute-path ancestor from being renamed or replaced."""

    with ExitStack() as held:
        for prefix in _windows_directory_prefixes(path):
            held.enter_context(hold_directory(prefix))
        yield


def replace_regular_file_by_handle(source: str, target: str) -> None:
    """Publish the exact opened source below a bound target parent chain."""

    source_parent = ntpath.normcase(ntpath.dirname(ntpath.abspath(source)))
    target_parent = ntpath.normcase(ntpath.dirname(ntpath.abspath(target)))
    if source_parent != target_parent:
        raise WindowsAclError("handle publication must remain in one held directory")
    with hold_directory_chain(target_parent):
        _get_api().replace_regular_file_by_handle(source, target)


def delete_regular_file_by_handle(path: str, *, missing_ok: bool = False) -> bool:
    """Delete the exact opened regular file rather than a path-raced replacement."""

    try:
        parent = ntpath.dirname(ntpath.abspath(path))
        with hold_directory_chain(parent):
            _get_api().delete_regular_file_by_handle(path)
    except WindowsAclError as exc:
        error = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
        if missing_ok and error in {2, 3}:
            return False
        raise
    return True


def private_security_for_directory(
    path: str,
    *,
    inherit_children: bool = False,
) -> WindowsFileSecurity:
    parent = capture_path(path, directory=True)
    assert_trusted_owner(parent)
    if inherit_children:
        return _get_api().private_security(
            parent.owner,
            ace_flags=_OBJECT_INHERIT_ACE | _CONTAINER_INHERIT_ACE,
        )
    return _get_api().private_security(parent.owner)


_HANDLE_INHERITANCE_LOCK = threading.Lock()
_PHASE_TWO_MUTATOR_MARKER = "--defenseclaw-phase-two-mutator"
_PHASE_TWO_LEASE_WAIT_SECONDS = 600.0


def _assert_real_phase_two_lease(path: str) -> os.stat_result:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise WindowsAclError("phase-two mutator lease is unavailable") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or getattr(info, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT
        or not stat.S_ISREG(info.st_mode)
        or info.st_size != 0
    ):
        raise WindowsAclError("phase-two mutator lease must be a real empty file")
    return info


def _expected_phase_two_lease_security(path: str) -> WindowsFileSecurity:
    parent = os.path.dirname(os.path.abspath(path))
    parent_info = os.lstat(parent)
    if (
        stat.S_ISLNK(parent_info.st_mode)
        or getattr(parent_info, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT
        or not stat.S_ISDIR(parent_info.st_mode)
    ):
        raise WindowsAclError("phase-two recovery root must be a real directory")
    return private_security_for_directory(parent)


def ensure_phase_two_mutator_lease(path: str) -> None:
    """Create and exactly verify the fixed private Windows mutator lease."""

    if os.name != "nt":
        raise WindowsAclError("Windows phase-two mutator leases require Windows")
    path = os.path.abspath(path)
    expected = _expected_phase_two_lease_security(path)
    if not os.path.lexists(path):
        try:
            write_new_file(path, b"", expected)
        except WindowsAclError:
            if not os.path.lexists(path):
                raise
    _assert_real_phase_two_lease(path)
    if capture_path(path) != expected:
        raise WindowsAclError("phase-two mutator lease owner/DACL is not private")


def _sharing_violation(exc: WindowsAclError) -> bool:
    return getattr(exc, "winerror", None) in {32, 33} or getattr(exc, "errno", None) in {32, 33}


@contextmanager
def hold_phase_two_mutator_lease(
    path: str,
    *,
    timeout: float | None = _PHASE_TWO_LEASE_WAIT_SECONDS,
) -> Iterator[_HeldPhaseTwoMutatorLease]:
    """Block until the fixed lease can be held with an exclusive share mode."""

    if os.name != "nt":
        raise WindowsAclError("Windows phase-two mutator leases require Windows")
    path = os.path.abspath(path)
    expected = _expected_phase_two_lease_security(path)
    before = _assert_real_phase_two_lease(path)
    api = _get_api()
    deadline = None if timeout is None else time.monotonic() + max(float(timeout), 0.0)
    while True:
        try:
            handle = api.open_exclusive_file(path)
            break
        except WindowsAclError as exc:
            if not _sharing_violation(exc):
                raise
            if deadline is not None and time.monotonic() >= deadline:
                raise WindowsAclError(
                    "phase-two mutator lease remained held; recovery did not race the live or orphaned child"
                ) from exc
            time.sleep(0.05)
    try:
        after = _assert_real_phase_two_lease(path)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise WindowsAclError("phase-two mutator lease changed while acquiring it")
        if api.get_security(handle) != expected:
            raise WindowsAclError("phase-two mutator lease owner/DACL changed")
        yield _HeldPhaseTwoMutatorLease(path=path, handle=handle)
    finally:
        api.close_handle(handle)


def _startupinfo_for_handle(handle: int):
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.lpAttributeList = {"handle_list": [handle]}
    return startupinfo


def _popen_with_inherited_lease(
    command: list[str],
    *,
    handle: int,
    stdout: Any = None,
    stderr: Any = None,
    text: bool = False,
    env: dict[str, str] | None = None,
) -> subprocess.Popen:
    with _HANDLE_INHERITANCE_LOCK:
        os.set_handle_inheritable(handle, True)
        try:
            return subprocess.Popen(
                command,
                close_fds=True,
                startupinfo=_startupinfo_for_handle(handle),
                stdout=stdout,
                stderr=stderr,
                text=text,
                env=env,
            )
        finally:
            os.set_handle_inheritable(handle, False)


def _terminate_windows_process_tree(process: subprocess.Popen) -> bool:
    taskkill = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "taskkill.exe")
    try:
        terminated = subprocess.run(
            [taskkill, "/PID", str(process.pid), "/T", "/F"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
        if terminated.returncode == 0:
            return True
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        process.kill()
    except OSError:
        pass
    return False


def _resolved_windows_command(command: list[str], env: dict[str, str] | None) -> list[str]:
    if not command or not isinstance(command[0], str) or not command[0]:
        raise ValueError("phase-two mutator command must be a non-empty string list")
    result = [os.fspath(value) for value in command]
    executable = result[0]
    search_path = env.get("PATH") if env is not None else None
    if os.path.dirname(executable):
        resolved = os.path.abspath(executable)
        if not os.path.isfile(resolved):
            raise FileNotFoundError(resolved)
    else:
        resolved = shutil.which(executable, path=search_path)
        if resolved is None:
            raise FileNotFoundError(executable)
    result[0] = resolved
    return result


def _run_phase_two_wrapper(
    command: list[str],
    *,
    lease: _HeldPhaseTwoMutatorLease,
    check: bool,
    capture_output: bool,
    text: bool,
    timeout: float | None,
    env: dict[str, str] | None,
) -> subprocess.CompletedProcess:
    wrapper = [
        sys.executable,
        "-I",
        "-m",
        "defenseclaw.windows_acl",
        _PHASE_TWO_MUTATOR_MARKER,
        lease.path,
        str(lease.handle),
        "--",
        *command,
    ]
    pipe = subprocess.PIPE if capture_output else None
    process = _popen_with_inherited_lease(
        wrapper,
        handle=lease.handle,
        stdout=pipe,
        stderr=pipe,
        text=text,
        env=env,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        _terminate_windows_process_tree(process)
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            stdout, stderr = exc.output, exc.stderr
        raise subprocess.TimeoutExpired(command, timeout, output=stdout, stderr=stderr) from None
    completed = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    if check:
        completed.check_returncode()
    return completed


def run_phase_two_mutator(
    command: list[str],
    *,
    lease_path: str,
    held_lease: object | None = None,
    **kwargs: Any,
) -> subprocess.CompletedProcess:
    """Run a mutating child behind a lease that survives controller death."""

    if os.name != "nt":
        raise WindowsAclError("Windows phase-two mutator wrappers require Windows")
    allowed = {"check", "capture_output", "text", "timeout", "env"}
    unexpected = set(kwargs) - allowed
    if unexpected:
        raise TypeError(f"unsupported phase-two mutator subprocess options: {sorted(unexpected)}")
    check = bool(kwargs.get("check", False))
    capture_output = bool(kwargs.get("capture_output", False))
    text = bool(kwargs.get("text", False))
    timeout = kwargs.get("timeout")
    env = kwargs.get("env")
    resolved = _resolved_windows_command(command, env)
    normalized_lease_path = os.path.abspath(lease_path)
    if held_lease is not None:
        if not isinstance(held_lease, _HeldPhaseTwoMutatorLease):
            raise TypeError("held_lease is not a Windows phase-two mutator lease")
        if os.path.normcase(held_lease.path) != os.path.normcase(normalized_lease_path):
            raise WindowsAclError("held phase-two mutator lease targets a different path")
        return _run_phase_two_wrapper(
            resolved,
            lease=held_lease,
            check=check,
            capture_output=capture_output,
            text=text,
            timeout=timeout,
            env=env,
        )
    with hold_phase_two_mutator_lease(normalized_lease_path) as acquired:
        return _run_phase_two_wrapper(
            resolved,
            lease=acquired,
            check=check,
            capture_output=capture_output,
            text=text,
            timeout=timeout,
            env=env,
        )


def _new_private_mutator_spool(lease_path: str, label: str) -> str:
    parent = os.path.dirname(lease_path)
    security = _expected_phase_two_lease_security(lease_path)
    for _ in range(128):
        path = os.path.join(parent, f".phase-two-mutator-{label}-{secrets.token_hex(16)}.spool")
        try:
            write_new_file(path, b"", security)
            return path
        except WindowsAclError:
            if not os.path.lexists(path):
                raise
    raise WindowsAclError("could not allocate a private phase-two mutator output spool")


def _phase_two_mutator_wrapper_main(arguments: list[str]) -> int:
    if (
        len(arguments) < 5
        or arguments[0] != _PHASE_TWO_MUTATOR_MARKER
        or arguments[3] != "--"
    ):
        raise SystemExit("invalid phase-two mutator wrapper invocation")
    lease_path = os.path.abspath(arguments[1])
    try:
        handle = int(arguments[2], 10)
    except ValueError as exc:
        raise SystemExit("invalid inherited phase-two lease handle") from exc
    command = arguments[4:]
    if not command:
        raise SystemExit("phase-two mutator wrapper command is empty")
    expected = _expected_phase_two_lease_security(lease_path)
    _assert_real_phase_two_lease(lease_path)
    if _get_api().get_security(handle) != expected:
        raise WindowsAclError("inherited phase-two mutator lease is invalid")
    stdout_path = _new_private_mutator_spool(lease_path, "stdout")
    stderr_path = _new_private_mutator_spool(lease_path, "stderr")
    try:
        with open(stdout_path, "w+b", buffering=0) as stdout_stream, open(
            stderr_path, "w+b", buffering=0
        ) as stderr_stream:
            process = _popen_with_inherited_lease(
                command,
                handle=handle,
                stdout=stdout_stream,
                stderr=stderr_stream,
            )
            returncode = process.wait()
            stdout_stream.seek(0)
            stderr_stream.seek(0)
            stdout = stdout_stream.read()
            stderr = stderr_stream.read()
        if stdout:
            sys.stdout.buffer.write(stdout)
            sys.stdout.buffer.flush()
        if stderr:
            sys.stderr.buffer.write(stderr)
            sys.stderr.buffer.flush()
        return returncode
    finally:
        for path in (stdout_path, stderr_path):
            try:
                os.unlink(path)
            except OSError:
                pass


def assert_trusted_owner(security: WindowsFileSecurity) -> None:
    owner = _sid_string(security.owner)
    if owner not in _get_api().trusted_owner_sids():
        raise WindowsAclError("file owner is not a trusted Windows principal")


def assert_not_broadly_writable(security: WindowsFileSecurity) -> None:
    _assert_no_broad_allow(security, _WRITE_RIGHTS, "write")


def assert_not_broadly_readable(security: WindowsFileSecurity) -> None:
    _assert_no_broad_allow(security, _READ_RIGHTS, "read")


def _assert_no_broad_allow(security: WindowsFileSecurity, rights: int, operation: str) -> None:
    for ace_type, ace_flags, access_mask, sid in _iter_dacl_aces(security.dacl):
        if ace_type not in {_ACCESS_ALLOWED_ACE_TYPE, _ACCESS_DENIED_ACE_TYPE}:
            raise WindowsAclError("DACL contains an unsupported ACE type")
        if ace_type != _ACCESS_ALLOWED_ACE_TYPE or ace_flags & _INHERIT_ONLY_ACE:
            continue
        if sid in _BROAD_SIDS and access_mask & rights:
            raise WindowsAclError(f"DACL grants broad {operation} access")


def _iter_dacl_aces(dacl: bytes):
    if len(dacl) < 8:
        raise WindowsAclError("DACL header is truncated")
    acl_size, ace_count = struct.unpack_from("<HH", dacl, 2)
    if acl_size != len(dacl):
        raise WindowsAclError("DACL length does not match its header")
    offset = 8
    for _ in range(ace_count):
        if offset + 8 > len(dacl):
            raise WindowsAclError("DACL ACE is truncated")
        ace_type, ace_flags, ace_size = struct.unpack_from("<BBH", dacl, offset)
        if ace_size < 12 or offset + ace_size > len(dacl):
            raise WindowsAclError("DACL ACE has an invalid size")
        access_mask = struct.unpack_from("<I", dacl, offset + 4)[0]
        sid = _sid_string(dacl[offset + 8 : offset + ace_size])
        yield ace_type, ace_flags, access_mask, sid
        offset += ace_size
    if offset != len(dacl):
        raise WindowsAclError("DACL contains trailing bytes")


def _sid_string(sid: bytes) -> str:
    if len(sid) < 8:
        raise WindowsAclError("SID is truncated")
    revision = sid[0]
    count = sid[1]
    expected = 8 + count * 4
    if revision != 1 or len(sid) != expected:
        raise WindowsAclError("SID has an invalid binary representation")
    authority = int.from_bytes(sid[2:8], "big")
    components = [str(struct.unpack_from("<I", sid, 8 + index * 4)[0]) for index in range(count)]
    suffix = "-".join(components)
    return f"S-{revision}-{authority}" + (f"-{suffix}" if suffix else "")


if __name__ == "__main__":
    raise SystemExit(_phase_two_mutator_wrapper_main(sys.argv[1:]))


__all__ = [
    "WindowsAclError",
    "WindowsFileSecurity",
    "apply_path",
    "assert_not_broadly_readable",
    "assert_not_broadly_writable",
    "assert_trusted_owner",
    "capture_fd",
    "capture_path",
    "ensure_phase_two_mutator_lease",
    "delete_regular_file_by_handle",
    "hold_directory",
    "hold_directory_chain",
    "hold_phase_two_mutator_lease",
    "move_file_no_replace",
    "open_regular_read_fd_shared_delete",
    "private_security_for_directory",
    "replace_regular_file_by_handle",
    "replace_file",
    "run_phase_two_mutator",
    "write_new_file",
]
