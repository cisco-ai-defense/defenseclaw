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

"""Authenticated handoff from the Python CLI to native Windows Setup."""

from __future__ import annotations

import contextlib
import ctypes
import hashlib
import json
import os
import re
import stat
import struct
import subprocess
import sys
from dataclasses import dataclass
from typing import BinaryIO

_LOCAL_APP_DATA_FOLDER_ID = "f1b32785-6fba-4fcf-9d55-7b8e7f157091"
_PROFILE_FOLDER_ID = "5e6c858f-0e22-4760-9afe-ea3317b67173"
_SETUP_NAME = "DefenseClawSetup-x64.exe"
_INSTALL_STATE_NAME = "install-state.json"
_PAYLOAD_MANIFEST_NAME = "payload-manifest.json"
_MAX_INSTALL_STATE_BYTES = 256 * 1024
_MAX_PAYLOAD_MANIFEST_BYTES = 8 * 1024 * 1024
_MAX_SETUP_BYTES = 512 * 1024 * 1024
_IMAGE_FILE_MACHINE_AMD64 = 0x8664
_PRODUCT_PUBLISHER = "Cisco Systems, Inc."
_RESTART_REQUIRED = 3010
_INSTALL_FAILURE = 1603
_SOURCE_BUILD_ID = re.compile(rb"defenseclaw-setup-([0-9a-f]{40})")
_SOURCE_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_TRANSACTION_ID = re.compile(r"[0-9a-f]{32}\Z")
_VERSION = re.compile(
    r"(?:0|[1-9][0-9]{0,9})\."
    r"(?:0|[1-9][0-9]{0,9})\."
    r"(?:0|[1-9][0-9]{0,9})"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z"
)

_INSTALL_STATE_REQUIRED_FIELDS = frozenset(
    {
        "schema_version",
        "version",
        "source_commit",
        "distribution_flavor",
        "install_kind",
        "install_scope",
        "install_root",
        "command_dir",
        "data_root",
        "runtime",
        "maintenance_path",
        "path_entry_owned",
        "connector",
        "mode",
        "unsigned_local_artifact",
        "release_signing_required",
        "toolchain",
        "installed_at_utc",
    }
)
_INSTALL_STATE_OPTIONAL_FIELDS = frozenset(
    {
        "path_separator_reused",
        "path_value_created",
        "codex_home",
        "claude_config_dir",
        "transaction_id",
    }
)
_PAYLOAD_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "version",
        "source_commit",
        "distribution_flavor",
        "python_version",
        "gateway_archive",
        "wheel",
        "python_embed",
        "yara_compat_wheel",
        "upgrade_manifest",
        "site_packages",
        "launcher",
        "startup_launcher",
        "cosign_verifier",
        "unsigned",
        "authenticode",
        "toolchain",
        "files",
    }
)


class NativeWindowsUninstallRefusal(RuntimeError):  # noqa: N818
    """The canonical native install exists but cannot be authenticated."""


@dataclass(frozen=True)
class NativeWindowsUninstallRequest:
    """Immutable custody and argv selected from the exact installer state."""

    platform_name: str
    wipe_data: bool
    install_root: str
    state_path: str
    payload_manifest_path: str
    setup_path: str
    version: str
    source_commit: str
    state_sha256: str
    payload_manifest_sha256: str
    argv: tuple[str, ...]


@dataclass(frozen=True)
class NativeWindowsUninstallOutcome:
    """Full native Setup outcome without POSIX-style status truncation."""

    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def restart_required(self) -> bool:
        return self.returncode == _RESTART_REQUIRED

    @property
    def refused(self) -> bool:
        return self.returncode == _INSTALL_FAILURE


def prepare_native_windows_uninstall(
    *,
    wipe_data: bool,
    platform_name: str | None = None,
) -> NativeWindowsUninstallRequest | None:
    """Resolve and validate the exact native install without changing state."""

    platform_name = platform_name or sys.platform
    if platform_name != "win32":
        return None

    local_app_data = _known_folder_path(_LOCAL_APP_DATA_FOLDER_ID)
    profile = _known_folder_path(_PROFILE_FOLDER_ID)
    if not local_app_data or not profile:
        raise NativeWindowsUninstallRefusal(
            "Windows Known Folders could not be resolved for native uninstall."
        )

    install_root = _exact_child(local_app_data, "Programs", "DefenseClaw")
    installer_root = _exact_child(install_root, "installer")
    state_path = _exact_child(installer_root, _INSTALL_STATE_NAME)
    payload_manifest_path = _exact_child(installer_root, _PAYLOAD_MANIFEST_NAME)
    cache_root = _exact_child(local_app_data, "DefenseClaw", "InstallerCache")
    setup_path = _exact_child(cache_root, _SETUP_NAME)

    if not os.path.lexists(state_path):
        return None

    for path, label, directory in (
        (install_root, "native install root", True),
        (installer_root, "native installer-state directory", True),
        (state_path, "native installer state", False),
        (payload_manifest_path, "native payload manifest", False),
        (cache_root, "native installer cache", True),
        (setup_path, "cached native Setup", False),
    ):
        _validate_private_path(path, label=label, directory=directory)

    state, state_sha256 = _read_private_json(
        state_path,
        label="native installer state",
        limit=_MAX_INSTALL_STATE_BYTES,
    )
    expected_paths = {
        "install_root": install_root,
        "command_dir": _exact_child(install_root, "bin"),
        "data_root": _exact_child(profile, ".defenseclaw"),
        "runtime": _exact_child(install_root, "runtime", "python"),
        "maintenance_path": setup_path,
    }
    version, source_commit = _validate_install_state(state, expected_paths)

    payload, payload_sha256 = _read_private_json(
        payload_manifest_path,
        label="native payload manifest",
        limit=_MAX_PAYLOAD_MANIFEST_BYTES,
    )
    _validate_payload_manifest(
        payload,
        version=version,
        source_commit=source_commit,
        distribution_flavor=str(state["distribution_flavor"]),
    )

    argv = [setup_path, "/uninstall", "/quiet"]
    if wipe_data:
        argv.append("DELETEUSERDATA=1")
    return NativeWindowsUninstallRequest(
        platform_name=platform_name,
        wipe_data=wipe_data,
        install_root=install_root,
        state_path=state_path,
        payload_manifest_path=payload_manifest_path,
        setup_path=setup_path,
        version=version,
        source_commit=source_commit,
        state_sha256=state_sha256,
        payload_manifest_sha256=payload_sha256,
        argv=tuple(argv),
    )


def execute_native_windows_uninstall(
    request: NativeWindowsUninstallRequest,
) -> NativeWindowsUninstallOutcome:
    """Authenticate and synchronously run cached Setup through fixed argv."""

    current = prepare_native_windows_uninstall(
        wipe_data=request.wipe_data,
        platform_name=request.platform_name,
    )
    if current is None or current != request:
        raise NativeWindowsUninstallRefusal(
            "Native installer state changed before uninstall dispatch."
        )

    with _open_locked_setup(request.setup_path) as stream:
        _validate_private_path(
            request.setup_path,
            label="locked cached native Setup",
            directory=False,
        )
        machine = _portable_executable_machine(stream)
        if machine != _IMAGE_FILE_MACHINE_AMD64:
            raise NativeWindowsUninstallRefusal(
                "Cached native Setup is not a Windows x64 executable."
            )
        before_digest, before_source = _setup_digest_and_source(stream)
        if before_source != request.source_commit:
            raise NativeWindowsUninstallRefusal(
                "Cached native Setup source identity differs from installer state."
            )
        _verify_setup_authenticode(
            request.setup_path,
            expected_version=request.version,
        )
        after_digest, after_source = _setup_digest_and_source(stream)
        if before_digest != after_digest or before_source != after_source:
            raise NativeWindowsUninstallRefusal(
                "Cached native Setup digest changed during authentication."
            )

        try:
            completed = subprocess.run(
                list(request.argv),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                close_fds=True,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise NativeWindowsUninstallRefusal(
                f"Could not run authenticated native Setup: {exc}"
            ) from exc

    return NativeWindowsUninstallOutcome(
        returncode=int(completed.returncode),
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
    )


def _known_folder_path(folder_id: str) -> str:
    from defenseclaw.doctor_hooks import _windows_known_folder_path

    return _windows_known_folder_path(folder_id)


def _exact_child(root: str, *parts: str) -> str:
    base = os.path.abspath(root)
    candidate = os.path.abspath(os.path.join(base, *parts))
    try:
        contained = os.path.commonpath((base, candidate)) == base
    except ValueError:
        contained = False
    if not contained:
        raise NativeWindowsUninstallRefusal(
            f"Native uninstall path escapes its Known Folder: {candidate}"
        )
    return candidate


def _validate_private_path(path: str, *, label: str, directory: bool) -> None:
    from defenseclaw.file_permissions import (
        _windows_acl_has_required_access,
        reject_reparse_path,
        windows_acl_write_error,
    )

    try:
        reject_reparse_path(path)
        info = os.lstat(path)
    except OSError as exc:
        raise NativeWindowsUninstallRefusal(
            f"Could not validate {label}: {exc}"
        ) from exc
    expected_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not expected_type:
        raise NativeWindowsUninstallRefusal(
            f"{label.capitalize()} is not the expected regular {'directory' if directory else 'file'}."
        )
    problem = windows_acl_write_error(path)
    if problem is not None:
        raise NativeWindowsUninstallRefusal(
            f"{label.capitalize()} is not current-user owned with a private DACL: {problem}."
        )
    try:
        required_access = _windows_acl_has_required_access(path)
    except OSError as exc:
        raise NativeWindowsUninstallRefusal(
            f"Could not validate {label} DACL: {exc}"
        ) from exc
    if not required_access:
        raise NativeWindowsUninstallRefusal(
            f"{label.capitalize()} does not have the required private owner/SYSTEM DACL."
        )


def _read_private_json(
    path: str,
    *,
    label: str,
    limit: int,
) -> tuple[dict[str, object], str]:
    from defenseclaw.file_permissions import open_regular_file_no_follow

    try:
        fd = open_regular_file_no_follow(path)
        try:
            size = os.fstat(fd).st_size
            if size <= 0 or size > limit:
                raise OSError(f"file is outside the {limit}-byte bound")
            raw = _read_exact_fd(fd, size)
        finally:
            os.close(fd)
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise NativeWindowsUninstallRefusal(
            f"Could not read {label} safely: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise NativeWindowsUninstallRefusal(f"{label.capitalize()} must be a JSON object.")
    return value, hashlib.sha256(raw).hexdigest()


def _read_exact_fd(fd: int, size: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = os.read(fd, min(1024 * 1024, remaining))
        if not chunk:
            raise OSError("unexpected end of file")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(fd, 1):
        raise OSError("file grew while reading")
    os.lseek(fd, 0, os.SEEK_SET)
    return b"".join(chunks)


def _validate_install_state(
    state: dict[str, object],
    expected_paths: dict[str, str],
) -> tuple[str, str]:
    fields = set(state)
    if not _INSTALL_STATE_REQUIRED_FIELDS.issubset(fields) or not fields.issubset(
        _INSTALL_STATE_REQUIRED_FIELDS | _INSTALL_STATE_OPTIONAL_FIELDS
    ):
        raise NativeWindowsUninstallRefusal(
            "Native installer state does not use the supported closed schema."
        )
    schema = state.get("schema_version")
    version = state.get("version")
    source_commit = state.get("source_commit")
    transaction_id = state.get("transaction_id", "")
    if schema != 1 or isinstance(schema, bool):
        raise NativeWindowsUninstallRefusal("Native installer state schema is unsupported.")
    if not isinstance(version, str) or len(version) > 192 or _VERSION.fullmatch(version) is None:
        raise NativeWindowsUninstallRefusal("Native installer state version is invalid.")
    if not isinstance(source_commit, str) or _SOURCE_COMMIT.fullmatch(source_commit) is None:
        raise NativeWindowsUninstallRefusal(
            "Native installer state source commit is invalid."
        )
    if transaction_id and (
        not isinstance(transaction_id, str)
        or _TRANSACTION_ID.fullmatch(transaction_id) is None
    ):
        raise NativeWindowsUninstallRefusal(
            "Native installer state transaction identity is invalid."
        )
    if (
        state.get("distribution_flavor") != "oss"
        or state.get("install_kind") != "native-windows-exe"
        or state.get("install_scope") != "user"
        or state.get("connector") not in {"codex", "claudecode", "none"}
        or state.get("mode") not in {"observe", "action"}
        or state.get("unsigned_local_artifact") is not False
        or state.get("release_signing_required") is not True
        or not isinstance(state.get("toolchain"), dict)
        or not isinstance(state.get("installed_at_utc"), str)
    ):
        raise NativeWindowsUninstallRefusal(
            "Native installer state is not an authenticated signed user installation."
        )
    for field, expected in expected_paths.items():
        value = state.get(field)
        if (
            not isinstance(value, str)
            or os.path.normcase(os.path.abspath(value))
            != os.path.normcase(os.path.abspath(expected))
        ):
            raise NativeWindowsUninstallRefusal(
                f"Native installer state has an unexpected {field.replace('_', ' ')}."
            )
    return version, source_commit


def _validate_payload_manifest(
    payload: dict[str, object],
    *,
    version: str,
    source_commit: str,
    distribution_flavor: str,
) -> None:
    if set(payload) != _PAYLOAD_MANIFEST_FIELDS:
        raise NativeWindowsUninstallRefusal(
            "Native payload manifest does not use the supported closed schema."
        )
    if (
        payload.get("schema_version") != 2
        or isinstance(payload.get("schema_version"), bool)
        or payload.get("version") != version
        or payload.get("source_commit") != source_commit
        or payload.get("distribution_flavor") != distribution_flavor
        or payload.get("unsigned") is not False
        or not isinstance(payload.get("authenticode"), dict)
        or not isinstance(payload.get("toolchain"), dict)
        or not isinstance(payload.get("files"), dict)
    ):
        raise NativeWindowsUninstallRefusal(
            "Native payload manifest does not match signed installer-state custody."
        )


@contextlib.contextmanager
def _open_locked_setup(path: str) -> BinaryIO:
    if os.name != "nt":
        raise NativeWindowsUninstallRefusal(
            "Native Windows Setup custody is unavailable on this platform."
        )
    import msvcrt
    from ctypes import wintypes

    generic_read = 0x80000000
    read_control = 0x00020000
    file_share_read = 0x00000001
    open_existing = 3
    file_attribute_normal = 0x00000080
    file_flag_open_reparse_point = 0x00200000
    file_attribute_directory = 0x00000010
    file_attribute_reparse_point = 0x00000400
    invalid_handle_value = ctypes.c_void_p(-1).value

    class _ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_ByHandleFileInformation),
    ]
    get_information.restype = wintypes.BOOL
    get_final_path = kernel32.GetFinalPathNameByHandleW
    get_final_path.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    get_final_path.restype = wintypes.DWORD
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    handle = create_file(
        os.path.abspath(path),
        generic_read | read_control,
        file_share_read,
        None,
        open_existing,
        file_attribute_normal | file_flag_open_reparse_point,
        None,
    )
    if handle == invalid_handle_value:
        raise NativeWindowsUninstallRefusal(
            f"Could not lock cached native Setup: {ctypes.WinError(ctypes.get_last_error())}"
        )
    fd = -1
    try:
        information = _ByHandleFileInformation()
        if not get_information(handle, ctypes.byref(information)):
            raise ctypes.WinError(ctypes.get_last_error())
        if information.dwFileAttributes & (
            file_attribute_directory | file_attribute_reparse_point
        ):
            raise NativeWindowsUninstallRefusal(
                "Cached native Setup handle is not a regular non-reparse file."
            )
        final_path = _final_path_for_handle(handle, get_final_path)
        if os.path.normcase(os.path.abspath(final_path)) != os.path.normcase(
            os.path.abspath(path)
        ):
            raise NativeWindowsUninstallRefusal(
                "Cached native Setup final handle path changed."
            )
        os.set_handle_inheritable(int(handle), False)
        fd = msvcrt.open_osfhandle(
            int(handle),
            os.O_RDONLY | getattr(os, "O_BINARY", 0),
        )
        handle = None
        with os.fdopen(fd, "rb", closefd=True) as stream:
            fd = -1
            yield stream
    except NativeWindowsUninstallRefusal:
        raise
    except OSError as exc:
        raise NativeWindowsUninstallRefusal(
            f"Could not validate cached native Setup handle: {exc}"
        ) from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if handle not in (None, invalid_handle_value):
            close_handle(handle)


def _final_path_for_handle(handle: object, get_final_path: object) -> str:
    size = 512
    while True:
        buffer = ctypes.create_unicode_buffer(size)
        length = int(get_final_path(handle, buffer, size, 0))
        if length == 0:
            raise ctypes.WinError(ctypes.get_last_error())
        if length < size:
            value = buffer.value
            if value.startswith("\\\\?\\UNC\\"):
                return "\\\\" + value[len("\\\\?\\UNC\\") :]
            if value.startswith("\\\\?\\"):
                return value[len("\\\\?\\") :]
            return value
        size = length + 1
        if size > 32768:
            raise OSError("cached native Setup final path exceeds the Windows limit")


def _portable_executable_machine(stream: BinaryIO) -> int:
    size = os.fstat(stream.fileno()).st_size
    if size <= 0 or size > _MAX_SETUP_BYTES:
        raise NativeWindowsUninstallRefusal(
            f"Cached native Setup is outside the {_MAX_SETUP_BYTES}-byte size bound."
        )
    header = _read_at(stream, 0, 64)
    if len(header) != 64 or header[:2] != b"MZ":
        raise NativeWindowsUninstallRefusal("Cached native Setup lacks an MZ header.")
    pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
    if pe_offset < 64 or pe_offset > size - 6:
        raise NativeWindowsUninstallRefusal(
            "Cached native Setup has an invalid PE header offset."
        )
    signature = _read_at(stream, pe_offset, 6)
    if signature[:4] != b"PE\0\0":
        raise NativeWindowsUninstallRefusal(
            "Cached native Setup lacks a valid PE signature."
        )
    return struct.unpack_from("<H", signature, 4)[0]


def _read_at(stream: BinaryIO, offset: int, size: int) -> bytes:
    stream.seek(offset)
    value = stream.read(size)
    stream.seek(0)
    return value


def _setup_digest_and_source(stream: BinaryIO) -> tuple[str, str]:
    stream.seek(0)
    digest = hashlib.sha256()
    sources: set[str] = set()
    overlap = b""
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
        searchable = overlap + chunk
        sources.update(
            match.group(1).decode("ascii")
            for match in _SOURCE_BUILD_ID.finditer(searchable)
        )
        overlap = searchable[-128:]
    stream.seek(0)
    if len(sources) != 1:
        raise NativeWindowsUninstallRefusal(
            "Cached native Setup does not contain one exact source build identity."
        )
    return digest.hexdigest(), next(iter(sources))


def _verify_setup_authenticode(path: str, *, expected_version: str) -> None:
    powershell = _system_powershell_path()
    if not powershell:
        raise NativeWindowsUninstallRefusal(
            "System Windows PowerShell is required to verify cached native Setup."
        )
    script = (
        "$sig=Get-AuthenticodeSignature -LiteralPath $args[0];"
        "$publisher='';"
        "if($sig.SignerCertificate){"
        "$publisher=$sig.SignerCertificate.GetNameInfo("
        "[Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false)};"
        "$version=[Diagnostics.FileVersionInfo]::GetVersionInfo($args[0]).ProductVersion;"
        "[pscustomobject]@{"
        "Status=[string]$sig.Status;"
        "Publisher=$publisher;"
        "SignatureType=[string]$sig.SignatureType;"
        "ProductVersion=[string]$version"
        "}|ConvertTo-Json -Compress"
    )
    try:
        completed = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", script, path],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
            close_fds=True,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise NativeWindowsUninstallRefusal(
            f"Could not verify cached native Setup Authenticode: {exc}"
        ) from exc
    if completed.returncode != 0:
        raise NativeWindowsUninstallRefusal(
            "System Windows PowerShell could not verify cached native Setup Authenticode."
        )
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise NativeWindowsUninstallRefusal(
            "Cached native Setup Authenticode output is malformed."
        ) from exc
    if not isinstance(value, dict) or set(value) != {
        "Status",
        "Publisher",
        "SignatureType",
        "ProductVersion",
    }:
        raise NativeWindowsUninstallRefusal(
            "Cached native Setup Authenticode output has an unexpected schema."
        )
    if (
        value["Status"] != "Valid"
        or value["Publisher"] != _PRODUCT_PUBLISHER
        or value["SignatureType"] != "Authenticode"
        or value["ProductVersion"] != expected_version
    ):
        raise NativeWindowsUninstallRefusal(
            "Cached native Setup signer, signature type, or version is not trusted."
        )


def _system_powershell_path() -> str | None:
    if os.name != "nt":
        return None
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_system_directory = kernel32.GetSystemDirectoryW
    get_system_directory.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    get_system_directory.restype = wintypes.UINT
    buffer = ctypes.create_unicode_buffer(32768)
    length = int(get_system_directory(buffer, len(buffer)))
    if length == 0 or length >= len(buffer):
        return None
    candidate = os.path.join(
        buffer.value,
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe",
    )
    return candidate if os.path.isfile(candidate) else None


__all__ = [
    "NativeWindowsUninstallOutcome",
    "NativeWindowsUninstallRefusal",
    "NativeWindowsUninstallRequest",
    "execute_native_windows_uninstall",
    "prepare_native_windows_uninstall",
]
