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

"""Bounded adapter for the bundled s-gw credential broker."""

from __future__ import annotations

import ctypes
import hashlib
import json
import ntpath
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defenseclaw.gateway import canonical_install_path, packaged_windows_gateway_path

_MAX_JSON_BYTES = 1024 * 1024
_DRIVER_TIMEOUT_SECONDS = 30
_SETUP_TIMEOUT_SECONDS = 120
_CONSOLE_OUTPUT_BYTES = 4 * 1024
_CONSOLE_ERROR_BYTES = 64 * 1024
_SAFE_DRIVER_ENV = {
    "SGW_AGENT_NAME": "DefenseClaw",
    "SGW_DISABLE_UPDATE_CHECK": "1",
    "SGW_EXECUTION_ENGINE": "rust",
}
_MCP_AGENT_NAMES = {
    "openclaw": "OpenClaw",
    "codex": "Codex",
    "claudecode": "Claude Code",
    "zeptoclaw": "ZeptoClaw",
    "hermes": "Hermes Agent",
    "cursor": "Cursor",
    "windsurf": "Windsurf",
    "geminicli": "Gemini CLI",
    "copilot": "GitHub Copilot CLI",
    "openhands": "OpenHands",
    "antigravity": "Antigravity",
    "opencode": "OpenCode",
    "omnigent": "OmniGent",
}
_AGENT_MCP_ARGS: list[str] = []
_MCP_SERVER_NAME = "s-gw"
_MCP_OWNER_ENV = {"DEFENSECLAW_MCP_OWNER": "s-gw-credential-protection-v1"}
_MANUAL_MCP_CONNECTORS = frozenset({"omnigent", "windsurf", "zeptoclaw"})
_PROXY_CONNECTORS = frozenset({"openclaw", "zeptoclaw"})
_REPAIRABLE_MODULE_STATES = frozenset({"artifact_invalid", "module_invalid", "receipt_invalid", "runner_unavailable"})
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$")
_MODULE_GENERATION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,191}$")
_MAX_ARGUMENT_BYTES = 64 * 1024
_MAX_ARGUMENTS = 256
_MCP_BINDING_LIMIT = 256
_MCP_BINDING_BYTES = 1024 * 1024

_DRIVER_ENV_KEYS = (
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LOGNAME",
    "TEMP",
    "TMP",
    "TMPDIR",
    "USER",
    "USERNAME",
    "USERPROFILE",
)
_SGW_ENV_KEYS = _DRIVER_ENV_KEYS + (
    "APPDATA",
    "DBUS_SESSION_BUS_ADDRESS",
    "DISPLAY",
    "HOMEDRIVE",
    "HOMEPATH",
    "LOCALAPPDATA",
    "NO_COLOR",
    "PROGRAMDATA",
    "TERM",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XDG_CURRENT_DESKTOP",
    "XDG_RUNTIME_DIR",
    "XDG_SESSION_TYPE",
)
_AGENT_PATH_ENV_KEYS = (
    "CLAUDE_CONFIG_DIR",
    "CODEX_HOME",
    "COPILOT_HOME",
    "GEMINI_CLI_HOME",
    "HERMES_HOME",
    "OMNIGENT_CONFIG_HOME",
    "OPENCODE_CONFIG_DIR",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "ZEPTOCLAW_HOME",
)
_PROCESS_INJECTION_ENV = frozenset(
    {
        "BASH_ENV",
        "ENV",
        "NODE_OPTIONS",
        "NODE_PATH",
        "NODE_REPL_EXTERNAL_MODULE",
        "NPM_CONFIG_NODE_OPTIONS",
        "PYTHONHOME",
        "PYTHONPATH",
        "RUBYOPT",
        "ZDOTDIR",
    }
)
_MCP_NEUTRALIZED_ENV = (
    "DYLD_FALLBACK_FRAMEWORK_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "GODEBUG",
    "LD_AUDIT",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "NODE_DEBUG",
    "NODE_DEBUG_NATIVE",
    "NODE_EXTRA_CA_CERTS",
    "NODE_OPTIONS",
    "NODE_PATH",
    "NODE_TLS_REJECT_UNAUTHORIZED",
    "NPM_CONFIG_NODE_OPTIONS",
    "OPENSSL_CONF",
)
_MCP_NEUTRALIZED_SGW_ENV = (
    "SGW_AGENT_PROCESS_TREE",
    "SGW_ALLOW_SECURITY_CLI",
    "SGW_APPLICATIONS_DIR",
    "SGW_APP_PATH",
    "SGW_ASKPASS_FILE",
    "SGW_AWS_DEV_ACCESS_KEY_ID",
    "SGW_AWS_DEV_CREDENTIAL",
    "SGW_CLI_PATH",
    "SGW_CONSOLE_CLI_PATH",
    "SGW_CONSOLE_LIVE",
    "SGW_CONSOLE_NODE_PATH",
    "SGW_CONSOLE_PORT",
    "SGW_CONSOLE_TOKEN",
    "SGW_CONSOLE_URL",
    "SGW_DISABLE_KEYCHAIN",
    "SGW_DISABLE_ONEPASSWORD_BACKUP",
    "SGW_DISABLE_PROCESS_AGENT_DETECTION",
    "SGW_E2E_TOKEN",
    "SGW_FAKE_SECRET_SERVICE_DB",
    "SGW_GUARD_AGENT",
    "SGW_GUARD_INSTRUCTIONS",
    "SGW_GUARD_MODE",
    "SGW_GUARD_TOKENIZED_ENV",
    "SGW_HELPER_INSTANCE_KEY",
    "SGW_HELPER_LAUNCHED_PID",
    "SGW_HELPER_LAUNCHED_TICKS",
    "SGW_HELPER_LAUNCH_NONCE",
    "SGW_HELPER_PORT",
    "SGW_HELPER_POWERSHELL_PATH",
    "SGW_HELPER_SCRIPT_PATH",
    "SGW_HELPER_SETTLE",
    "SGW_KEYCHAIN_ACCOUNT",
    "SGW_KEYCHAIN_HELPER",
    "SGW_KEYCHAIN_INSPECTOR",
    "SGW_KEYCHAIN_LEGACY_HELPERS",
    "SGW_KEYCHAIN_SERVICE",
    "SGW_KEYCHAIN_STATUS_CLI",
    "SGW_LOGIN_SESSION_ID",
    "SGW_MASTER_PASSPHRASE",
    "SGW_MENU_BAR_COUNT_MODE",
    "SGW_NODE_PATH",
    "SGW_ONEPASSWORD_TIMEOUT_MS",
    "SGW_OP_CLI",
    "SGW_OUTPUT_TRUNCATED",
    "SGW_REAL_OP_PATH",
    "SGW_REPO_ROOT",
    "SGW_REQUEST_AGENT_NAME",
    "SGW_SECRET",
    "SGW_SECRET_BACKEND",
    "SGW_SECRET_KEYCHAIN_SERVICE",
    "SGW_SECRET_SERVICE_HELPER",
    "SGW_SECRET_TOOL",
    "SGW_SECRET_TOOL_TIMEOUT_MS",
    "SGW_SKIP_APP_STOP",
    "SGW_SKIP_MAC_APP_CLI_REGISTRATION",
    "SGW_SSH_CLI",
    "SGW_SSH_CONTROL_DIR",
    "SGW_SSH_CREDENTIAL",
    "SGW_SSH_KEY",
    "SGW_SSH_PASSWORD",
    "SGW_SSH_PRIVATE_KEY",
    "SGW_SSH_SESSION_COMMAND",
    "SGW_STOP_CLIENT_PATH",
    "SGW_STOP_CLI_PATH",
    "SGW_STOP_HEALTH_URL",
    "SGW_STOP_HELPER_INSTANCE_KEY",
    "SGW_STOP_HELPER_PATH",
    "SGW_STOP_INSTANCE_KEY",
    "SGW_STOP_NODE_PATH",
    "SGW_STOP_PORT",
    "SGW_STOP_POWERSHELL_PATH",
    "SGW_SYSTEMCTL",
    "SGW_TEST_HOME_ROOT",
    "SGW_TEST_LIVE_HOME",
    "SGW_TEST_LIVE_RECOVERY_HOME",
    "SGW_TEST_LOCK_TIMEOUT_MS",
    "SGW_TEST_MODE",
    "SGW_WINDOWS_ACL_EXPECTED_SID",
    "SGW_WINDOWS_ACL_MODE",
    "SGW_WINDOWS_ACL_OPERATION_TIMEOUT_MS",
    "SGW_WINDOWS_ACL_PATH",
    "SGW_WINDOWS_ACL_TEST_ROOT",
    "SGW_WINDOWS_CREDENTIAL_HELPER",
    "SGW_WINDOWS_CREDENTIAL_HELPER_TIMEOUT_MS",
    "SGW_WINDOWS_HELPER_OPERATION_TIMEOUT_MS",
    "SGW_WINDOWS_PROCESS_INSPECTION_TIMEOUT_MS",
    "SGW_WINDOWS_STARTUP_ARGUMENTS",
    "SGW_WINDOWS_STARTUP_CLI",
    "SGW_WINDOWS_STARTUP_MODE",
    "SGW_WINDOWS_STARTUP_OPERATION_TIMEOUT_MS",
    "SGW_WINDOWS_STARTUP_TARGET",
    "SGW_WINDOWS_STARTUP_TEST_ROOT",
    "SGW_WINDOWS_STARTUP_WORKING",
)
_MCP_PINNED_SGW_ENV = frozenset(
    {
        "SGW_AGENT_NAME",
        "SGW_DISABLE_UPDATE_CHECK",
        "SGW_EXECUTION_ENGINE",
        "SGW_HOME",
        "SGW_RECOVERY_HOME",
        "SGW_TRUSTED_POWERSHELL",
    }
)

_SAFE_MESSAGES = {
    "artifact_invalid": "The bundled s-gw module artifact failed integrity validation.",
    "artifact_unavailable": "The bundled s-gw module is unavailable in this DefenseClaw build.",
    "command_invalid": "The bundled s-gw command description was invalid.",
    "connector_conflict": "s-gw found a conflicting agent credential integration.",
    "driver_failed": "The bundled s-gw module helper failed.",
    "driver_missing": "The bundled s-gw module helper is unavailable.",
    "driver_output_invalid": "The bundled s-gw module helper returned an invalid response.",
    "driver_output_too_large": "The bundled s-gw module helper returned too much data.",
    "driver_timeout": "The bundled s-gw module helper timed out.",
    "gateway_lifecycle_failed": "The DefenseClaw gateway could not be safely restarted after s-gw maintenance.",
    "incompatible": "The bundled s-gw module is incompatible with this DefenseClaw build.",
    "locked": "The local s-gw credential broker is not initialized.",
    "module_invalid": "The installed s-gw module failed integrity validation.",
    "mcp_reconciliation_failed": "One or more connector MCP registrations could not be reconciled.",
    "node_missing": "Node.js 20 or newer is required for credential protection.",
    "node_unsupported": "The installed Node.js version is too old for credential protection.",
    "not_installed": "The bundled s-gw module is not installed.",
    "receipt_invalid": "The installed s-gw receipt failed validation.",
    "runner_unavailable": "The supported s-gw runtime is unavailable for this platform.",
    "sgw_failed": "s-gw could not complete the requested operation.",
    "sgw_output_invalid": "s-gw returned an invalid response.",
    "sgw_output_too_large": "s-gw returned too much data.",
    "sgw_timeout": "s-gw did not respond in time.",
    "unavailable": "The local s-gw credential broker is unavailable.",
}


class CredentialProtectionError(RuntimeError):
    """An s-gw operation failed without exposing child-process output."""

    def __init__(self, code: str):
        safe_code = code if code in _SAFE_MESSAGES else "driver_failed"
        self.code = safe_code
        super().__init__(_SAFE_MESSAGES[safe_code])


class _DuplicateJSONKeyError(ValueError):
    pass


class _OutputTooLargeError(RuntimeError):
    pass


@dataclass(frozen=True)
class ModuleResources:
    driver: Path
    manifest: Path
    artifact: Path | None = None
    artifact_sha256: str = ""


ProcessRunner = Callable[..., subprocess.CompletedProcess[str]]
GatewayLifecycleAction = Callable[[], bool]


@dataclass(frozen=True)
class MCPRegistrationBinding:
    connector: str
    target: str
    entry: dict[str, Any]


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateJSONKeyError(key)
        value[key] = item
    return value


def _load_json_object(raw: bytes | str, *, invalid_code: str) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateJSONKeyError) as exc:
        raise CredentialProtectionError(invalid_code) from exc
    if not isinstance(value, dict):
        raise CredentialProtectionError(invalid_code)
    return value


def _normalized_home(home: str) -> str:
    if not isinstance(home, str) or not home or "\x00" in home or len(home) > 4096:
        raise CredentialProtectionError("command_invalid")
    expanded = os.path.abspath(os.path.expanduser(home))
    if not expanded or os.path.dirname(expanded) == expanded:
        raise CredentialProtectionError("command_invalid")
    return expanded


def _validated_arguments(arguments: list[str] | None) -> list[str]:
    if arguments is None:
        return []
    if not isinstance(arguments, list) or len(arguments) > _MAX_ARGUMENTS:
        raise CredentialProtectionError("command_invalid")
    out: list[str] = []
    total = 0
    for value in arguments:
        if not isinstance(value, str) or "\x00" in value:
            raise CredentialProtectionError("command_invalid")
        size = len(value.encode("utf-8", errors="strict"))
        if size > _MAX_ARGUMENT_BYTES:
            raise CredentialProtectionError("command_invalid")
        total += size
        if total > _MAX_JSON_BYTES:
            raise CredentialProtectionError("command_invalid")
        out.append(value)
    return out


def _copy_environment(keys: tuple[str, ...]) -> dict[str, str]:
    child_env: dict[str, str] = {}
    for key in keys:
        value = os.environ.get(key)
        if not value:
            continue
        if "\x00" in value:
            raise CredentialProtectionError("command_invalid")
        child_env[key] = value
    if os.name != "nt" and "HOME" not in child_env:
        home = os.path.expanduser("~")
        if home and "\x00" not in home:
            child_env["HOME"] = home
    return child_env


def _driver_environment() -> dict[str, str]:
    child_env = _copy_environment(_DRIVER_ENV_KEYS)
    child_env.update(_trusted_execution_environment())
    return child_env


def _sgw_environment(additions: dict[str, str], *, agent_paths: bool = False) -> dict[str, str]:
    keys = _SGW_ENV_KEYS + (_AGENT_PATH_ENV_KEYS if agent_paths else ())
    child_env = _copy_environment(keys)
    child_env.update(_trusted_execution_environment())
    child_env.update(additions)
    return child_env


def _trusted_execution_environment() -> dict[str, str]:
    if os.name != "nt":
        return {"PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"}

    powershell = _trusted_windows_powershell()
    version_dir = ntpath.dirname(powershell)
    windows_powershell = ntpath.dirname(version_dir)
    system32 = ntpath.dirname(windows_powershell)
    windows_root = ntpath.dirname(system32)
    if not windows_root or ntpath.dirname(windows_root) == windows_root:
        raise CredentialProtectionError("command_invalid")
    return {
        "PATH": ";".join((version_dir, system32, windows_root)),
        "SystemRoot": windows_root,
        "WINDIR": windows_root,
        "SGW_TRUSTED_POWERSHELL": powershell,
    }


def _trusted_windows_powershell() -> str:
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_windows_directory = kernel32.GetWindowsDirectoryW
        get_windows_directory.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
        get_windows_directory.restype = ctypes.c_uint
        buffer = ctypes.create_unicode_buffer(32_768)
        length = get_windows_directory(buffer, len(buffer))
    except (AttributeError, OSError) as exc:
        raise CredentialProtectionError("command_invalid") from exc
    if length == 0 or length >= len(buffer):
        raise CredentialProtectionError("command_invalid")

    windows_root = Path(buffer.value)
    candidate = windows_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    current = Path(candidate.anchor)
    try:
        for index, part in enumerate(candidate.parts[1:]):
            if not part or part in {".", ".."}:
                raise CredentialProtectionError("command_invalid")
            current = current / part
            metadata = current.lstat()
            reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            if current.is_symlink() or getattr(metadata, "st_file_attributes", 0) & reparse_flag:
                raise CredentialProtectionError("command_invalid")
            is_last = index == len(candidate.parts[1:]) - 1
            if (is_last and not stat.S_ISREG(metadata.st_mode)) or (not is_last and not stat.S_ISDIR(metadata.st_mode)):
                raise CredentialProtectionError("command_invalid")
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise CredentialProtectionError("command_invalid") from exc
    if ntpath.normcase(os.fspath(resolved)) != ntpath.normcase(os.fspath(candidate)):
        raise CredentialProtectionError("command_invalid")
    return os.fspath(resolved)


def _connector_agent_name(connector: str) -> str:
    name = _MCP_AGENT_NAMES.get(connector)
    if name is None:
        raise CredentialProtectionError("mcp_reconciliation_failed")
    return name


def _mcp_store_paths() -> tuple[str, str]:
    primary = os.path.abspath(os.path.expanduser("~/.s-gw"))
    if not primary or not os.path.isabs(primary) or os.path.dirname(primary) == primary or "\x00" in primary:
        raise CredentialProtectionError("mcp_reconciliation_failed")
    return primary, f"{primary}-recovery"


def _registered_mcp_environment(additions: dict[str, str], connector: str) -> dict[str, str]:
    if additions != _SAFE_DRIVER_ENV:
        raise CredentialProtectionError("command_invalid")
    primary, recovery = _mcp_store_paths()
    child_env = {key: "" for key in (*_MCP_NEUTRALIZED_ENV, *_MCP_NEUTRALIZED_SGW_ENV)}
    child_env.update(_MCP_OWNER_ENV)
    if os.name == "nt":
        child_env.update(_trusted_execution_environment())
    else:
        child_env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
    child_env.update(
        {
            "SGW_AGENT_NAME": _connector_agent_name(connector),
            "SGW_DISABLE_UPDATE_CHECK": "1",
            "SGW_EXECUTION_ENGINE": "rust",
            "SGW_HOME": primary,
            "SGW_RECOVERY_HOME": recovery,
        }
    )
    return child_env


def _inherited_guard_environment(additions: dict[str, str]) -> dict[str, str]:
    child_env: dict[str, str] = {}
    for key, value in os.environ.items():
        normalized = key.upper()
        if (
            normalized.startswith("SGW_")
            or normalized.startswith("LD_")
            or normalized.startswith("DYLD_")
            or normalized in _PROCESS_INJECTION_ENV
            or normalized in _MCP_NEUTRALIZED_ENV
            or (os.name == "nt" and normalized in {"SYSTEMROOT", "WINDIR"})
        ):
            continue
        if "\x00" in key or "=" in key or "\x00" in value:
            raise CredentialProtectionError("command_invalid")
        child_env[key] = value
    if os.name == "nt":
        trusted = _trusted_execution_environment()
        trusted.pop("PATH", None)
        child_env.update(trusted)
    child_env.update(additions)
    return child_env


def _read_bounded_output(stream, limit: int) -> str:
    size = stream.tell()
    if size > limit:
        raise _OutputTooLargeError
    stream.seek(0)
    raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise _OutputTooLargeError
    return raw.decode("utf-8", errors="replace")


def _run_bounded_capture(
    argv: list[str],
    *,
    cwd: str | None,
    env: dict[str, str],
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    # Temporary files keep child output out of memory. Only the bounded prefix
    # is ever read back into this process.
    with tempfile.TemporaryFile(mode="w+b") as stdout, tempfile.TemporaryFile(mode="w+b") as stderr:
        if os.name != "nt":
            os.fchmod(stdout.fileno(), 0o600)
            os.fchmod(stderr.fileno(), 0o600)
        completed = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            check=False,
            stdout=stdout,
            stderr=stderr,
            timeout=timeout,
            shell=False,
        )
        return subprocess.CompletedProcess(
            argv,
            completed.returncode,
            _read_bounded_output(stdout, _MAX_JSON_BYTES),
            _read_bounded_output(stderr, _MAX_JSON_BYTES),
        )


def _target_name() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    os_name = {"darwin": "darwin", "linux": "linux", "windows": "win32"}.get(system)
    arch = {
        "aarch64": "arm64",
        "arm64": "arm64",
        "amd64": "x64",
        "x86_64": "x64",
    }.get(machine)
    if not os_name or not arch:
        return ""
    return f"{os_name}-{arch}"


def _candidate_data_dirs() -> list[Path]:
    package_data = Path(__file__).resolve().parent / "_data" / "sgw"
    source_data = Path(__file__).resolve().parents[2] / "release"
    return [package_data, source_data]


def _read_manifest(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise CredentialProtectionError("driver_missing") from exc
    if len(raw) > _MAX_JSON_BYTES:
        raise CredentialProtectionError("driver_output_too_large")
    document = _load_json_object(raw, invalid_code="driver_output_invalid")
    if document.get("schema_version") != 1:
        raise CredentialProtectionError("driver_output_invalid")
    return document


def _checksum_from_file(path: Path, artifact_name: str) -> str:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ""
    for line in lines:
        parts = line.strip().split()
        if not parts:
            continue
        digest = parts[0].lower()
        if not _SHA256_RE.fullmatch(digest):
            continue
        if len(parts) == 1 or parts[-1].lstrip("*") == artifact_name:
            return digest
    return ""


def resolve_module_resources() -> ModuleResources:
    """Resolve installed wheel resources, then source-tree resources."""
    target = _target_name()
    package_data, source_release = _candidate_data_dirs()
    choices = (
        (package_data / "sgw_module.py", package_data / "s-gw-module.json", package_data),
        (
            source_release.parent / "scripts" / "sgw_module.py",
            source_release / "s-gw-module.json",
            None,
        ),
    )
    for driver, manifest, artifact_root in choices:
        if not driver.is_file() or not manifest.is_file() or driver.is_symlink() or manifest.is_symlink():
            continue
        document = _read_manifest(manifest)
        artifact_info = document.get("artifact")
        artifact = None
        digest = ""
        if target and artifact_root is not None and isinstance(artifact_info, dict):
            template = artifact_info.get("resource_template")
            if isinstance(template, str) and template:
                prefix = "_data/sgw/"
                try:
                    relative = template.format(target=target)
                except (KeyError, ValueError) as exc:
                    raise CredentialProtectionError("driver_output_invalid") from exc
                path_parts = Path(relative[len(prefix) :]) if relative.startswith(prefix) else None
                if path_parts is not None and not path_parts.is_absolute() and ".." not in path_parts.parts:
                    candidate = artifact_root / path_parts
                else:
                    candidate = Path()
                if candidate.is_file() and not candidate.is_symlink():
                    artifact = candidate
                    configured = artifact_info.get("sha256")
                    if isinstance(configured, str) and _SHA256_RE.fullmatch(configured.lower()):
                        digest = configured.lower()
                    if not digest:
                        checksum_file = candidate.with_suffix(candidate.suffix + ".sha256")
                        digest = _checksum_from_file(checksum_file, candidate.name)
                    if not digest:
                        digest = _checksum_from_file(
                            artifact_root / "checksums.txt",
                            path_parts.as_posix(),
                        )
        return ModuleResources(driver=driver, manifest=manifest, artifact=artifact, artifact_sha256=digest)
    raise CredentialProtectionError("driver_missing")


def _artifact_is_authenticated(resources: ModuleResources) -> bool:
    artifact = resources.artifact
    digest = resources.artifact_sha256.lower()
    if artifact is None or artifact.is_symlink() or not artifact.is_file():
        return False
    if not _SHA256_RE.fullmatch(digest):
        return False

    hasher = hashlib.sha256()
    try:
        with artifact.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                hasher.update(chunk)
    except OSError:
        return False
    return hasher.hexdigest() == digest


def credential_protection_default_enabled() -> bool:
    """Enable fresh installs only for a checksum-verified staged module."""
    try:
        resources = resolve_module_resources()
    except CredentialProtectionError:
        return False
    return _artifact_is_authenticated(resources)


def _decode_json(raw: str, *, invalid_code: str, too_large_code: str) -> dict[str, Any]:
    if len(raw.encode("utf-8", errors="replace")) > _MAX_JSON_BYTES:
        raise CredentialProtectionError(too_large_code)
    value = _load_json_object(raw, invalid_code=invalid_code)
    if value.get("schema_version", 1) != 1:
        raise CredentialProtectionError(invalid_code)
    return value


def _error_code_from_stderr(raw: str) -> str:
    try:
        value = _decode_json(
            raw,
            invalid_code="driver_failed",
            too_large_code="driver_output_too_large",
        )
    except CredentialProtectionError:
        return "driver_failed"
    error = value.get("error")
    if not isinstance(error, dict):
        return "driver_failed"
    code = error.get("code")
    return code if isinstance(code, str) and code in _SAFE_MESSAGES else "driver_failed"


def _run_driver(
    operation: str,
    *,
    home: str,
    extra_args: list[str] | None = None,
    resources: ModuleResources | None = None,
    runner: ProcessRunner | None = None,
    timeout: int = _DRIVER_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    resolved = resources or resolve_module_resources()
    resolved_home = _normalized_home(home)
    validated_extra_args = _validated_arguments(extra_args)
    argv = [
        sys.executable,
        str(resolved.driver),
        "--manifest",
        str(resolved.manifest),
    ]
    node = _host_node_path()
    if node:
        argv.extend(["--node", node])
    argv.extend(["--home", resolved_home, operation])
    argv.extend(validated_extra_args)
    child_env = _driver_environment()
    try:
        if runner is None:
            completed = _run_bounded_capture(
                argv,
                cwd=None,
                env=child_env,
                timeout=timeout,
            )
        else:
            completed = runner(
                argv,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=child_env,
                timeout=timeout,
                shell=False,
            )
    except FileNotFoundError as exc:
        raise CredentialProtectionError("driver_missing") from exc
    except subprocess.TimeoutExpired as exc:
        raise CredentialProtectionError("driver_timeout") from exc
    except _OutputTooLargeError as exc:
        raise CredentialProtectionError("driver_output_too_large") from exc
    except OSError as exc:
        raise CredentialProtectionError("driver_failed") from exc
    if (
        len((completed.stdout or "").encode("utf-8", errors="replace")) > _MAX_JSON_BYTES
        or len((completed.stderr or "").encode("utf-8", errors="replace")) > _MAX_JSON_BYTES
    ):
        raise CredentialProtectionError("driver_output_too_large")
    if completed.returncode != 0:
        raise CredentialProtectionError(_error_code_from_stderr(completed.stderr or ""))
    return _decode_json(
        completed.stdout or "",
        invalid_code="driver_output_invalid",
        too_large_code="driver_output_too_large",
    )


def _host_node_path() -> str:
    configured = os.environ.get("DEFENSECLAW_SGW_NODE", "").strip()
    candidate = configured or shutil.which("node")
    if not candidate or "\x00" in candidate:
        return ""
    if not os.path.isabs(candidate):
        candidate = shutil.which(candidate) or ""
    if not candidate:
        return ""
    try:
        resolved = Path(candidate).expanduser().resolve(strict=True)
    except OSError:
        return ""
    if not resolved.is_file():
        return ""
    return os.fspath(resolved)


def probe_module(
    home: str,
    *,
    resources: ModuleResources | None = None,
    runner: ProcessRunner | None = None,
) -> dict[str, Any]:
    return _run_driver("probe", home=home, resources=resources, runner=runner)


def install_module(
    home: str,
    *,
    resources: ModuleResources | None = None,
    runner: ProcessRunner | None = None,
) -> dict[str, Any]:
    resolved = resources or resolve_module_resources()
    try:
        current = _run_driver("status", home=home, resources=resolved, runner=runner)
    except CredentialProtectionError as exc:
        if exc.code not in _REPAIRABLE_MODULE_STATES:
            raise
        current = {"state": exc.code, "ready": False}
    if current.get("state") == "ready" and current.get("ready") is True:
        return current
    probe = probe_module(home, resources=resolved, runner=runner)
    if probe.get("ready") is False and probe.get("state") not in {"ready_to_install", "ready"}:
        state = str(probe.get("state") or "driver_failed")
        raise CredentialProtectionError(state)
    if probe.get("state") == "ready":
        return probe
    artifact = resolved.artifact
    digest = resolved.artifact_sha256.lower()
    if artifact is None or not _artifact_is_authenticated(resolved):
        raise CredentialProtectionError("artifact_unavailable")
    return _run_driver(
        "install",
        home=home,
        extra_args=["--artifact", str(artifact), "--sha256", digest],
        resources=resolved,
        runner=runner,
        timeout=_SETUP_TIMEOUT_SECONDS,
    )


def _validated_command(
    document: dict[str, Any],
    *,
    entrypoint_name: str,
    arguments: list[str],
) -> tuple[list[str], str, dict[str, str]]:
    if set(document) != {"schema_version", "argv", "cwd", "env"} or document.get("schema_version") != 1:
        raise CredentialProtectionError("command_invalid")
    raw_argv = document.get("argv")
    cwd = document.get("cwd")
    raw_env = document.get("env")
    if not isinstance(raw_argv, list) or len(raw_argv) < 2 or len(raw_argv) > 256:
        raise CredentialProtectionError("command_invalid")
    if not all(isinstance(value, str) and value and "\x00" not in value for value in raw_argv):
        raise CredentialProtectionError("command_invalid")
    if not os.path.isabs(raw_argv[0]) or not os.path.isabs(raw_argv[1]):
        raise CredentialProtectionError("command_invalid")
    if not isinstance(cwd, str) or not os.path.isabs(cwd) or "\x00" in cwd:
        raise CredentialProtectionError("command_invalid")
    package_root = os.path.realpath(cwd)
    resolved_entrypoint = os.path.realpath(raw_argv[1])
    try:
        if os.path.commonpath([package_root, resolved_entrypoint]) != package_root:
            raise CredentialProtectionError("command_invalid")
    except ValueError as exc:
        raise CredentialProtectionError("command_invalid") from exc
    expected_entrypoint = os.path.realpath(os.path.join(package_root, "dist", entrypoint_name))
    if resolved_entrypoint != expected_entrypoint:
        raise CredentialProtectionError("command_invalid")
    if raw_argv[2:] != arguments or not isinstance(raw_env, dict):
        raise CredentialProtectionError("command_invalid")
    if raw_env != _SAFE_DRIVER_ENV:
        raise CredentialProtectionError("command_invalid")
    return list(raw_argv), cwd, dict(_SAFE_DRIVER_ENV)


def _prepare_cli_command(
    home: str,
    sgw_args: list[str],
    *,
    resources: ModuleResources | None = None,
    runner: ProcessRunner | None = None,
) -> tuple[list[str], str, dict[str, str]]:
    sgw_args = _validated_arguments(sgw_args)
    document = _run_driver(
        "command",
        home=home,
        extra_args=["--entrypoint", "cli", "--", *sgw_args],
        resources=resources,
        runner=runner,
    )
    return _validated_command(document, entrypoint_name="cli.js", arguments=sgw_args)


def _prepare_mcp_command(
    home: str,
    *,
    resources: ModuleResources | None = None,
    runner: ProcessRunner | None = None,
) -> tuple[list[str], str, dict[str, str]]:
    document = _run_driver(
        "command",
        home=home,
        extra_args=["--entrypoint", "mcp", "--"],
        resources=resources,
        runner=runner,
    )
    return _validated_command(
        document,
        entrypoint_name="mcp-server.js",
        arguments=_AGENT_MCP_ARGS,
    )


def _active_mcp_connectors(cfg: Any) -> list[str]:
    from defenseclaw import connector_paths

    try:
        raw = list(cfg.active_connectors())
    except (AttributeError, TypeError, ValueError):
        raw = []
    seen: set[str] = set()
    connectors: list[str] = []
    for value in raw:
        name = connector_paths.normalize(str(value))
        if name in seen:
            continue
        seen.add(name)
        connectors.append(name)
    return connectors


def _mcp_connector_scope(
    cfg: Any,
    *,
    include_inactive: bool,
    connectors: Iterable[str] | None = None,
) -> list[str]:
    if connectors is not None:
        from defenseclaw import connector_paths

        selected: list[str] = []
        for raw in connectors:
            name = connector_paths.normalize(str(raw))
            if name not in connector_paths.KNOWN_CONNECTORS:
                raise CredentialProtectionError("mcp_reconciliation_failed")
            if name not in selected:
                selected.append(name)
        return selected
    if not include_inactive:
        return _active_mcp_connectors(cfg)

    from defenseclaw import connector_paths

    return list(connector_paths.KNOWN_CONNECTORS)


def _mcp_result(connector: str, state: str, *, changed: bool = False) -> dict[str, Any]:
    proxy_state = "gateway_runtime_required" if connector in _PROXY_CONNECTORS else "not_in_direct_upstream_path"
    return {
        "connector": connector,
        "mcp_registration": state,
        "changed": changed,
        "proxy_prompt_tokenization": proxy_state,
    }


def _mcp_changed_result(
    connector: str,
    state: str,
    current_entry: dict[str, Any],
    previous_entry: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result = _mcp_result(connector, state, changed=True)
    result["_current_entry"] = dict(current_entry)
    if previous_entry is not None:
        result["_previous_entry"] = dict(previous_entry)
    return result


def _entry_value(entry: Any, name: str, default: Any) -> Any:
    if isinstance(entry, dict):
        return entry.get(name, default)
    return getattr(entry, name, default)


def _mcp_entry_matches(entry: Any, expected: dict[str, Any]) -> bool:
    if _entry_value(entry, "command", "") != expected["command"]:
        return False
    if list(_entry_value(entry, "args", []) or []) != expected["args"]:
        return False
    if dict(_entry_value(entry, "env", {}) or {}) != expected["env"]:
        return False
    if _entry_value(entry, "url", "") or _entry_value(entry, "cwd", ""):
        return False
    return _entry_value(entry, "disabled", False) is False


def _mcp_managed_root(home: str) -> str:
    return os.path.normpath(os.path.join(_normalized_home(home), "modules", "s-gw"))


def _path_is_beneath(path: str, root: str) -> bool:
    if not isinstance(path, str) or not path or "\x00" in path or not os.path.isabs(path):
        return False
    candidate = os.path.normcase(os.path.abspath(path))
    managed = os.path.normcase(os.path.abspath(root))
    try:
        return candidate != managed and os.path.commonpath([candidate, managed]) == managed
    except ValueError:
        return False


def _mcp_entry_targets_managed_root(entry: Any, home: str) -> bool:
    managed = _mcp_managed_root(home)
    values = [_entry_value(entry, "command", "")]
    raw_args = _entry_value(entry, "args", [])
    if isinstance(raw_args, (list, tuple)):
        values.extend(raw_args)
    return any(isinstance(value, str) and _path_is_beneath(value, managed) for value in values)


def _owned_mcp_entry_snapshot(entry: Any, home: str) -> dict[str, Any] | None:
    command = _entry_value(entry, "command", "")
    raw_args = _entry_value(entry, "args", [])
    raw_env = _entry_value(entry, "env", {})
    if (
        not isinstance(command, str)
        or not command
        or "\x00" in command
        or not os.path.isabs(command)
        or not isinstance(raw_args, (list, tuple))
        or len(raw_args) != 1
        or not isinstance(raw_args[0], str)
        or not isinstance(raw_env, dict)
        or _entry_value(entry, "url", "")
        or _entry_value(entry, "cwd", "")
        or _entry_value(entry, "disabled", False) is not False
    ):
        return None

    entrypoint = raw_args[0]
    managed = _mcp_managed_root(home)
    if not _path_is_beneath(entrypoint, managed):
        return None
    relative = os.path.relpath(os.path.abspath(entrypoint), managed)
    parts = tuple(relative.split(os.path.sep))
    if (
        len(parts) != 4
        or not _MODULE_GENERATION_RE.fullmatch(parts[0])
        or parts[1:] != ("package", "dist", "mcp-server.js")
    ):
        return None
    if (
        len(raw_env) > 128
        or raw_env.get("DEFENSECLAW_MCP_OWNER") != _MCP_OWNER_ENV["DEFENSECLAW_MCP_OWNER"]
        or any(
            not isinstance(key, str)
            or not key
            or "\x00" in key
            or "=" in key
            or len(key) > 256
            or not isinstance(value, str)
            or "\x00" in value
            or len(value) > 16 * 1024
            for key, value in raw_env.items()
        )
    ):
        return None
    return {
        "command": command,
        "args": [entrypoint],
        "env": dict(raw_env),
    }


def _mcp_binding_path(home: str) -> str:
    return os.path.join(_normalized_home(home), "credential-protection", "mcp-registrations.json")


def _validate_mcp_transaction_lock(path: str, opened: os.stat_result) -> None:
    from defenseclaw.file_permissions import reject_reparse_path, windows_acl_write_error

    reject_reparse_path(path)
    observed = os.lstat(path)
    if not stat.S_ISREG(observed.st_mode) or not os.path.samestat(observed, opened):
        raise OSError("credential-protection transaction lock changed while opening")
    if os.name == "nt":
        if windows_acl_write_error(path) is not None:
            raise OSError("credential-protection transaction lock is not private")
        return
    if observed.st_uid != os.getuid() or stat.S_IMODE(observed.st_mode) & 0o077:
        raise OSError("credential-protection transaction lock is not private")


@contextmanager
def _mcp_binding_transaction(home: str) -> Iterator[None]:
    """Serialize the owned target and journal update as one transaction."""
    from defenseclaw import file_lock
    from defenseclaw.file_permissions import (
        make_private_directory,
        set_file_mode,
        windows_acl_write_error,
    )

    journal_path = _mcp_binding_path(home)
    directory = os.path.dirname(journal_path)
    lock_path = journal_path + ".lock"
    descriptor = -1
    lock_file = None
    acquired = False

    def close_lock() -> None:
        if lock_file is not None:
            try:
                if acquired:
                    file_lock._unlock_file(lock_file)
            finally:
                lock_file.close()
            return
        if descriptor != -1:
            os.close(descriptor)

    try:
        make_private_directory(directory)
        directory_info = os.stat(directory)
        if not stat.S_ISDIR(directory_info.st_mode):
            raise OSError("credential-protection transaction directory is not a directory")
        if os.name == "nt":
            if windows_acl_write_error(directory) is not None:
                raise OSError("credential-protection transaction directory is not private")
        elif directory_info.st_uid != os.getuid() or stat.S_IMODE(directory_info.st_mode) & 0o077:
            raise OSError("credential-protection transaction directory is not private")

        flags = os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(lock_path, flags | os.O_CREAT | os.O_EXCL, 0o600)
            set_file_mode(descriptor, lock_path, 0o600, set_owner=True)
        except FileExistsError:
            descriptor = os.open(lock_path, flags)

        opened = os.fstat(descriptor)
        _validate_mcp_transaction_lock(lock_path, opened)
        lock_file = os.fdopen(descriptor, "r+")
        descriptor = -1
        file_lock._lock_file_exclusive(lock_file, timeout_seconds=None)
        acquired = True
        _validate_mcp_transaction_lock(lock_path, os.fstat(lock_file.fileno()))
    except CredentialProtectionError:
        close_lock()
        raise
    except (OSError, ValueError) as exc:
        close_lock()
        raise CredentialProtectionError("mcp_reconciliation_failed") from exc
    except BaseException:
        close_lock()
        raise

    try:
        yield
        try:
            _validate_mcp_transaction_lock(lock_path, os.fstat(lock_file.fileno()))
        except (OSError, ValueError) as exc:
            raise CredentialProtectionError("mcp_reconciliation_failed") from exc
    finally:
        close_lock()


def _binding_entry_document(entry: dict[str, Any], home: str) -> dict[str, Any]:
    snapshot = _owned_mcp_entry_snapshot(entry, home)
    if snapshot is None:
        raise CredentialProtectionError("mcp_reconciliation_failed")
    return snapshot


def _load_mcp_bindings(home: str) -> list[MCPRegistrationBinding]:
    from defenseclaw import connector_paths
    from defenseclaw.file_permissions import (
        open_regular_file_no_follow,
        reject_reparse_path,
        windows_acl_write_error,
    )

    path = _mcp_binding_path(home)
    if not os.path.lexists(path):
        try:
            reject_reparse_path(path)
        except OSError as exc:
            raise CredentialProtectionError("mcp_reconciliation_failed") from exc
        return []
    try:
        fd = open_regular_file_no_follow(path)
        with os.fdopen(fd, "rb") as source:
            metadata = os.fstat(source.fileno())
            if metadata.st_size > _MCP_BINDING_BYTES:
                raise CredentialProtectionError("mcp_reconciliation_failed")
            if os.name == "nt":
                if windows_acl_write_error(path) is not None:
                    raise CredentialProtectionError("mcp_reconciliation_failed")
            elif metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
                raise CredentialProtectionError("mcp_reconciliation_failed")
            raw = source.read(_MCP_BINDING_BYTES + 1)
    except CredentialProtectionError:
        raise
    except OSError as exc:
        raise CredentialProtectionError("mcp_reconciliation_failed") from exc
    document = _load_json_object(raw, invalid_code="mcp_reconciliation_failed")
    if set(document) != {"schema_version", "registrations"} or document.get("schema_version") != 1:
        raise CredentialProtectionError("mcp_reconciliation_failed")
    records = document.get("registrations")
    if not isinstance(records, list) or len(records) > _MCP_BINDING_LIMIT:
        raise CredentialProtectionError("mcp_reconciliation_failed")
    bindings: list[MCPRegistrationBinding] = []
    seen: set[tuple[str, str]] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != {"connector", "target", "entry"}:
            raise CredentialProtectionError("mcp_reconciliation_failed")
        connector = connector_paths.normalize(str(record.get("connector") or ""))
        target = record.get("target")
        entry = record.get("entry")
        if (
            connector not in connector_paths.KNOWN_CONNECTORS
            or connector in _MANUAL_MCP_CONNECTORS
            or not isinstance(target, str)
            or not target
            or "\x00" in target
            or len(target) > 4096
            or not os.path.isabs(target)
            or os.path.normpath(target) != target
            or not isinstance(entry, dict)
            or set(entry) != {"command", "args", "env"}
        ):
            raise CredentialProtectionError("mcp_reconciliation_failed")
        normalized_target = os.path.normcase(os.path.abspath(target))
        identity = (connector, normalized_target)
        if identity in seen:
            raise CredentialProtectionError("mcp_reconciliation_failed")
        seen.add(identity)
        bindings.append(
            MCPRegistrationBinding(
                connector=connector,
                target=os.path.abspath(target),
                entry=_binding_entry_document(entry, home),
            )
        )
    return bindings


def _save_mcp_bindings(home: str, bindings: list[MCPRegistrationBinding]) -> None:
    from defenseclaw.file_permissions import atomic_write_private_bytes, delete_file_durable

    path = _mcp_binding_path(home)
    if not bindings:
        if os.path.lexists(path):
            try:
                delete_file_durable(path)
            except OSError as exc:
                raise CredentialProtectionError("mcp_reconciliation_failed") from exc
        return
    ordered = sorted(bindings, key=lambda item: (item.connector, os.path.normcase(item.target)))
    if len(ordered) > _MCP_BINDING_LIMIT:
        raise CredentialProtectionError("mcp_reconciliation_failed")
    document = {
        "schema_version": 1,
        "registrations": [
            {
                "connector": binding.connector,
                "target": binding.target,
                "entry": _binding_entry_document(binding.entry, home),
            }
            for binding in ordered
        ],
    }
    payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(payload) > _MCP_BINDING_BYTES:
        raise CredentialProtectionError("mcp_reconciliation_failed")
    try:
        atomic_write_private_bytes(path, payload)
    except OSError as exc:
        raise CredentialProtectionError("mcp_reconciliation_failed") from exc


def _current_mcp_target(cfg: Any, connector: str) -> str | None:
    from defenseclaw import connector_paths

    try:
        workspace = cfg.connector_workspace_dir()
    except (AttributeError, TypeError, ValueError):
        workspace = ""
    claw = getattr(cfg, "claw", None)
    openclaw_config = str(getattr(claw, "config_file", "") or "")
    target = connector_paths.mcp_write_target(
        connector,
        openclaw_config=openclaw_config,
        workspace_dir=workspace,
    )
    return os.path.abspath(target) if target else None


def _current_mcp_binding(cfg: Any, connector: str, entry: dict[str, Any]) -> MCPRegistrationBinding | None:
    target = _current_mcp_target(cfg, connector)
    if target is None:
        return None
    return MCPRegistrationBinding(
        connector=connector,
        target=target,
        entry=_binding_entry_document(entry, cfg.data_dir),
    )


def _binding_key(binding: MCPRegistrationBinding) -> tuple[str, str]:
    return binding.connector, os.path.normcase(os.path.abspath(binding.target))


def _mcp_registration_entries(
    home: str,
    connectors: Iterable[str],
    *,
    resources: ModuleResources | None = None,
    runner: ProcessRunner | None = None,
) -> dict[str, dict[str, Any]]:
    selected = list(connectors)
    argv, _cwd, env = _prepare_mcp_command(home, resources=resources, runner=runner)
    return {
        connector: {
            "command": argv[0],
            "args": argv[1:],
            "env": _registered_mcp_environment(env, connector),
        }
        for connector in selected
    }


def _read_connector_mcp(cfg: Any, connector: str) -> list[Any]:
    return list(cfg.mcp_servers(connector))


def has_sgw_mcp_registrations(
    cfg: Any,
    *,
    include_inactive: bool = False,
    reader: Callable[[str], list[Any]] | None = None,
) -> bool:
    """Check connector registrations by name without resolving the module."""
    if reader is None and _load_mcp_bindings(cfg.data_dir):
        return True
    read = reader or (lambda connector: _read_connector_mcp(cfg, connector))
    found = False
    for connector in _mcp_connector_scope(cfg, include_inactive=include_inactive):
        try:
            entries = read(connector)
        except Exception as exc:  # noqa: BLE001 - expose only a bounded inspection failure.
            raise CredentialProtectionError("mcp_reconciliation_failed") from exc
        if any(_entry_value(entry, "name", "") == _MCP_SERVER_NAME for entry in entries):
            found = True
    return found


def _write_connector_mcp(cfg: Any, connector: str, entry: dict[str, Any]) -> None:
    from defenseclaw.commands.cmd_mcp import _set_mcp_via_connector

    _set_mcp_via_connector(cfg, _MCP_SERVER_NAME, entry, connector=connector)


def _remove_connector_mcp(cfg: Any, connector: str) -> None:
    from defenseclaw.commands.cmd_mcp import _unset_mcp_via_connector

    _unset_mcp_via_connector(cfg, _MCP_SERVER_NAME, connector=connector)


def _inspect_mcp_registration(
    connector: str,
    expected: dict[str, Any],
    reader: Callable[[str], list[Any]],
    *,
    home: str | None = None,
) -> str:
    try:
        entries = reader(connector)
    except Exception:  # noqa: BLE001 - connector readers must fail per connector.
        return "failed"
    found = [entry for entry in entries if _entry_value(entry, "name", "") == _MCP_SERVER_NAME]
    if not found:
        return "manual" if connector in _MANUAL_MCP_CONNECTORS else "missing"
    if len(found) != 1:
        return "conflict"
    if _mcp_entry_matches(found[0], expected):
        return "unchanged"
    if home and _mcp_entry_targets_managed_root(found[0], home):
        return "failed"
    return "conflict"


def _binding_entries(binding: MCPRegistrationBinding) -> list[Any]:
    from defenseclaw import connector_paths

    return connector_paths.mcp_servers_at_target_strict(binding.connector, binding.target)


def _binding_matches(binding: MCPRegistrationBinding, expected: dict[str, Any] | None) -> bool:
    try:
        found = [entry for entry in _binding_entries(binding) if _entry_value(entry, "name", "") == _MCP_SERVER_NAME]
    except Exception:  # noqa: BLE001 - callers expose only bounded lifecycle states.
        return False
    if expected is None:
        return not found
    return len(found) == 1 and _mcp_entry_matches(found[0], expected)


def _cas_mcp_binding(
    binding: MCPRegistrationBinding,
    *,
    expected: dict[str, Any] | None,
    replacement: dict[str, Any] | None,
) -> None:
    from defenseclaw import connector_paths

    try:
        connector_paths.compare_and_swap_mcp_server_at_target(
            binding.connector,
            binding.target,
            _MCP_SERVER_NAME,
            expected=expected,
            replacement=replacement,
        )
    except Exception as exc:  # noqa: BLE001 - preserve connector diagnostics locally.
        raise CredentialProtectionError("mcp_reconciliation_failed") from exc
    if not _binding_matches(binding, replacement):
        raise CredentialProtectionError("mcp_reconciliation_failed")


def _rollback_binding_changes(
    changes: list[tuple[MCPRegistrationBinding, dict[str, Any] | None]],
) -> bool:
    ok = True
    for binding, previous in reversed(changes):
        try:
            _cas_mcp_binding(binding, expected=binding.entry, replacement=previous)
        except CredentialProtectionError:
            ok = False
    return ok


def _restore_removed_bindings(bindings: list[MCPRegistrationBinding]) -> bool:
    ok = True
    for binding in reversed(bindings):
        try:
            _cas_mcp_binding(binding, expected=None, replacement=binding.entry)
        except CredentialProtectionError:
            ok = False
    return ok


def _reconcile_bound_mcp_connectors(
    cfg: Any,
    *,
    home: str | None,
    resources: ModuleResources | None,
    runner: ProcessRunner | None,
) -> list[dict[str, Any]]:
    connectors = _active_mcp_connectors(cfg)
    if not connectors:
        return []
    resolved_home = home or cfg.data_dir
    bindings = _load_mcp_bindings(resolved_home)
    by_key = {_binding_key(binding): binding for binding in bindings}
    expected = _mcp_registration_entries(
        resolved_home,
        connectors,
        resources=resources,
        runner=runner,
    )
    states: dict[str, str] = {}
    desired: dict[str, MCPRegistrationBinding] = {}
    previous: dict[str, dict[str, Any] | None] = {}

    for connector in connectors:
        current = _current_mcp_binding(cfg, connector, expected[connector])
        if current is None:
            states[connector] = "manual" if connector in _MANUAL_MCP_CONNECTORS else "unsupported"
            continue
        desired[connector] = current
        owned = by_key.get(_binding_key(current))
        try:
            found = [
                entry for entry in _binding_entries(current) if _entry_value(entry, "name", "") == _MCP_SERVER_NAME
            ]
        except Exception:  # noqa: BLE001 - target read failures are bounded.
            states[connector] = "failed"
            continue
        if owned is None:
            if not found:
                states[connector] = "missing"
            elif any(_mcp_entry_targets_managed_root(entry, resolved_home) for entry in found):
                states[connector] = "failed"
            else:
                states[connector] = "conflict"
            previous[connector] = None
            continue
        if not found:
            states[connector] = "missing"
            previous[connector] = None
            continue
        if len(found) != 1 or not _mcp_entry_matches(found[0], owned.entry):
            states[connector] = (
                "failed"
                if any(_mcp_entry_targets_managed_root(entry, resolved_home) for entry in found)
                else "conflict"
            )
            continue
        previous[connector] = owned.entry
        states[connector] = "unchanged" if _mcp_entry_matches(found[0], expected[connector]) else "stale"

    if any(state in {"conflict", "failed"} for state in states.values()):
        return [_mcp_result(connector, states[connector]) for connector in connectors]

    changes: list[tuple[MCPRegistrationBinding, dict[str, Any] | None]] = []
    failed = ""
    for connector in connectors:
        if states[connector] not in {"missing", "stale"}:
            continue
        binding = desired[connector]
        prior = previous.get(connector)
        try:
            _cas_mcp_binding(binding, expected=prior, replacement=binding.entry)
        except CredentialProtectionError:
            states[connector] = "failed"
            failed = connector
            break
        changes.append((binding, prior))
        states[connector] = "updated" if prior is not None else "installed"

    if failed:
        _rollback_binding_changes(changes)
        return [
            _mcp_result(connector, "failed" if connector in desired else states[connector]) for connector in connectors
        ]

    updated_bindings = dict(by_key)
    for connector in connectors:
        if states[connector] in {"unchanged", "installed", "updated"}:
            binding = desired[connector]
            updated_bindings[_binding_key(binding)] = binding
    try:
        _save_mcp_bindings(resolved_home, list(updated_bindings.values()))
    except CredentialProtectionError:
        _rollback_binding_changes(changes)
        raise

    changed_by_connector = {binding.connector: prior for binding, prior in changes}
    results: list[dict[str, Any]] = []
    for connector in connectors:
        if connector not in changed_by_connector:
            results.append(_mcp_result(connector, states[connector]))
            continue
        binding = desired[connector]
        result = _mcp_changed_result(
            connector,
            states[connector],
            binding.entry,
            changed_by_connector[connector],
        )
        result["_binding_target"] = binding.target
        result["_binding_home"] = resolved_home
        results.append(result)
    return results


def mcp_connector_status(
    cfg: Any,
    *,
    home: str | None = None,
    resources: ModuleResources | None = None,
    runner: ProcessRunner | None = None,
    include_inactive: bool = False,
    reader: Callable[[str], list[Any]] | None = None,
) -> list[dict[str, Any]]:
    """Inspect exact s-gw MCP registrations without exposing command paths."""
    connectors = _mcp_connector_scope(cfg, include_inactive=include_inactive)
    if not connectors:
        return []
    resolved_home = home or cfg.data_dir
    try:
        expected = _mcp_registration_entries(
            resolved_home,
            connectors,
            resources=resources,
            runner=runner,
        )
    except CredentialProtectionError:
        return [_mcp_result(connector, "unavailable") for connector in connectors]
    read = reader or (lambda connector: _read_connector_mcp(cfg, connector))
    return [
        _mcp_result(
            connector,
            _inspect_mcp_registration(connector, expected[connector], read, home=resolved_home),
        )
        for connector in connectors
    ]


def reconcile_mcp_connectors(
    cfg: Any,
    *,
    home: str | None = None,
    resources: ModuleResources | None = None,
    runner: ProcessRunner | None = None,
    reader: Callable[[str], list[Any]] | None = None,
    writer: Callable[[str, dict[str, Any]], None] | None = None,
    remover: Callable[[str], None] | None = None,
) -> list[dict[str, Any]]:
    """Register the receipt-verified s-gw MCP command for active connectors."""
    if reader is None and writer is None and remover is None:
        if not _active_mcp_connectors(cfg):
            return []
        resolved_home = home or cfg.data_dir
        with _mcp_binding_transaction(resolved_home):
            return _reconcile_bound_mcp_connectors(
                cfg,
                home=resolved_home,
                resources=resources,
                runner=runner,
            )

    from defenseclaw import connector_paths

    connectors = _active_mcp_connectors(cfg)
    if not connectors:
        return []
    resolved_home = home or cfg.data_dir
    expected = _mcp_registration_entries(
        resolved_home,
        connectors,
        resources=resources,
        runner=runner,
    )
    read = reader or (lambda connector: _read_connector_mcp(cfg, connector))
    write = writer or (lambda connector, entry: _write_connector_mcp(cfg, connector, entry))
    remove = remover or (lambda connector: _remove_connector_mcp(cfg, connector))
    states = {
        connector: _inspect_mcp_registration(
            connector,
            expected[connector],
            read,
            home=resolved_home,
        )
        for connector in connectors
    }

    # Refuse known conflicts before touching any connector. A setup run should
    # not leave the fleet half-configured merely because the conflict happened
    # to sort after a writable connector.
    if any(state in {"conflict", "failed"} for state in states.values()):
        return [_mcp_result(connector, states[connector]) for connector in connectors]

    previous_entries: dict[str, dict[str, Any]] = {}
    changed: list[tuple[str, dict[str, Any] | None]] = []
    failed = ""
    for connector in connectors:
        original_state = states[connector]
        if original_state not in {"missing", "stale"}:
            continue
        if connector not in connector_paths.KNOWN_CONNECTORS:
            states[connector] = "unsupported"
            continue
        try:
            write(connector, expected[connector])
        except connector_paths.MCPWriteUnsupportedError:
            refused = "manual" if connector == "windsurf" else "conflict"
            states[connector] = refused
            if refused == "conflict":
                failed = connector
                break
            continue
        except Exception:  # noqa: BLE001 - never expose connector or child diagnostics.
            states[connector] = "failed"
            failed = connector
            break

        verified = _inspect_mcp_registration(connector, expected[connector], read)
        if verified == "unchanged":
            states[connector] = "updated" if original_state == "stale" else "installed"
            changed.append((connector, previous_entries.get(connector)))
        else:
            states[connector] = "failed"
            failed = connector
            break

    if failed:
        # The failing writer may have published the entry before reporting an
        # ownership-journal error, so include it only when the exact admission
        # command is now present. Never remove a conflicting operator entry.
        changed_connectors = {connector for connector, _previous in changed}
        if (
            failed not in changed_connectors
            and _inspect_mcp_registration(failed, expected[failed], read) == "unchanged"
        ):
            changed.append((failed, previous_entries.get(failed)))
        for connector, previous in reversed(changed):
            connector_entry = expected[connector]
            if _inspect_mcp_registration(connector, connector_entry, read) != "unchanged":
                states[connector] = "failed"
                continue
            try:
                if previous is None:
                    remove(connector)
                else:
                    write(connector, previous)
            except Exception:  # noqa: BLE001 - retain a safe failure result.
                states[connector] = "failed"
                continue
            if previous is None:
                restored = _inspect_mcp_registration(connector, connector_entry, read) in {"missing", "manual"}
            else:
                restored = _inspect_mcp_registration(connector, previous, read) == "unchanged"
            if not restored:
                states[connector] = "failed"
                continue
            states[connector] = "failed"
        return [_mcp_result(connector, states[connector]) for connector in connectors]

    changed_by_connector = {connector: previous for connector, previous in changed}
    results: list[dict[str, Any]] = []
    for connector in connectors:
        if connector not in changed_by_connector:
            results.append(_mcp_result(connector, states[connector]))
            continue
        results.append(
            _mcp_changed_result(
                connector,
                states[connector],
                expected[connector],
                changed_by_connector[connector],
            )
        )
    return results


def mcp_reconciliation_failed(results: list[dict[str, Any]]) -> bool:
    return any(item.get("mcp_registration") in {"conflict", "failed", "stale", "unavailable"} for item in results)


def _rollback_bound_reconciliation(results: list[dict[str, Any]]) -> bool:
    changed = [item for item in results if item.get("changed") is True]
    if not changed:
        return True
    homes = {str(item.get("_binding_home") or "") for item in changed}
    if len(homes) != 1 or not next(iter(homes)):
        return False
    home = next(iter(homes))
    try:
        bindings = _load_mcp_bindings(home)
    except CredentialProtectionError:
        return False
    by_key = {_binding_key(binding): binding for binding in bindings}
    performed: list[tuple[MCPRegistrationBinding, dict[str, Any] | None]] = []
    for item in reversed(changed):
        connector = str(item.get("connector") or "")
        target = item.get("_binding_target")
        current = item.get("_current_entry")
        previous = item.get("_previous_entry")
        if not isinstance(target, str) or not isinstance(current, dict):
            break
        binding = MCPRegistrationBinding(connector, target, current)
        prior = previous if isinstance(previous, dict) else None
        try:
            _cas_mcp_binding(binding, expected=current, replacement=prior)
        except CredentialProtectionError:
            break
        performed.append((binding, prior))
    else:
        for binding, prior in performed:
            key = _binding_key(binding)
            if prior is None:
                by_key.pop(key, None)
            else:
                by_key[key] = MCPRegistrationBinding(binding.connector, binding.target, prior)
        try:
            _save_mcp_bindings(home, list(by_key.values()))
            return True
        except CredentialProtectionError:
            pass

    for binding, prior in reversed(performed):
        try:
            _cas_mcp_binding(binding, expected=prior, replacement=binding.entry)
        except CredentialProtectionError:
            pass
    return False


def rollback_mcp_reconciliation(
    cfg: Any,
    results: list[dict[str, Any]],
    *,
    home: str | None = None,
    resources: ModuleResources | None = None,
    runner: ProcessRunner | None = None,
    reader: Callable[[str], list[Any]] | None = None,
    writer: Callable[[str, dict[str, Any]], None] | None = None,
    remover: Callable[[str], None] | None = None,
) -> bool:
    """Remove only exact s-gw entries created by one reconciliation run."""
    if any(item.get("_binding_target") for item in results if item.get("changed") is True):
        homes = {str(item.get("_binding_home") or "") for item in results if item.get("changed") is True}
        if len(homes) != 1 or not next(iter(homes)):
            return False
        resolved_home = next(iter(homes))
        try:
            with _mcp_binding_transaction(resolved_home):
                return _rollback_bound_reconciliation(results)
        except CredentialProtectionError:
            return False
    changed = [item for item in results if item.get("changed") is True]
    if not changed:
        return True
    read = reader or (lambda connector: _read_connector_mcp(cfg, connector))
    remove = remover or (lambda connector: _remove_connector_mcp(cfg, connector))
    write = writer or (lambda connector, entry: _write_connector_mcp(cfg, connector, entry))
    ok = True
    for item in reversed(changed):
        connector = str(item.get("connector") or "")
        current = item.get("_current_entry")
        previous = item.get("_previous_entry")
        if not isinstance(current, dict) or _inspect_mcp_registration(connector, current, read) != "unchanged":
            ok = False
            continue
        try:
            if isinstance(previous, dict):
                write(connector, previous)
            else:
                remove(connector)
        except Exception:  # noqa: BLE001 - caller gets a bounded rollback result.
            ok = False
            continue
        if isinstance(previous, dict):
            restored = _inspect_mcp_registration(connector, previous, read) == "unchanged"
        else:
            restored = _inspect_mcp_registration(connector, current, read) in {"missing", "manual"}
        if not restored:
            ok = False
    return ok


def _bound_mcp_result(
    binding: MCPRegistrationBinding,
    state: str,
    *,
    changed: bool = False,
    home: str = "",
) -> dict[str, Any]:
    result = _mcp_result(binding.connector, state, changed=changed)
    if changed:
        result["_previous_entry"] = binding.entry
        result["_binding_target"] = binding.target
        result["_binding_home"] = home
    return result


def _remove_bound_mcp_connectors(
    cfg: Any,
    *,
    home: str | None,
    include_inactive: bool,
    connectors: Iterable[str] | None,
) -> list[dict[str, Any]]:
    resolved_home = home or cfg.data_dir
    connector_scope = _mcp_connector_scope(
        cfg,
        include_inactive=include_inactive,
        connectors=connectors,
    )
    if not connector_scope:
        return []
    bindings = _load_mcp_bindings(resolved_home)
    binding_by_key = {_binding_key(binding): binding for binding in bindings if binding.connector in connector_scope}
    endpoint_keys = set(binding_by_key)
    endpoints: list[tuple[str, str, MCPRegistrationBinding | None]] = [
        (binding.connector, binding.target, binding) for binding in binding_by_key.values()
    ]
    for connector in connector_scope:
        target = _current_mcp_target(cfg, connector)
        if target is None:
            continue
        key = (connector, os.path.normcase(os.path.abspath(target)))
        if key in endpoint_keys:
            continue
        endpoint_keys.add(key)
        endpoints.append((connector, target, None))

    states: list[str] = []
    for connector, target, owned in endpoints:
        probe = owned or MCPRegistrationBinding(connector, target, {})
        try:
            found = [entry for entry in _binding_entries(probe) if _entry_value(entry, "name", "") == _MCP_SERVER_NAME]
        except Exception:  # noqa: BLE001 - target diagnostics stay private.
            states.append("failed")
            continue
        if owned is not None and len(found) == 1 and _mcp_entry_matches(found[0], owned.entry):
            states.append("owned")
            continue
        if not found:
            states.append("missing")
            continue
        if any(_mcp_entry_targets_managed_root(entry, resolved_home) for entry in found):
            states.append("failed")
            continue
        states.append("manual" if connector in _MANUAL_MCP_CONNECTORS else "conflict")

    if any(state == "failed" for state in states):
        results = [
            _bound_mcp_result(
                owned or MCPRegistrationBinding(connector, target, {}),
                state,
            )
            for (connector, target, owned), state in zip(endpoints, states, strict=True)
        ]
        present = {connector for connector, _target, _owned in endpoints}
        results.extend(
            _mcp_result(connector, "manual")
            for connector in connector_scope
            if connector in _MANUAL_MCP_CONNECTORS and connector not in present
        )
        return results

    removed: list[MCPRegistrationBinding] = []
    for index, (_connector, _target, owned) in enumerate(endpoints):
        if states[index] != "owned" or owned is None:
            continue
        try:
            _cas_mcp_binding(owned, expected=owned.entry, replacement=None)
        except CredentialProtectionError:
            states[index] = "failed"
            _restore_removed_bindings(removed)
            return [
                _bound_mcp_result(
                    endpoint_owned or MCPRegistrationBinding(connector, target, {}),
                    "failed" if state in {"owned", "removed"} else state,
                )
                for (connector, target, endpoint_owned), state in zip(endpoints, states, strict=True)
            ]
        removed.append(owned)
        states[index] = "removed"

    retained = {_binding_key(binding): binding for binding in bindings if binding.connector not in connector_scope}
    try:
        _save_mcp_bindings(resolved_home, list(retained.values()))
    except CredentialProtectionError:
        _restore_removed_bindings(removed)
        raise

    results = [
        _bound_mcp_result(
            owned or MCPRegistrationBinding(connector, target, {}),
            state,
            changed=state == "removed",
            home=resolved_home,
        )
        for (connector, target, owned), state in zip(endpoints, states, strict=True)
    ]
    present = {connector for connector, _target, _owned in endpoints}
    results.extend(
        _mcp_result(connector, "manual")
        for connector in connector_scope
        if connector in _MANUAL_MCP_CONNECTORS and connector not in present
    )
    return results


def remove_managed_mcp_connectors(
    cfg: Any,
    *,
    home: str | None = None,
    resources: ModuleResources | None = None,
    runner: ProcessRunner | None = None,
    include_inactive: bool = False,
    connectors: Iterable[str] | None = None,
    reader: Callable[[str], list[Any]] | None = None,
    writer: Callable[[str, dict[str, Any]], None] | None = None,
    remover: Callable[[str], None] | None = None,
) -> list[dict[str, Any]]:
    """Remove exact DefenseClaw s-gw registrations without touching conflicts."""
    if reader is None and writer is None and remover is None:
        resolved_home = home or cfg.data_dir
        with _mcp_binding_transaction(resolved_home):
            return _remove_bound_mcp_connectors(
                cfg,
                home=resolved_home,
                include_inactive=include_inactive,
                connectors=connectors,
            )

    connector_scope = _mcp_connector_scope(
        cfg,
        include_inactive=include_inactive,
        connectors=connectors,
    )
    if not connector_scope:
        return []
    resolved_home = home or cfg.data_dir
    read = reader or (lambda connector: _read_connector_mcp(cfg, connector))
    write = writer or (lambda connector, entry: _write_connector_mcp(cfg, connector, entry))
    remove = remover or (lambda connector: _remove_connector_mcp(cfg, connector))
    states: dict[str, str] = {}
    snapshots: dict[str, dict[str, Any]] = {}
    candidates: list[str] = []
    for connector in connector_scope:
        try:
            entries = read(connector)
        except Exception:  # noqa: BLE001 - keep connector diagnostics private.
            states[connector] = "failed"
            continue
        found = [entry for entry in entries if _entry_value(entry, "name", "") == _MCP_SERVER_NAME]
        if connector in _MANUAL_MCP_CONNECTORS:
            states[connector] = "manual"
            continue
        if not found:
            states[connector] = "missing"
            continue
        if len(found) != 1:
            states[connector] = "conflict"
            continue
        states[connector] = "present"
        candidates.append(connector)
    if any(state == "failed" for state in states.values()):
        return [_mcp_result(connector, states[connector]) for connector in connector_scope]
    if not candidates:
        return [_mcp_result(connector, states[connector]) for connector in connector_scope]

    expected = _mcp_registration_entries(
        resolved_home,
        candidates,
        resources=resources,
        runner=runner,
    )
    for connector in candidates:
        connector_entry = expected[connector]
        state = _inspect_mcp_registration(connector, connector_entry, read)
        states[connector] = "owned" if state == "unchanged" else state
        if state == "unchanged":
            snapshots[connector] = connector_entry

    removed: list[str] = []
    failed = ""
    for connector in connector_scope:
        if states[connector] != "owned":
            continue
        expected = snapshots[connector]
        try:
            remove(connector)
        except Exception:  # noqa: BLE001 - keep connector diagnostics private.
            states[connector] = "failed"
            failed = connector
            break
        if _inspect_mcp_registration(connector, expected, read) in {"missing", "manual"}:
            states[connector] = "removed"
            removed.append(connector)
            continue
        states[connector] = "failed"
        failed = connector
        break

    if failed:
        failed_snapshot = snapshots[failed]
        if failed not in removed and _inspect_mcp_registration(failed, failed_snapshot, read) in {
            "missing",
            "manual",
        }:
            removed.append(failed)
        for connector in reversed(removed):
            expected = snapshots[connector]
            if _inspect_mcp_registration(connector, expected, read) not in {"missing", "manual"}:
                states[connector] = "failed"
                continue
            try:
                write(connector, expected)
            except Exception:  # noqa: BLE001 - return a safe transactional failure.
                states[connector] = "failed"
                continue
            if _inspect_mcp_registration(connector, expected, read) != "unchanged":
                states[connector] = "failed"
                continue
            states[connector] = "failed"
        return [_mcp_result(connector, states[connector]) for connector in connector_scope]

    results: list[dict[str, Any]] = []
    for connector in connector_scope:
        result = _mcp_result(
            connector,
            states[connector],
            changed=states[connector] == "removed",
        )
        if states[connector] == "removed":
            result["_previous_entry"] = snapshots[connector]
        results.append(result)
    return results


def mcp_removal_failed(results: list[dict[str, Any]]) -> bool:
    return any(item.get("mcp_registration") in {"failed", "unavailable"} for item in results)


def _rollback_bound_removal(results: list[dict[str, Any]]) -> bool:
    removed = [item for item in results if item.get("changed") is True]
    if not removed:
        return True
    homes = {str(item.get("_binding_home") or "") for item in removed}
    if len(homes) != 1 or not next(iter(homes)):
        return False
    home = next(iter(homes))
    try:
        bindings = _load_mcp_bindings(home)
    except CredentialProtectionError:
        return False
    by_key = {_binding_key(binding): binding for binding in bindings}
    restored: list[MCPRegistrationBinding] = []
    for item in reversed(removed):
        connector = str(item.get("connector") or "")
        target = item.get("_binding_target")
        previous = item.get("_previous_entry")
        if not isinstance(target, str) or not isinstance(previous, dict):
            break
        binding = MCPRegistrationBinding(connector, target, previous)
        try:
            _cas_mcp_binding(binding, expected=None, replacement=previous)
        except CredentialProtectionError:
            break
        restored.append(binding)
    else:
        for binding in restored:
            by_key[_binding_key(binding)] = binding
        try:
            _save_mcp_bindings(home, list(by_key.values()))
            return True
        except CredentialProtectionError:
            pass

    for binding in reversed(restored):
        try:
            _cas_mcp_binding(binding, expected=binding.entry, replacement=None)
        except CredentialProtectionError:
            pass
    return False


def rollback_mcp_removal(
    cfg: Any,
    results: list[dict[str, Any]],
    *,
    home: str | None = None,
    resources: ModuleResources | None = None,
    runner: ProcessRunner | None = None,
    reader: Callable[[str], list[Any]] | None = None,
    writer: Callable[[str, dict[str, Any]], None] | None = None,
) -> bool:
    """Restore exact entries removed before a DefenseClaw config-save failure."""
    if any(item.get("_binding_target") for item in results if item.get("changed") is True):
        homes = {str(item.get("_binding_home") or "") for item in results if item.get("changed") is True}
        if len(homes) != 1 or not next(iter(homes)):
            return False
        resolved_home = next(iter(homes))
        try:
            with _mcp_binding_transaction(resolved_home):
                return _rollback_bound_removal(results)
        except CredentialProtectionError:
            return False
    removed = [item for item in results if item.get("changed") is True]
    if not removed:
        return True
    read = reader or (lambda connector: _read_connector_mcp(cfg, connector))
    write = writer or (lambda connector, entry: _write_connector_mcp(cfg, connector, entry))
    ok = True
    for item in reversed(removed):
        connector = str(item.get("connector") or "")
        expected = item.get("_previous_entry")
        if not isinstance(expected, dict):
            ok = False
            continue
        if _inspect_mcp_registration(connector, expected, read) not in {"missing", "manual"}:
            ok = False
            continue
        try:
            write(connector, expected)
        except Exception:  # noqa: BLE001 - caller receives one bounded rollback result.
            ok = False
            continue
        if _inspect_mcp_registration(connector, expected, read) != "unchanged":
            ok = False
    return ok


def _reconcile_mcp_connector_roster_locked(
    cfg: Any,
    *,
    removed_connectors: Iterable[str] = (),
    home: str | None = None,
    resources: ModuleResources | None = None,
    runner: ProcessRunner | None = None,
) -> list[dict[str, Any]]:
    """Synchronize owned s-gw registrations with the configured connector roster.

    Disabled credential protection is a no-op. When enabled, exact journal
    bindings for removed connectors or superseded workspace targets are
    removed first, then every active connector is reconciled. A later active
    connector failure restores the removals so the MCP roster changes as one
    transaction.
    """
    if not bool(getattr(getattr(cfg, "credential_protection", None), "enabled", False)):
        return []

    resolved_home = home or cfg.data_dir
    active = _active_mcp_connectors(cfg)
    active_targets = {
        connector: (
            os.path.normcase(os.path.abspath(target))
            if (target := _current_mcp_target(cfg, connector)) is not None
            else None
        )
        for connector in active
    }
    cleanup: list[str] = []

    def add_cleanup(raw: str) -> None:
        from defenseclaw import connector_paths

        connector = connector_paths.normalize(str(raw))
        if connector not in connector_paths.KNOWN_CONNECTORS:
            raise CredentialProtectionError("mcp_reconciliation_failed")
        if connector not in cleanup:
            cleanup.append(connector)

    for connector in removed_connectors:
        add_cleanup(connector)
    for binding in _load_mcp_bindings(resolved_home):
        current = active_targets.get(binding.connector)
        if current is None or os.path.normcase(os.path.abspath(binding.target)) != current:
            add_cleanup(binding.connector)

    cleanup_results: list[dict[str, Any]] = []
    if cleanup:
        cleanup_results = _remove_bound_mcp_connectors(
            cfg,
            home=resolved_home,
            include_inactive=False,
            connectors=cleanup,
        )
        if mcp_removal_failed(cleanup_results):
            raise CredentialProtectionError("mcp_reconciliation_failed")

    try:
        active_results = _reconcile_bound_mcp_connectors(
            cfg,
            home=resolved_home,
            resources=resources,
            runner=runner,
        )
    except CredentialProtectionError:
        if cleanup_results:
            _rollback_bound_removal(cleanup_results)
        raise

    if mcp_reconciliation_failed(active_results):
        if cleanup_results and not _rollback_bound_removal(cleanup_results):
            raise CredentialProtectionError("mcp_reconciliation_failed")
        raise CredentialProtectionError("mcp_reconciliation_failed")
    return cleanup_results + active_results


def reconcile_mcp_connector_roster(
    cfg: Any,
    *,
    removed_connectors: Iterable[str] = (),
    home: str | None = None,
    resources: ModuleResources | None = None,
    runner: ProcessRunner | None = None,
) -> list[dict[str, Any]]:
    """Synchronize owned s-gw registrations with the configured connector roster."""
    if not bool(getattr(getattr(cfg, "credential_protection", None), "enabled", False)):
        return []
    resolved_home = home or cfg.data_dir
    with _mcp_binding_transaction(resolved_home):
        return _reconcile_mcp_connector_roster_locked(
            cfg,
            removed_connectors=removed_connectors,
            home=resolved_home,
            resources=resources,
            runner=runner,
        )


def _run_sgw_json(
    home: str,
    sgw_args: list[str],
    *,
    resources: ModuleResources | None = None,
    runner: ProcessRunner | None = None,
    timeout: int = _DRIVER_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    argv, cwd, additions = _prepare_cli_command(home, sgw_args, resources=resources, runner=runner)
    child_env = _sgw_environment(additions)
    try:
        if runner is None:
            completed = _run_bounded_capture(
                argv,
                cwd=cwd,
                env=child_env,
                timeout=timeout,
            )
        else:
            completed = runner(
                argv,
                cwd=cwd,
                env=child_env,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                shell=False,
            )
    except subprocess.TimeoutExpired as exc:
        raise CredentialProtectionError("sgw_timeout") from exc
    except _OutputTooLargeError as exc:
        raise CredentialProtectionError("sgw_output_too_large") from exc
    except OSError as exc:
        raise CredentialProtectionError("sgw_failed") from exc
    if (
        len((completed.stdout or "").encode("utf-8", errors="replace")) > _MAX_JSON_BYTES
        or len((completed.stderr or "").encode("utf-8", errors="replace")) > _MAX_JSON_BYTES
    ):
        raise CredentialProtectionError("sgw_output_too_large")
    if completed.returncode != 0:
        raise CredentialProtectionError("sgw_failed")
    return _decode_json(
        completed.stdout or "",
        invalid_code="sgw_output_invalid",
        too_large_code="sgw_output_too_large",
    )


def _module_metadata(document: dict[str, Any]) -> dict[str, Any]:
    module = document.get("module") if isinstance(document.get("module"), dict) else {}
    node = document.get("node") if isinstance(document.get("node"), dict) else {}
    components = document.get("components") if isinstance(document.get("components"), dict) else {}
    approval_ui = components.get("approval_ui") if isinstance(components.get("approval_ui"), dict) else {}
    state = str(document.get("state") or "driver_failed")
    if state not in {
        "artifact_unavailable",
        "incompatible",
        "module_invalid",
        "node_missing",
        "node_unsupported",
        "not_installed",
        "ready",
        "ready_to_install",
        "receipt_invalid",
        "runner_unavailable",
    }:
        state = "module_invalid"
    version = str(module.get("version") or "")
    node_version = str(node.get("version") or "")
    minimum_node_version = str(node.get("minimum") or "20.0.0")
    if version and not _VERSION_RE.fullmatch(version):
        version = ""
        state = "module_invalid"
    if node_version and not _VERSION_RE.fullmatch(node_version):
        node_version = ""
        state = "module_invalid"
    if not _VERSION_RE.fullmatch(minimum_node_version):
        minimum_node_version = "20.0.0"
        state = "module_invalid"
    ready = bool(document.get("ready")) and state == "ready"
    ui_available = bool(
        ready
        and module.get("installed") is True
        and approval_ui.get("required") is True
        and approval_ui.get("available") is True
        and approval_ui.get("redistribution_status") == "approved"
    )
    return {
        "state": state,
        "ready": ready,
        "installed": bool(module.get("installed")),
        "version": version,
        "node_version": node_version,
        "minimum_node_version": minimum_node_version,
        "broker_state": "unavailable",
        "ui_available": ui_available,
        "error_code": "" if ready else state,
    }


def safe_status(
    home: str,
    *,
    enabled: bool,
    resources: ModuleResources | None = None,
    runner: ProcessRunner | None = None,
) -> dict[str, Any]:
    """Return allowlisted metadata only; child paths and output stay private."""
    if not enabled:
        return {
            "enabled": False,
            "state": "disabled",
            "ready": False,
            "installed": False,
            "version": "",
            "node_version": "",
            "minimum_node_version": "20.0.0",
            "broker_state": "unavailable",
            "ui_available": False,
            "error_code": "",
        }
    try:
        module_status = _run_driver("status", home=home, resources=resources, runner=runner)
        if module_status.get("state") == "not_installed":
            probe = _run_driver("probe", home=home, resources=resources, runner=runner)
            if probe.get("state") not in {"ready", "ready_to_install"}:
                module_status = probe
    except CredentialProtectionError as exc:
        return {
            "enabled": enabled,
            "state": "unavailable",
            "ready": False,
            "installed": False,
            "version": "",
            "node_version": "",
            "minimum_node_version": "20.0.0",
            "broker_state": "unavailable",
            "ui_available": False,
            "error_code": exc.code,
        }

    result = _module_metadata(module_status)
    if not result["ready"]:
        return {"enabled": enabled, **result}

    try:
        broker = _run_sgw_json(home, ["status"], resources=resources, runner=runner)
        unlock = broker.get("unlock") if isinstance(broker.get("unlock"), dict) else {}
        active_source = str(unlock.get("activeSource") or "none")
        broker_ready = bool(broker.get("ready"))
        if broker_ready:
            broker_state = "ready"
        elif active_source == "none":
            broker_state = "locked"
        else:
            broker_state = "unavailable"
        result.update(
            {
                "ready": broker_ready,
                "broker_state": broker_state,
                "error_code": "" if broker_ready else broker_state,
            }
        )
        return {"enabled": enabled, **result}
    except CredentialProtectionError as exc:
        result.update(
            {
                "ready": False,
                "broker_state": "unavailable",
                "ui_available": False,
                "error_code": exc.code,
            }
        )
        return {"enabled": enabled, **result}


def setup_broker(
    home: str,
    *,
    resources: ModuleResources | None = None,
    runner: ProcessRunner | None = None,
) -> dict[str, Any]:
    install_module(home, resources=resources, runner=runner)
    setup_result = _run_sgw_json(
        home,
        ["setup", "--no-open-console", "--no-service", "--no-menubar", "--no-agents"],
        resources=resources,
        runner=runner,
        timeout=_SETUP_TIMEOUT_SECONDS,
    )
    if setup_result.get("ok") is not True:
        raise CredentialProtectionError("sgw_failed")
    status = safe_status(home, enabled=True, resources=resources, runner=runner)
    if not status["ready"]:
        raise CredentialProtectionError(status.get("error_code") or "sgw_failed")
    return status


def _credential_gateway_running(home: str) -> bool:
    from defenseclaw.process_liveness import pid_alive, process_is_gateway, read_pid_file

    pid = read_pid_file(os.path.join(home, "gateway.pid"))
    return pid is not None and pid_alive(pid) and process_is_gateway(pid)


def _credential_gateway_lifecycle(action: str) -> bool:
    if action not in {"stop", "restart"}:
        return False
    try:
        executable = _privileged_gateway_binary()
    except CredentialProtectionError:
        return False
    try:
        result = subprocess.run(
            [executable, action],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def setup_broker_for_runtime(
    home: str,
    *,
    already_enabled: bool,
    platform_name: str | None = None,
    gateway_was_running: bool | None = None,
    stop_gateway: GatewayLifecycleAction | None = None,
    restart_gateway: GatewayLifecycleAction | None = None,
    broker_setup: Callable[[], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Repair s-gw without replacing a runner held by a live Windows gateway."""
    platform_name = platform_name or sys.platform
    if gateway_was_running is None:
        gateway_was_running = platform_name == "win32" and _credential_gateway_running(home)
    needs_quiesce = platform_name == "win32" and already_enabled and gateway_was_running
    setup_action = broker_setup or (lambda: setup_broker(home))
    if not needs_quiesce:
        return setup_action()

    stop = stop_gateway or (lambda: _credential_gateway_lifecycle("stop"))
    restart = restart_gateway or (lambda: _credential_gateway_lifecycle("restart"))
    if not stop():
        restart()
        raise CredentialProtectionError("gateway_lifecycle_failed")

    try:
        result = setup_action()
    finally:
        if not restart():
            raise CredentialProtectionError("gateway_lifecycle_failed")
    if result is None:
        raise CredentialProtectionError("sgw_failed")
    return result


def open_broker(
    home: str,
    *,
    gateway_binary: str | None = None,
    runner: ProcessRunner | None = None,
) -> None:
    data_dir = _normalized_home(home)
    gateway = _privileged_gateway_binary(gateway_binary)
    argv = [gateway, "sgw-console-open", "--data-dir", data_dir]
    child_env = _copy_environment(_SGW_ENV_KEYS)
    child_env.update(_trusted_execution_environment())
    process_runner = runner or _run_bounded_capture
    try:
        if runner is None:
            completed = process_runner(
                argv,
                cwd=None,
                env=child_env,
                timeout=_DRIVER_TIMEOUT_SECONDS,
            )
        else:
            completed = process_runner(
                argv,
                cwd=None,
                env=child_env,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=_DRIVER_TIMEOUT_SECONDS,
                shell=False,
            )
    except subprocess.TimeoutExpired as exc:
        raise CredentialProtectionError("sgw_timeout") from exc
    except _OutputTooLargeError as exc:
        raise CredentialProtectionError("sgw_output_too_large") from exc
    except OSError as exc:
        raise CredentialProtectionError("sgw_failed") from exc

    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    if (
        len(stdout.encode("utf-8", errors="replace")) > _CONSOLE_OUTPUT_BYTES
        or len(stderr.encode("utf-8", errors="replace")) > _CONSOLE_ERROR_BYTES
    ):
        raise CredentialProtectionError("sgw_output_too_large")
    if completed.returncode != 0:
        raise CredentialProtectionError("sgw_failed")
    result = _load_json_object(stdout, invalid_code="sgw_output_invalid")
    if set(result) != {"schema_version", "status"} or result.get("schema_version") != 1:
        raise CredentialProtectionError("sgw_output_invalid")
    if result.get("status") not in {"opened", "already_open"}:
        raise CredentialProtectionError("sgw_output_invalid")


def _privileged_gateway_binary(candidate: str | None = None) -> str:
    if candidate is None:
        candidate = packaged_windows_gateway_path() if os.name == "nt" else canonical_install_path()
    if not candidate or "\x00" in candidate or not os.path.isabs(candidate):
        raise CredentialProtectionError("driver_missing")

    requested = Path(os.path.abspath(candidate))
    current = Path(requested.anchor)
    try:
        for index, part in enumerate(requested.parts[1:]):
            if not part or part in {".", ".."}:
                raise CredentialProtectionError("driver_missing")
            current = current / part
            metadata = current.lstat()
            reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            if current.is_symlink() or getattr(metadata, "st_file_attributes", 0) & reparse_flag:
                raise CredentialProtectionError("driver_missing")
            is_last = index == len(requested.parts[1:]) - 1
            if (is_last and not stat.S_ISREG(metadata.st_mode)) or (not is_last and not stat.S_ISDIR(metadata.st_mode)):
                raise CredentialProtectionError("driver_missing")
            if os.name != "nt":
                if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                    raise CredentialProtectionError("driver_missing")
                if metadata.st_uid not in {0, os.getuid()}:
                    raise CredentialProtectionError("driver_missing")
        resolved = requested.resolve(strict=True)
    except OSError as exc:
        raise CredentialProtectionError("driver_missing") from exc

    if os.path.normcase(os.fspath(resolved)) != os.path.normcase(os.fspath(requested)):
        raise CredentialProtectionError("driver_missing")
    if os.name != "nt" and not os.access(resolved, os.X_OK):
        raise CredentialProtectionError("driver_missing")
    return os.fspath(resolved)


def launch_agent(
    home: str,
    connector: str,
    agent_args: list[str],
    *,
    command: str = "",
    inherit_environment: bool = False,
    resources: ModuleResources | None = None,
    runner: ProcessRunner | None = None,
) -> int:
    if command and ("\x00" in command or not os.path.isabs(command)):
        raise CredentialProtectionError("command_invalid")
    sgw_args = ["guard", "run", connector]
    if command:
        sgw_args.extend(["--command", command])
    sgw_args.extend(["--", *agent_args])
    argv, cwd, additions = _prepare_cli_command(home, sgw_args, resources=resources, runner=runner)
    additions["SGW_AGENT_NAME"] = _connector_agent_name(connector)
    child_env = (
        _inherited_guard_environment(additions)
        if inherit_environment
        else _sgw_environment(additions, agent_paths=True)
    )
    process_runner = runner or subprocess.run
    try:
        completed = process_runner(
            argv,
            cwd=cwd,
            env=child_env,
            check=False,
            shell=False,
        )
    except OSError as exc:
        raise CredentialProtectionError("sgw_failed") from exc
    return int(completed.returncode)


def remediation(status: dict[str, Any]) -> str:
    code = str(status.get("error_code") or status.get("state") or "")
    if code in {"node_missing", "node_unsupported"}:
        return "Install Node.js 20 or newer, then run 'defenseclaw setup credential-protection --yes'."
    if code in {"runner_unavailable", "artifact_unavailable"}:
        return "Install a DefenseClaw build containing the supported s-gw module for this platform."
    if code == "locked":
        return "Run 'defenseclaw setup credential-protection --yes' to initialize the local credential broker."
    if code == "connector_conflict":
        return "Open s-gw and resolve the reported agent integration conflict, then rerun setup."
    return "Run 'defenseclaw setup credential-protection --yes' to repair the credential broker."
