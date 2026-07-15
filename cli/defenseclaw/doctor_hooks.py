# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Validation for Windows-native Codex and Claude Code hooks.

This module never starts a configured hook command. Agent hook configuration is
untrusted input, so Doctor only parses those command lines and inspects their
resolved launcher/setup evidence on disk. Codex is the narrow exception to a
fully passive check: explicit Setup evidence binds one trusted Codex executable
into the protected hook contract lock, and Doctor may start that exact binary's
app-server with a bounded/no-console RPC to re-read effective cloud/admin hook
policy. The registered hook command remains data and is never executed.
"""

from __future__ import annotations

import base64
import binascii
import ctypes
import hashlib
import json
import ntpath
import os
import queue
import re
import shlex
import stat
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib

from defenseclaw.connector_contracts import resolve_connector_contract
from defenseclaw.inventory.plugin_identity import is_link_or_reparse

_SAFE_PATHEXT = (".exe", ".cmd")
_MANAGED_MARKER = re.compile(r"(?im)^\s*(?:#|rem\s+)\s*defenseclaw-managed-hook\s+v(\d+)\b")
_EXPECTED_CONTRACTS = {
    "codex": frozenset({"codex-hooks-v1", "codex-hooks-v2", "codex-hooks-v3"}),
    "claudecode": frozenset({"claudecode-hooks-v1"}),
}
_CODEX_HOOK_SPECS = {
    "SessionStart": ("session_start", "startup|resume|clear", 30),
    "UserPromptSubmit": ("user_prompt_submit", None, 30),
    "PreToolUse": ("pre_tool_use", "*", 30),
    "PermissionRequest": ("permission_request", "*", 30),
    "PostToolUse": ("post_tool_use", "*", 30),
    "SubagentStart": ("subagent_start", "*", 30),
    "SubagentStop": ("subagent_stop", "*", 90),
    "PreCompact": ("pre_compact", None, 30),
    "PostCompact": ("post_compact", None, 30),
    "Stop": ("stop", None, 90),
}
_CODEX_TRUSTED_CONTRACTS = frozenset({"codex-hooks-v2", "codex-hooks-v3"})
_CODEX_POLICY_TIMEOUT_SECONDS = 20.0
_CODEX_POLICY_MESSAGE_LIMIT = 2 * 1024 * 1024
_CLAUDE_FILE_CHANGED_MATCHER = (
    "CLAUDE.md|.claude/settings.json|.claude/settings.local.json|.mcp.json|.env|.envrc|"
    "package.json|pyproject.toml|go.mod|Cargo.toml|requirements.txt"
)
_REPAIR = {
    "codex": "defenseclaw setup codex --yes --restart",
    "claudecode": "defenseclaw setup claude-code --yes --restart",
}

_CODEX_REQUIRED_HOOKS: dict[str, tuple[str, str | None, int]] = {
    "SessionStart": ("session_start", "startup|resume|clear", 30),
    "UserPromptSubmit": ("user_prompt_submit", None, 30),
    "PreToolUse": ("pre_tool_use", "*", 30),
    "PermissionRequest": ("permission_request", "*", 30),
    "PostToolUse": ("post_tool_use", "*", 30),
    "SubagentStart": ("subagent_start", "*", 30),
    "SubagentStop": ("subagent_stop", "*", 90),
    "PreCompact": ("pre_compact", None, 30),
    "PostCompact": ("post_compact", None, 30),
    "Stop": ("stop", None, 90),
}

_CLAUDE_REQUIRED_HOOKS: dict[str, tuple[str | None, int]] = {
    "SessionStart": ("startup|resume|clear|compact", 30),
    "InstructionsLoaded": ("*", 30),
    "UserPromptSubmit": (None, 30),
    "UserPromptExpansion": (None, 30),
    "MessageDisplay": (None, 10),
    "PreToolUse": ("*", 30),
    "PermissionRequest": ("*", 30),
    "PostToolUse": ("*", 30),
    "PostToolUseFailure": ("*", 30),
    "PostToolBatch": (None, 90),
    "PermissionDenied": ("*", 30),
    "Notification": ("*", 30),
    "SubagentStart": ("*", 30),
    "SubagentStop": ("*", 90),
    "TaskCreated": (None, 30),
    "TaskCompleted": (None, 30),
    "Stop": (None, 90),
    "StopFailure": ("*", 30),
    "TeammateIdle": (None, 30),
    "ConfigChange": ("*", 30),
    "CwdChanged": (None, 30),
    "FileChanged": (_CLAUDE_FILE_CHANGED_MATCHER, 30),
    "WorktreeRemove": (None, 30),
    "PreCompact": ("*", 30),
    "PostCompact": ("*", 30),
    "SessionEnd": (None, 60),
    "Elicitation": ("*", 30),
    "ElicitationResult": ("*", 30),
}


@dataclass(frozen=True)
class WindowsHookCheck:
    state: str
    detail: str
    command: str = ""
    target: str = ""
    raw_target: str = ""

    @property
    def healthy(self) -> bool:
        return self.state == "healthy"

    @property
    def runtime_description(self) -> str:
        """Describe the registered runtime without executing command text.

        A healthy resolved target is safe to render directly after the
        ownership and containment checks below.  Failed targets, unresolved
        targets, and malformed commands remain untrusted input, so ``repr``
        keeps control characters inert in Doctor's human output while still
        showing the operator the exact registration that needs repair.
        """
        if self.target:
            runtime = f"runtime_path={self.target}" if self.healthy else f"runtime_path={self.target!r}"
        elif self.raw_target:
            runtime = f"runtime_path={self.raw_target!r}"
        elif self.command:
            runtime = f"runtime_command={self.command!r}"
        else:
            runtime = "runtime_path=unresolved"
        if self.healthy:
            return runtime
        return f"{runtime} runtime_state={self.state} runtime_error={self.detail}"


class _InspectionError(Exception):
    def __init__(self, state: str, detail: str) -> None:
        super().__init__(detail)
        self.state = state
        self.detail = detail


class _WindowsGUID(ctypes.Structure):
    _fields_ = (
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    )


def _windows_known_folder_path(folder_id: str) -> str:
    """Resolve a Known Folder without trusting spoofable environment values."""
    if os.name != "nt" or not hasattr(ctypes, "windll"):
        return ""
    raw = uuid.UUID(folder_id).bytes_le
    guid = _WindowsGUID.from_buffer_copy(raw)
    result = ctypes.c_wchar_p()
    shell32 = ctypes.windll.shell32
    ole32 = ctypes.windll.ole32
    try:
        status = int(shell32.SHGetKnownFolderPath(ctypes.byref(guid), 0, None, ctypes.byref(result)))
        if status != 0 or not result.value:
            return ""
        return os.path.abspath(result.value)
    finally:
        if result:
            ole32.CoTaskMemFree(result)


def _codex_system_requirements_path() -> str:
    # FOLDERID_ProgramData = {62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}
    program_data = _windows_known_folder_path("62ab5d82-fdc1-4dc3-a9dd-070d1d495d97")
    return os.path.join(program_data, "OpenAI", "Codex", "requirements.toml") if program_data else ""


def _cached_codex_executable(data_dir: str) -> tuple[str, bool]:
    path = os.path.join(data_dir, "agent_discovery.json")
    try:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, UnicodeError, ValueError):
        return "", False
    signal = (payload.get("agents") or {}).get("codex") if isinstance(payload, dict) else None
    if not isinstance(signal, dict):
        return "", False
    installed = signal.get("installed") is True
    executable = str(signal.get("binary_path") or "").strip()
    if not executable:
        return "", installed
    if any(char in executable for char in "\x00\r\n") or not os.path.isabs(executable):
        raise _InspectionError("stale", f"Codex discovery cached a non-absolute binary path: {executable!r}")
    try:
        from defenseclaw.inventory.agent_discovery import _is_trusted_binary_path

        trusted = _is_trusted_binary_path(executable, data_dir=data_dir)
    except (OSError, ValueError):
        trusted = False
    if not trusted:
        raise _InspectionError("foreign", f"Codex policy inspector binary is outside trusted prefixes: {executable}")
    return executable, installed


def _wait_for_codex_rpc(
    messages: queue.Queue[str],
    overflow: threading.Event,
    request_id: int,
    *,
    timeout: float,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while True:
        if overflow.is_set():
            raise _InspectionError("malformed", "Codex app-server exceeded the bounded response queue")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _InspectionError("stale", f"Codex app-server timed out waiting for response {request_id}")
        try:
            line = messages.get(timeout=min(remaining, 0.25))
        except queue.Empty:
            continue
        if len(line.encode("utf-8", errors="replace")) > 2 * 1024 * 1024:
            raise _InspectionError("malformed", "Codex app-server response exceeds 2 MiB")
        try:
            envelope = json.loads(line)
        except ValueError as exc:
            raise _InspectionError("malformed", f"Codex app-server returned invalid JSON: {exc}") from exc
        if not isinstance(envelope, dict) or envelope.get("id") != request_id:
            continue
        error = envelope.get("error")
        if error:
            raise _InspectionError("stale", f"Codex app-server RPC {request_id} failed: {error}")
        result = envelope.get("result")
        if not isinstance(result, dict):
            raise _InspectionError("malformed", f"Codex app-server RPC {request_id} returned no result")
        return result


def _inspect_codex_app_server_policy(executable: str, codex_home: str) -> tuple[bool | None, str]:
    env = os.environ.copy()
    env["CODEX_HOME"] = codex_home
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    try:
        process = subprocess.Popen(
            [executable, "app-server", "--stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            env=env,
            creationflags=creationflags,
        )
    except OSError as exc:
        raise _InspectionError("stale", f"cannot start Codex policy inspector {executable}: {exc}") from exc

    messages: queue.Queue[str] = queue.Queue(maxsize=64)
    overflow = threading.Event()
    stderr_parts: list[str] = []

    def read_stdout() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            try:
                messages.put_nowait(line)
            except queue.Full:
                overflow.set()
                return

    def read_stderr() -> None:
        assert process.stderr is not None
        remaining = 64 * 1024
        for chunk in iter(lambda: process.stderr.read(4096), ""):
            if remaining > 0:
                stderr_parts.append(chunk[:remaining])
                remaining -= len(chunk)

    stdout_thread = threading.Thread(target=read_stdout, daemon=True)
    stderr_thread = threading.Thread(target=read_stderr, daemon=True)
    stdout_thread.start()
    stderr_thread.start()
    try:
        assert process.stdin is not None
        initialize = {
            "method": "initialize",
            "id": 1,
            "params": {
                "clientInfo": {"name": "defenseclaw", "title": "DefenseClaw", "version": "1"},
            },
        }
        process.stdin.write(json.dumps(initialize, separators=(",", ":")) + "\n")
        process.stdin.flush()
        _wait_for_codex_rpc(messages, overflow, 1, timeout=20.0)
        process.stdin.write('{"method":"initialized"}\n')
        process.stdin.write('{"method":"configRequirements/read","id":2,"params":{}}\n')
        process.stdin.flush()
        result = _wait_for_codex_rpc(messages, overflow, 2, timeout=20.0)
        requirements = result.get("requirements")
        if requirements is None:
            return None, f"Codex app-server {executable} effective requirements"
        if not isinstance(requirements, dict):
            raise _InspectionError("malformed", "Codex app-server returned malformed requirements")
        value = requirements.get("allowManagedHooksOnly")
        if value is not None and type(value) is not bool:
            raise _InspectionError("malformed", "Codex allowManagedHooksOnly is not boolean")
        return value, f"Codex app-server {executable} effective requirements"
    except (BrokenPipeError, OSError) as exc:
        detail = "".join(stderr_parts).strip()
        suffix = f" ({detail})" if detail else ""
        raise _InspectionError("stale", f"Codex policy inspection failed: {exc}{suffix}") from exc
    finally:
        if process.stdin is not None:
            try:
                process.stdin.close()
            except OSError:
                pass
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2.0)


def _validate_codex_effective_policy(data_dir: str, config_path: str) -> str:
    executable, installed = _cached_codex_executable(data_dir)
    if executable:
        value, source = _inspect_codex_app_server_policy(executable, os.path.dirname(config_path))
    else:
        requirements_path = _codex_system_requirements_path()
        value = None
        source = requirements_path or "no system requirements source on this platform"
        if requirements_path:
            try:
                with open(requirements_path, "rb") as handle:
                    raw = handle.read(2 * 1024 * 1024 + 1)
            except FileNotFoundError:
                raw = b""
            except OSError as exc:
                raise _InspectionError("access-denied", f"cannot read {requirements_path}: {exc}") from exc
            if len(raw) > 2 * 1024 * 1024:
                raise _InspectionError("malformed", f"{requirements_path} exceeds 2 MiB")
            if raw:
                try:
                    document = tomllib.loads(raw.decode("utf-8"))
                except (UnicodeError, tomllib.TOMLDecodeError) as exc:
                    raise _InspectionError("malformed", f"cannot parse {requirements_path}: {exc}") from exc
                value = document.get("allow_managed_hooks_only")
                if value is not None and type(value) is not bool:
                    raise _InspectionError(
                        "malformed",
                        f"allow_managed_hooks_only in {requirements_path} is not boolean",
                    )
        if installed:
            raise _InspectionError(
                "stale",
                "Codex is installed but its trusted executable is absent from agent_discovery.json; "
                "effective cloud policy cannot be verified",
            )
    if value is True:
        raise _InspectionError(
            "foreign",
            f"Codex allow_managed_hooks_only from {source} disables DefenseClaw's user hook registration",
        )
    return source


def _repair_detail(connector: str, detail: str) -> str:
    return f"{detail}; run `{_REPAIR[connector]}` to repair the native registration"


def _windows_extensions(pathext: str) -> tuple[str, ...]:
    requested: list[str] = []
    for item in pathext.split(";"):
        extension = item.strip().lower()
        if extension and not extension.startswith("."):
            extension = "." + extension
        if extension in _SAFE_PATHEXT and extension not in requested:
            requested.append(extension)
    for extension in _SAFE_PATHEXT:
        if extension not in requested:
            requested.append(extension)
    return tuple(requested)


def _case_insensitive_file(directory: str, filename: str) -> str | None:
    try:
        entries = list(os.scandir(directory))
    except PermissionError as exc:
        raise _InspectionError("access-denied", f"access denied while searching {directory}: {exc}") from exc
    except OSError:
        return None
    for entry in entries:
        if entry.name.casefold() != filename.casefold():
            continue
        try:
            if entry.is_file(follow_symlinks=False) or entry.is_symlink():
                return os.path.abspath(entry.path)
        except PermissionError as exc:
            raise _InspectionError("access-denied", f"access denied while inspecting {entry.path}: {exc}") from exc
        except OSError:
            return None
    return None


def resolve_windows_command(
    binary: str,
    *,
    search_path: str,
    pathext: str,
) -> str | None:
    """Resolve an EXE/CMD with deterministic, non-executing PATHEXT rules."""
    binary = binary.strip()
    if not binary or any(char in binary for char in "\r\n\x00"):
        return None
    host_absolute = os.path.isabs(binary)
    windows_absolute = ntpath.isabs(binary)
    directory, filename = os.path.split(binary)
    if not directory and ("\\" in binary or windows_absolute):
        directory, filename = ntpath.split(binary)
    if directory or host_absolute or windows_absolute:
        directories = [directory or os.path.dirname(binary)]
    else:
        directories = [part.strip().strip('"') for part in search_path.split(";") if part.strip().strip('"')]

    _stem, extension = ntpath.splitext(filename)
    extensions = _windows_extensions(pathext)
    if extension:
        if extension.lower() not in extensions:
            return None
        names = [filename]
    else:
        names = [filename + suffix for suffix in extensions]

    for directory_name in directories:
        if not directory_name:
            continue
        for name in names:
            found = _case_insensitive_file(directory_name, name)
            if found:
                return found
    return None


def _is_within(path: str, root: str) -> bool:
    try:
        path_key = os.path.normcase(os.path.realpath(os.path.abspath(path)))
        root_key = os.path.normcase(os.path.realpath(os.path.abspath(root)))
        return os.path.commonpath((path_key, root_key)) == root_key and path_key != root_key
    except (OSError, ValueError):
        return False


def _stable_regular_file(path: str, root: str, *, read_limit: int = 0) -> bytes:
    """Inspect one contained regular file and detect links and replacement races."""
    try:
        before = os.lstat(path)
    except FileNotFoundError as exc:
        raise _InspectionError("missing", f"registered hook target is missing: {path}") from exc
    except PermissionError as exc:
        raise _InspectionError("access-denied", f"access denied to registered hook target {path}: {exc}") from exc
    except OSError as exc:
        raise _InspectionError("malformed", f"cannot inspect registered hook target {path}: {exc}") from exc
    if is_link_or_reparse(path) or not stat.S_ISREG(before.st_mode):
        raise _InspectionError("foreign", f"registered hook target is a symlink or reparse point: {path}")
    if not _is_within(path, root):
        raise _InspectionError("foreign", f"registered hook target escapes the DefenseClaw install directory: {path}")

    root_abs = os.path.abspath(root)
    current = os.path.dirname(os.path.abspath(path))
    inspected = [os.path.abspath(path)]
    while os.path.normcase(current) != os.path.normcase(root_abs):
        if is_link_or_reparse(current):
            raise _InspectionError("foreign", f"registered hook target crosses a symlink or reparse point: {current}")
        inspected.append(current)
        parent = os.path.dirname(current)
        if parent == current:
            raise _InspectionError(
                "foreign", f"registered hook target is outside the DefenseClaw install directory: {path}"
            )
        current = parent
    if is_link_or_reparse(root_abs):
        raise _InspectionError("foreign", f"DefenseClaw install directory is a symlink or reparse point: {root_abs}")
    inspected.append(root_abs)
    if os.name == "nt":  # ACL ownership has no faithful POSIX simulation.
        from defenseclaw.inventory.agent_discovery import _windows_acl_write_error

        for item in inspected:
            acl_error = _windows_acl_write_error(item)
            if acl_error:
                state = "access-denied" if acl_error.startswith("cannot read") else "foreign"
                raise _InspectionError(state, f"untrusted ownership or ACL on {item}: {acl_error}")

    body = b""
    if read_limit:
        try:
            with open(path, "rb") as handle:
                body = handle.read(read_limit)
        except PermissionError as exc:
            raise _InspectionError(
                "access-denied", f"access denied while reading registered hook target {path}: {exc}"
            ) from exc
        except OSError as exc:
            raise _InspectionError("malformed", f"cannot read registered hook target {path}: {exc}") from exc
    try:
        after = os.lstat(path)
    except OSError as exc:
        raise _InspectionError("stale", f"registered hook target changed during inspection: {path}") from exc
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after or is_link_or_reparse(path):
        raise _InspectionError("stale", f"registered hook target changed during inspection: {path}")
    return body


def _packaged_windows_install_root(
    data_dir: str,
    *,
    executable: str | None = None,
    declared_root: str | None = None,
) -> str | None:
    """Prove the install root used by the packaged Windows interpreter.

    The launcher-provided environment value is only corroborating evidence:
    the running interpreter layout and the installer's stable, non-reparse
    state must independently agree with it and with the active data root.
    """

    def path_key(value: str) -> str:
        return os.path.normcase(os.path.realpath(os.path.abspath(value)))

    executable_path = os.path.abspath(executable or sys.executable)
    python_dir = os.path.dirname(executable_path)
    runtime_dir = os.path.dirname(python_dir)
    install_root = os.path.dirname(runtime_dir)
    expected_executable = os.path.join(install_root, "runtime", "python", "python.exe")
    declared = os.environ.get("DEFENSECLAW_INSTALL_ROOT", "") if declared_root is None else declared_root
    if not declared or not data_dir:
        return None
    try:
        if path_key(executable_path) != path_key(expected_executable):
            return None
        if path_key(declared) != path_key(install_root):
            return None
        if _stable_regular_file(executable_path, install_root, read_limit=2) != b"MZ":
            return None
        state_path = os.path.join(install_root, "installer", "install-state.json")
        state_bytes = _stable_regular_file(state_path, install_root, read_limit=128 * 1024 + 1)
        if len(state_bytes) > 128 * 1024:
            return None
        state = json.loads(state_bytes.decode("utf-8-sig"))
    except (_InspectionError, OSError, UnicodeError, ValueError):
        return None
    if not isinstance(state, dict):
        return None
    if type(state.get("schema_version")) is not int or state["schema_version"] != 1:
        return None
    if state.get("install_kind") != "native-windows-exe" or state.get("install_scope") != "user":
        return None
    expected_paths = {
        "install_root": install_root,
        "command_dir": os.path.join(install_root, "bin"),
        "runtime": os.path.join(install_root, "runtime", "python"),
        "data_root": data_dir,
    }
    for field, expected in expected_paths.items():
        recorded = state.get(field)
        if not isinstance(recorded, str) or not recorded:
            return None
        try:
            if path_key(recorded) != path_key(expected):
                return None
        except (OSError, ValueError):
            return None
    return install_root


def _read_config(path: str, connector: str) -> dict[str, Any]:
    try:
        before = os.lstat(path)
    except FileNotFoundError as exc:
        raise _InspectionError("missing", f"hook registration file is missing: {path}") from exc
    except PermissionError as exc:
        raise _InspectionError("access-denied", f"access denied to hook registration file {path}: {exc}") from exc
    except OSError as exc:
        raise _InspectionError("malformed", f"cannot inspect hook registration file {path}: {exc}") from exc
    if is_link_or_reparse(path) or not stat.S_ISREG(before.st_mode):
        raise _InspectionError("foreign", f"hook registration file is a symlink or reparse point: {path}")
    try:
        with open(path, "rb") as handle:
            raw = handle.read(2 * 1024 * 1024 + 1)
    except PermissionError as exc:
        raise _InspectionError(
            "access-denied", f"access denied while reading hook registration file {path}: {exc}"
        ) from exc
    except OSError as exc:
        raise _InspectionError("malformed", f"cannot read hook registration file {path}: {exc}") from exc
    if len(raw) > 2 * 1024 * 1024:
        raise _InspectionError("malformed", f"hook registration file is too large: {path}")
    try:
        after = os.lstat(path)
    except OSError as exc:
        raise _InspectionError("stale", f"hook registration file changed during inspection: {path}") from exc
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise _InspectionError("stale", f"hook registration file changed during inspection: {path}")
    try:
        document = tomllib.loads(raw.decode("utf-8")) if connector == "codex" else json.loads(raw)
    except (UnicodeError, ValueError, tomllib.TOMLDecodeError) as exc:
        raise _InspectionError("malformed", f"cannot parse hook registration file {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise _InspectionError("malformed", f"hook registration file does not contain an object: {path}")
    return document


def _codex_policy_executable(data_dir: str) -> str:
    """Resolve Setup's exact protected Codex executable evidence.

    ``agent_discovery.json`` is deliberately excluded: it is an automatic,
    expiring inventory cache and therefore cannot grant process-launch
    authority. Only the version/contract-bound lock written after an explicit
    Setup selection is accepted here.
    """

    lock_path = os.path.join(data_dir, "hook_contract_lock.json")
    try:
        raw = _stable_regular_file(
            lock_path,
            os.path.abspath(data_dir),
            read_limit=_CODEX_POLICY_MESSAGE_LIMIT + 1,
        )
        if len(raw) > _CODEX_POLICY_MESSAGE_LIMIT:
            raise OSError("hook contract lock is too large")
        payload = json.loads(raw.decode("utf-8-sig"))
    except (_InspectionError, OSError, UnicodeError, ValueError) as exc:
        detail = exc.detail if isinstance(exc, _InspectionError) else str(exc)
        raise _InspectionError(
            "policy-blocked", f"cannot inspect protected Codex executable evidence: {detail}"
        ) from exc
    if not isinstance(payload, dict) or type(payload.get("version")) is not int:
        raise _InspectionError("policy-blocked", "Codex hook contract lock schema is malformed")
    if payload["version"] not in {1, 2}:
        raise _InspectionError("policy-blocked", "Codex hook contract lock schema is unsupported")
    connectors = payload.get("connectors")
    entry = connectors.get("codex") if isinstance(connectors, dict) else None
    if not isinstance(entry, dict):
        raise _InspectionError("policy-blocked", "Codex hook contract lock entry is missing")

    executable = str(entry.get("agent_executable") or "").strip()
    source = str(entry.get("agent_executable_source") or "").strip()
    expected_digest = str(entry.get("agent_executable_sha256") or "").strip()
    raw_version = str(entry.get("raw_agent_version") or "").strip()
    normalized_version = str(entry.get("normalized_agent_version") or "").strip()
    contract_id = str(entry.get("contract_id") or "").strip()
    if source != "setup-selected":
        raise _InspectionError(
            "policy-blocked", "Codex executable evidence was not created by an explicit Setup selection"
        )
    if not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
        raise _InspectionError("policy-blocked", "Codex executable evidence has no valid SHA-256 digest")
    compatibility = resolve_connector_contract("codex", raw_version)
    resolved_contract = compatibility.contract.contract_id if compatibility.contract is not None else ""
    if (
        not raw_version
        or not normalized_version
        or compatibility.normalized_version != normalized_version
        or compatibility.status != "known"
        or resolved_contract != contract_id
    ):
        raise _InspectionError(
            "policy-blocked", "Codex executable evidence is not bound to the recorded agent contract/version"
        )
    if not os.path.isabs(executable) or any(char in executable for char in "\x00\r\n"):
        raise _InspectionError("policy-blocked", f"selected Codex executable is not absolute: {executable!r}")
    executable = os.path.abspath(executable)
    if os.path.splitext(executable)[1].casefold() != ".exe":
        raise _InspectionError(
            "policy-blocked",
            "selected Codex policy executable is not a native Windows .exe image",
        )

    from defenseclaw.agent_selection import is_setup_trusted_binary, stable_executable_sha256
    from defenseclaw.inventory.agent_discovery import _binary_command_name

    if _binary_command_name(executable) != "codex":
        raise _InspectionError(
            "policy-blocked", f"selected Codex executable has an unexpected product name: {executable}"
        )
    if not is_setup_trusted_binary(executable, data_dir):
        raise _InspectionError(
            "policy-blocked",
            f"selected Codex executable is no longer in a trusted executable location: {executable}",
        )
    try:
        actual_digest = stable_executable_sha256(executable)
    except OSError as exc:
        raise _InspectionError("policy-blocked", f"cannot revalidate selected Codex executable: {exc}") from exc
    if actual_digest != expected_digest:
        raise _InspectionError("policy-blocked", "selected Codex executable no longer matches protected Setup evidence")
    return executable


def _inspect_codex_effective_hook_policy(data_dir: str, config_path: str) -> tuple[bool, str]:
    """Read Codex's merged system/cloud/MDM hook policy through app-server."""

    executable = _codex_policy_executable(data_dir)
    env = dict(os.environ)
    env["CODEX_HOME"] = os.path.dirname(os.path.abspath(config_path))
    creationflags = 0
    windows_job = None
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "CREATE_SUSPENDED", 0x00000004)
    try:
        process = subprocess.Popen(
            [executable, "app-server", "--stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env=env,
            creationflags=creationflags,
        )
    except (OSError, ValueError) as exc:
        raise _InspectionError("policy-blocked", f"cannot start Codex policy inspector: {exc}") from exc
    if os.name == "nt":
        from defenseclaw.tui.windows_process import WindowsJob

        try:
            # Popen created the native image suspended. Assign it before resume
            # so none of its descendants can escape in the start-to-assignment
            # race.
            windows_job = WindowsJob(process.pid, allow_breakaway=False)
        except BaseException as exc:
            try:
                process.kill()
                process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                pass
            raise _InspectionError(
                "policy-blocked", f"cannot contain Codex policy inspector process tree: {exc}"
            ) from exc

    responses: queue.Queue[tuple[str, Any]] = queue.Queue(maxsize=4)
    stderr_bytes = bytearray()
    stderr_lock = threading.Lock()

    def emit_response(kind: str, payload: Any) -> None:
        try:
            responses.put_nowait((kind, payload))
        except queue.Full:
            # Only IDs 1 and 2 are admitted below, so a full queue is itself a
            # bounded protocol failure rather than a reason to block this pump.
            return

    def read_responses() -> None:
        total = 0
        assert process.stdout is not None
        while True:
            try:
                line = process.stdout.readline(_CODEX_POLICY_MESSAGE_LIMIT + 1)
            except OSError as exc:
                emit_response("error", f"cannot read Codex policy response: {exc}")
                return
            if not line:
                emit_response("error", "Codex policy inspector closed stdout before replying")
                return
            total += len(line)
            if len(line) > _CODEX_POLICY_MESSAGE_LIMIT or total > _CODEX_POLICY_MESSAGE_LIMIT:
                emit_response("error", "Codex policy response exceeds the bounded message limit")
                return
            try:
                message = json.loads(line)
            except (UnicodeError, ValueError) as exc:
                emit_response("error", f"cannot parse Codex policy response: {exc}")
                return
            if isinstance(message, dict) and type(message.get("id")) is int and message["id"] in {1, 2}:
                emit_response("message", message)

    def read_stderr() -> None:
        assert process.stderr is not None
        try:
            while True:
                chunk = process.stderr.read(4096)
                if not chunk:
                    return
                with stderr_lock:
                    remaining = (64 * 1024) - len(stderr_bytes)
                    if remaining > 0:
                        stderr_bytes.extend(chunk[:remaining])
        except OSError:
            return

    response_thread = threading.Thread(target=read_responses, name="codex-policy-stdout", daemon=True)
    stderr_thread = threading.Thread(target=read_stderr, name="codex-policy-stderr", daemon=True)
    response_thread.start()
    stderr_thread.start()

    deadline = time.monotonic() + _CODEX_POLICY_TIMEOUT_SECONDS

    def diagnostic(detail: str) -> str:
        with stderr_lock:
            stderr = bytes(stderr_bytes).decode("utf-8", errors="replace").strip()
        return f"{detail} (stderr: {stderr})" if stderr else detail

    def send(message: dict[str, Any]) -> None:
        assert process.stdin is not None
        try:
            process.stdin.write((json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8"))
            process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise _InspectionError("policy-blocked", diagnostic(f"cannot send Codex policy RPC: {exc}")) from exc

    def wait_for(response_id: int) -> dict[str, Any]:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _InspectionError(
                    "policy-blocked",
                    diagnostic(f"timed out waiting for Codex policy response {response_id}"),
                )
            try:
                kind, payload = responses.get(timeout=remaining)
            except queue.Empty as exc:
                raise _InspectionError(
                    "policy-blocked",
                    diagnostic(f"timed out waiting for Codex policy response {response_id}"),
                ) from exc
            if kind == "error":
                raise _InspectionError("policy-blocked", diagnostic(str(payload)))
            if payload.get("id") != response_id:
                continue
            error = payload.get("error")
            if error is not None:
                raise _InspectionError("policy-blocked", diagnostic(f"Codex policy RPC {response_id} failed: {error}"))
            result = payload.get("result")
            if not isinstance(result, dict):
                raise _InspectionError(
                    "policy-blocked", diagnostic(f"Codex policy RPC {response_id} returned no object result")
                )
            return result

    try:
        send(
            {
                "method": "initialize",
                "id": 1,
                "params": {"clientInfo": {"name": "defenseclaw", "title": "DefenseClaw", "version": "1"}},
            }
        )
        wait_for(1)
        send({"method": "initialized"})
        send({"method": "configRequirements/read", "id": 2, "params": {}})
        result = wait_for(2)
        requirements = result.get("requirements")
        if requirements is None:
            return False, f"Codex app-server {executable} effective requirements"
        if not isinstance(requirements, dict):
            raise _InspectionError("policy-blocked", "Codex effective requirements are malformed")
        managed_only = requirements.get("allowManagedHooksOnly")
        if managed_only is not None and type(managed_only) is not bool:
            raise _InspectionError("policy-blocked", "Codex allowManagedHooksOnly requirement is malformed")
        return managed_only is True, f"Codex app-server {executable} effective requirements"
    finally:
        active_exception = sys.exception()
        cleanup_errors: list[str] = []
        job_closed = False

        def close_windows_job() -> None:
            nonlocal job_closed
            if windows_job is None or job_closed:
                return
            # Mark first so an exceptional fake/OS close cannot trigger an
            # unbounded retry from a later cleanup branch.
            job_closed = True
            try:
                windows_job.close()
            except OSError as exc:
                cleanup_errors.append(f"close Codex policy inspector Job Object: {exc}")

        if process.stdin is not None:
            try:
                process.stdin.close()
            except OSError as exc:
                cleanup_errors.append(f"close stdin: {exc}")
        if windows_job is not None:
            try:
                if not windows_job.terminate_sync(timeout=2):
                    cleanup_errors.append("Codex policy inspector Job Object did not become empty")
                    # A descendant may still own stdout/stderr. Closing the
                    # kill-on-close handle before touching those streams keeps
                    # the remaining cleanup bounded.
                    close_windows_job()
            except OSError as exc:
                cleanup_errors.append(f"terminate Codex policy inspector Job Object: {exc}")
                close_windows_job()
        elif process.poll() is None:
            try:
                process.terminate()
            except OSError as exc:
                cleanup_errors.append(f"terminate Codex policy inspector: {exc}")
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            close_windows_job()
            try:
                process.kill()
                process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired) as exc:
                cleanup_errors.append(f"reap Codex policy inspector: {exc}")
        except OSError as exc:
            cleanup_errors.append(f"reap Codex policy inspector: {exc}")
            close_windows_job()

        for thread in (response_thread, stderr_thread):
            thread.join(timeout=2)
        for thread, stream in (
            (response_thread, process.stdout),
            (stderr_thread, process.stderr),
        ):
            if thread.is_alive():
                # Closing a buffered pipe while another thread is blocked in a
                # read can itself wait on that stream's internal lock. The job
                # has already been killed/closed above; leave the daemon reader
                # to observe EOF instead of turning cleanup into an unbounded
                # close.
                cleanup_errors.append(f"{thread.name} did not stop")
                continue
            if stream is not None:
                try:
                    stream.close()
                except OSError as exc:
                    cleanup_errors.append(f"close Codex policy stream: {exc}")
        close_windows_job()
        if active_exception is None and cleanup_errors:
            raise _InspectionError("policy-blocked", "; ".join(cleanup_errors))


_codex_effective_policy_inspector = _inspect_codex_effective_hook_policy


def _validate_codex_effective_hook_policy(data_dir: str, config_path: str) -> str:
    """Fail closed when current effective policy ignores user hook config."""

    try:
        managed_only, source = _codex_effective_policy_inspector(data_dir, config_path)
    except _InspectionError:
        raise
    except Exception as exc:
        raise _InspectionError("policy-blocked", f"cannot inspect effective Codex policy: {exc}") from exc
    if managed_only:
        raise _InspectionError(
            "policy-blocked",
            "Codex effective policy sets allow_managed_hooks_only=true from "
            f"{source}, so the user-scoped DefenseClaw hooks are ignored",
        )
    return source


def _default_claude_managed_settings_paths() -> tuple[str, ...]:
    """Return locally inspectable Windows file-policy sources in merge order."""
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    root = os.path.join(program_files, "ClaudeCode")
    paths = [os.path.join(root, "managed-settings.json")]
    dropins = os.path.join(root, "managed-settings.d")
    try:
        with os.scandir(dropins) as entries:
            names = sorted(
                entry.name
                for entry in entries
                if not entry.name.startswith(".") and entry.name.lower().endswith(".json")
            )
    except FileNotFoundError:
        names = []
    except OSError as exc:
        raise _InspectionError("policy-blocked", f"cannot inspect Claude Code managed policy directory: {exc}") from exc
    paths.extend(os.path.join(dropins, name) for name in names)
    return tuple(paths)


def _read_optional_claude_policy(path: str) -> dict[str, Any] | None:
    """Read one passive JSON policy file, returning None when it is absent."""
    try:
        before = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _InspectionError("policy-blocked", f"cannot inspect Claude Code managed policy {path}: {exc}") from exc
    if is_link_or_reparse(path) or not stat.S_ISREG(before.st_mode):
        raise _InspectionError("policy-blocked", f"Claude Code managed policy is not a regular file: {path}")
    try:
        with open(path, "rb") as handle:
            raw = handle.read(2 * 1024 * 1024 + 1)
    except OSError as exc:
        raise _InspectionError("policy-blocked", f"cannot read Claude Code managed policy {path}: {exc}") from exc
    if len(raw) > 2 * 1024 * 1024:
        raise _InspectionError("policy-blocked", f"Claude Code managed policy is too large: {path}")
    try:
        after = os.lstat(path)
    except OSError as exc:
        raise _InspectionError(
            "policy-blocked", f"Claude Code managed policy changed during inspection: {path}"
        ) from exc
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise _InspectionError("policy-blocked", f"Claude Code managed policy changed during inspection: {path}")
    try:
        document = json.loads(raw)
    except (UnicodeError, ValueError) as exc:
        raise _InspectionError("policy-blocked", f"cannot parse Claude Code managed policy {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise _InspectionError("policy-blocked", f"Claude Code managed policy is not an object: {path}")
    return document


def _read_claude_registry_policy(hive_name: str) -> dict[str, Any] | None:
    """Read one locally inspectable Windows managed-settings registry tier."""
    if os.name != "nt":
        return None
    try:
        import winreg

        hive = getattr(winreg, hive_name)
        access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
        with winreg.OpenKey(hive, r"SOFTWARE\Policies\ClaudeCode", 0, access) as key:
            raw, value_type = winreg.QueryValueEx(key, "Settings")
    except FileNotFoundError:
        return None
    except (OSError, AttributeError) as exc:
        raise _InspectionError(
            "policy-blocked", f"cannot inspect Claude Code {hive_name} managed policy: {exc}"
        ) from exc
    if value_type not in {winreg.REG_SZ, winreg.REG_EXPAND_SZ} or not isinstance(raw, str):
        raise _InspectionError("policy-blocked", f"Claude Code {hive_name} Settings policy has an invalid type")
    try:
        document = json.loads(raw)
    except ValueError as exc:
        raise _InspectionError(
            "policy-blocked", f"cannot parse Claude Code {hive_name} Settings policy: {exc}"
        ) from exc
    if not isinstance(document, dict):
        raise _InspectionError("policy-blocked", f"Claude Code {hive_name} Settings policy is not an object")
    return document


def _merge_claude_file_policies(paths: tuple[str, ...]) -> dict[str, Any]:
    """Merge Claude file-policy tiers in their documented precedence order."""
    managed: dict[str, Any] = {}
    for path in paths:
        policy = _read_optional_claude_policy(path)
        if policy is None:
            continue
        # Base policy is read first; sorted drop-ins override scalars and
        # extend arrays, matching Claude Code's file-policy merge order.
        for key, value in policy.items():
            if isinstance(value, list) and isinstance(managed.get(key), list):
                combined = list(managed[key])
                combined.extend(item for item in value if item not in combined)
                managed[key] = combined
            else:
                managed[key] = value
    return managed


def _validate_claude_policy(document: dict[str, Any], managed_settings_paths: tuple[str, ...] | None) -> None:
    """Reject local policy states that prevent user-scoped Claude hooks."""
    if managed_settings_paths is None:
        # Claude chooses the highest available local managed tier rather than
        # merging tiers: HKLM, then system files, then HKCU.
        managed = _read_claude_registry_policy("HKEY_LOCAL_MACHINE") or {}
        policy_source = "machine registry"
        if not managed:
            managed = _merge_claude_file_policies(_default_claude_managed_settings_paths())
            policy_source = "system managed settings"
        if not managed:
            managed = _read_claude_registry_policy("HKEY_CURRENT_USER") or {}
            policy_source = "user registry"
    else:
        # An explicit list is a deterministic test/embedding seam and excludes
        # host registry state.
        managed = _merge_claude_file_policies(managed_settings_paths)
        policy_source = "explicit managed settings"

    # Claude only honors policyHelper from machine-managed policy. A value in
    # HKCU is ordinary user input and is explicitly ignored by Claude itself.
    if "policyHelper" in managed and policy_source != "user registry":
        raise _InspectionError(
            "policy-blocked",
            "Claude Code uses a dynamic policyHelper, so passive Doctor inspection cannot prove user hooks are active",
        )

    managed_disable = managed.get("disableAllHooks")
    if managed_disable is not None and not isinstance(managed_disable, bool):
        raise _InspectionError("policy-blocked", "Claude Code managed disableAllHooks policy is malformed")
    user_disable = document.get("disableAllHooks")
    if user_disable is not None and not isinstance(user_disable, bool):
        raise _InspectionError("policy-blocked", "Claude Code user disableAllHooks setting is malformed")
    if managed_disable is True or user_disable is True:
        source = "managed policy" if managed_disable is True else "user settings"
        raise _InspectionError("policy-blocked", f"Claude Code {source} sets disableAllHooks=true")
    if managed.get("allowManagedHooksOnly") is True:
        raise _InspectionError(
            "policy-blocked",
            "Claude Code managed policy sets allowManagedHooksOnly=true, so the user-scoped "
            "DefenseClaw hooks are ignored",
        )
    if "allowManagedHooksOnly" in managed and not isinstance(managed["allowManagedHooksOnly"], bool):
        raise _InspectionError("policy-blocked", "Claude Code managed allowManagedHooksOnly policy is malformed")
    strict = managed.get("strictPluginOnlyCustomization")
    if strict is True or (isinstance(strict, list) and "hooks" in strict):
        raise _InspectionError(
            "policy-blocked",
            "Claude Code managed policy restricts hooks to plugins or managed settings, so the "
            "user-scoped DefenseClaw hooks are ignored",
        )
    if strict is not None and not (
        isinstance(strict, bool) or (isinstance(strict, list) and all(isinstance(item, str) for item in strict))
    ):
        raise _InspectionError(
            "policy-blocked", "Claude Code managed strictPluginOnlyCustomization policy is malformed"
        )


def _managed_hook_command(command: str, connector: str) -> bool:
    """Report whether a command is a current or recognized legacy launcher."""
    try:
        target, _args, _kind = _command_target(command, connector)
    except _InspectionError:
        target = _malformed_owned_hook_target(command, connector)
        if not target:
            return False
    legacy_script = "codex-hook.sh" if connector == "codex" else "claude-code-hook.sh"
    return ntpath.basename(target).casefold() in {
        "defenseclaw-hook",
        "defenseclaw-hook.exe",
        "defenseclaw-hook.cmd",
        "defenseclaw-hook.ps1",
        "defenseclaw-gateway",
        "defenseclaw-gateway.exe",
        "defenseclaw-gateway.cmd",
        "defenseclaw-gateway.ps1",
        legacy_script,
    }


def _malformed_owned_hook_target(command: str, connector: str) -> str:
    """Recover an exact owned target while preserving malformed diagnostics."""
    value = command.strip()
    prefix = "set NoDefaultCurrentDirectoryInExePath=1&& "
    if value.casefold().startswith(prefix.casefold()):
        value = value[len(prefix) :].strip()
    if any(char in value for char in "\r\n\x00|<>"):
        return ""
    try:
        parts = _split_windows(value)
    except _InspectionError:
        return ""
    if parts and parts[0] == "&":
        parts = parts[1:]
    if not parts:
        return ""

    first_base = ntpath.basename(parts[0]).casefold()
    if first_base in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}:
        lowered = [part.casefold() for part in parts]
        try:
            file_index = lowered.index("-file")
        except ValueError:
            return ""
        if file_index + 1 >= len(parts):
            return ""
        target = parts[file_index + 1]
        args = parts[file_index + 2 :]
    else:
        target = parts[0]
        args = parts[1:]

    legacy_script = "codex-hook.sh" if connector == "codex" else "claude-code-hook.sh"
    if ntpath.basename(target).casefold() == legacy_script and not args:
        return target
    if args[:3] != ["hook", "--connector", connector]:
        return ""
    return target


def _matcher_covers(event: str, actual: Any, required: str | None) -> bool:
    """Report whether a configured matcher covers a required hook matcher."""
    if required is None:
        return True
    if actual is None:
        actual = ""
    if not isinstance(actual, str):
        return False
    if actual in {"", "*", required}:
        return True
    if event == "FileChanged":
        # FileChanged is a pipe-separated literal watch list. Additional
        # filenames broaden coverage without weakening the required set.
        return set(required.split("|")).issubset(actual.split("|"))
    return False


def _codex_hook_state_key_source(config_path: str) -> str:
    """Mirror Codex's Windows AbsolutePathBuf display normalization."""

    source = os.path.abspath(config_path)
    for prefix in ("\\\\?\\UNC\\", "\\\\.\\UNC\\"):
        if source.startswith(prefix):
            return "\\\\" + source[len(prefix) :]
    for prefix in ("\\\\?\\", "\\\\.\\"):
        if source.startswith(prefix):
            candidate = source[len(prefix) :]
            if re.match(r"(?i)^[a-z]:[\\/]", candidate):
                return candidate
    return source


def _codex_command_hook_hash(event_key: str, matcher: str | None, hook: dict[str, Any]) -> str:
    """Return Codex's canonical command-handler fingerprint for native Windows."""

    command = hook.get("command")
    if not isinstance(command, str) or not command.strip():
        raise _InspectionError("stale", "Codex command handler has an empty generic command")
    windows_command = hook.get("command_windows", command)
    if not isinstance(windows_command, str) or not windows_command.strip():
        raise _InspectionError("stale", "Codex command handler has an empty native command")

    timeout = hook.get("timeout", 600)
    if type(timeout) is not int or timeout < 0:  # bool is intentionally not accepted as an integer.
        raise _InspectionError("stale", "Codex command handler has an invalid timeout")
    timeout = max(timeout, 1)
    async_value = hook.get("async", False)
    if type(async_value) is not bool:
        raise _InspectionError("stale", "Codex command handler has an invalid async value")
    status_message = hook.get("statusMessage")
    if status_message is not None and not isinstance(status_message, str):
        raise _InspectionError("stale", "Codex command handler has an invalid statusMessage")

    normalized_handler = {
        "async": async_value,
        "command": windows_command,
        "timeout": timeout,
        "type": "command",
    }
    if status_message is not None:
        normalized_handler["statusMessage"] = status_message
    identity: dict[str, Any] = {
        "event_name": event_key,
        "hooks": [normalized_handler],
    }
    if event_key not in {"user_prompt_submit", "stop"} and matcher is not None:
        if not isinstance(matcher, str):
            raise _InspectionError("stale", "Codex hook matcher is not a string")
        identity["matcher"] = matcher
    canonical_text = json.dumps(
        identity,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    # Go's encoding/json always escapes the two JavaScript line separators,
    # even when SetEscapeHTML(false) leaves <, >, and & untouched. Codex uses
    # that serializer for its identity hash, so preserve the distinction for
    # valid Windows paths containing either code point.
    canonical = canonical_text.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029").encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _validate_codex_hook_contract(
    document: dict[str, Any],
    contract_id: str,
    config_path: str,
) -> None:
    """Require the complete installed Codex matrix and native trust evidence.

    Setup deliberately renders the current ten-row registration on every
    supported version. Older clients expose only the contract-tier subset at
    runtime, but keeping the installed superset makes upgrades deterministic.
    Codex 0.129+ understands ``hooks.state``; for those tiers Doctor also
    reproduces the vendor's positional hash contract instead of merely checking
    that some state value exists.
    """

    hooks = document.get("hooks")
    if not isinstance(hooks, dict):
        raise _InspectionError("missing", "hook registration has no hooks table")
    state = hooks.get("state")
    if contract_id in _CODEX_TRUSTED_CONTRACTS and not isinstance(state, dict):
        raise _InspectionError("stale", "Codex hook trust state is missing or malformed")

    key_source = _codex_hook_state_key_source(config_path)
    managed_commands: list[str] = []
    expected_events = set(_CODEX_HOOK_SPECS)
    for event, (event_key, expected_matcher, expected_timeout) in _CODEX_HOOK_SPECS.items():
        raw_groups = hooks.get(event)
        if not isinstance(raw_groups, list):
            raise _InspectionError("stale", f"Codex hook contract is missing {event}")
        owned: list[tuple[int, int, dict[str, Any], dict[str, Any], str]] = []
        for group_index, group in enumerate(raw_groups):
            if not isinstance(group, dict):
                continue
            handlers = group.get("hooks")
            if not isinstance(handlers, list):
                continue
            for handler_index, hook in enumerate(handlers):
                if not isinstance(hook, dict):
                    continue
                command = hook.get("command_windows")
                if not isinstance(command, str) or not command.strip():
                    command = hook.get("command")
                if not isinstance(command, str) or not command.strip():
                    continue
                if _managed_hook_command(command, "codex"):
                    owned.append((group_index, handler_index, group, hook, command))
        if len(owned) != 1:
            raise _InspectionError(
                "stale",
                f"Codex hook contract has {len(owned)} DefenseClaw handlers for {event}; expected exactly one",
            )

        group_index, handler_index, group, hook, command = owned[0]
        if hook.get("type") != "command":
            raise _InspectionError("stale", f"Codex {event} handler type is not command")
        generic_command = hook.get("command")
        windows_command = hook.get("command_windows")
        if (
            not isinstance(generic_command, str)
            or not generic_command.strip()
            or not isinstance(windows_command, str)
            or not windows_command.strip()
            or generic_command != windows_command
        ):
            raise _InspectionError(
                "stale",
                f"Codex {event} generic and native commands are not byte-identical",
            )
        async_value = hook.get("async", False)
        if type(async_value) is not bool or async_value:
            raise _InspectionError("stale", f"Codex {event} enforcement handler is asynchronous")
        if hook.get("statusMessage") is not None:
            raise _InspectionError("stale", f"Codex {event} has an unexpected statusMessage")
        actual_matcher = group.get("matcher")
        if actual_matcher != expected_matcher:
            raise _InspectionError(
                "stale",
                f"Codex {event} matcher is {actual_matcher!r}; expected {expected_matcher!r}",
            )
        timeout = hook.get("timeout")
        if type(timeout) is not int or timeout != expected_timeout:
            raise _InspectionError(
                "stale",
                f"Codex {event} timeout is {timeout!r}; expected {expected_timeout}",
            )
        current_hash = _codex_command_hook_hash(event_key, actual_matcher, hook)
        if contract_id in _CODEX_TRUSTED_CONTRACTS:
            key = f"{key_source}:{event_key}:{group_index}:{handler_index}"
            trust = state.get(key) if isinstance(state, dict) else None
            if not isinstance(trust, dict):
                raise _InspectionError("stale", f"Codex {event} trust state is missing")
            enabled = trust.get("enabled", True)
            if type(enabled) is not bool or not enabled:
                raise _InspectionError("stale", f"Codex {event} trust state is disabled")
            if trust.get("trusted_hash") != current_hash:
                raise _InspectionError("stale", f"Codex {event} trust state does not match its native handler")
        managed_commands.append(command)

    for event, raw_groups in hooks.items():
        if event == "state" or event in expected_events or not isinstance(raw_groups, list):
            continue
        for group in raw_groups:
            handlers = group.get("hooks") if isinstance(group, dict) else None
            if not isinstance(handlers, list):
                continue
            for hook in handlers:
                if not isinstance(hook, dict):
                    continue
                command = hook.get("command_windows") or hook.get("command")
                if isinstance(command, str) and _managed_hook_command(command, "codex"):
                    raise _InspectionError("stale", f"Codex has an unexpected DefenseClaw handler for {event}")

    if len(set(managed_commands)) != 1:
        raise _InspectionError("stale", "DefenseClaw Codex hook entries use inconsistent commands")


def _commands_from_hooks(
    document: dict[str, Any],
    connector: str,
    *,
    claude_managed_settings_paths: tuple[str, ...] | None = None,
) -> list[str]:
    """Extract managed commands after validating connector-specific policy."""
    if connector == "claudecode":
        _validate_claude_policy(document, claude_managed_settings_paths)
    hooks = document.get("hooks")
    if not isinstance(hooks, dict):
        raise _InspectionError("missing", "hook registration has no hooks table")
    if connector == "codex":
        features = document.get("features")
        if isinstance(features, dict) and features.get("hooks") is False:
            raise _InspectionError("malformed", "Codex features.hooks is explicitly disabled")
    commands: list[str] = []
    command_entries: list[tuple[str, dict[str, Any], dict[str, Any], str]] = []
    malformed_entry = False
    for event, entries in hooks.items():
        if event == "state":
            continue
        if not isinstance(entries, list):
            malformed_entry = True
            continue
        for entry in entries:
            nested = entry.get("hooks") if isinstance(entry, dict) else None
            if not isinstance(nested, list):
                malformed_entry = True
                continue
            for hook in nested:
                command = None
                if isinstance(hook, dict):
                    command = hook.get("command_windows") if connector == "codex" else None
                    if not isinstance(command, str) or not command.strip():
                        command = hook.get("command")
                if isinstance(command, str) and command.strip():
                    args = hook.get("args", None)
                    if "args" in hook:
                        if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
                            malformed_entry = True
                            continue
                        # Claude Code exec form stores the executable and argv
                        # separately. Reconstruct only for passive validation;
                        # Doctor never launches the registered command.
                        command = subprocess.list2cmdline([command, *args])
                    command = command.strip()
                    commands.append(command)
                    command_entries.append((event, entry, hook, command))
                else:
                    malformed_entry = True
    if malformed_entry and not commands:
        raise _InspectionError("malformed", "hook registration contains malformed command entries")
    if not commands:
        raise _InspectionError("missing", "hook registration contains no command entries")
    managed = [entry[3] for entry in command_entries if _managed_hook_command(entry[3], connector)]
    if not managed:
        raise _InspectionError("foreign", "hook registration contains commands, but none target DefenseClaw")
    unique = set(managed)
    if len(unique) != 1:
        raise _InspectionError("malformed", "DefenseClaw hook entries use inconsistent commands")
    return managed


def _handler_command_line(handler: dict[str, Any], connector: str, *, windows: bool) -> str:
    command = handler.get("command_windows") if connector == "codex" and windows else handler.get("command")
    if not isinstance(command, str) or not command.strip():
        raise _InspectionError("malformed", f"{connector} handler has no executable command")
    args = handler.get("args")
    if "args" in handler:
        if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
            raise _InspectionError("malformed", f"{connector} handler has malformed args")
        command = subprocess.list2cmdline([command, *args])
    return command.strip()


def _handler_targets_defenseclaw(handler: Any, connector: str) -> bool:
    if not isinstance(handler, dict):
        return False
    candidates = []
    for key in ("command_windows", "command") if connector == "codex" else ("command",):
        value = handler.get(key)
        if isinstance(value, str) and value.strip():
            candidates.append(value.strip())
    for command in candidates:
        lowered_command = command.casefold()
        if "defenseclaw-hook" in lowered_command or "defenseclaw-gateway" in lowered_command:
            return True
        if connector == "claudecode" and "args" in handler:
            args = handler.get("args")
            if isinstance(args, list) and all(isinstance(arg, str) for arg in args):
                command = subprocess.list2cmdline([command, *args])
        try:
            target, _args, _kind = _command_target(command, connector)
        except _InspectionError:
            continue
        if ntpath.basename(target).casefold() in {
            "defenseclaw-hook.exe",
            "defenseclaw-hook.cmd",
            "defenseclaw-hook.ps1",
            "defenseclaw-gateway.exe",
            "defenseclaw-gateway.cmd",
            "defenseclaw-gateway.ps1",
        }:
            return True
    legacy = "codex-hook.sh" if connector == "codex" else "claude-code-hook.sh"
    return any(legacy in command for command in candidates)


def _codex_normalized_source(config_path: str) -> str:
    source = os.path.abspath(config_path)
    for prefix in ("\\\\?\\UNC\\", "\\\\.\\UNC\\"):
        if source.startswith(prefix):
            return "\\\\" + source[len(prefix) :]
    for prefix in ("\\\\?\\", "\\\\.\\"):
        if source.startswith(prefix):
            candidate = source[len(prefix) :]
            if re.match(r"^[A-Za-z]:[\\/]", candidate):
                return candidate
    return source


def _codex_trusted_hash(event_key: str, matcher: Any, handler: dict[str, Any]) -> str:
    if handler.get("type") != "command":
        raise _InspectionError("malformed", "Codex DefenseClaw handler type is not command")
    selected = handler.get("command_windows") or handler.get("command")
    if not isinstance(selected, str) or not selected.strip():
        raise _InspectionError("malformed", "Codex DefenseClaw handler has no Windows command")
    timeout = handler.get("timeout", 600)
    if type(timeout) is not int or timeout < 0:
        raise _InspectionError("malformed", "Codex DefenseClaw handler timeout is invalid")
    timeout = max(timeout, 1)
    asynchronous = handler.get("async", False)
    if type(asynchronous) is not bool:
        raise _InspectionError("malformed", "Codex DefenseClaw handler async is not boolean")
    normalized_handler: dict[str, Any] = {
        "type": "command",
        "command": selected,
        "timeout": timeout,
        "async": asynchronous,
    }
    if "statusMessage" in handler:
        status = handler["statusMessage"]
        if not isinstance(status, str):
            raise _InspectionError("malformed", "Codex DefenseClaw statusMessage is not a string")
        normalized_handler["statusMessage"] = status
    identity: dict[str, Any] = {"event_name": event_key, "hooks": [normalized_handler]}
    if event_key not in {"user_prompt_submit", "stop"} and matcher is not None:
        if not isinstance(matcher, str):
            raise _InspectionError("malformed", "Codex DefenseClaw matcher is not a string")
        identity["matcher"] = matcher
    canonical_text = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    canonical = canonical_text.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029").encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _validate_codex_hook_matrix(document: dict[str, Any], config_path: str) -> int:
    hooks = document.get("hooks")
    if not isinstance(hooks, dict):
        raise _InspectionError("missing", "Codex hook registration has no hooks table")
    state = hooks.get("state")
    if not isinstance(state, dict):
        raise _InspectionError("stale", "Codex hook registration has no trusted hooks.state table")

    generic_commands: set[str] = set()
    windows_commands: set[str] = set()
    source = _codex_normalized_source(config_path)
    count = 0
    for event, (event_key, expected_matcher, expected_timeout) in _CODEX_REQUIRED_HOOKS.items():
        groups = hooks.get(event)
        if not isinstance(groups, list):
            raise _InspectionError("missing", f"Codex DefenseClaw hook event {event} is missing")
        owned: list[tuple[int, int, dict[str, Any], dict[str, Any]]] = []
        for group_index, group in enumerate(groups):
            if not isinstance(group, dict):
                continue
            handlers = group.get("hooks")
            if not isinstance(handlers, list):
                continue
            for handler_index, handler in enumerate(handlers):
                if _handler_targets_defenseclaw(handler, "codex"):
                    owned.append((group_index, handler_index, group, handler))
        if len(owned) != 1:
            raise _InspectionError(
                "stale",
                f"Codex event {event} has {len(owned)} DefenseClaw handlers; expected exactly one",
            )
        group_index, handler_index, group, handler = owned[0]
        if handler.get("type") != "command":
            raise _InspectionError("malformed", f"Codex event {event} handler type is not command")
        matcher = group.get("matcher") if "matcher" in group else None
        if matcher != expected_matcher:
            raise _InspectionError(
                "stale",
                f"Codex event {event} matcher is {matcher!r}; expected {expected_matcher!r}",
            )
        timeout = handler.get("timeout")
        if type(timeout) is not int or timeout != expected_timeout:
            raise _InspectionError(
                "stale",
                f"Codex event {event} timeout is {timeout!r}; expected {expected_timeout}",
            )
        if handler.get("async", False) is not False:
            raise _InspectionError("stale", f"Codex event {event} is asynchronous and cannot enforce policy")
        if "statusMessage" in handler or "status_message" in handler:
            raise _InspectionError("stale", f"Codex event {event} has an unexpected status message")

        generic = _handler_command_line(handler, "codex", windows=False)
        windows_command = _handler_command_line(handler, "codex", windows=True)
        for label, command in (("generic", generic), ("Windows", windows_command)):
            target, _args, _kind = _command_target(command, "codex")
            if ntpath.basename(target).casefold() not in {
                "defenseclaw-hook",
                "defenseclaw-hook.exe",
                "defenseclaw-hook.cmd",
                "defenseclaw-gateway",
                "defenseclaw-gateway.exe",
                "defenseclaw-gateway.cmd",
            }:
                raise _InspectionError(
                    "stale",
                    f"Codex event {event} {label} fallback is not the native DefenseClaw hook runtime",
                )
        generic_commands.add(generic)
        windows_commands.add(windows_command)

        key = f"{source}:{event_key}:{group_index}:{handler_index}"
        trust = state.get(key)
        if not isinstance(trust, dict):
            raise _InspectionError("stale", f"Codex event {event} trust state is missing: {key}")
        if trust.get("enabled") is False:
            raise _InspectionError("stale", f"Codex event {event} is disabled in trust state")
        expected_hash = _codex_trusted_hash(event_key, matcher, handler)
        if trust.get("trusted_hash") != expected_hash:
            raise _InspectionError("stale", f"Codex event {event} is not trusted for its current definition")
        count += 1

    if len(generic_commands) != 1 or len(windows_commands) != 1:
        raise _InspectionError("stale", "Codex DefenseClaw hook events use inconsistent command identities")

    for event, groups in hooks.items():
        if event == "state" or event in _CODEX_REQUIRED_HOOKS or not isinstance(groups, list):
            continue
        if any(
            _handler_targets_defenseclaw(handler, "codex")
            for group in groups
            if isinstance(group, dict)
            for handler in (group.get("hooks") if isinstance(group.get("hooks"), list) else [])
        ):
            raise _InspectionError("stale", f"unexpected Codex event {event} contains a DefenseClaw handler")
    return count


def _validate_claude_hook_matrix(document: dict[str, Any]) -> int:
    hooks = document.get("hooks")
    if not isinstance(hooks, dict):
        raise _InspectionError("missing", "Claude Code hook registration has no hooks table")
    commands: set[str] = set()
    count = 0
    for event, (expected_matcher, expected_timeout) in _CLAUDE_REQUIRED_HOOKS.items():
        groups = hooks.get(event)
        if not isinstance(groups, list):
            raise _InspectionError("missing", f"Claude Code DefenseClaw hook event {event} is missing")
        owned: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for group in groups:
            if not isinstance(group, dict):
                continue
            handlers = group.get("hooks")
            if not isinstance(handlers, list):
                continue
            for handler in handlers:
                if _handler_targets_defenseclaw(handler, "claudecode"):
                    owned.append((group, handler))
        if len(owned) != 1:
            raise _InspectionError(
                "stale",
                f"Claude Code event {event} has {len(owned)} DefenseClaw handlers; expected exactly one",
            )
        group, handler = owned[0]
        if handler.get("type") != "command":
            raise _InspectionError("malformed", f"Claude Code event {event} handler type is not command")
        matcher = group.get("matcher") if "matcher" in group else None
        if not _matcher_covers(event, matcher, expected_matcher):
            raise _InspectionError(
                "stale",
                f"Claude Code event {event} matcher {matcher!r} does not cover {expected_matcher!r}",
            )
        timeout = handler.get("timeout")
        if type(timeout) is not int or timeout != expected_timeout:
            raise _InspectionError(
                "stale",
                f"Claude Code event {event} timeout is {timeout!r}; expected {expected_timeout}",
            )
        expected_async = event == "MessageDisplay"
        if handler.get("async", False) is not expected_async:
            raise _InspectionError(
                "stale",
                f"Claude Code event {event} async is {handler.get('async', False)!r}; expected {expected_async}",
            )
        for container, label in ((group, "matcher group"), (handler, "handler")):
            for key in ("asyncRewake", "async_rewake"):
                if container.get(key) is True:
                    raise _InspectionError(
                        "stale",
                        f"Claude Code event {event} {label} sets {key}=true and cannot enforce policy",
                    )
            condition = container.get("if", "")
            if not isinstance(condition, str) or condition:
                raise _InspectionError(
                    "stale",
                    f"Claude Code event {event} {label} has a narrowing if condition",
                )
        command = _handler_command_line(handler, "claudecode", windows=True)
        target, _args, _kind = _command_target(command, "claudecode")
        if ntpath.basename(target).casefold() not in {
            "defenseclaw-hook",
            "defenseclaw-hook.exe",
            "defenseclaw-hook.cmd",
            "defenseclaw-hook.ps1",
        }:
            raise _InspectionError("stale", f"Claude Code event {event} does not use the native hook runtime")
        commands.add(command)
        count += 1
    if len(commands) != 1:
        raise _InspectionError("stale", "Claude Code DefenseClaw hook events use inconsistent commands")
    return count


def _split_windows(command: str) -> list[str]:
    try:
        parts = shlex.split(command, posix=False)
    except ValueError as exc:
        raise _InspectionError("malformed", f"cannot parse registered hook command: {exc}") from exc
    normalized: list[str] = []
    for part in parts:
        if len(part) >= 2 and part[0] == part[-1] and part[0] in {'"', "'"}:
            quote = part[0]
            part = part[1:-1]
            if parts and parts[0] == "&" and quote == "'":
                part = part.replace("''", "'")
        normalized.append(part)
    return normalized


def _command_target(command: str, connector: str) -> tuple[str, list[str], str]:
    value = command.strip()
    prefix = "set NoDefaultCurrentDirectoryInExePath=1&& "
    if value.casefold().startswith("set "):
        if not value.casefold().startswith(prefix.casefold()):
            raise _InspectionError("malformed", "registered hook command has an unsupported environment prefix")
        value = value[len(prefix) :].strip()
    if any(char in value for char in "\r\n\x00|<>"):
        raise _InspectionError("malformed", "registered hook command contains shell control operators")
    parts = _split_windows(value)
    if not parts:
        raise _InspectionError("malformed", "registered hook command is empty")
    call_operator = parts[0] == "&"
    if call_operator:
        parts = parts[1:]
    if not parts:
        raise _InspectionError("malformed", "registered hook command has no target")

    first_base = ntpath.basename(parts[0]).casefold()
    if first_base in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}:
        lowered = [part.casefold() for part in parts]
        if "-encodedcommand" in lowered:
            encoded_index = lowered.index("-encodedcommand")
            if encoded_index + 2 != len(parts):
                raise _InspectionError("malformed", "PowerShell EncodedCommand hook has unsupported launcher arguments")
            if lowered[1:encoded_index] != ["-nologo", "-noprofile", "-noninteractive"]:
                raise _InspectionError("malformed", "PowerShell EncodedCommand hook has unsupported launcher arguments")
            try:
                encoded = base64.b64decode(parts[encoded_index + 1], validate=True)
                if len(encoded) > 16 * 1024 or len(encoded) % 2:
                    raise ValueError("encoded script has invalid size")
                script = encoded.decode("utf-16-le")
            except (binascii.Error, UnicodeError, ValueError) as exc:
                raise _InspectionError("malformed", f"PowerShell EncodedCommand hook is invalid: {exc}") from exc
            match = re.fullmatch(
                r"\$ErrorActionPreference='Stop'; "
                r"\$env:NoDefaultCurrentDirectoryInExePath='1'; "
                r"& '((?:[^']|'')+)' hook --connector " + re.escape(connector) + r"; exit \$LASTEXITCODE",
                script,
            )
            if not match:
                raise _InspectionError("malformed", "PowerShell EncodedCommand hook has an unsupported script body")
            target = match.group(1).replace("''", "'")
            return target, ["hook", "--connector", connector], "direct"
        try:
            file_index = lowered.index("-file")
        except ValueError as exc:
            raise _InspectionError("malformed", "PowerShell hook command must use -File") from exc
        if file_index + 1 >= len(parts):
            raise _InspectionError("malformed", "PowerShell hook command has no script target")
        if lowered[1:file_index] != ["-noprofile", "-noninteractive"]:
            raise _InspectionError("malformed", "PowerShell hook command has unsupported launcher arguments")
        target = parts[file_index + 1]
        args = parts[file_index + 2 :]
        kind = "powershell"
    else:
        target = parts[0]
        args = parts[1:]
        kind = "powershell" if call_operator and ntpath.splitext(target)[1].casefold() == ".ps1" else "direct"
    if args != ["hook", "--connector", connector]:
        if len(args) == 3 and args[:2] == ["hook", "--connector"]:
            raise _InspectionError(
                "foreign",
                f"registered hook command targets connector {args[2]!r}, not {connector!r}",
            )
        raise _InspectionError("malformed", f"registered hook command has unexpected arguments for {connector}")
    return target, args, kind


def _resolve_target(raw_target: str, kind: str, *, search_path: str, pathext: str) -> str | None:
    if kind != "powershell":
        return resolve_windows_command(raw_target, search_path=search_path, pathext=pathext)
    directory, filename = os.path.split(raw_target)
    if not directory and "\\" in raw_target:
        directory, filename = ntpath.split(raw_target)
    if ntpath.splitext(filename)[1].casefold() != ".ps1" or not directory:
        return None
    return _case_insensitive_file(directory, filename)


def _contract_evidence(data_dir: str, connector: str, config_path: str) -> tuple[str, str, str]:
    lock_path = os.path.join(data_dir, "hook_contract_lock.json")
    try:
        with open(lock_path, encoding="utf-8") as handle:
            lock = json.load(handle)
    except FileNotFoundError as exc:
        raise _InspectionError("stale", "hook contract lock is missing") from exc
    except PermissionError as exc:
        raise _InspectionError("access-denied", f"access denied to hook contract lock {lock_path}: {exc}") from exc
    except (OSError, ValueError) as exc:
        raise _InspectionError("stale", f"hook contract lock is unreadable: {exc}") from exc
    entry = (lock.get("connectors") or {}).get(connector) if isinstance(lock, dict) else None
    if not isinstance(entry, dict):
        raise _InspectionError("stale", f"hook contract lock has no {connector} entry")
    contract = str(entry.get("contract_id") or "")
    status = str(entry.get("compatibility_status") or "")
    version = str(entry.get("hook_script_version") or "")
    if contract not in _EXPECTED_CONTRACTS[connector] or status not in {"known", "unversioned"} or not version:
        evidence = f"contract={contract or '?'}, status={status or '?'}, version={version or '?'}"
        raise _InspectionError(
            "stale",
            f"hook contract evidence is stale ({evidence})",
        )
    normalized_agent_version = str(entry.get("normalized_agent_version") or "")
    if status == "known" and not normalized_agent_version:
        raise _InspectionError("stale", "known hook contract evidence has no normalized agent version")
    compatibility = resolve_connector_contract(
        connector,
        normalized_agent_version if status == "known" else "",
    )
    resolved_contract = compatibility.contract.contract_id if compatibility.contract is not None else ""
    if compatibility.status != status or resolved_contract != contract:
        evidence = (
            f"contract={contract or '?'}, status={status or '?'}, agent_version={normalized_agent_version or '?'}"
        )
        raise _InspectionError(
            "stale",
            f"hook contract evidence does not match the recorded agent version ({evidence})",
        )
    locations = entry.get("locations")
    configured = locations.get("hook_config_paths") if isinstance(locations, dict) else None
    if isinstance(configured, list) and configured:
        expected = {os.path.normcase(os.path.realpath(os.path.abspath(str(item)))) for item in configured if item}
        actual = os.path.normcase(os.path.realpath(os.path.abspath(config_path)))
        if actual not in expected:
            raise _InspectionError("stale", "hook contract lock points at a different registration file")
    return f"contract={contract} version={version} status={status}", version, contract


def validate_windows_hook_registration(
    *,
    connector: str,
    config_path: str,
    data_dir: str,
    install_root: str,
    search_path: str,
    pathext: str,
    claude_managed_settings_paths: tuple[str, ...] | None = None,
    inspect_effective_policy: bool = True,
) -> WindowsHookCheck:
    """Return a classified Windows registration and effective-policy result.

    Registered hook commands are never executed. Codex validation may start the
    independently trusted Codex app-server for the bounded policy RPC described
    in the module docstring. Passive UI callers set ``inspect_effective_policy``
    false and surface that policy state as unverified rather than spawning from
    a render path.
    """
    connector = connector.strip().lower()
    command = ""
    target = ""
    raw_target = ""
    try:
        document = _read_config(config_path, connector)
        commands = _commands_from_hooks(
            document,
            connector,
            claude_managed_settings_paths=claude_managed_settings_paths,
        )
        command = commands[0]
        policy_detail = ""
        if connector == "codex":
            if inspect_effective_policy:
                policy_detail = _validate_codex_effective_hook_policy(data_dir, config_path)
        else:
            matrix_entries = _validate_claude_hook_matrix(document)
        raw_target, _args, kind = _command_target(command, connector)
        resolved = _resolve_target(raw_target, kind, search_path=search_path, pathext=pathext)
        if not resolved:
            raise _InspectionError("missing", f"registered hook target cannot be resolved with PATHEXT: {raw_target}")
        target = resolved
        basename = ntpath.basename(resolved).casefold()
        evidence, expected_runtime_version, contract_id = _contract_evidence(data_dir, connector, config_path)
        if basename in {"defenseclaw-gateway.exe", "defenseclaw-gateway.cmd"}:
            _stable_regular_file(resolved, install_root, read_limit=64 * 1024)
            raise _InspectionError("stale", f"registered hook uses the obsolete gateway launcher: {resolved}")
        if connector == "codex":
            matrix_entries = _validate_codex_hook_matrix(document, config_path)
            _validate_codex_hook_contract(document, contract_id, config_path)
        if kind == "powershell":
            if not basename.endswith(".ps1") or basename not in {"defenseclaw-hook.ps1", "defenseclaw-gateway.ps1"}:
                raise _InspectionError("foreign", f"PowerShell hook target is not DefenseClaw-owned: {resolved}")
            body = _stable_regular_file(resolved, install_root, read_limit=64 * 1024)
            marker = _MANAGED_MARKER.search(body.decode("utf-8", errors="replace"))
            if not marker:
                raise _InspectionError(
                    "foreign", f"PowerShell hook target has no DefenseClaw ownership marker: {resolved}"
                )
            if f"v{marker.group(1)}" != expected_runtime_version:
                raise _InspectionError(
                    "stale",
                    f"PowerShell hook target is version v{marker.group(1)}; expected {expected_runtime_version}",
                )
            runtime = "PowerShell"
        elif basename == "defenseclaw-hook.exe":
            header = _stable_regular_file(resolved, install_root, read_limit=2)
            if header != b"MZ":
                raise _InspectionError("foreign", f"registered hook executable is not a Windows PE file: {resolved}")
            runtime = "executable"
        elif basename == "defenseclaw-hook.cmd":
            body = _stable_regular_file(resolved, install_root, read_limit=64 * 1024)
            marker = _MANAGED_MARKER.search(body.decode("utf-8", errors="replace"))
            if not marker:
                raise _InspectionError("foreign", f"CMD hook target has no DefenseClaw ownership marker: {resolved}")
            if f"v{marker.group(1)}" != expected_runtime_version:
                raise _InspectionError(
                    "stale",
                    f"CMD hook target is version v{marker.group(1)}; expected {expected_runtime_version}",
                )
            runtime = "CMD"
        else:
            raise _InspectionError(
                "foreign", f"registered hook target is not the DefenseClaw hook launcher: {resolved}"
            )
        return WindowsHookCheck(
            "healthy",
            f"healthy Windows-native {runtime} registration; entries={matrix_entries}; target={resolved}; {evidence}"
            + (f"; policy={policy_detail}" if policy_detail else ""),
            command,
            resolved,
            raw_target,
        )
    except _InspectionError as exc:
        return WindowsHookCheck(
            exc.state,
            exc.detail if exc.state == "policy-blocked" else _repair_detail(connector, exc.detail),
            command,
            target,
            raw_target,
        )
