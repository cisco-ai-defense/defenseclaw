# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Passive validation for Windows-native Codex and Claude Code hooks.

This module deliberately never starts a configured command.  Agent hook
configuration is untrusted input, so Doctor only parses the command line and
inspects the resolved launcher and setup evidence on disk.
"""

from __future__ import annotations

import base64
import binascii
import json
import ntpath
import os
import re
import shlex
import stat
import subprocess
import sys
from dataclasses import dataclass
from typing import Any

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib

from defenseclaw.inventory.plugin_identity import is_link_or_reparse

_SAFE_PATHEXT = (".exe", ".cmd")
_MANAGED_MARKER = re.compile(r"(?im)^\s*(?:#|rem\s+)\s*defenseclaw-managed-hook\s+v(\d+)\b")
_EXPECTED_CONTRACT = {
    "codex": "codex-hooks-v1",
    "claudecode": "claudecode-hooks-v1",
}
_CLAUDE_FILE_CHANGED_MATCHER = (
    "CLAUDE.md|.claude/settings.json|.claude/settings.local.json|.mcp.json|.env|.envrc|"
    "package.json|pyproject.toml|go.mod|Cargo.toml|requirements.txt"
)
# Setup only observes initialization and cannot block. WorktreeCreate replaces
# Claude's default git behavior and must create/print a worktree path, so the
# generic security hook must not claim either event.
_CLAUDE_HOOK_MATCHERS = {
    "SessionStart": "startup|resume|clear|compact",
    "InstructionsLoaded": "*",
    "UserPromptSubmit": "",
    "UserPromptExpansion": "",
    "MessageDisplay": "",
    "PreToolUse": "*",
    "PermissionRequest": "*",
    "PostToolUse": "*",
    "PostToolUseFailure": "*",
    "PostToolBatch": "",
    "PermissionDenied": "*",
    "Notification": "*",
    "SubagentStart": "*",
    "SubagentStop": "",
    "TaskCreated": "",
    "TaskCompleted": "",
    "Stop": "",
    "StopFailure": "*",
    "TeammateIdle": "",
    "ConfigChange": "*",
    "CwdChanged": "",
    "FileChanged": _CLAUDE_FILE_CHANGED_MATCHER,
    "WorktreeRemove": "",
    "PreCompact": "*",
    "PostCompact": "*",
    "SessionEnd": "",
    "Elicitation": "*",
    "ElicitationResult": "*",
}
_CLAUDE_EVENTS_WITHOUT_MATCHERS = {
    "UserPromptSubmit",
    "PostToolBatch",
    "Stop",
    "TeammateIdle",
    "TaskCreated",
    "TaskCompleted",
    "WorktreeRemove",
    "CwdChanged",
}
_REPAIR = {
    "codex": "defenseclaw setup codex --yes --restart",
    "claudecode": "defenseclaw setup claude-code --yes --restart",
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


def _matcher_covers(event: str, actual: Any, required: str) -> bool:
    """Report whether a configured matcher covers a required hook matcher."""
    if event in _CLAUDE_EVENTS_WITHOUT_MATCHERS:
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


def _validate_claude_hook_contract(
    managed_entries: list[tuple[str, dict[str, Any], dict[str, Any], str]],
) -> None:
    """Require synchronous, unconditional coverage for every Claude event."""
    covered: set[str] = set()
    rejected: dict[str, str] = {}
    for event, entry, hook, _command in managed_entries:
        required_matcher = _CLAUDE_HOOK_MATCHERS.get(event)
        if required_matcher is None:
            continue
        if hook.get("type") != "command":
            rejected[event] = "handler type is not command"
            continue
        async_value = hook.get("async", False)
        if type(async_value) is not bool or async_value:
            rejected[event] = "handler is asynchronous"
            continue
        async_rewake = hook.get("asyncRewake", False)
        if type(async_rewake) is not bool or async_rewake:
            rejected[event] = "handler uses asynchronous rewake"
            continue
        condition = hook.get("if", "")
        if not isinstance(condition, str) or condition:
            rejected[event] = "handler has a narrowing if condition"
            continue
        if not _matcher_covers(event, entry.get("matcher"), required_matcher):
            rejected[event] = f"matcher {entry.get('matcher')!r} is narrower than {required_matcher!r}"
            continue
        covered.add(event)

    missing = [event for event in _CLAUDE_HOOK_MATCHERS if event not in covered]
    if not missing:
        return
    detail = ", ".join(missing)
    reasons = "; ".join(f"{event}: {rejected[event]}" for event in missing if event in rejected)
    if reasons:
        detail = f"{detail} ({reasons})"
    raise _InspectionError(
        "stale",
        f"Claude Code hook contract is incomplete; missing synchronous broad DefenseClaw registrations for: {detail}",
    )


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
    managed_entries = [entry for entry in command_entries if _managed_hook_command(entry[3], connector)]
    managed = [entry[3] for entry in managed_entries]
    if not managed:
        raise _InspectionError("foreign", "hook registration contains commands, but none target DefenseClaw")
    if connector == "claudecode":
        _validate_claude_hook_contract(managed_entries)
    unique = set(managed)
    if len(unique) != 1:
        raise _InspectionError("malformed", "DefenseClaw hook entries use inconsistent commands")
    return managed


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


def _contract_evidence(data_dir: str, connector: str, config_path: str) -> tuple[str, str]:
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
    if contract != _EXPECTED_CONTRACT[connector] or status not in {"known", "unversioned"} or not version:
        evidence = f"contract={contract or '?'}, status={status or '?'}, version={version or '?'}"
        raise _InspectionError(
            "stale",
            f"hook contract evidence is stale ({evidence})",
        )
    locations = entry.get("locations")
    configured = locations.get("hook_config_paths") if isinstance(locations, dict) else None
    if isinstance(configured, list) and configured:
        expected = {os.path.normcase(os.path.realpath(os.path.abspath(str(item)))) for item in configured if item}
        actual = os.path.normcase(os.path.realpath(os.path.abspath(config_path)))
        if actual not in expected:
            raise _InspectionError("stale", "hook contract lock points at a different registration file")
    return f"contract={contract} version={version} status={status}", version


def validate_windows_hook_registration(
    *,
    connector: str,
    config_path: str,
    data_dir: str,
    install_root: str,
    search_path: str,
    pathext: str,
    claude_managed_settings_paths: tuple[str, ...] | None = None,
) -> WindowsHookCheck:
    """Return a classified, side-effect-free Windows registration result."""
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
        raw_target, _args, kind = _command_target(command, connector)
        resolved = _resolve_target(raw_target, kind, search_path=search_path, pathext=pathext)
        if not resolved:
            raise _InspectionError("missing", f"registered hook target cannot be resolved with PATHEXT: {raw_target}")
        target = resolved
        basename = ntpath.basename(resolved).casefold()
        evidence, expected_runtime_version = _contract_evidence(data_dir, connector, config_path)
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
        elif basename in {"defenseclaw-gateway.exe", "defenseclaw-gateway.cmd"}:
            _stable_regular_file(resolved, install_root, read_limit=64 * 1024)
            raise _InspectionError("stale", f"registered hook uses the obsolete gateway launcher: {resolved}")
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
            f"healthy Windows-native {runtime} registration; entries={len(commands)}; target={resolved}; {evidence}",
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
