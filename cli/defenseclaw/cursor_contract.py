"""Exact, bounded validation for DefenseClaw's Cursor user-hook contract.

Cursor runs every matching hook and merges results in Enterprise > Team >
Project > User order. DefenseClaw owns the ordinary user registration and
validates its mode-matched action/fail-closed or observe/fail-open posture.
Setup readiness and Doctor share this connector-specific validator to avoid
accepting a mere command substring as proof that the complete persisted
contract is current.
"""

from __future__ import annotations

import json
import os
import shlex
import stat
from collections.abc import Iterable
from dataclasses import dataclass

CURSOR_HOOK_EVENTS = (
    "sessionStart",
    "sessionEnd",
    "preToolUse",
    "postToolUse",
    "postToolUseFailure",
    "subagentStart",
    "subagentStop",
    "beforeShellExecution",
    "beforeMCPExecution",
    "afterShellExecution",
    "afterMCPExecution",
    "beforeReadFile",
    "beforeTabFileRead",
    "afterFileEdit",
    "afterTabFileEdit",
    "beforeSubmitPrompt",
    "afterAgentResponse",
    "afterAgentThought",
    "stop",
    "preCompact",
    "workspaceOpen",
)

_MAX_CONFIG_BYTES = 2 * 1024 * 1024
_ENTRY_KEYS = {"type", "command", "timeout", "failClosed"}


@dataclass(frozen=True)
class CursorRegistrationValidation:
    ok: bool
    detail: str
    command: str = ""
    runtime_path: str = ""
    entry_count: int = 0


def split_cursor_hook_command(command: str, *, platform_name: str | None = None) -> list[str]:
    """Split only the narrow command shapes written to Cursor hooks.json."""
    is_windows = (platform_name or os.name) == "nt"
    try:
        parts = shlex.split(command, posix=not is_windows)
    except ValueError:
        return []
    if is_windows:
        if parts and parts[0] == "&":
            parts = parts[1:]
        normalized = []
        for part in parts:
            if len(part) >= 2 and part[0] == part[-1] and part[0] in {"'", '"'}:
                quote = part[0]
                part = part[1:-1]
                if quote == "'":
                    part = part.replace("''", "'")
            normalized.append(part)
        parts = normalized
    return parts


def _read_regular_json(path: str) -> object:
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode):
        raise OSError(f"{path} is not a regular file")
    if info.st_size > _MAX_CONFIG_BYTES:
        raise OSError(f"{path} exceeds the 2 MiB validation limit")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(info, opened):
            raise OSError(f"{path} changed while opening")
        with os.fdopen(fd, encoding="utf-8") as fh:
            fd = -1
            return json.load(fh)
    finally:
        if fd >= 0:
            os.close(fd)


def _normalized(path: str) -> str:
    return os.path.normcase(os.path.abspath(os.path.expanduser(path)))


def _managed_runtime(
    argv: list[str],
    *,
    expected_runtime_paths: set[str] | None = None,
) -> tuple[bool, str]:
    if not argv:
        return False, ""
    target = os.path.expanduser(argv[0])
    basename = os.path.basename(target).lower()
    is_managed_shape = basename in {"cursor-hook.sh", "cursor-hook.ps1"} and len(argv) == 1
    is_managed_shape = is_managed_shape or (
        basename in {"defenseclaw-hook", "defenseclaw-hook.exe"}
        and argv[1:]
        == [
            "hook",
            "--connector",
            "cursor",
        ]
    )
    # A current contract lock turns the runtime path into the ownership
    # boundary. Cursor preserves foreign hooks, including commands whose leaf
    # happens to be cursor-hook.ps1, so a basename match must not make those
    # registrations managed. The empty-set fallback retains the established
    # offline/legacy validation used before a lock has been published.
    if is_managed_shape and (
        not expected_runtime_paths or _normalized(target) in expected_runtime_paths
    ):
        return True, target
    return False, ""


def validate_cursor_registration(
    path: str,
    *,
    expected_runtime_paths: Iterable[str] = (),
    platform_name: str | None = None,
    require_runtime_markers: bool = True,
    expected_fail_closed: bool = False,
) -> CursorRegistrationValidation:
    """Validate Cursor schema, event coverage, runtime binding, and fail mode."""
    expected_paths = {
        _normalized(str(value)) for value in expected_runtime_paths if str(value).strip()
    }
    try:
        document = _read_regular_json(path)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return CursorRegistrationValidation(False, f"cannot parse configured hook file {path}: {exc}")
    if (
        not isinstance(document, dict)
        or isinstance(document.get("version"), bool)
        or document.get("version") != 1
    ):
        return CursorRegistrationValidation(False, "configured hook file must use Cursor hooks schema version 1")
    hooks = document.get("hooks")
    if not isinstance(hooks, dict):
        return CursorRegistrationValidation(False, "configured hook file has no hooks object")

    expected = set(CURSOR_HOOK_EVENTS)
    managed: list[tuple[str, dict[str, object], str, str]] = []
    malformed_managed: list[str] = []
    for event, entries in hooks.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            command = str(entry.get("command") or "").strip()
            argv = split_cursor_hook_command(command, platform_name=platform_name)
            is_managed, runtime_path = _managed_runtime(
                argv,
                expected_runtime_paths=expected_paths,
            )
            if not is_managed:
                continue
            if set(entry) != _ENTRY_KEYS:
                malformed_managed.append(str(event))
            managed.append((str(event), entry, command, runtime_path))

    if not managed:
        return CursorRegistrationValidation(False, "configured file has no DefenseClaw Cursor command entries")
    unexpected = sorted({event for event, *_rest in managed if event not in expected})
    if unexpected:
        return CursorRegistrationValidation(
            False,
            "DefenseClaw Cursor entries exist under unexpected events: " + ", ".join(unexpected),
        )
    counts = {event: 0 for event in CURSOR_HOOK_EVENTS}
    for event, *_rest in managed:
        counts[event] += 1
    missing = [event for event, count in counts.items() if count == 0]
    duplicate = [event for event, count in counts.items() if count != 1 and count != 0]
    if missing:
        return CursorRegistrationValidation(
            False,
            "configured Cursor hook coverage is incomplete: " + ", ".join(missing),
        )
    if duplicate:
        return CursorRegistrationValidation(
            False,
            "configured Cursor hook entries are duplicated: " + ", ".join(duplicate),
        )
    if malformed_managed:
        return CursorRegistrationValidation(
            False,
            "configured Cursor entries contain fields outside the managed contract: "
            + ", ".join(sorted(set(malformed_managed))),
        )

    invalid = []
    for event, entry, _command, _runtime in managed:
        timeout = entry.get("timeout")
        if (
            entry.get("type") != "command"
            or isinstance(timeout, bool)
            or timeout != 30
            or entry.get("failClosed") is not expected_fail_closed
        ):
            invalid.append(event)
    if invalid:
        return CursorRegistrationValidation(
            False,
            "configured Cursor entries must use type=command, timeout=30 seconds, and "
            f"failClosed={str(expected_fail_closed).lower()}: "
            + ", ".join(sorted(set(invalid))),
        )

    commands = {command for _event, _entry, command, _runtime in managed}
    runtime_values = {
        os.path.abspath(os.path.expanduser(runtime)) for _event, _entry, _command, runtime in managed
    }
    runtimes = {_normalized(runtime) for runtime in runtime_values}
    if len(commands) != 1 or len(runtimes) != 1:
        return CursorRegistrationValidation(False, "DefenseClaw Cursor entries use inconsistent commands")
    command = next(iter(commands))
    runtime_path = next(iter(runtime_values))
    if expected_paths and _normalized(runtime_path) not in expected_paths:
        return CursorRegistrationValidation(
            False,
            "configured Cursor runtime does not match the contract lock",
            command,
        )
    if not os.path.isfile(runtime_path):
        return CursorRegistrationValidation(
            False,
            f"configured Cursor hook runtime is missing: {runtime_path}",
            command,
        )

    is_windows = (platform_name or os.name) == "nt"
    basename = os.path.basename(runtime_path).lower()
    if is_windows and basename != "cursor-hook.ps1":
        return CursorRegistrationValidation(
            False,
            "Cursor on Windows must invoke the managed PowerShell input adapter",
            command,
        )
    if not is_windows and basename not in {"cursor-hook.sh", "defenseclaw-hook"}:
        return CursorRegistrationValidation(False, "Cursor uses an unsupported hook runtime for this host", command)
    if require_runtime_markers:
        markers = ["defenseclaw-managed-hook v8"]
        if basename == "cursor-hook.ps1":
            markers.extend(
                [
                    "--input-file",
                    "defenseclaw-hook.exe",
                    "ProcessStartInfo",
                    "RedirectStandardOutput",
                    "WaitForExit",
                    f"$failClosed = ${str(expected_fail_closed).lower()}",
                ]
            )
        try:
            with open(runtime_path, encoding="utf-8") as fh:
                body = fh.read(512 * 1024 + 1)
        except (OSError, UnicodeError) as exc:
            return CursorRegistrationValidation(False, f"cannot read configured Cursor runtime: {exc}", command)
        if len(body) > 512 * 1024 or any(marker not in body for marker in markers):
            return CursorRegistrationValidation(
                False,
                f"configured Cursor runtime is stale or invalid: {runtime_path}",
                command,
            )

    return CursorRegistrationValidation(
        True,
        "complete action user-hook registration"
        if expected_fail_closed
        else "complete observe user-hook registration",
        command,
        runtime_path,
        len(managed),
    )
