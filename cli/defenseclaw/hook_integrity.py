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

"""Drift checks for the generated per-user hook runtime files.

Setup seals each generated hook file's digest into ``hook_contract_lock.json``
and writes a connector-scoped ``.hook-<connector>.token`` that the script
reads. An edited script (an early ``exit 0``) silently disables enforcement,
and a missing token blocks every call; doctor and status report both
(GAP-1141, GAP-1138). Windows runs the native launcher instead, so these
Unix checks are skipped there.
"""

from __future__ import annotations

import base64
import hashlib
import json
import ntpath
import os
import posixpath
import re
import shlex
import stat
import string
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any, NamedTuple

from defenseclaw import codex_toml
from defenseclaw.file_permissions import read_regular_file_no_follow
from defenseclaw.hook_guard_matrix import TOOL_GUARD_HOOKS, unguarded_tool_events

_LOCK_LIMIT = 4 * 1024 * 1024


# The Windows native hook launcher is installed by the installer, not by
# setup, so only the installer can put it back (GAP-0378).
LAUNCHER_REINSTALL_STEP = (
    "run the DefenseClaw installer again the way you installed it (for example: "
    "irm https://github.com/cisco-ai-defense/defenseclaw/releases/latest/download/install.ps1 | iex); "
    "setup cannot recreate the launcher"
)
_LAUNCHER_PROBLEM_PREFIX = "the DefenseClaw hook launcher "
# A launcher path a plain command names: inside double quotes it may hold an
# apostrophe or an ampersand; unquoted it ends at a shell separator. The
# launcher inside a PowerShell bridge is read from its quoted literal instead
# (_powershell_literals), so a path like C:/Users/O'Neil is not cut short.
_WINDOWS_LAUNCHER = re.compile(
    r'"([A-Za-z]:[\\/][^"\r\n]*?defenseclaw-hook\.exe)"|([A-Za-z]:[\\/][^"\'&|<>\r\n]*?defenseclaw-hook\.exe)',
    re.IGNORECASE,
)
_LAUNCHER_LITERAL = re.compile(r"[A-Za-z]:[\\/].*defenseclaw-hook\.exe", re.IGNORECASE | re.DOTALL)
# PowerShell reads the apostrophe and U+2018 to U+201B as single quotes, and
# the renderers double each of them inside a literal (managed.PowerShellLiteral).
_POWERSHELL_QUOTES = "'\u2018\u2019\u201a\u201b"

# Per-user Windows Codex and Devin start this guard program instead of the
# launcher on the events they can block; it starts the defenseclaw-hook.exe
# beside it and answers a block when that launcher cannot start (rel-1-0-6
# GAP-0676). A missing or damaged guard lets those calls run uninspected, so
# doctor and status check the guard itself.
HOOK_GUARD_NAME = "defenseclaw-hook-guard.exe"
LAUNCHER_NAME = "defenseclaw-hook.exe"
_HOOK_GUARD_AGENTS = {"codex": "Codex", "devin": "Devin"}
_HOOK_GUARD_COMMANDS = {
    # windowsCodexGuardedHookCommand: <system>\cmd.exe /d /v:off /c "<guard>" launcher-guard-sibling hook ...
    "codex": re.compile(
        r'/d /v:off /c "([^"\r\n]*[\\/](?i:defenseclaw-hook-guard\.exe))" '
        r"launcher-guard-sibling hook --connector codex(?: |$)"
    ),
    # hookguard/devin.go: '<guard>' launcher-guard-devin <Event> hook --connector devin
    "devin": re.compile(
        r"^'((?:[^'\r\n]|'\\'')*/(?i:defenseclaw-hook-guard\.exe))' "
        r"launcher-guard-devin [A-Za-z0-9._-]+ hook --connector devin$"
    ),
}
# install.ps1 Save-HelperRecoveryCopy records "<sha256>  <name>" lines here.
_BINARY_DIGESTS = ("installer", "binaries.sha256")
_BINARY_DIGESTS_LIMIT = 64 * 1024
_RECORDED_BINARY_SIZE_LIMIT = 512 * 1024 * 1024
_SHA256_HEX = re.compile(r"[0-9a-fA-F]{64}")


def hook_guard_program(connector: str, command: str) -> str:
    """The hook guard a per-user Windows Codex or Devin hook *command* starts, else ""."""

    pattern = _HOOK_GUARD_COMMANDS.get(connector)
    match = pattern.search(command.strip()) if pattern is not None else None
    if match is None:
        return ""
    return match.group(1).replace("'\\''", "'") if connector == "devin" else match.group(1)


def _recorded_binary_digest(data_dir: str, name: str) -> str:
    """The sha256 the installer recorded for the binary *name*, else ""."""

    if not data_dir:
        return ""
    path = os.path.join(data_dir, *_BINARY_DIGESTS)
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return ""
        with open(path, "rb") as stream:
            body = stream.read(_BINARY_DIGESTS_LIMIT + 1)
    except OSError:
        return ""
    if len(body) > _BINARY_DIGESTS_LIMIT:
        return ""
    recorded = ""
    for line in body.decode("utf-8", "replace").splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1] == name and _SHA256_HEX.fullmatch(fields[0]):
            recorded = fields[0].lower()
    return recorded


def _same_object(first: os.stat_result, second: os.stat_result) -> bool:
    """Whether two looks at one path found the same file. No file index on either means nothing to compare."""

    index_a, index_b = getattr(first, "st_ino", 0), getattr(second, "st_ino", 0)
    if not index_a or not index_b:
        return True
    return index_a == index_b and getattr(first, "st_dev", 0) == getattr(second, "st_dev", 0)


def _recorded_match(path: str, recorded: str, before: os.stat_result | None = None) -> bool | None:
    """Whether the file at *path* is the copy whose sha256 the installer *recorded*.

    True when the digests agree, False when they differ. A file larger than the
    installer ever records cannot be that copy, so a size over the limit is a
    mismatch, not a digest that went unchecked. None when no digest can be
    computed: nothing recorded, or the file cannot be read (Defender or a deny
    ACE holding it), which is not a match. The hook guard treats that as no
    proof of damage; the launcher check treats it as a defect.

    ``open`` follows a link and ``fstat`` then describes the link's target, so
    the hashed bytes say nothing about the path. The path is therefore looked
    at again after the hash (*before* is the look that preceded it): it must
    still be a regular file that is no link, and the same file as before. A
    path that changed under the hash is not the recorded copy.
    """

    if not recorded:
        return None
    digest = hashlib.sha256()
    read = 0
    try:
        with open(path, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                return False  # whatever was opened is not a regular file, so not the recorded copy
            while chunk := stream.read(1024 * 1024):
                read += len(chunk)
                if read > _RECORDED_BINARY_SIZE_LIMIT:
                    return False
                digest.update(chunk)
        after = os.lstat(path)
    except OSError:
        return None
    if _is_link(after) or not stat.S_ISREG(after.st_mode):
        return False
    if before is not None and not _same_object(before, after):
        return False
    return digest.hexdigest() == recorded


def _differs_from_recorded(path: str, recorded: str) -> bool:
    """True when the file at *path* is provably not the copy the installer *recorded*."""

    return _recorded_match(path, recorded) is False


def hook_guard_problem(data_dir: str, connector: str, guard: str) -> HookProblem | None:
    """A missing, non-regular or altered hook *guard* of a Codex or Devin entry, else None.

    The gateway puts a missing guard back from the installer copy when it
    starts (per_user_helper_restore.go); it never replaces something at the
    guard path, so a damaged guard needs the installer.
    """

    agent = _HOOK_GUARD_AGENTS.get(connector, connector)
    setup = setup_command(connector)
    subject = f"the DefenseClaw hook guard {guard}"
    try:
        mode = os.lstat(guard).st_mode
    except (FileNotFoundError, NotADirectoryError):
        return HookProblem(
            f"{subject} is missing, so {agent} prompts and tool calls run without DefenseClaw",
            f"run `defenseclaw-gateway restart` to put the guard back from the installer copy, "
            f"or `{setup}` to start the launcher directly",
            blocking=True,
        )
    except OSError:
        return None  # unreadable here is not proof of damage
    if not stat.S_ISREG(mode):
        return HookProblem(
            f"{subject} is not a regular file, so {agent} prompts and tool calls run without DefenseClaw",
            LAUNCHER_REINSTALL_STEP,
            blocking=True,
        )
    recorded = _recorded_binary_digest(data_dir, HOOK_GUARD_NAME)
    if _differs_from_recorded(guard, recorded):
        return HookProblem(
            f"{subject} does not match the copy the installer recorded, "
            f"so {agent} prompts and tool calls may run without DefenseClaw",
            LAUNCHER_REINSTALL_STEP,
            blocking=True,
        )
    return None


def _is_windows() -> bool:
    return os.name == "nt"


class HookProblem(str):
    """A problem sentence that carries the one step that repairs it."""

    repair: str
    blocking: bool

    def __new__(cls, text: str, repair: str, *, blocking: bool = False) -> HookProblem:
        problem = super().__new__(cls, text)
        problem.repair = repair
        problem.blocking = blocking
        return problem


def repair_command(connector: str, problem: str) -> str:
    """The step that repairs *problem*: its own step, the installer for a missing launcher, else setup."""

    own = getattr(problem, "repair", "")
    if own:
        return own
    if problem.startswith(_LAUNCHER_PROBLEM_PREFIX):
        return LAUNCHER_REINSTALL_STEP
    return setup_command(connector)


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for nested in value.values() for item in _strings(nested)]
    if isinstance(value, list):
        return [item for nested in value for item in _strings(nested)]
    return []


_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_REPARSE_TAG_NAME_SURROGATE = 0x20000000  # symbolic links and junctions; not WOF or cloud placeholders
LAUNCHER_UNVERIFIED_SUFFIX = "is not verified: the installer recorded no copy of it to compare with"
_LAUNCHER_UNREADABLE = "cannot be read here, so it cannot be checked against the installer record"


def _is_link(info: os.stat_result) -> bool:
    """Whether *info* describes a link: a symbolic link, or a Windows name-surrogate reparse point.

    A regular Windows file can carry a reparse tag that is not a link (a
    compressed executable, a cloud placeholder); it is still the installed file
    when its digest agrees, so only a name surrogate counts as a link.
    """

    if stat.S_ISLNK(info.st_mode):
        return True
    reparse = getattr(info, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT
    return bool(reparse and getattr(info, "st_reparse_tag", 0) & _REPARSE_TAG_NAME_SURROGATE)


class LauncherHealth(NamedTuple):
    """What one look at a launcher file found: a defect (FAIL), or why it was not verified (WARN)."""

    defect: str = ""
    unverified: str = ""


def _launcher_health(launcher: str, data_dir: str = "") -> LauncherHealth:
    """Look at the launcher file at *launcher* once and say whether it can be the installed one.

    One rule decides it: the launcher is a regular file (not missing, not a
    folder, not a link) whose sha256 is the one the installer recorded for it
    (``installer/binaries.sha256``, next to the guard's). Another program
    under its name, or a truncated copy, differs from the record; nothing
    inside the file is parsed. A file that cannot be inspected or hashed is a
    defect, never a pass: its state is not known, and the same result is
    reported by every caller, so a file that changes between two looks cannot
    be shown as healthy by one of them. Only a launcher with nothing recorded
    to compare with is merely unverified.
    """

    recorded = _recorded_binary_digest(data_dir, LAUNCHER_NAME)
    try:
        info = os.lstat(launcher)
    except (FileNotFoundError, NotADirectoryError):
        return LauncherHealth(defect="is missing")
    except OSError:
        return LauncherHealth(defect=_LAUNCHER_UNREADABLE)
    if _is_link(info):
        return LauncherHealth(defect="is a link, not the installed file")
    if not stat.S_ISREG(info.st_mode):
        return LauncherHealth(defect="is not a regular file")
    if not recorded:
        return LauncherHealth(unverified=LAUNCHER_UNVERIFIED_SUFFIX)
    match = _recorded_match(launcher, recorded, info)
    if match is None:
        return LauncherHealth(defect=_LAUNCHER_UNREADABLE)
    if not match:
        return LauncherHealth(defect="does not match the copy the installer recorded")
    return LauncherHealth()


def _powershell_literals(script: str) -> list[str]:
    """The values of the single-quoted literals of the PowerShell *script*.

    A doubled quote character inside a literal is one character of its
    value, as ``managed.PowerShellLiteralValue`` reads it back.
    """

    values: list[str] = []
    index, end = 0, len(script)
    while index < end:
        if script[index] not in _POWERSHELL_QUOTES:
            index += 1
            continue
        index += 1
        value: list[str] = []
        closed = False
        while index < end:
            char = script[index]
            if char in _POWERSHELL_QUOTES:
                if index + 1 < end and script[index + 1] == char:
                    value.append(char)
                    index += 2
                    continue
                closed = True
                index += 1
                break
            value.append(char)
            index += 1
        if closed:
            values.append("".join(value))
    return values


def _launcher_paths(command: str) -> list[str]:
    """The launcher paths *command* starts: named in it, or in the literals of its encoded script."""

    paths = [match.group(1) or match.group(2) for match in _WINDOWS_LAUNCHER.finditer(command)]
    paths += [
        literal
        for literal in _powershell_literals(_encoded_script(command))
        if _LAUNCHER_LITERAL.fullmatch(literal)
    ]
    return list(dict.fromkeys(paths))


def _windows_hook_programs(cfg: Any, connector: str) -> tuple[list[str], list[str], HookProblem | None]:
    """The launcher files and hook guards the recorded hook files of *connector* start (per-user Windows).

    The third value is the Claude Code guard-chain defect found while reading them, if any.
    """

    if not _is_windows() or str(getattr(cfg, "deployment_mode", "") or "").strip().lower() == "managed_enterprise":
        # Managed installs (Secure Client included) keep their own status.
        return [], [], None
    launchers: list[str] = []
    guards: list[str] = []
    for path in _hook_config_paths(cfg, connector):
        try:
            if not path.is_file() or path.stat().st_size > _CONFIG_LIMIT:
                continue
            document = _load_agent_document(path)
        except (OSError, ValueError):
            continue
        if connector == "claudecode":
            hooks = document.get("hooks") if isinstance(document, dict) else None
            for groups in hooks.values() if isinstance(hooks, dict) else ():
                for group in groups if isinstance(groups, list) else ():
                    handlers = group.get("hooks") if isinstance(group, dict) else None
                    for handler in handlers if isinstance(handlers, list) else ():
                        parts = _claude_chain_wrapper_parts(handler)
                        if parts is not None:
                            _launcher, _inner, guard, approved = parts
                            if not _claude_chain_files_match(guard, approved):
                                return [], [], HookProblem(
                                    f"the Claude Code hook guard {guard} is missing or changed, "
                                    "so the registered hook cannot check events",
                                    "run `defenseclaw setup claude-code --yes`; it restores the hook guard",
                                )
        for value in _strings(document):
            launchers += [launcher for launcher in _launcher_paths(value) if launcher not in launchers]
            guard = hook_guard_program(connector, value)
            if guard and guard not in guards:
                guards.append(guard)
    return launchers, guards, None


class LauncherReport(NamedTuple):
    """The launcher and guard findings of one connector: problems (FAIL), else the first unverified launcher."""

    problems: list[str]
    unverified: str = ""


def hook_launcher_report(cfg: Any, connector: str) -> LauncherReport:
    """Report a Windows hook registration whose native launcher file cannot start.

    An antivirus quarantine or a cleanup tool can remove
    ``defenseclaw-hook.exe``, or a folder, a link or another program can take
    its place; every hook call then fails while status showed the connector
    as running (GAP-0378, GAP-0810). The launcher is read from every string
    of the recorded hook files and from the script of a PowerShell
    -EncodedCommand in it, so the bridges Kiro, Antigravity and the Codex
    fallback register are covered the same as a plain launcher path. Each
    launcher is looked at once (:func:`_launcher_health`) and doctor derives
    its FAIL, WARN and PASS from that one result. A Codex or Devin entry that
    starts the hook guard is reported when the guard is missing, not a
    regular file or not the copy the installer recorded (rel-1-0-6
    GAP-0676).

    A launcher with no recorded digest (an install from before the installer
    recorded it) is not compared: ``unverified`` names it so doctor warns and
    never passes it; the installer again records the digest (GAP-0810).
    """

    launchers, guards, chain_problem = _windows_hook_programs(cfg, connector)
    if chain_problem is not None:
        return LauncherReport([chain_problem])
    data_dir = str(getattr(cfg, "data_dir", "") or "")
    unverified = ""
    for launcher in launchers:
        health = _launcher_health(launcher, data_dir)
        if health.defect:
            return LauncherReport([f"{_LAUNCHER_PROBLEM_PREFIX}{launcher} {health.defect}, so every hook call fails"])
        if health.unverified and not unverified:
            unverified = f"{_LAUNCHER_PROBLEM_PREFIX}{launcher} {health.unverified}"
    for guard in guards:
        problem = hook_guard_problem(data_dir, connector, guard)
        if problem is not None:
            return LauncherReport([problem])
    return LauncherReport([], unverified)


def hook_launcher_problems(cfg: Any, connector: str) -> list[str]:
    """The launcher or guard problems of the registered hooks of *connector* (:func:`hook_launcher_report`)."""

    return hook_launcher_report(cfg, connector).problems


def setup_command(connector: str) -> str:
    """The per-user repair command for *connector*."""

    return f"defenseclaw setup {'claude-code' if connector == 'claudecode' else connector}"


def _hook_token_well_formed(path: Path) -> bool:
    """Whether a connector hook token holds the 64 hex characters the gateway mints."""
    try:
        with path.open("rb") as stream:
            body = stream.read(4097)
    except OSError:
        return True  # unreadable here is not proof of damage; the hook rows report access
    value = body.decode("ascii", "replace").strip()
    return len(body) <= 4096 and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _locked_hook_scripts(cfg: Any, connector: str) -> tuple[list[Path], dict[str, str]]:
    """The hook scripts setup sealed for *connector*, and their digests by file name."""

    data_dir = str(getattr(cfg, "data_dir", "") or "")
    lock_path = Path(data_dir, "hook_contract_lock.json")
    try:
        if not data_dir or lock_path.stat().st_size > _LOCK_LIMIT:
            return [], {}
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return [], {}  # the Hook contract row reports a missing or unreadable lock
    connectors = lock.get("connectors") if isinstance(lock, dict) else None
    entry = connectors.get(connector) if isinstance(connectors, dict) else None
    if not isinstance(entry, dict):
        return [], {}
    locations = entry.get("locations")
    raw_paths = locations.get("hook_script_paths") if isinstance(locations, dict) else None
    scripts = [Path(str(p)) for p in raw_paths if str(p or "").strip()] if isinstance(raw_paths, list) else []

    digests: dict[str, str] = {}
    # v2 locks keep the shared scripts' digests at the root; that copy wins.
    for source in (entry.get("hook_script_digests"), lock.get("shared_hook_script_digests")):
        if isinstance(source, dict):
            digests.update({str(name): str(value) for name, value in source.items()})
    return scripts, digests


def non_executable_hook_scripts(cfg: Any, connector: str) -> list[Path]:
    """Generated hook scripts of *connector* that lost their execute bit (GAP-0101).

    Setup writes them 0o700. Without the owner execute bit the agent reports a
    non-blocking hook error and runs every tool call unguarded. The sourced
    helpers (``_hardening.sh``) are 0o600 by design and are not listed.
    """

    if os.name == "nt":
        return []
    found: list[Path] = []
    for script in _locked_hook_scripts(cfg, connector)[0]:
        if script.suffix != ".sh" or script.name.startswith("_"):
            continue
        try:
            mode = script.stat().st_mode
        except OSError:
            continue
        if stat.S_ISREG(mode) and not mode & stat.S_IXUSR:
            found.append(script)
    return found


def missing_hook_scripts(cfg: Any, connector: str) -> list[Path]:
    """Sealed hook scripts of *connector* that are gone from disk (POSIX), for ``doctor --fix``.

    The gateway renders every generated script, and reseals its digest, each
    time it starts, so a missing file is repaired by the same restart that
    replaces an edited one (p0-round GAP-0402). A link to a gone target is
    reported separately and is not listed here.
    """

    if _is_windows():
        return _windows_missing_hook_files(cfg, connector)
    return [script for script in _locked_hook_scripts(cfg, connector)[0] if not os.path.lexists(script)]


def _windows_missing_hook_files(cfg: Any, connector: str) -> list[Path]:
    """Sealed files of *connector* gone from the data directory's hooks folder (per-user Windows).

    The gateway renders every file of that folder (the .ps1 adapters, the
    scripts and the mode sidecars) each time it starts, so ``doctor --fix``
    repairs a deleted one or a deleted folder with a restart (p0-round
    GAP-0402, L-win-J2-016). The native launcher outside that folder is
    reported by its own row (GAP-0378), and managed installs keep their own
    status.
    """

    if str(getattr(cfg, "deployment_mode", "") or "").strip().lower() == "managed_enterprise":
        return []
    data_dir = str(getattr(cfg, "data_dir", "") or "")
    if not data_dir:
        return []
    hooks = os.path.normcase(os.path.abspath(os.path.join(data_dir, "hooks")))
    return [
        script
        for script in _locked_hook_scripts(cfg, connector)[0]
        if os.path.normcase(os.path.dirname(os.path.abspath(script))) == hooks and not os.path.lexists(script)
    ]


def _moved_install_root(script: Path, data_dir: str) -> str:
    """The old DefenseClaw folder a sealed hook script names, when the install moved.

    Setup seals absolute paths. After an account rename or a home move the
    lock still names the old home, which no longer exists (GAP-0543).
    """

    if not data_dir:
        return ""
    old_root = script.parent.parent
    try:
        script.relative_to(Path(data_dir))
        return ""
    except ValueError:
        pass
    if os.path.lexists(old_root) or not Path(data_dir, "hooks", script.name).exists():
        return ""
    return str(old_root)


_DISABLED_PLACEHOLDER_MARKER = b"# defenseclaw-managed-hook v0 (disabled tombstone)"


def _is_disabled_placeholder(path: Path) -> bool:
    try:
        with path.open("rb") as stream:
            return _DISABLED_PLACEHOLDER_MARKER in stream.read(512)
    except OSError:
        return False


def _trusted_owner_uids() -> set[int]:
    return {os.geteuid(), 0}


def _untrusted_hook_file(connector: str, script: Path) -> HookProblem | str:
    """Why another account can change the generated hook *script* or its folder, or "" (rel-1-0-4 GAP-0600).

    Setup writes the script 0700 in a 0700 folder of this account (or root,
    for a managed install). A script another account owns or may write runs
    whatever that account puts there.
    """

    for item, kind in ((script, "script"), (script.parent, "folder")):
        try:
            info = item.stat()
        except OSError:
            return ""  # the missing and unreadable checks report it
        writable = info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        if info.st_uid in _trusted_owner_uids() and not writable:
            continue
        why = f"is owned by uid {info.st_uid}" if info.st_uid not in _trusted_owner_uids() else (
            f"is writable by other accounts (mode {stat.S_IMODE(info.st_mode):04o})"
        )
        if kind == "script":
            repair = f"run `{setup_command(connector)} --yes`; it writes the hook script again for this account"
        elif info.st_uid in _trusted_owner_uids():
            repair = f"run `chmod go-w {shlex.quote(str(item))}`"
        else:
            repair = f"give {item} back to this account (`chown`), then run `{setup_command(connector)} --yes`"
        return HookProblem(
            f"hook {kind} {item} {why}, so another account can change the hook DefenseClaw runs",
            repair,
        )
    return ""


def _opens_for_read(path: Path) -> bool:
    """Whether this account can open *path* for reading (a held file or a deny ACE cannot)."""

    try:
        with path.open("rb"):
            return True
    except OSError:
        return False


def hook_runtime_problems(cfg: Any, connector: str) -> list[str]:
    """Return short descriptions of drifted hook files for *connector*."""

    scripts, digests = _locked_hook_scripts(cfg, connector)
    if not scripts:
        return []

    from defenseclaw.fail_mode import _sha256_regular_file

    if _is_windows():
        # Windows: the sealed digests of the files setup wrote, the .ps1
        # adapters included. An edited copilot-hook.ps1 failed only the
        # Hook contract row, and doctor --fix said the scripts matched
        # (GAP-1658). The POSIX owner, mode and token checks do not apply.
        missing = _windows_missing_hook_files(cfg, connector)
        if missing:
            # A deleted hooks folder printed a step on each row it tripped
            # (Copilot hooks, Hook contract, Mode); this is the one finding,
            # and doctor --fix renders the folder again (p0-round GAP-0402).
            adapter = next((script for script in missing if script.suffix.lower() == ".ps1"), None)
            if adapter is not None:
                return [
                    f"hook adapter {adapter} is missing, so the agent cannot run it and DefenseClaw is not "
                    "guarding its tool calls"
                ]
            return [f"hook file {missing[0]} is missing; the gateway renders it again when it starts"]
        for script in scripts:
            expected = digests.get(script.name)
            if not expected or not script.is_file():
                continue
            actual = _sha256_regular_file(script)
            if not actual and not script.is_symlink() and not _opens_for_read(script):
                # Defender holding the file, or a deny ACE: not an edit (GAP-0403).
                # A link in place of the script, an oversized file or one that
                # changed during the read is drift that doctor --fix renders
                # again (GAP-2022).
                return [
                    f"hook script {script} cannot be read, so the agent cannot run it and DefenseClaw is not "
                    "guarding its tool calls"
                ]
            if actual != expected:
                return [
                    f"hook script {script} changed since setup (an edit, or a copy from another build; "
                    "it does not match hook_contract_lock.json)"
                ]
        return []

    problems: list[str] = []
    missing = [script for script in scripts if not os.path.lexists(script)]
    if missing:
        # The agent runs a hook it cannot find as a non-blocking error, so the
        # call goes through even when the fail mode is closed (GAP-0542).
        data_dir = str(getattr(cfg, "data_dir", "") or "")
        moved_from = _moved_install_root(missing[0], data_dir)
        if moved_from:
            problems.append(
                f"this install was set up in {moved_from} but now lives in {data_dir} "
                "(the account was renamed or its home moved): the agent hooks run scripts that no longer exist, "
                "so DefenseClaw is not guarding its tool calls"
            )
        else:
            problems.append(
                f"hook script {missing[0]} is missing, so the agent cannot run it and DefenseClaw is not "
                "guarding its tool calls"
            )
    for script in scripts:
        if script in missing:
            continue
        expected = digests.get(script.name)
        if not script.exists():
            # A link to a target that is gone: the agent cannot run it either,
            # so the posture warning must say so (p0 GAP-1384).
            problems.append(
                f"hook script {script} links to a file that is missing, so the agent cannot run it and "
                "DefenseClaw is not guarding its tool calls"
            )
            break
        if expected and not os.access(script, os.R_OK):
            # chmod 000 (an antivirus quarantine, a restored backup): the
            # agent cannot run it, which is not an edit (GAP-0403).
            problems.append(
                f"hook script {script} cannot be read, so the agent cannot run it and DefenseClaw is not "
                "guarding its tool calls"
            )
            break
        if expected and _sha256_regular_file(script) != expected:
            if _is_disabled_placeholder(script):
                # A rollback after a failed gateway start leaves this; the
                # cause is the start, not an edit (GAP-0367).
                problems.append(
                    f"hook script {script} changed since setup: it is the disabled placeholder left when the "
                    "gateway failed to set up this connector (or by a teardown), so its tool calls are not "
                    "checked; see `defenseclaw-gateway status` for the error, then run `defenseclaw-gateway start`"
                )
                break
            problems.append(
                f"hook script {script} changed since setup (an edit, or a copy from another build; "
                "it does not match hook_contract_lock.json)"
            )
            break

    hooks_dir = Path(str(getattr(cfg, "data_dir", "") or ""), "hooks")
    for script in scripts:
        if script in missing or script.parent != hooks_dir:
            continue  # managed plugin artifacts live in the agent's folders
        if untrusted := _untrusted_hook_file(connector, script):
            problems.append(untrusted)
            break

    for script in non_executable_hook_scripts(cfg, connector):
        problems.append(
            f"hook script {script} is not executable, so the agent cannot run it and its tool calls "
            "run unguarded (`defenseclaw doctor --fix` restores mode 0700)"
        )

    token_name = f".hook-{connector}.token"
    for script in scripts:
        if script.suffix != ".sh":
            continue
        try:
            text = script.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if token_name not in text:
            continue
        token_path = script.parent / token_name
        # A connector-scoped script clears any inherited
        # DEFENSECLAW_GATEWAY_TOKEN and reads only this file, so the env var
        # (which doctor and status load from .env) never stands in for it.
        if not token_path.is_file():
            problems.append(f"hook token {token_path} is missing, so every hook call fails")
        elif not _hook_token_well_formed(token_path):
            # An empty or damaged token fails every call too (GAP-1436).
            problems.append(f"hook token {token_path} is empty or damaged, so every hook call fails")
        break
    return problems


def unrunnable_hook_problem(cfg: Any, connector: str) -> str:
    """The first reason the agent cannot run the hooks of *connector*, or "".

    A hook the agent cannot start (missing, unreadable, not executable, or
    left at the old home after a move) is a non-blocking error to the agent,
    so the fail mode never applies (GAP-0403, GAP-0542). A hook entry edited
    so the agent skips it for a tool call (disabled, narrowed matcher, other
    type, short timeout) is the same (rel-1-0-4 GAP-0538).
    """

    for problem in hook_runtime_problems(cfg, connector):
        if "cannot run it" in problem or "no longer exist" in problem:
            return problem
    switched_off = agent_hook_switch_problems(cfg, connector) or unguarded_tool_call_hooks(cfg, connector)
    return switched_off[0] if switched_off else ""


_CONFIG_LIMIT = 2 * 1024 * 1024


# Agent config formats whose hook registrations are read from the decoded
# document (:func:`_hook_section`).
_STRUCTURED_SUFFIXES = (".json", ".toml", ".yaml", ".yml")

# Antigravity keeps each hook set under its own top-level name; Setup writes
# DefenseClaw's as defenseclaw-antigravity-<event> (antigravityOwnedHookKeys in
# internal/gateway/connector/hook_only.go). Devin's project hooks.v1.json holds
# the event map at its root (devinHooksObject in internal/gateway/connector/devin.go).
_ANTIGRAVITY_HOOK_KEY_PREFIX = "defenseclaw-antigravity-"
_DEVIN_PROJECT_HOOKS_FILE = "hooks.v1.json"

# A PowerShell -EncodedCommand (or an abbreviation of it) and its base64
# script: the per-user Windows hook command names the launcher only inside it.
_ENCODED_SCRIPT = re.compile(r"(?i)(?:^|\s)[-/]e[a-z]*\s+([A-Za-z0-9+/]{64,}={0,2})(?=\s|$)")


def _hook_section(document: Any, path: Path) -> list[Any] | None:
    """The hook registrations of the decoded agent config *path*, or None.

    Most agents keep them in a ``hooks`` section; Codex keeps its hook trust
    state beside the events (``[hooks.state]``), which registers nothing.
    Antigravity's hooks.json has a top-level key per hook set and Devin's
    project hooks.v1.json is the event map itself, so reading only a
    ``hooks`` key called a clean Setup of either unregistered (GAP-0489).
    """

    if not isinstance(document, dict):
        return None
    if path.name.lower() == _DEVIN_PROJECT_HOOKS_FILE:
        return [document]
    sections: list[Any] = []
    hooks = document.get("hooks")
    if isinstance(hooks, dict):
        sections.append({key: value for key, value in hooks.items() if key != "state"})
    elif isinstance(hooks, list):
        sections.append(hooks)
    sections.extend(
        value
        for key, value in document.items()
        if isinstance(key, str) and key.startswith(_ANTIGRAVITY_HOOK_KEY_PREFIX)
    )
    return sections or None


# Per-user Windows Claude Code registers its launcher through cmd.exe so a
# missing launcher blocks instead of failing open (GAP-1091). Keep this
# sentence and argv identical to internal/gateway/connector/claudecode_launcher_guard.go.
CLAUDE_LAUNCHER_GUARD_WORDS = (
    "DefenseClaw blocked this: its Claude Code hook launcher is missing. "
    "Run the DefenseClaw installer again to repair it."
).split()


# The per-user Windows direct handler runs the installed full hook as this
# guard instead of cmd.exe, which Cursor's argument-free import of the hook
# could not run (GAP-1011). Keep it identical to ClaudeCodeLauncherGuardArgv.
CLAUDE_LAUNCHER_GUARD_SUBCOMMAND = "launcher-guard"
_CLAUDE_WRAPPED_GUARD_SUBCOMMAND = "launcher-guard-wrapped"
_CLAUDE_WRAPPED_EXIT_BASE = 65536
_CLAUDE_NEUTRAL_EVENTS = frozenset({"Stop", "SubagentStop", "TeammateIdle", "StopFailure", "SessionEnd"})
_CLAUDE_CHAIN_WARNING = (
    "DefenseClaw could not start its Claude Code hook guard. "
    "Run the DefenseClaw installer again to repair it."
).split()


# The managed standalone wrapper names the missing guard and the repair that
# can restore it: Setup /repair, the only route that carries the guard payload.
# Keep it identical to claudeManagedGuardMissingWords in
# internal/gateway/connector/claudecode_chain.go.
_CLAUDE_MANAGED_GUARD_MISSING = (
    "DefenseClaw could not start its Claude Code hook guard defenseclaw-hook-guard.exe "
    "because it is missing from the install folder. "
    "Run DefenseClawSetup-Enterprise-Standalone-x64.exe /repair "
    "as an administrator to restore it. "
    "Setup is not installed on this computer: use the copy in your MDM package or the release download."
).split()


def _claude_wrapper_safe(path: str) -> bool:
    return (
        bool(path)
        and path.strip() == path
        and not any(ch in path for ch in '"%!\r\n')
        and (ntpath.isabs(path) or os.path.isabs(path))
        and (any(ch in path for ch in " \t") or not any(ch in path for ch in "&|<>^(),;="))
    )


def _claude_chain_wrapper_words(
    compare: str, guard: str, approved: str, launcher: str, event: str, unavailable_open: bool = False,
) -> list[str]:
    fail_code = "1" if event in _CLAUDE_NEUTRAL_EVENTS or unavailable_open else "2"
    warning = ["echo", *_CLAUDE_CHAIN_WARNING, "1>&2", "&", "exit", "/b", fail_code]
    mode = ["--unavailable-mode", "open"] if unavailable_open else []
    return [
        "/d", "/v:on", "/c", "if", "not", "exist", guard, "(", *warning, ")",
        "&", compare, "/b", guard, approved, ">nul", "2>&1", "||", "(", *warning, ")",
        "&", guard, _CLAUDE_WRAPPED_GUARD_SUBCOMMAND, launcher, "hook", "--connector", "claudecode",
        "--event", event, *mode,
        "&", "set", "dc_hook_status=!errorlevel!",
        "&", "if", "!dc_hook_status!", "equ", "0", "exit", "/b", "0",
        "&", "if", "!dc_hook_status!", "equ", "2", "exit", "/b", "2",
        "&", "if", "!dc_hook_status!", "geq", str(_CLAUDE_WRAPPED_EXIT_BASE + 1),
        "if", "!dc_hook_status!", "leq", str(2 * _CLAUDE_WRAPPED_EXIT_BASE - 1),
        "(", "set", "/a", f"dc_hook_result=!dc_hook_status!-{_CLAUDE_WRAPPED_EXIT_BASE}", ">nul",
        "&", "exit", "/b", "!dc_hook_result!", ")", "&", *warning,
    ]


def _claude_chain_wrapper_parts(handler: Any) -> tuple[str, list[str], str, str] | None:
    if not isinstance(handler, dict):
        return None
    command, args = handler.get("command"), handler.get("args")
    if not isinstance(command, str) or not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        return None
    system_root = os.environ.get("SystemRoot") or "C:\\Windows"
    processor = ntpath.join(system_root, "System32", "cmd.exe")
    compare = ntpath.join(system_root, "System32", "fc.exe")
    if ntpath.normcase(ntpath.normpath(command)) != ntpath.normcase(ntpath.normpath(processor)):
        return None
    if len(args) < 30 or args[:6] != ["/d", "/v:on", "/c", "if", "not", "exist"]:
        return None
    guard = args[6]
    if not _claude_wrapper_safe(guard) or ntpath.basename(guard).lower() != "defenseclaw-hook-guard.exe":
        return None
    approved = next(
        (args[i + 3] for i in range(8, len(args) - 3)
         if ntpath.normcase(ntpath.normpath(args[i])) == ntpath.normcase(ntpath.normpath(compare))
         and args[i + 1:i + 3] == ["/b", guard]),
        "",
    )
    if not _claude_wrapper_safe(approved) or ntpath.basename(approved).lower() != "defenseclaw-hook-guard.approved":
        return None
    for i in range(len(args) - 8):
        if args[i:i + 2] != [guard, _CLAUDE_WRAPPED_GUARD_SUBCOMMAND]:
            continue
        launcher = args[i + 2]
        inner = args[i + 3:i + 6]
        if not _claude_guardable_hook_executable(launcher) or inner != ["hook", "--connector", "claudecode"]:
            return None
        if args[i + 6] != "--event":
            return None
        event = args[i + 7]
        if not event or len(event) > 64 or not event.isascii() or not event.isalnum():
            return None
        unavailable_open = args[i + 8:i + 10] == ["--unavailable-mode", "open"]
        if args == _claude_chain_wrapper_words(compare, guard, approved, launcher, event, unavailable_open):
            return launcher, inner, guard, approved
    return None


def _claude_managed_wrapper_words(guard: str, launcher: str, event: str) -> list[str]:
    fail_code = "1" if event in _CLAUDE_NEUTRAL_EVENTS else "2"
    missing = ["echo", *_CLAUDE_MANAGED_GUARD_MISSING, "1>&2", "&", "exit", "/b", fail_code]
    warning = ["echo", *_CLAUDE_CHAIN_WARNING, "1>&2", "&", "exit", "/b", fail_code]
    return [
        "/d", "/v:on", "/c", "if", "not", "exist", guard, "(", *missing, ")",
        "&", guard, _CLAUDE_WRAPPED_GUARD_SUBCOMMAND, launcher,
        "hook", "--connector", "claudecode", "--enterprise-managed", "--event", event,
        "&", "set", "dc_hook_status=!errorlevel!",
        "&", "if", "!dc_hook_status!", "equ", "0", "exit", "/b", "0",
        "&", "if", "!dc_hook_status!", "equ", "2", "exit", "/b", "2",
        "&", "if", "!dc_hook_status!", "geq", str(_CLAUDE_WRAPPED_EXIT_BASE + 1),
        "if", "!dc_hook_status!", "leq", str(2 * _CLAUDE_WRAPPED_EXIT_BASE - 1),
        "(", "set", "/a", f"dc_hook_result=!dc_hook_status!-{_CLAUDE_WRAPPED_EXIT_BASE}", ">nul",
        "&", "exit", "/b", "!dc_hook_result!", ")", "&", *warning,
    ]


def _claude_managed_wrapper_parts(handler: Any) -> tuple[str, list[str]] | None:
    if not isinstance(handler, dict):
        return None
    command, args = handler.get("command"), handler.get("args")
    if not isinstance(command, str) or not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        return None
    system_root = os.environ.get("SystemRoot") or "C:\\Windows"
    processor = ntpath.join(system_root, "System32", "cmd.exe")
    if ntpath.normcase(ntpath.normpath(command)) != ntpath.normcase(ntpath.normpath(processor)):
        return None
    if len(args) < 25 or args[:6] != ["/d", "/v:on", "/c", "if", "not", "exist"]:
        return None
    guard = args[6]
    for index in range(8, len(args) - 8):
        if args[index:index + 2] != [guard, _CLAUDE_WRAPPED_GUARD_SUBCOMMAND]:
            continue
        launcher = args[index + 2]
        if not _claude_wrapper_safe(launcher) or not _claude_guardable_hook_executable(launcher):
            continue
        expected_guard = ntpath.join(ntpath.dirname(launcher), "defenseclaw-hook-guard.exe")
        if ntpath.normcase(ntpath.normpath(guard)) != ntpath.normcase(ntpath.normpath(expected_guard)):
            continue
        event = args[index + 8]
        if not event or len(event) > 64 or not event.isascii() or not event.isalnum():
            continue
        if args == _claude_managed_wrapper_words(guard, launcher, event):
            return launcher, ["hook", "--connector", "claudecode", "--enterprise-managed"]
    return None


def _claude_chain_files_match(guard: str, approved: str) -> bool:
    pair_dir = os.path.dirname(guard)
    generation = os.path.basename(pair_dir)
    if (not generation.startswith("chain-") or not generation[6:].isascii()
            or not generation[6:].isalnum()
            or os.path.normcase(os.path.dirname(approved)) != os.path.normcase(pair_dir)):
        return False
    record = os.path.join(os.path.dirname(pair_dir), "chain.json")
    try:
        with open(record, "rb") as fh:
            raw = fh.read(64 * 1024 + 1)
        if len(raw) > 64 * 1024:
            return False
        payload = json.loads(raw)
        if payload.get("generation") != generation:
            return False
        digest = payload.get("guard_sha256")
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            return False
        for path in (guard, approved):
            info = os.lstat(path)
            if not stat.S_ISREG(info.st_mode) or info.st_size == 0 or info.st_size > 64 * 1024 * 1024:
                return False
            hasher = hashlib.sha256()
            with open(path, "rb") as fh:
                for block in iter(lambda: fh.read(1024 * 1024), b""):
                    hasher.update(block)
            if hasher.hexdigest() != digest:
                return False
        return True
    except (OSError, ValueError, AttributeError, TypeError):
        return False


def _claude_guardable_hook_executable(path: str) -> bool:
    return (
        path.strip() == path
        and path != ""
        and not any(ch in path for ch in '"%!\r\n')
        and (ntpath.isabs(path) or os.path.isabs(path))
        and ntpath.basename(path).lower() == "defenseclaw-hook.exe"
    )


# The PreToolUse guard program: the installed full hook of a packaged install,
# the one-line install's GUI-subsystem guard beside its launcher (GAP-2467), or
# the gateway beside the launcher (a repository build). Keep it identical to
# claudeCodePreToolGuardProgram.
_CLAUDE_PRETOOL_GUARD_PROGRAMS = ("defenseclaw-hook.exe", "defenseclaw-hook-guard.exe", "defenseclaw-gateway.exe")


def _claude_pretool_guard_program(path: str) -> bool:
    return (
        path.strip() == path
        and path != ""
        and not any(ch in path for ch in '"%!\r\n')
        and (ntpath.isabs(path) or os.path.isabs(path))
        and ntpath.basename(path).lower() in _CLAUDE_PRETOOL_GUARD_PROGRAMS
    )


def _claude_pretool_guard_view(handler: dict, command: str, args: list[str]) -> dict | None:
    if len(args) not in (5, 7, 9) or args[0] != CLAUDE_LAUNCHER_GUARD_SUBCOMMAND:
        return None
    if args[2:5] != ["hook", "--connector", "claudecode"]:
        return None
    if len(args) >= 7 and (
        args[5] != "--event" or not args[6] or len(args[6]) > 64 or not args[6].isascii() or not args[6].isalnum()
    ):
        return None
    if len(args) == 9 and args[7:] != ["--unavailable-mode", "open"]:
        return None
    launcher = args[1]
    if not _claude_pretool_guard_program(command) or not _claude_guardable_hook_executable(launcher):
        return None
    if ntpath.normcase(ntpath.normpath(command)) == ntpath.normcase(ntpath.normpath(launcher)):
        return None
    view = dict(handler)
    view["command"] = launcher
    view["args"] = list(args[2:5])
    return view


def claude_launcher_guard_view(handler: Any) -> Any:
    """The exec-form handler a generated launcher guard runs, else *handler* unchanged.

    The guard is the cmd.exe launcher guard or the PreToolUse guard. Doctor's
    hook matrix and the status registration check both read a Claude Code
    handler through this view (GAP-0463).
    """
    if not isinstance(handler, dict):
        return handler
    command, args = handler.get("command"), handler.get("args")
    if not isinstance(command, str) or not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        return handler
    chain = _claude_chain_wrapper_parts(handler)
    if chain is not None:
        launcher, inner, _guard, _approved = chain
        view = dict(handler)
        view["command"], view["args"] = launcher, inner
        return view
    managed = _claude_managed_wrapper_parts(handler)
    if managed is not None:
        launcher, inner = managed
        view = dict(handler)
        view["command"], view["args"] = launcher, inner
        return view
    pretool = _claude_pretool_guard_view(handler, command, args)
    if pretool is not None:
        return pretool
    system_root = os.environ.get("SystemRoot") or "C:\\Windows"
    processor = ntpath.join(system_root, "System32", "cmd.exe")
    if ntpath.normcase(ntpath.normpath(command)) != ntpath.normcase(ntpath.normpath(processor)):
        return handler
    if len(args) < 8 or args[:4] != ["/d", "/c", "if", "exist"] or args[5] != "(" or args[6] != args[4]:
        return handler
    end = next((i for i in range(7, len(args) - 1) if args[i] == ")" and args[i + 1] == "else"), -1)
    if end < 0:
        return handler
    launcher, inner = args[4], args[7:end]
    expected = [
        "/d", "/c", "if", "exist", launcher, "(", launcher, *inner, ")", "else", "(", "echo",
        *CLAUDE_LAUNCHER_GUARD_WORDS, "1>&2", "&", "exit", "/b", "2", ")",
    ]
    if args != expected:
        return handler
    view = dict(handler)
    view["command"] = launcher
    view["args"] = list(inner)
    return view


def hook_handler_command_lines(handler: Any, connector: str) -> list[str]:
    """The command lines one decoded hook handler runs.

    Claude Code's exec form keeps the argv in ``args``, and per-user Windows
    runs the launcher through the cmd.exe guard, so ``command`` is cmd.exe and
    the launcher is named only in ``args``. Reading ``command`` alone made
    status call every hook of a 1.0.1 or later Windows install unregistered
    while doctor, which reads the same view, passed them (GAP-0463).
    """

    if connector == "claudecode":
        handler = claude_launcher_guard_view(handler)
    if not isinstance(handler, dict):
        return []
    args = handler.get("args")
    argv = list(args) if isinstance(args, list) and all(isinstance(arg, str) for arg in args) else None
    lines: list[str] = []
    for key in _HOOK_COMMAND_KEYS:
        value = handler.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        lines.append(subprocess.list2cmdline([value, *argv]) if key == "command" and argv is not None else value)
    return lines


def _hook_command_lines(value: Any, connector: str) -> list[str]:
    """Every command line in a decoded ``hooks`` section, read one handler at a time."""

    if isinstance(value, list):
        return [line for item in value for line in _hook_command_lines(item, connector)]
    if not isinstance(value, dict):
        return []
    found = hook_handler_command_lines(value, connector)
    for key, item in value.items():
        if not (key in _HOOK_COMMAND_KEYS and isinstance(item, str)):
            found.extend(_hook_command_lines(item, connector))
    return found


def _encoded_script(command: str) -> str:
    """The script of a PowerShell -EncodedCommand in *command*, else ""."""

    match = _ENCODED_SCRIPT.search(command)
    if not match:
        return ""
    try:
        return base64.b64decode(match.group(1), validate=True).decode("utf-16-le")
    except (ValueError, UnicodeDecodeError):
        return ""


def _decoded_command(command: str) -> str:
    """*command*, followed by the script of a PowerShell -EncodedCommand in it."""

    script = _encoded_script(command)
    return command + "\n" + script if script else command


def _defenseclaw_hook_command(cfg: Any, connector: str, command: str, *, strict: bool) -> bool:
    """Whether *command* runs a DefenseClaw hook.

    Per-user Unix hooks run a script under this data directory's ``hooks``
    folder (or an edited DefenseClaw entry, which the edited-hook check
    reports). Windows registers the native launcher, and managed installs
    their own runtime: there the command must name DefenseClaw or run a
    script in this data directory's hooks folder (the Windows Copilot
    PowerShell adapter, which names DefenseClaw only when the data directory
    does).
    """

    data_dir = str(getattr(cfg, "data_dir", "") or "")
    roots = dict.fromkeys((data_dir, os.path.realpath(data_dir)))
    hooks_dirs = [os.path.join(root, "hooks") + os.sep for root in roots]
    if strict:
        if any(hooks in command for hooks in hooks_dirs):
            return True
        script_name = HOOK_SCRIPT_NAMES.get(connector, "")
        return bool(script_name and edited_hook_script(command, script_name))
    if "defenseclaw" in _decoded_command(command).lower():
        return True
    lowered = command.casefold()
    return bool(data_dir) and any(hooks.casefold() in lowered for hooks in hooks_dirs)


def _registers_defenseclaw_hooks(cfg: Any, connector: str, path: Path, *, strict: bool) -> bool:
    """Whether the agent config file *path* registers a DefenseClaw hook.

    Setup also writes DefenseClaw text outside the hooks: the OTLP headers and
    resource attributes (``x-defenseclaw-source`` in Claude Code ``env`` and
    the Codex ``[otel]`` exporters), the Codex ``notify`` bridge, an MCP
    server entry. A whole-file match kept a file with no hooks looking
    registered (GAP-1230, GAP-1311), so for JSON, TOML and YAML only a hook
    command in the file's hook registrations (:func:`_hook_section`) counts.
    Other formats (the OpenCode plugin file) are matched as a whole.
    """

    raw = path.read_bytes()
    if path.suffix.lower() not in _STRUCTURED_SUFFIXES:
        return "defenseclaw" in raw.decode("utf-8", errors="replace").lower()
    native = None
    if connector == "claudecode" and strict:
        from defenseclaw.fail_mode import _claude_per_user_native_registration

        native = _claude_per_user_native_registration(cfg)
    try:
        document = _load_agent_document(path, raw)
    except ValueError:
        # A file the parser cannot read is reported by the agent itself;
        # never call it unregistered on that ground alone.
        return native is None and "defenseclaw" in raw.decode("utf-8", errors="replace").lower()
    if native is not None:
        # The native Linux registration has no hooks/ script path. Use the
        # verifier shared with Doctor and fail-mode, which checks the exact
        # executable, argv, required events and synchronous companions.
        from defenseclaw.fail_mode import _claude_native_registration_problem, claude_missing_registration

        return (
            _claude_native_registration_problem(raw.decode("utf-8", errors="replace"), native, str(cfg.data_dir))
            is None
            and claude_missing_registration(cfg, document) is None
        )
    section = _hook_section(document, path)
    if section is None:
        return False
    return any(
        _defenseclaw_hook_command(cfg, connector, command, strict=strict)
        for command in _hook_command_lines(section, connector)
    )


def registers_defenseclaw_hooks(cfg: Any, connector: str, path: str | os.PathLike[str]) -> bool:
    """Whether the agent config file at *path* registers a DefenseClaw hook of this install.

    The one ownership test doctor and status share: a hook command runs a
    script in this data directory's hooks folder (or names DefenseClaw where
    the install registers its launcher), so a custom DEFENSECLAW_HOME with no
    "defenseclaw" in its path counts too (GAP-1882).
    """

    try:
        return _registers_defenseclaw_hooks(cfg, connector, Path(path), strict=_tool_inspection_strict(cfg))
    except (OSError, ValueError, ImportError):
        return False


def _hook_config_paths(cfg: Any, connector: str) -> list[Path]:
    """The agent config files setup recorded hooks in for *connector*."""

    data_dir = str(getattr(cfg, "data_dir", "") or "")
    lock_path = Path(data_dir, "hook_contract_lock.json")
    try:
        if not data_dir or lock_path.stat().st_size > _LOCK_LIMIT:
            return []
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    connectors = lock.get("connectors") if isinstance(lock, dict) else None
    entry = connectors.get(connector) if isinstance(connectors, dict) else None
    locations = entry.get("locations") if isinstance(entry, dict) else None
    raw_paths = locations.get("hook_config_paths") if isinstance(locations, dict) else None
    if not isinstance(raw_paths, list):
        return []
    return [Path(str(raw)) for raw in raw_paths if str(raw or "").strip()]


# Connectors whose per-user Windows registration status reads from Doctor's
# native validator (cmd_doctor._windows_native_hook_check).
_WINDOWS_NATIVE_STATUS_CONNECTORS = frozenset({"claudecode", "copilot"})


def _windows_native_problem(cfg: Any, connector: str) -> HookProblem | None:
    """Doctor's verdict on the Windows registration of *connector* as a problem, or None when healthy."""

    from defenseclaw.commands.cmd_doctor import _windows_native_hook_check

    label = "Claude Code" if connector == "claudecode" else "Copilot"
    try:
        native = _windows_native_hook_check(cfg, connector)
    except Exception as exc:  # noqa: BLE001 - an uninspectable hook is not healthy.
        detail = f"inspection failed: {type(exc).__name__}"
        repair = ""
    else:
        if native.healthy:
            return None
        detail = f"{native.state}: {native.detail}"
        repair = native.repair
    return HookProblem(
        f"Windows {label} hook registration is not current: {detail}",
        repair or f"run `{setup_command(connector)} --yes --restart`",
        blocking=True,
    )


def _scanned_registration_problems(cfg: Any, connector: str) -> list[str]:
    """Report hook config files that no longer register DefenseClaw hooks.

    Setup records the agent config files it registered hooks in
    (``locations.hook_config_paths``). When one of them that exists has lost
    its DefenseClaw hook entries (for example the ``hooks`` key was deleted
    from ``~/.claude/settings.json``, or the Codex hook tables were removed and
    only its ``[otel]`` headers still name DefenseClaw), the agent runs
    unguarded; status says so instead of showing the connector as normal
    (GAP-1230, GAP-1311). Every recorded file is checked; on a managed
    install, whose hooks may sit in one machine layer, one is enough. When
    the entries are there, their commands must also be ones the shell can
    run (:func:`hook_command_problems`). Per-user Windows gets the same
    check: a Codex self-update left config.toml without hooks while
    ``guardrail mode action`` reported success (GAP-1035).
    """

    windows = _is_windows()
    managed = str(getattr(cfg, "deployment_mode", "") or "").strip().lower() == "managed_enterprise"
    if windows:
        launcher = hook_launcher_problems(cfg, connector)
        if launcher or managed:
            return launcher
    strict = not windows and not managed and bool(str(getattr(cfg, "data_dir", "") or ""))
    unregistered: list[Path] = []
    registered = False
    for path in _hook_config_paths(cfg, connector):
        try:
            if not path.is_file() or path.stat().st_size > _CONFIG_LIMIT:
                continue
            if _registers_defenseclaw_hooks(cfg, connector, path, strict=strict):
                registered = True
                continue
        except OSError:
            continue
        unregistered.append(path)
    if unregistered and (not registered or not managed):
        return [f"no DefenseClaw hooks are registered in {unregistered[0]}"]
    if registered:
        commands = [] if windows else hook_command_problems(cfg, connector)
        problems = commands or unguarded_tool_call_hooks(cfg, connector) or agent_hook_switch_problems(cfg, connector)
        if problems:
            return problems
        return []
    return agent_hook_switch_problems(cfg, connector)


def hook_registration_problems(cfg: Any, connector: str) -> list[str]:
    """Report a hook registration that leaves *connector* unguarded: the recorded files, then Doctor.s verdict.

    Per-user Windows registrations of Claude Code and Copilot are judged by
    the validator Doctor uses (cmd_doctor._windows_native_hook_check), so
    status cannot call a registration healthy that Doctor fails. The lock may
    record no hook file there, so a settings file cut down to no PreToolUse
    entry kept the connector RUNNING in status while Doctor failed it
    (GAP-0645, GAP-0068).
    """

    problems = _scanned_registration_problems(cfg, connector)
    if problems:
        return problems
    managed = str(getattr(cfg, "deployment_mode", "") or "").strip().lower() == "managed_enterprise"
    if _is_windows() and not managed and connector in _WINDOWS_NATIVE_STATUS_CONNECTORS:
        native = _windows_native_problem(cfg, connector)
        if native:
            return [native]
    return problems


def _tool_inspection_strict(cfg: Any) -> bool:
    managed = str(getattr(cfg, "deployment_mode", "") or "").strip().lower() == "managed_enterprise"
    return not _is_windows() and not managed and bool(str(getattr(cfg, "data_dir", "") or ""))


def _unguarded_tool_events(cfg: Any, connector: str, document: Any, path: Path) -> tuple[bool, list[tuple[str, str]]]:
    """Whether *document* registers DefenseClaw hooks, and the tool-guard events it leaves unguarded.

    The events and the fields their hook entries need are the shared table
    (hook_guard_matrix.TOOL_GUARD_HOOKS). A Claude Code settings file that
    kept every other DefenseClaw hook but lost PreToolUse left doctor passing
    while no tool call reached DefenseClaw (GAP-0645); an Antigravity or
    Copilot entry with ``enabled: false``, a narrowed matcher, another type
    or a short timeout did the same on Linux and macOS (rel-1-0-4 GAP-0538).
    Managed installs get the same checks: Antigravity, Devin, Hermes and
    Kiro keep user-writable per-user files there, and the enterprise policy
    guard checks no enabled flag or matcher. Only the timeout of a
    machine-policy connector is left to the enterprise policy reconcile.
    """

    if connector not in TOOL_GUARD_HOOKS:
        return False, []
    section = _hook_section(document, path)
    if section is None:
        return False, []
    strict = _tool_inspection_strict(cfg)
    native = None
    if connector == "claudecode" and strict:
        # The native launcher sits outside hooks/. Share its exact invocation
        # with the registration check before inspecting the tool event fields.
        from defenseclaw.fail_mode import _claude_native_primary_handler, _claude_per_user_native_registration

        native = _claude_per_user_native_registration(cfg)

    written = _hermes_written_command(cfg, connector)

    def owns(handler: Any) -> bool:
        if native is not None:
            return isinstance(handler, dict) and _claude_native_primary_handler(handler, native)
        return any(
            _defenseclaw_hook_command(cfg, connector, command, strict=strict) and (written is None or written(command))
            for command in hook_handler_command_lines(handler, connector)
        )

    if native is not None:
        from defenseclaw.hook_guard_matrix import _entries

        spec = TOOL_GUARD_HOOKS[connector]
        if not any(owns(entry.handler) for event in spec.events for entry in _entries(spec, document, event)):
            return False, []
    elif not any(
        _defenseclaw_hook_command(cfg, connector, command, strict=strict)
        for command in _hook_command_lines(section, connector)
    ):
        return False, []
    managed = str(getattr(cfg, "deployment_mode", "") or "").strip().lower() == "managed_enterprise"
    if path.name.lower() == _DEVIN_PROJECT_HOOKS_FILE and isinstance(document, dict):
        # The project file is the event map itself, as Setup writes it; a
        # foreign hook set the project keeps under a "hooks" key is one more
        # event name there, not the map (GAP-1720).
        document = {"hooks": document}
    unguarded = unguarded_tool_events(connector, document, owns, managed=managed)
    if connector == "hermes" and not unguarded:
        unguarded = _hermes_unapproved_hooks(document, path, owns)
    return True, unguarded


# Hermes runs a shell hook only once (event, command) is approved in this
# file beside config.yaml; a non-interactive Hermes skips an unapproved hook.
HERMES_ALLOWLIST_FILE = "shell-hooks-allowlist.json"


def hermes_approved_pairs(document: Any) -> set[tuple[str, str]]:
    """The (event, command) pairs a decoded Hermes shell-hooks-allowlist.json approves."""

    approvals = document.get("approvals") if isinstance(document, dict) else None
    if not isinstance(approvals, list):
        return set()
    return {
        (raw["event"], raw["command"])
        for raw in approvals
        if isinstance(raw, dict) and isinstance(raw.get("event"), str) and isinstance(raw.get("command"), str)
    }


def _hermes_written_command(cfg: Any, connector: str) -> Callable[[str], bool] | None:
    """Whether a Hermes hook command is one DefenseClaw wrote, so the registration checks apply to it.

    Setup, repair and teardown own a Hermes hook entry only by identity
    (hermesHookEntryOwned in internal/gateway/connector/hook_only.go): the
    current command or a plain spelling of it, or the generated script at an
    edited path. Any other
    command, even one that sits under this data directory, belongs to the
    user: Setup keeps it, does not approve it, and lists it in its notice. The
    checks used the wider "runs a DefenseClaw hook" test, so they failed a
    registration Setup had just written because of an entry Setup keeps by
    design, and repair rolled back (GAP-0873). A registration whose only
    entry is such a command is reported as unguarded instead. Every check that
    reads Hermes commands applies this one test (the tool-guard and approval
    checks, the commands the shell can run, the edited-entry check), so no
    check judges an entry that another spares. Only per-user Unix installs
    know the exact command; it returns None where every command is judged
    (another connector, Windows, managed).
    """

    if connector != "hermes" or not _tool_inspection_strict(cfg):
        return None
    data_dir = str(getattr(cfg, "data_dir", "") or "")
    current = {
        os.path.join(os.path.normpath(root), "hooks", HOOK_SCRIPT_NAMES["hermes"])
        for root in (data_dir, os.path.realpath(data_dir))
    }
    return lambda command: hermes_command_written(command, current)


def hermes_command_written(command: str, current: set[str]) -> bool:
    """Whether *command* is one Setup owns.

    That is a *current* command, a plain spelling of one, or the generated script at an edited path.

    The one test behind every Hermes registration check, the Python mirror of
    hermesHookEntryOwned. A plain spelling of the current command (another
    quoting, blanks around it, plain arguments after it) is the current entry:
    Setup replaces it, so a registration that holds one beside the entry Setup
    added is not two handlers to count (GAP-0873). Any other command belongs
    to the user: Setup keeps it and does not count it.
    """

    if command in current:
        return True
    if hermes_command_spells_script(command, current):
        return True
    # The edited-path matchers trim blanks, which would claim a command
    # Setup did not write: a command with a blank at either end belongs to the user.
    return command == command.strip() and bool(edited_hook_script(command, HOOK_SCRIPT_NAMES["hermes"]))


# The characters of a plain shell word: what posixHookCommandWord leaves unquoted.
_PLAIN_SHELL_CHARS = frozenset(string.ascii_letters + string.digits + "/._-+=:,@%")


def hermes_command_spells_script(command: str, current: set[str]) -> bool:
    """Whether *command* runs a *current* script by a plain spelling.

    Mirrors hermesCommandSpellsTheHookScript in
    internal/gateway/connector/hook_only.go: the first shell word, quoted with
    single or double quotes or not at all and with blanks around the command or
    inside the quotes, names exactly a current script, and whatever follows is
    plain words. A word outside that set anywhere (a second command, a
    redirection, an expansion) means the command does more than run the script.
    """

    text = command.strip(" \t")
    word: list[str] = []
    i = 0
    while i < len(text) and text[i] not in " \t":
        char = text[i]
        if char == "'":
            end = text.find("'", i + 1)
            if end < 0:
                return False
            word.append(text[i + 1 : end])
            i = end + 1
        elif char == '"':
            end = text.find('"', i + 1)
            if end < 0 or any(bad in text[i + 1 : end] for bad in "$`\\!"):
                return False
            word.append(text[i + 1 : end])
            i = end + 1
        elif text.startswith("\\'", i):
            word.append("'")
            i += 2
        elif char in _PLAIN_SHELL_CHARS:
            word.append(char)
            i += 1
        else:
            return False
    return "".join(word).strip(" \t") in current and all(
        char in " \t" or char in _PLAIN_SHELL_CHARS for char in text[i:]
    )


HERMES_HOME_RECORD_FILE = "hermes-home-setup.json"
_HERMES_HOME_RECORD_LIMIT = 64 * 1024


def hermes_command_hash(command: str) -> str:
    """The sha256 of a hook command, as the Hermes home record keeps it (hermesCommandHash in Go)."""

    return hashlib.sha256(command.encode("utf-8")).hexdigest()


def hermes_recorded_kept_commands(data_dir: str) -> dict[str, frozenset[str]]:
    """The command hashes of the entries Setup kept in place of an entry it wrote, by Hermes event.

    Read from the Hermes home record Setup writes in *data_dir* (hermes-home-setup.json, "hooks"
    section: hermesHookEntryRecord in internal/gateway/connector). The kept-entry notice lists an
    entry only when this record names it; it never reads what a command says, so a user hook that
    mentions a DefenseClaw hook as data or in a comment gets no notice (GAP-0940). No record, or one
    that cannot be read, lists nothing.
    """

    path = os.path.join(data_dir, HERMES_HOME_RECORD_FILE)
    try:
        document = json.loads(read_regular_file_no_follow(path, max_bytes=_HERMES_HOME_RECORD_LIMIT))
    except (OSError, ValueError):  # a link, a pipe, a file too large or not JSON is no record
        return {}
    hooks = document.get("hooks") if isinstance(document, dict) else None
    kept: dict[str, frozenset[str]] = {}
    for event, record in (hooks.items() if isinstance(hooks, dict) else ()):
        values = record.get("kept") if isinstance(record, dict) else None
        if isinstance(values, list):
            kept[str(event)] = frozenset(value for value in values if isinstance(value, str))
    return kept


def _hermes_unapproved_hooks(document: Any, path: Path, owns: Callable[[Any], bool]) -> list[tuple[str, str]]:
    """The DefenseClaw Hermes hooks of *document* that the allowlist beside *path* does not approve.

    Doctor on Linux and macOS passed a Hermes registration whose approvals
    were removed from the allowlist while Hermes skipped every hook; only
    the Windows validator read the file (rel-1-0-4 GAP-0339). The tool-guard
    events come first.
    """

    hooks = document.get("hooks") if isinstance(document, dict) else None
    if not isinstance(hooks, dict):
        return []
    allowlist = path.parent / HERMES_ALLOWLIST_FILE
    try:
        approved = hermes_approved_pairs(json.loads(allowlist.read_bytes()))
    except (OSError, ValueError):
        # A missing or unreadable allowlist approves nothing for Hermes either.
        approved = set()
    tool_events = TOOL_GUARD_HOOKS["hermes"].events
    events = sorted(hooks, key=lambda event: (event not in tool_events, str(event)))
    for event in events:
        entries = hooks[event]
        for entry in entries if isinstance(entries, list) else ():
            command = str(entry.get("command") or "").strip() if isinstance(entry, dict) else ""
            if command and owns(entry) and (event, command) not in approved:
                return [(event, f"has no approval in {allowlist}, and Hermes skips a shell hook it has not approved")]
    return []


def _unguarded_problem(connector: str, event: str, why: str, where: str) -> HookProblem:
    if not why:
        return tool_inspection_hook_problem(connector, event, where)
    label = "Claude Code" if connector == "claudecode" else connector
    if event in TOOL_GUARD_HOOKS[connector].events:
        consequence = f"{label} tool calls can run unchecked"
    else:
        consequence = f"{label} runs its {event} events without DefenseClaw"
    return HookProblem(
        f"the DefenseClaw {event} hook in {where} {why}, so {consequence}",
        f"run `{setup_command(connector)} --yes`; it registers the hook again",
    )


def unguarded_tool_call_problem(cfg: Any, connector: str, document: Any, where: str) -> str:
    """Why the decoded agent config *document* at *where* leaves tool calls unguarded, or "".

    A document that registers no DefenseClaw hook at all returns "": the
    unregistered-file check reports it.
    """

    _registered, unguarded = _unguarded_tool_events(cfg, connector, document, Path(where))
    return _unguarded_problem(connector, *unguarded[0], where) if unguarded else ""


def unguarded_tool_call_hooks(cfg: Any, connector: str) -> list[str]:
    """Report recorded agent config files whose DefenseClaw hooks leave tool calls unguarded.

    Every recorded file that registers DefenseClaw hooks must register the
    connector's tool-guard events with the fields of the shared table; on a
    managed install, whose hooks may sit in one machine layer, one file with
    the events is enough. Per-user Windows status runs the same check:
    doctor failed the Claude Code hooks row there while status kept the
    connector RUNNING (GAP-0068).
    """

    if connector not in TOOL_GUARD_HOOKS:
        return []
    managed = str(getattr(cfg, "deployment_mode", "") or "").strip().lower() == "managed_enterprise"
    gaps: list[tuple[Path, str, str]] = []
    covered = False
    for path in _hook_config_paths(cfg, connector):
        try:
            if not path.is_file() or path.stat().st_size > _CONFIG_LIMIT:
                continue
            document = _load_agent_document(path)
        except (OSError, ValueError, ImportError):
            continue
        registered, unguarded = _unguarded_tool_events(cfg, connector, document, path)
        gaps.extend((path, event, why) for event, why in unguarded)
        covered = covered or (registered and not unguarded)
    if not gaps or (managed and covered):
        return []
    path, event, why = gaps[0]
    return [_unguarded_problem(connector, event, why, str(path))]


def tool_inspection_hook_problem(connector: str, event: str, where: str) -> HookProblem:
    """The problem sentence for a tool-inspection event without its DefenseClaw hook."""

    label = "Claude Code" if connector == "claudecode" else connector
    return HookProblem(
        f"the DefenseClaw {event} hook is not registered in {where}, so {label} tool calls are not inspected",
        f"run `{setup_command(connector)} --yes`; it registers the missing hook",
    )


def _read_agent_config(path: Path) -> Any:
    try:
        if not path.is_file() or path.stat().st_size > _CONFIG_LIMIT:
            return None
        return _load_agent_document(path)
    except (OSError, ValueError):
        return None


def _load_agent_document(path: Path, raw: bytes | None = None) -> Any:
    """Decode an agent config file: TOML (Codex), YAML (Hermes) or JSON.

    Raises ValueError for a file that does not parse.
    """

    if raw is None:
        raw = path.read_bytes()
    suffix = path.suffix.lower()
    if suffix == ".toml":
        return codex_toml.loads(raw)
    if suffix in (".yaml", ".yml"):
        import yaml

        try:
            return yaml.safe_load(raw.decode("utf-8", errors="replace"))
        except yaml.YAMLError as exc:
            raise ValueError(f"{path}: {exc}") from exc
    return json.loads(raw.decode("utf-8", errors="replace"))


def _commandless_codex_handlers(document: Any) -> int:
    """Codex hook handlers without a command, which may leave hooks inactive."""

    hooks = document.get("hooks") if isinstance(document, dict) else None
    if not isinstance(hooks, dict):
        return 0
    count = 0
    for event, groups in hooks.items():
        if event == "state" or not isinstance(groups, list):
            continue
        for group in groups:
            handlers = group.get("hooks") if isinstance(group, dict) else None
            for handler in handlers if isinstance(handlers, list) else []:
                if (
                    isinstance(handler, dict)
                    and "command" not in handler
                    and handler.get("type", "command") == "command"
                ):
                    count += 1
    return count


def agent_hook_switch_problems(cfg: Any, connector: str, *, workspace_dir: str | None = None) -> list[str]:
    """Agent settings that stop the registered DefenseClaw hooks from running.

    The hook entries can be intact while the agent runs none of them: Claude
    Code with ``disableAllHooks`` (GAP-1066; in the settings of the project in
    the current folder, GAP-1067) or Codex with ``[features] hooks = false``
    (GAP-1094). Codex may run without DefenseClaw hooks when entries lose their
    command, for example after hook lines are deleted by hand (GAP-1102).
    Copilot reads ``disableAllHooks`` from its user and repository settings
    (rel-1-0-4 GAP-0580) and from the hook registration files themselves;
    settings that cannot be read fail too, since what Copilot does with them
    is unknown. Managed installs keep the hooks in machine policy that these settings
    cannot turn off, so they are not checked here.
    """

    if str(getattr(cfg, "deployment_mode", "") or "").strip().lower() == "managed_enterprise":
        return []
    problems: list[str] = []
    if connector == "claudecode":
        project = Path(workspace_dir or os.getcwd(), ".claude")
        paths = [*_hook_config_paths(cfg, connector), project / "settings.local.json", project / "settings.json"]
        for path in dict.fromkeys(paths):
            document = _read_agent_config(path)
            if isinstance(document, dict) and document.get("disableAllHooks") is True:
                problems.append(
                    HookProblem(
                        f"Claude Code disableAllHooks is true in {path}, so Claude Code runs none of its hooks "
                        "and DefenseClaw is not guarding its tool calls",
                        f"remove disableAllHooks from {path} (or set it to false), then restart Claude Code",
                    )
                )
                break
        if not _is_windows() and _strict_policy_tier(cfg, connector):
            # Only what the gateway checks: workspace_dir None is the pinned
            # claw.workspace_dir, not the folder this command runs in.
            refusal = _claude_strict_hook_shell_env_problem(cfg, workspace_dir)
            if refusal is not None:
                problems.append(refusal)
    elif connector == "codex":
        for path in _hook_config_paths(cfg, connector):
            document = _read_agent_config(path)
            if not isinstance(document, dict):
                continue
            features = document.get("features")
            if isinstance(features, dict) and (features.get("hooks") is False or features.get("codex_hooks") is False):
                problems.append(
                    HookProblem(
                        f"Codex hooks are turned off in {path} ([features] hooks = false), so Codex runs no hook "
                        "and DefenseClaw is not guarding its tool calls",
                        "run `codex features enable hooks`, then restart Codex",
                    )
                )
            orphans = _commandless_codex_handlers(document)
            if orphans:
                noun = "entry" if orphans == 1 else "entries"
                problems.append(
                    HookProblem(
                        f"{path} has {orphans} Codex hook {noun} without a command (left when hook lines were "
                        "deleted), so Codex may run without its DefenseClaw hooks",
                        f"run `{setup_command(connector)} --yes`; it removes the entries without a command",
                    )
                )
    elif connector == "copilot":
        from defenseclaw.connector_paths import connector_hook_config_paths, copilot_settings_resolution

        if workspace_dir is None:
            resolver = getattr(cfg, "connector_workspace_dir", None)
            workspace_dir = resolver() if callable(resolver) else ""
        settings = copilot_settings_resolution(workspace_dir)
        if settings.errors:
            problems.append(
                HookProblem(
                    "Copilot settings cannot be read (" + "; ".join(settings.errors) + "), so DefenseClaw cannot "
                    "tell whether Copilot runs its hooks",
                    "fix or remove the settings file named, then run `defenseclaw doctor` again",
                )
            )
        elif settings.disable_all_hooks:
            problems.append(
                HookProblem(
                    f"Copilot disableAllHooks is true in {settings.source}, so Copilot runs none of its hooks "
                    "and DefenseClaw is not guarding its tool calls",
                    f"remove disableAllHooks from {settings.source} (or set it to false), then restart Copilot",
                )
            )
        # A lock written before the hook files were recorded (an upgrade)
        # still has the registration at the path setup writes.
        try:
            canonical = [Path(item) for item in connector_hook_config_paths(connector, workspace_dir)]
        except ValueError:
            canonical = []
        for path in dict.fromkeys([*_hook_config_paths(cfg, connector), *canonical]):
            problem = copilot_registration_switch_problem(path)
            if problem:
                problems.append(problem)
                break
    return problems


# Agent settings and shell variables that stop or subvert a shell-form hook
# command (rel-1-0-6:GAP-0322). Mirrors internal/gateway/connector/hook_shell_env.go,
# which has the full reasoning. Claude Code starts a hook command through
# /bin/sh -c with process.env after it applied the env block of each settings
# source, lowest first: ~/.claude.json, user, project, local, --settings,
# managed. Where /bin/sh is bash (RHEL, macOS) SHELLOPTS=noexec runs none of
# the command, and CLAUDE_CODE_SHELL_PREFIX replaces it. BASH_ENV,
# BASH_FUNC_*%% and BASHOPTS reach the bash that runs a #!/bin/bash hook script
# (BASH_ENV can exit before the hook, an exported function replaces a command
# the script calls). A #!/bin/bash -p script ignores those three; they stay on
# the list either way, because a script rendered by an earlier build keeps
# #!/bin/bash until the gateway renders it again (and a rollback brings it
# back), and no hook needs them from a project's settings. FUNCNEST is still
# read by bash -p. ENV is not on the list: non-interactive shells never read it.
# The strict tier refuses such settings (agent_hook_switch_problems) for the
# sources the gateway checks too: user, ~/.claude.json, managed, and the
# project of the pinned claw.workspace_dir. Otherwise, and for the folder
# doctor or status runs in, it is a warning (agent_hook_env_warnings).
# A managed Claude Code install starts the native hook in exec form on POSIX,
# so its settings env does not govern the hook launch. Doctor and status still report
# SHELLOPTS values that can affect Bash tool scripts.
HOOK_SHELL_ENV_NAMES = ("BASHOPTS", "BASH_ENV", "CLAUDE_CODE_SHELL_PREFIX", "FUNCNEST", "SHELLOPTS")
_HOOK_SHELL_ENV_FUNCTION_PREFIX = "BASH_FUNC_"

# Connectors whose agent runs a hook command through bash (bash -c, or the
# account's login shell with -lc), where an inherited BASH_ENV runs before the
# command whatever the hook script starts with: Devin (GAP-0382), Copilot CLI
# (its hooks use the "bash" field) and Codex (the passwd login shell, bash on
# RHEL). Claude Code and Kiro use /bin/sh, which ignores BASH_ENV; Hermes,
# Antigravity and the Amp and OpenCode plugins start the hook with no shell.
_BASH_HOOK_RUNNERS = frozenset({"codex", "copilot", "devin"})


def _is_hook_shell_env_name(name: str) -> bool:
    return name in HOOK_SHELL_ENV_NAMES or name.startswith(_HOOK_SHELL_ENV_FUNCTION_PREFIX)


def _claude_keeps_env_value(value: Any) -> bool:
    """Whether Claude Code applies *value* from a settings env block.

    It keeps a string, number or boolean (stringified) and drops anything else
    (null, an object, an array) and a value holding NUL, so a dropped value in a
    higher source leaves a lower one in force.
    """

    if isinstance(value, str):
        return "\x00" not in value
    return isinstance(value, (bool, int, float))


def _hook_shell_env_takes_effect(name: str, value: Any) -> bool:
    if name.startswith(_HOOK_SHELL_ENV_FUNCTION_PREFIX):
        return True
    if isinstance(value, str):
        return value.strip() != ""
    return True


def _hook_shell_env_risk(name: str) -> str:
    if name == "SHELLOPTS":
        return "SHELLOPTS (with noexec, /bin/sh runs none of the hook command)"
    if name == "CLAUDE_CODE_SHELL_PREFIX":
        return "CLAUDE_CODE_SHELL_PREFIX (Claude Code runs that program in place of each hook command)"
    if name == "BASH_ENV":
        return "BASH_ENV (a #!/bin/bash hook script runs that file first, and it can exit before the hook)"
    if name == "BASHOPTS":
        return "BASHOPTS (sets options of a #!/bin/bash hook script)"
    if name == "FUNCNEST":
        return "FUNCNEST (makes the hook script's nested helper calls fail)"
    command = name[len(_HOOK_SHELL_ENV_FUNCTION_PREFIX):].removesuffix("%%")
    return f"{name} (an exported function that replaces the {command} command in a #!/bin/bash hook script)"


def _strict_policy_tier(cfg: Any, connector: str) -> bool:
    """Whether *connector* is in the strict policy tier (GuardrailConfig.hook_policy_tier)."""

    tier = getattr(getattr(cfg, "guardrail", None), "hook_policy_tier", None)
    try:
        return callable(tier) and str(tier(connector) or "").strip().lower() == "strict"
    except Exception:  # noqa: BLE001 - an unresolvable tier is the default tier
        return False


def _managed_install(cfg: Any) -> bool:
    return str(getattr(cfg, "deployment_mode", "") or "").strip().lower() == "managed_enterprise"


def pinned_workspace_dir(cfg: Any) -> str:
    """The pinned ``claw.workspace_dir`` the gateway checks (Config.ConnectorWorkspaceDir), or ""."""

    resolver = getattr(cfg, "connector_workspace_dir", None)
    if callable(resolver):
        try:
            return str(resolver() or "")
        except Exception:  # noqa: BLE001 - fall back to the raw value
            pass
    raw = str(getattr(getattr(cfg, "claw", None), "workspace_dir", "") or "").strip()
    return os.path.abspath(os.path.expanduser(raw)) if raw else ""


def _claude_managed_env_source() -> tuple[str, dict] | None:
    """The env block of the active Claude Code managed source, when it can be read."""

    try:
        from defenseclaw.connector_paths import connector_config_files
        from defenseclaw.doctor_hooks import _claude_managed_sources

        for source in _claude_managed_sources(connector_config_files("claudecode")[0], None, None):
            if source is not None and source.settings:
                env = source.settings.get("env")
                return (source.label, env) if isinstance(env, dict) else None
    except Exception:  # noqa: BLE001 - an unreadable managed tier is left out, as in the gateway
        return None
    return None


def _claude_env_blocks(cfg: Any, workspace_dir: str | None) -> list[tuple[Path | str, dict]]:
    """Claude Code env blocks, highest source first; *workspace_dir* None skips the project."""

    blocks: list[tuple[Path | str, dict]] = []
    managed = _claude_managed_env_source()
    if managed is not None:
        blocks.append(managed)
    paths: list[Path] = []
    if workspace_dir:
        project = Path(workspace_dir, ".claude")
        paths += [project / "settings.local.json", project / "settings.json"]
    paths += list(_hook_config_paths(cfg, "claudecode"))
    try:
        from defenseclaw.connector_paths import claude_mcp_state_path, connector_config_files

        paths.append(Path(connector_config_files("claudecode")[0]))
        paths.append(Path(claude_mcp_state_path()))
    except Exception:  # noqa: BLE001 - the recorded paths still apply
        pass
    for path in dict.fromkeys(paths):
        document = _read_agent_config(path)
        env = document.get("env") if isinstance(document, dict) else None
        if isinstance(env, dict):
            blocks.append((path, env))
    return blocks


def claude_settings_hook_shell_env(cfg: Any, workspace_dir: str | None = None) -> tuple[list[str], list[Path | str]]:
    """Names the effective Claude Code env sets that stop or subvert its shell-form hooks, and their sources.

    Claude Code applies env blocks name by name, lowest first: the highest
    source with a value it keeps decides a name, so "" clears a lower value and
    a dropped value (null, object, array, NUL) does not.
    """

    decided: set[str] = set()
    names: list[str] = []
    sources: list[Path | str] = []
    for source, env in _claude_env_blocks(cfg, workspace_dir):
        set_here = False
        for key in sorted(k for k in env if isinstance(k, str)):
            if not _is_hook_shell_env_name(key) or key in decided or not _claude_keeps_env_value(env[key]):
                continue
            decided.add(key)
            if _hook_shell_env_takes_effect(key, env[key]):
                names.append(key)
                set_here = True
        if set_here:
            sources.append(source)
    return sorted(names), sources


def _claude_hook_shell_env_problem(
    names: list[str], sources: list[Path | str], *, strict: bool, unchecked_folder: str = ""
) -> HookProblem:
    listed = ", ".join(names)
    where = " and ".join(str(source) for source in sources)
    risks = "; ".join(_hook_shell_env_risk(name) for name in names)
    text = (
        f"{where} {'sets' if len(sources) == 1 else 'set'} {listed} in the Claude Code env block, which Claude Code "
        f"applies to the hook commands it starts through /bin/sh: {risks}"
    )
    if strict:
        text += (
            ". The strict policy tier refuses it: the gateway does not set up Claude Code, so every Claude Code "
            "session of this account fails closed until it is removed (a session that applies the value may still "
            "start no hook)"
        )
        repair = (
            f"remove {listed} from that env block, or use the default policy tier, which only warns; "
            "then run: defenseclaw-gateway restart"
        )
    else:
        if unchecked_folder:
            text += (
                f". Claude Code started in {unchecked_folder} would apply it; the gateway checks only the pinned "
                "claw.workspace_dir, so nothing refused it"
            )
        repair = f"remove {listed} from that env block, then restart Claude Code"
    return HookProblem(text, repair)


def _claude_strict_hook_shell_env_problem(cfg: Any, workspace_dir: str | None) -> HookProblem | None:
    """The strict refusal for the sources the gateway checks, or None."""

    folder = workspace_dir if workspace_dir is not None else pinned_workspace_dir(cfg)
    names, sources = claude_settings_hook_shell_env(cfg, folder)
    return _claude_hook_shell_env_problem(names, sources, strict=True) if names else None


def inherited_hook_shell_env(environ: Any, connector: str) -> list[str]:
    """Shell variables in *environ* that stop or subvert *connector*'s hook command.

    SHELLOPTS with ``noexec`` stops every shell that starts a hook command
    (bash as /bin/sh, bash -c); CLAUDE_CODE_SHELL_PREFIX replaces Claude Code's;
    BASH_ENV runs before the command where the agent starts it through bash
    (_BASH_HOOK_RUNNERS). Exported functions are left out: environment modules
    export ``module`` and ``ml`` in every RHEL login shell, and a function only
    subverts a hook script that calls a command of the same name. An agent
    inherits these from the shell that starts it; DefenseClaw cannot change
    that environment, so this is reported, not refused.
    """

    found = []
    options = str(environ.get("SHELLOPTS", "") or "")
    if "noexec" in [option.strip() for option in options.split(":")]:
        found.append("SHELLOPTS")
    bash_env = str(environ.get("BASH_ENV", "") or "").strip()
    if connector in _BASH_HOOK_RUNNERS and bash_env and not _system_bash_env(bash_env, environ):
        found.append("BASH_ENV")
    if connector == "claudecode" and str(environ.get("CLAUDE_CODE_SHELL_PREFIX", "") or "").strip():
        found.append("CLAUDE_CODE_SHELL_PREFIX")
    return found


def _system_bash_env(path: str, environ: Any) -> bool:
    """Whether *path* is a system shell init file only root can change.

    Environment Modules and Lmod profiles export BASH_ENV to their own init
    script so batch bash gets the ``module`` function. Only root can change such
    a file, so it is not the hostile value this check looks for; warning on it
    on every doctor and status run was noise (rel-1-0-6:GAP-0393).

    bash opens the path as written, so the path is walked as written, one part
    at a time with lstat (_root_only_path): every folder on it, and the file,
    must be root-owned with no group or world write, and a symlink part must be
    root-owned too, with its target walked the same way. A link in a folder the
    user can write (the home, a user folder in /tmp) is therefore reported even
    when it points at a root-owned file, while Lmod's root-owned
    /usr/share/lmod/lmod link stays exempt. A relative or missing path, and a
    file that resolves into the home, are reported.
    """

    if not os.path.isabs(path):
        return False
    real = _root_only_path(path, 0)
    if real is None or not os.path.isfile(real):
        return False
    home = os.path.realpath(str(environ.get("HOME", "") or Path.home()))
    return not (real == home or real.startswith(home.rstrip(os.sep) + os.sep))


_ROOT_ONLY_LINK_LIMIT = 40


def _root_only_path(path: str, hops: int) -> str | None:
    """The symlink-free path of absolute *path* if only root can change any part of it, else None."""

    def root_only(info: os.stat_result, *, link: bool) -> bool:
        if info.st_uid != 0:
            return False
        # A link's own mode bits mean nothing; a folder or file must not be
        # group or world writable (a sticky /tmp still lets anyone add a file).
        return link or not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)

    try:
        if not root_only(os.lstat(os.sep), link=False):
            return None
    except OSError:
        return None
    current = os.sep
    for part in path.split(os.sep):
        if part in ("", "."):
            continue
        if part == "..":
            # current never holds a link, so going up is lexical.
            current = os.path.dirname(current)
            continue
        candidate = os.path.join(current, part)
        try:
            info = os.lstat(candidate)
        except OSError:
            return None
        if stat.S_ISLNK(info.st_mode):
            if hops >= _ROOT_ONLY_LINK_LIMIT or not root_only(info, link=True):
                return None
            try:
                target = os.readlink(candidate)
            except OSError:
                return None
            resolved = _root_only_path(target if os.path.isabs(target) else os.path.join(current, target), hops + 1)
            if resolved is None:
                return None
            current = resolved
            continue
        if not root_only(info, link=False):
            return None
        current = candidate
    return current


_INHERITED_RISK = {
    "SHELLOPTS": "SHELLOPTS with noexec (the shell that starts the hook command runs none of it)",
    "BASH_ENV": "BASH_ENV (the agent starts its hook commands through bash, which runs that file first)",
    "CLAUDE_CODE_SHELL_PREFIX": (
        "CLAUDE_CODE_SHELL_PREFIX (Claude Code runs that program in place of each hook command)"
    ),
}


def agent_hook_env_warnings(
    cfg: Any,
    connector: str,
    *,
    workspace_dir: str | None = None,
    environ: Any = None,
) -> list[HookProblem]:
    """Warnings for settings and shell variables that can stop *connector*'s hooks (rel-1-0-6:GAP-0322).

    *workspace_dir* None means the pinned ``claw.workspace_dir``, else the
    folder this command runs in. Outside the strict tier a Claude Code env block
    that sets a name in HOOK_SHELL_ENV_NAMES is a warning; in the strict tier
    agent_hook_switch_problems refuses what the gateway checks, and a project in
    an unpinned folder stays a warning (the gateway does not see it). The
    variables this shell would hand an agent it starts are a warning in every
    tier. A managed Claude Code install starts the native hook in exec form;
    SHELLOPTS warnings there concern Bash tool scripts only. Windows runs the
    native launcher without a POSIX shell.
    """

    if _is_windows():
        return []
    if connector == "claudecode" and _managed_install(cfg):
        return _managed_claude_shellopts_warnings(cfg, workspace_dir, os.environ if environ is None else environ)
    warnings: list[HookProblem] = []
    settings_names: set[str] = set()
    if connector == "claudecode":
        pinned = pinned_workspace_dir(cfg)
        folder = workspace_dir if workspace_dir is not None else (pinned or os.getcwd())
        unchecked = "" if (workspace_dir is not None or pinned) else folder
        for _source, env in _claude_env_blocks(cfg, folder):
            settings_names.update(
                key for key, value in env.items() if isinstance(key, str) and _claude_keeps_env_value(value)
            )
        names, sources = claude_settings_hook_shell_env(cfg, folder)
        if names and not _strict_policy_tier(cfg, connector):
            warnings.append(_claude_hook_shell_env_problem(names, sources, strict=False, unchecked_folder=unchecked))
        elif names and unchecked and _claude_strict_hook_shell_env_problem(cfg, None) is None:
            warnings.append(_claude_hook_shell_env_problem(names, sources, strict=False, unchecked_folder=unchecked))
    # A settings env block decides a name it sets, over the inherited value.
    inherited = [
        name
        for name in inherited_hook_shell_env(os.environ if environ is None else environ, connector)
        if name not in settings_names
    ]
    if inherited:
        listed = ", ".join(inherited)
        described = "; ".join(_INHERITED_RISK[name] for name in inherited)
        warnings.append(
            HookProblem(
                f"this shell's environment sets {described}, and an agent started from it passes that environment "
                "to its hook commands, so the DefenseClaw hook may not run; DefenseClaw cannot change the environment "
                "an agent inherits",
                f"unset {listed} in the shell profile that sets it, then start the agent from a new shell",
            )
        )
    return warnings


def _shellopts_noexec(value: Any) -> bool:
    return "noexec" in [option.strip() for option in str(value or "").split(":")]


def _managed_claude_shellopts_warnings(cfg: Any, workspace_dir: str | None, environ: Any) -> list[HookProblem]:
    """Report managed SHELLOPTS values that can affect Bash tool scripts."""

    folder = workspace_dir if workspace_dir is not None else (pinned_workspace_dir(cfg) or os.getcwd())
    effect = "so Bash tool scripts may stop early; the managed DefenseClaw hook uses exec form"
    for source, env in _claude_env_blocks(cfg, folder):
        if "SHELLOPTS" not in env or not _claude_keeps_env_value(env["SHELLOPTS"]):
            continue
        # The highest source with a kept value decides the name.
        if not _shellopts_noexec(env["SHELLOPTS"]):
            return []
        return [
            HookProblem(
                f"Claude Code settings {source} set SHELLOPTS with noexec, {effect}",
                f"remove SHELLOPTS from the env block of {source}, then restart Claude Code",
            )
        ]
    if _shellopts_noexec(environ.get("SHELLOPTS", "")):
        return [
            HookProblem(
                f"this shell's environment sets SHELLOPTS with noexec, and Claude Code started from it passes it "
                f"to Bash tool commands, {effect}",
                "unset SHELLOPTS in the shell profile that sets it, then start Claude Code from a new shell",
            )
        ]
    return []


def copilot_registration_switch_problem(path: Path | str) -> str:
    """Why the Copilot hook registration file at *path* turns its own hooks off, or "".

    Copilot also reads ``disableAllHooks`` from the hook file itself; setup
    refuses such a file (hook_only.go) and so does the Windows doctor, while
    POSIX doctor and status showed the hooks guarded. A value that is not a
    boolean fails too, since what Copilot does with it is unknown.
    """

    path = Path(path)
    document = _read_agent_config(path)
    if not isinstance(document, dict) or "disableAllHooks" not in document:
        return ""
    value = document["disableAllHooks"]
    if type(value) is not bool:
        return HookProblem(
            f"Copilot disableAllHooks in {path} is not a boolean, so DefenseClaw cannot tell whether Copilot "
            "runs its hooks",
            f"remove disableAllHooks from {path}, then restart Copilot",
        )
    if not value:
        return ""
    return HookProblem(
        f"Copilot disableAllHooks is true in {path}, so Copilot runs none of its hooks "
        "and DefenseClaw is not guarding its tool calls",
        f"remove disableAllHooks from {path} (or set it to false), then restart Copilot",
    )


def _registered_commands(value: Any) -> list[str]:
    """Every string under a ``command`` key of a decoded agent hook config."""

    found: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "command" and isinstance(item, str):
                found.append(item)
            else:
                found.extend(_registered_commands(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(_registered_commands(item))
    return found


def hook_command_problems(cfg: Any, connector: str) -> list[str]:
    """Report DefenseClaw hook commands that the agent shell cannot run.

    Agents run a Unix hook command through a shell. A registration whose
    script path contains a space and no quotes makes the shell run the first
    half of the path (``/home/dc``), so no hook call reaches the gateway while
    the other rows stay green (GAP-0382). Setup writes the path quoted. The
    Copilot ``bash`` entries and the Hermes ``config.yaml`` commands are
    checked like the ``command`` entries of the other agents (GAP-1385,
    GAP-1467).
    """

    if os.name == "nt":
        return []
    hooks_dir = os.path.join(str(getattr(cfg, "data_dir", "") or ""), "hooks")
    written = _hermes_written_command(cfg, connector)
    for path in _hook_config_paths(cfg, connector):
        try:
            if not path.is_file() or path.stat().st_size > _CONFIG_LIMIT:
                continue
            document = _load_agent_document(path)
        except (OSError, ValueError):
            continue
        for command in _hook_command_strings(document):
            if hooks_dir + os.sep not in command or (written is not None and not written(command)):
                continue
            try:
                tokens = shlex.split(command)
            except ValueError:
                tokens = []
            program = tokens[0] if tokens else command
            if program.startswith(hooks_dir + os.sep):
                continue
            return [
                f"hook command in {path} cannot run: the shell runs {program!r}, not the hook script "
                f"under {hooks_dir} (a path with a space must be quoted)"
            ]
    return edited_hook_problems(cfg, connector)


# The Unix hook script Setup registers for each hook connector. Windows
# registers the native launcher, whose ownership stays exact.
HOOK_SCRIPT_NAMES = {
    "antigravity": "antigravity-hook.sh",
    "claudecode": "claude-code-hook.sh",
    "codex": "codex-hook.sh",
    "copilot": "copilot-hook.sh",
    "cursor": "cursor-hook.sh",
    "devin": "devin-hook.sh",
    "hermes": "hermes-hook.sh",
    "kiro": "kiro-hook.sh",
}

_EDITED_HOOK_PREFIX = "hook command edited: "


def _split_hook_command(command: str) -> tuple[str, str] | None:
    """Split a hook command into its first shell word (unquoted) and the rest."""

    if not command.startswith("'"):
        match = re.search(r"[ \t]", command)
        return (command[: match.start()], command[match.start() :]) if match else (command, "")
    word: list[str] = []
    i = 0
    while i < len(command):
        if command[i] == "'":
            end = command.find("'", i + 1)
            if end < 0:
                return None
            word.append(command[i + 1 : end])
            i = end + 1
        elif command.startswith('"\'"', i):
            word.append("'")
            i += 3
        elif command.startswith("\\'", i):
            word.append("'")
            i += 2
        elif command[i] == " ":
            return "".join(word), command[i:]
        else:
            return None
    return "".join(word), ""


def edited_hook_script(command: str, script_name: str) -> str:
    """The script path when *command* has the shape of a DefenseClaw hook entry, else "".

    Mirrors ``editedDefenseClawHookCommand`` in
    internal/gateway/connector/helpers.go (the shared golden
    testdata/hook_edited_commands.json keeps them in step): an absolute,
    clean script path whose name is the connector's script name, possibly
    edited around ".sh" (copilot-hookX.sh), under a .defenseclaw directory,
    or the exact name under an edited DefenseClaw data directory, alone or
    with ``--event`` or ``--hook-surface``; or a copy of a DefenseClaw hook
    script anywhere (:func:`copied_hook_script`). Setup replaces such
    entries; doctor reports the ones that are not the current command
    (GAP-0906, GAP-0907, rel-1-0-4 GAP-0600).
    """

    return _edited_hook_shape(command, script_name) or copied_hook_script(command, script_name)


# The line every generated hook script of every release carries
# (hookSchemaVersionMarker in internal/gateway/connector/subprocess.go).
_HOOK_SCRIPT_MARKER = b"# defenseclaw-managed-hook v"
_HOOK_SCRIPT_HEAD = 512
_HOOK_BINDINGS = (" --event ", " --hook-surface ")


def _is_defenseclaw_hook_file(path: str) -> bool:
    """Whether *path* is a regular file that starts like a generated DefenseClaw hook script."""

    if os.name == "nt":
        return False
    try:
        # Non-blocking, so a named pipe in its place is refused, not waited on.
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return False
    try:
        return stat.S_ISREG(os.fstat(descriptor).st_mode) and _HOOK_SCRIPT_MARKER in os.read(
            descriptor, _HOOK_SCRIPT_HEAD
        )
    except OSError:
        return False
    finally:
        os.close(descriptor)


def copied_hook_script(command: str, script_name: str) -> str:
    """The script path when *command* runs a copy of a DefenseClaw hook script, else "".

    Mirrors ``copiedDefenseClawHookCommand`` in
    internal/gateway/connector/helpers.go: the first shell word is an
    absolute, clean path to a file that carries the generated-hook marker of
    any release (whatever follows it: Antigravity passes the event bare,
    Claude Code appends its missing-script guard), or a path with the
    connector's script name followed by DefenseClaw's ``--event`` /
    ``--hook-surface`` binding (the copy may have been deleted since). A
    shell or env wrapper in front of the script (:func:`_split_after_wrapper`)
    is looked through. An entry repointed at an old copy in another folder
    kept doctor and ``guardrail fail-mode`` green while the running gateway
    had added its own entry back beside it (rel-1-0-4 GAP-0600). Only
    DefenseClaw's current hook is a working registration, so Setup replaces
    such an entry wherever it points.
    """

    split = _split_after_wrapper(command.strip())
    if split is None:
        return ""
    word, rest = split
    if (
        any(char in word for char in "\x00\r\n")
        or not word.startswith("/")
        or word.startswith("//")
        or posixpath.normpath(word) != word
    ):
        return ""
    if rest.startswith(_HOOK_BINDINGS) and posixpath.basename(word) == script_name:
        return word
    return word if _is_defenseclaw_hook_file(word) else ""


# The programs a hook command can run a script through (hookShellWrappers in
# internal/gateway/connector/helpers.go).
_HOOK_SHELL_WRAPPERS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "env"})


def _split_after_wrapper(command: str) -> tuple[str, str] | None:
    """:func:`_split_hook_command` after one shell or env wrapper word and env's NAME=value words.

    Mirrors ``hookScriptWordAfterWrapper``: ``bash /old/copilot-hook.sh
    --event preToolUse`` ran an old copy the first-word check did not see
    (rel-1-0-4 GAP-0600).
    """

    split = _split_hook_command(command)
    if split is None:
        return None
    word, rest = split
    base = posixpath.basename(word)
    if base not in _HOOK_SHELL_WRAPPERS or ("/" in word and not word.startswith("/")):
        return split
    while True:
        split = _split_hook_command(rest.lstrip(" \t"))
        if split is None or base != "env" or "=" not in split[0] or split[0].startswith("/"):
            return split
        rest = split[1]


def _edited_hook_shape(command: str, script_name: str) -> str:
    """The script path when *command* runs the connector's script at an edited DefenseClaw path, else ""."""

    stem = script_name[:-3] if script_name.endswith(".sh") else ""
    if not stem.endswith("-hook") or "/" in script_name:
        return ""
    split = _split_hook_command(command.strip())
    if split is None:
        return ""
    word, rest = split
    if (
        any(char in word for char in "\x00\r\n")
        or not word.startswith("/")
        or word.startswith("//")
        or posixpath.normpath(word) != word
    ):
        return ""
    if rest and not rest.startswith(_HOOK_BINDINGS):
        return ""
    base = posixpath.basename(word)
    if not base.startswith(stem):
        return ""
    edit = base[len(stem) :]
    if ".sh" not in edit or " " in edit or "\t" in edit:
        return ""
    for part in posixpath.dirname(word).split("/"):
        part = part.lower()
        if part == ".defenseclaw" or (base == script_name and part.startswith(".") and "defenseclaw" in part):
            return word
    return ""


# The keys agents read a hook command from: ``command`` (Claude Code, Codex,
# Hermes), ``bash``/``powershell`` (Copilot) and Codex's Windows override.
_HOOK_COMMAND_KEYS = ("command", "bash", "powershell", "command_windows", "commandWindows")


def _hook_command_strings(value: Any) -> list[str]:
    """Every string under a hook command key of a decoded hook config."""

    found: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key in _HOOK_COMMAND_KEYS and isinstance(item, str):
                found.append(item)
            else:
                found.extend(_hook_command_strings(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(_hook_command_strings(item))
    return found


# DefenseClaw's own hook files: Copilot's <hooks>/defenseclaw.json and
# Kiro's .kiro/hooks/defenseclaw.json. On an event DefenseClaw binds, Setup
# leaves its own entry alone there (patchCopilotHooksForOS, patchKiroV3Hooks).
_OWNED_HOOK_FILE = "defenseclaw.json"
# kiroV3HookSpecs: name, description, trigger and matcher of each entry.
_KIRO_V3_SPECS = (
    ("defenseclaw-user-prompt", "DefenseClaw prompt inspection", "UserPromptSubmit", ""),
    ("defenseclaw-pre-tool", "DefenseClaw tool-use inspection", "PreToolUse", ".*"),
    ("defenseclaw-post-tool", "DefenseClaw tool-use audit", "PostToolUse", ".*"),
    ("defenseclaw-stop", "DefenseClaw session stop", "Stop", ""),
)
_POSIX_SAFE_WORD = re.compile(r"[A-Za-z0-9/._\-+=:,@%]+")


def _shell_quote(word: str) -> str:
    return "'" + word.replace("'", "'\\''") + "'"


def _locked_contract_id(cfg: Any, connector: str) -> str:
    lock_path = Path(str(getattr(cfg, "data_dir", "") or ""), "hook_contract_lock.json")
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8")) if lock_path.stat().st_size <= _LOCK_LIMIT else {}
    except (OSError, ValueError):
        return ""
    connectors = lock.get("connectors") if isinstance(lock, dict) else None
    entry = connectors.get(connector) if isinstance(connectors, dict) else None
    return str(entry.get("contract_id") or "") if isinstance(entry, dict) else ""


def _owned_file_renders(cfg: Any, connector: str, current: str) -> dict[str, dict[str, Any]]:
    """Setup's entry for each event DefenseClaw binds in its own hook file of *connector*."""

    if connector == "copilot":
        from defenseclaw.doctor_hooks import _COPILOT_CONTRACT_EVENTS

        events = _COPILOT_CONTRACT_EVENTS.get(_locked_contract_id(cfg, connector)) or tuple(
            {event for contract in _COPILOT_CONTRACT_EVENTS.values() for event in contract}
        )
        return {
            event: {
                "type": "command",
                "bash": f"{_shell_quote(current)} --event {_shell_quote(event)}",
                "timeoutSec": TOOL_GUARD_HOOKS["copilot"].timeout,
            }
            for event in events
        }
    if connector == "kiro":
        word = current if _POSIX_SAFE_WORD.fullmatch(current) else _shell_quote(current)
        renders = {}
        for name, description, trigger, matcher in _KIRO_V3_SPECS:
            entry: dict[str, Any] = {
                "name": name,
                "description": description,
                "trigger": trigger,
                "action": {"type": "command", "command": f"{word} --hook-surface v3"},
                "timeout": TOOL_GUARD_HOOKS["kiro"].timeout,
                "enabled": True,
            }
            if matcher:
                entry["matcher"] = matcher
            renders[trigger] = entry
        return renders
    return {}


def _same_hook_json(left: Any, right: Any) -> bool:
    # sameHookJSON: true is not 1, and key order does not matter.
    return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)


def _foreign_owned_file_entry(
    cfg: Any, connector: str, path: Path, document: Any, current: str
) -> tuple[str, bool] | None:
    """The first entry in DefenseClaw's own hook file, on an event it binds, that is not Setup's render.

    A wrapper (``bash <copy>``), a renamed copy or a copy without the
    generated-hook marker beside DefenseClaw's entry was not claimed by the
    command shape, so the agent ran it while doctor, status and fail-mode
    passed (rel-1-0-4 GAP-0600). DefenseClaw's own entry with Setup's command
    but another key (a per-entry ``env`` such as ``BASH_ENV``, a ``cwd``, a
    shorter timeout) runs the hook under the user's terms, so the whole entry
    must be Setup's, as the gateway's presence check requires. Returns the
    entry's command and True when that is what differs, else the entry and
    False.
    """

    if _is_windows() or path.name != _OWNED_HOOK_FILE or not isinstance(document, dict):
        return None  # Windows: the native validators check the handlers
    renders = _owned_file_renders(cfg, connector, current)
    hooks = document.get("hooks")
    if connector == "copilot" and isinstance(hooks, dict):
        bound = [(event, entry) for event in renders if isinstance(hooks.get(event), list) for entry in hooks[event]]
        for event, raw in hooks.items():
            if event in renders:
                continue
            entries = raw if isinstance(raw, list) else [raw]
            for entry in entries:
                if any(current in command for command in _hook_command_strings(entry)):
                    return f"unexpected Copilot event {event}: {json.dumps(entry, sort_keys=True)}", False
    elif connector == "kiro" and isinstance(hooks, list):
        bound = [
            (entry.get("trigger"), entry)
            for entry in hooks
            if isinstance(entry, dict) and entry.get("trigger") in renders
        ]
    else:
        return None
    matched: set[str] = set()
    for event, entry in bound:
        if event not in matched and _same_hook_json(entry, renders[event]):
            matched.add(event)
            continue
        expected = _hook_command_strings(renders[event])
        changed = [command for command in _hook_command_strings(entry) if command not in expected]
        return (changed[0], True) if changed else (json.dumps(entry, sort_keys=True), False)
    return None


def _edited_hook_problem(connector: str, path: Path, runs: str, current: str) -> HookProblem:
    return HookProblem(
        f"{_EDITED_HOOK_PREFIX}{connector}: {path} runs {runs}, not the hook script setup "
        f"registered ({current}), so that entry fails or runs unguarded",
        f"run `defenseclaw doctor --fix` or `{setup_command(connector)} --yes`; it replaces the edited entries",
    )


def _independent_handler_problem(connector: str, path: Path, runs: str, current: str) -> HookProblem:
    """Another entry on a bound event of DefenseClaw's own Copilot file.

    Setup replaces DefenseClaw's own entries there, but it cannot restore the
    event without dropping a handler that is not DefenseClaw's: it refuses
    that event and the gateway does not start the connector
    (hook_only.go copilotIndependentHandler, GAP-2372). The repair names the
    move first.
    """

    return HookProblem(
        f"{_EDITED_HOOK_PREFIX}{connector}: {path} runs {runs}, not the hook script setup "
        f"registered ({current}), so that entry fails or runs unguarded",
        f"move a handler that is not DefenseClaw's to another file in {path.parent} (Copilot reads every hook "
        f"file there), then run `{setup_command(connector)} --yes`; it replaces DefenseClaw's edited entries",
    )


def edited_hook_problems(cfg: Any, connector: str) -> list[str]:
    """Report DefenseClaw hook entries whose script path or name was edited.

    An edited entry keeps running a script that is not there: Copilot then
    denied every call next to the set setup added again, and Hermes, whose
    hook failures are fail-open, ran unguarded (GAP-0906, GAP-0907). An
    entry repointed at a copy of the script runs a hook DefenseClaw does not
    keep current, from any folder (rel-1-0-4 GAP-0600), and in DefenseClaw's
    own file any entry on a bound event that is not Setup's render
    (:func:`_foreign_owned_file_entry`). Setup (``doctor --fix`` restarts
    the gateway, which runs it) replaces them.
    """

    script_name = HOOK_SCRIPT_NAMES.get(connector)
    if os.name == "nt" or not script_name:
        return []
    data_dir = os.path.normpath(str(getattr(cfg, "data_dir", "") or ""))
    current = os.path.join(data_dir, "hooks", script_name)
    # Reported: an edited path under this install's home, and a command that
    # runs any copy of a DefenseClaw hook script (copied_hook_script), even
    # through a wrapper or from another data directory. An unedited entry of
    # another data directory is not reported here.
    owner = os.path.dirname(data_dir).rstrip("/") + "/"
    written = _hermes_written_command(cfg, connector)
    for path in _hook_config_paths(cfg, connector):
        try:
            if not path.is_file() or path.stat().st_size > _CONFIG_LIMIT:
                continue
            document = _load_agent_document(path)
        except (OSError, ValueError, ImportError):
            continue
        foreign = _foreign_owned_file_entry(cfg, connector, path, document, current)
        if foreign is not None:
            runs, command_changed = foreign
            # Setup's command with a type, timeout, matcher or enabled flag
            # that leaves the tool call unchecked: that check names the field.
            unguarded = [] if command_changed else unguarded_tool_call_hooks(cfg, connector)
            if not unguarded and connector == "copilot" and command_changed:
                return [_independent_handler_problem(connector, path, repr(runs.strip()), current)]
            return unguarded or [_edited_hook_problem(connector, path, repr(runs.strip()), current)]
        for command in _hook_command_strings(document):
            if written is not None and not written(command):
                continue
            word = edited_hook_script(command, script_name)
            first = (_split_hook_command(command.strip()) or ("",))[0]
            if word and first != current and (first.startswith(owner) or copied_hook_script(command, script_name)):
                return [
                    _edited_hook_problem(connector, path, word if first == word else repr(command.strip()), current)
                ]
    return []
