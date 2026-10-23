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
import json
import ntpath
import os
import posixpath
import re
import shlex
import stat
import subprocess
from pathlib import Path
from typing import Any

from defenseclaw import codex_toml

_LOCK_LIMIT = 4 * 1024 * 1024


# The Windows native hook launcher is installed by the installer, not by
# setup, so only the installer can put it back (GAP-0378).
LAUNCHER_REINSTALL_STEP = (
    "run the DefenseClaw installer again the way you installed it (for example: "
    "irm https://github.com/cisco-ai-defense/defenseclaw/releases/latest/download/install.ps1 | iex); "
    "setup cannot recreate the launcher"
)
_LAUNCHER_PROBLEM_PREFIX = "the DefenseClaw hook launcher "
_WINDOWS_LAUNCHER = re.compile(r"([A-Za-z]:[\\/][^\"'&|<>\r\n]*?defenseclaw-hook\.exe)", re.IGNORECASE)


def _is_windows() -> bool:
    return os.name == "nt"


class HookProblem(str):
    """A problem sentence that carries the one step that repairs it."""

    repair: str

    def __new__(cls, text: str, repair: str) -> HookProblem:
        problem = super().__new__(cls, text)
        problem.repair = repair
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


def hook_launcher_problems(cfg: Any, connector: str) -> list[str]:
    """Report a Windows hook registration whose native launcher file is gone.

    An antivirus quarantine or a cleanup tool can remove
    ``defenseclaw-hook.exe``; every hook call then fails while status showed
    the connector as running (GAP-0378).
    """

    if not _is_windows() or str(getattr(cfg, "deployment_mode", "") or "").strip().lower() == "managed_enterprise":
        # Managed installs (Secure Client included) keep their own status.
        return []
    for path in _hook_config_paths(cfg, connector):
        try:
            if not path.is_file() or path.stat().st_size > _CONFIG_LIMIT:
                continue
            document = _load_agent_document(path)
        except (OSError, ValueError):
            continue
        for value in _strings(document):
            for match in _WINDOWS_LAUNCHER.finditer(value):
                launcher = match.group(1)
                if not os.path.isfile(launcher):
                    return [f"{_LAUNCHER_PROBLEM_PREFIX}{launcher} is missing, so every hook call fails"]
    return []


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


def hook_runtime_problems(cfg: Any, connector: str) -> list[str]:
    """Return short descriptions of drifted hook files for *connector*."""

    if os.name == "nt":
        return []
    scripts, digests = _locked_hook_scripts(cfg, connector)
    if not scripts:
        return []

    from defenseclaw.fail_mode import _sha256_regular_file

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
    so the fail mode never applies (GAP-0403, GAP-0542).
    """

    for problem in hook_runtime_problems(cfg, connector):
        if "cannot run it" in problem or "no longer exist" in problem:
            return problem
    switched_off = agent_hook_switch_problems(cfg, connector)
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


def claude_launcher_guard_view(handler: Any) -> Any:
    """The exec-form handler a generated cmd.exe launcher guard runs, else *handler* unchanged.

    Doctor's hook matrix and the status registration check both read a
    Claude Code handler through this view (GAP-0463).
    """
    if not isinstance(handler, dict):
        return handler
    command, args = handler.get("command"), handler.get("args")
    if not isinstance(command, str) or not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        return handler
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


def _decoded_command(command: str) -> str:
    """*command*, followed by the script of a PowerShell -EncodedCommand in it."""

    match = _ENCODED_SCRIPT.search(command)
    if not match:
        return command
    try:
        script = base64.b64decode(match.group(1), validate=True).decode("utf-16-le")
    except (ValueError, UnicodeDecodeError):
        return command
    return command + "\n" + script


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
    try:
        document = _load_agent_document(path, raw)
    except ValueError:
        # A file the parser cannot read is reported by the agent itself;
        # never call it unregistered on that ground alone.
        return "defenseclaw" in raw.decode("utf-8", errors="replace").lower()
    section = _hook_section(document, path)
    if section is None:
        return False
    return any(
        _defenseclaw_hook_command(cfg, connector, command, strict=strict)
        for command in _hook_command_lines(section, connector)
    )


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


def hook_registration_problems(cfg: Any, connector: str) -> list[str]:
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
        return commands or missing_tool_inspection_hooks(cfg, connector) or agent_hook_switch_problems(cfg, connector)
    return agent_hook_switch_problems(cfg, connector)


# The hook events whose DefenseClaw handler must be registered for an
# agent's tool calls to be inspected. A Claude Code settings file that kept
# every other DefenseClaw hook but lost PreToolUse left doctor passing
# ("28 DefenseClaw hook(s) registered") and status showing the connector
# running in action mode while no tool call reached DefenseClaw (GAP-0645).
TOOL_INSPECTION_EVENTS: dict[str, tuple[str, ...]] = {
    "claudecode": ("PreToolUse",),
}


def _tool_inspection_strict(cfg: Any) -> bool:
    managed = str(getattr(cfg, "deployment_mode", "") or "").strip().lower() == "managed_enterprise"
    return not _is_windows() and not managed and bool(str(getattr(cfg, "data_dir", "") or ""))


def _tool_inspection_state(cfg: Any, connector: str, document: Any) -> tuple[bool, list[str]]:
    """Whether *document* registers DefenseClaw hooks, and the tool-inspection events it registers none for."""

    events = TOOL_INSPECTION_EVENTS.get(connector, ())
    hooks = document.get("hooks") if isinstance(document, dict) else None
    if not events or not isinstance(hooks, dict):
        return False, []
    strict = _tool_inspection_strict(cfg)

    def registers(value: Any) -> bool:
        return any(
            _defenseclaw_hook_command(cfg, connector, command, strict=strict)
            for command in _hook_command_lines(value, connector)
        )

    if not any(registers(value) for key, value in hooks.items() if key != "state"):
        return False, []
    return True, [event for event in events if not registers(hooks.get(event))]


def missing_tool_inspection_events(cfg: Any, connector: str, document: Any) -> list[str]:
    """The tool-inspection events of *connector* the decoded agent config *document* registers no DefenseClaw hook for.

    A document that registers no DefenseClaw hook at all returns nothing:
    the unregistered-file check reports it.
    """

    return _tool_inspection_state(cfg, connector, document)[1]


def missing_tool_inspection_hooks(cfg: Any, connector: str) -> list[str]:
    """Report recorded agent config files that lost a tool-inspection hook (GAP-0645).

    Every recorded file that registers DefenseClaw hooks must register the
    connector's tool-inspection events too; on a managed install, whose
    hooks may sit in one machine layer, one file is enough. Per-user
    Windows status runs the same check: doctor failed the Claude Code hooks
    row there while status kept the connector RUNNING (GAP-0068).
    """

    if not TOOL_INSPECTION_EVENTS.get(connector):
        return []
    managed = str(getattr(cfg, "deployment_mode", "") or "").strip().lower() == "managed_enterprise"
    gaps: list[tuple[Path, str]] = []
    covered = False
    for path in _hook_config_paths(cfg, connector):
        try:
            if not path.is_file() or path.stat().st_size > _CONFIG_LIMIT:
                continue
            document = _load_agent_document(path)
        except (OSError, ValueError, ImportError):
            continue
        registered, missing = _tool_inspection_state(cfg, connector, document)
        gaps.extend((path, event) for event in missing)
        covered = covered or (registered and not missing)
    if not gaps or (managed and covered):
        return []
    path, event = gaps[0]
    return [tool_inspection_hook_problem(connector, event, str(path))]


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
    """Codex hook handlers that have no command: Codex refuses to load the file."""

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
    (GAP-1094). Codex also refuses to start when hook entries have lost their
    command, for example after hook lines were deleted by hand (GAP-1102).
    Managed installs keep the hooks in machine policy that these settings
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
                        "deleted), so Codex refuses to start",
                        f"run `{setup_command(connector)} --yes`; it removes the entries without a command",
                    )
                )
    return problems


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
    edited = edited_hook_problems(cfg, connector)
    if edited:
        return edited
    hooks_dir = os.path.join(str(getattr(cfg, "data_dir", "") or ""), "hooks")
    for path in _hook_config_paths(cfg, connector):
        try:
            if not path.is_file() or path.stat().st_size > _CONFIG_LIMIT:
                continue
            document = _load_agent_document(path)
        except (OSError, ValueError):
            continue
        for command in _hook_command_strings(document):
            if hooks_dir + os.sep not in command:
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
    return []


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

    Mirrors ``editedDefenseClawHookScript`` / ``editedDefenseClawHookCommand``
    in internal/gateway/connector/helpers.go (the shared golden
    testdata/hook_edited_commands.json keeps them in step): an absolute,
    clean script path whose name is the connector's script name, possibly
    edited around ".sh" (copilot-hookX.sh), under a .defenseclaw directory,
    or the exact name under an edited DefenseClaw data directory, alone or
    with ``--event`` or ``--hook-surface``. Setup replaces such entries; doctor reports the ones
    that are not the current command (GAP-0906, GAP-0907).
    """

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
    if rest and not rest.startswith((" --event ", " --hook-surface ")):
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


def edited_hook_problems(cfg: Any, connector: str) -> list[str]:
    """Report DefenseClaw hook entries whose script path or name was edited.

    An edited entry keeps running a script that is not there: Copilot then
    denied every call next to the set setup added again, and Hermes, whose
    hook failures are fail-open, ran unguarded (GAP-0906, GAP-0907). Setup
    (``doctor --fix`` restarts the gateway, which runs it) replaces them.
    """

    script_name = HOOK_SCRIPT_NAMES.get(connector)
    if os.name == "nt" or not script_name:
        return []
    data_dir = os.path.normpath(str(getattr(cfg, "data_dir", "") or ""))
    current = os.path.join(data_dir, "hooks", script_name)
    # Only an edit of this install's own path is reported; setup also
    # replaces another data directory's entries, which are not an edit.
    owner = os.path.dirname(data_dir).rstrip("/") + "/"
    for path in _hook_config_paths(cfg, connector):
        try:
            if not path.is_file() or path.stat().st_size > _CONFIG_LIMIT:
                continue
            document = _load_agent_document(path)
        except (OSError, ValueError, ImportError):
            continue
        for command in _hook_command_strings(document):
            word = edited_hook_script(command, script_name)
            if word and word != current and word.startswith(owner):
                return [
                    HookProblem(
                        f"{_EDITED_HOOK_PREFIX}{connector}: {path} runs {word}, not the hook script setup "
                        f"registered ({current}), so that entry fails or runs unguarded",
                        f"run `defenseclaw doctor --fix` or `{setup_command(connector)} --yes`; "
                        "it replaces the edited entries",
                    )
                ]
    return []
