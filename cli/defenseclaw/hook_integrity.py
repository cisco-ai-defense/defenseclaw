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

import json
import os
import re
import shlex
import stat
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
            problems.append(f"hook script {script} is missing")
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


def _registration_text(text: str) -> str:
    """The part of an agent config file that can register DefenseClaw hooks.

    Setup also writes ``env`` entries that name DefenseClaw (the OTLP headers
    and resource attributes in ``~/.claude/settings.json``), so a whole-file
    match kept a settings file with no hooks looking registered (GAP-1230).
    For a JSON object only its ``hooks`` section counts; other formats are
    matched as a whole.
    """

    try:
        data = json.loads(text)
    except ValueError:
        return text.lower()
    if not isinstance(data, dict):
        return text.lower()
    if "hooks" in data:
        return json.dumps(data["hooks"]).lower()
    return json.dumps({key: value for key, value in data.items() if key != "env"}).lower()


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
    """Report hook config files that no longer mention DefenseClaw at all.

    Setup records the agent config files it registered hooks in
    (``locations.hook_config_paths``). When every one of them that exists has
    lost its DefenseClaw entries (for example the ``hooks`` key was deleted
    from ``~/.claude/settings.json``), the agent runs unguarded; status says
    so instead of showing the connector as normal (GAP-1230). When the
    entries are there, their commands must also be ones the shell can run
    (:func:`hook_command_problems`). Per-user Windows gets the same check: a
    Codex self-update left config.toml without hooks while ``guardrail mode
    action`` reported success (GAP-1035).
    """

    windows = _is_windows()
    if windows:
        launcher = hook_launcher_problems(cfg, connector)
        if launcher or str(getattr(cfg, "deployment_mode", "") or "").strip().lower() == "managed_enterprise":
            return launcher
    existing: list[Path] = []
    for path in _hook_config_paths(cfg, connector):
        try:
            if not path.is_file() or path.stat().st_size > _CONFIG_LIMIT:
                continue
            if "defenseclaw" in _registration_text(path.read_text(encoding="utf-8", errors="replace")):
                commands = [] if windows else hook_command_problems(cfg, connector)
                return commands or agent_hook_switch_problems(cfg, connector)
        except OSError:
            continue
        existing.append(path)
    if not existing:
        return agent_hook_switch_problems(cfg, connector)
    return [f"no DefenseClaw hooks are registered in {existing[0]}"]


def _read_agent_config(path: Path) -> Any:
    try:
        if not path.is_file() or path.stat().st_size > _CONFIG_LIMIT:
            return None
        return _load_agent_document(path)
    except (OSError, ValueError):
        return None


def _load_agent_document(path: Path) -> Any:
    raw = path.read_bytes()
    return codex_toml.loads(raw) if path.suffix == ".toml" else json.loads(raw.decode("utf-8", errors="replace"))


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
    the other rows stay green (GAP-0382). Setup writes the path quoted.
    """

    if os.name == "nt":
        return []
    hooks_dir = os.path.join(str(getattr(cfg, "data_dir", "") or ""), "hooks")
    for path in _hook_config_paths(cfg, connector):
        try:
            if not path.is_file() or path.stat().st_size > _CONFIG_LIMIT:
                continue
            document = _load_agent_document(path)
        except (OSError, ValueError):
            continue
        for command in _registered_commands(document):
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
