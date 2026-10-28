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

"""Hook registration and command checks against the files Setup writes.

fixtures/hook_layouts/hook_layouts.json holds the agent config file each
Bedrock connector's Go Setup writes on a POSIX host (Claude Code, Codex,
Copilot, Hermes, OpenCode), the same files with the hook entries removed but
other DefenseClaw text left (GAP-1311), and the Windows launcher commands.
internal/gateway/connector/testdata/claudecode_windows_handlers.json holds the
handlers per-user Windows Setup writes for Claude Code: the cmd.exe launcher
guard of 1.0.1 and later, the PreToolUse guard of 1.0.4 (the installed full
hook started with launcher-guard) and the exec form of 1.0.0; the Go test
TestClaudeCodeWindowsHandlersMatchTheSharedGolden checks it against Setup
(GAP-0463).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from defenseclaw import hook_integrity
from defenseclaw.hook_integrity import hook_command_problems, hook_registration_problems

_LAYOUTS = json.loads(
    (Path(__file__).resolve().parent / "fixtures" / "hook_layouts" / "hook_layouts.json").read_text(encoding="utf-8")
)
_CLAUDE_WINDOWS = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "internal"
        / "gateway"
        / "connector"
        / "testdata"
        / "claudecode_windows_handlers.json"
    ).read_text(encoding="utf-8")
)
_CONNECTORS = ["claudecode", "codex", "copilot", "hermes", "opencode"]
_REMOVABLE = ["claudecode", "codex", "copilot", "hermes"]

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX hook layouts")


def approve_hermes_hooks(config: Path) -> None:
    """Approve every hook of the Hermes *config* in its shell-hooks-allowlist.json, as Setup does.

    Hermes skips a shell hook it has not approved (rel-1-0-4 GAP-0339).
    """

    hooks = (yaml.safe_load(config.read_text(encoding="utf-8")) or {}).get("hooks") or {}
    approvals = [
        {"event": event, "command": entry["command"].strip(), "defenseclaw_managed": True}
        for event, entries in hooks.items()
        for entry in entries or ()
        if isinstance(entry, dict) and isinstance(entry.get("command"), str)
    ]
    allowlist = config.parent / hook_integrity.HERMES_ALLOWLIST_FILE
    allowlist.write_text(json.dumps({"approvals": approvals}), encoding="utf-8")


def _install(tmp_path: Path, connector: str, document: str, *, data_dir: Path | None = None, extra: list[Path] = ()):
    home = tmp_path / "home"
    data_dir = data_dir or home / ".defenseclaw"
    data_dir.mkdir(parents=True, exist_ok=True)
    config = home / _LAYOUTS[connector]["file"]
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(document.replace("{data_dir}", str(data_dir)).replace("{home}", str(home)), encoding="utf-8")
    if connector == "hermes":
        approve_hermes_hooks(config)
    paths = [str(config), *map(str, extra)]
    lock = {"version": 2, "connectors": {connector: {"locations": {"hook_config_paths": paths}}}}
    (data_dir / "hook_contract_lock.json").write_text(json.dumps(lock), encoding="utf-8")
    return SimpleNamespace(data_dir=str(data_dir), deployment_mode=""), config


@posix_only
@pytest.mark.parametrize("connector", _CONNECTORS)
def test_the_file_setup_writes_is_registered(tmp_path, monkeypatch, connector):
    monkeypatch.chdir(tmp_path)
    cfg, _ = _install(tmp_path, connector, _LAYOUTS[connector]["healthy"])
    assert hook_registration_problems(cfg, connector) == []
    assert hook_command_problems(cfg, connector) == []


@posix_only
@pytest.mark.parametrize("connector", _REMOVABLE)
def test_removed_hooks_are_reported_though_other_defenseclaw_text_stays(tmp_path, monkeypatch, connector):
    # GAP-1311: the Codex [otel] x-defenseclaw-source headers and notify
    # bridge, the Claude Code OTEL env and an MCP server entry name DefenseClaw
    # but register no hook.
    monkeypatch.chdir(tmp_path)
    removed = _LAYOUTS[connector]["removed"]
    assert "defenseclaw" in removed.lower()
    cfg, config = _install(tmp_path, connector, removed)
    assert hook_registration_problems(cfg, connector) == [f"no DefenseClaw hooks are registered in {config}"]


@posix_only
def test_json_settings_without_a_hooks_key_are_not_registered(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    document = json.dumps({"statusLine": {"command": "{data_dir}/hooks/claude-code-hook.sh"}})
    cfg, config = _install(tmp_path, "claudecode", document)
    assert hook_registration_problems(cfg, "claudecode") == [f"no DefenseClaw hooks are registered in {config}"]


@posix_only
def test_a_hook_that_is_not_defenseclaws_does_not_count(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    document = json.dumps({"hooks": {"PreToolUse": [{"hooks": [{"command": "/usr/local/bin/defenseclaw-audit.sh"}]}]}})
    cfg, config = _install(tmp_path, "claudecode", document)
    assert hook_registration_problems(cfg, "claudecode") == [f"no DefenseClaw hooks are registered in {config}"]


@posix_only
def test_every_recorded_path_is_checked(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    second = tmp_path / "home" / ".claude" / "settings.local.json"
    second.parent.mkdir(parents=True)
    second.write_text(_LAYOUTS["claudecode"]["removed"], encoding="utf-8")
    cfg, _ = _install(tmp_path, "claudecode", _LAYOUTS["claudecode"]["healthy"], extra=[second])
    assert hook_registration_problems(cfg, "claudecode") == [f"no DefenseClaw hooks are registered in {second}"]


@posix_only
def test_copilot_bash_hook_command_with_an_unquoted_space_cannot_run(tmp_path, monkeypatch):
    # GAP-1385: Copilot registers `bash` entries, which the command check skipped.
    monkeypatch.chdir(tmp_path)
    data_dir = tmp_path / "dc user" / ".defenseclaw"
    script = data_dir / "hooks" / "copilot-hook.sh"
    entry = {"type": "command", "bash": f"'{script}' --event 'preToolUse'", "timeoutSec": 30}
    good = json.dumps({"version": 1, "hooks": {"preToolUse": [entry]}})
    cfg, config = _install(tmp_path, "copilot", good, data_dir=data_dir)
    assert hook_registration_problems(cfg, "copilot") == []
    config.write_text(
        json.dumps({"version": 1, "hooks": {"preToolUse": [{**entry, "bash": f"{script} --event preToolUse"}]}}),
        encoding="utf-8",
    )
    problems = hook_command_problems(cfg, "copilot")
    assert problems and "cannot run" in problems[0] and str(config) in problems[0]
    assert hook_registration_problems(cfg, "copilot") == problems


@posix_only
def test_hermes_yaml_hook_command_with_an_unquoted_space_cannot_run(tmp_path, monkeypatch):
    # GAP-1467: the Hermes config.yaml was parsed as JSON, so its commands went unchecked.
    monkeypatch.chdir(tmp_path)
    data_dir = tmp_path / "dc user" / ".defenseclaw"
    script = data_dir / "hooks" / "hermes-hook.sh"
    fields = "      matcher: .*\n      timeout: 30\n"
    cfg, config = _install(
        tmp_path, "hermes", f"hooks:\n  pre_tool_call:\n    - command: \"'{script}'\"\n{fields}", data_dir=data_dir
    )
    assert hook_registration_problems(cfg, "hermes") == []
    config.write_text(f"hooks:\n  pre_tool_call:\n    - command: {script}\n{fields}", encoding="utf-8")
    problems = hook_command_problems(cfg, "hermes")
    assert problems and "cannot run" in problems[0] and str(config) in problems[0]


def _windows_document(connector: str, command: str) -> str:
    if connector == "codex":
        return (
            "[hooks]\n[[hooks.PreToolUse]]\nmatcher = '*'\n\n[[hooks.PreToolUse.hooks]]\n"
            f"command = '{command}'\ncommand_windows = '{command}'\ntimeout = 30\ntype = 'command'\n"
            "\n[otel.exporter.otlp-http.headers]\nx-defenseclaw-source = 'codex'\n"
        )
    if connector == "copilot":
        entry = {"type": "command", "powershell": command, "timeoutSec": 30}
        return json.dumps({"version": 1, "hooks": {"preToolUse": [entry]}})
    if connector == "hermes":
        return f"hooks:\n  pre_tool_call:\n    - command: '{command}'\n      matcher: .*\n      timeout: 30\n"
    handler = {"type": "command", "command": command, "timeout": 30}
    return json.dumps({"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [handler]}]}})


@pytest.mark.parametrize("connector", ["claudecode", "codex", "copilot", "hermes"])
def test_windows_launcher_registrations_are_registered(tmp_path, monkeypatch, connector):
    # Per-user Windows registers the native launcher inside a PowerShell
    # -EncodedCommand; the plain command text never names DefenseClaw.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(hook_integrity, "_is_windows", lambda: True)
    command = _LAYOUTS["windows_commands"][connector]
    assert "defenseclaw" not in command.lower()
    cfg, config = _install(tmp_path, connector, _windows_document(connector, command))
    if connector == "copilot":
        # This fixture pins presence detection, but has only one event and no
        # native contract evidence, so it is not a healthy Copilot install.
        assert hook_integrity._registers_defenseclaw_hooks(cfg, connector, config, strict=False)
        assert hook_registration_problems(cfg, connector)
    else:
        assert hook_registration_problems(cfg, connector) == []

    removed = {"codex": "[otel.exporter.otlp-http.headers]\nx-defenseclaw-source = 'codex'\n"}.get(
        connector, json.dumps({"hooks": {}, "env": {"OTEL_RESOURCE_ATTRIBUTES": "defenseclaw.connector=x"}})
    )
    if connector == "hermes":
        removed = "mcp_servers:\n  defenseclaw:\n    command: defenseclaw\n"
    config.write_text(removed, encoding="utf-8")
    assert hook_registration_problems(cfg, connector) == [f"no DefenseClaw hooks are registered in {config}"]


def _with_launcher(value, launcher: str):
    if isinstance(value, dict):
        return {key: _with_launcher(item, launcher) for key, item in value.items()}
    if isinstance(value, list):
        return [_with_launcher(item, launcher) for item in value]
    return launcher if value == _CLAUDE_WINDOWS["launcher"] else value


def _claude_windows_settings(handler: dict, launcher: str) -> str:
    entry = {**_with_launcher(handler, launcher), "timeout": 30}
    hooks = {event: [{"matcher": "*", "hooks": [entry]}] for event in ("PreToolUse", "PostToolUse", "UserPromptSubmit")}
    env = {"OTEL_RESOURCE_ATTRIBUTES": "defenseclaw.connector=claudecode"}
    return json.dumps({"env": env, "hooks": hooks})


@pytest.mark.parametrize("form", ["guard", "pretool_guard", "exec"])
def test_windows_claude_code_handlers_setup_writes_are_registered(tmp_path, monkeypatch, form):
    # GAP-0463: since 1.0.1 per-user Windows Setup runs the launcher through
    # cmd.exe (command = cmd.exe, launcher only in args). status read only the
    # command key and reported "no DefenseClaw hooks are registered" while
    # doctor passed the same 29 handlers. 1.0.0 wrote the exec form.
    from defenseclaw.commands.cmd_status import _hook_runtime_degraded_suffix

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(hook_integrity, "_is_windows", lambda: True)
    monkeypatch.setenv("SystemRoot", "C:\\Windows")
    launcher = tmp_path / "bin" / "defenseclaw-hook.exe"
    launcher.parent.mkdir()
    launcher.write_bytes(b"MZ")
    handler = _CLAUDE_WINDOWS[form]
    guard = tmp_path / "Programs" / "bin" / "defenseclaw-hook.exe"
    if form == "pretool_guard":
        # The PreToolUse guard is the installed full hook, a second file.
        guard.parent.mkdir(parents=True)
        guard.write_bytes(b"MZ")
        handler = {**handler, "command": str(guard)}
    cfg, config = _install(tmp_path, "claudecode", _claude_windows_settings(handler, str(launcher)))
    assert hook_registration_problems(cfg, "claudecode") == []
    assert _hook_runtime_degraded_suffix(cfg, "claudecode") == ""

    removed = {"env": {"OTEL_RESOURCE_ATTRIBUTES": "defenseclaw.connector=claudecode"}, "hooks": {}}
    config.write_text(json.dumps(removed), encoding="utf-8")
    assert hook_registration_problems(cfg, "claudecode") == [f"no DefenseClaw hooks are registered in {config}"]
    assert "DEGRADED" in _hook_runtime_degraded_suffix(cfg, "claudecode")


def test_status_and_doctor_read_the_claude_launcher_guard_the_same_way(monkeypatch):
    # One guard parser for both: doctor's hook matrix and the status check.
    import subprocess

    from defenseclaw import doctor_hooks

    monkeypatch.setenv("SystemRoot", "C:\\Windows")
    golden = _CLAUDE_WINDOWS
    assert doctor_hooks.claude_launcher_guard_view is hook_integrity.claude_launcher_guard_view
    assert not hasattr(doctor_hooks, "_claude_launcher_guard_view")
    view = hook_integrity.claude_launcher_guard_view(golden["guard"])
    assert view == golden["exec"]
    expected = [subprocess.list2cmdline([golden["launcher"], "hook", "--connector", "claudecode"])]
    assert hook_integrity.hook_handler_command_lines(golden["guard"], "claudecode") == expected
    assert hook_integrity.hook_handler_command_lines(golden["exec"], "claudecode") == expected
    # An edited guard is not the view doctor validates; status still sees the launcher it names.
    edited = {**golden["guard"], "args": [*golden["guard"]["args"][:-2], "0", ")"]}
    assert hook_integrity.claude_launcher_guard_view(edited) is edited
    assert golden["launcher"] in hook_integrity.hook_handler_command_lines(edited, "claudecode")[0]
    # The PreToolUse guard (GAP-1011) reads as the same exec form.
    assert hook_integrity.claude_launcher_guard_view(golden["pretool_guard"]) == golden["exec"]
    assert hook_integrity.hook_handler_command_lines(golden["pretool_guard"], "claudecode") == expected
    pretool = golden["pretool_guard"]
    for args in (
        [*pretool["args"], "--fail-open"],
        ["guard", *pretool["args"][1:]],
        [pretool["args"][0], "defenseclaw-hook.exe", *pretool["args"][2:]],
        [pretool["args"][0], "C:\\Windows\\System32\\cmd.exe", *pretool["args"][2:]],
        [*pretool["args"][:-1], "codex"],
    ):
        changed = {**pretool, "args": args}
        assert hook_integrity.claude_launcher_guard_view(changed) is changed, args
    same = {**pretool, "command": golden["launcher"]}
    assert hook_integrity.claude_launcher_guard_view(same) is same


def test_windows_copilot_adapter_in_a_data_dir_not_named_defenseclaw_is_registered(tmp_path, monkeypatch):
    # The Windows Copilot entry runs the PowerShell adapter in the data
    # directory's hooks folder; only the data directory names DefenseClaw, and
    # DEFENSECLAW_HOME may not. Doctor reads the adapter, so status must too.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(hook_integrity, "_is_windows", lambda: True)
    data_dir = tmp_path / "agent-guard"
    adapter = data_dir / "hooks" / "copilot-hook.ps1"
    command = f"& '{adapter}' -Event 'preToolUse'"
    if "defenseclaw" in command.lower():
        pytest.skip("the temporary folder names DefenseClaw")
    entry = {"type": "command", "powershell": command, "timeoutSec": 30}
    document = json.dumps({"version": 1, "hooks": {"preToolUse": [entry]}})
    cfg, config = _install(tmp_path, "copilot", document, data_dir=data_dir)
    assert hook_integrity._registers_defenseclaw_hooks(cfg, "copilot", config, strict=False)
    assert hook_registration_problems(cfg, "copilot")  # one event and an incomplete native lock
    config.write_text(json.dumps({"version": 1, "hooks": {}}), encoding="utf-8")
    assert hook_registration_problems(cfg, "copilot") == [f"no DefenseClaw hooks are registered in {config}"]
