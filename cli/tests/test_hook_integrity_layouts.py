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

import hashlib
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
    # The golden commands name launchers of another host; the launcher file
    # check has its own tests (test_hook_launcher_encoded_bridge.py).
    monkeypatch.setattr(hook_integrity, "_launcher_health", lambda launcher, data_dir="": hook_integrity.LauncherHealth())
    command = _LAYOUTS["windows_commands"][connector]
    assert "defenseclaw" not in command.lower()
    cfg, config = _install(tmp_path, connector, _windows_document(connector, command))
    if connector == "copilot":
        # This fixture pins presence detection, but has only one event and no
        # native contract evidence, so it is not a healthy Copilot install.
        assert hook_integrity._registers_defenseclaw_hooks(cfg, connector, config, strict=False)
        assert hook_registration_problems(cfg, connector)
    else:
        # The file scan is under test; Doctor's native verdict has its own tests.
        monkeypatch.setattr(hook_integrity, "_windows_native_problem", lambda cfg, connector: None)
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
    # The file scan is under test; Doctor's native verdict has its own tests.
    monkeypatch.setattr(hook_integrity, "_windows_native_problem", lambda cfg, connector: None)
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
    # The one-line install runs its GUI-subsystem guard beside the launcher
    # (GAP-2467), a repository build its gateway (GAP-1011 round 2); no other
    # DefenseClaw program is one.
    import ntpath

    bin_dir = ntpath.dirname(golden["launcher"])
    for program in ("defenseclaw-hook-guard.exe", "defenseclaw-gateway.exe"):
        guard = {**pretool, "command": ntpath.join(bin_dir, program)}
        assert hook_integrity.claude_launcher_guard_view(guard) == golden["exec"], program
        assert hook_integrity.hook_handler_command_lines(guard, "claudecode") == expected, program
    for command in (
        ntpath.join(bin_dir, "defenseclaw-acp.exe"),
        "defenseclaw-gateway.exe",
        "defenseclaw-hook-guard.exe",
    ):
        other = {**pretool, "command": command}
        assert hook_integrity.claude_launcher_guard_view(other) is other, command


def test_claude_chain_view_and_guard_drift(tmp_path, monkeypatch):
    monkeypatch.setenv("SystemRoot", "C:\\Windows")
    monkeypatch.setattr(hook_integrity, "_is_windows", lambda: True)
    chain = tmp_path / "chain"
    chain.mkdir()
    generation = "chain-abc123"
    pair = chain / generation
    pair.mkdir()
    guard = pair / "defenseclaw-hook-guard.exe"
    approved = pair / "defenseclaw-hook-guard.approved"
    body = b"approved guard image"
    guard.write_bytes(body)
    approved.write_bytes(body)
    (chain / "chain.json").write_text(json.dumps({"guard_sha256": hashlib.sha256(body).hexdigest(), "generation": generation}))
    launcher = str(tmp_path / "defenseclaw-hook.exe")
    command = "C:\\Windows\\System32\\cmd.exe"
    compare = "C:\\Windows\\System32\\fc.exe"
    words = hook_integrity._claude_chain_wrapper_words(
        compare, str(guard), str(approved), launcher, "UserPromptSubmit"
    )
    handler = {"type": "command", "command": command, "args": words}
    assert hook_integrity.claude_launcher_guard_view(handler) == {
        **handler, "command": launcher, "args": ["hook", "--connector", "claudecode"]
    }
    cfg, _ = _install(tmp_path, "claudecode", json.dumps({"hooks": {"UserPromptSubmit": [{"hooks": [handler]}]}}))
    assert hook_integrity.hook_launcher_problems(cfg, "claudecode") == []
    guard.write_bytes(b"changed guard")
    problems = hook_integrity.hook_launcher_problems(cfg, "claudecode")
    assert len(problems) == 1 and "missing or changed" in problems[0]
    assert "defenseclaw setup claude-code" in problems[0].repair
    edited = {**handler, "args": [*words[:-1], "0"]}
    assert hook_integrity.claude_launcher_guard_view(edited) is edited
    neutral = hook_integrity._claude_chain_wrapper_words(compare, str(guard), str(approved), launcher, "Stop")
    assert neutral[-1] == "1"
    direct = {"command": str(guard),
              "args": ["launcher-guard", launcher, "hook", "--connector", "claudecode", "--event", "PreToolUse"]}
    assert hook_integrity.claude_launcher_guard_view(direct)["command"] == launcher


def test_claude_chain_profile_bound_open_answer_is_owned(tmp_path):
    launcher = str(tmp_path / "defenseclaw-hook.exe")
    guard = str(tmp_path / "chain-abc123" / "defenseclaw-hook-guard.exe")
    approved = str(tmp_path / "chain-abc123" / "defenseclaw-hook-guard.approved")
    compare = "C:\\Windows\\System32\\fc.exe"
    command = "C:\\Windows\\System32\\cmd.exe"
    words = hook_integrity._claude_chain_wrapper_words(
        compare, guard, approved, launcher, "UserPromptSubmit", unavailable_open=True
    )
    handler = {"command": command, "args": words}
    assert words[-1] == "1"
    assert hook_integrity.claude_launcher_guard_view(handler)["command"] == launcher
    changed = {**handler, "args": [*words[:-1], "2"]}
    assert hook_integrity.claude_launcher_guard_view(changed) is changed
    direct = {"command": guard, "args": [
        "launcher-guard", launcher, "hook", "--connector", "claudecode",
        "--event", "PreToolUse", "--unavailable-mode", "open",
    ]}
    assert hook_integrity.claude_launcher_guard_view(direct)["args"] == ["hook", "--connector", "claudecode"]


def test_managed_claude_guard_view_carries_closed_and_neutral_answers(monkeypatch):
    monkeypatch.setenv("SystemRoot", "C:\\Windows")
    launcher = "C:\\Program Files\\DefenseClaw\\bin\\defenseclaw-hook.exe"
    guard = "C:\\Program Files\\DefenseClaw\\bin\\defenseclaw-hook-guard.exe"
    for event, unavailable_exit in (("UserPromptSubmit", "2"), ("PreToolUse", "2"),
                                    ("Stop", "1"), ("SubagentStop", "1")):
        words = hook_integrity._claude_managed_wrapper_words(guard, launcher, event)
        handler = {"command": "C:\\Windows\\System32\\cmd.exe", "args": words}
        assert words[-1] == unavailable_exit
        # A missing guard gives the reason that names it and the repair command.
        missing = " ".join(words[words.index("(") + 1:words.index(")")])
        assert "defenseclaw-hook-guard.exe" in missing
        assert "DefenseClawSetup-Enterprise-Standalone-x64.exe /repair" in missing
        assert "enterprise windows repair" not in missing
        assert missing.endswith(f"exit /b {unavailable_exit}")
        assert hook_integrity.claude_launcher_guard_view(handler) == {
            **handler,
            "command": launcher,
            "args": ["hook", "--connector", "claudecode", "--enterprise-managed"],
        }
        edited = {**handler, "args": [*words[:-1], "0"]}
        assert hook_integrity.claude_launcher_guard_view(edited) is edited


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


def _hermes_with_kept_entries(config: Path, data_dir: Path, *, keep_current: bool = True) -> None:
    """Rewrite the healthy Hermes config as repair leaves it: the user hook and an edited one kept, the allowlist unchanged."""

    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    edited = {"command": str(data_dir / "hooks" / "hookX"), "timeout": 30}
    kept = [{"command": "/usr/local/bin/audit-tool-calls", "timeout": 5}, edited]
    entries = document["hooks"]["pre_tool_call"]
    document["hooks"]["pre_tool_call"] = [*kept, *(entries if keep_current else [])]
    config.write_text(yaml.safe_dump(document), encoding="utf-8")


@posix_only
def test_a_kept_unapproved_edited_hermes_entry_is_not_a_registration_problem(tmp_path, monkeypatch):
    # GAP-0873: repair keeps a hand-edited entry beside the current one and
    # approves only the entries it writes. The registration check asked for an
    # approval of the kept entry too, so the repair failed and rolled back.
    monkeypatch.chdir(tmp_path)
    cfg, config = _install(tmp_path, "hermes", _LAYOUTS["hermes"]["healthy"])
    _hermes_with_kept_entries(config, Path(cfg.data_dir))
    assert hook_registration_problems(cfg, "hermes") == []
    assert hook_command_problems(cfg, "hermes") == []


@posix_only
def test_a_hermes_registration_with_only_an_edited_entry_is_reported(tmp_path, monkeypatch):
    # The benign twin above must not hide a registration that lost the current
    # command: an entry under the hooks folder that Setup did not write belongs
    # to the user, so the tool call is unguarded.
    monkeypatch.chdir(tmp_path)
    cfg, config = _install(tmp_path, "hermes", _LAYOUTS["hermes"]["healthy"])
    _hermes_with_kept_entries(config, Path(cfg.data_dir), keep_current=False)
    assert hook_registration_problems(cfg, "hermes")


@posix_only
def test_the_current_hermes_entry_still_needs_its_approval(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg, config = _install(tmp_path, "hermes", _LAYOUTS["hermes"]["healthy"])
    _hermes_with_kept_entries(config, Path(cfg.data_dir))
    (config.parent / hook_integrity.HERMES_ALLOWLIST_FILE).write_text(json.dumps({"approvals": []}), encoding="utf-8")
    problems = hook_registration_problems(cfg, "hermes")
    assert problems and "no approval" in problems[0]


_KEPT_ENTRY_FORMS = {
    "wrapped renamed hook": "bash {hooks}/hookX",
    "wrapped, quoted": "bash \"{hooks}/hookX\"",
    "renamed hook with arguments": "{hooks}/hookX --event pre_tool_call",
    "padded edited script": " {hooks}/hermes-hook.sh.off --event pre_tool_call",
    "trailing blank on edited script": "{hooks}/hermes-hook.sh.off --event pre_tool_call ",
}


@posix_only
@pytest.mark.parametrize("form", sorted(_KEPT_ENTRY_FORMS))
def test_every_check_leaves_a_kept_hermes_entry_alone(tmp_path, monkeypatch, form):
    # GAP-0873: Setup keeps and lists an entry it did not write, however the
    # command spells a path under the hooks folder. The check for commands the
    # shell can run and the edited-entry check judged them anyway, so the
    # registration Setup had just written failed readiness.
    monkeypatch.chdir(tmp_path)
    cfg, config = _install(tmp_path, "hermes", _LAYOUTS["hermes"]["healthy"])
    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    kept = _KEPT_ENTRY_FORMS[form].format(hooks=Path(cfg.data_dir) / "hooks")
    document["hooks"]["pre_tool_call"].insert(0, {"command": kept, "timeout": 30})
    config.write_text(yaml.safe_dump(document), encoding="utf-8")
    assert hook_command_problems(cfg, "hermes") == []
    assert hook_integrity.edited_hook_problems(cfg, "hermes") == []
    assert hook_registration_problems(cfg, "hermes") == []


@posix_only
def test_an_unpadded_edited_hermes_script_is_still_reported(tmp_path, monkeypatch):
    # The twin of the kept forms above: the generated script at an edited path
    # is an entry Setup wrote, which it replaces, so doctor still reports it.
    monkeypatch.chdir(tmp_path)
    cfg, config = _install(tmp_path, "hermes", _LAYOUTS["hermes"]["healthy"])
    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    edited = str(Path(cfg.data_dir, "hooks", "hermes-hook.sh.off")) + " --event pre_tool_call"
    document["hooks"]["pre_tool_call"].insert(0, {"command": edited, "timeout": 30})
    config.write_text(yaml.safe_dump(document), encoding="utf-8")
    assert any("hook command edited" in problem for problem in hook_command_problems(cfg, "hermes"))
