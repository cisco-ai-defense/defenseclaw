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

"""GAP-0645: doctor and status catch a Claude Code settings file without the DefenseClaw PreToolUse hook."""

from __future__ import annotations

import json
import sys
from types import SimpleNamespace

import pytest
from defenseclaw.commands import cmd_doctor, cmd_status
from defenseclaw.commands.cmd_doctor import _DoctorResult
from defenseclaw.hook_integrity import hook_registration_problems, repair_command, unguarded_tool_call_hooks

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Unix hook scripts only")

_EVENTS = ("SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop")


def _settings(tmp_path, *, events=_EVENTS, foreign_pre_tool_use=False):
    data_dir = tmp_path / ".defenseclaw"
    (data_dir / "hooks").mkdir(parents=True, exist_ok=True)
    script = str(data_dir / "hooks" / "claude-code-hook.sh")
    hooks = {event: [{"matcher": "*", "hooks": [{"type": "command", "command": script, "timeout": 30}]}] for event in events}
    if foreign_pre_tool_use:
        hooks["PreToolUse"] = [{"matcher": "*", "hooks": [{"type": "command", "command": "/usr/local/bin/lint-guard"}]}]
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"hooks": hooks}), encoding="utf-8")
    lock = {"version": 2, "connectors": {"claudecode": {"locations": {"hook_config_paths": [str(settings)]}}}}
    (data_dir / "hook_contract_lock.json").write_text(json.dumps(lock), encoding="utf-8")
    return SimpleNamespace(data_dir=str(data_dir)), settings


def test_status_reports_a_missing_pre_tool_use_hook(tmp_path):
    cfg, settings = _settings(tmp_path)
    assert hook_registration_problems(cfg, "claudecode") == []

    cfg, settings = _settings(tmp_path, events=tuple(event for event in _EVENTS if event != "PreToolUse"))
    problems = hook_registration_problems(cfg, "claudecode")
    assert problems and "PreToolUse" in problems[0] and str(settings) in problems[0]
    assert "tool calls are not inspected" in problems[0]
    assert repair_command("claudecode", problems[0]).startswith("run `defenseclaw setup claude-code --yes`")
    suffix = cmd_status._hook_runtime_degraded_suffix(cfg, "claudecode")
    assert "DEGRADED" in suffix and "PreToolUse" in suffix


def test_a_foreign_pre_tool_use_hook_does_not_count(tmp_path):
    cfg, _ = _settings(tmp_path, foreign_pre_tool_use=True)
    problems = unguarded_tool_call_hooks(cfg, "claudecode")
    assert problems and "PreToolUse" in problems[0]


def test_a_file_without_defenseclaw_hooks_is_left_to_the_unregistered_check(tmp_path):
    cfg, settings = _settings(tmp_path)
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [{"hooks": [{"command": "/usr/local/bin/lint-guard"}]}]}}))
    assert unguarded_tool_call_hooks(cfg, "claudecode") == []
    problems = hook_registration_problems(cfg, "claudecode")
    assert problems and problems[0].startswith("no DefenseClaw hooks are registered")


def test_managed_install_needs_one_layer_with_the_hook(tmp_path):
    cfg, settings = _settings(tmp_path, events=tuple(event for event in _EVENTS if event != "PreToolUse"))
    machine = tmp_path / "managed-settings.json"
    hook = {"type": "command", "command": "/opt/cisco/defenseclaw/bin/defenseclaw-hook hook --connector claudecode"}
    machine.write_text(json.dumps({"hooks": {event: [{"matcher": "*", "hooks": [hook]}] for event in _EVENTS}}))
    lock = {
        "version": 2,
        "connectors": {"claudecode": {"locations": {"hook_config_paths": [str(settings), str(machine)]}}},
    }
    (tmp_path / ".defenseclaw" / "hook_contract_lock.json").write_text(json.dumps(lock))
    managed = SimpleNamespace(data_dir=cfg.data_dir, deployment_mode="managed_enterprise")
    assert unguarded_tool_call_hooks(managed, "claudecode") == []
    # Per-user, every recorded file needs it.
    assert unguarded_tool_call_hooks(cfg, "claudecode")


def test_doctor_fails_claude_code_hooks_without_pre_tool_use(tmp_path):
    cfg, settings = _settings(tmp_path)
    result = _DoctorResult(passive=True, quiet=True)
    cmd_doctor._check_claudecode_hooks(cfg, result, platform_name="posix", config_path=str(settings))
    row = next(row for row in result.checks if row.get("label") == "Claude Code hooks")
    assert row["status"] == "pass", row

    cfg, settings = _settings(tmp_path, events=tuple(event for event in _EVENTS if event != "PreToolUse"))
    result = _DoctorResult(passive=True, quiet=True)
    cmd_doctor._check_claudecode_hooks(cfg, result, platform_name="posix", config_path=str(settings))
    row = next(row for row in result.checks if row.get("label") == "Claude Code hooks")
    assert row["status"] == "fail", row
    assert "4 DefenseClaw hook(s) registered, but the DefenseClaw PreToolUse hook is not registered" in row["detail"]
    assert "defenseclaw setup claude-code --yes" in row["remediation"]


def test_windows_status_reports_a_missing_pre_tool_use_hook(tmp_path, monkeypatch):
    """GAP-0068: per-user Windows status marks Claude Code DEGRADED without PreToolUse."""
    from defenseclaw import hook_integrity

    monkeypatch.setattr(hook_integrity, "_is_windows", lambda: True)
    monkeypatch.setattr(hook_integrity, "hook_launcher_problems", lambda cfg, connector: [])
    # The native verdict is healthy here; the file scan below is what is tested.
    monkeypatch.setattr(hook_integrity, "_windows_native_problem", lambda cfg, connector: None)
    data_dir = tmp_path / ".defenseclaw"
    data_dir.mkdir()
    launcher = "C:\\Users\\dcw\\.defenseclaw\\bin\\defenseclaw-hook.exe hook --connector claudecode"
    settings = tmp_path / "settings.json"
    lock = {"version": 2, "connectors": {"claudecode": {"locations": {"hook_config_paths": [str(settings)]}}}}
    (data_dir / "hook_contract_lock.json").write_text(json.dumps(lock), encoding="utf-8")
    cfg = SimpleNamespace(data_dir=str(data_dir))

    def write(events):
        hooks = {
            event: [{"matcher": "*", "hooks": [{"type": "command", "command": launcher, "timeout": 30}]}] for event in events
        }
        settings.write_text(json.dumps({"hooks": hooks}), encoding="utf-8")

    write(_EVENTS)
    assert hook_registration_problems(cfg, "claudecode") == []
    write(tuple(event for event in _EVENTS if event != "PreToolUse"))
    problems = hook_registration_problems(cfg, "claudecode")
    assert problems and "PreToolUse" in problems[0] and "tool calls are not inspected" in problems[0]
    suffix = cmd_status._hook_runtime_degraded_suffix(cfg, "claudecode")
    assert "DEGRADED" in suffix and "PreToolUse" in suffix


def test_windows_status_asks_doctors_registration_check_for_claude_code_gap0645(tmp_path, monkeypatch):
    """GAP-0645: status and Doctor judge the per-user Windows registration with one function.

    The lock names no hook file here, as on the failing host, so the file scan
    finds nothing; the native verdict is what makes status say DEGRADED.
    """
    from defenseclaw import hook_integrity
    from defenseclaw.commands import cmd_doctor
    from defenseclaw.doctor_hooks import WindowsHookCheck

    monkeypatch.setattr(hook_integrity, "_is_windows", lambda: True)
    monkeypatch.setattr(hook_integrity, "hook_launcher_problems", lambda cfg, connector: [])
    data_dir = tmp_path / ".defenseclaw"
    data_dir.mkdir()
    cfg = SimpleNamespace(data_dir=str(data_dir))
    verdict = {
        "check": WindowsHookCheck(
            "missing",
            "Claude Code DefenseClaw hook event PreToolUse is missing; run 'defenseclaw setup claude-code --yes --restart'",
            repair="run `defenseclaw setup claude-code --yes --restart`",
        )
    }
    monkeypatch.setattr(cmd_doctor, "_windows_native_hook_check", lambda cfg, connector: verdict["check"])

    problems = hook_registration_problems(cfg, "claudecode")
    assert problems and "PreToolUse is missing" in problems[0] and "not current" in problems[0]
    suffix = cmd_status._hook_runtime_degraded_suffix(cfg, "claudecode")
    assert "DEGRADED" in suffix and "PreToolUse" in suffix and "setup claude-code --yes --restart" in suffix

    verdict["check"] = WindowsHookCheck("healthy", "healthy Windows-native executable registration")
    assert hook_registration_problems(cfg, "claudecode") == []
    assert cmd_status._hook_runtime_degraded_suffix(cfg, "claudecode") == ""

    def broken(cfg, connector):
        raise OSError("unreadable")

    monkeypatch.setattr(cmd_doctor, "_windows_native_hook_check", broken)
    assert "inspection failed" in hook_registration_problems(cfg, "claudecode")[0]
