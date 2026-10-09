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

"""GAP-1141 / GAP-1138: doctor and status catch a drifted hook script or token."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import sys
from types import SimpleNamespace

import pytest
from defenseclaw.commands.cmd_doctor import _check_hook_runtime_integrity, _DoctorResult
from defenseclaw.hook_integrity import (
    hook_registration_problems,
    hook_runtime_problems,
    repair_command,
    unrunnable_hook_problem,
)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Unix hook scripts only")


def _install(tmp_path):
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    script = hooks / "codex-hook.sh"
    script.write_text('#!/bin/bash\n[ -f "${HOOK_DIR}/.hook-codex.token" ] || exit 2\n')
    script.chmod(0o700)
    (hooks / ".hook-codex.token").write_text("ab" * 32 + "\n")
    digest = "sha256:" + hashlib.sha256(script.read_bytes()).hexdigest()
    lock = {
        "version": 2,
        "connectors": {
            "codex": {
                "locations": {"hook_script_paths": [str(script)]},
                "hook_script_digests": {"codex-hook.sh": digest},
            }
        },
    }
    (tmp_path / "hook_contract_lock.json").write_text(json.dumps(lock))
    return SimpleNamespace(data_dir=str(tmp_path)), script


def test_clean_install_has_no_problems(tmp_path, monkeypatch):
    monkeypatch.delenv("DEFENSECLAW_GATEWAY_TOKEN", raising=False)
    cfg, _ = _install(tmp_path)
    assert hook_runtime_problems(cfg, "codex") == []


def test_edited_script_and_missing_token_fail_doctor(tmp_path, monkeypatch):
    monkeypatch.delenv("DEFENSECLAW_GATEWAY_TOKEN", raising=False)
    cfg, script = _install(tmp_path)
    text = script.read_text().splitlines(keepends=True)
    script.write_text(text[0] + "exit 0\n" + "".join(text[1:]))
    os.remove(tmp_path / "hooks" / ".hook-codex.token")

    problems = hook_runtime_problems(cfg, "codex")
    assert len(problems) == 2
    assert "changed since setup" in problems[0]
    assert ".hook-codex.token is missing" in problems[1]

    r = _DoctorResult(passive=True, quiet=True)
    _check_hook_runtime_integrity(cfg, "codex", r)
    row = next(row for row in r.checks if row.get("label") == "Hook runtime files")
    assert row["status"] == "fail"
    assert "doctor --fix" in row["detail"] and "setup codex" not in row["detail"]

    # GAP-0098: --fix restarts the gateway, which renders the script again.
    from defenseclaw.commands import cmd_doctor

    monkeypatch.setattr(cmd_doctor, "_doctor_active_connectors", lambda _cfg: ["codex"])
    monkeypatch.setattr(
        cmd_doctor, "_trusted_gateway_listener_for_lifecycle", lambda _cfg: SimpleNamespace(trusted=True, detail="")
    )

    def restart(_cfg, *, start_if_stopped):
        script.write_text("".join(text))
        return True, ""

    monkeypatch.setattr(cmd_doctor, "_repair_gateway_lifecycle", restart)
    assert cmd_doctor._fix_hook_script_drift(cfg, assume_yes=True, plan_only=True)[0] == "plan"
    assert cmd_doctor._fix_hook_script_drift(cfg, assume_yes=True)[0] == "pass"
    assert not any("changed since setup" in p for p in hook_runtime_problems(cfg, "codex"))


def test_non_executable_script_fails_doctor_and_fix_restores_it(tmp_path, monkeypatch):
    # GAP-0101: a 0644 hook script made Claude Code run every tool call
    # unguarded while doctor reported healthy and --fix had nothing to do.
    from defenseclaw.commands import cmd_doctor

    monkeypatch.delenv("DEFENSECLAW_GATEWAY_TOKEN", raising=False)
    monkeypatch.setattr(cmd_doctor, "_doctor_active_connectors", lambda _cfg: ["codex"])
    cfg, script = _install(tmp_path)
    script.chmod(0o644)

    r = _DoctorResult(passive=True, quiet=True)
    _check_hook_runtime_integrity(cfg, "codex", r)
    row = next(row for row in r.checks if row.get("label") == "Hook runtime files")
    assert row["status"] == "fail" and "not executable" in row["detail"]

    assert cmd_doctor._fix_hook_script_modes(cfg, assume_yes=True, plan_only=True)[0] == "plan"
    assert cmd_doctor._fix_hook_script_modes(cfg, assume_yes=True)[0] == "pass"
    assert script.stat().st_mode & 0o777 == 0o700
    assert hook_runtime_problems(cfg, "codex") == []


def test_mode_repair_does_not_execute_unreadable_tampered_script(tmp_path, monkeypatch):
    from defenseclaw import hook_integrity
    from defenseclaw.commands import cmd_doctor

    cfg, script = _install(tmp_path)
    script.write_text(script.read_text() + "# modified\n")
    script.chmod(0o000)
    monkeypatch.setattr(cmd_doctor, "_doctor_active_connectors", lambda _cfg: ["codex"])
    original_access = hook_integrity.os.access
    monkeypatch.setattr(
        hook_integrity.os,
        "access",
        lambda path, mode: False if str(path) == str(script) and not script.stat().st_mode & 0o400
        else original_access(path, mode),
    )

    try:
        assert "cannot be read" in hook_runtime_problems(cfg, "codex")[0]
        assert cmd_doctor._fix_hook_script_modes(cfg, assume_yes=True)[0] == "fail"
        assert script.stat().st_mode & 0o777 == 0
    finally:
        script.chmod(0o700)


def test_missing_scoped_token_is_reported_even_with_gateway_token_env(tmp_path, monkeypatch):
    # GAP-1138: doctor loads DEFENSECLAW_GATEWAY_TOKEN from .env, but the
    # connector-scoped hook clears it, so the missing file still breaks hooks.
    monkeypatch.setenv("DEFENSECLAW_GATEWAY_TOKEN", "from-dotenv")
    cfg, _ = _install(tmp_path)
    os.remove(tmp_path / "hooks" / ".hook-codex.token")
    problems = hook_runtime_problems(cfg, "codex")
    assert len(problems) == 1 and ".hook-codex.token is missing" in problems[0]


def test_empty_token_is_a_problem_like_a_missing_one(tmp_path, monkeypatch):
    # GAP-1436: status shows DEGRADED and doctor --fix re-issues both.
    monkeypatch.delenv("DEFENSECLAW_GATEWAY_TOKEN", raising=False)
    cfg, _ = _install(tmp_path)
    (tmp_path / "hooks" / ".hook-codex.token").write_text("")
    problems = hook_runtime_problems(cfg, "codex")
    assert len(problems) == 1 and "is empty or damaged" in problems[0]

    from defenseclaw.commands import cmd_doctor

    cfg.guardrail = SimpleNamespace(connectors={}, connector="codex")
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(cmd_doctor, "_doctor_active_connectors", lambda _cfg: ["codex"])
        assert cmd_doctor._connector_hook_credential_problems(cfg, None) == ["codex"]
        os.remove(tmp_path / "hooks" / ".hook-codex.token")
        assert cmd_doctor._connector_hook_credential_problems(cfg, None) == ["codex"]
    r = _DoctorResult(passive=True, quiet=True)
    _check_hook_runtime_integrity(cfg, "codex", r)
    assert not [row for row in r.checks if row.get("label") == "Hook runtime files"]


def test_removed_hook_registration_is_reported(tmp_path):
    # GAP-1230: the hooks key deleted from the agent's settings file.
    settings = tmp_path / "settings.json"
    hook = {"command": "/x/defenseclaw/claude-code-hook.sh"}
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [{"hooks": [hook]}]}}))
    lock = {"version": 2, "connectors": {"claudecode": {"locations": {"hook_config_paths": [str(settings)]}}}}
    (tmp_path / "hook_contract_lock.json").write_text(json.dumps(lock))
    cfg = SimpleNamespace(data_dir=str(tmp_path))
    assert hook_registration_problems(cfg, "claudecode") == []

    settings.write_text(json.dumps({"model": "x"}))
    problems = hook_registration_problems(cfg, "claudecode")
    assert problems and str(settings) in problems[0]

    # Setup's OTEL env entries name DefenseClaw too; they register no hook.
    env = {"OTEL_RESOURCE_ATTRIBUTES": "service.name=defenseclaw"}
    settings.write_text(json.dumps({"env": env, "hooks": {}}))
    assert hook_registration_problems(cfg, "claudecode")
    settings.write_text(json.dumps({"env": env}))
    assert hook_registration_problems(cfg, "claudecode")
    assert hook_registration_problems(cfg, "codex") == []


def test_unquoted_hook_path_with_a_space_fails_doctor(tmp_path):
    # GAP-0382: the shell runs the first half of an unquoted path with a space.
    data_dir = tmp_path / "dc ip8" / ".defenseclaw"
    (data_dir / "hooks").mkdir(parents=True)
    script = str(data_dir / "hooks" / "claude-code-hook.sh")
    settings = tmp_path / "settings.json"
    lock = {"version": 2, "connectors": {"claudecode": {"locations": {"hook_config_paths": [str(settings)]}}}}
    (data_dir / "hook_contract_lock.json").write_text(json.dumps(lock))
    cfg = SimpleNamespace(data_dir=str(data_dir))

    def register(command):
        settings.write_text(json.dumps({"hooks": {"PreToolUse": [{"hooks": [{"command": command}]}]}}))

    register(shlex.quote(script))
    assert hook_registration_problems(cfg, "claudecode") == []
    register(script)
    problems = hook_registration_problems(cfg, "claudecode")
    assert problems and "cannot run" in problems[0]
    r = _DoctorResult(passive=True, quiet=True)
    _check_hook_runtime_integrity(cfg, "claudecode", r)
    row = next(row for row in r.checks if row.get("label") == "Hook command")
    assert row["status"] == "fail"


def test_missing_windows_hook_launcher_names_the_installer(tmp_path, monkeypatch):
    # GAP-0378: the native launcher is gone; only the installer restores it.
    from defenseclaw import hook_integrity

    settings = tmp_path / "settings.json"
    launcher = "C:\\Users\\dcw-dr1\\.local\\bin\\defenseclaw-hook.exe"
    hook = {"type": "command", "command": launcher, "args": ["hook", "--connector", "claudecode"]}
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [{"hooks": [hook]}]}}))
    lock = {"version": 2, "connectors": {"claudecode": {"locations": {"hook_config_paths": [str(settings)]}}}}
    (tmp_path / "hook_contract_lock.json").write_text(json.dumps(lock))
    monkeypatch.setattr(hook_integrity, "_is_windows", lambda: True)

    problems = hook_registration_problems(SimpleNamespace(data_dir=str(tmp_path)), "claudecode")
    assert problems and launcher in problems[0]
    assert "installer" in hook_integrity.repair_command("claudecode", problems[0])


def test_older_build_render_is_not_reported_fresh(tmp_path, monkeypatch):
    # GAP-1316: an older build's script still holds the freshness sentinels,
    # but it does not match the digest setup sealed.
    from unittest import mock

    from defenseclaw.commands import cmd_doctor

    cfg, script = _install(tmp_path)
    script.write_text(script.read_text() + "# rendered by an older build\n")
    r = _DoctorResult(passive=True, quiet=True)
    with mock.patch.object(cmd_doctor, "_stale_generated_hook_reasons", return_value=[]):
        cmd_doctor._check_generated_hook_freshness(cfg, "codex", "Codex hooks", r)
    row = r.checks[-1]
    assert row["status"] == "warn" and "defenseclaw doctor --fix" in row["remediation"]


def test_fix_drops_a_stale_openclaw_lock_entry(tmp_path, monkeypatch):
    # GAP-0225: after an OpenClaw upgrade or downgrade the lock still named the
    # old version, the gateway refused to start and doctor --fix had no repair.
    from defenseclaw.commands import cmd_doctor
    from defenseclaw.inventory import agent_discovery

    lock_path = tmp_path / "hook_contract_lock.json"
    entries = {"openclaw": {"raw_agent_version": "OpenClaw 2026.9.8 (fc23bc8)"}, "codex": {"raw_agent_version": "0.142.4"}}
    lock_path.write_text(json.dumps({"version": 2, "connectors": entries}))
    installed = SimpleNamespace(agents={"openclaw": SimpleNamespace(version="OpenClaw 2026.6.8 (844f405)")})
    monkeypatch.setattr(agent_discovery, "_read_cache", lambda data_dir: installed)
    monkeypatch.setattr(
        cmd_doctor, "_trusted_gateway_listener_for_lifecycle", lambda _cfg: SimpleNamespace(trusted=True, detail="")
    )
    restarts = []
    monkeypatch.setattr(
        cmd_doctor, "_repair_gateway_lifecycle", lambda _cfg, *, start_if_stopped: (restarts.append(1) or True, "")
    )
    cfg = SimpleNamespace(data_dir=str(tmp_path))

    assert cmd_doctor._fix_stale_proxy_contract_lock(cfg, assume_yes=True, plan_only=True)[0] == "plan"
    assert cmd_doctor._fix_stale_proxy_contract_lock(cfg, assume_yes=True)[0] == "pass"
    assert set(json.loads(lock_path.read_text())["connectors"]) == {"codex"} and restarts == [1]
    assert cmd_doctor._fix_stale_proxy_contract_lock(cfg, assume_yes=True)[0] == "skip"


def test_install_moved_with_the_home_names_the_old_folder(tmp_path, monkeypatch):
    # GAP-0542 / GAP-0543: after a rename the lock (and the agent hooks) name
    # the old home; doctor and status say DefenseClaw is not guarding.
    monkeypatch.delenv("DEFENSECLAW_GATEWAY_TOKEN", raising=False)
    new_home = tmp_path / "new"
    new_home.mkdir()
    cfg, script = _install(new_home)
    lock_path = new_home / "hook_contract_lock.json"
    lock = json.loads(lock_path.read_text())
    old_script = str(tmp_path / "old" / "hooks" / script.name)
    lock["connectors"]["codex"]["locations"]["hook_script_paths"] = [old_script]
    lock_path.write_text(json.dumps(lock))

    problem = unrunnable_hook_problem(cfg, "codex")
    assert f"set up in {tmp_path / 'old'}" in problem
    assert "not guarding" in problem


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root reads mode 000 files")
def test_unreadable_script_is_reported_as_unguarded_not_edited(tmp_path, monkeypatch):
    # GAP-0403: chmod 000 makes every hook a non-blocking error, so the
    # connector is not guarded whatever its fail mode.
    monkeypatch.delenv("DEFENSECLAW_GATEWAY_TOKEN", raising=False)
    cfg, script = _install(tmp_path)
    script.chmod(0)
    try:
        problem = unrunnable_hook_problem(cfg, "codex")
        problems = hook_runtime_problems(cfg, "codex")
    finally:
        script.chmod(0o700)
    assert "cannot be read" in problem
    assert "changed since setup" not in " ".join(problems)


def test_missing_hook_script_is_named_as_missing_with_one_repair(tmp_path):
    from defenseclaw.commands.cmd_doctor import _repair_display_tag

    cfg, script = _install(tmp_path)
    script.unlink()
    problems = hook_runtime_problems(cfg, "codex")
    assert len(problems) == 1 and "is missing" in problems[0]
    assert "changed since setup" not in problems[0]

    result = _DoctorResult(passive=True, quiet=True)
    _check_hook_runtime_integrity(cfg, "codex", result)
    row = next(row for row in result.checks if row.get("label") == "Hook runtime files")
    assert row["detail"].count("doctor --fix") == 1
    assert _repair_display_tag("blocked") == "skip"


def _agent_config(tmp_path, connector, name):
    config = tmp_path / name
    lock = {"version": 2, "connectors": {connector: {"locations": {"hook_config_paths": [str(config)]}}}}
    (tmp_path / "hook_contract_lock.json").write_text(json.dumps(lock))
    return SimpleNamespace(data_dir=str(tmp_path)), config


def test_claude_disable_all_hooks_is_degraded_with_its_own_repair(tmp_path, monkeypatch):
    # GAP-1066/GAP-1067: the hooks stay registered but Claude Code runs none of them.
    monkeypatch.chdir(tmp_path)
    cfg, settings = _agent_config(tmp_path, "claudecode", "settings.json")
    hooks = {"PreToolUse": [{"hooks": [{"type": "command", "command": "/x/.defenseclaw/hooks/claude-code-hook.sh"}]}]}
    settings.write_text(json.dumps({"hooks": hooks}))
    assert hook_registration_problems(cfg, "claudecode") == []

    project = tmp_path / ".claude"
    project.mkdir()
    (project / "settings.local.json").write_text(json.dumps({"disableAllHooks": True}))
    problems = hook_registration_problems(cfg, "claudecode")
    assert problems and "disableAllHooks" in problems[0] and "settings.local.json" in problems[0]
    assert unrunnable_hook_problem(cfg, "claudecode") == problems[0]
    assert repair_command("claudecode", problems[0]).startswith("remove disableAllHooks from")


def test_codex_hooks_turned_off_or_left_without_command_fail_doctor(tmp_path):
    # GAP-1094: [features] hooks = false; GAP-1102: entries without a command.
    from defenseclaw.commands.cmd_doctor import _check_codex_hooks

    cfg, config = _agent_config(tmp_path, "codex", "config.toml")
    (tmp_path / "hooks").mkdir()
    (tmp_path / "hooks" / "codex-hook.sh").write_text("#!/bin/bash\n")
    command = "/home/u/.defenseclaw/hooks/codex-hook.sh --event PreToolUse"
    entry = "[[hooks.PreToolUse]]\nmatcher = '*'\n[[hooks.PreToolUse.hooks]]\ntype = 'command'\ntimeout = 30\n"
    config.write_text("[features]\nhooks = false\n" + entry + f"command = '{command}'\n")

    r = _DoctorResult()
    _check_codex_hooks(cfg, r, platform_name="posix", config_path=str(config))
    row = next(check for check in r.checks if check["label"] == "Codex hooks")
    assert row["status"] == "fail" and "turned off" in row["detail"]
    assert "codex features enable hooks" in row["remediation"]

    config.write_text(entry + entry + f"command = '{command}'\n")
    problems = hook_registration_problems(cfg, "codex")
    assert problems and "without a command" in problems[0] and "refuses to start" in problems[0]
