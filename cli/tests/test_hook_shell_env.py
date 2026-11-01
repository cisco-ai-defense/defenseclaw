# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Agent settings and shell variables that stop shell-form hooks (rel-1-0-6:GAP-0322).

Claude Code starts a hook command through /bin/sh -c with its environment plus
the env block of its settings sources. On RHEL and macOS /bin/sh is bash, and
SHELLOPTS=noexec in a project's .claude/settings.json made it run none of the
registered command: no hook ran and every call went ahead. The strict tier
refuses such settings in the sources the gateway checks (user,
~/.claude.json, managed, the pinned claw.workspace_dir); everything else is a
warning, as is a variable the agent would inherit from this shell.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from defenseclaw import hook_integrity
from defenseclaw.commands import cmd_doctor, cmd_status

pytestmark = pytest.mark.skipif(os.name == "nt", reason="Windows runs the native launcher without /bin/sh")


def _cfg(tmp_path: Path, monkeypatch, tier: str = "default", deployment: str = "", workspace: str = ""):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "home" / ".claude"))
    for name in ("SHELLOPTS", "CLAUDE_CODE_SHELL_PREFIX", "BASH_ENV"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(hook_integrity, "_claude_managed_env_source", lambda: None)
    (tmp_path / "dc").mkdir(exist_ok=True)
    return SimpleNamespace(
        data_dir=str(tmp_path / "dc"),
        deployment_mode=deployment,
        guardrail=SimpleNamespace(hook_policy_tier=lambda connector="": tier),
        claw=SimpleNamespace(workspace_dir=workspace),
    )


def _settings(path: Path, env: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"env": env}), encoding="utf-8")
    return path


def test_names_follow_claude_env_precedence(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    repo = tmp_path / "repo"
    project = _settings(repo / ".claude" / "settings.json", {"SHELLOPTS": "noexec", "PATH": "/bin"})
    user = _settings(tmp_path / "home" / ".claude" / "settings.json", {"BASH_FUNC_[%%": "", "POSIXLY_CORRECT": "1", "ENV": "/e"})

    names, sources = hook_integrity.claude_settings_hook_shell_env(cfg, str(repo))
    assert names == ["BASH_FUNC_[%%", "SHELLOPTS"]
    assert sources == [project, user]

    # A higher file that empties the name clears it.
    local = _settings(repo / ".claude" / "settings.local.json", {"SHELLOPTS": ""})
    names, sources = hook_integrity.claude_settings_hook_shell_env(cfg, str(repo))
    assert names == ["BASH_FUNC_[%%"] and sources == [user]

    # Review finding 1: null, an object, an array or NUL in a higher file is
    # dropped by Claude Code, so the lower value still applies.
    for dropped in (None, {}, [""], "no\x00exec"):
        local.write_text(json.dumps({"env": {"SHELLOPTS": dropped}}), encoding="utf-8")
        names, sources = hook_integrity.claude_settings_hook_shell_env(cfg, str(repo))
        assert names == ["BASH_FUNC_[%%", "SHELLOPTS"] and sources == [project, user], dropped


@pytest.mark.parametrize(
    "higher, lower, want",
    [
        ("project", "user", []),
        ("user", "global", ["SHELLOPTS"]),
        ("managed", "local", []),
    ],
)
def test_same_name_conflicts_across_tiers(tmp_path, monkeypatch, higher, lower, want):
    cfg = _cfg(tmp_path, monkeypatch)
    repo = tmp_path / "repo"
    files = {
        "local": repo / ".claude" / "settings.local.json",
        "project": repo / ".claude" / "settings.json",
        "user": tmp_path / "home" / ".claude" / "settings.json",
        "global": tmp_path / "home" / ".claude" / ".claude.json",
    }
    values = {"user": "noexec", "global": ""} if want else {higher: "", lower: "noexec"}
    for tier, value in values.items():
        if tier == "managed":
            monkeypatch.setattr(hook_integrity, "_claude_managed_env_source", lambda v=value: ("managed", {"SHELLOPTS": v}))
        else:
            _settings(files[tier], {"SHELLOPTS": value})
    names, _ = hook_integrity.claude_settings_hook_shell_env(cfg, str(repo))
    assert names == want


def test_numbers_and_booleans_count(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    _settings(tmp_path / "home" / ".claude" / "settings.json", {"FUNCNEST": 1, "BASHOPTS": False})
    assert hook_integrity.claude_settings_hook_shell_env(cfg, None)[0] == ["BASHOPTS", "FUNCNEST"]


@pytest.mark.parametrize("tier", ["default", "permissive"])
def test_default_tiers_warn_and_keep_the_hooks(tmp_path, monkeypatch, tier):
    cfg = _cfg(tmp_path, monkeypatch, tier)
    repo = tmp_path / "repo"
    project = _settings(repo / ".claude" / "settings.json", {"SHELLOPTS": "noexec"})

    assert hook_integrity.agent_hook_switch_problems(cfg, "claudecode", workspace_dir=str(repo)) == []
    warnings = hook_integrity.agent_hook_env_warnings(cfg, "claudecode", workspace_dir=str(repo), environ={})
    assert len(warnings) == 1
    assert str(project) in warnings[0] and "SHELLOPTS (with noexec, /bin/sh runs none of the hook command)" in warnings[0]
    assert warnings[0].repair.startswith("remove SHELLOPTS from that env block")

    monkeypatch.chdir(repo)
    suffix = cmd_status._hook_runtime_degraded_suffix(cfg, "claudecode")
    assert "WARNING" in suffix and "DEGRADED" not in suffix and str(project) in suffix
    assert "nothing refused it" in suffix  # the folder is not the pinned workspace

    result = cmd_doctor._DoctorResult()
    monkeypatch.setattr(cmd_doctor, "_workspace_dir", lambda _cfg: str(repo))
    cmd_doctor._emit_agent_hook_env_warnings(cfg, "claudecode", "Claude Code hook environment", result)
    assert [row["status"] for row in result.checks] == ["warn"]
    assert result.failed == 0


def test_strict_tier_refuses_what_the_gateway_checks(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    cfg = _cfg(tmp_path, monkeypatch, "strict", workspace=str(repo))
    project = _settings(repo / ".claude" / "settings.json", {"CLAUDE_CODE_SHELL_PREFIX": "/usr/bin/true"})

    problems = hook_integrity.agent_hook_switch_problems(cfg, "claudecode")
    assert len(problems) == 1 and str(project) in problems[0]
    for want in ("CLAUDE_CODE_SHELL_PREFIX (Claude Code runs that program", "strict policy tier refuses it",
                 "every Claude Code session of this account fails closed"):
        assert want in problems[0]
    assert "default policy tier" in problems[0].repair
    assert hook_integrity.agent_hook_env_warnings(cfg, "claudecode", environ={}) == []

    monkeypatch.chdir(tmp_path)
    assert "DEGRADED" in cmd_status._hook_runtime_degraded_suffix(cfg, "claudecode")

    # ENV cannot stop the launch and is not refused.
    project.write_text(json.dumps({"env": {"ENV": "/tmp/e"}}), encoding="utf-8")
    assert hook_integrity.agent_hook_switch_problems(cfg, "claudecode") == []


def test_strict_tier_unpinned_folder_is_a_warning_not_a_refusal(tmp_path, monkeypatch):
    # Review finding 7: the gateway never checked this folder, so status and
    # doctor run in it must not claim a refusal.
    cfg = _cfg(tmp_path, monkeypatch, "strict")
    repo = tmp_path / "repo"
    _settings(repo / ".claude" / "settings.json", {"SHELLOPTS": "noexec"})
    monkeypatch.chdir(repo)
    assert hook_integrity.agent_hook_switch_problems(cfg, "claudecode") == []
    warnings = hook_integrity.agent_hook_env_warnings(cfg, "claudecode", environ={})
    assert len(warnings) == 1 and "refuses" not in warnings[0] and "nothing refused it" in warnings[0]
    suffix = cmd_status._hook_runtime_degraded_suffix(cfg, "claudecode")
    assert "WARNING" in suffix and "DEGRADED" not in suffix


def test_inherited_environment_is_reported_in_every_tier(tmp_path, monkeypatch):
    for tier in ("default", "strict"):
        cfg = _cfg(tmp_path, monkeypatch, tier)
        environ = {"SHELLOPTS": "braceexpand:hashall:noexec", "BASH_FUNC_module%%": "() { :; }"}
        for connector in ("claudecode", "codex", "kiro"):
            warnings = hook_integrity.agent_hook_env_warnings(
                cfg, connector, workspace_dir=str(tmp_path / "repo"), environ=environ
            )
            assert len(warnings) == 1, (tier, connector, warnings)
            assert "this shell's environment sets SHELLOPTS with noexec" in warnings[0]
            assert warnings[0].repair.startswith("unset SHELLOPTS")

    cfg = _cfg(tmp_path, monkeypatch)
    # Exported functions (environment modules on RHEL) and other options are not reported.
    assert hook_integrity.agent_hook_env_warnings(
        cfg, "codex", environ={"SHELLOPTS": "braceexpand:hashall", "BASH_FUNC_module%%": "() { :; }"}
    ) == []
    # A shell prefix only replaces Claude Code's hook commands.
    assert hook_integrity.inherited_hook_shell_env({"CLAUDE_CODE_SHELL_PREFIX": "/bin/wrap"}, "claudecode") == [
        "CLAUDE_CODE_SHELL_PREFIX"
    ]
    assert hook_integrity.inherited_hook_shell_env({"CLAUDE_CODE_SHELL_PREFIX": "/bin/wrap"}, "codex") == []
    # A settings env block decides the name over the inherited value.
    _settings(tmp_path / "home" / ".claude" / "settings.json", {"SHELLOPTS": ""})
    assert hook_integrity.agent_hook_env_warnings(cfg, "claudecode", environ={"SHELLOPTS": "noexec"}) == []


@pytest.mark.parametrize("connector, reported", [
    ("devin", True), ("copilot", True), ("codex", True),
    ("claudecode", False), ("kiro", False), ("hermes", False), ("antigravity", False),
])
def test_inherited_bash_env_only_for_agents_that_start_hooks_through_bash(tmp_path, monkeypatch, connector, reported):
    # Lead follow-up: Devin, Copilot CLI and Codex start hook commands through
    # bash (-c or -lc), which runs BASH_ENV first, so a file that exits 0
    # skips the hook. /bin/sh (Claude Code, Kiro) ignores BASH_ENV, and
    # Hermes and Antigravity start the hook with no shell.
    cfg = _cfg(tmp_path, monkeypatch)
    found = hook_integrity.inherited_hook_shell_env({"BASH_ENV": "/tmp/exit0"}, connector)
    assert (found == ["BASH_ENV"]) is reported
    warnings = hook_integrity.agent_hook_env_warnings(cfg, connector, workspace_dir=str(tmp_path / "repo"), environ={"BASH_ENV": "/tmp/exit0"})
    assert bool(warnings) is reported
    if reported:
        assert "BASH_ENV (the agent starts its hook commands through bash" in warnings[0]


def test_managed_claude_code_is_pinned_by_machine_policy(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch, deployment="managed_enterprise")
    repo = tmp_path / "repo"
    _settings(repo / ".claude" / "settings.json", {"SHELLOPTS": "noexec"})
    assert hook_integrity.agent_hook_env_warnings(
        cfg, "claudecode", workspace_dir=str(repo), environ={"SHELLOPTS": "noexec"}
    ) == []
    assert hook_integrity.agent_hook_switch_problems(cfg, "claudecode", workspace_dir=str(repo)) == []


def test_strict_tier_is_read_from_the_real_guardrail_config():
    # The tier lives on cfg.guardrail (GuardrailConfig.hook_policy_tier); the
    # first live run read cfg.hook_policy_tier, which a real Config lacks, and
    # reported the strict tier as a warning.
    from defenseclaw import config

    cfg = config.default_config()
    assert hook_integrity._strict_policy_tier(cfg, "claudecode") is False
    cfg.guardrail.rule_pack = "strict"
    assert cfg.guardrail.hook_policy_tier("claudecode") == "strict"
    assert hook_integrity._strict_policy_tier(cfg, "claudecode") is True


def _fake_ownership(monkeypatch, user_paths):
    """lstat as if every path were root-owned with no group/world write, except *user_paths* and what is under them."""

    real_lstat = os.lstat
    users = [os.path.abspath(str(p)) for p in user_paths]

    def lstat(path, *args, **kwargs):
        info = real_lstat(path, *args, **kwargs)
        text = os.path.abspath(str(path))
        fields = list(info)
        if any(text == u or text.startswith(u + os.sep) for u in users):
            fields[4] = 1000
        else:
            fields[4] = 0
            fields[0] = info.st_mode & ~0o022
        return os.stat_result(fields)

    monkeypatch.setattr(hook_integrity.os, "lstat", lstat)


def test_system_bash_env_from_a_module_profile_is_not_reported(tmp_path, monkeypatch):
    # rel-1-0-6:GAP-0393: Environment Modules and Lmod export BASH_ENV to a
    # root-owned init script; that is not reported. The path is walked as
    # written (review 3): a link in a folder the user can write is reported
    # even when it points at a root-owned file; Lmod's root-owned link is not.
    cfg = _cfg(tmp_path, monkeypatch)
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    system = tmp_path / "etc" / "profile.d"
    system.mkdir(parents=True)
    root_file = system / "modules.sh"
    root_file.write_text("module() { :; }\n", encoding="utf-8")
    lmod = tmp_path / "usr" / "share" / "lmod"
    (lmod / "lmod-8.7" / "init").mkdir(parents=True)
    (lmod / "lmod-8.7" / "init" / "bash").write_text("module() { :; }\n", encoding="utf-8")
    (lmod / "lmod").symlink_to("lmod-8.7")  # relative, as Lmod installs it
    mine = home / "startup.sh"
    mine.write_text("exit 0\n", encoding="utf-8")
    home_link = home / "x"
    home_link.symlink_to(root_file)
    user_tmp = tmp_path / "tmp" / "userdir"
    user_tmp.mkdir(parents=True)
    tmp_link = user_tmp / "x"
    tmp_link.symlink_to(root_file)
    root_link_to_user = system / "points-home.sh"
    root_link_to_user.symlink_to(mine)
    _fake_ownership(monkeypatch, [home, user_tmp])
    base = {"HOME": str(home)}

    def reported(value):
        return hook_integrity.inherited_hook_shell_env({**base, "BASH_ENV": str(value)}, "codex") == ["BASH_ENV"]

    # Exempt: a root-owned file, and Lmod's root-owned link into its init.
    assert not reported(root_file)
    assert not reported(lmod / "lmod" / "init" / "bash")
    assert hook_integrity.agent_hook_env_warnings(
        cfg, "copilot", workspace_dir=str(tmp_path / "repo"), environ={**base, "BASH_ENV": str(root_file)}
    ) == []
    # Reported: a link in the home or in a user-owned /tmp folder pointing at
    # the root-owned file, a root-owned link to a home file, a file in the
    # home, a relative path, a missing file.
    for value in (home_link, tmp_link, root_link_to_user, mine, "startup.sh", tmp_path / "missing"):
        assert reported(value), value

    # A root-owned file in a folder others can write is reported.
    real_lstat = os.lstat

    def writable_parent(path, *args, **kwargs):
        info = real_lstat(path, *args, **kwargs)
        if os.path.abspath(str(path)) == str(system):
            fields = list(info)
            fields[0] = info.st_mode | 0o002
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(hook_integrity.os, "lstat", writable_parent)
    assert reported(root_file)
