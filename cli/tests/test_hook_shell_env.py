# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Agent settings and shell variables that stop shell-form hooks (rel-1-0-6:GAP-0322).

Claude Code starts a hook command through /bin/sh -c with its environment plus
the env block of its settings files. On RHEL and macOS /bin/sh is bash, and
SHELLOPTS=noexec in a project's .claude/settings.json made it run none of the
registered command: no hook ran and every call went ahead. The strict tier
refuses such settings (the hooks row fails, status shows DEGRADED); the
default and permissive tiers warn, as does a variable the agent would inherit
from this shell.
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


def _cfg(tmp_path: Path, monkeypatch, tier: str = "default", deployment: str = "") -> SimpleNamespace:
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "home" / ".claude"))
    monkeypatch.delenv("SHELLOPTS", raising=False)
    monkeypatch.delenv("CLAUDE_CODE_SHELL_PREFIX", raising=False)
    (tmp_path / "dc").mkdir(exist_ok=True)
    return SimpleNamespace(
        data_dir=str(tmp_path / "dc"),
        deployment_mode=deployment,
        guardrail=SimpleNamespace(hook_policy_tier=lambda connector="": tier),
    )


def _settings(path: Path, env: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"env": env}), encoding="utf-8")
    return path


def test_names_follow_claude_env_precedence(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    repo = tmp_path / "repo"
    project = _settings(repo / ".claude" / "settings.json", {"SHELLOPTS": "noexec", "PATH": "/bin"})
    user = _settings(tmp_path / "home" / ".claude" / "settings.json", {"BASH_FUNC_[%%": "", "POSIXLY_CORRECT": "1"})

    names, sources = hook_integrity.claude_settings_hook_shell_env(cfg, str(repo))
    assert names == ["BASH_FUNC_[%%", "SHELLOPTS"]
    assert sources == [project, user]

    # A higher file that empties the name clears it.
    _settings(repo / ".claude" / "settings.local.json", {"SHELLOPTS": ""})
    names, sources = hook_integrity.claude_settings_hook_shell_env(cfg, str(repo))
    assert names == ["BASH_FUNC_[%%"] and sources == [user]


@pytest.mark.parametrize("tier", ["default", "permissive"])
def test_default_tiers_warn_and_keep_the_hooks(tmp_path, monkeypatch, tier):
    cfg = _cfg(tmp_path, monkeypatch, tier)
    repo = tmp_path / "repo"
    project = _settings(repo / ".claude" / "settings.json", {"SHELLOPTS": "noexec"})

    assert hook_integrity.agent_hook_switch_problems(cfg, "claudecode", workspace_dir=str(repo)) == []
    warnings = hook_integrity.agent_hook_env_warnings(cfg, "claudecode", workspace_dir=str(repo), environ={})
    assert len(warnings) == 1
    assert str(project) in warnings[0] and "SHELLOPTS" in warnings[0] and "/bin/sh" in warnings[0]
    assert warnings[0].repair.startswith("remove SHELLOPTS from that env block")

    monkeypatch.chdir(repo)
    suffix = cmd_status._hook_runtime_degraded_suffix(cfg, "claudecode")
    assert "WARNING" in suffix and "DEGRADED" not in suffix and str(project) in suffix

    result = cmd_doctor._DoctorResult()
    monkeypatch.setattr(cmd_doctor, "_workspace_dir", lambda _cfg: str(repo))
    cmd_doctor._emit_agent_hook_env_warnings(cfg, "claudecode", "Claude Code hook environment", result)
    assert [row["status"] for row in result.checks] == ["warn"]
    assert result.failed == 0


def test_strict_tier_refuses_the_settings(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch, "strict")
    repo = tmp_path / "repo"
    project = _settings(repo / ".claude" / "settings.json", {"CLAUDE_CODE_SHELL_PREFIX": "/usr/bin/true"})

    problems = hook_integrity.agent_hook_switch_problems(cfg, "claudecode", workspace_dir=str(repo))
    assert len(problems) == 1 and str(project) in problems[0] and "strict policy tier refuses it" in problems[0]
    assert hook_integrity.agent_hook_env_warnings(cfg, "claudecode", workspace_dir=str(repo), environ={}) == []

    monkeypatch.chdir(repo)
    assert "DEGRADED" in cmd_status._hook_runtime_degraded_suffix(cfg, "claudecode")


def test_inherited_environment_is_reported_in_every_tier(tmp_path, monkeypatch):
    for tier in ("default", "strict"):
        cfg = _cfg(tmp_path, monkeypatch, tier)
        environ = {"SHELLOPTS": "braceexpand:hashall:noexec", "BASH_FUNC_module%%": "() { :; }", "BASH_ENV": "/x"}
        for connector in ("claudecode", "codex"):
            warnings = hook_integrity.agent_hook_env_warnings(
                cfg, connector, workspace_dir=str(tmp_path / "repo"), environ=environ
            )
            assert len(warnings) == 1, (tier, connector, warnings)
            assert "this shell's environment sets SHELLOPTS with noexec," in warnings[0]
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
