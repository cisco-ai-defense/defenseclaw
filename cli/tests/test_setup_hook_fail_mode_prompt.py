# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The outage prompt saves only a typed answer; Enter keeps what is there."""

from __future__ import annotations

import click
import yaml
from click.testing import CliRunner
from defenseclaw.commands.cmd_setup import _prompt_hook_fail_mode
from defenseclaw.config import GuardrailConfig, default_config, prepare_fresh_v8_config


def _run(current: str, tier: str = "default") -> tuple[str, str]:
    gc = GuardrailConfig(rule_pack=tier)
    if current:
        gc.hook_fail_mode = current

    @click.command()
    def run() -> None:
        _prompt_hook_fail_mode(gc)

    result = CliRunner().invoke(run, [], input="\n", catch_exceptions=False)
    assert result.exit_code == 0, result.output
    return result.output, gc.hook_fail_mode


def test_enter_on_a_new_install_keeps_the_policy_default() -> None:
    gc = GuardrailConfig(rule_pack="default")

    @click.command()
    def run() -> None:
        _prompt_hook_fail_mode(gc)

    result = CliRunner().invoke(run, [], input="\n", catch_exceptions=False)
    assert result.exit_code == 0, result.output
    assert "default on a new install" not in result.output
    assert not gc._hook_fail_mode_saved
    assert gc.effective_hook_fail_mode("codex") == "open"
    gc.rule_pack = "strict"
    assert gc.effective_hook_fail_mode("codex") == "closed"


def test_typed_closed_on_a_default_install_persists(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    cfg = prepare_fresh_v8_config(default_config())

    @click.command()
    def run() -> None:
        _prompt_hook_fail_mode(cfg.guardrail)

    result = CliRunner().invoke(run, [], input="2\n", catch_exceptions=False)
    assert result.exit_code == 0, result.output
    cfg.save()
    saved = yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))
    assert saved["guardrail"]["hook_fail_mode"] == "closed"


def test_saved_open_is_named_and_kept_on_enter() -> None:
    output, chosen = _run("open")
    assert "Enter to keep open" in output
    assert chosen == "open"


def test_interactive_init_action_policy_leaves_outage_choice_unset() -> None:
    from defenseclaw.commands.cmd_init import _prompt_action_policy

    chosen: dict[str, object] = {}

    @click.command()
    def run() -> None:
        chosen["fail"], _, _ = _prompt_action_policy(fail_mode=None, human_approval=False, hilt_min_severity=None)

    result = CliRunner().invoke(run, [], input="\n", catch_exceptions=False)
    assert result.exit_code == 0, result.output
    assert chosen["fail"] is None
