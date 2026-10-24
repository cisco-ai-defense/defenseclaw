# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The outage prompt defaults to the effective tier mode and saves the answer."""

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


def test_new_install_defaults_to_effective_outage_mode() -> None:
    output, chosen = _run("")
    assert "Current setting" not in output
    assert chosen == "open"
    assert "default on a new install" not in output


def test_strict_install_defaults_closed() -> None:
    _, chosen = _run("", "strict")
    assert chosen == "closed"


def test_enter_on_strict_default_persists_an_explicit_closed_choice(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    cfg = prepare_fresh_v8_config(default_config())
    cfg.guardrail.rule_pack = "strict"

    @click.command()
    def run() -> None:
        _prompt_hook_fail_mode(cfg.guardrail)

    result = CliRunner().invoke(run, [], input="\n", catch_exceptions=False)
    assert result.exit_code == 0, result.output
    cfg.save()
    saved = yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))
    assert saved["guardrail"]["hook_fail_mode"] == "closed"


def test_saved_open_default_is_named_as_the_current_setting() -> None:
    output, chosen = _run("open")
    assert "Current setting: open" in output
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
