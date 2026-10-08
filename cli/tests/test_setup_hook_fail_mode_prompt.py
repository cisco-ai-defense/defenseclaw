# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-1388/GAP-0353: closed is the recommended default; a saved open is named as the current setting."""

from __future__ import annotations

from types import SimpleNamespace

import click
from click.testing import CliRunner
from defenseclaw.commands.cmd_setup import _prompt_hook_fail_mode


def _run(current: str) -> tuple[str, str]:
    gc = SimpleNamespace(hook_fail_mode=current)

    @click.command()
    def run() -> None:
        _prompt_hook_fail_mode(gc)

    result = CliRunner().invoke(run, [], input="\n", catch_exceptions=False)
    assert result.exit_code == 0, result.output
    return result.output, gc.hook_fail_mode


def test_new_install_defaults_closed() -> None:
    output, chosen = _run("")
    assert "Current setting" not in output
    assert chosen == "closed"


def test_saved_open_default_is_named_as_the_current_setting() -> None:
    output, chosen = _run("open")
    assert "Current setting: open" in output
    assert chosen == "open"


def test_interactive_init_action_policy_defaults_closed() -> None:
    from defenseclaw.commands.cmd_init import _prompt_action_policy

    chosen: dict[str, object] = {}

    @click.command()
    def run() -> None:
        chosen["fail"], _, _ = _prompt_action_policy(fail_mode=None, human_approval=False, hilt_min_severity=None)

    result = CliRunner().invoke(run, [], input="\n", catch_exceptions=False)
    assert result.exit_code == 0, result.output
    assert chosen["fail"] == "closed"
