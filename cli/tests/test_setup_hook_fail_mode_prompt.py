# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-1388: the hook fail-mode prompt explains a default that is not the recommended choice."""

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


def test_saved_closed_default_is_named_as_the_current_setting() -> None:
    output, chosen = _run("closed")
    assert "Current setting: closed" in output
    assert chosen == "closed"


def test_open_default_needs_no_extra_line() -> None:
    output, chosen = _run("open")
    assert "Current setting" not in output
    assert chosen == "open"
