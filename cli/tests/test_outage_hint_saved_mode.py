# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""GAP-0039: a saved open hook_fail_mode wins over the strict policy, so the
outage hints name ``guardrail fail-mode closed`` then, and ``use-pack strict``
only when no mode is saved."""

from __future__ import annotations

from click.testing import CliRunner
from defenseclaw.commands import cmd_guardrail
from defenseclaw.config import (
    GuardrailConfig,
    PerConnectorGuardrailConfig,
    outage_block_hint,
    saved_hook_fail_mode_scope,
)

from tests.test_cmd_guardrail import make_ctx


def test_hint_follows_where_the_open_is_saved() -> None:
    gc = GuardrailConfig()
    assert saved_hook_fail_mode_scope(gc, "claudecode") == ""
    assert outage_block_hint(gc, "claudecode") == "defenseclaw guardrail use-pack strict"

    gc = GuardrailConfig(hook_fail_mode="open")
    assert saved_hook_fail_mode_scope(gc, "claudecode") == "global"
    assert outage_block_hint(gc, "claudecode") == "defenseclaw guardrail fail-mode closed"

    gc = GuardrailConfig(connectors={"claudecode": PerConnectorGuardrailConfig(hook_fail_mode="open")})
    assert saved_hook_fail_mode_scope(gc, "claudecode") == "connector"
    assert outage_block_hint(gc, "claudecode") == "defenseclaw guardrail fail-mode closed --connector claudecode"
    assert saved_hook_fail_mode_scope(gc, "codex") == ""


def test_status_names_fail_mode_closed_for_a_saved_open() -> None:
    app = make_ctx(enabled=True, connector="kiro", hook_fail_mode="open")
    app.cfg.guardrail.mode = "action"
    result = CliRunner().invoke(cmd_guardrail.status_cmd, [], obj=app)
    assert result.exit_code == 0, result.output
    assert "action mode with fail mode open" in result.output
    assert "defenseclaw guardrail fail-mode closed" in result.output
    assert "use-pack strict" not in result.output


def test_status_keeps_the_strict_hint_when_no_mode_is_saved() -> None:
    app = make_ctx(enabled=True, connector="kiro", hook_fail_mode="open")
    app.cfg.guardrail.mode = "action"
    app.cfg.guardrail._hook_fail_mode_saved = False  # the tier decides, as on a fresh default install
    result = CliRunner().invoke(cmd_guardrail.status_cmd, [], obj=app)
    assert result.exit_code == 0, result.output
    assert "defenseclaw guardrail use-pack strict" in result.output
    assert "fail-mode closed" not in result.output
