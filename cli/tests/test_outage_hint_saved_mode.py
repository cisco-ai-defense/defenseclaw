# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""GAP-0039: a saved open hook_fail_mode wins over the strict policy, so the
outage hints name ``guardrail fail-mode closed`` then, and ``use-pack strict``
only when no mode is saved."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import patch

from click.testing import CliRunner
from defenseclaw.commands import cmd_guardrail, cmd_init, cmd_migrate
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


def _init_outage_lines(guardrail: GuardrailConfig, closed: list[str] | None = None) -> list[str]:
    report = SimpleNamespace(
        status="ok", connector="claudecode", profile="observe", setup=[], readiness=[],
        next_commands=[], data_dir="/nonexistent",
    )
    lines: list[str] = []
    renderer = SimpleNamespace(title=lambda *a: None, section=lambda *a: None, step=lambda *a: None, echo=lines.append)
    with (
        patch("defenseclaw.config.load", return_value=SimpleNamespace(guardrail=guardrail)),
        patch.object(cmd_init.platform_support, "host_os", return_value="linux"),
        patch.object(cmd_init, "_sandboxes_possible", return_value=False),
        patch.object(cmd_init, "_unguarded_acp_summary", return_value=""),
        patch.object(cmd_init, "_closed_fail_mode_connectors", return_value=closed or []),
    ):
        cmd_init._render_first_run_report(report, renderer)
    return [line for line in lines if "the gateway is not running" in line]


def test_init_summary_names_fail_mode_closed_for_a_saved_open() -> None:
    lines = _init_outage_lines(GuardrailConfig(hook_fail_mode="open"))
    assert len(lines) == 1, lines
    assert "your saved fail mode" in lines[0]
    assert "defenseclaw guardrail fail-mode closed" in lines[0]
    assert "use-pack strict" not in lines[0]

    lines = _init_outage_lines(
        GuardrailConfig(connectors={"claudecode": PerConnectorGuardrailConfig(hook_fail_mode="open")})
    )
    assert len(lines) == 1 and "fail-mode closed --connector claudecode" in lines[0], lines


def test_init_summary_keeps_the_strict_hint_when_no_mode_is_saved() -> None:
    gc = GuardrailConfig(hook_fail_mode="open")
    gc._hook_fail_mode_saved = False  # the tier decides, as on a fresh default install
    lines = _init_outage_lines(gc)
    assert len(lines) == 1, lines
    assert "defenseclaw guardrail use-pack strict" in lines[0]
    assert "fail-mode closed" not in lines[0]


def _migrate_notice(tmp_path, guardrail: GuardrailConfig) -> str:
    (tmp_path / "hook_contract_lock.json").write_text(
        json.dumps({"connectors": {"claudecode": {"hook_fail_mode": "closed"}}}), encoding="utf-8"
    )
    out: list[str] = []
    with (
        patch("defenseclaw.config.load", return_value=SimpleNamespace(guardrail=guardrail, deployment_mode="")),
        patch.object(cmd_migrate.ux, "warn", side_effect=lambda m, *a, **k: out.append(m)),
        patch.object(cmd_migrate.ux, "subhead", side_effect=lambda m, *a, **k: out.append(m)),
    ):
        cmd_migrate._report_hook_fail_mode_changes(str(tmp_path))
    return "\n".join(out)


def test_migrate_notice_names_the_saved_open_not_the_default_policy(tmp_path) -> None:
    text = _migrate_notice(tmp_path, GuardrailConfig(hook_fail_mode="open"))
    assert "claudecode hooks now let a call run with a warning" in text
    assert "your saved fail mode" in text and "default policy" not in text
    assert "defenseclaw guardrail fail-mode closed" in text
    assert "use-pack strict" not in text


def test_migrate_notice_keeps_the_strict_hint_when_no_mode_is_saved(tmp_path) -> None:
    gc = GuardrailConfig(hook_fail_mode="open")
    gc._hook_fail_mode_saved = False
    text = _migrate_notice(tmp_path, gc)
    assert "(default policy)" in text
    assert "defenseclaw guardrail use-pack strict" in text
    assert "fail-mode closed" not in text


def test_init_summary_names_a_saved_closed_not_the_strict_policy() -> None:
    lines = _init_outage_lines(GuardrailConfig(hook_fail_mode="closed"), closed=["claudecode"])
    assert lines == ["  Your saved fail mode: hooks block the agent while the gateway is not running."], lines

    gc = GuardrailConfig(hook_fail_mode="closed")
    gc._hook_fail_mode_saved = False  # the strict tier decides
    lines = _init_outage_lines(gc, closed=["claudecode"])
    assert len(lines) == 1 and lines[0].startswith("  Strict policy: hooks block"), lines
