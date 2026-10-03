# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""CLI message wording (final-cert UX batch 11)."""

from __future__ import annotations

import io
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner
from defenseclaw import ux
from defenseclaw.commands import cmd_guardrail, cmd_setup
from defenseclaw.context import AppContext
from defenseclaw.logger import CanonicalObservabilityUnavailableError

from tests.helpers import cleanup_app, make_app_context
from tests.test_fail_mode_runtime import _runtime_cfg


def _app(cfg) -> AppContext:
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    return app


def _roster(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """claudecode and cursor in action mode, codex in observe mode, no fail-mode overrides."""
    cfg, _home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "", "codex": "", "cursor": ""})
    cfg.guardrail.mode = "observe"
    cfg.guardrail.connectors["claudecode"].mode = "action"
    cfg.guardrail.connectors["cursor"].mode = "action"
    return cfg


def _fail_mode(cfg, mode: str):
    state = SimpleNamespace(runtime="open", desired="open", current=True, drift=())
    with (
        patch.object(cmd_guardrail, "_gateway_running", return_value=False),
        patch.object(cmd_guardrail, "resolve_connector_fail_mode", return_value=state),
        patch.object(cmd_guardrail, "reconcile_connector_registration"),
        patch.object(cmd_setup, "_restart_services"),
    ):
        return CliRunner().invoke(cmd_guardrail.fail_mode_cmd, [mode, "--yes"], obj=_app(cfg))


def test_setup_skill_scanner_with_the_gateway_stopped_saves_and_exits_zero() -> None:
    # GAP-1970: the saved change ended with "Error: ... run the command again", rc 1.
    from defenseclaw.commands.cmd_setup import setup

    app, tmp_dir, db_path = make_app_context()
    try:
        app.logger.log_action = MagicMock(side_effect=CanonicalObservabilityUnavailableError("down"))
        result = CliRunner().invoke(setup, ["skill-scanner", "--non-interactive", "--use-behavioral"], obj=app)
        assert result.exit_code == 0, result.output
        assert app.cfg.scanners.skill_scanner.use_behavioral
        assert result.output.count("setup audit event was not recorded") == 1, result.output
        assert "run the command again" not in result.output
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_bare_disable_names_only_the_connectors_it_tears_down(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # GAP-1985: codex, already disabled on its own, was listed as torn down.
    cfg, _home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "open", "codex": "open", "cursor": "open"})
    cfg.guardrail.connectors["codex"].enabled = False
    with (
        patch.object(cmd_guardrail, "_resolve_active_connector", return_value="claudecode"),
        patch.object(cmd_guardrail, "_gateway_running", return_value=True),
        patch.object(cmd_setup, "_restart_services"),
    ):
        result = CliRunner().invoke(cmd_guardrail.disable_cmd, ["--yes"], obj=_app(cfg))
    assert result.exit_code == 0, result.output
    header = next(line for line in result.output.splitlines() if "Disabling guardrail" in line)
    assert header.strip() == "Disabling guardrail for Claude Code (claudecode), Cursor (cursor)", header
    assert "Codex (codex) is already disabled on its own." in result.output
    assert "teardown complete for 2 connectors: claudecode, cursor" in result.output


def test_fail_mode_closed_lists_the_observe_connector_it_closes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # GAP-1977 (a): the fan-out gives codex its own "closed", which applies in
    # observe mode too, but the output said codex stays fail-open.
    cfg = _roster(monkeypatch, tmp_path)
    result = _fail_mode(cfg, "closed")
    assert result.exit_code == 0, result.output
    assert "stays fail-open while in observe mode" not in result.output
    assert "Codex (codex): open → closed (its own setting, also in observe mode)" in result.output
    assert "Cursor (cursor): " in result.output
    assert "global default + 3 active connector overrides = closed)" in result.output
    assert cfg.guardrail.effective_hook_fail_mode("codex") == "closed"


def test_fail_mode_change_list_shows_a_disabled_connector_as_disabled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # GAP-1977 (b): a disabled codex was listed as changing and counted.
    cfg = _roster(monkeypatch, tmp_path)
    cfg.guardrail.connectors["codex"].enabled = False
    result = _fail_mode(cfg, "closed")
    assert result.exit_code == 0, result.output
    assert "Codex (codex): disabled (no hooks); closed is saved for when it is turned on again" in result.output
    assert "Codex (codex): open → closed" not in result.output
    assert "global default + 2 active connector overrides = closed; Codex is disabled (no hooks))" in result.output


def test_piped_windows_table_cell_keeps_its_right_padding() -> None:
    # GAP-1972: "| OK ready| codeguard" where the column was sized for "✓ ready".
    from rich.console import Console
    from rich.table import Table

    piped = io.StringIO()
    with (
        patch.object(ux.sys, "platform", "win32"),
        patch.object(ux, "_console_output_code_page", return_value=437),
    ):
        stream = ux.ascii_safe_redirected_stream(piped)
    with patch.object(sys, "stdout", stream):
        cell = ux.table_cell_text("✓ ready")
    assert ux.table_cell_text("✓ ready") == "✓ ready"
    table = Table()
    table.add_column("Status", no_wrap=True)
    table.add_column("Skill", no_wrap=True)
    table.add_row(cell, "codeguard")
    rendered = io.StringIO()
    Console(file=rendered, width=80, color_system=None, legacy_windows=False).print(table)
    stream.write(rendered.getvalue())
    assert "| OK ready | codeguard |" in piped.getvalue(), piped.getvalue()
