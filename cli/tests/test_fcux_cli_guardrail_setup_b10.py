# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Guardrail and setup message wording (final-cert UX batch 10)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import click
import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_guardrail, cmd_setup
from defenseclaw.context import AppContext
from defenseclaw.logger import CanonicalObservabilityUnavailableError

from tests.test_fail_mode_runtime import _runtime_cfg


def _app(cfg) -> AppContext:
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    return app


def _codex_off(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "open", "codex": "open", "cursor": "open"})
    cfg.guardrail.connectors["codex"].enabled = False
    return cfg, home


@pytest.mark.parametrize("restart", ["--restart", "--no-restart"])
def test_enable_header_names_only_the_connectors_it_sets_up(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, restart: str
) -> None:
    # GAP-1809: the header listed codex although it stays disabled.
    cfg, _home = _codex_off(monkeypatch, tmp_path)
    cfg.guardrail.enabled = False
    # Windows verifies the Claude Code executable first; the runner has none.
    with (
        patch.object(cmd_guardrail, "_resolve_active_connector", return_value="claudecode"),
        patch.object(cmd_setup, "_restart_services"),
        patch.object(cmd_setup, "_record_windows_setup_agent_selections", return_value=None),
    ):
        result = CliRunner().invoke(cmd_guardrail.enable_cmd, ["--yes", restart], obj=_app(cfg))
    assert result.exit_code == 0, result.output
    header = next(line for line in result.output.splitlines() if "Enabling guardrail" in line)
    assert header.strip() == "Enabling guardrail for Claude Code (claudecode), Cursor (cursor)", header
    assert result.output.count("Codex (codex) stays disabled; turn it on with:") == 1
    assert "guardrail enable --connector codex" in result.output
    assert "Restart any running affected agent (for example Codex)" in result.output


def test_status_shows_no_fail_mode_for_a_disabled_connector(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # GAP-1953: status said Fail=unknown while fail-mode said "disabled (no hooks)".
    cfg, _home = _codex_off(monkeypatch, tmp_path)
    with patch.object(cmd_guardrail, "_terminal_width", return_value=200):
        result = CliRunner().invoke(cmd_guardrail.status_cmd, [], obj=_app(cfg))
    assert result.exit_code == 0, result.output
    codex_row = next(line for line in result.output.splitlines() if " codex " in line)
    assert "unknown" not in codex_row, codex_row
    assert " disabled " in codex_row and " - " in codex_row, codex_row
    assert "fail - = disabled connector" in result.output


def test_offline_setup_audit_note_prints_once_in_plain_words() -> None:
    # GAP-1951: a 3-connector run printed the note 3 times, with "canonical".
    logger = MagicMock()
    logger.log_action.side_effect = CanonicalObservabilityUnavailableError("gateway stopped")
    app = SimpleNamespace(logger=logger)

    @click.command()
    def run() -> None:
        for name in ("claudecode", "codex", "cursor"):
            cmd_setup._log_setup_action(app, "setup-hook-connector", f"connector={name}", allow_offline=True)

    result = CliRunner().invoke(run, [])
    assert result.exit_code == 0, result.output
    assert result.output.count("setup audit event was not recorded") == 1, result.output
    assert "canonical" not in result.output
    assert "defenseclaw-gateway start" in result.output
