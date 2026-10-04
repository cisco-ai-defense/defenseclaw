# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Guardrail and setup CLI messages (final-cert fix batch 7)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner
from defenseclaw import platform_support
from defenseclaw.commands import cmd_guardrail, cmd_setup
from defenseclaw.context import AppContext

from tests.test_fail_mode_runtime import _runtime_cfg


def _app(cfg) -> AppContext:
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    return app


def test_teardown_restart_names_only_torn_down_connectors(tmp_path: Path, capsys) -> None:
    # GAP-1985: the disable restart said "3 hook connectors (claudecode, codex,
    # cursor): enforcement via native lifecycle surfaces" although codex was off.
    with patch.object(cmd_setup, "_restart_defense_gateway", return_value=True):
        cmd_setup._restart_services(
            str(tmp_path),
            connector="claudecode",
            connectors=["claudecode", "codex", "cursor"],
            summary_exclude=frozenset({"codex"}),
            teardown=True,
        )
    out = capsys.readouterr().out
    assert "2 hook connectors (claudecode, cursor): guardrail hooks removed" in out
    assert "enforcement via" not in out


def test_bare_disable_passes_the_torn_down_set_to_the_restart(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg, _home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "open", "codex": "open", "cursor": "open"})
    cfg.guardrail.connectors["codex"].enabled = False
    with (
        patch.object(cmd_guardrail, "_resolve_active_connector", return_value="claudecode"),
        patch.object(cmd_guardrail, "_gateway_running", return_value=True),
        patch.object(cmd_setup, "_restart_services") as restart,
    ):
        result = CliRunner().invoke(cmd_guardrail.disable_cmd, ["--yes"], obj=_app(cfg))
    assert result.exit_code == 0, result.output
    assert restart.call_args.kwargs["summary_exclude"] == frozenset({"codex"})
    assert restart.call_args.kwargs["teardown"] is True


def test_windows_support_reasons_hold_no_release_bookkeeping() -> None:
    # GAP-2106: "Platform support: supported - ... validation metadata is not
    # recorded and live evidence remains false" read as contradictory.
    for name, support in platform_support.WINDOWS_CONNECTOR_SUPPORT.items():
        text = support.reason.lower()
        for phrase in ("live evidence", "validation metadata", "certification"):
            assert phrase not in text, (name, support.reason)


def test_judge_step_says_settings_are_shared_once(capsys) -> None:
    # GAP-2107: the line was printed by the connector pick and again by the LLM step.
    gc = MagicMock()
    gc.judge.hook_connectors = []
    gc.judge.enabled = False
    with (
        patch.object(cmd_setup, "_prompt_checkbox_selection", return_value=[]),
        patch.object(cmd_setup, "_merge_batch_judge_selection"),
    ):
        cmd_setup._prompt_guardrail_judge_enablement(gc, ["claudecode"])
        cmd_setup._prompt_batch_judge_connectors(["claudecode"], gc)
    assert "shared by all connectors" not in capsys.readouterr().out
