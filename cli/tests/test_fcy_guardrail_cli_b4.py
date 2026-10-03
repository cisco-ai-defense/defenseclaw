"""Guardrail CLI fixes, batch 4 (GAP-2083, GAP-2156)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from defenseclaw.commands import cmd_setup

from tests.test_cmd_judge import invoke as judge_invoke
from tests.test_cmd_judge import make_ctx
from tests.test_cmd_setup_fu_phase2 import _BaseSetup, _invoke, _stub_side_effects
from tests.test_fcux_cli_messages_b11 import _fail_mode, _roster


def _judge_ctx(modes: dict[str, str], gate: list[str] | None = None):
    app = make_ctx(connectors=list(modes), hook_connectors=gate or [])
    app.cfg.guardrail.effective_mode = lambda c: modes.get(c, "observe")
    return app


@patch.object(cmd_setup, "_restart_services")
def test_judge_add_all_names_the_observe_connectors(_restart) -> None:
    # GAP-2083 (1): 'add all' was accepted silently with every connector in observe.
    app = _judge_ctx({"claudecode": "action", "codex": "observe", "hermes": "observe"})
    result = judge_invoke(app, ["add", "all", "--no-restart"])
    assert result.exit_code == 0, result.output
    assert app.cfg.guardrail.judge.hook_connectors == ["*"]
    assert "codex, hermes are in observe mode" in result.output


def test_judge_list_hint_for_an_observe_connector_points_to_setup() -> None:
    # GAP-2083 (3): the hint named 'judge add codex', which refuses an observe connector.
    app = _judge_ctx({"claudecode": "action", "codex": "observe"}, gate=["claudecode"])
    result = judge_invoke(app, ["list"])
    assert result.exit_code == 0, result.output
    assert "judge add codex" not in result.output
    assert "defenseclaw setup codex --mode action --enable-judge --yes" in result.output


class TestSetupNarrowsAllGate(_BaseSetup):
    def test_observe_setup_says_all_was_replaced_and_keeps_only_action(self) -> None:
        # GAP-2083 (2): setup codex rewrote '*' to [claudecode, hermes] silently,
        # keeping observe-mode hermes in the gate.
        self._seed_map("claudecode", "codex", "hermes")
        gc = self.app.cfg.guardrail
        gc.connectors["claudecode"].mode = "action"
        gc.judge.enabled = True
        gc.judge.hook_connectors = ["*"]
        with _stub_side_effects():
            res = _invoke(["codex", "--yes", "--no-restart", "--mode", "observe"], self.app)
        assert res.exit_code == 0, res.output
        assert gc.judge.hook_connectors == ["claudecode"]
        out = " ".join(res.output.split())
        assert "LLM judge gate 'all' was replaced with claudecode: codex, hermes are in observe mode" in out


def test_fail_mode_with_the_guardrail_off_reads_as_saved_not_active(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # GAP-2156: torn-down connectors were "active ... reconcile stale runtime" and "will now BLOCK".
    cfg = _roster(monkeypatch, tmp_path)
    cfg.guardrail.enabled = False
    result = _fail_mode(cfg, "closed")
    assert result.exit_code == 0, result.output
    assert "Claude Code (claudecode): guardrail off (no hooks); closed is saved for when it is turned on again" in (
        result.output
    )
    assert "reconcile stale runtime" not in result.output
    assert "will now BLOCK" not in result.output
    assert "Once the guardrail is enabled" in result.output
    assert cfg.guardrail.effective_hook_fail_mode("claudecode") == "closed"
