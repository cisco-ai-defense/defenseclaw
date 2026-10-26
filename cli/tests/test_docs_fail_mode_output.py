# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-0612: the fail-modes page quotes what `guardrail fail-mode` prints."""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_guardrail, cmd_setup
from defenseclaw.context import AppContext

from tests.test_fail_mode_runtime import _runtime_cfg

PAGE = Path(__file__).resolve().parents[2] / "docs-site" / "content" / "docs" / "reference" / "configuration" / "fail-modes.mdx"
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _lines(text: str) -> list[str]:
    lines = [_ANSI.sub("", line).rstrip() for line in text.splitlines()]
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()
    return lines


def _page_example() -> list[str]:
    section = PAGE.read_text(encoding="utf-8").split("## Persisted fail mode", 1)[1]
    return _lines(section.split("```text", 1)[1].split("```", 1)[0])


def _run(cfg, args: list[str]):
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()

    def runtime_state(cfg, name):
        mode = cfg.guardrail.effective_hook_fail_mode(name)
        return SimpleNamespace(runtime=mode, desired=mode, effective=mode, current=True, drift=(), note="")

    with (
        patch.object(cmd_guardrail, "_resolve_active_connector", return_value="claudecode"),
        patch.object(cmd_guardrail, "_gateway_running", return_value=False),
        patch.object(cmd_guardrail, "resolve_connector_fail_mode", side_effect=runtime_state),
        patch.object(cmd_guardrail, "reconcile_connector_registration"),
        patch.object(cmd_setup, "_restart_services"),
    ):
        result = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, args, obj=app)
    assert result.exit_code == 0, result.output
    return result.output


def test_the_persisted_fail_mode_example_is_the_command_output(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # The page's own setup: unset Claude Code in the default tier and unset
    # Codex in strict. A separate test covers an explicit saved choice.
    cfg, _home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "", "codex": ""})
    cfg.guardrail.hook_fail_mode = ""
    cfg.guardrail.connectors["codex"].rule_pack = "strict"
    assert _lines(_run(cfg, [])) == _page_example()


def test_a_per_user_explicit_closed_choice_wins_over_the_default_tier(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg, _home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "", "codex": ""})
    output = _run(cfg, ["closed", "--connector", "codex", "--yes"])
    assert cfg.guardrail.effective_hook_fail_mode("codex") == "closed"
    assert "gateway outage will now BLOCK" in output
    page = " ".join(PAGE.read_text(encoding="utf-8").split())
    assert "An explicit saved `closed` or `open` wins over the policy tier" in page


def test_global_closed_choice_is_saved_when_the_default_was_unset(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg, _home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "", "codex": ""})
    cfg.guardrail.hook_fail_mode = ""
    _run(cfg, ["closed", "--yes"])
    assert cfg.guardrail.hook_fail_mode == "closed"
    assert cfg.guardrail._hook_fail_mode_saved
    cfg.save.assert_called_once()


def test_scoped_open_choice_is_saved_even_when_strict_inherits_global_open(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg, _home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "", "codex": ""})
    cfg.guardrail.connectors["codex"].rule_pack = "strict"
    _run(cfg, ["open", "--connector", "codex", "--yes"])
    assert cfg.guardrail.connectors["codex"].hook_fail_mode == "open"
    cfg.save.assert_called_once()
