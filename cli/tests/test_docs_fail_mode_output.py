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
    after = section.split("after the second command:", 1)[1]
    return _lines(after.split("```text", 1)[1].split("```", 1)[0])


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
    # The page's own setup: Claude Code and Codex, `guardrail.hook_fail_mode: open`,
    # then its `closed --connector codex --yes`. The page showed the footer of a
    # closed global value (BLOCK, "Still fail-open", "Switch to open").
    cfg, _home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "", "codex": ""})
    _run(cfg, ["closed", "--connector", "codex", "--yes"])
    assert cfg.guardrail.connectors["codex"].hook_fail_mode == "closed"
    assert _lines(_run(cfg, [])) == _page_example()


def test_the_closed_global_footer_the_page_quotes_is_the_command_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg, _home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "open", "codex": ""})
    cfg.guardrail.hook_fail_mode = "closed"
    output = _lines(_run(cfg, []))
    page = PAGE.read_text(encoding="utf-8").split("## Persisted fail mode", 1)[1].split("\n## ", 1)[0]
    # A per-user connector is closed whatever it saved (sa-port-peer): the
    # footer is the BLOCK line alone, with no "Still fail-open" warning.
    footer = "  Invalid, unauthorized, incomplete, and unreachable gateway responses BLOCK connectors that are closed above."
    assert output[-1] == footer, output
    assert f"```text\n{footer}\n```" in page
    assert not any("Still fail-open" in line for line in output), output
    assert "Still fail-open" not in page
