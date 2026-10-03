"""Guardrail fail-mode messaging with the guardrail off (GAP-2178)."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_guardrail

from tests.test_fail_mode_runtime import _runtime_cfg
from tests.test_fcux_cli_messages_b11 import _app, _fail_mode, _roster


def test_fail_mode_while_off_counts_every_saved_connector(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # GAP-2178: the summary said "2 active connector overrides ... Codex is disabled (no hooks)"
    # although codex's value was written, and a separate warning repeated the per-line note.
    cfg = _roster(monkeypatch, tmp_path)
    cfg.guardrail.connectors["codex"].enabled = False
    cfg.guardrail.enabled = False
    result = _fail_mode(cfg, "closed")
    assert result.exit_code == 0, result.output
    out = " ".join(result.output.split())
    assert (
        "Codex (codex): disabled (no hooks); closed is saved; it stays disabled until "
        "'defenseclaw guardrail enable --connector codex'" in out
    )
    assert (
        "Config saved (global default + 3 connector overrides = closed; Codex saved, stays disabled until "
        "'defenseclaw guardrail enable --connector codex') — applies when the guardrail is enabled" in out
    )
    assert "active connector" not in out
    assert "currently disabled" not in out
    assert cfg.guardrail.connectors["codex"].hook_fail_mode == "closed"

    again = _fail_mode(cfg, "closed")
    assert again.exit_code == 0, again.output
    assert "Hook fail mode is already 'closed' for configured connectors — nothing to do." in again.output


def test_fail_mode_open_on_openclaw_only_says_it_does_not_apply(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # GAP-2448: "responses will now ALLOW the agent" although OpenClaw (no hooks)
    # keeps blocking its requests while the gateway is down.
    cfg, _home = _runtime_cfg(monkeypatch, tmp_path, {"openclaw": ""})
    cfg.guardrail.connectors = {}
    cfg.guardrail.connector = "openclaw"
    cfg.guardrail.hook_fail_mode = "closed"
    result = _fail_mode(cfg, "open")
    assert result.exit_code == 0, result.output
    out = " ".join(result.output.split())
    assert "OpenClaw is proxy-backed and has no hooks, so the hook fail mode does not apply to it" in out
    assert "will now ALLOW" not in out

    bare = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, [], obj=_app(cfg))
    assert bare.exit_code == 0, bare.output
    assert "OpenClaw (openclaw): closed (proxy-backed, no hooks" in " ".join(bare.output.split())
