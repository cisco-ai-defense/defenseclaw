"""rel-1-0-6 GAP-0576: ``guardrail fail-mode --connector`` for Kiro and the proxy connectors.

The refusal Kiro hit was in ``connector reconcile`` (Go), and
TestConnectorReconcileSelectedKiroAppliesEachFailMode proves it is gone; the
Kiro test here only pins the CLI side (reconcile, then verify, no rollback).
OpenClaw and ZeptoClaw have no hook registration: a scoped change saves the
outage mode of their PATH shims, skips ``connector reconcile`` and refreshes
the shims' installed mode with ``connector refresh-fail-modes``.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner
from defenseclaw import config as dcconfig
from defenseclaw.commands import cmd_guardrail
from defenseclaw.context import AppContext
from defenseclaw.fail_mode import ConnectorFailModeState

from tests.fail_mode_tier import policy_tier_follows_the_saved_fail_mode  # noqa: F401 - autouse fixture


def _app(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, names: list[str]) -> AppContext:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("DEFENSECLAW_FAIL_MODE", raising=False)
    data_dir = tmp_path / "data"
    (data_dir / "hooks").mkdir(parents=True)
    guardrail = dcconfig.GuardrailConfig()
    guardrail.enabled = True
    guardrail.hook_fail_mode = "open"
    guardrail.connectors = {name: dcconfig.PerConnectorGuardrailConfig() for name in names}
    cfg = SimpleNamespace(
        data_dir=str(data_dir),
        guardrail=guardrail,
        gateway=SimpleNamespace(host="127.0.0.1", port=18789),
        deployment_mode="",
    )
    cfg.active_connector = lambda: names[0]
    cfg.active_connectors = lambda: list(names)
    cfg.save = MagicMock()
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    return app


def _state(name: str, desired: str, runtime: str) -> ConnectorFailModeState:
    return ConnectorFailModeState(
        connector=name,
        desired=desired,
        configured=desired,
        runtime=runtime,
        sources=(("config", desired), ("hook-script", runtime)),
        drift=() if desired == runtime else (f"hook-script-{runtime}",),
    )


@pytest.mark.parametrize(("start", "mode"), [("open", "closed"), ("closed", "open")])
def test_scoped_kiro_fail_mode_refreshes_and_verifies(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, start: str, mode: str
) -> None:
    app = _app(monkeypatch, tmp_path, ["kiro", "codex"])
    app.cfg.guardrail.connectors["kiro"].hook_fail_mode = start
    with (
        patch.object(cmd_guardrail, "resolve_connector_fail_mode", return_value=_state("kiro", start, start)),
        patch.object(
            cmd_guardrail, "reconcile_connector_registration", return_value=_state("kiro", mode, mode)
        ) as reconcile,
    ):
        result = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, [mode, "--connector", "kiro", "--yes"], obj=app)
    assert result.exit_code == 0, result.output
    reconcile.assert_called_once_with(app.cfg, "kiro")
    assert app.cfg.guardrail.connectors["kiro"].hook_fail_mode == mode
    assert f"Kiro runtime registration refreshed and verified with fail={mode}" in result.output
    assert "restored" not in result.output


@pytest.mark.parametrize(("name", "label"), [("openclaw", "OpenClaw"), ("zeptoclaw", "ZeptoClaw")])
@pytest.mark.parametrize("mode", ["closed", "open"])
def test_scoped_proxy_fail_mode_saves_the_shim_mode_without_reconcile(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, name: str, label: str, mode: str
) -> None:
    app = _app(monkeypatch, tmp_path, [name, "codex"])
    app.cfg.guardrail.connectors[name].hook_fail_mode = "open" if mode == "closed" else "closed"
    with (
        patch.object(cmd_guardrail, "resolve_connector_fail_mode", return_value=_state(name, "open", "open")),
        patch.object(cmd_guardrail, "reconcile_connector_registration") as reconcile,
        patch.object(cmd_guardrail, "_refresh_hook_outage_modes") as refresh,
    ):
        result = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, [mode, "--connector", name, "--yes"], obj=app)
    assert result.exit_code == 0, result.output
    reconcile.assert_not_called()
    refresh.assert_called_once_with(app)
    app.cfg.save.assert_called_once()
    assert app.cfg.guardrail.connectors[name].hook_fail_mode == mode
    assert f"{label}'s PATH shims (curl, wget, ssh, nc, pip, npm)" in result.output
    assert "proxied model requests are blocked while the gateway is down" in result.output
    assert f"{label} PATH shims now use fail={mode}" in result.output
    for wrong in ("exit 2", "restored", "update failed", "registration refreshed and verified"):
        assert wrong not in result.output, result.output


def test_scoped_proxy_fail_mode_no_restart_saves_with_shim_wording(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    app = _app(monkeypatch, tmp_path, ["openclaw", "codex"])
    with (
        patch.object(cmd_guardrail, "resolve_connector_fail_mode", return_value=_state("openclaw", "open", "open")),
        patch.object(cmd_guardrail, "reconcile_connector_registration") as reconcile,
        patch.object(cmd_guardrail, "_refresh_hook_outage_modes") as refresh,
    ):
        result = CliRunner().invoke(
            cmd_guardrail.fail_mode_cmd, ["closed", "--connector", "openclaw", "--yes", "--no-restart"], obj=app
        )
    assert result.exit_code == 0, result.output
    reconcile.assert_not_called()
    refresh.assert_not_called()
    assert app.cfg.guardrail.connectors["openclaw"].hook_fail_mode == "closed"
    assert "PATH shims read it when they run" in result.output
    assert "runtime registration was not refreshed" not in result.output
    assert "exit 2" not in result.output
