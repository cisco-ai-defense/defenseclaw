"""rel-1-0-6 GAP-0576: ``guardrail fail-mode --connector`` for Kiro and the proxy connectors.

Kiro's selected refresh was refused by ``connector reconcile`` and the
change rolled back; the Go side now refreshes Kiro like Cursor and Devin
(TestConnectorReconcileSelectedKiroAppliesEachFailMode). OpenClaw and
ZeptoClaw have no hook registration, so a scoped change is refused before
anything is saved, with the reason and the global alternative.
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
def test_scoped_proxy_fail_mode_is_refused_before_any_change(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, name: str, label: str
) -> None:
    app = _app(monkeypatch, tmp_path, [name, "codex"])
    with (
        patch.object(cmd_guardrail, "resolve_connector_fail_mode", return_value=_state(name, "open", "open")),
        patch.object(cmd_guardrail, "reconcile_connector_registration") as reconcile,
    ):
        result = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, ["closed", "--connector", name, "--yes"], obj=app)
    assert result.exit_code == 1, result.output
    assert f"{label} is proxy-backed and has no hook registration to refresh" in result.output
    assert "Nothing was changed." in result.output
    assert "defenseclaw guardrail fail-mode closed" in result.output
    assert "restored" not in result.output and "update failed" not in result.output
    reconcile.assert_not_called()
    app.cfg.save.assert_not_called()
    assert app.cfg.guardrail.connectors[name].hook_fail_mode in ("", None)
