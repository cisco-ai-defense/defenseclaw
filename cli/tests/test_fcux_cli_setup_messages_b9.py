# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Setup and guardrail message wording (final-cert UX batch 9)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import click
import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_guardrail, cmd_setup
from defenseclaw.context import AppContext

from tests.test_fail_mode_runtime import _runtime_cfg


def _app(cfg) -> AppContext:
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    return app


def test_cursor_action_shows_closed_and_disabled_connector_has_no_drift(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # GAP-1717: status said Cursor Fail=open; the bare view printed drift for a
    # disabled connector and two contradicting rules.
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"codex": "open", "cursor": "open"})
    cfg.guardrail.connectors["cursor"].mode = "action"
    cfg.guardrail.connectors["codex"].enabled = False
    app = _app(cfg)
    with (
        patch("defenseclaw.fail_mode._is_windows", return_value=True),
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
    ):
        status = CliRunner().invoke(cmd_guardrail.status_cmd, [], obj=app)
        bare = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, [], obj=app)
    assert status.exit_code == 0, status.output
    cursor_row = next(line for line in status.output.splitlines() if " cursor " in line)
    assert "closed" in cursor_row and " open " not in cursor_row, cursor_row
    assert bare.exit_code == 0, bare.output
    assert "Cursor (cursor): closed" in bare.output
    assert "Codex (codex): disabled (no hooks)" in bare.output
    assert "drift" not in bare.output
    assert "follow each connector" not in bare.output


def test_enable_reports_only_the_connectors_it_set_up(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # GAP-1809: a connector disabled on its own stays disabled and is not
    # listed as set up.
    cfg, _home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "open", "codex": "open", "cursor": "open"})
    cfg.guardrail.enabled = False
    cfg.guardrail.connectors["codex"].enabled = False
    app = _app(cfg)
    with (
        patch.object(cmd_guardrail, "_resolve_active_connector", return_value="claudecode"),
        patch.object(cmd_setup, "_restart_services") as restart,
    ):
        result = CliRunner().invoke(cmd_guardrail.enable_cmd, ["--yes"], obj=app)
    assert result.exit_code == 0, result.output
    assert "connector setup complete for 2 connectors: claudecode, cursor" in result.output
    assert "Codex (codex) stays disabled" in result.output
    assert "guardrail enable --connector codex" in result.output
    assert restart.call_args.kwargs["summary_exclude"] == frozenset({"codex"})


def test_batch_setup_prints_one_summary(capsys: pytest.CaptureFixture[str]) -> None:
    # GAP-1781: one block for the run instead of 4-6 lines per connector.
    summary = {
        "modes": {"claudecode": "action", "codex": "action", "hermes": "action"},
        "fail_open": ["claudecode", "codex"],
        "workspace": None,
    }
    cmd_setup._echo_batch_setup_summary(["claudecode", "codex", "hermes"], summary, restart=False)
    out = capsys.readouterr().out
    assert out.count("Config saved") == 1
    assert "      - codex: action\n" in out
    assert out.count("fail-open") == 1 and "claudecode, codex" in out
    assert "registration and lock evidence" not in out


def test_unanswered_gateway_is_named_in_the_rollback_point_error() -> None:
    # GAP-1859: say the gateway did not answer, and for how long.
    with (
        patch.object(
            cmd_setup, "_capture_setup_applied_runtime_once", side_effect=cmd_setup._SetupGatewayNoAnswerError(4242)
        ),
        patch.object(cmd_setup.time, "sleep"),
        pytest.raises(cmd_setup._SetupGatewayNoAnswerError) as raised,
    ):
        cmd_setup._capture_setup_applied_runtime(SimpleNamespace())
    assert "the running gateway (PID 4242) did not answer within" in str(raised.value)
    assert "[site=" not in str(raised.value)


def test_rollback_restart_with_the_same_start_error_prints_it_once() -> None:
    # GAP-1808: the rollback restart is labelled and does not repeat the error.
    cfg = SimpleNamespace(
        data_dir="/nonexistent",
        gateway=SimpleNamespace(host="127.0.0.1", port=18789),
        active_connectors=lambda: ["codex"],
        active_connector=lambda: "codex",
    )
    cause = cmd_setup._GatewayRestartFailed("gateway restart/readiness failed for: defenseclaw-gateway.")

    def _fail(*_args, **_kwargs):
        click.echo("    Error: cannot start the gateway: port held")
        raise cmd_setup._GatewayRestartFailed(cause.message)

    runner = CliRunner()
    with runner.isolation() as (out, _err, *_rest), patch.object(cmd_setup, "_restart_services", side_effect=_fail):
        with pytest.raises(cmd_setup._GatewayRestartFailed):
            cmd_setup._restart_restored_connector_runtime(SimpleNamespace(cfg=cfg), same_failure=cause)
        text = out.getvalue().decode()
    assert "Restoring the previous configuration" in text
    assert "same error as above" in text
    assert "port held" not in text
