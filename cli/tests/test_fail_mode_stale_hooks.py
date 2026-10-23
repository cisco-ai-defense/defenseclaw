# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""A fail-mode change reaches the rendered hooks even with the gateway stopped.

GAP-0009 / GAP-0006: config unset guardrail.hook_fail_mode said closed while
the hooks kept failing open until the next gateway start, doctor reported
that hook as PASS, and config set printed nothing about it.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_config
from defenseclaw.config_inspect import ConfigV8WireResult

_CONFIG = (
    "config_version: 9\nguardrail:\n  enabled: true\n  hook_fail_mode: open\n  connectors:\n    codex: {mode: action}\n"
)


def _wire() -> ConfigV8WireResult:
    return ConfigV8WireResult(
        wire_version=1,
        kind="effective",
        config_version=9,
        source="/tmp/config.yaml",
        data_dir="/tmp/dc",
        plan_digest="digest",
        network_validation="offline_syntax_and_literal_policy_only",
        valid=None,
        effective={},
    )


def _run(tmp_path: Path, monkeypatch, args: list[str], *, gateway_running: bool, reconcile: MagicMock):
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    (tmp_path / "config.yaml").write_text(_CONFIG)
    with (
        patch("defenseclaw.gateway.local_policy_digest", return_value=None),
        patch.object(cmd_config, "inspect_v8_config", return_value=_wire()),
        patch("defenseclaw.process_liveness.pid_file_alive", return_value=gateway_running),
        patch("defenseclaw.fail_mode.reconcile_connector_registration", reconcile),
    ):
        return CliRunner().invoke(cmd_config.config_cmd, args)


@pytest.mark.parametrize("args", [["unset", "guardrail.hook_fail_mode"], ["set", "guardrail.hook_fail_mode", "closed"]])
def test_fail_mode_change_with_gateway_stopped_re_renders_hooks(tmp_path: Path, monkeypatch, args) -> None:
    reconcile = MagicMock()
    result = _run(tmp_path, monkeypatch, args, gateway_running=False, reconcile=reconcile)
    assert result.exit_code == 0, result.output
    assert [call.args[1] for call in reconcile.call_args_list] == ["codex"]
    assert "re-rendered the hooks now (codex fail-closed)" in result.output


def test_native_deny_connectors_are_re_rendered_outside_secure_client(tmp_path: Path, monkeypatch) -> None:
    # Per-user Antigravity, Copilot and Hermes hooks follow the fail mode, so
    # a fail-mode write re-renders them too (only Secure Client keeps them
    # upstream fail-open, GAP-0027).
    reconcile = MagicMock()
    config = _CONFIG + "".join(f"    {name}: {{mode: action}}\n" for name in ("antigravity", "copilot", "hermes"))
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    (tmp_path / "config.yaml").write_text(config)
    with (
        patch("defenseclaw.gateway.local_policy_digest", return_value=None),
        patch.object(cmd_config, "inspect_v8_config", return_value=_wire()),
        patch("defenseclaw.process_liveness.pid_file_alive", return_value=False),
        patch("defenseclaw.fail_mode.reconcile_connector_registration", reconcile),
    ):
        result = CliRunner().invoke(cmd_config.config_cmd, ["unset", "guardrail.hook_fail_mode"])
    assert result.exit_code == 0, result.output
    assert sorted(call.args[1] for call in reconcile.call_args_list) == ["antigravity", "codex", "copilot", "hermes"]
    assert "could not be re-rendered" not in result.output
    assert "keep their previous fail mode" not in result.output


def test_running_gateway_and_unrelated_keys_leave_hooks_to_the_gateway(tmp_path: Path, monkeypatch) -> None:
    reconcile = MagicMock()
    running = _run(
        tmp_path, monkeypatch, ["unset", "guardrail.hook_fail_mode"], gateway_running=True, reconcile=reconcile
    )
    assert running.exit_code == 0, running.output
    unrelated = _run(
        tmp_path, monkeypatch, ["set", "update.check", "false"], gateway_running=False, reconcile=reconcile
    )
    assert unrelated.exit_code == 0, unrelated.output
    reconcile.assert_not_called()


def test_failed_re_render_warns_that_hooks_keep_the_old_mode(tmp_path: Path, monkeypatch) -> None:
    reconcile = MagicMock(side_effect=OSError("native defenseclaw-gateway executable not found"))
    result = _run(
        tmp_path, monkeypatch, ["unset", "guardrail.hook_fail_mode"], gateway_running=False, reconcile=reconcile
    )
    assert result.exit_code == 0, result.output
    assert "codex hooks could not be re-rendered" in result.output
    assert "until defenseclaw-gateway start (wanted fail-closed)" in result.output


@pytest.mark.parametrize(
    ("effective", "desired", "status"),
    [("open", "closed", "fail"), ("closed", "open", "warn"), ("closed", "closed", "pass")],
)
def test_doctor_does_not_pass_a_hook_whose_fail_mode_drifted(effective, desired, status) -> None:
    from defenseclaw.commands import cmd_doctor

    report = {"effective": effective, "desired": desired, "runtime": effective, "provenance": "hook-script", "note": ""}
    cfg = SimpleNamespace(
        guardrail=SimpleNamespace(effective_mode=lambda _name: "action"),
        skill_dirs=lambda connector=None: [],
        plugin_dirs=lambda connector=None: [],
        mcp_servers=lambda connector=None, **_: [],
    )
    emitted: list[tuple[str, str, str]] = []
    with (
        patch("defenseclaw.fail_mode.connector_fail_mode_report", return_value=report),
        patch.object(cmd_doctor, "_workspace_dir", return_value=""),
        patch.object(
            cmd_doctor, "_emit", side_effect=lambda tag, label, detail="", **_: emitted.append((tag, label, detail))
        ),
    ):
        cmd_doctor._check_connector_inventory(cfg, "codex", cmd_doctor._DoctorResult())
    mode_rows = [row for row in emitted if row[1] == "Mode"]
    assert len(mode_rows) == 1 and mode_rows[0][0] == status, mode_rows
