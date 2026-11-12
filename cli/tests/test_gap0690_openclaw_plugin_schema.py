# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-0690: plugin config from an older setup is checked before readiness."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_doctor, cmd_status
from defenseclaw.commands.cmd_status import status as status_cmd
from defenseclaw.config import PerConnectorGuardrailConfig
from defenseclaw.openclaw_guardrail import patch_openclaw_config
from defenseclaw.openclaw_plugin_config import openclaw_plugin_config_issue

from tests.helpers import cleanup_app, make_app_context

MANIFEST = Path(__file__).resolve().parents[2] / "extensions" / "defenseclaw" / "openclaw.plugin.json"


def _installed_config(tmp_path: Path, plugin_config: dict) -> Path:
    manifest = tmp_path / "extensions" / "defenseclaw" / "openclaw.plugin.json"
    manifest.parent.mkdir(parents=True)
    shutil.copyfile(MANIFEST, manifest)
    config_file = tmp_path / "openclaw.json"
    config_file.write_text(json.dumps({"plugins": {"entries": {"defenseclaw": {
        "config": plugin_config,
        "hooks": {"allowConversationAccess": True},
    }}}}), encoding="utf-8")
    return config_file


def _doctor_result(config_file: Path) -> cmd_doctor._DoctorResult:
    cfg = SimpleNamespace(
        guardrail=SimpleNamespace(enabled=True),
        claw=SimpleNamespace(home_dir=str(config_file.parent), config_file=str(config_file)),
    )
    result = cmd_doctor._DoctorResult(quiet=True)
    with (
        patch.object(cmd_doctor, "_guardrail_proxy_intentionally_closed", return_value=False),
        patch.object(cmd_doctor, "_doctor_active_connectors", return_value=["openclaw"]),
        patch.object(cmd_doctor, "_connector_enabled", return_value=True),
    ):
        cmd_doctor._check_proxy_interception(cfg, result, live_health={"uptime_ms": 2000})
    return result


def test_gap0690_doctor_fails_immediately_when_plugin_config_is_rejected(tmp_path: Path) -> None:
    config_file = _installed_config(tmp_path, {"level": 3, "operatorNote": "note"})
    assert "schema rejects" in openclaw_plugin_config_issue(str(config_file), str(tmp_path))
    result = _doctor_result(config_file)
    assert result.failed == 1
    assert result.warned == 0
    assert result.checks[0]["label"] == "OpenClaw interception"
    assert "schema rejects" in result.checks[0]["detail"]


def test_gap0690_python_writer_refuses_rejected_config_without_changing_file(tmp_path: Path) -> None:
    config_file = _installed_config(tmp_path, {"operatorNote": "note"})
    original = config_file.read_bytes()
    with pytest.raises(ValueError, match="schema rejects"):
        patch_openclaw_config(str(config_file), "", 0, "", "")
    assert config_file.read_bytes() == original


def test_gap0690_accepted_plugin_config_twin_keeps_waiting_state(tmp_path: Path) -> None:
    config_file = _installed_config(tmp_path, {"mode": "observe", "agent": {"id": "alice"}})
    assert openclaw_plugin_config_issue(str(config_file), str(tmp_path)) is None
    result = _doctor_result(config_file)
    assert result.failed == 0
    assert result.warned == 1
    assert "waiting for the OpenClaw plugin" in result.checks[0]["detail"]


def test_gap0690_status_json_flags_rejected_config(tmp_path: Path) -> None:
    config_file = _installed_config(tmp_path, {"operatorNote": "note"})
    app, tmp_dir, db_path = make_app_context()
    try:
        app.cfg.data_dir = ""
        app.cfg.claw.home_dir = str(tmp_path)
        app.cfg.claw.config_file = str(config_file)
        app.cfg.guardrail.enabled = True
        app.cfg.guardrail.connector = "openclaw"
        app.cfg.guardrail.connectors = {"openclaw": PerConnectorGuardrailConfig(mode="action")}
        with patch.object(cmd_status, "_fetch_runtime_bound_health", return_value=None):
            result = CliRunner().invoke(status_cmd, ["--json"], obj=app, catch_exceptions=False)
        assert result.exit_code == 0, result.output
        assert "schema rejects" in json.loads(result.output)["openclaw_plugin_config_issue"]
    finally:
        cleanup_app(app, db_path, tmp_dir)
