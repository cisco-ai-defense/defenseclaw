# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""``guardrail hilt`` finishes when the gateway is down (the TUI's ``h`` key runs it)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_guardrail
from defenseclaw.config import PerConnectorGuardrailConfig, default_config
from defenseclaw.context import AppContext
from defenseclaw.logger import CanonicalObservabilityUnavailableError

from tests.environment import isolated_home_env


@pytest.fixture
def app(tmp_path, monkeypatch):
    for key, value in isolated_home_env(tmp_path / "home").items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr("defenseclaw.commands.cmd_setup._sync_guardrail_hilt_to_opa", lambda *a, **k: None)
    cfg = default_config()
    cfg.data_dir = str(tmp_path / "dc")
    cfg.policy_dir = str(tmp_path / "dc" / "policies")
    cfg.guardrail.enabled = False  # no gateway restart
    cfg.save = MagicMock()
    context = AppContext()
    context.cfg = cfg
    context.logger = MagicMock()
    context.logger.log_action.side_effect = CanonicalObservabilityUnavailableError("gateway is down")
    return context


@pytest.mark.parametrize("connector", [None, "codex"])
def test_a_saved_change_exits_0_when_the_audit_event_cannot_be_written(app, connector) -> None:
    args = ["on", "--min-severity", "HIGH", "--yes"]
    if connector:
        app.cfg.guardrail.connectors = {
            "codex": PerConnectorGuardrailConfig(),
            "claudecode": PerConnectorGuardrailConfig(),
        }
        args += ["--connector", connector]
    result = CliRunner().invoke(cmd_guardrail.hilt_cmd, args, obj=app)
    assert result.exit_code == 0, result.output
    app.cfg.save.assert_called_once()
    assert "the audit event was not recorded" in result.output
    hilt = app.cfg.guardrail.effective_hilt(connector or "")
    assert (hilt.enabled, hilt.min_severity) == (True, "HIGH")
