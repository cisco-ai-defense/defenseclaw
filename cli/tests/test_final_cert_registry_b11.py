# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Lean regressions for the registry CLI fix-only batch 11 (GAP-2266, GAP-2267)."""

from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner
from defenseclaw.commands import _scan_ui, cmd_registry
from defenseclaw.commands._audit_notice import NOT_RECORDED_WARNING
from defenseclaw.logger import CanonicalObservabilityUnavailableError

from tests.helpers import cleanup_app, make_app_context

HINT = "(start it with: defenseclaw-gateway start)."


@pytest.fixture
def registry_app(monkeypatch):
    app, tmp_dir, db_path = make_app_context()
    app.cfg.config_path = os.path.join(tmp_dir, "config.yaml")
    app.cfg.save()
    monkeypatch.setattr(cmd_registry, "sys", SimpleNamespace(stdin=SimpleNamespace(isatty=lambda: True)))
    yield app
    cleanup_app(app, db_path, tmp_dir)


def _run(app, *args: str):
    return CliRunner().invoke(cmd_registry.registry, list(args), obj=app)


def test_require_connector_enforce_undo_hint_keeps_the_connector(registry_app) -> None:
    # GAP-2266
    result = _run(registry_app, "require", "--type", "mcp", "--enabled", "--connector", "hermes", "--enforce")
    assert result.exit_code == 0, result.output
    undo = "defenseclaw registry require --type mcp --disabled --connector hermes --no-enforce"
    assert f"Turn it off with: {undo}" in result.output

    result = _run(registry_app, *undo.split()[2:])
    assert result.exit_code == 0, result.output
    policy = registry_app.cfg.asset_policy
    assert policy.effective_asset_type_policy("hermes", "mcp").registry_required is False
    assert policy.effective_mode("hermes") == "observe"


def test_gateway_not_running_warning_has_one_wording(registry_app) -> None:
    # GAP-2267: registry add/sync printed "start it with: X", "start it: X" and "start it with 'X'".
    assert NOT_RECORDED_WARNING.endswith(HINT)
    registry_app.logger.log_action = MagicMock(side_effect=CanonicalObservabilityUnavailableError("down"))
    result = _run(registry_app, "add", "s1", "--kind", "clawhub", "--content", "skill", "--non-interactive")
    assert result.exit_code == 0, result.output
    assert NOT_RECORDED_WARNING in result.output

    logger = MagicMock()
    logger.log_scan.side_effect = CanonicalObservabilityUnavailableError("down")
    with patch.object(_scan_ui, "_SCAN_NOT_RECORDED_NOTED", False), patch.object(_scan_ui.click, "echo") as echo:
        _scan_ui.record_scan(logger, object())
    assert echo.call_args.args[0] == (
        "  ⚠ The gateway isn't running, so this scan result was not recorded " + HINT
    )


@pytest.mark.parametrize(
    ("asset", "phrase"),
    [("mcp", "an MCP server that is not in the registry"), ("skill", "a skill that is not in the registry")],
)
@pytest.mark.parametrize("enabled", [False, True])
def test_require_warning_names_the_asset_in_product_wording(registry_app, asset, phrase, enabled) -> None:
    # GAP-2377: the observe/off warning said "a mcp that is not in the registry".
    registry_app.cfg.asset_policy.enabled = enabled
    registry_app.cfg.asset_policy.mode = "observe"
    result = _run(registry_app, "require", "--type", asset, "--enabled")
    assert result.exit_code == 0, result.output
    assert phrase in " ".join(result.output.split())
    assert "a mcp" not in result.output and "every mcp" not in result.output
