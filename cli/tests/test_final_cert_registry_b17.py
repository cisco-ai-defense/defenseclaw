# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Lean regressions for registry CLI batch 17 (GAP-2422, GAP-2424, GAP-2425)."""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_policy, cmd_registry, cmd_setup
from defenseclaw.registries.sync import SyncReport

from tests.helpers import cleanup_app, make_app_context


@pytest.fixture
def registry_app():
    app, tmp_dir, db_path = make_app_context()
    app.cfg.config_path = os.path.join(tmp_dir, "config.yaml")
    app.cfg.save()
    yield app
    cleanup_app(app, db_path, tmp_dir)


@pytest.fixture
def gateway(monkeypatch):
    restart = MagicMock(return_value=True)
    monkeypatch.setattr(cmd_policy, "_gateway_pid_alive", lambda app: True)
    monkeypatch.setattr(cmd_setup, "_restart_defense_gateway", restart)
    return restart


def _run(app, *args: str):
    return CliRunner().invoke(cmd_registry.registry, list(args), obj=app)


def test_require_enforce_restarts_a_running_gateway(registry_app, gateway) -> None:
    # GAP-2422: the gateway refuses an asset_policy reload, so the CLI restarts it.
    result = _run(registry_app, "require", "--type", "mcp", "--enabled", "--enforce")
    assert result.exit_code == 0, result.output
    gateway.assert_called_once_with(registry_app.cfg.data_dir, start_if_stopped=False)
    assert "Restarted the gateway; agent hooks use the new asset policy now." in result.output

    gateway.reset_mock()
    result = _run(registry_app, "require", "--type", "mcp", "--disabled", "--no-enforce", "--json")
    assert result.exit_code == 0, result.output
    gateway.assert_called_once()
    assert json.loads(result.stdout)["status"] == "ok"


def test_unchanged_asset_policy_does_not_restart(registry_app, gateway) -> None:
    assert _run(registry_app, "list").exit_code == 0
    gateway.assert_not_called()


def test_failed_restart_says_how_to_apply(registry_app, gateway) -> None:
    gateway.return_value = False
    result = _run(registry_app, "require", "--type", "skill", "--enabled", "--enforce")
    assert "the gateway restart failed" in result.stderr
    assert "defenseclaw-gateway restart" in result.stderr


def test_sync_table_sizes_source_column_to_longest_id(capsys) -> None:
    # GAP-2424
    long_id = "b11v-much-longer-registry-id-for-cols"
    cmd_registry._print_sync_reports([SyncReport(source_id=long_id), SyncReport(source_id="short")])
    lines = [
        line
        for line in capsys.readouterr().out.splitlines()
        if "FETCHED" in line or line.strip().startswith(("b11v", "short"))
    ]
    header, *rows = lines
    col = header.index("FETCHED")
    assert all(row[col] == "0" for row in rows), lines


def test_sync_all_says_why_nothing_was_synced(registry_app) -> None:
    # GAP-2425 (a): no sources.
    result = _run(registry_app, "sync", "--all")
    assert result.exit_code == 0, result.output
    assert "no registry sources are configured" in result.output
    assert "defenseclaw registry add <id>" in result.output

    # (b): the only source is disabled.
    assert (
        _run(
            registry_app,
            "add",
            "v16rg-src",
            "--kind",
            "clawhub",
            "--content",
            "skill",
            "--disabled",
            "--non-interactive",
        ).exit_code
        == 0
    )
    result = _run(registry_app, "sync", "--all")
    assert result.exit_code == 0, result.output
    assert "1 source is disabled (v16rg-src)" in result.output
    assert "--include-disabled" in result.output
