# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""With no connector configured, list --json still prints JSON (GAP-2073)."""

from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands.cmd_aibom import aibom
from defenseclaw.commands.cmd_mcp import mcp
from defenseclaw.commands.cmd_plugin import plugin
from defenseclaw.commands.cmd_skill import skill
from defenseclaw.tui.app import _inventory_scan_args, _no_connector_hint
from defenseclaw.tui.services.inventory_state import InventorySnapshot

from tests.helpers import cleanup_app, make_app_context, make_separate_stderr_runner


@pytest.mark.parametrize(
    ("group", "args"),
    [(skill, ["list"]), (mcp, ["list"]), (plugin, ["list"]), (aibom, ["scan"])],
)
def test_list_json_with_no_connector_prints_empty_json(group, args) -> None:
    app, tmp_dir, db_path = make_app_context()
    try:
        app.cfg.has_connector_configured = lambda: False  # type: ignore[method-assign]
        app.cfg.active_connectors = lambda: []  # type: ignore[method-assign]
        result = make_separate_stderr_runner().invoke(group, [*args, "--json"], obj=app)
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout) == []
        assert "no connector configured" in result.stderr
        text = make_separate_stderr_runner().invoke(group, args, obj=app)
        assert "no connector configured" in text.stdout
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_tui_reads_empty_inventory_and_the_no_connector_hint() -> None:
    assert InventorySnapshot.from_json("[]").skills == ()
    hint = _no_connector_hint("no connector configured — run 'defenseclaw setup <connector>'\n".encode())
    assert hint.startswith("No connector configured")
    assert _no_connector_hint(b"") == ""


def test_ide_only_scan_without_connector_returns_rows_or_error(monkeypatch: pytest.MonkeyPatch) -> None:
    from defenseclaw.commands import cmd_aibom

    app, tmp_dir, db_path = make_app_context()
    try:
        app.cfg.active_connectors = lambda: []  # type: ignore[method-assign]
        monkeypatch.setattr(cmd_aibom, "_fetch_ide_plugins", lambda _app: (
            {"enabled": True, "scope": "all", "plugins": [
                {"plugin_id": "github.copilot", "ide_product": "vscode", "is_ai": True},
            ]}, "",
        ))
        result = make_separate_stderr_runner().invoke(aibom, ["scan", "--only", "ide_plugins", "--json"], obj=app)
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["ide_plugins"][0]["plugin_id"] == "github.copilot"
        monkeypatch.setattr(cmd_aibom, "_fetch_ide_plugins", lambda _app: (None, "gateway unavailable"))
        error = make_separate_stderr_runner().invoke(aibom, ["scan", "--only", "ide_plugins"], obj=app)
        assert error.exit_code != 0 and "gateway unavailable" in error.output
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_tui_uses_full_scan_for_one_connector() -> None:
    full = ("aibom", "scan", "--json")
    class Config:
        def active_connectors(self) -> list[str]:
            return ["codex"]
    assert _inventory_scan_args(full, Config()) == full
    assert _inventory_scan_args(full, None) == (*full, "--only", "ide_plugins")
