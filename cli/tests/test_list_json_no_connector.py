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
from defenseclaw.tui.app import _no_connector_hint
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
