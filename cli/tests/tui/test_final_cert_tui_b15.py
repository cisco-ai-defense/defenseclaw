# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI UX batch 15 (GAP-2221, GAP-2222, GAP-2228, GAP-2229, GAP-2230)."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parent))

from defenseclaw.tui.command_line import command_result_summary  # noqa: E402
from defenseclaw.tui.models import HintState  # noqa: E402
from defenseclaw.tui.panels.registries import entry_detail_info, remove_source_intent  # noqa: E402
from defenseclaw.tui.services.ai_discovery_state import AIDiscoveryPanelModel  # noqa: E402
from defenseclaw.tui.services.catalog_state import PluginRow, catalog_row_cells, plugin_action_intent  # noqa: E402
from defenseclaw.tui.services.overview_state import OverviewPanelModel  # noqa: E402
from defenseclaw.tui.widgets.hint_bar import HintEngine  # noqa: E402
from fixtures import snapshot_app  # noqa: E402


def test_telemetry_wording_has_no_internal_terms() -> None:
    # GAP-2221: "canonical destination plan loading".
    detail = OverviewPanelModel().telemetry_detail()
    assert detail.startswith("loading telemetry destinations")
    assert "canonical" not in detail


def test_config_editor_esc_goes_back_to_the_tasks(tmp_path, monkeypatch) -> None:
    # GAP-2222: Esc did nothing in the config editor.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / ".defenseclaw"))
    from defenseclaw.config import default_config

    app = snapshot_app(tmp_path, setup_config=default_config())
    app.setup_model.mode = "config"
    action = app._handle_setup_key("esc")  # noqa: SLF001
    assert action.handled
    assert app.setup_model.mode == "wizards"
    assert action.hint == "Back to the Setup tasks."


def test_plugin_block_confirm_and_card_say_the_copy_still_loads() -> None:
    # GAP-2228: generic confirm, card dropped "still loads", Status "blocked".
    row = PluginRow(id="cron_providers/chronos", name="chronos", status="blocked", enabled=True, verdict="blocked")
    block = plugin_action_intent("b", row, origin="plugins", connector="hermes")
    assert block is not None and "installed copy keeps loading" in block.consequence
    unblock = plugin_action_intent("u", row, origin="plugins", connector="hermes")
    assert unblock is not None and "agent's own config" in unblock.consequence
    assert catalog_row_cells(row)[1:4:2] == ("enabled", "blocked")

    lines = [
        "[plugin] Blocked 'cron_providers/chronos' (hermes).",
        "  The installed copy still loads: block only refuses new installs.",
        "  To stop it: defenseclaw plugin quarantine cron_providers/chronos --connector hermes",
    ]
    summary = command_result_summary("plugin block cron_providers/chronos --connector hermes", lines)
    assert summary.startswith("New installs blocked; the installed copy still loads.")
    assert summary.endswith("--connector hermes")


def test_registry_remove_confirm_and_entry_detail() -> None:
    # GAP-2229: remove confirm explained nothing; detail repeated Name and URL.
    assert "policy rules it promoted" in remove_source_intent("sf1-local").consequence
    url = "https://mcp.deepwiki.com/mcp"
    entry = SimpleNamespace(
        source_id="sf1-local", name="deepwiki", type="mcp", status="clean", severity="", findings=0,
        approved=False, rejected=False, transport="streamable-http", command="", args=(),
        url=url, source_url="", location=url,
    )
    labels = [label for label, _value in entry_detail_info(entry).fields]
    assert "Name" not in labels and "Location" not in labels
    assert labels[-1] == "Keys"


def test_ai_discovery_hint_follows_panel_state() -> None:
    # GAP-2230: "s scan" offered while off; "a all models" after a.
    model = AIDiscoveryPanelModel()
    model.snapshot = SimpleNamespace(enabled=False)
    action = model.handle_key("s")
    assert action.intent is None and "Press d to turn it on" in action.hint

    engine = HintEngine()
    off = engine.hint_for(HintState(active_panel="ai", panel_conditions=("disabled",)))
    assert "s scan" not in off and "d turn on" in off
    all_models = engine.hint_for(HintState(active_panel="ai", panel_conditions=("all_models",)))
    assert "a recommended" in all_models and "s scan" in all_models
