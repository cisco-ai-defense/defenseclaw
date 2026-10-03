# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI fix batch fcz-b40: the Alerts detail box closes at 80x24."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from defenseclaw.tui.panels.alerts import AlertEvent
from fixtures import settle_panel, snapshot_app  # noqa: E402


async def test_alerts_detail_box_fits_above_hint_at_80x24(tmp_path) -> None:
    # GAP-2606: with the connector strip and a wrapped heading, #panel-main
    # kept 10 rows; the table's 4-row minimum plus the 7-row compact detail
    # pushed the box's bottom border off the panel.
    from textual.containers import VerticalScroll

    connectors = ["claudecode", "codex", "hermes", "opencode", "openhands"]
    app = snapshot_app(tmp_path)
    app.alerts_model.set_events(
        [
            AlertEvent(
                id=f"a{i}",
                severity="HIGH",
                action="circuit_breaker_open",
                target="",
                details="exporter paused after 3 failures; it retries in the background and resumes",
                connector=connectors[i % len(connectors)],
            )
            for i in range(20)
        ]
    )
    app._active_connector_names = lambda: list(connectors)  # noqa: SLF001
    async with app.run_test(size=(80, 24)) as pilot:
        app.action_switch_panel("alerts")
        await settle_panel(app, pilot)
        await pilot.press("enter")
        await pilot.pause()
        await pilot.pause()
        detail = app.query_one("#detail-panel", VerticalScroll)
        main = app.query_one("#panel-main")
        assert detail.has_class("compact") and app.detail_text
        assert detail.region.bottom <= main.region.bottom
        assert detail.max_scroll_y > 0
