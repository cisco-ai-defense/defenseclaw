# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI UX batch 19 (GAP-2441, GAP-2460)."""

from __future__ import annotations

import sys
from pathlib import Path

import defenseclaw.tui.app as app_module
from defenseclaw.tui.panels.alerts import AlertEvent
from defenseclaw.tui.widgets import tab_fit

sys.path.insert(0, str(Path(__file__).parent))
from fixtures import snapshot_app  # noqa: E402


async def test_alert_tab_badge_changes_with_the_overview_scope_at_80x24(tmp_path) -> None:
    # GAP-2441: after picking Claude Code the status bar read 15 alerts while
    # the tab kept "Alerts(24)" until the next refresh.
    app = snapshot_app(tmp_path)
    app._active_connector_names = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.alerts_model.set_events(
            [
                AlertEvent(id="a1", severity="HIGH", action="connector-hook", target="x", connector="claudecode"),
                AlertEvent(id="a2", severity="HIGH", action="connector-hook", target="y", connector="codex"),
                AlertEvent(id="a3", severity="CRITICAL", action="connector-hook", target="z", connector="codex"),
            ]
        )
        assert app.active_panel == "overview"
        app._set_connector_filter("claudecode")  # noqa: SLF001
        assert app._panel_unread_count("alerts") == 1  # noqa: SLF001
        assert "1" in app._tab_label_cache["alerts"] and "3" not in app._tab_label_cache["alerts"]  # noqa: SLF001
        app._set_connector_filter("")  # noqa: SLF001
        assert app._panel_unread_count("alerts") == 3  # noqa: SLF001
        assert "3" in app._tab_label_cache["alerts"]  # noqa: SLF001


def test_open_tab_reads_in_full_with_superscript_counts_at_160_columns(monkeypatch) -> None:
    # GAP-2460: "R Regist…", "V AI Di…", "6 Invent…" beside Alerts²⁹,
    # Log⁹⁹⁹⁺ and Audit⁵⁰⁶ on Linux, while Windows kept them whole.
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", False)
    tab_fit._NAMES_CACHE.clear()
    tab_fit._WIDE_CACHE.clear()
    unread = {"alerts": 29, "logs": 1200, "audit": 506}
    for width in range(140, 160):
        for name, key, title in app_module.PANELS:
            labels = tab_fit.fit_tab_labels(app_module.PANELS, name, unread, width)
            assert labels[name].startswith(f"{key} {title}"), (width, labels[name])
            assert tab_fit.strip_width(tuple(labels.values())) <= width
