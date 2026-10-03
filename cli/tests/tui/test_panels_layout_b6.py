# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""TUI panels layout batch 6: tab ellipsis, panel keys, idle agents, search."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from defenseclaw.models import Event
from defenseclaw.tui.app import PANELS
from defenseclaw.tui.panels.activity import ActivityPanelModel
from defenseclaw.tui.panels.alerts import AlertsPanelModel
from defenseclaw.tui.panels.audit import _matches_search_query
from defenseclaw.tui.screens.uninstall import UninstallScreen
from defenseclaw.tui.services.catalog_state import skill_list_to_row
from defenseclaw.tui.services.inventory_state import InventoryPanelModel
from defenseclaw.tui.services.overview_state import (
    ConnectorHealth,
    HealthSnapshot,
    OverviewConfig,
    OverviewPanelModel,
    SubsystemHealth,
)
from defenseclaw.tui.services.runtime_state import RuntimePanelModel
from defenseclaw.tui.widgets import tab_fit
from textual.app import App


def test_shortened_active_tab_always_ends_with_an_ellipsis(monkeypatch) -> None:
    # GAP-1541: with the Logs/Audit/AI badges up, the active tab read
    # "7 Sandbox" as if it were the full name.
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", False)
    busy = {"alerts": 5, "logs": 340, "audit": 109, "activity": 1, "ai": 34}
    for unread in (busy, {}):
        for active in ("sandboxes", "registries", "ai"):
            labels = tab_fit.fit_tab_labels(PANELS, active, unread, 66)
            assert tab_fit.strip_width(tuple(labels.values())) <= 66
            name = dict((panel, label) for panel, _key, label in PANELS)[active]
            shown = labels[active].split(" ", 1)[1]
            assert shown.startswith(name) or "…" in shown, (active, labels[active])
    # The Alerts count is never dropped for an ellipsis.
    assert tab_fit.fit_tab_labels(PANELS, "sandboxes", busy, 66)["alerts"] in {"2⁵", "2(5)"}


def test_runtime_starts_compact_on_short_screens_and_keeps_its_own_toggle() -> None:
    # GAP-1596: "p" on a tall screen expanded the planes over the table at 80x24.
    model = RuntimePanelModel()
    model.handle_key("p")
    model.short_screen = True
    assert model.planes_shown_expanded() is False
    model.handle_key("p")
    assert model.planes_shown_expanded() is True
    model.short_screen = False
    assert model.planes_shown_expanded() is False


def test_skill_gone_from_disk_reads_removed_like_the_cli() -> None:
    # GAP-1598: the TUI said "rejected"/"warning" where the CLI says removed.
    row = skill_list_to_row({"name": "ws1-review", "source": "scan-history", "verdict": "rejected"})
    assert row.status == "removed"
    assert row.verdict == "rejected"


def test_digit_and_activity_keys_stay_panel_keys() -> None:
    # GAP-1607: 1/2 on Activity switched its sub-tabs instead of the panel.
    activity = ActivityPanelModel()
    activity.handle_key("1")
    assert activity.tab == "commands"
    activity.handle_key("l")
    assert activity.tab == "mutations"
    assert "h/l switch" in activity.render_text()
    activity.handle_key("h")
    assert activity.tab == "commands"
    # GAP-1630: A opens Activity from Alerts too; X still deselects.
    alerts = AlertsPanelModel()
    assert alerts.handle_key("A").handled is False
    assert alerts.handle_key("X").hint == "Selection cleared."
    # GAP-1641: Tab moves to the next panel from Inventory.
    inventory = InventoryPanelModel()
    assert inventory.handle_key("tab").handled is False
    assert inventory.handle_key("shift+tab").handled is False


def test_audit_search_matches_the_columns() -> None:
    # GAP-1631: connector:/severity: read only the raw details and severity.
    verdict = Event(action="guardrail-verdict", connector="opencode", severity="CRITICAL", details="action=block")
    hook = Event(action="connector-hook", severity="INFO", details="connector=claudecode severity=CRITICAL decision=block")
    assert _matches_search_query(verdict, "connector:opencode severity:critical")
    assert _matches_search_query(verdict, "opencode CRITICAL")
    assert _matches_search_query(hook, "severity:critical")
    assert not _matches_search_query(hook, "connector:opencode")


def test_idle_opencode_is_not_degraded_and_inspections_count_as_traffic() -> None:
    now = datetime.now(timezone.utc)
    # GAP-1608: a closed OpenCode made the whole Agent row "degraded".
    model = OverviewPanelModel(
        OverviewConfig(
            claw_mode="claudecode",
            guardrail_connector="claudecode",
            connector_modes=(("claudecode", "action"), ("opencode", "action")),
        ),
        version="test",
    )
    model.set_health(
        HealthSnapshot(
            started_at=(now - timedelta(hours=1)).isoformat(),
            gateway=SubsystemHealth(state="running"),
            api=SubsystemHealth(state="running"),
            connectors=(
                ConnectorHealth(name="claudecode", state="running"),
                ConnectorHealth(name="opencode", state="running", source="manual"),
            ),
        )
    )
    assert model.subsystem_state("agent") == "running"
    assert model.agent_detail() == "2 connectors active · idle: OpenCode (not open)"
    # GAP-1617: OpenClaw's exec checks count, not only proxied requests.
    openclaw = OverviewPanelModel(OverviewConfig(claw_mode="openclaw", guardrail_connector="openclaw"), version="test")
    connector = ConnectorHealth(name="openclaw", state="running", tool_inspections=6, tool_blocks=4)
    openclaw.set_health(
        HealthSnapshot(
            uptime_ms=8 * 60 * 1000,
            gateway=SubsystemHealth(state="running"),
            connector=connector,
            connectors=(connector,),
        )
    )
    assert not any("seen 0 requests" in notice.message for notice in openclaw.build_notices())


async def test_uninstall_preview_key_runs_the_preview() -> None:
    # GAP-1606: "[p] Preview plan" did nothing; danger rows still need Enter.
    results: list[object] = []

    class Host(App[None]):
        def on_mount(self) -> None:
            self.push_screen(UninstallScreen(), results.append)

    app = Host()
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.press("u")
        await pilot.pause()
        assert results == []
        await pilot.press("p")
        await pilot.pause()
    assert [getattr(action, "action_id", None) for action in results] == ["dry-run"]
