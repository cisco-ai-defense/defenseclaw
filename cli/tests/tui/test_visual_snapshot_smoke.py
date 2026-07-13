# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Native Textual SVG snapshot smoke tests for the shell."""

from __future__ import annotations

import html
from types import SimpleNamespace

import pytest
from defenseclaw.config import RegistrySource
from defenseclaw.models import Event
from defenseclaw.tui.app import DefenseClawTUI
from defenseclaw.tui.panels.ai_discovery import AIDiscoveryPanelModel, AIUsageSignal, AIUsageSnapshot
from defenseclaw.tui.panels.alerts import AlertEvent, AlertsPanelModel
from defenseclaw.tui.panels.audit import AuditPanelModel
from defenseclaw.tui.panels.inventory import InventoryPanelModel, InventorySnapshot
from defenseclaw.tui.panels.logs import LogsPanelModel
from defenseclaw.tui.panels.mcps import MCPRow, MCPsPanelModel
from defenseclaw.tui.panels.overview import HealthSnapshot, OverviewPanelModel, SubsystemHealth
from defenseclaw.tui.panels.plugins import PluginRow, PluginScanSummary, PluginsPanelModel
from defenseclaw.tui.panels.registries import RegistriesPanelModel
from defenseclaw.tui.panels.setup import SetupPanelModel
from defenseclaw.tui.panels.skills import SkillRow, SkillsPanelModel
from defenseclaw.tui.panels.tools import ToolRow, ToolsPanelModel
from defenseclaw.tui.screens.command_preview import CommandPreviewScreen
from defenseclaw.tui.widgets.action_menu import ActionMenuScreen

QA_SIZES = ((80, 24), (120, 40), (180, 50))

TOP_LEVEL_PANELS = (
    ("overview", None, "Overview"),
    ("alerts", "2", "Alerts"),
    ("skills", "3", "Skills"),
    ("mcps", "4", "MCPs"),
    ("plugins", "5", "Plugins"),
    ("inventory", "6", "Inventory"),
    ("logs", "8", "Logs"),
    ("audit", "9", "Audit"),
    ("activity", "a", "Activity"),
    ("ai", "V", "AI Discovery"),
    ("registries", None, "Registries"),
    ("setup", "0", "Setup Wizards"),
)


def _snapshot_config(tmp_path) -> SimpleNamespace:
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    (policy_dir / "alpha.yaml").write_text("description: alpha policy\n", encoding="utf-8")
    return SimpleNamespace(
        data_dir=str(tmp_path),
        policy_dir=str(policy_dir),
        audit_db="",
        environment="test",
        claw=SimpleNamespace(mode="openclaw"),
        guardrail=SimpleNamespace(
            enabled=True,
            mode="observe",
            connector="openclaw",
            scanner_mode="local",
            rule_pack_dir="",
            port=4141,
            model="gpt-5-mini",
            strategy="default",
            judge_enabled=False,
            judge_model="",
            hilt=SimpleNamespace(enabled=False, min_severity="HIGH"),
        ),
        llm=SimpleNamespace(provider="openai", model="gpt-5-mini"),
        inspect_llm=SimpleNamespace(provider="", model=""),
        cisco_ai_defense=SimpleNamespace(endpoint=""),
        privacy=SimpleNamespace(disable_redaction=False),
        active_connector=lambda: "openclaw",
    )


def _snapshot_app(tmp_path) -> DefenseClawTUI:
    config = _snapshot_config(tmp_path)

    overview = OverviewPanelModel()
    overview.set_health(
        HealthSnapshot(
            gateway=SubsystemHealth(state="running", details={"port": 4141}),
            guardrail=SubsystemHealth(state="running"),
            watcher=SubsystemHealth(state="running"),
        )
    )

    alerts = AlertsPanelModel()
    alerts.set_events(
        [
            AlertEvent(id="a1", severity="HIGH", action="scan", target="skill://alpha", details="token found"),
            AlertEvent(id="a2", severity="LOW", action="proxy", target="gateway", details="normal traffic"),
        ]
    )

    skills = SkillsPanelModel(connector="openclaw")
    skills.apply_loaded(
        [
            SkillRow(name="alpha", status="active", description="math helper", source="local"),
            SkillRow(name="beta", status="blocked", description="database helper", source="registry"),
        ]
    )

    mcps = MCPsPanelModel(connector="openclaw")
    mcps.apply_loaded(
        [
            MCPRow(name="context7", status="active", transport="stdio", command="uvx context7"),
            MCPRow(name="filesystem", status="blocked", transport="stdio", command="node server.js"),
        ]
    )

    plugins = PluginsPanelModel(connector="openclaw")
    plugins.apply_loaded(
        [
            PluginRow(
                id="plug_tutor",
                name="Tutor",
                description="teaches operators",
                version="1.2.3",
                origin="local",
                status="installed",
                enabled=True,
                verdict="clean",
                scan=PluginScanSummary(clean=True),
            )
        ]
    )

    inventory = InventoryPanelModel(connector="openclaw")
    inventory.apply_loaded(
        InventorySnapshot.from_mapping(
            {
                "connector": "openclaw",
                "skills": [{"id": "alpha", "enabled": True, "eligible": True, "policy_verdict": "allowed"}],
                "plugins": [{"id": "plug_tutor", "name": "Tutor", "enabled": True, "status": "loaded"}],
                "mcp": [{"id": "context7", "transport": "stdio", "command": "uvx context7"}],
                "agents": [{"id": "default", "model": "gpt-5", "source": "openclaw", "is_default": True}],
                "model_providers": [{"id": "openai", "default_model": "gpt-5", "status": "ready"}],
                "memory": [{"id": "mem", "backend": "sqlite", "files": 1, "chunks": 3}],
                "summary": {"total_items": 6, "skills": {"count": 1}, "plugins": {"count": 1}, "mcp": {"count": 1}},
            }
        )
    )

    logs = LogsPanelModel()
    logs.lines["gateway"] = ["event tick seq=1", "error failed"]

    audit = AuditPanelModel()
    audit.set_events([Event(action="scan", target="skill://alpha", severity="HIGH", details="token found")])

    ai_discovery = AIDiscoveryPanelModel()
    ai_discovery.set_snapshot(
        AIUsageSnapshot(
            enabled=True,
            signals=(AIUsageSignal(signal_id="sig1", state="new", product="Codex", vendor="OpenAI"),),
        )
    )

    registries = RegistriesPanelModel(
        data_dir=tmp_path,
        sources=[RegistrySource(id="corp-skills", kind="http_yaml", content="skill", enabled=True)],
    )

    tools = ToolsPanelModel()
    tools.apply_loaded([ToolRow(name="write_file", scope="skill", status="blocked", reason="PII leak risk")])

    app = DefenseClawTUI(
        config=config,
        overview_model=overview,
        alerts_model=alerts,
        skills_model=skills,
        mcps_model=mcps,
        plugins_model=plugins,
        inventory_model=inventory,
        logs_model=logs,
        audit_model=audit,
        ai_discovery_model=ai_discovery,
        registries_model=registries,
        tools_model=tools,
        setup_model=SetupPanelModel({}),
    )
    app.activity_model.add_entry("doctor")
    app.activity_model.append_output("Checking gateway...")
    app.activity_model.finish_entry(0)
    return app


def _assert_svg_snapshot(svg: str, *needles: str) -> None:
    assert svg.startswith("<svg")
    assert len(svg) > 1_000
    normalized = html.unescape(svg).replace("\xa0", " ")
    for needle in needles:
        assert needle in normalized


@pytest.mark.asyncio
@pytest.mark.tui_snapshot
@pytest.mark.parametrize("size", QA_SIZES)
@pytest.mark.parametrize(("panel", "shortcut", "expected"), TOP_LEVEL_PANELS)
async def test_textual_top_level_panel_exports_svg_snapshot(
    tmp_path,
    panel: str,
    shortcut: str | None,
    expected: str,
    size: tuple[int, int],
) -> None:
    app = _snapshot_app(tmp_path)

    async with app.run_test(size=size) as pilot:
        if panel == "registries":
            app.action_switch_panel("registries")
        elif shortcut is not None:
            await pilot.press(shortcut)
        await pilot.pause()
        svg = app.export_screenshot()

    assert app.active_panel == panel
    _assert_svg_snapshot(svg, "DefenseClaw", expected)


@pytest.mark.asyncio
@pytest.mark.tui_snapshot
async def test_textual_command_preview_modal_exports_svg_snapshot(tmp_path) -> None:
    app = _snapshot_app(tmp_path)

    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press(":")
        await pilot.press(*"block skill alpha")
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen_stack[-1], CommandPreviewScreen)
        svg = app.export_screenshot()

    _assert_svg_snapshot(svg, "Confirm Command", "defenseclaw skill block alpha")


@pytest.mark.asyncio
@pytest.mark.tui_snapshot
async def test_textual_action_menu_exports_svg_snapshot(tmp_path) -> None:
    app = _snapshot_app(tmp_path)

    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("3")
        await pilot.press("o")
        await pilot.pause()
        assert isinstance(app.screen_stack[-1], ActionMenuScreen)
        svg = app.export_screenshot()

    _assert_svg_snapshot(svg, "Skills Actions", "Scan")


@pytest.mark.asyncio
@pytest.mark.tui_snapshot
async def test_textual_detail_state_exports_svg_snapshot(tmp_path) -> None:
    app = _snapshot_app(tmp_path)

    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("3")
        await pilot.press("enter")
        await pilot.pause()
        svg = app.export_screenshot()

    assert app.skills_model.detail_open is True
    # ``_format_skill_detail`` builds the header as
    # ``[bold #22D3EE]Skill[/] alpha`` and the SVG export captures the
    # raw markup payload as literal text — checking for ``Skill[/]
    # alpha`` keeps the assertion exactly aligned with the rendered
    # detail pane (no colon between "Skill" and the row name).
    _assert_svg_snapshot(svg, "Skill[/] alpha", "math helper")


@pytest.mark.asyncio
@pytest.mark.tui_snapshot
async def test_textual_setup_form_exports_svg_snapshot(tmp_path) -> None:
    app = _snapshot_app(tmp_path)

    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("0")
        await pilot.press("enter")  # wizard list -> goal menu.
        await pilot.pause()
        await pilot.press("enter")  # goal menu -> filtered form.
        await pilot.pause()
        svg = app.export_screenshot()

    assert app.setup_model.form_active is True
    _assert_svg_snapshot(svg, "Setup Wizard", "Connector Setup")


@pytest.mark.asyncio
@pytest.mark.tui_snapshot
async def test_textual_first_run_setup_exports_svg_snapshot() -> None:
    app = DefenseClawTUI(first_run=True)

    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        svg = app.export_screenshot()

    assert app.active_panel == "setup"
    _assert_svg_snapshot(svg, "DefenseClaw first-run setup", "Connector")
