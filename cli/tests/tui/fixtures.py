# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Fake-data DefenseClaw TUI for smoke tests and the defenseclaw-tui render script.

``snapshot_app`` builds the full app with every panel model pre-loaded, so
nothing reads the real home, gateway or SQLite. ``screen_text`` dumps the
current screen as plain text, which is what a person sees in the terminal.
"""

from __future__ import annotations

import io
from types import SimpleNamespace

from defenseclaw.config import RegistrySource
from defenseclaw.models import Event
from defenseclaw.tui.app import DefenseClawTUI
from defenseclaw.tui.panels.ai_discovery import (
    AIDiscoveryPanelModel,
    AIUsageModel,
    AIUsageSignal,
    AIUsageSnapshot,
)
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
from defenseclaw.tui.services.ai_discovery_state import AIUsageModelProvenance
from rich.console import Console


def snapshot_config(tmp_path) -> SimpleNamespace:
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


def snapshot_app(tmp_path, *, setup_config: object | None = None) -> DefenseClawTUI:
    config = snapshot_config(tmp_path)

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
            signals=(
                AIUsageSignal(signal_id="sig1", state="new", product="Codex", vendor="OpenAI"),
                AIUsageSignal(
                    signal_id="model1",
                    state="seen",
                    category="local_model",
                    product="Local Model Artifact",
                    vendor="Local",
                    model=AIUsageModel(
                        id="Qwen3-Q4_K_M",
                        status="installed",
                        format="gguf",
                        provenance=AIUsageModelProvenance(
                            publisher="Alibaba Cloud",
                            country_code="CN",
                            root_model="Qwen/Qwen3",
                            quantized=True,
                            quantization="Q4_K_M",
                            derivation="quantized",
                            source="catalog_exact",
                            confidence="high",
                        ),
                    ),
                ),
            ),
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
        setup_model=SetupPanelModel(setup_config if setup_config is not None else {}),
    )
    app.activity_model.add_entry("doctor")
    app.activity_model.append_output("Checking gateway...")
    app.activity_model.finish_entry(0)
    return app


def screen_text(app: DefenseClawTUI) -> str:
    """Return the current screen, including modals over it, as plain text."""

    width, height = app.size
    console = Console(
        width=width,
        height=height,
        file=io.StringIO(),
        force_terminal=True,
        color_system=None,
        record=True,
        legacy_windows=False,
        safe_box=False,
    )
    console.print(app.screen._compositor.render_update(full=True, screen_stack=app._background_screens))
    return console.export_text(styles=False)
