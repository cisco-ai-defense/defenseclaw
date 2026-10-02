# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI fixes: help/hint wrapping, Setup wording, catalog refresh."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field

from defenseclaw.tui.app import DefenseClawTUI
from defenseclaw.tui.panels.setup import WIZARD_DESCRIPTIONS, SetupWizard, wizard_goals
from defenseclaw.tui.widgets.hint_bar import pack_hint_items
from rich.text import Text


@dataclass
class _Guardrail:
    connector: str = "claudecode"


@dataclass
class _Claw:
    mode: str = "claudecode"


@dataclass
class _Config:
    guardrail: _Guardrail = field(default_factory=_Guardrail)
    claw: _Claw = field(default_factory=_Claw)


def test_help_descriptions_wrap_under_their_column() -> None:
    # GAP-1912: "taken)" and "first)" wrapped back to column 3.
    plain = Text.from_markup(DefenseClawTUI(config=_Config())._render_help_body()).plain
    assert "\n" + " " * 25 + "taken)" in plain
    assert "\n" + " " * 25 + "first)" in plain
    assert max(len(line) for line in plain.splitlines()) <= 72


def test_hint_bar_breaks_between_items_only() -> None:
    # GAP-1912: word wrap left "keys" alone on the second hint row.
    items = ["↑/↓ choose", "←/→ group", "Enter open", "i details", "c config", "f fill missing keys", "r refresh keys"]
    packed = pack_hint_items(" · ".join(items), 78)
    lines = packed.split("\n")
    assert len(lines) == 2 and all(len(line) <= 78 for line in lines)
    assert [item for line in lines for item in line.split(" · ")] == items
    assert pack_hint_items("A plain sentence that is long.", 10) == "A plain sentence that is long."


def test_setup_wording_names_agents_and_action_mode() -> None:
    # GAP-1916: "Run bare setup to choose the active hook connector set".
    bulk = next(goal for goal in wizard_goals(SetupWizard.CONNECTOR_SETUP, {}) if goal.id == "bulk")
    assert bulk.label == "Choose which agents DefenseClaw protects"
    assert "bare setup" not in bulk.summary and "hook connector" not in bulk.summary
    assert "observe or action (block)" in WIZARD_DESCRIPTIONS[int(SetupWizard.GUARDRAIL)]


def _skills_json(connector: str, status: str) -> bytes:
    return json.dumps(
        {"connector": connector, "skills": [{"name": "notes", "status": status, "eligible": True, "enabled": True}]}
    ).encode()


async def test_skills_refresh_loads_connectors_at_once_and_keeps_the_newest(monkeypatch) -> None:
    # GAP-1921: four sequential CLI loads, and an older load finishing last,
    # showed the previous enforcement state after r.
    import defenseclaw.tui.app as app_module

    app = DefenseClawTUI(config=_Config())
    app._active_connector_names = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]
    gates: list[asyncio.Event] = []
    in_flight = 0
    peak = 0
    status = {"value": "blocked"}

    async def fake(binary, args, **_kwargs):
        nonlocal in_flight, peak
        snapshot = status["value"]
        connector = args[args.index("--connector") + 1]
        gate = asyncio.Event()
        gates.append(gate)
        in_flight += 1
        peak = max(peak, in_flight)
        await gate.wait()
        in_flight -= 1
        return 0, _skills_json(connector, snapshot), b""

    monkeypatch.setattr(app_module, "_communicate_captured", fake)
    older = asyncio.create_task(app._load_catalog_model("skills"))
    await asyncio.sleep(0.01)
    status["value"] = "active"
    newer = asyncio.create_task(app._load_catalog_model("skills"))
    await asyncio.sleep(0.01)
    assert peak == 4  # both connectors of both loads run at once
    for gate in gates[2:]:
        gate.set()
    await newer
    for gate in gates[:2]:
        gate.set()
    await older
    assert {row.status for row in app.catalog_models["skills"].items} == {"active"}
