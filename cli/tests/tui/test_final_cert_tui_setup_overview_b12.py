# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI batch 12: Setup strategy, Overview keys, telemetry pointers, form hints."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from defenseclaw.observability.v8_status import V8DestinationStatus, V8OperatorStatus
from defenseclaw.tui.panels.setup import (
    SetupPanelModel,
    SetupWizard,
    _guardrail_wizard_fields_for,
    build_wizard_args,
    wizard_field_value,
    wizard_form_defs,
    wizard_goals,
)
from defenseclaw.tui.services.setup_state import telemetry_readiness_detail

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixtures import snapshot_app  # noqa: E402


def _strategy_argv(cfg: dict[str, Any], choice: str) -> tuple[str, ...]:
    fields = _guardrail_wizard_fields_for({}, cfg)
    fields = tuple(f.with_value(choice) if f.label == "Strategy" else f for f in fields)
    return build_wizard_args(SetupWizard.GUARDRAIL, fields)


def test_regex_only_is_emitted_over_a_judge_strategy() -> None:
    # GAP-2349: regex_only equalled the field default, so the flag was dropped
    # and judge_first (with the judge) stayed on.
    cfg = {"guardrail": {"detection_strategy": "judge_first", "judge": {"enabled": True}}}
    assert wizard_field_value(_guardrail_wizard_fields_for({}, cfg), "Strategy") == "judge_first"
    argv = _strategy_argv(cfg, "regex_only")
    assert argv[argv.index("--detection-strategy") + 1] == "regex_only"
    assert "--detection-strategy" not in _strategy_argv(cfg, "judge_first")


def test_strategy_opens_on_regex_only_while_the_judge_is_off() -> None:
    # GAP-2349: "Now: regex_only (judge off)" but the form opened on regex_judge.
    cfg = {"guardrail": {"detection_strategy": "regex_judge", "judge": {"enabled": False}}}
    assert wizard_field_value(_guardrail_wizard_fields_for({}, cfg), "Strategy") == "regex_only"
    argv = _strategy_argv(cfg, "regex_judge")
    assert argv[argv.index("--detection-strategy") + 1] == "regex_judge"


async def test_overview_read_only_keys_run_like_the_buttons(tmp_path) -> None:
    # GAP-2350: d asked to confirm doctor; the Run Doctor button did not.
    app = snapshot_app(tmp_path)
    ran: list[tuple[str, ...]] = []
    confirmed: list[tuple[str, ...]] = []

    async def run(parsed: Any, **_kw: Any) -> None:
        ran.append(tuple(parsed.args))

    async def confirm(intent: Any) -> None:
        confirmed.append(tuple(intent.args))

    async with app.run_test(size=(80, 24)) as pilot:
        app._run_and_report = run  # type: ignore[method-assign]  # noqa: SLF001
        app._confirm_and_run_intent = confirm  # type: ignore[method-assign]  # noqa: SLF001
        app.action_switch_panel("overview")
        await pilot.pause()
        await pilot.press("d")
        await pilot.pause()
        app._handle_overview_control("overview-run-doctor")  # noqa: SLF001
        await pilot.pause()
        await pilot.press("u")
        await pilot.pause()
    assert ran == [("doctor",), ("doctor",)]
    assert confirmed == [("upgrade",)]


def test_telemetry_pointers_name_the_export_telemetry_task() -> None:
    # GAP-2351: "the Observability task" / "setup Observability / destination".
    def dest(name: str, *, generated: bool = False) -> V8DestinationStatus:
        return V8DestinationStatus(
            name=name,
            kind="otlp",
            enabled=True,
            generated=generated,
            capabilities=("logs",),
            selected_signals=("logs",),
            policy_form="capability_default",
            endpoint="https://collector.example/v1/logs",
            route_count=1,
            buckets=(),
            redaction_profiles=("none",),
        )

    exports = V8OperatorStatus(
        source="config.yaml",
        data_dir="/tmp/dc",
        plan_digest="a" * 64,
        bucket_catalog_version=1,
        retention_days=30,
        local_path="/tmp/dc/audit.db",
        judge_bodies_path="/tmp/dc/judge.db",
        destinations=(dest("grafana"), dest("galileo"), dest("local-sqlite", generated=True)),
        buckets=(),
        warnings=(),
    )
    assert telemetry_readiness_detail(exports) == (
        "Local audit log is always on; 2 exports set in 0 Setup → Alerts & telemetry → Export telemetry."
    )
    model = SetupPanelModel({})
    model.set_observability_status(exports)
    telemetry = next(check for check in model.readiness_checks if check.title == "Telemetry")
    assert "2 exports" in telemetry.detail
    goal = next(goal for goal in wizard_goals(SetupWizard.OBSERVABILITY, {}) if goal.id == "list")
    model.open_wizard_form(SetupWizard.OBSERVABILITY, goal=goal)
    action = model.submit_wizard_form()
    assert action.intent is not None and action.intent.label == "setup Export telemetry"


def test_setup_form_hints_are_plain_words() -> None:
    # GAP-2352: "Select mode.", "Sets --port." and "(selected active member)".
    guardrail = {f.label: f for f in _guardrail_wizard_fields_for({}, {"claw": {"mode": "codex"}})}
    assert guardrail["Mode"].hint.startswith("observe only logs")
    assert not any("selected active member" in label for label in guardrail)
    gateway = {f.label: f.hint for f in wizard_form_defs(SetupWizard.GATEWAY, {})}
    assert not any(gateway[name].startswith("Sets --") for name in ("Host", "Port", "API Port"))
    assert "REST API port" in gateway["API Port"]


async def test_focused_hint_wraps_instead_of_being_cut_at_80x24(tmp_path) -> None:
    # GAP-2352: "Connector: Choose an active connector policy targe…".
    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        text = app._setup_wrapped_line("Connector: " + "word " * 20)  # noqa: SLF001
    assert text.count("\n") == 1
    assert "…" not in text
