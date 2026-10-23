# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""1.0.4 TUI fixes: 80x24 fit, honest status text, config save read-back."""

from __future__ import annotations

import asyncio
import io
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import PropertyMock, patch

import yaml
from defenseclaw import config as config_module
from defenseclaw.tui.app import DefenseClawTUI
from defenseclaw.tui.panels import setup_center
from defenseclaw.tui.panels.alerts import _target_without_connector
from defenseclaw.tui.panels.setup import SetupWizard
from defenseclaw.tui.panels.setup_catalog import PickerRow, TaskStatus
from defenseclaw.tui.policy_panel import hilt_change_modal
from defenseclaw.tui.screens.setup_picker import SetupPickerScreen
from defenseclaw.tui.services.config_watch import probe_config_generation
from defenseclaw.tui.services.overview_state import OverviewConfig, OverviewPanelModel
from defenseclaw.tui.services.policy_state import compact_matrix_lines
from defenseclaw.tui.services.sandbox_state import NO_ASKS_TEXT
from defenseclaw.tui.widgets.status_strip import StatusSegment, fit_status_segments
from rich.console import Console
from textual.app import App
from textual.geometry import Size
from textual.widgets import Input

sys.path.insert(0, str(Path(__file__).parent))

from fixtures import screen_text, settle_panel, snapshot_app  # noqa: E402
from test_protection_center import protection_model  # noqa: E402


async def test_palette_no_match_hint_is_whole_at_80_columns(tmp_path) -> None:
    # GAP-0151: the hint ended "Keep typing or use raw de" at the border.
    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press(":", *"zzqq")
        await pilot.pause()
        text = screen_text(app)
    assert "Keep typing, or type a full command" in text, text


def test_overview_key_row_lists_gateway_and_ai_discovery(tmp_path) -> None:
    # GAP-0153: G and z worked but the key row did not name them.
    app = snapshot_app(tmp_path)
    console = Console(width=71, record=True, color_system=None, file=io.StringIO())
    with patch.object(DefenseClawTUI, "size", new_callable=PropertyMock, return_value=Size(80, 24)):
        console.print(app._overview_renderable())  # noqa: SLF001
    text = " ".join(console.export_text().split())
    assert "[G] Gateway" in text and "[z] AI Discovery" in text, text


def test_failed_sandbox_doctor_shows_check_failed_not_the_setup_state() -> None:
    # GAP-0154: after a failed doctor the row still read "○ not set up".
    model = SimpleNamespace(wizard_status={SetupWizard.SANDBOX: "check failed"})
    assert setup_center.status_cell(model, SetupWizard.SANDBOX, TaskStatus("off")) == "! check failed"
    model.wizard_status[SetupWizard.SANDBOX] = "checked"
    assert setup_center.status_cell(model, SetupWizard.SANDBOX, TaskStatus("off")) == "○ not set up · check passed"


def test_empty_asks_text_says_a_host_port_asks_and_is_approved() -> None:
    # GAP-0155: same guidance as the sandbox guide (--host-port, then approve).
    assert "asks only if the run named it with --host-port PORT; approve that ask" in NO_ASKS_TEXT


async def test_picker_dismisses_once_on_a_double_enter() -> None:
    # GAP-0021: a second Enter that reached the picker before it was gone
    # dismissed it again and popped the screen under it (ScreenStackError).
    chosen: list[str | None] = []

    class Harness(App[None]):
        def on_mount(self) -> None:
            picker = SetupPickerScreen("Find a config field", (PickerRow("0:1", "Mode"),), filterable=True)
            self.push_screen(picker, chosen.append)

    app = Harness()
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        picker = app.screen
        box = picker.query_one(Input)
        picker.post_message(Input.Submitted(box, box.value))
        picker.post_message(Input.Submitted(box, box.value))
        await pilot.pause()
        await pilot.pause()
        assert len(app.screen_stack) == 1
    assert chosen == ["0:1"]


def test_compact_posture_detail_shows_every_severity_in_four_lines() -> None:
    # GAP-0022: at 80x24 the pane shows four lines and cut all four severities.
    pairs = compact_matrix_lines("observe", "CRITICAL", "MEDIUM", "off")
    assert len(pairs) == 2 and all(len(line) <= 66 for line in pairs), pairs
    joined = " ".join(pairs)
    assert all(severity in joined for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")), pairs
    model = protection_model()
    _title, lines = model.aside(compact=True)
    assert lines[0].startswith("Tool calls (")
    assert "CRITICAL" in lines[1] and "LOW" in lines[2], lines


def test_approval_preview_says_the_running_gateway_applies_it_now() -> None:
    # GAP-0030: the preview promised a restart; the gateway applies it live.
    model = protection_model()
    details = " ".join(hilt_change_modal(model, model.scope_row(""), "HIGH+").details)
    assert "applies it now" in details and "restarts" not in details, details


def test_approval_preview_on_secure_client_says_the_gateway_restarts() -> None:
    # Review of GAP-0030: on Secure Client `guardrail hilt` restarts the gateway.
    model = protection_model()
    details = " ".join(hilt_change_modal(model, model.scope_row(""), "HIGH+", secure_client=True).details)
    assert "restarts to apply it" in details and "applies it now" not in details, details


def test_alert_target_drops_the_connector_its_column_shows() -> None:
    # GAP-0112: "claudecode:PreToolUse" next to a Connector cell was cut to "claudecode:PreTo".
    assert _target_without_connector("claudecode:PreToolUse", "claudecode") == "PreToolUse"
    assert _target_without_connector("codex · preToolUse", "codex") == "preToolUse"
    assert _target_without_connector("skill://alpha", "codex") == "skill://alpha"
    assert _target_without_connector("codex:x", "—") == "codex:x"


def test_status_strip_keeps_whole_segments_then_an_ellipsis() -> None:
    # GAP-0112: the strip ended mid-word ("● Guar…").
    segments = [StatusSegment("Gateway", "running", "up 3m"), StatusSegment("Watchdog", "running"),
                StatusSegment("Guardrail", "running")]
    kept, cut = fit_status_segments(segments, 40)
    assert [segment.label for segment in kept] == ["Gateway", "Watchdog"] and cut
    kept, cut = fit_status_segments(segments, 200)
    assert len(kept) == 3 and not cut


async def test_alerts_controls_fit_at_80_columns(tmp_path) -> None:
    # GAP-0112: the one-row bar scrolled and showed "Select al".
    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.action_switch_panel("alerts")
        await settle_panel(app, pilot)
        text = screen_text(app)
        bar = app.query_one("#alerts-controls")
        assert bar.max_scroll_x == 0
    assert "Select all" in text and "Dismiss all" in text, text


async def test_inventory_detail_is_readable_at_80x24(tmp_path) -> None:
    # B-32: at 80x24 the open Skills detail kept one row, its top border.
    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.action_switch_panel("inventory")
        await settle_panel(app, pilot)
        await pilot.press("l", "home", "enter")
        await pilot.pause()
        await pilot.pause()
        text = screen_text(app)
    assert "SKILL: alpha" in text and "Eligible: true" in text and "Enabled: true" in text, text


def _save_app(monkeypatch, tmp_path) -> tuple[DefenseClawTUI, Path]:
    from defenseclaw.tui.services import config_audit

    payload = {
        "config_version": 8,
        "data_dir": str(tmp_path),
        "claw": {"mode": "claudecode"},
        "guardrail": {"enabled": True, "connector": "claudecode", "mode": "observe", "connectors": {"claudecode": {}}},
        "observability": {},
    }
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    monkeypatch.setenv("DEFENSECLAW_CONFIG", str(path))
    app = DefenseClawTUI(config=config_module.load(), config_path=path)
    for name in ("_render_chrome", "_schedule_signal_data_refresh", "_schedule_roster_catalog_refresh"):
        monkeypatch.setattr(app, name, lambda: None)
    monkeypatch.setattr(app, "_set_status", lambda message: setattr(app, "status_text", message))
    monkeypatch.setattr(app, "_write_activity", lambda message: app.activity_lines.append(message))
    monkeypatch.setattr(app, "_schedule_active_panel_refresh", lambda _reason="": 0)
    monkeypatch.setattr(config_audit, "record_config_save", lambda _cfg, _entries: True)
    return app, path


async def test_config_save_shows_a_key_another_writer_changed(monkeypatch, tmp_path) -> None:
    # GAP-1049: the save merged the other writer's guardrail.mode on disk, but
    # the TUI kept its stale copy and marked that generation seen.
    app, path = _save_app(monkeypatch, tmp_path)
    other = config_module.load()
    other.guardrail.mode = "action"
    other.save()

    model = app.setup_model
    model.mode = "config"
    model.active_section, model.active_line = next(
        (si, li)
        for si, section in enumerate(model.sections)
        for li, field in enumerate(section.fields)
        if field.key == "asset_policy.mode"
    )
    assert model.set_current_field_value("action")
    workers: list[object] = []
    monkeypatch.setattr(app, "run_worker", lambda work, **_kw: workers.append(work))
    with patch.object(DefenseClawTUI, "is_running", new_callable=PropertyMock, return_value=True):
        action = app._save_setup_config()  # noqa: SLF001 - the save entry point under test.
    assert "failed" not in action.hint, action.hint
    assert app.config.asset_policy.mode == "action"
    # The read-back runs as a worker, off the event loop.
    read_back = [w for w in workers if getattr(getattr(w, "cr_code", None), "co_name", "") == "_read_back_saved_config"]
    assert len(read_back) == 1, workers
    for work in workers:
        if work not in read_back and hasattr(work, "close"):
            work.close()  # other refreshes the save scheduled
    await read_back[0]

    assert config_module.load().guardrail.mode == "action"
    assert app.config.guardrail.mode == "action"
    assert app.config.asset_policy.mode == "action"
    assert app._config_watcher.applied == probe_config_generation(path)


async def test_config_read_back_does_not_wait_forever_for_a_stalled_writer(monkeypatch, tmp_path) -> None:
    # Review of GAP-1049: the read-back waited on config.yaml.lock with no
    # bound on Textual's event loop, so a stalled writer froze the TUI.
    from defenseclaw import config_writer
    from defenseclaw.tui import app as app_module

    app, path = _save_app(monkeypatch, tmp_path)
    monkeypatch.setattr(app_module, "_SAVE_READ_BACK_LOCK_TIMEOUT_S", 0.2)
    seen = app._config_watcher.applied
    other = config_module.load()
    other.guardrail.mode = "action"
    other.save()
    held, release = threading.Event(), threading.Event()

    def stalled_writer() -> None:
        with config_writer.hold_lock(str(path), timeout_s=None):
            held.set()
            release.wait(10)

    writer = threading.Thread(target=stalled_writer)
    writer.start()
    try:
        assert held.wait(5)
        app._config_read_back_running = True
        await asyncio.wait_for(app._read_back_saved_config(), timeout=5)
    finally:
        release.set()
        writer.join(10)
    assert not app._config_read_back_running
    assert any("read-back after save deferred" in line for line in app.activity_lines), app.activity_lines
    # The generation stays unseen, so the config poll loads it.
    assert app._config_watcher.applied == seen and app.config.guardrail.mode == "observe"
    for step in range(3):
        await app._poll_config_once(now=1000.0 + 10 * step)
    assert app.config.guardrail.mode == "action"


def _two_connector_overview() -> OverviewPanelModel:
    return OverviewPanelModel(
        OverviewConfig(guardrail_mode="observe", connector_modes=(("codex", "observe"), ("claudecode", "observe"))),
        version="test",
    )


def test_failed_identity_lookup_holds_for_a_connector_assignment() -> None:
    # Review of GAP-1271: the copied connector entry dropped lookup_error,
    # so codex read "profile strict" after a failed lookup.
    model = _two_connector_overview()
    model.set_guardrail_profile(
        {
            "profile": "lenient",
            "lookup_error": "directory unavailable",
            "effective": {"mode": "observe"},
            "overrides": [{"connector": "codex", "profile": "strict", "mode": "action"}],
        }
    )
    label = model.guardrail_mode_label("codex")
    assert "profile strict" not in label and "user lookup failed" in label, label


def test_failed_identity_lookup_for_the_filtered_connector_shows_a_notice() -> None:
    # Review of GAP-1271: the notice checked only the unscoped reply.
    model = _two_connector_overview()
    model.set_guardrail_profile({"profile": "strict", "effective": {"mode": "action"}})
    model.set_guardrail_profile({"profile": "lenient", "lookup_error": "directory unavailable"}, "codex")
    assert not any("Couldn't look up" in n.message for n in model.build_notices())
    messages = [n.message for n in model.build_notices(connector="codex")]
    assert any("Couldn't look up" in m and "directory unavailable" in m for m in messages), messages


def test_failed_identity_lookup_shows_a_notice_not_a_profile_label() -> None:
    # GAP-1271: a fallback profile read as the one chosen for you.
    model = OverviewPanelModel(
        OverviewConfig(guardrail_mode="observe", connector_modes=(("codex", "observe"),)), version="test"
    )
    model.set_guardrail_profile(
        {"profile": "lenient", "lookup_error": "directory unavailable", "effective": {"mode": "observe"}}
    )
    label = model.guardrail_mode_label()
    assert "profile lenient" not in label and "user lookup failed" in label, label
    messages = [notice.message for notice in model.build_notices()]
    assert any("Couldn't look up your account" in m and "directory unavailable" in m for m in messages), messages
