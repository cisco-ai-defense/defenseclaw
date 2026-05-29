# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Activity panel parity tests."""

from __future__ import annotations

from datetime import timedelta

from defenseclaw.tui.panels.activity import ActivityPanelModel
from defenseclaw.tui.services.gateway_events import parse_gateway_event, render_verdict_line


def test_activity_panel_empty_state_matches_go_contract() -> None:
    panel = ActivityPanelModel()

    assert panel.count == 0
    assert panel.is_running is False
    assert panel.last_command == ""
    assert "No commands" in panel.render_text()


def test_activity_panel_command_lifecycle() -> None:
    panel = ActivityPanelModel()

    panel.add_entry("doctor")
    panel.append_output("Checking gateway...")
    panel.append_output("Gateway: running")
    panel.finish_entry(0, timedelta(milliseconds=150))

    assert panel.count == 1
    assert panel.is_running is False
    assert panel.last_command == "doctor"
    rendered = panel.render_text()
    assert "Checking gateway..." in rendered
    assert "exit 0" in rendered


def test_activity_panel_terminal_and_history_key_flow() -> None:
    panel = ActivityPanelModel()
    panel.add_entry("status")
    panel.append_output("line")
    panel.finish_entry(0)

    assert panel.term_mode is True
    panel.handle_key("q")
    assert panel.term_mode is False
    panel.handle_key("enter")
    assert panel.term_mode is True


def test_activity_panel_mutation_diff_toggle(tmp_path) -> None:
    (tmp_path / "gateway.jsonl").write_text(
        (
            '{"ts":"2026-04-20T12:00:02Z","event_type":"activity","severity":"INFO",'
            '"activity":{"actor":"alice","action":"config-update","target_type":"config",'
            '"target_id":"cfg","version_from":"v1","version_to":"v2",'
            '"diff":[{"op":"replace","path":"/guardrail/enabled"}]}}\n'
        ),
        encoding="utf-8",
    )
    panel = ActivityPanelModel(tmp_path)
    panel.load_mutations()
    panel.handle_key("2")
    panel.handle_key("enter")

    rendered = panel.render_text()
    assert "alice" in rendered
    assert "config-update" in rendered
    assert "replace /guardrail/enabled" in rendered


def test_gateway_event_scan_rendering_matches_go_smoke() -> None:
    event = parse_gateway_event(
        '{"ts":"2026-04-20T12:00:00Z","event_type":"scan","severity":"HIGH",'
        '"scan":{"scan_id":"s1","scanner":"skill-scanner","target":"/x",'
        '"verdict":"warn","duration_ms":42,"severity_max":"HIGH"}}'
    )

    assert event.event_type == "scan"
    rendered = render_verdict_line(event)
    assert "skill-scanner" in rendered
    assert "s1" in rendered


def test_gateway_event_scan_finding_rendering_matches_go_smoke() -> None:
    event = parse_gateway_event(
        '{"ts":"2026-04-20T12:00:01Z","event_type":"scan_finding","severity":"CRITICAL",'
        '"scan_finding":{"scan_id":"s1","scanner":"skill-scanner","target":"f.py",'
        '"rule_id":"R42","line_number":7,"title":"bad"}}'
    )

    assert event.event_type == "scan_finding"
    rendered = render_verdict_line(event)
    assert "R42" in rendered
    assert "7" in rendered
