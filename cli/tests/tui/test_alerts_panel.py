# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Alerts panel parity tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from defenseclaw.tui.panels.alerts import AlertEvent, AlertFinding, AlertsPanelModel, humanize_alert_details
from defenseclaw.tui.services.gateway_events import count_recent_silent_bypass, load_gateway_egress


def test_humanize_alert_details_fast_paths_and_host_port() -> None:
    assert humanize_alert_details("") == ""
    assert humanize_alert_details("scanner failed on upload") == "scanner failed on upload"
    assert humanize_alert_details("host=api.example.com port=443 mode=strict") == "api.example.com:443 strict"
    assert humanize_alert_details("port=443 mode=strict") == ":443 strict"
    assert humanize_alert_details("host=api.example.com mode=strict") == "api.example.com strict"


def test_humanize_alert_details_model_noise_and_duplicate_stability() -> None:
    assert humanize_alert_details("model=openai/gpt-4o-mini mode=strict") == "strict gpt-4o-mini"
    assert humanize_alert_details("model=openai/") == "openai/"
    assert humanize_alert_details("host=h port=1 mode=x scanner=skill findings=3 max_severity=HIGH") == "h:1 x"
    assert humanize_alert_details("host=h port=1 extra=thing tail") == "h:1 extra=thing tail"
    assert humanize_alert_details("mode=first mode=second") == "first"


def test_alerts_filter_selection_and_counts() -> None:
    model = AlertsPanelModel()
    model.set_events(
        [
            AlertEvent(id="a1", severity="HIGH", action="scan", target="skill://one", details="token"),
            AlertEvent(id="a2", severity="LOW", action="proxy", target="gateway", details="safe"),
        ]
    )

    assert model.severity_counts()["HIGH"] == 1
    model.set_severity_filter("HIGH")
    assert [row.event.id for row in model.filtered] == ["a1"]
    model.toggle_select()
    assert model.selected_ids == {"a1"}
    model.select_all()
    assert model.selected_ids == {"a1"}
    model.deselect_all()
    assert model.selected_ids == set()

    action = model.handle_key("2")
    assert action.filter_change is not None
    assert action.filter_change.panel == "alerts"
    assert action.filter_change.filter_type == "severity"
    assert action.filter_change.new == "CRITICAL"


def test_alerts_default_hides_low_signal_rows_until_all_opt_in() -> None:
    model = AlertsPanelModel()
    model.set_events(
        [
            AlertEvent(id="a1", severity="HIGH", action="scan", target="skill://one"),
            AlertEvent(id="a2", severity="MEDIUM", action="proxy", target="gateway"),
            AlertEvent(id="a3", severity="INFO", action="connector-hook", target="preToolUse"),
        ]
    )

    assert [row.event.id for row in model.filtered] == ["a1"]
    assert "No actionable" not in model.empty_state()

    assert model.handle_key("1").handled is True
    assert {row.event.id for row in model.filtered} == {"a1", "a2", "a3"}


def test_alerts_slash_search_and_exact_severity_filter() -> None:
    model = AlertsPanelModel()
    model.set_events(
        [
            AlertEvent(id="a1", severity="HIGH", action="scan", target="skill://one", details="token"),
            AlertEvent(id="a2", severity="MEDIUM", action="proxy", target="gateway", details="rate limit"),
        ]
    )

    assert model.handle_key("/").handled is True
    assert model.filtering is True
    for char in "token":
        model.handle_key(char)
    assert [row.event.id for row in model.filtered] == ["a1"]
    assert model.active_filter_label() == "search 'token'"

    assert model.handle_key("enter").handled is True
    assert model.filtering is False
    model.set_severity_filter_exact("MEDIUM")
    assert [row.event.id for row in model.filtered] == []
    assert model.active_filter_label() == "Medium, search 'token'"

    assert model.handle_key("escape").handled is True
    assert model.filter_text == ""
    assert model.filtered


def test_alerts_connector_column_and_shared_filter() -> None:
    """8.13: CONNECTOR column + shared connector filter on the Alerts panel."""

    model = AlertsPanelModel()
    model.show_all_severities = True
    model.set_events(
        [
            AlertEvent(id="a1", severity="HIGH", action="connector-hook",
                       target="preToolUse", details="connector=codex action=block"),
            AlertEvent(id="a2", severity="MEDIUM", action="connector-hook",
                       target="preToolUse", details="connector=cursor action=alert"),
        ]
    )

    # Single-connector default: no CONNECTOR column.
    assert model.data_table_columns() == ("Sel", "Severity", "Time", "Action", "Target", "Details")

    model.show_connector_column = True
    assert model.data_table_columns() == (
        "Sel", "Severity", "Time", "Action", "Connector", "Target", "Details"
    )
    # Connector cell is index 4 (after Action).
    connectors = {row[4] for row in model.data_table_rows()}
    assert connectors == {"codex", "cursor"}

    model.set_connector_filter("codex")
    assert [row.event.id for row in model.filtered] == ["a1"]
    model.set_connector_filter("")
    assert {row.event.id for row in model.filtered} == {"a1", "a2"}


def test_alerts_connector_hook_uses_detail_severity_for_observe_findings() -> None:
    """Observe-mode hook findings store INFO rows but carry policy severity in details."""

    now = datetime(2026, 6, 24, 17, 46, tzinfo=timezone.utc)
    model = AlertsPanelModel()
    model.set_events(
        [
            AlertEvent(
                id="plain",
                timestamp=now,
                severity="INFO",
                action="connector-hook",
                target="PostToolUse",
                details="connector=codex action=allow raw_action=allow severity=NONE mode=observe",
            ),
            AlertEvent(
                id="finding",
                timestamp=now + timedelta(seconds=1),
                severity="INFO",
                action="connector-hook",
                target="PostToolUse",
                details="connector=codex action=allow raw_action=alert severity=HIGH mode=observe",
            ),
        ]
    )

    assert [row.event.id for row in model.filtered] == ["finding"]
    assert model.severity_counts()["HIGH"] == 1
    assert model.data_table_row_models()[0].cells[1] == "HIGH"

    model.set_severity_filter_exact("HIGH")
    assert [row.event.id for row in model.filtered] == ["finding"]


def test_alerts_connector_token_filters_by_connector() -> None:
    # E5: the Alerts panel honors the same ``connector:<name>`` search token
    # as Audit, matching the kv connector in the event details. Free text in
    # the same query still ANDs via the legacy substring search.
    model = AlertsPanelModel()
    model.set_events(
        [
            AlertEvent(
                id="h1",
                severity="LOW",
                action="connector-hook",
                target="preToolUse",
                details="connector=codex action=allow severity=NONE",
            ),
            AlertEvent(
                id="h2",
                severity="LOW",
                action="connector-hook",
                target="preToolUse",
                details="connector=cursor action=block severity=HIGH",
            ),
        ]
    )

    model.set_filter("connector:codex")
    assert [row.event.id for row in model.filtered] == ["h1"]

    # token + free text ANDs (block only on cursor).
    model.set_filter("connector:cursor block")
    assert [row.event.id for row in model.filtered] == ["h2"]

    model.set_filter("connector:nope")
    assert model.filtered == []


def test_alerts_refresh_ingests_scan_finding_from_gateway_jsonl(tmp_path) -> None:
    (tmp_path / "gateway.jsonl").write_text(
        (
            '{"ts":"2026-04-20T12:00:00Z","event_type":"scan_finding","severity":"HIGH",'
            '"scan_finding":{"scan_id":"sid1","scanner":"skill-scanner","target":"t.py",'
            '"rule_id":"R9","line_number":3,"title":"x"}}\n'
        ),
        encoding="utf-8",
    )
    model = AlertsPanelModel(tmp_path)
    model.show_all_severities = True
    model.refresh_gateway_scans()
    model.expanded.add("sid1")
    model.apply_filter()

    assert any(row.kind == "scan_finding" and row.event.action == "scan-finding" for row in model.filtered)
    finding = next(row for row in model.filtered if row.kind == "scan_finding")
    assert "R9" in finding.event.details
    assert "line=3" in finding.event.details


def test_alerts_refresh_clears_gateway_rows_when_data_dir_is_removed(tmp_path) -> None:
    (tmp_path / "gateway.jsonl").write_text(
        (
            '{"ts":"2026-04-20T12:00:00Z","event_type":"scan","severity":"HIGH",'
            '"scan":{"scan_id":"sid1","scanner":"skill-scanner","target":"t.py",'
            '"verdict":"warn","severity_max":"HIGH"}}\n'
        ),
        encoding="utf-8",
    )
    model = AlertsPanelModel(tmp_path)
    model.show_all_severities = True
    model.refresh()
    assert model.scan_blocks

    model.set_data_dir(None)
    model.refresh()

    assert model.scan_blocks == []
    assert model.egress_events == []
    assert all(row.kind == "audit" for row in model.filtered)


def test_alerts_refresh_ingests_gateway_egress_and_filters_warning_as_medium(tmp_path) -> None:
    now = datetime.now(timezone.utc)
    old = now - timedelta(minutes=10)
    (tmp_path / "gateway.jsonl").write_text(
        (
            '{"ts":"'
            + now.isoformat().replace("+00:00", "Z")
            + '","event_type":"egress","egress":{"target_host":"api.x.test",'
            '"target_path":"/v1/messages","body_shape":"messages","looks_like_llm":true,'
            '"branch":"shape","decision":"allow","reason":"shape-match","source":"ts"}}\n'
            '{"ts":"'
            + old.isoformat().replace("+00:00", "Z")
            + '","event_type":"egress","egress":{"target_host":"api.known.test",'
            '"target_path":"/v1/messages","body_shape":"messages","looks_like_llm":true,'
            '"branch":"known","decision":"allow","source":"ts"}}\n'
        ),
        encoding="utf-8",
    )
    model = AlertsPanelModel(tmp_path)
    model.show_all_severities = True
    model.refresh_gateway_scans()

    egress_rows = [row for row in model.filtered if row.kind == "egress"]
    assert len(egress_rows) == 2
    warning = next(row for row in egress_rows if row.event.target == "api.x.test")
    assert warning.event.severity == "WARNING"
    assert warning.event.action == "egress"
    assert "looks_like_llm=true" in warning.event.details
    assert model.severity_counts()["MEDIUM"] == 1

    model.set_severity_filter_exact("MEDIUM")
    assert [row.event.target for row in model.filtered] == ["api.x.test"]
    table_row = model.data_table_row_models()[0]
    assert table_row.selectable is False
    assert table_row.opens_detail is True
    assert table_row.key.startswith("egress:gw:egress:")

    egress = load_gateway_egress(tmp_path / "gateway.jsonl")
    assert count_recent_silent_bypass(egress, window_seconds=300) == 1


def test_alerts_enter_expands_scan_parent_and_toggles_detail_for_child(tmp_path) -> None:
    (tmp_path / "gateway.jsonl").write_text(
        (
            '{"ts":"2026-04-20T12:00:00Z","event_type":"scan","severity":"HIGH",'
            '"scan":{"scan_id":"sid1","scanner":"skill-scanner","target":"t.py",'
            '"verdict":"warn","duration_ms":42,"severity_max":"HIGH"}}\n'
            '{"ts":"2026-04-20T12:00:01Z","event_type":"scan_finding","severity":"HIGH",'
            '"scan_finding":{"scan_id":"sid1","scanner":"skill-scanner","target":"t.py",'
            '"rule_id":"R9","line_number":3,"title":"x"}}\n'
        ),
        encoding="utf-8",
    )
    model = AlertsPanelModel(tmp_path)
    model.refresh_gateway_scans()
    model.toggle_expand_or_detail()
    assert "sid1" in model.expanded

    child_index = next(index for index, row in enumerate(model.filtered) if row.kind == "scan_finding")
    model.set_cursor(child_index)
    model.toggle_expand_or_detail()
    assert model.detail_open is True


def test_alerts_expanded_findings_stay_under_scan_parent(tmp_path) -> None:
    (tmp_path / "gateway.jsonl").write_text(
        (
            '{"ts":"2026-04-20T12:00:00Z","event_type":"scan","severity":"HIGH",'
            '"scan":{"scan_id":"sid1","scanner":"skill-scanner","target":"old.py",'
            '"verdict":"warn","duration_ms":42,"severity_max":"HIGH"}}\n'
            '{"ts":"2026-04-20T12:00:05Z","event_type":"scan_finding","severity":"HIGH",'
            '"scan_finding":{"scan_id":"sid1","scanner":"skill-scanner","target":"old.py",'
            '"rule_id":"R9","line_number":3,"title":"x"}}\n'
        ),
        encoding="utf-8",
    )
    model = AlertsPanelModel(tmp_path)
    model.set_events([AlertEvent(id="newer", severity="LOW", action="proxy", target="gateway")])
    model.refresh_gateway_scans()
    model.expanded.add("sid1")
    model.apply_filter()

    rows = [(row.kind, row.scan_id or row.event.id) for row in model.filtered]
    assert ("scan", "sid1") in rows
    parent_index = rows.index(("scan", "sid1"))
    assert rows[parent_index + 1] == ("scan_finding", "sid1")


def test_alerts_detail_pairs_copy_text_and_store_enrichment() -> None:
    selected = AlertEvent(
        id="a1",
        severity="HIGH",
        action="proxy",
        target="gateway",
        details="host=api port=443 mode=strict model=openai/gpt-4o",
        run_id="run-1",
        trace_id="trace-1",
        request_id="req-1",
        session_id="sess-1",
    )

    class FakeStore:
        def list_findings_by_run_id(self, run_id: str) -> list[AlertFinding]:
            assert run_id == "run-1"
            return [
                AlertFinding(
                    id="f1",
                    scan_id="run-1",
                    severity="HIGH",
                    title="Hardcoded credential",
                    location="main.py:42",
                    remediation="Load from keychain",
                    scanner="skill-scanner",
                )
            ]

        def list_events_by_target(self, target: str, limit: int) -> list[AlertEvent]:
            assert target == "gateway"
            assert limit == 10
            return [
                selected,
                AlertEvent(id="a0", severity="LOW", action="allow", target="gateway"),
            ]

    model = AlertsPanelModel(store=FakeStore())
    model.set_events([selected])
    model.toggle_expand_or_detail()

    pairs = dict(model.detail_pairs())
    assert pairs["Summary"] == "api:443 strict gpt-4o"
    assert pairs["Details"] == "host=api port=443 mode=strict model=openai/gpt-4o"
    assert pairs["Run ID"] == "run-1"
    assert pairs["Trace ID"] == "trace-1"
    assert pairs["Request ID"] == "req-1"
    assert "Hardcoded credential" in pairs["Finding 1"]
    assert pairs["Remediation 1"] == "Load from keychain"
    assert "allow" in pairs["History 1"]

    copied = model.handle_key("y")
    assert copied.copy_text
    assert "Severity: HIGH" in copied.copy_text
    assert "Summary: api:443 strict gpt-4o" in copied.copy_text
    assert "Request ID: req-1" in copied.copy_text


def test_alerts_table_metadata_marks_scan_rows_non_selectable(tmp_path) -> None:
    (tmp_path / "gateway.jsonl").write_text(
        (
            '{"ts":"2026-04-20T12:00:00Z","event_type":"scan","severity":"HIGH",'
            '"scan":{"scan_id":"sid1","scanner":"skill-scanner","target":"t.py",'
            '"verdict":"warn","duration_ms":42,"severity_max":"HIGH",'
            '"total_count":2,"counts":{"HIGH":1,"LOW":1}}}\n'
        ),
        encoding="utf-8",
    )
    model = AlertsPanelModel(tmp_path)
    model.show_all_severities = True
    model.set_events([AlertEvent(id="a1", severity="LOW", action="proxy", target="gateway")])
    model.refresh_gateway_scans()

    table_rows = model.data_table_row_models()
    audit_row = next(row for row in table_rows if row.kind == "audit")
    scan_row = next(row for row in table_rows if row.kind == "scan")

    assert audit_row.key == "audit:a1"
    assert audit_row.selectable is True
    assert audit_row.opens_detail is True
    assert scan_row.key == "scan:sid1"
    assert scan_row.selectable is False
    assert scan_row.expands is True
    scan_details = next(row.event.details for row in model.filtered if row.kind == "scan")
    assert "total=2" in scan_details
    assert "counts=HIGH=1,LOW=1" in scan_details


def test_alerts_connector_hook_row_surfaces_connector_and_decision() -> None:
    """Hook rows should encode connector + decision in the table cells."""

    hook_event = AlertEvent(
        id="h1",
        severity="LOW",
        action="connector-hook",
        target="preToolUse",
        details=(
            "connector=claudecode action=allow severity=LOW mode=observe "
            "elapsed=320ms tool=Bash audit_id=abc123"
        ),
    )
    plain_event = AlertEvent(
        id="p1",
        severity="HIGH",
        action="proxy",
        target="gateway",
        details="host=api port=443 mode=strict",
    )

    model = AlertsPanelModel()
    model.show_all_severities = True
    model.set_events([hook_event, plain_event])

    rows = {row.alert_id: row for row in model.data_table_row_models()}
    assert rows["h1"].cells[4] == "claudecode · preToolUse"
    # ``LOW`` is non-NONE so it gets folded into the summary alongside
    # the decision and elapsed; the rest of the kv blob is hidden.
    assert rows["h1"].cells[5] == "allow · LOW · 320ms"

    # Non-hook rows preserve their existing humanized rendering so the
    # proxy/scan/egress legacy table layout is untouched.
    assert rows["p1"].cells[4] == "gateway"
    assert rows["p1"].cells[5] == "api:443 strict"


def test_alerts_connector_hook_detail_pairs_expand_kv_into_rows() -> None:
    """Hook detail panes should split kv details into labelled rows."""

    hook_event = AlertEvent(
        id="h1",
        severity="INFO",
        action="connector-hook",
        target="preToolUse",
        details=(
            "connector=claudecode action=allow severity=NONE mode=observe "
            "would_block=false elapsed=180ms tool=Bash "
            "payload=<redacted len=12 sha=deadbeefcafebabe>"
        ),
    )

    model = AlertsPanelModel()
    model.show_all_severities = True
    model.set_events([hook_event])
    model.toggle_expand_or_detail()

    pairs = dict(model.detail_pairs())
    # The kv blob is exploded into its own rows…
    assert pairs["Connector"] == "claudecode"
    assert pairs["Decision"] == "allow"
    assert pairs["Enforcement mode"] == "observe"
    assert pairs["Elapsed"] == "180ms"
    assert pairs["Tool"] == "Bash"
    # …redacted blobs are prettified for humans, and noisy
    # severity=NONE / would_block=false in observe mode are hidden.
    assert "redacted" in pairs["Payload"]
    assert "12 bytes" in pairs["Payload"]
    assert "Severity" not in pairs or pairs["Severity"] != "NONE"
    assert "Would block" not in pairs
    # The legacy Summary/Details rows are no longer emitted because
    # the exploded rows are strictly more useful.
    assert "Summary" not in pairs
    assert "Details" not in pairs


def test_alerts_connector_hook_blocked_keeps_severity_and_block_flag() -> None:
    """Enforce-mode blocked hooks must keep severity + would_block visible."""

    hook_event = AlertEvent(
        id="h1",
        severity="HIGH",
        action="connector-hook",
        target="postToolUse",
        details=(
            "connector=claudecode action=block severity=HIGH mode=enforce "
            "would_block=true elapsed=42ms reason=policy_match"
        ),
    )

    model = AlertsPanelModel()
    model.show_all_severities = True
    model.set_events([hook_event])
    model.toggle_expand_or_detail()

    pairs = dict(model.detail_pairs())
    assert pairs["Decision"] == "block"
    # In enforce mode we keep the structured severity + block flag so
    # operators see exactly why the request was rejected.
    assert pairs["Severity"] == "HIGH"
    assert pairs["Would block"] == "yes"
    assert pairs["Reason"] == "policy_match"


def test_alerts_connector_hook_copy_text_uses_structured_rows() -> None:
    """`y` should copy the same hook-aware view shown in the detail pane."""

    hook_event = AlertEvent(
        id="h1",
        severity="LOW",
        action="connector-hook",
        target="preToolUse",
        details=(
            "connector=claudecode action=allow severity=LOW mode=observe "
            "elapsed=99ms tool=Read"
        ),
    )

    model = AlertsPanelModel()
    model.show_all_severities = True
    model.set_events([hook_event])
    model.toggle_expand_or_detail()

    copied = model.handle_key("y").copy_text
    assert "Connector: claudecode" in copied
    assert "Decision: allow" in copied
    assert "Tool: Read" in copied
    # Hook copy text drops the noisy ``Summary``/``Details`` lines
    # used for proxy/scan rows; structured rows are the source of
    # truth.
    assert "Summary:" not in copied
    assert "Details: connector=" not in copied
