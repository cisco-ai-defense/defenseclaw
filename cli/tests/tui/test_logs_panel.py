# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Logs panel parity tests for the Textual TUI migration."""

from __future__ import annotations

from datetime import datetime, timezone

from defenseclaw.tui.panels import logs as logs_module
from defenseclaw.tui.panels.logs import (
    FILTER_ERRORS,
    FILTER_HOOKS,
    FILTER_LABELS,
    FILTER_NO_NOISE,
    FILTER_NONE,
    FILTER_PRESETS,
    FILTER_TYPE_PRESET,
    FILTER_TYPE_SEVERITY,
    LogsPanelModel,
)
from defenseclaw.tui.services.gateway_log_views import (
    EVENT_TYPE_FILTERS,
    GatewayLogRow,
    detail_pairs,
    project_v8_log_views,
    render_details_inline,
    render_gateway_log_line,
    render_otel_line,
    severity_rank,
    trim_categories,
)
from defenseclaw.tui.services.v8_event_history import V8EventHistoryRow


def _v8_row(
    *,
    bucket: str,
    event_name: str,
    source: str = "gateway",
    severity: str = "INFO",
    action: str = "",
    details: str = "",
    payload: dict[str, object] | None = None,
    request_id: str = "",
    run_id: str = "",
    session_id: str = "",
) -> GatewayLogRow:
    history = V8EventHistoryRow(
        id="record-1",
        timestamp=datetime(2026, 4, 16, 12, 34, 56, tzinfo=timezone.utc),
        bucket=bucket,
        event_name=event_name,
        source=source,
        severity=severity,
        action=action,
        actor="defenseclaw",
        details=details,
        connector="codex",
        redaction_profile="strict",
        request_id=request_id,
        run_id=run_id,
        session_id=session_id,
        payload=payload or {},
    )
    return project_v8_log_views((history,)).otel_rows[0]


def test_v8_history_verdict_fields_and_detail_pairs() -> None:
    row = _v8_row(
        bucket="guardrail.evaluation",
        event_name="guardrail.evaluation.completed",
        source="bedrock",
        severity="HIGH",
        action="block",
        details="pii",
        request_id="req-123",
        run_id="run-abc",
        session_id="sess-xyz",
        payload={
            "gen_ai.request.model": "claude",
            "gen_ai.operation.name": "prompt",
            "defenseclaw.guardrail.decision": "block",
            "defenseclaw.guardrail.reason": "pii",
            "defenseclaw.guardrail.rule_ids": ["pii.email", "injection.system", "policy.custom"],
            "defenseclaw.guardrail.latency_ms": 37,
        },
    )

    assert row.event_type == "verdict"
    assert row.action == "block"
    assert row.request_id == "req-123"
    assert row.run_id == "run-abc"
    assert row.session_id == "sess-xyz"
    assert row.provider == "bedrock"
    assert row.categories == ("pii.email", "injection.system", "policy.custom")
    assert row.latency_ms == 37

    rendered = render_gateway_log_line(row)
    assert "VERDICT" in rendered
    assert "BLOCK" in rendered
    assert "pii.email" in rendered
    assert "+1more" in rendered
    assert "(37ms)" in rendered

    detail = dict(detail_pairs(row))
    assert detail["Provider"] == "bedrock"
    assert detail["Request ID"] == "req-123"
    assert detail["Run ID"] == "run-abc"
    assert detail["Session ID"] == "sess-xyz"
    assert detail["Categories"] == "pii.email, injection.system, policy.custom"
    assert detail["Latency (ms)"] == "37"
    assert detail["Raw JSON"]


def test_v8_history_judge_lifecycle_error_and_diagnostic_fields() -> None:
    judge = _v8_row(
        bucket="guardrail.evaluation",
        event_name="guardrail.judge.completed",
        severity="CRITICAL",
        payload={
            "gen_ai.request.model": "gpt-4",
            "defenseclaw.judge.kind": "pii",
            "defenseclaw.judge.action": "block",
            "defenseclaw.judge.input_bytes": 512,
            "defenseclaw.guardrail.latency_ms": 90,
            "defenseclaw.judge.parse_error": "",
        },
    )
    assert judge.kind == "pii"
    assert judge.action == "block"
    assert judge.judge_severity == "CRITICAL"
    assert judge.judge_input_bytes == 512
    assert judge.latency_ms == 90

    lifecycle = _v8_row(
        bucket="agent.lifecycle",
        event_name="agent.lifecycle.ready",
        payload={"defenseclaw.gateway.port": "8081", "defenseclaw.gateway.host": "localhost"},
    )
    assert lifecycle.lifecycle_subsystem == "agent.lifecycle"
    assert lifecycle.lifecycle_details["port"] == "8081"
    assert lifecycle.lifecycle_details["host"] == "localhost"
    assert render_details_inline({"z": "1", "a": "2", "m": "3"}, 2) == "a=2 m=3"

    error = _v8_row(
        bucket="platform.health",
        event_name="platform.health.check.failed",
        source="opa",
        severity="HIGH",
        payload={
            "defenseclaw.error.code": "compile_failed",
            "defenseclaw.error.summary": "bad rego",
        },
    )
    diagnostic = _v8_row(
        bucket="diagnostic",
        event_name="diagnostic.pipeline.initialized",
        source="destinations",
        details="pipeline initialized",
    )
    detail = dict(detail_pairs(error))
    assert detail["Error code"] == "compile_failed"
    assert detail["Error message"] == "bad rego"
    assert dict(detail_pairs(diagnostic))["Diagnostic component"] == "destinations"


def test_logs_selected_structured_row_respects_search_and_preset_filters() -> None:
    panel = LogsPanelModel()
    panel.source = "verdicts"
    panel.filter_mode = FILTER_NONE
    panel.verdict_rows = [
        GatewayLogRow(raw="{}", event_type="verdict", action="allow", reason="clean"),
        GatewayLogRow(raw="{}", event_type="verdict", action="alert", reason="suspicious"),
        GatewayLogRow(raw="{}", event_type="verdict", action="block", reason="error injection"),
    ]
    panel.lines["verdicts"] = [
        "VERDICT ALLOW clean",
        "VERDICT ALERT suspicious",
        "VERDICT BLOCK error injection",
    ]

    panel.search_text = "suspicious"
    selected = panel.selected_verdict()
    assert selected is not None
    assert selected.action == "alert"

    panel.search_text = ""
    panel.filter_mode = FILTER_ERRORS
    selected = panel.selected_verdict()
    assert selected is not None
    assert selected.action == "block"

    panel.search_text = "no-such-token"
    assert panel.selected_verdict() is None

    # The structured detail row must use the same connector-filtered index
    # as the visible table, not the unfiltered structured list.
    panel.search_text = ""
    panel.filter_mode = FILTER_NONE
    panel.lines["verdicts"] = [
        "VERDICT ALLOW connector=codex clean",
        "VERDICT ALERT connector=cursor suspicious",
        "VERDICT BLOCK connector=codex error injection",
    ]
    panel.set_connector_filter("cursor")
    selected = panel.selected_verdict()
    assert selected is not None
    assert selected.action == "alert"


def test_logs_error_empty_and_cursor_scrolling_states(tmp_path) -> None:
    panel = LogsPanelModel(tmp_path)
    panel.refresh()
    panel.source = "verdicts"

    assert panel.error_messages["verdicts"] == ""
    assert "Log file is empty or not yet created" in panel.render_text()

    panel.source = "gateway"
    panel.filter_mode = FILTER_NONE
    panel.lines["gateway"] = [f"line {index}" for index in range(30)]

    assert panel.selected_raw_line() == "line 29"
    panel.move_cursor(-5, height=10)
    assert panel.selected_raw_line() == "line 24"
    assert panel.paused is True
    assert panel.scroll["gateway"] > 0

    panel.set_cursor(0, height=10)
    assert panel.selected_raw_line() == "line 0"
    assert panel.scroll["gateway"] == 0

    panel.lines["gateway"] = []
    panel.error_messages["gateway"] = ""
    assert "Log file is empty or not yet created" in panel.render_text()


def test_logs_refresh_retries_transient_process_log_reads(tmp_path, monkeypatch) -> None:
    (tmp_path / "gateway.log").write_text("gateway ready\n", encoding="utf-8")
    panel = LogsPanelModel(tmp_path)

    raw_reader = logs_module._tail_text_file
    raw_calls = 0

    def flaky_raw_reader(*args, **kwargs):
        nonlocal raw_calls
        if args[0].name == "gateway.log":
            raw_calls += 1
            if raw_calls == 1:
                raise OSError("transient raw read")
        return raw_reader(*args, **kwargs)

    monkeypatch.setattr(logs_module, "_tail_text_file", flaky_raw_reader)

    panel.refresh()
    assert panel.lines["gateway"] == []
    assert panel.error_messages["gateway"].startswith("Cannot open:")
    assert panel.error_messages["verdicts"] == ""

    panel.refresh()
    assert panel.lines["gateway"] == ["gateway ready"]
    assert panel.error_messages["gateway"] == ""
    assert panel.error_messages["verdicts"] == ""
    assert raw_calls == 2


def test_process_log_snapshot_is_read_without_mutating_model_until_applied(tmp_path) -> None:
    (tmp_path / "gateway.log").write_text("ready\nserving\n", encoding="utf-8")
    panel = LogsPanelModel(tmp_path)

    request = panel.pending_file_refresh("gateway")
    assert request is not None
    snapshot = panel.read_file_request(request)
    assert panel.lines["gateway"] == []

    assert panel.apply_file_snapshot(snapshot) is True
    assert panel.lines["gateway"] == ["ready", "serving"]
    assert panel.pending_file_refresh("gateway") is None


def test_refresh_files_can_limit_io_to_active_raw_source(tmp_path, monkeypatch) -> None:
    (tmp_path / "gateway.log").write_text("gateway\n", encoding="utf-8")
    (tmp_path / "watchdog.log").write_text("watchdog\n", encoding="utf-8")
    reads: list[str] = []
    raw_reader = logs_module._tail_text_file

    def tracked_reader(path, **kwargs):
        reads.append(path.name)
        return raw_reader(path, **kwargs)

    monkeypatch.setattr(logs_module, "_tail_text_file", tracked_reader)
    panel = LogsPanelModel(tmp_path)

    assert panel.refresh_files(("gateway",)) == {"gateway"}
    assert reads == ["gateway.log"]
    assert panel.lines["gateway"] == ["gateway"]
    assert panel.lines["watchdog"] == []


def test_logs_set_data_dir_none_clears_loaded_state(tmp_path) -> None:
    panel = LogsPanelModel(tmp_path)
    panel.lines["gateway"] = ["gateway ready"]
    panel.lines["verdicts"] = ["VERDICT ALLOW"]
    panel.verdict_rows = [GatewayLogRow(raw="{}", event_type="verdict", action="allow")]
    panel.otel_rows = [GatewayLogRow(raw="{}", event_type="lifecycle")]
    panel.filtered_lines()

    panel.set_data_dir(None)

    assert all(not lines for lines in panel.lines.values())
    assert all(not error for error in panel.error_messages.values())
    assert panel.verdict_rows == []
    assert panel.otel_rows == []
    assert panel.filtered_lines() == []


def test_logs_no_noise_default_hides_low_signal_severities() -> None:
    panel = LogsPanelModel()
    panel.filter_mode = FILTER_NO_NOISE
    panel.lines["gateway"] = [
        "12:00:00 INFO connector hook allow",
        "12:00:01 MEDIUM scan completed",
        "12:00:02 LOW background sync",
        "12:00:03 HIGH block policy violation",
        "12:00:04 INFO sink failure delivering webhook",
    ]

    assert panel.filtered_lines() == [
        "12:00:03 HIGH block policy violation",
        "12:00:04 INFO sink failure delivering webhook",
    ]


def test_logs_chip_cycles_schema_coverage_and_action_intents_are_data() -> None:
    panel = LogsPanelModel()
    panel.source = "verdicts"

    panel.handle_key("a")
    panel.handle_key("t")
    panel.handle_key("s")

    assert panel.verdict_action == "block"
    assert panel.verdict_event_type == "verdict"
    assert panel.verdict_severity == "CRITICAL"

    action = panel.handle_key("J")
    assert action.handled is True
    assert action.intent is None
    assert "judge response" in action.hint

    assert EVENT_TYPE_FILTERS == (
        "",
        "verdict",
        "judge",
        "lifecycle",
        "error",
        "diagnostic",
        "scan",
        "scan_finding",
        "activity",
    )
    assert severity_rank("CRITICAL") > severity_rank("HIGH")
    assert severity_rank("not-a-level") == 0
    assert trim_categories(("a", "b", "c"), 2) == ("a", "b", "+1more")


def test_logs_view_metadata_exposes_tabs_chips_search_status_and_styles() -> None:
    panel = LogsPanelModel()
    panel.source = "verdicts"
    panel.filter_mode = FILTER_ERRORS
    panel.verdict_action = "block"
    panel.verdict_event_type = "judge"
    panel.verdict_severity = "HIGH+"
    panel.paused = True
    panel.searching = True
    panel.search_text = "pii"
    panel.lines["verdicts"] = [
        "VERDICT ALLOW clean",
        "JUDGE BLOCK HIGH pii error",
    ]
    panel.verdict_rows = [
        GatewayLogRow(raw="{}", event_type="verdict", action="allow"),
        GatewayLogRow(raw="{}", event_type="judge", action="block"),
    ]

    header = panel.header_state()
    assert header.status.label == "PAUSED"
    assert header.status.style_key == "paused"
    assert header.status.hint == "Space to resume"
    assert header.search_label == "search: pii"
    assert header.search_prompt == "/ pii"
    assert header.line_count_label == "1 / 2 lines"
    assert [tab.label for tab in header.tabs] == ["Gateway", "Verdicts", "OTEL", "Watchdog"]
    assert [tab.style_key for tab in header.tabs if tab.active] == ["active-tab"]

    groups = {group.group: group for group in panel.chip_groups()}
    assert set(groups) == {"preset", "action", "type", "severity"}
    assert [chip.label for chip in groups["preset"].chips if chip.active] == ["Errors"]
    assert [chip.shortcut for chip in groups["preset"].chips[:3]] == ["1", "2", "3"]
    assert [chip.label for chip in groups["action"].chips if chip.active] == ["Block"]
    assert [chip.label for chip in groups["type"].chips if chip.active] == ["Judge"]
    assert [chip.label for chip in groups["severity"].chips if chip.active] == ["High+"]

    rows = panel.visible_row_views()
    assert len(rows) == 1
    assert rows[0].selected is True
    assert rows[0].style_key == "log-error"
    assert rows[0].detail_title == "Gateway event - JUDGE"

    table_rows = panel.data_table_row_models()
    assert table_rows[0].source == "verdicts"
    assert table_rows[0].cursor_index == 0
    assert table_rows[0].selected is True
    assert table_rows[0].event_type == "judge"
    assert table_rows[0].detail_title == "Gateway event - JUDGE"
    assert table_rows[0].key.startswith("verdicts:0:")


def test_logs_row_style_and_detail_title_metadata_for_other_sources() -> None:
    panel = LogsPanelModel()
    panel.filter_mode = FILTER_NONE
    panel.source = "gateway"
    panel.lines["gateway"] = [
        "gateway connected",
        "event tick seq=1",
        "warn slow path",
        "fatal crash",
    ]

    assert panel.line_style_key("gateway connected") == "clean"
    assert panel.line_style_key("event tick seq=1") == "dimmed"
    assert panel.line_style_key("VERDICT BLOCK HIGH") == "log-keyword"
    assert panel.line_style_key("warn slow path") == "log-warn"
    assert panel.line_style_key("fatal crash") == "log-error"
    assert panel.visible_row_views()[-1].detail_title == "Gateway log line"
    assert panel.data_table_columns() == ("Line",)
    assert panel.data_table_rows()[0] == ("gateway connected",)

    panel.source = "otel"
    panel.otel_rows = [GatewayLogRow(raw="{}", event_type="activity", activity_action="codex.notify.done")]
    panel.lines["otel"] = ["CODEX INFO action=codex.notify.done"]
    assert panel.selected_detail_title() == "OTEL event - ACTIVITY"


def test_logs_has_no_retired_global_redaction_state() -> None:
    panel = LogsPanelModel()
    panel.filter_mode = FILTER_NONE
    panel.lines["gateway"] = ["line one"]
    assert panel.header_state().redaction.visible is False
    assert "RAW redaction off" not in panel.render_text()
    assert panel.handle_key("R").modal is None


def test_logs_filter_change_metadata_and_modal_hooks() -> None:
    panel = LogsPanelModel()
    action = panel.handle_key("1")
    assert action.filter_change is not None
    assert action.filter_change.panel == "logs"
    assert action.filter_change.filter_type == FILTER_TYPE_PRESET
    assert action.filter_change.old == "no-noise"
    assert action.filter_change.new == ""

    panel.source = "verdicts"
    action = panel.handle_key("s")
    assert action.filter_change is not None
    assert action.filter_change.filter_type == FILTER_TYPE_SEVERITY
    assert action.filter_change.old == ""
    assert action.filter_change.new == "CRITICAL"

    panel.searching = True
    action = panel.handle_key("s")
    assert action.filter_change is None
    assert panel.search_text == "s"

    panel.searching = False
    assert panel.handle_key("R").modal is None
    assert panel.handle_key("N").modal == "notifications"
    assert panel.handle_key("J").modal == "judge-history"


def test_logs_hooks_filter_keeps_only_connector_hook_lines() -> None:
    """The Hooks preset narrows any source to connector-hook activity.

    OTEL renders hook lifecycle rows as ``HOOK`` lines and free-form
    gateway tails carry the ``connector-hook`` action, so the preset
    matches the ``hook`` token and drops everything else.
    """

    panel = LogsPanelModel()
    panel.source = "otel"
    panel.lines["otel"] = [
        "12:00:00.000 HOOK   INFO     cursor preToolUse   allow",
        "12:00:01.000 OTEL   INFO     subsystem=otel transition=completed",
        "12:00:02.000 CODEX  INFO     codex.notify.session",
    ]

    panel.set_filter(FILTER_HOOKS)
    filtered = panel.filtered_lines()
    assert len(filtered) == 1
    assert "HOOK" in filtered[0]


def test_logs_connector_search_token_filters_by_connector() -> None:
    # E5: the Logs search box honors the same ``connector:<name>`` token as
    # Audit/Alerts. Connector-hook lines carry ``connector=<name>``, so the
    # token matches that form; remaining free text keeps substring search.
    panel = LogsPanelModel()
    panel.source = "gateway"
    panel.lines["gateway"] = [
        "12:00:00 HOOK connector=codex action=allow preToolUse",
        "12:00:01 HOOK connector=cursor action=block preToolUse",
        "12:00:02 OTEL subsystem=otel transition=completed",
    ]

    panel.search_text = "connector:codex"
    filtered = panel.filtered_lines()
    assert len(filtered) == 1
    assert "connector=codex" in filtered[0]

    # token + free text ANDs.
    panel.search_text = "connector:cursor block"
    filtered = panel.filtered_lines()
    assert len(filtered) == 1
    assert "connector=cursor" in filtered[0]

    panel.search_text = "connector:nope"
    assert panel.filtered_lines() == []


def test_logs_connector_column_and_shared_filter() -> None:
    """8.13: CONNECTOR column + shared connector filter on the Logs panel."""

    panel = LogsPanelModel()
    panel.source = "gateway"
    panel.filter_mode = FILTER_NONE
    panel.lines["gateway"] = [
        "12:00:00 HOOK connector=codex action=allow preToolUse",
        "12:00:01 HOOK connector=cursor action=block preToolUse",
        "12:00:02 OTEL subsystem=otel transition=completed",
    ]

    # Single-connector default: single Line column.
    assert panel.data_table_columns() == ("Line",)

    panel.show_connector_column = True
    assert panel.data_table_columns() == ("Connector", "Line")
    rows = panel.data_table_rows()
    assert all(len(row.cells) == 2 for row in panel.data_table_row_models())
    # First cell is the parsed connector; untagged lines show the em dash.
    connectors = {row[0] for row in rows}
    assert "codex" in connectors and "cursor" in connectors and "—" in connectors

    # Shared filter narrows to one connector's lines.
    panel.set_connector_filter("codex")
    filtered = panel.filtered_lines()
    assert len(filtered) == 1
    assert "connector=codex" in filtered[0]
    panel.set_connector_filter("")
    assert len(panel.filtered_lines()) == 3


def test_logs_hooks_filter_is_registered_and_reachable_via_cycle() -> None:
    assert FILTER_HOOKS in FILTER_PRESETS
    assert FILTER_LABELS[FILTER_HOOKS] == "Hooks"

    panel = LogsPanelModel()
    # Key 9 stays free for the global Audit panel hotkey, so Hooks is not
    # bound to a number key — it must remain reachable by cycling with f.
    assert panel.handle_key("9").handled is False
    seen: set[str] = set()
    for _ in range(len(FILTER_PRESETS)):
        panel.handle_key("f")
        seen.add(panel.filter_mode)
    assert FILTER_HOOKS in seen

    # The Hooks chip is rendered without a number shortcut to avoid
    # implying the conflicting 9 key.
    hooks_chip = next(chip for chip in panel.filter_chip_group().chips if chip.value == FILTER_HOOKS)
    assert hooks_chip.shortcut == ""


def test_render_otel_line_collapses_connector_hook_lifecycle_to_summary() -> None:
    """HOOK lifecycle rows should surface connector + decision, not a kv blob.

    Previously the line rendered every key in lifecycle.details — the
    nested ``details`` kv string ended up smashed in alongside actor,
    audit_id, action, target, producing one of those 200-character
    horror lines. Now we promote ``connector hook · decision · ms``
    so users can scroll the OTEL/HOOK tab and read it.
    """

    row = _v8_row(
        bucket="agent.lifecycle",
        event_name="agent.lifecycle.hook.completed",
        payload={
            "defenseclaw.hook.action": "connector-hook",
            "defenseclaw.hook.target": "SessionStart",
            "defenseclaw.hook.details": (
                "connector=codex action=allow severity=NONE mode=action "
                "would_block=false elapsed=22ms"
            ),
        },
    )

    line = render_otel_line(row)
    # Stream stays HOOK so the existing tab routing keeps working.
    assert "HOOK" in line
    # Connector + hook phase is the head of the line.
    assert "codex SessionStart" in line
    # Decision and elapsed are the trailing tokens. Severity=NONE was
    # filtered out because it's the default.
    assert "allow" in line
    assert "22ms" in line
    assert "severity=NONE" not in line
    # Mode=action is non-default so it's surfaced.
    assert "action" in line


def test_detail_pairs_expands_connector_hook_inner_kv_into_labelled_rows() -> None:
    """The nested kv ``details`` string is the most useful thing in a
    HOOK lifecycle row. Expand it into Connector/Decision/Elapsed rows
    so users don't have to read ``Detail: details=connector=…`` blobs.
    """

    row = _v8_row(
        bucket="agent.lifecycle",
        event_name="agent.lifecycle.hook.completed",
        payload={
            "defenseclaw.hook.action": "connector-hook",
            "defenseclaw.hook.target": "PreToolUse",
            "defenseclaw.hook.details": (
                "connector=cursor tool=Bash action=block severity=HIGH "
                "mode=enforce would_block=true elapsed=412ms reason=secret-detected "
                "raw_payload=<redacted len=8 sha=84ed0c96>"
            ),
        },
    )

    pairs = dict(detail_pairs(row))
    assert pairs["Connector"] == "cursor"
    assert pairs["Tool"] == "Bash"
    assert pairs["Decision"] == "block"
    assert pairs["Severity (decision)"] == "HIGH"
    assert pairs["Enforcement mode"] == "enforce"
    assert pairs["Would block"] == "yes"
    assert pairs["Elapsed"] == "412ms"
    assert pairs["Reason"] == "secret-detected"
    # raw_payload digest is translated, not shown as <redacted len=…>.
    assert pairs["Raw payload"] == "redacted · 8 bytes · sha:84ed0c96"
    # The opaque ``Detail: details=…`` line is suppressed for hook rows.
    assert "Detail: details" not in pairs
    assert "Detail: action" not in pairs
    assert "Detail: target" not in pairs


def test_detail_pairs_preserves_lifecycle_rendering_for_non_hook_rows() -> None:
    """Non-hook lifecycle rows (config reloads, server transitions)
    keep the ``Detail: <key>`` rendering they relied on before."""

    row = _v8_row(
        bucket="agent.lifecycle",
        event_name="config.reloaded",
        payload={
            "defenseclaw.config.path": "/etc/defenseclaw/config.yaml",
            "defenseclaw.config.generation": "7",
        },
    )
    pairs = dict(detail_pairs(row))
    assert pairs["Detail: path"] == "/etc/defenseclaw/config.yaml"
    assert pairs["Detail: generation"] == "7"
    assert "Connector" not in pairs
