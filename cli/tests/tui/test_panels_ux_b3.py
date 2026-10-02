# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""TUI panels UX batch 3: alerts decision, audit detail/filters, logs follow, mutations, sandboxes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from defenseclaw.models import Event
from defenseclaw.tui.panels.activity import ActivityPanelModel, activity_mutations_from_v8_history
from defenseclaw.tui.panels.alerts import AlertEvent, AlertsPanelModel, _alert_details_label
from defenseclaw.tui.panels.audit import AUDIT_LOAD_LIMIT, AuditPanelModel, with_older_blocks
from defenseclaw.tui.panels.logs import LogsPanelModel
from defenseclaw.tui.services.v8_event_history import V8EventHistoryRow

_T0 = datetime(2026, 10, 2, 9, 0, tzinfo=timezone.utc)


def _v8(row_id: str, bucket: str, event_name: str, payload: dict, **extra) -> V8EventHistoryRow:
    return V8EventHistoryRow(
        id=row_id,
        timestamp=_T0,
        bucket=bucket,
        event_name=event_name,
        source="gateway",
        severity=extra.pop("severity", "CRITICAL"),
        action=extra.pop("action", "scan-finding"),
        actor="audit_logger",
        details=event_name,
        connector="claudecode",
        redaction_profile="",
        payload=payload,
        **extra,
    )


def test_alert_finding_names_its_decision_on_first_load_and_in_observe_mode() -> None:
    finding = _v8(
        "f1",
        "security.finding",
        "finding.observed",
        {"defenseclaw.evaluation.id": "ev1", "defenseclaw.finding.rule_id": "R1-MARKER-BLOCK"},
    )
    decision = _v8(
        "d1",
        "guardrail.evaluation",
        "hook.decision",
        {"defenseclaw.evaluation.id": "ev1", "defenseclaw.guardrail.effective_action": "block"},
        action="connector-hook",
    )
    model = AlertsPanelModel()
    # GAP-0999: the panel's own load path gets the decision context too.
    model.apply_v8_history((finding,), (decision,))
    assert ("Decision", "block") in model.audit_events[0].facts
    # GAP-1324: a summary-less finding row names its rule, not "finding.observed".
    assert _alert_details_label(model.audit_events[0]) == "R1-MARKER-BLOCK"

    # GAP-1213: an observe-mode match (action=allow raw_action=block) reads
    # "would block", replacing the evaluation's raw "allow".
    observed = "connector=claudecode result=ok action=allow raw_action=block mode=observe"
    model.store = SimpleNamespace(hook_details_for_alerts=lambda ids: {ids[0]: [observed]})
    model.set_events(
        [AlertEvent(id="f2", severity="CRITICAL", action="scan-finding", target="", facts=(("Decision", "allow"),))]
    )
    model.cursor = 0
    info = model.get_detail_info()
    assert info is not None
    assert dict(info.event.facts)["Decision"] == "would block (observe mode, allowed)"


def test_audit_detail_filters_and_window() -> None:
    hook_block = Event(
        id="h1",
        timestamp=_T0,
        action="connector-hook",
        target="PreToolUse",
        severity="INFO",
        connector="claudecode",
        details="connector=claudecode result=ok action=block raw_action=block severity=CRITICAL mode=action",
        structured={"defenseclaw.guardrail.decision": "none", "defenseclaw.guardrail.mode": "enforce"},
    )
    allow = Event(
        id="a1",
        timestamp=_T0,
        action="connector-hook",
        target="Stop",
        severity="INFO",
        connector="claudecode",
        details="connector=claudecode result=ok action=allow severity=NONE mode=action would_block=false",
    )
    panel = AuditPanelModel()
    panel.set_events([hook_block, allow])

    # GAP-1215: one Connector and one Decision, and "block", not "none".
    panel.cursor = 0
    labels = [label for label, _value in panel.detail_pairs()]
    pairs = dict(panel.detail_pairs())
    assert labels.count("Connector") == 1 and labels.count("Decision") == 1
    assert pairs["Decision"] == "block"
    # GAP-1323: the blocked row shows its CRITICAL severity; Risk drops the INFO allow row.
    assert panel.row_views()[0].severity_label == "CRITICAL"
    panel.set_common_filter("risk")
    assert [event.id for event in panel.filtered] == ["h1"]

    # GAP-1355: blocks older than the newest-500 window are still loaded, and
    # the summary says how far back the rest reaches.
    newest = [
        Event(id=f"n{index}", timestamp=_T0 - timedelta(seconds=index), action="ai_discovery", severity="INFO")
        for index in range(AUDIT_LOAD_LIMIT)
    ]
    old_block = Event(id="old", timestamp=_T0 - timedelta(hours=3), action="block-mcp", severity="HIGH")
    store = SimpleNamespace(list_block_event_summaries=lambda limit: [old_block])
    panel = AuditPanelModel()
    panel.set_events(with_older_blocks(store, newest))
    panel.set_common_filter("blocks")
    assert [event.id for event in panel.filtered] == ["old"]
    assert "+ all blocks; older: defenseclaw audit export" in panel.toolbar_state().summary_label


def test_logs_source_switch_opens_live_at_the_tail() -> None:
    panel = LogsPanelModel()
    panel.source = "gateway"
    panel.lines["gateway"] = [f"line {index}" for index in range(30)]
    panel.handle_key("k")
    assert panel.paused
    # GAP-1216: G follows the tail again, and switching sources keeps LIVE.
    panel.handle_key("G")
    assert not panel.paused
    panel.handle_key("l")
    assert panel.source != "gateway" and not panel.paused
    panel.handle_key("h")
    assert panel.source == "gateway" and not panel.paused
    assert panel.table_cursor_row() == 29


def test_cli_setting_change_is_a_mutation_that_names_the_field() -> None:
    from defenseclaw.logger import Logger

    sent: list[dict] = []
    logger = Logger.__new__(Logger)
    logger._emit = sent.append  # type: ignore[attr-defined]
    # GAP-1217 / GAP-1325: guardrail mode and block-at land as named diffs.
    logger.log_config_change("guardrail-mode", "scope=global mode=action previous=observe cleared=false")
    activity = sent[0]["activity"]
    assert activity["action"] == "config-update"
    assert activity["target_id"] == "guardrail-mode:global"
    assert activity["diff"] == [{"path": "mode", "op": "replace", "after": "action", "before": "observe"}]

    row = V8EventHistoryRow(
        id="m1",
        timestamp=_T0,
        bucket="compliance.activity",
        event_name="config.change.applied",
        source="cli",
        severity="INFO",
        action="config-update",
        actor="cli",
        details="config.change.applied",
        connector="",
        redaction_profile="",
        payload={
            "defenseclaw.admin.actor_ref": "cli:operator",
            "defenseclaw.admin.target_ref": "config:guardrail-mode:global",
            "defenseclaw.admin.diff": '[{"path":"mode","op":"replace","before":"observe","after":"action"}]',
        },
    )
    model = ActivityPanelModel()
    model.apply_mutations(activity_mutations_from_v8_history((row,)))
    model.set_tab("mutations")
    assert "config:guardrail-mode:global  mode: observe -> action" in model.render_text(height=24)
