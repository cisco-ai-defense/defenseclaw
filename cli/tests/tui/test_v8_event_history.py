# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Canonical v8 SQLite read-path coverage for Textual panels."""

from __future__ import annotations

import json
import sqlite3
from types import SimpleNamespace

from defenseclaw.tui.panels.activity import ActivityPanelModel
from defenseclaw.tui.panels.alerts import AlertsPanelModel
from defenseclaw.tui.panels.logs import LogsPanelModel
from defenseclaw.tui.services.v8_event_history import (
    V8EventHistoryReader,
    load_v8_egress_events,
    load_v8_event_history,
)

_AUDIT_EVENTS_SCHEMA = """CREATE TABLE audit_events (
    id TEXT PRIMARY KEY, timestamp TEXT, bucket TEXT, event_name TEXT,
    source TEXT, signal TEXT, severity TEXT, action TEXT, actor TEXT,
    details TEXT, connector TEXT, redaction_profile TEXT, run_id TEXT,
    trace_id TEXT, request_id TEXT, session_id TEXT, turn_id TEXT,
    scan_id TEXT, finding_id TEXT, payload_json TEXT, projected_record_json TEXT
)"""


def _store() -> SimpleNamespace:
    db = sqlite3.connect(":memory:")
    db.execute(_AUDIT_EVENTS_SCHEMA)
    rows = (
        (
            "config-1", "2026-07-07T12:00:00Z", "compliance.activity", "config.change.applied",
            "gateway", "logs", "INFO", "config.change", "operator:alice", "applied", "codex", "none",
            "run-1", "trace-1", "req-1", "session-1", "turn-1", "", "",
            {"defenseclaw.config.path": "observability.destinations.collector",
             "defenseclaw.config.generation": 8},
        ),
        (
            "finding-1", "2026-07-07T12:00:01Z", "security.finding", "finding.observed",
            "skill_scanner", "logs", "HIGH", "finding.observed", "defenseclaw", "unsafe capability",
            "codex", "none", "run-1", "trace-1", "req-1", "session-1", "turn-1", "scan-1", "finding-1",
            {"defenseclaw.finding.rule_id": "SKILL-001", "defenseclaw.finding.target_ref": "skill:demo",
             "defenseclaw.security.severity": "HIGH", "defenseclaw.finding.description": "unsafe capability"},
        ),
        (
            "egress-1", "2026-07-07T12:00:02Z", "network.egress", "egress.allowed",
            "gateway", "logs", "INFO", "egress.allowed", "defenseclaw", "shape bypass", "codex", "none",
            "run-1", "trace-1", "req-1", "session-1", "turn-1", "", "",
            {"defenseclaw.network.target_ref": "api.example.test",
             "defenseclaw.network.target_path": "/v1/chat", "defenseclaw.network.looks_like_llm": True,
             "defenseclaw.network.branch": "shape", "defenseclaw.network.decision": "allow"},
        ),
    )
    db.executemany(
        """INSERT INTO audit_events VALUES (
            ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?
        )""",
        [
            (
                *row[:-1],
                json.dumps(row[-1]),
                json.dumps(
                    {
                        "outcome": "allowed",
                        "correlation": {"trace_id": row[13], "span_id": "0123456789abcdef"},
                    }
                ),
            )
            for row in rows
        ],
    )
    db.commit()
    return SimpleNamespace(db=db)


def test_v8_panels_read_canonical_sqlite_without_gateway_jsonl(tmp_path) -> None:
    store = _store()
    history = load_v8_event_history(store)
    assert [row.id for row in history] == ["egress-1", "finding-1", "config-1"]
    assert history[0].trace_id == "trace-1"
    assert history[0].span_id == "0123456789abcdef"

    logs = LogsPanelModel(tmp_path, store=store)
    logs.refresh()
    assert {row.event_type for row in logs.verdict_rows} == {"scan_finding"}
    assert any("security.finding" in line and "finding.observed" in line for line in logs.lines["otel"])
    assert logs.header_state().redaction.visible is False

    activity = ActivityPanelModel(tmp_path, store=store)
    activity.load_mutations()
    assert [row.action for row in activity.mutations] == ["config.change"]
    assert activity.mutations[0].target_id == "observability.destinations.collector"

    egress = load_v8_egress_events(store)
    assert len(egress) == 1
    assert egress[0].looks_like_llm is True
    assert egress[0].branch == "shape"


def test_exact_v8_alerts_do_not_reingest_retired_jsonl(tmp_path) -> None:
    (tmp_path / "gateway.jsonl").write_text(
        '{"ts":"2026-07-07T12:00:00Z","event_type":"egress",'
        '"egress":{"target_host":"stale.example","decision":"allow","branch":"shape"}}\n'
    )
    model = AlertsPanelModel(tmp_path)
    model.refresh_gateway_scans()
    assert model.egress_events == []
    assert model.scan_blocks == []


def test_reader_treats_partial_schema_as_unsupported_without_querying_missing_columns() -> None:
    db = sqlite3.connect(":memory:")
    db.execute(
        """CREATE TABLE audit_events (
            bucket TEXT, event_name TEXT, source TEXT, signal TEXT,
            payload_json TEXT, projected_record_json TEXT, redaction_profile TEXT
        )"""
    )
    reader = V8EventHistoryReader(SimpleNamespace(db=db))

    assert reader.load() == ()


def test_reader_reprobes_unsupported_schema_after_migration() -> None:
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE audit_events (id TEXT PRIMARY KEY)")
    reader = V8EventHistoryReader(SimpleNamespace(db=db))
    assert reader.load() == ()

    db.execute("DROP TABLE audit_events")
    db.execute(_AUDIT_EVENTS_SCHEMA)
    db.execute(
        """INSERT INTO audit_events
               (id, timestamp, bucket, event_name, source, signal,
                redaction_profile, payload_json, projected_record_json)
           VALUES ('migrated', '2026-07-10T00:00:00Z', 'platform.health',
                   'health.ready', 'gateway', 'logs', 'none', '{}', '{}')"""
    )
    db.commit()

    assert [row.id for row in reader.load()] == ["migrated"]
