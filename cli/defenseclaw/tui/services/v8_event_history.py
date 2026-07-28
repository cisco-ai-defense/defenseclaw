# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Bounded, read-only adapter for the canonical v8 SQLite event history.

The gateway owns the schema and writes immutable local projections into the
additive ``audit_events`` columns.  TUI panels use this adapter instead of the
retired production ``gateway.jsonl`` side channel.  It never initializes or
migrates the database and returns an empty snapshot for a partial schema.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from defenseclaw.tui.services.event_models import EgressEvent, parse_timestamp

_REQUIRED_COLUMNS = frozenset(
    {
        "id",
        "timestamp",
        "bucket",
        "event_name",
        "source",
        "signal",
        "severity",
        "action",
        "actor",
        "details",
        "connector",
        "payload_json",
        "projected_record_json",
        "redaction_profile",
        "run_id",
        "trace_id",
        "request_id",
        "session_id",
        "turn_id",
        "scan_id",
        "finding_id",
    }
)
_MAX_ROWS = 1000
_MAX_PAYLOAD_BYTES = 64 * 1024


@dataclass(frozen=True)
class V8EventHistoryRow:
    id: str
    timestamp: datetime | None
    bucket: str
    event_name: str
    source: str
    severity: str
    action: str
    actor: str
    details: str
    connector: str
    redaction_profile: str
    run_id: str = ""
    trace_id: str = ""
    span_id: str = ""
    request_id: str = ""
    session_id: str = ""
    turn_id: str = ""
    scan_id: str = ""
    finding_id: str = ""
    outcome: str = ""
    payload: Mapping[str, Any] = field(default_factory=dict)
    payload_truncated: bool = False


class V8EventHistoryReader:
    """Connection-scoped canonical history reader with a cached schema probe."""

    def __init__(self, store: object) -> None:
        self.db = getattr(store, "db", None)
        self._supported: bool | None = None
        self._schema_version: int | None = None

    def load(self, limit: int = 500) -> tuple[V8EventHistoryRow, ...]:
        """Read newest rows, raising SQLite errors to the repository owner."""

        if self.db is None:
            return ()
        schema_version = int(self.db.execute("PRAGMA schema_version").fetchone()[0])
        if self._supported is None or schema_version != self._schema_version:
            columns = {
                str(row[1])
                for row in self.db.execute("PRAGMA table_info(audit_events)").fetchall()
            }
            self._supported = _REQUIRED_COLUMNS.issubset(columns)
            self._schema_version = schema_version
        if not self._supported:
            return ()
        bounded = max(1, min(int(limit), _MAX_ROWS))
        rows = self.db.execute(
            """SELECT id, timestamp, COALESCE(bucket,''), COALESCE(event_name,''),
                      COALESCE(source,''), COALESCE(severity,''), COALESCE(action,''),
                      COALESCE(actor,''), COALESCE(details,''), COALESCE(connector,''),
                      COALESCE(redaction_profile,''), COALESCE(run_id,''),
                      COALESCE(trace_id,''), COALESCE(request_id,''),
                      COALESCE(session_id,''), COALESCE(turn_id,''),
                      COALESCE(scan_id,''), COALESCE(finding_id,''),
                      substr(COALESCE(projected_record_json,''), 1, ?),
                      length(COALESCE(projected_record_json,'')),
                      substr(COALESCE(payload_json,''), 1, ?),
                      length(COALESCE(payload_json,''))
               FROM audit_events
               WHERE signal = 'logs' AND bucket IS NOT NULL AND bucket <> ''
               ORDER BY timestamp DESC, rowid DESC LIMIT ?""",
            (_MAX_PAYLOAD_BYTES, _MAX_PAYLOAD_BYTES, bounded),
        ).fetchall()
        return _decode_v8_event_history_rows(rows)


def load_v8_event_history(store: object | None, limit: int = 500) -> tuple[V8EventHistoryRow, ...]:
    """Read newest canonical log projections from an already-open Store.

    Compatibility callers retain the historical empty-on-error behavior.  The
    TUI read repository uses :class:`V8EventHistoryReader` directly so it can
    preserve a last-known-good snapshot and report a stale/error state.
    """

    if store is None:
        return ()
    try:
        return V8EventHistoryReader(store).load(limit)
    except Exception:  # noqa: BLE001 - partial/locked DBs degrade to an empty snapshot.
        return ()


def _decode_v8_event_history_rows(rows: list[tuple[Any, ...]]) -> tuple[V8EventHistoryRow, ...]:
    result: list[V8EventHistoryRow] = []
    for row in rows:
        raw_projection = str(row[18] or "")
        outcome = ""
        span_id = ""
        if raw_projection and int(row[19] or 0) <= _MAX_PAYLOAD_BYTES:
            try:
                projection = json.loads(raw_projection)
            except (TypeError, ValueError):
                projection = None
            if isinstance(projection, Mapping):
                outcome = payload_text(projection, "outcome")
                correlation = projection.get("correlation")
                if isinstance(correlation, Mapping):
                    span_id = payload_text(correlation, "span_id")
        raw_payload = str(row[20] or "")
        payload: Mapping[str, Any] = {}
        if raw_payload and int(row[21] or 0) <= _MAX_PAYLOAD_BYTES:
            try:
                decoded = json.loads(raw_payload)
            except (TypeError, ValueError):
                decoded = None
            if isinstance(decoded, Mapping):
                payload = decoded
        result.append(
            V8EventHistoryRow(
                id=str(row[0] or ""),
                timestamp=parse_timestamp(row[1]),
                bucket=str(row[2] or ""),
                event_name=str(row[3] or ""),
                source=str(row[4] or ""),
                severity=str(row[5] or ""),
                action=str(row[6] or ""),
                actor=str(row[7] or ""),
                details=str(row[8] or ""),
                connector=str(row[9] or ""),
                redaction_profile=str(row[10] or ""),
                run_id=str(row[11] or ""),
                trace_id=str(row[12] or ""),
                span_id=span_id,
                request_id=str(row[13] or ""),
                session_id=str(row[14] or ""),
                turn_id=str(row[15] or ""),
                scan_id=str(row[16] or ""),
                finding_id=str(row[17] or ""),
                outcome=outcome,
                payload=payload,
                payload_truncated=int(row[21] or 0) > _MAX_PAYLOAD_BYTES,
            )
        )
    return tuple(result)


def payload_text(payload: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (str, int, float)):
            text = str(value).strip()
            if text:
                return text
    return ""


def load_v8_egress_events(store: object | None, limit: int = 500) -> tuple[EgressEvent, ...]:
    """Project canonical network-egress logs for alerts/Overview counters."""

    return project_v8_egress_events(load_v8_event_history(store, limit=limit))


def project_v8_egress_events(
    rows: tuple[V8EventHistoryRow, ...],
) -> tuple[EgressEvent, ...]:
    """Project network-egress events from an existing history snapshot."""

    events: list[EgressEvent] = []
    for row in rows:
        if row.bucket != "network.egress":
            continue
        events.append(
            EgressEvent(
                timestamp=row.timestamp,
                target_host=payload_text(row.payload, "defenseclaw.network.target_ref"),
                target_path=payload_text(row.payload, "defenseclaw.network.target_path"),
                body_shape=payload_text(row.payload, "defenseclaw.network.body_shape"),
                looks_like_llm=payload_text(
                    row.payload,
                    "defenseclaw.network.looks_like_llm",
                ).lower()
                == "true",
                branch=payload_text(row.payload, "defenseclaw.network.branch"),
                decision=payload_text(
                    row.payload,
                    "defenseclaw.network.decision",
                    "defenseclaw.network.policy_outcome",
                ),
                reason=payload_text(row.payload, "defenseclaw.network.reason"),
                source=payload_text(row.payload, "defenseclaw.network.source") or row.source,
            )
        )
    return tuple(events)
