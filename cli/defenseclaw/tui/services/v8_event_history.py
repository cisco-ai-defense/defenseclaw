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

from defenseclaw.alert_semantics import (
    ALERT_ACTIONABLE_SEVERITIES,
    ALERT_ALL_SEVERITIES,
    ALERT_LEGACY_FINDING_ACTIONS,
    ALERT_NON_ALLOW_OUTCOMES,
)
from defenseclaw.hook_metrics import aggregate_connector_hook_decision
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
_MAX_FINDING_TAGS_BYTES = 16 * 1024


def _sql_string_values(values: tuple[str, ...]) -> str:
    return ",".join(f"'{value}'" for value in values)


# Keep this vocabulary aligned with the canonical outcome registry. Successful
# terminal outcomes (allowed/applied/completed/etc.) deliberately stay out of
# the Alerts queue; these values require operator attention even when an older
# producer persisted the row with INFO severity.
V8_NON_ALLOW_OUTCOMES = frozenset(ALERT_NON_ALLOW_OUTCOMES)
V8_LEGACY_FINDING_ACTIONS = frozenset(ALERT_LEGACY_FINDING_ACTIONS)

_V8_ALERT_WHERE_SQL_TEMPLATE = """
    (
        (
            bucket = 'security.finding'
            AND event_name = 'finding.observed'
            AND UPPER(COALESCE(severity, 'INFO')) IN
                ({all_severities})
            AND NOT EXISTS (
                SELECT 1
                FROM json_each(
                    CASE
                        WHEN json_valid(COALESCE(payload_json, ''))
                         AND json_type(
                                 payload_json,
                                 '$."defenseclaw.finding.tags"'
                             ) = 'array'
                        THEN json_extract(
                            payload_json,
                            '$."defenseclaw.finding.tags"'
                        )
                        ELSE '[]'
                    END
                ) AS finding_tag
                WHERE LOWER(CAST(finding_tag.value AS TEXT)) = 'detection-only'
            )
            AND LOWER(
                COALESCE(
                    CASE
                        WHEN json_valid(COALESCE(payload_json, ''))
                        THEN json_extract(
                            payload_json,
                            '$."defenseclaw.finding.tags"'
                        )
                    END,
                    ''
                )
            ) <> 'detection-only'
        )
        OR (
            bucket IN ('enforcement.action', 'network.egress')
            AND LOWER(
                COALESCE(
                    CASE WHEN json_valid(COALESCE(payload_json, ''))
                         THEN json_extract(
                             payload_json,
                             '$."defenseclaw.enforcement.effective_action"'
                         ) END,
                    CASE WHEN json_valid(COALESCE(payload_json, ''))
                         THEN json_extract(
                             payload_json,
                             '$."defenseclaw.guardrail.decision"'
                         ) END,
                    CASE WHEN json_valid(COALESCE(payload_json, ''))
                         THEN json_extract(
                             payload_json,
                             '$."defenseclaw.network.decision"'
                         ) END,
                    CASE WHEN json_valid(COALESCE(payload_json, ''))
                         THEN json_extract(
                             payload_json,
                             '$."defenseclaw.network.policy_outcome"'
                         ) END,
                    CASE WHEN json_valid(COALESCE(payload_json, ''))
                         THEN json_extract(
                             payload_json,
                             '$."defenseclaw.scan.verdict"'
                         ) END,
                    CASE WHEN json_valid(COALESCE(projected_record_json, ''))
                         THEN json_extract(projected_record_json, '$.outcome') END,
                    action,
                    ''
                )
            ) IN (
                {non_allow_outcomes}
            )
        )
        OR (
            bucket IN ('platform.health', 'diagnostic')
            AND UPPER(COALESCE(severity, 'INFO')) IN ('CRITICAL','HIGH','ERROR')
        )
        OR (
            bucket IS NULL
            AND (
                (
                    UPPER(COALESCE(severity, 'INFO')) IN
                        ({all_severities})
                    AND LOWER(COALESCE(action, '')) IN (
                        {legacy_finding_actions}
                    )
                )
                OR LOWER(COALESCE(action, '')) IN (
                    {non_allow_outcomes}
                )
                OR LOWER(COALESCE(action, '')) LIKE '%-failure'
                OR LOWER(COALESCE(action, '')) LIKE '%-failed'
                OR dc_hook_decision(
                    COALESCE(details, ''),
                    {structured_json},
                    {enforced}
                ) = 'block'
            )
        )
    )
"""


def _v8_alert_where_sql(columns: frozenset[str]) -> str:
    """Build legacy-compatible alert SQL from the columns actually present."""

    return _V8_ALERT_WHERE_SQL_TEMPLATE.format(
        structured_json="structured_json" if "structured_json" in columns else "NULL",
        enforced="enforced" if "enforced" in columns else "NULL",
        all_severities=_sql_string_values(ALERT_ALL_SEVERITIES),
        non_allow_outcomes=_sql_string_values(ALERT_NON_ALLOW_OUTCOMES),
        legacy_finding_actions=_sql_string_values(ALERT_LEGACY_FINDING_ACTIONS),
    )


# Alert windows are bounded, but the default panel intentionally prioritizes
# actionable records.  Canonical non-allow enforcement and legacy explicit
# blocks are displayed as HIGH when their outer severity is INFO; network
# egress INFO remains WARNING and therefore does not consume this priority
# lane.
_V8_ACTIONABLE_ALERT_WHERE_SQL = f"""
    (
        UPPER(COALESCE(severity, 'INFO')) IN (
            {_sql_string_values(ALERT_ACTIONABLE_SEVERITIES)}
        )
        OR (
            bucket = 'enforcement.action'
            AND UPPER(COALESCE(severity, 'INFO')) = 'INFO'
        )
        OR (
            bucket IS NULL
            AND UPPER(COALESCE(severity, 'INFO')) = 'INFO'
        )
    )
"""

_V8_SELECT_COLUMNS_TEMPLATE = """
    id, timestamp, COALESCE(bucket,''), COALESCE(event_name,''),
    COALESCE(source,''), COALESCE(severity,''), COALESCE(action,''),
    COALESCE(actor,''), COALESCE(details,''), COALESCE(connector,''),
    COALESCE(redaction_profile,''), COALESCE(run_id,''),
    COALESCE(trace_id,''), COALESCE(request_id,''),
    COALESCE(session_id,''), COALESCE(turn_id,''),
    COALESCE(scan_id,''), COALESCE(finding_id,''),
    substr(COALESCE(projected_record_json,''), 1, ?),
    length(COALESCE(projected_record_json,'')),
    substr(COALESCE(payload_json,''), 1, ?),
    length(COALESCE(payload_json,'')),
    substr(
        COALESCE(
            CASE WHEN json_valid(COALESCE(payload_json, ''))
                 THEN json_extract(
                     payload_json,
                     '$."defenseclaw.finding.tags"'
                 ) END,
            '[]'
        ),
        1,
        ?
    ),
    length(
        COALESCE(
            CASE WHEN json_valid(COALESCE(payload_json, ''))
                 THEN json_extract(
                     payload_json,
                     '$."defenseclaw.finding.tags"'
                 ) END,
            '[]'
        )
    ),
    CASE
        WHEN bucket IS NULL
         AND LOWER(COALESCE(action, '')) = 'connector-hook'
        THEN dc_hook_decision(
            COALESCE(details, ''),
            {structured_json},
            {enforced}
        )
        ELSE ''
    END
"""


def _v8_select_columns(columns: frozenset[str]) -> str:
    """Project a normalized hook decision without retaining legacy payloads."""

    return _V8_SELECT_COLUMNS_TEMPLATE.format(
        structured_json="structured_json" if "structured_json" in columns else "NULL",
        enforced="enforced" if "enforced" in columns else "NULL",
    )


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
    finding_tags: tuple[str, ...] = ()
    hook_decision: str = ""


class V8EventHistoryReader:
    """Connection-scoped canonical history reader with a cached schema probe."""

    def __init__(self, store: object) -> None:
        self.db = getattr(store, "db", None)
        self._supported: bool | None = None
        self._schema_version: int | None = None
        self._has_ack_projection = False
        self._columns: frozenset[str] = frozenset()
        if self.db is not None:
            self.db.create_function(
                "dc_hook_decision",
                3,
                aggregate_connector_hook_decision,
            )

    def load(self, limit: int = 500) -> tuple[V8EventHistoryRow, ...]:
        """Read newest rows, raising SQLite errors to the repository owner."""

        return self._load(limit, alert_only=False)

    def load_alerts(self, limit: int = 500) -> tuple[V8EventHistoryRow, ...]:
        """Read newest alert-eligible rows before applying the row bound.

        Filtering in SQLite prevents high-volume clean hook/scan telemetry
        from consuming the bounded Alerts window. The Python projection still
        validates every returned row as a defense-in-depth compatibility gate.
        """

        return self._load(limit, alert_only=True)

    def load_views(
        self,
        history_limit: int = 1000,
        alert_limit: int = 500,
    ) -> tuple[
        tuple[V8EventHistoryRow, ...],
        tuple[V8EventHistoryRow, ...],
    ]:
        """Read generic and alert-filtered histories in one SQLite snapshot."""

        if not self._schema_is_supported():
            return (), ()
        bounded_history = self._bounded_limit(history_limit)
        bounded_alerts = self._bounded_limit(alert_limit)
        ack_filter = self._alert_ack_filter_sql()
        alert_where = _v8_alert_where_sql(self._columns)
        select_columns = _v8_select_columns(self._columns)
        rows = self.db.execute(
            f"""SELECT * FROM (
               WITH history AS (
                   SELECT rowid AS dc_rowid, {select_columns}
                   FROM audit_events
                   WHERE signal = 'logs' AND bucket IS NOT NULL AND bucket <> ''
                   ORDER BY timestamp DESC, rowid DESC LIMIT ?
               ), newest_alerts AS (
                   SELECT rowid AS dc_rowid, timestamp AS dc_timestamp,
                          0 AS dc_priority
                   FROM audit_events
                   WHERE (
                           (signal = 'logs' AND bucket IS NOT NULL AND bucket <> '')
                           OR bucket IS NULL
                       )
                     AND {alert_where}
                     {ack_filter}
                   ORDER BY timestamp DESC, rowid DESC LIMIT ?
               ), actionable_alerts AS (
                   SELECT rowid AS dc_rowid, timestamp AS dc_timestamp,
                          1 AS dc_priority
                   FROM audit_events
                   WHERE (
                           (signal = 'logs' AND bucket IS NOT NULL AND bucket <> '')
                           OR bucket IS NULL
                       )
                     AND {alert_where}
                     AND {_V8_ACTIONABLE_ALERT_WHERE_SQL}
                     {ack_filter}
                   ORDER BY timestamp DESC, rowid DESC LIMIT ?
               ), selected_alerts AS (
                   SELECT dc_rowid, MAX(dc_priority) AS dc_priority,
                          MAX(dc_timestamp) AS dc_timestamp
                   FROM (
                       SELECT * FROM newest_alerts
                       UNION ALL
                       SELECT * FROM actionable_alerts
                   )
                   GROUP BY dc_rowid
                   ORDER BY dc_priority DESC, dc_timestamp DESC, dc_rowid DESC
                   LIMIT ?
               ), alerts AS (
                   SELECT audit_events.rowid AS dc_rowid, {select_columns}
                   FROM audit_events
                   JOIN selected_alerts
                     ON selected_alerts.dc_rowid = audit_events.rowid
               )
               SELECT * FROM (
                   SELECT 0 AS dc_view, history.* FROM history
                   UNION ALL
                   SELECT 1 AS dc_view, alerts.* FROM alerts
               )
               )
               ORDER BY dc_view, timestamp DESC, dc_rowid DESC""",
            (
                _MAX_PAYLOAD_BYTES,
                _MAX_PAYLOAD_BYTES,
                _MAX_FINDING_TAGS_BYTES,
                bounded_history,
                bounded_alerts,
                bounded_alerts,
                bounded_alerts,
                _MAX_PAYLOAD_BYTES,
                _MAX_PAYLOAD_BYTES,
                _MAX_FINDING_TAGS_BYTES,
            ),
        ).fetchall()
        history_rows = [tuple(row[2:]) for row in rows if int(row[0]) == 0]
        alert_rows = [tuple(row[2:]) for row in rows if int(row[0]) == 1]
        return (
            _decode_v8_event_history_rows(history_rows),
            _decode_v8_event_history_rows(alert_rows),
        )

    @staticmethod
    def _bounded_limit(limit: int) -> int:
        return max(1, min(int(limit), _MAX_ROWS))

    def _schema_is_supported(self) -> bool:
        if self.db is None:
            return False
        schema_version = int(self.db.execute("PRAGMA schema_version").fetchone()[0])
        if self._supported is None or schema_version != self._schema_version:
            columns = {str(row[1]) for row in self.db.execute("PRAGMA table_info(audit_events)").fetchall()}
            tables = {
                str(row[0]) for row in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            }
            self._supported = _REQUIRED_COLUMNS.issubset(columns)
            self._columns = frozenset(columns)
            self._has_ack_projection = "alert_acknowledgement_projection" in tables
            self._schema_version = schema_version
        return bool(self._supported)

    def _alert_ack_filter_sql(self) -> str:
        if not self._has_ack_projection:
            return ""
        return """AND NOT EXISTS (
            SELECT 1
            FROM alert_acknowledgement_projection AS projection
            WHERE projection.alert_id = audit_events.id
        )"""

    def _load(
        self,
        limit: int,
        *,
        alert_only: bool,
    ) -> tuple[V8EventHistoryRow, ...]:
        """Read a bounded canonical-history view."""

        if not self._schema_is_supported():
            return ()
        bounded = self._bounded_limit(limit)
        select_columns = _v8_select_columns(self._columns)
        if alert_only:
            alert_where = _v8_alert_where_sql(self._columns)
            alert_scope = f"""(
                (signal = 'logs' AND bucket IS NOT NULL AND bucket <> '')
                OR bucket IS NULL
            ) AND {alert_where} {self._alert_ack_filter_sql()}"""
            rows = self.db.execute(
                f"""WITH newest_alerts AS (
                       SELECT rowid AS dc_rowid, timestamp AS dc_timestamp,
                              0 AS dc_priority
                       FROM audit_events
                       WHERE {alert_scope}
                       ORDER BY timestamp DESC, rowid DESC LIMIT ?
                   ), actionable_alerts AS (
                       SELECT rowid AS dc_rowid, timestamp AS dc_timestamp,
                              1 AS dc_priority
                       FROM audit_events
                       WHERE {alert_scope}
                         AND {_V8_ACTIONABLE_ALERT_WHERE_SQL}
                       ORDER BY timestamp DESC, rowid DESC LIMIT ?
                   ), selected_alerts AS (
                       SELECT dc_rowid, MAX(dc_priority) AS dc_priority,
                              MAX(dc_timestamp) AS dc_timestamp
                       FROM (
                           SELECT * FROM newest_alerts
                           UNION ALL
                           SELECT * FROM actionable_alerts
                       )
                       GROUP BY dc_rowid
                       ORDER BY dc_priority DESC, dc_timestamp DESC, dc_rowid DESC
                       LIMIT ?
                   )
                   SELECT {select_columns}
                   FROM audit_events
                   JOIN selected_alerts
                     ON selected_alerts.dc_rowid = audit_events.rowid
                   ORDER BY timestamp DESC, audit_events.rowid DESC""",
                (
                    bounded,
                    bounded,
                    bounded,
                    _MAX_PAYLOAD_BYTES,
                    _MAX_PAYLOAD_BYTES,
                    _MAX_FINDING_TAGS_BYTES,
                ),
            ).fetchall()
            return _decode_v8_event_history_rows(rows)
        else:
            where = "signal = 'logs' AND bucket IS NOT NULL AND bucket <> ''"
        rows = self.db.execute(
            f"""SELECT {select_columns}
               FROM audit_events
               WHERE {where}
               ORDER BY timestamp DESC, rowid DESC LIMIT ?""",
            (
                _MAX_PAYLOAD_BYTES,
                _MAX_PAYLOAD_BYTES,
                _MAX_FINDING_TAGS_BYTES,
                bounded,
            ),
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


def load_v8_alert_history(
    store: object | None,
    limit: int = 500,
) -> tuple[V8EventHistoryRow, ...]:
    """Read a bounded canonical Alerts view from an already-open Store."""

    if store is None:
        return ()
    try:
        return V8EventHistoryReader(store).load_alerts(limit)
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
        finding_tags = _decode_finding_tags(row[22], row[23])
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
                finding_tags=finding_tags,
                hook_decision=str(row[24] or ""),
            )
        )
    return tuple(result)


def _decode_finding_tags(raw_value: Any, raw_length: Any) -> tuple[str, ...]:
    """Decode the independently bounded finding-tag field.

    Tags remain available even when a large evidence payload is intentionally
    not decoded, which keeps detection-only findings out of Alerts without
    loading their evidence blobs.
    """

    raw = str(raw_value or "")
    if not raw or int(raw_length or 0) > _MAX_FINDING_TAGS_BYTES:
        return ()
    try:
        decoded = json.loads(raw)
    except (TypeError, ValueError):
        decoded = raw
    if isinstance(decoded, list):
        values = decoded
    elif isinstance(decoded, str):
        values = [decoded]
    else:
        return ()
    return tuple(normalized for value in values if (normalized := str(value).strip().lower()))


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
