#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Validate canonical observability-v8 JSONL destination output."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

REQUIRED_FIELDS = {
    "schema_version",
    "bucket_catalog_version",
    "timestamp",
    "record_id",
    "bucket",
    "signal",
    "event_name",
    "source",
    "correlation",
    "provenance",
    "field_classes",
}
BUCKETS = {
    "compliance.activity",
    "security.finding",
    "guardrail.evaluation",
    "enforcement.action",
    "model.io",
    "tool.activity",
    "asset.scan",
    "asset.lifecycle",
    "network.egress",
    "agent.lifecycle",
    "ai.discovery",
    "telemetry.ingest",
    "platform.health",
    "diagnostic",
}
SIGNALS = {"logs", "traces", "metrics"}
SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
STABLE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
UUID_V4 = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)


def _parse_rfc3339_nano(value: str) -> datetime | None:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    fractional = re.match(r"^(.*\.\d{1,6})\d*([-+].*)?$", normalized)
    if fractional:
        normalized = fractional.group(1) + (fractional.group(2) or "")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def validate_record(
    line_no: int,
    raw: str,
    *,
    timestamp_min: datetime | None,
    timestamp_max: datetime | None,
    require_uuid_request_id: bool,
) -> tuple[list[str], str | None, str | None]:
    errors: list[str] = []
    try:
        record = json.loads(raw)
    except json.JSONDecodeError as exc:
        return [f"line {line_no}: invalid JSON: {exc}"], None, None
    if not isinstance(record, dict):
        return [f"line {line_no}: expected JSON object, got {type(record).__name__}"], None, None

    missing = REQUIRED_FIELDS - record.keys()
    if missing:
        errors.append(f"line {line_no}: missing canonical fields: {sorted(missing)}")

    if record.get("schema_version") != 1:
        errors.append(f"line {line_no}: schema_version must equal 1")
    if record.get("bucket_catalog_version") != 1:
        errors.append(f"line {line_no}: bucket_catalog_version must equal 1")

    timestamp = record.get("timestamp")
    if not isinstance(timestamp, str) or (parsed := _parse_rfc3339_nano(timestamp)) is None:
        errors.append(f"line {line_no}: timestamp is not RFC3339")
    else:
        if timestamp_min is not None and parsed < timestamp_min:
            errors.append(f"line {line_no}: timestamp precedes the allowed window")
        if timestamp_max is not None and parsed > timestamp_max:
            errors.append(f"line {line_no}: timestamp exceeds the allowed window")

    if not _nonempty_string(record.get("record_id")):
        errors.append(f"line {line_no}: record_id must be a non-empty string")
    if record.get("bucket") not in BUCKETS:
        errors.append(f"line {line_no}: unknown bucket={record.get('bucket')!r}")
    signal = record.get("signal")
    if signal not in SIGNALS:
        errors.append(f"line {line_no}: unknown signal={signal!r}")
    event_name = record.get("event_name")
    if not _nonempty_string(event_name) or not STABLE_TOKEN.fullmatch(event_name):
        errors.append(f"line {line_no}: event_name is not canonical")
        event_name = None
    if not _nonempty_string(record.get("source")) or not STABLE_TOKEN.fullmatch(record["source"]):
        errors.append(f"line {line_no}: source is not canonical")

    severity = record.get("severity")
    if severity is not None and severity not in SEVERITIES:
        errors.append(f"line {line_no}: unknown severity={severity!r}")
    if signal == "logs" and type(record.get("mandatory")) is not bool:
        errors.append(f"line {line_no}: log record requires boolean mandatory")

    correlation = record.get("correlation")
    request_id: str | None = None
    if not isinstance(correlation, dict):
        errors.append(f"line {line_no}: correlation must be an object")
    else:
        raw_request_id = correlation.get("request_id")
        if raw_request_id is not None and not isinstance(raw_request_id, str):
            errors.append(f"line {line_no}: correlation.request_id must be a string")
        elif isinstance(raw_request_id, str) and raw_request_id:
            request_id = raw_request_id
            if require_uuid_request_id and not UUID_V4.fullmatch(raw_request_id):
                errors.append(f"line {line_no}: correlation.request_id is not a v4 UUID")

    provenance = record.get("provenance")
    if not isinstance(provenance, dict):
        errors.append(f"line {line_no}: provenance must be an object")
    else:
        for field in ("producer", "binary_version"):
            if not _nonempty_string(provenance.get(field)):
                errors.append(f"line {line_no}: provenance.{field} must be non-empty")
        if not isinstance(provenance.get("registry_schema_version"), int) or provenance.get(
            "registry_schema_version", 0
        ) <= 0:
            errors.append(f"line {line_no}: provenance.registry_schema_version must be positive")
        if not isinstance(provenance.get("config_generation"), int) or provenance.get(
            "config_generation", -1
        ) < 0:
            errors.append(f"line {line_no}: provenance.config_generation must be non-negative")
    if not isinstance(record.get("field_classes"), dict):
        errors.append(f"line {line_no}: field_classes must be an object")

    return errors, event_name, request_id


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("--min-records", type=int, default=0)
    parser.add_argument("--ts-window-seconds", type=int, default=0)
    parser.add_argument("--require-uuid-request-id", action="store_true")
    parser.add_argument("--require-event-name", action="append", default=[])
    parser.add_argument("--require-shared-guardrail-request-id", action="store_true")
    args = parser.parse_args()

    if not args.path.is_file():
        print(f"ERROR: {args.path} does not exist", file=sys.stderr)
        return 2
    if args.min_records < 0 or args.ts_window_seconds < 0:
        parser.error("record count and timestamp window must be non-negative")

    timestamp_min: datetime | None = None
    timestamp_max: datetime | None = None
    if args.ts_window_seconds:
        now = datetime.now(timezone.utc)
        timestamp_min = now - timedelta(seconds=args.ts_window_seconds)
        timestamp_max = now + timedelta(seconds=5)

    errors: list[str] = []
    event_counts: dict[str, int] = {}
    request_events: dict[str, set[str]] = {}
    total = 0
    with args.path.open(encoding="utf-8") as stream:
        for line_no, line in enumerate(stream, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            total += 1
            found, event_name, request_id = validate_record(
                line_no,
                stripped,
                timestamp_min=timestamp_min,
                timestamp_max=timestamp_max,
                require_uuid_request_id=args.require_uuid_request_id,
            )
            errors.extend(found)
            if not found and event_name is not None:
                event_counts[event_name] = event_counts.get(event_name, 0) + 1
                if request_id:
                    request_events.setdefault(request_id, set()).add(event_name)

    if total < args.min_records:
        errors.append(f"file had {total} records; --min-records requires {args.min_records}")
    for required in args.require_event_name:
        if event_counts.get(required, 0) == 0:
            errors.append(f"file contained 0 records for required event_name {required!r}")
    if args.require_shared_guardrail_request_id:
        required_pair = {"guardrail.evaluation.completed", "guardrail.judge.completed"}
        if not any(required_pair <= names for names in request_events.values()):
            errors.append("no request_id correlated guardrail evaluation and judge completion records")

    if errors:
        print(f"FAIL: observability v8 JSONL validation failed ({len(errors)} issue(s)):", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print(f"OK: {total} canonical v8 record(s) validated across {len(event_counts)} event name(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
