#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Validate a gateway.jsonl file emitted by the DefenseClaw sidecar.

Intended for use inside CI after an e2e run — the sidecar must have
written to this file during the run (otherwise the file won't
exist and the script will exit non-zero). The schema mirrors the
Go definitions in internal/gatewaylog/events.go; if those change,
this script must move with them.

Usage:
    scripts/assert-gateway-jsonl.py <path-to-gateway.jsonl>
    scripts/assert-gateway-jsonl.py --require-type verdict <path>
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

REQUIRED_TOP_LEVEL_FIELDS = {"ts", "event_type", "severity"}

# Phase 6 adds UUID-v4 and timestamp sanity checks. The regex below
# is deliberately permissive on the variant nibble (both "a"/"b" and
# uppercase hex) because Go's uuid.NewString emits lowercase but
# client-supplied correlation ids could legitimately be uppercase.
UUID_V4_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)

REQUIRED_EVENT_FIELDS = {
    "verdict":    {"stage", "action"},
    "judge":      {"kind"},
    "lifecycle":  {"subsystem", "transition"},
    # Error payload's required field is "message"; "code" is
    # recommended but optional because some legacy error sites
    # predate the stable-code convention.
    "error":      {"subsystem", "message"},
    # Diagnostic payload uses "component" (not "subsystem") and
    # "message" — matches the Go DiagnosticPayload struct.
    "diagnostic": {"component", "message"},
    # v7 scanner fan-out. `scan` is the roll-up per invocation;
    # every finding lands on its own `scan_finding` sibling event
    # so SIEM can alert per row without joining to the parent.
    # Required fields mirror internal/gatewaylog/events.go
    # (ScanPayload / ScanFindingPayload). `verdict`, `severity_max`,
    # `rule_id`, and `line_number` are recommended but optional on
    # the wire because scanners may legitimately emit partials on
    # error paths.
    "scan":         {"scan_id", "scanner", "target"},
    "scan_finding": {"scan_id", "scanner", "target"},
    # v7 operator mutation log. Actor + action + target uniquely
    # identify the mutation; before/after/diff are optional because
    # create/delete mutations legitimately drop one side.
    "activity":   {"actor", "action", "target_type", "target_id"},
}

VALID_EVENT_TYPES = set(REQUIRED_EVENT_FIELDS.keys())
# The Go emitter serializes Severity as uppercase (CRITICAL, HIGH,
# MEDIUM, LOW, INFO). Accept either case so the validator works
# equally well against golden fixtures and live-captured JSONL.
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def _parse_rfc3339_nano(ts: str) -> datetime | None:
    """Parse an RFC3339Nano timestamp produced by Go's time.MarshalJSON.

    Go emits up to 9 fractional digits; Python's datetime supports at
    most 6. We trim the excess rather than rejecting the timestamp —
    the time is still well-formed, we just lose sub-microsecond
    precision we don't need for bounds checking.
    """
    # Normalise Zulu suffix to a UTC offset so fromisoformat on
    # pre-3.11 interpreters accepts it.
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    # Trim fractional digits beyond microseconds (match ".NNNNNN").
    frac_match = re.match(r"^(.*\.\d{1,6})\d*([-+].*)?$", ts)
    if frac_match:
        ts = frac_match.group(1) + (frac_match.group(2) or "")
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def validate_event(
    line_no: int,
    raw: str,
    required_type: str | None,
    ts_min: datetime | None,
    ts_max: datetime | None,
    require_uuid_request_id: bool,
) -> tuple[list[str], str | None, str | None]:
    """Return (error list, event_type or None, request_id or None)."""
    errs: list[str] = []
    try:
        event = json.loads(raw)
    except json.JSONDecodeError as exc:
        # Bail immediately — once parsing fails nothing else is
        # salvageable on this line and downstream checks would trip
        # on a string instead of a dict.
        return [f"line {line_no}: invalid JSON: {exc}"], None, None

    if not isinstance(event, dict):
        return ([f"line {line_no}: expected JSON object, got {type(event).__name__}"], None, None)

    missing_top = REQUIRED_TOP_LEVEL_FIELDS - event.keys()
    if missing_top:
        errs.append(f"line {line_no}: missing required top-level fields: {sorted(missing_top)}")

    etype = event.get("event_type")
    if etype not in VALID_EVENT_TYPES:
        errs.append(f"line {line_no}: unknown event_type={etype!r} (expected one of {sorted(VALID_EVENT_TYPES)})")

    sev = event.get("severity", "")
    if isinstance(sev, str):
        sev = sev.upper()
    if sev not in VALID_SEVERITIES:
        errs.append(f"line {line_no}: unknown severity={sev!r} (expected one of {sorted(VALID_SEVERITIES)})")

    # Phase 6: timestamp sanity. `ts` must parse as RFC3339Nano and
    # — when caller supplies a window — fall inside [ts_min, ts_max].
    # A clock-drifted producer can trip this even with well-formed
    # JSON, which is the point of the check.
    ts_raw = event.get("ts")
    if isinstance(ts_raw, str):
        parsed = _parse_rfc3339_nano(ts_raw)
        if parsed is None:
            errs.append(f"line {line_no}: ts={ts_raw!r} is not a valid RFC3339 timestamp")
        else:
            if ts_min is not None and parsed < ts_min:
                errs.append(
                    f"line {line_no}: ts={ts_raw!r} precedes allowed window start {ts_min.isoformat()}"
                )
            if ts_max is not None and parsed > ts_max:
                errs.append(
                    f"line {line_no}: ts={ts_raw!r} exceeds allowed window end {ts_max.isoformat()}"
                )

    if etype in REQUIRED_EVENT_FIELDS:
        payload = event.get(etype)
        if not isinstance(payload, dict):
            errs.append(f"line {line_no}: event_type={etype!r} requires nested object under {etype!r} key")
        else:
            missing_inner = REQUIRED_EVENT_FIELDS[etype] - payload.keys()
            if missing_inner:
                errs.append(
                    f"line {line_no}: event_type={etype!r} missing payload fields: {sorted(missing_inner)}"
                )

    # Phase 6: request_id format check. Not mandatory (lifecycle/
    # diagnostic events can legitimately lack a correlation id)
    # unless --require-uuid-request-id is set.
    request_id = event.get("request_id")
    if request_id is not None:
        if not isinstance(request_id, str):
            errs.append(f"line {line_no}: request_id={request_id!r} is not a string")
        elif require_uuid_request_id and request_id and not UUID_V4_RE.match(request_id):
            # Clients that supply their own correlation id may choose
            # a non-UUID format, so UUID validation is opt-in. The
            # default emitter always produces v4 UUIDs.
            errs.append(f"line {line_no}: request_id={request_id!r} is not a v4 UUID")

    if required_type is not None and etype != required_type:
        # Not an error per-event, but we'll tally at file level.
        pass

    return errs, etype, request_id


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("path", type=Path, help="Path to gateway.jsonl")
    parser.add_argument(
        "--require-type",
        choices=sorted(VALID_EVENT_TYPES),
        action="append",
        default=[],
        help=(
            "Fail if no event of this type is present in the file. "
            "May be specified multiple times; each must appear at least once."
        ),
    )
    parser.add_argument(
        "--min-events",
        type=int,
        default=0,
        help="Fail if fewer than this many events are present (default 0).",
    )
    parser.add_argument(
        "--ts-window-seconds",
        type=int,
        default=0,
        help=(
            "If >0, reject events whose ts is more than this many seconds in the past "
            "or in the future (relative to script execution). Phase 6 CI assertion."
        ),
    )
    parser.add_argument(
        "--require-uuid-request-id",
        action="store_true",
        help=(
            "Reject events whose request_id, when present, is not a v4 UUID. "
            "Use when all traffic is sourced from the DefenseClaw emitter "
            "(which always mints v4 UUIDs)."
        ),
    )
    parser.add_argument(
        "--require-shared-request-id",
        action="store_true",
        help=(
            "Assert that at least one request_id appears on both a verdict "
            "and a judge event. Phase 6 CI correlation invariant."
        ),
    )
    args = parser.parse_args()

    if not args.path.exists():
        print(f"ERROR: {args.path} does not exist", file=sys.stderr)
        return 2

    ts_min: datetime | None = None
    ts_max: datetime | None = None
    if args.ts_window_seconds > 0:
        now = datetime.now(timezone.utc)
        ts_min = now - timedelta(seconds=args.ts_window_seconds)
        # +5s forward drift tolerance per the Phase 6 plan.
        ts_max = now + timedelta(seconds=5)

    errors: list[str] = []
    type_counts: dict[str, int] = {}
    # request_id → set of event_types that carried it; used for the
    # shared-request-id correlation assertion.
    request_ids: dict[str, set[str]] = {}
    total = 0

    with args.path.open("r", encoding="utf-8") as f:
        for line_no, raw in enumerate(f, start=1):
            stripped = raw.strip()
            if not stripped:
                # Blank lines can appear mid-rotation; they are
                # valid JSONL so long as no partial event was
                # serialized. Skip without counting.
                continue
            total += 1
            errs, etype, request_id = validate_event(
                line_no,
                stripped,
                None,  # per-line required_type is flagged at file level below
                ts_min,
                ts_max,
                args.require_uuid_request_id,
            )
            errors.extend(errs)
            if not errs and etype is not None:
                type_counts[etype] = type_counts.get(etype, 0) + 1
                if isinstance(request_id, str) and request_id:
                    request_ids.setdefault(request_id, set()).add(etype)

    if total < args.min_events:
        errors.append(f"file had {total} events; --min-events requires {args.min_events}")

    for required in args.require_type:
        if type_counts.get(required, 0) == 0:
            errors.append(
                f"file contained 0 events of required type {required!r}; "
                f"observed types: {sorted(type_counts.keys())}"
            )

    if args.require_shared_request_id:
        shared = [
            rid for rid, types in request_ids.items()
            if "verdict" in types and "judge" in types
        ]
        if not shared:
            errors.append(
                "no request_id correlated a verdict with a judge event; "
                f"saw {len(request_ids)} distinct request_id(s) with type sets "
                f"{sorted({tuple(sorted(t)) for t in request_ids.values()})}"
            )

    if errors:
        print(f"FAIL: gateway.jsonl validation failed ({len(errors)} issue(s)):", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print(f"OK: {total} events validated across {len(type_counts)} type(s): {type_counts}")
    if args.require_shared_request_id:
        print(f"OK: {len(request_ids)} distinct request_id(s); correlation verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
