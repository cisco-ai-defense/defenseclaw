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
import sys
from pathlib import Path

REQUIRED_TOP_LEVEL_FIELDS = {"ts", "event_type", "severity"}

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
}

VALID_EVENT_TYPES = set(REQUIRED_EVENT_FIELDS.keys())
# The Go emitter serializes Severity as uppercase (CRITICAL, HIGH,
# MEDIUM, LOW, INFO). Accept either case so the validator works
# equally well against golden fixtures and live-captured JSONL.
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def validate_event(line_no: int, raw: str, required_type: str | None) -> list[str]:
    """Return a list of error strings; empty list means the event is valid."""
    errs: list[str] = []
    try:
        event = json.loads(raw)
    except json.JSONDecodeError as exc:
        # Bail immediately — once parsing fails nothing else is
        # salvageable on this line and downstream checks would trip
        # on a string instead of a dict.
        return [f"line {line_no}: invalid JSON: {exc}"]

    if not isinstance(event, dict):
        return [f"line {line_no}: expected JSON object, got {type(event).__name__}"]

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

    if required_type is not None and etype != required_type:
        # Not an error per-event, but we'll tally at file level.
        pass

    return errs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("path", type=Path, help="Path to gateway.jsonl")
    parser.add_argument(
        "--require-type",
        choices=sorted(VALID_EVENT_TYPES),
        help="Fail if no event of this type is present in the file.",
    )
    parser.add_argument(
        "--min-events",
        type=int,
        default=0,
        help="Fail if fewer than this many events are present (default 0).",
    )
    args = parser.parse_args()

    if not args.path.exists():
        print(f"ERROR: {args.path} does not exist", file=sys.stderr)
        return 2

    errors: list[str] = []
    type_counts: dict[str, int] = {}
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
            errs = validate_event(line_no, stripped, args.require_type)
            errors.extend(errs)
            # Track type histogram only for parse-successful events.
            if not errs:
                try:
                    t = json.loads(stripped).get("event_type", "")
                    type_counts[t] = type_counts.get(t, 0) + 1
                except json.JSONDecodeError:
                    pass

    if total < args.min_events:
        errors.append(f"file had {total} events; --min-events requires {args.min_events}")

    if args.require_type and type_counts.get(args.require_type, 0) == 0:
        errors.append(
            f"file contained 0 events of required type {args.require_type!r}; "
            f"observed types: {sorted(type_counts.keys())}"
        )

    if errors:
        print(f"FAIL: gateway.jsonl validation failed ({len(errors)} issue(s)):", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print(f"OK: {total} events validated across {len(type_counts)} type(s): {type_counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
