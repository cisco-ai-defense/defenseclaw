# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
#
# Assertion helpers layered on top of the v8 runtime invariants:
#   - canonical SQLite event-history structure and correlation
#   - RFC 3339 nanosecond timestamps and bounded request correlation identities
#   - real enforcement through sentinel side-effect files (lib/common.sh)
#
# Every assertion returns 0/1 and is logged; callers decide whether a failure
# is fatal (drivers wrap each in dc_record_result so one event's failure does
# not abort the cell).

# dc_assert_schema [min_events] — validate canonical SQLite event history.
dc_assert_schema() {
  local min="${1:-1}"
  if [ ! -f "${DC_AUDIT_DB}" ]; then
    dc_err "canonical audit database missing at ${DC_AUDIT_DB}"
    return 1
  fi
  python3 - "${DC_AUDIT_DB}" "${min}" <<'PY'
import datetime as dt
import json
import re
import sqlite3
import sys

RFC3339_NANO = re.compile(
    r"^(?P<second>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<fraction>\d{1,9}))?(?P<zone>Z|[+-]\d{2}:\d{2})$"
)


def parse_rfc3339_nano(value):
    if not isinstance(value, str):
        raise ValueError("timestamp is not a string")
    match = RFC3339_NANO.fullmatch(value)
    if match is None:
        raise ValueError("timestamp is not RFC 3339 with at most nanosecond precision")
    fraction = match.group("fraction")
    normalized = match.group("second")
    if fraction:
        normalized += "." + (fraction + "000000")[:6]
    zone = "+00:00" if match.group("zone") == "Z" else match.group("zone")
    return dt.datetime.fromisoformat(normalized + zone)

path, minimum = sys.argv[1], int(sys.argv[2])
connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2)
try:
    # Scope integrity to the event-history table. The gateway's migration
    # journal may update sqlite_schema while a live process is starting; the
    # connector contract owns event persistence, not whole-file migration QA.
    if connection.execute("PRAGMA quick_check('audit_events')").fetchone() != ("ok",):
        raise SystemExit("canonical audit event history failed quick_check")
    columns = {row[1] for row in connection.execute("PRAGMA table_info(audit_events)")}
    required = {"id", "timestamp", "action", "actor", "connector", "structured_json"}
    missing = sorted(required - columns)
    if missing:
        raise SystemExit("audit_events is missing canonical columns: " + ", ".join(missing))
    rows = connection.execute(
        "SELECT id, timestamp, action, actor, structured_json FROM audit_events ORDER BY rowid"
    ).fetchall()
finally:
    connection.close()

if len(rows) < minimum:
    raise SystemExit(f"canonical audit history has {len(rows)} events; want at least {minimum}")
structured = 0
for event_id, timestamp, action, actor, body in rows:
    if not all(isinstance(value, str) and value.strip() for value in (event_id, timestamp, action, actor)):
        raise SystemExit("canonical audit row has an empty required envelope field")
    try:
        parse_rfc3339_nano(timestamp)
    except ValueError as exc:
        raise SystemExit(f"canonical audit row has invalid timestamp: {timestamp}") from exc
    if body:
        payload = json.loads(body)
        if not isinstance(payload, dict):
            raise SystemExit("canonical audit structured_json is not an object")
        structured += 1
if minimum and structured < minimum:
    raise SystemExit(f"canonical audit history has {structured} structured events; want at least {minimum}")
PY
}

# dc_count_connector_events <connector> [since_rowid] — count canonical events
# attributed to a connector after the supplied SQLite cursor.
dc_count_connector_events() {
  local connector="$1" since="${2:-0}"
  [ -f "${DC_AUDIT_DB}" ] || { printf '0'; return 0; }
  python3 - "${DC_AUDIT_DB}" "${connector}" "${since}" <<'PY'
import json
import sqlite3
import sys

path, connector, since = sys.argv[1], sys.argv[2].lower(), int(sys.argv[3])
connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2)
try:
    rows = connection.execute(
        """SELECT connector, destination_app, agent_name, action, structured_json
           FROM audit_events WHERE rowid > ? ORDER BY rowid""",
        (since,),
    ).fetchall()
finally:
    connection.close()

count = 0
for row_connector, destination, agent, action, body in rows:
    if connector in {
        str(row_connector or "").lower(),
        str(destination or "").lower(),
        str(agent or "").lower(),
    }:
        count += 1
        continue
    if body:
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = {}
        if isinstance(payload, dict) and str(payload.get("connector", "")).lower() == connector:
            count += 1
print(count)
PY
}

# dc_assert_fired <connector> <since_rowid> — at least one canonical event was
# attributed to the connector since the probe started. This is the #1
# regression signal: an upstream release that renames/drops an event makes the
# hook stop firing, and this assertion goes red.
dc_assert_fired() {
  local connector="$1" since="${2:-0}" n
  n="$(dc_count_connector_events "${connector}" "${since}")"
  if [ "${n:-0}" -ge 1 ]; then
    return 0
  fi
  dc_err "no canonical events attributed to ${connector} after SQLite row ${since}"
  return 1
}

# dc_wait_for_connector_event <connector> <since_rowid> [tenths] — wait for the
# asynchronous scanner/router/SQLite pipeline to commit at least one row for
# this probe. Thirty seconds is the default upper bound; the common case returns
# on the first or second poll.
dc_wait_for_connector_event() {
  local connector="$1" since="${2:-0}" attempts="${3:-300}" n
  while [ "${attempts}" -gt 0 ]; do
    n="$(dc_count_connector_events "${connector}" "${since}")"
    if [ "${n:-0}" -ge 1 ]; then
      return 0
    fi
    attempts=$((attempts - 1))
    sleep 0.1
  done
  return 1
}

# dc_assert_verdict_block <since_rowid> — a block verdict was recorded after the
# probe. Pairs with the sentinel check so we prove both the decision AND the
# enforcement.
#
# Accept a terminal block/deny outcome or an explicitly enforced canonical row.
dc_assert_verdict_block() {
  local since="${1:-0}"
  [ -f "${DC_AUDIT_DB}" ] || return 1
  python3 - "${DC_AUDIT_DB}" "${since}" <<'PY'
import json
import sqlite3
import sys

path, since = sys.argv[1], int(sys.argv[2])
blocking = {"block", "blocked", "deny", "denied"}
connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2)
try:
    rows = connection.execute(
        """SELECT action, event_name, enforced, structured_json
           FROM audit_events WHERE rowid > ? ORDER BY rowid""",
        (since,),
    ).fetchall()
finally:
    connection.close()

for action, event_name, enforced, body in rows:
    values = {str(action or "").lower(), str(event_name or "").lower()}
    if enforced == 1 and any(token in value for value in values for token in ("block", "deny", "enforc")):
        raise SystemExit(0)
    if body:
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = {}
        if not isinstance(payload, dict):
            continue
        verdict = payload.get("verdict")
        if isinstance(verdict, dict):
            values.add(str(verdict.get("action", "")).lower())
            values.add(str(verdict.get("result", "")).lower())
        elif verdict is not None:
            values.add(str(verdict).lower())
        for key in ("action", "raw_action", "outcome", "result", "decision"):
            values.add(str(payload.get(key, "")).lower())
        if values & blocking:
            raise SystemExit(0)
raise SystemExit(1)
PY
}

# dc_assert_observability — prove canonical history integrity, recent timestamps,
# and bounded canonical request identifiers when a producer reports one.
dc_assert_observability() {
  dc_assert_schema 1 || return 1
  python3 - "${DC_AUDIT_DB}" "${DEFENSECLAW_HOME}/judge_bodies.db" <<'PY'
import datetime as dt
import os
import re
import sqlite3
import sys

RFC3339_NANO = re.compile(
    r"^(?P<second>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<fraction>\d{1,9}))?(?P<zone>Z|[+-]\d{2}:\d{2})$"
)


def parse_rfc3339_nano(value):
    if not isinstance(value, str):
        raise ValueError("timestamp is not a string")
    match = RFC3339_NANO.fullmatch(value)
    if match is None:
        raise ValueError("timestamp is not RFC 3339 with at most nanosecond precision")
    fraction = match.group("fraction")
    normalized = match.group("second")
    if fraction:
        normalized += "." + (fraction + "000000")[:6]
    zone = "+00:00" if match.group("zone") == "Z" else match.group("zone")
    return dt.datetime.fromisoformat(normalized + zone)

connection = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True, timeout=2)
try:
    rows = connection.execute("SELECT timestamp, request_id FROM audit_events").fetchall()
finally:
    connection.close()
now = dt.datetime.now(dt.timezone.utc)
for timestamp, request_id in rows:
    observed = parse_rfc3339_nano(timestamp)
    if abs((now - observed).total_seconds()) > 3600:
        raise SystemExit(f"canonical event timestamp is outside the one-hour window: {timestamp}")
    if request_id:
        valid_request_id = (
            isinstance(request_id, str)
            and len(request_id.encode("utf-8")) <= 128
            and not any(ord(character) < 0x20 or ord(character) == 0x7F for character in request_id)
        )
        if not valid_request_id:
            raise SystemExit("canonical request identity violates the gateway correlation contract")

# Judge-body retention is optional, but when its isolated database exists it
# must be a readable SQLite store with the canonical table. Do not require a
# file or a row when retention is disabled.
judge_path = sys.argv[2]
if os.path.isfile(judge_path):
    judge = sqlite3.connect(f"file:{judge_path}?mode=ro", uri=True, timeout=2)
    try:
        if judge.execute("PRAGMA quick_check('judge_responses')").fetchone() != ("ok",):
            raise SystemExit("isolated judge response history failed quick_check")
        columns = {row[1] for row in judge.execute("PRAGMA table_info(judge_responses)")}
    finally:
        judge.close()
    required = {"id", "timestamp", "raw_response"}
    missing = sorted(required - columns)
    if missing:
        raise SystemExit("judge_responses is missing canonical columns: " + ", ".join(missing))
PY
}

# dc_assert_otlp <connector> <since_rowid> — for native_otlp connectors
# (codex/claudecode/geminicli) assert telemetry tagged with the connector
# reached the sink. We look for tool_invocation / llm_prompt / llm_response
# events (the OTLP ingest path emits these) attributed to the connector.
dc_assert_otlp() {
  local connector="$1" since="${2:-0}"
  [ -f "${DC_AUDIT_DB}" ] || return 1
  python3 - "${DC_AUDIT_DB}" "${connector}" "${since}" <<'PY'
import json
import sqlite3
import sys

path, connector, since = sys.argv[1], sys.argv[2].lower(), int(sys.argv[3])
connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2)
try:
    rows = connection.execute(
        """SELECT connector, bucket, event_name, structured_json
           FROM audit_events WHERE rowid > ? ORDER BY rowid""",
        (since,),
    ).fetchall()
finally:
    connection.close()
for row_connector, bucket, event_name, body in rows:
    if str(row_connector or "").lower() != connector:
        continue
    bucket = str(bucket or "").lower()
    event_name = str(event_name or "").lower()
    if bucket in {"model.io", "tool.invocation"} or event_name.startswith(("model.", "tool.", "llm_")):
        raise SystemExit(0)
    if body:
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and str(payload.get("event_type", "")).lower() in {
            "tool_invocation", "llm_prompt", "llm_response"
        }:
            raise SystemExit(0)
raise SystemExit(1)
PY
}

# dc_assert_allowed <token> — observe path: the probe command actually ran, so
# its sentinel marker exists.
dc_assert_allowed() {
  if dc_sentinel_present "$1"; then
    return 0
  fi
  dc_err "allow probe did not run (sentinel ${1} absent)"
  return 1
}

# dc_assert_blocked <token> <since_line> — block path: the sentinel marker is
# ABSENT (the command never executed) AND a block verdict was recorded. Both
# must hold — a missing sentinel alone could be a crashed agent, and a block
# verdict alone does not prove the tool call was actually prevented.
dc_assert_blocked() {
  local token="$1" since="${2:-0}"
  if dc_sentinel_present "${token}"; then
    dc_err "block probe RAN (sentinel ${token} present) — enforcement regression"
    return 1
  fi
  if ! dc_assert_verdict_block "${since}"; then
    dc_err "no block verdict recorded after SQLite row ${since} (cannot confirm enforcement)"
    return 1
  fi
  return 0
}

# dc_assert_teardown <connector> <agent_config_file> — after
# `defenseclaw-gateway connector teardown`, the agent config no longer
# references DefenseClaw's hook script. Proves clean uninstall.
dc_assert_teardown() {
  local connector="$1" cfg="$2"
  if [ ! -f "${cfg}" ]; then
    # Some teardowns remove the file entirely — that is clean.
    return 0
  fi
  if grep -q "defenseclaw" "${cfg}" 2>/dev/null; then
    dc_err "teardown left a defenseclaw reference in ${cfg}"
    return 1
  fi
  return 0
}
