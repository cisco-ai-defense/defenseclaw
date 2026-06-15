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
# Assertion helpers layered on top of the existing CI invariants:
#   - gateway.jsonl schema      -> scripts/assert-gateway-jsonl.py
#   - observability invariants  -> test/e2e/observability_assertions.sh
#   - real enforcement          -> sentinel side-effect files (lib/common.sh)
#
# Every assertion returns 0/1 and is logged; callers decide whether a failure
# is fatal (drivers wrap each in dc_record_result so one event's failure does
# not abort the cell).

# dc_assert_schema [min_events] — validate gateway.jsonl envelope schema.
dc_assert_schema() {
  local min="${1:-1}"
  if [ ! -f "${DC_GATEWAY_JSONL}" ]; then
    dc_err "gateway.jsonl missing at ${DC_GATEWAY_JSONL}"
    return 1
  fi
  python3 "${DC_E2E_REPO_ROOT}/scripts/assert-gateway-jsonl.py" \
    "${DC_GATEWAY_JSONL}" --min-events "${min}"
}

# dc_count_connector_events <connector> [since_line] — count gateway.jsonl
# events attributed to a connector. Resilient across event shapes: matches any
# of destination_app / surface / aid_surface / connector carrying the name.
# When since_line is given, only events strictly after that 1-based line index
# are counted (so we assert "fired during this probe", not historically).
dc_count_connector_events() {
  local connector="$1" since="${2:-0}"
  [ -f "${DC_GATEWAY_JSONL}" ] || { printf '0'; return 0; }
  python3 - "${DC_GATEWAY_JSONL}" "${connector}" "${since}" <<'PY'
import json, sys
path, connector, since = sys.argv[1], sys.argv[2], int(sys.argv[3])
fields = ("destination_app", "surface", "aid_surface", "connector", "agent_name", "agent_type")
n = 0
with open(path, encoding="utf-8") as f:
    for i, line in enumerate(f, start=1):
        if i <= since:
            continue
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except Exception:
            continue
        blob = json.dumps(ev).lower()
        if any(str(ev.get(k, "")).lower() == connector for k in fields):
            n += 1
        elif connector in blob and ("hook" in blob or "tool" in blob or "lifecycle" in blob):
            n += 1
print(n)
PY
}

# dc_assert_fired <connector> <since_line> — at least one gateway event was
# attributed to the connector since the probe started. This is the #1
# regression signal: an upstream release that renames/drops an event makes the
# hook stop firing, and this assertion goes red.
dc_assert_fired() {
  local connector="$1" since="${2:-0}" n
  n="$(dc_count_connector_events "${connector}" "${since}")"
  if [ "${n:-0}" -ge 1 ]; then
    return 0
  fi
  dc_err "no gateway events attributed to ${connector} since line ${since}"
  return 1
}

# dc_assert_verdict_block <since_line> — a block verdict was recorded after the
# probe. Pairs with the sentinel check so we prove both the decision AND the
# enforcement.
#
# The gateway expresses a blocked tool call in more than one envelope shape, so
# accept any authoritative block signal:
#   - event_type "verdict"  -> verdict.action  in {block, deny}
#   - event_type "scan"     -> scan.verdict    in {block, deny}  (hook-rules
#                              scanner verdict; the v7 hook decision path emits
#                              this rather than a standalone "verdict" record)
# Keying on either keeps the assertion robust across connectors and across
# future renames of any single envelope.
dc_assert_verdict_block() {
  local since="${1:-0}"
  [ -f "${DC_GATEWAY_JSONL}" ] || return 1
  python3 - "${DC_GATEWAY_JSONL}" "${since}" <<'PY'
import json, sys
path, since = sys.argv[1], int(sys.argv[2])
blocking = ("block", "deny")
found = False
with open(path, encoding="utf-8") as f:
    for i, line in enumerate(f, start=1):
        if i <= since:
            continue
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except Exception:
            continue
        et = ev.get("event_type")
        if et == "verdict":
            action = str(ev.get("verdict", {}).get("action", "")).lower()
            if action in blocking:
                found = True
                break
        elif et == "scan":
            verdict = str(ev.get("scan", {}).get("verdict", "")).lower()
            if verdict in blocking:
                found = True
                break
sys.exit(0 if found else 1)
PY
}

# dc_assert_observability [extra args...] — run the shared Phase 6 invariants
# (timestamp sanity, request_id UUID, audit.db correlation). Reused verbatim
# from the OpenClaw stack so this harness can never diverge from it.
dc_assert_observability() {
  bash "${DC_E2E_REPO_ROOT}/test/e2e/observability_assertions.sh" \
    --jsonl "${DC_GATEWAY_JSONL}" \
    --db "${DC_AUDIT_DB}" \
    --ts-window-seconds 3600 \
    --no-require-verdict \
    "$@"
}

# dc_assert_otlp <connector> <since_line> — for native_otlp connectors
# (codex/claudecode/geminicli) assert telemetry tagged with the connector
# reached the sink. We look for tool_invocation / llm_prompt / llm_response
# events (the OTLP ingest path emits these) attributed to the connector.
dc_assert_otlp() {
  local connector="$1" since="${2:-0}"
  [ -f "${DC_GATEWAY_JSONL}" ] || return 1
  python3 - "${DC_GATEWAY_JSONL}" "${connector}" "${since}" <<'PY'
import json, sys
path, connector, since = sys.argv[1], sys.argv[2], int(sys.argv[3])
telemetry = {"tool_invocation", "llm_prompt", "llm_response"}
fields = ("destination_app", "surface", "aid_surface", "connector")
found = False
with open(path, encoding="utf-8") as f:
    for i, line in enumerate(f, start=1):
        if i <= since:
            continue
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except Exception:
            continue
        if ev.get("event_type") in telemetry and any(
            str(ev.get(k, "")).lower() == connector for k in fields
        ):
            found = True
            break
sys.exit(0 if found else 1)
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
    dc_err "no block verdict recorded since line ${since} (cannot confirm enforcement)"
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
