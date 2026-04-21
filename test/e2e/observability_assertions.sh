#!/usr/bin/env bash
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
# Phase 6 observability invariants. Run after an e2e scenario has
# driven real traffic through the sidecar. This script is the
# single source of truth for both CI (.github/workflows/e2e.yml)
# and local "make e2e" runs, so do not duplicate the assertions
# anywhere else — extend them here.
#
# The script asserts:
#   1. gateway.jsonl exists and is non-empty.
#   2. Every line is valid JSONL, carries a top-level ts / event_type /
#      severity, and uses the envelope shape defined in
#      internal/gatewaylog/events.go. Delegates to assert-gateway-jsonl.py.
#   3. Timestamps parse as RFC3339Nano and fall within a bounded
#      window (default: last 30 minutes + 5 seconds of forward drift).
#   4. request_id, when emitted, is a valid v4 UUID.
#   5. audit.db contains at least one row with a non-empty request_id.
#   6. When judge persistence is enabled (default), audit.db contains
#      at least one judge_responses row.
#
# The Splunk HEC mock assertion is opt-in: the CI workflow passes
# --splunk-mock-log only when judge traffic is expected (full-live
# with guardrail enabled).
#
# Usage:
#   test/e2e/observability_assertions.sh \
#       [--jsonl PATH] [--db PATH] \
#       [--ts-window-seconds N] [--require-judge] \
#       [--require-shared-request-id]

set -euo pipefail

JSONL_PATH="${JSONL_PATH:-$HOME/.defenseclaw/gateway.jsonl}"
AUDIT_DB_PATH="${AUDIT_DB_PATH:-$HOME/.defenseclaw/audit.db}"
TS_WINDOW_SECONDS="${TS_WINDOW_SECONDS:-1800}"
REQUIRE_JUDGE="${REQUIRE_JUDGE:-0}"
REQUIRE_SHARED_REQUEST_ID="${REQUIRE_SHARED_REQUEST_ID:-0}"
REQUIRE_VERDICT="${REQUIRE_VERDICT:-1}"
# Optional: set only via --splunk-mock-log (never from inherited env).
# GHA jobs export SPLUNK_MOCK_LOG for the mock listener even when this
# script must not assert judge sourcetype (core profile).
SPLUNK_MOCK_ASSERT_LOG=""

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --jsonl) JSONL_PATH="$2"; shift 2;;
        --db) AUDIT_DB_PATH="$2"; shift 2;;
        --ts-window-seconds) TS_WINDOW_SECONDS="$2"; shift 2;;
        --require-judge) REQUIRE_JUDGE=1; shift;;
        --require-shared-request-id) REQUIRE_SHARED_REQUEST_ID=1; shift;;
        --no-require-verdict) REQUIRE_VERDICT=0; shift;;
        --splunk-mock-log) SPLUNK_MOCK_ASSERT_LOG="$2"; shift 2;;
        --help|-h)
            sed -n '2,/^$/p' "$0"
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

ok() {
    echo "OK: $*"
}

echo "[observability_assertions] jsonl=$JSONL_PATH db=$AUDIT_DB_PATH ts_window=${TS_WINDOW_SECONDS}s"

# 1. JSONL file must exist and be non-empty.
if [[ ! -f "$JSONL_PATH" ]]; then
    fail "gateway.jsonl not found at $JSONL_PATH"
fi
if [[ ! -s "$JSONL_PATH" ]]; then
    fail "gateway.jsonl is empty at $JSONL_PATH"
fi
ok "gateway.jsonl present ($(wc -l <"$JSONL_PATH" | tr -d ' ') lines)"

# 2–4. Delegate structural + timestamp + UUID checks to the Python
# validator. Optional flags turn on the stricter Phase 6 assertions
# (shared request_id, required event types).
VALIDATOR_ARGS=(
    "$JSONL_PATH"
    --min-events 1
    --ts-window-seconds "$TS_WINDOW_SECONDS"
    --require-uuid-request-id
)
if [[ "$REQUIRE_VERDICT" == "1" ]]; then
    VALIDATOR_ARGS+=(--require-type verdict)
fi
if [[ "$REQUIRE_JUDGE" == "1" ]]; then
    VALIDATOR_ARGS+=(--require-type judge)
fi
if [[ "$REQUIRE_SHARED_REQUEST_ID" == "1" ]]; then
    VALIDATOR_ARGS+=(--require-shared-request-id)
fi

python3 "$REPO_ROOT/scripts/assert-gateway-jsonl.py" "${VALIDATOR_ARGS[@]}"

# 5. SQLite correlation check: at least one audit_events row must
# have a non-empty request_id. Skipped gracefully if sqlite3 isn't on
# the runner (should not happen in CI, but local developers without
# sqlite3 installed should still be able to use the JSONL portion).
if command -v sqlite3 >/dev/null 2>&1; then
    if [[ ! -f "$AUDIT_DB_PATH" ]]; then
        fail "audit.db not found at $AUDIT_DB_PATH"
    fi

    REQUEST_ID_COUNT=$(sqlite3 "$AUDIT_DB_PATH" \
        "SELECT COUNT(*) FROM audit_events WHERE request_id IS NOT NULL AND request_id != '';" || echo "0")
    if [[ "$REQUEST_ID_COUNT" == "0" ]]; then
        fail "audit_events had 0 rows with a populated request_id"
    fi
    ok "audit_events carried request_id on $REQUEST_ID_COUNT row(s)"

    # 6. Optional: require at least one judge_responses row when the
    # caller has confirmed judge persistence should be on.
    if [[ "$REQUIRE_JUDGE" == "1" ]]; then
        JUDGE_COUNT=$(sqlite3 "$AUDIT_DB_PATH" \
            "SELECT COUNT(*) FROM judge_responses;" || echo "0")
        if [[ "$JUDGE_COUNT" == "0" ]]; then
            fail "judge_responses had 0 rows (expected ≥1 with persistence on)"
        fi
        ok "judge_responses row count = $JUDGE_COUNT"
    fi
else
    echo "[observability_assertions] sqlite3 not installed; skipping DB checks"
fi

# 7. Optional Splunk HEC mock assertion. The CI workflow spins up a
# tiny listener that appends each HEC request body to the path passed
# via --splunk-mock-log; we grep for the judge sourcetype which proves
# the ForwardJudgeResponse path actually fired end-to-end.
if [[ -n "$SPLUNK_MOCK_ASSERT_LOG" ]]; then
    if [[ ! -f "$SPLUNK_MOCK_ASSERT_LOG" ]]; then
        fail "splunk-mock-log not found at $SPLUNK_MOCK_ASSERT_LOG"
    fi
    if ! grep -q 'defenseclaw:judge' "$SPLUNK_MOCK_ASSERT_LOG"; then
        fail "splunk-mock-log did not contain a 'defenseclaw:judge' sourcetype event"
    fi
    ok "splunk-mock-log contained a 'defenseclaw:judge' sourcetype event"
fi

echo "[observability_assertions] all assertions passed"
