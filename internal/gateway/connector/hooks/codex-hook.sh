#!/bin/bash
# defenseclaw-managed-hook v6
# DefenseClaw Codex hook — forwards the full hook event payload to the
# DefenseClaw gateway's /api/v1/codex/hook endpoint. Codex pipes the
# structured JSON event to stdin and reads the response from stdout.
#
# W3C trace propagation: if the agent has already exported
# DEFENSECLAW_TRACEPARENT / OTEL_TRACEPARENT (etc.), the validated
# values are sent to the gateway as traceparent / tracestate headers
# so the hook span links back to the agent's parent span. Validation
# happens in _hardening.sh — a malformed value is silently dropped
# (the hook still posts to the gateway, it just starts a new root
# span).
set -euo pipefail

# Windows: HOME may be unset when agents spawn hooks. Fall back to USERPROFILE.
HOME="${HOME:-${USERPROFILE:-$(cd ~ 2>/dev/null && pwd)}}"
export HOME

HOOK_SOURCE="${BASH_SOURCE[0]:-$0}"
HOOK_LINK_DEPTH=0
while [ -L "$HOOK_SOURCE" ]; do
  HOOK_LINK_DEPTH=$((HOOK_LINK_DEPTH + 1))
  [ "$HOOK_LINK_DEPTH" -le 40 ] || exit 2
  HOOK_PARENT="${HOOK_SOURCE%/*}"
  [ "$HOOK_PARENT" != "$HOOK_SOURCE" ] || HOOK_PARENT="."
  HOOK_BASE="$(cd -P -- "$HOOK_PARENT" 2>/dev/null && pwd)" || exit 2
  if [ -x /usr/bin/readlink ]; then
    HOOK_TARGET="$(/usr/bin/readlink -- "$HOOK_SOURCE")" || exit 2
  elif [ -x /bin/readlink ]; then
    HOOK_TARGET="$(/bin/readlink -- "$HOOK_SOURCE")" || exit 2
  else
    exit 2
  fi
  case "$HOOK_TARGET" in
    /*) HOOK_SOURCE="$HOOK_TARGET" ;;
    *) HOOK_SOURCE="$HOOK_BASE/$HOOK_TARGET" ;;
  esac
done
HOOK_PARENT="${HOOK_SOURCE%/*}"
[ "$HOOK_PARENT" != "$HOOK_SOURCE" ] || HOOK_PARENT="."
HOOK_DIR="$(cd -P -- "$HOOK_PARENT" 2>/dev/null && pwd)" || exit 2
unset HOOK_SOURCE HOOK_LINK_DEPTH HOOK_PARENT HOOK_BASE HOOK_TARGET
{{if .Managed}}
DEFENSECLAW_HOME="$(cd "${HOOK_DIR}/.." && pwd -P)"
export DEFENSECLAW_HOME
{{else}}
DEFENSECLAW_HOME="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
if [ ! -d "${DEFENSECLAW_HOME}" ] || [ -f "${DEFENSECLAW_HOME}/.disabled" ]; then
  exit 0
fi
{{end}}

# Plan B4 / S0.4: shell-side hook hardening, sourced BEFORE the
# missing-token branch so the helper is available to log + branch on
# DEFENSECLAW_STRICT_AVAILABILITY. Hardening only mutates env that
# downstream code controls (HOME, PATH, locale, GIT_*); none of the
# subsequent token-resolution logic depends on the operator's
# original PATH or HOME.
. "${HOOK_DIR}/_hardening.sh"
defenseclaw_harden_resources
defenseclaw_harden_env

# Fail mode governs response-layer failures (4xx, bad JSON, missing
# action). Transport failures (gateway unreachable / 5xx) are handled
# separately by fail_unreachable below — they ALWAYS allow unless the
# operator has set DEFENSECLAW_STRICT_AVAILABILITY=1, because a
# DefenseClaw outage must not brick the user's agent. Set BEFORE the
# missing-token check so defenseclaw_handle_missing_token below has a
# stable FAIL_MODE to log against.
FAIL_MODE="${DEFENSECLAW_FAIL_MODE:-{{.FailMode}}}"

# Bail early when neither the companion .token file nor the env var
# carries a token: without one the gateway will reject every request
# with 401, so the historical default is exit-0 (don't brick the
# agent). The helper preserves that default and additionally lets an
# operator who set DEFENSECLAW_STRICT_AVAILABILITY=1 fail-closed on a
# missing-token misconfiguration; either way, the bypass is recorded
# in hook-failures.jsonl.
DEFENSECLAW_HOOK_CONNECTOR="codex"
DEFENSECLAW_HOOK_NAME="codex-hook"
export DEFENSECLAW_HOOK_CONNECTOR DEFENSECLAW_HOOK_NAME

if [ ! -f "${HOOK_DIR}/{{.TokenFile}}" ] && [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ]; then
  defenseclaw_handle_missing_token codex codex-hook "codex tool"
fi

PAYLOAD="$(defenseclaw_read_stdin_capped)" || {
  echo "defenseclaw: codex hook refusing oversized payload" >&2
  if [ "$FAIL_MODE" = "closed" ]; then
    printf '{"decision":"block","reason":"DefenseClaw hook payload too large"}\n'
    exit 2
  fi
  exit 0
}
API_ADDR="{{.APIAddr}}"

# Source the token file written by defenseclaw setup (0o600, never baked
# into this script). The env var takes precedence if already set.
if [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ] && [ -f "${HOOK_DIR}/{{.TokenFile}}" ]; then
  # shellcheck source=/dev/null
  . "${HOOK_DIR}/{{.TokenFile}}"
fi
API_TOKEN="${DEFENSECLAW_GATEWAY_TOKEN:-}"

# Transport-layer failure: gateway is unreachable, the connection was
# refused, the request timed out, or the gateway answered with 5xx.
# Always allow unless the operator opted into strict availability.
fail_unreachable() {
  defenseclaw_log_hook_failure codex codex-hook "$1" transport "$FAIL_MODE"
  defenseclaw_emit_unreachable_stderr "codex tool" "$1"
  if defenseclaw_should_fail_closed_on_unreachable; then
    exit 2
  fi
  exit 0
}

# Response-layer failure: gateway answered but the answer was bad
# (auth failure, malformed JSON, missing action). These usually
# indicate misconfiguration — respect FAIL_MODE so an operator who
# explicitly set FAIL_MODE=closed is told about a real problem.
fail_response() {
  local reason
  reason="$(defenseclaw_response_failure_reason "$1")"
  defenseclaw_log_hook_failure codex codex-hook "$reason" response "$FAIL_MODE"
  echo "defenseclaw: codex hook error: $reason" >&2
  if [ "$FAIL_MODE" = "open" ]; then
    exit 0
  fi
  exit 2
}

AUTH_HEADER_ARGS=()
if [ -n "${API_TOKEN}" ]; then
  AUTH_HEADER_ARGS=(-H "Authorization: Bearer ${API_TOKEN}")
fi

# W3C trace propagation: mapfile fills
# TRACE_HEADER_ARGS with a sequence of `-H "traceparent: …"` /
# `-H "tracestate: …"` arguments; invalid env values are dropped
# by defenseclaw_extract_trace_context. On bash<4 the array stays
# empty (set -u-safe expansion below) so older shells degrade
# gracefully.
TRACE_HEADER_ARGS=()
if command -v mapfile >/dev/null 2>&1; then
  mapfile -t TRACE_HEADER_ARGS < <(defenseclaw_extract_trace_context)
fi

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "http://${API_ADDR}/api/v1/codex/hook" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: codex-hook/1.0" \
  "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}" \
  "${TRACE_HEADER_ARGS[@]+"${TRACE_HEADER_ARGS[@]}"}" \
  --connect-timeout 2 \
  --max-time 10 \
  -d "$PAYLOAD" 2>/dev/null) || {
  fail_unreachable "gateway unreachable"
}

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
RESULT=$(echo "$RESPONSE" | sed '$d')

# 5xx (server error) is treated as transport — the gateway hit an
# infrastructure problem, not a policy verdict. 4xx falls through to
# response-layer handling so auth/payload bugs surface loudly.
if [ -z "$HTTP_CODE" ]; then
  fail_unreachable "gateway returned no HTTP status"
elif [ "$HTTP_CODE" -ge 500 ] 2>/dev/null && [ "$HTTP_CODE" -lt 600 ] 2>/dev/null; then
  fail_unreachable "gateway returned HTTP ${HTTP_CODE}"
elif [ "$HTTP_CODE" -lt 200 ] 2>/dev/null || [ "$HTTP_CODE" -ge 300 ] 2>/dev/null; then
  fail_response "gateway returned HTTP ${HTTP_CODE}"
fi

OUTPUT=$(echo "$RESULT" | _dc_jq -c '.codex_output // empty' 2>/dev/null) || {
  fail_response "invalid JSON response"
}
if [ -n "$OUTPUT" ] && [ "$OUTPUT" != "null" ]; then
  echo "$OUTPUT"
fi

ACTION=$(echo "$RESULT" | _dc_jq -r '.action // "allow"' 2>/dev/null) || {
  fail_response "failed to parse action from response"
}

# Codex's hook protocol is strictly EITHER structured JSON on stdout
# with exit 0 (Codex parses the decision from the JSON) OR exit 2
# with the reason on stderr (Codex blocks with stderr as the
# message). Doing BOTH is a protocol violation: Codex sees exit 2,
# ignores stdout, finds an empty stderr, then logs
# "exited with code 2 but did not write a blocking reason to stderr"
# and FAILS OPEN — which is exactly the bug we hit when our gateway
# returned permissionDecision=deny on stdout AND we exited 2.
#
# Resolution: trust the structured JSON when the gateway gave us one
# (every block path in codex_hook.go does), and only fall back to
# the exit-2-plus-stderr path when no structured output exists.
if [ "$ACTION" = "block" ]; then
  if [ -n "$OUTPUT" ] && [ "$OUTPUT" != "null" ]; then
    # JSON on stdout already carries permissionDecision=deny /
    # decision=block. Exit 0 so Codex honors it.
    exit 0
  fi
  # codex_output was not extractable (no jq/python3 for object fields).
  # Construct minimal structured block JSON so Codex sees exit 0 + JSON
  # rather than exit 2 — newer Codex versions (v0.130+) treat exit 2 on
  # UserPromptSubmit as "hook failed" rather than "hook blocked".
  REASON=$(echo "$RESULT" | _dc_jq -r '.reason // empty' 2>/dev/null)
  if [ -z "$REASON" ]; then
    REASON="Blocked by DefenseClaw Codex policy."
  fi
  printf '{"decision":"block","reason":"%s"}\n' "$(defenseclaw_json_escape "$REASON")"
  exit 0
fi
exit 0
