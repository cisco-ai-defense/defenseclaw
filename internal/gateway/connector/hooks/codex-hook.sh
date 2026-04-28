#!/bin/bash
# defenseclaw-managed-hook v2
# DefenseClaw Codex hook — forwards the full hook event payload to the
# DefenseClaw gateway's /api/v1/codex/hook endpoint. Codex pipes the
# structured JSON event to stdin and reads the response from stdout.
set -euo pipefail

# Fail-open guard. See inspect-request.sh for rationale. We also bail
# early when the companion .token file is missing, because that means
# `defenseclaw setup` was never run for this connector or the token
# was wiped — either way the gateway will reject every request and
# we'd brick the agent.
DEFENSECLAW_HOME="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
if [ ! -d "${DEFENSECLAW_HOME}" ] || [ -f "${DEFENSECLAW_HOME}/.disabled" ]; then
  exit 0
fi
HOOK_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ ! -f "${HOOK_DIR}/.token" ] && [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ]; then
  exit 0
fi

# Plan B4 / S0.4: shell-side hook hardening.
. "${HOOK_DIR}/_hardening.sh"
defenseclaw_harden_resources
defenseclaw_harden_env

PAYLOAD=$(cat)
API_ADDR="${DEFENSECLAW_API_ADDR:-{{.APIAddr}}}"

# Source the token file written by defenseclaw setup (0o600, never baked
# into this script). The env var takes precedence if already set.
if [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ] && [ -f "${HOOK_DIR}/.token" ]; then
  # shellcheck source=/dev/null
  . "${HOOK_DIR}/.token"
fi
API_TOKEN="${DEFENSECLAW_GATEWAY_TOKEN:-}"

# Fail mode: "closed" (default) blocks the tool on any error;
# "open" allows through with a stderr warning.
FAIL_MODE="${DEFENSECLAW_FAIL_MODE:-{{.FailMode}}}"

log_hook_failure() {
  local reason="$1"
  local log_dir="${DEFENSECLAW_HOME}/logs"
  mkdir -p "$log_dir" 2>/dev/null || return 0
  chmod 700 "$log_dir" 2>/dev/null || true
  local log_file="${log_dir}/hook-failures.jsonl"
  local ts
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date 2>/dev/null || printf unknown)"
  local safe_reason
  safe_reason="$(printf '%s' "$reason" | tr '\n\r' '  ' | sed 's/\\/\\\\/g; s/"/\\"/g' 2>/dev/null || printf unavailable)"
  printf '{"ts":"%s","connector":"codex","hook":"codex-hook","reason":"%s","fail_mode":"%s"}\n' "$ts" "$safe_reason" "$FAIL_MODE" >> "$log_file" 2>/dev/null || true
  chmod 600 "$log_file" 2>/dev/null || true
}

fail_action() {
  log_hook_failure "$1"
  echo "defenseclaw: codex hook error: $1" >&2
  if [ "$FAIL_MODE" = "open" ]; then
    exit 0
  fi
  exit 2
}

AUTH_HEADER_ARGS=()
if [ -n "${API_TOKEN}" ]; then
  AUTH_HEADER_ARGS=(-H "Authorization: Bearer ${API_TOKEN}")
fi

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "http://${API_ADDR}/api/v1/codex/hook" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: codex-hook/1.0" \
  "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}" \
  --connect-timeout 2 \
  --max-time 10 \
  -d "$PAYLOAD" 2>/dev/null) || {
  fail_action "gateway unreachable"
}

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
RESULT=$(echo "$RESPONSE" | sed '$d')

if [ -z "$HTTP_CODE" ] || [ "$HTTP_CODE" -lt 200 ] 2>/dev/null || [ "$HTTP_CODE" -ge 300 ] 2>/dev/null; then
  fail_action "gateway returned HTTP ${HTTP_CODE:-unknown}"
fi

OUTPUT=$(echo "$RESULT" | jq -c '.codex_output // empty' 2>/dev/null) || {
  fail_action "invalid JSON response"
}
if [ -n "$OUTPUT" ] && [ "$OUTPUT" != "null" ]; then
  echo "$OUTPUT"
fi

ACTION=$(echo "$RESULT" | jq -r '.action // "allow"' 2>/dev/null) || {
  fail_action "failed to parse action from response"
}
if [ "$ACTION" = "block" ]; then
  exit 2
fi
exit 0
