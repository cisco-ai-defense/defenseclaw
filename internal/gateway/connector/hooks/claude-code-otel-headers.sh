#!/bin/bash
# defenseclaw-managed-hook v1
# DefenseClaw Claude Code otelHeadersHelper (per-user Linux and macOS).
# Claude Code runs it at start and again every
# CLAUDE_CODE_OTEL_HEADERS_HELPER_DEBOUNCE_MS, and adds the JSON headers it
# prints to its OTLP exports. It prints the connector-scoped bearer only
# while the loopback API port is free or held by this account: another
# account that holds the port while this account's gateway is stopped gets
# no credential (GAP-1421). The first argument (tests only) replaces
# /proc/net.
set -uo pipefail

HOME="${HOME:-$(cd ~ 2>/dev/null && pwd)}"
export HOME
HOOK_DIR="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)" || exit 0
# This helper lives in <data dir>/hooks, whatever DEFENSECLAW_HOME says.
DEFENSECLAW_HOME="$(cd -P -- "${HOOK_DIR}/.." 2>/dev/null && pwd)" || exit 0
export DEFENSECLAW_HOME

ANONYMOUS='{"x-defenseclaw-source":"claudecode","x-defenseclaw-client":"claudecode-otel/1.0"}'
API_ADDR="{{.APIAddr}}"
if ! . "${HOOK_DIR}/_hardening.sh" 2>/dev/null || defenseclaw_api_listener_foreign "$API_ADDR" "${1:-}"; then
  printf '%s\n' "$ANONYMOUS"
  exit 0
fi
token=""
token_file="${HOOK_DIR}/.otlp-claudecode.token"
if [ -f "$token_file" ] && [ ! -L "$token_file" ]; then
  IFS= read -r -n 128 token < "$token_file" 2>/dev/null || true
fi
[ "${#token}" -eq 64 ] || token=""
case "$token" in
  ''|*[!0-9a-f]*)
    printf '%s\n' "$ANONYMOUS"
    exit 0
    ;;
esac
printf '{"authorization":"Bearer %s","x-defenseclaw-source":"claudecode","x-defenseclaw-client":"claudecode-otel/1.0"}\n' "$token"
