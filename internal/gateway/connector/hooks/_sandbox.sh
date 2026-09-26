#!/bin/bash
# defenseclaw-managed-hook v1
# DefenseClaw OpenShell sandbox transport helpers.
#
# Rendered only into DefenseClaw's OpenShell overlay images, where it is
# root-owned and read-only to the workload, and sourced by the sandbox
# variants of the hooks right after _hardening.sh. Host hook directories never
# contain this file.
#
# Everything a hook needs to reach DefenseClaw is baked here at image build:
# the ingress address (host.openshell.internal, relayed by the OpenShell
# supervisor to the host-loopback hook ingress) and the request budgets. The
# only runtime input is the per-sandbox binding token, which OpenShell
# delivers as a provider placeholder in DEFENSECLAW_SANDBOX_TOKEN and swaps
# for the real credential only on the ingress endpoint.

# The workload can shape the environment every hook inherits (project
# settings env blocks, exported variables). Remove the loader, shell-startup,
# curl-configuration and proxy inputs before any child process starts; the
# ingress requests below also pass -q and --noproxy '*'. The payload cap is
# reset to the helper default for the same reason.
unset LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT BASH_ENV ENV CURL_HOME \
      http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy \
      NO_PROXY no_proxy DEFENSECLAW_HOOK_MAX_BODY

readonly DEFENSECLAW_SANDBOX_INGRESS="{{.APIAddr}}"
readonly DEFENSECLAW_SANDBOX_CONNECT_TIMEOUT={{.SandboxConnectTimeout}}
readonly DEFENSECLAW_SANDBOX_MAX_TIME={{.SandboxMaxTime}}
readonly DEFENSECLAW_SANDBOX_RETRY_MAX_TIME={{.SandboxRetryMaxTime}}
readonly DEFENSECLAW_SANDBOX_SESSION_END_MAX_TIME={{.SandboxSessionEndMaxTime}}

# defenseclaw_sandbox_require_token CONNECTOR HOOK_NAME SUBJECT
#
# The binding token is the only credential a sandbox hook may present. A
# missing or malformed token always fails closed: a sandbox hook never falls
# back to a host token file or to an unauthenticated request.
defenseclaw_sandbox_require_token() {
  local connector="${1:-unknown}"
  local hook_name="${2:-unknown}"
  local subject="${3:-tool}"
  local reason=""
  case "${DEFENSECLAW_SANDBOX_TOKEN:-}" in
    '') reason="missing sandbox binding token (DEFENSECLAW_SANDBOX_TOKEN unset)" ;;
    *$'\n'*|*$'\r'*) reason="malformed sandbox binding token" ;;
  esac
  if [ -z "$reason" ]; then
    return 0
  fi
  defenseclaw_log_hook_failure "$connector" "$hook_name" "$reason" transport closed
  echo "defenseclaw: ${reason}, blocking ${subject} (sandbox hooks fail closed)" >&2
  exit 2
}

# defenseclaw_sandbox_idempotency_key prints a fresh 128-bit random key, or
# nothing when the kernel offers no randomness source. The key names one hook
# invocation so the ingress can answer a retry from its dedupe window instead
# of evaluating the same event twice; it must not be guessable by the workload.
defenseclaw_sandbox_idempotency_key() {
  local key=""
  if [ -r /proc/sys/kernel/random/uuid ]; then
    IFS= read -r key < /proc/sys/kernel/random/uuid 2>/dev/null || key=""
  fi
  case "$key" in
    ????????-????-????-????-????????????) ;;
    *) key="" ;;
  esac
  case "$key" in
    *[!0-9a-f-]*) key="" ;;
  esac
  if [ -z "$key" ] && [ -r /dev/urandom ] && command -v od >/dev/null 2>&1; then
    key="$(od -An -N16 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')" || key=""
    case "$key" in
      ????????????????????????????????) ;;
      *) key="" ;;
    esac
    case "$key" in
      *[!0-9a-f]*) key="" ;;
    esac
  fi
  printf '%s' "$key"
}

# defenseclaw_sandbox_post PATH BODY MAX_TIME RETRY_MAX_TIME [CURL_ARGS...]
#
# POSTs BODY to the baked ingress and prints "<response body>\n<http code>",
# the same shape the host hooks read from curl -w. A transport failure (no
# connection, empty reply, timeout) or a relay 502/503/504 is retried exactly
# once with the same X-DefenseClaw-Hook-Idempotency-Key: the OpenShell relay
# occasionally drops a request, possibly after the ingress acted on it, and the
# ingress dedupes retries by key. Without a random key the request is sent
# once. The body travels on stdin so large payloads never hit the argv limit.
defenseclaw_sandbox_post() {
  local path="$1"
  local body="$2"
  local max_time="$3"
  local retry_max_time="$4"
  shift 4
  local key attempts=1 attempt=1 status out code
  local key_args=()
  key="$(defenseclaw_sandbox_idempotency_key)"
  if [ -n "$key" ]; then
    key_args=(-H "X-DefenseClaw-Hook-Idempotency-Key: ${key}")
    attempts=2
  fi
  while :; do
    status=0
    out="$(printf '%s' "$body" | curl -q -s --noproxy '*' -w '\n%{http_code}' -X POST \
      "http://${DEFENSECLAW_SANDBOX_INGRESS}${path}" \
      "${key_args[@]+"${key_args[@]}"}" \
      "$@" \
      --connect-timeout "$DEFENSECLAW_SANDBOX_CONNECT_TIMEOUT" \
      --max-time "$max_time" \
      --data-binary @- 2>/dev/null)" || status=$?
    if [ "$status" -eq 0 ]; then
      code="${out##*$'\n'}"
      case "$code" in
        502|503|504) status=1 ;;
      esac
    fi
    if [ "$status" -eq 0 ] || [ "$attempt" -ge "$attempts" ]; then
      break
    fi
    attempt=$((attempt + 1))
    max_time="$retry_max_time"
  done
  if [ "$status" -ne 0 ]; then
    return "$status"
  fi
  printf '%s' "$out"
}
