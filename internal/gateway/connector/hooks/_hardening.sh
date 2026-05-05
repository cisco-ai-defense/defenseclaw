#!/bin/bash
# defenseclaw-managed-hook v3
# Plan B4 / S0.4: shell-side hook hardening helpers.
#
# Schema versions:
#   v2 — initial hardening helpers (rlimit, env sanitization,
#        defenseclaw_handle_missing_token, plain
#        defenseclaw_log_hook_failure CONNECTOR HOOK REASON FAIL_MODE).
#   v3 — defenseclaw_log_hook_failure grew a CATEGORY argument
#        (transport|response) that lets operators tell infra outages
#        apart from misconfiguration in hook-failures.jsonl. Hook
#        scripts in this directory (claude-code-hook.sh, codex-hook.sh,
#        inspect-*.sh) pass the new arg in slot 4; older helpers
#        misroute it into FAIL_MODE, dropping the category field. The
#        version digit is therefore load-bearing: writeHookHelpers
#        compares it against the on-disk file and refuses to downgrade
#        so an older `defenseclaw-gateway restart` can't silently
#        clobber a newer install.
#
# Sourced at the top of every hook in this directory (claude-code-hook.sh,
# codex-hook.sh, inspect-*.sh) BEFORE any agent-supplied data is touched.
# The Go side already strips dangerous git env (sanitizeHookCWD +
# safeGitEnv); this file gives the shell-side scripts the matching
# defense surface so a rogue agent can't influence the hook by exporting
# GIT_*, HOME, PATH, etc. before invoking it.
#
# Usage:
#   . "$(dirname "${BASH_SOURCE[0]}")/_hardening.sh"
#   defenseclaw_harden_env
#   defenseclaw_harden_resources
#
# All helpers (except defenseclaw_log_hook_failure, which writes to
# DEFENSECLAW_HOME/logs) are idempotent and pure — no side effects
# beyond setting env / ulimit. They MUST NOT call out to the agent or
# the gateway.

# Resource limits — bound the hook so a stuck regex / hostile input
# can't wedge the agent. Plan F16 ask: CPU 5s, virt mem 512MiB, fds 32.
# Use ulimit -S (soft) so the hook doesn't try to exceed kernel maxima
# on platforms where defaults differ; soft limits still cause SIGXCPU
# / mmap failure when crossed, which is what we want.
defenseclaw_harden_resources() {
  ulimit -S -t 5     2>/dev/null || true
  ulimit -S -v 524288 2>/dev/null || true
  ulimit -S -n 32    2>/dev/null || true
}

# Sanitize PATH and git environment. Goal: any subprocess this hook
# spawns sees a known-good search path (no $HOME/bin first, no agent-
# injected entries) and a git that ignores user / system config.
defenseclaw_harden_env() {
  # Per-hook ephemeral HOME so any tool that stores state under $HOME
  # (gh, gcloud, openssl rand state, etc.) writes to a sandbox the
  # hook tears down on exit. Fall back to the gateway data dir if
  # mktemp is unavailable.
  if command -v mktemp >/dev/null 2>&1; then
    DEFENSECLAW_HOOK_HOME="$(mktemp -d -t defenseclaw-hook.XXXXXXXX 2>/dev/null || true)"
  fi
  if [ -z "${DEFENSECLAW_HOOK_HOME:-}" ]; then
    DEFENSECLAW_HOOK_HOME="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}/hook-tmp.$$"
    mkdir -p "$DEFENSECLAW_HOOK_HOME" 2>/dev/null || true
  fi
  export HOME="$DEFENSECLAW_HOOK_HOME"
  trap '_defenseclaw_hook_cleanup' EXIT

  export GIT_CONFIG_NOSYSTEM=1
  export GIT_CONFIG_GLOBAL=/dev/null
  unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY \
        GIT_CONFIG GIT_NAMESPACE GIT_OPTIONAL_LOCKS \
        GIT_TRACE GIT_TRACE_PACKET GIT_TRACE_PACK_ACCESS \
        GIT_SSH GIT_SSH_COMMAND

  # Lock down PATH — keep only the standard system bins where curl /
  # jq / sed / tail / cat / mktemp must live. Operators (and tests)
  # that need a custom path must set DEFENSECLAW_HOOK_PATH explicitly;
  # the variable is sticky across the script so any subsequent
  # subprocess inherits it. Setting it to an empty string disables
  # the override and falls back to the locked-down default.
  if [ -n "${DEFENSECLAW_HOOK_PATH:-}" ]; then
    export PATH="$DEFENSECLAW_HOOK_PATH"
  else
    export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
  fi

  # Keep the locale predictable so jq output / sed regex behavior
  # don't shift under the agent's locale.
  export LC_ALL=C
  export LANG=C
}

_defenseclaw_hook_cleanup() {
  if [ -n "${DEFENSECLAW_HOOK_HOME:-}" ] && [ -d "${DEFENSECLAW_HOOK_HOME}" ]; then
    case "$DEFENSECLAW_HOOK_HOME" in
      /tmp/*|/var/folders/*|"${DEFENSECLAW_HOME:-/dev/null}"/hook-tmp.*)
        rm -rf -- "$DEFENSECLAW_HOOK_HOME" 2>/dev/null || true
        ;;
    esac
  fi
}

# defenseclaw_validate_path checks that $1 matches the allow-list
# regex for path-like values pulled from agent payloads. Returns 0
# when safe, 1 when rejected. Use for any payload-derived string the
# hook subsequently passes to a subprocess.
defenseclaw_validate_path() {
  local val="$1"
  case "$val" in
    *$'\n'*|*$'\r'*|*$'\0'*) return 1 ;;
  esac
  # Allow-list: alphanumeric, underscore, dot, dash, slash. Reject
  # everything else (including spaces) so a payload can't smuggle
  # shell metacharacters into a downstream command.
  case "$val" in
    *[!A-Za-z0-9_./-]*) return 1 ;;
  esac
  return 0
}

# defenseclaw_resolve_cwd walks $PWD through realpath and refuses if
# the resolved path doesn't exist. Sets DEFENSECLAW_HOOK_CWD on
# success. The Go side enforces that the resolved path lives under
# the gateway data dir for git-touching hooks; the shell side mirrors
# this for hooks that don't go through the Go API.
defenseclaw_resolve_cwd() {
  local resolved
  if command -v realpath >/dev/null 2>&1; then
    resolved="$(realpath -e -- "${PWD:-/}" 2>/dev/null || true)"
  else
    resolved="${PWD:-/}"
  fi
  if [ -z "$resolved" ] || [ ! -d "$resolved" ]; then
    return 1
  fi
  DEFENSECLAW_HOOK_CWD="$resolved"
  export DEFENSECLAW_HOOK_CWD
  return 0
}

defenseclaw_json_escape() {
  {
    printf '%s' "${1:-}" | tr '\000-\037' ' ' | sed 's/\\/\\\\/g; s/"/\\"/g'
  } 2>/dev/null || printf unavailable
  return 0
}

# defenseclaw_log_hook_failure writes a structured JSON line to
# $DEFENSECLAW_HOME/logs/hook-failures.jsonl. All argument values are
# escaped before serialization so hostile strings can't smuggle a forged
# log entry past downstream parsers. Always returns 0 — logging must
# never fail the hook.
#
# Usage:
#   defenseclaw_log_hook_failure CONNECTOR HOOK_NAME REASON CATEGORY FAIL_MODE
#
# CATEGORY is one of: "transport" (gateway unreachable / 5xx) or
# "response" (4xx / parse error). The category lets operators tell the
# difference between an outage (infrastructure) and a misconfiguration
# (auth, bad payload) when triaging hook-failures.jsonl.
defenseclaw_log_hook_failure() {
  local connector="${1:-unknown}"
  local hook_name="${2:-unknown}"
  local reason="${3:-unknown}"
  local category="${4:-response}"
  local fail_mode="${5:-${FAIL_MODE:-open}}"
  local log_dir="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}/logs"
  mkdir -p "$log_dir" 2>/dev/null || return 0
  chmod 700 "$log_dir" 2>/dev/null || true
  local log_file="${log_dir}/hook-failures.jsonl"
  local ts
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date 2>/dev/null || printf unknown)"
  local safe_ts safe_connector safe_hook_name safe_reason safe_category safe_fail_mode
  safe_ts="$(defenseclaw_json_escape "$ts")"
  safe_connector="$(defenseclaw_json_escape "$connector")"
  safe_hook_name="$(defenseclaw_json_escape "$hook_name")"
  safe_reason="$(defenseclaw_json_escape "$reason")"
  safe_category="$(defenseclaw_json_escape "$category")"
  safe_fail_mode="$(defenseclaw_json_escape "$fail_mode")"
  printf '{"ts":"%s","connector":"%s","hook":"%s","reason":"%s","category":"%s","fail_mode":"%s"}\n' \
    "$safe_ts" "$safe_connector" "$safe_hook_name" "$safe_reason" "$safe_category" "$safe_fail_mode" \
    >> "$log_file" 2>/dev/null || true
  chmod 600 "$log_file" 2>/dev/null || true
  return 0
}

# defenseclaw_should_fail_closed_on_unreachable returns 0 (true) only
# when the operator has explicitly opted into strict availability via
# DEFENSECLAW_STRICT_AVAILABILITY=1. The default is to fail open on
# transport failures (gateway down / network error / 5xx) regardless
# of FAIL_MODE — a DefenseClaw outage must NEVER brick the user's
# coding agent. FAIL_MODE still governs response-layer failures (4xx,
# bad JSON, missing action) where the gateway answered but its answer
# was wrong; those represent likely misconfiguration that the operator
# should be told about loudly.
defenseclaw_should_fail_closed_on_unreachable() {
  case "${DEFENSECLAW_STRICT_AVAILABILITY:-0}" in
    1|true|TRUE|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

# defenseclaw_emit_unreachable_stderr writes a single stderr line whose
# verb (allowing/blocking) ACTUALLY matches what the hook is about to
# do on its next exit. The previous design unconditionally printed
# "allowing <subject>" and then exited 2 when
# DEFENSECLAW_STRICT_AVAILABILITY=1 was set, which lied to operators
# tailing stderr during an outage and made strict-mode incidents
# harder to triage. Centralizing the verb computation here means the
# six hook scripts can never drift on this contract.
#
# Usage:
#   defenseclaw_emit_unreachable_stderr SUBJECT REASON
#
# SUBJECT is a short noun describing what is allowed/blocked
# ("codex tool", "claude-code tool", "tool", "request", "response",
# "tool-response"). REASON is the underlying failure detail
# (e.g. "gateway unreachable", "gateway returned HTTP 502").
defenseclaw_emit_unreachable_stderr() {
  local subject="${1:-tool}"
  local reason="${2:-unknown}"
  if defenseclaw_should_fail_closed_on_unreachable; then
    echo "defenseclaw: gateway unreachable, blocking ${subject} (DEFENSECLAW_STRICT_AVAILABILITY=1): ${reason}" >&2
  else
    echo "defenseclaw: gateway unreachable, allowing ${subject}: ${reason}" >&2
  fi
}

# defenseclaw_handle_missing_token is the shared early-exit branch
# that codex-hook.sh and claude-code-hook.sh take when neither the
# companion .token file nor DEFENSECLAW_GATEWAY_TOKEN is present.
# Without a token the gateway will reject every request with 401, so
# the historical behaviour was to exit 0 ("can't talk to gateway →
# don't brick the agent"). That bypassed FAIL_MODE entirely.
#
# This helper preserves the historical default (allow-and-warn) but
# routes the bypass through the same DEFENSECLAW_STRICT_AVAILABILITY
# escape hatch as transport failures: an operator who explicitly opts
# into strict availability gets fail-closed even on a missing-token
# misconfiguration, AND every bypass — strict or not — is recorded in
# hook-failures.jsonl so the audit log is honest about the missed
# inspection.
#
# Usage:
#   defenseclaw_handle_missing_token CONNECTOR HOOK_NAME SUBJECT
#
# Exits 0 (allow) on the historical default path or 2 (block) when
# strict availability is set. Never returns to the caller.
defenseclaw_handle_missing_token() {
  local connector="${1:-unknown}"
  local hook_name="${2:-unknown}"
  local subject="${3:-tool}"
  local reason="missing gateway token (.token absent and DEFENSECLAW_GATEWAY_TOKEN unset)"
  defenseclaw_log_hook_failure "$connector" "$hook_name" "$reason" transport "${FAIL_MODE:-open}"
  if defenseclaw_should_fail_closed_on_unreachable; then
    echo "defenseclaw: ${reason}, blocking ${subject} (DEFENSECLAW_STRICT_AVAILABILITY=1)" >&2
    exit 2
  fi
  exit 0
}
