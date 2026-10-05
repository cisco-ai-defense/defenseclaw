#!/bin/bash
# defenseclaw-managed-hook v7
# Shell-side hook hardening helpers.
DEFENSECLAW_BAKED_HOOK_PATH=""
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
#   v4 — defenseclaw_harden_env now calls
#        _defenseclaw_sweep_stale_hook_dirs at the end so the legacy
#        fallback path (DEFENSECLAW_HOME/hook-tmp.$$, used when mktemp
#        is missing) doesn't accumulate orphaned directories from
#        crashed / SIGKILLed hooks where the EXIT trap never fires.
#        The sweep is best-effort; the EXIT-trap cleanup is still the
#        primary mechanism. Behaviour is otherwise identical to v3
#        (no helper signatures changed), so a downgrade to v3 only
#        loses the stale-dir sweep — older hook scripts that source
#        either version keep working unmodified.
#   v6 — adds the _dc_jq shim: real jq when available (unchanged on
#        Mac/Linux), python3 fallback for object + string fields, then a
#        pure-shell string-only last resort.  This makes block decisions
#        parse-able on hosts without jq.  No helper signatures changed;
#        hook scripts just replace bare `jq` calls with `_dc_jq`.
#        NOTE: an earlier iteration of v6 also restored curl/jq directories
#        from the pre-lockdown PATH after hardening. That was removed because
#        the pre-lockdown PATH is agent-controlled and restoring one of its
#        directories could re-admit an agent-planted binary. Windows no
#        longer uses these bash hooks (it runs the hook natively in the Go
#        binary), so the Git Bash /mingw64 workaround is no longer needed.
#   v7 — adds defenseclaw_user_identity_args, which the connector hooks
#        call to attach the real user's OS identity to the gateway
#        request. Call sites guard on the function being defined, so a
#        hook rendered by this build against an older helper loses the
#        per-user attribution rather than failing the hook. The bump is
#        how an operator tells "telemetry unattributed because the
#        helper predates it" from "unattributed because the lookup
#        failed".
#   v5 — adds defenseclaw_read_stdin_capped, a bounded replacement for
#        the historical PAYLOAD=$(cat) idiom. The unbounded read pulled
#        the entire agent payload into a shell variable BEFORE the
#        gateway's MaxBytesReader could trim it; a 100MB hostile body
#        could OOM the agent process. v5 caps the read at
#        ${DEFENSECLAW_HOOK_MAX_BODY:-1048576} bytes (1MB by default,
#        well above the largest legitimate prompt) using `head -c` and
#        emits a transport-category log line + fail-closed error when
#        the cap is exceeded so we don't silently truncate JSON.
#   v6 — adds W3C trace context forwarding helpers. Hooks can now
#        propagate an existing trace into the gateway via traceparent /
#        tracestate headers so a single span in the operator's APM
#        connects "agent saw tool call" → "gateway evaluated hook" →
#        "scanner emitted finding" → "audit row persisted". The two
#        new helpers:
#          - defenseclaw_extract_trace_context: parses
#            DEFENSECLAW_TRACEPARENT / DEFENSECLAW_TRACESTATE / the
#            OTEL_* equivalents from the agent's exported env. Returns
#            a curl -H argument array via stdout in line-buffered form
#            (one header per line) so callers can ingest it with
#            `mapfile -t TRACE_HEADER_ARGS < <(defenseclaw_extract_trace_context)`.
#          - defenseclaw_validate_traceparent: enforces the W3C format
#            (version-traceid-spanid-flags, 55 chars total, all hex)
#            before emitting the header so a hostile env value can't
#            forge an arbitrary string into the gateway's trace
#            context.
#        The Go side accepts the headers only on the two hook-bearing
#        routes (/api/v1/<connector>/hook, /api/v1/codex/notify) via
#        shouldExtractHookTrace, so an unscoped caller cannot splice
#        an arbitrary trace context into the gateway's trace tree.
#   v6 — refuses the stock macOS /usr/bin/python3 CLT launcher stub.
#        Adds _dc_python3_usable, which additionally verifies
#        `xcode-select -p` succeeds before trusting a python3 binary
#        under /usr/bin on Darwin, and switches both python3 call sites
#        (_dc_jq's fallback and defenseclaw_read_stdin_capped's tier 1)
#        to the new gate. Without the guard, QA on stock macOS hosts
#        (AVC + codex, no Xcode CLT) saw the "install command line
#        developer tools" GUI dialog pop on every hook invocation and
#        the subsequent codex hook then received an empty stdin payload,
#        posted a bad request to the gateway, and blocked the user's
#        prompt with a "codex hook error: gateway returned HTTP 400"
#        message. Internal-only helper; no hook-script signatures
#        changed and the schema marker stays at v6, so older gateways
#        that already wrote a v6 helper here (bare `command -v python3`
#        gate) still get the fix on next write via writeHookHelpers'
#        same-version bytes-different path.
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

# Windows compatibility: some agent runtimes (e.g. Codex on Windows) do
# not set HOME when spawning hook subprocesses. Without this, `set -u`
# causes an immediate "unbound variable" exit 1. Fall back to USERPROFILE
# (standard on Windows) or ~ expansion.
if [ -z "${HOME:-}" ]; then
  HOME="${USERPROFILE:-$(cd ~ 2>/dev/null && pwd)}"
  export HOME
fi

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
  _DEFENSECLAW_HOOK_HOME_OWNED=""
  # The account's real HOME, kept unexported for defenseclaw_gateway_cold_start.
  unset DEFENSECLAW_AGENT_HOME
  DEFENSECLAW_AGENT_HOME="${HOME:-}"
  if command -v mktemp >/dev/null 2>&1; then
    DEFENSECLAW_HOOK_HOME="$(mktemp -d -t defenseclaw-hook.XXXXXXXX 2>/dev/null || true)"
    if [ -n "$DEFENSECLAW_HOOK_HOME" ]; then
      _DEFENSECLAW_HOOK_HOME_OWNED=1
    fi
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

  # Lock down PATH — keep only standard system bins unless setup baked
  # a literal DEFENSECLAW_BAKED_HOOK_PATH into this helper file. Hooks
  # inherit the agent environment, so runtime DEFENSECLAW_HOOK_PATH (or
  # a companion "trusted" flag) is intentionally ignored; otherwise a
  # compromised agent could prepend trojan curl/jq/head.
  #
  # We deliberately do NOT restore any directory derived from the
  # pre-lockdown PATH. That PATH is agent-controlled, so adding one of its
  # directories back (to recover a curl/jq not on the hardened PATH) could
  # re-admit an agent-planted binary and defeat this lockdown. Tools that
  # are missing from the standard dirs are handled by the _dc_jq parsing
  # fallback below, not by widening PATH. On Windows the hook runs natively
  # in the DefenseClaw Go binary (no bash), so the previous Git Bash
  # /mingw64 special-casing is unnecessary here.
  unset DEFENSECLAW_HOOK_PATH DEFENSECLAW_HOOK_PATH_TRUSTED
  if [ -n "$DEFENSECLAW_BAKED_HOOK_PATH" ]; then
    export PATH="$DEFENSECLAW_BAKED_HOOK_PATH"
  else
    export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
  fi

  # Keep the locale predictable so jq output / sed regex behavior
  # don't shift under the agent's locale.
  export LC_ALL=C
  export LANG=C

  # L-3 (v4): best-effort sweep of stale fallback hook-tmp.* dirs
  # under DEFENSECLAW_HOME. The EXIT-trap cleanup above is still the
  # primary mechanism, but it's bypassed by SIGKILL / OOM / `kill -9`,
  # and on systems without mktemp every hook invocation creates
  # hook-tmp.<PID>. Without this sweep those orphans accumulate
  # forever. Runs AFTER PATH lockdown so we don't pick up an attacker-
  # planted `find`.
  _defenseclaw_sweep_stale_hook_dirs
}

# Resolve optional connector identity for the shared inspect-* scripts.  The
# selected connector is runtime state, never a render-time property of the one
# physical shared script.  Reject anything outside the connector-name grammar
# before it can participate in a token filename or HTTP header.
defenseclaw_shared_runtime_connector() {
  local connector="${DEFENSECLAW_CONNECTOR:-}"
  # Non-managed shells may supply an ephemeral connector selection, matching
  # the existing fail-mode/token override contract. Guardian-managed hooks do
  # not trust process environment for connector identity and use only the
  # installer-owned sidecars below.
  if [ "${DEFENSECLAW_MANAGED_HOOK:-0}" = "1" ]; then
    connector=""
  fi
  case "$connector" in
    *[!a-z0-9_-]*) return 0 ;;
    *) printf '%s' "$connector" ;;
  esac
  if [ -n "$connector" ]; then
    return 0
  fi
  local hook_dir="${1:-}"
  local candidate found="" suffix recorded
  for candidate in "${hook_dir}"/.hookcfg.*; do
    [ -f "$candidate" ] && [ ! -L "$candidate" ] || continue
    suffix="${candidate##*.hookcfg.}"
    [ "$suffix" != "legacy" ] && [ "$suffix" != "lock" ] || continue
    case "$suffix" in
      ""|*[!a-z0-9_-]*) continue ;;
    esac
    # Ignore lock files, interrupted atomic-write debris, and unrelated files
    # that merely share the prefix. A valid record must identify itself with
    # the exact connector encoded in its filename.
    recorded="$(defenseclaw_flat_hookcfg_value "$candidate" DEFENSECLAW_CONNECTOR 2>/dev/null || true)"
    [ "$recorded" = "$suffix" ] || continue
    if [ -n "$found" ]; then
      # Multiple connector records are intentionally ambiguous unless the
      # caller supplies DEFENSECLAW_CONNECTOR.
      return 0
    fi
    found="$suffix"
  done
  if [ -n "$found" ]; then
    printf '%s' "$found"
    return 0
  fi
  local config="${hook_dir}/.hookcfg"
  if [ -f "$config" ]; then
    if command -v jq >/dev/null 2>&1; then
      connector="$(jq -r '.fail_modes | keys | if length == 1 then .[0] else empty end' "$config" 2>/dev/null || true)"
    elif command -v python3 >/dev/null 2>&1; then
      connector="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1], encoding="utf-8")); k=list((d.get("fail_modes") or {}).keys()); print(k[0] if len(k)==1 else "")' "$config" 2>/dev/null || true)"
    fi
    case "$connector" in
      ""|*[!a-z0-9_-]*) return 0 ;;
      *) printf '%s' "$connector" ;;
    esac
  fi
}

defenseclaw_flat_hookcfg_value() {
  local config="$1"
  local wanted="$2"
  local key value
  [ -f "$config" ] && [ ! -L "$config" ] || return 1
  while IFS='=' read -r key value; do
    if [ "$key" = "$wanted" ]; then
      printf '%s' "$value"
      return 0
    fi
  done < "$config"
  return 1
}

# Return the shared legacy token path or the connector-scoped token path named
# by runtime state.  This does not search token files and never embeds one
# connector's credential path into shared script bytes.
defenseclaw_shared_hook_token_file() {
  local hook_dir="$1"
  local connector="${2:-}"
  if [ -n "$connector" ] && [ -f "${hook_dir}/.hook-${connector}.token" ]; then
    printf '%s/.hook-%s.token' "$hook_dir" "$connector"
  else
    printf '%s/.token' "$hook_dir"
  fi
}

# Resolve the selected connector's fail mode from the connector-aware shared
# runtime state.  An explicit process value still wins for non-managed
# ephemeral shells; guardian-managed hooks trust only installer-owned state.
# Malformed, ambiguous, or missing state fails closed.
defenseclaw_shared_runtime_fail_mode() {
  local hook_dir="$1"
  local connector="${2:-}"
  local mode="${DEFENSECLAW_FAIL_MODE:-}"
  if [ "${DEFENSECLAW_MANAGED_HOOK:-0}" = "1" ]; then
    mode=""
  fi
  local config="${hook_dir}/.hookcfg"
  local flat_config="${hook_dir}/.hookcfg.legacy"
  if [ -n "$connector" ]; then
    flat_config="${hook_dir}/.hookcfg.${connector}"
  fi
  if [ "$mode" != "open" ] && [ "$mode" != "closed" ]; then
    mode="$(defenseclaw_flat_hookcfg_value "$flat_config" DEFENSECLAW_FAIL_MODE 2>/dev/null || true)"
  fi
  if [ "$mode" != "open" ] && [ "$mode" != "closed" ] && [ -f "$config" ]; then
    if command -v jq >/dev/null 2>&1; then
      if [ -n "$connector" ]; then
        mode="$(jq -r --arg connector "$connector" '.fail_modes[$connector] // empty' "$config" 2>/dev/null || true)"
      else
        mode="$(jq -r '.legacy_fail_mode // empty' "$config" 2>/dev/null || true)"
      fi
    elif command -v python3 >/dev/null 2>&1; then
      mode="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1], encoding="utf-8")); c=sys.argv[2]; print((d.get("fail_modes") or {}).get(c, "") if c else d.get("legacy_fail_mode", ""))' "$config" "$connector" 2>/dev/null || true)"
    fi
  fi
  if [ "$mode" = "open" ]; then
    printf open
  else
    printf closed
  fi
}

# _defenseclaw_sweep_stale_hook_dirs removes orphaned hook-tmp.*
# directories under DEFENSECLAW_HOME that haven't been touched in 60+
# minutes. The 60-minute floor is the longest the hook itself can run
# (see VERSION_TIMEOUT_SECONDS / curl --max-time bounds: every hook
# completes within seconds, so any hook-tmp dir older than an hour is
# unambiguously orphaned). Best-effort; logs nothing because cleanup
# runs on a hot path and any noise here would race with the agent's
# own stdout/stderr. The find invocation is bounded:
#   - -maxdepth 1: never descend into the dirs we're removing
#   - -mindepth 1: don't accidentally rm DEFENSECLAW_HOME itself
#   - -name "hook-tmp.*": only the fallback-prefix pattern
#   - -mmin +60: older than 60 minutes
# Failure to find/rm is silently swallowed so a hardened FS (read-only
# DEFENSECLAW_HOME, missing find binary) can't break the hook.
_defenseclaw_sweep_stale_hook_dirs() {
  local root="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
  if [ ! -d "$root" ]; then
    return 0
  fi
  if ! command -v find >/dev/null 2>&1; then
    return 0
  fi
  find "$root" -mindepth 1 -maxdepth 1 -name "hook-tmp.*" -type d -mmin +60 \
    -exec rm -rf -- {} + 2>/dev/null || true
  return 0
}

_defenseclaw_hook_cleanup() {
  if [ -n "${DEFENSECLAW_HOOK_HOME:-}" ] && [ -d "${DEFENSECLAW_HOOK_HOME}" ]; then
    case "$DEFENSECLAW_HOOK_HOME" in
      /tmp/*|/var/folders/*|"${DEFENSECLAW_HOME:-/dev/null}"/hook-tmp.*)
        rm -rf -- "$DEFENSECLAW_HOOK_HOME" 2>/dev/null || true
        ;;
      */defenseclaw-hook.*)
        # mktemp -t honours TMPDIR, which some agents (Hermes) point at
        # their own cache; remove the directory this hook created there.
        if [ "${_DEFENSECLAW_HOOK_HOME_OWNED:-}" = 1 ]; then
          rm -rf -- "$DEFENSECLAW_HOOK_HOME" 2>/dev/null || true
        fi
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
  case "$val" in
    *..*) return 1 ;;
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

# defenseclaw_json_string_field extracts a simple top-level JSON string field.
# It is intentionally small: hook block/allow parsing only needs fields like
# "action" and "reason" when jq is unavailable (common in Git Bash on Windows).
defenseclaw_json_string_field() {
  local json="${1:-}"
  local field="${2:-}"
  local extracted status
  case "$field" in
    ""|*[!A-Za-z0-9_]*) return 1 ;;
  esac
  if ! command -v awk >/dev/null 2>&1; then
    return 2
  fi
  if extracted="$(printf '%s' "$json" | awk -v wanted="$field" '
    { text = text $0 "\n" }
    END {
      depth = 0
      started = 0
      found = 0
      n = length(text)
      for (i = 1; i <= n; i++) {
        c = substr(text, i, 1)
        if (!started) {
          if (c ~ /[[:space:]]/) continue
          if (c != "{") exit 2
          started = 1
          depth = 1
          continue
        }
        if (c == "\"") {
          start = i + 1
          escaped = 0
          for (j = start; j <= n; j++) {
            ch = substr(text, j, 1)
            if (escaped) { escaped = 0; continue }
            if (ch == "\\") { escaped = 1; continue }
            if (ch == "\"") break
          }
          if (j > n) exit 2
          token = substr(text, start, j - start)
          if (depth == 1) {
            k = j + 1
            while (k <= n && substr(text, k, 1) ~ /[[:space:]]/) k++
            if (substr(text, k, 1) == ":" && token == wanted) {
              if (found) exit 2
              v = k + 1
              while (v <= n && substr(text, v, 1) ~ /[[:space:]]/) v++
              if (substr(text, v, 1) != "\"") exit 2
              value_start = v + 1
              escaped = 0
              for (value_end = value_start; value_end <= n; value_end++) {
                ch = substr(text, value_end, 1)
                if (escaped) { escaped = 0; continue }
                if (ch == "\\") { escaped = 1; continue }
                if (ch == "\"") break
              }
              if (value_end > n) exit 2
              result = substr(text, value_start, value_end - value_start)
              found = 1
              i = value_end
              continue
            }
          }
          i = j
          continue
        }
        if (c == "{" || c == "[") depth++
        else if (c == "}" || c == "]") {
          depth--
          if (depth < 0) exit 2
          if (depth == 0) {
            if (found) { print result; exit 0 }
            exit 1
          }
        }
      }
      exit 2
    }
  ')"; then
    printf '%s' "$extracted" | sed 's/\\"/"/g; s/\\\\/\\/g; s/\\n/ /g; s/\\r/ /g; s/\\t/ /g'
    return 0
  else
    status=$?
    return "$status"
  fi
}

# _dc_python3_usable returns 0 when python3 is on PATH AND can be safely
# invoked. On stock macOS hosts without Xcode Command Line Tools,
# /usr/bin/python3 exists as a launcher stub that pops the "install
# command line developer tools" GUI dialog on first invocation and then
# exits non-zero without executing the script — a bare `command -v
# python3` check treats that stub as usable, and the resulting invocation
# both harasses the operator with an installer dialog and returns an
# empty body that fails the downstream hook (gateway sees a truncated
# payload, responds HTTP 400, hook fails closed and blocks the user's
# prompt). Skip the stub by verifying `xcode-select -p` succeeds when
# python3 resolves under /usr/bin on Darwin; if CLT is not installed,
# treat python3 as absent and fall through to the head(1) / string-only
# paths.
#
# `xcode-select -p` itself is safe to run without CLT: it is a macOS
# system binary (part of the base OS, not CLT) whose only side effect
# is to print the currently selected developer directory or exit 2. The
# GUI installer dialog is triggered by `xcode-select --install`, which
# this helper never invokes.
_dc_python3_usable() {
  local _dc_p3 _dc_uname
  _dc_p3="$(command -v python3 2>/dev/null || printf '')"
  [ -n "$_dc_p3" ] || return 1
  _dc_uname="$(uname -s 2>/dev/null || printf unknown)"
  case "$_dc_uname" in
    Darwin) : ;;
    *) return 0 ;;
  esac
  case "$_dc_p3" in
    /usr/bin/python3*)
      # Any /usr/bin/python3* on macOS is a CLT-managed path; the base
      # OS itself does not ship a working Python interpreter there.
      # Confirm CLT is present before trusting the binary.
      xcode-select -p >/dev/null 2>&1 || return 1
      ;;
  esac
  return 0
}

# _dc_jq is a drop-in shim for jq covering the small subset of filters
# used by DefenseClaw hook scripts.  When the real jq binary is present
# (all Unix installs; some Windows installs) it is used unchanged.
# When jq is absent the shim tries python3 (handles both string and
# object fields such as claude_code_output), then falls back to
# defenseclaw_json_string_field for string-only fields. For object fields
# (e.g. codex_output), a valid response where the field is absent still
# produces the requested jq default. A present structured value cannot be
# decoded by the string-only fallback and fails closed at the response layer.
#
# The python3 probe uses _dc_python3_usable, which refuses the stock
# macOS /usr/bin/python3 CLT stub. Without that guard, `command -v
# python3` returns success on a stock Mac, we invoke the stub, macOS
# pops the "install command line developer tools" dialog, and the
# subsequent gateway call fails with HTTP 400. See _dc_python3_usable
# above for the full rationale.
#
# Supported filter forms (covers all patterns in DefenseClaw hooks):
#   .field                    — raw value
#   .field // empty           — value or nothing on null/missing
#   .field // "default"       — value or literal default string
#
# Flags honored: -r (raw string output), -c (compact JSON output)
# shellcheck disable=SC2120
_dc_jq() {
  if command -v jq >/dev/null 2>&1; then
    jq "$@"
    return
  fi
  local _dcjq_raw=0 _dcjq_compact=0 _dcjq_exit=0 _dcjq_filter=""
  for _dcjq_a in "$@"; do
    case "$_dcjq_a" in
      -r)   _dcjq_raw=1 ;;
      -c)   _dcjq_compact=1 ;;
      # -e sets exit status from the output (used as a JSON-validity probe,
      # e.g. `_dc_jq -e .`). Without it the identity filter would be parsed
      # as the literal filter "-e" and the probe would silently misbehave.
      -e)   _dcjq_exit=1 ;;
      # Handle accidental merged forms: -r.field or -c.field (no space)
      -r.*) _dcjq_raw=1;     _dcjq_filter="${_dcjq_a#-r}" ;;
      -c.*) _dcjq_compact=1; _dcjq_filter="${_dcjq_a#-c}" ;;
      *)    _dcjq_filter="$_dcjq_a" ;;
    esac
  done
  # Python3 fallback: handles both string scalars and nested objects.
  # All values are passed via env to avoid shell quoting issues.
  # The script uses only double-quoted Python strings so it is safe
  # inside shell single quotes.
  #
  # _dc_python3_usable (not a bare `command -v python3`) guards the probe
  # so we never invoke the macOS CLT stub at /usr/bin/python3, which
  # would trigger an "install command line developer tools" GUI dialog
  # and return no output.
  if _dc_python3_usable; then
    DCJQ_FILTER="$_dcjq_filter" DCJQ_RAW="$_dcjq_raw" DCJQ_COMPACT="$_dcjq_compact" \
    DCJQ_EXIT="$_dcjq_exit" \
      python3 -c \
'import json,sys,os,re
f=os.environ.get("DCJQ_FILTER","")
raw=os.environ.get("DCJQ_RAW","0")=="1"
compact=os.environ.get("DCJQ_COMPACT","0")=="1"
exit_test=os.environ.get("DCJQ_EXIT","0")=="1"
try:
  data=json.load(sys.stdin)
except Exception:
  sys.exit(1)
fs=f.strip()
if fs in (".",""):
  # Identity filter / validity probe (jq -e .): valid JSON exits 0.
  if exit_test and (data is None or data is False):
    sys.exit(1)
  sep=(",",":") if compact else (", ",": ")
  sys.stdout.write((data if (raw and isinstance(data,str)) else json.dumps(data,separators=sep))+"\n")
  sys.exit(0)
m=re.match(r"^\.(\w+)\s*(?://\s*(.+))?$",fs)
if not m:
  sys.exit(1)
field=m.group(1)
dflt=(m.group(2) or "").strip()
val=data.get(field)
if val is None:
  if dflt in ("empty","null",""):
    sys.exit(0)
  dm=re.match(r"^\"(.*)\"$",dflt)
  sys.stdout.write((dm.group(1) if dm else dflt)+"\n")
  sys.exit(0)
if isinstance(val,str):
  sys.stdout.write(val+"\n")
else:
  sep=(",",":") if compact else (", ",": ")
  sys.stdout.write(json.dumps(val,separators=sep)+"\n")'
    return
  fi
  # String-only last resort: covers action / reason / block_reason. Object
  # fields cannot be decoded safely without jq or python3, so fail instead of
  # returning an empty value that could turn a structured deny into allow.
  local _dcjq_field _dcjq_default _dcjq_default_kind _dcjq_value _dcjq_json _dcjq_status
  case "$_dcjq_filter" in
    .|"") cat >/dev/null; return 1 ;;
  esac
  _dcjq_field="${_dcjq_filter#.}"
  _dcjq_field="${_dcjq_field%%//*}"
  _dcjq_field="${_dcjq_field%%[[:space:]]*}"
  _dcjq_default="null"
  _dcjq_default_kind="value"
  case "$_dcjq_filter" in
    *"//"*)
      _dcjq_default="${_dcjq_filter#*//}"
      _dcjq_default="${_dcjq_default#"${_dcjq_default%%[![:space:]]*}"}"
      _dcjq_default="${_dcjq_default%"${_dcjq_default##*[![:space:]]}"}"
      case "$_dcjq_default" in
        empty) _dcjq_default=""; _dcjq_default_kind="empty" ;;
        "") cat >/dev/null; return 1 ;;
        null) _dcjq_default="null" ;;
        \"*\")
          _dcjq_default="${_dcjq_default#\"}"
          _dcjq_default="${_dcjq_default%\"}"
          ;;
        *) cat >/dev/null; return 1 ;;
      esac
      ;;
  esac
  case "$_dcjq_field" in
    action|reason|block_reason|decision|permissionDecision|permissionDecisionReason|hook_event_name)
      _dcjq_json="$(cat)"
      if _dcjq_value="$(defenseclaw_json_string_field "$_dcjq_json" "$_dcjq_field")"; then
        printf '%s\n' "$_dcjq_value"
      else
        _dcjq_status=$?
        if [ "$_dcjq_status" -eq 1 ]; then
          if [ "$_dcjq_default_kind" != "empty" ]; then
            printf '%s\n' "$_dcjq_default"
          fi
        else
          return 1
        fi
      fi
      ;;
    *)
      _dcjq_json="$(cat)"
      if _dcjq_value="$(defenseclaw_json_string_field "$_dcjq_json" "$_dcjq_field")"; then
        # This fallback cannot validate an object field that is present as a
        # string. Treat it as a schema error instead of emitting an attacker-
        # controlled scalar where the hook expects structured JSON.
        return 1
      else
        _dcjq_status=$?
      fi
      if [ "$_dcjq_status" -eq 1 ]; then
        if [ "$_dcjq_default_kind" != "empty" ]; then
          printf '%s\n' "$_dcjq_default"
        fi
        return 0
      fi
      return 1
      ;;
  esac
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
  # stderr is redirected before the append so a failed open of the log
  # (full disk, read-only home) cannot print a shell diagnostic naming this
  # script into the agent-visible block reason (GAP-1974).
  printf '{"ts":"%s","connector":"%s","hook":"%s","reason":"%s","category":"%s","fail_mode":"%s"}\n' \
    "$safe_ts" "$safe_connector" "$safe_hook_name" "$safe_reason" "$safe_category" "$safe_fail_mode" \
    2>/dev/null >> "$log_file" || true
  chmod 600 "$log_file" 2>/dev/null || true
  return 0
}

# defenseclaw_gateway_binary DATA_DIR HOME prints the per-user gateway binary
# a cold start runs: the one that last ran this data directory, then the
# installer's ~/.local/bin, then the hardened PATH.
defenseclaw_gateway_binary() {
  local data="$1" home="$2" record="" candidate=""
  if [ -f "${data}/gateway.pid" ]; then
    IFS= read -r -n 4096 record < "${data}/gateway.pid" 2>/dev/null || true
    if [[ "$record" =~ \"executable\"[[:space:]]*:[[:space:]]*\"(/[^\"]+)\" ]]; then
      candidate="${BASH_REMATCH[1]}"
      case "$candidate" in
        */defenseclaw-gateway)
          if [ -f "$candidate" ] && [ -x "$candidate" ]; then
            printf '%s' "$candidate"
            return 0
          fi
          ;;
      esac
    fi
  fi
  candidate="${home}/.local/bin/defenseclaw-gateway"
  if [ -f "$candidate" ] && [ -x "$candidate" ]; then
    printf '%s' "$candidate"
    return 0
  fi
  candidate="$(command -v defenseclaw-gateway 2>/dev/null)" || return 1
  case "$candidate" in
    /*) [ -x "$candidate" ] && printf '%s' "$candidate" && return 0 ;;
  esac
  return 1
}

# defenseclaw_gateway_cold_start CURL_STATUS starts this account's per-user
# gateway when the hook's request was refused (curl exit 7): nothing else
# starts a per-user gateway after a reboot on Linux or macOS. It returns 0
# once `defenseclaw-gateway start --hook-cold-start` reports the gateway
# ready, and the caller retries its request once; any other outcome returns
# 1 and the caller fails as unreachable. It never starts a gateway that was
# stopped with `defenseclaw-gateway stop` (gateway.stopped), during an
# install (.install.lock), for a managed or socket hook, or when
# DEFENSECLAW_GATEWAY_AUTOSTART is 0. The start command serializes
# concurrent hooks and backs off after a failure. This is the one helper
# that calls out to the gateway's own CLI.
defenseclaw_gateway_cold_start() {
  [ "${1:-}" = "7" ] || return 1
  case "${DEFENSECLAW_MANAGED_HOOK:-0}" in
    1|true|TRUE|yes|YES) return 1 ;;
  esac
  case "${DEFENSECLAW_GATEWAY_AUTOSTART:-1}" in
    0|false|FALSE|no|NO|off|OFF) return 1 ;;
  esac
  [ -z "${DEFENSECLAW_HOOK_SOCKET:-}" ] || return 1
  local home="${DEFENSECLAW_AGENT_HOME:-}" data="" bin=""
  [ -n "$home" ] && [ -d "$home" ] || return 1
  data="${DEFENSECLAW_HOME:-${home}/.defenseclaw}"
  [ -d "$data" ] && [ -f "${data}/config.yaml" ] || return 1
  [ ! -e "${data}/gateway.stopped" ] || return 1
  [ ! -e "${data}/.install.lock" ] || return 1
  [ ! -e "${data}/.disabled" ] || return 1
  bin="$(defenseclaw_gateway_binary "$data" "$home")" || return 1
  # The gateway keeps running after the hook exits: give it the account's
  # HOME and installer bin directory, drop the hook's git and locale pins,
  # and lift the hook's soft resource limits back to the hard ones.
  (
    ulimit -S -t "$(ulimit -H -t)" 2>/dev/null || true
    ulimit -S -v "$(ulimit -H -v)" 2>/dev/null || true
    exec env -u GIT_CONFIG_NOSYSTEM -u GIT_CONFIG_GLOBAL -u LC_ALL -u LANG \
      HOME="$home" PATH="${home}/.local/bin:${PATH}" \
      "$bin" start --hook-cold-start </dev/null >/dev/null 2>&1
  )
}

# defenseclaw_own_gateway_stopped returns 0 when this account's per-user
# gateway is not running (no gateway.pid, or its process is gone). A 401 then
# came from another listener on the port, typically another account's gateway
# on the same default port, so token drift is the wrong diagnosis. Managed
# hooks and unreadable records keep the token advice.
defenseclaw_own_gateway_stopped() {
  case "${DEFENSECLAW_MANAGED_HOOK:-0}" in
    1|true|TRUE|yes|YES) return 1 ;;
  esac
  local pid_file="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}/gateway.pid"
  local data="" pid=""
  [ -e "$pid_file" ] || return 0
  IFS= read -r -n 4096 data < "$pid_file" 2>/dev/null || [ -n "$data" ] || return 1
  if [[ "$data" =~ \"pid\"[[:space:]]*:[[:space:]]*([0-9]+) ]]; then
    pid="${BASH_REMATCH[1]}"
  elif [[ "$data" =~ ^[[:space:]]*([0-9]+)[[:space:]]*$ ]]; then
    pid="${BASH_REMATCH[1]}"
  else
    return 1
  fi
  kill -0 "$pid" 2>/dev/null && return 1
  return 0
}

# defenseclaw_api_listener_foreign HOST:PORT returns 0 when this account's
# per-user gateway is not running and the loopback listener on PORT belongs to
# another account (GAP-1260). The hook then sends it no token or payload: an
# account that holds this account's port, or its old port after a move, would
# otherwise collect the connector's credential. A running gateway rendered the
# current API_ADDR itself, so the check costs only the PID test then. Linux
# reads the owner from /proc/net/tcp*; macOS lsof lists only this account's
# sockets, so a listener it does not show that still accepts is another's.
defenseclaw_api_listener_foreign() {
  case "${DEFENSECLAW_MANAGED_HOOK:-0}" in
    1|true|TRUE|yes|YES) return 1 ;;
  esac
  [ -z "${DEFENSECLAW_HOOK_SOCKET:-}" ] || return 1
  defenseclaw_own_gateway_stopped || return 1
  # The second argument (tests only) replaces /proc/net.
  local port="${1##*:}" net="${2:-/proc/net}" uid="${EUID:-}" hex="" table="" owner=""
  local _sl="" addr="" _rem="" st="" _q="" _t="" _r="" u="" _rest=""
  case "$port" in ''|*[!0-9]*) return 1 ;; esac
  [ -n "$uid" ] || return 1
  if [ -r "${net}/tcp" ]; then
    hex="$(printf '%04X' "$port")"
    for table in "${net}/tcp" "${net}/tcp6"; do
      [ -r "$table" ] || continue
      while read -r _sl addr _rem st _q _t _r u _rest; do
        [ "$st" = "0A" ] || continue
        case "$addr" in
          # 127.0.0.0/8, 0.0.0.0, ::, ::1 and v4-mapped loopback, kernel byte order.
          ??????7F:"$hex"|00000000:"$hex"|00000000000000000000000000000000:"$hex"|00000000000000000000000001000000:"$hex"|0000000000000000FFFF0000??????7F:"$hex") ;;
          *) continue ;;
        esac
        [ "$u" = "$uid" ] && return 1
        owner="$u"
      done < "$table"
    done
    [ -n "$owner" ]
    return
  fi
  if [ -x /usr/sbin/lsof ]; then
    /usr/sbin/lsof -nP -a -u "$uid" -iTCP:"$port" -sTCP:LISTEN -t >/dev/null 2>&1 && return 1
    (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null && return 0
  fi
  return 1
}

defenseclaw_response_failure_reason() {
  case "$1" in
    *"HTTP 401"*|*"HTTP 403"*)
      if defenseclaw_own_gateway_stopped; then
        printf '%s (this account'"'"'s gateway is not running, so another account or program answered on its port. Run `defenseclaw-gateway start`; if another account holds the port, it names a free one.)' "$1"
      else
        printf '%s (gateway auth failed; possible token drift. Run `defenseclaw doctor --fix` or `defenseclaw-gateway restart`.)' "$1"
      fi
      ;;
    *)
      printf '%s' "$1"
      ;;
  esac
}

# defenseclaw_should_fail_closed_on_unreachable returns 0 (true) when the
# connector's effective fail mode is closed, for guardian-installed managed
# hooks, or when strict availability is enabled. Fail mode therefore has one
# consistent meaning across malformed responses, auth failures, and transport
# failures instead of silently opening only the latter class.
defenseclaw_should_fail_closed_on_unreachable() {
  case "${FAIL_MODE:-open}" in
    closed) return 0 ;;
  esac
  case "${DEFENSECLAW_MANAGED_HOOK:-0}" in
    1|true|TRUE|yes|YES) return 0 ;;
  esac
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
  # The lead already says "gateway unreachable": name the cause and the next
  # step after the colon instead of repeating it (GAP-1204).
  if [ "$reason" = "gateway unreachable" ]; then
    local next=""
    next="$(defenseclaw_unreachable_next_step)"
    [ -z "$next" ] || reason="$next"
  fi
  if defenseclaw_should_fail_closed_on_unreachable; then
    echo "defenseclaw: gateway unreachable, blocking ${subject} (fail mode closed): ${reason}" >&2
  else
    echo "defenseclaw: gateway unreachable, allowing ${subject}: ${reason}" >&2
  fi
}

# defenseclaw_unreachable_notice_json prints a one-line hook result whose
# systemMessage tells the user that DefenseClaw is not checking this session
# and how to resume, when this account's own per-user gateway is down. A
# fail-open hook exits 0, and Claude Code and Codex do not show stderr then:
# the systemMessage is the only text the user sees. It prints nothing when
# the gateway is not this account's to start (managed or socket hooks).
defenseclaw_unreachable_notice_json() {
  local next="" text=""
  next="$(defenseclaw_unreachable_next_step)"
  [ -n "$next" ] || return 0
  local data="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
  if [ -e "${data}/gateway.stopped" ]; then
    text='DefenseClaw is not checking this session: the gateway was stopped with `defenseclaw-gateway stop`. Run `defenseclaw-gateway start` to resume protection.'
  elif defenseclaw_own_gateway_alive; then
    text='DefenseClaw is not checking this session: the gateway is running but did not answer. Run `defenseclaw-gateway restart` to resume protection.'
  else
    text='DefenseClaw is not checking this session: this account'"'"'s gateway is not running. Run `defenseclaw-gateway start` to resume protection.'
  fi
  printf '{"systemMessage":"%s"}\n' "$(defenseclaw_json_escape "$text")"
}

# defenseclaw_unreachable_next_step prints the next step for a per-user
# account whose own gateway is down: after `defenseclaw-gateway stop` the
# hooks deliberately do not start it again, so say how to resume. Managed
# hooks print nothing (their service is not the user's to start).
defenseclaw_unreachable_next_step() {
  case "${DEFENSECLAW_MANAGED_HOOK:-0}" in
    1|true|TRUE|yes|YES) return 0 ;;
  esac
  [ -z "${DEFENSECLAW_HOOK_SOCKET:-}" ] || return 0
  local data="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
  if [ -e "${data}/gateway.stopped" ]; then
    printf '%s' 'the gateway was stopped with `defenseclaw-gateway stop`; run `defenseclaw-gateway start` to resume protection'
  elif defenseclaw_own_gateway_stopped; then
    printf '%s' 'this account'"'"'s gateway is not running; run `defenseclaw-gateway start`'
  elif defenseclaw_own_gateway_alive; then
    # A frozen or hung gateway keeps its listener: the request timed out.
    printf '%s' 'the gateway is running but did not answer; check `defenseclaw-gateway status`, or run `defenseclaw-gateway restart`'
  fi
}

# defenseclaw_own_gateway_alive returns 0 when this account's per-user
# gateway.pid names a live process (frozen or hung if it did not answer).
defenseclaw_own_gateway_alive() {
  case "${DEFENSECLAW_MANAGED_HOOK:-0}" in
    1|true|TRUE|yes|YES) return 1 ;;
  esac
  local pid_file="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}/gateway.pid"
  local data="" pid=""
  [ -e "$pid_file" ] || return 1
  IFS= read -r -n 4096 data < "$pid_file" 2>/dev/null || [ -n "$data" ] || return 1
  if [[ "$data" =~ \"pid\"[[:space:]]*:[[:space:]]*([0-9]+) ]]; then
    pid="${BASH_REMATCH[1]}"
  elif [[ "$data" =~ ^[[:space:]]*([0-9]+)[[:space:]]*$ ]]; then
    pid="${BASH_REMATCH[1]}"
  else
    return 1
  fi
  kill -0 "$pid" 2>/dev/null
}

# defenseclaw_handle_missing_token is the shared early-exit branch
# that codex-hook.sh and claude-code-hook.sh take when neither the
# companion .token file nor DEFENSECLAW_GATEWAY_TOKEN is present.
# Without a token the gateway will reject every request with 401, so
# the historical behaviour was to exit 0 ("can't talk to gateway →
# don't brick the agent"). That bypassed FAIL_MODE entirely.
#
# This helper routes the bypass through the connector's FAIL_MODE and
# the DEFENSECLAW_STRICT_AVAILABILITY force-closed override. Every bypass
# is recorded in hook-failures.jsonl so the audit log is honest about the
# missed inspection.
#
# Usage:
#   defenseclaw_handle_missing_token CONNECTOR HOOK_NAME SUBJECT [TOKEN_FILE]
#
# TOKEN_FILE is the token file the hook looked for; the message names it so
# the user can find it (GAP-1425).
#
# Exits 0 for fail-open or 2 for fail-closed. Never returns to the caller.
defenseclaw_handle_missing_token() {
  local connector="${1:-unknown}"
  local hook_name="${2:-unknown}"
  local subject="${3:-tool}"
  local token_file="${4:-}"
  local reason="missing gateway token file"
  [ -z "$token_file" ] || reason="missing gateway token: ${token_file} not found"
  defenseclaw_log_hook_failure "$connector" "$hook_name" "$reason" transport "${FAIL_MODE:-open}"
  if defenseclaw_should_fail_closed_on_unreachable; then
    echo "defenseclaw: ${reason}, blocking ${subject} (fail mode closed)$(defenseclaw_missing_token_next_step "$connector")" >&2
    exit 2
  fi
  exit 0
}

# defenseclaw_missing_token_next_step names the per-user repair for a missing
# hook token (GAP-1138). Managed hooks print nothing: the service restores
# their token.
defenseclaw_missing_token_next_step() {
  case "${DEFENSECLAW_MANAGED_HOOK:-0}" in
    1|true|TRUE|yes|YES) return 0 ;;
  esac
  local setup_name="${1:-}"
  [ "$setup_name" = "claudecode" ] && setup_name="claude-code"
  [ -n "$setup_name" ] || return 0
  printf '%s' "; run \`defenseclaw setup ${setup_name}\` to restore the hook token"
}

# defenseclaw_read_stdin_capped reads stdin into a shell variable but
# refuses bodies larger than ${DEFENSECLAW_HOOK_MAX_BODY} (default 1MB).
# It writes the captured body to stdout so callers consume it via
# command substitution. On overflow it emits a transport-category log
# line, prints "" to stdout, and returns 1 — the hook should treat
# that as a fail-closed misconfiguration (a 1MB+ prompt is well
# outside any legitimate connector payload, and silently truncating
# JSON would yield a parse error downstream that's much harder to
# diagnose than a clear "body too large" error).
#
# Why `head -c` and not `dd`/`read`:
#   - `head -c N` is portable across coreutils + busybox, supported in
#     POSIX since 2024, and reads exactly N bytes then closes the pipe.
#   - It does NOT consume more than the cap+1 byte on the input fd,
#     so a hostile producer streaming 1GB of zeros gets cut off after
#     the first 1MB+1 — no OOM, no kernel pipe buffer abuse.
#   - The trailing "1 byte over" is detected by re-reading via
#     `head -c 1` from the same stdin; if anything remains we know
#     the cap was breached.
#
# Usage:
#   PAYLOAD="$(defenseclaw_read_stdin_capped)" || exit $?
#
# Returns 0 with the body on stdout. Returns 1 (overflow) with an
# empty stdout. If `head` is missing we read the body with a bounded
# python3 reader (overflow still returns 1); only when both head(1) and
# python3 are absent do we fall back to a legacy unbounded read so the
# hook still functions on minimal containers, logging it as a
# transport-category event so operators can spot it.
defenseclaw_read_stdin_capped() {
  local connector="${DEFENSECLAW_HOOK_CONNECTOR:-unknown}"
  local hook_name="${DEFENSECLAW_HOOK_NAME:-unknown}"
  local cap="${DEFENSECLAW_HOOK_MAX_BODY:-1048576}"
  case "$cap" in
    ''|*[!0-9]*) cap=1048576 ;;
  esac
  # Tier 1 — bounded python3 read (preferred). python3 is byte-exact on
  # every OS: it reads at most cap+1 bytes and reports overflow precisely.
  # We prefer it over head(1) because BSD/macOS `head -c N` OVER-READS a
  # pipe (it drains everything past N), which defeats any "is there a
  # byte past the cap?" probe and would silently truncate an oversized
  # body instead of failing closed. python3 is the same interpreter the
  # _dc_jq shim already relies on, so requiring it here adds no new dep on
  # the hosts these hooks actually run on.
  #
  # _dc_python3_usable (not a bare `command -v python3`) is the gate:
  # stock macOS hosts without CLT resolve /usr/bin/python3 to a launcher
  # stub that would trigger an OS installer dialog on first invocation
  # and return no body at all — the hook would then post an empty payload
  # to the gateway, get HTTP 400, and fail closed. Skipping the stub
  # falls through to the head(1) tier which reads stdin correctly on
  # stock macOS.
  if _dc_python3_usable; then
    local _dc_body _dc_rc
    _dc_body="$(DCHOOK_CAP="$cap" python3 -c \
'import sys,os
cap=int(os.environ.get("DCHOOK_CAP","1048576"))
data=sys.stdin.buffer.read(cap+1)
if len(data)>cap:
    sys.exit(3)
sys.stdout.buffer.write(data)')"
    _dc_rc=$?
    if [ "$_dc_rc" -eq 3 ]; then
      defenseclaw_log_hook_failure "$connector" "$hook_name" \
        "stdin body exceeded ${cap} byte cap" transport "${FAIL_MODE:-open}"
      echo "defenseclaw: hook payload exceeded ${cap} bytes; refusing to truncate" >&2
      return 1
    fi
    printf '%s' "$_dc_body"
    return 0
  fi
  # Tier 2 — head(1) fallback for python3-less hosts. Read cap+1 bytes in a
  # SINGLE call and compare the captured length: a two-call probe
  # (`head -c cap` then `head -c 1`) is unreliable because BSD head drains
  # the pipe on the first read, so the second read always sees EOF and an
  # oversized body would be truncated to cap bytes and accepted. The
  # `; printf x` + `%x` strip-guard preserves trailing newlines so the
  # length check is exact (command substitution otherwise trims them).
  # LANG=C (set by defenseclaw_harden_env) makes ${#body} a byte count.
  if command -v head >/dev/null 2>&1; then
    local body
    body="$(head -c "$((cap + 1))"; printf x)"
    body="${body%x}"
    if [ "${#body}" -gt "$cap" ]; then
      defenseclaw_log_hook_failure "$connector" "$hook_name" \
        "stdin body exceeded ${cap} byte cap" \
        transport "${FAIL_MODE:-open}"
      echo "defenseclaw: hook payload exceeded ${cap} bytes; refusing to truncate" >&2
      return 1
    fi
    printf '%s' "$body"
    return 0
  fi
  # Tier 3 — neither python3 nor head present (minimal container): legacy
  # unbounded read so the hook still functions, logged so operators can
  # spot the missing-tooling condition.
  defenseclaw_log_hook_failure "$connector" "$hook_name" \
    "head(1)/python3 missing; reading stdin unbounded (set DEFENSECLAW_HOOK_MAX_BODY)" \
    transport "${FAIL_MODE:-open}"
  cat
  return 0
}

# defenseclaw_validate_traceparent returns 0 when $1 matches the W3C
# trace context format (RFC 9110-bis / draft-ietf-tcs-traceparent):
#
#   version "-" trace-id "-" parent-id "-" trace-flags
#
#   version   :=  2 lower-hex chars
#   trace-id  := 32 lower-hex chars, MUST NOT be all-zero
#   parent-id := 16 lower-hex chars, MUST NOT be all-zero
#   flags     :=  2 lower-hex chars
#
# Total 55 characters with the three dashes. Validation is intentionally
# strict: the gateway treats traceparent as trusted input that joins
# the agent's span tree with the gateway's. A hostile env value that
# spoofs e.g. an admin's request would otherwise re-write the trace
# graph.
defenseclaw_validate_traceparent() {
  local v="${1:-}"
  case "${#v}" in
    55) : ;;
    *) return 1 ;;
  esac
  # Layout check: dashes at positions 3, 36, 53 (1-indexed).
  case "$v" in
    ??-????????????????????????????????-????????????????-??) : ;;
    *) return 1 ;;
  esac
  # Strict-hex check: any non-hex char rejects. Uppercase hex is valid
  # W3C trace-context and accepted by Go's OTel propagator.
  case "$v" in
    *[!0-9a-fA-F-]*) return 1 ;;
  esac
  # Trace-id and parent-id must not be all-zero.
  local trace_id parent_id
  trace_id="${v:3:32}"
  parent_id="${v:36:16}"
  case "$trace_id" in
    00000000000000000000000000000000) return 1 ;;
  esac
  case "$parent_id" in
    0000000000000000) return 1 ;;
  esac
  return 0
}

# defenseclaw_validate_tracestate accepts the comma-separated key=value
# list defined by W3C. We bound the length to 512 bytes (W3C SHOULD
# limit, the gateway also enforces it server-side) and refuse any byte
# that would be log-injectable. Only ASCII printables, "=", ",", "@",
# "_", "/", "-", and whitespace are permitted — matching the
# tracestate ABNF. The allow-list is expressed via a $'...' ANSI-C
# string so the literal tab inside the bracket expression survives
# bash's POSIX glob parser (a bare \t would be a syntax error).
defenseclaw_validate_tracestate() {
  local v="${1:-}"
  if [ ${#v} -gt 512 ]; then
    return 1
  fi
  local _allowed=$'A-Za-z0-9=,@_/. \t-'
  case "$v" in
    *[!$_allowed]*) return 1 ;;
  esac
  return 0
}

# defenseclaw_extract_trace_context emits one curl `-H "..."` argument
# per line (no carriage returns) for every trace header that should be
# forwarded to the gateway. Callers consume the output via
# `mapfile -t HEADERS < <(defenseclaw_extract_trace_context)` which
# preserves the exact quoting curl expects.
#
# Source precedence (first non-empty wins per header):
#
#   traceparent:  DEFENSECLAW_TRACEPARENT, then TRACEPARENT, then
#                 OTEL_TRACEPARENT.
#   tracestate:   DEFENSECLAW_TRACESTATE,  then TRACESTATE,  then
#                 OTEL_TRACESTATE.
#
# Validation runs on every candidate; an invalid value is logged via
# defenseclaw_log_hook_failure (response category — bad input from
# the agent) and skipped silently. The hook still posts to the
# gateway; it just does so without trace propagation, which fails
# safe (gateway starts a new root span).
defenseclaw_extract_trace_context() {
  local connector="${DEFENSECLAW_HOOK_CONNECTOR:-unknown}"
  local hook_name="${DEFENSECLAW_HOOK_NAME:-unknown}"

  local tp
  tp="${DEFENSECLAW_TRACEPARENT:-${TRACEPARENT:-${OTEL_TRACEPARENT:-}}}"
  if [ -n "$tp" ]; then
    if defenseclaw_validate_traceparent "$tp"; then
      printf '%s\n' "-H"
      printf '%s\n' "traceparent: $tp"
    else
      defenseclaw_log_hook_failure "$connector" "$hook_name" \
        "rejected malformed traceparent (length=${#tp})" \
        response "${FAIL_MODE:-open}"
    fi
  fi

  local ts
  ts="${DEFENSECLAW_TRACESTATE:-${TRACESTATE:-${OTEL_TRACESTATE:-}}}"
  if [ -n "$ts" ]; then
    if defenseclaw_validate_tracestate "$ts"; then
      printf '%s\n' "-H"
      printf '%s\n' "tracestate: $ts"
    else
      defenseclaw_log_hook_failure "$connector" "$hook_name" \
        "rejected malformed tracestate (length=${#ts})" \
        response "${FAIL_MODE:-open}"
    fi
  fi
}

# defenseclaw_user_identity_args
#
# Emits curl arguments carrying the OS identity of the user this hook is
# running as, one argument per line, in the same shape as
# defenseclaw_extract_trace_context.
#
# Callers must read this with a `while IFS= read -r` loop rather than
# `mapfile`. macOS ships bash 3.2, where mapfile does not exist, so a mapfile
# reader leaves the argument array empty and the endpoint silently sends no
# identity at all — on every stock macOS host, which is most of them.
#
# Identity has to be read here. These hooks reach the gateway over HTTP, and
# under a managed install the gateway runs as a service account with its own
# token and home directory; asking it who the user is would attribute every
# event on the endpoint to that one service identity. Only the hook runs as
# the real user.
#
# The gateway accepts these headers from loopback only, and treats them as
# attribution evidence rather than an authenticated assertion: any local
# process can reach the loopback listener and claim any value. Never use them
# for an authorization decision.
#
# Both values are rejected unless they match a conservative character class.
# A header value carrying CR or LF would let an account name append a second
# header or a request line to every hook call this endpoint makes.
#
# Every failure path is silent and returns success: this is called from a
# guardrail hook under errexit, where a nonzero return would convert a missing
# telemetry field into a blocked or allowed tool call.
defenseclaw_user_identity_args() {
  local facts
  facts="$(defenseclaw_session_facts_value)"
  if [ -n "$facts" ]; then
    printf '%s\n' "-H"
    printf '%s\n' "X-DefenseClaw-Session-Facts: $facts"
  fi

  command -v id >/dev/null 2>&1 || return 0

  local uid name
  uid="$(id -u 2>/dev/null)" || uid=""
  case "$uid" in
    '' | *[!0-9]*) ;;
    *)
      printf '%s\n' "-H"
      printf '%s\n' "X-DefenseClaw-User-Id: $uid"
      ;;
  esac

  name="$(id -un 2>/dev/null)" || name=""
  case "$name" in
    '' | *[!A-Za-z0-9._-]*) return 0 ;;
  esac
  printf '%s\n' "-H"
  printf '%s\n' "X-DefenseClaw-User-Name: $name"
  return 0
}

# defenseclaw_session_facts_value renders the X-DefenseClaw-Session-Facts
# value (v1;k=ssh;tty=..;ls=..;ca=..;krb=..;cc=..). The Kerberos default
# principal needs the credential cache read, which a shell cannot do (KCM is
# a socket protocol), so defenseclaw_session_facts_full takes the whole
# value from the gateway binary when it can; otherwise the value comes from
# the SSH and logind variables of this session alone. Every value is claimed
# attribution and is dropped unless it matches the header's allowlisted
# charset.
defenseclaw_session_facts_value() {
  local value kind tty ls ca pair v full
  full="$(defenseclaw_session_facts_full 2>/dev/null)" || full=""
  if [ -n "$full" ]; then
    printf '%s' "$full"
    return 0
  fi
  value="v1"
  kind=""
  ca="${SSH_CONNECTION:-}"
  ca="${ca%% *}"
  tty="${SSH_TTY:-}"
  tty="${tty#/dev/}"
  ls="${XDG_SESSION_ID:-}"
  if [ -n "$ca" ] || [ -n "$tty" ]; then
    kind="ssh"
  elif [ -n "$ls" ]; then
    kind="local"
  fi
  for pair in "k=$kind" "tty=$tty" "ls=$ls" "ca=$ca"; do
    v="${pair#*=}"
    case "$v" in
      '' | *[!A-Za-z0-9._@/:-]*) continue ;;
    esac
    [ "${#v}" -le 256 ] || continue
    value="$value;$pair"
  done
  [ "$value" = "v1" ] || printf '%s' "$value"
  return 0
}

# defenseclaw_session_facts_full prints the session facts value the gateway
# binary's `hook session-facts` computed for this session, Kerberos
# principal included, or nothing. The binary caches its answer in
# ~/.defenseclaw/session-facts.json for five minutes with the session
# variables it saw (env_key); a fresh record for the same variables is used
# as it is, so the binary runs at most once per five minutes per session. It
# runs only when a credential cache can exist (KRB5CCNAME or
# /etc/krb5.conf), never for a managed hook (the native hook reads the cache
# itself), and its answer is used only when it matches the header charset.
defenseclaw_session_facts_full() {
  case "${DEFENSECLAW_MANAGED_HOOK:-0}" in
    1|true|TRUE|yes|YES) return 0 ;;
  esac
  local home="${DEFENSECLAW_AGENT_HOME:-${HOME:-}}" env_key cache record="" re out="" bin=""
  case "$home" in
    /*) ;;
    *) return 0 ;;
  esac
  env_key="${KRB5CCNAME:-}|${XDG_SESSION_ID:-}|${SSH_CONNECTION:-}|${SSH_TTY:-}"
  case "$env_key" in
    *[!A-Za-z0-9._@/:%\ \|-]*) return 0 ;;
  esac
  cache="${home}/.defenseclaw/session-facts.json"
  if [ -f "$cache" ] && [ ! -L "$cache" ] && [ -n "$(find "$cache" -mmin -5 2>/dev/null)" ]; then
    IFS= read -r -d '' -n 4096 record < "$cache" 2>/dev/null || true
    re='"env_key":"([^"]*)"'
    if [[ "$record" =~ $re ]] && [ "${BASH_REMATCH[1]}" = "$env_key" ]; then
      re='"header":"([^"]*)"'
      if [[ "$record" =~ $re ]]; then
        out="${BASH_REMATCH[1]}"
      fi
      defenseclaw_session_facts_checked "$out"
      return 0
    fi
  fi
  [ -n "${KRB5CCNAME:-}" ] || [ -r /etc/krb5.conf ] || return 0
  bin="$(defenseclaw_gateway_binary "${DEFENSECLAW_HOME:-${home}/.defenseclaw}" "$home")" || return 0
  # The Go runtime cannot start under the hook's address-space limit.
  out="$(
    ulimit -S -v "$(ulimit -H -v)" 2>/dev/null || true
    HOME="$home" exec "$bin" hook session-facts </dev/null 2>/dev/null
  )" || return 0
  defenseclaw_session_facts_checked "$out"
  return 0
}

# defenseclaw_session_facts_checked prints a v1 session facts value that
# fits the header (its charset, at most 1024 bytes) and nothing otherwise.
defenseclaw_session_facts_checked() {
  case "$1" in
    v1\;*) ;;
    *) return 0 ;;
  esac
  case "$1" in
    *[!A-Za-z0-9._@/:\;=-]*) return 0 ;;
  esac
  [ "${#1}" -le 1024 ] || return 0
  printf '%s' "$1"
}
