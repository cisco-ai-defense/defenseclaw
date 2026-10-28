#!/bin/bash
# defenseclaw-managed-hook v10
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
#   v8 — adds defenseclaw_gateway_post, the one gateway request path of the
#        host hooks. It hands curl the Authorization header as a config line
#        on a descriptor and the request body on another, so neither the
#        gateway bearer nor the prompt or tool payload appears on a process
#        command line, which every local account can read. Hooks rendered by
#        this build call it directly: writeHookHelpers never replaces a newer
#        helper with an older one, and older hooks do not call it.
#        defenseclaw_harden_env also drops inherited variables named like the
#        hooks' private values (API_TOKEN, PAYLOAD, ...), so neither the
#        bearer nor the payload reaches a child process's environment.
#   v9 — adds explicit delivery-outcome logging (OUTCOME argument of
#        defenseclaw_log_hook_failure) and the delivery failure wrapper
#        (defenseclaw_log_hook_delivery_failure /
#        defenseclaw_hook_delivery_outcome) used by Codex, Claude Code and
#        Cursor. Every managed hook, Secure Client included, still fails
#        closed on an unreachable gateway or a missing token.
#        (Release 26.8.4 shipped these helpers as its v7; this line carries
#        them above main's v8 so an older writer cannot remove a helper used
#        by newer hook scripts.)
#   v10 — validates the entire JSON answer, including nested fields and
#         duplicate keys, before the awk fallback can extract an action.
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

# The hook's start, for the restart budget of defenseclaw_await_gateway.
# EPOCHREALTIME is a clock only from bash 5 on, where the environment cannot
# set it; bash 3.2 (macOS) counts the whole seconds of SECONDS from here.
_DC_HOOK_STARTED_US=""
if [ "${BASH_VERSINFO[0]:-0}" -ge 5 ]; then
  _DC_HOOK_STARTED_US="${EPOCHREALTIME:-}"
  _DC_HOOK_STARTED_US="${_DC_HOOK_STARTED_US/[.,]/}"
  case "$_DC_HOOK_STARTED_US" in
    ""|*[!0-9]*) _DC_HOOK_STARTED_US="" ;;
  esac
fi
_DC_HOOK_STARTED_S="${SECONDS:-0}"
_DC_GATEWAY_RESTART_WAITED=""
# Set only by defenseclaw_await_gateway for this call; an inherited value can
# never open a per-user outage (defenseclaw_per_user_outage_open).
_DC_TRANSPORT_STATUS=""
# The config's outage mode for this call (defenseclaw_config_outage_open);
# never inherited.
_DC_CONFIG_OUTAGE_MODE=""
_DC_OUTAGE_WARNING_THIS_CALL=""

# defenseclaw_stat_into GNU_FORMAT BSD_FORMAT PATH...: one stat for every
# PATH, output in _DC_STAT_OUT. GNU stat takes -c, BSD stat (macOS) -f. The
# old "stat -c ... || stat -f ..." spent a failed launch on every check on
# macOS, so one call there ran twice the programs Linux runs (GAP-1755). The
# first try follows OSTYPE and the spelling that answered is kept for this
# process (GNU coreutils on macOS keeps working, at one extra launch once).
# A failed try leaves no output behind. The install check each hook carries
# before it sources this file keeps its own spelling (it runs only while a
# lock exists, and it must stay the same text in every hook).
defenseclaw_stat_into() {
  local gnu="$1" bsd="$2"
  shift 2
  _DC_STAT_OUT=""
  if [ -z "${_DC_STAT_DIALECT:-}" ]; then
    case "${OSTYPE:-}" in
      darwin*|*bsd*) _DC_STAT_DIALECT=bsd ;;
      *) _DC_STAT_DIALECT=gnu ;;
    esac
  fi
  if [ "$_DC_STAT_DIALECT" = bsd ]; then
    _DC_STAT_OUT="$(stat -f "$bsd" "$@" 2>/dev/null)" && return 0
    _DC_STAT_OUT="$(stat -c "$gnu" "$@" 2>/dev/null)" || { _DC_STAT_OUT=""; return 1; }
    _DC_STAT_DIALECT=gnu
  else
    _DC_STAT_OUT="$(stat -c "$gnu" "$@" 2>/dev/null)" && return 0
    _DC_STAT_OUT="$(stat -f "$bsd" "$@" 2>/dev/null)" || { _DC_STAT_OUT=""; return 1; }
    _DC_STAT_DIALECT=bsd
  fi
}

# Resource limits — bound the hook so a stuck regex / hostile input
# can't wedge the agent. Plan F16 ask: CPU 5s, virt mem 512MiB, fds 32.
# Use ulimit -S (soft) so the hook doesn't try to exceed kernel maxima
# on platforms where defaults differ; soft limits still cause SIGXCPU
# / mmap failure when crossed, which is what we want.
defenseclaw_harden_resources() {
  ulimit -S -t 5     2>/dev/null || true
  # Go reserves more virtual address space than this shell budget even when
  # its resident memory is small. Keep the hook capped, and restore this
  # account's original soft limit only in the verified native POST child.
  # The forkless Hermes execution probe (no process may start) makes no
  # native POST, so it skips the command substitution.
  if [ "${_DC_FORKLESS_PROBE:-}" != "1" ]; then
    _DC_HOOK_NATIVE_VMEM_LIMIT="$(ulimit -S -v 2>/dev/null)"
  fi
  ulimit -S -v 524288 2>/dev/null || true
  ulimit -S -n 32    2>/dev/null || true
}

# Sanitize PATH and git environment. Goal: any subprocess this hook
# spawns sees a known-good search path (no $HOME/bin first, no agent-
# injected entries) and a git that ignores user / system config.
defenseclaw_harden_env() {
  # The hooks keep the bearer, the payload and the gateway's answer in these
  # names. An assignment keeps the export bit of an inherited variable of the
  # same name, which would copy the value into the environment of every child
  # process (curl, jq, the cold-started gateway), so drop inherited ones first.
  unset -v API_TOKEN PAYLOAD CONTENT TOOL_INPUT TOOL_OUTPUT INSPECT_BODY RESPONSE RESULT OUTPUT
  # The stat spelling is learned per process, never taken from the caller.
  unset -v _DC_STAT_OUT _DC_STAT_DIALECT

  # Only a rendered managed hook may select the managed socket transport.
  # Per-user scripts clear the managed marker before sourcing this helper;
  # an agent's inherited socket path must not bypass the API owner check.
  if [ "${DEFENSECLAW_MANAGED_HOOK:-0}" != "1" ]; then
    unset DEFENSECLAW_HOOK_SOCKET DEFENSECLAW_HOOK_SOCKET_UID
  fi

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
    # Never the DefenseClaw folder itself: a purge removed it (GAP-0654).
    mkdir "$DEFENSECLAW_HOOK_HOME" 2>/dev/null || true
  fi
  export HOME="$DEFENSECLAW_HOOK_HOME"
  trap '_defenseclaw_hook_cleanup' EXIT

  # A managed hook's socket transport names the session-facts binary after
  # this point. An inherited one would let the agent pick a binary for the
  # hook to run, and would make a Secure Client hook send session facts.
  unset DEFENSECLAW_SESSION_FACTS_BIN

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
  # planted `find`. Orphans come only from a killed hook, so one call in 32
  # keeps them bounded without a find on every call (issue #1130).
  [ $((RANDOM % 32)) -ne 0 ] || _defenseclaw_sweep_stale_hook_dirs
}

# Resolve optional connector identity for the shared inspect-* scripts.  The
# selected connector is runtime state, never a render-time property of the one
# physical shared script.  Reject anything outside the connector-name grammar
# before it can participate in a token filename or HTTP header.
defenseclaw_shared_runtime_connector() {
  local connector="${DEFENSECLAW_CONNECTOR:-}"
  # Non-managed shells may supply an ephemeral connector selection. It picks
  # the token and the identity the hook sends; it never opens the hook's fail
  # mode (defenseclaw_shared_runtime_fail_mode can only tighten for it).
  # Guardian-managed hooks do not trust process environment for connector
  # identity and use only the installer-owned sidecars below.
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
    elif _dc_python3_usable; then
      connector="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1], encoding="utf-8")); k=list((d.get("fail_modes") or {}).keys()); print(k[0] if len(k)==1 else "")' "$config" 2>/dev/null || true)"
    fi
    case "$connector" in
      ""|*[!a-z0-9_-]*) return 0 ;;
      *) printf '%s' "$connector" ;;
    esac
  fi
}

# Succeed only for a readable hooks/.hookcfg* file of at most 64 KiB (the
# writers' and the native hook's HookSidecarMaxBytes) with no NUL byte, which
# no writer emits and no reader accepts. A larger file is state the writers
# refuse to rewrite, so a reader that took a mode from it would keep that
# mode against a refresh. Pure bash (the hooks run with a minimal PATH):
# reading stops at the first NUL or after 64 KiB + 1 bytes, and succeeds only
# at the end of the file.
_dc_hookcfg_within_bounds() {
  local LC_ALL=C
  [ -f "$1" ] && [ -r "$1" ] || return 1
  if IFS= read -r -d '' -n 65537 _ < "$1"; then
    return 1
  fi
  return 0
}

# Print the value of one key of a flat KEY=value record (the
# hooks/.hookcfg.<connector> files the setup writers make: two lines,
# DEFENSECLAW_CONNECTOR and DEFENSECLAW_FAIL_MODE). A record that is not a
# regular file, is larger than 64 KiB, holds a NUL byte, has a line that is
# not KEY=value with an upper-case key, gives a key twice or ends without a
# newline (a write cut short) is malformed: nothing is printed and the call
# fails, so no caller reads an open mode out of it.
defenseclaw_flat_hookcfg_value() {
  local config="$1"
  local wanted="$2"
  local line="" key value="" found=0 seen=" "
  [ -f "$config" ] && [ ! -L "$config" ] || return 1
  # The line reads below would drop a NUL without a trace.
  _dc_hookcfg_within_bounds "$config" || return 1
  while IFS= read -r line; do
    case "$line" in
      *=*) ;;
      *) return 1 ;;
    esac
    key="${line%%=*}"
    case "$key" in
      ""|[0123456789]*|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_]*) return 1 ;;
    esac
    case "$seen" in
      *" $key "*) return 1 ;;
    esac
    seen="${seen}${key} "
    if [ "$key" = "$wanted" ]; then
      found=1
      value="${line#*=}"
    fi
  done < "$config"
  # read leaves an unterminated last line in $line.
  [ -z "$line" ] && [ "$found" = 1 ] || return 1
  printf '%s' "$value"
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

# Resolve the availability posture of the shared inspect-* scripts. One
# physical script serves every connector of this data directory, and nothing
# authenticates which connector an invocation runs for: DEFENSECLAW_CONNECTOR
# is the agent's environment, and two connector records leave the sidecars
# ambiguous. So any connector record (the flat .hookcfg.<connector> files or
# the JSON fail_modes map) that is not open closes the hook, whichever
# connector is selected: a selector can only tighten. With every record open,
# a selected connector (the single record, or the environment's choice) needs
# an open record of its own. With none selected on a managed hook (several
# guardian records), the records combine to the strictest: every one is open,
# so the administrator's open stands for the outage, unless an unscoped
# legacy record exists and is not open. Otherwise (no record, or a per-user
# hook with several) only the unscoped legacy mode can open the call, and only
# when its flat record (.hookcfg.legacy, which names no connector) and the
# JSON legacy_fail_mode both say open: every writer since 0.8.10 writes the two
# together. After an upgrade, a kept legacy open therefore never reopens a
# connector recorded closed. The JSON is the one document the writers make:
# a regular file (not a link) holding exactly one JSON object, no key given
# twice in any object (readers take the last, so it reads differently to
# each), no top-level key naming a field in another case, a version written
# as an integer from 2 to 2^63-1, gateway_addr, legacy_fail_mode and
# legacy_fail_mode_source strings or null, and fail_modes and
# fail_mode_sources, when present, objects of strings or null. It has
# no backslash (no writer emits one), nests at most 32 levels, and writes
# every number as JSON does. Anything else (empty or blank text, a byte-order
# mark, two documents, a version of 2.5, 2e0 or 02, a field of another type,
# fail_modes null, a value jq alone reads such as nan, +1 or .5) is
# malformed, on both parser paths alike; a missing fail_modes is the shape
# every release writes for an install with no connector entry yet. A
# connector record that is not a regular file, does not name its own
# connector, or is not the writers' KEY=value lines (see
# defenseclaw_flat_hookcfg_value) is malformed too. The JSON can name a
# connector no flat record does (a write cut short between the two, or a peer
# an older release recorded), so JSON that no parser can read (no jq or
# python3) is closed: only an install with no JSON state at all opens from the
# flat records alone. Secure Client
# delivery keeps its flat-record reading (unchanged in 1.0.4). The sidecars
# are the only input: DEFENSECLAW_FAIL_MODE in the agent's environment is not
# read (GAP-0315); guardian-managed hooks trust only installer-owned state.
# Malformed, ambiguous, unverifiable or missing state fails closed. A record
# counts as open only on a managed hook whose protected sidecar records
# managed_enterprise (defenseclaw_managed_runtime_sidecar). An earlier per-user
# open is never an outage exception.
defenseclaw_shared_runtime_fail_mode() {
  local hook_dir="$1"
  local connector="${2:-}"
  local config="${hook_dir}/.hookcfg"
  local candidate suffix recorded mode source selected="" summary="" raw="" managed_open=0 records=0 flat_names=""
  if defenseclaw_managed_runtime_sidecar "$config"; then
    managed_open=1
  fi
  if [ "$managed_open" != 1 ]; then
    printf closed
    return 0
  fi
  for candidate in "${hook_dir}"/.hookcfg.*; do
    [ -e "$candidate" ] || [ -L "$candidate" ] || continue
    suffix="${candidate##*.hookcfg.}"
    [ "$suffix" != "legacy" ] && [ "$suffix" != "lock" ] || continue
    case "$suffix" in
      ""|*[!a-z0-9_-]*) continue ;;
    esac
    # A file named for a connector is that connector's record. The writers'
    # lock (.hookcfg.lock) and atomic-write temporaries (.tmp-*) never take a
    # connector name, so a link, a directory, a record that names another
    # connector or none, or one that says anything but open, closes the hook.
    if [ -L "$candidate" ] || [ ! -f "$candidate" ]; then
      printf closed
      return 0
    fi
    recorded="$(defenseclaw_flat_hookcfg_value "$candidate" DEFENSECLAW_CONNECTOR 2>/dev/null || true)"
    mode="$(defenseclaw_flat_hookcfg_value "$candidate" DEFENSECLAW_FAIL_MODE 2>/dev/null || true)"
    source="$(defenseclaw_flat_hookcfg_value "$candidate" FAIL_MODE_SOURCE 2>/dev/null || true)"
    if [ "$recorded" != "$suffix" ] || [ "$mode" != "open" ] \
      || { [ "$source" != "config" ] && [ "$managed_open" != 1 ]; }; then
      printf closed
      return 0
    fi
    records=$((records + 1))
    flat_names="${flat_names:+$flat_names }$suffix"
    if [ "$suffix" = "$connector" ]; then
      selected=open
    fi
  done
  # The JSON state, as four words: connector entries, whether all of them
  # are open, the selected connector's entry, and the legacy mode. A parser
  # that runs and fails means malformed state. JSON no parser can read is
  # closed: it may record a connector no flat record names.
  if [ -e "$config" ] || [ -L "$config" ]; then
    local first=""
    if [ -L "$config" ] || [ ! -f "$config" ]; then
      printf closed
      return 0
    fi
    # jq skips a leading byte-order mark that no writer emits and the other
    # readers reject.
    IFS= read -r first < "$config" || true
    case "$first" in
      $'\xef\xbb\xbf'*) printf closed; return 0 ;;
    esac
    if ! _dc_hookcfg_within_bounds "$config" && { command -v jq >/dev/null 2>&1 || _dc_python3_usable; }; then
      # Larger than 64 KiB or holding a NUL: malformed for every reader and
      # refused by the writers, so a refresh could not replace it.
      summary="invalid"
    elif command -v jq >/dev/null 2>&1; then
      # jq reads numbers no other reader takes (nan, Infinity, +1, 01, .5)
      # and reads 2e0 as the integer 2, so a first pass reads the raw text:
      # with no backslash every quote opens or closes a string, so the text
      # outside strings holds every number and literal as written, the
      # nesting, and the top-level version token.
      raw="$(jq -R -s -r '
        def ws: . == 32 or . == 9 or . == 10 or . == 13;
        def number: reduce explode[] as $c (0;
          ($c >= 48 and $c <= 57) as $digit
          | if . == 0 then (if $c == 45 then 1 elif $c == 48 then 2 elif $digit then 3 else -1 end)
            elif . == 1 then (if $c == 48 then 2 elif $digit then 3 else -1 end)
            elif . == 2 then (if $c == 46 then 4 elif $c == 101 or $c == 69 then 6 else -1 end)
            elif . == 3 then (if $digit then 3 elif $c == 46 then 4 elif $c == 101 or $c == 69 then 6 else -1 end)
            elif . == 4 then (if $digit then 5 else -1 end)
            elif . == 5 then (if $digit then 5 elif $c == 101 or $c == 69 then 6 else -1 end)
            elif . == 6 then (if $c == 43 or $c == 45 then 7 elif $digit then 8 else -1 end)
            elif . == 7 or . == 8 then (if $digit then 8 else -1 end)
            else -1 end)
          | . == 2 or . == 3 or . == 5 or . == 8;
        def tokens: explode | map(if ws or . == 123 or . == 125 or . == 91 or . == 93 or . == 44 or . == 58 then 32 else . end)
          | implode | split(" ") | map(select(length > 0));
        def integer: explode | length > 0 and length <= 19 and .[0] >= 49 and .[0] <= 57 and all(.[]; . >= 48 and . <= 57);
        if index("\\") != null then "invalid" else
          split("\"") as $parts
          | reduce range(0; $parts | length; 2) as $i ({depth: 0, deepest: 0, ok: (($parts | length) % 2 == 1), versions: 0, version: ""};
              $parts[$i] as $outside
              | (if $i > 0 and .depth == 1 and $parts[$i - 1] == "version" and ([$outside | explode[] | select(ws | not)][0] == 58)
                 then .versions += 1 | .version = (($outside | tokens)[0] // "") else . end)
              | .ok = (.ok and ($outside | tokens | all(.[]; . == "true" or . == "false" or . == "null" or number)))
              | reduce ($outside | explode[]) as $c (.;
                  if $c == 123 or $c == 91 then .depth += 1 | .deepest = ([.deepest, .depth] | max)
                  elif $c == 125 or $c == 93 then .depth -= 1 else . end))
          | if .ok and .deepest <= 32 and .versions == 1 and (.version | integer)
              and ((.version | length) < 19 or .version <= "9223372036854775807") and (.version | tonumber) >= 2
            then "ok" else "invalid" end
        end' "$config" 2>/dev/null)" || raw="invalid"
      if [ "$raw" != "ok" ]; then
        summary="invalid"
      # --stream sees every key as written: a path met again after its value
      # ended is a key given twice, or a second document.
      elif ! summary="$(jq -n -r --stream --arg connector "$connector" --arg managed "$managed_open" --arg flat "$flat_names" '
        def word($source): if . == null or . == "" then "none" elif . == "open" and ($source == "config" or $managed == "1") then "open" else "closed" end;
        def text: . == null or type == "string";
        def fold: explode | map(if . == 383 then 115 elif . == 8490 then 107 else . end) | implode | ascii_downcase;
        [inputs] as $events
        | if (reduce $events[] as $event ({seen: {}, duplicate: false};
              if ($event | length) == 2 then
                . as $state
                | .duplicate = (.duplicate or any(range(0; ($event[0] | length) + 1) as $n | $event[0][:$n] | tojson; in($state.seen)))
                | .seen[$event[0] | tojson] = true
              else .seen[$event[0][:-1] | tojson] = true end) | .duplicate)
          then "invalid"
          else [fromstream($events[])] as $docs
          | if ($docs | length) != 1 then "invalid" else $docs[0]
          | if type == "object"
              and (.version | type) == "number" and .version >= 2
              and (.version | tojson | explode | all(. >= 48 and . <= 57))
              and (.gateway_addr | text) and (.legacy_fail_mode | text) and (.legacy_fail_mode_source | text)
              and ((has("fail_mode_sources") | not) or ((.fail_mode_sources | type) == "object" and all(.fail_mode_sources[]; text)))
              and ((has("fail_modes") | not) or ((.fail_modes | type) == "object" and all(.fail_modes[]; text)))
              and all(keys[]; . as $key | all("version", "gateway_addr", "fail_modes", "legacy_fail_mode", "fail_mode_sources", "legacy_fail_mode_source"; . == $key or ($key | fold) != .))
            then
              (if has("fail_modes") then .fail_modes else {} end) as $modes
              | (if has("fail_mode_sources") then .fail_mode_sources else {} end) as $sources
              | .legacy_fail_mode_source as $legacy_source
              | "\($modes | length) \(if [$modes | to_entries[] | .value == "open" and ($sources[.key] == "config" or $managed == "1")] | all then "open" else "closed" end) \(if $connector == "" then "none" else ($modes[$connector] | word($sources[$connector])) end) \(.legacy_fail_mode | word($legacy_source)) \(if [$flat | splits(" ") | select(length > 0) | $modes[.] == "open"] | all then "bound" else "unbound" end)"
            else "invalid" end end end' "$config" 2>/dev/null)"; then
        summary="invalid"
      fi
    elif _dc_python3_usable; then
      # -I: no PYTHON* variable (PYTHONOPTIMIZE, PYTHONPATH) of the agent's
      # environment changes this check.
      summary="$(python3 -I -c 'import json,sys
def need(ok):
  if not ok: sys.exit(1)
def unique(pairs):
  d={}
  for k,v in pairs:
    need(k not in d)
    d[k]=v
  return d
def constant(name):
  raise ValueError(name)
raw=open(sys.argv[1],encoding="utf-8",errors="replace").read()
need("\\" not in raw)
depth=deepest=0
quoted=False
for ch in raw:
  if ch=="\"":
    quoted=not quoted
  elif not quoted and ch in "{[":
    depth+=1
    deepest=max(deepest,depth)
  elif not quoted and ch in "}]":
    depth-=1
need(deepest<=32)
d=json.loads(raw,object_pairs_hook=unique,parse_constant=constant)
t=lambda v:v is None or isinstance(v,str)
fold=lambda k:k.replace("\u017f","s").replace("\u212a","k").encode("utf-8","surrogatepass").lower().decode("utf-8","surrogatepass")
need(isinstance(d,dict) and type(d.get("version")) is int and 2<=d["version"]<=9223372036854775807)
need(t(d.get("gateway_addr")) and t(d.get("legacy_fail_mode")) and t(d.get("legacy_fail_mode_source")))
need(all(k==f or fold(k)!=f for k in d for f in ("version","gateway_addr","fail_modes","legacy_fail_mode","fail_mode_sources","legacy_fail_mode_source")))
m=d.get("fail_modes",{})
s=d.get("fail_mode_sources",{})
need(isinstance(m,dict) and all(t(v) for v in m.values()))
need(isinstance(s,dict) and all(t(v) for v in s.values()))
g=sys.argv[3]=="1"
w=lambda v,src:"none" if v in (None,"") else ("open" if v=="open" and (src=="config" or g) else "closed")
c=sys.argv[2]
print(len(m),"open" if all(v=="open" and (s.get(k)=="config" or g) for k,v in m.items()) else "closed",w(m.get(c),s.get(c)) if c else "none",w(d.get("legacy_fail_mode"),d.get("legacy_fail_mode_source")),"bound" if all(m.get(n)=="open" for n in sys.argv[4].split()) else "unbound")' "$config" "$connector" "$managed_open" "$flat_names" 2>/dev/null)" || summary="invalid"
    elif [ "${DEFENSECLAW_MANAGED_HOOK:-0}" != "1" ] || [ "${_DC_SECURE_CLIENT_HOOK:-0}" != "1" ]; then
      printf closed
      return 0
    fi
    if [ -z "$summary" ] && { command -v jq >/dev/null 2>&1 || _dc_python3_usable; }; then
      # A parser that ran and printed nothing read no state: malformed.
      summary="invalid"
    fi
  fi
  local json_count=0 json_all=open json_selected=none json_legacy=none json_bound=bound
  if [ -n "$summary" ]; then
    # shellcheck disable=SC2086 # four fixed words, split on purpose
    set -- $summary
    json_count="${1:-}"
    json_all="${2:-}"
    json_selected="${3:-}"
    json_legacy="${4:-}"
    json_bound="${5:-}"
    case "$json_count" in
      ""|*[!0-9]*) printf closed; return 0 ;;
    esac
    # Exactly the five words the parsers print, nothing more.
    if [ "$#" -ne 5 ]; then
      printf closed
      return 0
    fi
  fi
  if [ "$json_all" != "open" ]; then
    printf closed
    return 0
  fi
  # The managed writer records a connector in the protected JSON and its flat
  # file together, so a flat open the JSON does not record open is a leftover
  # (an earlier per-user install, a torn-down connector) that no current
  # policy chose: it never opens a managed hook (GAP-0449). Secure Client
  # delivery keeps its flat-record reading.
  if [ -n "$summary" ] && [ "$json_bound" != "bound" ] && [ "${_DC_SECURE_CLIENT_HOOK:-0}" != "1" ]; then
    printf closed
    return 0
  fi
  # Every recorded connector is open. A selected connector (the one record,
  # or the environment's choice) must have an open record of its own.
  if [ -n "$connector" ]; then
    if [ "$selected" = "open" ] || [ "$json_selected" = "open" ]; then
      printf open
    else
      printf closed
    fi
    return 0
  fi
  # No selected connector: several records (an ambiguous identity) or none.
  # A closed record already closed it above.
  local legacy="${hook_dir}/.hookcfg.legacy" legacy_connector
  if [ "$managed_open" = 1 ] && { [ "$records" -gt 0 ] || [ "$json_count" -gt 0 ]; }; then
    # Managed: every guardian record is the administrator's open, so their
    # strictest combination is open. A legacy record, flat or JSON, joins it.
    if [ -e "$legacy" ] || [ -L "$legacy" ]; then
      if ! legacy_connector="$(defenseclaw_flat_hookcfg_value "$legacy" DEFENSECLAW_CONNECTOR 2>/dev/null)" \
        || [ -n "$legacy_connector" ] \
        || [ "$(defenseclaw_flat_hookcfg_value "$legacy" DEFENSECLAW_FAIL_MODE 2>/dev/null || true)" != "open" ]; then
        printf closed
        return 0
      fi
    fi
    if [ "$json_legacy" = "closed" ]; then
      printf closed
      return 0
    fi
    # A flat legacy open the parsed JSON does not record open is a leftover
    # too (GAP-0449).
    if [ -n "$summary" ] && [ "$json_legacy" != "open" ] && [ "${_DC_SECURE_CLIENT_HOOK:-0}" != "1" ] \
      && { [ -e "$legacy" ] || [ -L "$legacy" ]; }; then
      printf closed
      return 0
    fi
    printf open
    return 0
  fi
  # An administrator may have installed only an unscoped managed record.
  # Its flat and JSON records must agree when the JSON parser is available.
  if ! legacy_connector="$(defenseclaw_flat_hookcfg_value "$legacy" DEFENSECLAW_CONNECTOR 2>/dev/null)" \
    || [ -n "$legacy_connector" ] \
    || [ "$(defenseclaw_flat_hookcfg_value "$legacy" DEFENSECLAW_FAIL_MODE 2>/dev/null || true)" != "open" ]; then
    printf closed
    return 0
  fi
  if [ -n "$summary" ] && [ "$json_legacy" != "open" ]; then
    printf closed
    return 0
  fi
  printf open
}

# defenseclaw_managed_runtime_sidecar returns 0 when this hook is managed (its
# script sets DEFENSECLAW_MANAGED_HOOK) and config, hooks/.hookcfg, records
# managed_enterprise true, which only the guardian's managed writer sets. A
# per-user hook that inherits DEFENSECLAW_MANAGED_HOOK=1 reads a per-user
# sidecar without it, so its unsourced open stays closed. Builtins only: jq
# and python3 are not on every hardened PATH.
defenseclaw_managed_runtime_sidecar() {
  local config="$1" body=""
  [ "${DEFENSECLAW_MANAGED_HOOK:-0}" = "1" ] || return 1
  [ -f "$config" ] && [ ! -L "$config" ] || return 1
  IFS= read -r -d '' -n 65536 body < "$config" 2>/dev/null || [ -n "$body" ] || return 1
  [[ "$body" =~ \"managed_enterprise\"[[:space:]]*:[[:space:]]*true([^A-Za-z0-9_]|$) ]]
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

# Build the inspect tool request without placing tool content on argv. jq is
# optional on host hooks; Python provides the same JSON string encoding when
# jq is unavailable. Without either encoder the caller refuses the request.
defenseclaw_inspect_tool_body() {
  local tool="$1" field="$2"
  case "$field" in args|output) ;; *) return 1 ;; esac
  if command -v jq >/dev/null 2>&1; then
    case "$field" in
      args) jq -Rs --arg tool "$tool" '{tool: $tool, args: .}' ;;
      output) jq -Rs --arg tool "$tool" '{tool: $tool, output: .}' ;;
    esac
  elif _dc_python3_usable; then
    python3 -c 'import json,sys; print(json.dumps({"tool":sys.argv[1],sys.argv[2]:sys.stdin.read()}))' "$tool" "$field"
  else
    return 1
  fi
}

# defenseclaw_inspect_bounded_body TOOL FIELD encodes an 8 KiB head of the
# oversized input (on stdin) as a generic inspect request with the
# incomplete-review markers, the head the native hook's bounded review keeps
# of a long value. The gateway marks a bounded review uninspected whatever
# its size (observe: allow with the oversize warning; action: block), so a
# larger prefix only costs scan time: 64 KiB or more already ran past the
# generic endpoint's 200 ms scan budget and came back 504 with no verdict
# (GAP-1512, GAP-1841). Escaped, 8 KiB stays far under the 1 MiB body cap.
defenseclaw_inspect_bounded_body() {
  local LC_ALL=C
  local tool="$1" field="$2" input body
  input="$(cat; printf x)" || return 1
  input="${input%x}"
  body="$(printf '%s' "${input:0:8192}" | defenseclaw_inspect_tool_body "$tool" "$field")" || return 1
  printf '%s' "${body%?},\"content_truncated\":true,\"bounded_prefix_review\":true}"
}

# defenseclaw_json_string_field extracts a top-level JSON string field when
# jq and python3 are unavailable. The whole answer is validated first: a
# malformed sibling field cannot turn an "action":"allow" into a verdict.
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
    function ws() {
      while (p <= n && substr(text,p,1) ~ /[[:space:]]/) p++
    }
    function str(   start,c,esc,d) {
      if (substr(text,p,1) != "\"") return 0
      p++; start=p
      while (p <= n) {
        c=substr(text,p,1)
        if (c == "\"") {
          parsed=substr(text,start,p-start)
          p++
          return 1
        }
        if (c == "\\") {
          p++
          esc=substr(text,p,1)
          if (esc == "u") {
            for (d=1; d<=4; d++)
              if (substr(text,p+d,1) !~ /^[0-9a-fA-F]$/) return 0
            p+=5
            continue
          }
          if (index("\"\\/bfnrt",esc) == 0) return 0
          p++
          continue
        }
        if (c ~ /[[:cntrl:]]/) return 0
        p++
      }
      return 0
    }
    function number(   c) {
      if (substr(text,p,1) == "-") p++
      c=substr(text,p,1)
      if (c == "0") p++
      else if (c ~ /^[1-9]$/) {
        do { p++; c=substr(text,p,1) } while (c ~ /^[0-9]$/)
      } else return 0
      if (substr(text,p,1) == ".") {
        p++
        if (substr(text,p,1) !~ /^[0-9]$/) return 0
        while (substr(text,p,1) ~ /^[0-9]$/) p++
      }
      c=substr(text,p,1)
      if (c == "e" || c == "E") {
        p++; c=substr(text,p,1)
        if (c == "+" || c == "-") p++
        if (substr(text,p,1) !~ /^[0-9]$/) return 0
        while (substr(text,p,1) ~ /^[0-9]$/) p++
      }
      return 1
    }
    function val(level,   c) {
      if (level > 64) return 0
      ws(); c=substr(text,p,1)
      if (c == "{") return obj(level)
      if (c == "[") return arr(level)
      if (c == "\"") return str()
      if (substr(text,p,4) == "true" || substr(text,p,4) == "null") { p+=4; return 1 }
      if (substr(text,p,5) == "false") { p+=5; return 1 }
      return number()
    }
    function arr(level,   c) {
      p++; ws()
      if (substr(text,p,1) == "]") { p++; return 1 }
      while (p <= n) {
        if (!val(level+1)) return 0
        ws(); c=substr(text,p,1); p++
        if (c == "]") return 1
        if (c != ",") return 0
      }
      return 0
    }
    function obj(level,   id,key,c) {
      id=++objects
      p++; ws()
      if (substr(text,p,1) == "}") { p++; return 1 }
      while (p <= n) {
        if (!str()) return 0
        key=parsed
        if (index(key,"\\") || seen[id SUBSEP key]++) return 0
        ws()
        if (substr(text,p,1) != ":") return 0
        p++; ws()
        if (level == 0 && key == wanted) {
          if (!str()) return 0
          result=parsed; found=1
        } else if (!val(level+1)) return 0
        ws(); c=substr(text,p,1); p++
        if (c == "}") return 1
        if (c != ",") return 0
        ws()
      }
      return 0
    }
    END {
      found = 0
      n = length(text)
      p=1; ws()
      if (substr(text,p,1) != "{" || !obj(0)) exit 2
      ws()
      if (p <= n) exit 2
      if (found) { print result; exit 0 }
      exit 1
    }
  ')"; then
    # A caller that only validates the answer reads no value: no sed for it
    # (defenseclaw_json_answer_valid, issue #1130 / GAP-0267).
    [ "${3:-}" = --check ] && return 0
    printf '%s' "$extracted" | sed 's/\\"/"/g; s/\\\\/\\/g; s/\\n/ /g; s/\\r/ /g; s/\\t/ /g'
    return 0
  else
    status=$?
    return "$status"
  fi
}

# defenseclaw_json_answer_valid JSON FIELD returns 0 when JSON is one valid
# object with exactly one top-level string FIELD: the check of
# defenseclaw_json_string_field without decoding the value.
defenseclaw_json_answer_valid() {
  defenseclaw_json_string_field "${1:-}" "${2:-}" --check
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
  local _dcjq_field _dcjq_default _dcjq_default_kind _dcjq_value _dcjq_json _dcjq_status _dcjq_strict
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
      # An action decides whether a tool call proceeds. In the string-only
      # fallback, require the entire response to be one complete object.
      _dcjq_strict=""
      [ "$_dcjq_field" != action ] || _dcjq_strict=strict
      if _dcjq_value="$(defenseclaw_json_string_field "$_dcjq_json" "$_dcjq_field" "$_dcjq_strict")"; then
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
#   defenseclaw_log_hook_failure CONNECTOR HOOK_NAME REASON CATEGORY FAIL_MODE OUTCOME
# OUTCOME records the actual delivery decision, not merely configured policy:
# fail_open (the call ran unchecked), fail_closed (it was blocked) or
# diagnostic (a record that is no delivery decision: the call still went to
# the gateway). Every caller passes one; the gateway counts fail_open lines
# as unchecked calls and keeps the fail_mode rule only for lines older hooks
# wrote without one (unknown).
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
  local fail_mode="${5:-${FAIL_MODE:-closed}}"
  local outcome="${6:-unknown}"
  case "$outcome" in
    fail_open|fail_closed|diagnostic) : ;;
    *) outcome=unknown ;;
  esac
  # A per-user outage the hook lets through gets its one warning, with the
  # cause and the fix, from defenseclaw_emit_unreachable_stderr.
  if [ "$outcome" = "fail_open" ] &&
     ! { [ "$category" = transport ] && defenseclaw_per_user_outage_open; } &&
     ! { [[ "$reason" = "stdin body exceeded "* ]] && defenseclaw_per_user_oversize_open; }; then
    printf 'defenseclaw: WARNING hook fail-open; inspection bypassed (connector=%s hook=%s category=%s): %s\n' \
      "$(defenseclaw_json_escape "$connector")" "$(defenseclaw_json_escape "$hook_name")" \
      "$(defenseclaw_json_escape "$category")" "$(defenseclaw_json_escape "$reason")" >&2 || true
  fi
  local log_dir="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}/logs"
  # Only logs: a log line never creates the DefenseClaw folder a purge
  # removed (GAP-0654).
  [ -d "$log_dir" ] || mkdir "$log_dir" 2>/dev/null || return 0
  chmod 700 "$log_dir" 2>/dev/null || true
  local log_file="${log_dir}/hook-failures.jsonl"
  local ts
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date 2>/dev/null || printf unknown)"
  local safe_ts safe_connector safe_hook_name safe_reason safe_category safe_fail_mode
	local correlation_payload="${PAYLOAD:-${CONTENT:-}}" session_id="" call_id=""
	if [ -n "$correlation_payload" ]; then
	  session_id="$(_dc_hook_event_field "$correlation_payload" session_id 2>/dev/null)" || session_id=""
	  [ -n "$session_id" ] || session_id="$(_dc_hook_event_field "$correlation_payload" sessionID 2>/dev/null)" || session_id=""
	  [ -n "$session_id" ] || session_id="$(_dc_hook_event_field "$correlation_payload" sessionId 2>/dev/null)" || session_id=""
	  [ -n "$session_id" ] || session_id="$(_dc_hook_event_field "$correlation_payload" thread_id 2>/dev/null)" || session_id=""
	  call_id="$(_dc_hook_event_field "$correlation_payload" source_event_id 2>/dev/null)" || call_id=""
	  [ -n "$call_id" ] || call_id="$(_dc_hook_event_field "$correlation_payload" tool_call_id 2>/dev/null)" || call_id=""
	  [ -n "$call_id" ] || call_id="$(_dc_hook_event_field "$correlation_payload" callID 2>/dev/null)" || call_id=""
	fi
	session_id="${session_id:0:256}"
	call_id="${call_id:0:256}"
	[ -n "$call_id" ] || call_id="$$-${RANDOM}${RANDOM}"
  safe_ts="$(defenseclaw_json_escape "$ts")"
  safe_connector="$(defenseclaw_json_escape "$connector")"
  safe_hook_name="$(defenseclaw_json_escape "$hook_name")"
  safe_reason="$(defenseclaw_json_escape "$reason")"
  safe_category="$(defenseclaw_json_escape "$category")"
  safe_fail_mode="$(defenseclaw_json_escape "$fail_mode")"
  # stderr is redirected before the append so a failed open of the log
  # (full disk, read-only home) cannot print a shell diagnostic naming this
  # script into the agent-visible block reason (GAP-1974).
  printf '{"ts":"%s","connector":"%s","hook":"%s","reason":"%s","category":"%s","fail_mode":"%s","outcome":"%s","session_id":"%s","call_id":"%s"}\n' \
    "$safe_ts" "$safe_connector" "$safe_hook_name" "$safe_reason" "$safe_category" "$safe_fail_mode" "$outcome" \
    "$(defenseclaw_json_escape "$session_id")" "$(defenseclaw_json_escape "$call_id")" \
    2>/dev/null >> "$log_file" || true
  chmod 600 "$log_file" 2>/dev/null || true
  return 0
}

# Only use this wrapper for delivery failure branches that honor FAIL_MODE and
# apply strict availability to transport failures. Diagnostic-only records and
# payload reader fallbacks must not claim that inspection was bypassed.
defenseclaw_log_hook_delivery_failure() {
  local outcome mode="$5"
  # Keep the call-time tier in this shell for logging, warning and verdict.
  defenseclaw_resolve_hook_delivery_outcome "$4" "$5"
  outcome="$_DC_HOOK_DELIVERY_OUTCOME"
  # A per-user outage the hook lets through records the open outage mode it
  # followed, so the gateway reports the unchecked call when it is back.
  [ "$outcome" != fail_open ] || mode=open
  defenseclaw_log_hook_failure "$1" "$2" "$3" "$4" "$mode" "$outcome"
}

# defenseclaw_per_user_outage_open returns 0 (true) when a per-user hook lets
# the call through because this account's gateway is down (owner decision
# 2026-10-23, config.HookOutageFailMode): the call's last transport status
# (_DC_TRANSPORT_STATUS, defenseclaw_await_gateway) is 7, no gateway took the
# connection after the cold-start retries, and the connector's current config
# selects an open tier. Strict availability, this account's install
# window, an answer the gateway gave (any HTTP status, a cut-off or
# malformed body), another program on the port, a missing token and a
# config that is missing, malformed or strict keep the call closed. Managed,
# socket, Secure Client and shared inspect-* hooks never take this path. The
# defenseclaw-call-time-outage-v1: the config in this hook's own data
# directory alone decides the tier.
defenseclaw_per_user_outage_open() {
  case "${DEFENSECLAW_MANAGED_HOOK:-0}" in
    1|true|TRUE|yes|YES) return 1 ;;
  esac
  [ -z "${DEFENSECLAW_HOOK_SOCKET:-}" ] || return 1
  [ "${_DC_SECURE_CLIENT_HOOK:-0}" != 1 ] || return 1
  [ "${_DC_TRANSPORT_STATUS:-}" = 7 ] || return 1
  case "${DEFENSECLAW_STRICT_AVAILABILITY:-0}" in
    1|true|TRUE|yes|YES) return 1 ;;
  esac
  # Either data folder an installer may hold (GAP-0914, defenseclaw_install_held).
  ! defenseclaw_install_held || return 1
  local connector="${DEFENSECLAW_HOOK_CONNECTOR:-}"
  case "$connector" in
    ""|inspect|*[!a-z0-9_-]*) return 1 ;;
  esac
  [ -n "${HOOK_DIR:-}" ] || return 1
  defenseclaw_config_outage_open "$connector"
}

# defenseclaw_config_outage_open CONNECTOR returns 0 only when this hook's
# runtime config gives CONNECTOR the open outage mode now. The selected
# gateway binary runs `hook-outage-mode`, which reads config.yaml next to the
# hook's own data directory. Agent environment cannot select the config or
# binary. A missing binary, unreadable config, or other answer stays closed.
defenseclaw_config_outage_open() {
  local home="" hook_dir="${HOOK_DIR:-}" bin=""
  if [ -z "$_DC_CONFIG_OUTAGE_MODE" ]; then
    _DC_CONFIG_OUTAGE_MODE=closed
    if [ "${hook_dir#/}" != "$hook_dir" ] &&
      bin="$(defenseclaw_gateway_binary)"; then
      home="${bin%/.local/bin/defenseclaw-gateway}"
      # The Go runtime cannot start under the hook's address-space limit.
      _DC_CONFIG_OUTAGE_MODE="$(
        ulimit -S -v "$(ulimit -H -v)" 2>/dev/null || true
        HOME="$home" exec "$bin" hook-outage-mode --connector "$1" --hook-dir "$hook_dir" </dev/null 2>/dev/null
      )" || _DC_CONFIG_OUTAGE_MODE=closed
    fi
  fi
  [ "$_DC_CONFIG_OUTAGE_MODE" = open ]
}

# A completed bounded read can be sent for prefix review in the balanced
# per-user tier. The installed flat record carries that tier.
defenseclaw_per_user_oversize_open() {
  case "${DEFENSECLAW_MANAGED_HOOK:-0}" in 1|true|TRUE|yes|YES) return 1 ;; esac
  [ -z "${DEFENSECLAW_HOOK_SOCKET:-}" ] || return 1
  [ "${_DC_SECURE_CLIENT_HOOK:-0}" != 1 ] || return 1
  case "${DEFENSECLAW_STRICT_AVAILABILITY:-0}" in 1|true|TRUE|yes|YES) return 1 ;; esac
  ! defenseclaw_install_held || return 1
  local connector="${DEFENSECLAW_HOOK_CONNECTOR:-}" record="" recorded="" mode="" source=""
  [ "$connector" != inspect ] || connector="${RUNTIME_CONNECTOR:-}"
  case "$connector" in ""|*[!a-z0-9_-]*) return 1 ;; esac
  [ -n "${HOOK_DIR:-}" ] || return 1
  record="${HOOK_DIR}/.hookcfg.${connector}"
  recorded="$(defenseclaw_flat_hookcfg_value "$record" DEFENSECLAW_CONNECTOR 2>/dev/null)" || return 1
  mode="$(defenseclaw_flat_hookcfg_value "$record" DEFENSECLAW_FAIL_MODE 2>/dev/null)" || return 1
  source="$(defenseclaw_flat_hookcfg_value "$record" FAIL_MODE_SOURCE 2>/dev/null)" || return 1
  [ "$recorded" = "$connector" ] && [ "$mode" = open ] && [ "$source" = config ]
}

# Prepare a valid request from the cap's prefix. The pinned installed helper
# uses the same JSON encoder as the native hook. A missing or changed helper
# is a local failure and stays closed; it cannot create another allow path.
defenseclaw_prepare_oversized_stdin() {
  if _defenseclaw_prepare_oversized_stdin_impl "$@"; then
    return 0
  fi
  if [ "${1:-}" = 3 ]; then
    defenseclaw_log_hook_failure "${DEFENSECLAW_HOOK_CONNECTOR:-unknown}" "${DEFENSECLAW_HOOK_NAME:-unknown}" \
      "oversized prefix review unavailable" transport closed fail_closed
  fi
  return 1
}

_defenseclaw_prepare_oversized_stdin_impl() {
  [ "${1:-}" = 3 ] && defenseclaw_per_user_oversize_open || return 1
  local root="${DEFENSECLAW_AGENT_HOME:-}" bin mode path
  case "$root" in /*) ;; *) return 1 ;; esac
  bin="$root/.local/bin/defenseclaw-hook-post"
  for path in "$root" "$root/.local" "$root/.local/bin"; do
    [ -d "$path" ] && [ -O "$path" ] && [ ! -L "$path" ] || return 1
    defenseclaw_stat_into %a %Lp "$path" || return 1
    mode="$_DC_STAT_OUT"
    case "$mode" in ''|*[!0-7]*) return 1 ;; esac
    [ $((8#$mode & 8#022)) -eq 0 ] || return 1
  done
  [ -f "$bin" ] && [ -x "$bin" ] && [ -O "$bin" ] && [ ! -L "$bin" ] || return 1
  defenseclaw_stat_into %a %Lp "$bin" || return 1
  mode="$_DC_STAT_OUT"
  case "$mode" in ''|*[!0-7]*) return 1 ;; esac
  [ $((8#$mode & 8#022)) -eq 0 ] || return 1
  PAYLOAD="$(printf '%s' "$PAYLOAD" | (
    if [ -n "${_DC_HOOK_NATIVE_VMEM_LIMIT:-}" ]; then
      ulimit -S -v "$_DC_HOOK_NATIVE_VMEM_LIMIT" 2>/dev/null || exit 1
    fi
    exec "$bin" prefix-review --event "${BOUND_EVENT:-}"
  ))" || return 1
  # A reached gateway's malformed or error answer stays closed. The outage
  # resolver reads the installed record independently of this response mode.
  FAIL_MODE=closed
  [ -n "$PAYLOAD" ]
}

defenseclaw_warn_reviewed_oversize() {
  case "$1" in *'"bounded_prefix_review":true'*) ;; *) return 0 ;; esac
  local response="$2" status result action
  status="${response##*$'\n'}"
  case "$status" in 200|201|202) ;; *) return 0 ;; esac
  result="${response%$'\n'*}"
  action="$(defenseclaw_json_string_field "$result" action 2>/dev/null)" || return 0
  case "$action" in
    allow|alert) printf 'defenseclaw: warning: hook payload exceeded the bounded inspection cap; the gateway allowed and audited this call\n' >&2 ;;
  esac
}

defenseclaw_hook_delivery_outcome() {
  defenseclaw_resolve_hook_delivery_outcome "$1" "$2"
  printf '%s' "$_DC_HOOK_DELIVERY_OUTCOME"
}

defenseclaw_resolve_hook_delivery_outcome() {
  _DC_HOOK_DELIVERY_OUTCOME=fail_closed
  if [ "${1:-response}" = "transport" ] && defenseclaw_per_user_outage_open; then
    _DC_HOOK_DELIVERY_OUTCOME=fail_open
    return 0
  fi
  if [ "${2:-${FAIL_MODE:-closed}}" = "open" ] && ! defenseclaw_install_in_progress; then
    _DC_HOOK_DELIVERY_OUTCOME=fail_open
    if [ "${1:-response}" = "transport" ] && defenseclaw_should_fail_closed_on_unreachable; then
      _DC_HOOK_DELIVERY_OUTCOME=fail_closed
    fi
  fi
}

# defenseclaw_install_lock_held DATA returns 0 (true) while this account's
# installer holds its data directory DATA: DATA/.install.lock exists as any
# file type and is not stale (defenseclaw_install_lock_stale), or DATA
# exists but cannot be searched, so the lock cannot be shown absent; no DATA
# to look in counts as held too. The native hook (installLockHeld), the
# in-agent plugins and the Windows adapters apply the same rule (GAP-0914).
# defenseclaw_install_held below, the one install check of every shell hook,
# reads it.
defenseclaw_install_lock_held() {
  local data="${1:-}"
  [ -n "$data" ] || return 0
  if [ -e "${data}/.install.lock" ] || [ -L "${data}/.install.lock" ]; then
    defenseclaw_install_lock_stale "$data" && return 1
    return 0
  fi
  if [ -e "$data" ] || [ -L "$data" ]; then
    if [ -d "$data" ] && [ -x "$data" ]; then
      return 1
    fi
    return 0
  fi
  return 1
}
# defenseclaw_install_lock_stale DATA returns 0 (true) when DATA/.install.lock
# is a folder whose installer is proven gone (an interrupted-install record
# beside it does not hold it, GAP-1024): its pid names no process, or this hook's own (no
# hook writes a lock), or another process than its proc-start record names
# (a reused pid). It reads no clock (hookexec installLockStale, the one
# rule): a live owner keeps the lock for as long as it runs, and so do a
# lock without a valid pid, a lock without a proc-start record whose pid
# names a process (1.0.2, 1.0.3) and an owner whose identity cannot be read.
defenseclaw_install_lock_stale() {
  local data="${1:-}" lock rc pid recorded current
  lock="${data}/.install.lock"
  [ -d "$lock" ] && [ ! -L "$lock" ] || return 1
  rc=0
  pid="$(defenseclaw_install_lock_number "${lock}/pid")" || rc=$?
  [ "$rc" = 0 ] || return 1
  [ "$pid" -le 2147483647 ] || return 1
  # A live installer's pid names no other process: this one is reused.
  [ "$pid" = "$$" ] && return 0
  if ! kill -0 "$pid" 2>/dev/null; then
    # A process of another account refuses the signal; only ps proves it gone.
    command -v ps >/dev/null 2>&1 || return 1
    ps -p "$pid" >/dev/null 2>&1 || return 0
  fi
  # An installer that exited but is not reaped (a zombie) keeps its pid and
  # its start, but runs nothing.
  defenseclaw_process_ended "$pid" && return 0
  if [ ! -e "${lock}/proc-start" ] && [ ! -L "${lock}/proc-start" ]; then
    defenseclaw_process_started_after_lock "$pid" "$lock"
    return
  fi
  recorded="$(defenseclaw_install_lock_record "${lock}/proc-start")" || return 1
  current="$(defenseclaw_process_identity "$pid")" || return 1
  [ "$recorded" != "$current" ] && return 0
  return 1
}
# defenseclaw_process_identity PID prints the identity of process PID as the
# system keeps it from its creation, the record install.sh keeps of itself
# in a lock (proc-start; hookexec procidentity): on Linux its boot id and
# kernel start, "<boot_id> <starttime>" (field 22 of /proc/PID/stat); on
# macOS its creation second as `LC_ALL=C TZ=UTC ps -o lstart=` prints it,
# one space apart. No clock step moves either. It returns 1 when the system
# does not say.
defenseclaw_process_identity() {
  local boot stat out IFS=' '
  if [ -e /proc/self/stat ]; then
    boot="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)" || return 1
    stat="$(cat "/proc/${1:-}/stat" 2>/dev/null)" || return 1
    case "$stat" in *[\)]*) ;; *) return 1 ;; esac
    stat="${stat##*[\)]}"
    set -- $stat
    [ "$#" -ge 20 ] || return 1
    shift 19
    case "$1" in ''|*[!0-9]*) return 1 ;; esac
    case "$boot" in ''|*[!0-9a-f-]*) return 1 ;; esac
    printf '%s %s' "$boot" "$1"
    return 0
  fi
  [ "$(uname -s 2>/dev/null)" = Darwin ] && [ -x /bin/ps ] || return 1
  out="$(LC_ALL=C TZ=UTC /bin/ps -o lstart= -p "${1:-}" 2>/dev/null)" || return 1
  set -- $out
  [ "$#" -eq 5 ] || return 1
  printf '%s %s %s %s %s' "$1" "$2" "$3" "$4" "$5"
}
# defenseclaw_process_ended PID returns 0 when process PID has exited but
# keeps its pid: a zombie its parent has not reaped (hookexec
# procidentity.Ended). It returns 1 while it runs or when the system does
# not say.
defenseclaw_process_ended() {
  local stat IFS=' '
  if [ -e /proc/self/stat ]; then
    stat="$(cat "/proc/${1:-}/stat" 2>/dev/null)" || return 1
    case "$stat" in *[\)]*) ;; *) return 1 ;; esac
    stat="${stat##*[\)]}"
    set -- $stat
    case "${1:-}" in Z|X|x) return 0 ;; esac
    return 1
  fi
  [ -x /bin/ps ] || return 1
  stat="$(LC_ALL=C /bin/ps -o stat= -p "${1:-}" 2>/dev/null)" || return 1
  set -- $stat
  case "${1:-}" in Z*) return 0 ;; esac
  return 1
}
# defenseclaw_process_started_after_lock PID LOCK returns 0 when process PID
# started more than 2 s after LOCK was last changed: a 1.0.2/1.0.3 lock
# without a proc-start record whose pid a later process got (GAP-1465, the
# hookexec rule). It returns 1 when it started earlier or the system does not
# say.
defenseclaw_process_started_after_lock() {
  local locked="" started="" boot="" stat="" line="" out="" IFS=' '
  locked="$(stat -c %Y "${2:-}" 2>/dev/null || stat -f %m "${2:-}" 2>/dev/null)" || return 1
  case "$locked" in ''|*[!0-9]*) return 1 ;; esac
  if [ -e /proc/self/stat ]; then
    while IFS= read -r line; do
      case "$line" in "btime "*) boot="${line#btime }"; break ;; esac
    done < /proc/stat
    case "$boot" in ''|*[!0-9]*) return 1 ;; esac
    stat="$(cat "/proc/${1:-}/stat" 2>/dev/null)" || return 1
    case "$stat" in *[\)]*) ;; *) return 1 ;; esac
    stat="${stat##*[\)]}"
    set -- $stat
    [ "$#" -ge 20 ] || return 1
    shift 19
    case "$1" in ''|*[!0-9]*) return 1 ;; esac
    started=$((boot + $1 / 100))
  else
    [ "$(uname -s 2>/dev/null)" = Darwin ] && [ -x /bin/ps ] || return 1
    out="$(LC_ALL=C TZ=UTC /bin/ps -o lstart= -p "${1:-}" 2>/dev/null)" || return 1
    started="$(LC_ALL=C TZ=UTC date -j -u -f "%a %b %e %T %Y" "$out" +%s 2>/dev/null)" || return 1
    case "$started" in ''|*[!0-9]*) return 1 ;; esac
  fi
  [ "$started" -gt $((locked + 2)) ]
}
# defenseclaw_install_lock_record FILE prints the trimmed text of a small
# owner record (proc-start); it returns 1 when FILE is not a small regular
# file or is empty.
defenseclaw_install_lock_record() {
  local file="${1:-}" size text
  [ -f "$file" ] && [ ! -L "$file" ] && [ -r "$file" ] || return 1
  size="$(wc -c < "$file" 2>/dev/null | tr -d ' ')" || return 1
  case "$size" in ''|*[!0-9]*) return 1 ;; esac
  [ "$size" -le 128 ] || return 1
  text="$(cat "$file" 2>/dev/null)" || return 1
  text="${text#"${text%%[![:space:]]*}"}"
  text="${text%"${text##*[![:space:]]}"}"
  [ -n "$text" ] || return 1
  printf '%s' "$text"
}
# defenseclaw_install_lock_number FILE prints the decimal number of the owner
# record file (pid). It returns 1 when FILE is absent, empty or
# not a positive number, and 2 when it cannot be read (not a small regular
# file).
defenseclaw_install_lock_number() {
  local file="${1:-}" size text
  if [ ! -e "$file" ] && [ ! -L "$file" ]; then
    return 1
  fi
  [ -f "$file" ] && [ ! -L "$file" ] && [ -r "$file" ] || return 2
  size="$(wc -c < "$file" 2>/dev/null | tr -d ' ')" || return 2
  case "$size" in ''|*[!0-9]*) return 2 ;; esac
  [ "$size" -le 64 ] || return 2
  text="$(cat "$file" 2>/dev/null)" || return 2
  text="${text#"${text%%[![:space:]]*}"}"
  text="${text%"${text##*[![:space:]]}"}"
  case "$text" in ''|0*|*[!0-9]*) return 1 ;; esac
  [ "${#text}" -le 12 ] || return 1
  printf '%s' "$text"
}
# defenseclaw_install_held returns 0 (true) while an installer holds either
# data directory of this account's hook: the one DEFENSECLAW_HOME names, else
# ~/.defenseclaw, where install.sh and install.ps1 take the lock, and the one
# the hook was installed in (_DC_HOOK_DATA_DIR, the folder above its hooks
# folder), which the gateway rendered it into from its resolved data
# directory. An agent that runs the hook without DEFENSECLAW_HOME, or a
# data_dir apart from DEFENSECLAW_HOME, still finds the lock (GAP-0948).
# A per-user render also checks the data directory the gateway rendered it
# into (_DC_HOOK_HOME, written into the file), so a hard link, a symlink or a
# copy of the hook, run from any folder, is held by that install's lock.
defenseclaw_install_held() {
  if [ -n "${_DC_HOOK_HOME:-}" ] && defenseclaw_install_lock_held "${_DC_HOOK_HOME}"; then
    return 0
  fi
  defenseclaw_install_lock_held "${DEFENSECLAW_HOME:-${HOME:+${HOME}/.defenseclaw}}" && return 0
  [ -n "${_DC_HOOK_DATA_DIR:-}" ] && defenseclaw_install_lock_held "${_DC_HOOK_DATA_DIR}"
}

# defenseclaw_managed_lifecycle_held returns 0 (true) while the enterprise
# lifecycle of this computer runs: its run marker exists, as any file type.
# The lifecycle holds it with its lock, from before it can stop or restart
# the gateway until the gateway it started is ready, in the root-only /run
# (/var/run on macOS). The native hook (managedLifecycleActive) reads the
# same marker (GAP-1074).
defenseclaw_managed_lifecycle_held() {
  local marker
  for marker in /run/defenseclaw-lifecycle.active /var/run/defenseclaw-lifecycle.active; do
    if [ -e "$marker" ] || [ -L "$marker" ]; then
      return 0
    fi
  done
  return 1
}

# defenseclaw_install_in_progress returns 0 (true) while this account is
# being installed or upgraded (defenseclaw_install_held of its data
# directories). A managed hook outside Secure Client reads its computer's
# lifecycle instead (defenseclaw_managed_lifecycle_held): an administrator's
# open covers an outage, never an install, upgrade or lifecycle restart. A
# Secure Client hook keeps its delivery policy and returns 1.
defenseclaw_install_in_progress() {
  case "${DEFENSECLAW_MANAGED_HOOK:-0}" in
    1|true|TRUE|yes|YES)
      [ "${_DC_SECURE_CLIENT_HOOK:-0}" != 1 ] || return 1
      defenseclaw_managed_lifecycle_held
      return
      ;;
  esac
  defenseclaw_install_held
}

# While this account is being installed or upgraded, no failure may approve
# a hook call: defenseclaw_close_during_install closes FAIL_MODE then. A hook
# calls it after it selects its installed mode, and every failure answer
# calls it again when it answers (fail_unreachable, fail_response, an
# oversized payload, defenseclaw_should_fail_closed_on_unreachable): an
# install that starts while the call waits for the gateway closes that call
# too (GAP-0894).
defenseclaw_close_during_install() {
  [ "${FAIL_MODE:-}" != "closed" ] || return 0
  if defenseclaw_install_in_progress; then
    FAIL_MODE=closed
  fi
  return 0
}

# defenseclaw_native_output_agrees STYLE EVENT ACTION OUTPUT returns 0 when
# OUTPUT, the Claude Code (STYLE claudecode) or Codex (codex) object the
# gateway rendered for EVENT, gives the agent what ACTION asks for: a deny or
# block for block, an ask for confirm. The agent acts on that object, not on
# the action, so one that allows would let a blocked call run beside the
# block. It is the native hook's nativeOutputAgrees (GAP-0950).
defenseclaw_native_output_agrees() {
  local style="${1:-}" event="${2:-}" action="${3:-}" output="${4:-}" want=deny nested="" value=""
  [ "$action" != "confirm" ] || want=ask
  case "$output" in "{"*) ;; *) return 1 ;; esac
  nested="$(printf '%s' "$output" | _dc_jq -c '.hookSpecificOutput // empty' 2>/dev/null)" || return 1
  case "$nested" in
    "{"*)
      value="$(printf '%s' "$nested" | _dc_jq -r '.hookEventName // empty' 2>/dev/null)" || return 1
      [ -z "$value" ] || [ "$value" = "$event" ] || return 1
      case "$event" in
        PreToolUse)
          value="$(printf '%s' "$nested" | _dc_jq -r '.permissionDecision // empty' 2>/dev/null)" || return 1
          [ "$value" = "$want" ]
          return
          ;;
        PermissionRequest)
          value="$(printf '%s' "$nested" | _dc_jq -c '.decision // empty' 2>/dev/null)" || return 1
          case "$value" in "{"*) ;; *) return 1 ;; esac
          value="$(printf '%s' "$value" | _dc_jq -r '.behavior // empty' 2>/dev/null)" || return 1
          [ "$value" = "$want" ]
          return
          ;;
        Elicitation|ElicitationResult)
          [ "$action" = "block" ] || return 1
          value="$(printf '%s' "$nested" | _dc_jq -r '.action // empty' 2>/dev/null)" || return 1
          [ "$value" = "decline" ]
          return
          ;;
        UserPromptSubmit)
          # Older Codex contracts also carry a prompt denial here.
          if [ "$style" = "codex" ]; then
            value="$(printf '%s' "$nested" | _dc_jq -r '.permissionDecision // empty' 2>/dev/null)" || return 1
            [ "$value" != "$want" ] || return 0
          fi
          ;;
      esac
      ;;
  esac
  case "$event" in
    PreToolUse|PermissionRequest|Elicitation|ElicitationResult) return 1 ;;
  esac
  value="$(printf '%s' "$output" | _dc_jq -r '.decision // empty' 2>/dev/null)" || return 1
  if [ "$action" = "confirm" ]; then
    [ "$value" = "ask" ]
    return
  fi
  if [ "$event" = "PreCompact" ] && [ "$style" = "claudecode" ]; then
    # Claude Code stops a compaction on decision block (GAP-0326).
    [ "$value" = "block" ]
    return
  fi
  case "$event" in
    SessionStart|PreCompact|PostCompact)
      [ "$style" = "codex" ] || return 1
      value="$(printf '%s' "$output" | _dc_jq -c '.continue' 2>/dev/null)" || return 1
      [ "$value" = "false" ]
      return
      ;;
  esac
  [ "$value" = "block" ]
}

# Read only the helper path setup recorded beside this installed hook. Every
# path component from the account home down, the record and the binary must
# be owned by this account and unwritable by other accounts. No PID record,
# inherited HOME, PATH or XDG variable can choose an executable.
defenseclaw_gateway_binary() {
  local hook_dir="${HOOK_DIR:-}" record="" candidate="" home="" path=""
  local modes="" mode="" count=0 extra="" want=7
  local -a checked=()
  # --folder proves the record and the folders only: the hook-post helper
  # beside a gateway is checked by its caller (GAP-1755).
  [ "${1:-}" = --folder ] && want=6
  # --folder --set leaves the result in _DC_GATEWAY_BINARY (no command
  # substitution) and also proves the mode of the hook-post helper beside the
  # gateway in the same stat (_DC_HOOK_POST_MODE_OK), so the caller runs no
  # second stat (issue #1130 / GAP-0267).
  local set_result=0 post=""
  [ "${1:-}" = --folder ] && [ "${2:-}" = --set ] && set_result=1
  _DC_GATEWAY_BINARY=""
  _DC_HOOK_POST_MODE_OK=""
  case "$hook_dir" in /*) ;; *) return 1 ;; esac
  record="${hook_dir}/.gateway-helper"
  [ -f "$record" ] && [ -O "$record" ] && [ ! -L "$record" ] || return 1
  {
    IFS= read -r -n 4096 candidate || return 1
    if IFS= read -r -n 1 extra; then return 1; fi
  } < "$record"
  case "$candidate" in
    /*/.local/bin/defenseclaw-gateway) home="${candidate%/.local/bin/defenseclaw-gateway}" ;;
    *) return 1 ;;
  esac
  case "$home" in *'/../'*|*'/./'*|*'/..'|*'/.'|'') return 1 ;; esac
  if [ "$want" = 7 ]; then
    [ -f "$candidate" ] && [ -x "$candidate" ] && [ -O "$candidate" ] && [ ! -L "$candidate" ] || return 1
  fi
  for path in "$hook_dir" "${hook_dir}/.." "$home" "$home/.local" "$home/.local/bin"; do
    [ -d "$path" ] && [ -O "$path" ] && [ ! -L "$path" ] || return 1
  done
  checked=("$hook_dir" "${hook_dir}/.." "$record" "$home" "$home/.local" "$home/.local/bin")
  [ "$want" = 6 ] || checked+=("$candidate")
  if [ "$set_result" = 1 ]; then
    post="${candidate%/*}/defenseclaw-hook-post"
    if [ -f "$post" ] && [ -x "$post" ] && [ -O "$post" ] && [ ! -L "$post" ]; then
      checked+=("$post")
      want=7
    else
      post=""
    fi
  fi
  defenseclaw_stat_into %a %Lp "${checked[@]}" || return 1
  modes="$_DC_STAT_OUT"
  while IFS= read -r mode; do
    case "$mode" in ""|*[!0-7]*) return 1 ;; esac
    [ $((8#${mode} & 8#022)) -eq 0 ] || return 1
    count=$((count + 1))
  done <<< "$modes"
  [ "$count" -eq "$want" ] || return 1
  if [ "$set_result" = 1 ]; then
    _DC_GATEWAY_BINARY="$candidate"
    _DC_HOOK_POST_MODE_OK="$post"
    return 0
  fi
  printf '%s' "$candidate"
}

# defenseclaw_retry_busy POST: a gateway that is taking all the hook calls it
# can answer, or an account over its hook budget, answers 429 before it
# evaluates the call. POST is a function that sends the same call again and
# sets RESPONSE (the body, then a last line with the HTTP status). While the
# last answer is 429, wait the Retry-After the gateway asks for (it mirrors
# the header in retry_after_seconds; 1 s when absent, at most 3 s) and send
# again: at most 3 times and 6 s of waiting in all, which stays inside every
# agent's hook deadline. The native hook runner does the same (GAP-0205);
# without it a short burst failed the tool call (GAP-0535). Returns POST's
# status when a retry could not be sent; a 429 that outlasts the budget is
# left in RESPONSE for the caller's status handling.
defenseclaw_retry_busy() {
  local attempt=0 waited=0 delay
  while [ "$attempt" -lt 3 ] && [ "${RESPONSE##*$'\n'}" = "429" ]; do
    defenseclaw_split_response
    delay="$(printf '%s\n' "$RESULT" | _dc_jq -r '.retry_after_seconds // empty' 2>/dev/null || true)"
    case "$delay" in
      ""|*[!0-9]*) delay=1 ;;
    esac
    [ "$delay" -ge 1 ] || delay=1
    [ "$delay" -le 3 ] || delay=3
    [ $((waited + delay)) -le 6 ] || return 0
    sleep "$delay"
    waited=$((waited + delay))
    attempt=$((attempt + 1))
    "$1" || return $?
  done
  return 0
}

# defenseclaw_split_response sets HTTP_CODE to the last line of RESPONSE (the
# status curl's -w "\n%{http_code}" appends) and RESULT to the lines before
# it, with no child process: each hook call used to run tail and sed for this
# (issue #1130).
defenseclaw_split_response() {
  HTTP_CODE="${RESPONSE##*$'\n'}"
  case "$RESPONSE" in
    *$'\n'*) RESULT="${RESPONSE%$'\n'*}" ;;
    *) RESULT="" ;;
  esac
}

# _dc_hook_post_response is the POST defenseclaw_retry_busy runs for the
# hooks whose defenseclaw_hook_post prints the response.
_dc_hook_post_response() {
  RESPONSE=$(defenseclaw_hook_post)
}

# defenseclaw_gateway_cold_start starts this account's per-user gateway in
# the background after the hook's request was refused: nothing else starts a
# per-user gateway after a reboot on Linux or macOS. It returns at once;
# defenseclaw_await_gateway sends the call again while the gateway starts,
# and a start that takes longer than the hook's restart budget finishes
# after the hook, so the next call finds the gateway running. It returns 1
# without starting when the gateway was stopped with `defenseclaw-gateway
# stop` (gateway.stopped), during an install (.install.lock), for a managed
# or socket hook, or when DEFENSECLAW_GATEWAY_AUTOSTART is 0. The start
# command serializes concurrent hooks with a restart and backs off after a
# failure. Of the account's hooks that find the gateway down together, only
# the first launches a start: it takes .cold-start.lock and the start it
# launches holds the lock until it ends, so a restart runs one start, not
# one per hook (GAP-0143). See _dc_cold_start_lock. This is the one helper
# that calls out to the gateway's own CLI.
defenseclaw_gateway_cold_start() {
  case "${DEFENSECLAW_MANAGED_HOOK:-0}" in
    1|true|TRUE|yes|YES) return 1 ;;
  esac
  case "${DEFENSECLAW_GATEWAY_AUTOSTART:-1}" in
    0|false|FALSE|no|NO|off|OFF) return 1 ;;
  esac
  [ -z "${DEFENSECLAW_HOOK_SOCKET:-}" ] || return 1
  local home="" data="" bin="" detach="" lock="" token=""
  bin="$(defenseclaw_gateway_binary)" || return 1
  home="${bin%/.local/bin/defenseclaw-gateway}"
  data="${HOOK_DIR}/.."
  [ -d "$data" ] && [ -f "${data}/config.yaml" ] || return 1
  [ ! -e "${data}/gateway.stopped" ] || return 1
  ! defenseclaw_install_lock_held "$data" || return 1
  [ ! -e "${data}/.disabled" ] || return 1
  lock="${data}/.cold-start.lock"
  token="$$.${RANDOM}${RANDOM}"
  _dc_cold_start_lock "$lock" "$token" || return 0
  # In its own session where setsid exists, so the agent ending the hook's
  # process group does not end a start that is still running.
  detach="$(command -v setsid 2>/dev/null)" || detach=""
  # The gateway keeps running after the hook exits: give it the account's
  # HOME and installer bin directory, drop the hook's git and locale pins,
  # and lift the hook's soft resource limits back to the hard ones. The
  # lock goes when the start ends.
  (
    ulimit -S -t "$(ulimit -H -t)" 2>/dev/null || true
    ulimit -S -v "$(ulimit -H -v)" 2>/dev/null || true
    ${detach:+"$detach"} env -u GIT_CONFIG_NOSYSTEM -u GIT_CONFIG_GLOBAL -u LC_ALL -u LANG \
      HOME="$home" PATH="${home}/.local/bin:${PATH}" \
      "$bin" start --hook-cold-start
    _dc_cold_start_unlock "$lock" "$token"
  ) </dev/null >/dev/null 2>&1 &
  return 0
}

# _dc_cold_start_lock LOCK TOKEN returns 0 when this hook may launch the
# cold start: it created LOCK, holding the time and TOKEN, or replaced a
# stale one. The start it launches holds LOCK until that start ends
# (_dc_cold_start_unlock), however long its readiness wait. A lock 120 s or
# more old, or dated in the future, is a start that died. Replacing a stale
# lock is serialized by LOCK.break, so of the hooks that find it stale
# together only one launches. It returns 1 while another hook's start runs.
_dc_cold_start_lock() {
  local lock="$1" token="$2" guard="${1}.break" now="" won=1
  now="$(date +%s 2>/dev/null)" || now=""
  case "$now" in ''|*[!0-9]*) return 0 ;; esac
  ( set -C; printf '%s %s\n' "$now" "$token" > "$lock" ) 2>/dev/null && return 0
  _dc_cold_start_lock_stale "$lock" "$now" 120 || return 1
  if ! ( set -C; printf '%s\n' "$now" > "$guard" ) 2>/dev/null; then
    # Another hook is replacing the lock. A guard 5 s old is one whose hook
    # died in that step.
    ! _dc_cold_start_lock_stale "$guard" "$now" 5 || rm -f "${guard:?}"
    return 1
  fi
  if _dc_cold_start_lock_stale "$lock" "$now" 120; then
    rm -f "${lock:?}"
    ( set -C; printf '%s %s\n' "$now" "$token" > "$lock" ) 2>/dev/null && won=0
  fi
  rm -f "${guard:?}"
  return "$won"
}

# _dc_cold_start_lock_stale FILE NOW MAX returns 0 when the lock FILE was
# taken MAX seconds or more before NOW, or after it (a clock set back). A
# FILE without a readable time is stale once its mtime is 2 minutes old: it
# may be one another hook is still writing.
_dc_cold_start_lock_stale() {
  local stamp="" age=0
  [ -f "$1" ] && [ ! -L "$1" ] || return 1
  IFS= read -r -n 64 stamp < "$1" 2>/dev/null || true
  stamp="${stamp%% *}"
  case "$stamp" in
    ''|*[!0-9]*) [ -n "$(find "$1" -prune -mmin +2 2>/dev/null)" ]; return ;;
  esac
  age=$(($2 - stamp))
  [ "$age" -lt 0 ] || [ "$age" -ge "$3" ]
}

# _dc_cold_start_unlock LOCK TOKEN removes LOCK while it is still the one
# this start took.
_dc_cold_start_unlock() {
  local line=""
  [ -f "$1" ] && [ ! -L "$1" ] || return 0
  IFS= read -r -n 128 line < "$1" 2>/dev/null || true
  [ "${line#* }" = "$2" ] || return 0
  rm -f "${1:?}"
}

# _dc_hook_elapsed_ms sets _DC_ELAPSED_MS to the time since the hook
# started (whole seconds under bash 3.2).
_dc_hook_elapsed_ms() {
  local now=""
  if [ -n "${_DC_HOOK_STARTED_US:-}" ]; then
    now="${EPOCHREALTIME:-}"
    now="${now/[.,]/}"
    case "$now" in
      ""|*[!0-9]*) ;;
      *)
        _DC_ELAPSED_MS=$(( (10#$now - 10#$_DC_HOOK_STARTED_US) / 1000 ))
        return 0
        ;;
    esac
  fi
  _DC_ELAPSED_MS=$(( (${SECONDS:-0} - ${_DC_HOOK_STARTED_S:-0}) * 1000 ))
}

# defenseclaw_await_gateway CURL_STATUS POST sends a per-user hook call again
# while this account's gateway restarts or starts (GAP-0094, GAP-0102,
# GAP-0107). CURL_STATUS is the status of the first try; POST is a function
# that sends the same call again and sets RESPONSE. A refused connection
# (curl 7: nobody listens on the port yet) is sent again every 0.2 s until
# 3 s after the hook started, so a restart that is over by then is answered
# by the gateway that comes up, from its policy; the first refusal also starts
# the gateway (defenseclaw_gateway_cold_start). A dropped or cut-off answer
# may have processed the request, so it stays closed and is never retried
# into a later outage status. Returns 0 when RESPONSE holds
# an answer; otherwise the last curl status, and the caller fails as
# unreachable within about 3 s instead of waiting for the restart to end:
# blocked when the fail mode is closed, never allowed then. A timeout (28),
# a gateway stopped with `defenseclaw-gateway stop` (unless an install or
# upgrade, which stops it the same way, is in progress), and managed or
# socket hooks are not sent again.
defenseclaw_await_gateway() {
  local status="${1:-1}" post="${2:-}" launched="" tries=0
  local data="${DEFENSECLAW_HOME:-${DEFENSECLAW_AGENT_HOME:-${HOME}}/.defenseclaw}"
  # The final transport status of the call: 7 (no gateway took the
  # connection) is the one outage a per-user hook may let through
  # (defenseclaw_per_user_outage_open).
  _DC_TRANSPORT_STATUS="$status"
  [ -n "$post" ] || return "$status"
  case "${DEFENSECLAW_MANAGED_HOOK:-0}" in
    1|true|TRUE|yes|YES) return "$status" ;;
  esac
  [ -z "${DEFENSECLAW_HOOK_SOCKET:-}" ] || return "$status"
  while :; do
    _DC_TRANSPORT_STATUS="$status"
    case "$status" in
      0) return 0 ;;
      7) ;;
      *) return "$status" ;;
    esac
    # An operator stop is not a restart: the fail mode applies at once. An
    # install or upgrade stops the gateway the same way and starts it again
    # when it is done (.install.lock), so that one is (GAP-0140).
    [ ! -e "${data}/gateway.stopped" ] || defenseclaw_install_lock_held "$data" || return "$status"
    if [ "$status" = 7 ] && [ -z "$launched" ]; then
      launched=1
      defenseclaw_gateway_cold_start || true
    fi
    _dc_hook_elapsed_ms
    tries=$((tries + 1))
    # The next try must start inside the budget; the try count bounds the
    # wait even if the clock does not move.
    if [ $((_DC_ELAPSED_MS + 200)) -ge 3000 ] || [ "$tries" -gt 15 ]; then
      _DC_GATEWAY_RESTART_WAITED=1
      return "$status"
    fi
    sleep 0.2 2>/dev/null || return "$status"
    status=0
    "$post" || status=$?
  done
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

# defenseclaw_loopback_targets HOST:PORT sets _DC_LOOPBACK_TARGETS to the
# loopback addresses the native helper dials for this configured gateway, in
# its order, and _DC_LOOPBACK_PORT to the port. It returns 1 for anything the
# helper refuses. This is the shell copy of hookexec perUserLoopbackTargets:
# localhost is 127.0.0.1 then ::1, an IPv4-mapped address is its IPv4
# address, and any other spelling of 127.0.0.0/8 or ::1 is itself. Brackets
# are required exactly for IPv6 and the port has no leading zero. Both copies
# are tested against testdata/per_user_loopback_addrs.json. Bash 3.2.
defenseclaw_loopback_targets() {
  local spec="$1" host="" port="" bracketed="" o1="" o2="" o3="" o4=""
  _DC_LOOPBACK_TARGETS=()
  _DC_LOOPBACK_PORT=""
  port="${spec##*:}" host="${spec%:*}"
  [ "$host" != "$spec" ] || return 1
  [[ "$port" =~ ^[1-9][0-9]{0,4}$ ]] && [ "$port" -le 65535 ] || return 1
  case "$host" in
    \[*\]) host="${host#\[}" host="${host%\]}" bracketed=1 ;;
  esac
  case "$host" in ''|*\[*|*\]*) return 1 ;; esac
  case "$host" in
    [Ll][Oo][Cc][Aa][Ll][Hh][Oo][Ss][Tt])
      [ -z "$bracketed" ] || return 1
      _DC_LOOPBACK_TARGETS=(127.0.0.1 ::1)
      ;;
    *:*)
      [ -n "$bracketed" ] || return 1
      defenseclaw_ipv6_loopback "$host" || return 1
      _DC_LOOPBACK_TARGETS=("$_DC_IPV6_LOOPBACK")
      ;;
    *)
      [ -z "$bracketed" ] || return 1
      [[ "$host" =~ ^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$ ]] || return 1
      o1="${BASH_REMATCH[1]}" o2="${BASH_REMATCH[2]}" o3="${BASH_REMATCH[3]}" o4="${BASH_REMATCH[4]}"
      [ "$o1" = 127 ] && [ "$o2" -le 255 ] && [ "$o3" -le 255 ] && [ "$o4" -le 255 ] || return 1
      _DC_LOOPBACK_TARGETS=("$host")
      ;;
  esac
  _DC_LOOPBACK_PORT="$port"
}

# defenseclaw_ipv6_loopback ADDR sets _DC_IPV6_LOOPBACK to ::1 for any
# spelling of the IPv6 loopback, or to the IPv4 address of an IPv4-mapped
# 127.0.0.0/8 address, and returns 1 for every other or malformed address
# (the netip.ParseAddr grammar: 1-4 hex digits per group, at most one ::
# standing for at least one group, an optional final dotted IPv4, no zone).
defenseclaw_ipv6_loopback() {
  local in="$1" head="" tail="" part="" rest="" o1="" o2="" o3="" o4="" n=0 i=0 fill=0
  local -a groups=() tailgroups=()
  _DC_IPV6_LOOPBACK=""
  if [[ "$in" =~ ^(.*:)(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$ ]]; then
    o1="${BASH_REMATCH[2]}" o2="${BASH_REMATCH[3]}" o3="${BASH_REMATCH[4]}" o4="${BASH_REMATCH[5]}"
    [ "$o1" -le 255 ] && [ "$o2" -le 255 ] && [ "$o3" -le 255 ] && [ "$o4" -le 255 ] || return 1
    printf -v in '%s%x:%x' "${BASH_REMATCH[1]}" $((o1 * 256 + o2)) $((o3 * 256 + o4))
  fi
  case "$in" in *::*::*|*:::*) return 1 ;; esac
  head="$in" tail=""
  case "$in" in *::*) head="${in%%::*}" tail="${in#*::}" fill=1 ;; esac
  for rest in "$head" "$tail"; do
    i=$((i + 1))
    [ -n "$rest" ] || continue
    while :; do
      part="${rest%%:*}"
      [[ "$part" =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
      if [ "$i" -eq 1 ]; then
        groups+=($((16#$part)))
      else
        tailgroups+=($((16#$part)))
      fi
      [ "$rest" != "$part" ] || break
      rest="${rest#*:}"
    done
  done
  n=$((${#groups[@]} + ${#tailgroups[@]}))
  if [ "$fill" -eq 1 ]; then
    [ "$n" -le 7 ] || return 1
    while [ "$n" -lt 8 ]; do groups+=(0); n=$((n + 1)); done
  else
    [ "$n" -eq 8 ] || return 1
  fi
  groups+=(${tailgroups[@]+"${tailgroups[@]}"})
  [ "${groups[0]}" = 0 ] && [ "${groups[1]}" = 0 ] && [ "${groups[2]}" = 0 ] &&
    [ "${groups[3]}" = 0 ] && [ "${groups[4]}" = 0 ] || return 1
  if [ "${groups[5]}" = 0 ] && [ "${groups[6]}" = 0 ] && [ "${groups[7]}" = 1 ]; then
    _DC_IPV6_LOOPBACK=::1
    return 0
  fi
  [ "${groups[5]}" = 65535 ] && [ $((groups[6] >> 8)) -eq 127 ] || return 1
  _DC_IPV6_LOOPBACK="127.$((groups[6] & 255)).$((groups[7] >> 8)).$((groups[7] & 255))"
}

# defenseclaw_api_listener_foreign HOST:PORT is the pre-send listener check
# the 1.0.2 and 1.0.3 hook scripts call. An upgrade writes this helper before
# it replaces those scripts, and for that moment an old script called a
# function this helper no longer had (GAP-1532). It answers as the old check
# did: 0 (send nothing) while this account's gateway is stopped and the
# listener on PORT is not proven to be its own. Kept for upgrades from 1.0.2
# and 1.0.3; remove when those upgrade paths are retired.
defenseclaw_api_listener_foreign() {
  defenseclaw_own_gateway_stopped || return 1
  local rc=0
  defenseclaw_api_listener_unproven "${1:-}" || rc=$?
  [ "$rc" = 0 ]
}

# defenseclaw_api_listener_unproven HOST:PORT returns 0 for a foreign or
# unknown listener, 1 for this account's listener, and 2 for a proven free
# port. Hooks call it only for a call that got no answer
# (defenseclaw_gateway_post, defenseclaw_gateway_unreachable_reason), to tell
# a cold start from a foreign listener; before a send, the native helper's
# proof of the connected peer decides (GAP-1453). It never allows a send.
# Linux reads this namespace's procfs socket tables;
# macOS lsof lists this account's listeners. Managed hooks use their separate
# verified transport. The endpoints checked are the ones the native helper
# dials, in its order (defenseclaw_loopback_targets): the first one with a
# listener decides, because the helper stops at the first that accepts.
defenseclaw_api_listener_unproven() {
  case "${DEFENSECLAW_MANAGED_HOOK:-0}" in
    1|true|TRUE|yes|YES) return 1 ;;
  esac
  [ -z "${DEFENSECLAW_HOOK_SOCKET:-}" ] || return 1
  # The second and third arguments (tests only) replace /proc/net and lsof.
  local net="${2:-/proc/net}" lsof="${3:-/usr/sbin/lsof}" uid="${EUID:-}" target="" status=2
  [ -n "$uid" ] || return 0
  if ! defenseclaw_loopback_targets "$1"; then
    # A numeric port no listener can hold (0, above 65535, a leading zero)
    # on a valid loopback address is free, as it always was; the helper is
    # never asked to send. Any other refused address is unproven.
    case "${1##*:}" in ''|*[!0-9]*) return 0 ;; esac
    defenseclaw_loopback_targets "${1%:*}:1" && return 2
    return 0
  fi
  # ProcSubset=pid can hide /proc/net, while /proc/self/net still exposes
  # this process's network namespace. The second argument mirrors that
  # layout in tests.
  if [ ! -r "${net}/tcp" ] && [ "${net##*/}" = net ]; then
    net="${net%/net}/self/net"
  fi
  if [ -r "${net}/tcp" ]; then
    for target in "${_DC_LOOPBACK_TARGETS[@]}"; do
      status=0
      defenseclaw_procfs_listener_status "$target" "$_DC_LOOPBACK_PORT" "$net" "$uid" || status=$?
      [ "$status" = 2 ] || return "$status"
    done
    # No listener: the caller may cold-start this account's gateway, then
    # retry ownership proof before it sends. Never send on this status.
    return 2
  fi
  if [ -x "$lsof" ]; then
    # A socket this account owns on another address is not proof for the
    # configured destination. Require the exact local address in lsof.
    for target in "${_DC_LOOPBACK_TARGETS[@]}"; do
      case "$target" in
        *:*)
          "$lsof" -nP -a -u "$uid" -iTCP@"[$target]":"$_DC_LOOPBACK_PORT" -sTCP:LISTEN -t >/dev/null 2>&1 && return 1
          ;;
        *)
          "$lsof" -nP -a -u "$uid" -iTCP@"$target":"$_DC_LOOPBACK_PORT" -sTCP:LISTEN -t >/dev/null 2>&1 && return 1
          ;;
      esac
      (exec 3<>"/dev/tcp/${target}/${_DC_LOOPBACK_PORT}") 2>/dev/null && return 0
    done
    return 2
  fi
  return 0
}

# defenseclaw_gateway_unreachable_reason prints the reason a hook gives for a
# gateway request that got no answer. A per-user hook names another
# account's listener on this account's port, which a start cannot fix; it
# reads the socket tables only on this failure path (GAP-1453).
defenseclaw_gateway_unreachable_reason() {
  case "${DEFENSECLAW_MANAGED_HOOK:-0}" in
    1|true|TRUE|yes|YES) printf '%s' 'gateway unreachable'; return 0 ;;
  esac
  if [ -z "${DEFENSECLAW_HOOK_SOCKET:-}" ] && [ -n "${API_ADDR:-}" ] &&
     defenseclaw_api_listener_unproven "$API_ADDR"; then
    printf '%s' "${API_ADDR} is not proven to be this account's gateway; no token or payload was sent to it. Another account may hold the port. Run \`defenseclaw setup gateway --api-port <free-port>\` to choose a free port"
    return 0
  fi
  printf '%s' 'gateway unreachable'
  return 0
}

# defenseclaw_read_socket_table FILE puts FILE's lines in _DC_SOCKET_ROWS
# with one sequential read. The read builtin seeks back after every line it
# takes from a seekable file, and procfs rebuilds a socket table from the
# start on each such seek, so a line-by-line loop cost O(rows^2) per hook
# call; at 10 Hz the TIME_WAIT rows piled up until hooks timed out
# (GAP-1453). Linux always has Bash 4 mapfile (one lseek at the end); Bash
# 3.2 (macOS, which uses lsof, and its fixture tests) reads the file through
# one command substitution instead.
defenseclaw_read_socket_table() {
  local data="" IFS=$'\n' noglob=0
  _DC_SOCKET_ROWS=()
  if [ "${BASH_VERSINFO[0]:-0}" -ge 4 ]; then
    mapfile -t _DC_SOCKET_ROWS < "$1" 2>/dev/null
    return
  fi
  data="$(< "$1")" 2>/dev/null || return 1
  case "$-" in *f*) noglob=1 ;; esac
  set -f
  _DC_SOCKET_ROWS=($data)
  [ "$noglob" = 1 ] || set +f
  return 0
}

# defenseclaw_read_listen_rows FILE puts the LISTEN (0A) rows of FILE in
# _DC_SOCKET_ROWS. grep reads the table once and keeps the few listening rows,
# so a host with hundreds of thousands of TIME_WAIT rows is not walked row by
# row in Bash, which missed the 3 s budget (GAP-1756). Without grep the
# whole table is read (defenseclaw_read_socket_table).
defenseclaw_read_listen_rows() {
  local data="" IFS=$'\n' noglob=0
  if ! command -v grep >/dev/null 2>&1; then
    defenseclaw_read_socket_table "$1"
    return
  fi
  _DC_SOCKET_ROWS=()
  [ -r "$1" ] || return 1
  data="$(LC_ALL=C grep -F ' 0A ' "$1" 2>/dev/null)" || [ -z "$data" ] || return 1
  case "$-" in *f*) noglob=1 ;; esac
  set -f
  _DC_SOCKET_ROWS=($data)
  [ "$noglob" = 1 ] || set +f
  return 0
}

# defenseclaw_procfs_listener_status ADDR PORT NET UID classifies the
# listeners that can serve one normalised loopback endpoint (127.0.0.0/8 or
# ::1) in NET's tcp and tcp6 tables, with the return codes of
# defenseclaw_api_listener_unproven. A same-port listener on another
# loopback address cannot serve it; an exact binding supersedes a wildcard.
defenseclaw_procfs_listener_status() {
  local target="$1" port="$2" net="$3" uid="$4" hex="" exact="" mapped="" table="" o2="" o3="" o4=""
  local owner="" own="" v6_owner="" v6_own="" exact_owner="" exact_own=""
  local row="" addr="" st="" u="" IFS=$' \t\n'
  local -a fields=()
  printf -v hex '%04X' "$port"
  case "$target" in
    ::1) exact="00000000000000000000000001000000" ;;
    127.*)
      o2="${target#*.}" o4="${o2##*.}" o3="${o2%.*}" o2="${o2%%.*}" o3="${o3#*.}"
      printf -v exact '7F%02X%02X%02X' "$o2" "$o3" "$o4"
      exact="${exact:6:2}${exact:4:2}${exact:2:2}${exact:0:2}"
      mapped="0000000000000000FFFF0000${exact}"
      ;;
    *) return 0 ;;
  esac
  for table in "${net}/tcp" "${net}/tcp6"; do
    [ -r "$table" ] || continue
    defenseclaw_read_listen_rows "$table" || continue
    # Bash 3.2 (macOS) treats "${a[@]}" of an empty array as unbound under
    # set -u, and a table with no LISTEN row leaves none (GAP-2273).
    for row in ${_DC_SOCKET_ROWS[@]+"${_DC_SOCKET_ROWS[@]}"}; do
      # The state column is the only " 0A " (LISTEN) a row can hold; skip
      # the TIME_WAIT and connected rows before splitting. procfs rows have
      # no glob characters, so the unquoted split cannot expand a pattern.
      case "$row" in *" 0A "*) ;; *) continue ;; esac
      case "$row" in *[\*?[]*) continue ;; esac
      fields=($row)
      addr="${fields[1]:-}" st="${fields[3]:-}" u="${fields[7]:-}"
      [ "$st" = "0A" ] || continue
      case "$addr" in
        "$exact":"$hex"|"${mapped:-$exact}":"$hex")
          if [ "$u" = "$uid" ]; then exact_own=1; else exact_owner="$u"; fi
          ;;
        # An exact binding supersedes a wildcard on this address.
        00000000:"$hex")
          [ -n "$mapped" ] || continue
          if [ "$u" = "$uid" ]; then own=1; else owner="$u"; fi
          ;;
        # tcp6 does not report IPV6_V6ONLY. Keep these rows separate: an
        # IPv6-only wildcard can coexist with an IPv4 wildcard.
        00000000000000000000000000000000:"$hex")
          if [ "$u" = "$uid" ]; then v6_own=1; else v6_owner="$u"; fi
          ;;
        *) continue ;;
      esac
    done
  done
  [ -n "$exact_owner" ] && return 0
  [ -n "$exact_own" ] && return 1
  [ -n "$owner" ] && return 0
  [ -n "$own" ] && return 1
  if [ -n "$v6_owner$v6_own" ]; then
    # An IPv6 wildcard always serves ::1. For IPv4, a no-payload connect
    # distinguishes a dual-stack wildcard from an IPv6-only one. The native
    # helper still proves the held peer before sending the bearer or body.
    if [ -n "$mapped" ]; then
      (exec 3<>"/dev/tcp/${target}/${port}") 2>/dev/null || return 2
    fi
    [ -n "$v6_owner" ] && return 0
    return 1
  fi
  return 2
}

defenseclaw_response_failure_reason() {
  # A standalone gateway refuses an account its enumerator has not enrolled
  # yet: say so instead of "HTTP 403" (GAP-0738). RESULT is the body.
  if [ -n "${DEFENSECLAW_HOOK_SOCKET:-}" ]; then
    case "$1|${RESULT:-}" in
      *"HTTP 403"*"|"*enterprise_managed_uid_unregistered*)
        printf '%s' 'this account is not enrolled in DefenseClaw on this computer yet. DefenseClaw enrolls a new account within about five minutes of its first sign-in, so try again then; if this continues, the policy may exclude this account, so ask your administrator (enterprise_managed_uid_unregistered)'
        return 0
        ;;
      *"HTTP 403"*"|"*enterprise_managed_root_denied*)
        # Not token drift: the policy refuses root (GAP-0556).
        printf '%s' 'your organization does not allow agents to run as root on this computer. Run the agent from your own account. (enterprise_managed_root_denied)'
        return 0
        ;;
    esac
  fi
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

# defenseclaw_gateway_error_answer REASON prints, for a block of a call the
# gateway answered with a server error (REASON "gateway returned HTTP 5xx"),
# what it said: "HTTP 503: <its error>". The gateway is up, so the block
# must not read as an outage (GAP-1744: a Codex start refused for its runtime
# registration). It prints nothing for any other reason.
defenseclaw_gateway_error_answer() {
  local code="" detail=""
  case "${1:-}" in
    "gateway returned HTTP 5"[0-9][0-9]) code="${1#gateway returned }" ;;
    *) return 1 ;;
  esac
  detail="$(defenseclaw_json_string_field "${RESULT:-}" error 2>/dev/null)" || detail=""
  detail="${detail//[[:cntrl:]]/ }"
  detail="${detail:0:200}"
  if [ -n "$detail" ]; then
    printf '%s: %s' "$code" "$detail"
  else
    printf '%s' "$code"
  fi
}

# defenseclaw_gateway_error_block_text REASON prints the block text for a
# call the gateway answered with a server error (see
# defenseclaw_gateway_error_answer). When the gateway's error names the step
# that repairs it ("...; run: defenseclaw setup codex --yes") that step is
# the next step; otherwise doctor is.
defenseclaw_gateway_error_block_text() {
  local answer=""
  answer="$(defenseclaw_gateway_error_answer "${1:-}")" || return 1
  case "$answer" in
    *"run: defenseclaw "*) printf 'DefenseClaw blocked this because its gateway answered with an error (%s).' "$answer" ;;
    *) printf 'DefenseClaw blocked this because its gateway answered with an error (%s). Run defenseclaw doctor to see what to fix.' "$answer" ;;
  esac
}

# defenseclaw_should_fail_closed_on_unreachable returns 0 (true) when the
# connector's effective fail mode is closed or when strict availability is
# enabled. A guardian-installed managed hook's FAIL_MODE is the one the
# administrator's config resolved, baked at render time (owner decision
# 2026-10-20; under Secure Client #1163), and never DEFENSECLAW_FAIL_MODE.
# Managed standalone hooks still close malformed and error responses; the
# administrator's open choice applies only to an outage.
defenseclaw_should_fail_closed_on_unreachable() {
  # An install that started since the hook selected its mode closes it.
  defenseclaw_close_during_install
  # A per-user hook bakes closed for every failure (an older script's baked
  # open included); only an outage its current config opens lets the call
  # through (defenseclaw_per_user_outage_open).
  if [ "${DEFENSECLAW_MANAGED_HOOK:-0}" != 1 ]; then
    if defenseclaw_per_user_outage_open; then
      return 1
    fi
    return 0
  fi
  # Only an explicit open opens: an unset, empty or unknown FAIL_MODE closes.
  case "${FAIL_MODE:-}" in
    open) ;;
    *) return 0 ;;
  esac
  # An install or upgrade of this account's DefenseClaw (.install.lock) stops
  # its gateway and starts it again when it is done. That window is not an
  # outage, so a per-user hook does not let the call through unchecked
  # (GAP-0649). Managed and socket hooks keep the administrator's mode.
  case "${DEFENSECLAW_MANAGED_HOOK:-0}" in
    1|true|TRUE|yes|YES) ;;
    *) [ -n "${DEFENSECLAW_HOOK_SOCKET:-}" ] ||
      ! defenseclaw_install_lock_held "${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}" || return 0 ;;
  esac
  case "${DEFENSECLAW_STRICT_AVAILABILITY:-0}" in
    1|true|TRUE|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

# defenseclaw_should_fail_closed_on_missing_token is
# defenseclaw_should_fail_closed_on_unreachable for a missing gateway token,
# except that a guardian-installed managed hook outside an authenticated
# Secure Client deployment (_DC_SECURE_CLIENT_DELIVERY) always fails closed:
# its token is installer state, so a missing one is a broken or altered
# install, not an outage.
defenseclaw_should_fail_closed_on_missing_token() {
  case "${DEFENSECLAW_MANAGED_HOOK:-0}" in
    1|true|TRUE|yes|YES) [ "${_DC_SECURE_CLIENT_DELIVERY:-0}" = 1 ] || return 0 ;;
  esac
  defenseclaw_should_fail_closed_on_unreachable
}

# defenseclaw_failed_stop_event CONNECTOR EVENT [PAYLOAD] returns 0 (true)
# for a stop or session-end event, the exact set of the native hook runner
# (hookexec.NeutralLifecycleEvent in lifecycle.go). Failing such an event
# closed denies nothing: it keeps the agent running (Codex, Claude Code,
# Devin and Copilot continue the turn when a stop hook blocks, Cursor submits
# the block as the next prompt), every later turn fails closed and stops
# again, and the agent loops on model turns until DefenseClaw is back
# (#1140). EVENT is the event the registered command binds (Codex,
# Copilot). When it is empty the event comes from the payload's
# hook_event_name (or event); a payload that is not one JSON object, whose
# event fields are not strings (_dc_hook_event_field) or disagree, names no
# event. The Secure Client profile keeps its results. On success the event
# is left in _DC_FAILED_STOP_EVENT.
defenseclaw_failed_stop_event() {
  local connector="${1:-}" event="${2:-}" payload="${3:-}" named="" other="" stop=0
  _DC_FAILED_STOP_EVENT=""
  [ "${_DC_SECURE_CLIENT_HOOK:-0}" != "1" ] || return 1
  if [ -z "$event" ]; then
    [ -n "$payload" ] || return 1
    named="$(_dc_hook_event_field "$payload" hook_event_name)" || return 1
    other="$(_dc_hook_event_field "$payload" event)" || return 1
    if [ -n "$named" ] && [ -n "$other" ] && [ "$named" != "$other" ]; then
      return 1
    fi
    event="${named:-$other}"
  fi
  case "${connector}:${event}" in
    claudecode:Stop|claudecode:SubagentStop|claudecode:TeammateIdle|claudecode:StopFailure|claudecode:SessionEnd) stop=1 ;;
    codex:Stop|codex:SubagentStop|codex:SessionEnd) stop=1 ;;
    copilot:agentStop|copilot:subagentStop|copilot:sessionEnd|copilot:Stop|copilot:SubagentStop) stop=1 ;;
    devin:Stop|devin:SessionEnd) stop=1 ;;
    kiro:Stop) stop=1 ;;
    cursor:[Ss][Tt][Oo][Pp]|cursor:[Ss][Uu][Bb][Aa][Gg][Ee][Nn][Tt][Ss][Tt][Oo][Pp]|cursor:[Ss][Ee][Ss][Ss][Ii][Oo][Nn][Ee][Nn][Dd]) stop=1 ;;
  esac
  [ "$stop" = "1" ] || return 1
  _DC_FAILED_STOP_EVENT="$event"
  return 0
}

# _dc_hook_event_field PAYLOAD FIELD prints the string value of the payload's
# top-level FIELD (hook_event_name or event), or nothing when FIELD is absent
# or null. It fails when the payload is not exactly one JSON object or FIELD
# holds anything but a string, as the native runner's resolveHookEvent does
# (it decodes both event fields as strings): jq's `// empty` would turn a
# false value into an absent field.
_dc_hook_event_field() {
  local payload="${1:-}" field="${2:-}"
  case "$field" in
    hook_event_name|event|session_id|sessionID|sessionId|thread_id|source_event_id|tool_call_id|callID) ;;
    *) return 1 ;;
  esac
  if command -v jq >/dev/null 2>&1; then
    printf '%s' "$payload" | jq -rs --arg f "$field" '
      if length != 1 or (.[0] | type) != "object" then error("not one JSON object") else .[0][$f] end
      | if . == null then empty elif type == "string" then . else error("not a string") end' 2>/dev/null
    return
  fi
  if _dc_python3_usable; then
    printf '%s' "$payload" | DCEV_FIELD="$field" python3 -c '
import json,os,sys
try:
  d=json.loads(sys.stdin.read())
except Exception:
  sys.exit(1)
if not isinstance(d,dict):
  sys.exit(1)
v=d.get(os.environ["DCEV_FIELD"])
if v is None:
  sys.exit(0)
if not isinstance(v,str):
  sys.exit(1)
sys.stdout.write(v+"\n")' 2>/dev/null
    return
  fi
  # Last resort (no jq, no python3): the string scanner fails on a value that
  # is not a string, a repeated field or text after the object.
  local value="" status=0
  value="$(defenseclaw_json_string_field "$payload" "$field" strict)" || status=$?
  case "$status" in
    0) printf '%s\n' "$value" ;;
    1) ;;
    *) return 1 ;;
  esac
}

# defenseclaw_allow_failed_stop_event CONNECTOR HOOK_NAME EVENT PAYLOAD
# REASON CATEGORY is called on a path that is about to fail closed. For a
# stop or session-end event (defenseclaw_failed_stop_event) it answers the
# connector's neutral allow (Cursor's is {}) and exits 0; the failure is
# still logged, as fail mode open, like the native hook runner
# (allowFailClosedStop). For any other event it returns 0 and the caller
# fails closed as before.
defenseclaw_allow_failed_stop_event() {
  local connector="${1:-unknown}" hook_name="${2:-unknown}" event="${3:-}" payload="${4:-}"
  local reason="${5:-unknown}" category="${6:-transport}"
  defenseclaw_failed_stop_event "$connector" "$event" "$payload" || return 0
  # The record carries the fail_open outcome; the generic fail-open warning is
  # left out because the line below explains the allow (logDeliberateAllow).
  defenseclaw_log_hook_failure "$connector" "$hook_name" "$reason" "$category" open fail_open 2>/dev/null
  echo "DefenseClaw is not blocking the ${_DC_FAILED_STOP_EVENT:-stop} event, because a block there would keep the agent running; prompts and tool calls stay blocked until DefenseClaw is available. (${reason})" >&2
  [ "$connector" != "cursor" ] || printf '{}\n'
  exit 0
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
    # The gateway is up and answered with a server error: the line names its
    # answer, not an outage or a fail mode (GAP-1744).
    local answer=""
    if answer="$(defenseclaw_gateway_error_answer "$reason")"; then
      echo "defenseclaw: blocking ${subject}: the gateway answered with an error (${answer})" >&2
      return 0
    fi
    echo "defenseclaw: gateway unreachable, blocking ${subject} ($(defenseclaw_unreachable_mode_note)): ${reason}" >&2
  elif defenseclaw_per_user_outage_open; then
    # The Claude Code and Codex hooks show their systemMessage instead; the
    # generic inspect hooks rendered for them print none, so they keep this
    # line (GAP-1757). The once-per-session marker is taken only by a call
    # that shows the warning: a call that prints nothing here (a Codex
    # prompt, a Claude Code PostToolUse or Stop) leaves it for the next call
    # that does (GAP-1352).
    case "${DEFENSECLAW_HOOK_CONNECTOR:-}|${subject}" in
      "claudecode|claude-code "*|"codex|codex "*) : ;;
      *)
        if defenseclaw_first_outage_warning; then
          echo "defenseclaw: gateway unreachable, allowing ${subject} unchecked (fail mode open for an outage): ${reason}. If it does not start, run \`defenseclaw doctor\`." >&2
        fi
        ;;
    esac
  else
    echo "defenseclaw: gateway unreachable, allowing ${subject}: ${reason}" >&2
  fi
}

# defenseclaw_unreachable_mode_note names why a call the gateway did not
# decide was blocked, as the native hook line does (unreachableModeNote,
# GAP-1735): "fail mode closed" for a gateway outage the mode closed (no
# gateway took the connection, curl 7), strict availability, the install
# window, and managed, socket and Secure Client hooks; for a per-user call the
# gateway took and did not answer (a timeout, a dropped or cut-off answer),
# that it is not an outage and is blocked in every fail mode, so a saved open
# mode does not read as ignored (GAP-2279).
defenseclaw_unreachable_mode_note() {
  local closed='fail mode closed'
  case "${DEFENSECLAW_MANAGED_HOOK:-0}" in
    1|true|TRUE|yes|YES) printf '%s' "$closed"; return 0 ;;
  esac
  case "${DEFENSECLAW_STRICT_AVAILABILITY:-0}" in
    1|true|TRUE|yes|YES) printf '%s' "$closed"; return 0 ;;
  esac
  # A refused connection (7) is an outage. Any other failure while this
  # account's own gateway process is alive (a timeout, a dropped answer) is
  # a call the gateway took and did not answer; with no live gateway it
  # stays an outage the mode closed.
  if [ "${_DC_TRANSPORT_STATUS:-}" = 7 ] || [ -n "${DEFENSECLAW_HOOK_SOCKET:-}" ] ||
    [ "${_DC_SECURE_CLIENT_HOOK:-0}" = 1 ] || defenseclaw_install_held ||
    ! defenseclaw_own_gateway_alive; then
    printf '%s' "$closed"
    return 0
  fi
  printf '%s' 'not a gateway outage, so it is blocked in every fail mode'
}

# defenseclaw_unreachable_notice_json prints a one-line hook result whose
# systemMessage tells the user that DefenseClaw is not checking this session
# and how to resume, when this account's own per-user gateway is down. A
# fail-open hook exits 0, and Claude Code and Codex do not show stderr then:
# the systemMessage is the only text the user sees. It prints nothing when
# the gateway is not this account's to start (managed or socket hooks).
# Each per-user notice also names `defenseclaw-gateway status` (GAP-0093).
defenseclaw_unreachable_notice_json() {
  local next="" text=""
  next="$(defenseclaw_unreachable_next_step)"
  [ -n "$next" ] || return 0
  local data="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
  # During an install (.install.lock) a per-user hook fails closed
  # (defenseclaw_should_fail_closed_on_unreachable), so no notice names it.
  if [ -e "${data}/gateway.stopped" ]; then
    text='DefenseClaw is not checking this session: the gateway was stopped with `defenseclaw-gateway stop`. Run `defenseclaw-gateway start` to resume protection. `defenseclaw-gateway status` shows its state.'
  elif [ -n "${_DC_GATEWAY_RESTART_WAITED:-}" ] && ! defenseclaw_own_config_invalid; then
    text='DefenseClaw is not checking this session: this account'"'"'s gateway is restarting or not running (no answer within 3 seconds). Run `defenseclaw-gateway start` to resume protection. `defenseclaw-gateway status` shows its state.'
  elif defenseclaw_own_gateway_alive; then
    text='DefenseClaw is not checking this session: the gateway is running but did not answer. Run `defenseclaw-gateway restart` to resume protection. `defenseclaw-gateway status` shows its state.'
  elif defenseclaw_own_config_invalid; then
    text='DefenseClaw is not checking this session: the gateway could not start because config.yaml does not load. Run `defenseclaw config validate`, fix the file, then run `defenseclaw-gateway start`.'
  else
    text='DefenseClaw is not checking this session: this account'"'"'s gateway is not running. Run `defenseclaw-gateway start` to resume protection. `defenseclaw-gateway status` shows its state.'
  fi
  # A per-user outage the hook lets through also names the repair command.
  if defenseclaw_per_user_outage_open; then
    defenseclaw_first_outage_warning || return 0
    text="${text} If it does not start, run \`defenseclaw doctor\`."
  fi
  printf '{"systemMessage":"%s"}\n' "$(defenseclaw_json_escape "$text")"
}

# Reserve an advisory warning marker for this session. Missing session IDs or
# unwritable marker storage leave the warning visible. The marker never picks
# a helper, changes the mode, or changes the verdict.
defenseclaw_first_outage_warning() {
  case "$_DC_OUTAGE_WARNING_THIS_CALL" in
    1) return 0 ;;
    0) return 1 ;;
  esac
  local session="" digest="" dir="${HOOK_DIR:-}/.outage-warnings"
  session="$(_dc_hook_event_field "${PAYLOAD:-${CONTENT:-}}" session_id 2>/dev/null)" || session=""
  [ -n "$session" ] || session="$(_dc_hook_event_field "${PAYLOAD:-${CONTENT:-}}" sessionID 2>/dev/null)" || session=""
  [ -n "$session" ] || session="$(_dc_hook_event_field "${PAYLOAD:-${CONTENT:-}}" sessionId 2>/dev/null)" || session=""
  [ -n "$session" ] || session="$(_dc_hook_event_field "${PAYLOAD:-${CONTENT:-}}" thread_id 2>/dev/null)" || session=""
  if [ -z "$session" ]; then
    _DC_OUTAGE_WARNING_THIS_CALL=1
    return 0
  fi
  session="${session:0:256}"
  if command -v sha256sum >/dev/null 2>&1; then
    digest="$(printf '%s' "$session" | sha256sum)" || digest=""
  elif command -v shasum >/dev/null 2>&1; then
    digest="$(printf '%s' "$session" | shasum -a 256)" || digest=""
  fi
  digest="${digest%% *}"
  case "$digest" in
    ""|*[!a-fA-F0-9]*) _DC_OUTAGE_WARNING_THIS_CALL=1; return 0 ;;
  esac
  if ! mkdir -p -m 700 "$dir" 2>/dev/null; then
    _DC_OUTAGE_WARNING_THIS_CALL=1
    return 0
  fi
  if (set -C; : > "$dir/$digest") 2>/dev/null; then
    # One in 256 new sessions prunes old advisory markers. Repeated calls
    # never scan, and pruning cannot change the verdict.
    case "$digest" in
      00*) find "$dir" -type f -mtime +7 -delete >/dev/null 2>&1 || : ;;
    esac
    _DC_OUTAGE_WARNING_THIS_CALL=1
    return 0
  fi
  _DC_OUTAGE_WARNING_THIS_CALL=0
  return 1
}

# defenseclaw_unreachable_next_step prints the next step for a per-user
# account whose own gateway is down: after `defenseclaw-gateway stop` the
# hooks deliberately do not start it again, so say how to resume, and name
# `defenseclaw-gateway status` (GAP-0090, GAP-0093). Managed hooks print
# nothing (their service is not the user's to start).
defenseclaw_unreachable_next_step() {
  # The hook already proved the socket existed before sending. A later
  # connection failure cannot prove the gateway is stopped: its identity and
  # answer remain unverified, even if the administrator chose open for a
  # verified absence (GAP-0518).
  if [ -n "${DEFENSECLAW_HOOK_SOCKET:-}" ]; then
    printf '%s' 'the DefenseClaw hook socket did not provide a verified gateway answer; ask your administrator to inspect the gateway service and socket. (enterprise_managed_gateway_peer_unverified)'
    return 0
  fi
  case "${DEFENSECLAW_MANAGED_HOOK:-0}" in
    1|true|TRUE|yes|YES) return 0 ;;
  esac
  [ -z "${DEFENSECLAW_HOOK_SOCKET:-}" ] || return 0
  local data="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
  if defenseclaw_install_lock_held "$data"; then
    printf '%s' 'DefenseClaw is being installed or upgraded for this account and its gateway starts again when that is done; try again in a moment, or run the installer again if it has stopped (`defenseclaw-gateway status` shows its state)'
  elif [ -e "${data}/gateway.stopped" ]; then
    printf '%s' 'the gateway was stopped with `defenseclaw-gateway stop`; run `defenseclaw-gateway start` to resume protection (`defenseclaw-gateway status` shows its state)'
  elif defenseclaw_own_gateway_stopped && defenseclaw_own_config_invalid; then
    printf '%s' 'the gateway could not start because config.yaml does not load; run `defenseclaw config validate`, fix the file, then run `defenseclaw-gateway start`'
  elif [ -n "${_DC_GATEWAY_RESTART_WAITED:-}" ]; then
    printf '%s' 'this account'"'"'s gateway is restarting or not running (no answer within 3 seconds); try again in a moment, or run `defenseclaw-gateway start` (`defenseclaw-gateway status` shows its state)'
  elif defenseclaw_own_gateway_stopped; then
    printf '%s' 'this account'"'"'s gateway is not running; run `defenseclaw-gateway start` (`defenseclaw-gateway status` shows its state)'
  elif defenseclaw_own_gateway_alive; then
    # A frozen or hung gateway keeps its listener: the request timed out.
    printf '%s' 'the gateway is running but did not answer; check `defenseclaw-gateway status`, or run `defenseclaw-gateway restart`'
  fi
}

# defenseclaw_own_config_invalid returns 0 when the last hook start of this
# account's gateway failed because config.yaml does not load and the file has
# not changed since. A start cannot help then, so the hook names the file
# instead (GAP-0409). defenseclaw-gateway start writes the marker.
defenseclaw_own_config_invalid() {
  local data="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}" marker="" line="" n=0
  marker="${data}/gateway.cold-start-failed"
  [ -f "$marker" ] && [ ! -L "$marker" ] || return 1
  [ "$marker" -nt "${data}/config.yaml" ] || return 1
  while [ "$n" -lt 4 ] && IFS= read -r -n 256 line; do
    [ "$line" = "config-invalid" ] && return 0
    n=$((n + 1))
  done < "$marker"
  return 1
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
#   defenseclaw_handle_missing_token CONNECTOR HOOK_NAME SUBJECT [TOKEN_FILE [EVENT PAYLOAD]]
#
# TOKEN_FILE is the token file the hook looked for; the message names it so
# the user can find it (GAP-1425). EVENT and PAYLOAD, when the hook already
# knows them, let a stop event through (defenseclaw_allow_failed_stop_event).
#
# Exits 0 for fail-open or 2 for fail-closed. Never returns to the caller.
defenseclaw_handle_missing_token() {
  local connector="${1:-unknown}"
  local hook_name="${2:-unknown}"
  local subject="${3:-tool}"
  local token_file="${4:-}"
  local reason="missing gateway token file"
  [ -z "$token_file" ] || reason="missing gateway token: ${token_file} not found"
  if defenseclaw_should_fail_closed_on_missing_token; then
    defenseclaw_allow_failed_stop_event "$connector" "$hook_name" "${5:-}" "${6:-}" "$reason" transport
  fi
  if defenseclaw_should_fail_closed_on_missing_token; then
    defenseclaw_log_hook_failure "$connector" "$hook_name" "$reason" transport "${FAIL_MODE:-closed}" fail_closed
  else
    defenseclaw_log_hook_delivery_failure "$connector" "$hook_name" "$reason" transport "${FAIL_MODE:-closed}"
  fi
  if defenseclaw_should_fail_closed_on_missing_token; then
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
  if [ "$setup_name" = "inspect" ]; then
    printf '%s' '; this shared inspect hook is retired; run `defenseclaw doctor` to identify the active connector and repair its hook'
    return 0
  fi
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
# A body with a NUL byte is refused the same way. A bash variable cannot hold
# NUL: command substitution drops it without a word, so the body would reach
# the gateway altered, and a length check made after the drop undercounts (a
# NUL-padded body over the cap passed as a shorter one, and the bytes past the
# cap were never inspected). JSON carries NUL only escaped (\u0000), so no
# real connector payload has one.
#
# How it reads: bash's `read -r -d '' -n cap+1` takes at most cap+1 bytes
# (a producer streaming 1GB is cut off) with every byte but NUL intact
# (trailing newlines too), and it stops at a NUL, so both checks see the raw
# bytes. It reads a pipe one byte at a time (about 0.2 s per MiB on Linux,
# 0.3 s on macOS bash 3.2) and starts no program: no head(1) or python3
# (issue #1130 / GAP-0267).
#
# Usage:
#   PAYLOAD="$(defenseclaw_read_stdin_capped fail_closed)" || exit 2
#
# Returns 0 with the body on stdout. Returns 3 (overflow, with the first cap
# bytes on stdout) or 4 (NUL, empty stdout).
defenseclaw_read_stdin_capped() {
  # The caller passes the outcome its oversized-payload branch applies
  # (fail_open or fail_closed); an older caller without one logs unknown.
  local overflow_outcome="${1:-unknown}"
  local cap="${DEFENSECLAW_HOOK_MAX_BODY:-1048576}"
  case "$cap" in
    ''|*[!0-9]*) cap=1048576 ;;
  esac
  # bash reads at most cap+1 bytes itself: no head(1) or python3 process on
  # any host (issue #1130 / GAP-0267), and the read stays bounded when
  # neither is installed.
  _dc_read_stdin_exact "$cap" "$overflow_outcome"
}

# _dc_read_stdin_exact prints stdin unchanged, or refuses it (returns 4 for
# NUL, 3 for overflow, and prints nothing). LC_ALL=C makes
# ${#body} a byte count. See defenseclaw_read_stdin_capped.
_dc_read_stdin_exact() {
  local cap="$1" outcome="$2" body="" LC_ALL=C
  # -n cap+1 bounds the read (a producer streaming 1GB is cut off after
  # cap+1 bytes). read returns 0 when it stopped at a NUL or took all cap+1
  # bytes, and non-zero at the end of input.
  if IFS= read -r -d '' -n "$((cap + 1))" body && [ "${#body}" -le "$cap" ]; then
    _dc_stdin_refused "$cap" nul "$outcome"
    return 4
  fi
  if [ "${#body}" -gt "$cap" ]; then
    _dc_stdin_refused "$cap" overflow "$outcome"
    printf '%s' "${body:0:cap}"
    return 3
  fi
  _dc_stdin_over_transport "$body" "$outcome" && return 3
  printf '%s' "$body"
}

# The per-user transport (defenseclaw-hook-post, hookexec perUserHookMaxBody)
# sends at most 900 KiB, under the gateway's 1 MiB request cap. A body
# between that and the read cap passed the read, reached the helper whole and
# was refused there after the read, so a benign 0.9-1 MiB call (a long Bash
# heredoc, a large Write) failed closed as "the gateway is running but did
# not answer" with no gateway row, even in the balanced default (GAP-2279,
# GAP-2284). In the tier that reviews an oversized call from its prefix, the
# shell hook now treats such a body as oversized at the transport's cap, as
# the OpenCode and Amp plugins already do (900 KiB): it prints the body's
# first 900 KiB and returns 0 for the caller's overflow branch (rc 3), which
# sends the bounded prefix review for the gateway's usual verdict. Every
# other tier keeps its read cap and path unchanged.
_dc_stdin_over_transport() {
  local body="$1" outcome="$2" LC_ALL=C transport_cap=921600
  [ "${#body}" -gt "$transport_cap" ] || return 1
  [ -n "${DEFENSECLAW_AGENT_HOME:-}" ] &&
    [ -x "${DEFENSECLAW_AGENT_HOME}/.local/bin/defenseclaw-hook-post" ] || return 1
  defenseclaw_per_user_oversize_open || return 1
  _dc_stdin_refused "$transport_cap" overflow "$outcome"
  printf '%s' "${body:0:transport_cap}"
  return 0
}

# _dc_stdin_refused logs and reports a body defenseclaw_read_stdin_capped
# refused: $2 is overflow or nul, $3 the caller's delivery outcome.
_dc_stdin_refused() {
  local connector="${DEFENSECLAW_HOOK_CONNECTOR:-unknown}"
  local hook_name="${DEFENSECLAW_HOOK_NAME:-unknown}"
  if [ "$2" = nul ]; then
    defenseclaw_log_hook_failure "$connector" "$hook_name" \
      "stdin body has a NUL byte" transport "${FAIL_MODE:-closed}" "$3"
    echo "defenseclaw: hook payload has a NUL byte; refusing to alter it" >&2
    return 0
  fi
  local outcome="$3" log_mode="${FAIL_MODE:-closed}"
  if defenseclaw_per_user_oversize_open; then
    outcome=diagnostic
    log_mode=open
  fi
  defenseclaw_log_hook_failure "$connector" "$hook_name" \
    "stdin body exceeded $1 byte cap" transport "$log_mode" "$outcome"
  case "$outcome" in
    fail_open|diagnostic) ;;
    *) echo "defenseclaw: hook payload exceeded $1 bytes; refusing to truncate" >&2 ;;
  esac
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
        response "${FAIL_MODE:-closed}" diagnostic
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
        response "${FAIL_MODE:-closed}" diagnostic
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
  local facts secure_client=0
  # A Secure Client hook keeps its earlier headers: no session facts and the
  # account name as id reports it (issue #1092).
  defenseclaw_secure_client_hook && secure_client=1
  if [ "$secure_client" = 0 ]; then
    facts="$(defenseclaw_session_facts_value)"
    if [ -n "$facts" ]; then
      printf '%s\n' "-H"
      printf '%s\n' "X-DefenseClaw-Session-Facts: $facts"
    fi
  fi

  command -v id >/dev/null 2>&1 || return 0

  local uid name
  # bash sets EUID itself (read-only, never taken from the environment), so
  # this is id -u without a child process (issue #1130).
  uid="${EUID:-}"
  case "$uid" in
    '' | *[!0-9]*) ;;
    *)
      printf '%s\n' "-H"
      printf '%s\n' "X-DefenseClaw-User-Id: $uid"
      ;;
  esac

  name=""
  # A local account's name comes from /etc/passwd without a program (issue
  # #1130 / GAP-0267); a directory account (SSSD, macOS) still asks id.
  if [ "$secure_client" = 0 ] && [ -n "$uid" ] && [ -r /etc/passwd ]; then
    local pw_name="" pw_pass="" pw_uid="" pw_rest=""
    while IFS=: read -r pw_name pw_pass pw_uid pw_rest; do
      if [ "$pw_uid" = "$uid" ]; then
        name="$pw_name"
        break
      fi
    done < /etc/passwd
  fi
  [ -n "$name" ] || name="$(id -un 2>/dev/null)" || name=""
  # SSSD fully qualified names (alice@realm) report the bare account.
  [ "$secure_client" = 1 ] || name="${name%%@*}"
  case "$name" in
    '' | *[!A-Za-z0-9._-]*) return 0 ;;
  esac
  printf '%s\n' "-H"
  printf '%s\n' "X-DefenseClaw-User-Name: $name"
  return 0
}

# The rendered hook pins its profile before sourcing this helper. Do not
# infer the profile from DEFENSECLAW_HOME: Secure Client hooks live under the
# target users home, just like per-user hooks.
defenseclaw_secure_client_hook() {
  case "${DEFENSECLAW_MANAGED_HOOK:-0}" in
    1|true|TRUE|yes|YES) [ "${_DC_SECURE_CLIENT_HOOK:-0}" = 1 ] ;;
    *) return 1 ;;
  esac
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
# as it is, so the binary runs at most once per five minutes per session,
# unless the session's FILE or DIR credential cache changed after the record
# was written: a new kinit into the same cache changes the principal while
# the variables stay the same (GAP-1139). A cache that does not answer that
# check within a second (a stalled network or FUSE mount) sends the session
# variables alone (_dc_ccache_changed). It
# runs only when a credential cache can exist (KRB5CCNAME or /etc/krb5.conf;
# always on macOS, whose default API: cache needs neither), and its answer is
# used only when it matches the header charset. A standalone managed hook
# runs the administrator-owned hook binary its rendered socket transport names
# (DEFENSECLAW_SESSION_FACTS_BIN) instead, since a managed user has no
# per-user gateway binary; a managed hook that names none (Secure Client)
# sends the SSH and logind variables alone.
defenseclaw_session_facts_full() {
  local home="${DEFENSECLAW_AGENT_HOME:-${HOME:-}}" env_key cache record="" re out="" bin="${DEFENSECLAW_SESSION_FACTS_BIN:-}" ccache=""
  _DC_CCACHE_CHANGED=same
  case "${DEFENSECLAW_MANAGED_HOOK:-0}" in
    1|true|TRUE|yes|YES) [ -n "$bin" ] || return 0 ;;
  esac
  case "$bin" in
    '') ;;
    /*) { [ -f "$bin" ] && [ -x "$bin" ]; } || return 0 ;;
    *) return 0 ;;
  esac
  case "$home" in
    /*) ;;
    *) return 0 ;;
  esac
  env_key="${KRB5CCNAME:-}|${XDG_SESSION_ID:-}|${SSH_CONNECTION:-}|${SSH_TTY:-}"
  case "$env_key" in
    *[!A-Za-z0-9._@/:%\ \|-]*) return 0 ;;
  esac
  cache="${home}/.defenseclaw/session-facts.json"
  case "${KRB5CCNAME:-}" in
    '') ccache="/tmp/krb5cc_${EUID:-}" ;;
    FILE:/*) ccache="${KRB5CCNAME#FILE:}" ;;
    DIR::/*) ccache="${KRB5CCNAME#DIR::}" ;;
    DIR:/*) ccache="${KRB5CCNAME#DIR:}" ;;
    /*) ccache="$KRB5CCNAME" ;;
  esac
  local fresh=0 expires="" now=""
  if [ -f "$cache" ] && [ ! -L "$cache" ]; then
    IFS= read -r -d '' -n 4096 record < "$cache" 2>/dev/null || true
    if [ "${BASH_VERSINFO[0]:-0}" -ge 5 ]; then
      # Bash 5's epoch clock is a builtin. Unproven, expired and implausibly
      # future records refresh through the native identity collector.
      re='"expires_at":([0-9]{1,11})[,}]'
      now="$EPOCHSECONDS"
      if [[ "$record" =~ $re ]]; then
        expires="${BASH_REMATCH[1]}"
        if [ "$expires" -gt "$now" ] && [ "$expires" -le "$((now + 300))" ]; then fresh=1; fi
      fi
    elif [ -n "$(find "$cache" -mmin -5 2>/dev/null)" ]; then
      # macOS's system Bash 3.2 has no epoch clock.
      fresh=1
    fi
  fi
  if [ "$fresh" = 1 ] && [ -n "$ccache" ] && [ -z "${KRB5CCNAME:-}" ]; then
    # The default cache is in the local /tmp: the shell's own test reads it
    # without a program, so a warm hook stays within its program budget
    # (GAP-0267). A named cache may sit on a network mount that stalls, so it
    # keeps the bounded find (_dc_ccache_changed).
    if [ -e "$ccache" ] && [ "$ccache" -nt "$cache" ]; then _DC_CCACHE_CHANGED=newer; fi
    ccache=""
  fi
  if [ "$fresh" = 1 ] &&
    { [ -z "$ccache" ] || _dc_ccache_changed "$ccache" "$cache"; } && [ "${_DC_CCACHE_CHANGED:-same}" != newer ]; then
    # The binary would wait on a stalled cache too.
    [ "${_DC_CCACHE_CHANGED:-same}" != stalled ] || return 0
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
  case "${OSTYPE:-}" in
    darwin*) ;;
    *) [ -n "${KRB5CCNAME:-}" ] || [ -r /etc/krb5.conf ] || return 0 ;;
  esac
  [ -n "$bin" ] || bin="$(defenseclaw_gateway_binary)" || return 0
  # The Go runtime cannot start under the hook's address-space limit.
  out="$(
    ulimit -S -v "$(ulimit -H -v)" 2>/dev/null || true
    HOME="$home" exec "$bin" hook session-facts </dev/null 2>/dev/null
  )" || return 0
  defenseclaw_session_facts_checked "$out"
  return 0
}

# _dc_ccache_changed CCACHE RECORD sets _DC_CCACHE_CHANGED to newer when the
# credential cache CCACHE was modified after RECORD, same when not (or when
# it is gone), and stalled when the check gave no answer within a second.
# find runs the check in a process of its own, with none of the hook's
# descriptors, so a cache on a stalled network or FUSE mount holds that
# process, not the hook (bash 3.2 reads with whole seconds only). The "."
# line after it marks a check that answered: bash 3.2 gives a read that timed
# out the status of an empty input (1, not over 128).
_dc_ccache_changed() {
  local line="" status=0
  _DC_CCACHE_CHANGED=stalled
  IFS= read -r -t 1 line < <(exec </dev/null 2>/dev/null; find "$1" -prune -newer "$2" -print || :; printf '.\n') || status=$?
  if [ "$status" -gt 128 ] || [ -z "$line" ]; then
    return 0
  elif [ "$line" != . ]; then
    _DC_CCACHE_CHANGED=newer
  else
    _DC_CCACHE_CHANGED=same
  fi
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

# defenseclaw_tool_gate_max_time EVENT DEFAULT sets HOOK_MAX_TIME, the
# bound of the whole gateway request (curl --max-time): 4 s for an event that
# holds a tool call (PreToolUse, PermissionRequest), the native hook's answer
# budget with its scanner-progress ceiling (hookexec answer_deadline.go), and
# DEFAULT for every other event. A gateway that accepted the call and stalls
# in the middle of its answer then fails the call within the agent's 5 s, as
# the native hook does, instead of after 10 s (GAP-0323).
defenseclaw_tool_gate_max_time() {
  case "$1" in
    PreToolUse|PermissionRequest) HOOK_MAX_TIME=4 ;;
    *) HOOK_MAX_TIME="$2" ;;
  esac
}

# defenseclaw_payload_tool_gate_max_time PAYLOAD DEFAULT is
# defenseclaw_tool_gate_max_time for the event in the payload's top-level
# hook_event_name (_dc_hook_event_field), so JSON spacing and a nested
# hook_event_name key do not change the bound. A payload whose event cannot
# be read keeps DEFAULT.
defenseclaw_payload_tool_gate_max_time() {
  local event=""
  event="$(_dc_hook_event_field "$1" hook_event_name 2>/dev/null)" || event=""
  defenseclaw_tool_gate_max_time "$event" "$2"
}

# defenseclaw_keep_nul_visible copies a gateway answer with each NUL byte
# turned into U+0001. Command substitution drops NUL bytes, so an answer with
# "al<NUL>low" read as "allow" (GAP-1008). No JSON parser here (the strict
# validator, jq, Python) accepts an unescaped control character, so such an
# answer now fails as malformed.
# bash's read -d '' stops at each NUL, so the copy starts no program (issue
# #1130 / GAP-0267); each stop is one NUL, replaced by U+0001.
defenseclaw_keep_nul_visible() {
  local part="" out="" LC_ALL=C
  while IFS= read -r -d '' part; do
    out="${out}${part}"$'\001'
  done
  printf '%s' "${out}${part}"
}

# defenseclaw_gateway_post URL MAX_TIME BODY [CURL_ARGS...]
#
# POSTs BODY to the gateway at URL and prints "<response body>\n<http code>"
# (curl -w), returning curl's exit status so the caller can tell a refused
# connection (7) from other failures. Every host hook request to the gateway
# goes through here. A per-user request uses the native helper, which verifies
# the owner of the same connected socket that carries the bearer and event.
#
# Neither the bearer nor the body ever reaches curl's command line: any local
# account can read a process's arguments (ps, /proc/<pid>/cmdline), and exec
# monitors (auditd, Tetragon, EDR) record them, so a literal -H or -d argument
# would disclose the gateway credential and the prompt or tool payload. An
# Authorization header among CURL_ARGS (-H "Authorization: ..." or --header)
# reaches curl as a config line on descriptor 8 and BODY on descriptor 9; the
# arguments carry only the descriptor paths. printf is a shell builtin, so the
# process substitutions that write both values execute no program. The
# descriptor-backed --config form works on curl releases older than 7.55.0,
# which lack -H @file. An Authorization value with CR or LF, which would end
# the config line, is refused without running curl. -q, which must be curl's
# first argument, keeps it from reading a .curlrc: the hook replaces HOME, but
# CURL_HOME and XDG_CONFIG_HOME come from the agent's environment, and a
# .curlrc there could trace the bearer and body to a file or turn an HTTP 401
# into a transport failure. Bash 3.2 compatible.
defenseclaw_gateway_post() {
  local _dc_post_status=0 _dc_listener_status=0 _dc_post_peer_final=0
  _dc_gateway_post_once "$@" || _dc_post_status=$?
  case "$_dc_post_status" in
    1|28) ;;
    *) return "$_dc_post_status" ;;
  esac
  case "${DEFENSECLAW_MANAGED_HOOK:-0}" in
    1|true|TRUE|yes|YES) return "$_dc_post_status" ;;
  esac
  [ -z "${DEFENSECLAW_HOOK_SOCKET:-}" ] || return "$_dc_post_status"
  # The native helper ran and failed on its own terms, not with its outage
  # status (7): it reached a listener and refused its owner, or the call it
  # sent got no usable answer. That result is final. A socket table read
  # later may no longer show a foreign listener that unbound after the
  # refusal, and must not turn the refusal into a cold start, the one status
  # a per-user outage rule may let through.
  [ "$_dc_post_peer_final" = 0 ] || return 1
  # A per-user call that never reached a peer (refused, or not sent) reads
  # the socket tables once, so the outcome is the one the old send-time
  # preflight gave: no listener is a cold start (7), a foreign or unknown one
  # fails closed (1).
  defenseclaw_api_listener_unproven "${API_ADDR:-}" || _dc_listener_status=$?
  case "$_dc_listener_status" in
    2) return 7 ;;
    0) return 1 ;;
  esac
  return "$_dc_post_status"
}

# _dc_gateway_post_once makes one defenseclaw_gateway_post attempt.
# _dc_json_escape_shell VALUE sets _DC_JSON_ESCAPED to VALUE as the inside
# of a JSON string, with the shell's own substitutions (backslash, quote,
# newline, carriage return, tab); a value with any other control character
# goes through defenseclaw_json_escape. Bash 3.2 (macOS) runs ${v//x/y} in
# time quadratic in the value (110 KB took minutes), so there a value over
# 1 KiB goes through one sed and one awk, linear and the same encoding
# (GAP-2274); headers stay in the shell (GAP-1755).
_dc_json_escape_shell() {
  local LC_ALL=C v="${1:-}"
  if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ] && [ "${#v}" -gt 1024 ]; then
    v="$(printf '%sx' "$v" |
      LC_ALL=C sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e $'s/\r/\\\\r/g' -e $'s/\t/\\\\t/g' |
      LC_ALL=C awk 'BEGIN { ORS = "" } NR > 1 { print "\\n" } { print }')" || v=""
    case "$v" in
      *x) v="${v%x}" ;;
      *) v="$(defenseclaw_json_escape "${1:-}")" ;;
    esac
    case "$v" in
      *[[:cntrl:]]*) v="$(defenseclaw_json_escape "${1:-}")" ;;
    esac
    _DC_JSON_ESCAPED="$v"
    return 0
  fi
  v="${v//\\/\\\\}"
  v="${v//\"/\\\"}"
  v="${v//$'\n'/\\n}"
  v="${v//$'\r'/\\r}"
  v="${v//$'\t'/\\t}"
  case "$v" in
    *[[:cntrl:]]*) v="$(defenseclaw_json_escape "${1:-}")" ;;
  esac
  _DC_JSON_ESCAPED="$v"
}

_dc_gateway_post_once() {
  local _dc_post_url="$1" _dc_post_max_time="$2" _dc_post_body="$3"
  local _dc_post_auth="" _dc_post_arg
  local _dc_native_post=0 _dc_post_bin _dc_post_prefix _dc_post_path _dc_legacy_post=1
  local _dc_header_name _dc_header_value _dc_post_output _dc_post_headers _dc_post_sep _dc_field_index
  local -a _dc_post_args _dc_post_auth_args _dc_post_fields
  # A per-user post reads no socket table before it sends (GAP-1453): the
  # native helper proves the owner of the very connection it sends on, with
  # nothing written before that proof. Only an address the helper would
  # refuse stops here; defenseclaw_gateway_post classifies every unsent call.
  case "${DEFENSECLAW_MANAGED_HOOK:-0}" in
    1|true|TRUE|yes|YES) ;;
    *)
      if [ -z "${DEFENSECLAW_HOOK_SOCKET:-}" ]; then
        [ -n "${API_ADDR:-}" ] || return 1
        case "$_dc_post_url" in "http://""${API_ADDR}/"*) ;; *) return 1 ;; esac
        defenseclaw_loopback_targets "$API_ADDR" || return 1
        _dc_native_post=1
      fi
      ;;
  esac
  shift 3
  _dc_post_args=()
  _dc_post_auth_args=()
  while [ "$#" -gt 0 ]; do
    _dc_post_arg="$1"
    shift
    case "$_dc_post_arg" in
      -H|--header)
        if [ "$#" -gt 0 ]; then
          case "$1" in
            [Aa][Uu][Tt][Hh][Oo][Rr][Ii][Zz][Aa][Tt][Ii][Oo][Nn]:*)
              _dc_post_auth="$1"
              shift
              continue
              ;;
          esac
        fi
        ;;
    esac
    _dc_post_args+=("$_dc_post_arg")
  done
  case "$_dc_post_auth" in
    *$'\n'*|*$'\r'*) return 1 ;;
  esac
  if [ "$_dc_native_post" -eq 1 ]; then
    # The agent's deadline includes shell preparation and starting the native
    # helper. Give the helper only the time still left, reserving one second
    # for process startup on short tool-call budgets. Its own timeout starts
    # after startup, so passing the original four seconds could hold a tool
    # call beyond the agent's answer window on a busy host.
    case "$_dc_post_max_time" in ""|*[!0-9]*) return 1 ;; esac
    _dc_hook_elapsed_ms
    [ "$_DC_ELAPSED_MS" -ge 0 ] || _DC_ELAPSED_MS=0
    local _dc_post_remaining=$(( _dc_post_max_time - (_DC_ELAPSED_MS + 999) / 1000 ))
    [ "$_dc_post_remaining" -gt 0 ] || return 28
    if [ "$_dc_post_max_time" -le 4 ] && [ "$_dc_post_remaining" -gt 2 ]; then
      _dc_post_remaining=$((_dc_post_remaining - 1))
    fi
    # The same bound in milliseconds, for the helper (GAP-2279): the whole
    # seconds above round the shell's own time up, so a call that spent
    # 0.4 s reading a large body gave the helper 2 s of the 2.6 s left after
    # the startup reserve, and was closed at 2.4 s. The helper gets the time
    # left after that reserve, never less than the whole seconds above and
    # never a whole second more; an older helper reads only --max-time.
    local _dc_post_remaining_ms=$(( _dc_post_max_time * 1000 - _DC_ELAPSED_MS ))
    if [ "$_dc_post_max_time" -le 4 ]; then
      _dc_post_remaining_ms=$(( _dc_post_remaining_ms - 1000 ))
    fi
    if [ "$_dc_post_remaining_ms" -lt $(( _dc_post_remaining * 1000 )) ]; then
      _dc_post_remaining_ms=$(( _dc_post_remaining * 1000 ))
    fi
    # The executable that receives the bearer is the gateway setup recorded
    # beside this hook (.gateway-helper, defenseclaw_gateway_binary, which
    # proves the record and every folder on its path are this account's and
    # private), never one the agent's HOME or DEFENSECLAW_AGENT_HOME names
    # (GAP-1755), as the OpenCode and Amp plugins read it.
    local _dc_recovery_home="" _dc_recovery_path="" _dc_secure_meta="" _dc_secure_uid=""
    local _dc_secure_path _dc_secure_mode _dc_post_dir
    defenseclaw_gateway_binary --folder --set || return 1
    _dc_post_bin="$_DC_GATEWAY_BINARY"
    _dc_post_dir="${_dc_post_bin%/*}"
    # The small helper has the same connected-socket peer check as the full
    # CLI. An older installation without it keeps the verified CLI path.
    # A present but untrusted helper is refused below, never bypassed.
    if [ -e "${_dc_post_dir}/defenseclaw-hook-post" ] ||
       [ -L "${_dc_post_dir}/defenseclaw-hook-post" ]; then
      _dc_post_bin="${_dc_post_dir}/defenseclaw-hook-post"
      _dc_legacy_post=0
      [ -f "$_dc_post_bin" ] && [ -x "$_dc_post_bin" ] && [ -O "$_dc_post_bin" ] && [ ! -L "$_dc_post_bin" ] || return 1
      # The folder check already proved this helper's mode in its stat.
      if [ "${_DC_HOOK_POST_MODE_OK:-}" != "$_dc_post_bin" ]; then
        defenseclaw_stat_into %a %Lp "$_dc_post_bin" || return 1
        _dc_secure_mode="$_DC_STAT_OUT"
        case "$_dc_secure_mode" in ""|*[!0-7]*) return 1 ;; esac
        [ $((8#${_dc_secure_mode} & 8#022)) -eq 0 ] || return 1
      fi
    else
      # An older installer's roll-forward restores its saved installer folder
      # but does not know this new binary name. That folder carries a checked
      # recovery copy, so the 10 Hz path remains fast after the roll-forward.
      _dc_recovery_home="${DEFENSECLAW_HOME:-${HOOK_DIR%/*}}"
      case "$_dc_recovery_home" in
        /*)
          _dc_recovery_path="${_dc_recovery_home%/}/installer/defenseclaw-hook-post"
          if [ -e "$_dc_recovery_path" ] || [ -L "$_dc_recovery_path" ]; then
            _dc_post_bin="$_dc_recovery_path"
            _dc_legacy_post=0
            # Prove every parent, including custom data-dir ancestors. A
            # root-owned sticky temporary parent is safe; a writable
            # non-sticky or foreign-owned parent can replace this executable.
            _dc_secure_path="${_dc_recovery_home%/}/installer"
            while [ "$_dc_secure_path" != / ]; do
              [ -d "$_dc_secure_path" ] && [ ! -L "$_dc_secure_path" ] || return 1
              defenseclaw_stat_into '%a:%u' '%Lp:%u' "$_dc_secure_path" || return 1
              _dc_secure_meta="$_DC_STAT_OUT"
              _dc_secure_mode="${_dc_secure_meta%%:*}"
              _dc_secure_uid="${_dc_secure_meta#*:}"
              case "$_dc_secure_mode" in ""|*[!0-7]*) return 1 ;; esac
              case "$_dc_secure_uid" in ""|*[!0-9]*) return 1 ;; esac
              if [ -O "$_dc_secure_path" ]; then
                [ $((8#${_dc_secure_mode} & 8#022)) -eq 0 ] || return 1
              else
                [ "$_dc_secure_uid" = 0 ] || return 1
                if [ $((8#${_dc_secure_mode} & 8#022)) -ne 0 ]; then
                  [ $((8#${_dc_secure_mode} & 8#1000)) -ne 0 ] || return 1
                fi
              fi
              _dc_secure_path="${_dc_secure_path%/*}"
              [ -n "$_dc_secure_path" ] || _dc_secure_path=/
            done
            [ -f "$_dc_post_bin" ] && [ -x "$_dc_post_bin" ] && [ -O "$_dc_post_bin" ] && [ ! -L "$_dc_post_bin" ] || return 1
            defenseclaw_stat_into %a %Lp "$_dc_post_bin" || return 1
            _dc_secure_mode="$_DC_STAT_OUT"
            [ $((8#${_dc_secure_mode} & 8#022)) -eq 0 ] || return 1
          fi
          ;;
      esac
      if [ "$_dc_legacy_post" -eq 1 ]; then
        _dc_post_bin="$(defenseclaw_gateway_binary)" || return 1
      fi
    fi
    _dc_post_prefix="http://${API_ADDR}"
    _dc_post_path="${_dc_post_url:${#_dc_post_prefix}}"
    _dc_post_fields=()
    set -- "${_dc_post_args[@]+"${_dc_post_args[@]}"}"
    while [ "$#" -gt 0 ]; do
      case "$1" in
        -H|--header) [ "$#" -ge 2 ] || return 1; shift ;;
        *) return 1 ;;
      esac
      _dc_post_arg="$1"
      shift
      case "$_dc_post_arg" in *:*) ;; *) return 1 ;; esac
      _dc_header_name="${_dc_post_arg%%:*}"
      _dc_header_value="${_dc_post_arg#*:}"
      _dc_header_value="${_dc_header_value# }"
      case "$_dc_header_name" in ""|*[!A-Za-z0-9-]*) return 1 ;; esac
      case "$_dc_header_value" in *$'\n'*|*$'\r'*) return 1 ;; esac
      _dc_post_fields+=("$_dc_header_name" "$_dc_header_value")
    done
    if [ -n "$_dc_post_auth" ]; then
      _dc_header_value="${_dc_post_auth#*:}"
      _dc_header_value="${_dc_header_value# }"
      _dc_post_fields+=("Authorization" "$_dc_header_value")
    fi
    _dc_post_output="$(
      if [ "$_dc_legacy_post" -eq 1 ]; then
        # A hook can run during an upgrade before the small helper exists.
        # The existing gateway CLI accepts the original JSON envelope.
        # The shell encodes the envelope itself: a program per field made
        # the process count grow with the headers (GAP-1755).
        _dc_post_headers="" _dc_post_sep=""
        for ((_dc_field_index=0; _dc_field_index<${#_dc_post_fields[@]}; _dc_field_index+=2)); do
          _dc_json_escape_shell "${_dc_post_fields[_dc_field_index]}"
          _dc_post_headers="${_dc_post_headers}${_dc_post_sep}\"${_DC_JSON_ESCAPED}\":"
          _dc_json_escape_shell "${_dc_post_fields[_dc_field_index+1]}"
          _dc_post_headers="${_dc_post_headers}\"${_DC_JSON_ESCAPED}\""
          _dc_post_sep=,
        done
        _dc_json_escape_shell "$_dc_post_path"
        printf '{"path":"%s","headers":{%s},' "$_DC_JSON_ESCAPED" "$_dc_post_headers"
        _dc_json_escape_shell "$_dc_post_body"
        printf '"body":"%s"}' "$_DC_JSON_ESCAPED"
      else
        printf '%s\0' 'DCPOST1' "$_dc_post_path" "$_dc_post_body" "${_dc_post_fields[@]+"${_dc_post_fields[@]}"}"
      fi |
        (
          if [ -n "${_DC_HOOK_NATIVE_VMEM_LIMIT:-}" ]; then
            # 126, as for a helper that cannot run: nothing was sent.
            ulimit -S -v "$_DC_HOOK_NATIVE_VMEM_LIMIT" 2>/dev/null || exit 126
          fi
          _DC_HOOK_POST_DEADLINE_MS="$_dc_post_remaining_ms" exec "$_dc_post_bin" hook-post --api-addr "$API_ADDR" --max-time "$_dc_post_remaining" --curl-output
        ) 2>/dev/null |
        defenseclaw_keep_nul_visible
      exit "${PIPESTATUS[1]}"
    )" || {
      # 7 is the helper's outage status (hookexec.PerUserPostOutageExit: no
      # gateway took the connection) and 126 or 127 a helper that did not
      # run; neither reached a peer. Every other failure came after the
      # helper's connected-peer check decided, and stays closed
      # (defenseclaw_gateway_post).
      case "$?" in
        7|126|127) ;;
        *) _dc_post_peer_final=1 ;;
      esac
      return 1
    }
    defenseclaw_warn_reviewed_oversize "$_dc_post_body" "$_dc_post_output"
    printf '%s' "$_dc_post_output"
    return 0
  fi
  if [ -n "$_dc_post_auth" ]; then
    # The two characters a quoted curl config value escapes.
    _dc_post_auth="${_dc_post_auth//\\/\\\\}"
    _dc_post_auth="${_dc_post_auth//\"/\\\"}"
    _dc_post_auth_args=(--config /dev/fd/8)
  fi
  curl -q -s --noproxy '*' -w '\n%{http_code}' -X POST "$_dc_post_url" \
    "${_dc_post_args[@]+"${_dc_post_args[@]}"}" \
    "${_dc_post_auth_args[@]+"${_dc_post_auth_args[@]}"}" \
    --connect-timeout 2 \
    --max-time "$_dc_post_max_time" \
    --data-binary @/dev/fd/9 2>/dev/null \
    8< <(printf 'header = "%s"\n' "$_dc_post_auth") \
    9< <(printf '%s' "$_dc_post_body") |
    defenseclaw_keep_nul_visible
  return "${PIPESTATUS[0]}"
}
