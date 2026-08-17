#!/usr/bin/env bash
#
# DefenseClaw macOS installer — pure-function helpers.
#
# This library contains the side-effect-free pieces of install.sh so they
# can be unit-tested without touching /Library, sudo, or the LaunchDaemon.
# install.sh sources this file. tests/ also sources it.
#
# Functions in this file MUST NOT:
#   - call sudo, chown, chmod, install(8), launchctl
#   - write outside paths the caller passed in
#   - depend on globals other than what the caller exports
#
# They DO:
#   - parse strings, render YAML, run pure file I/O against caller-owned
#     paths (e.g. a tmpdir under /tmp/dctest-XXXX).

# ---- connector list parsing --------------------------------------------

# parse_connectors LIST -> echoes one normalized connector per line.
# Splits on comma, trims whitespace, lowercases. Empty entries are an
# error (caller's job to die() on non-zero return).
parse_connectors() {
  local raw="$1"
  if [[ -z "${raw}" ]]; then
    return 1
  fi
  # Reject leading/trailing/consecutive commas explicitly; `read -ra`
  # would silently drop a bare trailing empty field.
  case "${raw}" in
    ,*|*,|*,,*) return 1;;
  esac
  local -a out=()
  local IFS=','
  read -ra out <<< "${raw}"
  local c
  # Guard for bash 3.2: ${array[@]} on an empty array under `set -u`
  # would trip an "unbound variable" error.
  if [[ ${#out[@]} -eq 0 ]]; then
    return 1
  fi
  for c in "${out[@]}"; do
    c="$(printf '%s' "${c}" | tr '[:upper:]' '[:lower:]' | awk '{$1=$1};1')"
    if [[ -z "${c}" ]]; then
      return 1
    fi
    # Restrict to a YAML-safe key charset. Anything else would be
    # rendered raw into config.yaml where it could break the parser
    # or, worse, inject unrelated keys.
    if [[ ! "${c}" =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
      return 1
    fi
    printf '%s\n' "${c}"
  done
}

# is_supported_connector NAME -> exit 0 if name is auto-wireable.
is_supported_connector() {
  case "$1" in
    amp|codex|claudecode|cursor) return 0;;
    *) return 1;;
  esac
}

# classify_zero_target_reason CONNECTORS_CSV -> echoes classification token.
#
# Called by install.sh when render_targets_manifest produced zero rows
# despite a non-empty user set (AIFW-31486). Distinguishes the two
# operationally-different zero-target modes so an operator reading
# install.log can act on the right cause:
#
#   all-unsupported  Every requested connector is outside the auto-wire
#                    allow-list (amp|codex|claudecode|cursor). The
#                    hook-enumerator's tick will NOT fix this by itself
#                    — the operator has to rerun with --connector picking
#                    a supported entry.
#
#   none-installed   At least one requested connector IS supported, but
#                    no eligible user has any of them installed yet.
#                    This is the AIFW-31486 default customer case:
#                    the enumerator's 5-min tick picks it up
#                    automatically as connectors appear.
#
# Discovery-error separation: this helper only classifies "how did we
# end up with zero rows"; it does not classify "was metadata corrupt".
# When DC_DISCOVERY_ERRORS_LOG has entries after render_targets_manifest
# runs, install.sh treats that log as a fatal condition BEFORE reaching
# classify_zero_target_reason — an operator whose codex install has a
# corrupt package.json needs to hear "your metadata is unreadable at
# /path/to/package.json", not "we couldn't find any connector installed".
# See _record_discovery_error / _probe_json_version for the plumbing
# that feeds that log.
classify_zero_target_reason() {
  local raw="$1"
  local c
  local any_supported="false"
  while IFS= read -r c; do
    [[ -z "${c}" ]] && continue
    if is_supported_connector "${c}"; then
      any_supported="true"
      break
    fi
  done < <(parse_connectors "${raw}" 2>/dev/null || true)
  if [[ "${any_supported}" == "true" ]]; then
    printf 'none-installed\n'
  else
    printf 'all-unsupported\n'
  fi
}

# ---- home perms ---------------------------------------------------------

# home_perms_ok PATH -> exit 0 iff path has no group/other write bits.
# Mirrors validateUserHome() in internal/enterprisehooks/installer.go.
home_perms_ok() {
  local home="$1"
  local mode
  mode="$(stat -f '%Lp' "${home}" 2>/dev/null || stat -c '%a' "${home}" 2>/dev/null || echo "")"
  [[ -z "${mode}" ]] && return 0
  (( (8#${mode} & 8#022) == 0 ))
}

# ---- agent version discovery -------------------------------------------

# _record_discovery_error CONNECTOR PATH REASON -> void
#
# Appends a tab-separated record to the file named by
# DC_DISCOVERY_ERRORS_LOG (env var; caller-owned). Silently no-op when
# the env var is unset — callers who don't care about discovery errors
# (unit tests, ad-hoc invocations) keep the historical "corrupt
# metadata is silently treated as absent" behaviour.
#
# Record layout: USER\tCONNECTOR\tREASON\tPATH\n
#   USER      — DC_INSTALLER_TARGET_USER at the time of the failure
#               (empty when the caller didn't scope to a user).
#   CONNECTOR — connector token (amp / codex / claudecode / cursor).
#   REASON    — short machine-readable reason (e.g. "malformed-json").
#   PATH      — absolute path of the metadata file that failed to
#               parse; the operator can act on this directly.
#
# The append is best-effort (2>/dev/null) so a full disk or a
# read-only log path can never abort the installer mid-render.
_record_discovery_error() {
  local connector="$1"
  local path="$2"
  local reason="$3"
  [[ -n "${DC_DISCOVERY_ERRORS_LOG:-}" ]] || return 0
  printf '%s\t%s\t%s\t%s\n' \
    "${DC_INSTALLER_TARGET_USER:-}" \
    "${connector}" \
    "${reason}" \
    "${path}" >> "${DC_DISCOVERY_ERRORS_LOG}" 2>/dev/null || true
}

# _probe_json_version PATH CONNECTOR [EXPECTED_NAME] -> echoes version or ""
#
# Thin wrapper around _read_json_version that records a discovery
# error when the file exists but its JSON is malformed. Callers use
# this from inside discover_agent_version to consolidate the
# rc-2-to-error-log translation so each per-connector probe loop
# stays a single line.
#
# On rc 0 (well-formed or absent): output is passed through unchanged.
# On rc 2 (malformed): output is dropped, an error is recorded, and
# this helper still returns rc 0 so the outer probe loop can continue
# to the next fallback (e.g. Caskroom after npm). If EVERY probe for
# a connector on a given user's home is malformed and none yields a
# valid version, the recorded errors are what install.sh's zero-target
# branch surfaces to the operator.
_probe_json_version() {
  local path="$1"
  local connector="$2"
  local expected_name="${3:-}"
  local v rc
  v="$(_read_json_version "${path}" "${expected_name}")"
  rc=$?
  if [[ ${rc} -eq 2 ]]; then
    _record_discovery_error "${connector}" "${path}" "malformed-json"
    return 0
  fi
  printf '%s' "${v}"
}

# discover_agent_version CONNECTOR HOME -> echoes the agent version or "".
#
# Metadata-only: reads files under HOME or under signed system app bundles
# and never executes user-installed agent binaries. install.sh runs as root,
# so invoking $PATH-resolved `codex` / `claude` / etc. would be a
# privilege-escalation surface — the caller must pass --agent-version
# explicitly for connectors that don't ship a stable metadata file.
# _read_codex_version_as_user USER -> echoes codex --version output (first line, ≤512 bytes) or "".
#
# Runs `sudo -n -u USER codex --version` with a bounded wall-clock
# limit (5 s) so a hung codex cannot stall the installer. Pure-bash
# implementation: previously this shelled out to python3 for the
# timeout + bounded-read logic, but that violated the "no python3
# runtime dependency on install-time paths" rip-out (see the
# `_read_json_field` doc block below for the QA rationale). BSD does
# not ship `timeout(1)` so the timeout is implemented by
# background-launching the child and killing it after the deadline;
# the child's stdout is captured to a private temp file bounded at
# 512 bytes via `head -c` so a chatty codex cannot fill the pipe.
_read_codex_version_as_user() {
  local user="$1"
  local out_file rc=0
  # Fail closed on mktemp failure. The prior fallback
  # `/tmp/defenseclaw-codex-version.$$` was predictable — a
  # colocated user could pre-create a symlink at that path and
  # have `> "${out_file}"` write elsewhere, or race the
  # subsequent `head -n 1` read. Since this helper runs during
  # install (as root under launchd or `sudo`), that's a real
  # privesc surface. If mktemp fails, print nothing and return
  # non-zero so the caller falls through to alternative version
  # discovery paths.
  out_file="$(mktemp -t defenseclaw-codex-version.XXXXXX 2>/dev/null)" || return 1
  # Best-effort cleanup on any exit path.
  # shellcheck disable=SC2064
  trap "rm -f -- '${out_file}'" RETURN
  # Background the subprocess in its own process group so a
  # kill -TERM -PGID hits everything it spawned (defensive against a
  # codex wrapper that forks helpers). `setsid` is Linux-only; on
  # macOS the child inherits the shell's session and $$ but exec's
  # `-a` and `sudo`'s `-b` do not give us a clean PGID, so we settle
  # for killing the immediate PID plus a wait.
  ( sudo -n -u "${user}" codex --version 2>/dev/null | head -c 512 | head -n 1 > "${out_file}" ) &
  local pid=$!
  # Poll for completion with a 5-second wall-clock budget. `wait -n`
  # would block indefinitely; a tight sleep+kill loop hits the
  # deadline reliably.
  local waited=0
  while (( waited < 50 )); do
    if ! kill -0 "${pid}" 2>/dev/null; then
      break
    fi
    sleep 0.1
    waited=$((waited + 1))
  done
  if kill -0 "${pid}" 2>/dev/null; then
    kill -TERM "${pid}" 2>/dev/null || true
    sleep 0.1
    kill -KILL "${pid}" 2>/dev/null || true
  fi
  # `wait` reaps the child and returns its exit status; the trap
  # above cleans the tempfile once the function returns.
  wait "${pid}" 2>/dev/null || rc=$?
  local line
  line="$(head -n 1 -- "${out_file}" 2>/dev/null || true)"
  # Match the python variant's contract: return the trimmed first
  # line (or empty on any failure).
  printf '%s' "${line}"
  return 0
}


# _read_json_field PATH FIELD -> echoes the top-level FIELD or "".
#
# Exit codes:
#   0  — file missing OR file well-formed (FIELD emitted if present, empty
#        stdout if absent). Both cases are semantically "no error, field
#        just wasn't there."
#   2  — file exists but its top-level JSON structure is malformed (not an
#        object, unbalanced braces, invalid escape, truncated mid-value,
#        trailing garbage). Distinguishes "not installed" (empty stdout, rc 0)
#        from "installed but metadata corrupt" (empty stdout, rc 2) so
#        discover_agent_version can propagate a real discovery-error status
#        instead of silently classifying corrupt metadata as an absent
#        connector — see the DC_DISCOVERY_ERRORS_LOG plumbing in
#        discover_agent_version / install.sh for the full contract.
#
#
# Reads a JSON document from PATH and echoes the value of the given
# top-level string field, or empty on any error (missing file,
# unreadable file, malformed JSON, missing field, non-string value).
# Metadata-only: no shell interpolation of the payload, no exec of
# any binary the payload names. The reader is a depth-aware awk
# tokenizer scoped to top-level string-field lookup — no external
# runtime dependency.
#
# QA regression this addresses: stock macOS ships /usr/bin/python3 as
# a *stub* that requires Xcode Command Line Tools to actually invoke
# the interpreter. `[ -x /usr/bin/python3 ]` passes on those hosts,
# but the interpreter fails to launch and every DefenseClaw install
# that shelled out to python3 crashed on first-boot env_config trust
# check. Awk is part of the macOS base image, no CLT dependency.
_read_json_field() {
  local path="$1"
  local field="$2"
  [[ -f "${path}" ]] || return 0
  # Awk parser: matches the top-level `"<field>": "<value>"` pair
  # (immediately inside the outer object). Only the outer object's
  # members are iterated, so we don't need a general depth counter —
  # non-string, non-container values are skipped by scanning to the
  # next delimiter, and nested objects/arrays are consumed by a local
  # nest_depth counter that respects strings (a `{` inside a JSON
  # string doesn't inflate it). Escape sequences \" \\ \/ \n \r \t
  # \b \f are decoded; \uXXXX (BMP + surrogate pairs) are decoded to
  # UTF-8. On any tokenization error the parser bails and prints
  # nothing, matching the pre-existing "malformed → empty" contract
  # callers gate on.
  #
  # LC_ALL=C pins the locale for `sprintf("%c", cp)` and `substr` so
  # bytes emitted by utf8() are treated as raw octets. Under a UTF-8
  # locale, `%c` on a value ≥ 128 emits a UTF-8-encoded multi-byte
  # sequence for that codepoint (double-encoding what we're already
  # building) and `substr` iterates on characters not bytes. The C
  # locale keeps both operating on octets, which is what the parser
  # assumes end-to-end.
  LC_ALL=C awk -v FIELD="${field}" '
    function utf8(cp,    b0, b1, b2, b3) {
      if (cp < 0)         return ""
      if (cp < 128)       return sprintf("%c", cp)
      if (cp < 2048)      return sprintf("%c%c",
                                          192 + int(cp/64),
                                          128 + (cp%64))
      if (cp < 65536)     return sprintf("%c%c%c",
                                          224 + int(cp/4096),
                                          128 + int((cp/64)%64),
                                          128 + (cp%64))
      return sprintf("%c%c%c%c",
                     240 + int(cp/262144),
                     128 + int((cp/4096)%64),
                     128 + int((cp/64)%64),
                     128 + (cp%64))
    }
    function hex4(s,    i, c, v, n) {
      if (length(s) != 4) return -1
      n = 0
      for (i = 1; i <= 4; i++) {
        c = tolower(substr(s, i, 1))
        v = index("0123456789abcdef", c)
        if (v == 0) return -1
        n = n * 16 + (v - 1)
      }
      return n
    }
    # read_string() reads a JSON string starting AT the opening quote;
    # advances `pos` past the closing quote; returns the decoded value
    # or sets `err` on malformed input.
    function read_string(    out, c, esc, hex, cp, low) {
      if (substr(buf, pos, 1) != "\"") { err = 1; return "" }
      pos++
      out = ""
      while (pos <= buflen) {
        c = substr(buf, pos, 1); pos++
        if (c == "\"") return out
        if (c == "\\") {
          if (pos > buflen) { err = 1; return "" }
          esc = substr(buf, pos, 1); pos++
          if      (esc == "\"") out = out "\""
          else if (esc == "\\") out = out "\\"
          else if (esc == "/")  out = out "/"
          else if (esc == "b")  out = out sprintf("%c", 8)
          else if (esc == "f")  out = out sprintf("%c", 12)
          else if (esc == "n")  out = out "\n"
          else if (esc == "r")  out = out "\r"
          else if (esc == "t")  out = out "\t"
          else if (esc == "u") {
            if (pos + 3 > buflen) { err = 1; return "" }
            hex = substr(buf, pos, 4); pos += 4
            cp = hex4(hex)
            if (cp < 0) { err = 1; return "" }
            if (cp >= 55296 && cp <= 56319) {
              # High surrogate — expect \uDCxx low surrogate.
              if (substr(buf, pos, 2) != "\\u") { err = 1; return "" }
              pos += 2
              if (pos + 3 > buflen) { err = 1; return "" }
              hex = substr(buf, pos, 4); pos += 4
              low = hex4(hex)
              if (low < 56320 || low > 57343) { err = 1; return "" }
              cp = 65536 + ((cp - 55296) * 1024) + (low - 56320)
            } else if (cp >= 56320 && cp <= 57343) {
              err = 1; return ""
            }
            out = out utf8(cp)
          } else {
            err = 1; return ""
          }
        } else {
          out = out c
        }
      }
      err = 1
      return ""
    }
    # skip_string() advances past a JSON string without decoding.
    # Assumes `pos` is at the opening quote.
    function skip_string(    c) {
      if (substr(buf, pos, 1) != "\"") { err = 1; return }
      pos++
      while (pos <= buflen) {
        c = substr(buf, pos, 1); pos++
        if (c == "\"") return
        if (c == "\\") {
          if (pos > buflen) { err = 1; return }
          pos++
        }
      }
      err = 1
    }
    function skip_ws(    c) {
      while (pos <= buflen) {
        c = substr(buf, pos, 1)
        if (c == " " || c == "\t" || c == "\n" || c == "\r") pos++
        else return
      }
    }
    {
      # Accumulate the entire file into buf. Awk normally splits by
      # RS; the default is "\n" so we join with the same character to
      # rebuild the payload verbatim from the shell perspective.
      if (buf == "") buf = $0
      else           buf = buf "\n" $0
    }
    END {
      buflen = length(buf)
      pos = 1
      err = 0
      skip_ws()
      if (substr(buf, pos, 1) != "{") exit 2
      pos++
      # State machine: only the OUTER object members are iterated,
      # so keys are always at logical depth 1. For values that are
      # not the sought field, skip strings / numbers / literals /
      # nested containers to reach the next comma or closing brace.
      # The inner-container walk below uses its own local nest_depth
      # counter, so no top-level depth counter is needed here.
      #
      # We defer printing the matched value until AFTER the whole
      # object has been validated as well-formed. Emitting on match
      # would silently accept truncated inputs like
      # `{"version":"1",` — the field-then-comma-then-EOF shape a
      # crashed writer leaves behind. `found` records whether the
      # match happened; `val` holds the value; the print at the END
      # of a clean parse commits it.
      found = 0
      val = ""
      while (pos <= buflen) {
        skip_ws()
        # Reached EOF without a closing brace: object was truncated.
        # Malformed (rc 2).
        if (pos > buflen) exit 2
        c = substr(buf, pos, 1)
        if (c == "}") {
          # Closing brace — object end. Validate that only
          # whitespace follows (no trailing garbage) before
          # emitting.
          pos++
          skip_ws()
          # Trailing content after the outer `}` is malformed (rc 2).
          if (pos <= buflen) exit 2
          if (found) print val
          # Clean parse of a well-formed object. `found` distinguishes
          # "field present" (val emitted) from "field absent" (empty
          # stdout). Both are rc 0 — callers use empty stdout + rc 0
          # to mean "not present", empty stdout + rc 2 to mean "parse
          # failed".
          exit 0
        }
        if (c == ",") { pos++; continue }
        # Top-level key must be a JSON string. Anything else means the
        # object body is malformed.
        if (c != "\"") exit 2
        # Read the top-level key.
        key_is_target = 0
        key = read_string()
        if (err) exit 2
        if (key == FIELD) key_is_target = 1
        skip_ws()
        # `:` must follow the key. Absence = malformed.
        if (substr(buf, pos, 1) != ":") exit 2
        pos++
        skip_ws()
        c = substr(buf, pos, 1)
        if (key_is_target && c == "\"") {
          v = read_string()
          if (err) exit 2
          # Remember the last string value seen for FIELD. JSON
          # semantics: duplicate top-level keys are permitted but
          # ill-defined; most parsers keep the LAST one. Follow
          # that convention rather than the first-wins short-circuit.
          val = v
          found = 1
          continue
        }
        # Not the sought field (or non-string value) — skip the value
        # so we can reach the next key. Value can be string, number,
        # literal (true/false/null), object, or array.
        if (c == "\"") {
          skip_string()
          if (err) exit 2
          # A non-target string value invalidates a previously-found
          # match with the SAME key iff it was actually the same key;
          # we do not track that here because the key path above
          # already recorded the target hit. Non-target keys never
          # touch `found`/`val`.
        } else if (c == "{" || c == "[") {
          nest_depth = 1
          pos++
          while (pos <= buflen && nest_depth > 0) {
            c = substr(buf, pos, 1)
            if (c == "\"") {
              skip_string()
              if (err) exit 2
              continue
            }
            if (c == "{" || c == "[") nest_depth++
            else if (c == "}" || c == "]") nest_depth--
            pos++
          }
          # Unbalanced braces at inner-container boundary = malformed.
          if (nest_depth != 0) exit 2
        } else {
          # scalar: number / true / false / null — consume until we
          # hit a delimiter (comma, closing brace, whitespace).
          # Empty run (no scalar bytes at all) means the buffer ended
          # mid-value, e.g. `{"version":`. Treat that as malformed.
          start_pos = pos
          while (pos <= buflen) {
            c = substr(buf, pos, 1)
            if (c == "," || c == "}" || c == " " || c == "\t" ||
                c == "\n" || c == "\r") break
            pos++
          }
          if (pos == start_pos) exit 2
        }
      }
      # Ran off the end of the buffer without a closing brace: object
      # was truncated. Malformed (rc 2).
      exit 2
    }
  ' "${path}" 2>/dev/null
}

# _read_json_version PATH [EXPECTED_NAME] -> echoes the .version field or "".
#
# Convenience shim used by discover_agent_version to read a package's
# .version metadata. When EXPECTED_NAME is supplied, the file's .name
# field is compared against it and the version is only emitted on
# match — protects against reading the wrong package's metadata when
# multiple npm packages share a directory tree (Amp's @ampcode/cli
# identity check).
#
# Delegates to _read_json_field so we do not grow two copies of the
# same JSON reader.
#
# Exit codes mirror _read_json_field:
#   0  — file missing, name mismatch, or file well-formed. Empty stdout
#        means "no version to emit from this file, and that's fine".
#   2  — file exists but its JSON is malformed. Callers use this signal
#        to distinguish a truly absent metadata file (skip silently)
#        from a present-but-corrupt one (record a discovery error).
_read_json_version() {
  local path="$1"
  local expected_name="${2:-}"
  if [[ -n "${expected_name}" ]]; then
    local actual_name rc
    actual_name="$(_read_json_field "${path}" "name")"
    rc=$?
    # Propagate malformed-JSON status. A name mismatch on a
    # well-formed file (rc 0, actual_name != expected_name) is a
    # legitimate "different package in the same tree" outcome and
    # stays rc 0 with empty stdout.
    if [[ ${rc} -eq 2 ]]; then
      return 2
    fi
    if [[ "${actual_name}" != "${expected_name}" ]]; then
      return 0
    fi
  fi
  _read_json_field "${path}" "version"
}

discover_agent_version() {
  local connector="$1"
  local home="$2"
  case "${connector}" in
    amp)
      # Amp's supported npm distribution is @ampcode/cli. Read only the
      # package metadata from known npm prefixes; never execute the user-owned
      # `amp` shim while this helper is running beneath a root LaunchDaemon.
      # Curl/native installs may not retain package metadata, in which case an
      # empty version is intentional and the connector contract decides
      # whether unversioned reconciliation is permitted.
      local pkg
      for pkg in \
        "${home}"/.npm-global/lib/node_modules/@ampcode/cli/package.json \
        "${home}"/.local/lib/node_modules/@ampcode/cli/package.json \
        /usr/local/lib/node_modules/@ampcode/cli/package.json \
        /opt/homebrew/lib/node_modules/@ampcode/cli/package.json; do
        [[ -f "${pkg}" ]] || continue
        local v; v="$(_probe_json_version "${pkg}" amp "@ampcode/cli")"
        if [[ -n "${v}" ]]; then echo "${v}"; return; fi
      done
      ;;
    codex)
      # Codex-cli is a Rust binary that ships from three OpenAI-owned
      # channels on macOS. Probe order picks the first-party
      # ChatGPT.app bundled copy FIRST because it is the newest
      # distribution (auto-updated with the desktop app) and it is
      # what customers actually have on a fresh Mac — stray old
      # `npm i -g @openai/codex` installs from an earlier engagement
      # frequently linger and would otherwise win with a stale
      # version that fails our MinAgentVersion contract gate.
      #
      # Order:
      #   1. ChatGPT.app bundled binary       (Codex 0.145.0+ current)
      #   2. Homebrew Caskroom                (versioned dir name)
      #   3. npm module package.json         (user-global then system)
      #   4. `command -v codex` last resort   (arbitrary PATH install)
      #
      # Every probe runs as the target user via sudo -u (not root).
      # The app bundle is Gatekeeper-signed and world-readable by
      # design; running its --version as an unprivileged user is
      # safe. install.sh's outer sudo already dropped privs before
      # calling this helper, matching the security posture of the
      # hook guardian's connector.Setup call.
      local vraw

      # 1. ChatGPT.app bundled codex — /Applications/ChatGPT.app/
      # Contents/Resources/codex is the current stable location; the
      # older MacOS/ path is kept as a fallback for pre-2026 builds.
      local chatgpt_codex
      for chatgpt_codex in \
        /Applications/ChatGPT.app/Contents/Resources/codex \
        /Applications/ChatGPT.app/Contents/MacOS/codex; do
        [[ -x "${chatgpt_codex}" ]] || continue
        if [[ -n "${DC_INSTALLER_TARGET_USER:-}" ]]; then
          vraw="$(sudo -n -u "${DC_INSTALLER_TARGET_USER}" "${chatgpt_codex}" --version 2>/dev/null | head -1 || true)"
        else
          vraw="$("${chatgpt_codex}" --version 2>/dev/null | head -1 || true)"
        fi
        # Codex prints "codex-cli X.Y.Z" (or "codex-cli X.Y.Z-alpha.N");
        # take the first token that looks like a version.
        vraw="$(printf '%s' "${vraw}" | awk '{for(i=NF;i>=1;i--) if ($i ~ /^[0-9]+\.[0-9]+/) {print $i; exit}}')"
        if [[ -n "${vraw}" ]]; then echo "${vraw}"; return; fi
      done

      # 2. Homebrew cask keeps the binary under Caskroom with a
      # version in the path itself:
      #   /opt/homebrew/Caskroom/codex/<version>/...
      # Glob-based version pick (avoids shellcheck SC2010 on ls|grep).
      local caskroom ver dir dname
      for caskroom in /opt/homebrew/Caskroom/codex /usr/local/Caskroom/codex; do
        [[ -d "${caskroom}" ]] || continue
        ver=""
        for dir in "${caskroom}"/*/; do
          [[ -d "${dir}" ]] || continue
          dname="$(basename "${dir}")"
          [[ "${dname}" =~ ^[0-9]+\.[0-9]+ ]] || continue
          if [[ -z "${ver}" ]] || \
             [[ "$(printf '%s\n%s\n' "${ver}" "${dname}" | sort -V | tail -1)" == "${dname}" ]]; then
            ver="${dname}"
          fi
        done
        if [[ -n "${ver}" ]]; then echo "${ver}"; return; fi
      done

      # 3. npm module package.json — user-global first (most likely
      # up to date on developer boxes), then system dirs.
      local pkg
      for pkg in \
        "${home}"/.npm-global/lib/node_modules/@openai/codex/package.json \
        /usr/local/lib/node_modules/@openai/codex/package.json \
        /opt/homebrew/lib/node_modules/@openai/codex/package.json; do
        [[ -f "${pkg}" ]] || continue
        local v; v="$(_probe_json_version "${pkg}" codex)"
        if [[ -n "${v}" ]]; then echo "${v}"; return; fi
      done

      # 4. Last resort: exec codex --version as the target user (not
      # as root). Requires TARGET_USER to be known to the caller.
      if [[ -n "${DC_INSTALLER_TARGET_USER:-}" ]] && command -v codex >/dev/null 2>&1; then
        local vraw
        vraw="$(_read_codex_version_as_user "${DC_INSTALLER_TARGET_USER}" || true)"
        # Codex prints "codex-cli X.Y.Z"; take just the version token.
        vraw="$(printf '%s' "${vraw}" | awk '{for(i=NF;i>=1;i--) if ($i ~ /^[0-9]+\.[0-9]+/) {print $i; exit}}')"
        if [[ -n "${vraw}" ]]; then echo "${vraw}"; return; fi
      fi
      ;;
    claudecode)
      # Claude Code ships both as a standalone npm CLI (has a
      # package.json we can read) and as a Cursor / VS Code extension.
      local pkg
      for pkg in \
        "${home}"/.npm-global/lib/node_modules/@anthropic-ai/claude-code/package.json \
        /usr/local/lib/node_modules/@anthropic-ai/claude-code/package.json \
        /opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/package.json \
        "${home}"/.cursor/extensions/anthropic.claude-code-*/package.json \
        "${home}"/.vscode/extensions/anthropic.claude-code-*/package.json; do
        [[ -f "${pkg}" ]] || continue
        local v; v="$(_probe_json_version "${pkg}" claudecode)"
        if [[ -n "${v}" ]]; then echo "${v}"; return; fi
      done
      ;;
    cursor)
      # Cursor.app is a signed macOS bundle; read the Info.plist rather
      # than exec'ing the binary. PlistBuddy is an Apple system tool.
      if [[ -f /Applications/Cursor.app/Contents/Info.plist ]]; then
        /usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" \
          /Applications/Cursor.app/Contents/Info.plist 2>/dev/null || true
      fi
      ;;
  esac
}

# ---- per-connector userspace prep --------------------------------------
#
# Each prepare_* writes the connector's native hook config file under HOME
# if missing. When a target UID/GID is supplied, creation and ownership are
# applied through already-open directory/file descriptors. This keeps the
# privileged installer from following a connector directory swapped by the
# target user between validation and chown.

ensure_safe_userspace_path() {
  local dir="$1"
  local cfg="$2"
  if [[ -L "${dir}" || -L "${cfg}" ]]; then
    return 1
  fi
  if [[ -e "${dir}" && ! -d "${dir}" ]]; then
    return 1
  fi
  mkdir -p "${dir}" || return 1
  if [[ -L "${dir}" || -L "${cfg}" ]]; then
    return 1
  fi
}

# create_userspace_config_if_missing DIR NAME [UID GID] -> reads initial bytes
# on stdin.
#
# The installer can run as root while DIR belongs to the target user. Anchor
# the final-component lookup and creation to an already-opened directory file
# descriptor so replacing DIR or NAME with a symlink cannot redirect a
# privileged write. Existing regular files are left untouched.
create_userspace_config_if_missing() {
  local dir="$1"
  local name="$2"
  local uid="${3:-}"
  local gid="${4:-}"
  local py
  py="$(command -v python3 || echo /usr/bin/python3)"
  "${py}" -c '
import os
import re
import stat
import sys

directory, name, uid_raw, gid_raw = sys.argv[1:]
if not name or name in {".", ".."} or os.path.basename(name) != name:
    raise SystemExit("invalid userspace config filename")
if bool(uid_raw) != bool(gid_raw):
    raise SystemExit("userspace config ownership requires both UID and GID")
if uid_raw:
    if re.fullmatch(r"[0-9]+", uid_raw) is None or re.fullmatch(r"[0-9]+", gid_raw) is None:
        raise SystemExit("userspace config UID/GID must be decimal integers")
    target_uid = int(uid_raw, 10)
    target_gid = int(gid_raw, 10)
else:
    target_uid = None
    target_gid = None

payload = sys.stdin.buffer.read(64 * 1024 + 1)
if len(payload) > 64 * 1024:
    raise SystemExit("userspace config template exceeds its size bound")

directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
directory_flags |= getattr(os, "O_NOFOLLOW", 0)
directory_fd = os.open(directory, directory_flags)
created = False
file_fd = -1
file_info = None
try:
    opened_directory = os.fstat(directory_fd)
    if not stat.S_ISDIR(opened_directory.st_mode):
        raise OSError("userspace config parent is not a directory")
    try:
        existing = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        existing = None
    if existing is not None:
        if not stat.S_ISREG(existing.st_mode):
            raise OSError("userspace config path is not a regular file")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        file_fd = os.open(name, flags, dir_fd=directory_fd)
        file_info = os.fstat(file_fd)
        if not stat.S_ISREG(file_info.st_mode) or not os.path.samestat(existing, file_info):
            raise OSError("userspace config changed while being opened")
    else:
        os.fchmod(directory_fd, 0o700)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        file_fd = os.open(name, flags, 0o600, dir_fd=directory_fd)
        created = True
        view = memoryview(payload)
        while view:
            written = os.write(file_fd, view)
            if written <= 0:
                raise OSError("short userspace config write")
            view = view[written:]
        os.fchmod(file_fd, 0o600)
        os.fsync(file_fd)
        file_info = os.fstat(file_fd)
        if not stat.S_ISREG(file_info.st_mode) or file_info.st_nlink != 1:
            raise OSError("created userspace config lost regular-file custody")

    if target_uid is not None:
        # Refuse to change ownership through a hard link: changing this inode
        # must affect only the named connector config under our open parent.
        if file_info.st_nlink != 1:
            raise OSError("userspace config must have exactly one link before ownership change")
        os.fchown(file_fd, target_uid, target_gid)
        os.fchown(directory_fd, target_uid, target_gid)
        os.fsync(file_fd)

    named_file = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if not stat.S_ISREG(named_file.st_mode) or not os.path.samestat(
        os.fstat(file_fd), named_file
    ):
        raise OSError("userspace config changed during preparation")

    current_directory = os.lstat(directory)
    if stat.S_ISLNK(current_directory.st_mode) or not os.path.samestat(
        opened_directory, current_directory
    ):
        raise OSError("userspace config parent changed during creation")
    os.fsync(directory_fd)
except BaseException:
    if created:
        try:
            named_file = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if file_fd >= 0 and os.path.samestat(os.fstat(file_fd), named_file):
                os.unlink(name, dir_fd=directory_fd)
                os.fsync(directory_fd)
        except OSError:
            pass
    raise
finally:
    if file_fd >= 0:
        os.close(file_fd)
    os.close(directory_fd)
' "${dir}" "${name}" "${uid}" "${gid}"
}

prepare_codex_userspace() {
  local home="$1"
  local uid="${2:-}"
  local gid="${3:-}"
  local dir="${home}/.codex"
  local cfg="${home}/.codex/config.toml"
  ensure_safe_userspace_path "${dir}" "${cfg}" || return 1
  create_userspace_config_if_missing "${dir}" "config.toml" "${uid}" "${gid}" <<'TOML'
# Created by DefenseClaw installer so the enterprise hook guardian can
# repair this file. Edit freely; DefenseClaw only owns [hooks], [otel],
# and the top-level notify entries.
TOML
}

prepare_claudecode_userspace() {
  local home="$1"
  local uid="${2:-}"
  local gid="${3:-}"
  local dir="${home}/.claude"
  local cfg="${home}/.claude/settings.json"
  ensure_safe_userspace_path "${dir}" "${cfg}" || return 1
  printf '{}\n' | create_userspace_config_if_missing "${dir}" "settings.json" "${uid}" "${gid}"
}

prepare_cursor_userspace() {
  local home="$1"
  local uid="${2:-}"
  local gid="${3:-}"
  local dir="${home}/.cursor"
  local cfg="${home}/.cursor/hooks.json"
  ensure_safe_userspace_path "${dir}" "${cfg}" || return 1
  printf '{"version":1,"hooks":{}}\n' | create_userspace_config_if_missing "${dir}" "hooks.json" "${uid}" "${gid}"
}

prepare_userspace_for() {
  local connector="$1"
  local home="$2"
  local uid="${3:-}"
  local gid="${4:-}"
  case "${connector}" in
    # Amp's hook is a managed TypeScript plugin. The connector reconciliation
    # owns creating ~/.config/amp/plugins/defenseclaw.ts together with its
    # backup metadata; this packaging helper must never precreate a placeholder
    # file that would be mistaken for user state.
    amp)        : ;;
    codex)      prepare_codex_userspace      "${home}" "${uid}" "${gid}";;
    claudecode) prepare_claudecode_userspace "${home}" "${uid}" "${gid}";;
    cursor)     prepare_cursor_userspace     "${home}" "${uid}" "${gid}";;
  esac
}

# ---- local-user enumeration --------------------------------------------

# _enumerate_users_warn — internal helper that emits a per-filter drop
# reason when DC_INSTALLER_ENUMERATE_VERBOSE=1. install.sh flips this on
# so its install.log records why user X was excluded from targets.yaml;
# unit tests leave it off so the sourced-library harness stays quiet.
_enumerate_users_warn() {
  [[ "${DC_INSTALLER_ENUMERATE_VERBOSE:-}" == "1" ]] || return 0
  printf '[install] WARN: enumerate_local_users skipping %s: %s\n' "$1" "$2" >&2
}

# enumerate_local_users -> stdout, one line per eligible user in the form:
#   user:uid:gid:home
#
# Filters: UID >= 500, username does not start with `_`, home under /Users/,
# home is a real directory (not a symlink), and home_perms_ok passes.
# Reads OpenDirectory via dscl — same pattern the fresh-install preflight in
# install.sh already uses (see the block that gates on _existing_install_markers).
#
# Pure: no writes, no sudo. When DC_INSTALLER_ENUMERATE_VERBOSE=1 each
# filter drop emits a WARN on stderr so install.log captures why a
# specific user was excluded. Off by default (tests source this library
# and would otherwise emit spurious warns).
enumerate_local_users() {
  local names name uid gid home
  names="$(dscl . -list /Users UniqueID 2>/dev/null)" || {
    _enumerate_users_warn "(all users)" "dscl . -list /Users UniqueID failed — cannot enumerate local users"
    return 0
  }
  # dscl output is "user   uid". Filter and normalize in one pass.
  while IFS= read -r line; do
    name="$(printf '%s' "${line}" | awk '{print $1}')"
    uid="$(printf '%s' "${line}" | awk '{print $2}')"
    if [[ -z "${name}" || -z "${uid}" ]]; then
      _enumerate_users_warn "${name:-?}" "dscl row is missing name or uid: '${line}'"
      continue
    fi
    # Filter system accounts.
    case "${name}" in
      _*|daemon|nobody|root)
        _enumerate_users_warn "${name}" "system account (name matches system-user pattern)"
        continue;;
    esac
    if ! [[ "${uid}" =~ ^[0-9]+$ ]]; then
      _enumerate_users_warn "${name}" "uid '${uid}' is not numeric"
      continue
    fi
    if (( uid < 500 )); then
      _enumerate_users_warn "${name}" "uid ${uid} is below the local-user threshold (500)"
      continue
    fi

    home="$(dscl . -read "/Users/${name}" NFSHomeDirectory 2>/dev/null | sed -n 's/^NFSHomeDirectory: //p')"
    if [[ -z "${home}" ]]; then
      _enumerate_users_warn "${name}" "NFSHomeDirectory is empty in Open Directory"
      continue
    fi
    if [[ "${home}" != /Users/* ]]; then
      _enumerate_users_warn "${name}" "home '${home}' is not under /Users/ (network / mobile / MDM account)"
      continue
    fi
    if [[ ! -d "${home}" ]]; then
      _enumerate_users_warn "${name}" "home '${home}' is not a directory (may not be mounted)"
      continue
    fi
    if [[ -L "${home}" ]]; then
      _enumerate_users_warn "${name}" "home '${home}' is a symlink — refusing to follow"
      continue
    fi
    if ! home_perms_ok "${home}"; then
      local _mode
      _mode="$(stat -f '%Lp' "${home}" 2>/dev/null || stat -c '%a' "${home}" 2>/dev/null || echo '?')"
      _enumerate_users_warn "${name}" "home '${home}' is group/other writable (mode ${_mode}) — hook guardian will refuse"
      continue
    fi

    gid="$(dscl . -read "/Users/${name}" PrimaryGroupID 2>/dev/null | sed -n 's/^PrimaryGroupID: //p')"
    [[ "${gid}" =~ ^[0-9]+$ ]] || gid="20"

    printf '%s:%s:%s:%s\n' "${name}" "${uid}" "${gid}" "${home}"
  done <<< "${names}"
}

# ---- targets.yaml rendering --------------------------------------------

# render_targets_manifest SUPPORT_DIR CONNECTORS_CSV USER_LINES -> stdout
#
# Renders the hook-guardian manifest (`targets.yaml`) consumed by the
# `enterprise hooks reconcile` command. Schema mirrors ManifestTarget in
# internal/enterprisehooks/manifest.go.
#
# Args:
#   SUPPORT_DIR    e.g. /opt/cisco/secureclient/defenseclaw
#   CONNECTORS_CSV comma-separated list of connectors (e.g. amp,codex,claudecode,cursor)
#   USER_LINES     newline-separated user:uid:gid:home lines (as produced by
#                  enumerate_local_users)
#
# One `- ` block per (user × supported-and-installed connector).
# Unsupported connectors (not in is_supported_connector) are skipped: they
# have no per-user setup path in the CLI. Connectors the caller asked for
# but which discover_agent_version could not locate on THIS user's home
# ARE ALSO skipped — no CLI/app/extension present means there is nothing
# to hook, and emitting the row would just churn the guardian with a
# permanent "agent_version empty" failure per tick. Users who install the
# connector later are picked up by the hook-enumerator's next re-render.
yaml_double_quoted_scalar() {
  local value="$1"
  case "${value}" in
    *$'\n'*|*$'\r'*|*$'\t'*) return 1;;
  esac
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '"%s"' "${value}"
}

render_targets_manifest() {
  local support_dir="$1"
  local connectors_csv="$2"
  local user_lines="$3"
  local runtime_dir="${support_dir}/runtime"

  local -a connectors=()
  local c
  while IFS= read -r c; do
    [[ -z "${c}" ]] && continue
    connectors+=("${c}")
  done < <(parse_connectors "${connectors_csv}" 2>/dev/null || true)

  printf 'version: 1\n'
  printf 'targets:\n'

  if [[ ${#connectors[@]} -eq 0 ]]; then
    return 0
  fi
  if [[ -z "${user_lines}" ]]; then
    return 0
  fi

  local line name uid gid home ver q_name q_home q_connector q_ver
  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    name="${line%%:*}"
    local rest="${line#*:}"
    uid="${rest%%:*}"
    rest="${rest#*:}"
    gid="${rest%%:*}"
    home="${rest#*:}"
    [[ -n "${name}" && -n "${uid}" && -n "${gid}" && -n "${home}" ]] || continue
    q_name="$(yaml_double_quoted_scalar "${name}")" || continue
    q_home="$(yaml_double_quoted_scalar "${home}")" || continue

    for c in "${connectors[@]}"; do
      is_supported_connector "${c}" || continue
      q_connector="$(yaml_double_quoted_scalar "${c}")" || continue
      ver="$(DC_INSTALLER_TARGET_USER="${name}" discover_agent_version "${c}" "${home}" 2>/dev/null || true)"
      [[ -n "${ver}" ]] || continue
      q_ver="$(yaml_double_quoted_scalar "${ver}")" || q_ver='""'
      # data_dir is intentionally omitted from each target block: the
      # guardian's validateUserDataDir requires the data_dir to be inside
      # the target user's home (internal/enterprisehooks/installer.go),
      # but ${runtime_dir} is machine-wide root storage under SUPPORT_DIR.
      # Letting the Install() layer default to ~/.defenseclaw per user is
      # correct — that is where the connector's hook script and scoped
      # token per-user artifacts live.
      cat <<EOF
  - user: ${q_name}
    user_home: ${q_home}
    uid: ${uid}
    gid: ${gid}
    connector: ${q_connector}
    agent_version: ${q_ver}
    enabled: true
EOF
    done
  done <<< "${user_lines}"
}

# ---- config rendering --------------------------------------------------

# aid_endpoint_for_env ENV -> stdout
# Maps the installer's --env flag to the AI Defense cloud host that
# defenseclaw's managed CMID inspection client will target. The daemon
# appends the fixed /api/v1/inspect/defense_claw path itself; this
# helper only supplies the host.
#
# Kept as a pure-bash lookup so tests can exercise it without depending
# on the AID cloud being reachable. Adding a new environment is a
# one-line change here + a new case in the outer arg validator.
aid_endpoint_for_env() {
  local env="$1"
  case "${env}" in
    prod)    echo "https://us.api.inspect.aidefense.security.cisco.com";;
    preview) echo "https://preview.api.inspect.aidefense.aiteam.cisco.com";;
    *)       return 1;;
  esac
}

# resolve_aid_endpoint ENV OVERRIDE -> stdout effective endpoint
#
# When OVERRIDE is non-empty it wins over ENV: this is the --override-endpoint
# validation seam that lets an operator point the managed daemon at another
# AI Defense origin (e.g. a personal preview tenant) without adding a new
# --env case. The override uses the same bare-origin boundary as the v8 managed
# destination: HTTPS, a non-empty host, an optional valid TCP port, and no
# userinfo, path, query, fragment, whitespace, quote, or backslash. A single
# trailing slash is accepted and stripped for consistent path joining.
#
# Return codes let the caller emit a precise error:
#   0 - success (endpoint on stdout)
#   1 - unknown ENV (and no override) — invalid --env
#   2 - override supplied but malformed — invalid --override-endpoint
#
# Kept pure (stdout only, no warn/log) so tests can exercise precedence and
# validation without the AID cloud being reachable.
resolve_aid_endpoint() {
  local env="$1"
  local override="$2"
  if [[ -n "${override}" ]]; then
    # Keep this dependency-free and compatible with the Bash 3.2 shipped by
    # macOS. Validation deliberately happens before root/preflight checks in
    # install.sh so a rejected endpoint cannot mutate an existing host.
    [[ ${#override} -le 2048 ]] || return 2
    [[ "${override}" == https://* ]] || return 2
    [[ ! "${override}" =~ [[:space:]] ]] || return 2
    [[ "${override}" != *'"'* && "${override}" != *"'"* && "${override}" != *'\'* ]] || return 2

    local authority="${override#https://}"
    [[ -n "${authority}" ]] || return 2
    [[ "${authority}" != *'?'* && "${authority}" != *'#'* && "${authority}" != *'@'* ]] || return 2

    # Only the root slash is accepted. Strip it before validating authority;
    # any remaining slash is a source-controlled path and must fail closed.
    if [[ "${authority}" == */ ]]; then
      authority="${authority%/}"
    fi
    [[ -n "${authority}" && "${authority}" != */* ]] || return 2

    local host="" port="" remainder="" colonless="" has_port="false"
    if [[ "${authority}" == \[* ]]; then
      # Bracketed host (normally IPv6). Match net/url's origin shape: require
      # one closing bracket and permit only an optional :port after it.
      [[ "${authority}" == *']'* ]] || return 2
      host="${authority#\[}"
      host="${host%%\]*}"
      remainder="${authority#*\]}"
      [[ -n "${host}" ]] || return 2
      [[ "${host}" =~ ^[0-9A-Fa-f:.]+$ ]] || return 2
      case "${remainder}" in
        "") ;;
        :*) port="${remainder#:}"; has_port="true" ;;
        *) return 2 ;;
      esac
      [[ "${host}" != *'['* && "${host}" != *']'* ]] || return 2
    else
      [[ "${authority}" != *'['* && "${authority}" != *']'* ]] || return 2
      colonless="${authority//:/}"
      # An unbracketed host can contain at most the one host/port separator.
      (( ${#authority} - ${#colonless} <= 1 )) || return 2
      if [[ "${authority}" == *:* ]]; then
        host="${authority%%:*}"
        port="${authority#*:}"
        has_port="true"
      else
        host="${authority}"
      fi
      [[ -n "${host}" ]] || return 2
      [[ "${host}" =~ ^[A-Za-z0-9.-]+$ ]] || return 2
    fi

    if [[ "${has_port}" == "true" ]]; then
      [[ -n "${port}" && "${port}" =~ ^[0-9]+$ ]] || return 2
      # Strip leading zeroes before the arithmetic comparison so Bash does
      # not interpret a value such as 0443 as octal.
      while [[ ${#port} -gt 1 && "${port}" == 0* ]]; do
        port="${port#0}"
      done
      [[ ${#port} -le 5 ]] || return 2
      (( port >= 1 && port <= 65535 )) || return 2
    fi

    printf '%s\n' "${override%/}"
    return 0
  fi
  aid_endpoint_for_env "${env}"
}

# move_legacy_aside PATH BACKUP_ROOT VERSION [--dry-run] -> stdout log message.
#
# Idempotent installer helper for the "reconcile in place" path: relocate a
# legacy DefenseClaw location under BACKUP_ROOT with a
# .pre-<version>-<timestamp> suffix instead of deleting it. Missing PATH is a
# no-op; missing BACKUP_ROOT returns rc 3; a symlinked BACKUP_ROOT returns rc 4
# (mv into a symlink would follow the link). Callers get preserved rollback
# state and a fresh install landing zone without touching user data.
move_legacy_aside() {
  local path="$1" backup_root="$2" version="$3"
  shift 3
  local dry_run="false"
  local arg
  for arg in "$@"; do
    case "${arg}" in
      --dry-run) dry_run="true";;
      *) return 2;;
    esac
  done

  if [[ -z "${path}" || -z "${backup_root}" || -z "${version}" ]]; then
    return 2
  fi

  # Reject a version string that could path-traverse the target. version
  # flows into ${target}=${backup_root}/${base}.pre-${version}-${timestamp}
  # verbatim; a version containing '/' or '..' (e.g. a malformed
  # --version output captured unsanitized) would escape the backup_root.
  # Whitespace and shell metacharacters are also refused so `printf` /
  # `mv` cannot be steered by callers that failed to trim their input.
  if [[ "${version}" == */* || "${version}" == *".."* ]] \
      || [[ "${version}" =~ [[:space:][:cntrl:]\"\'\\\$\`\;\|\&\<\>] ]]; then
    return 2
  fi

  if [[ ! -e "${path}" && ! -L "${path}" ]]; then
    return 0
  fi

  # Reject a symlinked BACKUP_ROOT outright — mv into a symlink
  # target would follow the link and relocate legacy state into
  # whatever the symlink points at.
  if [[ -L "${backup_root}" ]]; then
    return 4
  fi

  local base timestamp target
  base="$(basename -- "${path}")"
  timestamp="$(date -u +%Y%m%dT%H%M%SZ 2>/dev/null || echo "unknown")"
  target="${backup_root}/${base}.pre-${version}-${timestamp}"

  if [[ "${dry_run}" == "true" ]]; then
    printf '[install] would move legacy path aside: %s -> %s\n' "${path}" "${target}"
    return 0
  fi

  if [[ ! -d "${backup_root}" ]]; then
    return 3
  fi

  # Collision suffix in case of same-second re-runs.
  local suffix=""
  local i
  for (( i = 0; i < 100; i++ )); do
    if [[ ! -e "${target}${suffix}" && ! -L "${target}${suffix}" ]]; then
      break
    fi
    suffix=".${i}"
  done
  target="${target}${suffix}"

  if ! /bin/mv -- "${path}" "${target}" 2>/dev/null; then
    return 4
  fi
  printf '[install] moved legacy path aside: %s -> %s\n' "${path}" "${target}"
  return 0
}

# render_config MODE PRIMARY API_PORT SUPPORT_DIR AID_ENDPOINT CONN... -> stdout
# Renders the full config.yaml. Pure stdout, no file writes.
# Extra args after AID_ENDPOINT are the full connector list (primary + others).
#
# SUPPORT_DIR is the module root under the managed install tree
# (/opt/cisco/secureclient/defenseclaw). config.yaml sits under
# SUPPORT_DIR/etc/config.yaml (root:wheel 0640). The managed_enterprise
# trust check walks every ancestor of config.yaml and refuses
# group-writable or non-root ancestors — the shipped layout is
# root:wheel 0755 all the way up, so it passes. Runtime state (audit
# DB, tokens, guardian state) lives in ${SUPPORT_DIR}/runtime; on the
# root-mode daemon everything under SUPPORT_DIR is root-owned.
#
# AID_ENDPOINT is the fully-qualified host (with scheme) that the
# managed CiscoDefenseClawInspectClient will target — produced by
# aid_endpoint_for_env. Empty is not accepted; if callers do not want
# remote inspection they should not run in managed_enterprise mode.
render_config() {
  local mode="$1"
  local primary="$2"
  local api_port="$3"
  local support_dir="$4"
  local aid_endpoint="$5"
  shift 5
  # Positional arg 6 is the number of home_dirs entries to consume next
  # (the new managed-inventory shape). The remaining args are connector
  # names. Legacy callers omit the count and pass connector names
  # directly; those still work because a non-numeric first-remaining
  # arg leaves home_dirs empty and treats every arg as a connector.
  local home_dirs_count=0
  local -a home_dirs=()
  if [[ "${1:-}" =~ ^[0-9]+$ ]]; then
    home_dirs_count="$1"
    shift
    local _idx
    for (( _idx = 0; _idx < home_dirs_count; _idx++ )); do
      # Stop early if the caller's declared count exceeds the number of
      # remaining positional args; a missing path would otherwise inject an
      # empty entry that violates the config schema's minLength:1 constraint.
      (( $# > 0 )) || break
      [[ -n "$1" ]] && home_dirs+=("$1")
      shift
    done
    unset _idx
  fi
  local -a connectors=("$@")
  local runtime_dir="${support_dir}/runtime"

  cat <<EOF
config_version: 8
deployment_mode: managed_enterprise

data_dir: "${runtime_dir}"

observability:
  local:
    path: "${runtime_dir}/audit.db"
    judge_bodies_path: "${runtime_dir}/judge_bodies.db"
  # Managed installs retain the previous secure-by-default behavior. To
  # change redaction, edit this profile (or add per-bucket overrides) and
  # validate the complete v8 source before restarting the daemon.
  defaults:
    redaction_profile: sensitive

gateway:
  api_bind: 127.0.0.1
  api_port: ${api_port}
  # Pin device_key_file into RUNTIME_DIR rather
  # than letting the Go defaults compute it from DEFENSECLAW_HOME. The
  # plist sets DEFENSECLAW_HOME to SUPPORT_DIR so managed_enterprise
  # trust checks accept every ancestor of config.yaml. Keeping mutable
  # runtime state below the dedicated runtime directory also preserves
  # the root-owned managed-install layout.
  device_key_file: "${runtime_dir}/device.key"
  # The skill/plugin/MCP watcher periodically re-scans agent component
  # directories and invokes the 'defenseclaw' python scanner binary.
  # In this managed_enterprise rollout we rely on AID cloud + local
  # regex as the only content classifiers (see mergeVerdict /
  # demoteLocalBlockForManaged in internal/gateway/guardrail.go); the
  # watcher would otherwise fail-close every plugin operation when the
  # python scanner isn't installed, and none of its verdicts feed into
  # the enforced action path we're building. Turn it off.
  watcher:
    enabled: false

guardrail:
  enabled: true
  mode: ${mode}
  scanner_mode: both
  # regex_only skips the LLM-judge routing; adjudication burns cycles
  # and we don't ship an LLM key on managed installs.
  detection_strategy: regex_only
  judge:
    enabled: false
  connector: ${primary}
EOF

  if (( ${#connectors[@]} > 1 )); then
    echo "  connectors:"
    local c
    for c in "${connectors[@]}"; do
      cat <<EOF
    ${c}:
      enabled: true
      mode: ${mode}
EOF
    done
  fi

  cat <<EOF

# In managed_enterprise mode the gateway authenticates AI Defense
# inspection with a bearer token sourced from the managed cloud auth
# provider. The daemon calls
# ${aid_endpoint}/api/v1/inspect/defense_claw with Authorization: Bearer
# <token>. The endpoint is installer-set; --env selects which AID cloud
# environment to target. See internal/gateway/cisco_inspect_defense_claw.go
# and internal/managed/cloudreg for the client-side implementation.
cisco_ai_defense:
  endpoint: "${aid_endpoint}"

# Continuous AI discovery (endpoint inventory). Enabled in managed_enterprise
# so the sidecar scans for supported connectors and broader "shadow AI" usage
# signals. Observability v8 sends those observations through its canonical
# runtime and configured destinations; the removed v7 emit_otel switch is not
# restored. Other ai_discovery.* keys keep their built-in defaults (mode
# enhanced, scan intervals). The scanner is a no-op unless enabled, so this
# block is required for endpoint inventory to flow.
#
# home_dirs is populated from the same enumerate_local_users filter that
# renders targets.yaml so per-user detectors (~/.claude/skills, ~/.codex/*,
# etc.) resolve to every eligible local user's home — not just the daemon's
# HOME (/var/root under root, which has no operator agent state).
ai_discovery:
  enabled: true
EOF

  if (( ${#home_dirs[@]} > 0 )); then
    echo "  home_dirs:"
    local h
    local quoted_home
    for h in "${home_dirs[@]}"; do
      # yaml_double_quoted_scalar performs the same escaping the rest of
      # this file relies on for user-supplied strings — inserting `h` raw
      # inside `"..."` would let a `\` or `"` in a legitimate home path
      # produce invalid YAML or a subtly different path.
      quoted_home="$(yaml_double_quoted_scalar "${h}")" || return 1
      printf '    - %s\n' "${quoted_home}"
    done
  fi

  cat <<EOF

# asset_policy is intentionally disabled in this managed_enterprise
# rollout. The AID cloud is the single authoritative source of block
# verdicts on this branch; asset_policy's mcp/skill/plugin allow-lists
# and the component (plugin) scanner it feeds would compete with the
# cloud's classification and (in the plugin case) fail-close every
# request when the 'defenseclaw' python plugin-scanner isn't installed.
# See internal/gateway/guardrail.go: mergeVerdict + demoteLocalBlockForManaged
# for the analogous local-pattern demotion, and the installer PR notes
# for the full "which sources enforce" decision matrix.
asset_policy:
  enabled: false

application_protection:
  enabled: false
EOF
}

# apply_ai_discovery_home_dirs CONFIG_PATH USER_LINES -> exit 0 on success
#
# Replaces the ai_discovery.home_dirs block in a rendered config.yaml
# with one entry per user home in USER_LINES (newline-delimited
# user:uid:gid:home rows, the same format enumerate_local_users emits).
#
# The initial render_config output contains a single placeholder entry
# under ai_discovery.home_dirs (see `__DEFENSECLAW_HOME_DIRS_PLACEHOLDER__`
# above); on first install the installer calls this helper right after
# render_config so the config that lands on disk already has the right
# list. On every subsequent enumerator tick, render-targets.sh calls
# this helper again with the current user set — same in-place block
# replace, atomic mv-if-changed so callers can no-op when the list
# hasn't moved.
#
# When USER_LINES is empty the block collapses to `home_dirs: []` so
# the Go side falls back to $HOME. That is still wrong on a
# root-launched daemon (leaves discovery blind), so callers should
# treat empty enumeration as a warning; the file remains valid YAML.
#
# Idempotent: two calls with the same input produce the same on-disk
# bytes.
apply_ai_discovery_home_dirs() {
  local config_path="$1"
  local user_lines="$2"

  if [[ ! -f "${config_path}" ]]; then
    printf 'apply_ai_discovery_home_dirs: config not found: %s\n' "${config_path}" >&2
    return 1
  fi

  # Resolve chained symlinks up-front so every downstream mktemp /
  # atomic rename lands in the CONCRETE target's directory (not the
  # link's parent dir on a different filesystem). rename(2) is atomic
  # only within a single filesystem; a temp file in ~/.dotfiles/…
  # renamed over a target under /Volumes/other-fs/… would fail with
  # EXDEV. Resolving the whole chain before we create the temp files
  # keeps the swap on the same fs as the concrete target.
  #
  # Bounded loop (max 16 hops, matching Linux MAXSYMLINKS) guards
  # against symlink cycles. On a resolution error or cycle we fall
  # back to the last resolvable path, and downstream mv will surface
  # a concrete errno the operator can act on.
  local target="${config_path}"
  local __hop
  for __hop in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do
    [[ -L "${target}" ]] || break
    local __link
    __link="$(readlink -- "${target}" 2>/dev/null || true)"
    if [[ -z "${__link}" ]]; then break; fi
    case "${__link}" in
      /*) target="${__link}" ;;
      *)  target="$(dirname -- "${target}")/${__link}" ;;
    esac
  done
  # If the resolved target is missing (broken symlink) fail loudly —
  # we cannot safely mint a temp beside a path that doesn't exist.
  if [[ ! -e "${target}" ]]; then
    printf 'apply_ai_discovery_home_dirs: config path %s resolves to missing target: %s\n' "${config_path}" "${target}" >&2
    return 1
  fi

  # Collect homes from user_lines. Skip empty rows so the newline at
  # end of a heredoc-produced list doesn't produce a phantom entry.
  local -a homes=()
  local line home
  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    home="${line##*:}"
    [[ -z "${home}" ]] && continue
    homes+=("${home}")
  done <<< "${user_lines}"

  # Build the replacement block. Two-space indent under ai_discovery,
  # four-space indent for list entries — matches render_config's shape.
  local block=""
  if (( ${#homes[@]} == 0 )); then
    block=$'  home_dirs: []\n'
  else
    block=$'  home_dirs:\n'
    for home in "${homes[@]}"; do
      # Quote to survive any home path containing spaces (rare on macOS
      # but real on network-mounted homes). No home path on macOS should
      # contain a literal double-quote, but escape defensively.
      home="${home//\"/\\\"}"
      block+="    - \"${home}\""$'\n'
    done
  fi

  # All tempfiles below live in the concrete target's directory so
  # the final rename(2) is a same-filesystem atomic swap.
  local tmp
  tmp="$(mktemp "${target}.hd.XXXXXX")" || return 1
  # Rewrite the ai_discovery block with awk (no external runtime dep):
  #   - find `ai_discovery:` line
  #   - keep `enabled: true` and any other scalar children
  #   - drop the old home_dirs block (list or scalar or placeholder)
  #   - inject the new block right after the ai_discovery: header
  # The block is emitted from awk via a token marker so we can inject
  # it AFTER awk exits with a single printf — BSD awk does not accept
  # embedded newlines in a `-v NAME=<multiline>` initialiser.
  # Non-zero rc bubbles up so the caller's atomic-swap semantics stay
  # intact.
  local marker='__DEFENSECLAW_HOME_DIRS_INJECT__'
  awk -v MARKER="${marker}" '
    function is_ws(c) { return c == " " || c == "\t" }
    function leading_ws_len(s,    n, i, c) {
      n = 0
      for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1)
        if (is_ws(c)) n++
        else break
      }
      return n
    }
    function strip(s) { sub(/^[ \t]+/, "", s); sub(/[ \t\r]+$/, "", s); return s }
    BEGIN {
      in_ai = 0
      seen_ai = 0
      consuming_home = 0
      home_indent_len = 0
      # direct_child_indent records the indentation depth of the FIRST
      # direct child of `ai_discovery:` we see; this is the level a
      # legitimate `home_dirs:` key lives at. A `home_dirs:` deeper
      # than direct_child_indent (say `ai_discovery.source.home_dirs`)
      # is an operator-added nested sub-map, not our top-level list —
      # preserve it verbatim. Zero means we have not seen a child yet.
      direct_child_indent = 0
    }
    {
      line = $0
      if (!in_ai) {
        if (line ~ /^ai_discovery:[ \t]*$/) {
          print line
          in_ai = 1
          seen_ai = 1
          # Emit a one-line marker after the header; a follow-up sed
          # pass replaces the marker with the freshly-rendered block.
          # This detour avoids passing multi-line data through
          # `awk -v` — BSD awk rejects embedded newlines in -v args.
          print MARKER
          direct_child_indent = 0
          next
        }
        print line
        next
      }
      # inside ai_discovery block ---------------------------------------
      stripped = strip(line)
      if (consuming_home) {
        if (stripped == "") { next }              # swallow blank line inside old block
        this_indent = leading_ws_len(line)
        if (this_indent > home_indent_len) { next } # nested list entry / comment
        consuming_home = 0
        # fall through to normal handling
      }
      # Non-indented (or empty line at top-level) -> ai_discovery block ends.
      if (stripped == "") { print line; next }
      first_char = substr(line, 1, 1)
      if (!is_ws(first_char)) {
        in_ai = 0
        print line
        next
      }
      this_indent = leading_ws_len(line)
      # Record the direct-child indent from the first child line we
      # see. render_config emits two-space YAML, so this is normally
      # 2 — but honor whatever the actual file uses so hand-edited
      # configs with a different indent still work.
      if (direct_child_indent == 0) direct_child_indent = this_indent
      # home_dirs child: drop entirely BUT ONLY at the direct-child
      # indent. A deeper `home_dirs:` under an operator-added subkey
      # (`ai_discovery.source.home_dirs`, `ai_discovery.overrides.
      # home_dirs`, …) belongs to that nested map and MUST be
      # preserved. Matching `home_dirs:` at any depth would silently
      # eat that user state on every reconcile tick.
      #
      # `home_dirs:` at direct-child indent with an empty tail means a
      # possibly-multi-line list follows — enter consuming_home mode
      # to swallow every deeper-indented line until the next same- or
      # lesser-indented sibling. BSD awk (macOS) does not support
      # gawk-style match(..., array); use a regex-then-substr split.
      if (this_indent == direct_child_indent && line ~ /^[ \t]+home_dirs:[ \t]*/) {
        home_indent_len = this_indent
        colon_pos = index(line, ":")
        tail = strip(substr(line, colon_pos + 1))
        if (tail == "") consuming_home = 1
        next
      }
      # Any other ai_discovery child (including a nested `home_dirs:`
      # under a deeper sub-map): preserve verbatim.
      print line
    }
    END {
      # A config.yaml without an `ai_discovery:` block is a real
      # anomaly on managed_enterprise: render_config always emits one
      # (see the ai_discovery: header render further up). Missing it
      # implies (a) an operator hand-edited the file and removed the
      # block, or (b) the config predates the block. In either case
      # the reconcile call silently returning "unchanged" would leave
      # the daemon blind to per-user home dirs — surface the anomaly
      # with a distinct exit code the caller maps to a loud error.
      if (!seen_ai) exit 3
    }
  ' "${target}" > "${tmp}"
  local rc=$?
  if (( rc == 3 )); then
    rm -f -- "${tmp}"
    printf 'apply_ai_discovery_home_dirs: no ai_discovery: block in %s (config predates ai_discovery or was hand-edited); refusing to silently succeed\n' "${config_path}" >&2
    return 1
  fi
  if (( rc != 0 )); then
    rm -f -- "${tmp}"
    return "${rc}"
  fi
  # Replace the one-line marker with the freshly-rendered block.
  # A sed-based swap would need metacharacter escaping across GNU/BSD
  # variants for a payload that legitimately contains forward slashes
  # (home paths) and other regex-active characters. Do it in a second
  # awk pass that reads the block from a scratch file — this dodges
  # both the sed-escaping problem and the "awk -v cannot hold embedded
  # newlines" BSD limitation.
  local block_file tmp2
  block_file="$(mktemp "${target}.hd-block.XXXXXX")" || { rm -f -- "${tmp}"; return 1; }
  printf '%s' "${block}" > "${block_file}"
  tmp2="$(mktemp "${target}.hd2.XXXXXX")" || { rm -f -- "${tmp}" "${block_file}"; return 1; }
  awk -v MARKER="${marker}" -v BLOCK_FILE="${block_file}" '
    BEGIN {
      block = ""
      while ((getline line < BLOCK_FILE) > 0) {
        block = block line "\n"
      }
      close(BLOCK_FILE)
    }
    $0 == MARKER { printf "%s", block; next }
    { print }
  ' "${tmp}" > "${tmp2}"
  rc=$?
  rm -f -- "${tmp}" "${block_file}"
  if (( rc != 0 )); then
    rm -f -- "${tmp2}"
    return "${rc}"
  fi
  tmp="${tmp2}"

  # Preserve mode + ownership from the existing target, then atomic-swap
  # only when the content actually changed so downstream reload
  # heuristics that watch mtime aren't triggered on a no-op tick.
  # `--reference` is a GNU coreutils extension not available on macOS
  # `chown`/`chmod`; the fallback uses `stat -f` to read the target's
  # existing owner/mode and re-apply them via the string form.
  #
  # Both fallbacks are gated on `[[ -e target ]]` so a target that
  # vanished between the resolve step and this block (rare, but a
  # concurrent unlink race is possible on shared home dirs) does not
  # abort under `set -e` when `stat -f` returns an empty string that
  # chown/chmod would then choke on. The `chown --reference` /
  # `chmod --reference` GNU variants short-circuit the fallback via
  # ||, so on Linux we never reach the guarded branch.
  if ! chown --reference="${target}" "${tmp}" 2>/dev/null; then
    if [[ -e "${target}" ]]; then
      chown "$(stat -f '%Su:%Sg' "${target}")" "${tmp}"
    fi
  fi
  if ! chmod --reference="${target}" "${tmp}" 2>/dev/null; then
    if [[ -e "${target}" ]]; then
      chmod "$(stat -f '%A' "${target}")" "${tmp}"
    fi
  fi

  if cmp -s "${tmp}" "${target}"; then
    rm -f -- "${tmp}"
    return 0
  fi
  # Check /bin/mv exit status so a rename failure (permissions,
  # cross-fs EXDEV — should not happen given the upfront symlink
  # resolution, but defense-in-depth — or a concurrent unlink) never
  # silently reports success. On failure remove the temp and return
  # non-zero. The explicit `return 0` after sync stops the function
  # from returning `sync`'s exit status as its own; `sync` is
  # best-effort and its rc must not decide the swap's outcome.
  #
  # Capture `mv`'s exit status BEFORE using it in the printf: an
  # `if ! /bin/mv …; then … $? …` chain resolves `$?` to the negated
  # test's status (always 0 in the taken branch) — the original
  # non-zero code from mv would be lost. Store it in `mv_rc` at the
  # invocation site so the diagnostic reports the real errno bucket.
  local mv_rc=0
  /bin/mv -f -- "${tmp}" "${target}" || mv_rc=$?
  if (( mv_rc != 0 )); then
    printf 'apply_ai_discovery_home_dirs: rename %s -> %s failed (rc=%d)\n' "${tmp}" "${target}" "${mv_rc}" >&2
    rm -f -- "${tmp}"
    return 1
  fi
  # Endpoint-durability: flush pending disk writes so the rename
  # survives a kernel panic / laptop-lid-close / power-drop
  # immediately after. Without this, a mid-boot crash between the
  # rename and the eventual buffer flush can lose the swap and leave
  # config.yaml empty on next boot — a hard-to-diagnose "daemon did
  # not come up after upgrade" bug. macOS `sync(1)` is a no-argument
  # wrapper around `sync(2)` (global buffer flush); over-inclusive
  # but always available. Best-effort — never causes the rewrite to
  # fail.
  sync 2>/dev/null || true
  return 0
}

# ---- legacy path relocation --------------------------------------------

# move_legacy_aside PATH BACKUP_ROOT VERSION [--dry-run] -> exit 0 on success
#
# Moves a legacy DefenseClaw path (e.g. /Library/DefenseClaw from a
# pre-Cisco-path install) aside under BACKUP_ROOT so an idempotent
# managed reinstall can proceed without silent data loss. Emits one
# `[install] ...` log line describing the action taken.
#
# Behavior:
#   - PATH missing / not a symlink target -> no-op, exit 0.
#   - PATH is a real file/dir/symlink -> renamed to
#     BACKUP_ROOT/<basename>.pre-<VERSION>-<TIMESTAMP>.
#   - --dry-run (may appear anywhere in the argv tail) -> logs the
#     intended action without touching disk. Used by tests and by
#     verbose install-log preview modes.
#
# Idempotent by design: two consecutive calls against the same
# already-relocated path both succeed (the second is a no-op).
#
# Kept in the pure-function library so tests can drive it under a
# tmpdir and so both installers (packaging/macos/install.sh and
# packaging/launchd/install-enterprise.sh) share one implementation.
# Callers are responsible for feeding a real absolute PATH; the helper
# does not sanitize input.
move_legacy_aside() {
  local path="$1" backup_root="$2" version="$3"
  shift 3
  local dry_run="false"
  local arg
  for arg in "$@"; do
    case "${arg}" in
      --dry-run) dry_run="true";;
      *) return 2;;
    esac
  done

  if [[ -z "${path}" || -z "${backup_root}" || -z "${version}" ]]; then
    return 2
  fi

  if [[ ! -e "${path}" && ! -L "${path}" ]]; then
    return 0
  fi

  # Reject a symlinked BACKUP_ROOT outright — mv into a symlink
  # target would follow the link and relocate legacy state into
  # whatever the symlink points at. The trust-check on the ancestor
  # chain in install.sh runs before we get here on real installs;
  # this second-line-of-defense guards direct call sites (tests,
  # future callers) that skip the outer check.
  if [[ -L "${backup_root}" ]]; then
    return 4
  fi

  local base timestamp target
  base="$(basename -- "${path}")"
  # No Date.now() here: date is fine (this runs on the operator's
  # machine, not under a fixed-clock replay), and the timestamp is
  # only a disambiguator against a re-run within the same version.
  timestamp="$(date -u +%Y%m%dT%H%M%SZ 2>/dev/null || echo "unknown")"
  target="${backup_root}/${base}.pre-${version}-${timestamp}"

  if [[ "${dry_run}" == "true" ]]; then
    printf '[install] would move legacy path aside: %s -> %s\n' "${path}" "${target}"
    return 0
  fi

  # BACKUP_ROOT must exist and be a real directory; on a real install
  # it is created by the caller (LOGS_DIR is a fine landing zone).
  # Missing / non-directory backup_root is a caller bug, not a
  # runtime condition to swallow.
  if [[ ! -d "${backup_root}" ]]; then
    return 3
  fi

  # If the target collides (two-runs-in-one-second edge case), append
  # a short suffix rather than clobbering. Loop bounded to keep the
  # helper trivially terminating.
  local suffix=""
  local i
  for (( i = 0; i < 100; i++ )); do
    if [[ ! -e "${target}${suffix}" && ! -L "${target}${suffix}" ]]; then
      break
    fi
    suffix=".${i}"
  done
  target="${target}${suffix}"

  if ! /bin/mv -- "${path}" "${target}" 2>/dev/null; then
    return 4
  fi
  printf '[install] moved legacy path aside: %s -> %s\n' "${path}" "${target}"
  return 0
}
