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

# ---- shared constants --------------------------------------------------

# Default AI Defense inspect endpoint used when env_config.json is absent
# or malformed at install time. Must match
# viper.SetDefault("cisco_ai_defense.endpoint", ...) in
# internal/config/config.go so the shell + Go sides agree on the
# managed_enterprise fallback. The sync-guard test
# t_default_aid_endpoint_matches_go under packaging/macos/tests/
# catches drift on every CI run.
#
# Declared conditionally so tests that re-source this library across
# cases (the harness sources it per-test-file) don't trip the bash
# "readonly variable" error on the second source. First definition wins.
if [[ -z "${DEFAULT_AID_ENDPOINT:-}" ]]; then
  readonly DEFAULT_AID_ENDPOINT="https://us.api.inspect.aidefense.security.cisco.com"
fi

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
    codex|claudecode|cursor) return 0;;
    *) return 1;;
  esac
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

# discover_agent_version CONNECTOR HOME -> echoes the agent version or "".
#
# Metadata-only: reads files under HOME or under signed system app bundles
# and never executes user-installed agent binaries. install.sh runs as root,
# so invoking $PATH-resolved `codex` / `claude` / etc. would be a
# privilege-escalation surface — the caller must pass --agent-version
# explicitly for connectors that don't ship a stable metadata file.
# _read_json_field PATH FIELD -> echoes the top-level FIELD or "".
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
  awk -v FIELD="${field}" '
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
      if (substr(buf, pos, 1) != "{") exit 0
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
        if (pos > buflen) exit 0
        c = substr(buf, pos, 1)
        if (c == "}") {
          # Closing brace — object end. Validate that only
          # whitespace follows (no trailing garbage) before
          # emitting.
          pos++
          skip_ws()
          if (pos <= buflen) exit 0
          if (found) print val
          exit 0
        }
        if (c == ",") { pos++; continue }
        if (c != "\"") exit 0
        # Read the top-level key.
        key_is_target = 0
        key = read_string()
        if (err) exit 0
        if (key == FIELD) key_is_target = 1
        skip_ws()
        if (substr(buf, pos, 1) != ":") exit 0
        pos++
        skip_ws()
        c = substr(buf, pos, 1)
        if (key_is_target && c == "\"") {
          v = read_string()
          if (err) exit 0
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
          if (err) exit 0
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
              if (err) exit 0
              continue
            }
            if (c == "{" || c == "[") nest_depth++
            else if (c == "}" || c == "]") nest_depth--
            pos++
          }
          if (nest_depth != 0) exit 0
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
          if (pos == start_pos) exit 0
        }
      }
      # Ran off the end of the buffer without a closing brace: object
      # was truncated. Discard any found value.
      exit 0
    }
  ' "${path}" 2>/dev/null
}

# _read_json_version PATH -> convenience shim for the .version field.
# Kept as a named helper so the connector-version-discovery code in
# discover_agent_version reads clearly; delegates to _read_json_field
# so we don't grow two copies of the same JSON reader.
_read_json_version() {
  _read_json_field "$1" "version"
}

# _native_claudecode_version_from_dir BASE -> echoes the version or "".
#
# Reads Claude Code's native-installer layout under BASE, which looks
# like:
#
#   BASE/
#     current            symlink to versions/<X.Y.Z>
#     versions/
#       <X.Y.Z>/         actual install root
#       <X.Y.Z-1>/       (older, kept for rollback)
#
# Metadata-only (matches the module's security posture — see the doc
# block on discover_agent_version). No binary is exec'd; we readlink
# the `current` pointer and basename it, or fall back to picking the
# highest version-shaped subdir under versions/. BASE typically resolves
# to `${home}/.local/share/claude`, `/opt/claude`, or
# `/usr/local/share/claude`.
_native_claudecode_version_from_dir() {
  local base="$1"
  [[ -n "${base}" && -d "${base}" ]] || return 0
  local current target dname ver
  local -r semver_re='^[0-9]+\.[0-9]+\.[0-9]+([._+-].*)?$'

  # 1. `current` symlink — user's active version.
  #    A user with multiple installed versions may have `claude version
  #    rollback`-ed to an older one; the `current` pointer reflects the
  #    active choice, so it wins over the highest-versions/* fallback.
  #    Only accept a `current` whose target actually resolves — a
  #    dangling symlink (aborted upgrade, manual rm -rf) is treated as
  #    absent and falls through to the versions/*/ scan below.
  current="${base}/current"
  if [[ -L "${current}" && -e "${current}" ]]; then
    target="$(readlink -n "${current}" 2>/dev/null || true)"
    if [[ -n "${target}" ]]; then
      dname="$(basename -- "${target}")"
      if [[ "${dname}" =~ ${semver_re} ]]; then
        echo "${dname}"
        return
      fi
    fi
  fi

  # 2. Highest versions/* entry. The native installer publishes each
  #    version under versions/<X.Y.Z>. Two on-disk shapes have been seen
  #    in the wild:
  #      a) directory:   versions/<X.Y.Z>/{node,claude,...}   (classic)
  #      b) executable file: versions/<X.Y.Z>                 (newer)
  #    Discovery must accept both — a QA host was silently reporting
  #    version="" because it only had shape (b) and no `current`
  #    symlink. Handles partial installs where the `current` symlink
  #    hasn't been flipped yet, and hosts that never publish a `current`
  #    pointer at all.
  local versions_dir="${base}/versions" entry
  if [[ -d "${versions_dir}" ]]; then
    ver=""
    for entry in "${versions_dir}"/*; do
      # Accept a directory OR a regular file (both shapes documented
      # above). A dangling symlink or FIFO is skipped — the semver
      # regex on the basename below is the authoritative filter.
      [[ -d "${entry}" || -f "${entry}" ]] || continue
      dname="$(basename "${entry}")"
      [[ "${dname}" =~ ${semver_re} ]] || continue
      if [[ -z "${ver}" ]] || _semver_gt "${dname}" "${ver}"; then
        ver="${dname}"
      fi
    done
    if [[ -n "${ver}" ]]; then
      echo "${ver}"
      return
    fi
  fi
}

# _semver_gt A B -> exit 0 iff A > B under SemVer 2.0.0 precedence.
#
# Ordering is: MAJOR.MINOR.PATCH first (numeric), then prerelease tail.
# A version WITHOUT a prerelease tail is HIGHER than the same version
# WITH one (e.g. 2.1.144 > 2.1.144-rc.1 > 2.1.144-alpha). Numeric
# identifiers in the prerelease tail compare numerically ("2" < "10");
# alphanumeric identifiers compare lexically; numeric identifiers rank
# below alphanumeric ones per §11.4.3.
#
# This replaces the `sort -V` idiom used previously — BSD sort -V (macOS)
# treats `1.0.0-alpha` as GREATER than `1.0.0`, which is the opposite of
# SemVer. `_native_claudecode_version_from_dir` and `_version_ge` both
# route through here so a supported-stable install is never starved by
# a same-major-minor prerelease.
_semver_gt() {
  local a="$1" b="$2"
  # Fast path: identical strings are not "greater than".
  [[ "${a}" == "${b}" ]] && return 1
  # semver_re elsewhere in this file accepts an optional [._+-]-prefixed
  # tail after MAJOR.MINOR.PATCH, so a version can arrive as any of
  # `2.1.144`, `2.1.144-rc.1`, `2.1.144.beta`, `2.1.144_dev`, or
  # `2.1.144+build.5`. Split the numeric MAJOR.MINOR.PATCH prefix off
  # every candidate before comparing so the prefix comparison is
  # apples-to-apples, then treat everything after that first non-digit
  # boundary as the prerelease/build tail. SemVer §10 says build
  # metadata (`+…`) MUST be ignored for precedence — strip it after the
  # prefix split.
  _semver_gt_split() {
    # sets `__prefix` and `__tail` from $1
    local raw="$1"
    __prefix=""
    __tail=""
    local i ch
    for (( i = 0; i < ${#raw}; i++ )); do
      ch="${raw:${i}:1}"
      if [[ "${ch}" =~ [0-9.] ]]; then
        __prefix+="${ch}"
      else
        __tail="${raw:${i}}"
        break
      fi
    done
    # SemVer §10: build metadata (`+build.5`, `+meta`, …) MUST be
    # ignored for precedence. Strip it BEFORE peeling the leading
    # separator so `<main>+build.N` produces an empty tail (making the
    # whole version rank identically to `<main>`).
    if [[ "${__tail:0:1}" == "+" ]]; then
      __tail=""
    else
      __tail="${__tail%%+*}"
    fi
    # Strip a leading separator character from the tail so downstream
    # split-by-`.` doesn't see a leading empty element.
    if [[ -n "${__tail}" ]]; then
      case "${__tail:0:1}" in
        -|_|. ) __tail="${__tail:1}" ;;
      esac
    fi
    # Guard trailing dots on __prefix (e.g. splitting "2.0.0.foo").
    __prefix="${__prefix%.}"
  }
  local __prefix __tail
  _semver_gt_split "${a}"
  local a_main="${__prefix}" a_pre="${__tail}"
  _semver_gt_split "${b}"
  local b_main="${__prefix}" b_pre="${__tail}"
  # Compare MAJOR.MINOR.PATCH numerically. Use `read -ra` (not the
  # unquoted `am=(${a_main})` split) so shell globbing can't expand a
  # `*` in a hostile version string against the working directory
  # (SC2206). IFS is scoped to the read via env-prefix syntax.
  local -a am bm
  IFS=. read -ra am <<< "${a_main}"
  IFS=. read -ra bm <<< "${b_main}"
  local i len an bn
  len=${#am[@]}
  if (( ${#bm[@]} > len )); then len=${#bm[@]}; fi
  for (( i = 0; i < len; i++ )); do
    an="${am[i]:-0}"
    bn="${bm[i]:-0}"
    # Guard non-numeric segments (they'd trip arithmetic under set -u).
    [[ "${an}" =~ ^[0-9]+$ ]] || an=0
    [[ "${bn}" =~ ^[0-9]+$ ]] || bn=0
    if (( an > bn )); then return 0; fi
    if (( an < bn )); then return 1; fi
  done
  # Main parts equal — compare prerelease tails per SemVer §11.4.
  if [[ -z "${a_pre}" && -z "${b_pre}" ]]; then return 1; fi
  if [[ -z "${a_pre}" ]]; then return 0; fi   # no-prerelease > prerelease
  if [[ -z "${b_pre}" ]]; then return 1; fi
  local -a apr bpr
  IFS=. read -ra apr <<< "${a_pre}"
  IFS=. read -ra bpr <<< "${b_pre}"
  local aid bid a_is_num b_is_num
  len=${#apr[@]}
  if (( ${#bpr[@]} > len )); then len=${#bpr[@]}; fi
  for (( i = 0; i < len; i++ )); do
    aid="${apr[i]:-}"
    bid="${bpr[i]:-}"
    if [[ -z "${aid}" ]]; then return 1; fi  # shorter tail loses (§11.4.4)
    if [[ -z "${bid}" ]]; then return 0; fi
    a_is_num=false; b_is_num=false
    [[ "${aid}" =~ ^[0-9]+$ ]] && a_is_num=true
    [[ "${bid}" =~ ^[0-9]+$ ]] && b_is_num=true
    if ${a_is_num} && ${b_is_num}; then
      if (( 10#${aid} > 10#${bid} )); then return 0; fi
      if (( 10#${aid} < 10#${bid} )); then return 1; fi
      continue
    fi
    if ${a_is_num}; then return 1; fi  # numeric < alphanumeric (§11.4.3)
    if ${b_is_num}; then return 0; fi
    # Both alphanumeric — lexicographic.
    if [[ "${aid}" > "${bid}" ]]; then return 0; fi
    if [[ "${aid}" < "${bid}" ]]; then return 1; fi
  done
  return 1
}

# _native_claudecode_version_from_bin BIN -> echoes the version or "".
#
# Reads the PATH-shim shape published by newer Claude Code native
# installers where the actual dispatcher lives at
# `<home>/.local/bin/claude` as a symlink to `../share/claude/versions/
# <X.Y.Z>` (or the analogous /usr/local/bin/claude,
# /opt/homebrew/bin/claude, /opt/claude/bin/claude system-wide shims).
# When no `current` symlink is published and versions/ contains only
# executable files, this shim is the only trustworthy source of the
# active version.
#
# Metadata-only: readlink + basename; no exec of the binary itself.
# Handles both absolute and relative symlink targets; a dangling symlink
# or a non-semver basename returns empty.
_native_claudecode_version_from_bin() {
  local bin="$1"
  [[ -n "${bin}" && -L "${bin}" ]] || return 0
  # A dangling symlink (aborted upgrade, manual rm of the target) is
  # treated as absent — the shim exists on disk but points nowhere, so
  # there's no active install to report. `-e` on the shim itself
  # follows the symlink and fails when the ultimate target is missing.
  [[ -e "${bin}" ]] || return 0
  local -r semver_re='^[0-9]+\.[0-9]+\.[0-9]+([._+-].*)?$'
  # Resolve the entire symlink chain to the final concrete target.
  # `readlink -f` walks the chain and prints the canonical path when
  # available (GNU coreutils and macOS 12+); older BSD `readlink -n`
  # only returns the immediate target, which for a shim like
  # `.../.local/bin/claude -> ../share/claude/current`
  # (which itself points at `versions/<X.Y.Z>`) yields `current`,
  # basenames to `current`, and fails the semver regex — silently
  # dropping the version we could have discovered.
  local resolved
  resolved="$(readlink -f -- "${bin}" 2>/dev/null || true)"
  # If `readlink -f` succeeded but the final basename isn't SemVer-
  # shaped, fall through to the mid-chain walk anyway. Case where
  # this matters: a shim like
  #   .../.local/bin/claude -> ../share/claude/versions/<X.Y.Z>/claude
  # canonicalises to `.../versions/<X.Y.Z>/claude` — final basename
  # is `claude`, which fails the regex, but the parent directory
  # `<X.Y.Z>` is what we want. macOS 12.3+ would silently drop this
  # discovery without the fallback; older macOS would find it via the
  # walk. Same on-disk layout → different result across macOS versions.
  if [[ -n "${resolved}" ]]; then
    local fast_dname
    fast_dname="$(basename -- "${resolved}")"
    if ! [[ "${fast_dname}" =~ ${semver_re} ]]; then
      # Give the mid-chain walk a chance to find a version-labelled
      # intermediate hop before conceding.
      resolved=""
    fi
  fi
  if [[ -z "${resolved}" ]]; then
    # Portable one-hop-at-a-time walk. Stops when we reach a non-
    # symlink (the concrete target) or after a chain-length guard
    # to defend against symlink loops. Also stops at a resolved
    # basename that already matches the semver regex — that means
    # a mid-chain node is version-labelled (the newer native-installer
    # shape where `bin/claude` is a symlink into `versions/<X.Y.Z>/`
    # directly), so we don't need to walk further even if the final
    # target is an executable named `claude` rather than `<X.Y.Z>`.
    local cur="${bin}"
    local step=0
    local -r max_steps=16
    local next dname_walk
    while [[ -L "${cur}" ]] && (( step < max_steps )); do
      next="$(readlink -n -- "${cur}" 2>/dev/null || true)"
      [[ -n "${next}" ]] || break
      # Resolve relative targets against the link's directory.
      if [[ "${next}" != /* ]]; then
        next="$(cd -- "$(dirname -- "${cur}")" && pwd -P)/${next}"
      fi
      dname_walk="$(basename -- "${next}")"
      if [[ "${dname_walk}" =~ ${semver_re} ]]; then
        # Mid-chain version marker — good enough.
        resolved="${next}"
        break
      fi
      cur="${next}"
      step=$((step + 1))
    done
    if [[ -z "${resolved}" ]]; then
      resolved="${cur}"
    fi
  fi
  [[ -n "${resolved}" ]] || return 0
  local dname
  dname="$(basename -- "${resolved}")"
  # If the final basename isn't semver-shaped, consult the parent
  # directory basename — the common newer-installer layout points
  # directly at the executable inside a version-labelled parent
  # (`versions/<X.Y.Z>/claude`). Skip this only if the parent's
  # basename also fails the regex; concede empty rather than guess.
  if ! [[ "${dname}" =~ ${semver_re} ]]; then
    local parent_dname
    parent_dname="$(basename -- "$(dirname -- "${resolved}")")"
    if [[ "${parent_dname}" =~ ${semver_re} ]]; then
      echo "${parent_dname}"
      return
    fi
    return 0
  fi
  echo "${dname}"
}

# Minimum-supported agent versions for the hook-contract gate. Values
# are the ``min_inclusive`` bounds from
# cli/defenseclaw/inventory/hook_contracts.json and must stay aligned
# with the ``MinAgentVersion`` constants in
# internal/gateway/connector/hook_contract.go. If a discovered install
# is below the minimum but a *higher* install is also present, the
# higher one wins; when no install meets the minimum the highest
# overall is still reported so the operator sees an actual version in
# the discovery output (the Go hook gate then reports "unsupported"
# rather than "unversioned").
#
# Declared conditionally so tests that re-source this library across
# cases don't trip bash's readonly-variable error on the second source.
if [[ -z "${MIN_CLAUDECODE_VERSION:-}" ]]; then
  readonly MIN_CLAUDECODE_VERSION="2.1.144"
  readonly MIN_CODEX_VERSION="0.124.0"
  readonly MIN_CURSOR_VERSION="1.7.0"
fi

# _version_ge A B -> exit 0 iff A >= B under SemVer 2.0.0 precedence.
# Empty inputs treated as "no answer" — returns 1. Used by
# _pick_highest_supported below and by direct callers that need to
# check a single version against a minimum. Routes through _semver_gt
# so BSD sort -V's inverted prerelease ordering can't feed a stable
# release below MIN when a same-major-minor prerelease is present.
_version_ge() {
  local a="$1" b="$2"
  [[ -n "${a}" && -n "${b}" ]] || return 1
  [[ "${a}" == "${b}" ]] && return 0
  _semver_gt "${a}" "${b}"
}

# _pick_highest_supported MIN_VERSION VERSION... -> echoes the highest
# candidate that is >= MIN_VERSION, or (when none clear the minimum)
# the highest candidate overall. Silent when no candidates are given.
#
# Motivation: hosts with multiple installs of the same agent (Homebrew
# npm-global + NVM, or ChatGPT.app + npm-global for codex) previously
# stopped at the first hit — often the stale Homebrew install — and
# reported a version below the hook contract's MinAgentVersion.
# Enumerating every install and picking the highest supported version
# fixes that class of bug at the discovery layer.
_pick_highest_supported() {
  local min="$1"; shift
  [[ $# -gt 0 ]] || return 0
  local best_supported="" best_overall="" v
  for v in "$@"; do
    [[ -n "${v}" ]] || continue
    # Track the overall highest so we always return *something* when
    # candidates exist. Route through _semver_gt so a same-major-minor
    # prerelease can never outrank its stable (BSD sort -V's inverted
    # prerelease order would).
    if [[ -z "${best_overall}" ]] || _semver_gt "${v}" "${best_overall}"; then
      best_overall="${v}"
    fi
    if _version_ge "${v}" "${min}"; then
      if [[ -z "${best_supported}" ]] || _semver_gt "${v}" "${best_supported}"; then
        best_supported="${v}"
      fi
    fi
  done
  if [[ -n "${best_supported}" ]]; then
    echo "${best_supported}"
  elif [[ -n "${best_overall}" ]]; then
    echo "${best_overall}"
  fi
}

# _emit_pkg_version_if_exists FILE -> echoes ".version" from FILE, or
# nothing if FILE is missing. Small wrapper so the connector loops
# below stay readable when they iterate 6-10 candidate globs.
_emit_pkg_version_if_exists() {
  [[ -f "$1" ]] || return 0
  _read_json_version "$1"
}

# _collect_node_manager_pkg_versions HOME NPM_SCOPE PKG -> echoes one
# version per line for every install of NPM_SCOPE/PKG we can find
# under the common Node version managers (NVM / Volta / fnm / asdf).
#
# QA regression this addresses: users with multiple `node` versions
# (Homebrew node + NVM node, for instance) have distinct copies of
# `@anthropic-ai/claude-code` under each Node root. The Homebrew-shipped
# global was often the stale one and it always won the first-hit loop.
# Globbing every candidate root and passing the results to
# _pick_highest_supported ensures the newest supported install wins
# regardless of `node` install order.
#
# Glob costs one readdir per manager root — well under a millisecond
# even on developer boxes with a dozen node versions.
_collect_node_manager_pkg_versions() {
  local home="$1" npm_scope="$2" pkg="$3"
  local relpath="${npm_scope}/${pkg}/package.json"
  local -a roots=(
    "${home}"/.nvm/versions/node/*/lib/node_modules/"${relpath}"
    "${home}"/.local/share/fnm/node-versions/*/installation/lib/node_modules/"${relpath}"
    "${home}"/.asdf/installs/nodejs/*/.npm/lib/node_modules/"${relpath}"
    # Volta's package image layout is:
    #   ~/.volta/tools/image/packages/<scope>/<pkg>/<version>/lib/node_modules/<scope>/<pkg>/package.json
    # An earlier iteration stopped at `<version>/package.json` and
    # silently missed every scoped Volta install.
    "${home}"/.volta/tools/image/packages/"${npm_scope}"/"${pkg}"/*/lib/node_modules/"${relpath}"
  )
  local candidate v
  for candidate in "${roots[@]}"; do
    # Bash 3.2 does not set nullglob by default; a missing directory
    # leaves the literal glob string in the array. `-f` guards.
    [[ -f "${candidate}" ]] || continue
    v="$(_read_json_version "${candidate}")"
    [[ -n "${v}" ]] && echo "${v}"
  done
}

discover_agent_version() {
  local connector="$1"
  local home="$2"
  # New policy (as of state v3 discovery): enumerate every candidate
  # install for the given connector, then hand the collected versions
  # to _pick_highest_supported. This replaces the old first-hit-wins
  # loops (which broke for multi-install hosts — see the QA regressions
  # documented above the helper).
  local -a versions=()
  local v pkg base chatgpt_codex

  case "${connector}" in
    codex)
      # Codex-cli ships from OpenAI through several channels; we
      # enumerate every visible install rather than short-circuiting on
      # the first hit so a stale npm-global doesn't win over a newer
      # ChatGPT.app bundle or a fresh NVM install.
      #
      # Channels probed (order does NOT determine which wins — see
      # _pick_highest_supported):
      #   1. ChatGPT.app bundled binary       (Codex 0.145.0+ current)
      #   2. Homebrew Caskroom                (versioned dir name)
      #   3. npm module package.json         (user-global then system)
      #   4. Node version managers (NVM/Volta/fnm/asdf) package.json
      #
      # The ChatGPT.app entries still exec the bundled binary because
      # they don't ship a discoverable metadata file — the app bundle
      # is Gatekeeper-signed and world-readable and install.sh's outer
      # sudo already dropped privs before calling this helper.
      for chatgpt_codex in \
        /Applications/ChatGPT.app/Contents/Resources/codex \
        /Applications/ChatGPT.app/Contents/MacOS/codex; do
        [[ -x "${chatgpt_codex}" ]] || continue
        local vraw
        if [[ -n "${DC_INSTALLER_TARGET_USER:-}" ]]; then
          vraw="$(sudo -n -u "${DC_INSTALLER_TARGET_USER}" "${chatgpt_codex}" --version 2>/dev/null | head -1 || true)"
        else
          vraw="$("${chatgpt_codex}" --version 2>/dev/null | head -1 || true)"
        fi
        vraw="$(printf '%s' "${vraw}" | awk '{for(i=NF;i>=1;i--) if ($i ~ /^[0-9]+\.[0-9]+/) {print $i; exit}}')"
        [[ -n "${vraw}" ]] && versions+=("${vraw}")
      done

      local caskroom dir dname
      for caskroom in /opt/homebrew/Caskroom/codex /usr/local/Caskroom/codex; do
        [[ -d "${caskroom}" ]] || continue
        for dir in "${caskroom}"/*/; do
          [[ -d "${dir}" ]] || continue
          dname="$(basename "${dir}")"
          [[ "${dname}" =~ ^[0-9]+\.[0-9]+ ]] || continue
          versions+=("${dname}")
        done
      done

      for pkg in \
        "${home}"/.npm-global/lib/node_modules/@openai/codex/package.json \
        /usr/local/lib/node_modules/@openai/codex/package.json \
        /opt/homebrew/lib/node_modules/@openai/codex/package.json; do
        v="$(_emit_pkg_version_if_exists "${pkg}")"
        [[ -n "${v}" ]] && versions+=("${v}")
      done

      # NVM / Volta / fnm / asdf globs.
      while IFS= read -r v; do
        [[ -n "${v}" ]] && versions+=("${v}")
      done < <(_collect_node_manager_pkg_versions "${home}" "@openai" "codex")

      _pick_highest_supported "${MIN_CODEX_VERSION}" ${versions[@]+"${versions[@]}"}
      ;;
    claudecode)
      # Claude Code ships through five channels:
      #
      #   1. Native installer (curl -fsSL https://claude.ai/install.sh
      #      | bash) — per-user under ~/.local/share/claude/versions/
      #      with a `current` symlink pointer.
      #   2. System-wide native install — /opt/claude or
      #      /usr/local/share/claude, same {current,versions/*} shape.
      #   3. npm-global CLI — @anthropic-ai/claude-code — legacy
      #      channel; still shipped through Homebrew's `node` and
      #      manually via `npm i -g`.
      #   4. Node version managers (NVM/Volta/fnm/asdf) — the same
      #      npm package installed under a per-node-version root. QA
      #      regression: previously not probed at all, so a stale
      #      Homebrew install would beat a supported NVM install.
      #   5. Cursor / VS Code editor extensions — extension dir name
      #      embeds the version (matches the codex probe pattern).
      #
      # We enumerate everything and pick the highest install that
      # meets MIN_CLAUDECODE_VERSION; if nothing clears the minimum,
      # the highest overall is still emitted so the Go hook gate
      # reports drift rather than the noisier "unversioned".
      for base in \
        "${home}/.local/share/claude" \
        /opt/claude \
        /usr/local/share/claude; do
        v="$(_native_claudecode_version_from_dir "${base}")"
        [[ -n "${v}" ]] && versions+=("${v}")
      done

      # PATH-shim probe. Newer native installers publish
      # `<home>/.local/bin/claude -> ../share/claude/versions/<X.Y.Z>`
      # without a `current` symlink and with versions/<X.Y.Z> as a
      # regular executable file. Without this probe the from_dir()
      # scan above still handles the file variant, but a QA host
      # reported here had a *stale* versions/ entry pinned by the
      # shim to an older release; the shim is the source of truth
      # for the active install, so we surface it explicitly. Handles
      # per-user and both system shim locations.
      local bin
      for bin in \
        "${home}/.local/bin/claude" \
        /usr/local/bin/claude \
        /opt/homebrew/bin/claude \
        /opt/claude/bin/claude; do
        v="$(_native_claudecode_version_from_bin "${bin}")"
        [[ -n "${v}" ]] && versions+=("${v}")
      done

      for pkg in \
        "${home}"/.npm-global/lib/node_modules/@anthropic-ai/claude-code/package.json \
        /usr/local/lib/node_modules/@anthropic-ai/claude-code/package.json \
        /opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/package.json \
        "${home}"/.cursor/extensions/anthropic.claude-code-*/package.json \
        "${home}"/.vscode/extensions/anthropic.claude-code-*/package.json; do
        v="$(_emit_pkg_version_if_exists "${pkg}")"
        [[ -n "${v}" ]] && versions+=("${v}")
      done

      while IFS= read -r v; do
        [[ -n "${v}" ]] && versions+=("${v}")
      done < <(_collect_node_manager_pkg_versions "${home}" "@anthropic-ai" "claude-code")

      _pick_highest_supported "${MIN_CLAUDECODE_VERSION}" ${versions[@]+"${versions[@]}"}
      ;;
    cursor)
      # Cursor.app is a signed macOS bundle. Two metadata sources:
      #   1. Info.plist ``CFBundleShortVersionString`` — the user-
      #      visible marketing version.
      #   2. Contents/Resources/app/package.json ``version`` — the
      #      Electron/npm layout the bundled agent reports at runtime;
      #      the two can lag out of sync for a release.
      # Enumerate both and let _pick_highest_supported pick the one
      # that meets MIN_CURSOR_VERSION; if both are below, the higher
      # of the two still ships.
      if [[ -f /Applications/Cursor.app/Contents/Info.plist ]]; then
        v="$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" \
          /Applications/Cursor.app/Contents/Info.plist 2>/dev/null || true)"
        [[ -n "${v}" ]] && versions+=("${v}")
      fi
      v="$(_emit_pkg_version_if_exists /Applications/Cursor.app/Contents/Resources/app/package.json)"
      [[ -n "${v}" ]] && versions+=("${v}")

      _pick_highest_supported "${MIN_CURSOR_VERSION}" ${versions[@]+"${versions[@]}"}
      ;;
  esac
}

# ---- per-connector userspace prep --------------------------------------
#
# Each prepare_* writes the connector's native hook config file under HOME
# if missing. They do NOT chown — the caller is expected to be running as
# the target user (the test harness) or as root with a follow-up chown
# (the real installer). They use install(8)/chmod for parents and writes.

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

prepare_codex_userspace() {
  local home="$1"
  local dir="${home}/.codex"
  local cfg="${home}/.codex/config.toml"
  ensure_safe_userspace_path "${dir}" "${cfg}" || return 1
  if [[ ! -f "${cfg}" ]]; then
    chmod 0700 "${dir}"
    cat > "${cfg}" <<'TOML'
# Created by DefenseClaw installer so the enterprise hook guardian can
# repair this file. Edit freely; DefenseClaw only owns [hooks], [otel],
# and the top-level notify entries.
TOML
    chmod 0600 "${cfg}"
  fi
}

prepare_claudecode_userspace() {
  local home="$1"
  local dir="${home}/.claude"
  local cfg="${home}/.claude/settings.json"
  ensure_safe_userspace_path "${dir}" "${cfg}" || return 1
  if [[ ! -f "${cfg}" ]]; then
    chmod 0700 "${dir}"
    printf '{}\n' > "${cfg}"
    chmod 0600 "${cfg}"
  fi
}

prepare_cursor_userspace() {
  local home="$1"
  local dir="${home}/.cursor"
  local cfg="${home}/.cursor/hooks.json"
  ensure_safe_userspace_path "${dir}" "${cfg}" || return 1
  if [[ ! -f "${cfg}" ]]; then
    chmod 0700 "${dir}"
    printf '{"version":1,"hooks":{}}\n' > "${cfg}"
    chmod 0600 "${cfg}"
  fi
}

prepare_userspace_for() {
  local connector="$1"
  local home="$2"
  case "${connector}" in
    codex)      prepare_codex_userspace      "${home}";;
    claudecode) prepare_claudecode_userspace "${home}";;
    cursor)     prepare_cursor_userspace     "${home}";;
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
#   CONNECTORS_CSV comma-separated list of connectors (e.g. codex,claudecode,cursor)
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

# _valid_aid_endpoint_url URL -> exit 0 iff URL is a well-formed
# HTTPS bare-origin AID endpoint. Enforces every property the
# downstream managed CMID inspection client and OTel AID ingest need:
#
#   - HTTPS only. CMID bearer tokens ride in the Authorization header;
#     accepting plaintext http:// would let a misconfigured
#     --override-endpoint (or a hostile env_config.json) exfiltrate
#     enterprise credentials on the wire.
#   - No userinfo (`user@host`, `user:pass@host`). URL userinfo is
#     silently dropped by Go's net/http on some redirect paths and is
#     never the right place to encode auth for the AID endpoint —
#     letting it through opens a credential-in-config leak.
#   - No path, query, fragment. The daemon appends
#     `/api/v1/inspect/defense_claw` and other suffixes itself; an
#     operator-supplied path would double-append (or silently override)
#     the routing. Query/fragment on the endpoint are equally
#     nonsensical.
#   - No whitespace, double quotes, or backslashes. Belt-and-braces so
#     the value can safely land inside a double-quoted YAML scalar in
#     render_config's cisco_ai_defense block.
#   - Optional `:port` on the host (integer only).
#
# Kept as a named helper so callers exercise the same regex regardless
# of whether the URL came from --override-endpoint or the AVC-owned
# env_config.json.
_valid_aid_endpoint_url() {
  local candidate="$1"
  # Reject early on whitespace, quotes, backslashes anywhere.
  case "${candidate}" in
    *[[:space:]]*|*'"'*|*'\'*) return 1 ;;
  esac
  # Bare-origin shape. Host must either end in `.cisco.com` (the
  # AVC-owned AI Defense hostnames) or be a loopback for local dev.
  # This mirrors validateAIDefenseEndpoint in internal/config/env_config.go
  # -- the sync-guard test in TestValidateAIDefenseEndpoint fails CI if
  # either side loosens its checks.
  local re_cisco='^https://[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*\.cisco\.com(:[0-9]+)?$'
  # Loopback: IPv4/hostname bare, or IPv6 in bracketed URL form. The Go
  # validator's u.Hostname() unwraps the brackets, so validateAIDefense
  # Endpoint accepts https://[::1] and https://[::1]:8080 as loopback;
  # the shell needs the same coverage or the sync-guard test drifts.
  local re_loopback='^https://(localhost|127\.0\.0\.1|\[::1\])(:[0-9]+)?$'
  if [[ "${candidate}" =~ ${re_cisco} ]] || [[ "${candidate}" =~ ${re_loopback} ]]; then
    return 0
  fi
  return 1
}

# resolve_aid_endpoint OVERRIDE CONFIG_FILE -> stdout effective endpoint
#
# Under the managed_enterprise contract the AI Defense endpoint that
# the daemon inspects against is authored by the AVC module and dropped
# at CONFIG_FILE (default
# /opt/cisco/secureclient/defenseclaw/env_config.json) as a single-
# field JSON document:
#
#   {
#     "cisco_ai_defense_endpoint": "https://us.api.inspect.aidefense.security.cisco.com"
#   }
#
# --override-endpoint is preserved as the release-owned adhoc-testing
# seam (personal preview tenants, sam-aid boxes, etc.) and wins over
# the file. Any trailing slash is stripped for consistent path joining
# — the daemon appends /api/v1/inspect/defense_claw itself.
#
# Return codes let the caller emit a precise per-source error:
#   0 - success (endpoint on stdout)
#   1 - config file missing / unreadable / not a regular file
#   2 - config file present but malformed (bad JSON, missing field,
#       URL failed the regex)
#   3 - override supplied but malformed — invalid --override-endpoint
#
# rc 3 is a new code (the previous version used rc 2 for the override
# case); callers wanting per-flag error messages should key off the
# new numbering.
#
# Kept pure (stdout only, no warn/log) so tests can exercise precedence
# and validation without the AID cloud being reachable.
resolve_aid_endpoint() {
  local override="$1"
  local config_file="$2"
  if [[ -n "${override}" ]]; then
    # Strip a lone trailing slash BEFORE validation so
    # "https://host.example.com/" is accepted (common paste). Any
    # other path component fails the bare-origin regex.
    local stripped="${override%/}"
    _valid_aid_endpoint_url "${stripped}" || return 3
    printf '%s\n' "${stripped}"
    return 0
  fi
  if [[ -z "${config_file}" || ! -f "${config_file}" ]]; then
    return 1
  fi
  local endpoint
  endpoint="$(_read_json_field "${config_file}" "cisco_ai_defense_endpoint")"
  if [[ -z "${endpoint}" ]]; then
    return 2
  fi
  local stripped_cfg="${endpoint%/}"
  _valid_aid_endpoint_url "${stripped_cfg}" || return 2
  printf '%s\n' "${stripped_cfg}"
  return 0
}

# render_config MODE PRIMARY API_PORT DISABLE_REDACTION SUPPORT_DIR AID_ENDPOINT CONN... -> stdout
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
  local disable_redaction="$4"
  local support_dir="$5"
  local aid_endpoint="$6"
  shift 6
  local -a connectors=("$@")
  local runtime_dir="${support_dir}/runtime"

  cat <<EOF
config_version: 6
deployment_mode: managed_enterprise

data_dir: "${runtime_dir}"
audit_db: "${runtime_dir}/audit.db"
judge_bodies_db: "${runtime_dir}/judge_bodies.db"

gateway:
  api_bind: 127.0.0.1
  api_port: ${api_port}
  # Pin device_key_file into RUNTIME_DIR (service-user writable) rather
  # than letting the Go defaults compute it from DEFENSECLAW_HOME. The
  # plist sets DEFENSECLAW_HOME to SUPPORT_DIR so managed_enterprise
  # trust checks accept every ancestor of config.yaml, but SUPPORT_DIR
  # itself is root:defenseclaw 0750 (no group write) — leaving the
  # default would send the daemon's first-boot write to
  # \${SUPPORT_DIR}/device.key and crash it with "permission denied".
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

privacy:
  disable_redaction: ${disable_redaction}

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
# <token>. The endpoint is sourced from the AVC-authored env_config.json
# at /opt/cisco/secureclient/defenseclaw/env_config.json (see the
# --config-file flag on install.sh); --override-endpoint on install.sh
# takes precedence for adhoc testing. See
# internal/gateway/cisco_inspect_defense_claw.go and
# internal/managed/cloudreg for the client-side implementation.
cisco_ai_defense:
  endpoint: "${aid_endpoint}"

# OpenTelemetry. In managed_enterprise the gateway auto-provisions a Cisco AI
# Defense event-ingest LOG sink from cisco_ai_defense.endpoint above: it POSTs
# DefenseClaw's own events to ${aid_endpoint}/api/v1/defenseclaw/events/ingest with
# a CMID bearer token (see internal/telemetry/cisco_aid_log_exporter.go). That
# sink is independent of otel.destinations[] and needs no user collector.
# otel.enabled is turned on so the telemetry provider (and that managed sink)
# are active; the "enabled requires a destination" rule is waived when the
# managed sink is present (see config.hasManagedAIDLogSink). Add entries under
# otel.destinations[] only if you also want to fan out to your own OTLP backend.
# Set DEFENSECLAW_DEBUG=1 for a stderr line confirming each successful send.
otel:
  enabled: true

# Continuous AI discovery (endpoint inventory). Enabled in managed_enterprise
# so the sidecar scans for supported connectors and broader "shadow AI" usage
# signals and ships the inventory to AI Defense as discovery events over the
# managed AID log sink above (see internal/inventory/ai_discovery.go and
# internal/telemetry/cisco_aid_log_exporter.go). emit_otel defaults on, which is
# what carries the inventory to that sink; other ai_discovery.* keys keep their
# built-in defaults (mode enhanced, scan intervals). The scanner is a no-op
# unless enabled, so this block is required for endpoint inventory to flow.
# Continuous AI discovery. home_dirs below is refreshed by
# com.cisco.secureclient.defenseclaw.hook-enumerator on every tick from
# the same eligible-user pass that renders hook-guardian/targets.yaml —
# do not hand-edit; changes will be overwritten. Without this list a
# launchd/root-launched daemon walks /var/root only and misses every
# user's per-user data (editor extensions, MCP configs, shell history).
ai_discovery:
  enabled: true
  home_dirs:
    - "__DEFENSECLAW_HOME_DIRS_PLACEHOLDER__"

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
  if ! /bin/mv -f -- "${tmp}" "${target}"; then
    printf 'apply_ai_discovery_home_dirs: rename %s -> %s failed (%s)\n' "${tmp}" "${target}" "$?" >&2
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
