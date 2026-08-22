#!/usr/bin/env bash
# discover_agent_version: per-connector metadata probing.
#
# Protected Codex/Claude discovery uses only passively version-bound native
# layouts; no client executes before the guardian publishes and validates its
# receipt. OpenCode retains its bounded target-user standalone probe.
. "${PKG_DIR}/lib/installer_lib.sh"

# Wrapper that masks any host `amp` / `claude` / `codex` / `opencode` CLI on PATH. We used
# to need this because the lib exec'd those binaries; keeping it around
# guards against a regression where a future CLI probe reintroduces the
# code-exec surface.
without_host_agent_bins() {
  local fakebin
  fakebin="$(mktest_tmp)"
  local bin
  for bin in amp claude codex opencode; do
    cat > "${fakebin}/${bin}" <<'SH'
#!/usr/bin/env bash
exit 127
SH
    chmod 0700 "${fakebin}/${bin}"
  done
  PATH="${fakebin}:${PATH}" "$@"
}

t_amp_from_user_npm_metadata_without_executing_cli() {
  local home; home="$(mktest_tmp)"
  local pkg_dir="${home}/.npm-global/lib/node_modules/@ampcode/cli"
  mkdir -p "${pkg_dir}"
  cat > "${pkg_dir}/package.json" <<'JSON'
{ "name": "@ampcode/cli", "version": "0.0.1777777777-gabc123" }
JSON
  local got
  got="$(without_host_agent_bins discover_agent_version amp "${home}")"
  assert_eq "${got}" "0.0.1777777777-gabc123" "amp version from trusted package metadata"
}

t_amp_metadata_requires_package_identity() {
  local home; home="$(mktest_tmp)"
  local pkg="${home}/package.json"
  cat > "${pkg}" <<'JSON'
{ "name": "@attacker/not-amp", "version": "9.9.9" }
JSON
  local got
  got="$(_read_json_version "${pkg}" "@ampcode/cli")"
  assert_eq "${got}" "" "mismatched Amp npm package identity rejected"
}

t_amp_missing_metadata_may_be_unversioned() {
  # Stub the safe metadata reader to make every known package path look absent.
  # discover_agent_version must return empty and must not fall through to
  # executing a PATH-resolved Amp binary.
  _read_json_version() { :; }
  local home got
  home="$(mktest_tmp)"
  got="$(without_host_agent_bins discover_agent_version amp "${home}" 2>/dev/null || true)"
  assert_eq "${got}" "" "amp without trusted metadata remains unversioned"
  # Restore the library definition for later cases in this sourced test file.
  . "${PKG_DIR}/lib/installer_lib.sh"
}

t_claudecode_extension_metadata_is_not_executable_authority() {
  local home; home="$(mktest_tmp)"
  local ext="${home}/.cursor/extensions/anthropic.claude-code-2.1.195-darwin-arm64"
  mkdir -p "${ext}"
  cat > "${ext}/package.json" <<'JSON'
{ "name": "claude-code", "version": "2.1.195" }
JSON

  local got
  got="$(without_host_agent_bins discover_agent_version claudecode "${home}")"
  assert_eq "${got}" "" "Cursor extension metadata cannot label a protected native image"
}

t_claudecode_vscode_metadata_is_not_executable_authority() {
  local home; home="$(mktest_tmp)"
  local ext="${home}/.vscode/extensions/anthropic.claude-code-2.0.99-darwin-arm64"
  mkdir -p "${ext}"
  cat > "${ext}/package.json" <<'JSON'
{ "name": "claude-code", "version": "2.0.99" }
JSON

  local got
  got="$(without_host_agent_bins discover_agent_version claudecode "${home}")"
  assert_eq "${got}" "" "VS Code extension metadata cannot label a protected native image"
}

t_claudecode_native_version_image_is_paired_passively() {
  local home; home="$(mktest_tmp)"
  local versions="${home}/.local/share/claude/versions"
  local older="${versions}/2.9.0" image="${versions}/2.10.0" sentinel="${home}/executed"
  mkdir -p "${versions}"
  printf '#!/usr/bin/env bash\ntouch %q\n' "${sentinel}" > "${older}"
  printf '#!/usr/bin/env bash\ntouch %q\n' "${sentinel}" > "${image}"
  chmod 0500 "${older}" "${image}"

  local got
  got="$(without_host_agent_bins discover_agent_version claudecode "${home}")"
  assert_eq "${got}" "2.10.0" "Claude newest image uses numeric dotted comparison"
  assert_eq "$(discover_agent_executable claudecode "${home}" "${got}")" "${image}" "Claude version pairs with the exact image"
  [[ ! -e "${sentinel}" ]] || _fail "Claude image executed during passive discovery"
}

t_codex_standalone_newest_version_is_numeric_and_passive() {
  local home; home="$(mktest_tmp)"
  local root="${home}/.codex/packages/standalone/releases"
  local older="${root}/0.99.0-aarch64-apple-darwin/bin/codex"
  local newest="${root}/0.100.0-aarch64-apple-darwin/bin/codex"
  local sentinel="${home}/executed"
  mkdir -p "$(dirname "${older}")" "$(dirname "${newest}")"
  printf '#!/usr/bin/env bash\ntouch %q\n' "${sentinel}" > "${older}"
  printf '#!/usr/bin/env bash\ntouch %q\n' "${sentinel}" > "${newest}"
  chmod 0500 "${older}" "${newest}"
  local got
  got="$(without_host_agent_bins discover_agent_version codex "${home}")"
  assert_eq "${got}" "0.100.0" "Codex standalone newest selection is numeric"
  assert_eq "$(discover_agent_executable codex "${home}" "${got}")" "${newest}" "Codex version pairs with exact standalone image"
  [[ ! -e "${sentinel}" ]] || _fail "Codex image executed during passive discovery"
  local body; body="$(declare -f discover_agent_version)"
  assert_not_contains "${body}" "/usr/bin/python3" "protected passive discovery has no Python/CLT dependency"
  assert_not_contains "${body}" "sort -V" "protected passive discovery has no GNU sort dependency"
}

t_claudecode_no_install_returns_empty() {
  # Empty tmp HOME + no CLI on PATH → empty version, cleanly.
  local home; home="$(mktest_tmp)"
  local got
  got="$(without_host_agent_bins discover_agent_version claudecode "${home}" 2>/dev/null || true)"
  assert_eq "${got}" "" "claudecode with no CLI/extensions returns empty"
}

t_codex_no_home_metadata_uses_system_or_empty() {
  # With no metadata under the tmp HOME, only an exactly paired system npm
  # native image may produce a version. ChatGPT.app, Caskroom directory names,
  # and PATH are deliberately not consulted.
  local home; home="$(mktest_tmp)"
  local got
  got="$(without_host_agent_bins discover_agent_version codex "${home}" 2>/dev/null || true)"
  # Either empty, or a plausible passively paired npm version.
  if [[ -n "${got}" && ! "${got}" =~ ^[0-9]+\.[0-9]+ ]]; then
    _fail "codex probe returned unexpected non-empty non-version: ${got}"
    return 1
  fi
}

t_codex_chatgpt_app_is_not_a_preselection_source() {
  local version_body executable_body
  version_body="$(declare -f discover_agent_version)"
  executable_body="$(declare -f discover_agent_executable)"
  assert_not_contains "${version_body}" '/Applications/ChatGPT.app/Contents' "Codex version discovery never executes ChatGPT.app"
  assert_not_contains "${executable_body}" '/Applications/ChatGPT.app/Contents' "Codex executable discovery never selects ChatGPT.app pre-receipt"
  assert_not_contains "${executable_body}" '--version' "Codex executable discovery remains passive"
}

t_codex_from_user_npm_metadata() {
  # Seed a user-scoped npm package plus its exact version-paired native image.
  local home; home="$(mktest_tmp)"
  local pkg_dir="${home}/.npm-global/lib/node_modules/@openai/codex"
  local native="${pkg_dir}/node_modules/@openai/codex-darwin-arm64/vendor/aarch64-apple-darwin/bin/codex"
  mkdir -p "${pkg_dir}" "$(dirname "${native}")"
  cat > "${pkg_dir}/package.json" <<'JSON'
{ "name": "@openai/codex", "version": "0.142.0" }
JSON
  printf '#!/usr/bin/env bash\n# signed image fixture\n' > "${native}"
  chmod 0500 "${native}"
  local got
  got="$(without_host_agent_bins discover_agent_version codex "${home}")"
  assert_eq "${got}" "0.142.0" "Codex version from native-paired user npm metadata"
  assert_eq "$(discover_agent_executable codex "${home}" "${got}")" "${native}" "Codex npm version pairs with exact native image"
}

t_opencode_from_user_npm_metadata_without_executing_cli() {
  # Skip only when a higher-priority official App/Homebrew installation is
  # present on the host. Those sources intentionally win over npm metadata.
  if [[ -f /Applications/OpenCode.app/Contents/Info.plist ]] \
     || [[ -L /opt/homebrew/opt/opencode ]] \
     || [[ -L /usr/local/opt/opencode ]]; then
    if [[ "${VERBOSE:-false}" == "true" ]]; then
      printf '  skip (higher-priority OpenCode metadata source on host)\n'
    fi
    return 0
  fi
  local home; home="$(mktest_tmp)"
  local pkg_dir="${home}/.npm-global/lib/node_modules/opencode-ai"
  mkdir -p "${pkg_dir}"
  cat > "${pkg_dir}/package.json" <<'JSON'
{ "name": "opencode-ai", "version": "1.18.19" }
JSON
  local got
  got="$(without_host_agent_bins discover_agent_version opencode "${home}")"
  assert_eq "${got}" "1.18.19" "opencode version from package metadata without CLI execution"
}

t_opencode_package_metadata_requires_identity_and_semver() {
  local dir; dir="$(mktest_tmp)"
  local pkg="${dir}/package.json"
  local got

  printf '{"name":"not-opencode","version":"1.18.19"}\n' > "${pkg}"
  got="$(_probe_opencode_json_version "${pkg}")"
  assert_eq "${got}" "" "mismatched OpenCode package identity rejected"

  local log="${dir}/errors.log"
  : > "${log}"
  printf '{"name":"opencode-ai","version":"not-a-version"}\n' > "${pkg}"
  got="$(DC_DISCOVERY_ERRORS_LOG="${log}" \
         DC_INSTALLER_TARGET_USER="alice" \
         _probe_opencode_json_version "${pkg}")"
  assert_eq "${got}" "" "invalid OpenCode metadata version rejected"
  assert_contains "$(cat "${log}")" "invalid-version" "invalid OpenCode version is reported"
  assert_contains "$(cat "${log}")" "${pkg}" "invalid OpenCode version report names metadata path"
}

t_opencode_homebrew_metadata_uses_active_formula_without_executing_client() {
  local prefix; prefix="$(mktest_tmp)"
  mkdir -p "${prefix}/Cellar/opencode/1.18.20/bin" "${prefix}/opt"
  local sentinel="${prefix}/executed"
  cat > "${prefix}/Cellar/opencode/1.18.20/bin/opencode" <<SH
#!/usr/bin/env bash
touch '${sentinel}'
exit 99
SH
  chmod 0700 "${prefix}/Cellar/opencode/1.18.20/bin/opencode"
  if ! ln -s ../Cellar/opencode/1.18.20 "${prefix}/opt/opencode" 2>/dev/null \
     || [[ ! -L "${prefix}/opt/opencode" ]]; then
    if [[ "${VERBOSE:-false}" == "true" ]]; then printf '  skip (symlinks unavailable)\n'; fi
    return 0
  fi
  # Discovery emits a truthful future version; the guardian contract remains
  # the authority that refuses >=1.18.20 until that runtime is reviewed.
  local got
  got="$(_probe_opencode_homebrew_version "${prefix}")"
  assert_eq "${got}" "1.18.20" "active Homebrew formula metadata candidate selected"
  if [[ -e "${sentinel}" ]]; then
    _fail "OpenCode Homebrew binary executed during metadata discovery"
  fi
}

t_opencode_app_metadata_requires_official_identity() {
  if [[ ! -x /usr/libexec/PlistBuddy ]]; then
    if [[ "${VERBOSE:-false}" == "true" ]]; then printf '  skip (PlistBuddy unavailable)\n'; fi
    return 0
  fi
  local dir; dir="$(mktest_tmp)"
  local plist="${dir}/Info.plist"
  cat > "${plist}" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>ai.opencode.desktop</string>
  <key>CFBundleShortVersionString</key><string>1.18.19</string>
</dict></plist>
PLIST
  local got
  got="$(_probe_opencode_app_version "${plist}")"
  assert_eq "${got}" "1.18.19" "official OpenCode app metadata accepted"

  /usr/libexec/PlistBuddy -c 'Set :CFBundleIdentifier example.attacker.desktop' "${plist}"
  got="$(_probe_opencode_app_version "${plist}")"
  assert_eq "${got}" "" "lookalike OpenCode app bundle identity rejected"
}

t_bounded_agent_probe_uses_target_user_and_exact_binary() {
  local dir; dir="$(mktest_tmp)"
  local fakebin="${dir}/fakebin"
  local agent="${dir}/.opencode/bin/opencode"
  local args_log="${dir}/sudo-args"
  mkdir -p "${fakebin}" "$(dirname "${agent}")"

  cat > "${fakebin}/sudo" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$@" > "${DC_TEST_SUDO_ARGS}"
[[ "$1" == "-n" && "$2" == "-u" && "$4" == "--" ]] || exit 90
export DC_TEST_EFFECTIVE_USER="$3"
shift 4
exec "$@"
SH
  cat > "${agent}" <<'SH'
#!/usr/bin/env bash
[[ "$1" == "--version" ]] || exit 91
printf '%s:1.18.19\n' "${DC_TEST_EFFECTIVE_USER}"
SH
  chmod 0700 "${fakebin}/sudo" "${agent}"

  local got
  got="$(DC_TEST_SUDO_ARGS="${args_log}" \
          _read_agent_version_as_user alice "${agent}" "${fakebin}/sudo")"
  assert_eq "${got}" "alice:1.18.19" "bounded probe executes through the requested target user"
  assert_eq "$(sed -n '5p' "${args_log}")" "${agent}" "bounded probe executes the supplied exact binary path"
  assert_eq "$(sed -n '6p' "${args_log}")" "--version" "bounded probe passes only the version argument"
}

t_opencode_standalone_uses_bounded_target_user_probe() {
  local home; home="$(mktest_tmp)"
  local standalone="${home}/.opencode/bin/opencode"
  local calls="${home}/probe-calls"
  local sentinel="${home}/executed-directly"
  mkdir -p "$(dirname "${standalone}")"
  cat > "${standalone}" <<SH
#!/usr/bin/env bash
touch '${sentinel}'
printf '9.9.9\n'
SH
  chmod 0700 "${standalone}"

  # Isolate this branch from any higher-priority host App/Homebrew/npm source.
  _probe_opencode_app_version() { :; }
  _probe_opencode_homebrew_version() { :; }
  _probe_opencode_json_version() { :; }
  _read_agent_version_as_user() {
    printf '%s\t%s\n' "$1" "$2" > "${calls}"
    printf '1.18.19'
  }

  local got
  got="$(DC_INSTALLER_TARGET_USER=alice discover_agent_version opencode "${home}")"
  # Restore definitions before assertions so later in-process cases are clean.
  . "${PKG_DIR}/lib/installer_lib.sh"

  assert_eq "${got}" "1.18.19" "standalone OpenCode version is discovered"
  assert_eq "$(cat "${calls}")" $'alice\t'"${standalone}" "standalone probe receives target user and exact official path"
  if [[ -e "${sentinel}" ]]; then
    _fail "standalone OpenCode binary bypassed the bounded target-user helper"
  fi
}

t_opencode_standalone_rejects_invalid_version_output() {
  local home; home="$(mktest_tmp)"
  local standalone="${home}/.opencode/bin/opencode"
  local log="${home}/errors.log"
  mkdir -p "$(dirname "${standalone}")"
  printf '#!/usr/bin/env bash\n' > "${standalone}"
  : > "${log}"
  chmod 0700 "${standalone}"

  _probe_opencode_app_version() { :; }
  _probe_opencode_homebrew_version() { :; }
  _probe_opencode_json_version() { :; }
  _read_agent_version_as_user() { printf 'not-a-version'; }

  local got
  got="$(DC_INSTALLER_TARGET_USER=alice DC_DISCOVERY_ERRORS_LOG="${log}" \
          discover_agent_version opencode "${home}")"
  . "${PKG_DIR}/lib/installer_lib.sh"

  assert_eq "${got}" "" "invalid standalone OpenCode version is rejected"
  assert_contains "$(cat "${log}")" "version-probe-failed" "failed standalone version probe is reported truthfully"
  assert_contains "$(cat "${log}")" "${standalone}" "failed standalone probe report names the exact path"
}

t_unknown_connector() {
  local got
  got="$(discover_agent_version geminicli "$(mktest_tmp)" 2>/dev/null || true)"
  assert_eq "${got}" "" "unknown connector returns empty string"
}

t_read_json_field_decodes_unicode_escape_bytes() {
  # Regression guard for the LC_ALL=C pin on the pure-awk JSON reader.
  # A UTF-8 locale would have `sprintf("%c", cp)` emit the multi-byte
  # UTF-8 sequence for the codepoint, DOUBLE-encoding what utf8()
  # already assembled. Then a subsequent `substr()` iterates on
  # characters not octets, mis-slicing our raw-byte buffer. Pinning
  # to C keeps every op on octets.
  #
  # Fixtures cover: ASCII \u0041 (== "A"), BMP-mid \u00e9 (== "é"
  # → 0xC3 0xA9), and a surrogate pair for U+1F600 (grinning face
  # → 0xF0 0x9F 0x98 0x80). All three must round-trip verbatim
  # regardless of the invoking shell's LC_ALL setting.
  local dir cfg got
  dir="$(mktest_tmp)"
  cfg="${dir}/uni.json"

  # ASCII escape
  printf '{"v":"\\u0041"}\n' > "${cfg}"
  got="$(LC_ALL=en_US.UTF-8 _read_json_field "${cfg}" v)"
  assert_eq "${got}" "A" "\\u0041 decodes to ASCII 'A' under en_US.UTF-8"

  # BMP-mid \u00e9 = é (UTF-8: 0xC3 0xA9)
  printf '{"v":"\\u00e9"}\n' > "${cfg}"
  got="$(LC_ALL=en_US.UTF-8 _read_json_field "${cfg}" v)"
  local want_e_acute
  want_e_acute="$(printf '\xc3\xa9')"
  assert_eq "${got}" "${want_e_acute}" "\\u00e9 decodes to UTF-8 'é' bytes under en_US.UTF-8"

  # Surrogate pair for U+1F600 grinning face → \uD83D\uDE00 (UTF-8: F0 9F 98 80)
  printf '{"v":"\\uD83D\\uDE00"}\n' > "${cfg}"
  got="$(LC_ALL=en_US.UTF-8 _read_json_field "${cfg}" v)"
  local want_grin
  want_grin="$(printf '\xf0\x9f\x98\x80')"
  assert_eq "${got}" "${want_grin}" "surrogate pair decodes to U+1F600 UTF-8 bytes under en_US.UTF-8"

  # And once more under C locale to confirm the pin isn't a workaround
  # that only works when the *caller* runs under C.
  got="$(LC_ALL=C _read_json_field "${cfg}" v)"
  assert_eq "${got}" "${want_grin}" "surrogate pair decodes correctly under LC_ALL=C too"
}

# ---- discovery-error propagation ---------------------------------------
#
# _read_json_field / _read_json_version / _probe_json_version /
# discover_agent_version distinguish "metadata absent" (file not there
# → connector genuinely not installed, rc 0, empty stdout, silent) from
# "metadata present but malformed" (rc 2, empty stdout, discovery
# error appended to DC_DISCOVERY_ERRORS_LOG when set). install.sh's
# zero-target branch treats a non-empty errors-log as fatal so a
# corrupt codex package.json cannot silently downgrade to a
# "none-installed → will pick up on next reconciler tick" warn path
# — the operator needs to see the failing path and repair the install.

t_read_json_field_rc_0_on_wellformed_missing_field() {
  local dir; dir="$(mktest_tmp)"
  local cfg="${dir}/pkg.json"
  printf '{"name":"x"}\n' > "${cfg}"
  local out rc
  out="$(_read_json_field "${cfg}" version)"
  rc=$?
  assert_eq "${out}" "" "well-formed JSON without target field emits empty stdout"
  assert_eq "${rc}"  "0" "well-formed JSON without target field exits 0 (absent, not malformed)"
}

t_read_json_field_rc_2_on_malformed() {
  local dir; dir="$(mktest_tmp)"
  local cfg="${dir}/pkg.json"
  # Truncated mid-value: opens object, key + colon, no scalar, no close.
  printf '{"version":' > "${cfg}"
  local out rc
  out="$(_read_json_field "${cfg}" version)"
  rc=$?
  assert_eq "${out}" "" "malformed JSON emits empty stdout"
  assert_eq "${rc}"  "2" "malformed JSON exits 2 (distinguishes from rc-0 absent)"
}

t_read_json_field_rc_2_on_non_object_root() {
  local dir; dir="$(mktest_tmp)"
  local cfg="${dir}/pkg.json"
  # Valid JSON but not a top-level object — for our use case (npm
  # package.json parsing) that's still malformed.
  printf '[1,2,3]\n' > "${cfg}"
  local rc
  _read_json_field "${cfg}" version >/dev/null
  rc=$?
  assert_eq "${rc}" "2" "non-object root JSON is malformed for this reader"
}

t_read_json_field_rc_0_on_missing_file() {
  local rc
  _read_json_field /nonexistent/path.json version >/dev/null
  rc=$?
  assert_eq "${rc}" "0" "missing file is rc 0 (nothing to parse — not a discovery error)"
}

# CodeRabbit regression: prior parser accepted a non-target scalar
# whose value was any run of non-delimiter bytes, so an invalid token
# like `wat` slipped through and the caller received a "valid version"
# from a malformed document. The scalar-validate step now rejects
# anything outside the JSON scalar grammar (true / false / null / a
# well-formed number per RFC 8259).
t_read_json_field_rc_2_on_garbage_non_target_scalar() {
  local dir; dir="$(mktest_tmp)"
  local cfg="${dir}/pkg.json"
  # Valid target string BEFORE the garbage. If the parser were still
  # lenient it would already have `val="1.2.3"` captured and exit 0.
  printf '{"version":"1.2.3","other":wat}' > "${cfg}"
  local out rc
  out="$(_read_json_field "${cfg}" version)"
  rc=$?
  assert_eq "${out}" "" "malformed JSON must not emit a captured value from an earlier member"
  assert_eq "${rc}"  "2" "unquoted garbage scalar (wat) must be rc 2, not treated as a valid non-target value"
}

# CodeRabbit regression: prior parser silently consumed a `,` between
# any two positions in the object body — including immediately before
# the closing `}` (trailing comma). RFC 8259 disallows trailing commas
# in JSON, so a document with one must return rc 2 and record as a
# discovery error, not silently produce the version from the preceding
# member.
t_read_json_field_rc_2_on_trailing_comma() {
  local dir; dir="$(mktest_tmp)"
  local cfg="${dir}/pkg.json"
  printf '{"version":"1.2.3",}' > "${cfg}"
  local out rc
  out="$(_read_json_field "${cfg}" version)"
  rc=$?
  assert_eq "${out}" "" "trailing comma must not emit a captured value from the preceding member"
  assert_eq "${rc}"  "2" "trailing comma is malformed JSON — rc 2"
}

# Also cover a leading / double comma (`{,"a":1}` and `{"a":1,,"b":2}`).
# These land in the same code path (comma without a preceding completed
# member) so we get symmetric coverage cheaply.
t_read_json_field_rc_2_on_leading_or_double_comma() {
  local dir; dir="$(mktest_tmp)"
  local cfg="${dir}/pkg.json"

  printf '{,"version":"1.2.3"}' > "${cfg}"
  local rc
  _read_json_field "${cfg}" version >/dev/null
  rc=$?
  assert_eq "${rc}" "2" "leading comma inside object is malformed"

  printf '{"version":"1.2.3",,"other":"x"}' > "${cfg}"
  _read_json_field "${cfg}" version >/dev/null
  rc=$?
  assert_eq "${rc}" "2" "double comma inside object is malformed"
}

# Regression pin for CodeRabbit ID 3802850710: two adjacent members
# without a comma between them (`{"a":"1" "b":"2"}`) is malformed per
# RFC 8259 — the parser previously accepted this because it never
# required a separator before the next quoted key. rc 2 keeps
# _probe_json_version's malformed-json path engaged instead of
# silently returning a truncated document's earlier value.
t_read_json_field_rc_2_on_missing_comma_between_members() {
  local dir; dir="$(mktest_tmp)"
  local cfg="${dir}/pkg.json"

  # Missing comma between the target field and the next member.
  printf '{"version":"1.2.3" "other":true}' > "${cfg}"
  local out rc
  out="$(_read_json_field "${cfg}" version)"
  rc=$?
  assert_eq "${out}" "" "missing-comma object must not emit the earlier member's value"
  assert_eq "${rc}"  "2" "missing comma between top-level members is malformed — rc 2"

  # Symmetric: missing comma where the earlier member is a non-target scalar
  # (target still appears later). Parser must reject BEFORE consuming target.
  printf '{"other":42 "version":"9.9.9"}' > "${cfg}"
  out="$(_read_json_field "${cfg}" version)"
  rc=$?
  assert_eq "${out}" "" "missing-comma object with target as later member is malformed"
  assert_eq "${rc}"  "2" "missing comma is malformed even when target appears after — rc 2"
}

# End-to-end guard: _probe_json_version must record the missing-comma
# document as malformed-json so install.sh's zero-target branch
# surfaces the corrupt metadata file to the operator.
t_probe_json_version_records_missing_comma() {
  local dir; dir="$(mktest_tmp)"
  local cfg="${dir}/pkg.json"
  local log; log="${dir}/errors.log"
  : > "${log}"

  printf '{"version":"1.2.3" "other":true}' > "${cfg}"
  local out
  out="$(DC_DISCOVERY_ERRORS_LOG="${log}" \
         DC_INSTALLER_TARGET_USER="alice" \
         _probe_json_version "${cfg}" codex)"
  assert_eq "${out}" "" "missing-comma package.json yields empty version through the probe"
  assert_contains "$(cat "${log}")" "malformed-json" "missing comma recorded as malformed-json"
  assert_contains "$(cat "${log}")" "${cfg}" "missing comma records failing path"
}

# End-to-end guard: _probe_json_version must record both bad inputs as
# malformed-json in DC_DISCOVERY_ERRORS_LOG (so install.sh's zero-
# target branch can surface a corrupt metadata file instead of
# silently classifying it as "connector not installed"). Sanity-checks
# that the fixed parser's rc 2 flows through the wrapper.
t_probe_json_version_records_garbage_and_trailing_comma() {
  local dir; dir="$(mktest_tmp)"
  local cfg="${dir}/pkg.json"
  local log; log="${dir}/errors.log"
  : > "${log}"

  # Garbage non-target scalar.
  printf '{"version":"1.2.3","other":wat}' > "${cfg}"
  local out
  out="$(DC_DISCOVERY_ERRORS_LOG="${log}" \
         DC_INSTALLER_TARGET_USER="alice" \
         _probe_json_version "${cfg}" codex)"
  assert_eq "${out}" "" "garbage-scalar package.json yields empty version through the probe"
  assert_contains "$(cat "${log}")" "malformed-json" "garbage scalar recorded as malformed-json"
  assert_contains "$(cat "${log}")" "${cfg}" "garbage scalar records failing path"

  # Reset log and try trailing comma.
  : > "${log}"
  printf '{"version":"1.2.3",}' > "${cfg}"
  out="$(DC_DISCOVERY_ERRORS_LOG="${log}" \
         DC_INSTALLER_TARGET_USER="alice" \
         _probe_json_version "${cfg}" codex)"
  assert_eq "${out}" "" "trailing-comma package.json yields empty version through the probe"
  assert_contains "$(cat "${log}")" "malformed-json" "trailing comma recorded as malformed-json"
}

# Positive-side smoke: the tightened parser must NOT reject well-formed
# JSON that mixes different scalar types (string, number, literal).
# Regression guard so the fix above doesn't over-strict.
t_read_json_field_rc_0_on_mixed_valid_scalars() {
  local dir; dir="$(mktest_tmp)"
  local cfg="${dir}/pkg.json"
  printf '{"version":"1.2.3","count":42,"active":true,"data":null,"ratio":-3.14e2}' > "${cfg}"
  local out rc
  out="$(_read_json_field "${cfg}" version)"
  rc=$?
  assert_eq "${out}" "1.2.3" "well-formed multi-type object still extracts target"
  assert_eq "${rc}"  "0" "well-formed multi-type object is rc 0"
}

t_probe_json_version_records_malformed_when_log_set() {
  local dir; dir="$(mktest_tmp)"
  local cfg="${dir}/pkg.json"
  local log="${dir}/errors.log"
  : > "${log}"
  # Malformed: unclosed object.
  printf '{"version":"1.0.0"' > "${cfg}"
  local out
  # Assignments must live INSIDE the command substitution — otherwise
  # `VAR=x out="$(...)"` is a list of assignments to the test shell, not
  # an env prefix for the probe, and the DC_* values leak into every
  # test case that runs after this one. Shellcheck SC2034.
  out="$(DC_DISCOVERY_ERRORS_LOG="${log}" \
         DC_INSTALLER_TARGET_USER="alice" \
         _probe_json_version "${cfg}" codex)"
  assert_eq "${out}" "" "malformed metadata produces empty version output"
  # Log line must carry user, connector, reason, path — tab-separated.
  local line
  line="$(cat "${log}")"
  assert_contains "${line}" "alice"          "discovery log records target user"
  assert_contains "${line}" "codex"          "discovery log records connector"
  assert_contains "${line}" "malformed-json" "discovery log records short reason"
  assert_contains "${line}" "${cfg}"         "discovery log records failing path"
}

t_probe_json_version_no_log_when_env_unset() {
  local dir; dir="$(mktest_tmp)"
  local cfg="${dir}/pkg.json"
  printf '{"version":' > "${cfg}"
  local out rc
  unset DC_DISCOVERY_ERRORS_LOG
  out="$(_probe_json_version "${cfg}" codex)"
  rc=$?
  assert_eq "${out}" "" "malformed metadata with no log configured still emits empty"
  assert_eq "${rc}"  "0" "probe never bubbles rc 2 up; error is quietly recorded via the log"
}

t_probe_json_version_passthrough_on_wellformed() {
  local dir; dir="$(mktest_tmp)"
  local cfg="${dir}/pkg.json"
  local log="${dir}/errors.log"
  : > "${log}"
  printf '{"name":"@openai/codex","version":"0.142.0"}\n' > "${cfg}"
  local out
  out="$(DC_DISCOVERY_ERRORS_LOG="${log}" _probe_json_version "${cfg}" codex)"
  assert_eq "${out}" "0.142.0" "well-formed metadata passes the version through"
  assert_eq "$(wc -c < "${log}" | tr -d ' ')" "0" \
    "well-formed metadata does NOT append to the discovery error log"
}

t_discover_agent_version_records_error_for_corrupt_codex_npm() {
  # QA scenario: user has codex installed via npm but the package.json
  # got truncated (partial download, disk full during install). Without
  # discovery-error propagation, discover_agent_version returned "" and
  # install.sh silently classified this as "codex not installed —
  # nothing to wire", proceeded, and the customer's codex hook was
  # never registered. The reconciler could not recover on its own.
  # With the DC_DISCOVERY_ERRORS_LOG side channel, the corrupt
  # package.json is now surfaced to install.sh as a fatal condition.
  #
  # Passive discovery always inspects this user metadata before any paired
  # system source, so the corruption is reported even if a system npm image
  # can subsequently supply a usable version.
  local home; home="$(mktest_tmp)"
  local log; log="$(mktest_tmp)/log"
  : > "${log}"
  local pkg_dir="${home}/.npm-global/lib/node_modules/@openai/codex"
  mkdir -p "${pkg_dir}"
  # Truncated mid-key — obviously malformed.
  printf '{"version"' > "${pkg_dir}/package.json"

  local got
  got="$(DC_DISCOVERY_ERRORS_LOG="${log}" \
         DC_INSTALLER_TARGET_USER="bob" \
         without_host_agent_bins discover_agent_version codex "${home}" 2>/dev/null || true)"
  if [[ -n "${got}" && ! "${got}" =~ ^[0-9]+\.[0-9]+ ]]; then
    _fail "corrupt home metadata fell through to malformed version output: ${got}"
  fi
  # The log must have received an entry pointing at the corrupt file.
  assert_contains "$(cat "${log}")" "@openai/codex/package.json" \
    "corrupt codex package.json path was recorded in the discovery error log"
}

run_case "amp from trusted user npm metadata" t_amp_from_user_npm_metadata_without_executing_cli
run_case "amp package metadata identity"      t_amp_metadata_requires_package_identity
run_case "amp without metadata is unversioned" t_amp_missing_metadata_may_be_unversioned
run_case "claudecode extension metadata is not executable authority" t_claudecode_extension_metadata_is_not_executable_authority
run_case "claudecode VS Code metadata is not executable authority" t_claudecode_vscode_metadata_is_not_executable_authority
run_case "claudecode native version image is paired passively" t_claudecode_native_version_image_is_paired_passively
run_case "codex standalone newest version is numeric and passive" t_codex_standalone_newest_version_is_numeric_and_passive
run_case "claudecode without install"        t_claudecode_no_install_returns_empty
run_case "codex without home metadata"       t_codex_no_home_metadata_uses_system_or_empty
run_case "codex from user npm metadata"      t_codex_from_user_npm_metadata
run_case "codex ChatGPT.app is not a preselection source" t_codex_chatgpt_app_is_not_a_preselection_source
run_case "opencode from user npm metadata without CLI execution" t_opencode_from_user_npm_metadata_without_executing_cli
run_case "opencode package metadata requires identity + semver" t_opencode_package_metadata_requires_identity_and_semver
run_case "opencode Homebrew metadata uses active formula without executing it" t_opencode_homebrew_metadata_uses_active_formula_without_executing_client
run_case "opencode app metadata requires official identity" t_opencode_app_metadata_requires_official_identity
run_case "bounded agent probe uses target user and exact binary" t_bounded_agent_probe_uses_target_user_and_exact_binary
run_case "opencode standalone uses bounded target-user probe" t_opencode_standalone_uses_bounded_target_user_probe
run_case "opencode standalone rejects invalid version output" t_opencode_standalone_rejects_invalid_version_output
run_case "unknown connector returns empty"   t_unknown_connector
run_case "_read_json_field decodes \\uXXXX under UTF-8 locale" t_read_json_field_decodes_unicode_escape_bytes
run_case "_read_json_field rc 0 for well-formed w/o field" t_read_json_field_rc_0_on_wellformed_missing_field
run_case "_read_json_field rc 2 for malformed body"        t_read_json_field_rc_2_on_malformed
run_case "_read_json_field rc 2 for non-object root"       t_read_json_field_rc_2_on_non_object_root
run_case "_read_json_field rc 0 for missing file"          t_read_json_field_rc_0_on_missing_file
run_case "_read_json_field rc 2 on garbage non-target scalar" t_read_json_field_rc_2_on_garbage_non_target_scalar
run_case "_read_json_field rc 2 on trailing comma"           t_read_json_field_rc_2_on_trailing_comma
run_case "_read_json_field rc 2 on leading/double comma"     t_read_json_field_rc_2_on_leading_or_double_comma
run_case "_read_json_field rc 2 on missing comma between members" t_read_json_field_rc_2_on_missing_comma_between_members
run_case "_read_json_field rc 0 on mixed valid scalars"      t_read_json_field_rc_0_on_mixed_valid_scalars
run_case "_probe_json_version records garbage/trailing-comma" t_probe_json_version_records_garbage_and_trailing_comma
run_case "_probe_json_version records missing comma"          t_probe_json_version_records_missing_comma
run_case "_probe_json_version records malformed when log set"    t_probe_json_version_records_malformed_when_log_set
run_case "_probe_json_version no log without env var set"        t_probe_json_version_no_log_when_env_unset
run_case "_probe_json_version passthrough on well-formed"        t_probe_json_version_passthrough_on_wellformed
run_case "discover_agent_version records corrupt codex metadata" t_discover_agent_version_records_error_for_corrupt_codex_npm
