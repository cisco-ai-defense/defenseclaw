#!/usr/bin/env bash
# discover_agent_version: per-connector metadata probing.
#
# The lib never execs agent binaries (see the security note in
# installer_lib.sh:discover_agent_version), so all cases are driven from
# staged tmpdirs / bundle files — no host-agent leakage possible.
. "${PKG_DIR}/lib/installer_lib.sh"

# Wrapper that masks any host `amp` / `claude` / `codex` CLI on PATH. We used
# to need this because the lib exec'd those binaries; keeping it around
# guards against a regression where a future CLI probe reintroduces the
# code-exec surface.
without_host_agent_bins() {
  local fakebin
  fakebin="$(mktest_tmp)"
  local bin
  for bin in amp claude codex; do
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

t_claudecode_via_cursor_extension() {
  local home; home="$(mktest_tmp)"
  local ext="${home}/.cursor/extensions/anthropic.claude-code-2.1.195-darwin-arm64"
  mkdir -p "${ext}"
  cat > "${ext}/package.json" <<'JSON'
{ "name": "claude-code", "version": "2.1.195" }
JSON

  local got
  got="$(without_host_agent_bins discover_agent_version claudecode "${home}")"
  assert_eq "${got}" "2.1.195" "claudecode version from Cursor extension"
}

t_claudecode_via_vscode_extension() {
  local home; home="$(mktest_tmp)"
  local ext="${home}/.vscode/extensions/anthropic.claude-code-2.0.99-darwin-arm64"
  mkdir -p "${ext}"
  cat > "${ext}/package.json" <<'JSON'
{ "name": "claude-code", "version": "2.0.99" }
JSON

  local got
  got="$(without_host_agent_bins discover_agent_version claudecode "${home}")"
  assert_eq "${got}" "2.0.99" "claudecode version from VS Code extension"
}

t_claudecode_no_install_returns_empty() {
  # Empty tmp HOME + no CLI on PATH → empty version, cleanly.
  local home; home="$(mktest_tmp)"
  local got
  got="$(without_host_agent_bins discover_agent_version claudecode "${home}" 2>/dev/null || true)"
  assert_eq "${got}" "" "claudecode with no CLI/extensions returns empty"
}

t_codex_no_home_metadata_uses_system_or_empty() {
  # With no metadata under the tmp HOME, the probe falls through to
  # /Applications/ChatGPT.app -> Homebrew Caskroom -> system npm dirs
  # -> PATH. On a CI/dev box without any codex install, that returns
  # empty. On a dev box with codex installed (via any channel), we get
  # a real version. Both are valid; assert the shape rather than the
  # specific value.
  local home; home="$(mktest_tmp)"
  local got
  got="$(without_host_agent_bins discover_agent_version codex "${home}" 2>/dev/null || true)"
  # Either empty, or a plausible version string (semver-ish, possibly
  # with an -alpha.N / -beta.N suffix from ChatGPT.app pre-release builds).
  if [[ -n "${got}" && ! "${got}" =~ ^[0-9]+\.[0-9]+ ]]; then
    _fail "codex probe returned unexpected non-empty non-version: ${got}"
    return 1
  fi
}

t_codex_chatgpt_app_bundled_wins_over_npm() {
  # Regression guard for the sathishr scenario: a customer with a stale
  # `npm i -g @openai/codex@0.104.0` (predating our MinAgentVersion
  # of 0.124.0) AND the ChatGPT.app desktop app installed (which
  # bundles Codex 0.145.0+) MUST have the probe return the newer
  # ChatGPT.app version. If the probe order regresses back to
  # npm-first, this test catches it because the stale npm metadata
  # would win and the guardian would fail with
  # "codex agent version 0.104.0 is not verified against a known
  # hook contract" on every reconcile — the exact silent-fail
  # surface we shipped with in early 2026.7.3.
  #
  # Runs only when /Applications/ChatGPT.app is present so CI /
  # non-desktop-app boxes still pass. On a box with ChatGPT.app
  # missing this returns "skip".
  local chatgpt_codex="/Applications/ChatGPT.app/Contents/Resources/codex"
  if [[ ! -x "${chatgpt_codex}" ]]; then
    if [[ "${VERBOSE:-false}" == "true" ]]; then printf '  skip (ChatGPT.app not installed)\n'; fi
    return 0
  fi
  local home; home="$(mktest_tmp)"
  # Seed a stale user-npm codex install like sathishr had.
  local pkg_dir="${home}/.npm-global/lib/node_modules/@openai/codex"
  mkdir -p "${pkg_dir}"
  cat > "${pkg_dir}/package.json" <<'JSON'
{ "name": "@openai/codex", "version": "0.104.0" }
JSON
  # Probe as this user (DC_INSTALLER_TARGET_USER must resolve — use
  # the current login user so sudo -n -u succeeds without a
  # password prompt).
  local got
  got="$(DC_INSTALLER_TARGET_USER="$(id -un)" discover_agent_version codex "${home}" 2>&1)"
  # Expect the ChatGPT.app-bundled version — a semver >= 0.124.0. The
  # stale 0.104.0 must NOT win.
  if [[ "${got}" == "0.104.0" ]]; then
    _fail "codex probe returned the stale npm 0.104.0 instead of the newer ChatGPT.app-bundled version — the ChatGPT.app-first probe order must remain intact"
    return 1
  fi
  if [[ ! "${got}" =~ ^[0-9]+\.[0-9]+ ]]; then
    _fail "codex probe returned unexpected value with both stale npm + ChatGPT.app present: '${got}'"
    return 1
  fi
}

t_codex_from_user_npm_metadata() {
  # Verifies the npm fallback branch: seed a user-scoped npm package.json
  # under the tmp HOME and expect the probe to read the version from it.
  # Skips when a higher-priority source is present on the host
  # (/Applications/ChatGPT.app-bundled binary or /*/Caskroom/codex/*
  # dir) — those correctly win over stale npm installs on real customer
  # boxes, but would defeat this test's fixture. The ChatGPT.app-wins
  # case is covered by t_codex_chatgpt_app_bundled_wins_over_npm above.
  if [[ -x /Applications/ChatGPT.app/Contents/Resources/codex ]] \
     || [[ -x /Applications/ChatGPT.app/Contents/MacOS/codex ]] \
     || compgen -G "/opt/homebrew/Caskroom/codex/*/" >/dev/null 2>&1 \
     || compgen -G "/usr/local/Caskroom/codex/*/" >/dev/null 2>&1; then
    if [[ "${VERBOSE:-false}" == "true" ]]; then
      printf '  skip (higher-priority codex source on host — see t_codex_chatgpt_app_bundled_wins_over_npm for the coverage)\n'
    fi
    return 0
  fi
  local home; home="$(mktest_tmp)"
  local pkg_dir="${home}/.npm-global/lib/node_modules/@openai/codex"
  mkdir -p "${pkg_dir}"
  cat > "${pkg_dir}/package.json" <<'JSON'
{ "name": "@openai/codex", "version": "0.142.0" }
JSON
  local got
  got="$(without_host_agent_bins discover_agent_version codex "${home}")"
  assert_eq "${got}" "0.142.0" "codex version from user-npm metadata"
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
  # Skip when a higher-priority codex source is present on the host —
  # ChatGPT.app / Caskroom win over the npm probe, so a real dev box
  # with codex installed via either channel would return a valid
  # version and never touch our corrupt fixture. The unit-level
  # coverage on _probe_json_version already proves the log-append
  # semantics; this is the end-to-end guard for the codex npm branch.
  if [[ -x /Applications/ChatGPT.app/Contents/Resources/codex ]] \
     || [[ -x /Applications/ChatGPT.app/Contents/MacOS/codex ]] \
     || compgen -G "/opt/homebrew/Caskroom/codex/*/" >/dev/null 2>&1 \
     || compgen -G "/usr/local/Caskroom/codex/*/" >/dev/null 2>&1; then
    if [[ "${VERBOSE:-false}" == "true" ]]; then
      printf '  skip (higher-priority codex source on host — end-to-end covered by _probe_json_version unit tests above)\n'
    fi
    return 0
  fi
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
  assert_eq "${got}" "" "corrupt npm package.json still yields empty version (fall-through preserved)"
  # The log must have received an entry pointing at the corrupt file.
  assert_contains "$(cat "${log}")" "@openai/codex/package.json" \
    "corrupt codex package.json path was recorded in the discovery error log"
}

run_case "amp from trusted user npm metadata" t_amp_from_user_npm_metadata_without_executing_cli
run_case "amp package metadata identity"      t_amp_metadata_requires_package_identity
run_case "amp without metadata is unversioned" t_amp_missing_metadata_may_be_unversioned
run_case "claudecode via Cursor extension"   t_claudecode_via_cursor_extension
run_case "claudecode via VS Code extension"  t_claudecode_via_vscode_extension
run_case "claudecode without install"        t_claudecode_no_install_returns_empty
run_case "codex without home metadata"       t_codex_no_home_metadata_uses_system_or_empty
run_case "codex from user npm metadata"      t_codex_from_user_npm_metadata
run_case "codex ChatGPT.app-bundled wins over stale npm" t_codex_chatgpt_app_bundled_wins_over_npm
run_case "unknown connector returns empty"   t_unknown_connector
run_case "_read_json_field decodes \\uXXXX under UTF-8 locale" t_read_json_field_decodes_unicode_escape_bytes
run_case "_read_json_field rc 0 for well-formed w/o field" t_read_json_field_rc_0_on_wellformed_missing_field
run_case "_read_json_field rc 2 for malformed body"        t_read_json_field_rc_2_on_malformed
run_case "_read_json_field rc 2 for non-object root"       t_read_json_field_rc_2_on_non_object_root
run_case "_read_json_field rc 0 for missing file"          t_read_json_field_rc_0_on_missing_file
run_case "_probe_json_version records malformed when log set"    t_probe_json_version_records_malformed_when_log_set
run_case "_probe_json_version no log without env var set"        t_probe_json_version_no_log_when_env_unset
run_case "_probe_json_version passthrough on well-formed"        t_probe_json_version_passthrough_on_wellformed
run_case "discover_agent_version records corrupt codex metadata" t_discover_agent_version_records_error_for_corrupt_codex_npm
