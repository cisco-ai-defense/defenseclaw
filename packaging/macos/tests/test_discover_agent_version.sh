#!/usr/bin/env bash
# discover_agent_version: per-connector metadata probing.
#
# The lib never execs agent binaries (see the security note in
# installer_lib.sh:discover_agent_version), so all cases are driven from
# staged tmpdirs / bundle files — no host-agent leakage possible.
. "${PKG_DIR}/lib/installer_lib.sh"

# Wrapper that masks any host `claude` / `codex` CLI on PATH. We used
# to need this because the lib exec'd those binaries; keeping it around
# guards against a regression where a future CLI probe reintroduces the
# code-exec surface.
without_host_agent_bins() {
  local fakebin
  fakebin="$(mktest_tmp)"
  local bin
  for bin in claude codex; do
    cat > "${fakebin}/${bin}" <<'SH'
#!/usr/bin/env bash
exit 127
SH
    chmod 0700 "${fakebin}/${bin}"
  done
  PATH="${fakebin}:${PATH}" "$@"
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
  # /opt/homebrew/Caskroom/codex etc. On a CI/dev box without codex
  # installed anywhere, that returns empty. On a dev box with codex
  # installed, we get a real version (that's fine — the point of
  # discover_agent_version is to find one when it exists). Both are
  # valid; assert the shape rather than the specific value.
  local home; home="$(mktest_tmp)"
  local got
  got="$(without_host_agent_bins discover_agent_version codex "${home}" 2>/dev/null || true)"
  # Either empty, or a plausible version string (semver-ish).
  if [[ -n "${got}" && ! "${got}" =~ ^[0-9]+\.[0-9]+ ]]; then
    _fail "codex probe returned unexpected non-empty non-version: ${got}"
    return 1
  fi
}

t_codex_from_user_npm_metadata() {
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

t_json_version_rejects_control_syntax() {
  local root got
  root="$(mktest_tmp)"
  cat > "${root}/package.json" <<'JSON'
{ "name": "untrusted", "version": "1.2.3;$(touch /tmp/not-allowed)" }
JSON
  got="$(_read_json_version "${root}/package.json")"
  assert_eq "${got}" "" "untrusted package version syntax rejected"
}

t_json_version_rejects_fifo_without_blocking() {
  local root fifo output pid still_running
  root="$(mktest_tmp)"
  fifo="${root}/package.json"
  output="${root}/output"
  mkfifo "${fifo}"
  _read_json_version "${fifo}" >"${output}" &
  pid=$!
  still_running=true
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if ! kill -0 "${pid}" 2>/dev/null; then
      still_running=false
      break
    fi
    sleep 0.05
  done
  if [[ "${still_running}" == "true" ]]; then
    kill -9 "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
    _fail "FIFO package metadata blocked the privileged version probe"
    return 1
  fi
  wait "${pid}" || true
  assert_eq "$(cat "${output}")" "" "FIFO package metadata is rejected"
}

t_json_version_rejects_oversized_metadata() {
  local root got
  root="$(mktest_tmp)"
  dd if=/dev/zero of="${root}/package.json" bs=1024 count=257 2>/dev/null
  got="$(_read_json_version "${root}/package.json")"
  assert_eq "${got}" "" "oversized package metadata rejected"
}

run_case "claudecode via Cursor extension"   t_claudecode_via_cursor_extension
run_case "claudecode via VS Code extension"  t_claudecode_via_vscode_extension
run_case "claudecode without install"        t_claudecode_no_install_returns_empty
run_case "codex without home metadata"       t_codex_no_home_metadata_uses_system_or_empty
run_case "codex from user npm metadata"      t_codex_from_user_npm_metadata
run_case "unknown connector returns empty"   t_unknown_connector
run_case "package JSON version syntax is bounded" t_json_version_rejects_control_syntax
run_case "package JSON FIFO is non-blocking" t_json_version_rejects_fifo_without_blocking
run_case "package JSON size is bounded" t_json_version_rejects_oversized_metadata
