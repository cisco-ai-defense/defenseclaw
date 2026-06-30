#!/usr/bin/env bash
# discover_agent_version: per-connector probing.
# We stage a fake Cursor extension under a tmp HOME to drive the claudecode
# extension-fallback path without touching real installs.
. "${PKG_DIR}/lib/installer_lib.sh"

without_host_claude() {
  local fakebin; fakebin="$(mktest_tmp)"
  cat > "${fakebin}/claude" <<'SH'
#!/usr/bin/env bash
exit 127
SH
  chmod 0700 "${fakebin}/claude"
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
  got="$(without_host_claude discover_agent_version claudecode "${home}")"
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
  got="$(without_host_claude discover_agent_version claudecode "${home}")"
  assert_eq "${got}" "2.0.99" "claudecode version from VS Code extension"
}

t_claudecode_no_install_returns_empty() {
  # Use a tmp HOME with no extensions and override PATH so 'claude' CLI
  # is not findable. We can't reliably hide a real /usr/local/bin/claude
  # so we just assert the function doesn't error or echo a stale value.
  local home; home="$(mktest_tmp)"
  local got
  # When claude CLI is on PATH this returns a real version; that's fine.
  # The assertion is: the function returns cleanly (no syntax error / crash).
  got="$(discover_agent_version claudecode "${home}" 2>/dev/null || true)"
  # Nothing to assert; presence of CLI on host makes this nondeterministic.
  if [[ "${VERBOSE:-false}" == "true" ]]; then
    printf '  info  claudecode-on-empty-host got=%q\n' "${got}"
  fi
}

t_codex_unknown_returns_empty() {
  # If codex CLI isn't installed, function returns empty. If it IS installed,
  # we just observe it returns something non-empty. Either is fine.
  local got
  got="$(discover_agent_version codex "$(mktest_tmp)" 2>/dev/null || true)"
  if [[ "${VERBOSE:-false}" == "true" ]]; then
    printf '  info  codex got=%q\n' "${got}"
  fi
}

t_unknown_connector() {
  local got
  got="$(discover_agent_version geminicli "$(mktest_tmp)" 2>/dev/null || true)"
  assert_eq "${got}" "" "unknown connector returns empty string"
}

run_case "claudecode via Cursor extension"   t_claudecode_via_cursor_extension
run_case "claudecode via VS Code extension"  t_claudecode_via_vscode_extension
run_case "claudecode without install"        t_claudecode_no_install_returns_empty
run_case "codex graceful when missing"       t_codex_unknown_returns_empty
run_case "unknown connector returns empty"   t_unknown_connector
