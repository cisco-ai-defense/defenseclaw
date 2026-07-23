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

t_claudecode_via_native_current_symlink() {
  # Native installer layout: ~/.local/share/claude/current is a
  # symlink to versions/<X.Y.Z>. This is the officially-recommended
  # install path (curl -fsSL https://claude.ai/install.sh | bash) and
  # what most users have today. Discovery must resolve the symlink
  # target's basename to the semver.
  local home; home="$(mktest_tmp)"
  local vers="${home}/.local/share/claude/versions"
  mkdir -p "${vers}/2.1.173"
  ln -s "versions/2.1.173" "${home}/.local/share/claude/current"

  local got
  got="$(without_host_agent_bins discover_agent_version claudecode "${home}")"
  assert_eq "${got}" "2.1.173" "claudecode version from native ~/.local/share/claude/current symlink"
}

t_claudecode_via_native_versions_dir_no_symlink() {
  # Partial-install fallback: no `current` symlink yet, but versions/*
  # is populated. Discovery must pick the highest semver-shaped basename.
  local home; home="$(mktest_tmp)"
  local vers="${home}/.local/share/claude/versions"
  mkdir -p "${vers}/2.1.171" "${vers}/2.1.173" "${vers}/2.1.170"

  local got
  got="$(without_host_agent_bins discover_agent_version claudecode "${home}")"
  assert_eq "${got}" "2.1.173" "claudecode picks highest versions/*/ when no current symlink"
}

t_claudecode_native_broken_current_symlink_falls_back() {
  # `current` symlink points at a nonexistent target (e.g. a manual
  # `rm -rf versions/*` after an aborted upgrade). Discovery must
  # fall back to the highest existing versions/* dir rather than
  # returning empty.
  local home; home="$(mktest_tmp)"
  local vers="${home}/.local/share/claude/versions"
  mkdir -p "${vers}/2.1.171"
  ln -s "versions/2.1.999-does-not-exist" "${home}/.local/share/claude/current"

  local got
  got="$(without_host_agent_bins discover_agent_version claudecode "${home}")"
  assert_eq "${got}" "2.1.171" "claudecode falls back to versions/*/ when current symlink dangles"
}

t_claudecode_native_wins_over_stale_npm() {
  # Regression guard for the reported bug: a user with the native
  # installer AND a stale ~/.npm-global copy of @anthropic-ai/claude-code
  # must NOT resolve to the stale npm version. If the probe order
  # regresses to npm-first, the hook-contract validator surfaces the
  # stale version and (in managed_enterprise mode=action) fails the
  # reconcile — the exact silent-fail surface this fix eliminates.
  local home; home="$(mktest_tmp)"
  local vers="${home}/.local/share/claude/versions"
  mkdir -p "${vers}/2.1.173"
  ln -s "versions/2.1.173" "${home}/.local/share/claude/current"

  local pkg_dir="${home}/.npm-global/lib/node_modules/@anthropic-ai/claude-code"
  mkdir -p "${pkg_dir}"
  cat > "${pkg_dir}/package.json" <<'JSON'
{ "name": "@anthropic-ai/claude-code", "version": "1.0.99" }
JSON

  local got
  got="$(without_host_agent_bins discover_agent_version claudecode "${home}")"
  assert_eq "${got}" "2.1.173" "native install must win over a stale npm-global claude-code"
}

t_claudecode_via_native_helper_direct() {
  # Direct exercise of the pure helper against an operator-supplied
  # base dir (matches how the system-wide Linux probes call it with
  # /opt/claude and /usr/local/share/claude). Keeps the helper's
  # contract testable without depending on how discover_agent_version
  # threads $home.
  local base; base="$(mktest_tmp)/opt-claude"
  mkdir -p "${base}/versions/2.1.180"
  ln -s "versions/2.1.180" "${base}/current"

  local got
  got="$(_native_claudecode_version_from_dir "${base}")"
  assert_eq "${got}" "2.1.180" "native helper resolves version from an arbitrary base dir"

  # Empty on a missing / non-conforming base.
  got="$(_native_claudecode_version_from_dir "${base}.does-not-exist" 2>/dev/null || true)"
  assert_eq "${got}" "" "native helper returns empty when base dir is missing"

  # Empty on a base with no current + no versions.
  local empty_base; empty_base="$(mktest_tmp)/empty-claude"
  mkdir -p "${empty_base}"
  got="$(_native_claudecode_version_from_dir "${empty_base}" 2>/dev/null || true)"
  assert_eq "${got}" "" "native helper returns empty when base dir has neither current nor versions"

  # Non-semver dir names are ignored.
  local weird_base; weird_base="$(mktest_tmp)/weird-claude"
  mkdir -p "${weird_base}/versions/latest" "${weird_base}/versions/nightly"
  got="$(_native_claudecode_version_from_dir "${weird_base}" 2>/dev/null || true)"
  assert_eq "${got}" "" "native helper rejects non-semver dir names"
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

run_case "claudecode via Cursor extension"   t_claudecode_via_cursor_extension
run_case "claudecode via VS Code extension"  t_claudecode_via_vscode_extension
run_case "claudecode without install"        t_claudecode_no_install_returns_empty
run_case "claudecode via native current symlink"                  t_claudecode_via_native_current_symlink
run_case "claudecode via native versions/*  (no symlink)"         t_claudecode_via_native_versions_dir_no_symlink
run_case "claudecode native broken current symlink falls back"    t_claudecode_native_broken_current_symlink_falls_back
run_case "claudecode native install wins over stale npm"          t_claudecode_native_wins_over_stale_npm
run_case "claudecode native helper direct-call semantics"         t_claudecode_via_native_helper_direct
run_case "codex without home metadata"       t_codex_no_home_metadata_uses_system_or_empty
run_case "codex from user npm metadata"      t_codex_from_user_npm_metadata
run_case "codex ChatGPT.app-bundled wins over stale npm" t_codex_chatgpt_app_bundled_wins_over_npm
run_case "unknown connector returns empty"   t_unknown_connector
