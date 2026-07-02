#!/usr/bin/env bash
# prepare_*_userspace: pre-create connector hook config files in a tmp HOME.
. "${PKG_DIR}/lib/installer_lib.sh"

t_codex_creates() {
  local home; home="$(mktest_tmp)"
  prepare_codex_userspace "${home}"
  assert_file_exists "${home}/.codex/config.toml"
  assert_file_mode "${home}/.codex/config.toml" "600"
  assert_file_mode "${home}/.codex" "700"

  # Idempotent: second call must not clobber.
  printf 'MY_USER_EDIT\n' >> "${home}/.codex/config.toml"
  prepare_codex_userspace "${home}"
  local body; body="$(cat "${home}/.codex/config.toml")"
  assert_contains "${body}" "MY_USER_EDIT" "idempotent: existing content preserved"
}

t_claudecode_creates() {
  local home; home="$(mktest_tmp)"
  prepare_claudecode_userspace "${home}"
  assert_file_exists "${home}/.claude/settings.json"
  assert_file_mode "${home}/.claude/settings.json" "600"
  assert_file_mode "${home}/.claude" "700"
  local body; body="$(cat "${home}/.claude/settings.json")"
  assert_eq "${body}" "{}" "settings.json initial body"
}

t_cursor_creates() {
  local home; home="$(mktest_tmp)"
  prepare_cursor_userspace "${home}"
  assert_file_exists "${home}/.cursor/hooks.json"
  assert_file_mode "${home}/.cursor/hooks.json" "600"
  assert_file_mode "${home}/.cursor" "700"
  local body; body="$(cat "${home}/.cursor/hooks.json")"
  assert_contains "${body}" '"version":1' "hooks.json carries schema version"
  assert_contains "${body}" '"hooks":{}'  "hooks.json has empty hooks map"
}

t_dispatch_via_helper() {
  local home; home="$(mktest_tmp)"
  prepare_userspace_for cursor     "${home}"
  prepare_userspace_for codex      "${home}"
  prepare_userspace_for claudecode "${home}"
  assert_file_exists "${home}/.cursor/hooks.json"
  assert_file_exists "${home}/.codex/config.toml"
  assert_file_exists "${home}/.claude/settings.json"
}

t_rejects_symlinked_agent_dir() {
  local home target status
  home="$(mktest_tmp)"
  target="$(mktest_tmp)"
  ln -s "${target}" "${home}/.codex"
  prepare_codex_userspace "${home}"
  status=$?
  assert_status "${status}" 1 "symlinked .codex rejected"
  if [[ -e "${target}/config.toml" ]]; then
    _fail "symlink target was written through"
  fi
}

t_rejects_symlinked_config_file() {
  local home target status
  home="$(mktest_tmp)"
  target="$(mktest_tmp)/settings.json"
  mkdir -p "${home}/.claude"
  printf '{}\n' > "${target}"
  ln -s "${target}" "${home}/.claude/settings.json"
  prepare_claudecode_userspace "${home}"
  status=$?
  assert_status "${status}" 1 "symlinked settings.json rejected"
}

run_case "codex userspace pre-create + idempotent" t_codex_creates
run_case "claudecode userspace pre-create"         t_claudecode_creates
run_case "cursor userspace pre-create"             t_cursor_creates
run_case "prepare_userspace_for dispatch"          t_dispatch_via_helper
run_case "symlinked agent dir rejected"            t_rejects_symlinked_agent_dir
run_case "symlinked config file rejected"          t_rejects_symlinked_config_file
