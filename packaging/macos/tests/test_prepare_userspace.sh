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

t_dispatch_via_lib_subcommand() {
  local home; home="$(mktest_tmp)"
  /bin/bash "${PKG_DIR}/lib/installer_lib.sh" prepare-userspace cursor "${home}"
  assert_file_exists "${home}/.cursor/hooks.json"
  assert_file_mode "${home}/.cursor/hooks.json" "600"
}

t_dispatch_via_lib_subcommand_rejects_symlink() {
  local home target status
  home="$(mktest_tmp)"
  target="$(mktest_tmp)"
  ln -s "${target}" "${home}/.cursor"
  /bin/bash "${PKG_DIR}/lib/installer_lib.sh" prepare-userspace cursor "${home}"
  status=$?
  assert_status "${status}" 1 "installer_lib prepare-userspace rejects symlinked .cursor"
  if [[ -e "${target}/hooks.json" ]]; then
    _fail "symlink target ${target}/hooks.json was written through"
  fi
}

# Symlink-rejection matrix: for each connector, we exercise both
# the directory-symlink and file-symlink attack surfaces, and after
# rejection we verify the symlink target was never written to.

# Helper: run prep(<dir>), assert exit=1, verify target untouched.
_assert_symlink_dir_rejected() {
  local prep="$1"     # function name
  local subdir="$2"   # e.g. .codex
  local leaf="$3"     # e.g. config.toml
  local home target status
  home="$(mktest_tmp)"
  target="$(mktest_tmp)"
  ln -s "${target}" "${home}/${subdir}"
  "${prep}" "${home}"
  status=$?
  assert_status "${status}" 1 "symlinked ${subdir} rejected"
  if [[ -e "${target}/${leaf}" ]]; then
    _fail "symlink target ${target}/${leaf} was written through"
  fi
}

# Helper: for a file-symlink, stage a canary in the target; prep must
# refuse and the canary must remain unchanged.
_assert_symlink_file_rejected() {
  local prep="$1"     # function name
  local subdir="$2"
  local leaf="$3"
  local canary="$4"   # sentinel content
  local home target status
  home="$(mktest_tmp)"
  target="$(mktest_tmp)/${leaf}"
  mkdir -p "${home}/${subdir}" "$(dirname "${target}")"
  printf '%s\n' "${canary}" > "${target}"
  ln -s "${target}" "${home}/${subdir}/${leaf}"
  "${prep}" "${home}"
  status=$?
  assert_status "${status}" 1 "symlinked ${subdir}/${leaf} rejected"
  local now; now="$(cat "${target}")"
  assert_eq "${now}" "${canary}" "symlink target ${target} untouched"
}

t_codex_rejects_symlink_dir()      { _assert_symlink_dir_rejected  prepare_codex_userspace      .codex   config.toml; }
t_codex_rejects_symlink_file()     { _assert_symlink_file_rejected prepare_codex_userspace      .codex   config.toml   "USER_CANARY_CODEX"; }
t_claudecode_rejects_symlink_dir() { _assert_symlink_dir_rejected  prepare_claudecode_userspace .claude  settings.json; }
t_claudecode_rejects_symlink_file(){ _assert_symlink_file_rejected prepare_claudecode_userspace .claude  settings.json '{"user":"canary"}'; }
t_cursor_rejects_symlink_dir()     { _assert_symlink_dir_rejected  prepare_cursor_userspace     .cursor  hooks.json; }
t_cursor_rejects_symlink_file()    { _assert_symlink_file_rejected prepare_cursor_userspace     .cursor  hooks.json    '{"user":"canary"}'; }

run_case "codex userspace pre-create + idempotent" t_codex_creates
run_case "claudecode userspace pre-create"         t_claudecode_creates
run_case "cursor userspace pre-create"             t_cursor_creates
run_case "prepare_userspace_for dispatch"          t_dispatch_via_helper
run_case "installer_lib prepare-userspace dispatch" t_dispatch_via_lib_subcommand
run_case "installer_lib prepare-userspace rejects symlink" t_dispatch_via_lib_subcommand_rejects_symlink
run_case "codex rejects symlinked .codex dir"      t_codex_rejects_symlink_dir
run_case "codex rejects symlinked config.toml"     t_codex_rejects_symlink_file
run_case "claudecode rejects symlinked .claude dir" t_claudecode_rejects_symlink_dir
run_case "claudecode rejects symlinked settings.json" t_claudecode_rejects_symlink_file
run_case "cursor rejects symlinked .cursor dir"    t_cursor_rejects_symlink_dir
run_case "cursor rejects symlinked hooks.json"     t_cursor_rejects_symlink_file
