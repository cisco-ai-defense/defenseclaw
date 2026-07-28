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

t_descriptor_anchored_ownership() {
  local home uid gid
  home="$(mktest_tmp)"
  uid="$(id -u)"
  gid="$(id -g)"
  prepare_userspace_for codex "${home}" "${uid}" "${gid}"
  assert_file_exists "${home}/.codex/config.toml"
  local dir_owner file_owner
  dir_owner="$(stat -f '%u:%g' "${home}/.codex" 2>/dev/null || stat -c '%u:%g' "${home}/.codex")"
  file_owner="$(stat -f '%u:%g' "${home}/.codex/config.toml" 2>/dev/null || stat -c '%u:%g' "${home}/.codex/config.toml")"
  assert_eq "${dir_owner}" "${uid}:${gid}" "descriptor-anchored directory ownership"
  assert_eq "${file_owner}" "${uid}:${gid}" "descriptor-anchored config ownership"
}

t_descriptor_ownership_rejects_hardlinked_config() {
  local home source status uid gid
  home="$(mktest_tmp)"
  source="$(mktest_tmp)/source"
  uid="$(id -u)"
  gid="$(id -g)"
  mkdir -p "${home}/.codex"
  printf 'preserve-me\n' > "${source}"
  ln "${source}" "${home}/.codex/config.toml"
  status=0
  prepare_userspace_for codex "${home}" "${uid}" "${gid}" >/dev/null 2>&1 || status=$?
  assert_status "${status}" 1 "hardlinked config rejected before privileged ownership change"
  assert_eq "$(cat "${source}")" "preserve-me" "hardlink source remains unchanged"
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

t_atomic_creator_rejects_post_check_dangling_symlink() {
  local home target status
  home="$(mktest_tmp)"
  target="$(mktest_tmp)/root-write-canary"
  mkdir -p "${home}/.codex"
  # Simulate a user planting a dangling link after the shell precheck but
  # before the privileged creator opens the final component.
  ln -s "${target}" "${home}/.codex/config.toml"
  status=0
  printf 'attacker-chosen-write\n' \
    | create_userspace_config_if_missing "${home}/.codex" "config.toml" \
    >/dev/null 2>&1 || status=$?
  assert_status "${status}" 1 "post-check dangling symlink rejected"
  if [[ -e "${target}" || -L "${target}" ]]; then
    _fail "atomic creator followed dangling symlink to ${target}"
  fi
}

t_atomic_creator_rejects_post_check_directory_swap() {
  local home original attacker status
  home="$(mktest_tmp)"
  original="${home}/.cursor"
  attacker="$(mktest_tmp)"
  mkdir -p "${original}"
  # Simulate replacement of the checked directory before the anchored open.
  rmdir "${original}"
  ln -s "${attacker}" "${original}"
  status=0
  printf '{"version":1}\n' \
    | create_userspace_config_if_missing "${original}" "hooks.json" \
    >/dev/null 2>&1 || status=$?
  assert_status "${status}" 1 "post-check directory symlink rejected"
  if [[ -e "${attacker}/hooks.json" ]]; then
    _fail "atomic creator followed replaced parent to ${attacker}/hooks.json"
  fi
}

run_case "codex userspace pre-create + idempotent" t_codex_creates
run_case "claudecode userspace pre-create"         t_claudecode_creates
run_case "cursor userspace pre-create"             t_cursor_creates
run_case "prepare_userspace_for dispatch"          t_dispatch_via_helper
run_case "descriptor-anchored ownership"           t_descriptor_anchored_ownership
run_case "descriptor ownership rejects hardlink"  t_descriptor_ownership_rejects_hardlinked_config
run_case "codex rejects symlinked .codex dir"      t_codex_rejects_symlink_dir
run_case "codex rejects symlinked config.toml"     t_codex_rejects_symlink_file
run_case "claudecode rejects symlinked .claude dir" t_claudecode_rejects_symlink_dir
run_case "claudecode rejects symlinked settings.json" t_claudecode_rejects_symlink_file
run_case "cursor rejects symlinked .cursor dir"    t_cursor_rejects_symlink_dir
run_case "cursor rejects symlinked hooks.json"     t_cursor_rejects_symlink_file
run_case "atomic creator rejects post-check dangling symlink" t_atomic_creator_rejects_post_check_dangling_symlink
run_case "atomic creator rejects post-check directory swap" t_atomic_creator_rejects_post_check_directory_swap
