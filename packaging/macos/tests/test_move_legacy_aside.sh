#!/usr/bin/env bash
# move_legacy_aside: pure-function relocation of legacy DefenseClaw
# paths under a caller-supplied backup root. Used by the idempotent-
# reinstall flow so an existing legacy layout (pre-Cisco path) is
# preserved for forensics rather than deleted or triggering a hard
# refusal.
. "${PKG_DIR}/lib/installer_lib.sh"

t_missing_path_is_noop() {
  local case_dir backup_root
  case_dir="$(mktest_tmp)"
  backup_root="${case_dir}/backup"
  mkdir "${backup_root}"
  # Nonexistent source path must succeed silently (exit 0, no output).
  local out
  out="$(move_legacy_aside "${case_dir}/does-not-exist" "${backup_root}" "0.8.4" 2>&1)"
  assert_eq "${out}" "" "no output on missing path"
  assert_eq "$(ls "${backup_root}")" "" "backup root remains empty"
}

t_moves_regular_dir_aside() {
  local case_dir backup_root legacy
  case_dir="$(mktest_tmp)"
  backup_root="${case_dir}/backup"
  legacy="${case_dir}/DefenseClaw"
  mkdir "${backup_root}"
  mkdir "${legacy}"
  printf 'legacy-marker\n' >"${legacy}/state"

  local out
  out="$(move_legacy_aside "${legacy}" "${backup_root}" "0.8.4" 2>&1)"
  assert_contains "${out}" "moved legacy path aside" "logs the relocation"
  assert_contains "${out}" "${legacy}" "logs the source"
  assert_contains "${out}" "${backup_root}/DefenseClaw.pre-0.8.4-" \
    "target path uses the pre-<version>- prefix"

  # Source is gone.
  [[ ! -e "${legacy}" ]] || _fail "legacy path still exists after move"

  # Target exists under backup_root and contains the original content.
  local found
  found="$(find "${backup_root}" -maxdepth 1 -name 'DefenseClaw.pre-0.8.4-*' | head -1)"
  [[ -n "${found}" ]] || _fail "no backup path created"
  [[ -d "${found}" ]] || _fail "backup path is not a directory"
  assert_eq "$(cat "${found}/state")" "legacy-marker" "content preserved"
}

t_moves_regular_file_aside() {
  local case_dir backup_root legacy
  case_dir="$(mktest_tmp)"
  backup_root="${case_dir}/backup"
  legacy="${case_dir}/com.defenseclaw.gateway.plist"
  mkdir "${backup_root}"
  printf 'legacy-plist\n' >"${legacy}"

  move_legacy_aside "${legacy}" "${backup_root}" "0.8.4" >/dev/null 2>&1 \
    || _fail "move_legacy_aside failed on regular file"

  [[ ! -e "${legacy}" ]] || _fail "legacy file still exists after move"
  local found
  found="$(find "${backup_root}" -maxdepth 1 -name 'com.defenseclaw.gateway.plist.pre-0.8.4-*' | head -1)"
  [[ -n "${found}" ]] || _fail "no backup file created"
  assert_eq "$(cat "${found}")" "legacy-plist" "file content preserved"
}

t_dry_run_does_not_touch_disk() {
  local case_dir backup_root legacy
  case_dir="$(mktest_tmp)"
  backup_root="${case_dir}/backup"
  legacy="${case_dir}/DefenseClaw"
  mkdir "${backup_root}"
  mkdir "${legacy}"
  printf 'preserve\n' >"${legacy}/marker"

  local out
  out="$(move_legacy_aside "${legacy}" "${backup_root}" "0.8.4" --dry-run 2>&1)"
  assert_contains "${out}" "would move legacy path aside" "logs dry-run intent"

  # Source unchanged.
  [[ -d "${legacy}" ]] || _fail "dry-run mutated source directory"
  assert_eq "$(cat "${legacy}/marker")" "preserve" "dry-run left content untouched"

  # Backup root empty.
  assert_eq "$(ls "${backup_root}")" "" "dry-run did not populate backup root"
}

t_second_call_is_idempotent() {
  # After the first call moves the source aside, a second call with
  # the same source path is a no-op (the source no longer exists).
  local case_dir backup_root legacy
  case_dir="$(mktest_tmp)"
  backup_root="${case_dir}/backup"
  legacy="${case_dir}/DefenseClaw"
  mkdir "${backup_root}"
  mkdir "${legacy}"

  move_legacy_aside "${legacy}" "${backup_root}" "0.8.4" >/dev/null 2>&1 \
    || _fail "first move failed"
  # Should succeed silently.
  local rc=0
  move_legacy_aside "${legacy}" "${backup_root}" "0.8.4" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 0 "second move on absent path is a no-op"
}

t_missing_backup_root_returns_error() {
  local case_dir legacy
  case_dir="$(mktest_tmp)"
  legacy="${case_dir}/DefenseClaw"
  mkdir "${legacy}"
  local rc=0
  move_legacy_aside "${legacy}" "${case_dir}/nonexistent-backup" "0.8.4" \
    >/dev/null 2>&1 || rc=$?
  # exit 3 == backup_root missing (see installer_lib.sh:move_legacy_aside).
  assert_status "${rc}" 3 "missing backup_root returns error 3"
  [[ -d "${legacy}" ]] || _fail "source directory clobbered on error path"
}

t_symlink_target_relocated() {
  # A symlink at the legacy path is itself relocated (the symlink,
  # not the pointee). The reinstall contract's goal is to clear the
  # legacy path from the filesystem so a fresh render can land; the
  # symlink target belongs to whoever created it.
  local case_dir backup_root legacy target
  case_dir="$(mktest_tmp)"
  backup_root="${case_dir}/backup"
  target="${case_dir}/actual-content"
  legacy="${case_dir}/DefenseClaw"
  mkdir "${backup_root}"
  mkdir "${target}"
  printf 'pointee\n' >"${target}/keep-me"
  ln -s "${target}" "${legacy}"

  move_legacy_aside "${legacy}" "${backup_root}" "0.8.4" >/dev/null 2>&1 \
    || _fail "move failed on symlink"

  # Symlink at the legacy location is gone.
  [[ ! -L "${legacy}" && ! -e "${legacy}" ]] || _fail "legacy symlink still present"
  # Pointee (the actual content) is untouched.
  [[ -d "${target}" ]] || _fail "pointee content was disturbed"
  assert_eq "$(cat "${target}/keep-me")" "pointee" "pointee content preserved"
}

run_case "missing path is a no-op"                     t_missing_path_is_noop
run_case "moves regular dir aside with timestamped backup" t_moves_regular_dir_aside
run_case "moves regular file aside"                    t_moves_regular_file_aside
run_case "dry-run leaves disk untouched"               t_dry_run_does_not_touch_disk
run_case "second call is idempotent"                   t_second_call_is_idempotent
run_case "missing backup_root returns error"           t_missing_backup_root_returns_error
run_case "symlink target relocated, pointee preserved" t_symlink_target_relocated
