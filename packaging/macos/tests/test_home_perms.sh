#!/usr/bin/env bash
# home_perms_ok mirrors the guardian's check: reject group/other-write.
. "${PKG_DIR}/lib/installer_lib.sh"

t_0755_passes() {
  local d; d="$(mktest_tmp)"
  chmod 0755 "${d}"
  local rc; home_perms_ok "${d}"; rc=$?
  assert_status "${rc}" 0 "0755 should pass"
}

t_0700_passes() {
  local d; d="$(mktest_tmp)"
  chmod 0700 "${d}"
  local rc; home_perms_ok "${d}"; rc=$?
  assert_status "${rc}" 0 "0700 should pass"
}

t_0770_rejected() {
  local d; d="$(mktest_tmp)"
  chmod 0770 "${d}"
  local rc; home_perms_ok "${d}"; rc=$?
  assert_status "${rc}" 1 "0770 (group-write) should fail"
}

t_0775_rejected() {
  local d; d="$(mktest_tmp)"
  chmod 0775 "${d}"
  local rc; home_perms_ok "${d}"; rc=$?
  assert_status "${rc}" 1 "0775 (group-write) should fail"
}

t_0707_rejected() {
  local d; d="$(mktest_tmp)"
  chmod 0707 "${d}"
  local rc; home_perms_ok "${d}"; rc=$?
  assert_status "${rc}" 1 "0707 (other-write) should fail"
}

t_missing_path_is_ok() {
  # When stat fails, we deliberately return ok so the install can proceed
  # (the guardian will catch the real check). This is documented.
  local rc; home_perms_ok "/nonexistent/$(date +%s)"; rc=$?
  assert_status "${rc}" 0 "nonexistent path returns ok (guardian re-checks)"
}

run_case "0755 passes"  t_0755_passes
run_case "0700 passes"  t_0700_passes
run_case "0770 rejected" t_0770_rejected
run_case "0775 rejected" t_0775_rejected
run_case "0707 rejected" t_0707_rejected
run_case "missing path returns ok" t_missing_path_is_ok
