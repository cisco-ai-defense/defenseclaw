#!/usr/bin/env bash
# No-fatal gate for install.sh: an install over a tree carrying every
# drift class it can meet (mode, ACL, user flags, symlinks, wrong types,
# leftovers, failed per-user records, a slow gateway) repairs or logs each
# one and exits 0. Runs unprivileged against a fixture machine root (the
# test-root seam is ignored under root, so these cases never run as
# root); foreign-owner drift needs root to create and is covered on a
# host run instead. Every chown to the stamped owner is still exercised:
# the fixture stamps the invoking user.
. "${PKG_DIR}/tests/lib_fixture.sh"

_gate_prefix() { printf '%s/root/opt/cisco/secureclient/defenseclaw' "$1"; }

t_install_repairs_drifted_tree_and_exits_zero() {
  local b; b="$(fixture_bundle)"
  local out rc=0
  out="$(fixture_install "${b}" --connector codex 2>&1)" || rc=$?
  assert_status "${rc}" 0 "fresh fixture install"

  local prefix; prefix="$(_gate_prefix "${b}")"
  local outside="${b}/outside-target"
  printf 'keep\n' > "${outside}"
  chmod 0600 "${outside}"

  # Drift every class this installer owns.
  chmod 0777 "${prefix}/etc"
  chmod 0666 "${prefix}/etc/config.yaml"
  chflags uchg "${prefix}/etc/config.yaml"
  chflags uchg "${prefix}/bin/defenseclaw-gateway"
  chflags uchg "${prefix}/runtime/policies/guardrail/default/rules.yaml"
  chmod +a "everyone allow write,add_file,file_inherit,directory_inherit" "${prefix}"
  rm -f "${prefix}/hook-guardian/targets.yaml"
  ln -s "${outside}" "${prefix}/hook-guardian/targets.yaml"
  rm -f "${prefix}/lib/render-targets.sh"
  mkdir "${prefix}/lib/render-targets.sh"
  mkdir -p "${prefix}/runtime/policies/guardrail.new/stale"
  chflags uchg "${prefix}/runtime/policies/guardrail.new/stale"
  printf 'leftover\n' > "${b}/root/Library/LaunchDaemons/com.defenseclaw.gateway.plist"
  chflags uchg "${b}/root/Library/LaunchDaemons/com.defenseclaw.gateway.plist"
  chflags uchg "${b}/root/Library/Logs/Cisco/SecureClient/DefenseClaw/install.log"
  chflags uchg "${b}/root/Library/LaunchDaemons/com.cisco.secureclient.defenseclaw.plist"

  out="$(fixture_install "${b}" --connector codex 2>&1)" || rc=$?
  assert_status "${rc}" 0 "drifted reinstall exits 0"

  assert_eq "$(cat "${outside}")" "keep" "symlink target content untouched"
  assert_file_mode "${outside}" 600
  [[ -f "${prefix}/hook-guardian/targets.yaml" && ! -L "${prefix}/hook-guardian/targets.yaml" ]] \
    || _fail "targets.yaml must be republished as a regular file"
  [[ -f "${prefix}/lib/render-targets.sh" ]] || _fail "wrong-type render-targets.sh must be replaced"
  assert_eq "$(stat -f '%Sf' "${prefix}/etc/config.yaml")" "-" "config uchg cleared"
  assert_file_mode "${prefix}/etc/config.yaml" 640
  assert_file_mode "${prefix}/etc" 755
  assert_eq "$(stat -f '%Sf' "${prefix}/bin/defenseclaw-gateway")" "-" "binary uchg cleared"
  assert_eq "$(ls -lde "${prefix}" | sed -n '2p')" "" "inheritable ACL stripped from the install root"
  [[ ! -e "${b}/root/Library/LaunchDaemons/com.defenseclaw.gateway.plist" ]] \
    || _fail "legacy plist must be removed"
  [[ ! -e "${prefix}/runtime/policies/guardrail.new" ]] || _fail "stale flagged stage must be cleared"
  [[ -d "${prefix}/runtime/policies/guardrail/default" ]] || _fail "rule packs republished"

  assert_contains "${out}" 'defenseclaw_boundary action=' "boundary logged"
  assert_contains "${out}" 'reason="symlink"' "symlink boundary"
  assert_contains "${out}" 'reason="wrong_type"' "wrong-type boundary"
  assert_contains "${out}" 'defenseclaw_recover component="install"' "recovery logged"
  assert_contains "${out}" 'what="legacy_plist"' "legacy plist recovery"
  assert_contains "${out}" 'defenseclaw_repair component="install"' "repair logged"
  assert_not_contains "${out}" "ERROR:" "no fatal error printed"
  fixture_cleanup "${b}"
}

t_install_isolates_per_user_failures() {
  local b; b="$(fixture_bundle)"
  fixture_add_user "${b}" alice 501
  fixture_add_user "${b}" bob 502
  fixture_add_user "${b}" carol 503
  # alice uses Codex; bob's home is group-writable (skipped by the
  # enumerator filter); carol's record vanishes between -list and -read.
  mkdir -p "${b}/root/Users/alice/.codex"
  printf '{}\n' > "${b}/root/Users/alice/.codex/auth.json"
  chmod 0775 "${b}/root/Users/bob"
  printf 'carol\n' > "${b}/dscl-read-fail"
  local out rc=0
  out="$(fixture_install "${b}" --connector codex 2>&1)" || rc=$?
  assert_status "${rc}" 0 "per-user failures never fail the install"
  local manifest; manifest="$(cat "$(_gate_prefix "${b}")/hook-guardian/targets.yaml")"
  assert_contains "${manifest}" 'user: "alice"' "healthy user rendered"
  assert_not_contains "${manifest}" 'user: "bob"' "filtered user not rendered"
  assert_contains "${out}" 'defenseclaw_skip component="install" reason="dscl_read_failed" unit="user:carol"' \
    "vanished record skipped with a marker"
  [[ -e "${b}/state/com.cisco.secureclient.defenseclaw.hook-guardian" ]] || _fail "guardian loaded"
  fixture_cleanup "${b}"
}

t_install_continues_with_no_users_and_slow_gateway() {
  local b; b="$(fixture_bundle)"
  # The gateway never comes up and the enumerator fails to load: the
  # guardian must still be loaded and the install must exit 0.
  printf '#!/bin/bash\n[ "$1" = print ] && [ "$2" = system/com.cisco.secureclient.defenseclaw ] && exit 113\nexec "%s/shim/launchctl.real" "$@"\n' \
    "${b}" > "${b}/shim/launchctl.wrap"
  mv "${b}/shim/launchctl" "${b}/shim/launchctl.real"
  mv "${b}/shim/launchctl.wrap" "${b}/shim/launchctl"
  chmod 0755 "${b}/shim/launchctl"
  touch "${b}/state/fail-bootstrap-com.cisco.secureclient.defenseclaw.hook-enumerator"
  local out rc=0
  out="$(DC_TEST_GATEWAY_WAIT=1 fixture_install "${b}" --connector codex 2>&1)" || rc=$?
  assert_status "${rc}" 0 "zero users, slow gateway and a failed enumerator bootstrap still exit 0"
  assert_contains "${out}" 'reason="no_eligible_users"' "zero users logged"
  assert_contains "${out}" 'reason="not_running_after_bootstrap" subsystem="gateway"' "gateway degraded logged"
  assert_contains "${out}" 'label="com.cisco.secureclient.defenseclaw.hook-enumerator" reason="bootstrap_failed"' \
    "enumerator bootstrap failure logged"
  [[ -e "${b}/state/com.cisco.secureclient.defenseclaw.hook-guardian" ]] \
    || _fail "guardian must be loaded even when the gateway and enumerator are not"
  fixture_cleanup "${b}"
}

t_install_allow_empty_users_flag_still_accepted() {
  local b; b="$(fixture_bundle)"
  local out rc=0
  out="$(fixture_install "${b}" --connector codex --allow-empty-users 2>&1)" || rc=$?
  assert_status "${rc}" 0 "--allow-empty-users is accepted"
  fixture_cleanup "${b}"
}

run_case "install repairs a drifted tree and exits 0"            t_install_repairs_drifted_tree_and_exits_zero
run_case "install isolates per-user failures"                    t_install_isolates_per_user_failures
run_case "install continues with no users and a slow gateway"    t_install_continues_with_no_users_and_slow_gateway
run_case "install still accepts --allow-empty-users"             t_install_allow_empty_users_flag_still_accepted
