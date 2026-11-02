#!/usr/bin/env bash
# install.sh launchd ordering, canonical plist copies and the integrity
# manifest, driven unprivileged against a fixture machine root.
. "${PKG_DIR}/tests/lib_fixture.sh"

_li_prefix() { printf '%s/root/opt/cisco/secureclient/defenseclaw' "$1"; }

t_install_enables_then_bootstraps_in_order() {
  local b; b="$(fixture_bundle)"
  local rc=0
  fixture_install "${b}" --connector codex >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 0 "fixture install"
  local calls
  calls="$(grep -E '^(enable|bootstrap) ' "${b}/state/calls" \
    | sed -e 's|^bootstrap system .*/|bootstrap |' -e 's|\.plist$||' -e 's|^enable system/|enable |')"
  assert_eq "${calls}" "enable com.cisco.secureclient.defenseclaw.hook-guardian
bootstrap com.cisco.secureclient.defenseclaw.hook-guardian
enable com.cisco.secureclient.defenseclaw
bootstrap com.cisco.secureclient.defenseclaw
enable com.cisco.secureclient.defenseclaw.hook-enumerator
bootstrap com.cisco.secureclient.defenseclaw.hook-enumerator" \
    "enable before each bootstrap; guardian, then gateway, then enumerator"
  fixture_cleanup "${b}"
}

t_install_reports_guardian_not_loaded() {
  local b; b="$(fixture_bundle)"
  touch "${b}/state/fail-bootstrap-com.cisco.secureclient.defenseclaw.hook-guardian"
  local out rc=0
  out="$(fixture_install "${b}" --connector codex 2>&1)" || rc=$?
  assert_status "${rc}" 0 "a guardian that will not load never fails the install"
  assert_contains "${out}" 'label="com.cisco.secureclient.defenseclaw.hook-guardian" reason="not_loaded_after_bootstrap" subsystem="launchd"' \
    "guardian not loaded is reported as degraded"
  [[ -e "${b}/state/com.cisco.secureclient.defenseclaw" ]] || _fail "gateway still loaded"
  [[ -e "${b}/state/com.cisco.secureclient.defenseclaw.hook-enumerator" ]] || _fail "enumerator still loaded"
  fixture_cleanup "${b}"
}

t_install_writes_canonical_plist_copies() {
  local b; b="$(fixture_bundle)"
  local rc=0
  fixture_install "${b}" --connector codex --skip-launchd >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 0 "fixture install"
  local dir; dir="$(_li_prefix "${b}")/etc/launchd"
  assert_file_mode "${dir}" 755
  local label copy digest
  for label in com.cisco.secureclient.defenseclaw \
               com.cisco.secureclient.defenseclaw.hook-guardian \
               com.cisco.secureclient.defenseclaw.hook-enumerator; do
    copy="${dir}/${label}.plist"
    assert_file_exists "${copy}"
    assert_file_mode "${copy}" 644
    assert_file_mode "${copy}.sha256" 644
    cmp -s "${copy}" "${b}/root/Library/LaunchDaemons/${label}.plist" \
      || _fail "canonical copy of ${label} differs from the published plist"
    digest="$(shasum -a 256 "${copy}" | awk '{print $1}')"
    assert_eq "$(cat "${copy}.sha256")" "${digest}" "${label} digest is bare lowercase hex"
  done
  fixture_cleanup "${b}"
}

t_install_writes_integrity_manifest() {
  local b; b="$(fixture_bundle)"
  local rc=0
  fixture_install "${b}" --connector codex --skip-launchd >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 0 "fixture install"
  local prefix; prefix="$(_li_prefix "${b}")"
  local manifest="${prefix}/etc/integrity.sha256"
  assert_file_exists "${manifest}"
  assert_file_mode "${manifest}" 644
  local body; body="$(cat "${manifest}")"
  assert_contains "${body}" "  ${prefix}/bin/defenseclaw-gateway" "binary listed by absolute path"
  assert_contains "${body}" "  ${prefix}/lib/installer_lib.sh" "library listed"
  assert_contains "${body}" "  ${prefix}/lib/render-targets.sh" "enumerator script listed"
  local verify_rc=0
  shasum -a 256 -c "${manifest}" >/dev/null 2>&1 || verify_rc=$?
  assert_status "${verify_rc}" 0 "manifest verifies with shasum -c"
  fixture_cleanup "${b}"
}

t_prereq_checks_never_fail() {
  . "${PKG_DIR}/lib/installer_lib.sh"
  local dir out rc=0
  dir="$(mktemp -d)"

  out="$(dc_run_prereq_checks 2>&1)" || rc=$?
  assert_status "${rc}" 0 "prerequisite checks without a binary never fail"
  assert_eq "${out}" "" "prerequisite checks without a binary log nothing"

  rc=0
  out="$(dc_run_prereq_checks "${dir}/missing" "${dir}" 18970 2>&1)" || rc=$?
  assert_status "${rc}" 0 "a missing gateway binary never fails the install"
  assert_contains "${out}" 'defenseclaw_prereq' "a missing gateway binary is a prerequisite line"
  assert_contains "${out}" 'check="binary_exec_allowed"' "a missing gateway binary names the check"

  printf '#!/bin/bash\nexit 126\n' >"${dir}/blocked"
  chmod 0755 "${dir}/blocked"
  rc=0
  out="$(dc_run_prereq_checks "${dir}/blocked" "${dir}" 18970 2>&1)" || rc=$?
  assert_status "${rc}" 0 "a binary that cannot run never fails the install"
  assert_contains "${out}" 'check="binary_exec_allowed"' "a blocked gateway binary names the check"

  printf '#!/bin/bash\necho "defenseclaw_prereq check=\\"hook_transport_tools\\"" >&2\nexit 0\n' >"${dir}/gw"
  chmod 0755 "${dir}/gw"
  rc=0
  out="$(dc_run_prereq_checks "${dir}/gw" "${dir}" 18970 2>&1)" || rc=$?
  assert_status "${rc}" 0 "prerequisite findings never fail the install"
  assert_contains "${out}" 'hook_transport_tools' "the gateway's findings reach the install log"

  # A finding only the exec probe produces must reach the log too.
  printf '#!/bin/bash\ncase " $* " in *" --exec-probe "*) echo "defenseclaw_prereq check=\\"binary_exec_allowed\\" detail=\\"version probe failed\\"" >&2 ;; esac\nexit 0\n' >"${dir}/gw-probe"
  chmod 0755 "${dir}/gw-probe"
  rc=0
  out="$(dc_run_prereq_checks "${dir}/gw-probe" "${dir}" 18970 2>&1)" || rc=$?
  assert_status "${rc}" 0 "an exec-probe finding never fails the install"
  assert_contains "${out}" 'version probe failed' "the exec probe's findings reach the install log"
  rm -rf "${dir}"
}

run_case "install enables then bootstraps guardian, gateway, enumerator" t_install_enables_then_bootstraps_in_order
run_case "install reports a guardian that is not loaded"               t_install_reports_guardian_not_loaded
run_case "install writes canonical plist copies"                       t_install_writes_canonical_plist_copies
run_case "install writes the integrity manifest"                       t_install_writes_integrity_manifest
run_case "prerequisite checks never fail the install"               t_prereq_checks_never_fail
