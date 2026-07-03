#!/usr/bin/env bash
# Sanity-check the packaging assets that install.sh expects to ship.

t_plist_exists_and_parses() {
  local plist="${REPO_ROOT}/packaging/launchd/com.defenseclaw.gateway.plist"
  assert_file_exists "${plist}"
  if command -v plutil >/dev/null 2>&1; then
    local out rc=0
    out="$(plutil -lint "${plist}" 2>&1)" || rc=$?
    assert_status "${rc}" 0 "plutil -lint should succeed"
    assert_contains "${out}" "OK" "plutil OK"
  fi
}

t_plist_contains_managed_paths() {
  local plist="${REPO_ROOT}/packaging/launchd/com.defenseclaw.gateway.plist"
  local body; body="$(cat "${plist}")"
  assert_contains "${body}" "/Library/DefenseClaw/bin/defenseclaw-gateway" "binary path"
  assert_contains "${body}" "DEFENSECLAW_CONFIG"                          "config env var"
  assert_contains "${body}" "/Library/Application Support/DefenseClaw"    "support dir path"
  assert_contains "${body}" "com.defenseclaw.gateway"                     "launchd label"
  assert_contains "${body}" "<key>KeepAlive</key>"                         "KeepAlive set"
  assert_contains "${body}" "<key>RunAtLoad</key>"                         "RunAtLoad set"
}

t_plist_service_user_matches_gateway_expectation() {
  # The gateway binary hardcodes trustedRuntimeOwner to look up a user
  # literally named "defenseclaw" (see internal/managed/trust_unix.go).
  # The shipped plist MUST reference that exact name or the daemon will
  # reject the managed_enterprise data_dir trust check on boot.
  local plist="${REPO_ROOT}/packaging/launchd/com.defenseclaw.gateway.plist"
  local uname gname
  if ! command -v plutil >/dev/null 2>&1; then
    return 0
  fi
  uname="$(plutil -extract UserName  raw "${plist}" 2>/dev/null || true)"
  gname="$(plutil -extract GroupName raw "${plist}" 2>/dev/null || true)"
  assert_eq "${uname}" "defenseclaw" "shipped plist UserName is 'defenseclaw' (got: ${uname})"
  assert_eq "${gname}" "defenseclaw" "shipped plist GroupName is 'defenseclaw' (got: ${gname})"
}

t_install_lib_syntax() {
  local rc=0
  bash -n "${PKG_DIR}/lib/installer_lib.sh" 2>&1 || rc=$?
  assert_status "${rc}" 0 "installer_lib.sh parses cleanly"
}

t_install_sh_syntax() {
  local rc=0
  bash -n "${PKG_DIR}/install.sh" 2>&1 || rc=$?
  assert_status "${rc}" 0 "install.sh parses cleanly"
}

t_uninstall_sh_syntax() {
  local rc=0
  bash -n "${PKG_DIR}/uninstall.sh" 2>&1 || rc=$?
  assert_status "${rc}" 0 "uninstall.sh parses cleanly"
}

t_install_sh_is_executable() {
  if [[ ! -x "${PKG_DIR}/install.sh" ]]; then
    _fail "install.sh missing +x"
    return 1
  fi
}

t_uninstall_sh_is_executable() {
  if [[ ! -x "${PKG_DIR}/uninstall.sh" ]]; then
    _fail "uninstall.sh missing +x"
    return 1
  fi
}

t_scrub_py_exists_and_executable() {
  assert_file_exists "${PKG_DIR}/lib/scrub_agent_configs.py"
  if [[ ! -x "${PKG_DIR}/lib/scrub_agent_configs.py" ]]; then
    _fail "scrub_agent_configs.py missing +x"
    return 1
  fi
}

t_install_has_service_user_helper() {
  # We can't invoke dscl in tests (needs root, mutates system state), so
  # instead we lock in the contract: install.sh must define an
  # ensure_service_user function and its execution path must actually
  # call ensure_service_user before touching the LaunchDaemon plist.
  local body
  body="$(cat "${PKG_DIR}/install.sh")"
  assert_contains "${body}" "ensure_service_user()"       "ensure_service_user function defined"
  assert_contains "${body}" "ensure_service_user \""      "ensure_service_user is invoked"
  # ensure_service_user must run before we bootstrap launchd, otherwise
  # launchd will spawn a service whose UserName references a missing user.
  local user_line boot_line
  user_line=$(grep -n 'ensure_service_user "'  "${PKG_DIR}/install.sh" | head -1 | cut -d: -f1)
  boot_line=$(grep -n 'launchctl bootstrap system "\${PLIST_DST}"' "${PKG_DIR}/install.sh" | head -1 | cut -d: -f1)
  if [[ -z "${user_line}" || -z "${boot_line}" ]]; then
    _fail "could not locate ensure_service_user or launchctl bootstrap line"
    return 1
  fi
  if (( user_line >= boot_line )); then
    _fail "ensure_service_user (line ${user_line}) must run before launchctl bootstrap (line ${boot_line})"
    return 1
  fi
}

t_scrub_py_syntax() {
  local rc=0
  /usr/bin/python3 -c "import ast; ast.parse(open('${PKG_DIR}/lib/scrub_agent_configs.py').read())" 2>&1 || rc=$?
  assert_status "${rc}" 0 "scrub_agent_configs.py parses"
}

# Regression guard for the "shippable bundle" contract: install.sh must
# discover the plist and binary next to itself (SCRIPT_DIR-relative)
# before falling back to the repo tree, and it must NOT try to `go build`
# when no repo tree is available. Simulate a bundle in a tmpdir and
# confirm the script picks the bundle-local assets.
t_bundle_layout_resolves_locally() {
  local bundle; bundle="$(mktest_tmp)"
  # mktest_tmp may return a path with a trailing slash from $TMPDIR;
  # normalize so grep and the trace lines compare cleanly.
  bundle="${bundle%/}"
  # $bundle may still contain a mid-path `//` from the $TMPDIR concat
  # (e.g. `/var/.../T//dctest...`). Bash's set -x prints it verbatim,
  # so canonicalize via cd -P to match what install.sh's SCRIPT_DIR
  # resolves to.
  bundle="$(cd "${bundle}" && pwd -P)"
  mkdir -p "${bundle}/lib"
  cp "${PKG_DIR}/install.sh"                              "${bundle}/install.sh"
  cp "${PKG_DIR}/lib/installer_lib.sh"                    "${bundle}/lib/installer_lib.sh"
  # Fake bundle-local plist + binary so the resolution has something to
  # find. Contents don't matter, only existence.
  printf '<?xml version="1.0"?><plist/>' > "${bundle}/com.defenseclaw.gateway.plist"
  printf '#!/bin/sh\nexit 0\n' > "${bundle}/defenseclaw-gateway"
  chmod 0755 "${bundle}/defenseclaw-gateway" "${bundle}/install.sh"

  # Bypass the root check so we can reach the resolution block.
  sed -i.bak 's/\[\[ \$EUID -eq 0 \]\] || die/[[ 1 -eq 0 ]] || : /' "${bundle}/install.sh"
  rm -f "${bundle}/install.sh.bak"

  # Non-strict trace: filter for the PLIST/BINARY resolution lines.
  local trace
  trace="$(bash -x "${bundle}/install.sh" --connector codex --skip-launchd --skip-connector 2>&1 | \
    grep -E "PLIST_SRC=|BINARY_SRC=/" || true)"

  assert_contains "${trace}" "PLIST_SRC=${bundle}/com.defenseclaw.gateway.plist" "plist resolved from bundle"
  assert_contains "${trace}" "BINARY_SRC=${bundle}/defenseclaw-gateway"          "binary resolved from bundle"
}

# Complementary: with NO bundle-local binary AND no repo tree, install.sh
# must die with a clear message rather than trying to `go build`.
t_bundle_without_binary_and_no_repo_dies() {
  local bundle; bundle="$(mktest_tmp)"
  bundle="$(cd "${bundle}" && pwd -P)"
  mkdir -p "${bundle}/lib"
  cp "${PKG_DIR}/install.sh"                              "${bundle}/install.sh"
  cp "${PKG_DIR}/lib/installer_lib.sh"                    "${bundle}/lib/installer_lib.sh"
  printf '<?xml version="1.0"?><plist/>' > "${bundle}/com.defenseclaw.gateway.plist"
  chmod 0755 "${bundle}/install.sh"
  sed -i.bak 's/\[\[ \$EUID -eq 0 \]\] || die/[[ 1 -eq 0 ]] || : /' "${bundle}/install.sh"
  rm -f "${bundle}/install.sh.bak"

  local out rc=0
  out="$("${bundle}/install.sh" --connector codex --skip-launchd --skip-connector 2>&1)" || rc=$?
  assert_status "${rc}" 1 "missing binary + no repo should die"
  assert_contains "${out}" "no repo tree" "explains missing repo tree"
}

run_case "plist exists and lints"     t_plist_exists_and_parses
run_case "plist references managed paths" t_plist_contains_managed_paths
run_case "plist service user matches gateway expectation" t_plist_service_user_matches_gateway_expectation
run_case "installer_lib.sh syntax"    t_install_lib_syntax
run_case "install.sh syntax"          t_install_sh_syntax
run_case "uninstall.sh syntax"        t_uninstall_sh_syntax
run_case "install.sh executable"      t_install_sh_is_executable
run_case "uninstall.sh executable"    t_uninstall_sh_is_executable
run_case "scrub_agent_configs.py present and +x" t_scrub_py_exists_and_executable
run_case "scrub_agent_configs.py syntax"          t_scrub_py_syntax
run_case "install.sh has ensure_service_user + calls it before launchd" t_install_has_service_user_helper
run_case "bundle layout: plist + binary resolve locally" t_bundle_layout_resolves_locally
run_case "bundle without binary + no repo dies"          t_bundle_without_binary_and_no_repo_dies
