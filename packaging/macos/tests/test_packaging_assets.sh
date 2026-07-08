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

t_install_passes_guardian_auth_dir_to_cli() {
  # Regression guard: the plist sets DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR
  # to ${SUPPORT_DIR}/hook-guardian-state so the running daemon uses the
  # installer-created dir. The `enterprise hooks install` CLI invocation
  # inside install.sh MUST inherit that same env var — otherwise the
  # CLI falls back to `${data_dir}-hook-guardian` (= runtime-hook-guardian)
  # which doesn't exist, and every per-connector hook wiring call fails
  # the authorization-directory trust check.
  #
  # This test locks in the contract by checking that every line that
  # invokes `enterprise hooks install` in install.sh has
  # DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR set on the same command.
  # Squash backslash-continuations so multi-line env-var blocks appear
  # as a single logical line, then find every logical line that runs
  # `enterprise hooks install`. Each such line must set
  # DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR.
  local bad
  bad="$(/usr/bin/python3 - "${PKG_DIR}/install.sh" <<'PY'
import re, sys
src = open(sys.argv[1]).read()
# Join backslash-newline continuations into one logical line.
joined = re.sub(r"\\\n\s*", " ", src)
bad = []
for i, line in enumerate(joined.splitlines(), start=1):
    if "enterprise hooks install" not in line:
        continue
    # printf templates + log lines that only PRINT the command are
    # tagged with 'printf' or 'log ' — we only care about invocations.
    if re.search(r"\blog\b|\bwarn\b|\bprintf\b", line):
        continue
    if "DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR" not in line:
        bad.append((i, line.strip()[:200]))
for i, l in bad:
    print(f"{i}: {l}")
PY
)"
  if [[ -n "${bad}" ]]; then
    _fail "found 'enterprise hooks install' invocation(s) without DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR — the CLI will resolve to \${data_dir}-hook-guardian and fail the authorization-directory trust check:
${bad}"
    return 1
  fi
  # ALSO check the operator-facing repair-command hints (log/warn/printf
  # lines that echo an example command back to the operator). Those
  # should also carry the env var so a copy-pasted retry works.
  local hints
  hints=$(grep -n 'enterprise hooks install' "${PKG_DIR}/install.sh" | \
          grep -E 'log |warn |printf ' | \
          grep -v 'DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR' | \
          grep -v 'log "  \[' || true)
  # Filter out the pure-info "running:" trace line which doesn't need
  # to include env vars (it's a status log, not a runnable snippet).
  hints=$(printf '%s' "${hints}" | grep -v 'running: enterprise hooks install' || true)
  if [[ -n "${hints}" ]]; then
    _fail "found operator-facing 'enterprise hooks install' hint(s) without DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR — copy-pasted retries will fail:
${hints}"
    return 1
  fi
}

t_scrub_py_syntax() {
  local rc=0
  /usr/bin/python3 -c "import ast; ast.parse(open('${PKG_DIR}/lib/scrub_agent_configs.py').read())" 2>&1 || rc=$?
  assert_status "${rc}" 0 "scrub_agent_configs.py parses"
}

# _setup_bundle_fixture WITH_BINARY
#   Prints the fresh tmpdir path on stdout, populated with the installer
#   scaffolding (install.sh, installer_lib.sh, plist stub). When
#   WITH_BINARY=true, also drops in a stub defenseclaw-gateway. Tests
#   drive install.sh with DC_INSTALLER_SKIP_ROOT_CHECK=1 (an explicit
#   test-only env seam in install.sh) so no sudo is needed AND the
#   fixture doesn't have to keep chasing changes to the production
#   root-check line.
#
#   Also sets root:wheel-equivalent ownership expectations on the fake
#   plist: install.sh now refuses to copy a non-root-owned plist into
#   /Library/LaunchDaemons, so the fixture chowns via install(1)
#   pattern where possible. Under `bash -n` tests we can't actually
#   chown to root; the fixture pre-emptively skips the plist validator
#   by setting the seam.
#
#   Uses stdout instead of bash 4.3+ namerefs (macOS bash 3.2 has no
#   `local -n`).
_setup_bundle_fixture() {
  local with_binary="$1"
  local bundle
  bundle="$(mktest_tmp)"
  # mktest_tmp may return a trailing-slash / mid-path `//` from $TMPDIR
  # concat. Canonicalize via cd -P so grep + trace comparisons match
  # what install.sh's SCRIPT_DIR resolves to.
  bundle="${bundle%/}"
  bundle="$(cd "${bundle}" && pwd -P)"
  mkdir -p "${bundle}/lib"
  cp "${PKG_DIR}/install.sh"           "${bundle}/install.sh"
  cp "${PKG_DIR}/lib/installer_lib.sh" "${bundle}/lib/installer_lib.sh"
  printf '<?xml version="1.0"?><plist/>' > "${bundle}/com.defenseclaw.gateway.plist"
  chmod 0755 "${bundle}/install.sh"
  if [[ "${with_binary}" == "true" ]]; then
    printf '#!/bin/sh\nexit 0\n' > "${bundle}/defenseclaw-gateway"
    chmod 0755 "${bundle}/defenseclaw-gateway"
  fi
  printf '%s\n' "${bundle}"
}

# Regression guard for the "shippable bundle" contract: install.sh must
# discover the plist and binary next to itself (SCRIPT_DIR-relative)
# before falling back to the repo tree.
t_bundle_layout_resolves_locally() {
  local bundle
  bundle="$(_setup_bundle_fixture true)"

  local trace
  # DC_INSTALLER_SKIP_ROOT_CHECK is a test-only seam declared in
  # install.sh's preflight block; it also skips the plist-source
  # ownership check so the fake stub plist under a tmpdir doesn't need
  # to be root-owned.
  trace="$(DC_INSTALLER_SKIP_ROOT_CHECK=1 bash -x "${bundle}/install.sh" \
    --connector codex --skip-launchd --skip-connector 2>&1 | \
    grep -E "PLIST_SRC=|BINARY_SRC=/" || true)"

  assert_contains "${trace}" "PLIST_SRC=${bundle}/com.defenseclaw.gateway.plist" "plist resolved from bundle"
  assert_contains "${trace}" "BINARY_SRC=${bundle}/defenseclaw-gateway"          "binary resolved from bundle"
}

# Complementary: with NO bundle-local binary AND no repo tree, install.sh
# must die with a clear message rather than trying to `go build`.
t_bundle_without_binary_and_no_repo_dies() {
  local bundle
  bundle="$(_setup_bundle_fixture false)"

  local out rc=0
  out="$(DC_INSTALLER_SKIP_ROOT_CHECK=1 "${bundle}/install.sh" \
    --connector codex --skip-launchd --skip-connector 2>&1)" || rc=$?
  assert_status "${rc}" 1 "missing binary + no repo should die"
  assert_contains "${out}" "no repo tree" "explains missing repo tree"
}

# PLIST validator regression: install.sh's plist-source ownership check
# must be a TWO-TIER policy:
#   - override (--plist or DEFENSECLAW_PLIST_SRC): require root-owned
#   - bundle / repo default: allow the extracting user's uid (a plist
#     extracted from our shipped tarball is owned by whoever ran `tar -x`,
#     not root; requiring root there would break the documented
#     `sudo ./install.sh` bundle flow — see PR #440 review feedback).
# Group/world-writable bits must always be refused, regardless of origin.
# We drive install.sh through DC_INSTALLER_SKIP_ROOT_CHECK=1 to bypass
# the euid check but DO NOT set DC_INSTALLER_SKIP_PLIST_VALIDATION here —
# we WANT the validator to run.
t_plist_validator_accepts_bundle_default_owned_by_user() {
  local bundle
  bundle="$(_setup_bundle_fixture true)"
  # Bundle default plist is owned by the current (non-root) uid — this
  # models the extracted-tarball flow. Mode is 0644 (safe).
  chmod 0644 "${bundle}/com.defenseclaw.gateway.plist"
  # Run under `bash -x` so we can positively confirm two things:
  #   1. PLIST_SRC actually resolved to the bundle-local plist (not the
  #      repo default or an earlier candidate).
  #   2. PLIST_SRC_ORIGIN is "bundle" so the validator applied the
  #      relaxed policy (skip root-owner requirement).
  # Without these, a regression that dies BEFORE the ownership branch
  # or resolves PLIST_SRC to some other path would still pass the
  # negative-only `assert_not_contains "must be owned by root"` check.
  local out rc=0
  out="$(DC_INSTALLER_SKIP_ROOT_CHECK=1 bash -x "${bundle}/install.sh" \
    --connector codex --skip-launchd --skip-connector 2>&1)" || rc=$?
  local trace
  trace="$(printf '%s' "${out}" | grep -E 'PLIST_SRC=|PLIST_SRC_ORIGIN=' || true)"
  assert_contains "${trace}" "PLIST_SRC=${bundle}/com.defenseclaw.gateway.plist" "plist resolved from bundle"
  assert_contains "${trace}" "PLIST_SRC_ORIGIN=bundle"                            "origin is bundle (relaxed policy)"
  # And the ownership branch must not have fired.
  assert_not_contains "${out}" "must be owned by root" "bundle default plist accepted"
}

t_plist_validator_rejects_bundle_default_that_is_world_writable() {
  local bundle
  bundle="$(_setup_bundle_fixture true)"
  chmod 0646 "${bundle}/com.defenseclaw.gateway.plist"
  local out rc=0
  out="$(DC_INSTALLER_SKIP_ROOT_CHECK=1 "${bundle}/install.sh" \
    --connector codex --skip-launchd --skip-connector 2>&1)" || rc=$?
  assert_status "${rc}" 1 "world-writable plist rejected"
  assert_contains "${out}" "group/other writable" "explains why"
}

t_plist_validator_rejects_override_owned_by_non_root() {
  # DEFENSECLAW_PLIST_SRC forces override policy; a non-root owner must
  # be rejected even if the file is otherwise safe.
  local bundle
  bundle="$(_setup_bundle_fixture true)"
  local override_plist="${bundle}/override.plist"
  printf '<?xml version="1.0"?><plist/>' > "${override_plist}"
  chmod 0644 "${override_plist}"
  local out rc=0
  out="$(DC_INSTALLER_SKIP_ROOT_CHECK=1 \
    DEFENSECLAW_PLIST_SRC="${override_plist}" \
    "${bundle}/install.sh" \
    --connector codex --skip-launchd --skip-connector 2>&1)" || rc=$?
  assert_status "${rc}" 1 "override plist owned by non-root rejected"
  assert_contains "${out}" "must be owned by root" "explains why"
  assert_contains "${out}" "DEFENSECLAW_PLIST_SRC" "names the override source"
}

t_plist_validator_rejects_missing_env_override() {
  # Regression guard: if DEFENSECLAW_PLIST_SRC is set but the file it
  # names doesn't exist, install.sh MUST die before the lookup loop
  # rather than silently falling through to the bundle default. Silent
  # fallback would substitute a different plist AND downgrade the
  # ownership policy from `override` (strict) to `bundle` (relaxed).
  local bundle
  bundle="$(_setup_bundle_fixture true)"
  local out rc=0
  out="$(DC_INSTALLER_SKIP_ROOT_CHECK=1 \
    DEFENSECLAW_PLIST_SRC="${bundle}/does-not-exist.plist" \
    "${bundle}/install.sh" \
    --connector codex --skip-launchd --skip-connector 2>&1)" || rc=$?
  assert_status "${rc}" 1 "missing env-override plist must fail"
  assert_contains "${out}" "DEFENSECLAW_PLIST_SRC" "error names the env var"
  assert_contains "${out}" "does not exist"        "error names the missing state"
  # Must NOT silently install the bundle default.
  assert_not_contains "${out}" "com.defenseclaw.gateway.plist installed" "no silent fallback"
}

t_plist_validator_fails_closed_when_stat_output_empty() {
  # Simulate stat failure by shimming a `stat` on PATH that outputs
  # nothing. install.sh must die rather than silently skipping the check.
  local bundle
  bundle="$(_setup_bundle_fixture true)"
  local shimbin="${bundle}/shim"
  mkdir -p "${shimbin}"
  printf '#!/bin/sh\nexit 0\n' > "${shimbin}/stat"
  chmod 0755 "${shimbin}/stat"
  local out rc=0
  out="$(DC_INSTALLER_SKIP_ROOT_CHECK=1 PATH="${shimbin}:${PATH}" \
    "${bundle}/install.sh" \
    --connector codex --skip-launchd --skip-connector 2>&1)" || rc=$?
  assert_status "${rc}" 1 "stat empty must fail closed"
  assert_contains "${out}" "cannot stat plist source" "explains why"
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
run_case "install.sh passes DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR on every hooks-install call" \
  t_install_passes_guardian_auth_dir_to_cli
run_case "bundle layout: plist + binary resolve locally" t_bundle_layout_resolves_locally
run_case "bundle without binary + no repo dies"          t_bundle_without_binary_and_no_repo_dies
run_case "plist validator accepts bundle default owned by extracting user" \
  t_plist_validator_accepts_bundle_default_owned_by_user
run_case "plist validator rejects world-writable bundle default" \
  t_plist_validator_rejects_bundle_default_that_is_world_writable
run_case "plist validator rejects --override owned by non-root" \
  t_plist_validator_rejects_override_owned_by_non_root
run_case "plist validator rejects missing env-override (no silent fallback)" \
  t_plist_validator_rejects_missing_env_override
run_case "plist validator fails closed when stat output empty" \
  t_plist_validator_fails_closed_when_stat_output_empty
