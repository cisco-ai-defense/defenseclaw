#!/usr/bin/env bash
# Sanity-check the packaging assets that install.sh expects to ship.

t_plist_exists_and_parses() {
  local plist="${REPO_ROOT}/packaging/launchd/com.cisco.secureclient.defenseclaw.plist"
  assert_file_exists "${plist}"
  if command -v plutil >/dev/null 2>&1; then
    local out rc=0
    out="$(plutil -lint "${plist}" 2>&1)" || rc=$?
    assert_status "${rc}" 0 "plutil -lint should succeed"
    assert_contains "${out}" "OK" "plutil OK"
  fi
}

t_guardian_and_enumerator_plists_exist_and_parse() {
  # The hook-guardian + hook-enumerator LaunchDaemons together deliver
  # per-user hook wiring for every eligible local user on the box.
  # install.sh installs and bootstraps both; the shipped bundle must
  # therefore include both plist templates.
  local g="${REPO_ROOT}/packaging/launchd/com.cisco.secureclient.defenseclaw.hook-guardian.plist"
  local e="${REPO_ROOT}/packaging/launchd/com.cisco.secureclient.defenseclaw.hook-enumerator.plist"
  assert_file_exists "${g}"
  assert_file_exists "${e}"
  if command -v plutil >/dev/null 2>&1; then
    local out rc=0
    out="$(plutil -lint "${g}" 2>&1)" || rc=$?
    assert_status "${rc}" 0 "guardian plutil -lint should succeed"
    out="$(plutil -lint "${e}" 2>&1)" || rc=$?
    assert_status "${rc}" 0 "enumerator plutil -lint should succeed"
  fi
  # The enumerator invokes the render-targets.sh helper we ship under
  # /opt/cisco/secureclient/defenseclaw/lib/render-targets.sh. If a
  # future edit accidentally points at a stale bin/ path, catch it here.
  local body
  body="$(cat "${e}")"
  assert_contains "${body}" "/opt/cisco/secureclient/defenseclaw/lib/render-targets.sh" \
    "enumerator plist points at lib/render-targets.sh"
  assert_contains "${body}" "<key>StartInterval</key>" "enumerator has StartInterval"
  assert_contains "${body}" "com.cisco.secureclient.defenseclaw.hook-enumerator" \
    "enumerator label is namespaced under com.cisco.secureclient.defenseclaw"

  body="$(cat "${g}")"
  assert_contains "${body}" "enterprise" "guardian invokes enterprise subcommand"
  assert_contains "${body}" "hooks"      "guardian invokes hooks subcommand"
  # The guardian runs the long-running `watch` mode so tampering with a
  # per-user hook config or hook script is fsnotify-detected and healed
  # within ~1 s. If this ever regresses back to `reconcile`, heal
  # latency silently blows out to ~5 min.
  assert_contains "${body}" "<string>watch</string>" "guardian runs long-running watch mode"
  assert_not_contains "${body}" "<string>reconcile</string>" \
    "guardian must not use one-shot reconcile (regresses fsnotify auto-heal)"
  # --interval 60s is the periodic backstop *inside* watch; it is NOT a
  # substitute for real fsnotify reactivity. Both must be present.
  # 60s (was 5m) tightens worst-case tamper-detection for SharedWriter
  # Write tampers (native agent configs) and generic-script Writes to
  # ~1 min. No additional resource cost — same long-running process.
  assert_contains "${body}" "<string>--interval</string>" "guardian passes --interval flag"
  assert_contains "${body}" "<string>60s</string>"        "guardian backstop interval is 60s"
  assert_contains "${body}" "/opt/cisco/secureclient/defenseclaw/hook-guardian/targets.yaml" \
    "guardian points at the installer-rendered manifest path"
  # Restart policy: KeepAlive (right for long-running watch) NOT
  # StartInterval (would relaunch every N seconds — pointless with a
  # long-running process and would spawn duplicates).
  assert_contains "${body}" "<key>KeepAlive</key>" "guardian uses KeepAlive"
  assert_not_contains "${body}" "<key>StartInterval</key>" \
    "guardian must not use StartInterval in watch mode (would relaunch long-running process)"
}

t_render_targets_sh_exists_and_is_executable() {
  # render-targets.sh is invoked by the hook-enumerator LaunchDaemon.
  # It must be shipped in the bundle and be +x so /bin/bash doesn't
  # need to be edited to allow execution.
  local rt="${PKG_DIR}/lib/render-targets.sh"
  assert_file_exists "${rt}"
  if [[ ! -x "${rt}" ]]; then
    _fail "render-targets.sh missing +x"
    return 1
  fi
  local rc=0
  bash -n "${rt}" 2>&1 || rc=$?
  assert_status "${rc}" 0 "render-targets.sh parses cleanly"
}

t_install_bootstraps_guardian_and_enumerator() {
  # Regression guard: install.sh MUST install and bootstrap both the
  # hook-guardian and hook-enumerator LaunchDaemons — otherwise no
  # user's hooks ever get wired on a fresh customer install.
  local body
  body="$(cat "${PKG_DIR}/install.sh")"
  assert_contains "${body}" 'install_file_no_replace "${GUARDIAN_PLIST_SRC}" "${GUARDIAN_PLIST_DST}"' \
    "install.sh copies the guardian plist"
  assert_contains "${body}" 'install_file_no_replace "${ENUMERATOR_PLIST_SRC}" "${ENUMERATOR_PLIST_DST}"' \
    "install.sh copies the enumerator plist"
  assert_contains "${body}" 'launchctl bootstrap system "${GUARDIAN_PLIST_DST}"' \
    "install.sh bootstraps the guardian daemon"
  assert_contains "${body}" 'launchctl bootstrap system "${ENUMERATOR_PLIST_DST}"' \
    "install.sh bootstraps the enumerator daemon"
  assert_contains "${body}" 'render_targets_manifest' \
    "install.sh renders the initial targets.yaml manifest"
  assert_contains "${body}" 'enumerate_local_users' \
    "install.sh enumerates local users via the shared helper"
}

t_install_no_longer_hardcodes_single_target_user() {
  # Regression guard: the pre-2026.7.3 flow called
  #   "${GATEWAY_BIN}" enterprise hooks install --connector ... --user "${TARGET_USER}"
  # inline, which silently no-op'd whenever TARGET_USER was empty. The
  # multi-user rewrite REPLACES those inline calls with a manifest-based
  # reconcile owned by the hook-guardian LaunchDaemon. Grepping for a
  # bare `enterprise hooks install` invocation must return zero code
  # matches (comments are fine — they're filtered by the same grep the
  # guardian-auth-dir regression test uses).
  local bad
  bad="$(/usr/bin/python3 - "${PKG_DIR}/install.sh" <<'PY'
import re, sys
src = open(sys.argv[1]).read()
joined = re.sub(r"\\\n\s*", " ", src)
bad = []
for i, line in enumerate(joined.splitlines(), start=1):
    if "enterprise hooks install" not in line:
        continue
    # Skip pure prints / logs / comments.
    stripped = line.lstrip()
    if stripped.startswith("#"):
        continue
    if re.search(r"\blog\b|\bwarn\b|\bprintf\b", line):
        continue
    bad.append((i, line.strip()[:200]))
for i, l in bad:
    print(f"{i}: {l}")
PY
)"
  if [[ -n "${bad}" ]]; then
    _fail "found live 'enterprise hooks install' invocation(s) in install.sh — the multi-user rewrite should route wiring through the hook-guardian reconcile only:
${bad}"
    return 1
  fi
}

t_plist_contains_managed_paths() {
  local plist="${REPO_ROOT}/packaging/launchd/com.cisco.secureclient.defenseclaw.plist"
  local body; body="$(cat "${plist}")"
  assert_contains "${body}" "/opt/cisco/secureclient/defenseclaw/bin/defenseclaw-gateway" "binary path"
  assert_contains "${body}" "DEFENSECLAW_CONFIG"                                          "config env var"
  assert_contains "${body}" "/opt/cisco/secureclient/defenseclaw"                          "support dir path"
  assert_contains "${body}" "com.cisco.secureclient.defenseclaw"                          "launchd label"
  assert_contains "${body}" "<key>KeepAlive</key>"                                        "KeepAlive set"
  assert_contains "${body}" "<key>RunAtLoad</key>"                                        "RunAtLoad set"
}

t_plist_runs_as_root_by_default() {
  # DefenseClaw's macOS daemon runs as root — the managed cloud auth
  # provider requires root to read + re-perm its on-disk credential
  # store. The shipped plist deliberately OMITS UserName and GroupName
  # so launchd defaults to root (uid 0). If a future edit reintroduces
  # those keys, this test catches it — the daemon would silently break
  # managed cloud auth.
  local plist="${REPO_ROOT}/packaging/launchd/com.cisco.secureclient.defenseclaw.plist"
  if ! command -v plutil >/dev/null 2>&1; then
    return 0
  fi
  local uname_rc=0 gname_rc=0
  plutil -extract UserName  raw "${plist}" >/dev/null 2>&1 || uname_rc=$?
  plutil -extract GroupName raw "${plist}" >/dev/null 2>&1 || gname_rc=$?
  if [[ "${uname_rc}" == "0" ]]; then
    _fail "shipped plist has a UserName key; daemon must run as root (managed cloud auth requires it). Remove UserName + GroupName from the plist template."
    return 1
  fi
  if [[ "${gname_rc}" == "0" ]]; then
    _fail "shipped plist has a GroupName key; daemon must run as root (managed cloud auth requires it). Remove UserName + GroupName from the plist template."
    return 1
  fi
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

t_install_does_not_create_service_user() {
  # The service-user creation machinery (ensure_service_user,
  # dscl_ensure_prop, dseditgroup, sysadminctl invocations, and the
  # numeric UID scan) was removed with the switch to running the
  # daemon as root. Guard against reintroduction — a reappearance
  # means someone is trying to work around the managed cloud auth
  # provider's root requirement by resurrecting a service user, which
  # does NOT work (see the plist comment for the full rationale).
  local body
  body="$(cat "${PKG_DIR}/install.sh")"
  assert_not_contains "${body}" "ensure_service_user"    "install.sh must not create a service user (daemon runs as root)"
  assert_not_contains "${body}" "find_free_system_uid"   "install.sh must not scan for a free UID (no service user)"
  assert_not_contains "${body}" "dscl_ensure_record"     "install.sh must not manipulate dscl records (no service user)"
  assert_not_contains "${body}" "dscl_ensure_prop"       "install.sh must not manipulate dscl props (no service user)"
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
#   WITH_BINARY=true, also drops in a stub defenseclaw (the bundle artifact
#   name; install.sh resolves the bundle binary under this name). Tests
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
  printf '<?xml version="1.0"?><plist/>' > "${bundle}/com.cisco.secureclient.defenseclaw.plist"
  chmod 0755 "${bundle}/install.sh"
  if [[ "${with_binary}" == "true" ]]; then
    printf '#!/bin/sh\nexit 0\n' > "${bundle}/defenseclaw"
    chmod 0755 "${bundle}/defenseclaw"
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

  assert_contains "${trace}" "PLIST_SRC=${bundle}/com.cisco.secureclient.defenseclaw.plist" "plist resolved from bundle"
  assert_contains "${trace}" "BINARY_SRC=${bundle}/defenseclaw"          "binary resolved from bundle"
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
  chmod 0644 "${bundle}/com.cisco.secureclient.defenseclaw.plist"
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
  assert_contains "${trace}" "PLIST_SRC=${bundle}/com.cisco.secureclient.defenseclaw.plist" "plist resolved from bundle"
  assert_contains "${trace}" "PLIST_SRC_ORIGIN=bundle"                            "origin is bundle (relaxed policy)"
  # And the ownership branch must not have fired.
  assert_not_contains "${out}" "must be owned by root" "bundle default plist accepted"
}

t_plist_validator_rejects_bundle_default_that_is_world_writable() {
  local bundle
  bundle="$(_setup_bundle_fixture true)"
  chmod 0646 "${bundle}/com.cisco.secureclient.defenseclaw.plist"
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
  assert_not_contains "${out}" "com.cisco.secureclient.defenseclaw.plist installed" "no silent fallback"
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

t_install_log_sink_is_after_preflight() {
  # Regression guard: install.sh's persistent log-sink tee must NOT
  # fire before the fresh-host preflight. Setting it up earlier
  # implicitly creates ${LOGS_DIR}/install.log which then trips both:
  #   1. The fresh-host marker loop (LOGS_DIR appears "existing")
  #   2. The `create_install_directory_no_replace ${LOGS_DIR}` at
  #      line ~678 (the dir was already created by mkdir -p)
  # Either failure locks the operator out of reinstall after
  # uninstall --purge. Uninstall wipes LOGS_DIR wholesale so no
  # persistence across install/uninstall cycles is desired anyway.
  #
  # This test enforces the ordering by grepping for both landmarks
  # (the tee call + the LOGS_DIR creation) and asserting the tee
  # appears AFTER the create_install_directory_no_replace line.
  local install="${REPO_ROOT}/packaging/macos/install.sh"
  local tee_line create_line
  tee_line="$(grep -n 'tee -a "\${_install_log_path}"' "${install}" | head -1 | cut -d: -f1)"
  create_line="$(grep -n 'create_install_directory_no_replace "\${LOGS_DIR}"' "${install}" | head -1 | cut -d: -f1)"
  if [[ -z "${tee_line}" || -z "${create_line}" ]]; then
    _fail "could not locate install.log tee (line=${tee_line:-?}) or LOGS_DIR creation (line=${create_line:-?}) in install.sh"
    return 1
  fi
  if (( tee_line < create_line )); then
    _fail "install.log tee at line ${tee_line} precedes LOGS_DIR creation at line ${create_line} — self-lockout on reinstall"
    return 1
  fi
}

t_install_does_not_precreate_cmid_log_file() {
  # Running the daemon as root means the managed cloud auth provider
  # can create its own log file without any installer help. The earlier
  # stop-gap (pre-creating the file with defenseclaw ownership) was
  # removed with the root switch. Guard against reintroducing it — a
  # chown of that file to a service uid is a strong signal someone
  # regressed to a non-root daemon.
  local body; body="$(cat "${REPO_ROOT}/packaging/macos/install.sh")"
  assert_not_contains "${body}" 'chown "${SERVICE_UID}:${SERVICE_GID}" "${CMID_LOG_FILE}"' \
    "install.sh must not pre-create the managed-auth log with service-user ownership (daemon runs as root)"
  assert_not_contains "${body}" 'CMID_LOG_FILE=' \
    "install.sh must not declare CMID_LOG_FILE (no log-file stop-gap needed as root)"
}

t_install_does_not_relax_cmid_store_perms() {
  # Same rationale as the log file. The managed cloud auth provider
  # can read + fchmod its credential store without any installer help
  # when the caller is root. The earlier stop-gap (chgrp to service
  # group + 0640) was removed. Guard against re-adding it — messing
  # with the perms of a file the provider actively rewrites is fragile
  # and unnecessary.
  local body; body="$(cat "${REPO_ROOT}/packaging/macos/install.sh")"
  assert_not_contains "${body}" '/opt/cisco/secureclient/cloudmanagement/etc/cmidstore.json' \
    "install.sh must not touch the managed-auth credential store (daemon runs as root)"
  assert_not_contains "${body}" 'CMID_STORE=' \
    "install.sh must not declare CMID_STORE (no store-perm stop-gap needed as root)"
}

t_uninstall_still_sweeps_legacy_cmid_log_file() {
  # Even in root-mode we keep the sweep so upgrades from a pre-root
  # DefenseClaw install don't leave a defenseclaw-owned log file
  # dangling under a shared log dir.
  local body; body="$(cat "${REPO_ROOT}/packaging/macos/uninstall.sh")"
  assert_contains "${body}" "/Library/Logs/Cisco/SecureClient/CloudManagement/defenseclaw-gateway_cmidapi.log" \
    "uninstall sweeps the legacy managed-auth log file"
  # Never rm above the specific file — that dir is shared.
  assert_not_contains "${body}" 'rm -rf "/Library/Logs/Cisco' \
    "uninstall MUST NOT recurse into the shared log tree"
  assert_not_contains "${body}" 'rm -rf /Library/Logs/Cisco' \
    "uninstall MUST NOT recurse into the shared log tree (no-quote form)"
}

t_install_refuses_existing_state_before_build_or_launchd_mutation() {
  local body; body="$(cat "${REPO_ROOT}/packaging/macos/install.sh")"
  assert_contains "${body}" "existing DefenseClaw installation detected at" \
    "managed bundle refuses an in-place hard-cut bypass"
  assert_contains "${body}" "no changes were made. This installer is fresh-install-only" \
    "managed bundle gives an explicit no-change refusal"
  assert_contains "${body}" "remain on the current version" \
    "managed bundle gives a fail-closed path when no staged enterprise upgrader exists"
  assert_contains "${body}" "dscl . -list /Users" \
    "managed bundle checks every local home even when a target user is selected"
  assert_not_contains "${body}" 'elif [[ "${DC_INSTALLER_SKIP_ROOT_CHECK:-}" != "1" ]]' \
    "all-user dscl enumeration must not be conditional on TARGET_HOME being empty"
  assert_contains "${body}" "command -v \"\${_installed_command}\"" \
    "managed bundle checks package-manager/custom PATH installations"
  assert_contains "${body}" '"${GUARDIAN_PLIST_DST}"' \
    "managed bundle detects the current guardian plist"
  assert_contains "${body}" '"${LEGACY_GUARDIAN_PLIST_DST}"' \
    "managed bundle detects the legacy guardian plist"
  assert_contains "${body}" '"${GUARDIAN_LAUNCHD_LABEL}"' \
    "managed bundle detects the current guardian job"
  assert_contains "${body}" '"${LEGACY_GUARDIAN_LAUNCHD_LABEL}"' \
    "managed bundle detects the legacy guardian job"

  local guard_line build_line mutation_line
  guard_line="$(grep -n "existing DefenseClaw installation detected at" \
    "${REPO_ROOT}/packaging/macos/install.sh" | head -1 | cut -d: -f1)"
  build_line="$(grep -n 'go build -o defenseclaw-gateway' \
    "${REPO_ROOT}/packaging/macos/install.sh" | head -1 | cut -d: -f1)"
  mutation_line="$(grep -n 'create_install_directory_no_replace "${INSTALL_PREFIX}"' \
    "${REPO_ROOT}/packaging/macos/install.sh" | head -1 | cut -d: -f1)"
  if [[ -z "${guard_line}" || -z "${build_line}" || -z "${mutation_line}" \
     || "${guard_line}" -ge "${build_line}" \
     || "${guard_line}" -ge "${mutation_line}" ]]; then
    _fail "existing-install guard must precede build and installed-file writes"
  fi
  assert_not_contains "${body}" 'mv -f -- "${temporary}" "${destination}"' \
    "managed bundle publication must not force-replace a concurrent destination"
  assert_contains "${body}" 'ln "${temporary}" "${destination}"' \
    "managed bundle uses no-replace publication"
  assert_contains "${body}" "appeared concurrently and was preserved" \
    "managed bundle reports concurrent-state preservation"

  # The final boundary after a potentially slow local build must repeat every
  # current and legacy gateway/guardian job+plist pair from the initial
  # preflight. Merely mentioning these variables in the initial marker list is
  # insufficient: a guardian can appear while the binary is being built.
  local final_boundary
  final_boundary="$(sed -n '/# Repeat the launchd\/path boundary immediately before mutation/,/unset _lbl_plist/p' \
    "${REPO_ROOT}/packaging/macos/install.sh")"
  for expected in \
    '"${LAUNCHD_LABEL}:${PLIST_DST}"' \
    '"${GUARDIAN_LAUNCHD_LABEL}:${GUARDIAN_PLIST_DST}"' \
    '"${LEGACY_LAUNCHD_LABEL}:${LEGACY_PLIST_DST}"' \
    '"${LEGACY_GUARDIAN_LAUNCHD_LABEL}:${LEGACY_GUARDIAN_PLIST_DST}"'; do
    assert_contains "${final_boundary}" "${expected}" \
      "final mutation boundary repeats ${expected}"
  done
}

run_case "plist exists and lints"     t_plist_exists_and_parses
run_case "guardian + enumerator plists exist and lint" t_guardian_and_enumerator_plists_exist_and_parse
run_case "render-targets.sh present + executable + parses" t_render_targets_sh_exists_and_is_executable
run_case "install.sh bootstraps guardian + enumerator daemons" t_install_bootstraps_guardian_and_enumerator
run_case "install.sh no longer inline-calls 'enterprise hooks install'" t_install_no_longer_hardcodes_single_target_user
run_case "plist references managed paths" t_plist_contains_managed_paths
run_case "install.log sink is set up AFTER fresh-host preflight + LOGS_DIR create" t_install_log_sink_is_after_preflight
run_case "install does not pre-create CMID log file (root daemon owns lifecycle)"    t_install_does_not_precreate_cmid_log_file
run_case "install does not relax CMID store perms (root daemon owns lifecycle)"      t_install_does_not_relax_cmid_store_perms
run_case "uninstall still sweeps legacy CMID log file from pre-root installs"        t_uninstall_still_sweeps_legacy_cmid_log_file
run_case "install refuses existing state before build or launchd mutation"           t_install_refuses_existing_state_before_build_or_launchd_mutation
run_case "plist runs as root by default (managed CMID needs it)" t_plist_runs_as_root_by_default
run_case "installer_lib.sh syntax"    t_install_lib_syntax
run_case "install.sh syntax"          t_install_sh_syntax
run_case "uninstall.sh syntax"        t_uninstall_sh_syntax
run_case "install.sh executable"      t_install_sh_is_executable
run_case "uninstall.sh executable"    t_uninstall_sh_is_executable
run_case "scrub_agent_configs.py present and +x" t_scrub_py_exists_and_executable
run_case "scrub_agent_configs.py syntax"          t_scrub_py_syntax
run_case "install.sh does NOT create a service user (root-mode daemon)" t_install_does_not_create_service_user
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
