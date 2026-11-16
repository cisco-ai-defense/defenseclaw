#!/usr/bin/env bash
# No-fatal gate for uninstall.sh --purge: purge over an install carrying
# flags, symlinks, a failing per-user scrub, a deleted user's leftover
# home, manifest-only and ledger-only users, and a missing library always
# exits 0, removes everything DefenseClaw owns that it can, isolates each
# user, and summarises leftovers on the last line of uninstall.log.
# Runs unprivileged against a fixture machine root.
. "${PKG_DIR}/tests/lib_fixture.sh"

# _purge_fixture -> stdout: a bundle with an install and per-user state.
#   me        the invoking user (so `id -u` resolves and the per-user
#             attempt goes through the sudo stub): its Claude settings
#             fail as the user and succeed on the root retry
#   bob       Cursor hooks.json that fails every scrub attempt
#   olduser   no dscl record; a managed ~/.defenseclaw left behind
#   unmanaged no dscl record; an unmanaged ~/.defenseclaw (kept)
#   manifestonly / ledgeronly  known only from targets.yaml / the ledger
_purge_fixture() {
  local b me prefix
  b="$(fixture_bundle)"
  me="$(id -un)"
  fixture_add_user "${b}" "${me}" "$(id -u)"
  fixture_add_user "${b}" bob 502
  # Stub scrubber: ALWAYS_FAIL never scrubs; FAIL_AS_USER fails only when
  # run through `sudo -u`; anything else is rewritten to "scrubbed".
  cat > "${b}/defenseclaw" <<'EOF'
#!/bin/bash
file=""
while [ $# -gt 0 ]; do
  case "$1" in --file) file="$2"; shift 2 ;; *) shift ;; esac
done
[ -n "${file}" ] || exit 0
grep -q ALWAYS_FAIL "${file}" && exit 4
if grep -q FAIL_AS_USER "${file}" && [ -n "${DC_TEST_RUN_AS:-}" ]; then exit 4; fi
printf 'scrubbed\n' > "${file}"
EOF
  chmod 0755 "${b}/defenseclaw"
  fixture_install "${b}" --connector codex,claudecode,cursor >/dev/null 2>&1 || true
  prefix="${b}/root/opt/cisco/secureclient/defenseclaw"

  local home="${b}/root/Users/${me}"
  mkdir -p "${home}/.claude" "${home}/.codex" "${home}/.defenseclaw/hooks"
  printf '{"FAIL_AS_USER":1}\n' > "${home}/.claude/settings.json"
  printf '[hooks]\n' > "${home}/.codex/config.toml"
  mkdir -p "${home}/.copilot/hooks"
  printf '{"version":1,"hooks":{}}\n' > "${home}/.copilot/hooks/defenseclaw.json"
  printf 'DEFENSECLAW_MANAGED_HOOK=1\n' > "${home}/.defenseclaw/hooks/claude-code-hook.sh"
  chflags uchg "${home}/.defenseclaw/hooks/claude-code-hook.sh"
  printf 'keep\n' > "${b}/outside"
  ln -s "${b}/outside" "${home}/.defenseclaw/hooks/link-out"

  mkdir -p "${b}/root/Users/bob/.cursor" "${b}/root/Users/bob/.defenseclaw/hooks"
  printf '{"ALWAYS_FAIL":1}\n' > "${b}/root/Users/bob/.cursor/hooks.json"
  printf 'x\n' > "${b}/root/Users/bob/.defenseclaw/hooks/cursor-hook.sh"

  mkdir -p "${b}/root/Users/olduser/.defenseclaw/hooks"
  printf '#!/bin/sh\nDEFENSECLAW_MANAGED_HOOK=1\n' > "${b}/root/Users/olduser/.defenseclaw/hooks/codex-hook.sh"
  mkdir -p "${b}/root/Users/unmanaged/.defenseclaw/hooks"
  printf '#!/bin/sh\n' > "${b}/root/Users/unmanaged/.defenseclaw/hooks/codex-hook.sh"

  mkdir -p "${b}/root/Users/manifestonly/.defenseclaw" "${b}/root/Users/ledgeronly/.defenseclaw"
  cat >> "${prefix}/hook-guardian/targets.yaml" <<EOF
  - user: "manifestonly"
    user_home: "${b}/root/Users/manifestonly"
    uid: 601
    gid: 20
    connector: "codex"
    agent_version: ""
    enabled: true
EOF
  printf '{"targets":[{"connector":"codex","user_home":"%s","data_dir":"%s/.defenseclaw"}]}\n' \
    "${b}/root/Users/ledgeronly" "${b}/root/Users/ledgeronly" \
    > "${prefix}/hook-guardian-state/protected_targets.json"

  # Machine drift: flags on a plist, inside the install tree and a log.
  chflags uchg "${b}/root/Library/LaunchDaemons/com.cisco.secureclient.defenseclaw.plist"
  chflags uchg "${prefix}/etc/config.yaml"
  printf 'log\n' > "${b}/root/Library/Logs/Cisco/SecureClient/DefenseClaw/gateway.log"
  chflags uappnd "${b}/root/Library/Logs/Cisco/SecureClient/DefenseClaw/gateway.log"
  printf '%s\n' "${b}"
}

t_purge_completes_and_isolates_users() {
  local b; b="$(_purge_fixture)"
  local me; me="$(id -un)"
  local out rc=0
  out="$(fixture_uninstall "${b}" --purge -y 2>&1)" || rc=$?
  assert_status "${rc}" 0 "purge exits 0 with leftovers"

  local prefix="${b}/root/opt/cisco/secureclient/defenseclaw"
  local logs="${b}/root/Library/Logs/Cisco/SecureClient/DefenseClaw"
  [[ ! -e "${prefix}" ]] || _fail "install tree must be removed"
  [[ ! -e "${b}/root/Library/LaunchDaemons/com.cisco.secureclient.defenseclaw.plist" ]] \
    || _fail "flagged plist must be removed"
  assert_eq "$(ls -A "${logs}")" "uninstall.log" "log folder keeps only uninstall.log"
  [[ ! -e "${b}/state/com.cisco.secureclient.defenseclaw.hook-guardian" ]] || _fail "guardian booted out"

  assert_eq "$(cat "${b}/root/Users/${me}/.claude/settings.json")" "scrubbed" "root retry scrubbed the config"
  assert_eq "$(cat "${b}/root/Users/${me}/.copilot/hooks/defenseclaw.json")" "scrubbed" "GitHub Copilot's hook file scrubbed"
  assert_contains "${out}" 'reason="scrub_root_retry"' "root retry logged"
  [[ ! -e "${b}/root/Users/${me}/.defenseclaw" ]] || _fail "flagged ~/.defenseclaw removed"
  assert_eq "$(cat "${b}/outside")" "keep" "symlink target inside ~/.defenseclaw untouched"

  assert_contains "$(cat "${b}/root/Users/bob/.cursor/hooks.json")" "ALWAYS_FAIL" "failed scrub leaves the file as is"
  [[ ! -e "${b}/root/Users/bob/.defenseclaw" ]] || _fail "bob's ~/.defenseclaw removed despite the failed scrub"
  assert_contains "${out}" 'connector="cursor" path="'"${b}"'/root/Users/bob/.cursor/hooks.json" reason="scrub_failed" unit="user:bob"' \
    "failed user x connector skipped with a marker"

  [[ ! -e "${b}/root/Users/olduser/.defenseclaw" ]] || _fail "deleted user's managed folder removed"
  [[ -e "${b}/root/Users/unmanaged/.defenseclaw" ]] || _fail "unmanaged folder kept"
  [[ ! -e "${b}/root/Users/manifestonly/.defenseclaw" ]] || _fail "manifest-only user purged"
  [[ ! -e "${b}/root/Users/ledgeronly/.defenseclaw" ]] || _fail "ledger-only user purged"

  local last
  last="$(tail -1 "${logs}/uninstall.log")"
  assert_contains "${last}" "[uninstall] done with 1 warning(s); left behind:" "summary on the last log line"
  assert_contains "${last}" "bob/.cursor/hooks.json (scrub_failed)" "summary names the leftover"

  # A second purge is safe and still exits 0.
  rc=0
  out="$(fixture_uninstall "${b}" --purge -y 2>&1)" || rc=$?
  assert_status "${rc}" 0 "second purge exits 0"
  [[ ! -e "${prefix}" ]] || _fail "install tree stays gone"
  fixture_cleanup "${b}"
}

t_purge_without_library_still_finds_users() {
  local b; b="$(_purge_fixture)"
  # A re-run from a copy without lib/ after the install tree's lib/ is
  # gone: the target set is built from dscl, the manifest, the ledger
  # and the home scan.
  rm -rf "${b}/lib" "${b}/root/opt/cisco/secureclient/defenseclaw/lib"
  local out rc=0
  out="$(fixture_uninstall "${b}" --purge -y --keep-agent-configs 2>&1)" || rc=$?
  assert_status "${rc}" 0 "purge without the library exits 0"
  [[ ! -e "${b}/root/Users/bob/.defenseclaw" ]] || _fail "dscl user purged without the library"
  [[ ! -e "${b}/root/Users/olduser/.defenseclaw" ]] || _fail "scanned user purged without the library"
  [[ ! -e "${b}/root/Users/manifestonly/.defenseclaw" ]] || _fail "manifest user purged without the library"
  [[ ! -e "${b}/root/Users/ledgeronly/.defenseclaw" ]] || _fail "ledger user purged without the library"
  [[ ! -e "${b}/root/opt/cisco/secureclient/defenseclaw" ]] || _fail "install tree removed"
  fixture_cleanup "${b}"
}

t_purge_skips_symlinked_home() {
  local b; b="$(fixture_bundle)"
  mkdir -p "${b}/elsewhere/.defenseclaw/hooks"
  printf 'DEFENSECLAW_MANAGED_HOOK=1\n' > "${b}/elsewhere/.defenseclaw/hooks/codex-hook.sh"
  ln -s "${b}/elsewhere" "${b}/root/Users/linked"
  printf 'linked 700\n' >> "${b}/users"
  local out rc=0
  out="$(fixture_uninstall "${b}" --purge -y 2>&1)" || rc=$?
  assert_status "${rc}" 0 "purge with a symlinked home exits 0"
  [[ -e "${b}/elsewhere/.defenseclaw" ]] || _fail "a symlinked home is never followed"
  assert_contains "${out}" 'reason="home_symlink"' "symlinked home skipped with a marker"
  fixture_cleanup "${b}"
}

t_clean_purge_removes_log_folder() {
  local b; b="$(fixture_bundle)"
  local rc=0
  fixture_install "${b}" --connector codex >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 0 "fixture install"
  local logs="${b}/root/Library/Logs/Cisco/SecureClient/DefenseClaw"
  printf 'log\n' > "${logs}/gateway.log"
  [[ -f "${logs}/gateway.log" ]] || _fail "fixture log folder missing before the purge"
  local out
  rc=0
  out="$(fixture_uninstall "${b}" --purge -y 2>&1)" || rc=$?
  assert_status "${rc}" 0 "clean purge exits 0"
  assert_contains "${out}" "[uninstall] done." "clean purge reports done"
  [[ ! -e "${logs}" && ! -L "${logs}" ]] || _fail "a clean purge removes the log folder, uninstall.log included ($(ls -A "${logs}" 2>&1))"
  fixture_cleanup "${b}"
}

t_root_retry_refuses_symlinked_parent() {
  local b; b="$(_purge_fixture)"
  local me; me="$(id -un)"
  local home="${b}/root/Users/${me}"
  # The user swaps ~/.claude for a link to a folder holding someone else's
  # settings; the user-run scrub fails there, and root must not retry.
  mkdir -p "${b}/victim"
  printf '{"FAIL_AS_USER":1}\n' > "${b}/victim/settings.json"
  rm -rf "${home}/.claude"
  ln -s "${b}/victim" "${home}/.claude"
  local out rc=0
  out="$(fixture_uninstall "${b}" --purge -y 2>&1)" || rc=$?
  assert_status "${rc}" 0 "purge exits 0"
  assert_contains "$(cat "${b}/victim/settings.json")" "FAIL_AS_USER" "root never edits through a symlinked parent"
  assert_contains "${out}" "is a symlink, so it is not retried as root" "the refusal is logged"
  fixture_cleanup "${b}"
}

t_user_purge_keeps_earlier_warnings() {
  local b; b="$(fixture_bundle)"
  local rc=0
  fixture_install "${b}" --connector codex >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 0 "fixture install"
  fixture_add_user "${b}" "$(id -un)" "$(id -u)"
  local logs="${b}/root/Library/Logs/Cisco/SecureClient/DefenseClaw"
  printf '[uninstall] done with 1 warning(s); left behind: /Users/bob/.cursor/hooks.json (scrub_failed)\n' > "${logs}/uninstall.log"
  local out
  rc=0
  out="$(fixture_uninstall "${b}" --purge -y --user "$(id -un)" 2>&1)" || rc=$?
  assert_status "${rc}" 0 "a --user purge exits 0"
  assert_contains "$(cat "${logs}/uninstall.log" 2>&1)" "bob/.cursor/hooks.json (scrub_failed)" "an earlier warning survives a --user purge"
  fixture_cleanup "${b}"
}

run_case "purge completes, isolates users and summarises leftovers" t_purge_completes_and_isolates_users
run_case "a --user purge keeps earlier warnings"                  t_user_purge_keeps_earlier_warnings
run_case "a clean purge removes the log folder"                     t_clean_purge_removes_log_folder
run_case "purge without the library still finds every user"         t_purge_without_library_still_finds_users
run_case "root retry refuses a symlinked parent folder"          t_root_retry_refuses_symlinked_parent
run_case "purge never follows a symlinked home"                     t_purge_skips_symlinked_home
