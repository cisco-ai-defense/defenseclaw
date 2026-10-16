#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# The managed macOS pkg postinstall gives the signed gateway that both
# DefenseClaw LaunchAgents run a new inode (copy to a temporary file in the
# same folder, then rename) before `enterprise macos ensure` reloads the
# loaded per-user jobs. This extracts the helper and the generated postinstall
# from scripts/build-macos-enterprise-pkg.sh and runs the helper against an
# isolated file; no package, launchctl or macOS host is needed.
BUILD_SH="${REPO_ROOT}/scripts/build-macos-enterprise-pkg.sh"

# pkg_stat <gnu-format> <bsd-format> <path>: GNU and BSD stat differ.
pkg_stat() {
  if stat --version >/dev/null 2>&1; then
    stat -c "$1" "$3"
  else
    stat -f "$2" "$3"
  fi
}

pkg_refresh() { # pkg_refresh <helper-file> <binary>
  bash -c '. "$1"; refresh_signed_launchagent_binary "$2"' _ "$1" "$2"
}

pkg_extract_helper() { # pkg_extract_helper <out-file>
  awk '/^refresh_signed_launchagent_binary\(\) \{/ { copying=1 } copying { print } copying && /^}/ { exit }' "${BUILD_SH}" >"$1"
  grep -q '^refresh_signed_launchagent_binary() {' "$1"
}

t_postinstall_replaces_the_gateway_with_a_new_inode() {
  local d; d="$(mktest_tmp)"
  pkg_extract_helper "${d}/replace.sh" || { _fail "helper not found in the pkg build script"; return 1; }
  local bin="${d}/defenseclaw-gateway" other="${d}/other-product"
  printf '%s\n' 'signed gateway bytes' >"${bin}"
  printf '%s\n' 'unrelated bytes' >"${other}"
  chmod 0755 "${bin}"
  local before owner first second
  before="$(pkg_stat '%d:%i' '%d:%i' "${bin}")"
  owner="$(pkg_stat '%u:%g' '%u:%g' "${bin}")"
  pkg_refresh "${d}/replace.sh" "${bin}"
  assert_status "$?" 0 "replace exits 0"
  first="$(pkg_stat '%d:%i' '%d:%i' "${bin}")"
  [[ "${before}" != "${first}" ]] || _fail "the gateway kept its inode: a loaded job could keep a stale signature"
  assert_eq "$(pkg_stat '%a' '%Lp' "${bin}")" "755" "mode kept"
  assert_eq "$(pkg_stat '%u:%g' '%u:%g' "${bin}")" "${owner}" "owner kept"
  assert_eq "$(cat "${bin}")" "signed gateway bytes" "content kept"
  # Every run replaces the file again (a pkg reinstall of the same version).
  pkg_refresh "${d}/replace.sh" "${bin}"
  second="$(pkg_stat '%d:%i' '%d:%i' "${bin}")"
  [[ "${first}" != "${second}" ]] || _fail "a second replace kept the inode"
  assert_eq "$(cat "${other}")" "unrelated bytes" "another file is untouched"
}

t_postinstall_refuses_a_symlink_as_the_signed_binary() {
  local d; d="$(mktest_tmp)"
  pkg_extract_helper "${d}/replace.sh" || { _fail "helper not found in the pkg build script"; return 1; }
  printf '%s\n' 'target bytes' >"${d}/target"
  ln -s "${d}/target" "${d}/gateway-link"
  local rc=0
  pkg_refresh "${d}/replace.sh" "${d}/gateway-link" || rc=$?
  [[ "${rc}" -ne 0 ]] || _fail "postinstall accepted a symlink as the signed binary"
  [[ -L "${d}/gateway-link" ]] || _fail "the symlink was replaced"
}

t_postinstall_failed_rename_keeps_the_old_binary() {
  local d; d="$(mktest_tmp)"
  pkg_extract_helper "${d}/replace.sh" || { _fail "helper not found in the pkg build script"; return 1; }
  local bin="${d}/defenseclaw-gateway"
  printf '%s\n' 'signed gateway bytes' >"${bin}"
  chmod 0755 "${bin}"
  local inode; inode="$(pkg_stat '%d:%i' '%d:%i' "${bin}")"
  mkdir "${d}/fakebin"
  printf '#!/bin/sh\nexit 1\n' >"${d}/fakebin/mv"
  chmod 0755 "${d}/fakebin/mv"
  local rc=0
  PATH="${d}/fakebin:${PATH}" pkg_refresh "${d}/replace.sh" "${bin}" || rc=$?
  [[ "${rc}" -ne 0 ]] || _fail "a failed rename appeared to succeed"
  assert_eq "$(pkg_stat '%d:%i' '%d:%i' "${bin}")" "${inode}" "old binary kept"
  assert_eq "$(cat "${bin}")" "signed gateway bytes" "old content kept"
  if find "${d}" -maxdepth 1 -name '.defenseclaw-gateway.pkg.*' | grep -q .; then
    _fail "a postinstall temporary file remains"
  fi
}

t_postinstall_replaces_the_gateway_before_ensure() {
  local d; d="$(mktest_tmp)"
  awk '/^cat >"\$SCRIPTS\/postinstall" <<'\''EOF'\''$/ { copying=1; next } copying && /^EOF$/ { exit } copying { print }' "${BUILD_SH}" >"${d}/postinstall"
  [[ -s "${d}/postinstall" ]] || { _fail "generated postinstall not found"; return 1; }
  local refresh_line ensure_line
  refresh_line="$(grep -n '^if ! refresh_signed_launchagent_binary ' "${d}/postinstall" | head -n 1 | cut -d: -f1)"
  ensure_line="$(grep -n 'enterprise macos ensure --from-package' "${d}/postinstall" | tail -n 1 | cut -d: -f1)"
  [[ -n "${refresh_line}" && -n "${ensure_line}" ]] || { _fail "replace or ensure line missing"; return 1; }
  [[ "${refresh_line}" -lt "${ensure_line}" ]] || _fail "the gateway is replaced after ensure ran"
  if command -v shellcheck >/dev/null 2>&1; then
    local rc=0
    shellcheck "${d}/postinstall" >"${d}/shellcheck.out" 2>&1 || rc=$?
    assert_status "${rc}" 0 "shellcheck of the generated postinstall: $(head -5 "${d}/shellcheck.out")"
  fi
}

run_case "pkg postinstall replaces the gateway with a new inode" t_postinstall_replaces_the_gateway_with_a_new_inode
run_case "pkg postinstall refuses a symlink" t_postinstall_refuses_a_symlink_as_the_signed_binary
run_case "pkg postinstall failed rename keeps the old binary" t_postinstall_failed_rename_keeps_the_old_binary
run_case "pkg postinstall replaces the gateway before ensure" t_postinstall_replaces_the_gateway_before_ensure
