#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# GAP-0868 / GAP-0903 / GAP-0979 on macOS: the package's preinstall holds
# (SIGSTOP) each sandbox daemon of a DefenseClaw before 1.0.4, the
# LaunchAgent's versioned copy included, and its postinstall ends the held
# ones (SIGKILL) before the programs get new files; from 1.0.4 nothing is
# held. ps is a stand-in that lists a real sleeping process under the
# daemon's command line, so this runs on Linux too.
BUILD_SH="${REPO_ROOT}/scripts/build-macos-enterprise-pkg.sh"

_hold_extract() {
  local d=$1 name=$2
  awk -v name="${name}" '$0 == "cat >\"$SCRIPTS/" name "\" <<'"'"'EOF'"'"'" { copying=1; next } copying && /^EOF$/ { exit } copying { print }' \
    "${BUILD_SH}" | sed -e "s#/opt/cisco/defenseclaw/lifecycle#${d}/state#g" \
    -e 's#@DC_PKG_VERSION@#1.0.5#' -e 's#root_owned "$record"#[ -f "$record" ]#' >"${d}/${name}"
}

_hold_state() { sed 's/^.*) //' "/proc/$1/stat" 2>/dev/null | cut -d' ' -f1; }

t_pkg_holds_pre_104_sandbox_daemons() {
  [[ -d /proc/self ]] || { echo "  skip: needs /proc"; return 0; }
  local d; d="$(mktest_tmp)"
  mkdir -p "${d}/state" "${d}/bin"
  _hold_extract "${d}" preinstall
  _hold_extract "${d}" postinstall
  grep -q 'sandbox-daemons.held' "${d}/preinstall" || { _fail "the preinstall holds no sandbox daemon"; return 1; }
  sleep 300 &
  local pid=$!
  cat >"${d}/bin/ps" <<MOCK
#!/bin/sh
case "\$*" in
  *command=*) echo "${pid} Sun Oct 25 10:00:00 2026 /opt/cisco/defenseclaw/bin/launch-agents/0123abcd/defenseclaw-gateway sandbox-daemon"
              echo "999999 Sun Oct 25 10:00:00 2026 /usr/bin/other sandbox-daemon" ;;
  *lstart=*) [ -e /proc/${pid} ] && echo "Sun Oct 25 10:00:00 2026" ;;
esac
MOCK
  printf '#!/bin/sh\nexit 1\n' >"${d}/bin/sleep"  # no recovery during the test
  chmod +x "${d}/bin/ps" "${d}/bin/sleep"
  printf '{"product_version": "1.0.3"}\n' >"${d}/state/deployment.json"
  PATH="${d}/bin:${PATH}" sh "${d}/preinstall" >/dev/null 2>&1
  assert_status "$(_hold_state "${pid}" | tr -d '\n' | grep -c T)" 1 "the 1.0.3 LaunchAgent daemon was not held"
  grep -q "^${pid}|" "${d}/state/sandbox-daemons.held" || _fail "the held daemon was not recorded"
  # The postinstall's kill, before its programs get new files (its own
  # later steps fail here: no payload).
  PATH="${d}/bin:${PATH}" sh "${d}/postinstall" >/dev/null 2>&1
  wait "${pid}" 2>/dev/null
  if [[ -e "/proc/${pid}" && "$(_hold_state "${pid}")" != Z ]]; then _fail "the held daemon survived the postinstall"; kill -KILL "${pid}"; fi
  [[ ! -e "${d}/state/sandbox-daemons.held" ]] || _fail "the held list was left behind"
  # From 1.0.4 the daemon counts those MicroVMs: nothing is held.
  sleep 300 &
  pid=$!
  sed -i.bak "s/^  \*command=\*) echo \"[0-9]*/  *command=*) echo \"${pid}/" "${d}/bin/ps"
  printf '{"product_version": "1.0.4"}\n' >"${d}/state/deployment.json"
  PATH="${d}/bin:${PATH}" sh "${d}/preinstall" >/dev/null 2>&1
  assert_status "$(_hold_state "${pid}" | tr -d '\n' | grep -c T)" 0 "a 1.0.4 daemon was held"
  kill -KILL "${pid}" 2>/dev/null
}

run_case "pkg holds a pre-1.0.4 sandbox daemon through the program swap" t_pkg_holds_pre_104_sandbox_daemons
