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

# True when pid ended within about 5 s; else kills it, so a missed kill fails
# the case instead of hanging it on a stopped process.
_hold_gone() {
  local _
  for _ in $(seq 50); do
    [[ -e "/proc/$1" && "$(_hold_state "$1")" != Z ]] || { wait "$1" 2>/dev/null; return 0; }
    sleep 0.1
  done
  kill -KILL "$1" 2>/dev/null; wait "$1" 2>/dev/null
  return 1
}

# A stand-in ps: the -axo listing shows pid under the daemon's command line
# with the start time list_start, and -o lstart= prints now_start (with the
# leading pad macOS ps adds) while the process lives.
_hold_ps() {
  local d=$1 pid=$2 list_start=$3 now_start=$4
  cat >"${d}/bin/ps" <<MOCK
#!/bin/sh
case "\$*" in
  *command=*) echo "${pid} ${list_start} /opt/cisco/defenseclaw/bin/launch-agents/0123abcd/defenseclaw-gateway sandbox-daemon"
              echo "999999 ${list_start} /usr/bin/other sandbox-daemon" ;;
  *lstart=*) [ -e /proc/${pid} ] && echo " ${now_start}" ;;
esac
MOCK
  chmod +x "${d}/bin/ps"
}

t_pkg_holds_pre_104_sandbox_daemons() {
  [[ -d /proc/self ]] || { echo "  skip: needs /proc"; return 0; }
  local d; d="$(mktest_tmp)"
  mkdir -p "${d}/state" "${d}/bin"
  _hold_extract "${d}" preinstall
  _hold_extract "${d}" postinstall
  grep -q 'sandbox-daemons.held' "${d}/preinstall" || { _fail "the preinstall holds no sandbox daemon"; return 1; }
  sleep 300 &
  local pid=$!
  _hold_ps "${d}" "${pid}" "Sun Oct 25 10:00:00 2026" "Sun Oct 25 10:00:00 2026"
  printf '#!/bin/sh\nexit 1\n' >"${d}/bin/sleep"  # no recovery during the test
  chmod +x "${d}/bin/sleep"
  printf '{"product_version": "1.0.3"}\n' >"${d}/state/deployment.json"
  PATH="${d}/bin:${PATH}" sh "${d}/preinstall" >/dev/null 2>&1
  assert_status "$(_hold_state "${pid}" | tr -d '\n' | grep -c T)" 1 "the 1.0.3 LaunchAgent daemon was not held"
  grep -q "^${pid}|" "${d}/state/sandbox-daemons.held" || _fail "the held daemon was not recorded"
  # The postinstall's kill, before its programs get new files (its own
  # later steps fail here: no payload).
  PATH="${d}/bin:${PATH}" sh "${d}/postinstall" >/dev/null 2>&1
  _hold_gone "${pid}" || _fail "the held daemon survived the postinstall"
  [[ ! -e "${d}/state/sandbox-daemons.held" ]] || _fail "the held list was left behind"
  # From 1.0.4 the daemon counts those MicroVMs: nothing is held.
  sleep 300 &
  pid=$!
  _hold_ps "${d}" "${pid}" "Sun Oct 25 10:00:00 2026" "Sun Oct 25 10:00:00 2026"
  printf '{"product_version": "1.0.4"}\n' >"${d}/state/deployment.json"
  PATH="${d}/bin:${PATH}" sh "${d}/preinstall" >/dev/null 2>&1
  assert_status "$(_hold_state "${pid}" | tr -d '\n' | grep -c T)" 0 "a 1.0.4 daemon was held"
  kill -KILL "${pid}" 2>/dev/null
}

# lstart pads a day from 1 to 9 with a space (strftime %c); the held list
# keeps it folded, so the postinstall must fold its own read the same way.
# A held process that is no longer the same one is resumed, not left stopped.
t_pkg_hold_single_digit_day_and_resume() {
  [[ -d /proc/self ]] || { echo "  skip: needs /proc"; return 0; }
  local d; d="$(mktest_tmp)"
  mkdir -p "${d}/state" "${d}/bin"
  _hold_extract "${d}" preinstall
  _hold_extract "${d}" postinstall
  printf '#!/bin/sh\nexit 1\n' >"${d}/bin/sleep"
  chmod +x "${d}/bin/sleep"
  printf '{"product_version": "1.0.2"}\n' >"${d}/state/deployment.json"
  sleep 300 &
  local pid=$!
  _hold_ps "${d}" "${pid}" "Fri Nov  6 01:50:08 2026" "Fri Nov  6 01:50:08 2026"
  PATH="${d}/bin:${PATH}" sh "${d}/preinstall" >/dev/null 2>&1
  assert_status "$(_hold_state "${pid}" | tr -d '\n' | grep -c T)" 1 "the day-6 daemon was not held"
  PATH="${d}/bin:${PATH}" sh "${d}/postinstall" >/dev/null 2>&1
  _hold_gone "${pid}" || _fail "the held day-6 daemon survived the postinstall"
  # The pid now names another start: resume it, never kill it.
  sleep 300 &
  pid=$!
  _hold_ps "${d}" "${pid}" "Fri Nov  6 01:50:08 2026" "Sat Nov  7 09:00:00 2026"
  PATH="${d}/bin:${PATH}" sh "${d}/preinstall" >/dev/null 2>&1
  assert_status "$(_hold_state "${pid}" | tr -d '\n' | grep -c T)" 1 "the daemon was not held"
  PATH="${d}/bin:${PATH}" sh "${d}/postinstall" >/dev/null 2>&1
  [[ -e "/proc/${pid}" ]] || _fail "a process that was no longer the held daemon was killed"
  assert_status "$(_hold_state "${pid}" | tr -d '\n' | grep -c T)" 0 "a held process the postinstall did not kill stays stopped"
  [[ ! -e "${d}/state/sandbox-daemons.held" ]] || _fail "the held list was left behind"
  kill -KILL "${pid}" 2>/dev/null
}

run_case "pkg holds a pre-1.0.4 sandbox daemon through the program swap" t_pkg_holds_pre_104_sandbox_daemons
run_case "pkg hold matches a day 1-9 start and resumes what it does not kill" t_pkg_hold_single_digit_day_and_resume
