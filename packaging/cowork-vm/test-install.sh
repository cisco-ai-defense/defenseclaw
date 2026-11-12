#!/bin/bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# Root regression test for the Claude Cowork VM install.sh, on a throwaway
# Linux host with systemd (a CI runner or a stand-in VM). It installs a real
# package the way Claude does and checks the security properties of the
# installer:
#   - install, unchanged re-run, and startup with and without policies/
#   - a link at $DATA/home is refused with exit 18 and its target untouched
#   - links the account plants ($DATA/gateway.out, $DATA/policies.new) are
#     not followed; no-systemd output is root-only (folder 0700, logs 0600)
#   - a spoofed 127.0.0.1:18970 listener gives exit 17, never "sensor up"
#   - a decoy gateway (this account, same home) on 18970 that the status CLI
#     accepts gives exit 17 "did not report healthy": the health check is
#     bound to the PID this run started (install.sh listener_is)
#   - a helper that does not broker gives exit 17 and no root gateway
#   - a helper whose Plane C has no process connector (cn_proc), only
#     fanotify, gives exit 17, never "sensor up"
#   - under systemd and without it, the helper holds exactly its six
#     capabilities (install.sh HELPER_CAPS) with no_new_privs, and the
#     gateway none; under systemd the helper's syscall filter is on
# It changes the host (account defenseclaw-cowork, /opt/defenseclaw-cowork,
# /etc and /var/lib folders, transient units) and removes it all at the end
# unless --keep. It refuses a host that already has the sensor unless --force.
#
#   sudo test-install.sh PACKAGE.tar.gz [--force] [--keep]
set -uo pipefail
pkg=${1:?usage: test-install.sh PACKAGE.tar.gz [--force] [--keep]}; shift
force=0 keep=0
for a in "$@"; do case "$a" in --force) force=1 ;; --keep) keep=1 ;; *) echo "unknown argument $a"; exit 2 ;; esac; done
[ "$(id -u)" = 0 ] || { echo "test-install.sh must run as root"; exit 2; }
[ -d /run/systemd/system ] || { echo "test-install.sh needs systemd"; exit 2; }
if [ -e /opt/defenseclaw-cowork ] && [ "$force" != 1 ]; then echo "the sensor is already installed here; pass --force on a throwaway host"; exit 2; fi
case "$(uname -m)" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; *) echo "unsupported host"; exit 2 ;; esac
D=/var/lib/defenseclaw-cowork A=defenseclaw-cowork R=/run/defenseclaw-cowork
ARGS="tenant=ci,device=ci-$arch,collector=collector.invalid:4318"
t="$(mktemp -d)"; chmod 0755 "$t"
fails=0
ok() { echo "ok   $*"; }
bad() { echo "FAIL $*"; fails=$((fails + 1)); }
cleanup() {
  systemctl stop defenseclaw-cowork defenseclaw-cowork-helper dc-cowork-test-spoof dc-cowork-test-decoy > /dev/null 2>&1
  systemctl reset-failed defenseclaw-cowork defenseclaw-cowork-helper dc-cowork-test-spoof dc-cowork-test-decoy > /dev/null 2>&1
  local f pid; for f in gateway helper; do pid="$(cat "$R/$f.pid" 2> /dev/null)"; [ -n "$pid" ] && kill "$pid" 2> /dev/null; done
  rm -rf "$t" /etc/dc-ci-canary-file /etc/dc-ci-canary-absent
  if [ "$keep" != 1 ]; then
    rm -rf /opt/defenseclaw-cowork /etc/defenseclaw-cowork "$D" "$R" /run/defenseclaw-cowork-sensor \
      /run/systemd/system/defenseclaw-cowork.slice
    rmdir /sys/fs/cgroup/defenseclaw-cowork 2> /dev/null
    systemctl daemon-reload
    getent passwd "$A" > /dev/null && userdel "$A" 2> /dev/null
  fi
}
trap cleanup EXIT
mkdir "$t/pkg"; tar -xzf "$pkg" -C "$t/pkg" || { echo "cannot unpack $pkg"; exit 2; }
# run <dir> [VAR=value...]: install.sh from an unpacked copy, as Claude starts it.
run() {
  local dir=$1; shift
  OUT="$(cd "$dir" && env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin COWORK_VM_ARCH="$arch" COWORK_EDR_INTEGRATION_ARGS="$ARGS" "$@" bash ./install.sh 2>&1)"
  RC=$?; LAST="$(tail -n 1 <<< "$OUT")"
}
copy() { rm -rf "${t:?}/$1"; cp -a "$t/pkg" "$t/$1"; }
as_acct() { setpriv --reuid="$A" --regid="$A" --init-groups -- "$@"; }
mode() { stat -c %a "$1"; }
# install.sh HELPER_CAPS as a /proc/<pid>/status mask: CAP_CHOWN (0),
# CAP_DAC_READ_SEARCH (2), CAP_NET_ADMIN (12), CAP_NET_RAW (13),
# CAP_SYS_PTRACE (19), CAP_SYS_ADMIN (21).
HELPER_CAPMASK=0000000000283005 NO_CAPS=0000000000000000
cap() { awk -v k="$2:" '$1 == k { print $2 }' "/proc/$1/status" 2> /dev/null; }
caps_check() { # caps_check <how> <helper pid> <gateway pid>
  local h=$1 hp=$2 gp=$3
  if [ "$(cap "$hp" CapBnd)" = "$HELPER_CAPMASK" ] && [ "$(cap "$hp" CapEff)" = "$HELPER_CAPMASK" ] && [ "$(cap "$hp" CapAmb)" = "$NO_CAPS" ] &&
      [ "$(cap "$hp" NoNewPrivs)" = 1 ]; then
    ok "$h: the helper holds only its six capabilities (CapBnd = CapEff = $HELPER_CAPMASK), no_new_privs"
  else bad "$h: helper pid $hp CapBnd $(cap "$hp" CapBnd) CapEff $(cap "$hp" CapEff) CapAmb $(cap "$hp" CapAmb) NoNewPrivs $(cap "$hp" NoNewPrivs), want $HELPER_CAPMASK and 1"; fi
  if [ "$(cap "$gp" CapBnd)" = "$NO_CAPS" ] && [ "$(cap "$gp" CapEff)" = "$NO_CAPS" ] && [ "$(cap "$gp" CapPrm)" = "$NO_CAPS" ]; then
    ok "$h: the gateway holds no capability, bounding set empty"
  else bad "$h: gateway pid $gp CapBnd $(cap "$gp" CapBnd) CapEff $(cap "$gp" CapEff) CapPrm $(cap "$gp" CapPrm)"; fi
}

run "$t/pkg"
if [ "$RC" = 0 ] && [[ "$LAST" == *"sensor up"*"via the root helper"* ]]; then ok "install: $LAST"; else bad "install rc=$RC: $OUT"; fi
[ "$(ps -o uid= -p "$(systemctl show -p MainPID --value defenseclaw-cowork)" | tr -d ' ')" = "$(id -u "$A")" ] &&
  ok "the gateway runs as $A" || bad "the gateway does not run as $A"
caps_check systemd "$(systemctl show -p MainPID --value defenseclaw-cowork-helper)" "$(systemctl show -p MainPID --value defenseclaw-cowork)"
filter="$(systemctl show -p SystemCallFilter --value defenseclaw-cowork-helper)"
if [[ "$filter" == "~"* ]] && [[ " ${filter#\~} " == *" ptrace "* ]] && [[ " $filter " == *" process_vm_readv "* ]] &&
    [[ " $filter " == *" mount "* ]] && [ "$(cap "$(systemctl show -p MainPID --value defenseclaw-cowork-helper)" Seccomp)" = 2 ]; then
  ok "systemd: the helper's syscall filter refuses ptrace, process_vm_readv/writev and @mount (seccomp on)"
else bad "systemd: helper SystemCallFilter '$filter'"; fi
if ! as_acct grep -qx 'policy_dir: /opt/defenseclaw-cowork/policies' /etc/defenseclaw-cowork/config.yaml; then
  bad "config policy_dir is not /opt/defenseclaw-cowork/policies"
elif [ -d "$t/pkg/policies" ]; then
  [ -d /opt/defenseclaw-cowork/policies ] && [ "$(stat -c %U /opt/defenseclaw-cowork/policies)" = root ] &&
    ok "rule packs root-owned under /opt (policy_dir)" || bad "rule packs not root-owned under /opt"
else
  [ ! -e /opt/defenseclaw-cowork/policies ] && ok "no packaged policies: none under /opt, embedded pack (policy_dir set)" ||
    bad "a package without policies left /opt/defenseclaw-cowork/policies"
fi
run "$t/pkg"
[ "$RC" = 0 ] && [[ "$LAST" == *"already running"* ]] && ok "unchanged re-run keeps the sensor" || bad "re-run rc=$RC: $LAST"

if [ -d "$t/pkg/policies" ]; then
  copy nopol; rm -rf "$t/nopol/policies"; run "$t/nopol"
  if [ "$RC" = 0 ] && [[ "$LAST" == *"sensor up"* ]] && [ ! -e /opt/defenseclaw-cowork/policies ]; then ok "startup without packaged policies (embedded pack)"
  else bad "without policies rc=$RC: $LAST"; fi
  run "$t/pkg"; [ "$RC" = 0 ] && [ -d /opt/defenseclaw-cowork/policies ] && ok "startup with packaged policies again" || bad "with policies rc=$RC: $LAST"
else
  echo "note: this package has no policies/; the with-policies case is covered by the release package"
fi

# $DATA/home planted as a link by the account.
before="$(stat -c '%U:%G %a' /etc/systemd/system)"
as_acct sh -c "mv $D/home $D/home.real && ln -s /etc/systemd/system $D/home"
copy changed; echo "# changed" >> "$t/changed/install.sh"; run "$t/changed"
if [ "$RC" = 18 ] && [[ "$LAST" == *"$D/home is a link or not a folder"* ]] && [ "$(stat -c '%U:%G %a' /etc/systemd/system)" = "$before" ]; then
  ok "exit 18 on a \$DATA/home link, target untouched"
else bad "\$DATA/home link: rc=$RC $LAST"; fi
as_acct sh -c "rm $D/home && mv $D/home.real $D/home"

# Links the account plants, followed by a no-systemd start (the path that opens files as root).
install -m 0600 /dev/null /etc/dc-ci-canary-file; echo canary > /etc/dc-ci-canary-file; rm -f /etc/dc-ci-canary-absent
canary_sum="$(sha256sum < /etc/dc-ci-canary-file)"
as_acct ln -sfn /etc/dc-ci-canary-absent "$D/gateway.out"
as_acct ln -sfn /etc/dc-ci-canary-file "$D/policies.new"
# Logs an older run left world-readable: the start must replace them with 0600 files.
install -m 0644 /dev/null "$R/helper.log"; install -m 0644 /dev/null "$R/gateway.log"
copy changed2; echo "# changed 2" >> "$t/changed2/install.sh"; run "$t/changed2" DEFENSECLAW_COWORK_NO_SYSTEMD=1
[ "$RC" = 0 ] && [[ "$LAST" == *"sensor up"* ]] && ok "no-systemd start" || bad "no-systemd start rc=$RC: $OUT"
caps_check no-systemd "$(cat "$R/helper.pid" 2> /dev/null)" "$(cat "$R/gateway.pid" 2> /dev/null)"
[ ! -e /etc/dc-ci-canary-absent ] && ok "a planted gateway.out link is not followed" || bad "root created the gateway.out link target"
[ "$(sha256sum < /etc/dc-ci-canary-file)" = "$canary_sum" ] && [ "$(stat -c '%U %a' /etc/dc-ci-canary-file)" = "root 600" ] &&
  ok "a planted policies.new link is not followed" || bad "the policies.new link target changed"
if [ "$(mode "$R")" = 700 ] && [ "$(mode "$R/helper.log")" = 600 ] && [ "$(mode "$R/gateway.log")" = 600 ]; then
  ok "no-systemd output is root-only ($R 0700, preseeded 0644 logs now 0600)"
else bad "no-systemd output modes: $R $(mode "$R"), helper.log $(mode "$R/helper.log"), gateway.log $(mode "$R/gateway.log")"; fi
as_acct rm -f "$D/gateway.out" "$D/policies.new"
run "$t/pkg"; [ "$RC" = 0 ] && ok "back under systemd" || bad "back under systemd rc=$RC: $LAST"

# A spoofed API listener: another account answers /health on 18970 during the restart.
mkdir -p "$t/spoof"; exec 3<> /dev/tcp/127.0.0.1/18970 && printf 'GET /health HTTP/1.0\r\n\r\n' >&3 && sed '1,/^\r$/d' <&3 > "$t/spoof/health"; exec 3<&-
systemctl stop defenseclaw-cowork defenseclaw-cowork-helper
systemd-run --quiet --unit=dc-cowork-test-spoof --uid=nobody --working-directory="$t/spoof" python3 -m http.server --bind 127.0.0.1 18970
sleep 2
copy changed3; echo "# changed 3" >> "$t/changed3/install.sh"; run "$t/changed3"
if [ "$RC" = 17 ] && [[ "$OUT" != *"sensor up"* ]]; then ok "a spoofed 18970 listener gives exit 17: $LAST"; else bad "spoofed listener: rc=$RC $LAST"; fi
systemctl stop dc-cowork-test-spoof; systemctl reset-failed dc-cowork-test-spoof > /dev/null 2>&1

# A decoy gateway: a second real gateway as $A, with the unit's environment
# (same DEFENSECLAW_HOME), holds 18970. The status CLI accepts it as this
# account's gateway (running=true), so only the started-PID check stops it.
run "$t/pkg"; [ "$RC" = 0 ] && [[ "$LAST" == *"sensor up"* ]] && ok "a normal start after the spoof" || bad "start after the spoof rc=$RC: $LAST"
read -r -a decoy_env <<< "$(systemctl show -p Environment --value defenseclaw-cowork)"
decoy_set=(); for e in "${decoy_env[@]}"; do decoy_set+=(--setenv="$e"); done
systemctl stop defenseclaw-cowork defenseclaw-cowork-helper
systemd-run --quiet --unit=dc-cowork-test-decoy --uid="$A" --gid="$A" "${decoy_set[@]}" /opt/defenseclaw-cowork/bin/defenseclaw-gateway
decoy_pid="" held=0
for _ in $(seq 1 40); do
  decoy_pid="$(systemctl show -p MainPID --value dc-cowork-test-decoy)"
  [ -n "$decoy_pid" ] && [ "$decoy_pid" != 0 ] && ss -ltnpH 'sport = :18970' | grep -q "pid=$decoy_pid," && { held=1; break; }
  sleep 0.5
done
if [ "$held" = 1 ]; then ok "the decoy (PID $decoy_pid) holds 127.0.0.1:18970"; else bad "the decoy does not hold 18970: $(ss -ltnpH 'sport = :18970')"; fi
decoy_running="$(cd / && as_acct env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin "${decoy_env[@]}" /opt/defenseclaw-cowork/bin/defenseclaw-gateway status --json 2> /dev/null |
  python3 -c 'import json, sys; print(json.load(sys.stdin).get("running"))' 2> /dev/null)"
[ "$decoy_running" = True ] && ok "the status CLI accepts the decoy (running=true)" || bad "the status CLI does not accept the decoy (running=$decoy_running)"
copy changed4; echo "# changed 4" >> "$t/changed4/install.sh"; run "$t/changed4"
if [ "$RC" = 17 ] && [[ "$LAST" == *"did not report healthy"* ]] && [[ "$OUT" != *"sensor up"* ]]; then ok "a decoy gateway on 18970 gives exit 17: $LAST"
else bad "decoy gateway: rc=$RC $LAST"; fi
systemctl stop dc-cowork-test-decoy; systemctl reset-failed dc-cowork-test-decoy > /dev/null 2>&1

# A helper that never brokers (no socket): exit 17, and the gateway is never root.
copy nobroker; printf '#!/bin/sh\nexec sleep 600\n' > "$t/nobroker/bin/defenseclaw-sensor-helper"; chmod 0755 "$t/nobroker/bin/defenseclaw-sensor-helper"
run "$t/nobroker"
gw_user="$(ps -o uid= -C defenseclaw-gateway | tr -d ' ' | sort -u | tr '\n' ' ')"
if [ "$RC" = 17 ] && [[ "$LAST" == *"Plane C"* ]] && [[ " $gw_user" != *" 0 "* ]]; then ok "a non-brokering helper gives exit 17, no root gateway: $LAST"
else bad "non-brokering helper: rc=$RC gateway user '$gw_user' $LAST"; fi

# A helper whose Plane C runs on fanotify alone (no netlink, so no cn_proc):
# exit 17 naming the process connector, never "sensor up".
copy nocnproc; sed -i 's/-p RestrictAddressFamilies="AF_UNIX AF_NETLINK AF_PACKET"/-p RestrictAddressFamilies="AF_UNIX AF_PACKET"/' "$t/nocnproc/install.sh"
if grep -q 'RestrictAddressFamilies="AF_UNIX AF_PACKET"' "$t/nocnproc/install.sh"; then
  run "$t/nocnproc"
  if [ "$RC" = 17 ] && [[ "$LAST" == *"cn_proc"* ]] && [[ "$OUT" != *"sensor up"* ]]; then ok "a Plane C without cn_proc gives exit 17: $LAST"
  else bad "Plane C without cn_proc: rc=$RC $LAST"; fi
else bad "could not take AF_NETLINK from the helper unit"; fi

run "$t/pkg"; [ "$RC" = 0 ] && ok "a normal start recovers" || bad "recovery rc=$RC: $LAST"
if [ "$fails" = 0 ]; then echo "all Cowork install.sh root checks passed"; else echo "$fails Cowork install.sh root checks failed"; exit 1; fi
