#!/bin/bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# DefenseClaw sensor for the Claude Cowork VM: install.sh.
#
# Claude Desktop unpacks the signed package into an emptied folder and runs
# this script as root, with no arguments, at every VM start (at most once per
# boot). It installs the sensor out of the unpack folder and starts it in
# detection-only mode:
#   defenseclaw-sensor-helper  root bounded to six capabilities (HELPER_CAPS),
#                              no network (AF_UNIX, AF_NETLINK, AF_PACKET only):
#                              the process table, connections, kernel events
#                              (cn_proc, fanotify) and DNS answers
#   defenseclaw-gateway        the unprivileged system account defenseclaw-cowork,
#                              brokering its runtime planes through the helper
#                              and exporting OTLP to the collector
# Both run in defenseclaw-cowork.slice, which the kernel holds to the Cowork
# sensor budget: 1 CPU core and 800 MB of memory. There is no root-gateway
# mode: the package always ships a gateway and helper from one build.
#
# Root never writes, changes the owner or mode of, or reads through a path
# inside a folder the gateway account owns (/etc/defenseclaw-cowork,
# /var/lib/defenseclaw-cowork): that is done as the account. Binaries, rule
# packs and the CA live in the root-owned /opt/defenseclaw-cowork.
#
# Install arguments (COWORK_EDR_INTEGRATION_ARGS, from the .args file the
# customer's device management writes; not covered by the signature, so
# identifiers only): tenant=<id>,device=<id>,collector=<host>:<port>.
# collector is required; any other key is refused.
#
# Safe to re-run: an unchanged package leaves a healthy sensor running. A run
# that fails before the start step leaves the previous sensor running.
#
# Exit codes (never 200-243, which Claude reserves). The last line of output
# names the problem (Claude shows the last 4 KB in cowork-edr-integration.txt):
#   0   the sensor is running and healthy
#   11  not run as root
#   12  the package architecture does not match the VM (COWORK_VM_ARCH)
#   13  a bad or unknown install argument, or an argument to install.sh
#   14  no collector install argument, or not host:port
#   15  the rendered configuration does not validate
#   16  the sensor could not be started (systemd or the fallback launcher)
#   17  the sensor did not report healthy within 60 s
#   18  the package files, account or folders could not be installed (also
#       any unexpected status in 200-243, which Claude reserves)
set -u
umask 022
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C

PKG_ARCH="@ARCH@"
PKG_VERSION="@VERSION@"
SRC="$(cd "$(dirname "$0")" && pwd)"
DEST=/opt/defenseclaw-cowork
CONF=/etc/defenseclaw-cowork
DATA=/var/lib/defenseclaw-cowork
RUNDIR=/run/defenseclaw-cowork
SOCKDIR=/run/defenseclaw-cowork-sensor
SOCKET="$SOCKDIR/sensor-helper.sock"
ACCOUNT=defenseclaw-cowork
UNIT=defenseclaw-cowork
HELPER_UNIT=defenseclaw-cowork-helper
SLICE=defenseclaw-cowork.slice
API_PORT=18970
HEALTH_WAIT=60

log() { echo "defenseclaw-cowork: $*"; }
fail() { log "FAILED: $1"; exit "$2"; }
# A command that fails in an unexpected way must still not exit 200-243.
trap 'rc=$?; if [ "$rc" -ge 200 ] && [ "$rc" -le 243 ]; then echo "defenseclaw-cowork: FAILED: unexpected status $rc"; exit 18; fi' EXIT

[ "$(id -u)" = 0 ] || fail "install.sh must run as root (Claude runs it as root in the Cowork VM)" 11
[ "$#" = 0 ] || fail "install.sh takes no arguments; put tenant, device and collector in the install arguments file" 13

vmarch="${COWORK_VM_ARCH:-}"
if [ -z "$vmarch" ]; then
  case "$(uname -m)" in x86_64) vmarch=amd64 ;; aarch64) vmarch=arm64 ;; *) vmarch="$(uname -m)" ;; esac
fi
case "$vmarch" in
  amd64 | arm64) ;;
  *) fail "unsupported VM architecture '$vmarch' (this sensor supports amd64 and arm64)" 12 ;;
esac
[ "$vmarch" = "$PKG_ARCH" ] || fail "this package is for $PKG_ARCH but the VM is $vmarch; deliver defenseclaw-cowork-$vmarch.tar.gz" 12

# ---- install arguments: tenant, device, collector only --------------------------------------------
tenant=""; device=""; collector=""; seen=","
args="${COWORK_EDR_INTEGRATION_ARGS:-}"
if [ -n "$args" ]; then
  [[ "$args" =~ ^[A-Za-z0-9][A-Za-z0-9._:=,-]{0,255}$ ]] ||
    fail "the install arguments must be one line of A-Z a-z 0-9 . _ : = , - (at most 256 characters)" 13
  IFS=, read -r -a kvs <<< "$args"
  for kv in "${kvs[@]}"; do
    [[ "$kv" == *=* ]] || fail "install argument '$kv' is not key=value (expected tenant=, device=, collector=)" 13
    k="${kv%%=*}"; v="${kv#*=}"
    case "$k" in
      tenant | device | collector) ;;
      *) fail "unknown install argument '$k' (expected tenant, device, collector; never put secrets in the arguments file)" 13 ;;
    esac
    [[ "$seen" == *",$k,"* ]] && fail "install argument $k is given twice" 13
    seen="$seen$k,"
    [[ "$v" =~ ^[A-Za-z0-9._:-]{1,200}$ ]] || fail "install argument $k has an empty or invalid value" 13
    case "$k" in tenant) tenant="$v" ;; device) device="$v" ;; collector) collector="$v" ;; esac
  done
fi
[ -n "$collector" ] || fail "no collector in the install arguments (collector=host:port); events would have nowhere to go" 14
[[ "$collector" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,252}[A-Za-z0-9])?:([0-9]{1,5})$ ]] ||
  fail "collector must be host:port (got '$collector')" 14
port="${BASH_REMATCH[2]}"
{ [ "$((10#$port))" -ge 1 ] && [ "$((10#$port))" -le 65535 ]; } || fail "collector port must be 1-65535 (got $port)" 14

for f in bin/defenseclaw-gateway bin/defenseclaw-sensor-helper config.yaml.tmpl; do
  [ -f "$SRC/$f" ] && [ ! -L "$SRC/$f" ] || fail "the package is incomplete: $f is missing" 18
done
CA_SRC=""; [ -f "$SRC/collector-ca.pem" ] && CA_SRC="$SRC/collector-ca.pem"

# ---- session homes ------------------------------------------------------------------------------
work="$(mktemp -d /tmp/defenseclaw-cowork.XXXXXX)" || fail "cannot create a temporary folder in /tmp" 18
trap 'rc=$?; rm -rf "$work"; if [ "$rc" -ge 200 ] && [ "$rc" -le 243 ]; then echo "defenseclaw-cowork: FAILED: unexpected status $rc"; exit 18; fi' EXIT
# Every Cowork session is its own Linux user with a home under /sessions (the
# stand-ins and other images use /home). The helper also gets the /home/* and
# /sessions/* patterns, which the sensor re-expands while it runs
# (R108-COWORK-1), so a session created after this run is watched.
getent passwd > "$work/passwd" || fail "cannot list the accounts (getent passwd failed)" 18
homes_yaml=""; homes_csv=""; nhomes=0
while IFS=: read -r _ _ uid _ _ home _; do
  case "$uid" in '' | *[!0-9]*) continue ;; esac
  [ "$uid" -ge 1000 ] && [ "$uid" -lt 60000 ] || continue
  [[ "$home" =~ ^/(home|sessions)/[A-Za-z0-9._-]+$ ]] || continue
  [ -d "$home" ] && [ ! -L "$home" ] || continue
  [ "$nhomes" -lt 4096 ] || break
  homes_yaml="${homes_yaml:+$homes_yaml, }\"$home\""; homes_csv="${homes_csv:+$homes_csv,}$home"; nhomes=$((nhomes + 1))
done < "$work/passwd"
helper_homes="${homes_csv:+$homes_csv,}/home/*,/sessions/*"

# ---- render and validate the configuration before anything is touched ------------------------------
render() { # render <ca path or empty> <output> [data dir, default $DATA]
  sed -e "s|@HOMES@|[${homes_yaml}]|" -e "s|@TENANT@|${tenant:-unset}|" -e "s|@DEVICE@|${device:-unset}|" \
    -e "s|@VM_ARCH@|$vmarch|" -e "s|@COLLECTOR@|$collector|" -e "s|@SENSOR_VERSION@|$PKG_VERSION|" -e "s|@DATA@|${3:-$DATA}|" \
    -e "s|@POLICY_DIR@|$DEST/policies|" -e "s|@PORT@|$API_PORT|" "$SRC/config.yaml.tmpl" |
    if [ -n "$1" ]; then sed -e "s|@CA_CERT@|$1|"; else sed -e '/@CA_CERT@/d'; fi > "$2"
}
# Validated with data_dir under $work, so this root process never loads
# anything from the account-writable data folder (for example its .env).
mkdir -p "$work/home" "$work/data" && render "$CA_SRC" "$work/config.yaml" "$work/data" || fail "cannot render the configuration" 18
if ! DEFENSECLAW_HOME="$work" HOME="$work/home" "$SRC/bin/defenseclaw-gateway" config validate --config "$work/config.yaml" > "$work/validate.log" 2>&1; then
  tail -n 5 "$work/validate.log"
  fail "the rendered configuration does not validate (install arguments: collector=$collector)" 15
fi

# ---- the account and its folders ----------------------------------------------------------------
if ! getent passwd "$ACCOUNT" > /dev/null; then
  useradd --system --user-group --no-create-home --home-dir "$DATA" --shell /usr/sbin/nologin \
    --comment "DefenseClaw Cowork VM sensor" "$ACCOUNT" > "$work/useradd.log" 2>&1 ||
    { tail -n 3 "$work/useradd.log"; fail "cannot create the system account $ACCOUNT" 18; }
fi
acct_uid="$(id -u "$ACCOUNT")" && acct_gid="$(id -g "$ACCOUNT")" || fail "cannot resolve the account $ACCOUNT" 18
[ "$acct_uid" -lt 1000 ] && [ "$acct_uid" != 0 ] || fail "the account $ACCOUNT exists with uid $acct_uid; it must be a system account" 18
# Runs a command as the gateway account, with no privilege to regain.
as_acct() { setpriv --reuid="$acct_uid" --regid="$acct_gid" --init-groups --no-new-privs --inh-caps=-all --bounding-set=-all -- "$@"; }

# /etc/defenseclaw-cowork and /var/lib/defenseclaw-cowork sit in root-owned
# folders, so only root can replace them. One that is not a real folder owned
# by the account (left by an earlier build, or a link) is moved aside, never
# changed in place.
account_folder() { # account_folder <path>
  local d=$1 owner
  if [ -L "$d" ] || { [ -e "$d" ] && [ ! -d "$d" ]; }; then
    owner=x
  elif [ -d "$d" ]; then
    owner="$(stat -c %u "$d")" || fail "cannot read $d" 18
  else
    owner=""
  fi
  if [ -n "$owner" ] && [ "$owner" != "$acct_uid" ]; then
    mv -T "$d" "$d.stale-$(date +%s)" || fail "cannot move aside $d (not a folder owned by $ACCOUNT)" 18
    log "warning: moved aside $d: it was not a folder owned by $ACCOUNT"
    owner=""
  fi
  if [ -z "$owner" ]; then
    mkdir -m 0700 "$d" && chown -h "$ACCOUNT:$ACCOUNT" "$d" || fail "cannot create $d" 18
  fi
  as_acct chmod 0700 "$d" || fail "cannot set the mode of $d" 18
}
account_folder "$CONF"
account_folder "$DATA"
# The gateway's HOME, inside the account's own folder: only checked (lstat)
# and created by the account; root never follows a link the account planted.
if [ -L "$DATA/home" ] || { [ -e "$DATA/home" ] && [ ! -d "$DATA/home" ]; }; then
  fail "$DATA/home is a link or not a folder; the sensor refuses to use it" 18
fi
[ -d "$DATA/home" ] || as_acct mkdir -m 0700 "$DATA/home" || fail "cannot create $DATA/home" 18

# ---- binaries, rule packs and config ----------------------------------------------------------------
changed=0
install -d -o root -g root -m 0755 "$DEST" "$DEST/bin" || fail "cannot create $DEST" 18
# Root only: pids, the fingerprint and, without systemd, the sensor output.
install -d -o root -g root -m 0700 "$RUNDIR" || fail "cannot create $RUNDIR" 18
copy_if_changed() { # copy_if_changed <src> <dest> <mode>
  if ! cmp -s "$1" "$2"; then
    install -o root -g root -m "$3" "$1" "$2.new" && mv -f "$2.new" "$2" || fail "cannot install $2" 18
    changed=1
  fi
}
copy_if_changed "$SRC/bin/defenseclaw-gateway" "$DEST/bin/defenseclaw-gateway" 0755
copy_if_changed "$SRC/bin/defenseclaw-sensor-helper" "$DEST/bin/defenseclaw-sensor-helper" 0755
if [ -n "$CA_SRC" ]; then
  copy_if_changed "$CA_SRC" "$DEST/collector-ca.pem" 0644
elif [ -e "$DEST/collector-ca.pem" ]; then
  rm -f "$DEST/collector-ca.pem" || fail "cannot remove $DEST/collector-ca.pem" 18
  changed=1
fi
# Rule packs, root-owned under /opt (config policy_dir), until the gateway
# starts without them (R108-COWORK-4); a package without policies/ removes them.
if [ -d "$SRC/policies" ]; then
  if ! diff -rq "$SRC/policies" "$DEST/policies" > /dev/null 2>&1; then
    rm -rf "$DEST/policies.new" && cp -R "$SRC/policies" "$DEST/policies.new" &&
      chown -R root:root "$DEST/policies.new" && chmod -R u=rwX,go=rX "$DEST/policies.new" &&
      rm -rf "$DEST/policies" && mv -T "$DEST/policies.new" "$DEST/policies" || fail "cannot install the rule packs" 18
    changed=1
  fi
elif [ -e "$DEST/policies" ]; then
  rm -rf "$DEST/policies" || fail "cannot remove $DEST/policies" 18
  changed=1
fi
render "${CA_SRC:+$DEST/collector-ca.pem}" "$work/config.final" || fail "cannot render the configuration" 18
# The config is compared and written as the account, inside its own folder.
if ! as_acct cat "$CONF/config.yaml" 2> /dev/null | cmp -s - "$work/config.final"; then
  as_acct sh -c 'umask 077; cat > "$1.new" && mv -f "$1.new" "$1"' sh "$CONF/config.yaml" < "$work/config.final" ||
    fail "cannot write $CONF/config.yaml" 18
  changed=1
fi
{ printf '%s\n' "$PKG_VERSION" > "$DEST/VERSION.new" && mv -f "$DEST/VERSION.new" "$DEST/VERSION"; } ||
  fail "cannot write $DEST/VERSION" 18

# What the running sensor was started with; /run is empty after every boot.
helper_cmd=("$DEST/bin/defenseclaw-sensor-helper" --socket "$SOCKET" --service-account "$ACCOUNT" --home-dirs "$helper_homes")
# GOMEMLIMIT holds the root helper's Go heap well inside its MemoryMax=300M:
# near 200 MiB the runtime collects harder instead of letting garbage from a
# large discovery read reach the cgroup limit (cowork-1-0-8 GAP-0008). Set on
# the command, so the systemd unit and the start without systemd both get it.
helper_cmd=(/usr/bin/env GOMEMLIMIT=200MiB "${helper_cmd[@]}")
gw_env=("DEFENSECLAW_HOME=$CONF" "HOME=$DATA/home" "DEFENSECLAW_SENSOR_HELPER_SOCKET=$SOCKET")
# install.sh itself is in it: the unit settings live here.
self_digest="$(sha256sum < "$SRC/install.sh" | cut -d' ' -f1)"
fingerprint() { printf '%s\n' "$PKG_VERSION" "$self_digest" "${helper_cmd[*]}" "${gw_env[*]}" | sha256sum | cut -d' ' -f1; }

# ---- start ------------------------------------------------------------------------------------------
use_systemd=0
[ -d /run/systemd/system ] && [ "${DEFENSECLAW_COWORK_NO_SYSTEMD:-}" != 1 ] && use_systemd=1

pid_alive() { # pid_alive <pidfile> <binary>: also a binary replaced since it started ("(deleted)")
  local pid exe; pid="$(cat "$1" 2> /dev/null)" || return 1
  case "$pid" in '' | *[!0-9]*) return 1 ;; esac
  exe="$(readlink "/proc/$pid/exe" 2> /dev/null)" || return 1
  [ "$exe" = "$2" ] || [ "$exe" = "$2 (deleted)" ]
}
stop_sensor() {
  rm -f "$RUNDIR/fingerprint"
  # Units from an earlier run, even when this run launches without systemd.
  if [ -d /run/systemd/system ]; then
    systemctl stop "$UNIT" "$HELPER_UNIT" > /dev/null 2>&1
    systemctl reset-failed "$UNIT" "$HELPER_UNIT" > /dev/null 2>&1
  fi
  local f b pid
  for f in gateway helper; do
    b="$DEST/bin/defenseclaw-$([ "$f" = gateway ] && echo gateway || echo sensor-helper)"
    if pid_alive "$RUNDIR/$f.pid" "$b"; then
      pid="$(cat "$RUNDIR/$f.pid")"; kill "$pid" 2> /dev/null
      for _ in 1 2 3 4 5 6 7 8 9 10; do [ -d "/proc/$pid" ] || break; sleep 0.5; done
      [ -d "/proc/$pid" ] && kill -9 "$pid" 2> /dev/null
    fi
    rm -f "$RUNDIR/$f.pid"
  done
}
running() {
  if [ "$use_systemd" = 1 ]; then
    systemctl is-active --quiet "$UNIT" && systemctl is-active --quiet "$HELPER_UNIT"
  else
    pid_alive "$RUNDIR/gateway.pid" "$DEST/bin/defenseclaw-gateway" &&
      pid_alive "$RUNDIR/helper.pid" "$DEST/bin/defenseclaw-sensor-helper"
  fi
}
gateway_pid() {
  if [ "$use_systemd" = 1 ]; then systemctl show -p MainPID --value "$UNIT" 2> /dev/null; else cat "$RUNDIR/gateway.pid" 2> /dev/null; fi
}

# The helper's whole privilege: root, held to these capabilities by its
# bounding set (systemd CapabilityBoundingSet=, setpriv --bounding-set without
# systemd), so it never holds CAP_DAC_OVERRIDE, CAP_SETUID, CAP_SYS_MODULE or
# the rest. It stays uid 0 rather than a dedicated user with ambient
# capabilities: the socket it publishes and the peer checks it makes are
# root's. Each one was taken out in turn on the amd64 and arm64 stand-ins
# (R109-COWORK-S3), and what is named here stopped working without it:
#   CAP_NET_ADMIN        the cn_proc socket's 4 MiB receive buffer (SO_RCVBUFFORCE;
#                        without it net.core.rmem_max caps it near 416 KiB and an
#                        exec burst overflows it), and joining cn_proc at all on
#                        kernels before 6.6 (Plane C)
#   CAP_SYS_ADMIN        fanotify_init for the credential-path watch (Plane C)
#   CAP_NET_RAW          the AF_PACKET socket of the DNS capture (Plane B)
#   CAP_SYS_PTRACE       /proc/<pid>/fd and /proc/<pid>/exe of the session users'
#                        processes: connection owners (Plane B), the image a
#                        client exec runs and its digest (Plane C)
#   CAP_DAC_READ_SEARCH  the session homes (0750) and other users' /proc/<pid>/fd
#                        folders: the credential paths fanotify marks, the
#                        installed client images it hashes, connection owners
#   CAP_CHOWN            the socket and its folder go to the gateway's group
# The bound limits what a faulty helper can do, not what a compromised one can:
# uid 0 with CAP_SYS_PTRACE and CAP_SYS_ADMIN is still close to root. Under
# systemd, HELPER_SYSCALLS also refuses the calls it never makes and an
# attacker would want first: ptrace and the cross-process memory calls (its
# /proc reads need only the ptrace access check, not the call) and mounts.
# The no-systemd fallback cannot carry that filter.
HELPER_CAPS="CAP_NET_ADMIN CAP_SYS_ADMIN CAP_NET_RAW CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_CHOWN"
HELPER_SYSCALLS="~ptrace process_vm_readv process_vm_writev @mount"
helper_bset="-all"; for c in $HELPER_CAPS; do c="${c#CAP_}"; helper_bset="$helper_bset,+${c,,}"; done
# Unit hardening both processes get. Each directive was checked on the stand-ins
# with every plane up. Left out: MemoryDenyWriteExecute (bytedance/sonic, which
# both binaries link, maps executable memory at start on amd64 and the process
# panics) and ProtectProc/ProcSubset (the helper reads every process's /proc).
HARDEN=(-p NoNewPrivileges=yes -p PrivateTmp=yes -p ProtectHome=read-only -p ProtectKernelModules=yes
  -p ProtectKernelTunables=yes -p ProtectKernelLogs=yes -p ProtectControlGroups=yes -p ProtectClock=yes
  -p ProtectHostname=yes -p LockPersonality=yes -p RestrictRealtime=yes -p RestrictSUIDSGID=yes
  -p SystemCallArchitectures=native)

# The Cowork sensor budget for both processes, enforced by the kernel.
slice_unit() {
  printf '%s\n' "[Unit]" "Description=DefenseClaw Cowork VM sensor (1 CPU core, 800 MB)" "" "[Slice]" \
    "CPUAccounting=yes" "CPUQuota=100%" "MemoryAccounting=yes" "MemoryHigh=700M" "MemoryMax=800M" "TasksMax=512"
}
start_systemd() {
  slice_unit > "$work/slice"
  if ! cmp -s "$work/slice" "/run/systemd/system/$SLICE"; then
    install -m 0644 "$work/slice" "/run/systemd/system/$SLICE" && systemctl daemon-reload ||
      fail "systemd could not load $SLICE" 16
  fi
  systemd-run --quiet --unit="$HELPER_UNIT" --slice="$SLICE" \
    --description="DefenseClaw Cowork VM sensor helper (root, no network)" \
    -p SyslogIdentifier=defenseclaw-sensor-helper \
    -p Restart=always -p RestartSec=2 -p CapabilityBoundingSet="$HELPER_CAPS" -p AmbientCapabilities= \
    -p RestrictAddressFamilies="AF_UNIX AF_NETLINK AF_PACKET" -p IPAddressDeny=any -p RestrictNamespaces=yes \
    -p SystemCallFilter="$HELPER_SYSCALLS" \
    -p ProtectSystem=full "${HARDEN[@]}" -p MemoryMax=300M \
    "${helper_cmd[@]}" > "$work/start.log" 2>&1 ||
    { tail -n 3 "$work/start.log"; fail "systemd could not start $HELPER_UNIT" 16; }
  for _ in $(seq 1 40); do [ -S "$SOCKET" ] && break; sleep 0.25; done
  local e envs=()
  for e in "${gw_env[@]}"; do envs+=(--setenv="$e"); done
  systemd-run --quiet --unit="$UNIT" --slice="$SLICE" \
    --description="DefenseClaw Cowork VM sensor (detection only)" -p User="$ACCOUNT" -p Group="$ACCOUNT" "${envs[@]}" \
    -p Restart=always -p RestartSec=2 -p CapabilityBoundingSet= -p AmbientCapabilities= \
    -p ProtectSystem=strict -p ReadWritePaths="$CONF $DATA" "${HARDEN[@]}" -p RestrictNamespaces="user pid" \
    "$DEST/bin/defenseclaw-gateway" > "$work/start.log" 2>&1 ||
    { tail -n 3 "$work/start.log"; fail "systemd could not start $UNIT" 16; }
}
# Without systemd: detached processes, held to the budget by a cgroup v2
# group when the kernel offers one. Their output goes to the root-owned
# /run/defenseclaw-cowork, opened by root before the gateway drops privilege.
CG=/sys/fs/cgroup/defenseclaw-cowork
start_detached() {
  local limited=0 pid
  if [ -f /sys/fs/cgroup/cgroup.controllers ] && mkdir -p "$CG" 2> /dev/null; then
    echo "+cpu +memory" > /sys/fs/cgroup/cgroup.subtree_control 2> /dev/null
    { echo 734003200 > "$CG/memory.high" && echo 838860800 > "$CG/memory.max" &&
      echo "100000 100000" > "$CG/cpu.max"; } 2> /dev/null && limited=1
  fi
  [ "$limited" = 1 ] || log "warning: no cgroup v2 here, so the 1 CPU / 800 MB budget is not enforced by the kernel"
  enter_cg() { [ "$limited" = 1 ] && echo "$BASHPID" > "$CG/cgroup.procs"; }
  # New files each start, created 0600 (an older run left them 0644). The
  # umask 077 below also reaches both processes, where systemd gives them
  # 0022; that is harmless, because the socket and every folder they create
  # get their modes from an explicit chmod.
  rm -f "$RUNDIR/helper.log" "$RUNDIR/gateway.log"
  ( umask 077; enter_cg; exec setsid setpriv --bounding-set="$helper_bset" --inh-caps=-all --no-new-privs \
      "${helper_cmd[@]}" > "$RUNDIR/helper.log" 2>&1 < /dev/null ) &
  echo $! > "$RUNDIR/helper.pid"
  for _ in $(seq 1 40); do [ -S "$SOCKET" ] && break; sleep 0.25; done
  ( umask 077; enter_cg; cd /; exec setsid env -i PATH="$PATH" "${gw_env[@]}" setpriv --reuid="$acct_uid" --regid="$acct_gid" \
      --init-groups --no-new-privs --inh-caps=-all --bounding-set=-all \
      "$DEST/bin/defenseclaw-gateway" > "$RUNDIR/gateway.log" 2>&1 < /dev/null ) &
  echo $! > "$RUNDIR/gateway.pid"
  # Until each pid runs its own binary: right after the fork it can still be
  # setsid or setpriv, more so on a loaded VM. About 2 s.
  for _ in $(seq 1 8); do
    sleep 0.25
    pid_alive "$RUNDIR/helper.pid" "$DEST/bin/defenseclaw-sensor-helper" &&
      pid_alive "$RUNDIR/gateway.pid" "$DEST/bin/defenseclaw-gateway" && break
  done
  pid_alive "$RUNDIR/helper.pid" "$DEST/bin/defenseclaw-sensor-helper" || { tail -n 3 "$RUNDIR/helper.log"; fail "the sensor helper exited at start" 16; }
  pid_alive "$RUNDIR/gateway.pid" "$DEST/bin/defenseclaw-gateway" || { tail -n 6 "$RUNDIR/gateway.log"; fail "the sensor gateway exited at start" 16; }
  if [ "$limited" = 1 ]; then
    for pid in "$(cat "$RUNDIR/helper.pid")" "$(cat "$RUNDIR/gateway.pid")"; do
      grep -qx '0::/defenseclaw-cowork' "/proc/$pid/cgroup" 2> /dev/null ||
        fail "process $pid did not enter the budget cgroup $CG" 16
    done
  fi
}
start_sensor() { if [ "$use_systemd" = 1 ]; then start_systemd; else start_detached; fi; }

# ---- health: the started gateway's own status, no curl ------------------------------------------
# One field of `defenseclaw-gateway status --json` (indented JSON, one member
# per line), by its dotted path: a structural read, not a text search.
json_field() { # json_field <dotted path> < status.json
  awk -v want="$1" '
    { line = $0; sub(/^[ \t]+/, "", line); key = ""; rest = line
      if (match(line, /^"[^"]*": /)) { key = substr(line, 2, RLENGTH - 4); rest = substr(line, RLENGTH + 1) }
      if (rest ~ /^[{[]$/) { stack[++n] = key; next }
      if (rest ~ /^[]}],?$/) { n--; next }
      if (key == "") next
      path = ""; for (i = 1; i <= n; i++) if (stack[i] != "") path = path stack[i] "."
      if (path key == want) { sub(/,$/, "", rest); print rest; exit } }'
}
# The 127.0.0.1 API listener belongs to the gateway this run started, not to
# another process holding the port.
listener_is() { # listener_is <pid>
  local pid=$1 hexport inode fd
  case "$pid" in '' | 0 | *[!0-9]*) return 1 ;; esac
  printf -v hexport '%04X' "$API_PORT"
  inode="$(awk -v a="0100007F:$hexport" '$2 == a && $4 == "0A" { print $10; exit }' /proc/net/tcp)"
  [ -n "$inode" ] || return 1
  for fd in /proc/"$pid"/fd/*; do
    [ "$(readlink "$fd" 2> /dev/null)" = "socket:[$inode]" ] && return 0
  done
  return 1
}
HEALTH_REASON=""
# wait_healthy <seconds>: 0 when the started gateway answers its status and
# Plane C runs the process connector (cn_proc) through the sensor helper; 1
# when it answers but Plane C does not (after PLANE_GRACE seconds), including a
# Plane C on fanotify alone, which has no exec, exit or privilege events; 2
# when it never answers.
PLANE_GRACE=20
wait_healthy() {
  local deadline=$((SECONDS + $1)) up_at="" pid
  while [ "$SECONDS" -lt "$deadline" ]; do
    pid="$(gateway_pid)"
    if timeout 10 env -i PATH="$PATH" "${gw_env[@]}" setpriv --reuid="$acct_uid" --regid="$acct_gid" --init-groups \
        "$DEST/bin/defenseclaw-gateway" status --json > "$work/status.json" 2> /dev/null &&
        [ "$(json_field running < "$work/status.json")" = true ] && listener_is "$pid"; then
      [ -n "$up_at" ] || up_at=$SECONDS
      if [ "$(json_field health.ai_runtime.details.planes.c.running < "$work/status.json")" = true ] &&
          [[ "$(json_field health.ai_runtime.details.planes.c.mechanism < "$work/status.json")" == *"cn_proc"*"(via the sensor helper)"* ]]; then
        HEALTH_SECONDS=$((SECONDS - START_SECONDS)); return 0
      fi
      HEALTH_REASON="$(json_field health.ai_runtime.details.planes.c.reason < "$work/status.json")"
      [ $((SECONDS - up_at)) -ge "$PLANE_GRACE" ] && return 1
    fi
    sleep 1
  done
  [ -n "$up_at" ] && return 1
  return 2
}

fp="$(fingerprint)"
HEALTH_SECONDS=0; START_SECONDS=$SECONDS
if running && [ "$(cat "$RUNDIR/fingerprint" 2> /dev/null)" = "$fp" ] && [ "$changed" = 0 ]; then
  if wait_healthy 15; then
    log "already running $PKG_VERSION, nothing changed"
    exit 0
  fi
  log "the running sensor is not healthy; restarting it"
fi
stop_sensor
start_sensor
START_SECONDS=$SECONDS
wait_healthy "$HEALTH_WAIT"; rc=$?
if [ "$rc" != 0 ]; then
  if [ "$use_systemd" = 1 ]; then
    journalctl -u "$UNIT" -u "$HELPER_UNIT" -n 12 --no-pager -o cat 2> /dev/null | tail -n 12
  else
    tail -n 6 "$RUNDIR/helper.log" "$RUNDIR/gateway.log" 2> /dev/null
  fi
  [ "$rc" = 1 ] && fail "the sensor answers but its kernel event plane (Plane C) is not running the process connector (cn_proc) through the sensor helper${HEALTH_REASON:+: $HEALTH_REASON}" 17
  fail "the sensor gateway did not report healthy on 127.0.0.1:$API_PORT within $HEALTH_WAIT s" 17
fi
fingerprint > "$RUNDIR/fingerprint" || fail "cannot write $RUNDIR/fingerprint" 18
log "sensor up ($PKG_VERSION, $vmarch, device ${device:-unset}, gateway as $ACCOUNT via the root helper) after ${HEALTH_SECONDS}s"
exit 0
