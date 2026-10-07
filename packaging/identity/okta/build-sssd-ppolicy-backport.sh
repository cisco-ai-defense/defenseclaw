#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# build-sssd-ppolicy-backport.sh - build RHEL 9's own SSSD 2.9.8 source
# package with the ldap_use_ppolicy option backported, so SSSD can bind to the
# Okta LDAP Interface.
#
# Why: Okta answers SSSD's password-policy request control with a response
# control that has no value. SSSD 2.9 cannot parse it and fails the bind, so
# no Okta user resolves (`getent passwd` finds nothing, `sssctl domain-status`
# says Offline). SSSD 2.10 and later have the option ldap_use_ppolicy; RHEL 9
# ships 2.9. This script applies the same change to RHEL's source package.
#
# It is pinned to sssd-2.9.8-4.el9_8.1. backport-ppolicy.py matches exact text
# and stops with the first text it does not find on any other source package.
# It only builds: it installs nothing. The packages it builds are a local fork
# of a Red Hat package: Red Hat does not support them, and you own the rebuild
# for every later SSSD security update. The commands to install them are
# printed at the end.
#
# Run as a normal user with sudo (dnf needs it); about 15 minutes on 2 vCPUs.
# Exit codes: 0 built, 1 a step failed, 2 bad arguments, 3 unsupported host.

set -euo pipefail

SELF=$(basename "$0")
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
NVR=sssd-2.9.8-4.el9_8.1
WORK="$HOME/sssd-ppolicy-build"
DRY_RUN=0

usage() {
  cat << USAGE
Usage: $SELF [--workdir DIR] [--nvr NAME-VERSION-RELEASE] [--dry-run]

Build $NVR with the ldap_use_ppolicy backport. Builds only; installs nothing.

  --workdir DIR   Build folder (default \$HOME/sssd-ppolicy-build)
  --nvr NVR       Source package to rebuild (default $NVR). Only that
                  release is supported.
  --dry-run       Print the steps and change nothing
  -h, --help      Show this help

Run as a normal user with sudo. Needs about 5 GB free in the work folder.
USAGE
}

log() { printf '== %s %s\n' "$(date -u +%H:%M:%S)" "$*"; }
fail() {
  local rc=$1
  shift
  printf '%s: error: %s\n' "$SELF" "$*" >&2
  exit "$rc"
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --workdir) [[ $# -ge 2 && -n $2 ]] || fail 2 "--workdir needs a value"; WORK=$2; shift 2 ;;
    --nvr) [[ $# -ge 2 && -n $2 ]] || fail 2 "--nvr needs a value"; NVR=$2; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) usage >&2; fail 2 "unknown option: $1" ;;
  esac
done
[[ $WORK == /* ]] || fail 2 "--workdir must be an absolute path"
[[ $NVR =~ ^sssd-[0-9][A-Za-z0-9._]*-[0-9][A-Za-z0-9._]*$ ]] || fail 2 "--nvr must look like sssd-2.9.8-4.el9_8.1"
[[ $NVR == sssd-2.9.8-4.el9_8.1 ]] ||
  fail 3 "only sssd-2.9.8-4.el9_8.1 is supported ($NVR was asked). backport-ppolicy.py matches exact source text of that package."

[[ -r /etc/os-release ]] || fail 3 "no /etc/os-release"
# shellcheck disable=SC1091
. /etc/os-release
[[ ${VERSION_ID:-} == 9* && " ${ID:-} ${ID_LIKE:-} " == *" rhel "* ]] ||
  fail 3 "this recipe is for RHEL 9 (and its rebuilds); this host is ${PRETTY_NAME:-unknown}"
((EUID != 0)) || fail 3 "run as a normal user with sudo: rpmbuild must not run as root"
command -v sudo > /dev/null || fail 3 "sudo is required for dnf"

T="$WORK/rpmbuild"
SPEC="$T/SPECS/sssd.spec"

if ((DRY_RUN)); then
  cat << PLAN
Dry run: nothing will be changed. The steps would be:
  1. sudo dnf install rpm-build gcc dnf-plugins-core
  2. download $NVR.src.rpm into $WORK
  3. unpack it into $T and install its build dependencies
  4. unpack the sources with RHEL's own patches, copy the tree, run $HERE/backport-ppolicy.py in the copy,
     and save the difference as $T/SOURCES/9001-ppolicy-backport.patch
  5. add that patch to the spec and append .okta1 to the release
  6. rpmbuild -bb --nocheck, leaving the packages in $T/RPMS
PLAN
  exit 0
fi

mkdir -p "$WORK"
log "tools"
sudo dnf -y -q install rpm-build gcc dnf-plugins-core

log "source package $NVR"
if [[ ! -f "$WORK/$NVR.src.rpm" ]]; then
  sudo dnf -q download --source --disableexcludes=all --enablerepo='*-source-rpms' --destdir "$WORK" "$NVR"
  sudo chown "$(id -u):$(id -g)" "$WORK/$NVR.src.rpm"
fi
[[ $(rpm -qp --qf '%{NAME}-%{VERSION}-%{RELEASE}' "$WORK/$NVR.src.rpm") == "$NVR" ]] ||
  fail 1 "the downloaded source package is not $NVR"

log "unpack and build dependencies"
rm -rf "$T"
rpm -i --define "_topdir $T" "$WORK/$NVR.src.rpm" 2>&1 | grep -v -E 'warning: (user|group) ' || true
[[ -f $SPEC ]] || fail 1 "the source package has no sssd.spec"
sudo dnf -y -q builddep --disableexcludes=all --enablerepo='codeready-builder-*' "$SPEC"

log "prepare the sources with RHEL's own patches"
rpmbuild --define "_topdir $T" -bp "$SPEC" > "$WORK/prep.log" 2>&1 || { tail -30 "$WORK/prep.log"; fail 1 "rpmbuild -bp failed"; }
SRC=$(find "$T/BUILD" -mindepth 1 -maxdepth 1 -type d -name 'sssd-*' | head -1)
[[ -n $SRC ]] || fail 1 "no sssd source tree under $T/BUILD"
rm -rf "$SRC.orig"
cp -a "$SRC" "$SRC.orig"

log "apply the backport"
(cd "$SRC" && python3 "$HERE/backport-ppolicy.py") || fail 1 "backport-ppolicy.py stopped: this is not the expected source"
# diff exits 1 when the trees differ, which is the expected case.
(cd "$T/BUILD" && diff -ruN "$(basename "$SRC").orig" "$(basename "$SRC")" > "$T/SOURCES/9001-ppolicy-backport.patch") || [[ $? -eq 1 ]]
grep -q 'ldap_use_ppolicy' "$T/SOURCES/9001-ppolicy-backport.patch" || fail 1 "the saved patch does not mention ldap_use_ppolicy"

log "add the patch to the spec"
last=$(grep -n -E '^Patch[0-9]+:' "$SPEC" | tail -1 | cut -d: -f1 || true)
[[ -n $last ]] || fail 1 "the spec lists no patches; unexpected source package"
sed -i "${last}a Patch9001: 9001-ppolicy-backport.patch" "$SPEC"
sed -i -E 's/^(Release:[[:space:]]*)(.*)$/\1\2.okta1/' "$SPEC"
grep -n -E '^(Release|Patch9001):' "$SPEC"

log "build (about 15 minutes)"
rpmbuild --define "_topdir $T" -bb --nocheck "$SPEC" > "$WORK/build.log" 2>&1 ||
  { grep -v mock "$WORK/build.log" | tail -40; fail 1 "rpmbuild -bb failed; the full log is $WORK/build.log"; }

log "built"
find "$T/RPMS" -name '*.rpm' -not -name '*debuginfo*' -not -name '*debugsource*' -not -name '*-devel-*' | sort
cat << NEXT

Nothing was installed. To use the packages on this host, as root:
  1. Install the ones that match what is installed (same names), newer than the stock build:
       rpm -Uvh --oldpackage \$(for p in \$(rpm -qa 'sssd*' 'libsss_*' 'python3-sss*' 'libipa_hbac*' 'python3-libipa_hbac*'); do
         ls $T/RPMS/*/"\$(rpm -q --qf '%{NAME}' "\$p")"-2.9.8-4.el9.1.okta1.*.rpm; done)
     (--oldpackage is needed because a local build has dist .el9, which sorts below .el9_8.1.)
  2. Keep dnf from putting the stock build back, in /etc/dnf/dnf.conf:
       excludepkgs=sssd* libsss_* python3-sss* python3-sssdconfig libipa_hbac* python3-libipa_hbac python3-libsss_nss_idmap
  3. systemctl restart sssd, then check: grep ldap_use_ppolicy /usr/share/sssd/cfg_rules.ini
NEXT
