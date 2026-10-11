#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# join-entra-domain-services.sh - join a Linux host to a Microsoft Entra Domain
# Services managed domain with realmd and SSSD, so the host sees Entra users and
# their Entra groups as Active Directory accounts.
#
# DefenseClaw never calls Entra ID. Entra Domain Services syncs the tenant's
# users and groups into a managed Active Directory domain; SSSD (id_provider =
# ad) reads it, and DefenseClaw reads the accounts and groups NSS reports
# (directory active_directory). The managed domain itself is created in Azure
# first; see README.md for the prerequisites and the cost.
#
# It changes the host, so it only PRINTS the plan unless you pass --apply.
#
# Usage:
#   join-entra-domain-services.sh join  --domain DOMAIN --admin UPN [--short-names] [--apply]
#   join-entra-domain-services.sh names short|qualified [--apply]
#   join-entra-domain-services.sh flush [--apply]
#   join-entra-domain-services.sh check [--user NAME] [--group NAME]
#
# Commands:
#   join        install realmd, SSSD and adcli, discover the domain and join it
#               (realm join asks for the admin password on the terminal)
#   names       short: set use_fully_qualified_names = False, so accounts and
#               groups are named alice and ml-team instead of alice@DOMAIN and
#               ml-team@DOMAIN; qualified: set it back to True (the realm join
#               default). Restarts SSSD and clears its cache.
#   flush       clear the SSSD cache (sss_cache -E), so a group change in Entra
#               shows before SSSD's entry_cache_timeout (90 minutes by default)
#   check       read-only: the realm, the SSSD naming, and id/getent answers
#
# Options:
#   --domain DOMAIN   the managed domain's DNS name
#   --admin UPN       a member of "AAD DC Administrators" who may join computers
#   --short-names     join: set short names right after the join
#   --user NAME       check: the account to show
#   --group NAME      check: the group to look up
#   --apply           make the changes; without it the script only prints them
#   --dry-run         print the plan (the default)
#   -h, --help        show this help
#
# Exit codes: 0 success or a complete plan, 1 a step failed, 2 bad usage.
# Tested on RHEL 9.8 (dnf). The apt package list is untested. See README.md.

set -euo pipefail

SSSD_CONF=/etc/sssd/sssd.conf
DNF_PACKAGES=(realmd sssd sssd-tools sssd-ad adcli krb5-workstation samba-common-tools oddjob oddjob-mkhomedir authselect)
APT_PACKAGES=(realmd sssd sssd-tools sssd-ad adcli krb5-user samba-common-bin oddjob oddjob-mkhomedir packagekit)

usage() {
  sed -n '2,/^set -euo/p' "$0" | sed -e '/^set -euo/d' -e 's/^# \{0,1\}//' | sed -n '3,$p'
}

die() {
  printf 'error: %s\n' "$1" >&2
  exit "${2:-1}"
}

command=""
domain=""
admin=""
naming=""
user_name=""
group_name=""
apply=0
short_names=0

[ "$#" -gt 0 ] || { usage; exit 2; }
case "$1" in
  -h | --help) usage; exit 0 ;;
  join | flush | check) command=$1; shift ;;
  names)
    command=names; shift
    [ "$#" -gt 0 ] || die "names needs short or qualified" 2
    case "$1" in short | qualified) naming=$1; shift ;; *) die "names takes short or qualified, not $1" 2 ;; esac
    ;;
  *) die "unknown command: $1 (see --help)" 2 ;;
esac
while [ "$#" -gt 0 ]; do
  case "$1" in
    --domain) [ "$#" -ge 2 ] || die "--domain needs a value" 2; domain=$2; shift 2 ;;
    --admin) [ "$#" -ge 2 ] || die "--admin needs a value" 2; admin=$2; shift 2 ;;
    --short-names) short_names=1; shift ;;
    --user) [ "$#" -ge 2 ] || die "--user needs a value" 2; user_name=$2; shift 2 ;;
    --group) [ "$#" -ge 2 ] || die "--group needs a value" 2; group_name=$2; shift 2 ;;
    --apply) apply=1; shift ;;
    --dry-run) apply=0; shift ;;
    -h | --help) usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" 2 ;;
  esac
done
if [ "$command" = join ]; then
  [ -n "$domain" ] || die "--domain is required (see --help)" 2
  [[ $domain =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die "--domain is not a DNS domain: $domain" 2
  [ -n "$admin" ] || die "--admin is required (see --help)" 2
  [[ $admin == *@* ]] || die "--admin takes a UPN (user@domain): $admin" 2
fi

run() {
  printf '  %s\n' "$*"
  if [ "$apply" -eq 1 ]; then
    "$@"
  fi
}

need_root() {
  if [ "$apply" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
    die "run as root (sudo) to make changes, or drop --apply to see the plan" 2
  fi
}

do_names() {
  local value=True
  [ "$1" = short ] && value=False
  echo "Set use_fully_qualified_names = $value in $SSSD_CONF and restart SSSD:"
  if [ "$apply" -eq 1 ]; then
    [ -f "$SSSD_CONF" ] || die "$SSSD_CONF is missing: join the domain first"
    cp -p "$SSSD_CONF" "$SSSD_CONF.bak"
    if grep -Eq '^use_fully_qualified_names[[:space:]]*=' "$SSSD_CONF"; then
      sed -i -E "s/^use_fully_qualified_names[[:space:]]*=.*/use_fully_qualified_names = $value/" "$SSSD_CONF"
    else
      sed -i -E "/^\[domain\//a use_fully_qualified_names = $value" "$SSSD_CONF"
    fi
    echo "  kept the previous file as $SSSD_CONF.bak"
  else
    echo "  edit use_fully_qualified_names in every [domain/...] section (a backup is kept)"
  fi
  run sss_cache -E
  run systemctl restart sssd
}

do_join() {
  if command -v dnf >/dev/null 2>&1; then
    echo "Install realmd, SSSD and adcli:"
    run dnf -y install "${DNF_PACKAGES[@]}"
  elif command -v apt-get >/dev/null 2>&1; then
    echo "Install realmd, SSSD and adcli (untested on apt hosts):"
    run env DEBIAN_FRONTEND=noninteractive apt-get install -y "${APT_PACKAGES[@]}"
  else
    die "no dnf or apt-get: install realmd, sssd and adcli yourself"
  fi
  echo "Discover and join the managed domain (the host's DNS must resolve the domain controllers):"
  # realm join authenticates with Kerberos: the realm is the upper-case domain.
  local principal="${admin%%@*}@${domain^^}"
  run realm discover "$domain"
  run realm join --membership-software=adcli -U "$principal" "$domain"
  if [ "$short_names" -eq 1 ]; then
    do_names short
  fi
}

do_check() {
  local failed=0
  echo "Realm:"
  if ! realm list 2>/dev/null | grep -E '^[^ ]|realm-name|configured|server-software|client-software|login-formats' | sed 's/^/  /'; then
    echo "  realm list failed or no realm is configured"
    failed=1
  fi
  echo "SSSD naming:"
  if [ -r "$SSSD_CONF" ]; then
    grep -E '^(id_provider|use_fully_qualified_names|entry_cache_timeout)[[:space:]]*=' "$SSSD_CONF" | sed 's/^/  /' || true
  else
    echo "  $SSSD_CONF is readable by root only; run check with sudo to see it"
  fi
  if [ -n "$user_name" ]; then
    echo "Account $user_name:"
    if ! id "$user_name" 2>&1 | sed 's/^/  /'; then
      failed=1
    fi
  fi
  if [ -n "$group_name" ]; then
    echo "Group $group_name:"
    if ! getent group "$group_name" | sed 's/^/  /'; then
      echo "  not found by that name; with use_fully_qualified_names = True it is $group_name@<domain>"
      failed=1
    fi
  fi
  return "$failed"
}

case "$command" in
  join) need_root; [ "$apply" -eq 1 ] || echo "Plan (nothing changes without --apply):"; do_join ;;
  names) need_root; [ "$apply" -eq 1 ] || echo "Plan (nothing changes without --apply):"; do_names "$naming" ;;
  flush) need_root; [ "$apply" -eq 1 ] || echo "Plan (nothing changes without --apply):"; echo "Clear the SSSD cache:"; run sss_cache -E ;;
  check) do_check ;;
esac
