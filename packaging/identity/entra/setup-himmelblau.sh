#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# setup-himmelblau.sh - let a Linux host see Microsoft Entra ID users and their
# Entra groups through Himmelblau, so DefenseClaw can match Entra groups.
#
# DefenseClaw never calls Entra ID. It reads the accounts and groups NSS
# reports. The Azure `aad` module gives an account no Entra groups; Himmelblau
# does: `id` and initgroups name each Entra group the user is in. This script
# installs Himmelblau from its signed apt repository, writes
# /etc/himmelblau/himmelblau.conf with the settings DefenseClaw needs, and
# restarts the daemons in an order that avoids the stuck restart of the 5.0
# nightly. Run it as root.
#
# It changes the host, so it only PRINTS the plan unless you pass --apply.
#
# Usage:
#   setup-himmelblau.sh install   --domain DOMAIN [--allow-group ID]... [--short-names] [--apply]
#   setup-himmelblau.sh configure --domain DOMAIN [--allow-group ID]... [--short-names] [--apply]
#   setup-himmelblau.sh restart   [--apply]
#   setup-himmelblau.sh check     [--user NAME]
#
# Commands:
#   install     add the apt repository, install the packages, then configure
#   configure   write himmelblau.conf (the old one is kept as .bak) and restart
#   restart     stop the sockets and daemons, clear the saved file descriptors,
#               start them again (the 5.0 nightly leaves the units stuck on a
#               second plain `systemctl restart`)
#   check       read-only: daemon state, NSS lines, the config keys DefenseClaw
#               cares about, and `id` of one account
#
# Options:
#   --domain DOMAIN     the tenant domain, for example contoso.onmicrosoft.com
#   --allow-group ID    object id of an Entra group whose members may sign in
#                       (pam_allow_groups; repeatable). Without one, every user
#                       of the tenant can sign in.
#   --short-names       keep Himmelblau's default cn_name_mapping = true: accounts
#                       are named by the short name and carry no UPN, so a
#                       DefenseClaw users entry written as a UPN cannot match.
#                       By default the script sets cn_name_mapping = false.
#   --user NAME         check: the account to show
#   --apply             make the changes; without it the script only prints them
#   --dry-run           print the plan (the default)
#   -h, --help          show this help
#
# Environment:
#   HIMMELBLAU_REPO     the apt repository (default: the nightly channel for
#                       Ubuntu 24.04, the only free channel)
#
# Before users sign in: Entra requires a registered MFA method for remote
# sign-in through Himmelblau, and the first sign-in asks for a Windows Hello PIN
# of at least 6 characters. See README.md.
#
# Exit codes: 0 success or a complete plan, 1 a step failed, 2 bad usage.
# Tested on Ubuntu 24.04 with Himmelblau 5.0.0 nightly. See README.md.

set -euo pipefail

REPO=${HIMMELBLAU_REPO:-https://packages.himmelblau-idm.org/nightly/latest/deb/ubuntu24.04}
KEY_URL=https://packages.himmelblau-idm.org/himmelblau.asc
KEYRING=/etc/apt/keyrings/himmelblau.gpg
SOURCES=/etc/apt/sources.list.d/himmelblau.list
CONF=/etc/himmelblau/himmelblau.conf
PACKAGES=(himmelblau nss-himmelblau pam-himmelblau himmelblau-sshd-config)
SOCKETS=(himmelblaud.socket himmelblaud-tasks.socket himmelblaud-broker.socket)
SERVICES=(himmelblaud himmelblaud-tasks)

usage() {
  sed -n '2,/^set -euo/p' "$0" | sed -e '/^set -euo/d' -e 's/^# \{0,1\}//' | sed -n '3,$p'
}

die() {
  printf 'error: %s\n' "$1" >&2
  exit "${2:-1}"
}

command=""
domain=""
user_name=""
apply=0
short_names=0
allow_groups=()

[ "$#" -gt 0 ] || { usage; exit 2; }
case "$1" in
  -h | --help) usage; exit 0 ;;
  install | configure | restart | check) command=$1; shift ;;
  *) die "unknown command: $1 (see --help)" 2 ;;
esac
while [ "$#" -gt 0 ]; do
  case "$1" in
    --domain) [ "$#" -ge 2 ] || die "--domain needs a value" 2; domain=$2; shift 2 ;;
    --allow-group) [ "$#" -ge 2 ] || die "--allow-group needs a value" 2; allow_groups+=("$2"); shift 2 ;;
    --short-names) short_names=1; shift ;;
    --user) [ "$#" -ge 2 ] || die "--user needs a value" 2; user_name=$2; shift 2 ;;
    --apply) apply=1; shift ;;
    --dry-run) apply=0; shift ;;
    -h | --help) usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" 2 ;;
  esac
done

guid_re='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
for id in "${allow_groups[@]}"; do
  [[ $id =~ $guid_re ]] || die "--allow-group takes a group object id (a GUID), not a name: $id" 2
done
if [ "$command" = install ] || [ "$command" = configure ]; then
  [ -n "$domain" ] || die "--domain is required (see --help)" 2
  [[ $domain =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die "--domain is not a DNS domain: $domain" 2
fi

# run prints a step, and runs it with --apply.
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

config_text() {
  printf '[global]\n'
  printf 'domain = %s\n' "$domain"
  if [ "$short_names" -eq 0 ]; then
    printf 'cn_name_mapping = false\n'
  fi
  if [ "${#allow_groups[@]}" -gt 0 ]; then
    local joined
    joined=$(IFS=,; printf '%s' "${allow_groups[*]}")
    printf 'pam_allow_groups = %s\n' "$joined"
  fi
  printf 'home_attr = CN\nhome_alias = CN\nuse_etc_skel = true\n'
}

do_restart() {
  echo "Restart the Himmelblau daemons:"
  run systemctl stop "${SOCKETS[@]}" "${SERVICES[@]}"
  run systemctl clean --what=fdstore himmelblaud.service
  run systemctl start "${SOCKETS[@]}"
  run systemctl start "${SERVICES[@]}"
  if [ "$apply" -eq 1 ]; then
    sleep 3
    systemctl is-active "${SERVICES[@]}" || die "the Himmelblau daemons did not start; see journalctl -u himmelblaud"
  fi
}

do_configure() {
  echo "Write $CONF:"
  config_text | sed 's/^/    /'
  if [ "${#allow_groups[@]}" -eq 0 ]; then
    echo "  note: no --allow-group, so every user of the tenant can sign in to this host"
  fi
  if [ "$apply" -eq 1 ]; then
    install -d -m 0755 "$(dirname "$CONF")"
    if [ -f "$CONF" ]; then
      cp -p "$CONF" "$CONF.bak"
      echo "  kept the previous file as $CONF.bak"
    fi
    config_text > "$CONF.new"
    chmod 0644 "$CONF.new"
    mv "$CONF.new" "$CONF"
  fi
  do_restart
}

do_install() {
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    if [ "${ID:-}" != ubuntu ] || [ "${VERSION_ID:-}" != 24.04 ]; then
      echo "warning: tested on Ubuntu 24.04 only; this host is ${PRETTY_NAME:-unknown}" >&2
    fi
  fi
  if command -v dpkg >/dev/null 2>&1 && [ "$(dpkg --print-architecture)" != amd64 ]; then
    die "the Himmelblau apt repository serves amd64 packages; this host is $(dpkg --print-architecture)"
  fi
  echo "Add the Himmelblau apt repository ($REPO):"
  run apt-get update -qq
  run apt-get install -y -qq curl gnupg ca-certificates
  run install -d -m 0755 "$(dirname "$KEYRING")"
  printf '  curl -fsSL %s | gpg --dearmor > %s\n' "$KEY_URL" "$KEYRING"
  printf '  echo "deb [arch=amd64 signed-by=%s] %s ./" > %s\n' "$KEYRING" "$REPO" "$SOURCES"
  if [ "$apply" -eq 1 ]; then
    curl -fsSL "$KEY_URL" | gpg --dearmor --yes -o "$KEYRING"
    chmod 0644 "$KEYRING"
    printf 'deb [arch=amd64 signed-by=%s] %s ./\n' "$KEYRING" "$REPO" > "$SOURCES"
  fi
  echo "Install the packages (they add himmelblau to passwd, group and shadow in nsswitch.conf and to PAM):"
  run apt-get update -qq
  run env DEBIAN_FRONTEND=noninteractive apt-get install -y "${PACKAGES[@]}"
  do_configure
}

do_check() {
  echo "Daemons:"
  for unit in "${SERVICES[@]}"; do
    printf '  %-18s %s\n' "$unit" "$(systemctl is-active "$unit" 2>/dev/null || true)"
  done
  echo "NSS (/etc/nsswitch.conf):"
  grep -E '^(passwd|group):' /etc/nsswitch.conf 2>/dev/null | sed 's/^/  /' || echo "  not readable"
  if ! grep -Eq '^group:.*himmelblau' /etc/nsswitch.conf 2>/dev/null; then
    echo "  warning: himmelblau is not on the group line, so no Entra group reaches DefenseClaw"
  fi
  echo "Config ($CONF):"
  if [ -r "$CONF" ]; then
    grep -E '^(domain|domains|cn_name_mapping|pam_allow_groups)[[:space:]]*=' "$CONF" | sed 's/^/  /' || true
    if ! grep -Eq '^cn_name_mapping[[:space:]]*=[[:space:]]*false' "$CONF"; then
      echo "  note: cn_name_mapping is not false, so accounts carry no UPN for DefenseClaw users entries"
    fi
    if ! grep -Eq '^pam_allow_groups' "$CONF"; then
      echo "  note: no pam_allow_groups, so every user of the tenant can sign in"
    fi
  else
    echo "  missing: the daemon does not start without a domain"
  fi
  if [ -n "$user_name" ]; then
    echo "Account $user_name:"
    id "$user_name" 2>&1 | sed 's/^/  /' || true
    echo "  (getent group NAME finds no Entra group by design; getent group GID does)"
  fi
}

case "$command" in
  install) need_root; [ "$apply" -eq 1 ] || echo "Plan (nothing changes without --apply):"; do_install ;;
  configure) need_root; [ "$apply" -eq 1 ] || echo "Plan (nothing changes without --apply):"; do_configure ;;
  restart) need_root; [ "$apply" -eq 1 ] || echo "Plan (nothing changes without --apply):"; do_restart ;;
  check) do_check ;;
esac
