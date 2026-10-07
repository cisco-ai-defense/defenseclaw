#!/bin/bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# macos-entra-group-bridge.sh - put a Mac user into (or take them out of) a
# local group that stands for a Microsoft Entra ID group, so a DefenseClaw
# groups assignment can match it.
#
# Platform SSO signs Entra users in to a Mac but puts no Entra group into the
# macOS group database: `id` shows only local groups, and the Platform SSO
# AdditionalGroups and AdministratorGroups settings create empty local groups
# without adding anyone. DefenseClaw reads the macOS groups, so a groups
# assignment that names an Entra group matches no one until a local group
# carries the membership. Intune decides who is in the Entra group: assign this
# script with ACTION=add to the Entra group, and a copy with ACTION=remove to
# the users who are not in it.
#
# Intune runs macOS shell scripts as root without arguments, so the settings
# block below can be filled in instead of passing options.
#
# Usage:
#   macos-entra-group-bridge.sh add    --group NAME [--user NAME] [--apply]
#   macos-entra-group-bridge.sh remove --group NAME [--user NAME] [--apply]
#   macos-entra-group-bridge.sh check  --group NAME [--user NAME]
#
# Options:
#   --group NAME   the local group, named as the DefenseClaw assignment names it
#                  (for example ml-team). It is created when missing; an empty
#                  group Platform SSO created with that name is used as it is.
#   --user NAME    the account (default: the user signed in at the console)
#   --apply        make the change; without it the script only prints it
#   --dry-run      print the plan (the default)
#   -h, --help     show this help
#
# After a change, DefenseClaw picks the new group up within 15 minutes, or at
# once after the gateway restarts.
#
# Exit codes: 0 success or a complete plan, 1 a step failed, 2 bad usage.
# Tested on macOS 15.8 with Platform SSO (Company Portal). See README.md.

# --- settings for an Intune script (used when no command is given) --------
ACTION=""          # add or remove
GROUP_NAME=""      # the local group, for example ml-team
APPLY="no"         # yes to make the change
# ---------------------------------------------------------------------------

set -euo pipefail

usage() {
  sed -n '2,/^# --- settings/p' "$0" | sed -e '/^# --- settings/d' -e 's/^# \{0,1\}//' | sed -n '3,$p'
}

die() {
  printf 'error: %s\n' "$1" >&2
  exit "${2:-1}"
}

command=$ACTION
group=$GROUP_NAME
account=""
apply=0
[ "$APPLY" = yes ] && apply=1

if [ "$#" -gt 0 ]; then
  case "$1" in
    -h | --help) usage; exit 0 ;;
    add | remove | check) command=$1; shift ;;
    *) die "unknown command: $1 (see --help)" 2 ;;
  esac
fi
while [ "$#" -gt 0 ]; do
  case "$1" in
    --group) [ "$#" -ge 2 ] || die "--group needs a value" 2; group=$2; shift 2 ;;
    --user) [ "$#" -ge 2 ] || die "--user needs a value" 2; account=$2; shift 2 ;;
    --apply) apply=1; shift ;;
    --dry-run) apply=0; shift ;;
    -h | --help) usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" 2 ;;
  esac
done
case "$command" in add | remove | check) ;; *) die "give add, remove or check (or set ACTION)" 2 ;; esac
[ -n "$group" ] || die "--group is required (or set GROUP_NAME)" 2
[[ $group =~ ^[A-Za-z0-9._-]+$ ]] || die "--group takes a short name of letters, digits, dot, dash or underscore: $group" 2

if [ -z "$account" ]; then
  account=$(/usr/bin/stat -f %Su /dev/console)
  case "$account" in
    "" | root | loginwindow | _mbsetupuser) echo "no user is signed in at the console; nothing to do"; exit 0 ;;
  esac
fi
/usr/bin/id "$account" >/dev/null 2>&1 || die "no account named $account"

if [ "$apply" -eq 1 ] && [ "$command" != check ] && [ "$(/usr/bin/id -u)" -ne 0 ]; then
  die "run as root (Intune runs scripts as root), or drop --apply to see the plan" 2
fi

group_exists() { /usr/bin/dscl . -read "/Groups/$group" PrimaryGroupID >/dev/null 2>&1; }
is_member() { /usr/sbin/dseditgroup -o checkmember -m "$account" "$group" >/dev/null 2>&1; }

run() {
  printf '  %s\n' "$*"
  if [ "$apply" -eq 1 ]; then
    "$@"
  fi
}

case "$command" in
  check)
    if ! group_exists; then
      echo "group $group does not exist on this Mac"
      exit 0
    fi
    if is_member; then echo "$account is a member of $group"; else echo "$account is not a member of $group"; fi
    ;;
  add)
    [ "$apply" -eq 1 ] || echo "Plan (nothing changes without --apply):"
    if ! group_exists; then
      run /usr/sbin/dseditgroup -o create -r "Entra group $group (DefenseClaw)" "$group"
    fi
    if group_exists && is_member; then
      echo "$account is already a member of $group"
    else
      run /usr/sbin/dseditgroup -o edit -a "$account" -t user "$group"
    fi
    ;;
  remove)
    [ "$apply" -eq 1 ] || echo "Plan (nothing changes without --apply):"
    if group_exists && is_member; then
      run /usr/sbin/dseditgroup -o edit -d "$account" -t user "$group"
    else
      echo "$account is not a member of $group"
    fi
    ;;
esac
