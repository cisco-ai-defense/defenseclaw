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
# carries the membership.
#
# Intune decides who is in the Entra group, but it evaluates a user assignment
# for the Mac's primary user and runs the script as root, not as that user. So
# the Intune copy (the settings block below, no arguments) must name the
# account in USER_NAME, and it adds that account only while that account is
# the user in front at the console: another user in front (fast user
# switching), or the login window, is a failure Intune retries, never a
# change for whoever is there. Removal acts on the named account at any time.
# DefenseClaw expects one signed-in Entra user per Mac.
#
# Usage:
#   macos-entra-group-bridge.sh add    --group NAME [--user NAME] [--apply]
#   macos-entra-group-bridge.sh remove --group NAME [--user NAME] [--apply]
#   macos-entra-group-bridge.sh check  --group NAME [--user NAME]
#
# Options:
#   --group NAME   the local group, named as the DefenseClaw assignment names it
#                  (for example ml-team): a letter or digit, then letters,
#                  digits, dot, dash or underscore, at most 64 characters. It is
#                  created when missing; an empty group Platform SSO created
#                  with that name is used as it is. Built-in and privileged
#                  groups (admin, wheel, staff, com.apple.*, any group with
#                  an id below 500) are refused.
#   --user NAME    the account (default: the user in front at the console)
#   --allow-system-group
#                  allow a built-in or privileged group anyway
#   --apply        make the change; without it the script only prints it
#   --dry-run      print the plan (the default)
#   -h, --help     show this help
#
# After a change, DefenseClaw picks the new group up within 15 minutes, or at
# once after the gateway restarts. remove leaves the group in place (an empty
# group is harmless); delete it with dseditgroup -o delete NAME when no
# assignment uses it.
#
# Exit codes: 0 success or a complete plan, 1 a step failed or the named user
# is not in front at the console (Intune retries), 2 bad usage.
# Tested on macOS 15.8 with Platform SSO (Company Portal). See README.md.

# --- settings for an Intune script (used when no command is given) --------
ACTION=""          # add or remove
GROUP_NAME=""      # the local group, for example ml-team
USER_NAME=""       # the macOS account of the Entra user this copy is for (required)
APPLY="no"         # yes to make the change
ALLOW_SYSTEM_GROUP="no"  # yes only to bridge into a built-in or privileged group
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
account=$USER_NAME
apply=0
allow_system=0
[ "$APPLY" = yes ] && apply=1
[ "$ALLOW_SYSTEM_GROUP" = yes ] && allow_system=1
# Intune runs the script without arguments: that is the copy whose settings
# block names the account.
intune=1
[ "$#" -gt 0 ] && intune=0

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
    --user)
      if [ "$#" -lt 2 ] || [ -z "$2" ]; then
        die "--user needs an account name (leave it out for the user at the console)" 2
      fi
      account=$2; shift 2 ;;
    --allow-system-group) allow_system=1; shift ;;
    --apply) apply=1; shift ;;
    --dry-run) apply=0; shift ;;
    -h | --help) usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" 2 ;;
  esac
done
case "$command" in add | remove | check) ;; *) die "give add, remove or check (or set ACTION)" 2 ;; esac
[ -n "$group" ] || die "--group is required (or set GROUP_NAME)" 2
if [ "${#group}" -gt 64 ] || ! [[ $group =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
  die "--group takes a short name: a letter or digit, then letters, digits, dot, dash or underscore, at most 64 characters: $group" 2
fi
if [ "$allow_system" -eq 0 ]; then
  case "$group" in
    admin | wheel | staff | everyone | localaccounts | daemon | operator | nobody | nogroup | com.apple.*)
      die "$group is a built-in or privileged macOS group: a member gets its rights (admin makes the user an administrator). Name the group the DefenseClaw assignment uses, or pass --allow-system-group (ALLOW_SYSTEM_GROUP=yes) if this is really meant" 2 ;;
  esac
fi
if [ -n "$account" ] && { [ "${#account}" -gt 255 ] || ! [[ $account =~ ^[A-Za-z0-9_][A-Za-z0-9._@-]*$ ]]; }; then
  die "--user takes an account short name: $account" 2
fi
if [ "$intune" -eq 1 ] && [ -z "$account" ]; then
  die "set USER_NAME in the settings block: Intune runs this copy for the Mac's primary user, not for whoever is at the console, so the copy must name the account" 2
fi

console=$(/usr/bin/stat -f %Su /dev/console 2>/dev/null || true)
case "$console" in "" | root | loginwindow | _mbsetupuser) console="" ;; esac
if [ -z "$account" ]; then
  [ -n "$console" ] || die "no user is in front at the console (the login window is showing, or nobody is signed in); give --user, or run this again when the user is in front" 1
  account=$console
fi
if [ "$intune" -eq 1 ] && [ "$command" = add ] && [ "$account" != "$console" ]; then
  # Intune evaluated the assignment for the Mac's primary user; adding
  # whoever is in front would give a non-member the group's profile.
  if [ -z "$console" ]; then
    die "$account is not in front at the console (the login window is showing); nothing changed, and Intune runs this script again later" 1
  fi
  die "$account is not the user in front at the console ($console); this copy adds only the account it names while that account is in front. Nothing changed; Intune runs this script again later. DefenseClaw expects one signed-in Entra user per Mac" 1
fi
/usr/bin/id "$account" >/dev/null 2>&1 || die "no account named $account"

if [ "$apply" -eq 1 ] && [ "$command" != check ] && [ "$(/usr/bin/id -u)" -ne 0 ]; then
  die "run as root (Intune runs scripts as root), or drop --apply to see the plan" 2
fi

group_exists() { /usr/bin/dscl . -read "/Groups/$group" PrimaryGroupID >/dev/null 2>&1; }
is_member() { /usr/sbin/dseditgroup -o checkmember -m "$account" "$group" >/dev/null 2>&1; }

# A group the system owns (an id below 500) is refused by its id too, so a
# built-in group with a name the list above misses is not bridged into.
if [ "$allow_system" -eq 0 ] && [ "$command" != check ] && group_exists; then
  gid=$(/usr/bin/dscl . -read "/Groups/$group" PrimaryGroupID 2>/dev/null | /usr/bin/awk '{print $2}')
  if [[ $gid =~ ^[0-9]+$ ]] && [ "$gid" -lt 500 ]; then
    die "$group (id $gid) is a system group: a member gets its rights. Pass --allow-system-group (ALLOW_SYSTEM_GROUP=yes) if this is really meant" 2
  fi
fi

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
    if group_exists; then
      echo "the group $group stays on this Mac; delete it with: dseditgroup -o delete $group (when no assignment uses it)"
    fi
    ;;
esac
