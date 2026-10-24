#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
# Intune Linux root platform script. Edit the two settings below before upload.
set -euo pipefail
GROUP_NAME="replace-with-local-group"
MEMBERS=() # Example: (alice bob). This script owns the complete member list.
STATE_DIR=/var/lib/defenseclaw-intune/local-groups

[[ $EUID == 0 ]] || { echo 'error: run as root' >&2; exit 1; }
[[ $GROUP_NAME =~ ^[a-z_][a-z0-9_-]*$ && $GROUP_NAME != replace-with-local-group ]] || {
  echo 'error: set GROUP_NAME to a local group name before upload' >&2; exit 2;
}
# A member is an existing local account. Its name may hold the dots and capitals
# useradd accepts (john.doe); it never starts with a dot or a dash, is never all
# digits (getent would take it for a uid), and holds no comma or colon, which
# gpasswd and /etc/group use as separators.
for user in "${MEMBERS[@]}"; do
  [[ ${#user} -le 32 && $user =~ ^[A-Za-z0-9_][A-Za-z0-9._-]*[$]?$ && ! $user =~ ^[0-9]+$ ]] || {
    echo "error: invalid user name: $user" >&2; exit 2;
  }
  entry=$(getent -s files passwd "$user") || { echo "error: no local account: $user" >&2; exit 1; }
  [[ ${entry%%:*} == "$user" ]] || { echo "error: no local account: $user" >&2; exit 1; }
done
# Only manage groups created by this script. An arbitrary existing local group
# may grant sudo, file, or service privileges even when its name looks harmless.
umask 077
install -d -m 0700 -- "$STATE_DIR"
marker=$STATE_DIR/$GROUP_NAME
group_entry=$(getent -s files group "$GROUP_NAME" || true)
if [[ -z $group_entry ]]; then
  if getent group "$GROUP_NAME" > /dev/null; then
    echo "error: $GROUP_NAME resolves through NSS but is not a local group" >&2
    exit 1
  fi
  if [[ -e $marker || -L $marker ]]; then
    echo "error: stale ownership record for $GROUP_NAME; review it before reuse" >&2
    exit 1
  fi
  groupadd -- "$GROUP_NAME"
  group_entry=$(getent -s files group "$GROUP_NAME")
  gid=$(cut -d: -f3 <<< "$group_entry")
  printf "%s\n" "$gid" > "$marker"
else
  gid=$(cut -d: -f3 <<< "$group_entry")
  if [[ ! -f $marker || -L $marker || $(cat -- "$marker") != "$gid" ]]; then
    echo "error: $GROUP_NAME is an existing group not owned by this script" >&2
    exit 1
  fi
fi
current=$(getent -s files group "$GROUP_NAME" | cut -d: -f4)
IFS=, read -ra current_members <<< "$current"
normalize() { printf '%s\n' "$@" | sed '/^$/d' | LC_ALL=C sort -u; }
passwd_entries=$(getent -s files passwd) || { echo 'error: cannot read local accounts' >&2; exit 1; }
mapfile -t primary_members < <(printf '%s\n' "$passwd_entries" | awk -F: -v gid="$gid" '$4 == gid { print $1 }')
wanted_supplementary=()
for user in "${MEMBERS[@]}"; do
  primary=0
  for member in "${primary_members[@]}"; do
    [[ $user != "$member" ]] || primary=1
  done
  [[ $primary == 1 ]] || wanted_supplementary+=("$user")
done
unwanted_primary=()
for member in "${primary_members[@]}"; do
  wanted=0
  for user in "${MEMBERS[@]}"; do
    [[ $user != "$member" ]] || wanted=1
  done
  [[ $wanted == 1 ]] || unwanted_primary+=("$member")
done
current_all=$(normalize "${current_members[@]}" "${primary_members[@]}")
wanted_all=$(normalize "${MEMBERS[@]}")
current_supplementary=$(normalize "${current_members[@]}")
wanted_supplementary_set=$(normalize "${wanted_supplementary[@]}")
if [[ $current_all == "$wanted_all" && $current_supplementary == "$wanted_supplementary_set" ]]; then
  echo "unchanged: $GROUP_NAME"
  exit 0
fi
if [[ $current_supplementary != "$wanted_supplementary_set" ]]; then
  wanted=$(IFS=,; echo "${wanted_supplementary[*]}")
  gpasswd -M "$wanted" "$GROUP_NAME"
  echo "updated: $GROUP_NAME (${#MEMBERS[@]} requested member(s))"
fi
if [[ ${#unwanted_primary[@]} -gt 0 ]]; then
  for member in "${unwanted_primary[@]}"; do
    echo "warning: $member remains in $GROUP_NAME because its primary group must be changed" >&2
  done
  exit 1
fi
