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
for user in "${MEMBERS[@]}"; do
  [[ $user =~ ^[a-z_][a-z0-9_-]*$ ]] || { echo "error: invalid user name: $user" >&2; exit 2; }
  getent -s files passwd "$user" > /dev/null || { echo "error: no local account: $user" >&2; exit 1; }
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
if [[ $(normalize "${current_members[@]}") == $(normalize "${MEMBERS[@]}") ]]; then
  echo "unchanged: $GROUP_NAME"
  exit 0
fi
wanted=$(IFS=,; echo "${MEMBERS[*]}")
gpasswd -M "$wanted" "$GROUP_NAME"
echo "updated: $GROUP_NAME (${#MEMBERS[@]} member(s))"
