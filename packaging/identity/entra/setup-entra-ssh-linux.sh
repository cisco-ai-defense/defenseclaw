#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# setup-entra-ssh-linux.sh - let Microsoft Entra ID users sign in over SSH to an
# Azure Linux VM, then install DefenseClaw for them.
#
# It wraps the Azure CLI. It enables a system-assigned managed identity on the VM,
# installs the AADSSHLoginForLinux extension (which adds the `aad` NSS, PAM and
# SSH modules), and gives users or groups the Azure role that allows the sign-in.
#
# DefenseClaw does not use anything this script does: it reads the account that
# the `aad` module creates (directory entra_id, source nss_aad, the UPN as the
# principal). The `aad` module gives no Entra groups, so a DefenseClaw groups
# assignment cannot name an Entra group on this VM; use `users` assignments.
#
# It changes Azure resources, so it only PRINTS the plan unless you pass --apply.
#
# Usage:
#   setup-entra-ssh-linux.sh --resource-group RG --vm VM [--user UPN]... [--group NAME]... [--admin] [--apply]
#
# Options:
#   -g, --resource-group RG   the VM's resource group (required)
#   -n, --vm VM               the VM name (required)
#       --user UPN            grant this user the sign-in role (repeatable)
#       --group NAME          grant this Entra group the sign-in role (repeatable)
#       --admin               use "Virtual Machine Administrator Login" (sudo rights)
#                             instead of "Virtual Machine User Login"
#       --apply               make the changes; without it the script only reads and prints
#       --dry-run             print the plan (the default; accepted for clarity)
#   -h, --help                show this help
#
# Environment:
#   AZ   the Azure CLI to run (default: az). Sign in first with `az login`, or point
#        AZ at a wrapper that selects a signed-in configuration.
#
# Exit codes: 0 success or a complete plan, 1 an Azure CLI call failed, 2 bad usage.
# Tested against an Ubuntu 22.04 VM in the plan mode. See README.md.

set -euo pipefail

AZ=${AZ:-az}
EXT_PUBLISHER=Microsoft.Azure.ActiveDirectory
EXT_NAME=AADSSHLoginForLinux

usage() {
  sed -n '2,/^set -euo/p' "$0" | sed -e '/^set -euo/d' -e 's/^# \{0,1\}//' | sed -n '3,$p'
}

die() {
  printf 'error: %s\n' "$1" >&2
  exit "${2:-1}"
}

rg=""
vm=""
apply=0
admin=0
users=()
groups=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    -g | --resource-group) [ "$#" -ge 2 ] || die "$1 needs a value" 2; rg=$2; shift 2 ;;
    -n | --vm) [ "$#" -ge 2 ] || die "$1 needs a value" 2; vm=$2; shift 2 ;;
    --user) [ "$#" -ge 2 ] || die "--user needs a value" 2; users+=("$2"); shift 2 ;;
    --group) [ "$#" -ge 2 ] || die "--group needs a value" 2; groups+=("$2"); shift 2 ;;
    --admin) admin=1; shift ;;
    --apply) apply=1; shift ;;
    --dry-run) apply=0; shift ;;
    -h | --help) usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" 2 ;;
  esac
done
[ -n "$rg" ] || die "--resource-group is required (see --help)" 2
[ -n "$vm" ] || die "--vm is required (see --help)" 2

if [ "$admin" -eq 1 ]; then
  role="Virtual Machine Administrator Login"
else
  role="Virtual Machine User Login"
fi

command -v "$AZ" >/dev/null 2>&1 || die "the Azure CLI ($AZ) was not found; install it or set AZ" 1
"$AZ" account show --query id -o tsv >/dev/null 2>&1 || die "the Azure CLI is not signed in; run: $AZ login" 1

tag="[plan]"
[ "$apply" -eq 1 ] && tag="[apply]"

# step DESCRIPTION COMMAND...  prints the step and runs it only with --apply.
step() {
  local description=$1
  shift
  if [ "$apply" -eq 1 ]; then
    printf '%s %s\n' "$tag" "$description"
    "$@" >/dev/null || die "failed: $description" 1
  else
    printf '%s would: %s\n' "$tag" "$description"
  fi
}

vm_info=$("$AZ" vm show -g "$rg" -n "$vm" --query "[id, storageProfile.osDisk.osType, identity.type || 'None']" -o tsv 2>&1) ||
  die "cannot read the VM $vm in $rg: $vm_info" 1
vm_id=$(printf '%s\n' "$vm_info" | sed -n 1p)
vm_os=$(printf '%s\n' "$vm_info" | sed -n 2p)
vm_identity=$(printf '%s\n' "$vm_info" | sed -n 3p)
[ "$vm_os" = "Linux" ] || die "$vm is a $vm_os VM; this script is for Linux VMs" 1
echo "VM: $vm ($vm_os) in $rg"

# Resolve all principals before any VM or role changes.
user_ids=()
group_ids=()
for principal in ${users[@]+"${users[@]}"}; do
  oid=$("$AZ" ad user show --id "$principal" --query id -o tsv 2>/dev/null) ||
    die "user $principal was not found in Entra ID" 1
  [ -n "$oid" ] || die "user $principal was not found in Entra ID" 1
  user_ids+=("$oid")
done
for principal in ${groups[@]+"${groups[@]}"}; do
  oid=$("$AZ" ad group show --group "$principal" --query id -o tsv 2>/dev/null) ||
    die "group $principal was not found in Entra ID" 1
  [ -n "$oid" ] || die "group $principal was not found in Entra ID" 1
  group_ids+=("$oid")
done

# 1. System-assigned managed identity (the extension needs it).
case "${vm_identity:-None}" in
  *SystemAssigned*) echo "ok: system-assigned managed identity is on" ;;
  *) step "enable the system-assigned managed identity" "$AZ" vm identity assign -g "$rg" -n "$vm" ;;
esac

# 2. The AADSSHLoginForLinux extension.
ext_state=$("$AZ" vm extension list -g "$rg" --vm-name "$vm" --query "[?name=='$EXT_NAME'].provisioningState | [0]" -o tsv 2>/dev/null || true)
if [ "$ext_state" = "Succeeded" ]; then
  echo "ok: extension $EXT_NAME is installed"
else
  [ -z "$ext_state" ] || echo "note: extension $EXT_NAME is in state $ext_state; setting it again"
  step "install the $EXT_NAME extension" "$AZ" vm extension set -g "$rg" --vm-name "$vm" \
    --publisher "$EXT_PUBLISHER" --name "$EXT_NAME"
fi

# 3. The sign-in role, for each user and group.
grant() {
  local kind=$1 principal=$2 oid=$3 principal_type count
  if [ "$kind" = "user" ]; then
    principal_type=User
  else
    principal_type=Group
  fi
  count=$("$AZ" role assignment list --assignee "$oid" --scope "$vm_id" --role "$role" --query 'length(@)' -o tsv 2>/dev/null || echo 0)
  if [ "${count:-0}" -gt 0 ]; then
    echo "ok: $kind $principal already has \"$role\" on the VM"
  else
    step "give $kind $principal the role \"$role\" on the VM" "$AZ" role assignment create \
      --assignee-object-id "$oid" --assignee-principal-type "$principal_type" --role "$role" --scope "$vm_id"
  fi
}
for i in "${!users[@]}"; do grant user "${users[i]}" "${user_ids[i]}"; done
for i in "${!groups[@]}"; do grant group "${groups[i]}" "${group_ids[i]}"; done
if [ "${#users[@]}" -eq 0 ] && [ "${#groups[@]}" -eq 0 ]; then
  echo "note: no --user or --group given, so no sign-in role was checked or granted"
fi

if [ "$apply" -eq 0 ]; then
  echo "Nothing was changed. Run again with --apply to make these changes."
else
  echo "Done. Sign in with: $AZ extension add --name ssh && $AZ ssh vm -g $rg -n $vm"
fi
