#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# verify-okta-identity.sh - check that a Linux host sees Okta users the way
# DefenseClaw needs, and ask DefenseClaw which guardrail profile each user gets.
#
# It only reads: it changes nothing on the host and never calls Okta.
#
#   1. SSSD: the service runs, this SSSD knows ldap_use_ppolicy, the Okta
#      domain is Online, and sssd.conf is root-only (run as root for the last
#      two).
#   2. Each --user: getent and id show the account and the expected group;
#      with --expect-upn, SSSD InfoPipe returns the user principal name.
#   3. DefenseClaw: the gateway answers which profile the user resolves to
#      (and, with --expect-profile, that it is the one you expect). On a
#      managed host run as root and it uses `defenseclaw-gateway enterprise
#      linux profile-explain`; on a per-user install run as the user whose
#      gateway you want to ask and it uses `defenseclaw guardrail profile
#      explain`.
#
# Exit codes: 0 no check failed (skipped checks do not fail), 1 at least one
# check failed, 2 bad arguments.

set -uo pipefail

SELF=$(basename "$0")
CFG_RULES=${OKTA_KIT_SSSD_CFG_RULES:-/usr/share/sssd/cfg_rules.ini}
MANAGED_GATEWAY=/opt/defenseclaw/bin/defenseclaw-gateway

USERS=() EXPECT_GROUP="" EXPECT_PROFILE="" CONNECTOR="" DOMAIN="okta" EXPECT_UPN=0 ALLOW_GROUP=""
SKIP_DC=0 DC_CMD=""
PASS=0 FAILED=0 SKIPPED=0

usage() {
  cat << USAGE
Usage: $SELF --user NAME [--user NAME ...] [options]

Read-only check of an Okta user setup (Okta LDAP Interface, SSSD, DefenseClaw).

Options:
  --user NAME            POSIX account to check (the Okta unixUsername). Repeatable.
  --expect-group GROUP   A group every --user must be in, as id -Gn prints it
  --expect-profile NAME  The guardrail profile DefenseClaw must pick for every --user
  --connector NAME       Connector for the profile check, for example claudecode
  --allow-group GROUP    The group that may sign in (install-sssd-okta.sh --allow-group):
                         check that it resolves
  --domain NAME          SSSD domain name (default okta)
  --expect-upn           Check that SSSD InfoPipe returns a userPrincipalName
                         (standalone enterprise; needs root)
  --defenseclaw CMD      defenseclaw (per-user install) or the path of
                         defenseclaw-gateway (managed host). Default: detect.
  --skip-defenseclaw     Check only NSS and SSSD
  -h, --help             Show this help

Exit codes: 0 no check failed, 1 a check failed, 2 bad arguments.
USAGE
}

pass() { printf 'PASS  %s\n' "$*"; PASS=$((PASS + 1)); }
fail() { printf 'FAIL  %s\n' "$*"; FAILED=$((FAILED + 1)); }
skip() { printf 'SKIP  %s\n' "$*"; SKIPPED=$((SKIPPED + 1)); }
info() { printf '      %s\n' "$*"; }
die() { printf '%s: error: %s\n' "$SELF" "$*" >&2; exit 2; }

parse_args() {
  while [[ $# -gt 0 ]]; do
    case $1 in
      --user) [[ $# -ge 2 && -n $2 ]] || die "--user needs a value"; USERS+=("$2"); shift 2 ;;
      --expect-group) [[ $# -ge 2 && -n $2 ]] || die "--expect-group needs a value"; EXPECT_GROUP=$2; shift 2 ;;
      --expect-profile) [[ $# -ge 2 && -n $2 ]] || die "--expect-profile needs a value"; EXPECT_PROFILE=$2; shift 2 ;;
      --connector) [[ $# -ge 2 && -n $2 ]] || die "--connector needs a value"; CONNECTOR=$2; shift 2 ;;
      --allow-group) [[ $# -ge 2 && -n $2 ]] || die "--allow-group needs a value"; ALLOW_GROUP=$2; shift 2 ;;
      --domain) [[ $# -ge 2 && -n $2 ]] || die "--domain needs a value"; DOMAIN=$2; shift 2 ;;
      --defenseclaw) [[ $# -ge 2 && -n $2 ]] || die "--defenseclaw needs a value"; DC_CMD=$2; shift 2 ;;
      --expect-upn) EXPECT_UPN=1; shift ;;
      --skip-defenseclaw) SKIP_DC=1; shift ;;
      -h | --help) usage; exit 0 ;;
      *) usage >&2; die "unknown option: $1" ;;
    esac
  done
  ((${#USERS[@]} > 0)) || { usage >&2; die "give at least one --user"; }
  local u
  for u in "${USERS[@]}"; do
    [[ $u =~ ^[A-Za-z0-9._@-]+$ ]] || die "unsafe user name: $u"
  done
  [[ $DOMAIN =~ ^[A-Za-z0-9_-]+$ ]] || die "unsafe --domain"
  [[ -z $EXPECT_GROUP || $EXPECT_GROUP =~ ^[A-Za-z0-9._@-]+$ ]] || die "unsafe --expect-group"
  [[ -z $EXPECT_PROFILE || $EXPECT_PROFILE =~ ^[a-z0-9][a-z0-9_-]*$ ]] || die "unsafe --expect-profile"
  [[ -z $CONNECTOR || $CONNECTOR =~ ^[A-Za-z0-9_-]+$ ]] || die "unsafe --connector"
  [[ -z $ALLOW_GROUP || $ALLOW_GROUP =~ ^[A-Za-z0-9._-]+$ ]] || die "unsafe --allow-group"
}

check_sssd() {
  echo "SSSD"
  if systemctl is-active sssd > /dev/null 2>&1; then
    pass "sssd service is active"
  else
    fail "sssd service is not active (systemctl status sssd)"
  fi

  if [[ -r $CFG_RULES ]]; then
    if grep -q '^option = ldap_use_ppolicy$' "$CFG_RULES"; then
      pass "this SSSD knows ldap_use_ppolicy (it can bind to Okta)"
    else
      fail "this SSSD has no ldap_use_ppolicy: stock SSSD 2.9 cannot bind to Okta (use SSSD 2.10 or later, or the backport)"
    fi
  else
    skip "ldap_use_ppolicy probe: $CFG_RULES is not readable"
  fi

  if [[ -n $ALLOW_GROUP ]]; then
    if getent group "$ALLOW_GROUP" > /dev/null 2>&1; then
      pass "the allowed group $ALLOW_GROUP resolves"
    else
      fail "the allowed group $ALLOW_GROUP does not resolve, so nobody can sign in: the Okta group needs a gidNumber and members"
    fi
  fi
  if ((EUID != 0)); then
    skip "domain status and sssd.conf checks need root"
    return
  fi
  if ! command -v sssctl > /dev/null; then
    skip "domain status: sssctl is not installed (sssd-tools)"
  elif sssctl domain-status "$DOMAIN" -o 2> /dev/null | grep -q 'Online status: Online'; then
    pass "SSSD domain $DOMAIN is Online"
  else
    fail "SSSD domain $DOMAIN is not Online (sssctl domain-status $DOMAIN -o; journalctl -u sssd). Common causes: wrong bind password, sign-on policy (LDAP 49), no ldap_use_ppolicy = false, no network to the LDAP Interface"
  fi
  local conf=/etc/sssd/sssd.conf stat_out
  if [[ -r $conf ]]; then
    stat_out=$(stat -c '%a %U:%G' "$conf")
    if [[ $stat_out == "600 root:root" ]]; then
      pass "$conf is root:root 0600"
    else
      fail "$conf is $stat_out; SSSD needs root:root 0600 because it holds the bind password"
    fi
    grep -Eq '^[[:space:]]*ldap_use_ppolicy[[:space:]]*=[[:space:]]*false' "$conf" ||
      fail "$conf does not set ldap_use_ppolicy = false (Okta's password-policy response breaks the bind)"
    grep -Eq '^[[:space:]]*ldap_read_rootdse[[:space:]]*=[[:space:]]*authenticated' "$conf" ||
      fail "$conf does not set ldap_read_rootdse = authenticated (Okta refuses the anonymous root DSE read)"
  fi
}

check_user() {
  local user=$1 line groups
  echo "User $user"
  if line=$(getent passwd "$user"); then
    IFS=: read -r _ _ uid gid _ home _ <<< "$line"
    pass "getent passwd: uid $uid, gid $gid, home $home"
  else
    fail "getent passwd $user finds nothing. Check: the domain is Online; the Okta user has uidNumber, gidNumber and unixUsername; the bind user can read users (custom role); the uid is inside min_id..max_id"
    return
  fi
  if groups=$(id -Gn "$user" 2> /dev/null); then
    info "groups: $groups"
    if [[ -n $EXPECT_GROUP ]]; then
      if [[ " $groups " == *" $EXPECT_GROUP "* ]]; then
        pass "id -Gn lists $EXPECT_GROUP"
      else
        fail "id -Gn does not list $EXPECT_GROUP. The Okta group needs a gidNumber and the user must be a member; SSSD caches entries for entry_cache_timeout (sss_cache -E refreshes them)"
      fi
    fi
  else
    fail "id -Gn $user failed"
  fi
  if ((EXPECT_UPN)); then
    check_upn "$user"
  fi
  if ((SKIP_DC == 0)); then
    check_profile "$user"
  fi
}

check_upn() {
  local user=$1 out
  if ((EUID != 0)); then
    skip "InfoPipe userPrincipalName needs root"
    return
  fi
  if ! command -v dbus-send > /dev/null; then
    skip "InfoPipe userPrincipalName: dbus-send is not installed"
    return
  fi
  out=$(dbus-send --system --print-reply --dest=org.freedesktop.sssd.infopipe /org/freedesktop/sssd/infopipe \
    org.freedesktop.sssd.infopipe.GetUserAttr "string:$user" array:string:userPrincipalName 2>&1) || true
  if grep -Eq 'string "[^"]+@[^"]+"' <<< "$out"; then
    pass "InfoPipe returns a userPrincipalName: $(grep -Eo 'string "[^"]+@[^"]+"' <<< "$out" | head -1 | cut -d'"' -f2)"
  else
    fail "InfoPipe returns no userPrincipalName. Add ldap_user_principal = uid to the domain and user_attributes = +mail, +userPrincipalName to [ifp] (install-sssd-okta.sh --map-upn), then sss_cache -E and restart sssd"
  fi
}

# explain_json prints the gateway's answer for one user as JSON, or returns 1.
explain_json() {
  local user=$1 args=()
  local base=${DC_CMD##*/}
  if [[ $base == defenseclaw-gateway ]]; then
    args=(enterprise linux profile-explain --user "$user")
    [[ -n $CONNECTOR ]] && args+=(--connector "$CONNECTOR")
    "$DC_CMD" "${args[@]}"
  else
    args=(guardrail profile explain --user "$user" --json)
    [[ -n $CONNECTOR ]] && args+=(--connector "$CONNECTOR")
    "$DC_CMD" "${args[@]}"
  fi
}

detect_defenseclaw() {
  [[ -n $DC_CMD ]] && return 0
  if ((EUID == 0)) && [[ -x $MANAGED_GATEWAY ]]; then
    DC_CMD=$MANAGED_GATEWAY
  elif command -v defenseclaw > /dev/null; then
    DC_CMD=$(command -v defenseclaw)
  fi
  [[ -n $DC_CMD ]]
}

check_profile() {
  local user=$1 out summary
  if [[ -z $DC_CMD ]]; then
    skip "profile check: no DefenseClaw found (run as root on a managed host, or as the user on a per-user install)"
    return
  fi
  if ! command -v python3 > /dev/null; then
    skip "profile check: python3 is needed to read the answer"
    return
  fi
  if ! out=$(explain_json "$user" 2>&1); then
    fail "DefenseClaw could not explain $user: $(head -c 300 <<< "$out" | tr '\n' ' ')"
    return
  fi
  if ! summary=$(python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except ValueError:
    print("unreadable")
    sys.exit(0)
s = d.get("subject") or {}
print("|".join([
    "ok", str(d.get("profiles_configured")), d.get("profile") or "", d.get("match") or "",
    d.get("matched_group") or "", str(s.get("group_count", 0)), d.get("lookup_error") or "",
    "; ".join(d.get("warnings") or []),
]))' <<< "$out"); then
    fail "could not read DefenseClaw's answer"
    return
  fi
  if [[ $summary == unreadable ]]; then
    fail "DefenseClaw's answer for $user is not JSON: $(head -c 200 <<< "$out" | tr '\n' ' ')"
    return
  fi
  local _ok configured profile match matched groups lookup_error warnings
  IFS='|' read -r _ok configured profile match matched groups lookup_error warnings <<< "$summary"
  if [[ -n $lookup_error ]]; then
    fail "DefenseClaw's directory lookup for $user failed: $lookup_error"
    return
  fi
  if [[ $configured != True ]]; then
    skip "no guardrail profiles are configured, so guardrail.* applies to $user"
    return
  fi
  info "DefenseClaw: profile ${profile:-none}, match ${match:-none}${matched:+ ($matched)}, $groups group(s) seen"
  [[ -n $warnings ]] && info "warnings: $warnings"
  if [[ -n $EXPECT_PROFILE ]]; then
    if [[ $profile == "$EXPECT_PROFILE" ]]; then
      pass "DefenseClaw picks profile $EXPECT_PROFILE for $user"
    else
      fail "DefenseClaw picks profile '${profile:-none}' for $user, expected $EXPECT_PROFILE (match ${match:-none}). Compare the group spelling in profile_assignments with id -Gn"
    fi
  elif [[ $match == default_lookup_failed ]]; then
    fail "DefenseClaw could not look up $user and used the default profile (default_lookup_failed)"
  else
    pass "DefenseClaw resolved $user to profile ${profile:-none} (match ${match:-none})"
  fi
}

main() {
  parse_args "$@"
  if ((SKIP_DC == 0)); then
    detect_defenseclaw || true
  fi
  check_sssd
  local user
  for user in "${USERS[@]}"; do
    check_user "$user"
  done
  echo
  printf 'Result: %d passed, %d failed, %d skipped\n' "$PASS" "$FAILED" "$SKIPPED"
  ((FAILED == 0))
}

main "$@"
