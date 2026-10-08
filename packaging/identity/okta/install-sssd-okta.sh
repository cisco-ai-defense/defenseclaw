#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# install-sssd-okta.sh - make a RHEL-family host read Okta users and groups
# through the Okta LDAP Interface with SSSD.
#
# Each step is skipped when it is already done, so a second run with the same
# options changes nothing. The script:
#   1. checks the host: root, RHEL family, the SSSD packages, and that this
#      SSSD can talk to Okta (option ldap_use_ppolicy; stock SSSD 2.9 cannot)
#   2. renders sssd-okta.conf.tmpl, checks it with `sssctl config-check`, and
#      tests the bind user against Okta when ldapsearch is installed
#   3. installs /etc/sssd/sssd.conf (root, mode 0600; the previous file is
#      kept as sssd.conf.bak-<time>) and restarts SSSD when the file changed
#   4. selects the authselect sssd profile with home directories
#   5. writes an sshd drop-in so members of the allowed group can sign in
#      with their Okta password
#
# It never calls the Okta API (see okta-ldap-setup.py for the Okta side) and
# never prints the bind password. The password comes from a file, from
# OKTA_BIND_PASSWORD or from a prompt, never from the command line.
#
# Exit codes: 0 done or nothing to do, 1 a step failed, 2 bad arguments,
# 3 the host cannot be configured (not RHEL family, missing packages, or an
# SSSD that cannot bind to Okta).

set -euo pipefail

SELF=$(basename "$0")
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
TEMPLATE="$HERE/sssd-okta.conf.tmpl"
CONF=/etc/sssd/sssd.conf
SSHD_DROPIN=/etc/ssh/sshd_config.d/45-okta-ldap.conf
MARKER="Managed by DefenseClaw packaging/identity/okta"
CFG_RULES=${OKTA_KIT_SSSD_CFG_RULES:-/usr/share/sssd/cfg_rules.ini}

ORG="" OKTA_DOMAIN="okta.com" LDAP_HOST="" BASE_DN="" BIND_LOGIN="" PW_FILE="" ALLOW_GROUP=""
DOMAIN="okta" ID_MIN=1710000 ID_MAX=1729999 ENTRY_CACHE_TIMEOUT=600
CA_BUNDLE="/etc/pki/tls/certs/ca-bundle.crt"
MAP_UPN=0 NO_SSHD=0 NO_PAM=0 INSTALL_PACKAGES=0 SKIP_BIND_TEST=0 FORCE=0 DRY_RUN=0
RENDER_ONLY=""
PASSWORD=""
WORK=""

usage() {
  cat <<USAGE
Usage: $SELF --org NAME --bind-login LOGIN --allow-group GROUP [options]

Configure SSSD and sshd on a RHEL-family host for the Okta LDAP Interface.

Required:
  --org NAME                Okta org sub-domain: "example" for example.okta.com.
                            Not needed when --ldap-host and --base-dn are given.
  --bind-login LOGIN        Okta login of the bind user SSSD reads with
  --allow-group GROUP       Okta group (with a gidNumber) whose members may sign
                            in. It is also the sshd Match Group.

Options:
  --bind-password-file FILE File holding the bind user's password (mode 0600 or
                            0400). Otherwise OKTA_BIND_PASSWORD, otherwise a prompt.
  --okta-domain DOMAIN      okta.com (default). Only okta.com was tested; for
                            another Okta domain also check --ldap-host and --base-dn.
  --ldap-host HOST          LDAP Interface host (default <org>.ldap.<okta-domain>)
  --base-dn DN              Base DN (default dc=<org>,dc=okta,dc=com)
  --domain NAME             SSSD domain name (default okta)
  --id-min N --id-max N     SSSD ID range (default 1710000 to 1729999). It must
                            hold every uidNumber and gidNumber you set in Okta.
  --entry-cache-timeout S   Seconds SSSD caches an entry (default 600)
  --ca-bundle FILE          CA bundle that signs the Okta certificate
                            (default /etc/pki/tls/certs/ca-bundle.crt)
  --map-upn                 Report the Okta login as the user principal name
                            (standalone enterprise profile only)
  --no-sshd                 Do not write the sshd drop-in
  --no-pam                  Do not run authselect or enable oddjobd
  --install-packages        dnf install missing packages instead of stopping
  --skip-bind-test          Do not test the bind user with ldapsearch
  --render-only FILE        Write the rendered config to FILE (mode 0600),
                            check it, and change nothing else. Works on any Linux.
  --dry-run                 Show what would change, change nothing
  --force                   Replace an sssd.conf this script did not write or
                            one with other SSSD domains; also let authselect
                            replace a modified profile
  -h, --help                Show this help

Exit codes: 0 done or nothing to do, 1 a step failed, 2 bad arguments,
3 the host cannot be configured.
USAGE
}

log() { printf '%s\n' "$*"; }
warn() { printf '%s: warning: %s\n' "$SELF" "$*" >&2; }
fail() {
  local rc=$1
  shift
  printf '%s: error: %s\n' "$SELF" "$*" >&2
  exit "$rc"
}

cleanup() {
  if [[ -n $WORK && -d $WORK ]]; then
    find "$WORK" -type f -exec shred -u {} + 2> /dev/null || true
    rm -rf -- "$WORK"
  fi
}
trap cleanup EXIT

# act runs a command, or only says it would in --dry-run.
act() {
  if ((DRY_RUN)); then
    log "  [dry-run] would run: $*"
  else
    "$@"
  fi
}

need_value() {
  [[ $# -ge 2 && -n $2 ]] || fail 2 "$1 needs a value"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case $1 in
      --org) need_value "$@"; ORG=$2; shift 2 ;;
      --okta-domain) need_value "$@"; OKTA_DOMAIN=$2; shift 2 ;;
      --ldap-host) need_value "$@"; LDAP_HOST=$2; shift 2 ;;
      --base-dn) need_value "$@"; BASE_DN=$2; shift 2 ;;
      --bind-login) need_value "$@"; BIND_LOGIN=$2; shift 2 ;;
      --bind-password-file) need_value "$@"; PW_FILE=$2; shift 2 ;;
      --allow-group) need_value "$@"; ALLOW_GROUP=$2; shift 2 ;;
      --domain) need_value "$@"; DOMAIN=$2; shift 2 ;;
      --id-min) need_value "$@"; ID_MIN=$2; shift 2 ;;
      --id-max) need_value "$@"; ID_MAX=$2; shift 2 ;;
      --entry-cache-timeout) need_value "$@"; ENTRY_CACHE_TIMEOUT=$2; shift 2 ;;
      --ca-bundle) need_value "$@"; CA_BUNDLE=$2; shift 2 ;;
      --render-only) need_value "$@"; RENDER_ONLY=$2; shift 2 ;;
      --map-upn) MAP_UPN=1; shift ;;
      --no-sshd) NO_SSHD=1; shift ;;
      --no-pam) NO_PAM=1; shift ;;
      --install-packages) INSTALL_PACKAGES=1; shift ;;
      --skip-bind-test) SKIP_BIND_TEST=1; shift ;;
      --dry-run) DRY_RUN=1; shift ;;
      --force) FORCE=1; shift ;;
      -h | --help) usage; exit 0 ;;
      *) usage >&2; fail 2 "unknown option: $1" ;;
    esac
  done
}

validate_args() {
  [[ -n $BIND_LOGIN ]] || fail 2 "--bind-login is required"
  [[ -n $ALLOW_GROUP ]] || fail 2 "--allow-group is required"
  [[ $BIND_LOGIN =~ ^[A-Za-z0-9._@+-]+$ ]] || fail 2 "--bind-login may hold only letters, digits and . _ @ + -"
  [[ $ALLOW_GROUP =~ ^[A-Za-z0-9._-]+$ ]] || fail 2 "--allow-group may hold only letters, digits and . _ -"
  [[ $DOMAIN =~ ^[A-Za-z0-9_-]+$ ]] || fail 2 "--domain may hold only letters, digits, _ and -"
  [[ $ID_MIN =~ ^[0-9]+$ && $ID_MAX =~ ^[0-9]+$ ]] || fail 2 "--id-min and --id-max must be numbers"
  ((ID_MIN < ID_MAX)) || fail 2 "--id-min must be below --id-max"
  [[ $ENTRY_CACHE_TIMEOUT =~ ^[0-9]+$ ]] || fail 2 "--entry-cache-timeout must be a number of seconds"
  [[ $CA_BUNDLE =~ ^/[A-Za-z0-9._/+-]+$ ]] || fail 2 "--ca-bundle must be an absolute path"
  [[ $OKTA_DOMAIN =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || fail 2 "--okta-domain must be a domain such as okta.com"
  if [[ -z $LDAP_HOST || -z $BASE_DN ]]; then
    [[ -n $ORG ]] || fail 2 "--org is required unless --ldap-host and --base-dn are both given"
    [[ $ORG =~ ^[A-Za-z0-9-]+$ ]] || fail 2 "--org must be the org sub-domain, for example example"
  fi
  if [[ -z $LDAP_HOST ]]; then
    LDAP_HOST="$ORG.ldap.$OKTA_DOMAIN"
  fi
  if [[ -z $BASE_DN ]]; then
    local part dn="dc=$ORG"
    IFS=. read -ra parts <<< "$OKTA_DOMAIN"
    for part in "${parts[@]}"; do dn+=",dc=$part"; done
    BASE_DN=$dn
  fi
  [[ $LDAP_HOST =~ ^[A-Za-z0-9.-]+$ ]] || fail 2 "--ldap-host must be a host name"
  [[ $BASE_DN =~ ^[A-Za-z0-9=,.-]+$ ]] || fail 2 "--base-dn may hold only letters, digits and = , . -"
  if [[ -n $RENDER_ONLY ]]; then
    ((DRY_RUN == 0)) || fail 2 "--render-only and --dry-run cannot be combined"
    [[ $RENDER_ONLY == /* ]] || fail 2 "--render-only needs an absolute path"
  fi
}

# fetch_password fills PASSWORD from a file, the environment or a prompt.
fetch_password() {
  if [[ -n $PW_FILE ]]; then
    [[ -f $PW_FILE && -r $PW_FILE ]] || fail 2 "cannot read the password file $PW_FILE"
    local mode
    mode=$(stat -c '%a' "$PW_FILE")
    [[ $mode == 600 || $mode == 400 ]] || fail 2 "the password file $PW_FILE must be mode 0600 or 0400 (it is $mode)"
    PASSWORD=$(< "$PW_FILE")
  elif [[ -n ${OKTA_BIND_PASSWORD:-} ]]; then
    PASSWORD=$OKTA_BIND_PASSWORD
  elif [[ -t 0 && ! ($DRY_RUN == 1) ]]; then
    read -rsp "Password of the Okta bind user $BIND_LOGIN: " PASSWORD < /dev/tty
    printf '\n' >&2
  fi
  unset OKTA_BIND_PASSWORD
  if [[ -n $PASSWORD ]]; then
    [[ $PASSWORD != *$'\n'* && $PASSWORD != *$'\r'* ]] || fail 2 "the bind password must be one line"
  fi
}

mask() {
  sed -E 's/^([[:space:]]*ldap_default_authtok[[:space:]]*=[[:space:]]*).*/\1<redacted>/' "$1"
}

os_family_ok() {
  [[ -r /etc/os-release ]] || return 1
  local id="" id_like=""
  # shellcheck disable=SC1091
  id=$(. /etc/os-release && printf '%s' "${ID:-}")
  # shellcheck disable=SC1091
  id_like=$(. /etc/os-release && printf '%s' "${ID_LIKE:-}")
  [[ " $id $id_like " =~ \ (rhel|centos|fedora|rocky|almalinux|ol)\  ]]
}

ppolicy_supported() {
  [[ -r $CFG_RULES ]] || return 2
  grep -q '^option = ldap_use_ppolicy$' "$CFG_RULES"
}

check_host() {
  log "Checking the host"
  os_family_ok || fail 3 "this script configures RHEL-family hosts (tested on RHEL 9.8). On another Linux use --render-only FILE and install the file by hand."
  if ((EUID != 0)) && ((DRY_RUN == 0)); then
    fail 1 "run as root (or use --dry-run or --render-only)"
  fi
  local missing=() pkg
  local need=(sssd sssd-ldap sssd-dbus sssd-tools authselect)
  ((NO_PAM)) || need+=(oddjob-mkhomedir)
  for pkg in "${need[@]}"; do
    rpm -q "$pkg" > /dev/null 2>&1 || missing+=("$pkg")
  done
  if ((${#missing[@]} > 0)); then
    if ((INSTALL_PACKAGES)); then
      act dnf -y install "${missing[@]}"
    else
      fail 3 "missing packages: ${missing[*]}. Install them (dnf install ${missing[*]}) or run again with --install-packages."
    fi
  fi
  ppolicy_check
  log "  ok: RHEL family, packages present"
}

# ppolicy_check stops the run when this host's SSSD cannot bind to Okta. With
# "warn" (--render-only) it only warns, because the file may be for another host.
ppolicy_check() {
  local rc=0 msg
  ppolicy_supported || rc=$?
  if ((rc == 0)); then
    log "  ok: this SSSD knows ldap_use_ppolicy"
  elif ((rc == 1)); then
    msg="this SSSD cannot bind to Okta: it has no ldap_use_ppolicy option (SSSD 2.9 as shipped in RHEL 9). Use SSSD 2.10 or later, or build the 2.9 package with the backport (build-sssd-ppolicy-backport.sh)."
    if [[ ${1:-} == warn ]]; then warn "$msg"; else fail 3 "$msg"; fi
  else
    warn "cannot read $CFG_RULES; sssctl config-check below decides whether this SSSD knows ldap_use_ppolicy"
  fi
}

render() {
  local out=$1 pw=$2
  [[ -r $TEMPLATE ]] || fail 1 "template not found: $TEMPLATE"
  command -v python3 > /dev/null || fail 3 "python3 is required to render the template"
  local ifp="+mail" upn_flag=0
  if ((MAP_UPN)); then
    ifp="+mail, +userPrincipalName"
    upn_flag=1
  fi
  OKTA_KIT_DOMAIN=$DOMAIN OKTA_KIT_IFP_ATTRS=$ifp OKTA_KIT_ALLOW_GROUP=$ALLOW_GROUP \
    OKTA_KIT_LDAP_URI="ldaps://$LDAP_HOST:636" OKTA_KIT_CA_BUNDLE=$CA_BUNDLE \
    OKTA_KIT_BIND_DN="uid=$BIND_LOGIN,$BASE_DN" OKTA_KIT_BIND_PASSWORD=$pw OKTA_KIT_BASE_DN=$BASE_DN \
    OKTA_KIT_ID_MIN=$ID_MIN OKTA_KIT_ID_MAX=$ID_MAX OKTA_KIT_ENTRY_CACHE_TIMEOUT=$ENTRY_CACHE_TIMEOUT \
    OKTA_KIT_UPN=$upn_flag \
    python3 - "$TEMPLATE" "$out" << 'PY'
import os
import re
import sys
import tempfile

template, out = sys.argv[1:3]
prefix = "OKTA_KIT_"
values = {k[len(prefix):]: v for k, v in os.environ.items() if k.startswith(prefix)}
# Never let a remote Okta group shadow a local group used by sudoers or PAM.
with open("/etc/group", encoding="utf-8", errors="replace") as groups:
    local_groups = {line.partition(":")[0] for line in groups if ":" in line}
values["FILTER_GROUPS"] = ", ".join(sorted(local_groups | {"root", "wheel", "sudo", "adm"}))
keep_upn = values.get("UPN") == "1"
text = []
for line in open(template, encoding="ascii"):
    if line.startswith("@UPN@"):
        if not keep_upn:
            continue
        line = line[len("@UPN@"):]
    text.append(line)
body = "".join(text)
unknown = sorted({m for m in re.findall(r"@([A-Z_]+)@", body) if m not in values})
if unknown:
    sys.exit("template placeholders without a value: " + ", ".join(unknown))
# One pass, so a value that looks like a placeholder is never expanded again.
body = re.sub(r"@([A-Z_]+)@", lambda m: values[m.group(1)], body)
fd, temporary = tempfile.mkstemp(prefix=".sssd-okta-", dir=os.path.dirname(out) or ".")
try:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(body)
    os.replace(temporary, out)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PY
}

config_check() {
  local file=$1
  if ! command -v sssctl > /dev/null; then
    warn "sssctl is not installed; skipping the config check"
    return 0
  fi
  if ((EUID != 0)); then
    log "  skipped: sssctl config-check needs root"
    return 0
  fi
  local out issues
  if ! out=$(sssctl config-check -c "$file" 2>&1); then
    printf '%s\n' "$out" >&2
    fail 1 "sssctl config-check rejected the rendered config"
  fi
  issues=$(sed -n 's/^Issues identified by validators: \([0-9][0-9]*\).*/\1/p' <<< "$out")
  if [[ -n $issues && $issues != 0 ]]; then
    printf '%s\n' "$out" >&2
    fail 1 "sssctl config-check found issues in the rendered config"
  fi
  log "  ok: sssctl config-check found no issues"
}

bind_test() {
  if ((SKIP_BIND_TEST)); then
    warn "bind was not tested (--skip-bind-test); an initially Online SSSD domain can later go Offline"
    return 0
  fi
  if [[ -z $PASSWORD ]]; then
    warn "bind was not tested (no password given); an initially Online SSSD domain can later go Offline"
    return 0
  fi
  if ! command -v ldapsearch > /dev/null; then
    warn "bind was not tested; install openldap-clients to test the bind user before SSSD changes"
    return 0
  fi
  printf '%s' "$PASSWORD" > "$WORK/bind.pw"
  local out rc=0 count
  # Okta's LDAP Interface does not implement the "who am I" operation, so search for users instead.
  out=$(LDAPTLS_CACERT=$CA_BUNDLE ldapsearch -LLL -x -H "ldaps://$LDAP_HOST:636" -D "uid=$BIND_LOGIN,$BASE_DN" \
    -y "$WORK/bind.pw" -o nettimeout=15 -b "ou=users,$BASE_DN" -z 3 '(objectClass=inetOrgPerson)' dn 2>&1) || rc=$?
  # ldapsearch exits 4 when the size limit cut the list short, which is what -z 3 asks for.
  if ((rc != 0 && rc != 4)); then
    printf '%s\n' "$out" | head -5 >&2
    case $out in
      *"sign on policy"*) warn "Okta's sign-on policy for the LDAP Interface blocks this user. Give it a password-only rule (okta-ldap-setup.py signon-policy)." ;;
      *"Invalid credentials"*) warn "Okta refused the login or password of the bind user." ;;
      *"Can't contact"*) warn "cannot reach $LDAP_HOST:636. Check DNS, the firewall and the CA bundle $CA_BUNDLE." ;;
    esac
    fail 1 "the bind test failed; /etc/sssd/sssd.conf was not changed"
  fi
  count=$(grep -c '^dn:' <<< "$out" || true)
  if ((count >= 2)); then
    log "  ok: the bind user can bind to ldaps://$LDAP_HOST:636 and read users"
  else
    warn "the bind user binds but finds $count user entry: it needs a custom Okta admin role that reads users and groups (okta-ldap-setup.py bind-role)"
  fi
}

install_conf() {
  local rendered=$1
  if ((EUID != 0)) && [[ ! -r $CONF ]]; then
    log "  cannot read $CONF without root; a dry run as root compares it with the new config"
    return 0
  fi
  if [[ -e $CONF ]]; then
    if cmp -s "$rendered" "$CONF"; then
      log "  unchanged: $CONF already has this configuration"
      CONF_CHANGED=0
      return 0
    fi
    if ! grep -q "$MARKER" "$CONF" && ((FORCE == 0)); then
      fail 3 "$CONF was not written by this script (it has no '$MARKER' line). Nothing was changed. Rerun with --force to replace it; the old file is kept as a backup."
    fi
    # The marker identifies the kit, but an administrator may have joined
    # another SSSD domain since the first run. Never drop that domain implicitly.
    local other_domains
    other_domains=$(python3 - "$CONF" "$DOMAIN" <<'PYCONF'
import configparser
import sys

config = configparser.ConfigParser(interpolation=None, strict=False)
config.read(sys.argv[1])
wanted = sys.argv[2]
listed = {name.strip() for name in config.get("sssd", "domains", fallback="").split(",") if name.strip()}
sections = {name[7:] for name in config.sections() if name.startswith("domain/")}
print(", ".join(sorted((listed | sections) - {wanted})))
PYCONF
)
    if [[ -n $other_domains ]] && ((FORCE == 0)); then
      fail 3 "$CONF also configures SSSD domain(s) $other_domains. No changes were made. Merge the new Okta settings into the existing file manually, or use --force to replace all domains."
    fi
    if ((DRY_RUN)); then
      log "  would replace $CONF; changes (password hidden):"
      diff -u <(mask "$CONF") <(mask "$rendered") | sed 's/^/    /' || true
      CONF_CHANGED=1
      return 0
    fi
    local backup
    backup="$CONF.bak-$(date -u +%Y%m%dT%H%M%SZ)"
    cp -p "$CONF" "$backup"
    log "  backup: $backup (restore this exact file to undo this run)"
    PREVIOUS_SSSD_CONF=$backup
  elif ((DRY_RUN)); then
    log "  would create $CONF (mode 0600, root); undo by removing this file"
    CONF_CHANGED=1
    return 0
  fi
  [[ -d $(dirname "$CONF") ]] || install -d -m 0711 -o root -g root "$(dirname "$CONF")"
  install -m 0600 -o root -g root "$rendered" "$CONF"
  restorecon "$CONF" > /dev/null 2>&1 || true
  CONF_CHANGED=1
  log "  installed: $CONF"
}

authselect_profile_check() {
  ((NO_PAM)) && return 0
  local current
  current=$(authselect current --raw 2> /dev/null || true)
  if [[ -n $current && $current != sssd* ]] && ((FORCE == 0)); then
    fail 3 "authselect uses '$current'; replacing a custom or winbind profile removes its PAM features. Review the change and rerun with --force, or use --no-pam."
  fi
}

pam_step() {
  if ((NO_PAM)); then
    log "  skipped: authselect and oddjobd (--no-pam)"
    return 0
  fi
  authselect_profile_check
  local current="" features=() force=()
  current=$(authselect current --raw 2> /dev/null || true)
  log "  previous authselect profile: ${current:-none} (restore this to undo the install)"
  if [[ $current == sssd* && $current == *with-mkhomedir* ]]; then
    log "  unchanged: authselect already uses sssd with-mkhomedir"
  else
    read -ra features <<< "${current#sssd}"
    [[ $current == sssd* ]] || features=()
    ((FORCE)) && force=(--force)
    act authselect select sssd "${features[@]}" with-mkhomedir "${force[@]}" ||
      fail 1 "authselect refused to change the profile (it may be customized); rerun with --force to replace it"
  fi
  if systemctl is-enabled oddjobd > /dev/null 2>&1 && systemctl is-active oddjobd > /dev/null 2>&1; then
    log "  unchanged: oddjobd is enabled and running"
  else
    act systemctl enable --now oddjobd
  fi
}

sshd_step() {
  if ((NO_SSHD)); then
    log "  skipped: sshd drop-in (--no-sshd)"
    return 0
  fi
  local want="$WORK/sshd-dropin.conf"
  cat > "$want" << DROPIN
# $MARKER/install-sssd-okta.sh.
# Members of $ALLOW_GROUP sign in with their Okta password (sshd, PAM, SSSD,
# LDAP bind to Okta). Everyone else keeps the sshd default.
Match Group $ALLOW_GROUP
    PasswordAuthentication yes
    KbdInteractiveAuthentication yes
Match all
DROPIN
  if [[ -r $SSHD_DROPIN ]] && cmp -s "$want" "$SSHD_DROPIN"; then
    log "  unchanged: $SSHD_DROPIN"
    return 0
  fi
  if ((DRY_RUN)); then
    log "  would write $SSHD_DROPIN:"
    sed 's/^/    /' "$want"
    return 0
  fi
  local backup=""
  if [[ -e $SSHD_DROPIN ]]; then
    backup="$SSHD_DROPIN.bak-$(date -u +%Y%m%dT%H%M%SZ)"
    cp -p "$SSHD_DROPIN" "$backup"
    log "  backup: $backup (move it out of sshd_config.d; sshd only reads *.conf)"
  fi
  [[ -d $(dirname "$SSHD_DROPIN") ]] || install -d -m 0755 -o root -g root "$(dirname "$SSHD_DROPIN")"
  install -m 0600 -o root -g root "$want" "$SSHD_DROPIN"
  restorecon "$SSHD_DROPIN" > /dev/null 2>&1 || true
  if ! sshd -t 2> "$WORK/sshd-test.err"; then
    local rejected
    rejected=$(head -1 "$WORK/sshd-test.err")
    cat "$WORK/sshd-test.err" >&2
    if [[ -n $backup ]]; then cp -p "$backup" "$SSHD_DROPIN"; else rm -f -- "$SSHD_DROPIN"; fi
    fail 1 "sshd -t rejected a configuration file: $rejected. The new drop-in was rolled back; $CONF was already replaced (previous: ${PREVIOUS_SSSD_CONF:-none, this was a first install})."
  fi
  systemctl reload sshd
  log "  installed: $SSHD_DROPIN (sshd reloaded; open sessions stay)"
}

wait_online() {
  local i
  for ((i = 0; i < 25; i++)); do
    if sssctl domain-status "$DOMAIN" -o 2> /dev/null | grep -q 'Online status: Online'; then
      # SSSD can report Online before its first LDAP connection attempt.
      sleep 25
      if sssctl domain-status "$DOMAIN" -o 2> /dev/null | grep -q 'Online status: Online'; then
        return 0
      fi
    fi
    sleep 1
  done
  return 1
}

# check_allow_group warns when nobody could sign in because the allowed group does not resolve.
check_allow_group() {
  if getent group "$ALLOW_GROUP" > /dev/null 2>&1; then
    log "  ok: the allowed group $ALLOW_GROUP resolves"
  else
    warn "the allowed group $ALLOW_GROUP does not resolve, so nobody can sign in: give the Okta group a gidNumber and members (okta-ldap-setup.py assign-posix)"
  fi
}

sssd_config_stale() {
  # A previous run may have installed the config and then failed at PAM or sshd.
  # Compare nanoseconds so a rerun in the same second still notices that change.
  local started config_time service_time
  systemctl is-active sssd > /dev/null 2>&1 || return 0
  started=$(systemctl show sssd -p ActiveEnterTimestamp --value 2> /dev/null) || return 0
  config_time=$(date -d "$(stat -c %y "$CONF" 2> /dev/null)" +%s%N 2> /dev/null) || return 0
  service_time=$(date -d "$started" +%s%N 2> /dev/null) || return 0
  ((config_time > service_time))
}

restart_sssd() {
  if ((DRY_RUN)); then
    if ((${CONF_CHANGED:-0})) || sssd_config_stale; then
      log "  would restart sssd and wait for the $DOMAIN domain to be Online"
    fi
    log "  would enable sssd at boot"
    return 0
  fi
  systemctl enable sssd > /dev/null 2>&1
  if ((CONF_CHANGED)) || sssd_config_stale; then
    systemctl restart sssd
    sss_cache -E > /dev/null 2>&1 || true
    if wait_online; then
      log "  ok: sssd restarted, domain $DOMAIN is Online"
      check_allow_group
    else
      sssctl domain-status "$DOMAIN" -o 2>&1 | head -5 >&2 || true
      fail 1 "sssd restarted but the $DOMAIN domain is not Online. Read: journalctl -u sssd -n 50. Previous config: ${PREVIOUS_SSSD_CONF:-none, this was a first install}."
    fi
  elif wait_online; then
    log "  ok: sssd is running and the $DOMAIN domain is Online"
    check_allow_group
  else
    fail 1 "sssd is running but the $DOMAIN domain is not Online; check the bind and journalctl -u sssd. Previous config: ${PREVIOUS_SSSD_CONF:-none, this was a first install}."
  fi
}

CONF_CHANGED=0
PREVIOUS_SSSD_CONF=""

main() {
  umask 077
  parse_args "$@"
  validate_args
  ((DRY_RUN)) && log "Dry run: nothing will be changed."
  WORK=$(mktemp -d "${TMPDIR:-/var/tmp}/okta-kit.XXXXXX")
  chmod 700 "$WORK"

  fetch_password
  local pw=$PASSWORD
  if [[ -z $pw ]]; then
    if ((DRY_RUN)); then
      pw="<bind password>"
    else
      fail 2 "no bind password: use --bind-password-file, OKTA_BIND_PASSWORD or a terminal prompt"
    fi
  fi

  if [[ -n $RENDER_ONLY ]]; then
    log "Rendering $RENDER_ONLY"
    ppolicy_check warn
    render "$RENDER_ONLY" "$pw"
    config_check "$RENDER_ONLY"
    log "Wrote $RENDER_ONLY (mode 0600). Install it as $CONF and restart sssd."
    exit 0
  fi

  check_host
  log "Rendering and checking the config"
  render "$WORK/sssd.conf" "$pw"
  config_check "$WORK/sssd.conf"
  bind_test
  authselect_profile_check
  log "SSSD config ($CONF)"
  install_conf "$WORK/sssd.conf"
  log "PAM and home directories"
  pam_step
  log "sshd"
  sshd_step
  log "SSSD service"
  restart_sssd
  if ((DRY_RUN)); then
    log "Dry run done; nothing was changed."
  else
    log "Done. Check the result with: $HERE/verify-okta-identity.sh --user <posix name> --expect-group <group>"
  fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
