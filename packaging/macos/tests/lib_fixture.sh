#!/usr/bin/env bash
# Shared fixture for driving install.sh and uninstall.sh end to end,
# unprivileged, against a fixture machine root. Sourced by test files;
# not a test file itself.
#
# fixture_bundle -> stdout: a fresh bundle dir laid out like the shipped
# bundle, with:
#   root/   fixture machine root (DC_INSTALLER_TEST_ROOT /
#           DC_UNINSTALL_TEST_ROOT); root/Users holds fixture homes
#   shim/   stub launchctl, dscl and sudo, first on PATH
#   state/  launchctl stub state: one file per loaded label
#   users   "name uid" lines the dscl stub reports
#   dscl-read-fail  names whose `dscl . -read` fails
#
# The launchctl stub keeps a loaded set: `bootstrap system <plist>` loads
# the plist's label, `bootout` unloads it, `print system/<label>` reports
# "state = running" while loaded.

fixture_bundle() {
  local b
  b="$(mktest_tmp)"
  b="$(cd "${b%/}" && pwd -P)"
  mkdir -p "${b}/lib" "${b}/policies/guardrail/default" "${b}/root/Users" "${b}/shim" "${b}/state"
  cp "${PKG_DIR}/install.sh" "${PKG_DIR}/uninstall.sh" "${b}/"
  cp "${PKG_DIR}/lib/installer_lib.sh" "${PKG_DIR}/lib/render-targets.sh" \
     "${PKG_DIR}/lib/scrub_agent_configs.py" "${b}/lib/"
  local p
  for p in com.cisco.secureclient.defenseclaw \
           com.cisco.secureclient.defenseclaw.hook-guardian \
           com.cisco.secureclient.defenseclaw.hook-enumerator; do
    printf '<?xml version="1.0"?><plist><dict><key>Label</key><string>%s</string></dict></plist>\n' \
      "${p}" > "${b}/${p}.plist"
    chmod 0644 "${b}/${p}.plist"
  done
  printf 'rules: []\n' > "${b}/policies/guardrail/default/rules.yaml"
  printf '#!/bin/sh\nexit 0\n' > "${b}/defenseclaw"
  : > "${b}/users"
  : > "${b}/dscl-read-fail"

  cat > "${b}/shim/launchctl" <<EOF
#!/bin/bash
state="${b}/state"
case "\$1" in
  print)
    label="\${2#system/}"
    if [ -e "\${state}/\${label}" ]; then
      printf '%s = {\n\tstate = running\n\tpid = 4242\n}\n' "system/\${label}"
      exit 0
    fi
    exit 113 ;;
  bootstrap)
    label="\$(basename "\$3" .plist)"
    [ -e "\${state}/fail-bootstrap-\${label}" ] && { echo "Bootstrap failed: 5: Input/output error" >&2; exit 5; }
    touch "\${state}/\${label}"; exit 0 ;;
  bootout)
    if [ "\$2" = system ]; then label="\$(basename "\$3" .plist)"; else label="\${2#system/}"; fi
    [ -e "\${state}/stuck-\${label}" ] && exit 0
    rm -f "\${state}/\${label}"; exit 0 ;;
  *) exit 0 ;;
esac
EOF
  cat > "${b}/shim/dscl" <<EOF
#!/bin/bash
users="${b}/users"
if [ "\$2" = -list ]; then
  if [ "\$4" = UniqueID ]; then cat "\${users}"; else awk '{print \$1}' "\${users}"; fi
  exit 0
fi
if [ "\$2" = -read ]; then
  name="\${3#/Users/}"
  grep -qx "\${name}" "${b}/dscl-read-fail" && exit 1
  grep -q "^\${name} " "\${users}" || exit 56
  case "\$4" in
    NFSHomeDirectory) echo "NFSHomeDirectory: ${b}/root/Users/\${name}" ;;
    PrimaryGroupID) echo "PrimaryGroupID: \$(id -g)" ;;
    "") echo "RecordName: \${name}" ;;
  esac
  exit 0
fi
exit 0
EOF
  # sudo -u USER CMD...: run CMD as the caller, flagged so a stub scrub
  # binary can tell a per-user run from the root retry.
  cat > "${b}/shim/sudo" <<'EOF'
#!/bin/bash
while [ $# -gt 0 ]; do
  case "$1" in
    -n) shift ;;
    -u) DC_TEST_RUN_AS="$2"; export DC_TEST_RUN_AS; shift 2 ;;
    *) break ;;
  esac
done
exec "$@"
EOF
  chmod 0755 "${b}/shim/"* "${b}/install.sh" "${b}/uninstall.sh" "${b}/defenseclaw" \
    "${b}/lib/scrub_agent_configs.py"
  printf '%s\n' "${b}"
}

# fixture_add_user BUNDLE NAME UID: register a dscl user with a home.
fixture_add_user() {
  local b="$1" name="$2" uid="$3"
  printf '%s %s\n' "${name}" "${uid}" >> "${b}/users"
  mkdir -p "${b}/root/Users/${name}"
  chmod 0755 "${b}/root/Users/${name}"
}

# fixture_install BUNDLE [ARGS ...]
fixture_install() {
  local b="$1"; shift
  DC_INSTALLER_SKIP_ROOT_CHECK=1 DC_INSTALLER_TEST_ROOT="${b}/root" \
    DC_RETRY_SLEEP=0 DC_INSTALLER_GATEWAY_WAIT_SECONDS="${DC_TEST_GATEWAY_WAIT:-2}" \
    PATH="${b}/shim:${PATH}" "${b}/install.sh" "$@"
}

# fixture_uninstall BUNDLE [ARGS ...]
fixture_uninstall() {
  local b="$1"; shift
  DC_UNINSTALL_SKIP_ROOT_CHECK=1 DC_UNINSTALL_TEST_ROOT="${b}/root" \
    DC_RETRY_SLEEP=0 PATH="${b}/shim:${PATH}" "${b}/uninstall.sh" "$@"
}

# fixture_cleanup BUNDLE: clear flags so the runner's rm -rf succeeds.
fixture_cleanup() {
  chflags -R nouchg,nouappnd "$1" 2>/dev/null || true
  chmod -R u+w "$1" 2>/dev/null || true
}
