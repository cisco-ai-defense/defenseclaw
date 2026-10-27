#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# Build the macOS standalone managed-enterprise installer package
# (defenseclaw-enterprise-<version>-darwin-arm64.pkg).
#
# The package installs the gateway, hook runtime and sensor helper under
# /opt/cisco/defenseclaw/bin, the standard user's sandbox launcher
# /usr/local/bin/defenseclaw (a link to the gateway) and the launch agents of
# the per-user sandbox daemon in /Library/LaunchAgents; its postinstall runs
#   defenseclaw-gateway enterprise macos ensure --from-package
# which validates the administrator config, creates the _defenseclaw service
# account and LaunchDaemons, activates them in order and rolls back on any
# failure. Deploy it with any tool that installs flat packages. Remove it with
#   sudo /opt/cisco/defenseclaw/bin/defenseclaw-gateway enterprise macos uninstall [--purge]
# Managed packages do not carry optional Fleet source.
# A pinned e2fsprogs build is carried under share/e2fsprogs with its GPL
# notice and source. The managed MicroVM uses it only when neither an explicit
# administrator directory nor a user's own build supplies the tools.
#
# Called by the `packaging-macos-enterprise` Make target.
#
# Usage:
#   scripts/build-macos-enterprise-pkg.sh --version 1.2.3 [--dist-dir dist]
#       [--payload DIR]
#
#   --payload DIR   use prebuilt darwin/arm64 binaries (defenseclaw-gateway,
#                   defenseclaw-hook, defenseclaw-sensor-helper and optionally
#                   defenseclaw-acp) instead of building them.
#
# Signing is optional and off by default:
#   MACOS_APP_SIGN_IDENTITY        "Developer ID Application: ..." codesigns
#                                  the binaries with the hardened runtime;
#                                  "-" uses an ad hoc identity for CI.
#   MACOS_INSTALLER_SIGN_IDENTITY  "Developer ID Installer: ..." signs the
#                                  product archive.
#   MACOS_SIGN_KEYCHAIN            keychain holding both identities.
# Notarize the signed package separately (xcrun notarytool submit ...).

set -euo pipefail

readonly PKG_ID="com.cisco.defenseclaw.enterprise"
readonly INSTALL_BIN="opt/cisco/defenseclaw/bin"
readonly LAUNCHER_DIR="usr/local/bin"
readonly LAUNCH_AGENTS_DIR="Library/LaunchAgents"

VERSION=""
DIST_DIR="dist"
PAYLOAD=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
        --dist-dir) DIST_DIR="${2:?--dist-dir needs a value}"; shift 2 ;;
        --payload) PAYLOAD="${2:?--payload needs a value}"; shift 2 ;;
        -h | --help) sed -n '2,35p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
VERSION="${VERSION#v}"
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.+-][0-9A-Za-z.+-]+)?$ ]]; then
    echo "--version must be a release version such as 1.2.3 (got '${VERSION}')" >&2
    exit 2
fi
if [ "$(uname -s)" != Darwin ]; then
    echo "pkgbuild and productbuild run on macOS only" >&2
    exit 1
fi
for command in pkgbuild productbuild; do
    command -v "$command" >/dev/null || { echo "missing $command (install the Xcode command line tools)" >&2; exit 1; }
done

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$DIST_DIR"
DIST_DIR="$(cd "$DIST_DIR" && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-enterprise-pkg.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
ROOT="$WORK/root"
SCRIPTS="$WORK/scripts"
# The payload's directories install with these modes: /usr/local/bin and
# /Library/LaunchAgents must stay readable whatever umask the builder has.
umask 022
mkdir -p "$ROOT/$INSTALL_BIN" "$SCRIPTS"

binaries=(defenseclaw-gateway defenseclaw-hook defenseclaw-sensor-helper)
if [ -n "$PAYLOAD" ]; then
    for name in "${binaries[@]}" defenseclaw-acp; do
        if [ -f "$PAYLOAD/$name" ]; then
            install -m 0755 "$PAYLOAD/$name" "$ROOT/$INSTALL_BIN/$name"
        elif [ "$name" != defenseclaw-acp ]; then
            echo "payload $PAYLOAD lacks $name" >&2
            exit 1
        fi
    done
else
    build() { # build <output> <package> <ldflags>
        (cd "$REPO_ROOT" && CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 \
            go build -trimpath -buildvcs=false -ldflags "$3" -o "$ROOT/$INSTALL_BIN/$1" "$2")
    }
    # The Makefile passes GIT_COMMIT and BUILD_DATE (GAP-1446): a source tree
    # without .git (git archive) builds with GIT_COMMIT=<sha> on the make line.
    COMMIT="${GIT_COMMIT:-}"
    if [ -z "$COMMIT" ] || [ "$COMMIT" = unknown ]; then
        COMMIT="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    fi
    DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
    version_flags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}"
    build defenseclaw-gateway ./cmd/defenseclaw "$version_flags"
    build defenseclaw-hook ./cmd/defenseclaw-hook "$version_flags"
    build defenseclaw-sensor-helper ./cmd/defenseclaw-sensor-helper "$version_flags"
    build defenseclaw-acp ./cmd/defenseclaw-acp "$version_flags"
fi

# The standard account cannot install Homebrew or Xcode tools. Build these on
# the packaging Mac and carry the complete corresponding source and notice.
# They stay under a root-owned package path and are selected only as fallback.
e2fs_root="$ROOT/opt/cisco/defenseclaw/share/e2fsprogs"
"$REPO_ROOT/scripts/build-macos-e2fsprogs.sh" "$e2fs_root"

# The standard user's sandbox launcher: the gateway under the name defenseclaw
# (internal/cli/launcher.go). A package-owned symlink, so only an installer or
# administrator can change where it points.
mkdir -p "$ROOT/$LAUNCHER_DIR"
ln -s "/$INSTALL_BIN/defenseclaw-gateway" "$ROOT/$LAUNCHER_DIR/defenseclaw"

# The per-user sandbox daemon's launch agents. A changed signed program gets
# a new path as well as a new inode, so launchd cannot reuse an old signature
# decision after an upgrade. The lifecycle renders the same path from the
# installed gateway's SHA-256.
if [ -n "${MACOS_APP_SIGN_IDENTITY:-}" ]; then
    sign_args=(--force)
    # Ad hoc signing lets the disposable macOS CI install lane exercise the
    # same signed-program copy and label path without a release certificate.
    if [ "$MACOS_APP_SIGN_IDENTITY" != - ]; then
        sign_args+=(--timestamp)
    fi
    sign_args+=(--options runtime --sign "$MACOS_APP_SIGN_IDENTITY")
    [ -n "${MACOS_SIGN_KEYCHAIN:-}" ] && sign_args+=(--keychain "$MACOS_SIGN_KEYCHAIN")
    for binary in "$ROOT/$INSTALL_BIN"/* "$e2fs_root/sbin"/*; do
        codesign "${sign_args[@]}" --identifier "com.cisco.defenseclaw.$(basename "$binary")" "$binary"
    done
fi
gateway_digest=$(shasum -a 256 "$ROOT/$INSTALL_BIN/defenseclaw-gateway" | awk '{print $1}')
agent_program="/$INSTALL_BIN/launch-agents/$gateway_digest/defenseclaw-gateway"
install -d -m 0755 "$ROOT/$INSTALL_BIN/launch-agents" "${ROOT}${agent_program%/*}"
cp -p "$ROOT/$INSTALL_BIN/defenseclaw-gateway" "$ROOT$agent_program"

# launchd loads a launch agent
# only when root:wheel owns it and nobody else can write it, which pkgbuild
# --ownership recommended gives (mode 0644 here). The agents load at each
# account's next sign-in; the launcher bootstraps them on demand for an
# account that is already signed in. Each label carries the first 12 digits
# of the gateway's SHA-256 too: macOS keeps the code-signing decision it made
# for a job label, and killed the job of an upgraded program under its old
# label (GAP-0206). The lifecycle names the same label and removes the
# plists of earlier labels (openshell.LaunchAgentLabel).
mkdir -p "$ROOT/$LAUNCH_AGENTS_DIR"
agent_tag=$(printf '%s' "$gateway_digest" | cut -c1-12)
for label in com.cisco.defenseclaw.sandbox com.cisco.defenseclaw.openshell-gateway; do
    agent="$REPO_ROOT/packaging/launchd-standalone/agents/$label.plist"
    [ -f "$agent" ] || { echo "missing $agent" >&2; exit 1; }
    sed -e "s|/$INSTALL_BIN/defenseclaw-gateway|$agent_program|" -e "s|<string>$label</string>|<string>$label.$agent_tag</string>|" \
        "$agent" >"$ROOT/$LAUNCH_AGENTS_DIR/$label.$agent_tag.plist"
    chmod 0644 "$ROOT/$LAUNCH_AGENTS_DIR/$label.$agent_tag.plist"
done

# preinstall refuses before any file lands on a Secure Client host: the two
# deployments share the gateway port and the lifecycle would refuse anyway.
# It also refuses a release below the confirmed signed bundle's floor, and a
# downgrade before the older binaries replace the installed ones unless the
# administrator created the root-owned rollback marker
# /opt/cisco/defenseclaw/lifecycle/allow-downgrade (postinstall consumes it).
# It refuses while a sandbox daemon of DefenseClaw 1.0.3 or older has a
# sandbox running too (the legacy sandbox guard, GAP-0903).
cat >"$SCRIPTS/preinstall" <<'EOF'
#!/bin/sh
if [ -e /opt/cisco/secureclient/defenseclaw ] ||
    ls /Library/LaunchDaemons/com.cisco.secureclient.defenseclaw*.plist >/dev/null 2>&1; then
    echo "DefenseClaw is already managed by Cisco Secure Client on this Mac; the standalone package cannot be installed beside it." >&2
    exit 1
fi
state=/opt/cisco/defenseclaw/lifecycle
package_version="@DC_PKG_VERSION@"
record="$state/deployment.json"
marker="$state/allow-downgrade"
gateway=/opt/cisco/defenseclaw/bin/defenseclaw-gateway
# owner_mode PATH: the owner's uid and the permission bits (octal) of PATH
# itself, not of a symlink's target.
owner_mode() { stat -f '%u %Lp' "$1" 2>/dev/null; }
root_owned() {
    [ -f "$1" ] && [ ! -L "$1" ] && ro_info=$(owner_mode "$1") && [ "${ro_info%% *}" = 0 ]
}
# acl_closed PATH: no access control entry on PATH itself lets another
# account change it. A list that cannot be read is not closed.
acl_closed() {
    t_acl=$(ls -lde "$1" 2>/dev/null) || return 1
    ! printf '%s\n' "$t_acl" | sed 1d | grep -Eq ' allow .*(write|append|add_|delete|chown)'
}
# root_only PATH: PATH itself, not a symlink's target, belongs to root, and
# neither its mode nor an access control entry lets another account write
# it. An owner, mode or access control list that cannot be read is not
# root's.
root_only() {
    t_info=$(owner_mode "$1") || return 1
    case $t_info in
        "0 "[0-7]*) t_mode=${t_info#0 } ;;
        *) return 1 ;;
    esac
    case $t_mode in *[!0-7]*) return 1 ;; esac
    [ $((0$t_mode & 022)) -eq 0 ] || return 1
    acl_closed "$1"
}
# trusted PATH: PATH is a regular file, not a symlink, and only root can
# change what it names. PATH is looked up one entry at a time, as the kernel
# looks it up, following every symlink on the way (its target from / or from
# the folder that holds it): every folder an entry is found in, and the
# file, are root_only, and every symlink belongs to root and no access
# control entry lets another account change it. A check of only the
# folders the path ends in missed the folder that holds a symlink and the
# folders a symlink's target passes through: an account that could write
# one could swap the symlink between the check and the run. t_real is
# then the file PATH names, reached through folders only, and the caller
# runs that file. A symlink that cannot be read, or more than 32 of them,
# is not trusted.
trusted() {
    t_real=
    [ -f "$1" ] && [ ! -L "$1" ] || return 1
    case $1 in /*) ;; *) return 1 ;; esac
    root_only / || return 1
    t_dir=/
    t_rest=$1
    t_hops=0
    while :; do
        case $t_rest in
            /*) t_rest=${t_rest#/}; continue ;;
            "") return 1 ;;
            */*)
                t_name=${t_rest%%/*}
                t_rest=${t_rest#*/}
                t_more=/
                ;;
            *)
                t_name=$t_rest
                t_rest=
                t_more=
                ;;
        esac
        case $t_name in
            .) continue ;;
            ..)
                t_dir=${t_dir%/*}
                t_dir=${t_dir:-/}
                continue
                ;;
        esac
        t_path=${t_dir%/}/$t_name
        if [ -L "$t_path" ]; then
            t_hops=$((t_hops + 1))
            [ "$t_hops" -le 32 ] || return 1
            t_info=$(owner_mode "$t_path") || return 1
            [ "${t_info%% *}" = 0 ] || return 1
            acl_closed "$t_path" || return 1
            t_link=$(readlink "$t_path") || return 1
            case $t_link in
                "") return 1 ;;
                /*) t_dir=/ ;;
            esac
            t_rest=$t_link$t_more$t_rest
            continue
        fi
        root_only "$t_path" || return 1
        if [ -z "$t_more" ] && [ -f "$t_path" ]; then
            t_real=$t_path
            return 0
        fi
        [ -d "$t_path" ] || return 1
        t_dir=$t_path
    done
}
installed=
if root_owned "$record"; then
    installed=$(sed -n 's/.*"product_version": *"\([^"]*\)".*/\1/p' "$record" | head -n 1)
fi
# refuse CODE MESSAGE [SAID]: nothing was changed; stderr shows SAID (MESSAGE
# when there is none). The Installer shows only a
# generic error, so leave the reason in the package result an MDM detection
# or an administrator reads. The result reports the running deployment as
# its own status sees it (GAP-1428: a fixed document said every service was
# down). The fixed document stays the fallback for an installed gateway that
# cannot answer, or is not a root-owned file only root can change (trusted;
# it is not run).
refuse() {
    code=$1 said=${3:-$2}
    message=$(printf '%s' "$2" | tr -d '"\\|&')
    echo "$said" >&2
    umask 077
    result="$state/last-package-result.json"
    error="{\"code\":\"$code\",\"message\":\"$message\"}"
    present=true
    [ -n "$installed" ] || present=false
    if ! { [ -x "$gateway" ] && trusted "$gateway" && "$t_real" enterprise macos status --json 2>/dev/null | sed \
        -e 's/^  "ok": [a-z]*,$/  "ok": false,/' \
        -e 's/^  "action": "[a-z-]*",$/  "action": "ensure",/' \
        -e 's/^  "noop": [a-z]*,$/  "noop": false,/' \
        -e '/^  "noop_reason": /d' \
        -e "s|^  \"product_version\": \"[^\"]*\",\$|  \"product_version\": \"$package_version\",|" \
        -e "s|^  \"errors\": \[\],\$|  \"errors\": [$error],|" \
        -e "s|^  \"errors\": \[\$|  \"errors\": [$error,|" \
        -e 's/^  "exit_code": [0-9]*$/  "exit_code": 1/' >"$result.tmp" &&
        grep -q "\"$code\"" "$result.tmp" && grep -q '^  "exit_code": 1$' "$result.tmp"; }; then
        printf '{"schema_version":2,"ok":false,"action":"ensure","noop":false,"profile":"standalone","platform":"darwin","product_version":"%s","installed_version":"%s","installed":%s,"transaction_pending":false,"services":[],"readiness":{"gateway":false,"guardian":false,"enumerator":false,"sensor_helper":false},"inspection":{"local":"unknown","ai_defense":"unknown"},"machine_policy":{},"enrollment":{"targets":0,"pending":0,"failed":0,"exempt":0},"coverage_complete":false,"security_complete":false,"errors":[%s],"exit_code":1}\n' \
            "$package_version" "$installed" "$present" "$error" >"$result.tmp"
    fi
    mv -f "$result.tmp" "$result" && echo "See $result." >&2
    exit 1
}
# A Mac that takes signed policy bundles must not run a release below the one
# its confirmed bundle requires (min_product_version), even for a deliberate
# rollback or a reinstall after uninstall --keep-state: a bundle signed with
# a lower floor lifts it. A gateway from 1.0.4 on reads the floor before any
# file is replaced, and its binary carries floor_check_marker: looking for
# it, without running the gateway, tells a gateway that cannot run from one
# before 1.0.4, which has no check and is not asked. When the installed
# gateway is gone or older (uninstall --keep-state, or an uninstall that
# failed after removing the binaries), the root-only copy that uninstall kept
# in the lifecycle folder answers. Only a gateway that was read and has no
# marker is an older one: a gateway that cannot be read, and a gateway with
# the marker or a kept copy that is not a root-owned file only root can
# change (trusted: another account cannot change it, a folder above it, or
# a symlink on the way to it, by mode or access control entry), or whose
# owner or mode cannot be read, leave the floor unchecked unless the other
# one answers, and the install is refused; a trusted checker is run by the
# path it resolves to. Only exit 0 lets the install go on: exit 3
# is the refusal, and any other result (execution denied, killed, crashed)
# leaves the floor unchecked, so the install is refused too.
floor_check_marker=defenseclaw-package-floor-check/1
kept="$state/floor-check"
checker=
unchecked=
if [ -e "$gateway" ] || [ -L "$gateway" ]; then
    grep -qaF "$floor_check_marker" "$gateway" 2>/dev/null
    case $? in
    0)
        if trusted "$gateway"; then
            checker=$t_real
        else
            unchecked="$gateway has the floor check, but it is not a root-owned file that only root can change (another account can change it, a folder above it, or a symlink on the way to it), or its owner or mode could not be read"
        fi
        ;;
    1) ;; # a gateway before 1.0.4: it has no floor check
    *) unchecked="$gateway could not be read to tell whether it has the floor check" ;;
    esac
fi
if [ -z "$checker" ]; then
    if [ ! -L "$kept" ] && trusted "$kept/defenseclaw-gateway"; then
        checker=$t_real
        unchecked=
    elif [ -L "$kept" ] || [ -e "$kept/defenseclaw-gateway" ] || [ -L "$kept/defenseclaw-gateway" ]; then
        unchecked="$kept/defenseclaw-gateway, the gateway an uninstall kept for the floor check, is not a root-owned file that only root can change, in a folder that is not a symlink (another account can change it, a folder above it, or a symlink on the way to it), or its owner or mode could not be read"
    fi
fi
if [ -n "$checker" ]; then
    floor_msg=$("$checker" enterprise bundle floor-check --product-version "$package_version" 2>&1 >/dev/null)
    floor_rc=$?
    if [ "$floor_rc" -ne 0 ]; then
        [ "$floor_rc" -eq 3 ] || floor_msg="The release floor of the confirmed signed policy bundle could not be checked: $checker exited $floor_rc${floor_msg:+ ($floor_msg)}. Let it run (for example, trust it in the application control policy) and install again."
        floor_msg=$(printf '%s' "${floor_msg#Error: }" | tr '\n' ' ' | tr -d '"\\|&')
        refuse product_floor_refused "Refusing to install DefenseClaw $package_version: $floor_msg Nothing was changed."
    fi
elif [ -n "$unchecked" ]; then
    refuse product_floor_refused "Refusing to install DefenseClaw $package_version: The release floor of the confirmed signed policy bundle could not be checked: $unchecked. Restore it as a readable, root-owned file that only root can write, in folders only root can write, and install again. Nothing was changed."
fi
if [ -n "$installed" ] && ! [ -f "$marker" ] && ! awk -v a="$package_version" -v b="$installed" '
    function norm(v) { sub(/^v/, "", v); sub(/\+.*/, "", v); return v }
    BEGIN {
        a = norm(a); b = norm(b); pa = ""; pb = ""
        if (index(a, "-")) { pa = substr(a, index(a, "-") + 1); a = substr(a, 1, index(a, "-") - 1) }
        if (index(b, "-")) { pb = substr(b, index(b, "-") + 1); b = substr(b, 1, index(b, "-") - 1) }
        na = split(a, x, "."); nb = split(b, y, "."); n = na > nb ? na : nb
        for (i = 1; i <= n; i++) {
            xi = (i <= na) ? x[i] + 0 : 0; yi = (i <= nb) ? y[i] + 0 : 0
            if (xi > yi) exit 0
            if (xi < yi) exit 1
        }
        if (pa == pb || pa == "") exit 0
        if (pb == "") exit 1
        np = split(pa, u, "."); nq = split(pb, w, "."); m = np > nq ? np : nq
        for (i = 1; i <= m; i++) {
            if (u[i] == w[i]) continue
            if (u[i] ~ /^[0-9]+$/ && w[i] ~ /^[0-9]+$/) exit (u[i] + 0 > w[i] + 0) ? 0 : 1
            exit (u[i] > w[i]) ? 0 : 1
        }
        exit 0
    }'; then
    refuse downgrade_refused "DefenseClaw $installed is installed; refusing to downgrade to $package_version, so nothing was changed. For a deliberate rollback, create $marker as root first."
fi
# @LEGACY_SANDBOX_GUARD@
if command -v dc_legacy_sandbox_guard >/dev/null 2>&1 &&
    ! dc_legacy_sandbox_guard darwin /opt/cisco/defenseclaw/bin/defenseclaw-gateway /usr/local/bin/defenseclaw; then
    refuse sandboxes_running "DefenseClaw ${installed:-an earlier release} is installed, and this install was refused: $dc_guard_reason" "$dc_guard_message"
fi
exit 0
EOF
"$REPO_ROOT/scripts/stamp-package-script.sh" "$VERSION" "$SCRIPTS/preinstall" "$SCRIPTS/preinstall"

# postinstall applies the deployment. A failure has already been rolled back
# by the lifecycle; it fails the install so the MDM reports it. It waits for
# a config-apply run that holds the lifecycle lock, as that trigger does,
# instead of failing the install as busy after the default 5 seconds. It
# waits 8 minutes, not the trigger's 10: the macOS Installer stops a package
# script at 10 minutes, and the lifecycle must write its lifecycle_busy
# result (exit 75) before that for the MDM wrapper to report it (GAP-1413).
cat >"$SCRIPTS/postinstall" <<'EOF'
#!/bin/sh
prefix=/opt/cisco/defenseclaw
gateway=/opt/cisco/defenseclaw/bin/defenseclaw-gateway
state=/opt/cisco/defenseclaw/lifecycle
umask 077
mkdir -p "$state" && chmod 0700 "$state"
# The Installer can write a payload file over the old one in place while a
# daemon or an account's LaunchAgent still holds it. macOS keeps the code
# signature it checked with that file and can kill every later start of the
# new program for code signing (OS_REASON_CODESIGNING, GAP-0049). Give each
# program the package installed a new file (a copy in the same folder renamed
# over it) before ensure, which then reloads every account's loaded
# LaunchAgent because the gateway file changed.
refresh_program() {
    file=$1
    if [ ! -f "$file" ] || [ -L "$file" ]; then
        return 1
    fi
    tmp=$(mktemp "${file%/*}/.${file##*/}.pkg.XXXXXXXX") || return 1
    if ! cp -p "$file" "$tmp" || ! mv -f "$tmp" "$file"; then
        rm -f "$tmp"
        return 1
    fi
}
refresh_programs() {
    for program in "$1/bin/defenseclaw-gateway" "$1/bin/defenseclaw-hook" "$1/bin/defenseclaw-sensor-helper" \
        "$1/bin/defenseclaw-acp" "$1"/bin/launch-agents/*/defenseclaw-gateway "$1"/share/e2fsprogs/sbin/*; do
        case $program in
        */bin/defenseclaw-acp | */bin/launch-agents/* | */share/e2fsprogs/sbin/*)
            # Optional: an unmatched pattern stays literal and is skipped.
            [ -e "$program" ] || [ -L "$program" ] || continue
            ;;
        esac
        if ! refresh_program "$program"; then
            echo "DefenseClaw: could not give $program a new file; reinstall the package." >&2
            return 1
        fi
    done
}
if ! refresh_programs "$prefix"; then
    exit 1
fi
downgrade=""
if [ -f "$state/allow-downgrade" ] && [ ! -L "$state/allow-downgrade" ] && [ "$(stat -f %u "$state/allow-downgrade")" = 0 ]; then
    downgrade=--allow-downgrade
fi
"$gateway" enterprise macos ensure --from-package $downgrade --reason package --json --lock-wait 8m \
    >"$state/last-package-result.json" 2>"$state/last-package-result.log"
status=$?
rm -f "$state/allow-downgrade"
if [ "$status" -ne 0 ]; then
    echo "DefenseClaw: the managed deployment did not apply (exit $status)." >&2
    # The Installer shows only a generic error, so name the cause (the
    # first error of the JSON result, one line) in install.log, as the
    # Linux postinstall does (GAP-1744, GAP-2331). ensure --json writes
    # indented JSON, so join the lines first.
    cause=$(tr '\n' ' ' 2>/dev/null <"$state/last-package-result.json" |
        sed -nE 's/.*"errors":[[:space:]]*\[[[:space:]]*\{[[:space:]]*"code":[[:space:]]*"([^"]*)",[[:space:]]*"message":[[:space:]]*"(([^"\\]|\\.)*)".*/\1: \2/p' |
        head -n 1 |
        sed 's/\\"/"/g; s/\\u003c/</g; s/\\u003e/>/g; s/\\u0026/\&/g')
    if [ -n "$cause" ]; then
        echo "DefenseClaw: $cause" >&2
    fi
    # A failed install records no pkg receipt, and ensure does not write
    # one, so receipt-based MDM inventory reports the Mac as not
    # installed until the pkg installs again (GAP-2359).
    echo "DefenseClaw: fix that, then install the package again. That finishes the install and records the pkg receipt that MDM inventory reads." >&2
    echo "DefenseClaw: sudo $gateway enterprise macos ensure --from-package also finishes the install, but records no pkg receipt." >&2
    echo "DefenseClaw: the full result is in $state/last-package-result.json." >&2
fi
if [ "$status" -eq 0 ]; then
    # Installer does not remove files omitted by a newer package receipt.
    # Retire the source path shipped by older managed packages.
    legacy=/opt/cisco/defenseclaw/share/fleet/policy_compiler.py
    for directory in /opt/cisco/defenseclaw/share /opt/cisco/defenseclaw/share/fleet; do
        if [ -L "$directory" ]; then
            echo "DefenseClaw: old package source path has an unsafe directory; remove it as administrator." >&2
            exit 1
        fi
    done
    if [ -e "$legacy" ] || [ -L "$legacy" ]; then
        if [ -L "$legacy" ] || [ ! -f "$legacy" ] || [ "$(stat -f %u "$legacy")" != 0 ]; then
            echo "DefenseClaw: old package source path is unsafe; remove it as administrator." >&2
            exit 1
        fi
        rm -f "$legacy" || exit 1
    fi
fi
exit "$status"
EOF
chmod 0755 "$SCRIPTS/preinstall" "$SCRIPTS/postinstall"

COMPONENT="$WORK/defenseclaw-enterprise-component.pkg"
pkgbuild --root "$ROOT" --identifier "$PKG_ID" --version "$VERSION" \
    --scripts "$SCRIPTS" --install-location / --ownership recommended "$COMPONENT"

cat >"$WORK/distribution.xml" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>DefenseClaw Managed Enterprise</title>
    <options customize="never" require-scripts="true" hostArchitectures="arm64"/>
    <domains enable_anywhere="false" enable_currentUserHome="false" enable_localSystem="true"/>
    <volume-check>
        <allowed-os-versions><os-version min="13.0"/></allowed-os-versions>
    </volume-check>
    <choices-outline><line choice="default"/></choices-outline>
    <choice id="default" visible="false">
        <pkg-ref id="${PKG_ID}"/>
    </choice>
    <pkg-ref id="${PKG_ID}" version="${VERSION}" onConclusion="none">defenseclaw-enterprise-component.pkg</pkg-ref>
</installer-gui-script>
EOF

OUTPUT="$DIST_DIR/defenseclaw-enterprise-${VERSION}-darwin-arm64.pkg"
product_args=(--distribution "$WORK/distribution.xml" --package-path "$WORK")
if [ -n "${MACOS_INSTALLER_SIGN_IDENTITY:-}" ]; then
    product_args+=(--sign "$MACOS_INSTALLER_SIGN_IDENTITY" --timestamp)
    [ -n "${MACOS_SIGN_KEYCHAIN:-}" ] && product_args+=(--keychain "$MACOS_SIGN_KEYCHAIN")
fi
productbuild "${product_args[@]}" "$OUTPUT"
"$REPO_ROOT/scripts/test-managed-package-no-fleet-compiler.sh" "$OUTPUT"
(cd "$DIST_DIR" && shasum -a 256 "$(basename "$OUTPUT")" >"$(basename "$OUTPUT").sha256")
echo "built $OUTPUT"
