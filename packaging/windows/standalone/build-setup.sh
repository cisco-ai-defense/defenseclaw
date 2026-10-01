#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# packaging/windows/standalone/build-setup.sh — build the MDM-deployable standalone
# enterprise Setup, DefenseClawSetup-Enterprise-Standalone-x64.exe.
#
# The standalone profile has no Cisco Secure Client dependency: no CMID
# credential broker, no private cloud-auth overlay, PowerShell 7, and the
# vendor-neutral Program Files\Cisco\DefenseClaw roots. This script is
# separate from the Secure Client AVC build kit (build-managed-windows-
# bundle.sh + lib/assemble.*), which it neither reads nor changes.
#
# Two payload channels:
#
#   default (hash-pinned, unsigned)
#       Builds the seven inner files from this checkout and embeds them
#       with distribution_flavor "standalone-unsigned". At install time the
#       Setup stages the digests it verified against its own manifest as the
#       lifecycle's hash_pinned trust anchor, so the trust root is the Setup
#       file your MDM delivered (Intune and other MDMs pin the package hash).
#
#   --payload-dir <dir> (Authenticode-signed)
#       Embeds seven inner files that were already Authenticode-signed
#       (Cisco release signing, or your own code-signing certificate for
#       customer re-signing) with distribution_flavor "standalone". The
#       lifecycle requires a Valid signature on every file; pass
#       allowedsigners=<sha256>,... to the Setup to pin your signer.
#       Sign the outer Setup with the same certificate afterward.
#
#   --sign-command <cmd> (Authenticode-signed, built here)
#       Builds the seven inner files like the default channel, runs
#       "<cmd> <file>" on each of them (the command signs the file in place,
#       for example packaging/mdm/signing/authenticode-sign.sh), embeds them
#       with distribution_flavor "standalone", then signs the outer Setup
#       with the same command. Exclusive with --payload-dir.
#
# Usage:
#   packaging/windows/standalone/build-setup.sh --version 1.4.0 \
#       [--out-dir dist/windows-standalone-1.4.0]
#       [--payload-dir <signed> | --sign-command <cmd>]
#
# Prereqs: bash, git, go. Runs on macOS or Linux (cross-builds windows/amd64).

set -euo pipefail

usage() {
    sed -n '4,44p' "$0" | sed 's/^# \{0,1\}//'
}

die() {
    printf 'standalone build-setup: %s\n' "$*" >&2
    exit 1
}

VERSION=""
OUT_DIR=""
SIGNED_PAYLOAD_DIR=""
SIGN_COMMAND=""
while [ $# -gt 0 ]; do
    case "$1" in
        --version)      VERSION="${2:?--version needs a value}"; shift 2 ;;
        --out-dir)      OUT_DIR="${2:?--out-dir needs a value}"; shift 2 ;;
        --payload-dir)  SIGNED_PAYLOAD_DIR="${2:?--payload-dir needs a value}"; shift 2 ;;
        --sign-command) SIGN_COMMAND="${2:?--sign-command needs a value}"; shift 2 ;;
        -h|--help)     usage; exit 0 ;;
        *)             usage >&2; die "unknown argument: $1" ;;
    esac
done

[ -n "${VERSION}" ] || die "--version is required"
[ -z "${SIGNED_PAYLOAD_DIR}" ] || [ -z "${SIGN_COMMAND}" ] || die "--payload-dir and --sign-command are exclusive"
[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]] || die "--version must be a release version (got '${VERSION}')"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SOURCE_COMMIT="$(git -C "${REPO_ROOT}" rev-parse HEAD)"
[[ "${SOURCE_COMMIT}" =~ ^[0-9a-f]{40}$ ]] || die "cannot resolve the source commit"
OUT_DIR="${OUT_DIR:-${REPO_ROOT}/dist/windows-standalone-${VERSION}}"
mkdir -p "${OUT_DIR}"
OUT_DIR="$(cd "${OUT_DIR}" && pwd)"

# The standalone inventory: the Secure Client set without the CMID broker.
# Must match standalonePayloadFiles in cmd/defenseclaw-enterprise-setup.
PAYLOAD_FILES=(
    DefenseClawEnterprise.psm1
    defenseclaw-acp.exe
    defenseclaw-gateway.exe
    defenseclaw-hook.exe
    defenseclaw-sensor-helper.exe
    defenseclaw.exe
    install-enterprise.ps1
)

STAGE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/dc-standalone-windows.XXXXXX")"
EMBED_DIR="${REPO_ROOT}/cmd/defenseclaw-enterprise-setup/payload"
cleanup() {
    rm -rf "${STAGE_DIR}"
    # The embed directory is git-ignored except its .gitkeep; leave it as
    # the checkout had it so a later build cannot embed a stale payload.
    find "${EMBED_DIR}" -mindepth 1 -maxdepth 1 ! -name .gitkeep -exec rm -rf {} +
}
trap cleanup EXIT

if [ -n "$(find "${EMBED_DIR}" -mindepth 1 -maxdepth 1 ! -name .gitkeep -print -quit)" ]; then
    die "${EMBED_DIR} already holds a payload; remove it before building"
fi

if [ -n "${SIGNED_PAYLOAD_DIR}" ]; then
    FLAVOR="standalone"
    UNSIGNED_FLAG=()
    SIGNED_PAYLOAD_DIR="$(cd "${SIGNED_PAYLOAD_DIR}" && pwd)"
    for name in "${PAYLOAD_FILES[@]}"; do
        [ -f "${SIGNED_PAYLOAD_DIR}/${name}" ] || die "signed payload is missing ${name}"
        cp -f "${SIGNED_PAYLOAD_DIR}/${name}" "${STAGE_DIR}/${name}"
    done
    while IFS= read -r -d '' extra; do
        base="$(basename "${extra}")"
        found=0
        for name in "${PAYLOAD_FILES[@]}"; do
            if [ "${base}" = "${name}" ]; then found=1; break; fi
        done
        [ "${found}" -eq 1 ] || die "signed payload contains unexpected entry: ${base}"
    done < <(find "${SIGNED_PAYLOAD_DIR}" -mindepth 1 -maxdepth 1 -print0)
else
    FLAVOR="standalone-unsigned"
    UNSIGNED_FLAG=(--unsigned)
    ICON_PATH="${REPO_ROOT}/macos/DefenseClawMac/DefenseClawMac/Assets.xcassets/AppIcon.appiconset/icon_256.png"
    build() {
        local output="$1" package="$2" component="$3" gui="$4"
        local ldflags="-s -w -buildid=defenseclaw-${component}-${VERSION}-windows-amd64 -X main.version=${VERSION} -X main.commit=${SOURCE_COMMIT}"
        if [ "${gui}" = "gui" ]; then
            ldflags="${ldflags} -H=windowsgui"
        fi
        echo "==> building ${output##*/} (${package})"
        ( cd "${REPO_ROOT}" && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
            go build -trimpath -buildvcs=false -ldflags "${ldflags}" -o "${output}" "${package}" )
        ( cd "${REPO_ROOT}" && go run ./internal/tools/windowsresources \
            -target windows_amd64 -executable "${output}" \
            -component "${component}" -version "${VERSION}" -icon "${ICON_PATH}" )
    }
    build "${STAGE_DIR}/defenseclaw-gateway.exe" ./cmd/defenseclaw gateway console
    build "${STAGE_DIR}/defenseclaw-acp.exe" ./cmd/defenseclaw-acp acp-guard console
    build "${STAGE_DIR}/defenseclaw-hook.exe" ./cmd/defenseclaw-hook hook gui
    build "${STAGE_DIR}/defenseclaw-sensor-helper.exe" ./cmd/defenseclaw-sensor-helper sensor-helper gui
    # The CLI is the gateway image, exactly as in the Secure Client kit.
    cp -f "${STAGE_DIR}/defenseclaw-gateway.exe" "${STAGE_DIR}/defenseclaw.exe"
    cp -f "${REPO_ROOT}/packaging/windows/install-enterprise.ps1" "${STAGE_DIR}/install-enterprise.ps1"
    cp -f "${REPO_ROOT}/packaging/windows/DefenseClawEnterprise.psm1" "${STAGE_DIR}/DefenseClawEnterprise.psm1"
    if [ -n "${SIGN_COMMAND}" ]; then
        FLAVOR="standalone"
        UNSIGNED_FLAG=()
        for name in "${PAYLOAD_FILES[@]}"; do
            echo "==> signing ${name}"
            "${SIGN_COMMAND}" "${STAGE_DIR}/${name}" || die "signing ${name} failed"
        done
    fi
fi

EMITTER="${STAGE_DIR}/.windows-repro-manifest"
echo "==> building the native manifest emitter"
( unset GOOS GOARCH GOFLAGS CGO_ENABLED; cd "${REPO_ROOT}" && \
    go build -trimpath -buildvcs=false -o "${EMITTER}" ./cmd/windows-repro-manifest )

PAYLOAD_ONLY="${STAGE_DIR}/payload"
mkdir -p "${PAYLOAD_ONLY}"
for name in "${PAYLOAD_FILES[@]}"; do
    cp -f "${STAGE_DIR}/${name}" "${PAYLOAD_ONLY}/${name}"
done

echo "==> emitting the ${FLAVOR} payload manifest"
"${EMITTER}" emit-manifest \
    --version "${VERSION}" \
    --source-commit "${SOURCE_COMMIT}" \
    --payload-dir "${PAYLOAD_ONLY}" \
    --distribution-flavor "${FLAVOR}" \
    --out "${EMBED_DIR}/manifest.json" \
    ${UNSIGNED_FLAG[@]+"${UNSIGNED_FLAG[@]}"}
for name in "${PAYLOAD_FILES[@]}"; do
    cp -f "${PAYLOAD_ONLY}/${name}" "${EMBED_DIR}/${name}"
done

SETUP="${OUT_DIR}/DefenseClawSetup-Enterprise-Standalone-x64.exe"
echo "==> building ${SETUP##*/}"
( cd "${REPO_ROOT}" && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
    go build -trimpath -buildvcs=false \
    -ldflags "-s -w -buildid=defenseclaw-enterprise-setup-standalone-${SOURCE_COMMIT}" \
    -o "${SETUP}" ./cmd/defenseclaw-enterprise-setup )
if [ -n "${SIGN_COMMAND}" ]; then
    echo "==> signing ${SETUP##*/}"
    "${SIGN_COMMAND}" "${SETUP}" || die "signing ${SETUP##*/} failed"
fi

if command -v sha256sum >/dev/null 2>&1; then
    ( cd "${OUT_DIR}" && sha256sum "${SETUP##*/}" > "${SETUP##*/}.sha256" )
else
    ( cd "${OUT_DIR}" && shasum -a 256 "${SETUP##*/}" > "${SETUP##*/}.sha256" )
fi
cp -f "${EMBED_DIR}/manifest.json" "${OUT_DIR}/payload-manifest.json"
echo "==> done: ${SETUP}"
echo "    flavor=${FLAVOR} version=${VERSION} commit=${SOURCE_COMMIT:0:12}"
echo "    sha256: $(cut -d' ' -f1 "${SETUP}.sha256")"
