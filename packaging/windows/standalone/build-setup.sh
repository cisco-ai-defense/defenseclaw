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
#       Builds the eight inner files from this checkout and embeds them
#       with distribution_flavor "standalone-unsigned". At install time the
#       Setup stages the digests it verified against its own manifest as the
#       lifecycle's hash_pinned trust anchor, so the trust root is the Setup
#       file your MDM delivered (Intune and other MDMs pin the package hash).
#
#   --payload-dir <dir> (Authenticode-signed)
#       Embeds the signed inner executables/scripts and the hash-bound
#       policy_compiler.py source file.
#       (Cisco release signing, or your own code-signing certificate for
#       customer re-signing) with distribution_flavor "standalone". The
#       lifecycle requires a Valid signature on every file; pass
#       allowedsigners=<sha256>,... to the Setup to pin your signer.
#       Sign the outer Setup with the same certificate afterward.
#
#   --sign-command <cmd> (Authenticode-signed executables/scripts, built here)
#       Builds the eight inner files like the default channel, runs
#       "<cmd> <file>" on each of them (the command signs the file in place,
#       for example packaging/mdm/signing/authenticode-sign.sh), embeds them
#       with distribution_flavor "standalone", then signs the outer Setup
#       with the same command. Exclusive with --payload-dir.
#
#   Both signed channels need --signing-type DEV|PROD and
#   --expected-signer-sha256 <64-hex>: windows-avc-assembler verifies every
#   signable inner file against that chain policy and signer fingerprint before it
#   appends the payload trailer. That check runs powershell.exe, so the
#   signed channels need a Windows build host (Git Bash or MSYS2); the
#   default unsigned channel builds anywhere.
#
# Usage:
#   packaging/windows/standalone/build-setup.sh --version 1.4.0 \
#       [--out-dir dist/windows-standalone-1.4.0]
#       [--payload-dir <signed> | --sign-command <cmd>]
#       [--signing-type DEV|PROD --expected-signer-sha256 <sha256>]
#
# defenseclaw-scanners.exe carries the Python scanner runtime
# (build-scanner-runtime.sh: CPython 3.13 and the uv.lock scanner pins).
#
# Prereqs: bash, git, go, uv, python3, curl. Runs on macOS or Linux
# (cross-builds windows/amd64).

set -euo pipefail

usage() {
    sed -n '4,53p' "$0" | sed 's/^# \{0,1\}//'
}

die() {
    printf 'standalone build-setup: %s\n' "$*" >&2
    exit 1
}

VERSION=""
OUT_DIR=""
SIGNED_PAYLOAD_DIR=""
SIGN_COMMAND=""
SIGNING_TYPE=""
EXPECTED_SIGNER_SHA256=""
while [ $# -gt 0 ]; do
    case "$1" in
        --version)      VERSION="${2:?--version needs a value}"; shift 2 ;;
        --out-dir)      OUT_DIR="${2:?--out-dir needs a value}"; shift 2 ;;
        --payload-dir)  SIGNED_PAYLOAD_DIR="${2:?--payload-dir needs a value}"; shift 2 ;;
        --sign-command) SIGN_COMMAND="${2:?--sign-command needs a value}"; shift 2 ;;
        --signing-type) SIGNING_TYPE="${2:?--signing-type needs a value}"; shift 2 ;;
        --expected-signer-sha256) EXPECTED_SIGNER_SHA256="${2:?--expected-signer-sha256 needs a value}"; shift 2 ;;
        -h|--help)     usage; exit 0 ;;
        *)             usage >&2; die "unknown argument: $1" ;;
    esac
done

[ -n "${VERSION}" ] || die "--version is required"
[ -z "${SIGNED_PAYLOAD_DIR}" ] || [ -z "${SIGN_COMMAND}" ] || die "--payload-dir and --sign-command are exclusive"
[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]] || die "--version must be a release version (got '${VERSION}')"
# Check the signing policy before any build work: the assembler needs it to
# verify a signed payload, and an unsigned build must not carry one.
if [ -n "${SIGNED_PAYLOAD_DIR}" ] || [ -n "${SIGN_COMMAND}" ]; then
    [[ "${SIGNING_TYPE}" =~ ^(DEV|PROD)$ ]] || die "--payload-dir and --sign-command need --signing-type DEV or PROD"
    [[ "${EXPECTED_SIGNER_SHA256}" =~ ^[0-9A-Fa-f]{64}$ ]] || die "--payload-dir and --sign-command need --expected-signer-sha256 <64-hex>"
    case "$(uname -s)" in
        MINGW*|MSYS*|CYGWIN*) ;;
        *) die "signed standalone builds need a Windows build host: windows-avc-assembler verifies Authenticode with powershell.exe" ;;
    esac
elif [ -n "${SIGNING_TYPE}" ] || [ -n "${EXPECTED_SIGNER_SHA256}" ]; then
    die "--signing-type and --expected-signer-sha256 apply only with --payload-dir or --sign-command"
fi

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
    defenseclaw-scanners.exe
    defenseclaw-sensor-helper.exe
    defenseclaw.exe
    install-enterprise.ps1
    policy_compiler.py
)

STAGE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/dc-standalone-windows.XXXXXX")"
EMBED_DIR="${REPO_ROOT}/cmd/defenseclaw-enterprise-setup/payload"
SCANNERS_EMBED_DIR="${REPO_ROOT}/cmd/defenseclaw-scanners/payload"
cleanup() {
    rm -rf "${STAGE_DIR:?}"
    # The embed directories are git-ignored except their .gitkeep; leave
    # them as the checkout had them so a later build cannot embed a stale
    # payload.
    find "${EMBED_DIR}" "${SCANNERS_EMBED_DIR}" -mindepth 1 -maxdepth 1 ! -name .gitkeep -exec rm -rf {} +
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
    cmp -s "${STAGE_DIR}/policy_compiler.py" "${REPO_ROOT}/edge-connector/tools/policy_compiler.py" || \
        die "signed payload policy_compiler.py differs from the release source"
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
    echo "==> building the scanner runtime"
    "${REPO_ROOT}/packaging/windows/standalone/build-scanner-runtime.sh" --out-dir "${STAGE_DIR}/scanner-runtime"
    cp -f "${STAGE_DIR}/scanner-runtime/runtime.zip" "${STAGE_DIR}/scanner-runtime/runtime.json" "${SCANNERS_EMBED_DIR}/"
    build "${STAGE_DIR}/defenseclaw-scanners.exe" ./cmd/defenseclaw-scanners launcher console
    # The CLI is the gateway image, exactly as in the Secure Client kit.
    cp -f "${STAGE_DIR}/defenseclaw-gateway.exe" "${STAGE_DIR}/defenseclaw.exe"
    cp -f "${REPO_ROOT}/packaging/windows/install-enterprise.ps1" "${STAGE_DIR}/install-enterprise.ps1"
    cp -f "${REPO_ROOT}/packaging/windows/DefenseClawEnterprise.psm1" "${STAGE_DIR}/DefenseClawEnterprise.psm1"
    cp -f "${REPO_ROOT}/edge-connector/tools/policy_compiler.py" "${STAGE_DIR}/policy_compiler.py"
    if [ -n "${SIGN_COMMAND}" ]; then
        FLAVOR="standalone"
        UNSIGNED_FLAG=()
        for name in "${PAYLOAD_FILES[@]}"; do
            # Python source is hash-bound by the signed outer Setup manifest.
            # Authenticode cannot be embedded in a .py file.
            if [ "${name}" = policy_compiler.py ]; then continue; fi
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
SETUP_UNSIGNED="${STAGE_DIR}/DefenseClawSetup-Enterprise-Standalone-x64.unsigned.exe"
echo "==> building ${SETUP##*/} (outer EXE, no trailer yet)"
( cd "${REPO_ROOT}" && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
    go build -trimpath -buildvcs=false \
    -ldflags "-s -w -buildid=defenseclaw-enterprise-setup-standalone-${SOURCE_COMMIT}" \
    -o "${SETUP_UNSIGNED}" ./cmd/defenseclaw-enterprise-setup )

# Spec 003: the payload is no longer carried via //go:embed. Append the
# [archive][manifest][footer] trailer to the just-built outer EXE so
# runtime loadEmbeddedEnterprisePayload can read it off the tail of the
# running image. windows-avc-assembler runs on the host (so we unset
# GOOS/GOARCH), and -Flavor Standalone selects the shorter MDM
# inventory + "standalone[-unsigned]" distribution tag. The AVC
# Enterprise path is unaffected.
echo "==> appending ${FLAVOR} payload trailer -> ${SETUP##*/}"
ASSEMBLER_SIGNING_FLAGS=()
if [ "${FLAVOR}" = "standalone-unsigned" ]; then
    ASSEMBLER_SIGNING_FLAGS=(-AllowUnsigned)
else
    # The signed channels (--payload-dir / --sign-command) hand the
    # assembler signed executables/scripts plus the release-source Python
    # compiler. The signed module pins the compiler digest; the signed outer
    # Setup binds the trailer and is checked again before installation.
    ASSEMBLER_SIGNING_FLAGS=(
        -SigningType "${SIGNING_TYPE}"
        -ExpectedSignerSha256 "${EXPECTED_SIGNER_SHA256}"
    )
fi
( unset GOOS GOARCH GOFLAGS CGO_ENABLED; cd "${REPO_ROOT}" && \
    go run ./cmd/windows-avc-assembler \
        -PayloadDir "${PAYLOAD_ONLY}" \
        -SetupExeUnsigned "${SETUP_UNSIGNED}" \
        -SourceCommit "${SOURCE_COMMIT}" \
        -Version "${VERSION}" \
        -Out "${OUT_DIR}" \
        -Flavor Standalone \
        "${ASSEMBLER_SIGNING_FLAGS[@]}" )

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
