#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# assemble.sh — the DefenseClaw-authored assembler AVC runs between its
# two `signtool sign` invocations. Ships inside the build kit produced
# by packaging/scripts/build-managed-windows-bundle.sh.
#
# See docs/specs/002-windows-avc-packaging/design.md § Data flow for
# the full DefenseClaw-side + AVC-side flow. REQ-09 (requirements.md)
# is this file's contract.
#
# EXIT CODES (design.md § Interfaces)
#   0 — success
#   2 — invalid CLI args
#   3 — preflight failure (missing env from repro-flags.sh)
#   4 — Cisco-signature assertion failed (non-allow-unsigned only)
#   5 — go build failure
#   6 — I/O error (missing input, permission denied)
#
# USAGE (from README-AVC.md inside the kit)
#   ./assemble.sh \
#       --payload-dir ./payload \
#       --source-dir  ./source \
#       --out-dir     ./out \
#       --source-commit <40-char lowercase git OID> \
#       --version <semver> \
#       --cmid-pseudo-version <v0.0.0-YYYYMMDDhhmmss-<12hex>>
#
# --allow-unsigned skips the Cisco-signature preflight and stamps
# `"unsigned": true` into manifest.json + provenance.json. Meant for
# local developer builds; a runtime install then requires
# `--allow-unsigned --certification-codex-home <disposable-path>` to
# succeed (see cmd/defenseclaw-enterprise-setup/platform_windows.go).

set -euo pipefail

# ---------------------------------------------------------------------------
# Layout probe. This script must work identically whether it lives at
# packaging/scripts/lib/assemble.sh (in-repo dev loop) or at
# ./assemble.sh (shipped kit root — one directory above the lib/ folder
# holding repro-flags.sh + assert-cisco-signature.sh + finalize.sh).
# ---------------------------------------------------------------------------
_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "${_SCRIPT_DIR}/repro-flags.sh" ]; then
    _LIB_DIR="${_SCRIPT_DIR}"
elif [ -f "${_SCRIPT_DIR}/packaging/scripts/lib/repro-flags.sh" ]; then
    _LIB_DIR="${_SCRIPT_DIR}/packaging/scripts/lib"
else
    echo "assemble: could not locate packaging/scripts/lib/ next to assemble.sh" >&2
    exit 6
fi
readonly _LIB_DIR

# `die` is used by assert-cisco-signature.sh — must be defined before
# sourcing it. Prints to stderr and exits with the code in $1; every
# other arg is joined with spaces as the diagnostic.
die() {
    local code="$1"
    shift
    printf 'assemble: %s\n' "$*" >&2
    exit "${code}"
}

# ---------------------------------------------------------------------------
# CLI parsing.
# ---------------------------------------------------------------------------
usage() {
    cat >&2 <<'EOF'
Usage: assemble.sh [OPTIONS]

Options:
  --payload-dir <path>           Directory of AVC-signed inner files
                                 (default: ./payload)
  --source-dir  <path>           Trimmed Go source tree with vendor/
                                 (default: ./source)
  --out-dir     <path>           Output directory
                                 (default: ./out)
  --source-commit <sha>          40-char lowercase git OID (required)
  --version <semver>             Release version (required)
  --allow-unsigned               Skip Cisco-signature assertion; emit
                                 manifest.json with "unsigned": true
  -h, --help                     Show this usage and exit 0

Exit codes: 0=ok 2=usage 3=preflight 4=signature 5=build 6=io.

Note: the bundler-side `payload-metadata.json` (see
packaging/scripts/build-managed-windows-bundle.sh) is the audit
trail for cmid_pseudo_version; assemble does not re-emit it.
EOF
}

PAYLOAD_DIR="./payload"
SOURCE_DIR="./source"
OUT_DIR="./out"
SOURCE_COMMIT=""
VERSION=""
ALLOW_UNSIGNED=0

while [ $# -gt 0 ]; do
    case "$1" in
        --payload-dir)          PAYLOAD_DIR="${2:?}"; shift 2 ;;
        --source-dir)           SOURCE_DIR="${2:?}"; shift 2 ;;
        --out-dir)              OUT_DIR="${2:?}"; shift 2 ;;
        --source-commit)        SOURCE_COMMIT="${2:?}"; shift 2 ;;
        --version)              VERSION="${2:?}"; shift 2 ;;
        # Accept and ignore for backward-compat with older bundler
        # callers that pass this arg. The bundler-side
        # `payload-metadata.json` is the audit trail; assemble does
        # not need to re-emit or thread cmid through — see CR
        # spec-002:PRRT_kwDORuAK-s6af8i8.
        --cmid-pseudo-version)  shift 2 ;;
        --allow-unsigned)       ALLOW_UNSIGNED=1; shift ;;
        -h|--help)              usage; exit 0 ;;
        *)                      usage; die 2 "unknown flag: $1" ;;
    esac
done

[ -n "${SOURCE_COMMIT}" ]        || die 2 "--source-commit required"
[ -n "${VERSION}" ]              || die 2 "--version required"

if ! [[ "${SOURCE_COMMIT}" =~ ^[0-9a-f]{40}$ ]]; then
    die 2 "--source-commit must be a 40-char lowercase git OID (got: '${SOURCE_COMMIT}')"
fi

[ -d "${PAYLOAD_DIR}" ]  || die 6 "payload-dir not found: ${PAYLOAD_DIR}"
[ -d "${SOURCE_DIR}" ]   || die 6 "source-dir not found: ${SOURCE_DIR}"
mkdir -p "${OUT_DIR}"

# Resolve every user-supplied directory to an absolute path up front.
# Later stages `cd "${SOURCE_DIR}"` inside subshells to invoke `go build`
# under the shipped kit's module root; if we left OUT_DIR / PAYLOAD_DIR
# relative, those subshells' relative paths would resolve against the
# source tree instead of the caller's CWD and land the outer EXE inside
# ./source/ instead of ./out/ (CodeRabbit spec-002 finding — "both
# assemblers build artifacts into the wrong directory").
PAYLOAD_DIR="$(cd "${PAYLOAD_DIR}" && pwd)"
SOURCE_DIR="$(cd "${SOURCE_DIR}" && pwd)"
OUT_DIR="$(cd "${OUT_DIR}" && pwd)"

# ---------------------------------------------------------------------------
# Stage (a): source repro-flags.sh so subsequent go invocations use the
# fixed env. This ALSO exports GOOS=windows / GOARCH=amd64, so we must
# NOT build the emitter (a CI-host tool) under this env — the emitter
# build happens in a clean subshell below, before we source repro-flags.
# ---------------------------------------------------------------------------
_stage() { printf '==> %s\n' "$*"; }
_stage "assemble.sh — DefenseClaw enterprise Setup kit assembler"
_stage "payload=${PAYLOAD_DIR} source=${SOURCE_DIR} out=${OUT_DIR}"
_stage "version=${VERSION} source-commit=${SOURCE_COMMIT:0:12}... allow-unsigned=${ALLOW_UNSIGNED}"

# ---------------------------------------------------------------------------
# Stage 0: build cmd/windows-repro-manifest for the CI host (native
# arch). The three subcommands run on the runner, not inside the outer
# Setup, so we need a native binary — not a Windows cross-build.
# ---------------------------------------------------------------------------
EMITTER="${OUT_DIR}/.windows-repro-manifest"
_stage "stage 0/6  build native windows-repro-manifest"
(
    unset GOFLAGS GOOS GOARCH GOTOOLCHAIN CGO_ENABLED || true
    cd "${SOURCE_DIR}"
    go build -trimpath -buildvcs=false \
        -o "${EMITTER}" \
        ./cmd/windows-repro-manifest
) || die 5 "windows-repro-manifest native build failed"

# ---------------------------------------------------------------------------
# Stage (b): repro-flags preflight. From here on `go build` is the
# outer-Setup cross-build.
# ---------------------------------------------------------------------------
unset GOFLAGS GOOS GOARCH CGO_ENABLED || true
# shellcheck source=/dev/null
. "${_LIB_DIR}/repro-flags.sh"

# Callers must supply SOURCE_DATE_EPOCH before running assemble.sh; we
# derive DEFENSECLAW_BUILDID from --source-commit so the ID always
# matches the manifest / provenance source_commit fields.
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    die 3 "SOURCE_DATE_EPOCH must be exported by the caller (see README-AVC.md)"
fi
export DEFENSECLAW_BUILDID="defenseclaw-enterprise-setup-${SOURCE_COMMIT}"

_stage "stage 1/6  preflight"
if ! defenseclaw_repro_preflight; then
    die 3 "repro-flags preflight failed"
fi

# ---------------------------------------------------------------------------
# Stage (c): Cisco-signature assertion for every payload file, unless
# --allow-unsigned. The five expected filenames are pinned; refusing
# unknown names catches a payload dir with a stray file.
# ---------------------------------------------------------------------------
_stage "stage 2/6  verify-signatures"
EXPECTED_PAYLOAD=(
    DefenseClawEnterprise.psm1
    defenseclaw-gateway.exe
    defenseclaw-hook.exe
    defenseclaw.exe
    install-enterprise.ps1
)

for name in "${EXPECTED_PAYLOAD[@]}"; do
    [ -f "${PAYLOAD_DIR}/${name}" ] || die 6 "payload-dir missing required file: ${name}"
done

# Refuse stray files so a mis-staged payload doesn't slip past.
while IFS= read -r -d '' extra; do
    base=$(basename "${extra}")
    found=0
    for name in "${EXPECTED_PAYLOAD[@]}"; do
        if [ "${base}" = "${name}" ]; then found=1; break; fi
    done
    if [ "${found}" -eq 0 ]; then
        die 6 "payload-dir contains unexpected entry: ${base}"
    fi
done < <(find "${PAYLOAD_DIR}" -mindepth 1 -maxdepth 1 -print0)

if [ "${ALLOW_UNSIGNED}" -eq 0 ]; then
    # shellcheck source=/dev/null
    . "${_LIB_DIR}/assert-cisco-signature.sh"
    for name in "${EXPECTED_PAYLOAD[@]}"; do
        defenseclaw_assert_cisco_signature "${PAYLOAD_DIR}/${name}"
    done
fi

# ---------------------------------------------------------------------------
# Stage (d): emit manifest.json into the Go embed dir.
# ---------------------------------------------------------------------------
EMBED_DIR="${SOURCE_DIR}/cmd/defenseclaw-enterprise-setup/payload"
mkdir -p "${EMBED_DIR}"

_stage "stage 3/6  emit-manifest"
# Use an array so an empty --allow-unsigned expansion doesn't inject
# an empty positional arg (`""`) into the emitter's argv, and so a
# future --unsigned=<value>-style flag can't be word-split by mistake.
UNSIGNED_FLAG=()
if [ "${ALLOW_UNSIGNED}" -eq 1 ]; then
    UNSIGNED_FLAG=(--unsigned)
fi
"${EMITTER}" emit-manifest \
    --version "${VERSION}" \
    --source-commit "${SOURCE_COMMIT}" \
    --payload-dir "${PAYLOAD_DIR}" \
    --out "${EMBED_DIR}/manifest.json" \
    "${UNSIGNED_FLAG[@]}" \
    || die 6 "emit-manifest failed"

# ---------------------------------------------------------------------------
# Stage (e): copy the signed payload into the embed dir. //go:embed
# picks up every file under payload/*.
# ---------------------------------------------------------------------------
_stage "stage 4/6  stage-payload"
for name in "${EXPECTED_PAYLOAD[@]}"; do
    cp -f "${PAYLOAD_DIR}/${name}" "${EMBED_DIR}/${name}" \
        || die 6 "copy failed: ${name}"
done

# ---------------------------------------------------------------------------
# Stage (f): outer Setup EXE cross-build.
# ---------------------------------------------------------------------------
_stage "stage 5/6  go-build DefenseClawSetup-Enterprise-x64.exe"
(
    cd "${SOURCE_DIR}"
    defenseclaw_repro_build \
        "${OUT_DIR}/DefenseClawSetup-Enterprise-x64.exe" \
        ./cmd/defenseclaw-enterprise-setup
) || die 5 "outer Setup EXE go build failed"

# ---------------------------------------------------------------------------
# Stage (g): emit-provenance. setup_sha256 is left empty; AVC (or the
# optional finalize.sh helper) fills it after step-3 signtool sign.
# We deliberately do NOT write the .sha256 sidecar — the sidecar's
# whole point is to record the SIGNED EXE's hash, which is only
# knowable after AVC step 3 (design.md § Decisions).
# ---------------------------------------------------------------------------
_stage "stage 6/6  emit-provenance"
"${EMITTER}" emit-provenance \
    --version "${VERSION}" \
    --source-commit "${SOURCE_COMMIT}" \
    --out "${OUT_DIR}/DefenseClawSetup-Enterprise-x64.exe.provenance.json" \
    --setup-sha256-placeholder \
    "${UNSIGNED_FLAG[@]}" \
    || die 6 "emit-provenance failed"

rm -f "${EMITTER}"

_stage "done  out/DefenseClawSetup-Enterprise-x64.exe + provenance.json ready"
_stage "next  AVC signs the outer EXE, then invokes finalize.sh (or"
_stage "      populates .sha256 + provenance.setup_sha256 in-pipeline)"
