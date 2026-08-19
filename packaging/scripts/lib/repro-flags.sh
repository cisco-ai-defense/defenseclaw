#!/usr/bin/env bash
#
# repro-flags.sh — single source of truth for the reproducibility envs
# and `go build` invocation used by the Windows managed-enterprise AVC
# assembly step. Sourced by assemble.sh (Workstream A2). See
# docs/specs/001-windows-deterministic-build/design.md § Components.
#
# WHY THIS FILE EXISTS
# --------------------
# When AVC runs `assemble.sh` on their signing pipeline, `go build`
# receives whatever env is in place. Ambient GOFLAGS, GOTOOLCHAIN, or
# CGO_ENABLED would silently produce a different DefenseClawSetup-
# Enterprise-x64.exe, breaking the byte-identical contract the AVC
# handoff depends on. This file exports every reproducibility-critical
# env so its values are DEFINED by DefenseClaw, not by AVC's host.
#
# WHY GOTOOLCHAIN IS PINNED HERE INSTEAD OF IN go.mod
# ---------------------------------------------------
# Pinning `toolchain go1.26.4` in go.mod would force every OSS build
# and every contributor `go mod tidy` invocation to download that
# toolchain. The reproducibility invariant is a managed-enterprise-
# only concern, so it lives on this out-of-band path. `make lint`
# runs scripts/check-go-mod-no-toolchain.sh to prevent regression.
#
# USAGE
# -----
#   source packaging/scripts/lib/repro-flags.sh
#   SOURCE_DATE_EPOCH=1234567890 \
#     DEFENSECLAW_BUILDID=defenseclaw-enterprise-setup-abcdef... \
#     defenseclaw_repro_preflight    # asserts every required env
#   defenseclaw_repro_build \
#     "out/DefenseClawSetup-Enterprise-x64.exe" \
#     ./cmd/defenseclaw-enterprise-setup

# The six AVC-confirmed envs. Values are declared here, not passed in,
# so a caller cannot accidentally change one to a non-reproducible
# setting. SOURCE_DATE_EPOCH and DEFENSECLAW_BUILDID are per-build and
# MUST be exported by the caller before running preflight/build.
export GOFLAGS="-trimpath -buildvcs=false -mod=vendor"
export GOTOOLCHAIN="go1.26.4"
export CGO_ENABLED="0"
export GOOS="windows"
export GOARCH="amd64"

# Names of the six required per-build envs; used by both preflight
# and the parity lint (scripts/check-repro-flags-parity.sh) so
# adding/removing an env here is caught in one place.
REPRO_REQUIRED_ENVS=(
    GOFLAGS
    GOTOOLCHAIN
    CGO_ENABLED
    GOOS
    GOARCH
    SOURCE_DATE_EPOCH
    DEFENSECLAW_BUILDID
)
# Intentionally not exported: this array is a script-local metadata
# constant, not an environment variable a child process should see.
# Bash exports arrays as an opaque "NAME=(...)"-style scalar most tools
# can't parse anyway.

# defenseclaw_repro_preflight refuses to run if any required env is
# missing, empty, or (for SOURCE_DATE_EPOCH) not a positive integer.
# Prints ONE diagnostic per missing env so a caller who omitted three
# of them fixes them in one round.
defenseclaw_repro_preflight() {
    local missing=()
    local name
    for name in "${REPRO_REQUIRED_ENVS[@]}"; do
        if [[ -z "${!name:-}" ]]; then
            missing+=("${name} is unset or empty")
        fi
    done
    if [[ "${SOURCE_DATE_EPOCH:-}" != "" ]]; then
        if ! [[ "${SOURCE_DATE_EPOCH}" =~ ^[1-9][0-9]*$ ]]; then
            missing+=("SOURCE_DATE_EPOCH must be a positive integer (got: '${SOURCE_DATE_EPOCH}')")
        fi
    fi
    if [[ "${GOTOOLCHAIN}" != "go1.26.4" ]]; then
        missing+=("GOTOOLCHAIN must be 'go1.26.4' (got: '${GOTOOLCHAIN}')")
    fi
    if [[ ${#missing[@]} -gt 0 ]]; then
        printf 'repro-flags preflight: %s\n' "${missing[@]}" >&2
        return 1
    fi
    return 0
}

# defenseclaw_repro_build invokes `go build` with the exact flag list
# the AVC reproducibility contract requires. Callers pass output path
# and package path only; every other flag is fixed here.
defenseclaw_repro_build() {
    local out="$1"
    local pkg="$2"
    if [[ -z "${out}" || -z "${pkg}" ]]; then
        echo "defenseclaw_repro_build: <output-path> <package-path> required" >&2
        return 1
    fi
    defenseclaw_repro_preflight || return 1
    go build \
        -mod=vendor \
        -trimpath \
        -buildvcs=false \
        -buildid="${DEFENSECLAW_BUILDID}" \
        -o "${out}" \
        "${pkg}"
}
