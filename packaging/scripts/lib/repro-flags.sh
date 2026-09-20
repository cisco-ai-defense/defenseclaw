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

# Required-exact-value map: env name -> exact value the reproducibility
# contract expects. A caller can source this file and then unset or
# rewrite any of these before running preflight; each fixed-value check
# below compares against the literal required value so mutations are
# caught, not silently accepted.
_repro_expected_value() {
    case "$1" in
        GOFLAGS)      printf '%s' "-trimpath -buildvcs=false -mod=vendor" ;;
        GOTOOLCHAIN)  printf '%s' "go1.26.4" ;;
        CGO_ENABLED)  printf '%s' "0" ;;
        GOOS)         printf '%s' "windows" ;;
        GOARCH)       printf '%s' "amd64" ;;
        *)            return 1 ;;
    esac
}

# defenseclaw_repro_preflight refuses to run if any required env is
# missing, empty, has an unexpected fixed value, or (for
# SOURCE_DATE_EPOCH) is not a positive integer. Prints ONE diagnostic
# per issue so a caller who broke three envs fixes them in one round.
defenseclaw_repro_preflight() {
    local missing=()
    local name
    for name in "${REPRO_REQUIRED_ENVS[@]}"; do
        if [[ -z "${!name:-}" ]]; then
            missing+=("${name} is unset or empty")
            continue
        fi
        # SOURCE_DATE_EPOCH and DEFENSECLAW_BUILDID are per-build values
        # supplied by the caller; every other required env is a fixed
        # literal defined by _repro_expected_value above.
        if [[ "${name}" == "SOURCE_DATE_EPOCH" || "${name}" == "DEFENSECLAW_BUILDID" ]]; then
            continue
        fi
        local expected
        if ! expected="$(_repro_expected_value "${name}")"; then
            continue
        fi
        if [[ "${!name}" != "${expected}" ]]; then
            missing+=("${name} must be '${expected}' (got: '${!name}')")
        fi
    done
    if [[ -n "${SOURCE_DATE_EPOCH:-}" ]]; then
        if ! [[ "${SOURCE_DATE_EPOCH}" =~ ^[1-9][0-9]*$ ]]; then
            missing+=("SOURCE_DATE_EPOCH must be a positive integer (got: '${SOURCE_DATE_EPOCH}')")
        fi
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
#
# NOTE: `go build` itself has no `-buildid` flag; the build ID is a
# link-time argument passed via `-ldflags`. Passing `-buildid=...`
# directly to `go build` fails with "flag provided but not defined:
# -buildid". Always route the DEFENSECLAW_BUILDID pin through
# -ldflags.
defenseclaw_repro_build() {
    # Guard the arg-count check BEFORE reading $1/$2 so a caller
    # running with `set -u` sees the diagnostic below, not an
    # unbound-variable exit.
    if [[ $# -lt 2 ]]; then
        echo "defenseclaw_repro_build: <output-path> <package-path> required" >&2
        return 1
    fi
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
        -ldflags="-buildid=${DEFENSECLAW_BUILDID}" \
        -o "${out}" \
        "${pkg}"
}
