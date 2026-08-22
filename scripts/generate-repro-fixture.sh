#!/usr/bin/env bash
#
# generate-repro-fixture.sh
#
# Regenerates internal/build-repro/testdata/signed-payload-fixture.tar.zst
# from six deterministic placeholder files. Used by the Workstream E
# reproducibility gate (see docs/specs/001-windows-deterministic-build/).
#
# The generator produces byte-identical output on every run:
#   - Placeholder file contents are hard-coded short strings.
#   - tar(1) is called with --sort=name and mtime=@0 to freeze order
#     and timestamps.
#   - zstd is called with a fixed compression level and no progress
#     printing.
#
# The fixture MUST remain dummy-unsigned. See testdata/README.md.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REPO_ROOT

FIXTURE_DIR="${REPO_ROOT}/internal/build-repro/testdata"
FIXTURE_TAR_ZST="${FIXTURE_DIR}/signed-payload-fixture.tar.zst"

# require_bin — fail-fast for tools this script needs.
require_bin() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "generate-repro-fixture: missing required tool: $1" >&2
        exit 2
    }
}
require_bin tar
require_bin zstd

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

# Each entry: filename<TAB>fixed-content. Every content string is a
# short deterministic byte sequence, not a real PE/PS1. See
# testdata/README.md for why placeholder bytes are fine.
mkdir -p "${work}/payload"
printf 'DefenseClawEnterprise-module-fixture-v1\n'  > "${work}/payload/DefenseClawEnterprise.psm1"
printf 'defenseclaw-broker-fixture-v1\n'            > "${work}/payload/defenseclaw-cmid-broker.exe"
printf 'defenseclaw-gateway-fixture-v1\n'           > "${work}/payload/defenseclaw-gateway.exe"
printf 'defenseclaw-hook-fixture-v1\n'              > "${work}/payload/defenseclaw-hook.exe"
printf 'defenseclaw-cli-fixture-v1\n'               > "${work}/payload/defenseclaw.exe"
printf 'install-enterprise-fixture-v1\n'            > "${work}/payload/install-enterprise.ps1"

# BSD tar (macOS default) and GNU tar accept a slightly different flag
# set for reproducibility. Detect and branch.
#
# COPYFILE_DISABLE=1 tells macOS tar (which links to libarchive) NOT to
# include AppleDouble `._*` companion files carrying extended attributes.
# Without this, a tarball generated on macOS extracts to a mixed set of
# `foo` + `._foo` entries on Linux, which breaks the byte-stability
# contract and confuses gnu tar with 'implausibly old time stamp'
# warnings.
export COPYFILE_DISABLE=1
if tar --version 2>&1 | grep -qi 'gnu'; then
    tar \
        --sort=name \
        --owner=0 --group=0 --numeric-owner \
        --mtime='@0' \
        --no-xattrs \
        -C "${work}" \
        -cf "${work}/fixture.tar" \
        payload
else
    # BSD tar: --uid=0 --gid=0 --numeric-owner. `--no-xattrs` is BSD tar's
    # switch to skip xattrs; combined with COPYFILE_DISABLE this excludes
    # every AppleDouble `._*` entry a macOS host would otherwise inject.
    # Set mtimes to 0 in advance so BSD tar reads the frozen timestamp.
    # TZ=UTC pins the interpretation of `-t YYYYMMDDhhmm.ss` — without it,
    # a non-UTC host reads the argument in local time and the resulting
    # tar entry's mtime differs from a GNU-tar --mtime='@0' entry,
    # breaking cross-host fixture SHA-256 stability.
    TZ=UTC find "${work}/payload" -exec touch -t 197001010000.00 {} +
    tar \
        --uid 0 --gid 0 --numeric-owner \
        --no-xattrs \
        -C "${work}" \
        -cf "${work}/fixture.tar" \
        payload
fi

# Use a fixed compression level. --long=27 makes zstd emit a stable
# window-size flag so the same input+level produces the same output
# across zstd builds.
zstd --no-progress --long=27 -19 -q --force \
    -o "${FIXTURE_TAR_ZST}" \
    "${work}/fixture.tar"

sha=$(shasum -a 256 "${FIXTURE_TAR_ZST}" | awk '{print $1}')
echo "fixture: ${FIXTURE_TAR_ZST}"
echo "sha256:  ${sha}"
echo ""
echo "Update the FIXTURE_EXPECTED_SHA256 constant in"
echo "  .github/workflows/windows-deterministic-build.yml"
echo "to this value in the same PR that regenerates the fixture."
