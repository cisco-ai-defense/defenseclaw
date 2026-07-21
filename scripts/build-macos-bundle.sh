#!/usr/bin/env bash
#
# Assemble the macOS installer bundle: cross-build the gateway (single
# arch or universal via lipo), copy the installer scripts + plist +
# helpers, generate the README, then produce a tarball + sha256.
#
# Called by the `packaging-macos-bundle` Make target; extracted so the
# recipe stays a thin wrapper (per repo lint policy against oversized
# Make recipes).
#
# Args:
#   $1  BUNDLE_GOOS       (currently only "darwin" is supported)
#   $2  BUNDLE_GOARCH     ("amd64" | "arm64" | "universal")
#   $3  BUNDLE_NAME       e.g. defenseclaw-macos-0.8.0-darwin-arm64
#   $4  BUNDLE_DIR        e.g. dist/defenseclaw-macos-0.8.0-darwin-arm64
#   $5  DIST_DIR          e.g. dist
#   $6  VERSION           e.g. 0.8.0
#   $7  LDFLAGS           e.g. -X main.version=0.8.0
#                         (passed to `go build -ldflags` as-is)
#   $8  TAGS              (optional) comma-separated `go build -tags` value.
#                         Defaults to "cmid" — the managed bundle needs the
#                         managed cloud auth provider linked in. Pass "" to
#                         opt out (local packaging tests only).
#   $9  CMID_OVERLAY      (optional) path (absolute or relative to the repo
#                         root) to the real cloudreg provider_cisco.go file
#                         that imports the private managed cloud auth
#                         module. When non-empty AND TAGS contains "cmid",
#                         the script swaps this file into
#                         internal/managed/cloudreg/ before building and
#                         restores the OSS stub on exit. Required on the
#                         release box; unnecessary for OSS packaging tests.
#   $10 CMID_VERSION      (optional) pseudo-version of the private managed
#                         cloud auth module to `go get` after the overlay
#                         swap. Required when CMID_OVERLAY is non-empty.
#
# GOPRIVATE (from the environment) must be set on the release box so
# `go get` can resolve the pinned pseudo-version from its private origin.

set -euo pipefail

if [[ $# -lt 7 ]]; then
  echo "usage: $0 GOOS GOARCH BUNDLE_NAME BUNDLE_DIR DIST_DIR VERSION LDFLAGS [TAGS] [CMID_OVERLAY] [CMID_VERSION]" >&2
  exit 64
fi

BUNDLE_GOOS="$1"
BUNDLE_GOARCH="$2"
BUNDLE_NAME="$3"
BUNDLE_DIR="$4"
DIST_DIR="$5"
VERSION="$6"
LDFLAGS="$7"
# Use ${8-cmid} (no colon) so an intentionally empty override
# (BUNDLE_TAGS="") is preserved — only truly-unset arg #8 defaults to
# "cmid". The Makefile documents the empty override for local
# packaging tests that don't have the private overlay handy.
TAGS="${8-cmid}"
CMID_OVERLAY="${9:-}"
CMID_VERSION="${10:-}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ---- input validation ---------------------------------------------------

if [[ "${BUNDLE_GOOS}" != "darwin" ]]; then
  echo "build-macos-bundle: BUNDLE_GOOS must be 'darwin' (got '${BUNDLE_GOOS}')" >&2
  exit 1
fi
case "${BUNDLE_GOARCH}" in
  amd64|arm64|universal) ;;
  *)
    echo "build-macos-bundle: BUNDLE_GOARCH must be amd64, arm64, or universal (got '${BUNDLE_GOARCH}')" >&2
    exit 1
    ;;
esac

echo "==> packaging macOS bundle: ${BUNDLE_NAME}"
rm -rf "${BUNDLE_DIR}"
mkdir -p "${BUNDLE_DIR}/lib"

# ---- managed cloud auth provider overlay (release-only) ---------------
#
# The OSS repo commits a stub at internal/managed/cloudreg/provider_cisco.go
# (an empty init(); no external imports) so public builds succeed with
# no private-registry access. Managed release builds swap in the real
# file before `go build -tags cmid`, then restore the stub after
# (whether the build succeeds or fails), leaving the working tree clean
# for the next run.
#
# The overlay is only applied when -tags cmid is active AND CMID_OVERLAY
# (arg #9) is non-empty. Before mutating anything, we snapshot the three
# files we're about to touch (provider_cisco.go, go.mod, go.sum) into a
# temp dir; on exit we copy them back verbatim — no git dependency, so
# this works whether or not the source files were tracked / committed
# before the build.

CLOUDREG_TARGET="${REPO_ROOT}/internal/managed/cloudreg/provider_cisco.go"
OVERLAY_APPLIED=0
OVERLAY_SNAPSHOT_DIR=""

restore_overlay() {
  if [[ "${OVERLAY_APPLIED}" -eq 1 ]] && [[ -n "${OVERLAY_SNAPSHOT_DIR}" ]] && [[ -d "${OVERLAY_SNAPSHOT_DIR}" ]]; then
    echo "==> restoring cloudreg stub + go.mod/go.sum from snapshot"
    cp "${OVERLAY_SNAPSHOT_DIR}/provider_cisco.go" "${CLOUDREG_TARGET}"
    cp "${OVERLAY_SNAPSHOT_DIR}/go.mod"           "${REPO_ROOT}/go.mod"
    cp "${OVERLAY_SNAPSHOT_DIR}/go.sum"           "${REPO_ROOT}/go.sum"
    OVERLAY_APPLIED=0
  fi
  if [[ -n "${OVERLAY_SNAPSHOT_DIR}" ]] && [[ -d "${OVERLAY_SNAPSHOT_DIR}" ]]; then
    rm -rf "${OVERLAY_SNAPSHOT_DIR}"
  fi
}
trap restore_overlay EXIT

if [[ ",${TAGS}," == *",cmid,"* ]] && [[ -n "${CMID_OVERLAY}" ]]; then
  if [[ -z "${CMID_VERSION}" ]]; then
    echo "build-macos-bundle: CMID_OVERLAY is set but CMID_VERSION is empty — pass CMID_VERSION=<pseudo-version> to Make" >&2
    exit 1
  fi
  OVERLAY_ABS="${CMID_OVERLAY}"
  [[ "${OVERLAY_ABS}" != /* ]] && OVERLAY_ABS="${REPO_ROOT}/${OVERLAY_ABS}"
  if [[ ! -f "${OVERLAY_ABS}" ]]; then
    echo "build-macos-bundle: overlay file not found: ${OVERLAY_ABS}" >&2
    exit 1
  fi
  OVERLAY_SNAPSHOT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/dc-cmid-overlay.XXXXXX")"
  echo "==> snapshotting cloudreg stub + go.mod/go.sum to ${OVERLAY_SNAPSHOT_DIR}"
  cp "${CLOUDREG_TARGET}"     "${OVERLAY_SNAPSHOT_DIR}/provider_cisco.go"
  cp "${REPO_ROOT}/go.mod"    "${OVERLAY_SNAPSHOT_DIR}/go.mod"
  cp "${REPO_ROOT}/go.sum"    "${OVERLAY_SNAPSHOT_DIR}/go.sum"
  # Flip OVERLAY_APPLIED BEFORE the swap: a mid-write `cp` failure past
  # this point corrupts CLOUDREG_TARGET, and we still want the trap to
  # restore it from the snapshot.
  OVERLAY_APPLIED=1
  echo "==> applying cloudreg overlay: ${OVERLAY_ABS}"
  cp "${OVERLAY_ABS}" "${CLOUDREG_TARGET}"
  echo "==> pinning managed cloud auth module @${CMID_VERSION}"
  ( cd "${REPO_ROOT}" && go get "github.com/cisco-aispg/ai-common/cmid@${CMID_VERSION}" )
fi

# ---- build gateway ------------------------------------------------------

# Array-form invocation so we don't re-parse a shell string via eval;
# LDFLAGS is passed to `go build -ldflags <value>` as a single argument.
build_arch() {
  local arch="$1" out="$2"
  echo "==> building gateway (darwin/${arch}${TAGS:+ tags=${TAGS}})"
  local -a go_args=(build)
  if [[ -n "${TAGS}" ]]; then
    go_args+=(-tags "${TAGS}")
  fi
  go_args+=(-ldflags "${LDFLAGS}" -o "${out}" ./cmd/defenseclaw)
  GOOS=darwin GOARCH="${arch}" CGO_ENABLED=0 go "${go_args[@]}"
}

# The shipped artifact file is named "defenseclaw" (not "defenseclaw-gateway").
# install.sh discovers it bundle-locally under this name and installs it to the
# runtime path .../bin/defenseclaw-gateway, which stays the canonical daemon
# name everywhere else (launchd, systemd, watchdog, process detection).
cd "${REPO_ROOT}"
if [[ "${BUNDLE_GOARCH}" == "universal" ]]; then
  command -v lipo >/dev/null 2>&1 \
    || { echo "build-macos-bundle: 'lipo' not found — universal builds must run on macOS with Xcode CLT" >&2; exit 1; }
  build_arch amd64 "${BUNDLE_DIR}/defenseclaw.amd64"
  build_arch arm64 "${BUNDLE_DIR}/defenseclaw.arm64"
  echo "==> lipo-creating universal binary"
  lipo -create -output "${BUNDLE_DIR}/defenseclaw" \
    "${BUNDLE_DIR}/defenseclaw.amd64" \
    "${BUNDLE_DIR}/defenseclaw.arm64"
  rm -f "${BUNDLE_DIR}/defenseclaw.amd64" "${BUNDLE_DIR}/defenseclaw.arm64"
  lipo -info "${BUNDLE_DIR}/defenseclaw"
else
  build_arch "${BUNDLE_GOARCH}" "${BUNDLE_DIR}/defenseclaw"
fi
chmod 0755 "${BUNDLE_DIR}/defenseclaw"

# ---- copy installer scripts + plist -------------------------------------

echo "==> copying installer scripts"
cp packaging/macos/install.sh                       "${BUNDLE_DIR}/install.sh"
cp packaging/macos/uninstall.sh                     "${BUNDLE_DIR}/uninstall.sh"
cp packaging/macos/lib/installer_lib.sh             "${BUNDLE_DIR}/lib/installer_lib.sh"
cp packaging/macos/lib/scrub_agent_configs.py       "${BUNDLE_DIR}/lib/scrub_agent_configs.py"
cp packaging/launchd/com.cisco.secureclient.defenseclaw.plist \
    "${BUNDLE_DIR}/com.cisco.secureclient.defenseclaw.plist"
chmod 0755 "${BUNDLE_DIR}/install.sh" "${BUNDLE_DIR}/uninstall.sh"
chmod 0755 "${BUNDLE_DIR}/lib/installer_lib.sh" "${BUNDLE_DIR}/lib/scrub_agent_configs.py"
chmod 0644 "${BUNDLE_DIR}/com.cisco.secureclient.defenseclaw.plist"

# ---- README -------------------------------------------------------------

echo "==> writing README"
scripts/write-macos-bundle-readme.sh \
  "${BUNDLE_DIR}/README.md" \
  "${VERSION}" \
  "${BUNDLE_GOOS}" \
  "${BUNDLE_GOARCH}"

# ---- tarball + checksum -------------------------------------------------

echo "==> creating tarball"
( cd "${DIST_DIR}" && tar -czf "${BUNDLE_NAME}.tar.gz" "${BUNDLE_NAME}" )
( cd "${DIST_DIR}" && shasum -a 256 "${BUNDLE_NAME}.tar.gz" > "${BUNDLE_NAME}.tar.gz.sha256" )

echo ""
echo "==> bundle ready:"
echo "    ${BUNDLE_DIR}/"
echo "    ${DIST_DIR}/${BUNDLE_NAME}.tar.gz"
echo "    ${DIST_DIR}/${BUNDLE_NAME}.tar.gz.sha256"
