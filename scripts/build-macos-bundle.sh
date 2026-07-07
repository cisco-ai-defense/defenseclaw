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
#   $1  BUNDLE_GOOS      (currently only "darwin" is supported)
#   $2  BUNDLE_GOARCH    ("amd64" | "arm64" | "universal")
#   $3  BUNDLE_NAME      e.g. defenseclaw-macos-0.8.0-darwin-arm64
#   $4  BUNDLE_DIR       e.g. dist/defenseclaw-macos-0.8.0-darwin-arm64
#   $5  DIST_DIR         e.g. dist
#   $6  VERSION          e.g. 0.8.0
#   $7  LDFLAGS          e.g. -X main.version=0.8.0
#                        (passed to `go build -ldflags` as-is)

set -euo pipefail

if [[ $# -lt 7 ]]; then
  echo "usage: $0 GOOS GOARCH BUNDLE_NAME BUNDLE_DIR DIST_DIR VERSION LDFLAGS" >&2
  exit 64
fi

BUNDLE_GOOS="$1"
BUNDLE_GOARCH="$2"
BUNDLE_NAME="$3"
BUNDLE_DIR="$4"
DIST_DIR="$5"
VERSION="$6"
LDFLAGS="$7"

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

# ---- build gateway ------------------------------------------------------

# Array-form invocation so we don't re-parse a shell string via eval;
# LDFLAGS is passed to `go build -ldflags <value>` as a single argument.
build_arch() {
  local arch="$1" out="$2"
  echo "==> building gateway (darwin/${arch})"
  local -a go_args=(build -ldflags "${LDFLAGS}" -o "${out}" ./cmd/defenseclaw)
  GOOS=darwin GOARCH="${arch}" CGO_ENABLED=0 go "${go_args[@]}"
}

cd "${REPO_ROOT}"
if [[ "${BUNDLE_GOARCH}" == "universal" ]]; then
  command -v lipo >/dev/null 2>&1 \
    || { echo "build-macos-bundle: 'lipo' not found — universal builds must run on macOS with Xcode CLT" >&2; exit 1; }
  build_arch amd64 "${BUNDLE_DIR}/defenseclaw-gateway.amd64"
  build_arch arm64 "${BUNDLE_DIR}/defenseclaw-gateway.arm64"
  echo "==> lipo-creating universal binary"
  lipo -create -output "${BUNDLE_DIR}/defenseclaw-gateway" \
    "${BUNDLE_DIR}/defenseclaw-gateway.amd64" \
    "${BUNDLE_DIR}/defenseclaw-gateway.arm64"
  rm -f "${BUNDLE_DIR}/defenseclaw-gateway.amd64" "${BUNDLE_DIR}/defenseclaw-gateway.arm64"
  lipo -info "${BUNDLE_DIR}/defenseclaw-gateway"
else
  build_arch "${BUNDLE_GOARCH}" "${BUNDLE_DIR}/defenseclaw-gateway"
fi
chmod 0755 "${BUNDLE_DIR}/defenseclaw-gateway"

# ---- copy installer scripts + plist -------------------------------------

echo "==> copying installer scripts"
cp packaging/macos/install.sh                       "${BUNDLE_DIR}/install.sh"
cp packaging/macos/uninstall.sh                     "${BUNDLE_DIR}/uninstall.sh"
cp packaging/macos/lib/installer_lib.sh             "${BUNDLE_DIR}/lib/installer_lib.sh"
cp packaging/macos/lib/scrub_agent_configs.py       "${BUNDLE_DIR}/lib/scrub_agent_configs.py"
cp packaging/launchd/com.defenseclaw.gateway.plist  "${BUNDLE_DIR}/com.defenseclaw.gateway.plist"
chmod 0755 "${BUNDLE_DIR}/install.sh" "${BUNDLE_DIR}/uninstall.sh"
chmod 0755 "${BUNDLE_DIR}/lib/installer_lib.sh" "${BUNDLE_DIR}/lib/scrub_agent_configs.py"
chmod 0644 "${BUNDLE_DIR}/com.defenseclaw.gateway.plist"

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
