#!/usr/bin/env bash
# DefenseClaw installer — downloads the latest release archive for the current platform.
# Mirrors the root install.sh logic to match GoReleaser archive naming.
set -euo pipefail

REPO="defenseclaw/defenseclaw"
BINARY="defenseclaw"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "${ARCH}" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *)       echo "Unsupported architecture: ${ARCH}" >&2; exit 1 ;;
esac

case "${OS}" in
    linux|darwin) ;;
    *) echo "Unsupported OS: ${OS}" >&2; exit 1 ;;
esac

echo "Detected: ${OS}/${ARCH}"
echo "Installing ${BINARY} to ${INSTALL_DIR}..."

if [ -n "${VERSION:-}" ]; then
    LATEST="$VERSION"
else
    LATEST=$(curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' | head -1 | sed 's/.*"v/v/' | sed 's/".*//')
fi

URL="https://github.com/${REPO}/releases/download/${LATEST}/${BINARY}_${LATEST#v}_${OS}_${ARCH}.tar.gz"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl -sSfL "${URL}" -o "${TMP}/${BINARY}.tar.gz"
tar -xzf "${TMP}/${BINARY}.tar.gz" -C "${TMP}"

if [ -w "${INSTALL_DIR}" ]; then
    mv "${TMP}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
else
    echo "Requires sudo to install to ${INSTALL_DIR}"
    sudo mv "${TMP}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
fi

chmod +x "${INSTALL_DIR}/${BINARY}"

echo "${BINARY} ${LATEST} installed to ${INSTALL_DIR}/${BINARY}"
echo ""
echo "Run 'defenseclaw init' to get started."
