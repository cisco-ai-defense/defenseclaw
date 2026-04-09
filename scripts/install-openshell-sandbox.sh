#!/usr/bin/env bash
#
# Install openshell-sandbox from NVIDIA's OCI image — no Docker required.
#
# Extracts the openshell-sandbox binary directly from the
# ghcr.io/nvidia/openshell/cluster image using the OCI distribution
# API. Only the layer containing the binary is downloaded (~6MB),
# not the full image.
#
# Requirements: curl, tar, python3 (for JSON parsing)
#
# Usage:
#   ./install-openshell-sandbox.sh
#   OPENSHELL_VERSION=0.0.15 ./install-openshell-sandbox.sh
#   ./install-openshell-sandbox.sh --install-dir /usr/local/bin
#   ./install-openshell-sandbox.sh --help
#
set -euo pipefail

main() {

# ── Defaults ─────────────────────────────────────────────────────────────────

OPENSHELL_VERSION="${OPENSHELL_VERSION:-0.0.16}"
INSTALL_DIR="${OPENSHELL_INSTALL_DIR:-${HOME}/.local/bin}"
OCI_IMAGE="nvidia/openshell/cluster"
OCI_REGISTRY="ghcr.io"
BINARY_NAME="openshell-sandbox"
BINARY_PATH_IN_IMAGE="opt/openshell/bin/openshell-sandbox"

# ── Terminal Formatting ──────────────────────────────────────────────────────

if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'
    DIM='\033[2m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; DIM=''; NC=''
fi

info()  { printf "${BLUE}  ▸${NC} %s\n" "$*"; }
ok()    { printf "${GREEN}  ✓${NC} %s\n" "$*"; }
warn()  { printf "${YELLOW}  !${NC} %s\n" "$*" >&2; }
err()   { printf "${RED}  ✗${NC} %s\n" "$*" >&2; }
die()   { err "$@"; exit 1; }

# ── Argument parsing ─────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)
            [[ $# -lt 2 ]] && die "--version requires a value"
            OPENSHELL_VERSION="$2"; shift 2 ;;
        --install-dir)
            [[ $# -lt 2 ]] && die "--install-dir requires a path"
            INSTALL_DIR="$2"; shift 2 ;;
        --help|-h)
            cat <<USAGE
Usage: install-openshell-sandbox.sh [OPTIONS]

Install the openshell-sandbox binary from NVIDIA's OCI image.
No Docker daemon required — uses the OCI distribution API directly.

Options:
  --version VERSION   OpenShell version to install (default: ${OPENSHELL_VERSION})
  --install-dir DIR   Where to place the binary (default: ~/.local/bin)
  --help, -h          Show this help

Environment variables:
  OPENSHELL_VERSION      Same as --version
  OPENSHELL_INSTALL_DIR  Same as --install-dir
USAGE
            exit 0 ;;
        *) die "Unknown option: $1" ;;
    esac
done

# ── Preflight checks ────────────────────────────────────────────────────────

printf "\n${BOLD}  openshell-sandbox installer${NC}\n"
printf "  ${DIM}Version: ${OPENSHELL_VERSION} | Source: ${OCI_REGISTRY}/${OCI_IMAGE}${NC}\n\n"

for cmd in curl tar python3; do
    if ! command -v "$cmd" &>/dev/null; then
        die "${cmd} is required but not found"
    fi
done

OS="$(uname -s)"
ARCH="$(uname -m)"

if [[ "${OS}" != "Linux" ]]; then
    die "openshell-sandbox requires Linux (detected: ${OS})"
fi

case "${ARCH}" in
    x86_64|amd64)  OCI_ARCH="amd64" ;;
    aarch64|arm64) OCI_ARCH="arm64" ;;
    *) die "Unsupported architecture: ${ARCH}" ;;
esac

if command -v "${BINARY_NAME}" &>/dev/null; then
    existing="$("${BINARY_NAME}" --version 2>&1 | awk '{print $NF}')"
    ok "${BINARY_NAME} ${existing} already installed at $(command -v "${BINARY_NAME}")"
    exit 0
fi

info "Target: linux/${OCI_ARCH}"

# ── Helper: JSON field extraction without jq ─────────────────────────────────

_json() {
    python3 -c "import sys,json; print(json.load(sys.stdin)$1)"
}

# ── Helper: get a fresh auth token ───────────────────────────────────────────

_auth_token() {
    curl -fsSL \
        "https://${OCI_REGISTRY}/token?service=${OCI_REGISTRY}&scope=repository:${OCI_IMAGE}:pull" \
        | _json "['token']"
}

# ── Step 1: Resolve the platform-specific manifest digest ────────────────────

info "Fetching manifest index..."

TOKEN="$(_auth_token)"

ARCH_DIGEST=$(curl -fsSL \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.index.v1+json" \
    "https://${OCI_REGISTRY}/v2/${OCI_IMAGE}/manifests/${OPENSHELL_VERSION}" \
    | python3 -c "
import sys, json
idx = json.load(sys.stdin)
for m in idx.get('manifests', []):
    p = m.get('platform', {})
    if p.get('architecture') == '${OCI_ARCH}' and p.get('os') == 'linux':
        print(m['digest'])
        sys.exit(0)
sys.exit(1)
") || die "No linux/${OCI_ARCH} manifest in ${OCI_IMAGE}:${OPENSHELL_VERSION}"

# ── Step 2: Fetch platform manifest + image config ──────────────────────────

info "Fetching image metadata..."

TOKEN="$(_auth_token)"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

curl -fsSL \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
    "https://${OCI_REGISTRY}/v2/${OCI_IMAGE}/manifests/${ARCH_DIGEST}" \
    > "${TMPDIR}/manifest.json" \
    || die "Failed to fetch platform manifest"

CONFIG_DIGEST=$(python3 -c "
import json
with open('${TMPDIR}/manifest.json') as f:
    print(json.load(f)['config']['digest'])
")

curl -fsSL \
    -H "Authorization: Bearer ${TOKEN}" \
    "https://${OCI_REGISTRY}/v2/${OCI_IMAGE}/blobs/${CONFIG_DIGEST}" \
    > "${TMPDIR}/config.json" \
    || die "Failed to fetch image config"

# ── Step 3: Walk Dockerfile history to find the sandbox layer ────────────────

LAYER_INDEX=$(python3 -c "
import json
with open('${TMPDIR}/config.json') as f:
    cfg = json.load(f)
idx = 0
for h in cfg.get('history', []):
    if h.get('empty_layer'):
        continue
    if '${BINARY_NAME}' in h.get('created_by', ''):
        print(idx)
        break
    idx += 1
else:
    print(-1)
")

if [[ "${LAYER_INDEX}" == "-1" ]]; then
    die "Could not locate ${BINARY_NAME} in image layer history — image format may have changed"
fi

LAYER_INFO=$(python3 -c "
import json
with open('${TMPDIR}/manifest.json') as f:
    layer = json.load(f)['layers'][${LAYER_INDEX}]
print(layer['digest'], layer['size'])
")
LAYER_DIGEST="${LAYER_INFO%% *}"
LAYER_BYTES="${LAYER_INFO##* }"
LAYER_MB=$(( LAYER_BYTES / 1048576 ))

info "Downloading sandbox binary (~${LAYER_MB}MB compressed)..."

# ── Step 4: Download the single layer and extract ────────────────────────────

TOKEN="$(_auth_token)"

curl -fsSL \
    -H "Authorization: Bearer ${TOKEN}" \
    "https://${OCI_REGISTRY}/v2/${OCI_IMAGE}/blobs/${LAYER_DIGEST}" \
    | tar xzf - -C "${TMPDIR}" "${BINARY_PATH_IN_IMAGE}" 2>/dev/null \
    || die "Failed to extract ${BINARY_NAME} from layer"

EXTRACTED="${TMPDIR}/${BINARY_PATH_IN_IMAGE}"
if [[ ! -f "${EXTRACTED}" ]]; then
    die "${BINARY_NAME} not found in extracted layer — image layout may have changed"
fi

# ── Step 5: Install ──────────────────────────────────────────────────────────

mkdir -p "${INSTALL_DIR}" 2>/dev/null || true

if [[ -w "${INSTALL_DIR}" ]] || mkdir -p "${INSTALL_DIR}" 2>/dev/null; then
    install -m 755 "${EXTRACTED}" "${INSTALL_DIR}/${BINARY_NAME}"
else
    info "Elevated permissions required to install to ${INSTALL_DIR}"
    sudo mkdir -p "${INSTALL_DIR}"
    sudo install -m 755 "${EXTRACTED}" "${INSTALL_DIR}/${BINARY_NAME}"
fi

# ── Step 6: Verify ───────────────────────────────────────────────────────────

INSTALLED_VER="$("${INSTALL_DIR}/${BINARY_NAME}" --version 2>&1 | awk '{print $NF}' || echo "${OPENSHELL_VERSION}")"
ok "${BINARY_NAME} ${INSTALLED_VER} installed to ${INSTALL_DIR}/${BINARY_NAME}"

# PATH hint
case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
        echo ""
        warn "${INSTALL_DIR} is not on your PATH"
        info "Add to your shell config:"
        printf "    ${CYAN}export PATH=\"%s:\$PATH\"${NC}\n" "${INSTALL_DIR}"
        ;;
esac

echo ""

}

main "$@"
