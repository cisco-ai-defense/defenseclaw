#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

#
# DefenseClaw Upgrade Script
#
# Downloads the gateway binary and Python CLI wheel from a GitHub release,
# runs version-specific migrations, and restarts services.
#
# Non-destructive: artifacts are downloaded and verified BEFORE the gateway
# is stopped, so a failed download never disrupts a running gateway.
#
# Plugin installation is NOT handled here — it is part of the initial
# release install (install.sh) and is release-specific.
#
# Usage:
#   ./scripts/upgrade.sh [--yes] [--version VERSION] [--help]
#
# Options:
#   --yes, -y             Skip confirmation prompts
#   --version VERSION     Upgrade to a specific release (default: latest)
#   --help, -h            Show this help
#
# Environment variables:
#   VERSION               Same as --version
#   DEFENSECLAW_HOME      Override install directory (default: ~/.defenseclaw)
#   OPENCLAW_HOME         Override OpenClaw config dir (default: ~/.openclaw)
#
set -euo pipefail

main() {

# ── Configuration ─────────────────────────────────────────────────────────────

readonly DEFENSECLAW_HOME="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
readonly DEFENSECLAW_VENV="${DEFENSECLAW_HOME}/.venv"
readonly INSTALL_DIR="${HOME}/.local/bin"
readonly OPENCLAW_HOME="${OPENCLAW_HOME:-${HOME}/.openclaw}"
readonly BACKUP_ROOT="${DEFENSECLAW_HOME}/backups"
readonly REPO="cisco-ai-defense/defenseclaw"
readonly UPGRADE_PROTOCOL_VERSION=1
readonly UPGRADE_MANIFEST_NAME="upgrade-manifest.json"

# ── Terminal Formatting ───────────────────────────────────────────────────────

if [[ -t 1 ]] || [[ "${FORCE_COLOR:-}" == "1" ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'
    DIM='\033[2m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; DIM=''; NC=''
fi

# ── Logging ───────────────────────────────────────────────────────────────────

info()    { printf "${BLUE}  ▸${NC} %s\n" "$*"; }
ok()      { printf "${GREEN}  ✓${NC} %s\n" "$*"; }
warn()    { printf "${YELLOW}  !${NC} %s\n" "$*"; }
err()     { printf "${RED}  ✗${NC} %s\n" "$*" >&2; }
section() { printf "\n${BOLD}${CYAN}─── %s${NC}\n\n" "$*"; }
step()    { printf "  ${CYAN}→${NC} %s\n" "$*"; }

die() { err "$@"; exit 1; }
has() { command -v "$1" &>/dev/null; }

validate_version() {
    local version="$1"
    [[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
        || die "Invalid release version: ${version}. Expected MAJOR.MINOR.PATCH."
}

preflight_python_wheel() {
    local wheel="$1"
    local uv_bin
    uv_bin="$(command -v uv 2>/dev/null || true)"
    [[ -z "${uv_bin}" ]] \
        && die "uv not found on PATH — cannot update Python CLI. Install uv, then re-run the upgrade."

    local preflight_python="${DEFENSECLAW_VENV}/bin/python"
    if [[ ! -x "${preflight_python}" ]]; then
        local preflight_venv="${STAGING_DIR}/wheel-preflight-venv"
        "${uv_bin}" --no-config venv "${preflight_venv}" --python 3.12 --quiet \
            || die "Could not create Python CLI preflight environment; no services changed."
        preflight_python="${preflight_venv}/bin/python"
    fi

    step "Resolving Python CLI dependencies ..."
    "${uv_bin}" --no-config pip install --python "${preflight_python}" --dry-run --quiet "${wheel}" \
        || die "Python CLI wheel dependencies are unsatisfiable; no services changed."
    ok "Python CLI dependency preflight passed"
}

# ── Argument Parsing ──────────────────────────────────────────────────────────

YES=0
RELEASE_VERSION="${VERSION:-}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes|-y)   YES=1; shift ;;
        --version)
            [[ $# -lt 2 ]] && die "--version requires a value"
            RELEASE_VERSION="$2"; shift 2 ;;
        --help|-h)
            cat <<EOF

  DefenseClaw Upgrade Script

  Usage: $(basename "$0") [OPTIONS]

  Options:
    --yes, -y             Skip confirmation prompts
    --version VERSION     Upgrade to a specific release (e.g. 0.2.0)
    --help, -h            Show this help

  Environment variables:
    VERSION               Same as --version
    DEFENSECLAW_HOME      Override install directory (default: ~/.defenseclaw)
    OPENCLAW_HOME         Override OpenClaw config dir (default: ~/.openclaw)

EOF
                exit 0 ;;
        *) err "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Header ────────────────────────────────────────────────────────────────────

printf "\n"
printf "${BOLD}  DefenseClaw Upgrade${NC}\n"
printf "  ${DIM}Downloads release artifacts from GitHub and replaces installed files${NC}\n"
printf "\n"

# ── Platform Detection ────────────────────────────────────────────────────────

section "Detecting Platform"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "${ARCH}" in
    x86_64|amd64)  ARCH_NORM="amd64" ;;
    aarch64|arm64) ARCH_NORM="arm64" ;;
    *) die "Unsupported architecture: ${ARCH}" ;;
esac

case "${OS}" in
    darwin) OS_NAME="macOS" ;;
    linux)  OS_NAME="Linux" ;;
    *)      die "Unsupported OS: ${OS}" ;;
esac

ok "${OS_NAME} (${ARCH_NORM})"

# ── Resolve target release version ───────────────────────────────────────────

section "Resolving Release Version"

if [[ -n "${RELEASE_VERSION}" ]]; then
    RELEASE_VERSION="${RELEASE_VERSION#v}"
    validate_version "${RELEASE_VERSION}"
    ok "Target version: ${RELEASE_VERSION}"
else
    info "Fetching latest release from GitHub..."
    RELEASE_VERSION=$(curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep -oE '"tag_name": *"[^"]+"' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+') \
        || die "Failed to fetch latest release. Use --version x.y.z to specify explicitly."
    [[ -n "${RELEASE_VERSION}" ]] \
        || die "Could not parse latest release version. Use --version x.y.z to specify explicitly."
    validate_version "${RELEASE_VERSION}"
    ok "Latest release: ${RELEASE_VERSION}"
fi

# ── Detect currently installed version ───────────────────────────────────────

CURRENT_VERSION="unknown"
if has defenseclaw; then
    CURRENT_VERSION=$(defenseclaw --version 2>/dev/null \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 \
        || python3 -c "from defenseclaw import __version__; print(__version__)" 2>/dev/null \
        || echo "unknown")
fi
CURRENT_VERSION="${CURRENT_VERSION:-unknown}"

ok "Installed version : ${CURRENT_VERSION}"
ok "Upgrade target    : ${RELEASE_VERSION}"

# ── Same-version repair ──────────────────────────────────────────────────────

if [[ "${CURRENT_VERSION}" == "${RELEASE_VERSION}" ]]; then
    warn "Already at version ${RELEASE_VERSION}; continuing to re-apply artifacts and same-version migrations"
fi

# ── Artifact helper ───────────────────────────────────────────────────────────

fetch_artifact() {
    local url="$1" dest="$2"
    local attempt
    for attempt in 1 2 3; do
        if curl -sSfL "${url}" -o "${dest}"; then
            return 0
        fi
        [[ "${attempt}" -lt 3 ]] || break
        sleep $((2 ** (attempt - 1)))
    done
    die "Failed to download: ${url}"
}

fetch_optional_artifact() {
    local url="$1" dest="$2"
    local attempt
    for attempt in 1 2 3; do
        if curl -sSfL "${url}" -o "${dest}" 2>/dev/null; then
            return 0
        fi
        [[ "${attempt}" -lt 3 ]] || break
        sleep $((2 ** (attempt - 1)))
    done
    return 1
}

# ── Pre-flight: verify artifacts exist before touching anything ───────────────

section "Pre-flight Check"

TARBALL_NAME="defenseclaw_${RELEASE_VERSION}_${OS}_${ARCH_NORM}.tar.gz"
WHL_NAME="defenseclaw-${RELEASE_VERSION}-py3-none-any.whl"
TARBALL_URL="https://github.com/${REPO}/releases/download/${RELEASE_VERSION}/${TARBALL_NAME}"
WHL_URL="https://github.com/${REPO}/releases/download/${RELEASE_VERSION}/${WHL_NAME}"
CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${RELEASE_VERSION}/checksums.txt"
CHECKSUMS_SIG_URL="${CHECKSUMS_URL}.sig"
CHECKSUMS_CERT_URL="${CHECKSUMS_URL}.pem"
UPGRADE_MANIFEST_URL="https://github.com/${REPO}/releases/download/${RELEASE_VERSION}/${UPGRADE_MANIFEST_NAME}"

for artifact_url in "${TARBALL_URL}" "${WHL_URL}"; do
    http_code=$(curl -sSo /dev/null -w "%{http_code}" -L --head "${artifact_url}" 2>/dev/null || echo "000")
    if [[ "${http_code}" -ge 400 || "${http_code}" == "000" ]]; then
        die "Artifact not found (HTTP ${http_code}): ${artifact_url}
  Version ${RELEASE_VERSION} may not exist or is missing platform artifacts."
    fi
done
ok "Release artifacts verified"

# ── Download artifacts to staging (gateway still running) ─────────────────────

section "Downloading Artifacts"

STAGING_DIR="$(mktemp -d)"
trap 'rm -rf "${STAGING_DIR}"' EXIT

# Pull checksums.txt FIRST so every downloaded artifact is verified against
# the published goreleaser manifest. Old releases may not publish one; in
# that case we proceed with a clear warning rather than blocking the
# upgrade. ``CHECKSUMS_FILE=""`` signals "no manifest available" downstream.
CHECKSUMS_FILE=""
CHECKSUMS_SIG_FILE=""
CHECKSUMS_CERT_FILE=""
ASSET_DIGESTS_FILE=""
UPGRADE_MANIFEST_FILE=""
MIGRATION_FAILURE_POLICY="warn"
REQUIRED_MIGRATIONS_MISSING=""
UPGRADE_INCOMPLETE=0
if fetch_optional_artifact "${CHECKSUMS_URL}" "${STAGING_DIR}/checksums.txt"; then
    CHECKSUMS_FILE="${STAGING_DIR}/checksums.txt"
    ok "Checksum manifest downloaded (checksums.txt)"
else
    warn "checksums.txt unavailable — release artifacts will be downloaded WITHOUT integrity verification"
fi

if [[ -n "${CHECKSUMS_FILE}" ]]; then
    if fetch_optional_artifact "${CHECKSUMS_SIG_URL}" "${STAGING_DIR}/checksums.txt.sig"; then
        CHECKSUMS_SIG_FILE="${STAGING_DIR}/checksums.txt.sig"
    fi
    if fetch_optional_artifact "${CHECKSUMS_CERT_URL}" "${STAGING_DIR}/checksums.txt.pem"; then
        CHECKSUMS_CERT_FILE="${STAGING_DIR}/checksums.txt.pem"
    fi
fi

fetch_asset_digests() {
    [[ -n "${ASSET_DIGESTS_FILE}" ]] && return 0
    command -v python3 &>/dev/null || return 1

    local release_json="${STAGING_DIR}/release-assets.json"
    local digests="${STAGING_DIR}/asset-digests.txt"
    curl -sSfL "https://api.github.com/repos/${REPO}/releases/tags/${RELEASE_VERSION}" \
        -o "${release_json}" 2>/dev/null || return 1
    python3 - "${release_json}" > "${digests}" <<'PY' || return 1
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)

for asset in data.get("assets", []):
    name = asset.get("name")
    digest = asset.get("digest") or ""
    if not isinstance(name, str) or not isinstance(digest, str):
        continue
    if not digest.startswith("sha256:"):
        continue
    sha = digest.split(":", 1)[1]
    if len(sha) == 64 and all(c in "0123456789abcdefABCDEF" for c in sha):
        print(sha.lower(), name)
PY
    [[ -s "${digests}" ]] || return 1
    ASSET_DIGESTS_FILE="${digests}"
}

# Pick a sha256 implementation once, up-front, so verify_checksum below is
# branch-free in the hot path.
SHA256_CMD=""
if command -v sha256sum &>/dev/null; then
    SHA256_CMD="sha256sum"
elif command -v shasum &>/dev/null; then
    SHA256_CMD="shasum -a 256"
else
    if [[ -n "${CHECKSUMS_FILE}" ]]; then
        die "Neither sha256sum nor shasum found — cannot verify release checksums"
    fi
fi

verify_checksum() {
    local file="$1" filename="$2"
    [[ -z "${CHECKSUMS_FILE}" ]] && ! fetch_asset_digests && return 0
    local expected actual
    expected=""
    if [[ -n "${CHECKSUMS_FILE}" ]]; then
        expected="$(awk -v f="${filename}" '$2 == f || $2 == "./" f {print $1; exit}' "${CHECKSUMS_FILE}")"
    fi
    if [[ -z "${expected}" ]] && fetch_asset_digests; then
        expected="$(awk -v f="${filename}" '$2 == f {print $1; exit}' "${ASSET_DIGESTS_FILE}")"
        [[ -n "${expected}" ]] \
            && warn "checksums.txt missing ${filename}; using GitHub release asset digest."
    fi
    if [[ -z "${expected}" ]]; then
        die "No checksum entry for ${filename} in checksums.txt or GitHub asset metadata — refusing to install an unrecognized artifact"
    fi
    [[ -n "${SHA256_CMD}" ]] \
        || die "No sha256 tool found — cannot verify ${filename}"
    actual="$(${SHA256_CMD} "${file}" | awk '{print $1}')"
    # tr-based lowercasing because macOS ships bash 3.2 where ``${var,,}`` is unavailable.
    expected="$(printf '%s' "${expected}" | tr '[:upper:]' '[:lower:]')"
    actual="$(printf '%s' "${actual}" | tr '[:upper:]' '[:lower:]')"
    if [[ "${expected}" != "${actual}" ]]; then
        die "Checksum mismatch for ${filename}: expected ${expected}, got ${actual}
  Refusing to install — possible tampering or corrupted download."
    fi
}

verify_checksums_sigstore() {
    [[ -z "${CHECKSUMS_FILE}" ]] && return 0
    if [[ -z "${CHECKSUMS_SIG_FILE}" && -z "${CHECKSUMS_CERT_FILE}" ]]; then
        return 0
    fi
    if [[ -z "${CHECKSUMS_SIG_FILE}" || -z "${CHECKSUMS_CERT_FILE}" ]]; then
        warn "checksums.txt Sigstore signature assets are incomplete; continuing without signature verification."
        return 0
    fi
    if ! command -v cosign >/dev/null 2>&1; then
        warn "checksums.txt Sigstore signature is present, but cosign was not found on PATH; continuing without signature verification."
        return 0
    fi

    local cosign_output
    if ! cosign_output="$(cosign verify-blob \
        --certificate "${CHECKSUMS_CERT_FILE}" \
        --signature "${CHECKSUMS_SIG_FILE}" \
        --certificate-identity-regexp "^https://github.com/${REPO}/.+" \
        --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
        "${CHECKSUMS_FILE}" 2>&1)"; then
        err "checksums.txt Sigstore signature verification failed."
        printf '%s\n' "${cosign_output}" | head -5 >&2
        exit 1
    fi
    ok "Checksum signature verified (Sigstore)"
}

print_new_upgrade_script_hint() {
    info "    Use the upgrade script shipped with that release:"
    info "    curl -fsSL https://raw.githubusercontent.com/${REPO}/${RELEASE_VERSION}/scripts/upgrade.sh | bash -s -- --version ${RELEASE_VERSION}"
}

manifest_value() {
    local key="$1" path="$2"
    python3 - "${key}" "${path}" <<'PY'
import json
import sys

key = sys.argv[1]
path = sys.argv[2]
with open(path, encoding="utf-8") as fh:
    value = json.load(fh).get(key, "")
if isinstance(value, bool):
    raise SystemExit(1)
if isinstance(value, (str, int)):
    print(value)
elif value is None:
    print("")
else:
    raise SystemExit(1)
PY
}

load_upgrade_manifest() {
    local manifest_path="${STAGING_DIR}/${UPGRADE_MANIFEST_NAME}"
    if ! fetch_optional_artifact "${UPGRADE_MANIFEST_URL}" "${manifest_path}"; then
        return 0
    fi

    verify_checksum "${manifest_path}" "${UPGRADE_MANIFEST_NAME}"

    local schema_version release_version min_protocol policy
    schema_version="$(manifest_value "schema_version" "${manifest_path}")" \
        || die "Could not parse ${UPGRADE_MANIFEST_NAME}"
    release_version="$(manifest_value "release_version" "${manifest_path}")" \
        || die "Could not parse ${UPGRADE_MANIFEST_NAME}"
    min_protocol="$(manifest_value "min_upgrade_protocol" "${manifest_path}")" \
        || die "Could not parse ${UPGRADE_MANIFEST_NAME}"
    policy="$(manifest_value "migration_failure_policy" "${manifest_path}")" \
        || die "Could not parse ${UPGRADE_MANIFEST_NAME}"

    [[ -z "${schema_version}" ]] \
        && die "${UPGRADE_MANIFEST_NAME} missing integer schema_version"
    [[ "${schema_version}" =~ ^[0-9]+$ ]] \
        || die "${UPGRADE_MANIFEST_NAME} schema_version must be an integer"
    if [[ "${schema_version}" -gt 1 ]]; then
        warn "Release ${RELEASE_VERSION} uses upgrade manifest schema ${schema_version}, which this upgrader does not understand."
        print_new_upgrade_script_hint
        exit 1
    fi

    [[ "${release_version}" == "${RELEASE_VERSION}" ]] \
        || die "${UPGRADE_MANIFEST_NAME} release_version mismatch: expected ${RELEASE_VERSION}, got ${release_version:-<missing>}"

    [[ -z "${min_protocol}" ]] && min_protocol=1
    [[ "${min_protocol}" =~ ^[0-9]+$ ]] \
        || die "${UPGRADE_MANIFEST_NAME} min_upgrade_protocol must be an integer"
    if [[ "${min_protocol}" -gt "${UPGRADE_PROTOCOL_VERSION}" ]]; then
        warn "Release ${RELEASE_VERSION} requires upgrade protocol ${min_protocol}, but this upgrader supports ${UPGRADE_PROTOCOL_VERSION}."
        print_new_upgrade_script_hint
        exit 1
    fi

    [[ -z "${policy}" ]] && policy="warn"
    case "${policy}" in
        warn|fail) MIGRATION_FAILURE_POLICY="${policy}" ;;
        *) die "${UPGRADE_MANIFEST_NAME} has invalid migration_failure_policy: ${policy}" ;;
    esac

    UPGRADE_MANIFEST_FILE="${manifest_path}"
    ok "Upgrade manifest loaded"
}

validate_tarball_members() {
    local archive="$1" listing details entry mode
    listing="$(tar -tzf "${archive}")" \
        || die "Could not inspect gateway tarball before extraction"
    while IFS= read -r entry; do
        [[ -z "${entry}" ]] && continue
        case "${entry}" in
            /*|..|../*|*/..|*/../*)
                die "Unsafe gateway tarball entry: ${entry}"
                ;;
        esac
    done <<< "${listing}"

    details="$(tar -tvzf "${archive}")" \
        || die "Could not inspect gateway tarball metadata before extraction"
    while IFS= read -r entry; do
        [[ -z "${entry}" ]] && continue
        mode="${entry%% *}"
        case "${mode}" in
            l*|h*)
                die "Unsafe gateway tarball link entry: ${entry}"
                ;;
            -*|d*) ;;
            *)
                die "Unsupported gateway tarball entry type: ${entry}"
                ;;
        esac
    done <<< "${details}"
}

verify_checksums_sigstore
load_upgrade_manifest

step "Downloading gateway binary ..."
fetch_artifact "${TARBALL_URL}" "${STAGING_DIR}/${TARBALL_NAME}"
verify_checksum "${STAGING_DIR}/${TARBALL_NAME}" "${TARBALL_NAME}"
validate_tarball_members "${STAGING_DIR}/${TARBALL_NAME}"
tar -xzf "${STAGING_DIR}/${TARBALL_NAME}" -C "${STAGING_DIR}" \
    || die "Could not extract gateway tarball"
[[ -f "${STAGING_DIR}/defenseclaw" ]] \
    || die "Gateway tarball did not contain the expected defenseclaw binary"
ok "Gateway binary downloaded"

step "Downloading Python CLI wheel ..."
whl_name="${WHL_NAME}"
fetch_artifact "${WHL_URL}" "${STAGING_DIR}/${whl_name}"
verify_checksum "${STAGING_DIR}/${whl_name}" "${whl_name}"
ok "Python CLI wheel downloaded"
preflight_python_wheel "${STAGING_DIR}/${whl_name}"

# a download alone is not proof of integrity. The
# legacy upgrade flow extracted the tarball and pip-installed the
# wheel without ever comparing the artifact bytes to a published
# checksum or signature. We now require either:
#
#  1) a `<artifact>.sha256` sidecar published alongside each artifact
#     in the same GitHub release, OR
#  2) operator-provided pinned digests via the env vars
#     DEFENSECLAW_UPGRADE_TARBALL_SHA256 and
#     DEFENSECLAW_UPGRADE_WHL_SHA256.
#
# When neither is supplied, the upgrade aborts. Operators that
# explicitly accept the unverified path can opt back into the legacy
# behavior with DEFENSECLAW_UPGRADE_ALLOW_UNVERIFIED=1.
verify_artifact_sha256() {
    local file="$1" name="$2" pinned_env="$3"
    local pinned="${!pinned_env:-}"
    local sidecar_url="${4}"
    local actual
    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "${file}" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "${file}" | awk '{print $1}')"
    else
        die "no sha256sum/shasum available — refusing to install unverified ${name}"
    fi
    if [[ -n "${pinned}" ]]; then
        if [[ "${pinned,,}" != "${actual,,}" ]]; then
            die "checksum mismatch for ${name}: expected ${pinned} got ${actual}"
        fi
        ok "${name}: pinned sha256 match"
        return 0
    fi
    # Try sidecar.
    if curl -sSfL --head "${sidecar_url}" -o /dev/null 2>/dev/null; then
        local sidecar_dest="${STAGING_DIR}/$(basename "${file}").sha256"
        if curl -sSfL "${sidecar_url}" -o "${sidecar_dest}"; then
            local published
            published="$(awk '{print $1; exit}' "${sidecar_dest}" | tr -d '[:space:]')"
            if [[ -n "${published}" && "${published,,}" == "${actual,,}" ]]; then
                ok "${name}: published .sha256 sidecar match"
                return 0
            fi
            die "checksum mismatch for ${name}: published ${published} got ${actual}"
        fi
    fi
    if [[ "${DEFENSECLAW_UPGRADE_ALLOW_UNVERIFIED:-0}" == "1" ]]; then
        warn "${name}: no checksum available and DEFENSECLAW_UPGRADE_ALLOW_UNVERIFIED=1 — proceeding without verification"
        return 0
    fi
    die "no published .sha256 for ${name} and no pinned ${pinned_env}; refusing to install unverified artifact
  Set DEFENSECLAW_UPGRADE_ALLOW_UNVERIFIED=1 to proceed anyway (NOT recommended)."
}

verify_artifact_sha256 \
    "${STAGING_DIR}/gateway.tar.gz" "gateway tarball" \
    DEFENSECLAW_UPGRADE_TARBALL_SHA256 "${TARBALL_URL}.sha256"
verify_artifact_sha256 \
    "${STAGING_DIR}/${whl_name}" "python wheel" \
    DEFENSECLAW_UPGRADE_WHL_SHA256 "${WHL_URL}.sha256"

# Only extract after verification succeeds.
tar -xzf "${STAGING_DIR}/gateway.tar.gz" -C "${STAGING_DIR}"

# ── Confirm ───────────────────────────────────────────────────────────────────

if [[ "${YES}" -eq 0 ]]; then
    printf "\n  This will:\n"
    printf "    1. Back up config files in ${BOLD}~/.defenseclaw/${NC}\n"
    printf "    2. Stop gateway, install pre-downloaded artifacts\n"
    printf "    3. Run version-specific migrations\n"
    printf "    4. Restart services and verify health\n"
    printf "       ${DIM}Source: github.com/${REPO}/releases/tag/${RELEASE_VERSION}${NC}\n\n"
    read -r -p "  Proceed? [y/N] " REPLY
    case "$REPLY" in
        [Yy]*) ;;
        *) echo "  Aborted."; exit 0 ;;
    esac
fi

# ── Create backup ─────────────────────────────────────────────────────────────

section "Creating Backup"

TIMESTAMP=$(date +%Y%m%dT%H%M%S)
BACKUP_DIR="${BACKUP_ROOT}/upgrade-${TIMESTAMP}"
mkdir -p "${BACKUP_DIR}"

if [[ -d "${DEFENSECLAW_HOME}" ]]; then
    for f in config.yaml .env guardrail_runtime.json device.key \
        active_connector.json codex_backup.json claudecode_backup.json \
        zeptoclaw_backup.json codex_config_backup.json; do
        src="${DEFENSECLAW_HOME}/$f"
        [[ -f "${src}" ]] && cp "${src}" "${BACKUP_DIR}/" && ok "Backed up: $f"
    done
    if [[ -d "${DEFENSECLAW_HOME}/policies" ]]; then
        cp -r "${DEFENSECLAW_HOME}/policies" "${BACKUP_DIR}/policies"
        ok "Backed up: policies/"
    fi
    if [[ -d "${DEFENSECLAW_HOME}/connector_backups" ]]; then
        cp -r "${DEFENSECLAW_HOME}/connector_backups" "${BACKUP_DIR}/connector_backups"
        ok "Backed up: connector_backups/"
    fi
fi

OPENCLAW_JSON="${OPENCLAW_HOME}/openclaw.json"
if [[ -f "${OPENCLAW_JSON}" ]]; then
    cp "${OPENCLAW_JSON}" "${BACKUP_DIR}/openclaw.json"
    ok "Backed up: openclaw.json"
fi

ok "Backup saved to: ${BACKUP_DIR}"

# ── Stop services ─────────────────────────────────────────────────────────────

section "Stopping Services"

step "Stopping defenseclaw-gateway ..."
defenseclaw-gateway stop 2>/dev/null && ok "Gateway stopped" || warn "Gateway was not running"

# ── Install from staging (fast, no network) ───────────────────────────────────

section "Installing Artifacts"

mkdir -p "${INSTALL_DIR}"

# Snapshot the previous gateway binary so the operator can roll back
# manually if the new binary fails health check. Keeps the upgrade
# truly non-destructive — even in the worst case the previous binary
# is one ``cp`` away.
if [[ -f "${INSTALL_DIR}/defenseclaw-gateway" ]]; then
    cp "${INSTALL_DIR}/defenseclaw-gateway" "${BACKUP_DIR}/defenseclaw-gateway.previous" \
        && chmod +x "${BACKUP_DIR}/defenseclaw-gateway.previous" \
        && ok "Snapshotted previous gateway → ${BACKUP_DIR}/defenseclaw-gateway.previous" \
        || warn "Could not snapshot previous gateway binary"
fi

cp "${STAGING_DIR}/defenseclaw" "${INSTALL_DIR}/defenseclaw-gateway"
chmod +x "${INSTALL_DIR}/defenseclaw-gateway"

if [[ "${OS}" == "darwin" ]]; then
    codesign -f -s - "${INSTALL_DIR}/defenseclaw-gateway" 2>/dev/null || true
fi
ok "Gateway binary installed"

# Verify the freshly-installed binary reports the expected version. A
# truncated tarball or failed copy surfaces here as a warning instead of
# as a confusing post-deploy bug report.
gw_version_output="$("${INSTALL_DIR}/defenseclaw-gateway" --version 2>&1 || true)"
if printf '%s' "${gw_version_output}" | grep -Fq "${RELEASE_VERSION}"; then
    ok "Gateway binary verified (${RELEASE_VERSION})"
else
    warn "Gateway version verification failed: expected ${RELEASE_VERSION}"
    info "    binary reported: $(printf '%s' "${gw_version_output}" | head -n1 | cut -c1-200)"
fi

UV_BIN="$(command -v uv 2>/dev/null || true)"
[[ -z "${UV_BIN}" ]] \
    && die "uv not found on PATH — cannot update Python CLI. Install: curl -LsSf https://astral.sh/uv/install.sh | sh"

if [[ ! -d "${DEFENSECLAW_VENV}" ]]; then
    step "Creating venv at ${DEFENSECLAW_VENV} ..."
    "${UV_BIN}" --no-config venv "${DEFENSECLAW_VENV}" --python 3.12
fi

VENV_PYTHON="${DEFENSECLAW_VENV}/bin/python"
"${UV_BIN}" --no-config pip install --python "${VENV_PYTHON}" --quiet \
    --reinstall --no-cache --strict "${STAGING_DIR}/${whl_name}" \
    || die "Failed to install CLI wheel"
"${UV_BIN}" --no-config pip check --python "${VENV_PYTHON}" \
    || die "CLI dependency validation failed; launcher was not published"
"${VENV_PYTHON}" -I -c '
import asyncio
import tempfile
from defenseclaw.tui.app import DefenseClawTUI
async def smoke():
    with tempfile.TemporaryDirectory(prefix="defenseclaw-tui-smoke-") as data_dir:
        app = DefenseClawTUI(data_dir=data_dir)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
asyncio.run(smoke())
' || die "CLI TUI launch validation failed; launcher was not published"
ln -sf "${DEFENSECLAW_VENV}/bin/defenseclaw" "${INSTALL_DIR}/defenseclaw"
ok "Python CLI installed"

# ── Run migrations ────────────────────────────────────────────────────────────

section "Running Migrations"

# Run migrations with the freshly-installed CLI environment. The Python
# helper is intentionally verbose (click.echo); redirect that progress to
# stderr so command substitution captures only the numeric count.
MIGRATION_FAILED=0
if ! MIGRATION_COUNT=$(MIGRATION_FROM_VERSION="${CURRENT_VERSION}" \
    MIGRATION_TO_VERSION="${RELEASE_VERSION}" \
    MIGRATION_OPENCLAW_HOME="${OPENCLAW_HOME}" \
    MIGRATION_DEFENSECLAW_HOME="${DEFENSECLAW_HOME}" \
    "${VENV_PYTHON}" - <<'PY'
import contextlib
import os
import sys

from defenseclaw.migrations import run_migrations

with contextlib.redirect_stdout(sys.stderr):
    count = run_migrations(
        os.environ["MIGRATION_FROM_VERSION"],
        os.environ["MIGRATION_TO_VERSION"],
        os.environ["MIGRATION_OPENCLAW_HOME"],
        os.environ["MIGRATION_DEFENSECLAW_HOME"],
    )
print(count)
PY
); then
    MIGRATION_FAILED=1
    MIGRATION_COUNT=0
fi

if [[ ! "${MIGRATION_COUNT}" =~ ^[0-9]+$ ]]; then
    warn "Migration runner returned a non-numeric count: ${MIGRATION_COUNT}"
    MIGRATION_FAILED=1
    MIGRATION_COUNT=0
fi

if [[ "${MIGRATION_FAILED}" -eq 1 ]]; then
    warn "Migration runner failed; upgrade will continue. Run: defenseclaw doctor --fix"
elif [[ "${MIGRATION_COUNT}" -eq 0 ]]; then
    ok "No migrations needed"
else
    ok "Applied ${MIGRATION_COUNT} migration(s)"
fi

if [[ -n "${UPGRADE_MANIFEST_FILE}" ]]; then
    if ! REQUIRED_MIGRATIONS_MISSING="$(
        MIGRATION_DEFENSECLAW_HOME="${DEFENSECLAW_HOME}" \
        "${VENV_PYTHON}" - "${UPGRADE_MANIFEST_FILE}" <<'PY'
import json
import os
import sys

from defenseclaw import migration_state

with open(sys.argv[1], encoding="utf-8") as fh:
    manifest = json.load(fh)

required = manifest.get("required_cli_migrations", [])
if not isinstance(required, list):
    raise SystemExit("required_cli_migrations must be a list")

data_dir = os.environ["MIGRATION_DEFENSECLAW_HOME"]
state = migration_state.load(data_dir)
missing = [
    version
    for version in required
    if isinstance(version, str) and not migration_state.is_applied(state, version)
]
print("\n".join(missing))
PY
    )"; then
        MIGRATION_FAILED=1
        REQUIRED_MIGRATIONS_MISSING="unable to inspect migration cursor"
    fi
fi

if [[ -n "${REQUIRED_MIGRATIONS_MISSING}" ]]; then
    migration_label="Expected"
    [[ "${MIGRATION_FAILURE_POLICY}" == "fail" ]] && migration_label="Required"
    warn "${migration_label} migration(s) were not recorded: $(printf '%s' "${REQUIRED_MIGRATIONS_MISSING}" | tr '\n' ' ')"
    MIGRATION_FAILED=1
fi

if [[ "${MIGRATION_FAILURE_POLICY}" == "fail" && "${MIGRATION_FAILED}" -eq 1 ]]; then
    UPGRADE_INCOMPLETE=1
fi

# ── Start services ────────────────────────────────────────────────────────────

section "Starting Services"

step "Starting defenseclaw-gateway ..."
defenseclaw-gateway start && ok "Gateway started" || warn "Could not start gateway"

step "Restarting OpenClaw gateway ..."
openclaw gateway restart 2>/dev/null \
    && ok "OpenClaw gateway restarted" \
    || warn "Could not restart OpenClaw gateway automatically. Run: openclaw gateway restart"

# ── Health verification ───────────────────────────────────────────────────────

section "Verifying Gateway Health"

HEALTH_TIMEOUT=60
HEALTH_INTERVAL=2
ELAPSED=0
HEALTH_OK=0
HEALTH_URL="$("${VENV_PYTHON}" - <<'PY' 2>/dev/null || true
from defenseclaw.config import load

cfg = load()
bind = getattr(cfg.gateway, "api_bind", "")
if not bind:
    if cfg.openshell.is_standalone() and cfg.guardrail.host not in ("", "localhost", "127.0.0.1"):
        bind = cfg.guardrail.host
    else:
        bind = "127.0.0.1"
print(f"http://{bind}:{cfg.gateway.api_port}/health")
PY
)"
if [[ -z "${HEALTH_URL}" ]]; then
    HEALTH_URL="http://127.0.0.1:18970/health"
fi

# Mirror cmd_upgrade._poll_health: print state transitions in real time
# (including the first "unreachable" probe after a crashed sidecar) so
# operators aren't staring at a blank terminal for the full timeout.
LAST_STATE=""
while [[ "${ELAPSED}" -lt "${HEALTH_TIMEOUT}" ]]; do
    HTTP_CODE=$(curl -s -o /tmp/dc-upgrade-health.$$ -w "%{http_code}" "${HEALTH_URL}" 2>/dev/null || echo "000")
    STATUS=$(cat /tmp/dc-upgrade-health.$$ 2>/dev/null || echo "")
    rm -f /tmp/dc-upgrade-health.$$

    if [[ "${HTTP_CODE}" == "200" && -n "${STATUS}" ]]; then
        GW_STATE=$(printf '%s' "${STATUS}" \
            | grep -oE '"state"[[:space:]]*:[[:space:]]*"[^"]*"' \
            | head -1 \
            | sed -E 's/.*"state"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/' \
            || echo "unknown")
        if [[ -z "${GW_STATE}" ]]; then
            GW_STATE="unknown"
        fi
    else
        GW_STATE="unreachable"
    fi

    if [[ "${GW_STATE}" != "${LAST_STATE}" ]]; then
        info "    gateway: ${GW_STATE}"
        LAST_STATE="${GW_STATE}"
    fi

    if [[ "${GW_STATE}" == "running" ]]; then
        ok "Gateway is healthy"
        HEALTH_OK=1
        break
    fi
    sleep "${HEALTH_INTERVAL}"
    ELAPSED=$((ELAPSED + HEALTH_INTERVAL))
done

if [[ "${HEALTH_OK}" -eq 0 ]]; then
    warn "Gateway did not become healthy within ${HEALTH_TIMEOUT}s"
    info "Check logs: ~/.defenseclaw/gateway.log (pretty) / ~/.defenseclaw/gateway.jsonl (structured)"
    info "Run:  defenseclaw-gateway status"
fi

# ── Done ──────────────────────────────────────────────────────────────────────

if [[ "${UPGRADE_INCOMPLETE}" -eq 1 ]]; then
    section "Upgrade Incomplete"
    warn "Release ${RELEASE_VERSION} marked its migrations as mandatory, but they did not complete cleanly."
    printf "\n"
    printf "  Backup saved to: ${DIM}${BACKUP_DIR}${NC}\n"
    info "Run: defenseclaw migrations status"
    info "Then re-run: defenseclaw upgrade --version ${RELEASE_VERSION}"
    printf "\n"
    exit 1
fi

section "Upgrade Complete"

ok "DefenseClaw upgraded: ${CURRENT_VERSION} → ${RELEASE_VERSION}"
printf "\n"
printf "  Backup saved to: ${DIM}${BACKUP_DIR}${NC}\n"

# Surface component drift now (rather than waiting for the operator to
# discover it next time they run ``defenseclaw version``). Use the CLI's
# machine-readable report so this script is not coupled to human copy.
if has defenseclaw && command -v python3 >/dev/null 2>&1; then
    if drift_output="$(defenseclaw version --json --no-drift-exit 2>/dev/null)"; then
        if printf '%s' "${drift_output}" | python3 -c 'import json,sys; data=json.load(sys.stdin); raise SystemExit(0 if not data.get("ok", True) else 1)'; then
            printf "\n"
            warn "Component drift detected after upgrade — run \`defenseclaw version\` for details"
            warn "If the plugin is out of sync, reinstall it from the ${RELEASE_VERSION} release tarball"
        fi
    fi
fi

printf "\n"

} # end main()

main "$@"
