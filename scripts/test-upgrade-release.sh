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

set -euo pipefail

# Match the production installer/upgrade custody boundary and make the smoke
# deterministic on development hosts with a permissive login umask.
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="cisco-ai-defense/defenseclaw"
UPGRADE_BASELINE_POLICY="${UPGRADE_BASELINE_POLICY:-${ROOT}/release/upgrade-baselines.json}"
FROM_VERSION="${FROM_VERSION:-0.7.2}"
FROM_VERSIONS="${FROM_VERSIONS:-}"
TARGET_VERSION="${TARGET_VERSION:-}"
REQUIRED_BRIDGE_VERSION="${REQUIRED_BRIDGE_VERSION:-}"
V8_ACTIVATION_VERSION="0.8.5"
PROTECTED_ARTIFACT_VERSION="0.8.4"
RELEASE_ROOT="${RELEASE_ROOT:-}"
RELEASE_DIR="${RELEASE_DIR:-}"
BASELINE_MODE="${BASELINE_MODE:-auto}" # auto | install | seed
BASELINE_DEPENDENCIES="${BASELINE_DEPENDENCIES:-target}" # target | published
START_SOURCE_GATEWAY="${START_SOURCE_GATEWAY:-0}"
SUCCESS_PATH_ONLY="${SUCCESS_PATH_ONLY:-0}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-1}"
PORT="${PORT:-}"
KEEP_WORKDIR="${KEEP_WORKDIR:-0}"
PREPARE_ONLY=0
BUILD_PLATFORM=""

WORKDIR=""
SERVER_PID=""
SMOKE_HOME=""
RELEASE_URL=""
FROM_VERSION_LIST=()
FROM_CONFIG_VERSION=""
CANDIDATE_WHEEL_NAME=""
CANDIDATE_RUNTIME_CONFIG_VERSION=""

usage() {
    cat <<'EOF'
Usage: scripts/test-upgrade-release.sh [options]

Build or consume candidate release artifacts, install an older DefenseClaw in a
throwaway HOME, redirect its upgrade command to the local candidate artifacts,
then run and verify a real upgrade. This direct-controller harness is retained
for schema-1 release fixtures. Use test-upgrade-protocol-release.sh for
schema-2 refusal and signed resolver/handoff gates.

Options:
  --from-version VERSION     Installed baseline version to upgrade from (default: 0.7.2)
  --from-versions LIST       Space/comma-separated baseline versions to test
  --target-version VERSION   Candidate version (default: pyproject.toml version)
  --release-dir DIR          Existing artifact dir, e.g. dist/ from the release workflow
  --release-root DIR         Existing local release root containing VERSION/<assets>
  --baseline-mode MODE       auto, install, or seed (default: auto)
  --baseline-dependencies M  target (broad matrix) or published (real-dependency canary)
  --start-source-gateway     Start and health-check the published source before upgrade
  --success-path-only        Skip duplicate refusal cases in a dedicated success canary
  --health-timeout SECONDS   Gateway health wait passed to upgrade (default: 1)
  --port PORT                Local release server port (default: random high port)
  --platform OS/ARCH         Build platform for --prepare-only (default: current host)
  --prepare-only             Build/validate candidate release root, print it, and exit
  --keep-workdir             Keep temp HOME/logs for debugging
  --help                     Show this help

Examples:
  make upgrade-legacy-smoke
  make upgrade-legacy-smoke-matrix
  scripts/test-upgrade-release.sh --from-version 0.7.2
  scripts/test-upgrade-release.sh --from-versions "0.8.3,0.8.2,0.8.1,0.8.0,0.7.2,0.7.1"
  scripts/test-upgrade-release.sh --release-dir dist --baseline-mode seed

For a Linux host without the repo's Go toolchain, build/copy artifacts first:
  scripts/test-upgrade-release.sh --prepare-only --platform linux/arm64 --keep-workdir
  scp -r /tmp/candidate-root user@linux:/tmp/
  ssh user@linux 'scripts/test-developer-target-activation.sh --release-root /tmp/candidate-root --target-version 0.8.5 --from-version 0.8.4 --baseline-mode seed'

That developer activation checks target migration/health only. Use the signed
protocol harness for positive production resolver, bridge, receipt, and
rollback certification.
EOF
}

log() { printf '==> %s\n' "$*"; }
ok() { printf 'OK: %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

assert_exact_reported_version() {
    local label="$1"
    local expected="$2"
    local reported="$3"
    python3 - "${label}" "${expected}" "${reported}" <<'PY' \
        || die "${label} did not report exact version ${expected}"
import re
import sys

label, expected, reported = sys.argv[1:]
versions = re.findall(
    r"(?<![0-9A-Za-z.+-])(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)(?![0-9A-Za-z.+-])",
    reported,
)
if versions != [expected]:
    raise SystemExit(f"{label} reported {versions!r}; want exactly [{expected!r}]")
PY
}

cleanup() {
    local status=$?
    stop_smoke_gateway
    if [[ -n "${SERVER_PID:-}" ]]; then
        kill "${SERVER_PID}" >/dev/null 2>&1 || true
        wait "${SERVER_PID}" >/dev/null 2>&1 || true
    fi
    if [[ "${KEEP_WORKDIR}" != "1" && -n "${WORKDIR:-}" && -d "${WORKDIR}" ]]; then
        rm -rf "${WORKDIR}"
    elif [[ -n "${WORKDIR:-}" ]]; then
        warn "Kept smoke workdir: ${WORKDIR}"
    fi
    return "${status}"
}
trap cleanup EXIT

stop_smoke_gateway() {
    if [[ -n "${SMOKE_HOME:-}" && -x "${SMOKE_HOME}/.local/bin/defenseclaw-gateway" ]]; then
        HOME="${SMOKE_HOME}" \
        DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
        PATH="${SMOKE_HOME}/.local/bin:${PATH}" \
            "${SMOKE_HOME}/.local/bin/defenseclaw-gateway" stop \
            >"${SMOKE_HOME}/gateway-stop.log" 2>&1 || true
    fi
}

start_source_gateway_canary() {
    [[ "${START_SOURCE_GATEWAY}" == "1" ]] || return 0
    local start_log="${SMOKE_HOME}/source-gateway-start.log"
    local health_response="${SMOKE_HOME}/source-gateway-health.json"
    if ! HOME="${SMOKE_HOME}" \
        DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
        OPENCLAW_HOME="${SMOKE_HOME}/.openclaw" \
        PATH="${SMOKE_HOME}/.local/bin:${PATH}" \
            "${SMOKE_HOME}/.local/bin/defenseclaw-gateway" start \
            >"${start_log}" 2>&1; then
        tail_log "${start_log}"
        die "could not start published source gateway ${FROM_VERSION}"
    fi
    local attempt
    for attempt in $(seq 1 120); do
        if HOME="${SMOKE_HOME}" \
            DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
            OPENCLAW_HOME="${SMOKE_HOME}/.openclaw" \
            PATH="${SMOKE_HOME}/.local/bin:${PATH}" \
                "${SMOKE_HOME}/.local/bin/defenseclaw-gateway" status \
                >>"${start_log}" 2>&1 \
            && curl -fsS --max-time 1 http://127.0.0.1:18970/health \
                >"${health_response}" 2>>"${start_log}" \
            && python3 - "${health_response}" "${FROM_VERSION}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    payload = json.load(stream)
gateway = payload.get("gateway") if isinstance(payload, dict) else None
provenance = payload.get("provenance") if isinstance(payload, dict) else None
if (
    not isinstance(gateway, dict)
    or gateway.get("state") not in {"running", "disabled"}
    or not isinstance(provenance, dict)
    or provenance.get("binary_version") != sys.argv[2]
):
    raise SystemExit(1)
PY
        then
            ok "Published source gateway ${FROM_VERSION} is version-bound healthy before resolver handoff"
            return 0
        fi
        sleep 0.25
    done
    tail_log "${start_log}"
    [[ ! -s "${health_response}" ]] || cat "${health_response}" >&2
    die "published source gateway ${FROM_VERSION} did not reach version-bound health"
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --from-version)
                [[ $# -ge 2 ]] || die "--from-version requires a value"
                FROM_VERSION="$2"; shift 2 ;;
            --from-versions)
                [[ $# -ge 2 ]] || die "--from-versions requires a value"
                FROM_VERSIONS="$2"; shift 2 ;;
            --target-version)
                [[ $# -ge 2 ]] || die "--target-version requires a value"
                TARGET_VERSION="$2"; shift 2 ;;
            --release-dir)
                [[ $# -ge 2 ]] || die "--release-dir requires a value"
                RELEASE_DIR="$2"; shift 2 ;;
            --release-root)
                [[ $# -ge 2 ]] || die "--release-root requires a value"
                RELEASE_ROOT="$2"; shift 2 ;;
            --baseline-mode)
                [[ $# -ge 2 ]] || die "--baseline-mode requires a value"
                BASELINE_MODE="$2"; shift 2 ;;
            --baseline-dependencies)
                [[ $# -ge 2 ]] || die "--baseline-dependencies requires a value"
                BASELINE_DEPENDENCIES="$2"; shift 2 ;;
            --start-source-gateway)
                START_SOURCE_GATEWAY=1; shift ;;
            --success-path-only)
                SUCCESS_PATH_ONLY=1; shift ;;
            --health-timeout)
                [[ $# -ge 2 ]] || die "--health-timeout requires a value"
                HEALTH_TIMEOUT="$2"; shift 2 ;;
            --port)
                [[ $# -ge 2 ]] || die "--port requires a value"
                PORT="$2"; shift 2 ;;
            --platform)
                [[ $# -ge 2 ]] || die "--platform requires a value"
                BUILD_PLATFORM="$2"; shift 2 ;;
            --prepare-only)
                PREPARE_ONLY=1; KEEP_WORKDIR=1; shift ;;
            --keep-workdir)
                KEEP_WORKDIR=1; shift ;;
            --help|-h)
                usage; exit 0 ;;
            *)
                die "unknown argument: $1" ;;
        esac
    done
}

current_version() {
    python3 - <<'PY'
from pathlib import Path
import re

text = Path("pyproject.toml").read_text(encoding="utf-8")
match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
if not match:
    raise SystemExit("could not read pyproject.toml version")
print(match.group(1))
PY
}

abs_path() {
    python3 - "$1" <<'PY'
from pathlib import Path
import sys

print(Path(sys.argv[1]).expanduser().resolve())
PY
}

detect_platform() {
    if [[ -n "${BUILD_PLATFORM}" ]]; then
        case "${BUILD_PLATFORM}" in
            linux/amd64|linux/arm64|darwin/amd64|darwin/arm64|windows/amd64|windows/arm64)
                OS_NAME="${BUILD_PLATFORM%%/*}"
                ARCH_NAME="${BUILD_PLATFORM##*/}"
                return ;;
            *)
                die "--platform must be one of linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64, windows/arm64" ;;
        esac
    fi
    case "$(uname -s)" in
        Darwin) OS_NAME="darwin" ;;
        Linux) OS_NAME="linux" ;;
        *) die "unsupported OS for upgrade smoke: $(uname -s)" ;;
    esac
    case "$(uname -m)" in
        arm64|aarch64) ARCH_NAME="arm64" ;;
        x86_64|amd64) ARCH_NAME="amd64" ;;
        *) die "unsupported architecture for upgrade smoke: $(uname -m)" ;;
    esac
}

normalize_baseline_versions() {
    local raw="${FROM_VERSION}"
    if [[ -n "${FROM_VERSIONS}" ]]; then
        raw="${FROM_VERSIONS//,/ }"
    fi

    FROM_VERSION_LIST=()
    local version
    for version in ${raw}; do
        [[ -n "${version}" ]] || continue
        [[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
            || die "invalid baseline version: ${version}"
        if ! version_lte "${version}" "${TARGET_VERSION}"; then
            warn "Skipping baseline ${version}; target ${TARGET_VERSION} is older"
            continue
        fi
        FROM_VERSION_LIST+=("${version}")
    done
    [[ "${#FROM_VERSION_LIST[@]}" -gt 0 ]] || die "no baseline versions provided"
    FROM_VERSION="${FROM_VERSION_LIST[0]}"
}

published_baseline_config_version() {
    local version="$1"
    local runtime_config="${CANDIDATE_RUNTIME_CONFIG_VERSION:-}"
    if [[ -z "${runtime_config}" ]]; then
        runtime_config="$(candidate_runtime_config_version "$(current_version)")"
    fi
    python3 - \
        "${UPGRADE_BASELINE_POLICY}" \
        "${version}" \
        "${runtime_config}" <<'PY'
import json
from pathlib import Path
import re
import stat
import sys


policy_path = Path(sys.argv[1])
requested_version = sys.argv[2]
candidate_runtime = int(sys.argv[3])
canonical_version = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


def fail(message: str) -> None:
    raise SystemExit(f"invalid published-baseline policy: {message}")


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate JSON key {key!r}")
        document[key] = value
    return document


try:
    info = policy_path.lstat()
    if policy_path.is_symlink() or not stat.S_ISREG(info.st_mode):
        fail("policy path must be a real regular file")
    if info.st_size > 1024 * 1024:
        fail("policy exceeds the 1 MiB parser bound")
    raw = policy_path.read_text(encoding="utf-8")
except (OSError, UnicodeError) as exc:
    fail(f"could not read {policy_path}: {exc}")

try:
    policy = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
except (TypeError, ValueError) as exc:
    fail(f"malformed JSON: {exc}")

expected_keys = {
    "schema_version",
    "published_baselines",
    "published_baseline_config_versions",
    "platform_published_baselines",
}
if type(policy) is not dict or set(policy) != expected_keys:
    fail("schema 2 fields do not match the reviewed contract")
if type(policy["schema_version"]) is not int or policy["schema_version"] != 2:
    fail("schema_version must be the integer 2")

versions = policy["published_baselines"]
if type(versions) is not list or not versions:
    fail("published_baselines must be a non-empty array")
if any(type(item) is not str or canonical_version.fullmatch(item) is None for item in versions):
    fail("published_baselines contains a non-canonical version")
if len(set(versions)) != len(versions):
    fail("published_baselines contains a duplicate version")


def version_tuple(value: str) -> tuple[int, int, int]:
    return tuple(int(part) for part in value.split("."))


if versions != sorted(versions, key=version_tuple, reverse=True):
    fail("published_baselines must be ordered newest to oldest")

config_versions = policy["published_baseline_config_versions"]
if type(config_versions) is not dict or set(config_versions) != set(versions):
    fail("published_baseline_config_versions keys must exactly match published_baselines")
for published_version in versions:
    value = config_versions[published_version]
    if type(value) is not int or value < 1 or value > candidate_runtime:
        fail(
            f"{published_version} config version must be positive and no newer "
            "than the candidate runtime"
        )

platforms = policy["platform_published_baselines"]
if type(platforms) is not dict or set(platforms) != {"windows"}:
    fail("platform_published_baselines must contain exactly the reviewed Windows subset")
windows_versions = platforms["windows"]
if type(windows_versions) is not list or not windows_versions:
    fail("reviewed Windows baseline subset must be a non-empty array")
if (
    any(type(item) is not str or item not in config_versions for item in windows_versions)
    or len(set(windows_versions)) != len(windows_versions)
):
    fail("reviewed Windows baselines must be a unique subset of published_baselines")
windows_set = set(windows_versions)
if windows_versions != [item for item in versions if item in windows_set]:
    fail("reviewed Windows baselines must preserve published_baselines ordering")

if requested_version not in config_versions:
    fail(f"{requested_version} is not a reviewed published baseline")
print(config_versions[requested_version])
PY
}

candidate_runtime_config_version() {
    local target_version="${1:-${TARGET_VERSION}}"
    python3 - "${ROOT}" "${target_version}" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
target = tuple(map(int, sys.argv[2].split(".")))
if target >= (0, 8, 5):
    path = root / "internal/config/observability_v8_types.go"
    pattern = r"^\s*ObservabilityV8ConfigVersion\s*=\s*([1-9][0-9]*)\s*$"
else:
    path = root / "internal/config/config.go"
    pattern = r"^\s*const\s+CurrentConfigVersion\s*=\s*([1-9][0-9]*)\s*$"
match = re.search(pattern, path.read_text(encoding="utf-8"), re.MULTILINE)
if match is None:
    raise SystemExit(f"could not resolve candidate runtime config version from {path}")
print(match.group(1))
PY
}

version_lte() {
    python3 - "$1" "$2" <<'PY'
import sys


def parse(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


raise SystemExit(0 if parse(sys.argv[1]) <= parse(sys.argv[2]) else 1)
PY
}

target_uses_observability_v8() {
    version_lte "${V8_ACTIVATION_VERSION}" "${TARGET_VERSION}"
}

fresh_install_tool_path() {
    # A developer may already have DefenseClaw on their ambient PATH. The
    # production fresh installer correctly refuses that installation, but the
    # isolated smoke HOME must not mistake it for state inside the fixture.
    # Preserve every other tool directory and omit only entries that expose an
    # existing DefenseClaw CLI or gateway.
    local entry sanitized=""
    local -a entries=()
    IFS=: read -r -a entries <<<"${PATH}"
    for entry in "${entries[@]}"; do
        [[ -n "${entry}" ]] || continue
        if [[ -e "${entry}/defenseclaw" || -L "${entry}/defenseclaw" \
            || -e "${entry}/defenseclaw-gateway" || -L "${entry}/defenseclaw-gateway" ]]; then
            continue
        fi
        sanitized="${sanitized:+${sanitized}:}${entry}"
    done
    [[ -n "${sanitized}" ]] || die "could not construct an isolated baseline installer PATH"
    printf '%s\n' "${sanitized}"
}

validate_inputs() {
    normalize_baseline_versions
    [[ "${TARGET_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid --target-version: ${TARGET_VERSION}"
    CANDIDATE_RUNTIME_CONFIG_VERSION="$(candidate_runtime_config_version)" \
        || die "could not resolve candidate runtime config version"
    [[ "${CANDIDATE_RUNTIME_CONFIG_VERSION}" =~ ^[1-9][0-9]*$ ]] \
        || die "candidate runtime config version is invalid"
    local version config_version
    for version in "${FROM_VERSION_LIST[@]}"; do
        if ! config_version="$(published_baseline_config_version "${version}")"; then
            die "could not resolve the reviewed config version for baseline ${version}"
        fi
        [[ "${config_version}" =~ ^[1-9][0-9]*$ ]] \
            || die "published baseline ${version} resolved to an invalid config version"
    done
    case "${BASELINE_MODE}" in
        auto|install|seed) ;;
        *) die "--baseline-mode must be auto, install, or seed" ;;
    esac
    case "${BASELINE_DEPENDENCIES}" in
        target|published) ;;
        *) die "--baseline-dependencies must be target or published" ;;
    esac
    if [[ "${BASELINE_DEPENDENCIES}" == "published" && "${BASELINE_MODE}" != "seed" ]]; then
        die "--baseline-dependencies published requires --baseline-mode seed"
    fi
    [[ "${START_SOURCE_GATEWAY}" == "0" || "${START_SOURCE_GATEWAY}" == "1" ]] \
        || die "START_SOURCE_GATEWAY must be 0 or 1"
    [[ "${SUCCESS_PATH_ONLY}" == "0" || "${SUCCESS_PATH_ONLY}" == "1" ]] \
        || die "SUCCESS_PATH_ONLY must be 0 or 1"
    if [[ -n "${RELEASE_DIR}" && -n "${RELEASE_ROOT}" ]]; then
        die "use only one of --release-dir or --release-root"
    fi
    if [[ "${PREPARE_ONLY}" != "1" && -n "${BUILD_PLATFORM}" ]]; then
        die "--platform is only valid with --prepare-only"
    fi
}

build_candidate_release() {
    RELEASE_ROOT="${WORKDIR}/candidate-release"
    local out="${RELEASE_ROOT}/${TARGET_VERSION}"
    local build_root="${ROOT}"
    mkdir -p "${out}"

    # The production release workflow stamps the requested tag into an
    # ephemeral checkout before building.  A future-version smoke must do the
    # same: otherwise --target-version 0.8.4 would silently build the source
    # tree's currently pinned wheel/manifest (for example 0.8.0) and would not
    # exercise the bytes that the release job will publish.  Copying also keeps
    # the developer's dirty worktree and generated directories untouched.
    if [[ "$(current_version)" != "${TARGET_VERSION}" ]]; then
        build_root="${WORKDIR}/stamped-source"
        log "Preparing isolated source stamped as ${TARGET_VERSION}"
        python3 - "${ROOT}" "${build_root}" <<'PY'
from pathlib import Path
import shutil
import sys

source = Path(sys.argv[1]).resolve()
destination = Path(sys.argv[2]).resolve()
ignored_everywhere = {
    ".git",
    ".venv",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "__pycache__",
    "node_modules",
}


def ignore(directory: str, names: list[str]) -> list[str]:
    at_root = Path(directory).resolve() == source
    return [
        name
        for name in names
        if name in ignored_everywhere
        or (at_root and name in {"build", "dist"})
        or name.endswith(".egg-info")
    ]


shutil.copytree(source, destination, symlinks=True, ignore=ignore)
PY
        "${build_root}/scripts/stamp-version.sh" "${TARGET_VERSION}" >/dev/null
        make -C "${build_root}" check-version-sync >/dev/null
    fi

    log "Building candidate CLI wheel"
    make -C "${build_root}" dist-cli DIST_DIR="${out}"
    if version_lte "${PROTECTED_ARTIFACT_VERSION}" "${TARGET_VERSION}"; then
        log "Building candidate plugin"
        make -C "${build_root}" dist-plugin DIST_DIR="${out}"
    fi

    log "Building candidate gateway (${OS_NAME}/${ARCH_NAME})"
    make -C "${build_root}" sync-openclaw-extension
    if version_lte "${PROTECTED_ARTIFACT_VERSION}" "${TARGET_VERSION}"; then
        # Production verification checks the native executable format and
        # architecture inside every protected gateway. Cross-build all six
        # payloads so prepare-only cannot report green with placeholder bytes
        # that the release workflow's verify-runtime gate would reject.
        local fixture_os fixture_arch fixture_stage canonical_archive
        for fixture_os in darwin linux windows; do
            for fixture_arch in amd64 arm64; do
                fixture_stage="${WORKDIR}/gateway-${fixture_os}-${fixture_arch}"
                mkdir -p "${fixture_stage}"
                (
                    cd "${build_root}"
                    CGO_ENABLED=0 GOOS="${fixture_os}" GOARCH="${fixture_arch}" \
                        go build -ldflags "-s -w -X main.version=${TARGET_VERSION}" \
                        -o "${fixture_stage}/defenseclaw" ./cmd/defenseclaw
                )
                if [[ "${fixture_os}" == "windows" ]]; then
                    canonical_archive="${out}/defenseclaw_${TARGET_VERSION}_windows_${fixture_arch}.zip"
                    python3 - "${fixture_stage}/defenseclaw" "${canonical_archive}" <<'PY'
import sys
import zipfile

source, destination = sys.argv[1:]
with zipfile.ZipFile(destination, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
    archive.write(source, arcname="defenseclaw.exe")
PY
                else
                    canonical_archive="${out}/defenseclaw_${TARGET_VERSION}_${fixture_os}_${fixture_arch}.tar.gz"
                    tar -czf "${canonical_archive}" -C "${fixture_stage}" defenseclaw
                fi
                printf '%s\n' '{}' > "${canonical_archive}.sbom.json"
            done
        done
    else
        local stage="${WORKDIR}/gateway-${OS_NAME}-${ARCH_NAME}"
        mkdir -p "${stage}"
        (
            cd "${build_root}"
            CGO_ENABLED=0 GOOS="${OS_NAME}" GOARCH="${ARCH_NAME}" \
                go build -ldflags "-s -w -X main.version=${TARGET_VERSION}" \
                -o "${stage}/defenseclaw" ./cmd/defenseclaw
        )
        tar -czf "${out}/defenseclaw_${TARGET_VERSION}_${OS_NAME}_${ARCH_NAME}.tar.gz" \
            -C "${stage}" defenseclaw
    fi

    log "Generating candidate upgrade manifest/checksums"
    python3 "${build_root}/scripts/generate-upgrade-manifest.py" \
        --out "${out}/upgrade-manifest.json"
    if version_lte "${PROTECTED_ARTIFACT_VERSION}" "${TARGET_VERSION}"; then
        python3 "${build_root}/scripts/release_candidate.py" prepare-runtime \
            --release-dir "${out}" \
            --version "${TARGET_VERSION}"
        python3 "${build_root}/scripts/release_candidate.py" verify-runtime \
            --release-dir "${out}" \
            --version "${TARGET_VERSION}"
        python3 "${build_root}/scripts/release_candidate.py" stage-resolvers \
            --release-dir "${out}" \
            --version "${TARGET_VERSION}"
    fi
    (cd "${out}" && find . -type f ! -name checksums.txt ! -name checksums.txt.sig ! -name checksums.txt.pem \
        | sed 's#^\./##' | sort | xargs shasum -a 256 > checksums.txt)
}

prepare_release_root() {
    if [[ -n "${RELEASE_ROOT}" ]]; then
        RELEASE_ROOT="$(abs_path "${RELEASE_ROOT}")"
        return
    fi

    if [[ -n "${RELEASE_DIR}" ]]; then
        local dir
        dir="$(abs_path "${RELEASE_DIR}")"
        [[ -d "${dir}" ]] || die "--release-dir not found: ${dir}"
        RELEASE_ROOT="${WORKDIR}/candidate-release-root"
        mkdir -p "${RELEASE_ROOT}"
        ln -s "${dir}" "${RELEASE_ROOT}/${TARGET_VERSION}"
        return
    fi

    build_candidate_release
}

assert_candidate_assets() {
    local dir="${RELEASE_ROOT}/${TARGET_VERSION}"
    local selected schema_version wheel_name gateway_name wheel gateway
    [[ -d "${dir}" ]] || die "release root must contain ${TARGET_VERSION}/: ${RELEASE_ROOT}"
    [[ -f "${dir}/upgrade-manifest.json" ]] || die "upgrade-manifest.json missing from ${dir}"
    [[ -f "${dir}/checksums.txt" ]] || die "checksums.txt missing from ${dir}"
    selected="$(python3 - \
        "${dir}/upgrade-manifest.json" "${TARGET_VERSION}" "${OS_NAME}" "${ARCH_NAME}" <<'PY'
import json
import sys

path, version, os_name, arch = sys.argv[1:]
with open(path, encoding="utf-8") as stream:
    manifest = json.load(stream)
schema = manifest.get("schema_version")
if schema == 2:
    artifacts = manifest["release_artifacts"]
    wheel = artifacts["wheel"]
    gateway = artifacts["gateways"][os_name][arch]
elif schema == 1:
    wheel = f"defenseclaw-{version}-py3-none-any.whl"
    extension = "zip" if os_name == "windows" else "tar.gz"
    gateway = f"defenseclaw_{version}_{os_name}_{arch}.{extension}"
else:
    raise SystemExit(f"unsupported candidate manifest schema: {schema!r}")
print(schema)
print(wheel)
print(gateway)
PY
)" || die "could not select candidate artifacts from upgrade-manifest.json"
    schema_version="$(printf '%s\n' "${selected}" | sed -n '1p')"
    wheel_name="$(printf '%s\n' "${selected}" | sed -n '2p')"
    gateway_name="$(printf '%s\n' "${selected}" | sed -n '3p')"
    wheel="${dir}/${wheel_name}"
    gateway="${dir}/${gateway_name}"
    [[ -f "${wheel}" ]] || die "manifest-bound candidate wheel missing from ${dir}: ${wheel_name}"
    [[ -f "${gateway}" ]] \
        || die "manifest-bound candidate gateway missing for ${OS_NAME}/${ARCH_NAME}: ${gateway_name}"
    CANDIDATE_WHEEL_NAME="${wheel_name}"
    python3 - \
        "${wheel}" "${gateway}" "${schema_version}" "${dir}" "${TARGET_VERSION}" \
        "${OS_NAME}" "${ARCH_NAME}" <<'PY'
import io
from pathlib import Path
import sys
import tarfile
import zipfile

wheel, gateway = map(Path, sys.argv[1:3])
schema = int(sys.argv[3])
directory = Path(sys.argv[4])
version, os_name, arch = sys.argv[5:]
if schema == 2:
    magic = b"DEFENSECLAW-PROTECTED-ARTIFACT-V1\n"
    def protected_payload(path):
        outer = path.read_bytes()
        if not outer.startswith(magic) or len(outer) == len(magic):
            raise SystemExit(f"protected artifact envelope is invalid: {path.name}")
        return bytes(value ^ 0xA5 for value in outer[len(magic):])
    if zipfile.is_zipfile(wheel):
        raise SystemExit("protected candidate wheel remained directly package-installable")
    wheel_source = io.BytesIO(protected_payload(wheel))
    gateway_source = io.BytesIO(protected_payload(gateway))
else:
    wheel_source = wheel
    gateway_source = gateway
with zipfile.ZipFile(wheel_source) as archive:
    bytecode = [
        name for name in archive.namelist()
        if "/__pycache__/" in name or name.endswith((".pyc", ".pyo"))
    ]
if bytecode:
    sample = ", ".join(bytecode[:5])
    raise SystemExit(
        f"candidate wheel contains stale Python bytecode ({len(bytecode)} file(s)): {sample}"
    )
if os_name == "windows":
    with zipfile.ZipFile(gateway_source) as archive:
        members = [member for member in archive.infolist() if not member.is_dir()]
        if any(
            Path(member.filename.replace("\\", "/")).is_absolute()
            or ".." in Path(member.filename.replace("\\", "/")).parts
            for member in members
        ):
            raise SystemExit("manifest-bound Windows gateway archive has an unsafe member")
        runtimes = [
            member
            for member in members
            if Path(member.filename.replace("\\", "/")).name == "defenseclaw.exe"
        ]
        if len(runtimes) != 1:
            raise SystemExit("manifest-bound Windows gateway archive lacks one runtime binary")
else:
    with tarfile.open(fileobj=gateway_source if schema == 2 else None,
                      name=None if schema == 2 else gateway,
                      mode="r:gz") as archive:
        if not any(Path(member.name).name == "defenseclaw" for member in archive.getmembers()):
            raise SystemExit("manifest-bound gateway archive lacks the runtime binary")
if schema == 2:
    extension = "zip" if os_name == "windows" else "tar.gz"
    canonical_gateway = directory / f"defenseclaw_{version}_{os_name}_{arch}.{extension}"
    canonical_wheel = directory / f"defenseclaw-{version}-py3-none-any.whl"
    if version == "0.8.4":
        boundary = (
            "DefenseClaw 0.8.4 must be installed by the release-owned staged upgrade resolver.\n"
        )
    else:
        boundary = f"DefenseClaw {version} requires the 0.8.4 upgrade bridge.\n"
    expected = (
        boundary
        +
        "No changes were made. Run the release-owned upgrade resolver without a version.\n"
    ).encode()
    if os_name == "windows":
        if canonical_gateway.read_bytes() != expected or zipfile.is_zipfile(canonical_gateway):
            raise SystemExit("canonical Windows gateway refusal envelope became installable")
    else:
        if canonical_gateway.read_bytes() != expected:
            raise SystemExit("canonical gateway refusal envelope changed")
        try:
            with tarfile.open(canonical_gateway, mode="r:gz"):
                pass
        except tarfile.TarError:
            pass
        else:
            raise SystemExit("canonical gateway refusal envelope became installable")
    if canonical_wheel.read_bytes() != expected or zipfile.is_zipfile(canonical_wheel):
        raise SystemExit("canonical wheel refusal envelope became installable")
print("wheel_bytecode=clean")
PY
}

start_release_server() {
    local attempt
    for attempt in 1 2 3 4 5; do
        if [[ -z "${PORT}" ]]; then
            PORT=$((18000 + RANDOM % 20000))
        fi
        log "Starting local release server on 127.0.0.1:${PORT}"
        python3 -m http.server "${PORT}" --bind 127.0.0.1 --directory "${RELEASE_ROOT}" \
            >"${WORKDIR}/release-server.log" 2>&1 &
        SERVER_PID=$!
        sleep 1
        if curl -fsSI "http://127.0.0.1:${PORT}/${TARGET_VERSION}/checksums.txt" >/dev/null 2>&1; then
            RELEASE_URL="http://127.0.0.1:${PORT}"
            return
        fi
        kill "${SERVER_PID}" >/dev/null 2>&1 || true
        wait "${SERVER_PID}" >/dev/null 2>&1 || true
        SERVER_PID=""
        PORT=""
    done
    die "could not start local release server; see ${WORKDIR}/release-server.log"
}

install_curl_rewrite_probe() {
    local shim_dir="$1"
    local curl_command real_curl
    curl_command="$(type -P curl)" \
        || die "an external curl executable is required for the upgrade release gate"
    real_curl="$(abs_path "${curl_command}")" \
        || die "could not resolve the external curl executable for the upgrade release gate"
    [[ -f "${real_curl}" && -x "${real_curl}" ]] \
        || die "the resolved curl path is not an executable file: ${real_curl}"
    mkdir -p "${shim_dir}"
    cat > "${shim_dir}/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
: "${UPGRADE_GATE_REAL_CURL:?}"
: "${UPGRADE_GATE_RELEASE_URL:?}"
prefix="https://github.com/cisco-ai-defense/defenseclaw/releases/download"
latest="https://api.github.com/repos/cisco-ai-defense/defenseclaw/releases/latest"
args=()
for argument in "$@"; do
    if [[ "${argument}" == "${latest}" ]]; then
        printf '{"tag_name":"%s"}\n' "${UPGRADE_GATE_TARGET_VERSION:?}"
        exit 0
    fi
    argument="${argument//${prefix}/${UPGRADE_GATE_RELEASE_URL}}"
    args+=("${argument}")
done
exec "${UPGRADE_GATE_REAL_CURL}" "${args[@]}"
SH
    chmod 700 "${shim_dir}/curl"
    printf '%s\n' "${real_curl}"
}

prepare_required_bridge_assets() {
    [[ -n "${REQUIRED_BRIDGE_VERSION}" ]] || return 0
    [[ "${REQUIRED_BRIDGE_VERSION}" != "${TARGET_VERSION}" ]] || return 0

    local bridge_dir="${RELEASE_ROOT}/${REQUIRED_BRIDGE_VERSION}"
    local previous_from="${FROM_VERSION}"
    local asset
    local bridge_wheel="defenseclaw-${REQUIRED_BRIDGE_VERSION}-2-py3-none-any.dcwheel"
    local bridge_gateway="defenseclaw_${REQUIRED_BRIDGE_VERSION}_protocol2_${OS_NAME}_${ARCH_NAME}.dcgateway"
    mkdir -p "${bridge_dir}"
    for asset in \
        "${bridge_wheel}" \
        "${bridge_gateway}" \
        checksums.txt \
        checksums.txt.sig \
        checksums.txt.pem \
        upgrade-manifest.json; do
        download_old_asset "${asset}" "${bridge_dir}/${asset}" \
            "${REQUIRED_BRIDGE_VERSION}" \
            || die "required bridge asset is unavailable: ${REQUIRED_BRIDGE_VERSION}/${asset}"
    done
    local cosign_command cosign_path
    cosign_command="$(command -v cosign)" \
        || die "cosign is required to authenticate published bridge ${REQUIRED_BRIDGE_VERSION}"
    cosign_path="$(abs_path "${cosign_command}")" \
        || die "cosign is required to authenticate published bridge ${REQUIRED_BRIDGE_VERSION}"
    python3 "${ROOT}/scripts/historical_release_auth.py" \
        --version "${REQUIRED_BRIDGE_VERSION}" \
        --release-dir "${bridge_dir}" \
        --cosign "${cosign_path}" \
        --asset "${bridge_wheel}" \
        --asset "${bridge_gateway}" \
        --asset upgrade-manifest.json \
        || die "required bridge authentication failed: ${REQUIRED_BRIDGE_VERSION}"
    FROM_VERSION="${previous_from}"
    ok "Authenticated published bridge assets: ${REQUIRED_BRIDGE_VERSION} (${OS_NAME}/${ARCH_NAME})"
}

tail_log() {
    local file="$1"
    if [[ -f "${file}" ]]; then
        printf '\n--- %s tail ---\n' "${file}" >&2
        tail -80 "${file}" >&2 || true
    fi
}

tail_v8_upgrade_log_secret_safe() {
    local file="$1"
    [[ -f "${file}" ]] || return 0
    printf '\n--- %s redacted tail ---\n' "${file}" >&2
    python3 - "${file}" "${SMOKE_HOME}/fixture-evidence/environment.historical.source" <<'PY' >&2
from pathlib import Path
import re
import sys

text = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
protected = [
    "upgrade-smoke-flat-protected-value",
    "upgrade-smoke-splunk-protected-value",
    "upgrade-smoke-http-protected-value",
    "Bearer upgrade-smoke-otlp-protected-value",
    "upgrade-smoke-otlp-protected-value",
    "Bearer upgrade-smoke-v8-otlp-value",
    "upgrade-smoke-v8-otlp-value",
    "upgrade-smoke-v8-http-value",
]
environment_path = Path(sys.argv[2])
if environment_path.is_file() and not environment_path.is_symlink():
    for line in environment_path.read_text(encoding="utf-8", errors="strict").splitlines():
        name, separator, value = line.partition("=")
        if name == "DEFENSECLAW_GATEWAY_TOKEN" and separator:
            if re.fullmatch(r"[0-9a-f]{64}", value):
                protected.append(value)
            break
for value in protected:
    text = text.replace(value, "[REDACTED]")
print("\n".join(text.splitlines()[-80:]))
PY
}

materialize_authenticated_artifact() {
    local source="$1"
    local checksums="$2"
    local destination="$3"
    python3 - "${source}" "${checksums}" "${destination}" <<'PY'
import hashlib
import os
from pathlib import Path
import re
import stat
import sys

source = Path(sys.argv[1]).absolute()
checksums = Path(sys.argv[2]).absolute()
destination = Path(sys.argv[3]).absolute()
magic = b"DEFENSECLAW-PROTECTED-ARTIFACT-V1\n"
maximum_size = 512 * 1024 * 1024 + len(magic)


def regular_file(path: Path, *, maximum: int) -> os.stat_result:
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_size <= 0
        or info.st_size > maximum
    ):
        raise RuntimeError(f"release-test input is not a bounded regular file: {path}")
    return info


source_info = regular_file(source, maximum=maximum_size)
regular_file(checksums, maximum=8 * 1024 * 1024)
entries: dict[str, str] = {}
for line_number, line in enumerate(checksums.read_text(encoding="utf-8").splitlines(), 1):
    match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
    if not match:
        raise RuntimeError(f"invalid checksum line {line_number}")
    digest, name = match.groups()
    if name in entries:
        raise RuntimeError(f"duplicate checksum entry: {name}")
    entries[name] = digest
expected = entries.get(source.name)
if expected is None:
    raise RuntimeError(f"authenticated checksums do not cover {source.name}")

parent = destination.parent
parent_info = parent.lstat()
if (
    stat.S_ISLNK(parent_info.st_mode)
    or not stat.S_ISDIR(parent_info.st_mode)
    or parent_info.st_uid != os.geteuid()
    or stat.S_IMODE(parent_info.st_mode) & 0o077
):
    raise RuntimeError("materialization custody directory is not private")

read_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
write_flags = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
source_fd = os.open(source, read_flags)
destination_fd = None
created = False
try:
    opened = os.fstat(source_fd)
    if not os.path.samestat(source_info, opened):
        raise RuntimeError("protected artifact changed while opening")

    outer_digest = hashlib.sha256()
    while True:
        chunk = os.read(source_fd, 1024 * 1024)
        if not chunk:
            break
        outer_digest.update(chunk)
    if outer_digest.hexdigest() != expected:
        raise RuntimeError("protected artifact does not match authenticated checksums")

    os.lseek(source_fd, 0, os.SEEK_SET)
    if os.read(source_fd, len(magic)) != magic:
        raise RuntimeError("protected artifact envelope magic is invalid")
    destination_fd = os.open(destination, write_flags, 0o600)
    created = True
    consumed_digest = hashlib.sha256(magic)
    decoded_bytes = 0
    while True:
        encoded = os.read(source_fd, 1024 * 1024)
        if not encoded:
            break
        consumed_digest.update(encoded)
        decoded = bytes(value ^ 0xA5 for value in encoded)
        decoded_bytes += len(decoded)
        view = memoryview(decoded)
        while view:
            written = os.write(destination_fd, view)
            if written <= 0:
                raise RuntimeError("protected artifact materialization write failed")
            view = view[written:]
    if decoded_bytes == 0 or consumed_digest.hexdigest() != expected:
        raise RuntimeError("protected artifact changed during materialization")
    os.fsync(destination_fd)
    os.close(destination_fd)
    destination_fd = None
    directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
except BaseException:
    if destination_fd is not None:
        os.close(destination_fd)
    if created:
        try:
            destination.unlink()
        except FileNotFoundError:
            pass
    raise
finally:
    os.close(source_fd)
PY
}

release_test_artifact_path() {
    local source="$1"
    local checksums="$2"
    local destination="$3"
    case "${source}" in
        *.dcwheel|*.dcgateway)
            materialize_authenticated_artifact "${source}" "${checksums}" "${destination}" \
                || return 1
            printf '%s\n' "${destination}"
            ;;
        *)
            printf '%s\n' "${source}"
            ;;
    esac
}

download_old_asset() {
    local name="$1"
    local dest="$2"
    local version="${3:-${FROM_VERSION}}"
    local url="https://github.com/${REPO}/releases/download/${version}/${name}"
    local temporary="${dest}.download.$$"
    local max_bytes=536870912
    case "${name}" in
        checksums.txt) max_bytes=8388608 ;;
        checksums.txt.pem) max_bytes=65536 ;;
        checksums.txt.sig) max_bytes=16384 ;;
        upgrade-manifest.json) max_bytes=4194304 ;;
    esac
    if ! curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL \
        --max-filesize "${max_bytes}" "${url}" -o "${temporary}"; then
        rm -f "${temporary}"
        return 1
    fi
    mv "${temporary}" "${dest}"
}

published_baseline_artifact_names() {
    local version="$1"
    if ! version_lte "${PROTECTED_ARTIFACT_VERSION}" "${version}"; then
        printf '%s\n' \
            "defenseclaw-${version}-py3-none-any.whl" \
            "defenseclaw_${version}_${OS_NAME}_${ARCH_NAME}.tar.gz"
        return 0
    fi

    printf '%s\n' \
        "defenseclaw-${version}-2-py3-none-any.dcwheel" \
        "defenseclaw_${version}_protocol2_${OS_NAME}_${ARCH_NAME}.dcgateway"
}

stage_authenticated_baseline() {
    local version="$1"
    local old_dir="${WORKDIR}/published-release/${version}"
    mkdir -p "${old_dir}"
    local baseline_names old_wheel_name old_gateway_name name
    baseline_names="$(published_baseline_artifact_names "${version}")"
    old_wheel_name="$(printf '%s\n' "${baseline_names}" | sed -n '1p')"
    old_gateway_name="$(printf '%s\n' "${baseline_names}" | sed -n '2p')"
    local marker="${old_dir}/.authenticated-${OS_NAME}-${ARCH_NAME}"
    if [[ -f "${marker}" ]]; then
        return 0
    fi
    for name in \
        checksums.txt \
        checksums.txt.sig \
        checksums.txt.pem \
        "${old_wheel_name}" \
        "${old_gateway_name}"; do
        if [[ ! -f "${old_dir}/${name}" ]]; then
            download_old_asset "${name}" "${old_dir}/${name}" "${version}" \
                || die "published baseline asset is unavailable: ${version}/${name}"
        fi
    done
    local cosign_command cosign_path
    cosign_command="$(command -v cosign)" \
        || die "cosign is required to authenticate published baseline ${version}"
    cosign_path="$(abs_path "${cosign_command}")" \
        || die "cosign is required to authenticate published baseline ${version}"
    python3 "${ROOT}/scripts/historical_release_auth.py" \
        --version "${version}" \
        --release-dir "${old_dir}" \
        --cosign "${cosign_path}" \
        --asset "${old_wheel_name}" \
        --asset "${old_gateway_name}" \
        || die "published baseline authentication failed: ${version}"
    printf '%s\n' "${version} ${old_wheel_name} ${old_gateway_name}" >"${marker}"
    chmod 600 "${marker}"
    ok "Authenticated published baseline ${version} (${OS_NAME}/${ARCH_NAME})"
}

seed_baseline_install() {
    log "Seeding baseline ${FROM_VERSION} install"
    mkdir -p "${SMOKE_HOME}/.local/bin" "${SMOKE_HOME}/.defenseclaw"

    stage_authenticated_baseline "${FROM_VERSION}"
    local old_dir="${WORKDIR}/published-release/${FROM_VERSION}"
    local baseline_names old_wheel_name old_gateway_name old_wheel old_gateway
    baseline_names="$(published_baseline_artifact_names "${FROM_VERSION}")"
    old_wheel_name="$(printf '%s\n' "${baseline_names}" | sed -n '1p')"
    old_gateway_name="$(printf '%s\n' "${baseline_names}" | sed -n '2p')"
    old_wheel="${old_dir}/${old_wheel_name}"
    old_gateway="${old_dir}/${old_gateway_name}"
    local custody="${SMOKE_HOME}/.release-test-custody"
    mkdir -p "${custody}"
    local installed_old_wheel installed_old_gateway wheel_custody_path gateway_custody_path
    wheel_custody_path="${custody}/${old_wheel_name}"
    gateway_custody_path="${custody}/${old_gateway_name}"
    if [[ "${old_wheel_name}" == *.dcwheel ]]; then
        wheel_custody_path="${custody}/${old_wheel_name%.dcwheel}.whl"
    fi
    if [[ "${old_gateway_name}" == *.dcgateway ]]; then
        gateway_custody_path="${custody}/${old_gateway_name%.dcgateway}.tar.gz"
    fi
    installed_old_wheel="$(release_test_artifact_path \
        "${old_wheel}" "${old_dir}/checksums.txt" \
        "${wheel_custody_path}")" \
        || die "could not materialize authenticated baseline wheel ${FROM_VERSION}"
    installed_old_gateway="$(release_test_artifact_path \
        "${old_gateway}" "${old_dir}/checksums.txt" \
        "${gateway_custody_path}")" \
        || die "could not materialize authenticated baseline gateway ${FROM_VERSION}"
    uv --no-config venv "${SMOKE_HOME}/.defenseclaw/.venv" --python 3.12 --quiet
    local venv_python="${SMOKE_HOME}/.defenseclaw/.venv/bin/python"
    if [[ "${BASELINE_DEPENDENCIES}" == "published" ]]; then
        uv --no-config pip install --python "${venv_python}" --quiet "${installed_old_wheel}" \
            >"${SMOKE_HOME}/seed-published-dependencies.log" 2>&1 \
            || { tail_log "${SMOKE_HOME}/seed-published-dependencies.log"; die "could not resolve published baseline dependencies"; }
        uv --no-config pip check --python "${venv_python}" --quiet \
            >>"${SMOKE_HOME}/seed-published-dependencies.log" 2>&1 \
            || { tail_log "${SMOKE_HOME}/seed-published-dependencies.log"; die "published baseline dependency set is inconsistent"; }
        ok "Resolved the published ${FROM_VERSION} wheel's own dependency graph"
    else
        [[ -n "${CANDIDATE_WHEEL_NAME}" ]] \
            || die "candidate wheel name was not selected from the upgrade manifest"
        local candidate_dir="${RELEASE_ROOT}/${TARGET_VERSION}"
        local candidate_wheel
        candidate_wheel="$(release_test_artifact_path \
            "${candidate_dir}/${CANDIDATE_WHEEL_NAME}" "${candidate_dir}/checksums.txt" \
            "${custody}/${CANDIDATE_WHEEL_NAME%.dcwheel}.whl")" \
            || die "could not materialize authenticated target dependency wheel"
        uv --no-config pip install --python "${venv_python}" --quiet \
            "${candidate_wheel}" \
            >"${SMOKE_HOME}/seed-target-deps.log" 2>&1 \
            || { tail_log "${SMOKE_HOME}/seed-target-deps.log"; die "could not seed target dependency set"; }
        uv --no-config pip install --python "${venv_python}" --quiet --no-deps "${installed_old_wheel}" \
            >"${SMOKE_HOME}/seed-old-wheel.log" 2>&1 \
            || { tail_log "${SMOKE_HOME}/seed-old-wheel.log"; die "could not install old wheel"; }
    fi

    ln -sf "${SMOKE_HOME}/.defenseclaw/.venv/bin/defenseclaw" "${SMOKE_HOME}/.local/bin/defenseclaw"

    local gateway_stage="${WORKDIR}/old-gateway/${FROM_VERSION}"
    mkdir -p "${gateway_stage}"
    tar -xzf "${installed_old_gateway}" -C "${gateway_stage}"
    cp "${gateway_stage}/defenseclaw" "${SMOKE_HOME}/.local/bin/defenseclaw-gateway"
    chmod +x "${SMOKE_HOME}/.local/bin/defenseclaw-gateway"
}

install_baseline() {
    if [[ "${BASELINE_MODE}" == "seed" ]]; then
        seed_baseline_install
        return
    fi

    log "Installing baseline ${FROM_VERSION} with scripts/install.sh"
    local baseline_path
    baseline_path="$(fresh_install_tool_path)"
    if HOME="${SMOKE_HOME}" DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
        PATH="${SMOKE_HOME}/.local/bin:${baseline_path}" VERSION="${FROM_VERSION}" \
        "${ROOT}/scripts/install.sh" --yes --connector none \
        >"${SMOKE_HOME}/install-baseline.log" 2>&1; then
        return
    fi

    if [[ "${BASELINE_MODE}" == "install" ]]; then
        tail_log "${SMOKE_HOME}/install-baseline.log"
        die "baseline install failed"
    fi

    warn "baseline installer failed; falling back to seeded old wheel"
    tail_log "${SMOKE_HOME}/install-baseline.log"
    seed_baseline_install
}

resolve_baseline_config_version() {
    if ! FROM_CONFIG_VERSION="$(published_baseline_config_version "${FROM_VERSION}")"; then
        die "could not resolve the reviewed config version for baseline ${FROM_VERSION}"
    fi
    [[ "${FROM_CONFIG_VERSION}" =~ ^[1-9][0-9]*$ ]] \
        || die "published baseline ${FROM_VERSION} resolved to an invalid config version"
}

seed_pre_v8_otel_fixture() {
    resolve_baseline_config_version
    log "Seeding config-v${FROM_CONFIG_VERSION} flat OTel upgrade fixture for ${FROM_VERSION}"
    mkdir -p "${SMOKE_HOME}/.defenseclaw"
    cat >"${SMOKE_HOME}/.defenseclaw/config.yaml" <<YAML
config_version: ${FROM_CONFIG_VERSION}
guardrail:
  enabled: false
gateway:
  fleet_mode: disabled
  watcher:
    enabled: false
otel:
  enabled: true
  protocol: grpc
  endpoint: 127.0.0.1:4317
  headers:
    X-Upgrade-Fixture: preserved
  traces:
    enabled: true
    sampler: always_on
  metrics:
    enabled: true
  logs:
    enabled: true
    emit_individual_findings: true
  destinations:
    - name: existing-otlp
      preset: generic-otlp
      enabled: true
      protocol: grpc
      endpoint: collector.example.test:4317
      traces: {enabled: true}
      metrics: {enabled: false}
      logs: {enabled: false}
YAML
}

finalize_observability_upgrade_fixture() {
    local data_dir="${SMOKE_HOME}/.defenseclaw"
    local openclaw_home="${SMOKE_HOME}/.openclaw"
    local evidence_dir="${SMOKE_HOME}/fixture-evidence"

    chmod 600 "${data_dir}/config.yaml" "${data_dir}/.env"
    cp -p "${data_dir}/config.yaml" "${evidence_dir}/config.historical.source"
    cp -p "${data_dir}/.env" "${evidence_dir}/environment.historical.source"

    # An installed but stopped stack exercises the production bundle refresh
    # without requiring Docker or a remote service. Runtime restart behavior,
    # down-without--v, fault rollback, and live inventory are covered by the
    # focused production contract tests invoked once for every v8 smoke run.
    cp -R "${ROOT}/bundles/local_observability_stack" "${data_dir}/observability-stack"
    mkdir -p \
        "${data_dir}/observability-stack/operator" \
        "${data_dir}/observability-stack/grafana/dashboards"
    cat >"${data_dir}/observability-stack/operator/volume-continuity.txt" <<'EOF'
operator-owned volume continuity marker
EOF
    cat >"${data_dir}/observability-stack/grafana/dashboards/team-upgrade-smoke.json" <<'EOF'
{"title":"Operator Custom Dashboard","uid":"team-upgrade-smoke"}
EOF
}

assert_source_gateway_canary_preserved_fixture() {
    local data_dir="${SMOKE_HOME}/.defenseclaw"
    local evidence_dir="${SMOKE_HOME}/fixture-evidence"
    [[ -f "${evidence_dir}/config.historical.source" ]] || return 0
    cmp -s "${evidence_dir}/config.historical.source" "${data_dir}/config.yaml" \
        || die "source gateway canary changed the historical config before resolver handoff"
    cmp -s "${evidence_dir}/environment.historical.source" "${data_dir}/.env" \
        || die "source gateway canary changed the historical environment before resolver handoff"
}

seed_v8_observability_fixture() {
    resolve_baseline_config_version
    log "Seeding representative comment-heavy config-v${FROM_CONFIG_VERSION} observability fixture for ${FROM_VERSION}"
    local data_dir="${SMOKE_HOME}/.defenseclaw"
    local openclaw_home="${SMOKE_HOME}/.openclaw"
    local evidence_dir="${SMOKE_HOME}/fixture-evidence"
    mkdir -p "${data_dir}/state" "${openclaw_home}" "${evidence_dir}"
    chmod 700 "${data_dir}" "${data_dir}/state" "${openclaw_home}" "${evidence_dir}"

    # The values are deliberately recognizable test canaries. Verification
    # checks that they move into the private .env transaction and never occur
    # in the v8 YAML or command output. They are never printed by this script.
    cat >"${data_dir}/config.yaml" <<YAML
# ┌──── OBSERVABILITY UPGRADE SMOKE ────┐
# comments, order, and unrelated settings must survive
config_version: ${FROM_CONFIG_VERSION}
data_dir: ${data_dir}
audit_db: ${data_dir}/state/audit-custom.db # custom audit path
judge_bodies_db: ${data_dir}/state/judge-custom.db # custom judge path
guardrail:
  enabled: true
  retain_judge_bodies: false
gateway:
  fleet_mode: disabled
  watcher:
    enabled: false
otel:
  enabled: true
  protocol: grpc
  endpoint: 127.0.0.1:4317
  headers:
    X-Flat-Protected: upgrade-smoke-flat-protected-value
  traces:
    enabled: true
    sampler: always_on
  metrics:
    enabled: true
    export_interval_s: 60
    temporality: delta
  logs:
    enabled: true
    emit_individual_findings: true
  resource:
    attributes:
      service.name: defenseclaw-upgrade-smoke
      deployment.environment: historical-matrix
  destinations:
    - name: existing-otlp
      preset: generic-otlp
      enabled: true
      protocol: grpc
      endpoint: collector.example.test:4317
      traces: {enabled: true}
      metrics: {enabled: false}
      logs: {enabled: true}
    - name: galileo
      preset: galileo
      enabled: true
      protocol: http
      endpoint: https://api.galileo.ai/otel/traces
      traces: {enabled: true}
      metrics: {enabled: true}
      logs: {enabled: true}
audit_sinks:
  - name: splunk-protected
    kind: splunk_hec
    enabled: true
    splunk_hec:
      endpoint: https://splunk.example.test/services/collector
      token: upgrade-smoke-splunk-protected-value
  - name: http-protected
    kind: http_jsonl
    enabled: true
    http_jsonl:
      url: https://events.example.test/v1/audit
      bearer_token: upgrade-smoke-http-protected-value
  - name: audit-otlp
    kind: otlp_logs
    enabled: true
    otlp_logs:
      endpoint: https://audit.example.test/v1/logs
      protocol: http
      logger_name: defenseclaw.upgrade-smoke
      headers:
        Authorization: Bearer upgrade-smoke-otlp-protected-value
observability:
  connectors:
    codex:
      audit_sinks: [] # explicit connector export suppression
      webhooks: []
privacy:
  disable_redaction: false # compatibility redaction must be materialized
ai_discovery:
  enabled: true
  emit_otel: false # legacy provider-specific export override
notifications:
  enabled: true # unrelated section survives
YAML
    local gateway_token
    gateway_token="$(python3 -I -B -c 'import secrets; print(secrets.token_hex(32))')" \
        || die "could not generate the isolated fixture gateway token"
    [[ "${gateway_token}" =~ ^[0-9a-f]{64}$ ]] \
        || die "isolated fixture gateway token has an invalid shape"
    cat >"${data_dir}/.env" <<ENV
# exact pre-upgrade environment bytes must be recoverable
PRESERVE_UPGRADE_SMOKE_ENV=preserved
DEFENSECLAW_GATEWAY_TOKEN=${gateway_token}
ENV
    unset gateway_token
    finalize_observability_upgrade_fixture
}

seed_native_v8_observability_fixture() {
    resolve_baseline_config_version
    [[ "${FROM_CONFIG_VERSION}" == "8" ]] \
        || die "native v8 fixture requires a reviewed config-v8 baseline"
    log "Seeding representative native config-v8 observability fixture for ${FROM_VERSION}"
    local data_dir="${SMOKE_HOME}/.defenseclaw"
    local openclaw_home="${SMOKE_HOME}/.openclaw"
    local evidence_dir="${SMOKE_HOME}/fixture-evidence"
    mkdir -p "${data_dir}/state" "${openclaw_home}" "${evidence_dir}"
    chmod 700 "${data_dir}" "${data_dir}/state" "${openclaw_home}" "${evidence_dir}"

    cat >"${data_dir}/config.yaml" <<YAML
# ┌──── OBSERVABILITY UPGRADE SMOKE ────┐
# comments, order, and unrelated settings must survive
config_version: 8
data_dir: ${data_dir}
guardrail:
  enabled: true
  retain_judge_bodies: false
gateway:
  fleet_mode: disabled
  watcher:
    enabled: false
observability:
  defaults:
    redaction_profile: strict
  local:
    path: ${data_dir}/state/audit-custom.db
    judge_bodies_path: ${data_dir}/state/judge-custom.db
    retention_days: 90
  destinations:
    - name: existing-otlp
      kind: otlp
      enabled: false
      protocol: grpc
      endpoint: collector.example.test:4317
      headers:
        Authorization:
          env: DEFENSECLAW_V8_FIXTURE_OTLP_AUTHORIZATION
      send:
        signals: [logs, traces]
        buckets: [compliance.activity, platform.health]
        redaction_profile: strict
    - name: v8-http-protected
      kind: http_jsonl
      enabled: false
      endpoint: https://events.example.test/v1/audit
      bearer_env: DEFENSECLAW_V8_FIXTURE_HTTP_BEARER
      send:
        signals: [logs]
        buckets: [compliance.activity]
        redaction_profile: strict
  connectors:
    codex:
      webhooks: []
notifications:
  enabled: true # unrelated section survives
YAML
    local gateway_token
    gateway_token="$(python3 -I -B -c 'import secrets; print(secrets.token_hex(32))')" \
        || die "could not generate the isolated fixture gateway token"
    [[ "${gateway_token}" =~ ^[0-9a-f]{64}$ ]] \
        || die "isolated fixture gateway token has an invalid shape"
    cat >"${data_dir}/.env" <<ENV
# exact native-v8 environment bytes must survive later upgrades
PRESERVE_UPGRADE_SMOKE_ENV=preserved
DEFENSECLAW_GATEWAY_TOKEN=${gateway_token}
DEFENSECLAW_V8_FIXTURE_OTLP_AUTHORIZATION=Bearer upgrade-smoke-v8-otlp-value
DEFENSECLAW_V8_FIXTURE_HTTP_BEARER=upgrade-smoke-v8-http-value
ENV
    unset gateway_token

    # A real config-v8 host already has the v8 activation recorded. Seed the
    # cursor through the authenticated published baseline's own state API so a
    # later candidate must preserve, rather than invent, that history.
    local baseline_python="${data_dir}/.venv/bin/python"
    [[ -x "${baseline_python}" ]] \
        || die "published config-v8 baseline interpreter is unavailable"
    HOME="${SMOKE_HOME}" DEFENSECLAW_HOME="${data_dir}" \
        "${baseline_python}" -I - "${data_dir}" "${FROM_VERSION}" <<'PY'
import os
from pathlib import Path
import shutil
import sys

from defenseclaw import migration_state
from defenseclaw.bundle_refresh import _build_local_observability_manifest
from defenseclaw.migrations import MIGRATIONS
from defenseclaw.paths import bundled_local_observability_dir

data_dir, source_version = sys.argv[1:]
state = migration_state.bootstrap(
    None,
    from_version=source_version,
    package_version=source_version,
    registry_versions=[version for version, _description, _migration in MIGRATIONS],
)
if "0.8.5" not in state.applied:
    raise SystemExit("published config-v8 baseline did not record the v8 activation")
migration_state.save(data_dir, state)

data_root = Path(data_dir)
source_bundle = bundled_local_observability_dir().absolute()
destination = data_root / "observability-stack"
if not source_bundle.is_dir():
    raise SystemExit("published config-v8 baseline has no bundled observability stack")
shutil.copytree(source_bundle, destination)
manifest = _build_local_observability_manifest(source_bundle, source_version)
manifest_path = destination / ".defenseclaw-bundle-manifest.json"
manifest_path.write_bytes(manifest.raw)
os.chmod(manifest_path, 0o600)
(destination / "operator").mkdir(parents=True, exist_ok=True)
(destination / "grafana/dashboards").mkdir(parents=True, exist_ok=True)
(destination / "operator/volume-continuity.txt").write_text(
    "operator-owned volume continuity marker\n",
    encoding="utf-8",
)
(destination / "grafana/dashboards/team-upgrade-smoke.json").write_text(
    '{"title":"Operator Custom Dashboard","uid":"team-upgrade-smoke"}\n',
    encoding="utf-8",
)
PY
    chmod 600 "${data_dir}/config.yaml" "${data_dir}/.env"
    cp -p "${data_dir}/config.yaml" "${evidence_dir}/config.historical.source"
    cp -p "${data_dir}/.env" "${evidence_dir}/environment.historical.source"
}

seed_upgrade_fixture() {
    resolve_baseline_config_version
    if target_uses_observability_v8; then
        if (( FROM_CONFIG_VERSION < 8 )); then
            seed_v8_observability_fixture
        elif (( FROM_CONFIG_VERSION == 8 )); then
            seed_native_v8_observability_fixture
        else
            die "no reviewed upgrade fixture exists for config-v${FROM_CONFIG_VERSION} baseline ${FROM_VERSION}"
        fi
    else
        seed_pre_v8_otel_fixture
    fi
}

run_v8_source_contract_tests() {
    target_uses_observability_v8 || return 0
    if [[ "${UPGRADE_SMOKE_SKIP_SOURCE_CONTRACTS:-0}" == "1" ]]; then
        warn "Skipping v8 source contract tests by explicit UPGRADE_SMOKE_SKIP_SOURCE_CONTRACTS=1"
        return 0
    fi

    local result_log="${WORKDIR}/v8-source-contracts.log"
    touch "${result_log}"
    chmod 600 "${result_log}"
    log "Proving v8 permission, retry, rollback, and bundle contracts"
    python3 "${ROOT}/scripts/telemetry_runtime_assets.py" \
        --root "${ROOT}" \
        --stage "${ROOT}/cli/defenseclaw/_data/telemetry/v8" \
        >"${result_log}" 2>&1 \
        || { tail_log "${result_log}"; die "could not stage checked telemetry resources for v8 source tests"; }
    if ! PYTHONDONTWRITEBYTECODE=1 uv run python -m pytest -q --tb=short \
        cli/tests/test_observability_v8_activation.py \
        cli/tests/test_observability_v8_upgrade_migration.py \
        cli/tests/test_local_observability_bundle_upgrade.py \
        cli/tests/test_local_observability_upgrade_wiring.py \
        >>"${result_log}" 2>&1; then
        tail_log "${result_log}"
        die "v8 source contract tests failed (private log: ${result_log})"
    fi
    ok "v8 source contracts passed (permission, retry, rollback, bundle)"
}

patch_installed_upgrade_endpoint() {
    local force_latest_version="${1:-}"
    local upgrade_py
    upgrade_py="$(find "${SMOKE_HOME}/.defenseclaw/.venv" \
        -path '*/site-packages/defenseclaw/commands/cmd_upgrade.py' -print -quit)"
    [[ -n "${upgrade_py}" ]] || die "installed cmd_upgrade.py not found"

    python3 - "${upgrade_py}" "${RELEASE_URL}" "${force_latest_version}" <<'PY'
import os
from pathlib import Path
import stat
import sys
import tempfile

path = Path(sys.argv[1])
release_url = sys.argv[2]
force_latest_version = sys.argv[3]
metadata = path.lstat()
if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
    raise SystemExit(f"installed upgrade module is not a real regular file: {path}")
text = path.read_text(encoding="utf-8")
old = 'GITHUB_DL = f"https://github.com/{GITHUB_REPO}/releases/download"'
new = f'GITHUB_DL = "{release_url}"'
if old not in text:
    raise SystemExit(f"release URL constant not found in {path}")
text = text.replace(old, new, 1)
if force_latest_version:
    old_latest = "target_version = _fetch_latest_version()"
    new_latest = f'target_version = "{force_latest_version}"'
    if text.count(old_latest) != 1:
        raise SystemExit(f"latest-version resolver call not found exactly once in {path}")
    text = text.replace(old_latest, new_latest, 1)

# uv may hardlink installed package files from a shared cache on Linux. Never
# rewrite that inode in place: doing so would contaminate the next independently
# seeded historical fixture. Publish a fully flushed same-directory inode and
# atomically replace only this throwaway installation's directory entry.
descriptor, staged_name = tempfile.mkstemp(
    prefix=f".{path.name}.protocol-endpoint-",
    dir=path.parent,
)
staged = Path(staged_name)
with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
    os.fchmod(handle.fileno(), stat.S_IMODE(metadata.st_mode))
    handle.write(text)
    handle.flush()
    os.fsync(handle.fileno())
os.replace(staged, path)
parent_fd = os.open(
    path.parent,
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
)
try:
    os.fsync(parent_fd)
finally:
    os.close(parent_fd)
if path.read_text(encoding="utf-8") != text or path.lstat().st_nlink != 1:
    raise SystemExit(f"installed upgrade endpoint patch was not isolated: {path}")
PY
}

prepare_isolated_docker_path() {
    # The fixture represents an installed but stopped stack. An unreachable
    # DOCKER_HOST alone is ambiguous when a developer's real local stack has
    # bound the standard ports, and the production refresher correctly fails
    # closed in that situation. Put a private, purpose-limited docker shim
    # first on PATH so only this throwaway HOME observes an authoritative empty
    # `docker ps`; every mutating docker operation remains forbidden.
    local shim_dir="${SMOKE_HOME}/.upgrade-test-bin"
    mkdir -p "${shim_dir}"
    chmod 700 "${shim_dir}"
    cat >"${shim_dir}/docker" <<'SH'
#!/bin/sh
if [ "${1:-}" = "ps" ]; then
    exit 0
fi
printf '%s\n' 'upgrade smoke docker isolation forbids mutating operations' >&2
exit 125
SH
    chmod 700 "${shim_dir}/docker"
}

upgrade_supports_allow_unverified() {
    HOME="${SMOKE_HOME}" DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="${SMOKE_HOME}/.local/bin:${PATH}" \
        defenseclaw upgrade --help 2>/dev/null | grep -q -- "--allow-unverified"
}

candidate_has_checksum_signature() {
    local dir="${RELEASE_ROOT}/${TARGET_VERSION}"
    [[ -f "${dir}/checksums.txt.sig" && -f "${dir}/checksums.txt.pem" ]]
}

run_upgrade() {
    log "Running upgrade ${FROM_VERSION} -> ${TARGET_VERSION}"
    prepare_isolated_docker_path
    local -a args=(upgrade --version "${TARGET_VERSION}" --yes --health-timeout "${HEALTH_TIMEOUT}")
    if upgrade_supports_allow_unverified && ! candidate_has_checksum_signature; then
        args+=(--allow-unverified)
    fi

    # The fixture represents an installed but stopped optional stack. Point
    # Docker discovery at a nonexistent private socket so a developer running
    # this smoke cannot stop a real host stack that shares the compose project
    # name. Running-stack restart/down-without--v is proven by the invoked
    # production contract tests.
    if ! HOME="${SMOKE_HOME}" DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
        DOCKER_HOST="${UPGRADE_SMOKE_DOCKER_HOST:-unix://${SMOKE_HOME}/no-docker.sock}" \
        PATH="${SMOKE_HOME}/.upgrade-test-bin:${SMOKE_HOME}/.local/bin:${PATH}" defenseclaw "${args[@]}" \
        >"${SMOKE_HOME}/upgrade.log" 2>&1; then
        if target_uses_observability_v8; then
            tail_v8_upgrade_log_secret_safe "${SMOKE_HOME}/upgrade.log"
        else
            tail_log "${SMOKE_HOME}/upgrade.log"
        fi
        die "upgrade command failed"
    fi

    # The upgrade command runs inside the already-installed baseline process.
    # Baselines that perform an in-process post-upgrade drift check can still
    # have the old CLI version cached in sys.modules after replacing the wheel
    # on disk. Do not fail on that warning here; verify_upgrade launches the
    # freshly installed CLI/gateway as new processes and catches real drift.
    if grep -E "Traceback|AttributeError|Required migration\\(s\\).*not recorded" \
        "${SMOKE_HOME}/upgrade.log" >/dev/null; then
        if target_uses_observability_v8; then
            tail_v8_upgrade_log_secret_safe "${SMOKE_HOME}/upgrade.log"
        else
            tail_log "${SMOKE_HOME}/upgrade.log"
        fi
        die "upgrade log contains a known regression marker"
    fi
}

verify_upgrade() {
    log "Verifying upgraded install"
    local venv_python="${SMOKE_HOME}/.defenseclaw/.venv/bin/python"
    local release_dir="${RELEASE_ROOT}/${TARGET_VERSION}"
    local require_v8=0
    if target_uses_observability_v8; then
        require_v8=1
    fi

    local cli_version gateway_version
    cli_version="$(HOME="${SMOKE_HOME}" DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
        PATH="${SMOKE_HOME}/.local/bin:${PATH}" defenseclaw --version)" \
        || die "defenseclaw --version failed"
    assert_exact_reported_version "defenseclaw" "${TARGET_VERSION}" "${cli_version}"

    gateway_version="$(HOME="${SMOKE_HOME}" DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
        PATH="${SMOKE_HOME}/.local/bin:${PATH}" defenseclaw-gateway --version)" \
        || die "defenseclaw-gateway --version failed"
    assert_exact_reported_version \
        "defenseclaw-gateway" "${TARGET_VERSION}" "${gateway_version}"

    "${venv_python}" - \
        "${SMOKE_HOME}/.defenseclaw" \
        "${release_dir}/upgrade-manifest.json" \
        "${require_v8}" \
        "${V8_ACTIVATION_VERSION}" <<'PY'
import json
from pathlib import Path
import sys

data_dir = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
require_v8 = sys.argv[3] == "1"
v8_activation_version = sys.argv[4]
cursor_path = data_dir / ".migration_state.json"
cursor = json.loads(cursor_path.read_text(encoding="utf-8"))
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
applied = set(cursor.get("applied", []))
missing = [
    version
    for version in manifest.get("required_cli_migrations", [])
    if isinstance(version, str) and version not in applied
]
if missing:
    raise SystemExit(f"missing required migrations in cursor: {', '.join(missing)}")
if require_v8:
    if v8_activation_version not in manifest.get("required_cli_migrations", []):
        raise SystemExit("target manifest does not require observability-v8 migration")
    if v8_activation_version not in applied:
        raise SystemExit("observability-v8 migration is absent from the cursor")
print("cursor_applied=" + ",".join(cursor.get("applied", [])))
PY

    if target_uses_observability_v8; then
        if (( FROM_CONFIG_VERSION == 8 )); then
            "${venv_python}" - \
                "${SMOKE_HOME}/.defenseclaw" \
                "${SMOKE_HOME}/fixture-evidence" \
                "${SMOKE_HOME}/upgrade.log" \
                "${TARGET_VERSION}" \
                "${FROM_VERSION}" <<'PY'
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import stat
import sys

from defenseclaw.bundle_refresh import _build_local_observability_manifest
from defenseclaw.observability.v8_config import load_validate_v8
from defenseclaw.paths import bundled_local_observability_dir
from dotenv import dotenv_values
import yaml

data_dir = Path(sys.argv[1])
evidence_dir = Path(sys.argv[2])
upgrade_log = Path(sys.argv[3])
target_version = sys.argv[4]
source_version = sys.argv[5]
config_path = data_dir / "config.yaml"
environment_path = data_dir / ".env"
config_bytes = config_path.read_bytes()
environment_bytes = environment_path.read_bytes()
historical_config = (evidence_dir / "config.historical.source").read_bytes()
historical_environment = (evidence_dir / "environment.historical.source").read_bytes()

if config_bytes != historical_config:
    raise SystemExit("native-v8 config bytes changed without a target config migration")
if environment_bytes != historical_environment:
    raise SystemExit("native-v8 environment bytes changed without a target config migration")
config = load_validate_v8(config_bytes, source_name=str(config_path)).source
if config.get("config_version") != 8:
    raise SystemExit("native-v8 source no longer has config_version 8")
for legacy in ("otel", "audit_sinks", "privacy"):
    if legacy in config:
        raise SystemExit(f"native-v8 source gained legacy block: {legacy}")

destinations = {
    item.get("name"): item
    for item in (config.get("observability") or {}).get("destinations", [])
    if isinstance(item, dict) and isinstance(item.get("name"), str)
}
if set(destinations) != {"existing-otlp", "v8-http-protected"}:
    raise SystemExit("native-v8 destination set changed across the upgrade")
if destinations["existing-otlp"].get("headers") != {
    "Authorization": {"env": "DEFENSECLAW_V8_FIXTURE_OTLP_AUTHORIZATION"}
}:
    raise SystemExit("native-v8 OTLP secret reference changed across the upgrade")
if destinations["v8-http-protected"].get("bearer_env") != "DEFENSECLAW_V8_FIXTURE_HTTP_BEARER":
    raise SystemExit("native-v8 HTTP secret reference changed across the upgrade")

historical_environment_values = dotenv_values(evidence_dir / "environment.historical.source")
historical_gateway_token = historical_environment_values.get("DEFENSECLAW_GATEWAY_TOKEN")
if not isinstance(historical_gateway_token, str) or re.fullmatch(r"[0-9a-f]{64}", historical_gateway_token) is None:
    raise SystemExit("historical fixture gateway token is missing or invalid")
expected_environment = {
    "PRESERVE_UPGRADE_SMOKE_ENV": "preserved",
    "DEFENSECLAW_GATEWAY_TOKEN": historical_gateway_token,
    "DEFENSECLAW_V8_FIXTURE_OTLP_AUTHORIZATION": "Bearer upgrade-smoke-v8-otlp-value",
    "DEFENSECLAW_V8_FIXTURE_HTTP_BEARER": "upgrade-smoke-v8-http-value",
}
actual_environment = dotenv_values(environment_path)
if any(actual_environment.get(name) != value for name, value in expected_environment.items()):
    raise SystemExit("native-v8 environment continuity failed")
if stat.S_IMODE(environment_path.stat().st_mode) != 0o600:
    raise SystemExit("native-v8 environment is not mode 0600")
openclaw_home = data_dir.parent / ".openclaw"
try:
    openclaw_info = openclaw_home.lstat()
except FileNotFoundError:
    raise SystemExit("native-v8 fixture OpenClaw home disappeared across the upgrade") from None
if not stat.S_ISDIR(openclaw_info.st_mode) or stat.S_IMODE(openclaw_info.st_mode) != 0o700:
    raise SystemExit("native-v8 fixture OpenClaw home mode changed across the upgrade")
log_text = upgrade_log.read_text(encoding="utf-8", errors="replace")
protected_values = (
    value
    for name, value in expected_environment.items()
    if name != "PRESERVE_UPGRADE_SMOKE_ENV"
)
if any(value in config_bytes.decode() or value in log_text for value in protected_values):
    raise SystemExit("native-v8 protected value escaped into YAML or upgrade output")

activation_manifests = sorted((data_dir / "backups").glob("observability-v8-*/manifest.json"))
if activation_manifests:
    raise SystemExit("native-v8 source unexpectedly ran the v7-to-v8 activation")
normal_backups = sorted(
    path
    for path in (data_dir / "backups").glob("upgrade-*")
    if path.is_dir() and not path.is_symlink()
)
if not any(
    (path / "config.yaml").is_file()
    and (path / ".env").is_file()
    and (path / "config.yaml").read_bytes() == historical_config
    and (path / ".env").read_bytes() == historical_environment
    for path in normal_backups
):
    raise SystemExit("native-v8 upgrade retained no byte-exact source backup")

for comment in (
    "# ┌──── OBSERVABILITY UPGRADE SMOKE ────┐",
    "# comments, order, and unrelated settings must survive",
    "# unrelated section survives",
):
    if comment not in config_bytes.decode():
        raise SystemExit(f"native-v8 comment token was lost: {comment}")

stack = data_dir / "observability-stack"
bundle_manifest = json.loads(
    (stack / ".defenseclaw-bundle-manifest.json").read_text(encoding="utf-8")
)
if bundle_manifest.get("bundle_version") != target_version:
    raise SystemExit("native-v8 local bundle was not refreshed to the target")
if (stack / "operator/volume-continuity.txt").read_bytes() != (
    b"operator-owned volume continuity marker\n"
):
    raise SystemExit("native-v8 operator volume marker was lost")
if (stack / "grafana/dashboards/team-upgrade-smoke.json").read_bytes() != (
    b'{"title":"Operator Custom Dashboard","uid":"team-upgrade-smoke"}\n'
):
    raise SystemExit("native-v8 operator dashboard was lost")
target_bundle = bundled_local_observability_dir()
expected_bundle_manifest = json.loads(
    _build_local_observability_manifest(target_bundle, target_version).raw
)
if bundle_manifest != expected_bundle_manifest:
    raise SystemExit("native-v8 local bundle manifest differs from the complete target package")
for item in bundle_manifest.get("files", []):
    relative = item.get("path")
    digest = item.get("sha256")
    if not isinstance(relative, str) or not isinstance(digest, str):
        raise SystemExit("invalid native-v8 local bundle manifest entry")
    installed = stack / relative
    packaged = target_bundle / relative
    if hashlib.sha256(installed.read_bytes()).hexdigest() != digest:
        raise SystemExit(f"native-v8 bundle digest mismatch: {relative}")
    if installed.read_bytes() != packaged.read_bytes():
        raise SystemExit(f"native-v8 bundle differs from target package: {relative}")

database = data_dir / "state/audit-custom.db"
if not database.is_file():
    raise SystemExit("native-v8 target gateway did not initialize SQLite")
connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
try:
    if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
        raise SystemExit("native-v8 SQLite database failed quick_check")
    tables = {
        row[0]
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    required = {
        "correlation_events",
        "correlation_identifiers",
        "correlation_observations",
        "correlation_relationships",
        "correlation_receipts",
    }
    if not required.issubset(tables):
        raise SystemExit("native-v8 SQLite database lost correlation tables")
finally:
    connection.close()

print("config_v8_native_fixture=byte_exact")
print("v8_activation_recovery=not_reapplied")
print("native_v8_release_backup_and_receipt=ok")
print("local_bundle_manifest=target_exact_custom_preserved")
PY
        else
        "${venv_python}" - \
            "${SMOKE_HOME}/.defenseclaw" \
            "${SMOKE_HOME}/fixture-evidence" \
            "${SMOKE_HOME}/upgrade.log" \
            "${TARGET_VERSION}" \
            "${FROM_VERSION}" \
            "${FROM_CONFIG_VERSION}" \
            "${PROTECTED_ARTIFACT_VERSION}" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys

from dotenv import dotenv_values
import yaml
from defenseclaw.bundle_refresh import _build_local_observability_manifest
from defenseclaw.paths import bundled_local_observability_dir

data_dir = Path(sys.argv[1])
evidence_dir = Path(sys.argv[2])
upgrade_log = Path(sys.argv[3])
target_version = sys.argv[4]
source_version = sys.argv[5]
source_config_version = int(sys.argv[6])
bridge_version = sys.argv[7]
config_path = data_dir / "config.yaml"
config_bytes = config_path.read_bytes()
config_text = config_bytes.decode("utf-8")
config = yaml.safe_load(config_text) or {}

if config.get("config_version") != 8:
    raise SystemExit(f"config_version={config.get('config_version')!r}; want 8")
for legacy in ("otel", "audit_sinks", "privacy"):
    if legacy in config:
        raise SystemExit(f"rejected legacy block remains in v8 config: {legacy}")
if (config.get("ai_discovery") or {}).get("emit_otel") is not None:
    raise SystemExit("legacy ai_discovery.emit_otel remains in v8 config")

observability = config.get("observability") or {}
if (observability.get("defaults") or {}).get("redaction_profile") != "legacy-v7":
    raise SystemExit("legacy-v7 compatibility redaction was not materialized")
if (observability.get("trace_policy") or {}).get("sampler") != "always_on":
    raise SystemExit("trace sampler was not preserved")
if observability.get("metric_policy") != {
    "export_interval_seconds": 60,
    "temporality": "delta",
}:
    raise SystemExit("metric interval/temporality was not preserved")
if (observability.get("resource") or {}).get("attributes") != {
    "service.name": "defenseclaw-upgrade-smoke",
    "deployment.environment.name": "historical-matrix",
}:
    raise SystemExit("resource attributes were not canonicalized exactly")
if observability.get("local") != {
    "path": str(data_dir / "state/audit-custom.db"),
    "judge_bodies_path": str(data_dir / "state/judge-custom.db"),
}:
    raise SystemExit("non-default audit/judge paths were not preserved")
if (config.get("guardrail") or {}).get("retain_judge_bodies") is not False:
    raise SystemExit("judge-body retention enablement was not preserved")
gateway = config.get("gateway") or {}
if gateway.get("fleet_mode") != "disabled" or (gateway.get("watcher") or {}).get("enabled") is not False:
    raise SystemExit("hermetic gateway connectivity policy was not preserved")
openclaw_home = data_dir.parent / ".openclaw"
try:
    openclaw_info = openclaw_home.lstat()
except FileNotFoundError:
    raise SystemExit("fixture OpenClaw home disappeared across the staged upgrade") from None
if not stat.S_ISDIR(openclaw_info.st_mode) or stat.S_IMODE(openclaw_info.st_mode) != 0o700:
    raise SystemExit("fixture OpenClaw home mode changed across the staged upgrade")

destinations = {
    item.get("name"): item
    for item in observability.get("destinations", [])
    if isinstance(item, dict) and isinstance(item.get("name"), str)
}
required_destinations = {
    "gateway-jsonl",
    "gateway-console",
    "local-observability",
    "existing-otlp",
    "galileo",
    "galileo-logs-metrics",
    "splunk-protected",
    "http-protected",
    "audit-otlp",
}
missing = sorted(required_destinations - destinations.keys())
if missing:
    raise SystemExit(f"missing migrated destinations: {missing!r}")
local = destinations["local-observability"]
if (
    local.get("kind") != "otlp"
    or local.get("protocol") != "grpc"
    or local.get("endpoint") != "127.0.0.1:4317"
    or (local.get("network_safety") or {}).get("allow_private_networks") is not True
):
    raise SystemExit("flat OTel transport did not become local-observability")
if local.get("headers") != {
    "X-Flat-Protected": {"env": "DEFENSECLAW_MIGRATED_LOCAL_OBSERVABILITY_X_FLAT_PROTECTED"}
}:
    raise SystemExit("flat OTel header was not promoted to a protected reference")

def route_signals(destination: dict) -> set[tuple[str, ...]]:
    return {
        tuple(route.get("signals", []))
        for route in destination.get("routes", [])
        if isinstance(route, dict) and route.get("action", "send") == "send"
    }

gateway_jsonl = destinations["gateway-jsonl"]
if (
    gateway_jsonl.get("kind") != "jsonl"
    or gateway_jsonl.get("enabled", True) is not True
    or gateway_jsonl.get("path") != str(data_dir / "gateway.jsonl")
    or gateway_jsonl.get("rotation")
    != {"max_size_mb": 50, "max_backups": 5, "max_age_days": 30, "compress": True}
    or route_signals(gateway_jsonl) != {("logs",)}
):
    raise SystemExit("gateway JSONL behavior was not generated exactly")
gateway_console = destinations["gateway-console"]
if gateway_console.get("kind") != "console" or route_signals(gateway_console) != {("logs",)}:
    raise SystemExit("gateway console behavior was not generated exactly")

if not {("logs",), ("traces",), ("metrics",)}.issubset(route_signals(local)):
    raise SystemExit("flat OTel logs/traces/metrics routes were not preserved")
if route_signals(destinations["existing-otlp"]) != {("logs",), ("traces",)}:
    raise SystemExit("named OTel signal narrowing was not preserved")
galileo = destinations["galileo"]
if galileo.get("preset") != "galileo" or route_signals(galileo) != {("traces",)}:
    raise SystemExit("Galileo trace preset/route was not preserved")
if (galileo.get("batch") or {}).get("scheduled_delay_ms") != 1000:
    raise SystemExit("Galileo inherited delay did not receive the v8 preset")
if route_signals(destinations["galileo-logs-metrics"]) != {("logs",), ("metrics",)}:
    raise SystemExit("Galileo non-trace signals were not split losslessly")

for destination_name in required_destinations:
    destination = destinations[destination_name]
    for route in destination.get("routes", []):
        if not isinstance(route, dict) or route.get("action", "send") != "send":
            continue
        signals = set(route.get("signals", []))
        if signals.intersection({"logs", "traces"}) and route.get("redaction_profile") != "legacy-v7":
            raise SystemExit(f"compatibility redaction missing from {destination_name}")

if destinations["splunk-protected"].get("kind") != "splunk_hec":
    raise SystemExit("Splunk HEC audit sink was not generated")
if destinations["http-protected"].get("kind") != "http_jsonl":
    raise SystemExit("HTTP JSONL audit sink was not generated")
if destinations["audit-otlp"].get("kind") != "otlp":
    raise SystemExit("OTLP audit-log sink was not generated")
for destination_name in ("splunk-protected", "http-protected", "audit-otlp"):
    if route_signals(destinations[destination_name]) != {("logs",)}:
        raise SystemExit(f"audit push route mismatch for {destination_name}")

for destination_name in ("local-observability", "existing-otlp", "galileo", "galileo-logs-metrics"):
    routes = destinations[destination_name].get("routes", [])
    if not any(
        isinstance(route, dict)
        and route.get("selector") == {"buckets": ["ai.discovery"]}
        and route.get("action") == "drop"
        for route in routes
    ):
        raise SystemExit(f"ai_discovery.emit_otel=false was lost for {destination_name}")

for destination_name in ("splunk-protected", "http-protected", "audit-otlp"):
    routes = destinations[destination_name].get("routes", [])
    if not any(
        isinstance(route, dict)
        and route.get("selector") == {"connectors": ["codex"]}
        and route.get("action") == "drop"
        for route in routes
    ):
        raise SystemExit(f"connector audit suppression was lost for {destination_name}")
if destinations["splunk-protected"].get("token_env") != "DEFENSECLAW_MIGRATED_SPLUNK_PROTECTED_TOKEN":
    raise SystemExit("Splunk token was not promoted")
if destinations["http-protected"].get("bearer_env") != "DEFENSECLAW_MIGRATED_HTTP_PROTECTED_BEARER":
    raise SystemExit("HTTP bearer token was not promoted")
audit_otlp = destinations["audit-otlp"]
if audit_otlp.get("logger_name") != "defenseclaw.upgrade-smoke":
    raise SystemExit("OTLP logger_name was not preserved")
if audit_otlp.get("headers") != {
    "Authorization": {"env": "DEFENSECLAW_MIGRATED_AUDIT_OTLP_AUTHORIZATION"}
}:
    raise SystemExit("OTLP audit header was not promoted")

expected_environment = {
    "PRESERVE_UPGRADE_SMOKE_ENV": "preserved",
    "DEFENSECLAW_MIGRATED_LOCAL_OBSERVABILITY_X_FLAT_PROTECTED": "upgrade-smoke-flat-protected-value",
    "DEFENSECLAW_MIGRATED_SPLUNK_PROTECTED_TOKEN": "upgrade-smoke-splunk-protected-value",
    "DEFENSECLAW_MIGRATED_HTTP_PROTECTED_BEARER": "upgrade-smoke-http-protected-value",
    "DEFENSECLAW_MIGRATED_AUDIT_OTLP_AUTHORIZATION": "Bearer upgrade-smoke-otlp-protected-value",
}
actual_environment = dotenv_values(data_dir / ".env")
for name, value in expected_environment.items():
    if actual_environment.get(name) != value:
        raise SystemExit(f"protected environment promotion mismatch for {name}")
historical_environment_values = dotenv_values(evidence_dir / "environment.historical.source")
historical_gateway_token = historical_environment_values.get("DEFENSECLAW_GATEWAY_TOKEN")
if not isinstance(historical_gateway_token, str) or re.fullmatch(r"[0-9a-f]{64}", historical_gateway_token) is None:
    raise SystemExit("historical fixture gateway token is missing or invalid")
if actual_environment.get("DEFENSECLAW_GATEWAY_TOKEN") != historical_gateway_token:
    raise SystemExit("gateway token changed across the staged upgrade")
if os.name != "nt" and stat.S_IMODE((data_dir / ".env").stat().st_mode) != 0o600:
    raise SystemExit("promoted .env is not mode 0600")
protected_values = (
    *(value for name, value in expected_environment.items() if name != "PRESERVE_UPGRADE_SMOKE_ENV"),
    historical_gateway_token,
)
log_text = upgrade_log.read_text(encoding="utf-8", errors="replace")
if any(value in config_text or value in log_text for value in protected_values):
    raise SystemExit("protected fixture value escaped into v8 YAML or upgrade output")

activation_manifests = sorted((data_dir / "backups").glob("observability-v8-*/manifest.json"))
if len(activation_manifests) != 1:
    raise SystemExit("expected exactly one observability-v8 recovery manifest")
activation_dir = activation_manifests[0].parent
activation_manifest = json.loads(activation_manifests[0].read_text(encoding="utf-8"))
activation_config = activation_dir / "config.source"
activation_environment = activation_dir / "environment.source"
if yaml.safe_load(activation_config.read_text(encoding="utf-8")).get("config_version") != 7:
    raise SystemExit("activation recovery config is not the config-v7 bridge state")
manifest_by_role = {item["role"]: item for item in activation_manifest.get("files", [])}
if manifest_by_role.get("config", {}).get("sha256") != hashlib.sha256(activation_config.read_bytes()).hexdigest():
    raise SystemExit("activation config recovery digest mismatch")
if manifest_by_role.get("environment", {}).get("sha256") != hashlib.sha256(
    activation_environment.read_bytes()
).hexdigest():
    raise SystemExit("activation environment recovery digest mismatch")

historical_config = evidence_dir / "config.historical.source"
historical_environment = evidence_dir / "environment.historical.source"
historical_config_bytes = historical_config.read_bytes()
historical_environment_bytes = historical_environment.read_bytes()
historical_document = yaml.safe_load(historical_config_bytes.decode("utf-8")) or {}
if historical_document.get("config_version") != source_config_version:
    raise SystemExit(
        f"historical source config_version={historical_document.get('config_version')!r}; "
        f"want reviewed version {source_config_version} for {source_version}"
    )

normal_backup_dirs = sorted(
    path for path in (data_dir / "backups").glob("upgrade-*") if path.is_dir() and not path.is_symlink()
)
if not normal_backup_dirs:
    raise SystemExit("upgrade created no normal source/bridge backup")


def matching_backup_dirs(config_source: bytes, environment_source: bytes) -> list[Path]:
    matches = []
    for backup_dir in normal_backup_dirs:
        backup_config = backup_dir / "config.yaml"
        backup_environment = backup_dir / ".env"
        if (
            backup_config.is_file()
            and not backup_config.is_symlink()
            and backup_environment.is_file()
            and not backup_environment.is_symlink()
            and backup_config.read_bytes() == config_source
            and backup_environment.read_bytes() == environment_source
        ):
            matches.append(backup_dir)
    return matches


historical_backups = matching_backup_dirs(historical_config_bytes, historical_environment_bytes)
bridge_backups = matching_backup_dirs(
    activation_config.read_bytes(),
    activation_environment.read_bytes(),
)


def version_tuple(value: str) -> tuple[int, int, int]:
    return tuple(int(part) for part in value.split("."))


source_is_older_than_bridge = version_tuple(source_version) < version_tuple(bridge_version)
if source_is_older_than_bridge:
    phase_one_backups = [
        path
        for path in historical_backups
        if (path / "phase1-source-gateway").is_file()
        and not (path / "phase1-source-gateway").is_symlink()
    ]
    if not phase_one_backups:
        raise SystemExit("phase one retained no byte-exact historical config/.env backup")
    phase_two_backups = [path for path in bridge_backups if path not in phase_one_backups]
    if not phase_two_backups:
        raise SystemExit("phase two retained no distinct byte-exact config-v7 bridge backup")

else:
    if not historical_backups:
        raise SystemExit("direct bridge upgrade retained no byte-exact historical config/.env backup")
    if not bridge_backups:
        raise SystemExit("direct bridge upgrade backup does not match the pre-v8 activation state")

for comment in (
    "# ┌──── OBSERVABILITY UPGRADE SMOKE ────┐",
    "# comments, order, and unrelated settings must survive",
    "# unrelated section survives",
):
    if comment not in config_text:
        raise SystemExit(f"comment-heavy YAML token was lost: {comment}")

stack = data_dir / "observability-stack"
manifest_path = stack / ".defenseclaw-bundle-manifest.json"
bundle_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
if bundle_manifest.get("bundle_version") != target_version:
    raise SystemExit("local bundle manifest is not stamped with the target version")
if len(bundle_manifest.get("dashboard_uids", [])) != 14:
    raise SystemExit("local bundle manifest does not contain all fourteen dashboards")
if set(bundle_manifest.get("named_volumes", [])) != {
    "grafana-data",
    "loki-data",
    "prometheus-data",
    "tempo-data",
}:
    raise SystemExit("local bundle named-volume contract changed")
if (stack / "operator/volume-continuity.txt").read_bytes() != b"operator-owned volume continuity marker\n":
    raise SystemExit("operator volume-continuity marker was not preserved")
if (stack / "grafana/dashboards/team-upgrade-smoke.json").read_bytes() != (
    b'{"title":"Operator Custom Dashboard","uid":"team-upgrade-smoke"}\n'
):
    raise SystemExit("operator custom dashboard was not preserved")

target_bundle = bundled_local_observability_dir()
expected_bundle_manifest = json.loads(
    _build_local_observability_manifest(target_bundle, target_version).raw
)
if bundle_manifest != expected_bundle_manifest:
    raise SystemExit("local bundle manifest differs from the complete target package")
for item in bundle_manifest.get("files", []):
    relative = item.get("path")
    digest = item.get("sha256")
    if not isinstance(relative, str) or not isinstance(digest, str):
        raise SystemExit("invalid local bundle manifest entry")
    installed = stack / relative
    packaged = target_bundle / relative
    if hashlib.sha256(installed.read_bytes()).hexdigest() != digest:
        raise SystemExit(f"installed managed bundle digest mismatch: {relative}")
    if installed.read_bytes() != packaged.read_bytes():
        raise SystemExit(f"installed managed bundle differs from target package: {relative}")

sqlite_path = data_dir / "state/audit-custom.db"
if not sqlite_path.is_file():
    raise SystemExit("fresh target gateway did not initialize the configured SQLite database")
connection = sqlite3.connect(f"file:{sqlite_path}?mode=ro", uri=True)
try:
    if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
        raise SystemExit("configured SQLite database failed quick_check")
finally:
    connection.close()

print("config_v8_historical_fixture=ok")
print("v8_secret_promotion=ok")
print("v8_recovery_backups=historical_and_bridge_byte_exact")
print("local_bundle_manifest=target_exact_custom_preserved")
PY
        fi

        local receipt_from="${FROM_VERSION}"
        if [[ -n "${REQUIRED_BRIDGE_VERSION}" ]] \
            && ! version_lte "${REQUIRED_BRIDGE_VERSION}" "${FROM_VERSION}"; then
            receipt_from="${REQUIRED_BRIDGE_VERSION}"
        fi
        "${venv_python}" "${ROOT}/scripts/check_upgrade_receipt.py" \
            --data-dir "${SMOKE_HOME}/.defenseclaw" \
            --from-version "${receipt_from}" \
            --target-version "${TARGET_VERSION}" \
            --timeout-seconds 10 \
            || die "target gateway did not admit and acknowledge the successful upgrade receipt"
    else
        "${venv_python}" - "${SMOKE_HOME}/.defenseclaw" <<'PY'
from pathlib import Path
import sys

import yaml

data_dir = Path(sys.argv[1])
config = yaml.safe_load((data_dir / "config.yaml").read_text(encoding="utf-8")) or {}
if config.get("config_version") != 7:
    raise SystemExit(f"config_version={config.get('config_version')!r}; want 7")
otel = config.get("otel") or {}
destinations = otel.get("destinations") or []
names = [item.get("name") for item in destinations if isinstance(item, dict)]
if names != ["local-observability", "existing-otlp"]:
    raise SystemExit(f"named OTel migration mismatch: {names!r}")
migrated = destinations[0]
if migrated.get("endpoint") != "127.0.0.1:4317":
    raise SystemExit(f"legacy endpoint was not preserved: {migrated!r}")
if migrated.get("headers") != {"X-Upgrade-Fixture": "preserved"}:
    raise SystemExit(f"legacy headers were not preserved: {migrated!r}")
if any(key in otel for key in ("endpoint", "protocol", "headers")):
    raise SystemExit(f"flat OTel transport fields remain: {otel!r}")
if otel.get("traces") != {"sampler": "always_on"}:
    raise SystemExit(f"process-wide trace policy was not preserved: {otel.get('traces')!r}")
if otel.get("logs") != {"emit_individual_findings": True}:
    raise SystemExit(f"process-wide log policy was not preserved: {otel.get('logs')!r}")
backup = data_dir / "config.yaml.pre-observability-migration.bak"
if not backup.is_file():
    raise SystemExit("named OTel migration did not create its one-time backup")
print("config_v7_named_otel=ok")
PY
    fi

    local gateway_status_log="${SMOKE_HOME}/gateway-status.log"
    if ! HOME="${SMOKE_HOME}" DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
        PATH="${SMOKE_HOME}/.local/bin:${PATH}" defenseclaw-gateway status \
        >"${gateway_status_log}" 2>&1; then
        tail_log "${gateway_status_log}"
        die "freshly started target gateway is not healthy"
    fi
    ok "Fresh target gateway is running and healthy"

    "${venv_python}" - <<'PY'
import textual
from defenseclaw.tui.widgets.native_metrics import MetricDatum, MetricTile

metric = MetricDatum(
    key="hook_calls",
    label="Hook Calls",
    value=0,
    progress=0.0,
    detail="gateway offline",
    state="error",
    target_panel="logs",
)
tile = MetricTile(metric)
tile.refresh_metric(metric)
print("textual_version=" + getattr(textual, "__version__", "unknown"))
print("metric_tile_refresh=ok")
PY
}

run_one_upgrade_smoke() {
    FROM_VERSION="$1"
    local home_name="${FROM_VERSION//[^A-Za-z0-9._-]/_}"
    SMOKE_HOME="${WORKDIR}/home-${home_name}"
    rm -rf "${SMOKE_HOME}"
    mkdir -p "${SMOKE_HOME}"

    install_baseline
    seed_upgrade_fixture
    start_source_gateway_canary
    assert_source_gateway_canary_preserved_fixture
    patch_installed_upgrade_endpoint
    run_upgrade
    verify_upgrade
    stop_smoke_gateway

    ok "Upgrade smoke passed: ${FROM_VERSION} -> ${TARGET_VERSION} (${OS_NAME}/${ARCH_NAME})"
    if [[ "${KEEP_WORKDIR}" == "1" ]]; then
        ok "Upgrade log: ${SMOKE_HOME}/upgrade.log"
    fi
}

main() {
    parse_args "$@"
    cd "${ROOT}"
    if [[ -z "${TARGET_VERSION}" ]]; then
        TARGET_VERSION="$(current_version)"
    fi
    validate_inputs
    detect_platform

    # macOS exposes its private temporary root through the /var symlink.  The
    # production v8 activation correctly rejects symlinks anywhere in the
    # protected config parent chain, so carry the physical path into every
    # fixture rather than accidentally testing the public /var alias.
    WORKDIR="$(abs_path "$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-upgrade-smoke.XXXXXX")")"

    prepare_release_root
    assert_candidate_assets
    if [[ "${PREPARE_ONLY}" == "1" ]]; then
        ok "Prepared candidate release root: ${RELEASE_ROOT}"
        ok "Contains ${TARGET_VERSION} artifacts for ${OS_NAME}/${ARCH_NAME}"
        return
    fi
    start_release_server
    run_v8_source_contract_tests
    local version
    for version in "${FROM_VERSION_LIST[@]}"; do
        run_one_upgrade_smoke "${version}"
    done

    ok "Upgrade smoke matrix passed for ${#FROM_VERSION_LIST[@]} baseline(s): ${FROM_VERSION_LIST[*]} -> ${TARGET_VERSION} (${OS_NAME}/${ARCH_NAME})"
    if [[ "${KEEP_WORKDIR}" == "1" ]]; then
        ok "Upgrade logs retained under: ${WORKDIR}"
    else
        ok "Temp HOME/logs cleaned automatically; re-run with --keep-workdir to retain them"
    fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
