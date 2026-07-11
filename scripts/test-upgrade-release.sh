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
FROM_VERSION="${FROM_VERSION:-0.7.2}"
FROM_VERSIONS="${FROM_VERSIONS:-}"
TARGET_VERSION="${TARGET_VERSION:-}"
V8_ACTIVATION_VERSION="0.8.5"
RELEASE_ROOT="${RELEASE_ROOT:-}"
RELEASE_DIR="${RELEASE_DIR:-}"
BASELINE_MODE="${BASELINE_MODE:-auto}" # auto | install | seed
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

usage() {
    cat <<'EOF'
Usage: scripts/test-upgrade-release.sh [options]

Build or consume candidate release artifacts, install an older DefenseClaw in a
throwaway HOME, redirect its upgrade command to the local candidate artifacts,
then run and verify a real upgrade.

Options:
  --from-version VERSION     Installed baseline version to upgrade from (default: 0.7.2)
  --from-versions LIST       Space/comma-separated baseline versions to test
  --target-version VERSION   Candidate version (default: pyproject.toml version)
  --release-dir DIR          Existing artifact dir, e.g. dist/ from the release workflow
  --release-root DIR         Existing local release root containing VERSION/<assets>
  --baseline-mode MODE       auto, install, or seed (default: auto)
  --health-timeout SECONDS   Gateway health wait passed to upgrade (default: 1)
  --port PORT                Local release server port (default: random high port)
  --platform OS/ARCH         Build platform for --prepare-only (default: current host)
  --prepare-only             Build/validate candidate release root, print it, and exit
  --keep-workdir             Keep temp HOME/logs for debugging
  --help                     Show this help

Examples:
  make upgrade-smoke
  make upgrade-smoke-matrix
  scripts/test-upgrade-release.sh --from-version 0.7.2
  scripts/test-upgrade-release.sh --from-versions "0.8.3,0.8.2,0.8.1,0.8.0,0.7.2,0.7.1"
  scripts/test-upgrade-release.sh --release-dir dist --baseline-mode seed

For a Linux host without the repo's Go toolchain, build/copy artifacts first:
  scripts/test-upgrade-release.sh --prepare-only --platform linux/arm64 --keep-workdir
  scp -r /tmp/candidate-root user@linux:/tmp/
  ssh user@linux 'scripts/test-upgrade-release.sh --release-root /tmp/candidate-root'
EOF
}

log() { printf '==> %s\n' "$*"; }
ok() { printf 'OK: %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

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
            linux/amd64|linux/arm64|darwin/amd64|darwin/arm64)
                OS_NAME="${BUILD_PLATFORM%%/*}"
                ARCH_NAME="${BUILD_PLATFORM##*/}"
                return ;;
            *)
                die "--platform must be one of linux/amd64, linux/arm64, darwin/amd64, darwin/arm64" ;;
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

validate_inputs() {
    normalize_baseline_versions
    [[ "${TARGET_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid --target-version: ${TARGET_VERSION}"
    case "${BASELINE_MODE}" in
        auto|install|seed) ;;
        *) die "--baseline-mode must be auto, install, or seed" ;;
    esac
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
    mkdir -p "${out}"

    log "Building candidate CLI wheel"
    make -C "${ROOT}" dist-cli DIST_DIR="${out}"

    log "Building candidate gateway (${OS_NAME}/${ARCH_NAME})"
    make -C "${ROOT}" sync-openclaw-extension
    local stage="${WORKDIR}/gateway-${OS_NAME}-${ARCH_NAME}"
    mkdir -p "${stage}"
    CGO_ENABLED=0 GOOS="${OS_NAME}" GOARCH="${ARCH_NAME}" \
        go build -ldflags "-s -w -X main.version=${TARGET_VERSION}" \
        -o "${stage}/defenseclaw" "${ROOT}/cmd/defenseclaw"
    tar -czf "${out}/defenseclaw_${TARGET_VERSION}_${OS_NAME}_${ARCH_NAME}.tar.gz" \
        -C "${stage}" defenseclaw

    log "Generating candidate upgrade manifest/checksums"
    python3 "${ROOT}/scripts/generate-upgrade-manifest.py" \
        --out "${out}/upgrade-manifest.json"
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
    local wheel="${dir}/defenseclaw-${TARGET_VERSION}-py3-none-any.whl"
    [[ -d "${dir}" ]] || die "release root must contain ${TARGET_VERSION}/: ${RELEASE_ROOT}"
    [[ -f "${wheel}" ]] \
        || die "candidate wheel missing from ${dir}"
    [[ -f "${dir}/defenseclaw_${TARGET_VERSION}_${OS_NAME}_${ARCH_NAME}.tar.gz" ]] \
        || die "candidate gateway archive missing for ${OS_NAME}/${ARCH_NAME} in ${dir}"
    [[ -f "${dir}/upgrade-manifest.json" ]] || die "upgrade-manifest.json missing from ${dir}"
    [[ -f "${dir}/checksums.txt" ]] || die "checksums.txt missing from ${dir}"
    python3 - "${wheel}" <<'PY'
from pathlib import Path
import sys
import zipfile

wheel = Path(sys.argv[1])
with zipfile.ZipFile(wheel) as archive:
    bytecode = [
        name for name in archive.namelist()
        if "/__pycache__/" in name or name.endswith((".pyc", ".pyo"))
    ]
if bytecode:
    sample = ", ".join(bytecode[:5])
    raise SystemExit(
        f"candidate wheel contains stale Python bytecode ({len(bytecode)} file(s)): {sample}"
    )
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
    python3 - "${file}" <<'PY' >&2
from pathlib import Path
import sys

text = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
protected = (
    "upgrade-smoke-flat-protected-value",
    "upgrade-smoke-splunk-protected-value",
    "upgrade-smoke-http-protected-value",
    "Bearer upgrade-smoke-otlp-protected-value",
    "upgrade-smoke-otlp-protected-value",
)
for value in protected:
    text = text.replace(value, "[REDACTED]")
print("\n".join(text.splitlines()[-80:]))
PY
}

download_old_asset() {
    local name="$1"
    local dest="$2"
    local url="https://github.com/${REPO}/releases/download/${FROM_VERSION}/${name}"
    curl -fsSL "${url}" -o "${dest}"
}

seed_baseline_install() {
    log "Seeding baseline ${FROM_VERSION} install"
    mkdir -p "${SMOKE_HOME}/.local/bin" "${SMOKE_HOME}/.defenseclaw"

    local old_dir="${WORKDIR}/old-release/${FROM_VERSION}"
    mkdir -p "${old_dir}"
    local old_wheel="${old_dir}/defenseclaw-${FROM_VERSION}-py3-none-any.whl"
    local old_gateway="${old_dir}/defenseclaw_${FROM_VERSION}_${OS_NAME}_${ARCH_NAME}.tar.gz"
    download_old_asset "defenseclaw-${FROM_VERSION}-py3-none-any.whl" "${old_wheel}" \
        || die "could not download old wheel for ${FROM_VERSION}; choose a release with assets"
    download_old_asset "defenseclaw_${FROM_VERSION}_${OS_NAME}_${ARCH_NAME}.tar.gz" "${old_gateway}" \
        || die "could not download old gateway for ${FROM_VERSION}/${OS_NAME}/${ARCH_NAME}"

    uv --no-config venv "${SMOKE_HOME}/.defenseclaw/.venv" --python 3.12 --quiet
    local venv_python="${SMOKE_HOME}/.defenseclaw/.venv/bin/python"
    uv --no-config pip install --python "${venv_python}" --quiet \
        "${RELEASE_URL}/${TARGET_VERSION}/defenseclaw-${TARGET_VERSION}-py3-none-any.whl" \
        >"${SMOKE_HOME}/seed-target-deps.log" 2>&1 \
        || { tail_log "${SMOKE_HOME}/seed-target-deps.log"; die "could not seed target dependency set"; }
    uv --no-config pip install --python "${venv_python}" --quiet --no-deps "${old_wheel}" \
        >"${SMOKE_HOME}/seed-old-wheel.log" 2>&1 \
        || { tail_log "${SMOKE_HOME}/seed-old-wheel.log"; die "could not install old wheel"; }

    ln -sf "${SMOKE_HOME}/.defenseclaw/.venv/bin/defenseclaw" "${SMOKE_HOME}/.local/bin/defenseclaw"

    local gateway_stage="${WORKDIR}/old-gateway/${FROM_VERSION}"
    mkdir -p "${gateway_stage}"
    tar -xzf "${old_gateway}" -C "${gateway_stage}"
    cp "${gateway_stage}/defenseclaw" "${SMOKE_HOME}/.local/bin/defenseclaw-gateway"
    chmod +x "${SMOKE_HOME}/.local/bin/defenseclaw-gateway"
}

install_baseline() {
    if [[ "${BASELINE_MODE}" == "seed" ]]; then
        seed_baseline_install
        return
    fi

    log "Installing baseline ${FROM_VERSION} with scripts/install.sh"
    if HOME="${SMOKE_HOME}" DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
        PATH="${SMOKE_HOME}/.local/bin:${PATH}" VERSION="${FROM_VERSION}" \
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

seed_pre_v8_otel_fixture() {
    log "Seeding pre-v8 flat OTel upgrade fixture"
    mkdir -p "${SMOKE_HOME}/.defenseclaw"
    cat >"${SMOKE_HOME}/.defenseclaw/config.yaml" <<'YAML'
config_version: 6
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

seed_v8_observability_fixture() {
    log "Seeding representative comment-heavy v7 observability fixture"
    local data_dir="${SMOKE_HOME}/.defenseclaw"
    local evidence_dir="${SMOKE_HOME}/fixture-evidence"
    mkdir -p "${data_dir}/state" "${evidence_dir}"
    chmod 700 "${data_dir}" "${data_dir}/state" "${evidence_dir}"

    # The values are deliberately recognizable test canaries. Verification
    # checks that they move into the private .env transaction and never occur
    # in the v8 YAML or command output. They are never printed by this script.
    cat >"${data_dir}/config.yaml" <<YAML
# ┌──── OBSERVABILITY UPGRADE SMOKE ────┐
# comments, order, and unrelated settings must survive
config_version: 7
data_dir: ${data_dir}
audit_db: ${data_dir}/state/audit-custom.db # custom audit path
judge_bodies_db: ${data_dir}/state/judge-custom.db # custom judge path
guardrail:
  enabled: true
  retain_judge_bodies: false
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
    cat >"${data_dir}/.env" <<'ENV'
# exact pre-upgrade environment bytes must be recoverable
PRESERVE_UPGRADE_SMOKE_ENV=preserved
ENV
    chmod 600 "${data_dir}/config.yaml" "${data_dir}/.env"
    cp -p "${data_dir}/config.yaml" "${evidence_dir}/config.v7.source"
    cp -p "${data_dir}/.env" "${evidence_dir}/environment.v7.source"

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

seed_upgrade_fixture() {
    if target_uses_observability_v8; then
        seed_v8_observability_fixture
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
    if ! PYTHONDONTWRITEBYTECODE=1 uv run python -m pytest -q \
        cli/tests/test_observability_v8_activation.py \
        cli/tests/test_observability_v8_upgrade_migration.py \
        cli/tests/test_local_observability_bundle_upgrade.py \
        cli/tests/test_local_observability_upgrade_wiring.py \
        >"${result_log}" 2>&1; then
        die "v8 source contract tests failed (private log: ${result_log})"
    fi
    ok "v8 source contracts passed (permission, retry, rollback, bundle)"
}

patch_installed_upgrade_endpoint() {
    local upgrade_py
    upgrade_py="$(find "${SMOKE_HOME}/.defenseclaw/.venv" \
        -path '*/site-packages/defenseclaw/commands/cmd_upgrade.py' -print -quit)"
    [[ -n "${upgrade_py}" ]] || die "installed cmd_upgrade.py not found"

    python3 - "${upgrade_py}" "${RELEASE_URL}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
release_url = sys.argv[2]
text = path.read_text(encoding="utf-8")
old = 'GITHUB_DL = f"https://github.com/{GITHUB_REPO}/releases/download"'
new = f'GITHUB_DL = "{release_url}"'
if old not in text:
    raise SystemExit(f"release URL constant not found in {path}")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
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
        tail_log "${SMOKE_HOME}/upgrade.log"
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

    HOME="${SMOKE_HOME}" DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
    PATH="${SMOKE_HOME}/.local/bin:${PATH}" \
        defenseclaw --version | grep -F "${TARGET_VERSION}" >/dev/null \
        || die "defenseclaw --version does not report ${TARGET_VERSION}"

    HOME="${SMOKE_HOME}" DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
    PATH="${SMOKE_HOME}/.local/bin:${PATH}" \
        defenseclaw-gateway --version | grep -F "${TARGET_VERSION}" >/dev/null \
        || die "defenseclaw-gateway --version does not report ${TARGET_VERSION}"

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
        "${venv_python}" - \
            "${SMOKE_HOME}/.defenseclaw" \
            "${SMOKE_HOME}/fixture-evidence" \
            "${SMOKE_HOME}/upgrade.log" \
            "${TARGET_VERSION}" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys

from dotenv import dotenv_values
import yaml
from defenseclaw.paths import bundled_local_observability_dir

data_dir = Path(sys.argv[1])
evidence_dir = Path(sys.argv[2])
upgrade_log = Path(sys.argv[3])
target_version = sys.argv[4]
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
if os.name != "nt" and stat.S_IMODE((data_dir / ".env").stat().st_mode) != 0o600:
    raise SystemExit("promoted .env is not mode 0600")
protected_values = tuple(value for name, value in expected_environment.items() if name != "PRESERVE_UPGRADE_SMOKE_ENV")
log_text = upgrade_log.read_text(encoding="utf-8", errors="replace")
if any(value in config_text or value in log_text for value in protected_values):
    raise SystemExit("protected fixture value escaped into v8 YAML or upgrade output")

source_config = evidence_dir / "config.v7.source"
source_environment = evidence_dir / "environment.v7.source"
normal_backups = sorted((data_dir / "backups").glob("upgrade-*/config.yaml"))
if not normal_backups or any(path.read_bytes() != source_config.read_bytes() for path in normal_backups):
    raise SystemExit("every normal/staged upgrade backup must be the byte-exact v7 source")

activation_manifests = sorted((data_dir / "backups").glob("observability-v8-*/manifest.json"))
if len(activation_manifests) != 1:
    raise SystemExit("expected exactly one observability-v8 recovery manifest")
activation_dir = activation_manifests[0].parent
activation_manifest = json.loads(activation_manifests[0].read_text(encoding="utf-8"))
activation_config = activation_dir / "config.source"
activation_environment = activation_dir / "environment.source"
if yaml.safe_load(activation_config.read_text(encoding="utf-8")).get("config_version") != 7:
    raise SystemExit("activation recovery config is not the exact pre-v8 source")
if activation_environment.read_bytes() != source_environment.read_bytes():
    raise SystemExit("activation recovery .env is not byte-exact")
manifest_by_role = {item["role"]: item for item in activation_manifest.get("files", [])}
if manifest_by_role.get("config", {}).get("sha256") != hashlib.sha256(activation_config.read_bytes()).hexdigest():
    raise SystemExit("activation config recovery digest mismatch")
if manifest_by_role.get("environment", {}).get("sha256") != hashlib.sha256(
    activation_environment.read_bytes()
).hexdigest():
    raise SystemExit("activation environment recovery digest mismatch")

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
print("v8_recovery_backups=byte_exact")
print("local_bundle_manifest=target_exact_custom_preserved")
PY
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
