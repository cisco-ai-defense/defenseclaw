#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# Live release gate for E2E-9. This script intentionally uses Docker, published
# baseline artifacts, the release-owned resolver, and the bundled local-
# observability bridge. It refuses to run when the shared compose project or
# any standard stack port is already in use.

set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST_GOMODCACHE="$(go env GOMODCACHE)"
# Docker Desktop commonly installs the Compose CLI plugin beneath the caller's
# Docker config directory. The continuity gate intentionally replaces HOME for
# the test installation, so retain only Docker's original config lookup path;
# otherwise the published baseline can falsely report that Compose is absent.
HOST_DOCKER_CONFIG="${DOCKER_CONFIG:-${HOME}/.docker}"
# Source the production release-upgrade harness for artifact preparation,
# baseline installation, checksum serving, and target endpoint patching. Its
# main function is guarded, so sourcing does not run a smoke test.
# shellcheck source=scripts/test-upgrade-release.sh
source "${ROOT}/scripts/test-upgrade-release.sh"
trap - EXIT

TARGET_VERSION=""
FROM_VERSION=""
FROM_VERSIONS=""
FROM_VERSION_EXPLICIT="0"
BASELINE_MODE="seed"
HEALTH_TIMEOUT="60"
KEEP_WORKDIR="0"
RELEASE_ROOT=""
RELEASE_DIR=""
PRE_STAMP=""
POST_STAMP=""
METRIC_CUTOVER_SECONDS=""
OWNED_STACK="0"
LOCAL_CANDIDATE_PROVENANCE_FIXTURE="0"

usage() {
    cat <<'EOF'
Usage: scripts/test-observability-v8-upgrade-continuity.sh [options]

Run the complete live E2E-9 release gate against a private HOME and the real
local Prometheus/Loki/Tempo/Grafana stack.

Options:
  --release-root DIR       Existing root containing candidate artifacts
  --release-dir DIR        Existing release artifact directory
  --from-version VERSION   Bridge baseline (default: candidate manifest requirement)
  --target-version VERSION Candidate hard-cut version (default: checkout version)
  --health-timeout SECONDS Upgrade gateway health timeout (default: 60)
  --keep-workdir           Keep the private HOME, logs, stack, and volumes
  --help                   Show this help

Without --release-root/--release-dir, the checkout must already be stamped to
the candidate; the shared release helper builds and serves its artifacts.
EOF
}

parse_continuity_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --release-root)
                [[ $# -ge 2 ]] || die "--release-root requires a value"
                RELEASE_ROOT="$2"; shift 2 ;;
            --release-dir)
                [[ $# -ge 2 ]] || die "--release-dir requires a value"
                RELEASE_DIR="$2"; shift 2 ;;
            --from-version)
                [[ $# -ge 2 ]] || die "--from-version requires a value"
                FROM_VERSION="$2"; FROM_VERSIONS="$2"; FROM_VERSION_EXPLICIT="1"; shift 2 ;;
            --target-version)
                [[ $# -ge 2 ]] || die "--target-version requires a value"
                TARGET_VERSION="$2"; shift 2 ;;
            --health-timeout)
                [[ $# -ge 2 ]] || die "--health-timeout requires a value"
                HEALTH_TIMEOUT="$2"; shift 2 ;;
            --keep-workdir)
                KEEP_WORKDIR="1"; shift ;;
            --help|-h)
                usage; exit 0 ;;
            *)
                die "unknown argument: $1" ;;
        esac
    done
}

continuity_cleanup() {
    local status=$?
    stop_smoke_gateway
    if [[ "${KEEP_WORKDIR}" != "1" && "${OWNED_STACK}" == "1" ]]; then
        HOME="${SMOKE_HOME}" DOCKER_CONFIG="${HOST_DOCKER_CONFIG}" DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
        PATH="${SMOKE_HOME}/.local/bin:${PATH}" \
            defenseclaw setup local-observability reset \
            >"${SMOKE_HOME}/local-observability-reset.log" 2>&1 || true
    fi
    if [[ -n "${SERVER_PID:-}" ]]; then
        kill "${SERVER_PID}" >/dev/null 2>&1 || true
        wait "${SERVER_PID}" >/dev/null 2>&1 || true
    fi
    if [[ "${KEEP_WORKDIR}" != "1" && -n "${WORKDIR:-}" && -d "${WORKDIR}" ]]; then
        chmod -R u+w "${WORKDIR}" 2>/dev/null || true
        rm -rf "${WORKDIR}"
    elif [[ -n "${WORKDIR:-}" ]]; then
        warn "Kept continuity workdir and live volumes for inspection: ${WORKDIR}"
    fi
    return "${status}"
}

require_private_stack_boundary() {
    command -v docker >/dev/null 2>&1 || die "Docker is required"
    docker info >/dev/null 2>&1 || die "Docker daemon is not available"
    local existing
    existing="$(docker ps -aq --filter label=com.docker.compose.project=defenseclaw-observability)"
    [[ -z "${existing}" ]] || die "the defenseclaw-observability compose project is already present"
    python3 - <<'PY'
import socket

ports = (3000, 3100, 3200, 4317, 4318, 9090)
occupied = []
for port in ports:
    sock = socket.socket()
    sock.settimeout(0.15)
    try:
        if sock.connect_ex(("127.0.0.1", port)) == 0:
            occupied.append(port)
    finally:
        sock.close()
if occupied:
    raise SystemExit("local-observability ports already in use: " + ", ".join(map(str, occupied)))
PY
}

write_initial_v7_config() {
    local data_dir="${SMOKE_HOME}/.defenseclaw"
    mkdir -p "${data_dir}/state"
    chmod 700 "${data_dir}" "${data_dir}/state"
    python3 - "${data_dir}/config.yaml" "${data_dir}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
data_dir = sys.argv[2]
path.write_text(
    "config_version: 7\n"
    f"data_dir: {data_dir}\n"
    f"audit_db: {data_dir}/state/audit.db\n"
    f"judge_bodies_db: {data_dir}/state/judge-bodies.db\n"
    "claw:\n"
    "  mode: ''\n"
    "guardrail:\n"
    "  enabled: true\n"
    "gateway:\n"
    "  fleet_mode: disabled\n"
    "  watcher:\n"
    "    enabled: false\n",
    encoding="utf-8",
)
path.chmod(0o600)
PY
}

normalize_baseline_stack_access() {
    # Published 0.8.3 copied public bind-mounted stack configuration with the
    # caller's umask. The release gate intentionally uses umask 077 for its
    # private HOME, so normalize this legacy seed to the modes a functioning
    # 0.8.3 deployment historically had. Target activation later verifies the
    # 0.8.4 manifest modes independently.
    HOME="${SMOKE_HOME}" DOCKER_CONFIG="${HOST_DOCKER_CONFIG}" DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
    "${SMOKE_HOME}/.defenseclaw/.venv/bin/python" - \
        "${SMOKE_HOME}/.defenseclaw/observability-stack" <<'PY'
import os
from pathlib import Path
import shutil
import sys

from defenseclaw.paths import bundled_local_observability_dir

stack = Path(sys.argv[1])
if not stack.exists():
    shutil.copytree(bundled_local_observability_dir(), stack)
if not stack.is_dir():
    raise SystemExit("legacy local-observability stack seed is unavailable")
for root, directories, files in os.walk(stack, followlinks=False):
    root_path = Path(root)
    root_path.chmod(0o755)
    directories[:] = [name for name in directories if not (root_path / name).is_symlink()]
    for name in files:
        path = root_path / name
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(stack).as_posix()
        path.chmod(0o755 if relative == "run.sh" or relative.startswith("bin/") else 0o644)
PY
}

write_continuity_v7_config() {
    local data_dir="${SMOKE_HOME}/.defenseclaw"
    mkdir -p "${SMOKE_HOME}/fixture-evidence"
    python3 - "${data_dir}/config.yaml" "${data_dir}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
data_dir = sys.argv[2]
path.write_text(
    "# observability-v8 live history continuity fixture\n"
    "config_version: 7\n"
    f"data_dir: {data_dir}\n"
    f"audit_db: {data_dir}/state/audit.db\n"
    f"judge_bodies_db: {data_dir}/state/judge-bodies.db\n"
    "claw:\n"
    "  mode: ''\n"
    "guardrail:\n"
    "  enabled: true\n"
    "  retain_judge_bodies: true\n"
    # This fixture deliberately selects no agent connector. Make that
    # standalone topology explicit so the target gateway can prove healthy
    # local API and observability continuity without silently inventing an
    # OpenClaw fleet dependency on 127.0.0.1:18789.
    "gateway:\n"
    "  fleet_mode: disabled\n"
    "  watcher:\n"
    "    enabled: false\n"
    "otel:\n"
    "  enabled: true\n"
    "  protocol: http\n"
    "  endpoint: http://127.0.0.1:4318\n"
    "  traces:\n"
    "    enabled: true\n"
    "    sampler: always_on\n"
    "  metrics:\n"
    "    enabled: true\n"
    "    export_interval_s: 60\n"
    "    temporality: delta\n"
    "  logs:\n"
    "    enabled: true\n",
    encoding="utf-8",
)
path.chmod(0o600)
PY
    cp -p "${data_dir}/config.yaml" "${SMOKE_HOME}/fixture-evidence/config.v7.source"
}

start_baseline_stack() {
    log "Starting the published ${FROM_VERSION} local-observability bundle"
    # Claim cleanup ownership before startup so a partially-created compose
    # project is removed if the baseline command fails midway.
    OWNED_STACK="1"
    # Released 0.8.3 inherited the caller's umask when seeding public stack
    # configuration. Use the historical deployment mode here; the 0.8.4
    # upgrade is separately required to normalize every managed mode from its
    # signed bundle manifest, even though this harness itself keeps umask 077.
    (
        umask 022
        HOME="${SMOKE_HOME}" DOCKER_CONFIG="${HOST_DOCKER_CONFIG}" DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
        PATH="${SMOKE_HOME}/.local/bin:${PATH}" \
            defenseclaw setup local-observability up \
            --no-config --no-refresh-bundle --timeout 180
    ) >"${SMOKE_HOME}/local-observability-up.log" 2>&1 \
        || { tail_log "${SMOKE_HOME}/local-observability-up.log"; die "baseline stack failed to start"; }
}

volume_inventory() {
    docker volume ls \
        --filter label=com.docker.compose.project=defenseclaw-observability \
        --format '{{.Name}}' | LC_ALL=C sort
}

assert_four_history_volumes() {
    local inventory="$1"
    local count
    count="$(wc -l <"${inventory}" | tr -d ' ')"
    [[ "${count}" == "4" ]] || die "local stack volume count=${count}, want four"
    for suffix in grafana-data loki-data prometheus-data tempo-data; do
        grep -Eq "(^|_)${suffix}$" "${inventory}" \
            || die "missing ${suffix} from local stack volume inventory"
    done
}

emit_continuity_phase() {
    local phase="$1"
    local stamp="$2"
    log "Emitting ${phase}-upgrade root/subagent continuity execution ${stamp}"
    HOME="${SMOKE_HOME}" DOCKER_CONFIG="${HOST_DOCKER_CONFIG}" DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
    DC_TEST_LOCAL_OBSERVABILITY_OTLP_ENDPOINT="http://127.0.0.1:4318" \
    DC_TEST_UPGRADE_CONTINUITY_PHASE="${phase}" \
    DC_TEST_UPGRADE_CONTINUITY_STAMP="${stamp}" \
    GOCACHE="${WORKDIR}/go-cache" GOMODCACHE="${HOST_GOMODCACHE}" \
        go test ./internal/gateway \
        -run '^TestLocalObservabilityUpgradeContinuityProducerScenario$' -count=1 -v \
        >"${SMOKE_HOME}/producer-${phase}.log" 2>&1 \
        || { tail_log "${SMOKE_HOME}/producer-${phase}.log"; die "${phase}-upgrade producer failed"; }
}

wait_for_pre_upgrade_metrics() {
    local stamp="$1"
    log "Waiting for the baseline Prometheus scrape to persist ${stamp}"
    .venv/bin/python - "${stamp}" <<'PY'
import sys
import time

sys.path.insert(0, "scripts")
import check_grafana_dashboards as dashboards

stamp = sys.argv[1]
expected = {"root", "direct", "nested"}
minimum_fixture_time = int(stamp) / 1_000_000_000 - 30
query = (
    'defenseclaw_agent_last_seen_seconds{connector="codex",'
    'gen_ai_agent_type=~"root|direct|nested"}'
)
deadline = time.monotonic() + 60
last_error = "series not yet scraped"
while time.monotonic() < deadline:
    try:
        series = dashboards._prometheus_vector(query, timeout_seconds=15)
        observed = {
            item.get("metric", {}).get("gen_ai_agent_type")
            for item in series
            if dashboards._positive_prometheus_series(item)
            and float(item.get("value", [0, 0])[-1]) >= minimum_fixture_time
        }
        if expected.issubset(observed):
            raise SystemExit(0)
        last_error = f"missing={sorted(expected - observed)}"
    except dashboards.AuditError as exc:
        last_error = str(exc)
    time.sleep(2)
raise SystemExit(f"baseline Prometheus scrape did not persist continuity series: {last_error}")
PY
}

run_live_upgrade() {
    log "Running release-owned resolver upgrade ${FROM_VERSION} -> ${TARGET_VERSION} with the stack active"
    local resolver="${RELEASE_ROOT}/${TARGET_VERSION}/defenseclaw-upgrade.sh"
    local curl_shim="${SMOKE_HOME}/.upgrade-test-bin"
    local real_curl
    [[ -f "${resolver}" ]] || die "release-owned resolver is missing from the authenticated candidate"
    real_curl="$(install_curl_rewrite_probe "${curl_shim}")"
    if ! HOME="${SMOKE_HOME}" DOCKER_CONFIG="${HOST_DOCKER_CONFIG}" DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
        PYTHONDONTWRITEBYTECODE=1 \
        DEFENSECLAW_UPGRADE_TEST_MODE=1 \
        DEFENSECLAW_UPGRADE_TEST_RELEASE_BASE_URL="${RELEASE_URL}" \
        UPGRADE_GATE_REAL_CURL="${real_curl}" \
        UPGRADE_GATE_RELEASE_URL="${RELEASE_URL}" \
        UPGRADE_GATE_TARGET_VERSION="${TARGET_VERSION}" \
        PATH="${curl_shim}:${SMOKE_HOME}/.local/bin:${PATH}" \
            bash "${resolver}" --yes --version "${TARGET_VERSION}" \
        >"${SMOKE_HOME}/upgrade.log" 2>&1; then
        tail_v8_upgrade_log_secret_safe "${SMOKE_HOME}/upgrade.log"
        die "release-owned live-stack upgrade failed"
    fi
}

prepare_local_candidate_provenance_fixture() {
    [[ "${LOCAL_CANDIDATE_PROVENANCE_FIXTURE}" == "1" ]] || return 0
    local release_dir="${RELEASE_ROOT}/${TARGET_VERSION}"
    local bridge_checksums="${RELEASE_ROOT}/${REQUIRED_BRIDGE_VERSION}/checksums.txt"
    local fixture_bin="${SMOKE_HOME}/.local/bin"
    local verifier_log="${SMOKE_HOME}/continuity-cosign.log"
    local cosign_command real_cosign
    [[ -f "${bridge_checksums}" ]] \
        || die "authenticated bridge checksums are missing from the local release root"
    cosign_command="$(command -v cosign)" \
        || die "cosign is required to authenticate the published bridge"
    real_cosign="$(abs_path "${cosign_command}")" \
        || die "cosign is required to authenticate the published bridge"
    mkdir -p "${fixture_bin}"
    chmod 700 "${fixture_bin}"
    python3 - "${release_dir}" "${bridge_checksums}" "${TARGET_VERSION}" <<'PY'
import hashlib
from pathlib import Path
import stat
import sys

from scripts.release_candidate import (
    RELEASE_PROVENANCE_FILENAME,
    RELEASE_SOURCE_MAP_FILENAME,
    _canonical_json,
    _release_identity_documents,
)

release_dir = Path(sys.argv[1])
bridge_payload = Path(sys.argv[2]).read_bytes()
target_version = sys.argv[3]
target_checksums = (release_dir / "checksums.txt").read_bytes()


def fixture_git_identity(label: bytes, payload: bytes) -> str:
    # Git commit/tree IDs are authenticated by the real release signature in
    # production. The local continuity fixture replaces that one external
    # signature boundary, so deterministic canonical SHA-1-shaped values are
    # sufficient to exercise the closed resolver contract without .git data.
    return hashlib.sha1(label + b"\0" + payload).hexdigest()


source_map, provenance = _release_identity_documents(
    target_version,
    fixture_git_identity(b"source-commit", target_checksums),
    source_tree=fixture_git_identity(b"source-tree", target_checksums),
    bridge_commit=fixture_git_identity(b"bridge-commit", bridge_payload),
    bridge_tree=fixture_git_identity(b"bridge-tree", bridge_payload),
    bridge_checksums_sha256=hashlib.sha256(bridge_payload).hexdigest(),
)
if source_map is None or provenance is None:
    raise SystemExit("continuity candidate did not produce hard-cut provenance")
(release_dir / RELEASE_SOURCE_MAP_FILENAME).write_text(
    _canonical_json(source_map), encoding="utf-8"
)
(release_dir / RELEASE_PROVENANCE_FILENAME).write_text(
    _canonical_json(provenance), encoding="utf-8"
)

excluded = {"checksums.txt", "checksums.txt.pem", "checksums.txt.sig"}
files = []
for path in release_dir.iterdir():
    info = path.lstat()
    if path.name in excluded:
        continue
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise SystemExit(f"continuity release fixture has unsafe member: {path.name}")
    files.append(path)
rows = [
    f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}"
    for path in sorted(files, key=lambda item: item.name)
]
(release_dir / "checksums.txt").write_text("\n".join(rows) + "\n", encoding="utf-8")
PY
    printf '%s\n' 'defenseclaw-continuity-fixture-signature-v1' \
        >"${release_dir}/checksums.txt.sig"
    printf '%s\n' \
        '-----BEGIN CERTIFICATE-----' \
        'ZGVmZW5zZWNsYXctY29udGludWl0eS1maXh0dXJlLWNlcnRpZmljYXRlLXYx' \
        '-----END CERTIFICATE-----' \
        >"${release_dir}/checksums.txt.pem"
    chmod 600 "${release_dir}/checksums.txt.sig" "${release_dir}/checksums.txt.pem"

    # A source-built candidate cannot obtain GitHub's keyless OIDC identity.
    # Model only that external target-signature boundary with a private verifier
    # shim. Published bridge signatures are delegated to the real Cosign binary;
    # all other production resolver checks remain active, including mandatory
    # signature assets, exact workflow identity/issuer arguments, authenticated
    # checksums, protected-artifact digests, and commit-before-mutation ordering.
    # Externally supplied candidates never use this fixture and must carry a
    # real Sigstore signature verified by the real cosign binary.
    python3 - "${fixture_bin}/cosign" "${verifier_log}" "${real_cosign}" <<'PY'
from pathlib import Path
import shlex
import sys

path = Path(sys.argv[1])
log_path = Path(sys.argv[2])
real_cosign = sys.argv[3]
script = f'''#!/usr/bin/env bash
set -euo pipefail
[[ "$#" -eq 10 ]]
[[ "$1" == "verify-blob" ]]
[[ "$2" == "--certificate" ]]
certificate="$3"
[[ "$4" == "--signature" ]]
signature="$5"
[[ "$6" == "--certificate-identity" ]]
[[ "$7" == "https://github.com/cisco-ai-defense/defenseclaw/.github/workflows/release.yaml@refs/heads/main" ]]
[[ "$8" == "--certificate-oidc-issuer" ]]
[[ "$9" == "https://token.actions.githubusercontent.com" ]]
checksums="${{10}}"
if [[ "$(cat "$signature")" != "defenseclaw-continuity-fixture-signature-v1" ]]; then
    exec {shlex.quote(real_cosign)} "$@"
fi
[[ "$(cat "$signature")" == "defenseclaw-continuity-fixture-signature-v1" ]]
grep -Fx -- '-----BEGIN CERTIFICATE-----' "$certificate" >/dev/null
grep -Fx -- '-----END CERTIFICATE-----' "$certificate" >/dev/null
python3 - "$checksums" <<'CHECKSUMS'
from pathlib import Path
import re
import sys

lines = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
if not lines or any(re.fullmatch(r"[0-9a-f]{{64}}  [A-Za-z0-9._-]+", line) is None for line in lines):
    raise SystemExit("continuity checksum fixture is malformed")
CHECKSUMS
printf '%s\\n' 'verified exact release workflow identity and issuer' >> {str(log_path)!r}
'''
path.write_text(script, encoding="utf-8")
path.chmod(0o700)
PY
}

assert_local_candidate_provenance_verified() {
    [[ "${LOCAL_CANDIDATE_PROVENANCE_FIXTURE}" == "1" ]] || return 0
    grep -Fx 'verified exact release workflow identity and issuer' \
        "${SMOKE_HOME}/continuity-cosign.log" >/dev/null \
        || die "release-owned resolver did not invoke the strict local Sigstore boundary fixture"
}

verify_target_activation() {
    HOME="${SMOKE_HOME}" DOCKER_CONFIG="${HOST_DOCKER_CONFIG}" DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
    PATH="${SMOKE_HOME}/.local/bin:${PATH}" \
        defenseclaw --version | grep -F "${TARGET_VERSION}" >/dev/null \
        || die "target CLI version is not active"
    HOME="${SMOKE_HOME}" DOCKER_CONFIG="${HOST_DOCKER_CONFIG}" DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
    PATH="${SMOKE_HOME}/.local/bin:${PATH}" \
        defenseclaw-gateway --version | grep -F "${TARGET_VERSION}" >/dev/null \
        || die "target gateway version is not active"
    HOME="${SMOKE_HOME}" DOCKER_CONFIG="${HOST_DOCKER_CONFIG}" DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
    PATH="${SMOKE_HOME}/.local/bin:${PATH}" \
        defenseclaw setup local-observability status \
        >"${SMOKE_HOME}/local-observability-status.log" 2>&1 \
        || { tail_log "${SMOKE_HOME}/local-observability-status.log"; die "upgraded stack is not ready"; }
    python3 - \
        "${SMOKE_HOME}/.defenseclaw" \
        "${TARGET_VERSION}" \
        "${RELEASE_ROOT}/${TARGET_VERSION}/upgrade-manifest.json" <<'PY'
import json
import os
from pathlib import Path
import stat
import sys

import yaml

data_dir = Path(sys.argv[1])
target = sys.argv[2]
upgrade_manifest_path = Path(sys.argv[3])
config = yaml.safe_load((data_dir / "config.yaml").read_text(encoding="utf-8")) or {}
if config.get("config_version") != 8:
    raise SystemExit("release-owned resolver did not activate config_version 8")
gateway = config.get("gateway") or {}
if gateway.get("fleet_mode") != "disabled" or (gateway.get("watcher") or {}).get("enabled") is not False:
    raise SystemExit("release-owned resolver did not preserve the hermetic gateway policy")
if (config.get("claw") or {}).get("mode") != "" or str((config.get("guardrail") or {}).get("connector") or "").strip():
    raise SystemExit("release-owned resolver did not preserve the explicit no-connector identity")
cursor = json.loads((data_dir / ".migration_state.json").read_text(encoding="utf-8"))
upgrade_manifest = json.loads(upgrade_manifest_path.read_text(encoding="utf-8"))
required = upgrade_manifest.get("required_cli_migrations", [])
if not isinstance(required, list) or not required:
    raise SystemExit("hard-cut candidate has no required CLI migration")
missing = [version for version in required if version not in cursor.get("applied", [])]
if missing:
    raise SystemExit(f"required migration cursor entries are absent: {missing}")
manifest = json.loads(
    (data_dir / "observability-stack/.defenseclaw-bundle-manifest.json").read_text(encoding="utf-8")
)
if manifest.get("bundle_version") != target:
    raise SystemExit("installed local bundle is not target-stamped")
if len(manifest.get("dashboard_uids", [])) != 14:
    raise SystemExit("installed local bundle does not own all fourteen dashboards")
if set(manifest.get("named_volumes", [])) != {
    "grafana-data", "loki-data", "prometheus-data", "tempo-data"
}:
    raise SystemExit("installed local bundle named-volume contract drifted")
if os.name != "nt":
    stack = data_dir / "observability-stack"
    for item in manifest.get("files", []):
        relative = item.get("path")
        expected_mode = item.get("mode")
        if not isinstance(relative, str) or not isinstance(expected_mode, int):
            raise SystemExit("installed local bundle mode manifest is malformed")
        candidate = stack / relative
        actual_mode = stat.S_IMODE(candidate.stat().st_mode)
        if actual_mode != expected_mode:
            raise SystemExit(f"installed local bundle mode drifted for {relative}")
PY
}

assert_published_bridge_binary_sqlite_rollback_compatibility() {
    # This is the concrete rollback-binary compatibility gate for the v8 hard
    # cut. The production controller's injected-failure rollback paths are
    # covered by the protocol tests; here we exercise the state that exists
    # after that rollback has restored config: the authenticated, published
    # 0.8.4 gateway must be able to reopen and use the exact audit.db already
    # migrated additively by the target gateway.
    [[ "${FROM_VERSION}" == "0.8.4" ]] \
        || die "v8 rollback-binary compatibility requires published bridge 0.8.4"
    case "${OS_NAME}" in
        darwin|linux) ;;
        *) die "0.8.4 rollback-binary compatibility is POSIX-only" ;;
    esac

    local target_gateway="${SMOKE_HOME}/.local/bin/defenseclaw-gateway"
    local bridge_gateway="${WORKDIR}/old-gateway/${FROM_VERSION}/defenseclaw"
    # The published 0.8.4 daemon derives a stale-process pgrep pattern from
    # filepath.Base(os.Executable()). Its archived artifact is named only
    # "defenseclaw", so invoking that pathname inside this repository can
    # terminate the release server and harness shells whose argv also contains
    # that broad word. Run the already-authenticated bytes through a private
    # alphanumeric hard-link basename. The embedded code signature and inode
    # remain identical, while the legacy cleanup pattern becomes unique to this
    # one rollback probe. Current binaries have a stronger executable-identity
    # check; this containment exists solely for the immutable bridge.
    local bridge_probe_name="dcb084probe${POST_STAMP}"
    local bridge_probe_dir="${WORKDIR}/rollback-bridge-probe"
    local bridge_probe="${bridge_probe_dir}/${bridge_probe_name}"
    local auth_marker="${WORKDIR}/published-release/${FROM_VERSION}/.authenticated-${OS_NAME}-${ARCH_NAME}"
    local data_dir="${SMOKE_HOME}/.defenseclaw"
    local audit_db="${data_dir}/state/audit.db"
    local v7_config="${SMOKE_HOME}/fixture-evidence/config.v7.source"
    local v8_config="${SMOKE_HOME}/fixture-evidence/config.v8.after-upgrade"
    local bridge_start_log="${SMOKE_HOME}/rollback-bridge-gateway-start.log"
    local bridge_health="${SMOKE_HOME}/fixture-evidence/rollback-bridge-health.json"
    local target_start_log="${SMOKE_HOME}/rollback-target-gateway-restart.log"
    local target_health="${SMOKE_HOME}/fixture-evidence/rollback-target-health.json"
    # ``details`` is governed content and the published bridge correctly
    # redacts it before persistence. Anchor the compatibility probe on the
    # target identifier instead: target is a stable control-plane identity,
    # so both the v7 API projection and SQLite can match it exactly without
    # weakening redaction for this test.
    local probe_target="rollback-binary-compatibility-${POST_STAMP}"

    [[ -f "${auth_marker}" && ! -L "${auth_marker}" ]] \
        || die "published bridge authentication custody marker is absent"
    [[ -x "${bridge_gateway}" && ! -L "${bridge_gateway}" ]] \
        || die "retained authenticated published bridge gateway is absent"
    [[ -x "${target_gateway}" && ! -L "${target_gateway}" ]] \
        || die "active target gateway is absent"
    [[ -f "${v7_config}" && ! -L "${v7_config}" ]] \
        || die "byte-preserved v7 rollback config is absent"
    install -d -m 700 "${bridge_probe_dir}"
    [[ "${bridge_probe_name}" =~ ^[A-Za-z0-9]+$ && "${bridge_probe_name}" != *defenseclaw* ]] \
        || die "rollback bridge probe basename is not process-scan safe"
    ln "${bridge_gateway}" "${bridge_probe}" \
        || die "could not bind authenticated bridge bytes to private rollback probe"
    python3 - "${bridge_gateway}" "${bridge_probe}" <<'PY'
import hashlib
import os
from pathlib import Path
import sys

source = Path(sys.argv[1])
probe = Path(sys.argv[2])
if source.is_symlink() or probe.is_symlink() or not source.is_file() or not probe.is_file():
    raise SystemExit("rollback bridge probe is not a pair of regular files")
source_stat = os.stat(source, follow_symlinks=False)
probe_stat = os.stat(probe, follow_symlinks=False)
if (source_stat.st_dev, source_stat.st_ino) != (probe_stat.st_dev, probe_stat.st_ino):
    raise SystemExit("rollback bridge probe does not share authenticated artifact inode")
if hashlib.sha256(source.read_bytes()).digest() != hashlib.sha256(probe.read_bytes()).digest():
    raise SystemExit("rollback bridge probe bytes differ from authenticated artifact")
PY
    "${bridge_probe}" --version | grep -F "${FROM_VERSION}" >/dev/null \
        || die "retained bridge gateway is not version ${FROM_VERSION}"

    # Prove that the target gateway actually applied the additive v8 database
    # migration before giving the old binary custody of this same file.
    python3 - "${audit_db}" "${probe_target}" <<'PY'
from pathlib import Path
import sqlite3
import sys

database = Path(sys.argv[1])
probe_target = sys.argv[2]
if not database.is_file() or database.is_symlink():
    raise SystemExit("target gateway did not create a regular audit.db")
connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
try:
    if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
        raise SystemExit("v8-migrated audit.db failed quick_check before rollback probe")
    tables = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }
    required = {
        "audit_events",
        "correlation_events",
        "correlation_identifiers",
        "correlation_identity_claims",
        "correlation_observations",
        "correlation_relationships",
        "correlation_relationship_evidence",
        "correlation_cursors",
        "correlation_pending_operations",
        "correlation_receipts",
    }
    if missing := sorted(required - tables):
        raise SystemExit(f"target gateway did not apply correlation migrations: {missing}")
    if connection.execute(
        "SELECT COUNT(*) FROM audit_events WHERE target = ?", (probe_target,)
    ).fetchone() != (0,):
        raise SystemExit("rollback probe marker unexpectedly exists before old binary write")
finally:
    connection.close()
PY

    cp -p "${data_dir}/config.yaml" "${v8_config}"
    stop_smoke_gateway
    cp -p "${v7_config}" "${data_dir}/config.yaml"

    log "Probing published ${FROM_VERSION} rollback binary against the v8-migrated audit.db"
    if ! HOME="${SMOKE_HOME}" DEFENSECLAW_HOME="${data_dir}" \
        OPENCLAW_HOME="${SMOKE_HOME}/.openclaw" \
        PATH="${SMOKE_HOME}/.local/bin:${PATH}" \
            "${bridge_probe}" start >"${bridge_start_log}" 2>&1; then
        tail_log "${bridge_start_log}"
        die "published bridge gateway could not start after v7 config restoration"
    fi

    local attempt
    local bridge_healthy="0"
    for attempt in $(seq 1 120); do
        if curl -fsS --max-time 1 http://127.0.0.1:18970/health \
                >"${bridge_health}" 2>>"${bridge_start_log}" \
            && python3 - "${bridge_health}" "${FROM_VERSION}" <<'PY'
import json
from pathlib import Path
import sys

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
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
            bridge_healthy="1"
            break
        fi
        sleep 0.25
    done
    if [[ "${bridge_healthy}" != "1" ]]; then
        tail_log "${bridge_start_log}"
        die "published bridge gateway did not reach version-bound health on migrated audit.db"
    fi

    # Exercise the old binary's authenticated write and read APIs without ever
    # placing the gateway token in argv, logs, or fixture evidence.
    python3 - "${data_dir}/.env" "${probe_target}" <<'PY'
import json
from pathlib import Path
import sys
import urllib.request

dotenv = Path(sys.argv[1])
probe_target = sys.argv[2]
token = ""
for line in dotenv.read_text(encoding="utf-8").splitlines():
    key, separator, value = line.partition("=")
    if separator and key.strip() in {
        "DEFENSECLAW_GATEWAY_TOKEN",
        "OPENCLAW_GATEWAY_TOKEN",
    }:
        token = value.strip()
        if token:
            break
if not token:
    raise SystemExit("restored bridge gateway token is unavailable")

headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json",
    "X-DefenseClaw-Client": "upgrade-continuity-gate",
}
body = json.dumps(
    {
        "action": "gateway-tool-call",
        "target": probe_target,
        "actor": "release-continuity-gate",
        "details": "published bridge compatibility write",
        "severity": "INFO",
    }
).encode("utf-8")
write = urllib.request.Request(
    "http://127.0.0.1:18970/audit/event",
    data=body,
    headers=headers,
    method="POST",
)
with urllib.request.urlopen(write, timeout=10) as response:
    result = json.load(response)
    if response.status != 200 or result != {"status": "ok"}:
        raise SystemExit("published bridge audit write was not acknowledged")

read = urllib.request.Request(
    "http://127.0.0.1:18970/alerts?limit=500",
    headers=headers,
    method="GET",
)
with urllib.request.urlopen(read, timeout=10) as response:
    events = json.load(response)
if not isinstance(events, list) or not any(
    isinstance(event, dict)
    and event.get("target") == probe_target
    for event in events
):
    raise SystemExit("published bridge could not read back its audit write")
PY

    HOME="${SMOKE_HOME}" DEFENSECLAW_HOME="${data_dir}" \
    PATH="${SMOKE_HOME}/.local/bin:${PATH}" \
        "${bridge_probe}" stop >"${SMOKE_HOME}/rollback-bridge-gateway-stop.log" 2>&1 \
        || { tail_log "${SMOKE_HOME}/rollback-bridge-gateway-stop.log"; die "published bridge gateway did not stop cleanly"; }

    python3 - "${audit_db}" "${probe_target}" "${FROM_VERSION}" <<'PY'
from pathlib import Path
import sqlite3
import sys

database = Path(sys.argv[1])
probe_target = sys.argv[2]
bridge_version = sys.argv[3]
connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
try:
    if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
        raise SystemExit("audit.db failed quick_check after published bridge write")
    row = connection.execute(
        "SELECT COUNT(*), COALESCE(MAX(binary_version), '') "
        "FROM audit_events WHERE target = ?",
        (probe_target,),
    ).fetchone()
    if row != (1, bridge_version):
        raise SystemExit(f"published bridge write provenance mismatch: {row!r}")
    tables = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }
    if "correlation_identity_claims" not in tables or "correlation_receipts" not in tables:
        raise SystemExit("published bridge damaged additive correlation tables")
finally:
    connection.close()
PY

    # Restore the target state and prove that both the v8 config and target
    # gateway remain healthy after the old binary has used the migrated DB.
    cp -p "${v8_config}" "${data_dir}/config.yaml"
    if ! HOME="${SMOKE_HOME}" DEFENSECLAW_HOME="${data_dir}" \
        OPENCLAW_HOME="${SMOKE_HOME}/.openclaw" \
        PATH="${SMOKE_HOME}/.local/bin:${PATH}" \
            "${target_gateway}" start >"${target_start_log}" 2>&1; then
        tail_log "${target_start_log}"
        die "target gateway did not restart after bridge rollback-binary probe"
    fi
    local target_healthy="0"
    for attempt in $(seq 1 120); do
        if curl -fsS --max-time 1 http://127.0.0.1:18970/health \
                >"${target_health}" 2>>"${target_start_log}" \
            && python3 - "${target_health}" "${TARGET_VERSION}" <<'PY'
import json
from pathlib import Path
import sys

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
provenance = payload.get("provenance") if isinstance(payload, dict) else None
if not isinstance(provenance, dict) or provenance.get("binary_version") != sys.argv[2]:
    raise SystemExit(1)
PY
        then
            target_healthy="1"
            break
        fi
        sleep 0.25
    done
    if [[ "${target_healthy}" != "1" ]]; then
        tail_log "${target_start_log}"
        die "target gateway did not become version-bound healthy after rollback-binary probe"
    fi

    ok "Published ${FROM_VERSION} gateway passed health/read/write compatibility on target-migrated audit.db"
}

resolve_continuity_upgrade_contract() {
    local manifest="${RELEASE_ROOT}/${TARGET_VERSION}/upgrade-manifest.json"
    local required_bridge
    required_bridge="$(python3 - "${manifest}" "${TARGET_VERSION}" <<'PY'
import json
import re
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
target = sys.argv[2]
if payload.get("release_version") != target:
    raise SystemExit("candidate manifest release_version mismatch")
if payload.get("min_upgrade_protocol", 1) < 2:
    raise SystemExit("E2E-9 requires a hard-cut protocol manifest")
bridge = payload.get("required_bridge_version")
minimum = payload.get("minimum_source_version")
if not isinstance(bridge, str) or not re.fullmatch(r"\d+\.\d+\.\d+", bridge):
    raise SystemExit("candidate manifest has no canonical required_bridge_version")
if minimum != bridge:
    raise SystemExit("candidate manifest bridge/minimum-source contract drifted")
required = payload.get("required_cli_migrations")
if not isinstance(required, list) or not required:
    raise SystemExit("hard-cut candidate has no required CLI migration")
print(bridge)
PY
    )" || die "candidate is not a valid manifest-driven v8 hard cut"

    if [[ "${FROM_VERSION_EXPLICIT}" == "0" ]]; then
        FROM_VERSION="${required_bridge}"
        FROM_VERSIONS="${required_bridge}"
    elif [[ "${FROM_VERSION}" != "${required_bridge}" ]]; then
        die "E2E-9 continuity must start at manifest-required bridge ${required_bridge}, got ${FROM_VERSION}"
    fi
    REQUIRED_BRIDGE_VERSION="${required_bridge}"
}

run_continuity_verifier() {
    log "Verifying pre/post history and all dashboard queries"
    .venv/bin/python - <<'PY'
from pathlib import Path
import shutil

source = Path("bundles/local_observability_stack")
packaged = Path("cli/defenseclaw/_data/local_observability_stack")
if packaged.exists():
    shutil.rmtree(packaged)
packaged.parent.mkdir(parents=True, exist_ok=True)
shutil.copytree(source, packaged)
PY
    .venv/bin/python scripts/check_observability_v8_upgrade_continuity.py \
        --pre-stamp "${PRE_STAMP}" \
        --post-stamp "${POST_STAMP}" \
        --metric-cutover-seconds "${METRIC_CUTOVER_SECONDS}" \
        --lookback-hours 2 \
        --wait-seconds 90 \
        --dashboard-deadline-seconds 300 \
        >"${SMOKE_HOME}/continuity-report.json" 2>&1 \
        || { tail_log "${SMOKE_HOME}/continuity-report.json"; die "history/dashboard continuity failed"; }
}

main_continuity() {
    parse_continuity_args "$@"
    cd "${ROOT}"
    if [[ -z "${TARGET_VERSION}" ]]; then
        TARGET_VERSION="$(current_version)"
    fi
    [[ "${TARGET_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
        || die "invalid target version: ${TARGET_VERSION}"
    [[ "${HEALTH_TIMEOUT}" =~ ^[1-9][0-9]*$ ]] \
        || die "--health-timeout must be a positive integer"
    [[ -z "${RELEASE_ROOT}" || -z "${RELEASE_DIR}" ]] \
        || die "use only one of --release-root or --release-dir"
    if [[ -z "${RELEASE_ROOT}" && -z "${RELEASE_DIR}" ]]; then
        [[ "$(current_version)" == "${TARGET_VERSION}" ]] \
            || die "build checkout is not stamped ${TARGET_VERSION}; provide --release-root/--release-dir"
    fi
    detect_platform
    require_private_stack_boundary

    WORKDIR="$(abs_path "$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-upgrade-continuity.XXXXXX")")"
    SMOKE_HOME="${WORKDIR}/home"
    mkdir -p "${SMOKE_HOME}"
    PRE_STAMP="$(python3 -c 'import time; print(time.time_ns())')"
    POST_STAMP="$((PRE_STAMP + 1))"
    trap continuity_cleanup EXIT

    if [[ -z "${RELEASE_ROOT}" && -z "${RELEASE_DIR}" ]]; then
        LOCAL_CANDIDATE_PROVENANCE_FIXTURE="1"
    fi
    prepare_release_root
    assert_candidate_assets
    resolve_continuity_upgrade_contract
    prepare_required_bridge_assets
    prepare_local_candidate_provenance_fixture
    assert_candidate_assets
    [[ "${FROM_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
        || die "invalid baseline version: ${FROM_VERSION}"
    start_release_server
    run_v8_source_contract_tests

    install_baseline
    write_initial_v7_config
    normalize_baseline_stack_access
    start_baseline_stack
    write_continuity_v7_config
    patch_installed_upgrade_endpoint
    volume_inventory >"${WORKDIR}/volumes.before"
    assert_four_history_volumes "${WORKDIR}/volumes.before"

    emit_continuity_phase pre "${PRE_STAMP}"
    wait_for_pre_upgrade_metrics "${PRE_STAMP}"
    METRIC_CUTOVER_SECONDS="$(python3 -c 'import time; print(time.time())')"
    run_live_upgrade
    assert_local_candidate_provenance_verified
    verify_target_activation
    assert_published_bridge_binary_sqlite_rollback_compatibility
    volume_inventory >"${WORKDIR}/volumes.after"
    assert_four_history_volumes "${WORKDIR}/volumes.after"
    cmp "${WORKDIR}/volumes.before" "${WORKDIR}/volumes.after" >/dev/null \
        || die "release-owned resolver replaced the local observability history volumes"

    emit_continuity_phase post "${POST_STAMP}"
    run_continuity_verifier
    ok "E2E-9 passed: real ${FROM_VERSION} → ${TARGET_VERSION} hard-cut upgrade retained all four history volumes"
    ok "Pre/post continuity report: ${SMOKE_HOME}/continuity-report.json"
}

main_continuity "$@"
