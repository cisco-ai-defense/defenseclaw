#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# Fast, test-only activation canary for an unsigned exact-SHA candidate.
#
# Ordinary PRs cannot mint the release workflow's Fulcio identity. This
# harness therefore does not call an installed updater or the release-owned
# resolver. It authenticates a published baseline, creates a throwaway HOME,
# checksum-binds and materializes the local candidate bytes, installs them
# directly, then runs the target migration and exact-version health checks in
# fresh processes. Production resolver/provenance, bridge handoff, receipts,
# rollback/recovery, and Docker continuity remain signed certification gates.

set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck source=scripts/test-upgrade-release.sh
source "${ROOT}/scripts/test-upgrade-release.sh"

developer_usage() {
    cat <<'EOF'
Usage: scripts/test-developer-target-activation.sh [options]

Required:
  --release-root DIR         Unsigned exact-SHA candidate root containing VERSION/
  --baseline-mode seed       Authenticate and seed the published baseline in a temp HOME

Common options are inherited from test-upgrade-release.sh, including:
  --from-version VERSION
  --from-versions LIST
  --target-version VERSION
  --baseline-dependencies target|published
  --health-timeout SECONDS
  --keep-workdir

This is a developer validation harness, not an operator upgrade path. It never
changes the caller's HOME and cannot establish signed release provenance.
EOF
}

sanitize_developer_activation_environment() {
    local variable
    while IFS= read -r variable; do
        case "${variable}" in
            DEFENSECLAW_*|OPENCLAW_HOME|DOCKER_HOST|PYTHONHOME|PYTHONPATH|VIRTUAL_ENV)
                unset "${variable}"
                ;;
        esac
    done < <(compgen -e)
}

select_private_api_port() {
    python3 - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
    listener.bind(("127.0.0.1", 0))
    print(listener.getsockname()[1])
PY
}

isolate_fixture_gateway_port() {
    local port="$1"
    python3 - \
        "${SMOKE_HOME}/.defenseclaw/config.yaml" \
        "${SMOKE_HOME}/fixture-evidence/config.historical.source" \
        "${port}" <<'PY'
import os
from pathlib import Path
import sys
import tempfile

config_path = Path(sys.argv[1])
evidence_path = Path(sys.argv[2])
port = int(sys.argv[3])
if not 1024 <= port <= 65535:
    raise SystemExit("developer fixture API port is outside the unprivileged range")
source = config_path.read_text(encoding="utf-8")
needle = "gateway:\n  fleet_mode: disabled\n"
replacement = (
    "gateway:\n"
    "  api_bind: 127.0.0.1\n"
    f"  api_port: {port}\n"
    "  fleet_mode: disabled\n"
)
if source.count(needle) != 1:
    raise SystemExit("developer fixture gateway block changed unexpectedly")
updated = source.replace(needle, replacement, 1)

for path in (config_path, evidence_path):
    descriptor, staged_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    staged = Path(staged_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            stream.write(updated)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(staged, path)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        staged.unlink(missing_ok=True)
        raise
PY
}

resolve_developer_candidate_contract() {
    local selected
    selected="$(python3 - \
        "${RELEASE_ROOT}/${TARGET_VERSION}/upgrade-manifest.json" \
        "${OS_NAME}" "${ARCH_NAME}" <<'PY'
import json
import sys

path, os_name, arch = sys.argv[1:]
with open(path, encoding="utf-8") as stream:
    manifest = json.load(stream)
print(manifest.get("schema_version", ""))
print((manifest.get("release_artifacts") or {}).get("gateways", {}).get(os_name, {}).get(arch, ""))
PY
)" || die "could not resolve the developer candidate contract"
    CANDIDATE_SCHEMA_VERSION="$(printf '%s\n' "${selected}" | sed -n '1p')"
    CANDIDATE_GATEWAY_NAME="$(printf '%s\n' "${selected}" | sed -n '2p')"
    [[ -n "${CANDIDATE_GATEWAY_NAME}" ]] \
        || die "candidate manifest does not select a gateway for ${OS_NAME}/${ARCH_NAME}"
}

materialize_candidate_gateway() {
    local archive="$1"
    local destination="$2"
    python3 - "${archive}" "${destination}" <<'PY'
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile

archive = Path(sys.argv[1])
destination = Path(sys.argv[2])
maximum = 512 * 1024 * 1024

with tarfile.open(archive, mode="r:gz") as bundle:
    members = [
        member
        for member in bundle.getmembers()
        if Path(member.name.replace("\\", "/")).name == "defenseclaw"
    ]
    if len(members) != 1 or not members[0].isfile():
        raise SystemExit("candidate gateway archive must contain one regular runtime")
    source = bundle.extractfile(members[0])
    if source is None:
        raise SystemExit("candidate gateway runtime could not be opened")
    descriptor, staged_name = tempfile.mkstemp(prefix=".candidate-gateway-", dir=destination.parent)
    staged = Path(staged_name)
    total = 0
    try:
        os.fchmod(descriptor, 0o700)
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise RuntimeError("candidate gateway runtime exceeds the 512 MiB bound")
            view = memoryview(chunk)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise RuntimeError("candidate gateway write failed")
                view = view[written:]
        if total == 0:
            raise RuntimeError("candidate gateway runtime is empty")
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        staged.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)
    os.replace(staged, destination)

info = destination.lstat()
if destination.is_symlink() or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
    raise SystemExit("installed candidate gateway lost its regular-file custody")
PY
}

run_developer_direct_activation() {
    log "Running isolated target activation ${FROM_VERSION} -> ${TARGET_VERSION}"
    prepare_isolated_docker_path

    local data_dir="${SMOKE_HOME}/.defenseclaw"
    local install_dir="${SMOKE_HOME}/.local/bin"
    local venv_python="${data_dir}/.venv/bin/python"
    local release_dir="${RELEASE_ROOT}/${TARGET_VERSION}"
    local custody="${SMOKE_HOME}/.developer-candidate-custody"
    local candidate_wheel="${custody}/${CANDIDATE_WHEEL_NAME%.dcwheel}.whl"
    local candidate_gateway_archive="${custody}/${CANDIDATE_GATEWAY_NAME%.dcgateway}.tar.gz"
    local candidate_gateway="${custody}/defenseclaw-gateway"
    local log_file="${SMOKE_HOME}/upgrade.log"

    mkdir -p "${custody}"
    chmod 700 "${custody}"
    : >"${log_file}"
    chmod 600 "${log_file}"

    release_test_artifact_path \
        "${release_dir}/${CANDIDATE_WHEEL_NAME}" \
        "${release_dir}/checksums.txt" \
        "${candidate_wheel}" >/dev/null \
        || die "could not materialize checksum-bound candidate wheel"
    release_test_artifact_path \
        "${release_dir}/${CANDIDATE_GATEWAY_NAME}" \
        "${release_dir}/checksums.txt" \
        "${candidate_gateway_archive}" >/dev/null \
        || die "could not materialize checksum-bound candidate gateway"
    materialize_candidate_gateway "${candidate_gateway_archive}" "${candidate_gateway}"

    # A caller may request a source-health canary. Stop only the gateway inside
    # this throwaway HOME before the target migration enforces quiescence.
    HOME="${SMOKE_HOME}" \
    DEFENSECLAW_HOME="${data_dir}" \
    OPENCLAW_HOME="${SMOKE_HOME}/.openclaw" \
    PATH="${install_dir}:${PATH}" \
        "${install_dir}/defenseclaw-gateway" stop >>"${log_file}" 2>&1 || true

    local -a install_args=(
        --no-config pip install
        --python "${venv_python}"
        --quiet
        --reinstall
    )
    if [[ "${BASELINE_DEPENDENCIES}" == "target" ]]; then
        install_args+=(--offline --no-deps)
    fi
    "$(command -v uv)" "${install_args[@]}" "${candidate_wheel}" \
        >>"${log_file}" 2>&1 \
        || { tail_v8_upgrade_log_secret_safe "${log_file}"; die "candidate wheel install failed"; }

    cp "${candidate_gateway}" "${install_dir}/.defenseclaw-gateway.developer-candidate"
    chmod 700 "${install_dir}/.defenseclaw-gateway.developer-candidate"
    mv -f \
        "${install_dir}/.defenseclaw-gateway.developer-candidate" \
        "${install_dir}/defenseclaw-gateway"
    ln -sf "${venv_python%/python}/defenseclaw" "${install_dir}/defenseclaw"

    # This is the target-owned migration entry point used after controller
    # handoff, but run in a clean interpreter without claiming controller,
    # provenance, receipt, or rollback success. Bundle continuity is excluded
    # here because it belongs to full signed certification.
    if ! HOME="${SMOKE_HOME}" \
        DEFENSECLAW_HOME="${data_dir}" \
        DEFENSECLAW_CONFIG="${data_dir}/config.yaml" \
        OPENCLAW_HOME="${SMOKE_HOME}/.openclaw" \
        PYTHONDONTWRITEBYTECODE=1 \
        DOCKER_HOST="${UPGRADE_SMOKE_DOCKER_HOST:-unix://${SMOKE_HOME}/no-docker.sock}" \
        PATH="${SMOKE_HOME}/.upgrade-test-bin:${install_dir}:${PATH}" \
            "${venv_python}" -I - \
                "${FROM_VERSION}" "${TARGET_VERSION}" \
                "${SMOKE_HOME}/.openclaw" "${data_dir}" \
                >>"${log_file}" 2>&1 <<'PY'
import sys

from defenseclaw.migrations import run_migrations

count = run_migrations(
    sys.argv[1],
    sys.argv[2],
    sys.argv[3],
    sys.argv[4],
    upgrade_handles_local_bundle=True,
)
print(f"developer_target_migrations={count}")
PY
    then
        tail_v8_upgrade_log_secret_safe "${log_file}"
        die "fresh target migration process failed"
    fi

    if ! HOME="${SMOKE_HOME}" \
        DEFENSECLAW_HOME="${data_dir}" \
        DEFENSECLAW_CONFIG="${data_dir}/config.yaml" \
        DEFENSECLAW_SIDECAR_DIAG=1 \
        OPENCLAW_HOME="${SMOKE_HOME}/.openclaw" \
        PATH="${install_dir}:${PATH}" \
            "${install_dir}/defenseclaw-gateway" start >>"${log_file}" 2>&1; then
        tail_v8_upgrade_log_secret_safe "${data_dir}/gateway.log"
        tail_v8_upgrade_log_secret_safe "${log_file}"
        die "fresh target gateway failed to start"
    fi

    if ! HOME="${SMOKE_HOME}" \
        DEFENSECLAW_HOME="${data_dir}" \
        DEFENSECLAW_CONFIG="${data_dir}/config.yaml" \
        OPENCLAW_HOME="${SMOKE_HOME}/.openclaw" \
        PYTHONDONTWRITEBYTECODE=1 \
        PATH="${install_dir}:${PATH}" \
            "${venv_python}" -I - \
                "${data_dir}" "${HEALTH_TIMEOUT}" "${TARGET_VERSION}" \
                >>"${log_file}" 2>&1 <<'PY'
import sys

from defenseclaw import config as config_module
from defenseclaw.commands.cmd_upgrade import _poll_health

config_module._load_dotenv_into_os(sys.argv[1])
configuration = config_module.load()
_poll_health(configuration, int(sys.argv[2]), expected_version=sys.argv[3])
print("developer_fresh_process_health=ok")
PY
    then
        tail_v8_upgrade_log_secret_safe "${data_dir}/gateway.log"
        tail_v8_upgrade_log_secret_safe "${log_file}"
        die "fresh target exact-version health check failed"
    fi
}

verify_developer_direct_activation() {
    log "Verifying isolated target migration and runtime"
    local data_dir="${SMOKE_HOME}/.defenseclaw"
    local install_dir="${SMOKE_HOME}/.local/bin"
    local venv_python="${data_dir}/.venv/bin/python"
    local release_dir="${RELEASE_ROOT}/${TARGET_VERSION}"

    local cli_version gateway_version
    cli_version="$(HOME="${SMOKE_HOME}" DEFENSECLAW_HOME="${data_dir}" \
        PATH="${install_dir}:${PATH}" defenseclaw --version)" \
        || die "developer candidate CLI version command failed"
    assert_exact_reported_version "developer candidate CLI" "${TARGET_VERSION}" "${cli_version}"
    gateway_version="$(HOME="${SMOKE_HOME}" DEFENSECLAW_HOME="${data_dir}" \
        PATH="${install_dir}:${PATH}" defenseclaw-gateway --version)" \
        || die "developer candidate gateway version command failed"
    assert_exact_reported_version \
        "developer candidate gateway" "${TARGET_VERSION}" "${gateway_version}"

    "${venv_python}" -I - \
        "${data_dir}" \
        "${SMOKE_HOME}/fixture-evidence" \
        "${SMOKE_HOME}/upgrade.log" \
        "${release_dir}/upgrade-manifest.json" \
        "${TARGET_VERSION}" \
        "${FROM_CONFIG_VERSION}" \
        "${DEVELOPER_API_PORT}" <<'PY'
import hashlib
import json
from pathlib import Path
import sqlite3
import stat
import sys

from dotenv import dotenv_values
import yaml

data_dir = Path(sys.argv[1])
evidence_dir = Path(sys.argv[2])
activation_log = Path(sys.argv[3])
manifest_path = Path(sys.argv[4])
target_version = sys.argv[5]
source_config_version = int(sys.argv[6])
developer_api_port = int(sys.argv[7])
if source_config_version > 8:
    raise SystemExit(f"no reviewed developer verifier exists for config-v{source_config_version}")
legacy_source = source_config_version < 8

manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
if manifest.get("release_version") != target_version:
    raise SystemExit("candidate manifest release version does not match the requested target")
cursor = json.loads((data_dir / ".migration_state.json").read_text(encoding="utf-8"))
applied = set(cursor.get("applied", []))
required = {
    item for item in manifest.get("required_cli_migrations", []) if isinstance(item, str)
}
missing = sorted(required - applied)
if missing:
    raise SystemExit(f"developer target activation missed required migrations: {missing}")
if "0.8.5" not in applied:
    raise SystemExit("observability-v8 migration is absent from the cursor")

config_path = data_dir / "config.yaml"
config_text = config_path.read_text(encoding="utf-8")
config = yaml.safe_load(config_text) or {}
if config.get("config_version") != 8:
    raise SystemExit(f"config_version={config.get('config_version')!r}; want 8")
for legacy in ("otel", "audit_sinks", "privacy"):
    if legacy in config:
        raise SystemExit(f"legacy block remains after target activation: {legacy}")
if (config.get("ai_discovery") or {}).get("emit_otel") is not None:
    raise SystemExit("legacy ai_discovery.emit_otel remains after target activation")
gateway = config.get("gateway") or {}
if gateway.get("api_bind") != "127.0.0.1" or gateway.get("api_port") != developer_api_port:
    raise SystemExit("developer target gateway escaped its private API endpoint")
openclaw_home = data_dir.parent / ".openclaw"
try:
    openclaw_info = openclaw_home.lstat()
except FileNotFoundError:
    raise SystemExit("developer fixture OpenClaw home disappeared across target activation") from None
if not stat.S_ISDIR(openclaw_info.st_mode) or stat.S_IMODE(openclaw_info.st_mode) != 0o700:
    raise SystemExit("developer fixture OpenClaw home mode changed across target activation")

destinations = {
    item.get("name"): item
    for item in (config.get("observability") or {}).get("destinations", [])
    if isinstance(item, dict) and isinstance(item.get("name"), str)
}
required_destinations = (
    {
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
    if legacy_source
    else {"existing-otlp", "v8-http-protected"}
)
missing_destinations = sorted(required_destinations - destinations.keys())
if missing_destinations:
    raise SystemExit(f"target migration lost destinations: {missing_destinations}")

if not legacy_source:
    native_otlp = destinations["existing-otlp"]
    if (
        native_otlp.get("kind") != "otlp"
        or native_otlp.get("enabled") is not False
        or native_otlp.get("headers")
        != {"Authorization": {"env": "DEFENSECLAW_V8_FIXTURE_OTLP_AUTHORIZATION"}}
    ):
        raise SystemExit("native-v8 OTLP destination changed across target activation")
    native_http = destinations["v8-http-protected"]
    if (
        native_http.get("kind") != "http_jsonl"
        or native_http.get("enabled") is not False
        or native_http.get("bearer_env") != "DEFENSECLAW_V8_FIXTURE_HTTP_BEARER"
    ):
        raise SystemExit("native-v8 HTTP destination changed across target activation")

expected_environment = (
    {
        "PRESERVE_UPGRADE_SMOKE_ENV": "preserved",
        "DEFENSECLAW_MIGRATED_LOCAL_OBSERVABILITY_X_FLAT_PROTECTED":
            "upgrade-smoke-flat-protected-value",
        "DEFENSECLAW_MIGRATED_SPLUNK_PROTECTED_TOKEN":
            "upgrade-smoke-splunk-protected-value",
        "DEFENSECLAW_MIGRATED_HTTP_PROTECTED_BEARER":
            "upgrade-smoke-http-protected-value",
        "DEFENSECLAW_MIGRATED_AUDIT_OTLP_AUTHORIZATION":
            "Bearer upgrade-smoke-otlp-protected-value",
    }
    if legacy_source
    else {
        "PRESERVE_UPGRADE_SMOKE_ENV": "preserved",
        "DEFENSECLAW_V8_FIXTURE_OTLP_AUTHORIZATION":
            "Bearer upgrade-smoke-v8-otlp-value",
        "DEFENSECLAW_V8_FIXTURE_HTTP_BEARER": "upgrade-smoke-v8-http-value",
    }
)
if not legacy_source:
    historical_environment = dotenv_values(
        evidence_dir / "environment.historical.source"
    )
    gateway_token = historical_environment.get("DEFENSECLAW_GATEWAY_TOKEN")
    if (
        not isinstance(gateway_token, str)
        or len(gateway_token) != 64
        or any(character not in "0123456789abcdef" for character in gateway_token)
    ):
        raise SystemExit("native-v8 fixture has no canonical generated gateway token")
    expected_environment["DEFENSECLAW_GATEWAY_TOKEN"] = gateway_token
actual_environment = dotenv_values(data_dir / ".env")
for name, value in expected_environment.items():
    if actual_environment.get(name) != value:
        raise SystemExit(f"protected environment promotion mismatch for {name}")
if stat.S_IMODE((data_dir / ".env").stat().st_mode) != 0o600:
    raise SystemExit("target .env is not mode 0600")
protected_values = tuple(
    value for name, value in expected_environment.items() if name != "PRESERVE_UPGRADE_SMOKE_ENV"
)
log_text = activation_log.read_text(encoding="utf-8", errors="replace")
if any(value in config_text or value in log_text for value in protected_values):
    raise SystemExit("protected fixture value escaped into v8 YAML or activation output")

historical = yaml.safe_load(
    (evidence_dir / "config.historical.source").read_text(encoding="utf-8")
) or {}
if historical.get("config_version") != source_config_version:
    raise SystemExit("developer fixture does not match its reviewed baseline config family")

activation_manifests = sorted((data_dir / "backups").glob("observability-v8-*/manifest.json"))
if legacy_source:
    if len(activation_manifests) != 1:
        raise SystemExit("target migration did not retain exactly one activation recovery manifest")
    activation_manifest = json.loads(activation_manifests[0].read_text(encoding="utf-8"))
    activation_dir = activation_manifests[0].parent
    source_config = activation_dir / "config.source"
    source_environment = activation_dir / "environment.source"
    by_role = {item["role"]: item for item in activation_manifest.get("files", [])}
    if by_role.get("config", {}).get("sha256") != hashlib.sha256(
        source_config.read_bytes()
    ).hexdigest():
        raise SystemExit("target activation config recovery digest mismatch")
    if by_role.get("environment", {}).get("sha256") != hashlib.sha256(
        source_environment.read_bytes()
    ).hexdigest():
        raise SystemExit("target activation environment recovery digest mismatch")
else:
    if activation_manifests:
        raise SystemExit("native-v8 source unexpectedly ran the v7-to-v8 activation")
    if config_path.read_bytes() != (evidence_dir / "config.historical.source").read_bytes():
        raise SystemExit("native-v8 config bytes changed without a target migration")
    if (data_dir / ".env").read_bytes() != (
        evidence_dir / "environment.historical.source"
    ).read_bytes():
        raise SystemExit("native-v8 environment bytes changed without a target migration")

receipt_root = data_dir / ".upgrade-receipts"
if receipt_root.exists() and any(receipt_root.glob("*.json")):
    raise SystemExit("developer direct activation must not claim a production upgrade receipt")

database = data_dir / "state/audit-custom.db"
if not database.is_file():
    raise SystemExit("fresh target gateway did not initialize the configured SQLite database")
connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
try:
    if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
        raise SystemExit("configured SQLite database failed quick_check")
    tables = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    required_tables = {
        "correlation_events",
        "correlation_identifiers",
        "correlation_observations",
        "correlation_relationships",
        "correlation_receipts",
    }
    if not required_tables.issubset(tables):
        raise SystemExit(
            "fresh target SQLite database lacks correlation tables: "
            + ", ".join(sorted(required_tables - tables))
        )
finally:
    connection.close()

for comment in (
    "# ┌──── OBSERVABILITY UPGRADE SMOKE ────┐",
    "# comments, order, and unrelated settings must survive",
    "# unrelated section survives",
):
    if comment not in config_text:
        raise SystemExit(f"comment-heavy YAML token was lost: {comment}")

print("developer_target_migration=ok")
print("developer_target_recovery_digest=" + ("ok" if legacy_source else "not_applicable"))
print("developer_target_native_v8_continuity=" + ("not_applicable" if legacy_source else "ok"))
print("developer_target_sqlite_correlation=ok")
print("developer_production_receipt=absent")
PY

    local gateway_status_log="${SMOKE_HOME}/gateway-status.log"
    if ! HOME="${SMOKE_HOME}" DEFENSECLAW_HOME="${data_dir}" PATH="${install_dir}:${PATH}" \
        defenseclaw-gateway status >"${gateway_status_log}" 2>&1; then
        tail_log "${gateway_status_log}"
        die "developer candidate gateway is not healthy"
    fi
    ok "Isolated target migration and fresh-process health passed"
}

run_one_developer_activation() {
    FROM_VERSION="$1"
    local home_name="${FROM_VERSION//[^A-Za-z0-9._-]/_}"
    SMOKE_HOME="${WORKDIR}/developer-home-${home_name}"
    mkdir -p "${SMOKE_HOME}"
    case "$(abs_path "${SMOKE_HOME}")" in
        "${WORKDIR}"/*) ;;
        *) die "developer activation HOME escaped its private workdir" ;;
    esac

    install_baseline
    seed_upgrade_fixture
    DEVELOPER_API_PORT="$(select_private_api_port)"
    isolate_fixture_gateway_port "${DEVELOPER_API_PORT}"
    run_developer_direct_activation
    verify_developer_direct_activation
    stop_smoke_gateway

    ok "Developer target activation passed: ${FROM_VERSION} -> ${TARGET_VERSION} (${OS_NAME}/${ARCH_NAME})"
}

main_developer_activation() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        developer_usage
        return
    fi
    sanitize_developer_activation_environment
    parse_args "$@"
    cd "${ROOT}"
    if [[ -z "${TARGET_VERSION}" ]]; then
        TARGET_VERSION="$(current_version)"
    fi
    [[ -n "${RELEASE_ROOT}" ]] \
        || die "developer target activation requires --release-root"
    [[ -z "${RELEASE_DIR}" ]] \
        || die "developer target activation accepts --release-root, not --release-dir"
    [[ "${BASELINE_MODE}" == "seed" ]] \
        || die "developer target activation requires --baseline-mode seed"
    [[ "${PREPARE_ONLY}" == "0" ]] \
        || die "developer target activation cannot prepare a candidate"
    [[ "${START_SOURCE_GATEWAY}" == "0" ]] \
        || die "source gateway execution belongs to signed certification"

    validate_inputs
    detect_platform
    WORKDIR="$(abs_path "$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-developer-activation.XXXXXX")")"
    prepare_release_root
    assert_candidate_assets
    resolve_developer_candidate_contract
    [[ "${CANDIDATE_SCHEMA_VERSION}" == "2" ]] \
        || die "developer target activation requires a schema-2 candidate"
    local release_dir="${RELEASE_ROOT}/${TARGET_VERSION}"
    if [[ -e "${release_dir}/checksums.txt.sig" || -L "${release_dir}/checksums.txt.sig" \
        || -e "${release_dir}/checksums.txt.pem" || -L "${release_dir}/checksums.txt.pem" ]]; then
        die "signed or partially signed candidates must use the production protocol certification harness"
    fi

    local version
    for version in "${FROM_VERSION_LIST[@]}"; do
        run_one_developer_activation "${version}"
    done
    ok "Developer activation matrix passed for ${#FROM_VERSION_LIST[@]} baseline(s)"
    ok "No production resolver, provenance, bridge, receipt, or rollback success was claimed"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main_developer_activation "$@"
fi
