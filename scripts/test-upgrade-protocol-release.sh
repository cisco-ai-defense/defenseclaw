#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# Manifest-derived release gate. Capable published controllers must complete
# the ordinary upgrade smoke. Older controllers and the candidate-owned updater
# must reject an unsupported source before stop, backup, receipt, config, or
# artifact mutation.

set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck source=scripts/test-upgrade-release.sh
source "${ROOT}/scripts/test-upgrade-release.sh"
trap - EXIT

REFUSAL_SENTINEL_PIDS=()

protocol_cleanup() {
    local status=$?
    local pid
    if [[ "${REFUSAL_SENTINEL_PIDS[0]+set}" == "set" ]]; then
        for pid in "${REFUSAL_SENTINEL_PIDS[@]}"; do
            kill "${pid}" >/dev/null 2>&1 || true
            wait "${pid}" >/dev/null 2>&1 || true
        done
    fi
    if [[ -n "${SERVER_PID:-}" ]]; then
        kill "${SERVER_PID}" >/dev/null 2>&1 || true
        wait "${SERVER_PID}" >/dev/null 2>&1 || true
    fi
    if [[ "${KEEP_WORKDIR:-0}" != "1" && -n "${WORKDIR:-}" && -d "${WORKDIR}" ]]; then
        chmod -R u+w "${WORKDIR}" 2>/dev/null || true
        rm -rf "${WORKDIR}"
    elif [[ -n "${WORKDIR:-}" ]]; then
        warn "Kept protocol gate workdir: ${WORKDIR}"
    fi
    return "${status}"
}

manifest_value() {
    local key="$1"
    local default_value="$2"
    python3 - "${RELEASE_ROOT}/${TARGET_VERSION}/upgrade-manifest.json" "${key}" "${default_value}" <<'PY'
import json
import sys

path, key, default = sys.argv[1:]
with open(path, encoding="utf-8") as handle:
    value = json.load(handle).get(key, default)
if isinstance(value, bool) or not isinstance(value, (str, int)):
    raise SystemExit(f"manifest field {key} must be a string or integer")
print(value)
PY
}

manifest_array_values() {
    local key="$1"
    python3 - "${RELEASE_ROOT}/${TARGET_VERSION}/upgrade-manifest.json" "${key}" <<'PY'
import json
import re
import sys

path, key = sys.argv[1:]
with open(path, encoding="utf-8") as handle:
    values = json.load(handle).get(key, [])
if not isinstance(values, list):
    raise SystemExit(f"manifest field {key} must be an array")
seen = set()
for value in values:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value):
        raise SystemExit(f"manifest field {key} contains a non-canonical version")
    if value in seen:
        raise SystemExit(f"manifest field {key} contains a duplicate version")
    seen.add(value)
    print(value)
PY
}

manifest_array_contains() {
    local key="$1"
    local expected="$2"
    manifest_array_values "${key}" | grep -Fxq "${expected}"
}

prepare_required_bridge_assets() {
    [[ -n "${REQUIRED_BRIDGE_VERSION}" ]] || return 0
    [[ "${REQUIRED_BRIDGE_VERSION}" != "${TARGET_VERSION}" ]] || return 0

    local bridge_dir="${RELEASE_ROOT}/${REQUIRED_BRIDGE_VERSION}"
    local previous_from="${FROM_VERSION}"
    local asset
    mkdir -p "${bridge_dir}"
    FROM_VERSION="${REQUIRED_BRIDGE_VERSION}"
    for asset in \
        "defenseclaw-${REQUIRED_BRIDGE_VERSION}-py3-none-any.whl" \
        "defenseclaw_${REQUIRED_BRIDGE_VERSION}_${OS_NAME}_${ARCH_NAME}.tar.gz" \
        checksums.txt \
        checksums.txt.sig \
        checksums.txt.pem \
        upgrade-manifest.json; do
        download_old_asset "${asset}" "${bridge_dir}/${asset}" \
            || die "required bridge asset is unavailable: ${REQUIRED_BRIDGE_VERSION}/${asset}"
    done
    FROM_VERSION="${previous_from}"
    ok "Published bridge assets staged: ${REQUIRED_BRIDGE_VERSION} (${OS_NAME}/${ARCH_NAME})"
}

baseline_protocol() {
    local version="$1"
    local old_dir="${WORKDIR}/protocol-wheels/${version}"
    local old_wheel="${old_dir}/defenseclaw-${version}-py3-none-any.whl"
    mkdir -p "${old_dir}"
    if [[ ! -f "${old_wheel}" ]]; then
        FROM_VERSION="${version}"
        download_old_asset "defenseclaw-${version}-py3-none-any.whl" "${old_wheel}" \
            || die "published baseline wheel is unavailable: ${version}"
    fi
    python3 - "${old_wheel}" <<'PY'
import ast
import sys
import zipfile

with zipfile.ZipFile(sys.argv[1]) as archive:
    try:
        source = archive.read("defenseclaw/commands/cmd_upgrade.py").decode("utf-8")
    except KeyError:
        print(1)
        raise SystemExit

tree = ast.parse(source, filename="defenseclaw/commands/cmd_upgrade.py")
for node in tree.body:
    value = None
    if isinstance(node, ast.Assign) and any(
        isinstance(target, ast.Name) and target.id == "_UPGRADE_PROTOCOL_VERSION"
        for target in node.targets
    ):
        value = node.value
    elif (
        isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "_UPGRADE_PROTOCOL_VERSION"
    ):
        value = node.value
    if isinstance(value, ast.Constant) and isinstance(value.value, int):
        print(value.value)
        raise SystemExit
print(1)
PY
}

version_lt() {
    ! version_lte "$2" "$1"
}

snapshot_state() {
    local output="$1"
    local gateway="${SMOKE_HOME}/.local/bin/defenseclaw-gateway"
    local real_gateway="${gateway}.protocol-gate-real"
    local venv_python="${SMOKE_HOME}/.defenseclaw/.venv/bin/python"
    local package_dir
    package_dir="$("${venv_python}" - <<'PY'
from pathlib import Path
import defenseclaw

print(Path(defenseclaw.__file__).resolve().parent)
PY
)"
    python3 - \
        "${SMOKE_HOME}/.defenseclaw" \
        "${package_dir}" \
        "${SMOKE_HOME}/.local/bin/defenseclaw" \
        "${gateway}" \
        "${real_gateway}" \
        "${output}" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

data_dir, package_dir, cli_link, gateway, real_gateway, output = map(Path, sys.argv[1:])
state = {}


def record(path: Path, key: str, *, exclude_venv: bool = False) -> None:
    info = path.lstat()
    base = {"mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid}
    if path.is_symlink():
        state[key] = {**base, "type": "symlink", "target": os.readlink(path)}
    elif path.is_dir():
        state[key] = {**base, "type": "directory"}
        for child in sorted(path.iterdir(), key=lambda item: item.name):
            if exclude_venv and child.name == ".venv":
                continue
            record(child, f"{key}/{child.name}")
    elif path.is_file():
        state[key] = {
            **base,
            "type": "file",
            "size": info.st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    else:
        state[key] = {**base, "type": "other"}


record(data_dir, "data", exclude_venv=True)
record(data_dir / ".venv", "venv")
record(package_dir, "installed-cli")
for label, path in (
    ("cli-link", cli_link),
    ("gateway-shim", gateway),
    ("gateway-real", real_gateway),
):
    record(path, label)
output.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

install_stop_probe() {
    local gateway="${SMOKE_HOME}/.local/bin/defenseclaw-gateway"
    local real_gateway="${gateway}.protocol-gate-real"
    mv "${gateway}" "${real_gateway}"
    cat > "${gateway}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "stop" ]]; then
    : "${UPGRADE_GATE_STOP_MARKER:?}"
    : > "${UPGRADE_GATE_STOP_MARKER}"
    exit 0
fi
: "${UPGRADE_GATE_REAL_GATEWAY:?}"
exec "${UPGRADE_GATE_REAL_GATEWAY}" "$@"
SH
    chmod 700 "${gateway}"
}

restore_stop_probe() {
    local gateway="${SMOKE_HOME}/.local/bin/defenseclaw-gateway"
    local real_gateway="${gateway}.protocol-gate-real"
    if [[ -f "${real_gateway}" ]]; then
        rm -f "${gateway}"
        mv "${real_gateway}" "${gateway}"
        chmod 700 "${gateway}"
    fi
}

install_curl_rewrite_probe() {
    local shim_dir="$1"
    local real_curl
    real_curl="$(command -v curl)"
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

assert_no_success_receipt() {
    python3 - "${SMOKE_HOME}/.defenseclaw/.upgrade-receipts" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
if not root.exists():
    raise SystemExit
for path in root.glob("*.json"):
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("status") in {"succeeded", "partial"}:
        raise SystemExit(f"refused upgrade wrote a success receipt: {path}")
PY
}

assert_staged_success_receipt() {
    python3 - \
        "${SMOKE_HOME}/.defenseclaw/.upgrade-receipts" \
        "${REQUIRED_BRIDGE_VERSION}" \
        "${TARGET_VERSION}" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
bridge, target = sys.argv[2:]
receipts = [
    json.loads(path.read_text(encoding="utf-8"))
    for path in sorted(root.glob("*.json"))
]
terminal = [receipt for receipt in receipts if receipt.get("target_version") == target]
if len(terminal) != 1:
    raise SystemExit(f"expected one terminal target receipt, got {len(terminal)}")
receipt = terminal[0]
if receipt.get("from_version") != bridge:
    raise SystemExit(f"target receipt did not originate from bridge {bridge}")
if receipt.get("status") != "succeeded" or receipt.get("migration_status") != "completed":
    raise SystemExit(f"target receipt is not fully successful: {receipt!r}")
if receipt.get("artifacts_verified") is not True or receipt.get("failure_code"):
    raise SystemExit(f"target receipt lacks verified terminal facts: {receipt!r}")
if any(receipt.get("status") in {"pending", "partial"} for receipt in receipts):
    raise SystemExit("staged upgrade left a pending or partial receipt")
PY
}

prepare_refusal_home() {
    local baseline="$1"
    local case_name="$2"
    FROM_VERSION="${baseline}"
    SMOKE_HOME="${WORKDIR}/refusal-${baseline}-${case_name}"
    mkdir -p "${SMOKE_HOME}"
    install_baseline
    seed_upgrade_fixture

    (
        while :; do
            sleep 30
        done
    ) &
    REFUSAL_SENTINEL_PID=$!
    REFUSAL_SENTINEL_PIDS+=("${REFUSAL_SENTINEL_PID}")
    printf '%s\n' "${REFUSAL_SENTINEL_PID}" > "${SMOKE_HOME}/.defenseclaw/gateway.pid"

    REFUSAL_STOP_MARKER="${WORKDIR}/${baseline}-${case_name}.stop-called"
    REFUSAL_REAL_GATEWAY="${SMOKE_HOME}/.local/bin/defenseclaw-gateway.protocol-gate-real"
    install_stop_probe
}

verify_refusal_invariants() {
    local before="$1"
    local after="$2"
    local baseline_version="$3"
    local log_file="$4"
    local status="$5"

    [[ "${status}" -ne 0 ]] || die "unsupported upgrade unexpectedly succeeded"
    [[ ! -e "${REFUSAL_STOP_MARKER}" ]] || die "unsupported upgrade reached the service-stop boundary"
    kill -0 "${REFUSAL_SENTINEL_PID}" >/dev/null 2>&1 \
        || die "gateway sentinel PID changed during refused upgrade"
    [[ "$(cat "${SMOKE_HOME}/.defenseclaw/gateway.pid")" == "${REFUSAL_SENTINEL_PID}" ]] \
        || die "gateway PID file changed during refused upgrade"

    local observed_version
    observed_version="$(HOME="${SMOKE_HOME}" DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
        PATH="${SMOKE_HOME}/.local/bin:${PATH}" defenseclaw --version)"
    [[ "${observed_version}" == *"${baseline_version}"* ]] \
        || die "refused upgrade changed installed CLI version: ${observed_version}"

    snapshot_state "${after}"
    cmp "${before}" "${after}" >/dev/null \
        || die "refused upgrade mutated config, data, permissions, CLI, or gateway bytes"
    assert_no_success_receipt
    grep -Eiq "protocol|minimum source|required bridge|upgrade bridge|without --version|upgrade.*first|source version" "${log_file}" \
        || die "refusal log did not explain the protocol/source bridge requirement"
}

run_installed_controller_refusal() {
    local baseline="$1"
    log "Proving installed ${baseline} controller refuses ${TARGET_VERSION} before mutation"
    prepare_refusal_home "${baseline}" "installed"
    patch_installed_upgrade_endpoint

    local before="${WORKDIR}/${baseline}-installed.before.json"
    local after="${WORKDIR}/${baseline}-installed.after.json"
    local log_file="${WORKDIR}/${baseline}-installed-refusal.log"
    snapshot_state "${before}"

    set +e
    HOME="${SMOKE_HOME}" \
    DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
    UPGRADE_GATE_STOP_MARKER="${REFUSAL_STOP_MARKER}" \
    UPGRADE_GATE_REAL_GATEWAY="${REFUSAL_REAL_GATEWAY}" \
    PATH="${SMOKE_HOME}/.local/bin:${PATH}" \
        defenseclaw upgrade --version "${TARGET_VERSION}" --yes --health-timeout "${HEALTH_TIMEOUT}" \
        >"${log_file}" 2>&1
    local status=$?
    set -e

    verify_refusal_invariants "${before}" "${after}" "${baseline}" "${log_file}" "${status}"
    restore_stop_probe
    ok "Installed ${baseline} controller refused pre-mutation"
}

run_candidate_updater_refusal() {
    local baseline="$1"
    log "Proving candidate-owned updater refuses source ${baseline} before mutation"
    prepare_refusal_home "${baseline}" "candidate-updater"

    local curl_shim="${SMOKE_HOME}/.upgrade-test-bin"
    local real_curl
    real_curl="$(install_curl_rewrite_probe "${curl_shim}")"
    local before="${WORKDIR}/${baseline}-candidate-updater.before.json"
    local after="${WORKDIR}/${baseline}-candidate-updater.after.json"
    local log_file="${WORKDIR}/${baseline}-candidate-updater-refusal.log"
    snapshot_state "${before}"

    set +e
    HOME="${SMOKE_HOME}" \
    DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
    OPENCLAW_HOME="${SMOKE_HOME}/.openclaw" \
    UPGRADE_GATE_STOP_MARKER="${REFUSAL_STOP_MARKER}" \
    UPGRADE_GATE_REAL_GATEWAY="${REFUSAL_REAL_GATEWAY}" \
    UPGRADE_GATE_REAL_CURL="${real_curl}" \
    UPGRADE_GATE_RELEASE_URL="${RELEASE_URL}" \
    PATH="${curl_shim}:${SMOKE_HOME}/.local/bin:${PATH}" \
        bash "${ROOT}/scripts/upgrade.sh" --yes --version "${TARGET_VERSION}" \
        >"${log_file}" 2>&1
    local status=$?
    set -e

    verify_refusal_invariants "${before}" "${after}" "${baseline}" "${log_file}" "${status}"
    restore_stop_probe
    ok "Candidate-owned updater refused source ${baseline} pre-mutation"
}

run_candidate_updater_staged_success() {
    local baseline="$1"
    log "Proving one-command staged upgrade ${baseline} -> ${REQUIRED_BRIDGE_VERSION} -> ${TARGET_VERSION}"
    FROM_VERSION="${baseline}"
    SMOKE_HOME="${WORKDIR}/staged-${baseline}"
    rm -rf "${SMOKE_HOME}"
    mkdir -p "${SMOKE_HOME}"
    install_baseline
    seed_upgrade_fixture
    prepare_isolated_docker_path

    local curl_shim="${SMOKE_HOME}/.upgrade-test-bin"
    local real_curl
    local log_file="${SMOKE_HOME}/upgrade.log"
    real_curl="$(install_curl_rewrite_probe "${curl_shim}")"

    if ! HOME="${SMOKE_HOME}" \
        DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
        OPENCLAW_HOME="${SMOKE_HOME}/.openclaw" \
        DOCKER_HOST="${UPGRADE_SMOKE_DOCKER_HOST:-unix://${SMOKE_HOME}/no-docker.sock}" \
        DEFENSECLAW_UPGRADE_TEST_MODE=1 \
        DEFENSECLAW_UPGRADE_TEST_RELEASE_BASE_URL="${RELEASE_URL}" \
        UPGRADE_GATE_REAL_CURL="${real_curl}" \
        UPGRADE_GATE_RELEASE_URL="${RELEASE_URL}" \
        UPGRADE_GATE_TARGET_VERSION="${TARGET_VERSION}" \
        PATH="${curl_shim}:${SMOKE_HOME}/.local/bin:${PATH}" \
            bash "${ROOT}/scripts/upgrade.sh" --yes >"${log_file}" 2>&1; then
        tail_v8_upgrade_log_secret_safe "${log_file}"
        die "one-command staged upgrade failed: ${baseline} -> ${TARGET_VERSION}"
    fi

    grep -Fq "${baseline} → ${REQUIRED_BRIDGE_VERSION} bridge → fresh controller → ${TARGET_VERSION}" \
        "${log_file}" || die "staged upgrade log did not prove the resolved bridge handoff"
    verify_upgrade
    assert_staged_success_receipt
    stop_smoke_gateway
    ok "One-command staged upgrade passed: ${baseline} -> ${REQUIRED_BRIDGE_VERSION} -> ${TARGET_VERSION}"
}

run_protocol_case() {
    local baseline="$1"
    if version_lte "${TARGET_VERSION}" "${baseline}"; then
        ok "Skipping baseline ${baseline}; it is not older than target ${TARGET_VERSION}"
        return
    fi

    local supported_protocol
    supported_protocol="$(baseline_protocol "${baseline}")"
    [[ "${supported_protocol}" =~ ^[1-9][0-9]*$ ]] \
        || die "baseline ${baseline} has invalid upgrade protocol: ${supported_protocol}"

    local source_too_old=0
    if [[ -n "${MINIMUM_SOURCE_VERSION}" ]] && version_lt "${baseline}" "${MINIMUM_SOURCE_VERSION}"; then
        source_too_old=1
    fi
    local protocol_too_old=0
    if (( supported_protocol < CANDIDATE_MIN_PROTOCOL )); then
        protocol_too_old=1
    fi

    if [[ -n "${REQUIRED_BRIDGE_VERSION}" && "${baseline}" == "${REQUIRED_BRIDGE_VERSION}" ]]; then
        (( supported_protocol >= CANDIDATE_MIN_PROTOCOL )) \
            || die "required bridge ${baseline} does not support candidate protocol ${CANDIDATE_MIN_PROTOCOL}"
        [[ "${source_too_old}" == "0" ]] \
            || die "required bridge ${baseline} is older than minimum source ${MINIMUM_SOURCE_VERSION}"
    fi

    if [[ "${protocol_too_old}" == "1" || "${source_too_old}" == "1" ]]; then
        run_installed_controller_refusal "${baseline}"
        if [[ "${source_too_old}" == "1" ]]; then
            run_candidate_updater_refusal "${baseline}"
            if manifest_array_contains auto_bridge_from "${baseline}"; then
                run_candidate_updater_staged_success "${baseline}"
            else
                ok "Source ${baseline} is intentionally outside auto_bridge_from; refusal is the supported path"
            fi
        fi
        return
    fi

    log "Baseline ${baseline} supports protocol ${supported_protocol}; requiring full upgrade success"
    run_one_upgrade_smoke "${baseline}"
}

main_protocol_gate() {
    parse_args "$@"
    cd "${ROOT}"
    if [[ -z "${TARGET_VERSION}" ]]; then
        TARGET_VERSION="$(current_version)"
    fi
    validate_inputs
    detect_platform
    WORKDIR="$(abs_path "$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-upgrade-protocol.XXXXXX")")"
    trap protocol_cleanup EXIT

    prepare_release_root
    assert_candidate_assets

    CANDIDATE_MIN_PROTOCOL="$(manifest_value min_upgrade_protocol 1)"
    MINIMUM_SOURCE_VERSION="$(manifest_value minimum_source_version "")"
    REQUIRED_BRIDGE_VERSION="$(manifest_value required_bridge_version "")"
    [[ "${CANDIDATE_MIN_PROTOCOL}" =~ ^[1-9][0-9]*$ ]] \
        || die "candidate min_upgrade_protocol must be a positive integer"
    [[ -z "${MINIMUM_SOURCE_VERSION}" || "${MINIMUM_SOURCE_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
        || die "candidate minimum_source_version must be X.Y.Z"
    [[ -z "${REQUIRED_BRIDGE_VERSION}" || "${REQUIRED_BRIDGE_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
        || die "candidate required_bridge_version must be X.Y.Z"
    if [[ -n "${REQUIRED_BRIDGE_VERSION}" && -z "${MINIMUM_SOURCE_VERSION}" ]]; then
        die "candidate required_bridge_version requires minimum_source_version"
    fi
    if [[ -n "${REQUIRED_BRIDGE_VERSION}" ]]; then
        manifest_array_values auto_bridge_from >/dev/null
    fi

    prepare_required_bridge_assets
    start_release_server
    run_v8_source_contract_tests

    local baseline
    for baseline in "${FROM_VERSION_LIST[@]}"; do
        run_protocol_case "${baseline}"
    done
    ok "Manifest-derived protocol matrix passed: ${FROM_VERSION_LIST[*]} -> ${TARGET_VERSION}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main_protocol_gate "$@"
fi
