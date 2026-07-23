#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# Manifest-derived release gate. Schema-aware immutable controllers must refuse
# a schema-2 target before mutation. Earlier tagged controllers must fail on
# the canonical gateway refusal envelope during extraction, also before backup
# or stop. The release-owned resolver must then complete every signed source.

set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly FIRST_SCHEMA2_RELEASE="0.8.4"
readonly OBSERVABILITY_V8_HARD_CUT_VERSION="0.8.5"
REFUSAL_CONTRACT_ONLY=0

# shellcheck source=scripts/test-upgrade-release.sh
source "${ROOT}/scripts/test-upgrade-release.sh"
trap - EXIT

REFUSAL_SENTINEL_PIDS=()

protocol_usage() {
    usage
    cat <<'EOF'

Protocol-gate-only options:
  --refusal-contract-only  Prove schema-2 pre-mutation refusal only. This is
                           for unsigned PR candidates; the signed release
                           workflow owns the positive resolver success path.
EOF
}

parse_protocol_args() {
    local -a shared_args=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --refusal-contract-only)
                REFUSAL_CONTRACT_ONLY=1
                shift
                ;;
            --help|-h)
                protocol_usage
                exit 0
                ;;
            *)
                shared_args+=("$1")
                shift
                ;;
        esac
    done
    if [[ "${#shared_args[@]}" -gt 0 ]]; then
        parse_args "${shared_args[@]}"
    else
        parse_args
    fi
}

protocol_cleanup() {
    local status=$?
    local pid
    # The protocol harness replaces the base smoke harness's EXIT trap below.
    # Preserve its most important guarantee: a source/target gateway that was
    # started inside the throwaway HOME must be stopped even when a later
    # assertion aborts before the success path's explicit stop. Otherwise the
    # sandbox gateway can keep the real API port (18970) after WORKDIR is
    # deleted and make the developer's ordinary hooks fail authentication.
    stop_smoke_gateway
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
    local values
    values="$(manifest_array_values "${key}")" || return 1
    grep -Fxq "${expected}" <<<"${values}"
}

manifest_windows_sources_are_empty() {
    python3 - "${RELEASE_ROOT}/${TARGET_VERSION}/upgrade-manifest.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    platform_tested = json.load(handle).get("platform_tested_source_versions")
if not isinstance(platform_tested, dict) or set(platform_tested) != {"windows"}:
    raise SystemExit(
        "platform_tested_source_versions must contain exactly the Windows source list"
    )
windows = platform_tested["windows"]
if not isinstance(windows, list):
    raise SystemExit("platform_tested_source_versions.windows must be a list")
raise SystemExit(0 if not windows else 1)
PY
}

baseline_protocol() {
    local version="$1"
    local old_dir="${WORKDIR}/published-release/${version}"
    local baseline_names old_wheel_name old_wheel
    baseline_names="$(published_baseline_artifact_names "${version}")"
    old_wheel_name="$(printf '%s\n' "${baseline_names}" | sed -n '1p')"
    old_wheel="${old_dir}/${old_wheel_name}"
    [[ -f "${old_wheel}" ]] \
        || die "authenticated published baseline wheel is unavailable: ${version}"
    local inspection_root="${WORKDIR}/protocol-inspection"
    mkdir -p "${inspection_root}"
    old_wheel="$(release_test_artifact_path \
        "${old_wheel}" "${old_dir}/checksums.txt" \
        "${inspection_root}/${version}-${OS_NAME}-${ARCH_NAME}-protocol.whl")" \
        || die "could not materialize authenticated protocol-inspection wheel: ${version}"
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

baseline_has_schema_gate() {
    local version="$1"
    local old_dir="${WORKDIR}/published-release/${version}"
    local baseline_names old_wheel_name old_wheel
    baseline_names="$(published_baseline_artifact_names "${version}")"
    old_wheel_name="$(printf '%s\n' "${baseline_names}" | sed -n '1p')"
    old_wheel="${old_dir}/${old_wheel_name}"
    [[ -f "${old_wheel}" ]] \
        || die "baseline wheel must be staged before schema-gate inspection: ${version}"
    local inspection_root="${WORKDIR}/protocol-inspection"
    mkdir -p "${inspection_root}"
    old_wheel="$(release_test_artifact_path \
        "${old_wheel}" "${old_dir}/checksums.txt" \
        "${inspection_root}/${version}-${OS_NAME}-${ARCH_NAME}-schema.whl")" \
        || die "could not materialize authenticated schema-inspection wheel: ${version}"
    python3 - "${old_wheel}" <<'PY'
import ast
import sys
import zipfile

with zipfile.ZipFile(sys.argv[1]) as archive:
    try:
        source = archive.read("defenseclaw/commands/cmd_upgrade.py").decode("utf-8")
    except KeyError:
        print(0)
        raise SystemExit

tree = ast.parse(source, filename="defenseclaw/commands/cmd_upgrade.py")
has_manifest_fetch = "_UPGRADE_MANIFEST_FILENAME" in source
has_schema_refusal = any(
    isinstance(node, ast.Compare)
    and isinstance(node.left, ast.Name)
    and node.left.id == "schema_version"
    and len(node.ops) == 1
    and isinstance(node.ops[0], ast.Gt)
    and len(node.comparators) == 1
    and isinstance(node.comparators[0], ast.Constant)
    and node.comparators[0].value == 1
    for node in ast.walk(tree)
)
print(1 if has_manifest_fetch and has_schema_refusal else 0)
PY
}

version_lt() {
    ! version_lte "$2" "$1"
}

snapshot_state() {
    local output="$1"
    local openclaw_home="${SMOKE_HOME}/.openclaw"
    local gateway="${SMOKE_HOME}/.local/bin/defenseclaw-gateway"
    local real_gateway="${gateway}.protocol-gate-real"
    local venv_python="${SMOKE_HOME}/.defenseclaw/.venv/bin/python"
    local package_dir
    package_dir="$(PYTHONDONTWRITEBYTECODE=1 "${venv_python}" - <<'PY'
from pathlib import Path
import defenseclaw

print(Path(defenseclaw.__file__).resolve().parent)
PY
)"
    python3 - \
        "${SMOKE_HOME}/.defenseclaw" \
        "${openclaw_home}" \
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

data_dir, openclaw_home, package_dir, cli_link, gateway, real_gateway, output = map(
    Path, sys.argv[1:]
)
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
record(openclaw_home, "openclaw")
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

materialize_baseline_cli_startup_state() {
    local venv_python="${SMOKE_HOME}/.defenseclaw/.venv/bin/python"

    # Seed every ordinary immutable-controller root-callback mutation before
    # the refusal snapshot so the comparison isolates the upgrade path. The
    # oldest published controller also reconciles its CodeGuard skill before
    # dispatching `upgrade`; that immutable startup behavior must not be
    # mistaken for an upgrade mutation. Disable bytecode writes here and on the
    # command under test because interpreter caches are not release or operator state.
    HOME="${SMOKE_HOME}" \
    DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
    PYTHONDONTWRITEBYTECODE=1 \
        "${venv_python}" - <<'PY' \
        || die "could not materialize immutable controller startup state"
from defenseclaw import config as cfg_mod
from defenseclaw.db import Store

cfg = cfg_mod.load()
try:
    from defenseclaw.main import _ensure_codeguard_skill
except ImportError:
    pass
else:
    _ensure_codeguard_skill(cfg)

store = Store(cfg.audit_db)
try:
    store.init()
finally:
    store.close()
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

assert_reviewed_resolver_asset_contract() {
    local release_dir="${RELEASE_ROOT}/${TARGET_VERSION}"
    local posix_resolver="${release_dir}/defenseclaw-upgrade.sh"
    python3 - \
        "${ROOT}/scripts/upgrade.sh" \
        "${release_dir}/defenseclaw-upgrade.sh" \
        "${ROOT}/scripts/upgrade.ps1" \
        "${release_dir}/defenseclaw-upgrade.ps1" \
        "${release_dir}/checksums.txt" <<'PY' \
        || die "reviewed release-owned resolver assets failed byte-for-byte validation"
import hashlib
from pathlib import Path
import re
import stat
import sys

posix_source, posix_candidate, windows_source, windows_candidate, checksums = map(
    Path, sys.argv[1:]
)
lines = checksums.read_text(encoding="utf-8").splitlines()
for source, candidate in (
    (posix_source, posix_candidate),
    (windows_source, windows_candidate),
):
    info = candidate.lstat()
    if candidate.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise SystemExit(f"candidate resolver is not a regular file: {candidate.name}")
    payload = candidate.read_bytes()
    if not payload:
        raise SystemExit(f"candidate resolver is empty: {candidate.name}")
    if payload != source.read_bytes():
        raise SystemExit(f"candidate resolver differs from reviewed source: {candidate.name}")
    if payload.splitlines()[-1] != b"# DefenseClaw upgrade resolver complete v1":
        raise SystemExit(f"candidate resolver is incomplete: {candidate.name}")
    pattern = re.compile(rf"([0-9a-f]{{64}})  {re.escape(candidate.name)}")
    entries = [match.group(1) for line in lines if (match := pattern.fullmatch(line))]
    if len(entries) != 1:
        raise SystemExit(f"checksums.txt must bind {candidate.name} exactly once")
    if entries[0] != hashlib.sha256(payload).hexdigest():
        raise SystemExit(f"checksums.txt does not bind the exact {candidate.name} bytes")
PY
    bash -n "${posix_resolver}" \
        || die "candidate resolver asset is not valid Bash"
    ok "Reviewed release-owned resolver assets are complete and checksum-bound"
}

prepare_refusal_home() {
    local baseline="$1"
    local case_name="$2"
    FROM_VERSION="${baseline}"
    SMOKE_HOME="${WORKDIR}/refusal-${baseline}-${case_name}"
    mkdir -p "${SMOKE_HOME}"
    install_baseline
    seed_upgrade_fixture
    mkdir -p "${SMOKE_HOME}/.openclaw"
    printf '%s\n' '{"sentinel":"refusal-must-not-mutate"}' \
        > "${SMOKE_HOME}/.openclaw/openclaw.json"
    chmod 700 "${SMOKE_HOME}/.openclaw"
    chmod 600 "${SMOKE_HOME}/.openclaw/openclaw.json"
    materialize_baseline_cli_startup_state

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
    local refusal_mode="${6:-schema}"

    [[ "${status}" -ne 0 ]] || die "unsupported upgrade unexpectedly succeeded"
    [[ ! -e "${REFUSAL_STOP_MARKER}" ]] || die "unsupported upgrade reached the service-stop boundary"
    kill -0 "${REFUSAL_SENTINEL_PID}" >/dev/null 2>&1 \
        || die "gateway sentinel PID changed during refused upgrade"
    [[ "$(cat "${SMOKE_HOME}/.defenseclaw/gateway.pid")" == "${REFUSAL_SENTINEL_PID}" ]] \
        || die "gateway PID file changed during refused upgrade"

    local observed_version
    observed_version="$(HOME="${SMOKE_HOME}" DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
        PYTHONDONTWRITEBYTECODE=1 \
        PATH="${SMOKE_HOME}/.local/bin:${PATH}" defenseclaw --version)"
    [[ "${observed_version}" == *"${baseline_version}"* ]] \
        || die "refused upgrade changed installed CLI version: ${observed_version}"

    snapshot_state "${after}"
    if ! cmp "${before}" "${after}" >/dev/null; then
        diff -u "${before}" "${after}" >&2 || true
        die "refused upgrade mutated config, data, OpenClaw state, permissions, CLI, or gateway bytes"
    fi
    assert_no_success_receipt
    case "${refusal_mode}" in
        schema)
            grep -Eiq "schema|protocol|minimum source|required bridge|upgrade bridge|without --version|upgrade.*first|source version|tested.*matrix|published-baseline" "${log_file}" \
                || die "refusal log did not explain the protocol/source bridge requirement"
            ;;
        artifact-provenance)
            # A protocol-2 controller must not honor the legacy test-only
            # --allow-unverified escape hatch for a modern target.  In an
            # unsigned PR candidate this authentication refusal necessarily
            # happens before the signed schema/source policy can be trusted.
            grep -Fq -- \
                "--allow-unverified cannot bypass mandatory 0.8.4+ manifest or artifact provenance checks" \
                "${log_file}" \
                || die "modern controller did not reject the legacy unverified override"
            grep -Fq \
                "checksums.txt is not signed (no Sigstore signature/certificate assets were published)" \
                "${log_file}" \
                || die "modern controller did not identify the unsigned candidate envelope"
            grep -Fq \
                "Modern release provenance is mandatory; --allow-unverified cannot override it." \
                "${log_file}" \
                || die "modern controller did not explain the mandatory provenance boundary"
            ;;
        legacy-schema)
            grep -Eiq "schema|protocol|upgrade script shipped with that release" "${log_file}" \
                || die "legacy schema-aware refusal did not explain its forward-compatibility gate"
            grep -Fq \
                "curl -fsSL https://raw.githubusercontent.com/${REPO}/${TARGET_VERSION}/scripts/upgrade.sh | bash -s -- --version ${TARGET_VERSION}" \
                "${log_file}" \
                || die "legacy schema-aware controller hint changed; record the explicit-target handoff trap"
            ;;
        artifact-envelope)
            grep -Fq "Release artifacts verified" "${log_file}" \
                || die "legacy controller did not prove both conventional artifact HEAD requests"
            grep -Eiq "(^|[^[:alnum:]_])(tar|gzip)([^[:alnum:]_]|$)|not (in )?gzip format|non-zero exit status|CalledProcessError" "${log_file}" \
                || die "legacy controller did not fail at canonical gateway extraction"
            ;;
        immutable-bridge-empty-windows)
            # The published 0.8.4 controller predates the schema-2 allowance
            # for an empty platform list.  The current resolver understands
            # that truthful value as "Windows unsupported", but the immutable
            # bridge must fail closed before mutation when it reads it.
            grep -Fq \
                "upgrade-manifest.json platform_tested_source_versions.windows must be a non-empty version list." \
                "${log_file}" \
                || die "immutable 0.8.4 controller did not prove its known empty-Windows pre-mutation refusal"
            ;;
        *) die "unknown installed-controller refusal mode: ${refusal_mode}" ;;
    esac
}

run_installed_controller_refusal() {
    local baseline="$1"
    local refusal_mode="${2:-schema}"
    local invocation before after log_file status
    local -a command_args
    for invocation in explicit latest; do
        log "Proving installed ${baseline} controller refuses ${TARGET_VERSION} before mutation (${refusal_mode}, ${invocation})"
        prepare_refusal_home "${baseline}" "installed-${invocation}"
        command_args=(upgrade)
        # The immutable legacy controller may require its existing explicit
        # opt-in before it will parse an unsigned PR candidate's manifest.
        # This is confined to the pre-mutation refusal fixture: the modern
        # resolver never receives this flag, and release.yaml still requires
        # the real release-workflow signature for every positive path.
        if [[ "${REFUSAL_CONTRACT_ONLY}" == "1" ]] \
            && upgrade_supports_allow_unverified \
            && ! candidate_has_checksum_signature; then
            command_args+=(--allow-unverified)
        fi
        if [[ "${invocation}" == "explicit" ]]; then
            patch_installed_upgrade_endpoint
            command_args+=(--version "${TARGET_VERSION}")
        else
            # Exercise the common `defenseclaw upgrade` path deterministically
            # against the sealed candidate rather than whatever release GitHub
            # happens to mark latest while this draft candidate is still gated.
            patch_installed_upgrade_endpoint "${TARGET_VERSION}"
        fi
        command_args+=(--yes --health-timeout "${HEALTH_TIMEOUT}")

        before="${WORKDIR}/${baseline}-installed-${invocation}.before.json"
        after="${WORKDIR}/${baseline}-installed-${invocation}.after.json"
        log_file="${WORKDIR}/${baseline}-installed-${invocation}-refusal.log"
        snapshot_state "${before}"

        set +e
        HOME="${SMOKE_HOME}" \
        DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
        PYTHONDONTWRITEBYTECODE=1 \
        UPGRADE_GATE_STOP_MARKER="${REFUSAL_STOP_MARKER}" \
        UPGRADE_GATE_REAL_GATEWAY="${REFUSAL_REAL_GATEWAY}" \
        PATH="${SMOKE_HOME}/.local/bin:${PATH}" \
            defenseclaw "${command_args[@]}" \
            >"${log_file}" 2>&1
        status=$?
        set -e

        verify_refusal_invariants \
            "${before}" "${after}" "${baseline}" "${log_file}" "${status}" "${refusal_mode}"
        restore_stop_probe
        ok "Installed ${baseline} controller refused ${invocation} target pre-mutation"
    done
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
    PYTHONDONTWRITEBYTECODE=1 \
    UPGRADE_GATE_STOP_MARKER="${REFUSAL_STOP_MARKER}" \
    UPGRADE_GATE_REAL_GATEWAY="${REFUSAL_REAL_GATEWAY}" \
    UPGRADE_GATE_REAL_CURL="${real_curl}" \
    UPGRADE_GATE_RELEASE_URL="${RELEASE_URL}" \
    PATH="${curl_shim}:${SMOKE_HOME}/.local/bin:${PATH}" \
        bash "${RELEASE_ROOT}/${TARGET_VERSION}/defenseclaw-upgrade.sh" \
        --yes --version "${TARGET_VERSION}" \
        >"${log_file}" 2>&1
    local status=$?
    set -e

    verify_refusal_invariants "${before}" "${after}" "${baseline}" "${log_file}" "${status}"
    restore_stop_probe
    ok "Candidate-owned updater refused source ${baseline} pre-mutation"
}

run_candidate_updater_staged_success() {
    local baseline="$1"
    local invocation="${2:-latest}"
    local expected_path
    local -a resolver_args=(--yes)
    case "${invocation}" in
        latest) ;;
        explicit) resolver_args+=(--version "${TARGET_VERSION}") ;;
        *) die "unknown staged resolver invocation: ${invocation}" ;;
    esac
    log "Proving ${invocation} resolver staging ${baseline} -> ${REQUIRED_BRIDGE_VERSION} -> ${TARGET_VERSION}"
    FROM_VERSION="${baseline}"
    SMOKE_HOME="${WORKDIR}/staged-${baseline}"
    rm -rf "${SMOKE_HOME}"
    mkdir -p "${SMOKE_HOME}"
    install_baseline
    seed_upgrade_fixture
    prepare_isolated_docker_path
    start_source_gateway_canary

    local curl_shim="${SMOKE_HOME}/.upgrade-test-bin"
    local real_curl
    local log_file="${SMOKE_HOME}/upgrade.log"
    real_curl="$(install_curl_rewrite_probe "${curl_shim}")"

    if ! HOME="${SMOKE_HOME}" \
        DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
        OPENCLAW_HOME="${SMOKE_HOME}/.openclaw" \
        PYTHONDONTWRITEBYTECODE=1 \
        DOCKER_HOST="${UPGRADE_SMOKE_DOCKER_HOST:-unix://${SMOKE_HOME}/no-docker.sock}" \
        DEFENSECLAW_UPGRADE_TEST_MODE=1 \
        DEFENSECLAW_UPGRADE_TEST_RELEASE_BASE_URL="${RELEASE_URL}" \
        UPGRADE_GATE_REAL_CURL="${real_curl}" \
        UPGRADE_GATE_RELEASE_URL="${RELEASE_URL}" \
        UPGRADE_GATE_TARGET_VERSION="${TARGET_VERSION}" \
        PATH="${curl_shim}:${SMOKE_HOME}/.local/bin:${PATH}" \
            bash "${RELEASE_ROOT}/${TARGET_VERSION}/defenseclaw-upgrade.sh" \
            "${resolver_args[@]}" >"${log_file}" 2>&1; then
        tail_v8_upgrade_log_secret_safe "${log_file}"
        die "one-command staged upgrade failed: ${baseline} -> ${TARGET_VERSION}"
    fi

    expected_path="${baseline} → ${REQUIRED_BRIDGE_VERSION} bridge → fresh controller → ${TARGET_VERSION}"
    if [[ "${baseline}" == "${REQUIRED_BRIDGE_VERSION}" ]] \
        && version_lt "${OBSERVABILITY_V8_HARD_CUT_VERSION}" "${TARGET_VERSION}"; then
        expected_path="${baseline} → ${OBSERVABILITY_V8_HARD_CUT_VERSION} → ${TARGET_VERSION}"
    elif version_lt "${OBSERVABILITY_V8_HARD_CUT_VERSION}" "${TARGET_VERSION}"; then
        expected_path="${baseline} → ${REQUIRED_BRIDGE_VERSION} bridge → fresh controller → ${OBSERVABILITY_V8_HARD_CUT_VERSION} → ${TARGET_VERSION}"
    fi
    grep -Fq "${expected_path}" \
        "${log_file}" || die "staged upgrade log did not prove the resolved bridge handoff"
    verify_upgrade
    stop_smoke_gateway
    ok "${invocation} resolver staged upgrade passed: ${baseline} -> ${REQUIRED_BRIDGE_VERSION} -> ${TARGET_VERSION}"
}

run_candidate_updater_direct_success() {
    local baseline="$1"
    log "Proving release-owned resolver upgrade ${baseline} -> ${TARGET_VERSION}"
    FROM_VERSION="${baseline}"
    SMOKE_HOME="${WORKDIR}/release-resolver-${baseline}"
    rm -rf "${SMOKE_HOME}"
    mkdir -p "${SMOKE_HOME}"
    install_baseline
    seed_upgrade_fixture
    prepare_isolated_docker_path
    start_source_gateway_canary

    local curl_shim="${SMOKE_HOME}/.upgrade-test-bin"
    local real_curl
    local log_file="${SMOKE_HOME}/upgrade.log"
    real_curl="$(install_curl_rewrite_probe "${curl_shim}")"

    if ! HOME="${SMOKE_HOME}" \
        DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
        OPENCLAW_HOME="${SMOKE_HOME}/.openclaw" \
        PYTHONDONTWRITEBYTECODE=1 \
        DOCKER_HOST="${UPGRADE_SMOKE_DOCKER_HOST:-unix://${SMOKE_HOME}/no-docker.sock}" \
        DEFENSECLAW_UPGRADE_TEST_MODE=1 \
        DEFENSECLAW_UPGRADE_TEST_RELEASE_BASE_URL="${RELEASE_URL}" \
        UPGRADE_GATE_REAL_CURL="${real_curl}" \
        UPGRADE_GATE_RELEASE_URL="${RELEASE_URL}" \
        UPGRADE_GATE_TARGET_VERSION="${TARGET_VERSION}" \
        PATH="${curl_shim}:${SMOKE_HOME}/.local/bin:${PATH}" \
            bash "${RELEASE_ROOT}/${TARGET_VERSION}/defenseclaw-upgrade.sh" \
            --yes >"${log_file}" 2>&1; then
        tail_v8_upgrade_log_secret_safe "${log_file}"
        die "release-owned resolver upgrade failed: ${baseline} -> ${TARGET_VERSION}"
    fi

    verify_upgrade
    stop_smoke_gateway
    ok "Release-owned resolver upgrade passed: ${baseline} -> ${TARGET_VERSION}"
}

run_protocol_case() {
    local baseline="$1"
    if version_lte "${TARGET_VERSION}" "${baseline}"; then
        ok "Skipping baseline ${baseline}; it is not older than target ${TARGET_VERSION}"
        return
    fi

    stage_authenticated_baseline "${baseline}"
    local supported_protocol
    supported_protocol="$(baseline_protocol "${baseline}")"
    [[ "${supported_protocol}" =~ ^[1-9][0-9]*$ ]] \
        || die "baseline ${baseline} has invalid upgrade protocol: ${supported_protocol}"
    local has_schema_gate
    has_schema_gate="$(baseline_has_schema_gate "${baseline}")"
    [[ "${has_schema_gate}" == "0" || "${has_schema_gate}" == "1" ]] \
        || die "baseline ${baseline} returned invalid schema-gate capability: ${has_schema_gate}"
    local legacy_schema_one_controller=0
    local installed_refusal_mode="schema"
    if version_lt "${baseline}" "${FIRST_SCHEMA2_RELEASE}"; then
        legacy_schema_one_controller=1
        if [[ "${has_schema_gate}" == "1" ]]; then
            installed_refusal_mode="legacy-schema"
        else
            installed_refusal_mode="artifact-envelope"
        fi
    elif [[ "${REFUSAL_CONTRACT_ONLY}" == "1" ]] && ! candidate_has_checksum_signature; then
        # The PR refusal job deliberately has no release-workflow Fulcio
        # identity.  A modern controller therefore must stop at immutable
        # artifact authentication, before it may trust candidate schema or
        # source-version policy.  Older controllers retain their separate
        # schema/artifact compatibility assertions above.
        installed_refusal_mode="artifact-provenance"
    fi

    local source_too_old=0
    if [[ -n "${MINIMUM_SOURCE_VERSION}" ]] && version_lt "${baseline}" "${MINIMUM_SOURCE_VERSION}"; then
        source_too_old=1
    fi
    local protocol_too_old=0
    if (( supported_protocol < CANDIDATE_MIN_PROTOCOL )); then
        protocol_too_old=1
    fi
    local immutable_bridge_empty_windows_refusal=0
    if [[ "${baseline}" == "${FIRST_SCHEMA2_RELEASE}" \
        && "${baseline}" == "${REQUIRED_BRIDGE_VERSION}" ]] \
        && manifest_windows_sources_are_empty; then
        # The signed policy is truthful: Windows cannot cross a hard cut when
        # 0.8.4 was not published there.  The immutable 0.8.4 controller did
        # not yet accept an empty platform matrix, so prove that known refusal
        # and let the current release-owned resolver own the positive path.
        immutable_bridge_empty_windows_refusal=1
    fi
    local resolver_owned_post_cut_bridge=0
    if [[ -n "${REQUIRED_BRIDGE_VERSION}" \
        && "${baseline}" == "${REQUIRED_BRIDGE_VERSION}" ]] \
        && version_lt "${OBSERVABILITY_V8_HARD_CUT_VERSION}" "${TARGET_VERSION}"; then
        # The immutable 0.8.4 controller owns only the 0.8.4 -> 0.8.5 hard
        # cut.  Sending it directly to a later target preserves the 0.8.4
        # dependency graph and recreates the release failure this gate exists
        # to prevent.  The current release-owned resolver must insert 0.8.5.
        resolver_owned_post_cut_bridge=1
    fi

    if [[ -n "${REQUIRED_BRIDGE_VERSION}" && "${baseline}" == "${REQUIRED_BRIDGE_VERSION}" ]]; then
        (( supported_protocol >= CANDIDATE_MIN_PROTOCOL )) \
            || die "required bridge ${baseline} does not support candidate protocol ${CANDIDATE_MIN_PROTOCOL}"
        [[ "${source_too_old}" == "0" ]] \
            || die "required bridge ${baseline} is older than minimum source ${MINIMUM_SOURCE_VERSION}"
    fi

    if [[ "${CANDIDATE_SCHEMA_VERSION}" -eq 2 ]]; then
        local source_is_tested=0
        if manifest_array_contains tested_source_versions "${baseline}"; then
            source_is_tested=1
        fi
        if [[ "${REFUSAL_CONTRACT_ONLY}" == "1" ]]; then
            [[ "${source_is_tested}" == "1" ]] \
                || die "refusal-contract source ${baseline} is absent from tested_source_versions"
            run_installed_controller_refusal "${baseline}" "${installed_refusal_mode}"
            return
        fi
        if [[ "${SUCCESS_PATH_ONLY}" == "1" ]]; then
            [[ "${source_is_tested}" == "1" ]] \
                || die "success canary source ${baseline} is absent from tested_source_versions"
            if [[ "${source_too_old}" == "1" ]]; then
                [[ -n "${REQUIRED_BRIDGE_VERSION}" ]] \
                    || die "success canary source ${baseline} requires a bridge contract"
                manifest_array_contains auto_bridge_from "${baseline}" \
                    || die "success canary source ${baseline} is absent from auto_bridge_from"
                run_candidate_updater_staged_success "${baseline}"
            else
                run_candidate_updater_direct_success "${baseline}"
            fi
            return
        fi
        if [[ "${source_is_tested}" -eq 0 ]]; then
            run_installed_controller_refusal "${baseline}" "${installed_refusal_mode}"
            run_candidate_updater_refusal "${baseline}"
            return
        fi

        if [[ "${immutable_bridge_empty_windows_refusal}" -eq 1 ]]; then
            run_installed_controller_refusal "${baseline}" "immutable-bridge-empty-windows"
        elif [[ "${resolver_owned_post_cut_bridge}" -eq 1 ]]; then
            log "Required bridge ${baseline} uses the release-owned ${OBSERVABILITY_V8_HARD_CUT_VERSION} bootstrap path"
        elif [[ "${legacy_schema_one_controller}" -eq 1 \
                || "${protocol_too_old}" -eq 1 \
                || "${source_too_old}" -eq 1 ]]; then
            run_installed_controller_refusal "${baseline}" "${installed_refusal_mode}"
        else
            log "Schema-2 baseline ${baseline} is capable; requiring installed-controller success"
            run_one_upgrade_smoke "${baseline}"
        fi

        if [[ "${resolver_owned_post_cut_bridge}" -eq 1 ]]; then
            run_candidate_updater_staged_success "${baseline}"
        elif [[ "${source_too_old}" -eq 1 ]]; then
            [[ -n "${REQUIRED_BRIDGE_VERSION}" ]] \
                || die "tested source ${baseline} requires a bridge, but the signed bridge contract is absent"
            manifest_array_contains auto_bridge_from "${baseline}" \
                || die "tested pre-bridge source ${baseline} is absent from auto_bridge_from"
            # Frozen schema-1 controllers hand their selected target to the
            # current release-owned resolver with --version.  Prove that exact
            # immutable handoff now stages the bridge instead of producing a
            # second refusal and another command for the operator.
            run_candidate_updater_staged_success "${baseline}" explicit
        else
            run_candidate_updater_direct_success "${baseline}"
        fi
        return
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
    parse_protocol_args "$@"
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
    CANDIDATE_SCHEMA_VERSION="$(manifest_value schema_version 1)"
    CANDIDATE_RUNTIME_CONFIG_VERSION="$(manifest_value runtime_config_version "")"
    MINIMUM_SOURCE_VERSION="$(manifest_value minimum_source_version "")"
    REQUIRED_BRIDGE_VERSION="$(manifest_value required_bridge_version "")"
    [[ "${CANDIDATE_MIN_PROTOCOL}" =~ ^[1-9][0-9]*$ ]] \
        || die "candidate min_upgrade_protocol must be a positive integer"
    [[ "${CANDIDATE_SCHEMA_VERSION}" =~ ^[1-9][0-9]*$ ]] \
        || die "candidate schema_version must be a positive integer"
    if version_lte "${FIRST_SCHEMA2_RELEASE}" "${TARGET_VERSION}"; then
        [[ "${CANDIDATE_SCHEMA_VERSION}" -eq 2 ]] \
            || die "0.8.4+ protocol gate requires upgrade manifest schema 2"
        local expected_runtime_config_version=8
        [[ "${TARGET_VERSION}" == "${FIRST_SCHEMA2_RELEASE}" ]] \
            && expected_runtime_config_version=7
        [[ "${CANDIDATE_RUNTIME_CONFIG_VERSION}" == "${expected_runtime_config_version}" ]] \
            || die "schema-2 runtime_config_version must be ${expected_runtime_config_version} for ${TARGET_VERSION}"
        [[ -n "$(manifest_array_values tested_source_versions)" ]] \
            || die "schema-2 protocol gate requires a non-empty tested_source_versions matrix"
    else
        [[ "${CANDIDATE_SCHEMA_VERSION}" -eq 1 ]] \
            || die "pre-0.8.4 protocol gate requires upgrade manifest schema 1"
        [[ -z "${CANDIDATE_RUNTIME_CONFIG_VERSION}" ]] \
            || die "schema-1 protocol manifest must not declare runtime_config_version"
    fi
    if [[ "${SUCCESS_PATH_ONLY}" == "1" && "${CANDIDATE_SCHEMA_VERSION}" -ne 2 ]]; then
        die "--success-path-only requires a schema-2 candidate"
    fi
    if [[ "${REFUSAL_CONTRACT_ONLY}" == "1" && "${CANDIDATE_SCHEMA_VERSION}" -ne 2 ]]; then
        die "--refusal-contract-only requires a schema-2 candidate"
    fi
    if [[ "${REFUSAL_CONTRACT_ONLY}" == "1" && "${SUCCESS_PATH_ONLY}" == "1" ]]; then
        die "--refusal-contract-only and --success-path-only are mutually exclusive"
    fi
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

    if [[ "${REFUSAL_CONTRACT_ONLY}" == "1" ]]; then
        assert_reviewed_resolver_asset_contract
    else
        prepare_required_bridge_assets
    fi
    start_release_server
    if [[ "${REFUSAL_CONTRACT_ONLY}" != "1" ]]; then
        run_v8_source_contract_tests
    fi

    local baseline
    for baseline in "${FROM_VERSION_LIST[@]}"; do
        run_protocol_case "${baseline}"
    done
    if [[ "${REFUSAL_CONTRACT_ONLY}" == "1" ]]; then
        ok "Unsigned-PR schema-2 refusal contract passed: ${FROM_VERSION_LIST[*]} -> ${TARGET_VERSION}"
        ok "Signed resolver success remains mandatory in release.yaml after candidate signing"
    else
        ok "Manifest-derived protocol matrix passed: ${FROM_VERSION_LIST[*]} -> ${TARGET_VERSION}"
    fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main_protocol_gate "$@"
fi
