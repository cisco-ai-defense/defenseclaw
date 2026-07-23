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
#   ./scripts/upgrade.sh [--yes] [--version VERSION] [--plan] [--help]
#
# Options:
#   --yes, -y             Skip confirmation prompts
#   --version VERSION     Select a specific final release (required bridges are still staged)
#   --plan                Verify contracts and print the resolved path only
#   --help, -h            Show this help
#
# Environment variables:
#   VERSION               Same as --version
#   DEFENSECLAW_HOME      Override install directory (default: ~/.defenseclaw)
#   OPENCLAW_HOME         Override OpenClaw config dir (default: ~/.openclaw)
#
set -euo pipefail

# Backups can contain config credentials and the promoted-secret environment.
# Pin creation to owner-only permissions even on hosts whose interactive umask
# is group-writable (for example 0002).
umask 077

main() {

# ── Configuration ─────────────────────────────────────────────────────────────

CONTROLLER_HOME_INPUT="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
CONTROLLER_HOME="$(python3 - "${CONTROLLER_HOME_INPUT}" <<'PY'
import os
import sys

value = os.path.expanduser(sys.argv[1])
if not os.path.isabs(value) or any(character in value for character in ("\n", "\r", "\t")):
    raise SystemExit("DEFENSECLAW_HOME must be an absolute path")
print(os.path.abspath(value))
PY
)" || { printf '%s\n' "DEFENSECLAW_HOME must be an absolute stable controller path; no changes were made." >&2; exit 1; }
readonly CONTROLLER_HOME
unset CONTROLLER_HOME_INPUT
DEFENSECLAW_HOME="${CONTROLLER_HOME}"
readonly DEFENSECLAW_VENV="${DEFENSECLAW_HOME}/.venv"
readonly INSTALL_DIR="${HOME}/.local/bin"
if [[ -n "${DEFENSECLAW_CONFIG+x}" ]]; then
    CONFIG_OVERRIDE_EXPLICIT=1
else
    CONFIG_OVERRIDE_EXPLICIT=0
fi
CONFIG_PATH="${DEFENSECLAW_CONFIG:-${CONTROLLER_HOME}/config.yaml}"
DATA_DIR="${CONTROLLER_HOME}"
if [[ -n "${OPENCLAW_HOME+x}" ]]; then
    OPENCLAW_HOME_EXPLICIT=1
else
    OPENCLAW_HOME_EXPLICIT=0
fi
OPENCLAW_HOME="${OPENCLAW_HOME:-${HOME}/.openclaw}"
readonly BACKUP_ROOT="${DEFENSECLAW_HOME}/backups"
readonly BRIDGE_PHASE1_STATE_NAMES_JSON='[".env",".migration_state.json","guardrail_runtime.json","device.key","active_connector.json","codex_backup.json","claudecode_backup.json","zeptoclaw_backup.json","codex_config_backup.json","codex_env.sh","codex.env","policies","connector_backups","hooks",".upgrade-shims","observability-stack"]'
readonly REPO="cisco-ai-defense/defenseclaw"
readonly UPGRADE_PROTOCOL_VERSION=2
readonly OBSERVABILITY_V8_HARD_CUT_VERSION="0.8.5"
readonly COSIGN_BOOTSTRAP_VERSION="2.6.3"
readonly COSIGN_BOOTSTRAP_MAX_BYTES="209715200"
readonly UPGRADE_MANIFEST_NAME="upgrade-manifest.json"
readonly RELEASE_PROVENANCE_NAME="release-provenance.json"
readonly HISTORICAL_BOOTSTRAP_MCP_SCANNER_CONSTRAINT='cisco-ai-mcp-scanner @ https://files.pythonhosted.org/packages/5d/74/6e72cbd496c0d33dfab1b4aee62792620236e63cccf278a8c896c6feb740/cisco_ai_mcp_scanner-4.7.2-py3-none-any.whl#sha256=6ed0b8ced168886f572aec30a971c7b0e2e1de7eea489d3821627184fd271ac8'
# MCP Scanner 4.7.2 declares this exact LiteLLM version. Keep the historical
# bootstrap graph metadata-consistent: uv overrides can force a different
# version to resolve, but the resulting environment then fails `uv pip check`.
readonly HISTORICAL_BOOTSTRAP_LITELLM_CONSTRAINT='litellm @ https://files.pythonhosted.org/packages/75/80/caeb4cdcad96451ba83ad3ba2a9da08b1e1a915fa845c489f56ea044488b/litellm-1.83.7-py3-none-any.whl#sha256=5784a1d9a9a4a8acd6ca1e347003a5e2e1b3c749b4d41e7da4904577adade111'
# Bound every remaining transitive choice to packages that existed when the
# immutable 0.8.5 hard-cut release was published. This is not a full hash lock,
# but later PyPI uploads cannot silently change the historical bootstrap graph.
readonly HISTORICAL_BOOTSTRAP_EXCLUDE_NEWER='2026-07-18T19:02:08Z'
readonly UPGRADE_RECOVERY_ROOT="${DEFENSECLAW_HOME}/.upgrade-recovery"
readonly UPGRADE_LOCK_FILE="${UPGRADE_RECOVERY_ROOT}/upgrade.lock"
readonly UPGRADE_ADVISORY_LOCK_FILE="${UPGRADE_RECOVERY_ROOT}/upgrade.advisory.lock"
UPGRADE_LOCK_TOKEN=""
UPGRADE_ADVISORY_LOCK_HELD=0
UPGRADE_ADVISORY_LOCK_OPEN=0
UPGRADE_RECOVERY_ROOT_CREATED=0
UPGRADE_ADVISORY_LOCK_CREATED=0
UPGRADE_RECOVERY_ROOT_DEVICE=""
UPGRADE_RECOVERY_ROOT_INODE=""
UPGRADE_ADVISORY_LOCK_DEVICE=""
UPGRADE_ADVISORY_LOCK_INODE=""
BRIDGE_PHASE1_RECOVERY_TERMINAL_CONTROLLER=""
BRIDGE_PHASE1_RECOVERY_TERMINAL_VERSION=""

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

version_lt() {
    python3 - "$1" "$2" <<'PY'
import sys


def parse(value):
    return tuple(int(part) for part in value.split("."))


raise SystemExit(0 if parse(sys.argv[1]) < parse(sys.argv[2]) else 1)
PY
}

version_gte() {
    ! version_lt "$1" "$2"
}

# Keep one bounded, fail-closed parser for every phase-one gateway.pid
# decision, including crash recovery. Published gateways write a JSON pidInfo
# object; legacy integer files remain supported for older/manual installs.
GATEWAY_PID_PARSER="$(cat <<'PY'
import json
import os
import re
import stat
import subprocess
import sys

MAX_PID_FILE_BYTES = 4096
JSON_FIELDS = {"pid", "executable", "start_time", "start_identity"}


def _process_executable(pid):
    if sys.platform.startswith("linux"):
        return os.readlink(f"/proc/{pid}/exe")
    if sys.platform == "darwin":
        completed = subprocess.run(
            ["/bin/ps", "-p", str(pid), "-o", "comm="],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        value = (completed.stdout or "").strip()
        if completed.returncode != 0 or not value:
            raise RuntimeError("gateway process executable is unavailable")
        return value
    raise RuntimeError("gateway process executable verification is unsupported")


def _process_start_identity(pid):
    if sys.platform.startswith("linux"):
        with open(f"/proc/{pid}/stat", encoding="utf-8") as stream:
            payload = stream.read(65536)
        closing = payload.rfind(")")
        if closing < 0:
            raise RuntimeError("gateway process start identity is malformed")
        fields = payload[closing + 1 :].split()
        if len(fields) < 20:
            raise RuntimeError("gateway process start identity is incomplete")
        return fields[19]
    if sys.platform == "darwin":
        completed = subprocess.run(
            ["/bin/ps", "-p", str(pid), "-o", "lstart="],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        value = (completed.stdout or "").strip()
        if completed.returncode != 0 or not value:
            raise RuntimeError("gateway process start identity is unavailable")
        return value
    return ""


def _same_executable(observed, expected):
    expected_real = os.path.realpath(expected)
    if sys.platform.startswith("linux"):
        return os.path.realpath(observed) == expected_real
    if sys.platform == "darwin":
        expected_name = os.path.basename(expected_real)
        observed_name = os.path.basename(observed)
        return observed == expected_real or observed_name == expected_name or observed.endswith(expected_name)
    return False


def inspect_gateway_pid(path, expected_executable):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return "missing", 0
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError("gateway PID custody is not a regular file")
    if info.st_uid != os.geteuid() or not 0 < info.st_size <= MAX_PID_FILE_BYTES:
        raise RuntimeError("gateway PID custody is not bounded and current-user-owned")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not os.path.samestat(info, opened):
            raise RuntimeError("gateway PID custody changed while opening")
        payload = os.read(descriptor, MAX_PID_FILE_BYTES + 1)
    finally:
        os.close(descriptor)
    if not payload or len(payload) > MAX_PID_FILE_BYTES:
        raise RuntimeError("gateway PID custody is empty or oversized")
    try:
        text = payload.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise RuntimeError("gateway PID custody is not UTF-8") from exc

    executable = ""
    start_identity = ""
    if re.fullmatch(r"[1-9][0-9]*", text):
        pid = int(text)
    else:
        try:
            record = json.loads(text)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("gateway PID custody is neither legacy integer nor JSON pidInfo") from exc
        if not isinstance(record, dict) or not set(record).issubset(JSON_FIELDS) or "pid" not in record:
            raise RuntimeError("gateway JSON PID custody has an invalid schema")
        pid = record.get("pid")
        executable = record.get("executable", "")
        start_time = record.get("start_time", 0)
        start_identity = record.get("start_identity", "")
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            raise RuntimeError("gateway JSON PID custody has an invalid pid")
        if not isinstance(executable, str) or not executable or not os.path.isabs(executable):
            raise RuntimeError("gateway JSON PID custody has an invalid executable")
        if not isinstance(start_time, int) or isinstance(start_time, bool) or start_time < 0:
            raise RuntimeError("gateway JSON PID custody has an invalid start_time")
        if not isinstance(start_identity, str):
            raise RuntimeError("gateway JSON PID custody has an invalid start_identity")

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return "dead", pid
    except PermissionError as exc:
        raise RuntimeError("gateway PID ownership cannot be verified") from exc

    expected_info = os.lstat(expected_executable)
    if stat.S_ISLNK(expected_info.st_mode) or not stat.S_ISREG(expected_info.st_mode):
        raise RuntimeError("expected gateway executable is not a regular file")
    observed_executable = _process_executable(pid)
    if not _same_executable(observed_executable, expected_executable):
        raise RuntimeError("gateway PID identifies an unrelated live executable")
    if executable and os.path.realpath(executable) != os.path.realpath(expected_executable):
        raise RuntimeError("gateway JSON PID executable does not match the managed gateway")
    if start_identity and _process_start_identity(pid) != start_identity:
        raise RuntimeError("gateway JSON PID start identity does not match the live process")
    return "live", pid


def main():
    if len(sys.argv) != 3:
        raise RuntimeError("gateway PID parser requires path and expected executable")
    state, pid = inspect_gateway_pid(sys.argv[1], sys.argv[2])
    print(f"{state}\t{pid}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"gateway PID validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
PY
)"

# One bounded, content-addressed identity for the source controller venv.
# Moving the tree into same-filesystem custody preserves this identity; a
# same-version replacement does not satisfy it.
VENV_IDENTITY_PARSER="$(cat <<'PY'
import hashlib
import json
import os
import stat


def venv_identity(root):
    root = os.path.abspath(root)
    digest = hashlib.sha256()
    node_count = 0
    byte_count = 0

    def visit(path, relative):
        nonlocal node_count, byte_count
        node_count += 1
        if node_count > 100000:
            raise RuntimeError("managed source venv exceeds its identity node bound")
        info = os.lstat(path)
        if info.st_uid != os.geteuid():
            raise RuntimeError("managed source venv contains a foreign-owned member")
        item = {"path": relative, "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid}
        if stat.S_ISLNK(info.st_mode):
            item.update(kind="symlink", target=os.readlink(path))
        elif stat.S_ISREG(info.st_mode):
            byte_count += info.st_size
            if byte_count > 4 * 1024 * 1024 * 1024:
                raise RuntimeError("managed source venv exceeds its identity byte bound")
            value = hashlib.sha256()
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
            try:
                opened = os.fstat(descriptor)
                if not os.path.samestat(info, opened):
                    raise RuntimeError("managed source venv member changed while hashing")
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    value.update(chunk)
            finally:
                os.close(descriptor)
            item.update(kind="file", size=info.st_size, sha256=value.hexdigest())
        elif stat.S_ISDIR(info.st_mode):
            item["kind"] = "directory"
        else:
            raise RuntimeError("managed source venv contains an unsupported member")
        digest.update(json.dumps(item, sort_keys=True, separators=(",", ":")).encode())
        digest.update(b"\n")
        if item["kind"] == "directory":
            with os.scandir(path) as entries:
                children = sorted(entries, key=lambda entry: entry.name)
            for child in children:
                child_relative = child.name if relative == "." else f"{relative}/{child.name}"
                visit(child.path, child_relative)

    visit(root, ".")
    return digest.hexdigest()
PY
)"

gateway_pid_status() {
    python3 -c "${GATEWAY_PID_PARSER}" "$1" "$2"
}

preflight_python_wheel() {
    local wheel="$1"
    local uv_bin
    local -a dependency_args=(--only-binary litellm)
    uv_bin="$(command -v uv 2>/dev/null || true)"
    [[ -z "${uv_bin}" ]] \
        && die "uv not found on PATH — cannot update Python CLI. Install uv, then re-run the upgrade."

    local preflight_python="${DEFENSECLAW_VENV}/bin/python"
    if [[ ! -x "${preflight_python}" ]]; then
        local preflight_venv="${STAGING_DIR}/wheel-preflight-venv"
        env -u UV_CONSTRAINT -u UV_OVERRIDE -u UV_EXCLUDE_NEWER \
            "${uv_bin}" --no-config venv "${preflight_venv}" --python 3.12 --quiet \
            || die "Could not create Python CLI preflight environment; no services changed."
        preflight_python="${preflight_venv}/bin/python"
    fi

    case "${RELEASE_VERSION}" in
        0.8.4|0.8.5)
            prepare_historical_bootstrap_constraints
            dependency_args+=(
                --constraints "${HISTORICAL_BOOTSTRAP_CONSTRAINTS_FILE}"
                --exclude-newer "${HISTORICAL_BOOTSTRAP_EXCLUDE_NEWER}"
            )
            ;;
    esac
    step "Resolving Python CLI dependencies ..."
    env -u UV_CONSTRAINT -u UV_OVERRIDE -u UV_EXCLUDE_NEWER \
        "${uv_bin}" --no-config pip install \
        --python "${preflight_python}" --dry-run --quiet \
        "${dependency_args[@]}" "${wheel}" \
        || die "Python CLI wheel dependencies are unsatisfiable; no services changed."
    ok "Python CLI dependency preflight passed"
}

begin_release_upgrade_receipt() {
    [[ "${BRIDGE_PHASE1}" -ne 1 && "${CURRENT_VERSION}" != "unknown" \
        && -n "${RELEASE_PROVENANCE_FILE}" ]] || return 0

    local source_python="${DEFENSECLAW_VENV}/bin/python"
    [[ -x "${source_python}" ]] \
        || die "The provenance-authenticated source controller cannot create a durable upgrade receipt. No services changed."
    [[ "${CHECKSUMS_SIGNATURE_VERIFIED}" -eq 1 ]] \
        || die "The modern release artifacts were not authenticated; no upgrade receipt or service mutation was attempted."

    local receipt_path receipt_name
    receipt_path="$(
        DEFENSECLAW_HOME="${DATA_DIR}" "${source_python}" -I -B - \
            "${DATA_DIR}" "${CURRENT_VERSION}" "${RELEASE_VERSION}" <<'PY'
import os
import sys

from defenseclaw.upgrade_receipt import (
    begin_upgrade_receipt,
    finalize_interrupted_upgrade_receipts,
)

data_dir, source_version, target_version = sys.argv[1:]
finalize_interrupted_upgrade_receipts(data_dir, current_version=source_version)
receipt = begin_upgrade_receipt(
    data_dir,
    from_version=source_version,
    target_version=target_version,
    artifacts_verified=True,
)
print(os.fspath(receipt))
PY
    )" || die "Could not create the durable upgrade compliance receipt; no services changed."
    receipt_name="${receipt_path#"${DATA_DIR}/.upgrade-receipts/"}"
    [[ -n "${receipt_path}" \
        && "${receipt_path}" == "${DATA_DIR}/.upgrade-receipts/"* \
        && "${receipt_name}" != */* \
        && "${receipt_name}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}[.]json$ ]] \
        || die "The durable upgrade receipt escaped the managed controller directory; no services changed."
    UPGRADE_RECEIPT_PATH="${receipt_path}"
    UPGRADE_RECEIPT_FAILURE_CODE="install_failed"
    ok "Durable upgrade receipt committed before mutation"
}

finish_release_upgrade_receipt() {
    local status="$1" failure_code="${2:-}"
    [[ -n "${UPGRADE_RECEIPT_PATH}" ]] || return 0
    DEFENSECLAW_HOME="${DATA_DIR}" "${VENV_PYTHON}" -I -B - \
        "${UPGRADE_RECEIPT_PATH}" "${status}" "${failure_code}" <<'PY'
from pathlib import Path
import sys

from defenseclaw import upgrade_receipt

path = Path(sys.argv[1])
status, failure_code = sys.argv[2:]
if status == "succeeded":
    supersede = getattr(upgrade_receipt, "supersede_prior_upgrade_receipts", None)
    if supersede is not None:
        supersede(path)
upgrade_receipt.complete_upgrade_receipt(
    path,
    status=status,
    failure_code=failure_code,
)
PY
    local transition_status=$?
    [[ "${transition_status}" -eq 0 ]] || return "${transition_status}"
    UPGRADE_RECEIPT_TERMINAL=1
}

recover_interrupted_phase_two() {
    local journal_root="${DEFENSECLAW_HOME}/.upgrade-recovery"
    local journal="${journal_root}/phase-two-active.json"
    [[ -e "${journal}" || -L "${journal}" ]] || return 0
    [[ "${PLAN_ONLY}" -eq 0 ]] \
        || die "An interrupted hard-cut recovery is active. Re-run without --plan so the authenticated 0.8.4 bridge can be restored first."

    section "Recovering Interrupted Hard-Cut Upgrade"
    local recovery_fields wheel expected_digest receipt_status recorded_config_path uv_bin venv_python
    recovery_fields="$(python3 - "${journal}" "${DEFENSECLAW_HOME}" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

journal = Path(sys.argv[1])
recovery_home = Path(os.path.abspath(os.path.expanduser(sys.argv[2])))
root = journal.parent
root_info = root.lstat()
info = journal.lstat()
if root != recovery_home / ".upgrade-recovery":
    raise SystemExit("phase-two recovery journal escaped DEFENSECLAW_HOME")
if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
    raise SystemExit("phase-two recovery root is unsafe")
if stat.S_IMODE(root_info.st_mode) != 0o700 or root_info.st_uid != os.getuid():
    raise SystemExit("phase-two recovery root is not owner-only")
if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
    raise SystemExit("phase-two recovery journal is unsafe")
if stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid() or not 0 < info.st_size <= 65536:
    raise SystemExit("phase-two recovery journal is not bounded and owner-only")
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(journal, flags)
try:
    opened = os.fstat(fd)
    if not os.path.samestat(info, opened):
        raise SystemExit("phase-two recovery journal changed while opening")
    raw = os.read(fd, 65537)
finally:
    os.close(fd)
if not raw or len(raw) > 65536:
    raise SystemExit("phase-two recovery journal is invalid")
document = json.loads(raw)
required = {
    "schema_version", "source_version", "source_gateway_was_running",
    "local_bundle_mutation_intent", "target_version", "os_name", "recovery_home", "data_dir",
    "backup_dir", "receipt_path", "release_provenance_sha256", "release_provenance",
    "receipt_provenance_binding_sha256", "rollback_wheel_path", "rollback_wheel_sha256",
    "rollback_gateway_path", "rollback_gateway_sha256", "active_gateway_path",
    "gateway_snapshot", "state_files", "backup_root_snapshot",
}
if not isinstance(document, dict) or set(document) != required or document.get("schema_version") != 4:
    raise SystemExit("phase-two recovery journal schema is invalid")
if not isinstance(document.get("source_gateway_was_running"), bool):
    raise SystemExit("phase-two recovery journal lacks source gateway state")
if not isinstance(document.get("local_bundle_mutation_intent"), bool):
    raise SystemExit("phase-two recovery journal lacks bundle mutation intent")
semver = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
source = document.get("source_version")
target = document.get("target_version")
recorded_recovery_home = document.get("recovery_home")
data_dir = document.get("data_dir")
backup_dir = document.get("backup_dir")
receipt_path = document.get("receipt_path")
wheel = document.get("rollback_wheel_path")
digest = document.get("rollback_wheel_sha256")
provenance_digest = document.get("release_provenance_sha256")
receipt_binding = document.get("receipt_provenance_binding_sha256")
values = (
    source, target, recorded_recovery_home, data_dir, backup_dir, receipt_path,
    wheel, digest, provenance_digest, receipt_binding,
)
if not all(isinstance(value, str) and value and "\n" not in value and "\r" not in value for value in values):
    raise SystemExit("phase-two recovery journal contains invalid scalar values")
if (
    not semver.fullmatch(source)
    or not semver.fullmatch(target)
    or not re.fullmatch(r"[0-9a-f]{64}", digest)
    or not re.fullmatch(r"[0-9a-f]{64}", provenance_digest)
    or not re.fullmatch(r"[0-9a-f]{64}", receipt_binding)
):
    raise SystemExit("phase-two recovery journal contains invalid identities")
provenance = document.get("release_provenance")
top = {
    "schema_version", "release_version", "source_commit", "source_tree",
    "policy_commit", "policy_tree", "release_source_map_sha256",
    "source_install_identity", "bridge",
}
identity_keys = {
    "schema_version", "source_release", "source_install_compatibility_epoch",
    "runtime_config_version",
}
bridge_keys = {"version", "commit", "tree", "checksums_sha256"}
if not isinstance(provenance, dict) or set(provenance) != top or provenance.get("schema_version") != 1:
    raise SystemExit("phase-two release provenance is not closed schema 1")
identity = provenance.get("source_install_identity")
bridge = provenance.get("bridge")
if not isinstance(identity, dict) or set(identity) != identity_keys:
    raise SystemExit("phase-two release provenance source identity is invalid")
if not isinstance(bridge, dict) or set(bridge) != bridge_keys:
    raise SystemExit("phase-two release provenance bridge identity is invalid")
if (
    provenance.get("release_version") != target
    or identity.get("source_release") != target
    or identity.get("schema_version") != 1
    or bridge.get("version") != "0.8.4"
    or source != bridge.get("version")
):
    raise SystemExit("phase-two release provenance identity differs")
sha1_values = (
    provenance.get("source_commit"), provenance.get("source_tree"),
    provenance.get("policy_commit"), provenance.get("policy_tree"),
    bridge.get("commit"), bridge.get("tree"),
)
sha256_values = (provenance.get("release_source_map_sha256"), bridge.get("checksums_sha256"))
if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value) for value in sha1_values):
    raise SystemExit("phase-two release provenance Git identity is invalid")
if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in sha256_values):
    raise SystemExit("phase-two release provenance digest identity is invalid")
epoch = identity.get("source_install_compatibility_epoch")
runtime = identity.get("runtime_config_version")
if target == "0.8.5":
    if type(epoch) is not int or epoch != 2 or type(runtime) is not int or runtime != 8:
        raise SystemExit("phase-two release provenance lacks the exact 0.8.5 identity")
elif type(epoch) is not int or epoch < 2 or type(runtime) is not int or runtime < 8:
    raise SystemExit("phase-two release provenance reuses a pre-hard-cut identity")
canonical_provenance = (json.dumps(provenance, indent=2, sort_keys=True) + "\n").encode()
if hashlib.sha256(canonical_provenance).hexdigest() != provenance_digest:
    raise SystemExit("phase-two release provenance digest changed")
recorded_recovery_home = Path(os.path.abspath(os.path.expanduser(recorded_recovery_home)))
if recorded_recovery_home != recovery_home:
    raise SystemExit("phase-two recovery journal targets a different controller home")
data_dir = Path(os.path.abspath(os.path.expanduser(data_dir)))
backup_dir = Path(os.path.abspath(os.path.expanduser(backup_dir)))
receipt_path = Path(os.path.abspath(os.path.expanduser(receipt_path)))
wheel = Path(os.path.abspath(os.path.expanduser(wheel)))
state_files = document.get("state_files")
snapshot_fields = {"active_path", "backup_path", "existed", "sha256", "mode", "windows_security"}
if (
    not isinstance(state_files, list)
    or len(state_files) != 7
    or any(not isinstance(item, dict) or set(item) != snapshot_fields for item in state_files)
):
    raise SystemExit("phase-two recovery state inventory is invalid")
state_paths = [item.get("active_path") for item in state_files]
if any(not isinstance(path, str) or not os.path.isabs(path) for path in state_paths):
    raise SystemExit("phase-two recovery state paths are invalid")
config_path = Path(os.path.abspath(state_paths[0]))
expected_state_paths = [
    str(config_path),
    str(config_path) + ".pre-observability-migration.bak",
    str(config_path) + ".lock",
    str(config_path) + ".tmp-f3395",
    str(data_dir / ".env"),
    str(data_dir / ".env.lock"),
    str(data_dir / ".migration_state.json"),
]
if [os.path.abspath(path) for path in state_paths] != expected_state_paths:
    raise SystemExit("phase-two recovery state inventory is inconsistent")
if backup_dir.parent != data_dir / "backups":
    raise SystemExit("phase-two recovery backup escaped the managed backup root")
backup_root_snapshot = document.get("backup_root_snapshot")
directory_snapshot_fields = {
    "active_path", "device", "inode", "mode",
    "preexisting_recovery_entries", "windows_security",
}
if not isinstance(backup_root_snapshot, dict) or set(backup_root_snapshot) != directory_snapshot_fields:
    raise SystemExit("phase-two recovery backup-root snapshot is invalid")
backup_root_path = backup_root_snapshot.get("active_path")
preexisting = backup_root_snapshot.get("preexisting_recovery_entries")
if (
    not isinstance(backup_root_path, str)
    or Path(os.path.abspath(backup_root_path)) != data_dir / "backups"
    or not isinstance(backup_root_snapshot.get("device"), int)
    or isinstance(backup_root_snapshot.get("device"), bool)
    or backup_root_snapshot["device"] < 0
    or not isinstance(backup_root_snapshot.get("inode"), int)
    or isinstance(backup_root_snapshot.get("inode"), bool)
    or backup_root_snapshot["inode"] <= 0
    or not isinstance(backup_root_snapshot.get("mode"), int)
    or isinstance(backup_root_snapshot.get("mode"), bool)
    or not isinstance(preexisting, list)
    or len(preexisting) > 256
):
    raise SystemExit("phase-two recovery backup-root snapshot is inconsistent")
parsed_preexisting = []
for entry in preexisting:
    if not isinstance(entry, dict) or set(entry) != {"name", "device", "inode"}:
        raise SystemExit("phase-two recovery backup-root inventory is invalid")
    name, device, inode = entry.get("name"), entry.get("device"), entry.get("inode")
    if (
        not isinstance(name, str)
        or not re.fullmatch(r"observability-v8-[0-9a-f]{32}", name)
        or not isinstance(device, int)
        or isinstance(device, bool)
        or device < 0
        or not isinstance(inode, int)
        or isinstance(inode, bool)
        or inode <= 0
    ):
        raise SystemExit("phase-two recovery backup-root inventory is invalid")
    parsed_preexisting.append((name, device, inode))
if parsed_preexisting != sorted(set(parsed_preexisting)) or len({item[0] for item in parsed_preexisting}) != len(parsed_preexisting):
    raise SystemExit("phase-two recovery backup-root inventory is inconsistent")
custody = backup_dir / "hard-cut-rollback"
try:
    wheel.relative_to(custody)
except ValueError as exc:
    raise SystemExit("phase-two bridge wheel escaped retained custody") from exc
if receipt_path.parent != data_dir / ".upgrade-receipts":
    raise SystemExit("phase-two receipt escaped the private queue")
wheel_info = wheel.lstat()
if stat.S_ISLNK(wheel_info.st_mode) or not stat.S_ISREG(wheel_info.st_mode):
    raise SystemExit("retained bridge wheel is unsafe")
actual = hashlib.sha256(wheel.read_bytes()).hexdigest()
if actual != digest.lower():
    raise SystemExit("retained bridge wheel digest mismatch")
receipt_info = receipt_path.lstat()
if stat.S_ISLNK(receipt_info.st_mode) or not stat.S_ISREG(receipt_info.st_mode) or not 0 < receipt_info.st_size <= 16384:
    raise SystemExit("phase-two receipt is unsafe")
receipt = json.loads(receipt_path.read_bytes())
if receipt.get("from_version") != source or receipt.get("target_version") != target:
    raise SystemExit("phase-two receipt identity mismatch")
binding_payload = {
    "schema_version": 1,
    "receipt_id": receipt.get("receipt_id"),
    "source_version": source,
    "target_version": target,
    "release_provenance_sha256": provenance_digest,
}
expected_binding = hashlib.sha256(
    json.dumps(binding_payload, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()
if expected_binding != receipt_binding:
    raise SystemExit("phase-two receipt provenance binding changed")
status = receipt.get("status")
if status in {"succeeded", "rolled_back"}:
    source_was_running = document["source_gateway_was_running"]
    active_gateway = Path(os.path.abspath(os.path.expanduser(document["active_gateway_path"])))
    expected_gateway = Path.home() / ".local" / "bin" / "defenseclaw-gateway"
    if active_gateway != expected_gateway:
        raise SystemExit("terminal phase-two journal targets a different gateway")
    venv_python = recorded_recovery_home / ".venv" / "bin" / "python"
    try:
        active_gateway_info = active_gateway.lstat()
    except OSError as exc:
        raise SystemExit("terminal phase-two gateway is missing") from exc
    if (
        not venv_python.is_file()
        or stat.S_ISLNK(active_gateway_info.st_mode)
        or not stat.S_ISREG(active_gateway_info.st_mode)
    ):
        raise SystemExit("terminal phase-two installed artifacts are missing")
    expected_version = target if status == "succeeded" else source
    gateway_environment = os.environ.copy()
    gateway_environment["DEFENSECLAW_HOME"] = str(data_dir)
    gateway_environment["DEFENSECLAW_CONFIG"] = str(config_path)
    gateway_version = subprocess.run(
        [str(active_gateway), "--version"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
        env=gateway_environment,
    )
    gateway_output = (gateway_version.stdout or "") + (gateway_version.stderr or "")
    reported_versions = re.findall(
        r"(?<![0-9A-Za-z.])(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?![0-9A-Za-z.])",
        gateway_output,
    )
    if gateway_version.returncode != 0 or reported_versions != [expected_version]:
        raise SystemExit("terminal phase-two gateway version is not proven")
    cli_version = subprocess.run(
        [str(venv_python), "-I", "-B", "-c", "from defenseclaw import __version__; print(__version__)"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
        env=gateway_environment,
    )
    if cli_version.returncode != 0 or (cli_version.stdout or "").strip() != expected_version:
        raise SystemExit("terminal phase-two CLI version is not proven")
    gateway_status = subprocess.run(
        [str(active_gateway), "status"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
        env=gateway_environment,
    )
    expected_running = status == "succeeded" or source_was_running
    if expected_running != (gateway_status.returncode == 0):
        raise SystemExit("terminal phase-two gateway running state is not proven")
    journal.unlink()
    directory_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    print("terminal")
    raise SystemExit
if status != "pending":
    raise SystemExit("phase-two receipt is terminal without a recoverable outcome")
print(str(wheel))
print(digest.lower())
print(status)
print(str(config_path))
PY
)" || die "Could not validate the interrupted phase-two recovery journal; no recovery mutation was attempted."

    wheel="$(printf '%s\n' "${recovery_fields}" | sed -n '1p')"
    if [[ "${wheel}" == "terminal" ]]; then
        ok "Removed a stale terminal phase-two recovery journal"
        return 0
    fi
    expected_digest="$(printf '%s\n' "${recovery_fields}" | sed -n '2p')"
    receipt_status="$(printf '%s\n' "${recovery_fields}" | sed -n '3p')"
    recorded_config_path="$(printf '%s\n' "${recovery_fields}" | sed -n '4p')"
    [[ "${receipt_status}" == "pending" && -n "${wheel}" && -n "${expected_digest}" \
       && -n "${recorded_config_path}" ]] \
        || die "Interrupted phase-two recovery journal did not yield a pending bridge plan."

    uv_bin="$(command -v uv 2>/dev/null || true)"
    [[ -n "${uv_bin}" ]] \
        || die "uv is required to bootstrap the retained 0.8.4 recovery controller."
    venv_python="${DEFENSECLAW_VENV}/bin/python"
    python3 - "${journal_root}/phase-two-mutator.lease" "${uv_bin}" \
        "${DEFENSECLAW_VENV}" "${venv_python}" "${wheel}" "${expected_digest}" <<'PY' \
        || die "Could not bootstrap the retained 0.8.4 controller under the phase-two mutator lease."
import fcntl
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys

lease, uv, venv, venv_python, wheel = map(Path, sys.argv[1:6])
expected_digest = sys.argv[6]
info = lease.lstat()
if (
    stat.S_ISLNK(info.st_mode)
    or not stat.S_ISREG(info.st_mode)
    or info.st_uid != os.getuid()
    or stat.S_IMODE(info.st_mode) != 0o600
):
    raise SystemExit("phase-two mutator lease is unsafe")
flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(lease, flags)
try:
    opened = os.fstat(descriptor)
    if not os.path.samestat(info, opened):
        raise SystemExit("phase-two mutator lease changed while opening")
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    if hashlib.sha256(wheel.read_bytes()).hexdigest() != expected_digest:
        raise SystemExit("retained bridge wheel changed before recovery bootstrap")
    if not venv_python.is_file():
        raise SystemExit("managed bridge environment is missing during recovery")
    uv_environment = os.environ.copy()
    for name in ("UV_CONSTRAINT", "UV_OVERRIDE", "UV_EXCLUDE_NEWER"):
        uv_environment.pop(name, None)
    subprocess.run(
        [
            str(uv), "--no-config", "pip", "install", "--python",
            str(venv_python), "--quiet", "--offline", "--no-deps", "--reinstall", str(wheel),
        ],
        check=True,
        env=uv_environment,
        pass_fds=(descriptor,),
    )
finally:
    os.close(descriptor)
PY
    DEFENSECLAW_HOME="${CONTROLLER_HOME}" DEFENSECLAW_CONFIG="${recorded_config_path}" \
        "${venv_python}" -I -B -c \
        'from defenseclaw.commands.cmd_upgrade import _recover_interrupted_hard_cut; raise SystemExit(0 if _recover_interrupted_hard_cut() else 1)' \
        || die "The retained 0.8.4 controller could not complete interrupted hard-cut recovery."
    ok "Interrupted phase two rolled back to a healthy authenticated bridge"
}

acquire_upgrade_lock() {
    local lock_claim recovery_root_created recovery_root_device recovery_root_inode
    lock_claim="$(python3 - "${DEFENSECLAW_HOME}" "${UPGRADE_RECOVERY_ROOT}" "${UPGRADE_LOCK_FILE}" "$$" <<'PY'
import atexit
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import time

data_home, recovery_root, lock_path, shell_pid_raw = sys.argv[1:]
shell_pid = int(shell_pid_raw)
uid = os.geteuid()


def require_private_directory(path: str, *, create: bool = False) -> bool:
    created = False
    if create:
        try:
            os.mkdir(path, 0o700)
            created = True
        except FileExistsError:
            pass
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise RuntimeError(f"upgrade recovery path is not a real directory: {path}")
    if info.st_uid != uid or stat.S_IMODE(info.st_mode) & 0o077:
        raise RuntimeError(f"upgrade recovery path is not private to the current user: {path}")
    return created


data_home = os.path.abspath(os.path.expanduser(data_home))
recovery_root = os.path.abspath(recovery_root)
lock_path = os.path.abspath(lock_path)
if not os.path.lexists(data_home):
    parent = os.path.dirname(data_home)
    parent_info = os.lstat(parent)
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or stat.S_ISLNK(parent_info.st_mode)
        or parent_info.st_uid != uid
        or stat.S_IMODE(parent_info.st_mode) & 0o022
    ):
        raise RuntimeError("DEFENSECLAW_HOME parent is unsafe for upgrade state")
    os.mkdir(data_home, 0o700)
data_info = os.lstat(data_home)
if not stat.S_ISDIR(data_info.st_mode) or stat.S_ISLNK(data_info.st_mode):
    raise RuntimeError("DEFENSECLAW_HOME must be a real directory before upgrade")
if data_info.st_uid != uid:
    raise RuntimeError("DEFENSECLAW_HOME is not owned by the current user")
if os.path.dirname(recovery_root) != data_home or os.path.dirname(lock_path) != recovery_root:
    raise RuntimeError("upgrade recovery paths escaped DEFENSECLAW_HOME")
recovery_root_created = require_private_directory(recovery_root, create=True)
recovery_root_info = os.lstat(recovery_root)
recovery_root_claim_complete = False


def clean_abandoned_created_root() -> None:
    if recovery_root_created and not recovery_root_claim_complete:
        try:
            current = os.lstat(recovery_root)
            if os.path.samestat(recovery_root_info, current):
                os.rmdir(recovery_root)
        except OSError:
            pass


atexit.register(clean_abandoned_created_root)


def process_start_identity(pid):
    """Return a precise Linux process identity, or None when unavailable.

    ``/proc/<pid>/stat`` field 22 is the kernel start tick and changes on PID
    reuse. macOS does not expose an equivalently precise, unprivileged value
    here, so callers retain the schema-1 live-PID fail-closed behavior there
    rather than pretending that ``ps lstart`` is a unique identity.
    """
    if not sys.platform.startswith("linux"):
        return None
    try:
        with open(f"/proc/{pid}/stat", "rb") as stream:
            raw = stream.read()
    except (OSError, ValueError):
        return None
    closing_parenthesis = raw.rfind(b")")
    if closing_parenthesis < 0:
        return None
    fields = raw[closing_parenthesis + 2:].split()
    # ``fields`` starts with original field 3 (state), so index 19 is field
    # 22 (starttime). The command itself may contain spaces/parentheses.
    if len(fields) < 20:
        return None
    start_ticks = fields[19]
    if not start_ticks.isdigit() or len(start_ticks) > 32:
        return None
    return "linux:" + start_ticks.decode("ascii")


shell_start_identity = process_start_identity(shell_pid)

token = secrets.token_hex(32)
payload_fields = {
    "schema_version": 1,
    "pid": shell_pid,
    "token": token,
}
if shell_start_identity is not None:
    payload_fields["schema_version"] = 2
    payload_fields["process_start"] = shell_start_identity
payload = json.dumps(
    payload_fields,
    sort_keys=True,
    separators=(",", ":"),
).encode() + b"\n"

for _attempt in range(4):
    try:
        descriptor = os.open(
            lock_path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        created_info = os.fstat(descriptor)
    except FileExistsError:
        stale_descriptor = None
        try:
            stale_descriptor = os.open(
                lock_path,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            opened = os.fstat(stale_descriptor)
            named = os.lstat(lock_path)
            if (
                not stat.S_ISREG(opened.st_mode)
                or stat.S_ISLNK(named.st_mode)
                or not os.path.samestat(opened, named)
            ):
                raise RuntimeError("upgrade lock is not a real file")
            if opened.st_uid != uid or stat.S_IMODE(opened.st_mode) & 0o077:
                raise RuntimeError("upgrade lock is not private to the current user")
            raw = os.read(stale_descriptor, 4097)
            if len(raw) > 4096:
                raise RuntimeError("upgrade lock is too large")
            try:
                current = json.loads(raw)
                pid = current.get("pid")
                current_token = current.get("token")
                schema_version = current.get("schema_version")
                if (
                    schema_version not in (1, 2)
                    or not isinstance(pid, int)
                    or isinstance(pid, bool)
                    or pid < 1
                    or not isinstance(current_token, str)
                    or len(current_token) != 64
                ):
                    raise ValueError("invalid upgrade lock")
                process_start = current.get("process_start")
                legacy_process_identity = False
                if schema_version == 2 and (
                    not isinstance(process_start, str)
                    or not process_start
                    or len(process_start) > 128
                    or "\x00" in process_start
                ):
                    raise ValueError("invalid upgrade lock process identity")
                if schema_version == 2 and not process_start.startswith("linux:"):
                    # Earlier resolver builds stored a second-resolution
                    # ``ps lstart`` value. Preserve its dead-PID cleanup
                    # behavior, but never reclaim it while the PID is live:
                    # it cannot prove against a same-second reuse.
                    legacy_process_identity = True
            except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
                # A claimant may be between O_EXCL and fsync. Never steal a
                # fresh partial claim; an abandoned partial file becomes
                # recoverable after the short initialization window.
                if time.time() - opened.st_mtime < 10:
                    raise RuntimeError("another upgrade is acquiring the recovery lock") from exc
                pid = 0
                schema_version = 0
                process_start = None
                legacy_process_identity = False

            live = False
            if pid:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    live = True
                else:
                    live = True
            if live and schema_version == 2:
                if legacy_process_identity:
                    raise RuntimeError("could not verify the active upgrade process identity")
                observed_start = process_start_identity(pid)
                if observed_start is None:
                    raise RuntimeError("could not verify the active upgrade process identity")
                live = secrets.compare_digest(process_start, observed_start)
            if live:
                raise RuntimeError(f"another DefenseClaw upgrade is active (pid {pid})")

            quarantine = f"{lock_path}.stale-{secrets.token_hex(16)}"
            os.rename(lock_path, quarantine)
            quarantined = os.lstat(quarantine)
            if not os.path.samestat(opened, quarantined):
                if not os.path.lexists(lock_path):
                    os.rename(quarantine, lock_path)
                raise RuntimeError("upgrade lock raced stale-claim cleanup")
            os.unlink(quarantine)
            directory_fd = os.open(recovery_root, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except FileNotFoundError:
            continue
        finally:
            if stale_descriptor is not None:
                os.close(stale_descriptor)
        continue

    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        info = os.lstat(lock_path)
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or not os.path.samestat(created_info, info)
        ):
            raise RuntimeError("created upgrade lock is not a real file")
        if info.st_uid != uid or stat.S_IMODE(info.st_mode) & 0o077:
            raise RuntimeError("created upgrade lock is not private")
        directory_fd = os.open(recovery_root, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        cleanup_descriptor = None
        try:
            cleanup_descriptor = os.open(
                lock_path,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            opened = os.fstat(cleanup_descriptor)
            named = os.lstat(lock_path)
            if os.path.samestat(created_info, opened) and os.path.samestat(opened, named):
                quarantine = f"{lock_path}.abandoned-{secrets.token_hex(16)}"
                os.rename(lock_path, quarantine)
                quarantined = os.lstat(quarantine)
                if os.path.samestat(opened, quarantined):
                    os.unlink(quarantine)
                elif not os.path.lexists(lock_path):
                    os.rename(quarantine, lock_path)
        except OSError:
            pass
        finally:
            if cleanup_descriptor is not None:
                os.close(cleanup_descriptor)
        raise
    print(
        f"{token}\t{int(recovery_root_created)}\t"
        f"{recovery_root_info.st_dev}\t{recovery_root_info.st_ino}"
    )
    recovery_root_claim_complete = True
    break
else:
    raise RuntimeError("could not acquire the DefenseClaw upgrade lock")
PY
)" || die "Could not acquire the private upgrade lock. No installed state changed."
    IFS=$'\t' read -r \
        UPGRADE_LOCK_TOKEN \
        recovery_root_created \
        recovery_root_device \
        recovery_root_inode <<< "${lock_claim}"
    if [[ ! "${UPGRADE_LOCK_TOKEN}" =~ ^[0-9a-f]{64}$ \
          || ! "${recovery_root_created}" =~ ^[01]$ \
          || ! "${recovery_root_device}" =~ ^[0-9]+$ \
          || ! "${recovery_root_inode}" =~ ^[0-9]+$ ]]; then
        UPGRADE_LOCK_TOKEN=""
        die "Could not acquire the private upgrade lock. No installed state changed."
    fi
    UPGRADE_RECOVERY_ROOT_CREATED="${recovery_root_created}"
    UPGRADE_RECOVERY_ROOT_DEVICE="${recovery_root_device}"
    UPGRADE_RECOVERY_ROOT_INODE="${recovery_root_inode}"

    local advisory_claim
    if ! advisory_claim="$(python3 - \
        "${UPGRADE_RECOVERY_ROOT}" \
        "${UPGRADE_ADVISORY_LOCK_FILE}" \
        "${UPGRADE_RECOVERY_ROOT_DEVICE}" \
        "${UPGRADE_RECOVERY_ROOT_INODE}" <<'PY'
import os
import secrets
import stat
import sys

root = os.path.abspath(sys.argv[1])
path = os.path.abspath(sys.argv[2])
expected_root = (int(sys.argv[3]), int(sys.argv[4]))
if os.path.dirname(path) != root:
    raise RuntimeError("upgrade advisory lock escaped recovery custody")
root_info = os.lstat(root)
if (
    not stat.S_ISDIR(root_info.st_mode)
    or stat.S_ISLNK(root_info.st_mode)
    or root_info.st_uid != os.geteuid()
    or stat.S_IMODE(root_info.st_mode) & 0o077
    or (root_info.st_dev, root_info.st_ino) != expected_root
):
    raise RuntimeError("upgrade recovery root is unsafe")

flags = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
created = False
descriptor = None
try:
    try:
        descriptor = os.open(path, flags, 0o600)
        created = True
    except FileExistsError:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    opened = os.fstat(descriptor)
    named = os.lstat(path)
    if (
        not stat.S_ISREG(opened.st_mode)
        or stat.S_ISLNK(named.st_mode)
        or not os.path.samestat(opened, named)
        or opened.st_uid != os.geteuid()
        or stat.S_IMODE(opened.st_mode) & 0o077
    ):
        raise RuntimeError("upgrade advisory lock inode is unsafe")
    print(f"{int(created)}\t{opened.st_dev}\t{opened.st_ino}")
except BaseException:
    if created and descriptor is not None:
        try:
            named = os.lstat(path)
            opened = os.fstat(descriptor)
            if os.path.samestat(opened, named):
                quarantine = f"{path}.abandoned-{secrets.token_hex(16)}"
                os.rename(path, quarantine)
                quarantined = os.lstat(quarantine)
                if not os.path.samestat(opened, quarantined):
                    if not os.path.lexists(path):
                        os.rename(quarantine, path)
                    raise RuntimeError("upgrade advisory lock raced failed acquisition cleanup")
                os.unlink(quarantine)
                root_fd = os.open(root, os.O_RDONLY)
                try:
                    os.fsync(root_fd)
                finally:
                    os.close(root_fd)
        except OSError:
            pass
    raise
finally:
    if descriptor is not None:
        os.close(descriptor)
PY
)"; then
        release_upgrade_lock
        die "Could not prepare the private upgrade mutation lease. No installed state changed."
    fi
    local advisory_created advisory_device advisory_inode
    IFS=$'\t' read -r \
        advisory_created \
        advisory_device \
        advisory_inode <<< "${advisory_claim}"
    if [[ ! "${advisory_created}" =~ ^[01]$ \
          || ! "${advisory_device}" =~ ^[0-9]+$ \
          || ! "${advisory_inode}" =~ ^[0-9]+$ ]]; then
        release_upgrade_lock
        die "Could not prepare the private upgrade mutation lease. No installed state changed."
    fi
    UPGRADE_ADVISORY_LOCK_CREATED="${advisory_created}"
    UPGRADE_ADVISORY_LOCK_DEVICE="${advisory_device}"
    UPGRADE_ADVISORY_LOCK_INODE="${advisory_inode}"

    # Keep a kernel lock on a stable inode in addition to the diagnostic PID
    # record above. Descriptor 9 is inherited by external children, so killing
    # only this shell cannot let a retry race an in-flight uv/copy helper. The
    # kernel releases it only after the last surviving process closes the
    # shared open-file description (or after a reboot kills the whole tree).
    if ! exec 9>>"${UPGRADE_ADVISORY_LOCK_FILE}"; then
        release_upgrade_lock
        die "Could not open the private upgrade mutation lease. No installed state changed."
    fi
    UPGRADE_ADVISORY_LOCK_OPEN=1
    if ! python3 - \
        "${UPGRADE_RECOVERY_ROOT}" \
        "${UPGRADE_ADVISORY_LOCK_FILE}" \
        9 \
        "${UPGRADE_RECOVERY_ROOT_DEVICE}" \
        "${UPGRADE_RECOVERY_ROOT_INODE}" \
        "${UPGRADE_ADVISORY_LOCK_CREATED}" \
        "${UPGRADE_ADVISORY_LOCK_DEVICE}" \
        "${UPGRADE_ADVISORY_LOCK_INODE}" <<'PY'
import fcntl
import os
import stat
import sys

(
    root,
    path,
    descriptor_raw,
    expected_root_device_raw,
    expected_root_inode_raw,
    created_raw,
    expected_device_raw,
    expected_inode_raw,
) = sys.argv[1:]
root = os.path.abspath(root)
path = os.path.abspath(path)
descriptor = int(descriptor_raw)
expected_root = (int(expected_root_device_raw), int(expected_root_inode_raw))
expected_device = int(expected_device_raw)
expected_inode = int(expected_inode_raw)
root_info = os.lstat(root)
if (
    os.path.dirname(path) != root
    or not stat.S_ISDIR(root_info.st_mode)
    or stat.S_ISLNK(root_info.st_mode)
    or root_info.st_uid != os.geteuid()
    or stat.S_IMODE(root_info.st_mode) & 0o077
    or (root_info.st_dev, root_info.st_ino) != expected_root
):
    raise RuntimeError("upgrade recovery root changed before mutation lease acquisition")
opened = os.fstat(descriptor)
named = os.lstat(path)
if (
    not stat.S_ISREG(opened.st_mode)
    or stat.S_ISLNK(named.st_mode)
    or not os.path.samestat(opened, named)
    or opened.st_uid != os.geteuid()
    or stat.S_IMODE(opened.st_mode) & 0o077
    or (opened.st_dev, opened.st_ino) != (expected_device, expected_inode)
):
    raise RuntimeError("upgrade advisory lock inode is unsafe")
try:
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError as exc:
    raise RuntimeError("a surviving upgrade process still holds the mutation lease") from exc
PY
    then
        release_upgrade_lock
        die "Another upgrade process or surviving mutation child is still active. No installed state changed."
    fi
    UPGRADE_ADVISORY_LOCK_HELD=1
}

release_upgrade_lock() {
    # Drop this shell's descriptor before testing/removing a lease it created.
    # Children inherit FD 9, so handing it to the cleanup child would share the
    # same open-file description and make flock falsely succeed while a
    # surviving mutator still owns the lease. The cleanup probe opens a fresh
    # descriptor below; if that probe is blocked, the named inode is retained.
    if [[ "${UPGRADE_ADVISORY_LOCK_OPEN:-0}" -eq 1 ]]; then
        exec 9>&-
    fi
    UPGRADE_ADVISORY_LOCK_OPEN=0

    # The diagnostic PID/token claim remains in place until advisory cleanup
    # finishes, so a cooperative retry cannot enter midway.
    if [[ "${UPGRADE_ADVISORY_LOCK_CREATED:-0}" -eq 1 ]]; then
        python3 - \
            "${UPGRADE_RECOVERY_ROOT}" \
            "${UPGRADE_ADVISORY_LOCK_FILE}" \
            "${UPGRADE_RECOVERY_ROOT_DEVICE:-}" \
            "${UPGRADE_RECOVERY_ROOT_INODE:-}" \
            "${UPGRADE_ADVISORY_LOCK_DEVICE:-}" \
            "${UPGRADE_ADVISORY_LOCK_INODE:-}" <<'PY' >/dev/null 2>&1 || true
import fcntl
import os
import secrets
import stat
import sys
import time

root, advisory_path = map(os.path.abspath, sys.argv[1:3])
expected_root = (int(sys.argv[3]), int(sys.argv[4]))
expected_advisory = (int(sys.argv[5]), int(sys.argv[6]))
uid = os.geteuid()

if os.path.dirname(advisory_path) != root:
    raise RuntimeError("upgrade advisory cleanup escaped recovery custody")

root_info = os.lstat(root)
if (
    not stat.S_ISDIR(root_info.st_mode)
    or stat.S_ISLNK(root_info.st_mode)
    or root_info.st_uid != uid
    or stat.S_IMODE(root_info.st_mode) & 0o077
    or (root_info.st_dev, root_info.st_ino) != expected_root
):
    raise RuntimeError("upgrade recovery root changed before cleanup")

if os.path.lexists(advisory_path):
    descriptor = os.open(
        advisory_path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        named = os.lstat(advisory_path)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_ISLNK(named.st_mode)
            or not os.path.samestat(opened, named)
            or opened.st_uid != uid
            or stat.S_IMODE(opened.st_mode) & 0o077
            or (opened.st_dev, opened.st_ino) != expected_advisory
        ):
            raise RuntimeError("upgrade advisory lock changed before cleanup")
        # The resolver's descriptor was just closed above. A cooperative retry
        # remains behind the diagnostic claim, but an already-open observer can
        # legitimately win the first fresh-descriptor probe. Give a transient
        # holder a short chance to close; retain the inode rather than unlinking
        # it if an inherited mutation child still owns the lease.
        deadline = time.monotonic() + 0.25
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.01)
        quarantine = f"{advisory_path}.released-{secrets.token_hex(16)}"
        os.rename(advisory_path, quarantine)
        quarantined = os.lstat(quarantine)
        if not os.path.samestat(opened, quarantined):
            if not os.path.lexists(advisory_path):
                os.rename(quarantine, advisory_path)
            raise RuntimeError("upgrade advisory lock raced cleanup")
        os.unlink(quarantine)
        directory_fd = os.open(root, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        os.close(descriptor)
PY
    fi

    UPGRADE_ADVISORY_LOCK_HELD=0

    # Release the diagnostic claim only after the advisory lease is gone and
    # its descriptor is closed. Token and inode checks prevent deleting a
    # replacement claim.
    if [[ -n "${UPGRADE_LOCK_TOKEN:-}" ]]; then
        python3 - \
            "${UPGRADE_RECOVERY_ROOT}" \
            "${UPGRADE_LOCK_FILE}" \
            "${UPGRADE_LOCK_TOKEN}" \
            "${UPGRADE_RECOVERY_ROOT_DEVICE:-}" \
            "${UPGRADE_RECOVERY_ROOT_INODE:-}" <<'PY' >/dev/null 2>&1 || true
import json
import os
import secrets
import stat
import sys

root, lock_path, expected_token, expected_device_raw, expected_inode_raw = sys.argv[1:]
root = os.path.abspath(root)
lock_path = os.path.abspath(lock_path)
expected_root = (int(expected_device_raw), int(expected_inode_raw))
if os.path.dirname(lock_path) != root:
    raise RuntimeError("upgrade lock cleanup escaped recovery custody")
root_info = os.lstat(root)
if (
    not stat.S_ISDIR(root_info.st_mode)
    or stat.S_ISLNK(root_info.st_mode)
    or root_info.st_uid != os.geteuid()
    or stat.S_IMODE(root_info.st_mode) & 0o077
    or (root_info.st_dev, root_info.st_ino) != expected_root
):
    raise RuntimeError("upgrade recovery root changed before lock cleanup")

descriptor = os.open(
    lock_path,
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0),
)
try:
    opened = os.fstat(descriptor)
    named = os.lstat(lock_path)
    if (
        not stat.S_ISREG(opened.st_mode)
        or stat.S_ISLNK(named.st_mode)
        or not os.path.samestat(opened, named)
        or opened.st_uid != os.geteuid()
        or stat.S_IMODE(opened.st_mode) & 0o077
    ):
        raise RuntimeError("upgrade lock changed before cleanup")
    raw = os.read(descriptor, 4097)
    if len(raw) > 4096:
        raise RuntimeError("upgrade lock is too large")
    payload = json.loads(raw)
    if payload.get("schema_version") not in (1, 2) or payload.get("token") != expected_token:
        raise RuntimeError("upgrade lock token changed before cleanup")
    quarantine = f"{lock_path}.released-{secrets.token_hex(16)}"
    os.rename(lock_path, quarantine)
    quarantined = os.lstat(quarantine)
    if not os.path.samestat(opened, quarantined):
        if not os.path.lexists(lock_path):
            os.rename(quarantine, lock_path)
        raise RuntimeError("upgrade lock raced cleanup")
    os.unlink(quarantine)
    directory_fd = os.open(root, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
finally:
    os.close(descriptor)
PY
    fi
    UPGRADE_LOCK_TOKEN=""

    # A resolver-created recovery root is removed only if its exact inode is
    # still present and empty. Never rename the root: active journals or a
    # racing retry must remain at the canonical recovery path.
    if [[ "${UPGRADE_RECOVERY_ROOT_CREATED:-0}" -eq 1 ]]; then
        python3 - \
            "${UPGRADE_RECOVERY_ROOT}" \
            "${UPGRADE_RECOVERY_ROOT_DEVICE:-}" \
            "${UPGRADE_RECOVERY_ROOT_INODE:-}" <<'PY' >/dev/null 2>&1 || true
import os
import stat
import sys

root = os.path.abspath(sys.argv[1])
expected_root = (int(sys.argv[2]), int(sys.argv[3]))
parent = os.path.dirname(root)
name = os.path.basename(root)
parent_fd = os.open(parent, os.O_RDONLY)
try:
    current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if (
        not stat.S_ISDIR(current.st_mode)
        or stat.S_ISLNK(current.st_mode)
        or current.st_uid != os.geteuid()
        or stat.S_IMODE(current.st_mode) & 0o077
        or (current.st_dev, current.st_ino) != expected_root
    ):
        raise RuntimeError("upgrade recovery root changed before removal")
    try:
        os.rmdir(name, dir_fd=parent_fd)
    except OSError:
        pass
    else:
        os.fsync(parent_fd)
finally:
    os.close(parent_fd)
PY
    fi

    UPGRADE_ADVISORY_LOCK_CREATED=0
    UPGRADE_RECOVERY_ROOT_CREATED=0
    UPGRADE_RECOVERY_ROOT_DEVICE=""
    UPGRADE_RECOVERY_ROOT_INODE=""
    UPGRADE_ADVISORY_LOCK_DEVICE=""
    UPGRADE_ADVISORY_LOCK_INODE=""
}

register_bridge_phase1_recovery_journal() {
    BRIDGE_RECOVERY_PLAN_ID="$(python3 - \
        "${CONTROLLER_HOME}" \
        "${DATA_DIR}" \
        "${CONFIG_PATH}" \
        "${OPENCLAW_HOME}" \
        "${BACKUP_ROOT}" \
        "${BACKUP_DIR}" \
        "${UPGRADE_RECOVERY_ROOT}" \
        "${CURRENT_VERSION}" \
        "${RELEASE_VERSION}" \
        "${BRIDGE_SOURCE_WAS_RUNNING}" \
        "${BRIDGE_SOURCE_HEALTH_URL}" \
        "${BRIDGE_EXPECTED_GATEWAY_SHA256}" \
        "${BRIDGE_EXPECTED_WHEEL_SHA256}" \
        "${DEFENSECLAW_VENV}" \
        "${VENV_IDENTITY_PARSER}" \
        "${DEFENSECLAW_CONFIG:-}" <<'PY'
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from urllib.parse import urlsplit

(
    recovery_home,
    data_home,
    config_path,
    openclaw_home,
    backup_root,
    backup_dir,
    recovery_root,
    source_version,
    bridge_version,
    source_was_running_raw,
    source_health_url,
    bridge_gateway_sha256,
    bridge_wheel_sha256,
    source_venv,
    venv_identity_parser,
    config_override,
) = sys.argv[1:]
uid = os.geteuid()
venv_identity_namespace = {"__name__": "defenseclaw_venv_identity"}
exec(venv_identity_parser, venv_identity_namespace)
venv_identity = venv_identity_namespace["venv_identity"]


def digest(path: str) -> str:
    value = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def require_directory(path: str, *, private: bool) -> None:
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise RuntimeError(f"recovery custody is not a real directory: {path}")
    if info.st_uid != uid:
        raise RuntimeError(f"recovery custody is not current-user-owned: {path}")
    if private and stat.S_IMODE(info.st_mode) & 0o077:
        raise RuntimeError(f"recovery custody is not private: {path}")


def require_file(path: str) -> None:
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise RuntimeError(f"recovery custody is not a real file: {path}")
    if info.st_uid != uid:
        raise RuntimeError(f"recovery custody is not current-user-owned: {path}")


def directory_identity(path: str) -> dict[str, int]:
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"phase-one identity root is unsafe: {path}")
    return {"device": info.st_dev, "inode": info.st_ino}


def fsync_tree(root: str) -> None:
    directories = []
    for current, names, files in os.walk(root, topdown=True, followlinks=False):
        directories.append(current)
        for name in names:
            candidate = os.path.join(current, name)
            if os.path.islink(candidate):
                continue
        for name in files:
            candidate = os.path.join(current, name)
            if os.path.islink(candidate):
                continue
            info = os.lstat(candidate)
            if not stat.S_ISREG(info.st_mode):
                raise RuntimeError(f"unsupported recovery custody member: {candidate}")
            descriptor = os.open(candidate, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    for directory in reversed(directories):
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


recovery_home = os.path.abspath(os.path.expanduser(recovery_home))
data_home = os.path.abspath(os.path.expanduser(data_home))
config_path = os.path.abspath(os.path.expanduser(config_path))
openclaw_home = os.path.abspath(os.path.expanduser(openclaw_home))
backup_root = os.path.abspath(backup_root)
backup_dir = os.path.abspath(backup_dir)
recovery_root = os.path.abspath(recovery_root)
config_override = os.path.abspath(os.path.expanduser(config_override)) if config_override else ""
if re.fullmatch(r"\d+\.\d+\.\d+", source_version) is None or re.fullmatch(
    r"\d+\.\d+\.\d+", bridge_version
) is None:
    raise RuntimeError("phase-one recovery versions are invalid")
require_directory(recovery_home, private=False)
require_directory(data_home, private=False)
require_directory(recovery_root, private=True)
require_directory(backup_root, private=True)
require_directory(backup_dir, private=True)
if os.path.dirname(backup_dir) != backup_root:
    raise RuntimeError("phase-one backup escaped the private backup root")
if backup_root != os.path.join(recovery_home, "backups"):
    raise RuntimeError("phase-one controller custody escaped the controller home")
if recovery_root != os.path.join(recovery_home, ".upgrade-recovery"):
    raise RuntimeError("phase-one recovery root escaped the controller home")
expected_config = config_override or os.path.join(recovery_home, "config.yaml")
if config_path != expected_config:
    raise RuntimeError("phase-one config path does not match the resolved source configuration")
require_file(config_path)
openclaw_home_existed = os.path.lexists(openclaw_home)
if openclaw_home_existed:
    require_directory(openclaw_home, private=False)
    openclaw_identity_path = openclaw_home
else:
    openclaw_identity_path = os.path.dirname(openclaw_home) or "."
    require_directory(openclaw_identity_path, private=False)
backup_name = os.path.basename(backup_dir)
if not backup_name.startswith("upgrade-") or "/" in backup_name:
    raise RuntimeError("phase-one backup name is invalid")
health = urlsplit(source_health_url)
try:
    health_port = health.port
except ValueError as exc:
    raise RuntimeError("phase-one source health endpoint is invalid") from exc
if (
    health.scheme != "http"
    or health.hostname is None
    or health_port is None
    or not 1 <= health_port <= 65535
    or health.username is not None
    or health.password is not None
    or health.path != "/health"
    or health.query
    or health.fragment
):
    raise RuntimeError("phase-one source health endpoint is invalid")

gateway = os.path.join(backup_dir, "phase1-source-gateway")
require_file(gateway)
bridge_gateway = os.path.join(backup_dir, "phase1-bridge-gateway")
bridge_wheel = os.path.join(
    backup_dir, f"defenseclaw-{bridge_version}-2-py3-none-any.whl"
)
require_file(bridge_gateway)
require_file(bridge_wheel)
if digest(bridge_gateway) != bridge_gateway_sha256 or digest(bridge_wheel) != bridge_wheel_sha256:
    raise RuntimeError("phase-one bridge activation custody digest changed")
for custody_file in (gateway, bridge_gateway, bridge_wheel):
    descriptor = os.open(custody_file, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
backup_descriptor = os.open(backup_dir, os.O_RDONLY)
try:
    os.fsync(backup_descriptor)
finally:
    os.close(backup_descriptor)

journal = os.path.join(recovery_root, "phase-one-active.json")
if os.path.lexists(journal):
    raise RuntimeError("another phase-one recovery journal is active")
plan_id = "phase-one-" + secrets.token_hex(16)
document = {
    "schema_version": 4,
    "kind": "defenseclaw-phase-one-recovery",
    "plan_id": plan_id,
    "recovery_home": recovery_home,
    "data_dir": data_home,
    "config_path": config_path,
    "openclaw_home_existed": openclaw_home_existed,
    "path_identities": {
        "recovery_home": directory_identity(recovery_home),
        "data_dir": directory_identity(data_home),
        "openclaw_home": directory_identity(openclaw_identity_path),
        "config_parent": directory_identity(os.path.dirname(config_path) or "."),
    },
    "source_version": source_version,
    "bridge_version": bridge_version,
    "source_was_running": source_was_running_raw == "1",
    "source_health_url": source_health_url,
    "backup_directory": backup_name,
    "gateway_sha256": digest(gateway),
    "bridge_gateway_sha256": bridge_gateway_sha256,
    "bridge_wheel_sha256": bridge_wheel_sha256,
    "source_venv_identity_sha256": venv_identity(source_venv),
    "state_snapshot_ready": False,
    "state_manifest_sha256": None,
    "state_mutation_started": False,
    "active_snapshot_ready": False,
    "active_manifest_sha256": None,
    "openclaw_home": openclaw_home,
    "config_override": config_override or None,
}
payload = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
candidate = os.path.join(recovery_root, f".{plan_id}.tmp")
descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    with os.fdopen(descriptor, "wb", closefd=True) as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(candidate, journal)
    root_descriptor = os.open(recovery_root, os.O_RDONLY)
    try:
        os.fsync(root_descriptor)
    finally:
        os.close(root_descriptor)
except BaseException:
    try:
        os.unlink(candidate)
    except OSError:
        pass
    raise

with open(journal, "rb") as stream:
    if stream.read() != payload:
        raise RuntimeError("phase-one recovery journal readback mismatch")
print(plan_id)
PY
)" || die "Could not durably register phase-one recovery; no services changed."
    BRIDGE_SOURCE_VENV_IDENTITY_SHA256="$(python3 - \
        "${UPGRADE_RECOVERY_ROOT}/phase-one-active.json" \
        "${BRIDGE_RECOVERY_PLAN_ID}" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    payload = json.load(stream)
value = payload.get("source_venv_identity_sha256")
if payload.get("plan_id") != sys.argv[2] or not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
    raise SystemExit(1)
print(value)
PY
)" || die "Could not read back the bound source venv identity; no services changed."
}

seal_bridge_phase1_state_snapshot_journal() {
    python3 - \
        "${BACKUP_DIR}" \
        "${UPGRADE_RECOVERY_ROOT}" \
        "${BRIDGE_RECOVERY_PLAN_ID}" <<'PY'
import hashlib
import json
import os
import secrets
import stat
import sys

backup_dir = os.path.abspath(sys.argv[1])
recovery_root = os.path.abspath(sys.argv[2])
expected_plan_id = sys.argv[3]
uid = os.geteuid()
journal = os.path.join(recovery_root, "phase-one-active.json")
snapshot_root = os.path.join(backup_dir, "phase1-state")
manifest_path = os.path.join(snapshot_root, "manifest.json")


def digest(path: str) -> str:
    value = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def require_directory(path: str) -> None:
    info = os.lstat(path)
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != uid
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise RuntimeError(f"phase-one snapshot directory is unsafe: {path}")


def require_file(path: str) -> None:
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != uid:
        raise RuntimeError(f"phase-one snapshot file is unsafe: {path}")


require_directory(recovery_root)
require_directory(backup_dir)
require_directory(snapshot_root)
require_file(manifest_path)
if os.path.getsize(manifest_path) > 4 * 1024 * 1024:
    raise RuntimeError("phase-one state manifest exceeds its recovery bound")
directories = []
for current, _names, files in os.walk(snapshot_root, topdown=True, followlinks=False):
    directories.append(current)
    for name in files:
        path = os.path.join(current, name)
        if os.path.islink(path):
            continue
        require_file(path)
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
for directory in reversed(directories):
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

info = os.lstat(journal)
if (
    not stat.S_ISREG(info.st_mode)
    or stat.S_ISLNK(info.st_mode)
    or info.st_uid != uid
    or stat.S_IMODE(info.st_mode) & 0o077
):
    raise RuntimeError("phase-one recovery journal is unsafe")
with open(journal, "rb") as stream:
    payload = json.load(stream)
if (
    payload.get("schema_version") != 4
    or payload.get("kind") != "defenseclaw-phase-one-recovery"
    or payload.get("plan_id") != expected_plan_id
    or payload.get("state_snapshot_ready") is not False
    or payload.get("state_manifest_sha256") is not None
    or payload.get("state_mutation_started") is not False
    or payload.get("active_snapshot_ready") is not False
    or payload.get("active_manifest_sha256") is not None
):
    raise RuntimeError("phase-one recovery journal changed before state seal")
payload["state_snapshot_ready"] = True
payload["state_manifest_sha256"] = digest(manifest_path)
raw = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
candidate = os.path.join(recovery_root, f".{expected_plan_id}.state-{secrets.token_hex(16)}.tmp")
descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    with os.fdopen(descriptor, "wb", closefd=True) as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(candidate, journal)
    root_descriptor = os.open(recovery_root, os.O_RDONLY)
    try:
        os.fsync(root_descriptor)
    finally:
        os.close(root_descriptor)
finally:
    if os.path.lexists(candidate):
        os.unlink(candidate)
PY
    BRIDGE_STATE_SNAPSHOT_READY=1
}

mark_bridge_phase1_state_mutation_started() {
    python3 - "${UPGRADE_RECOVERY_ROOT}" "${BRIDGE_RECOVERY_PLAN_ID}" <<'PY'
import json
import os
import secrets
import stat
import sys

root = os.path.abspath(sys.argv[1])
plan_id = sys.argv[2]
journal = os.path.join(root, "phase-one-active.json")
info = os.lstat(journal)
if (
    not stat.S_ISREG(info.st_mode)
    or stat.S_ISLNK(info.st_mode)
    or info.st_uid != os.geteuid()
    or stat.S_IMODE(info.st_mode) & 0o077
):
    raise RuntimeError("phase-one recovery journal is unsafe before mutation")
with open(journal, encoding="utf-8") as stream:
    payload = json.load(stream)
if (
    payload.get("schema_version") != 4
    or payload.get("kind") != "defenseclaw-phase-one-recovery"
    or payload.get("plan_id") != plan_id
    or payload.get("state_snapshot_ready") is not True
    or payload.get("state_mutation_started") is not False
    or payload.get("active_snapshot_ready") is not False
    or payload.get("active_manifest_sha256") is not None
):
    raise RuntimeError("phase-one mutation journal precondition changed")
payload["state_mutation_started"] = True
raw = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
candidate = os.path.join(root, f".{plan_id}.mutation-{secrets.token_hex(16)}.tmp")
descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    with os.fdopen(descriptor, "wb", closefd=True) as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(candidate, journal)
    root_fd = os.open(root, os.O_RDONLY)
    try:
        os.fsync(root_fd)
    finally:
        os.close(root_fd)
    with open(journal, "rb") as stream:
        if stream.read() != raw:
            raise RuntimeError("phase-one mutation journal readback mismatch")
finally:
    if os.path.lexists(candidate):
        os.unlink(candidate)
PY
}

complete_bridge_phase1_recovery_journal() {
    local expected_plan_id="$1"
    local terminal_controller="${2:-bridge}"
    python3 - "${UPGRADE_RECOVERY_ROOT}" "${expected_plan_id}" "${DEFENSECLAW_VENV}" \
        "${terminal_controller}" "${VENV_IDENTITY_PARSER}" <<'PY'
import json
import os
import secrets
import stat
import sys

root, expected_plan_id, active_venv, terminal_controller, identity_parser = sys.argv[1:]
journal = os.path.join(root, "phase-one-active.json")
info = os.lstat(journal)
if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
    raise RuntimeError("phase-one recovery journal is not a real file")
with open(journal, "rb") as stream:
    payload = json.load(stream)
if (
    payload.get("schema_version") != 4
    or payload.get("kind") != "defenseclaw-phase-one-recovery"
    or payload.get("plan_id") != expected_plan_id
):
    raise RuntimeError("refusing to clear a different phase-one recovery journal")
if terminal_controller not in {"bridge", "source"}:
    raise RuntimeError("phase-one terminal controller identity is invalid")
marker = os.path.join(active_venv, ".defenseclaw-phase-one-owner.json")
if terminal_controller == "bridge":
    marker_info = os.lstat(marker)
    if (
        not stat.S_ISREG(marker_info.st_mode)
        or stat.S_ISLNK(marker_info.st_mode)
        or marker_info.st_uid != os.geteuid()
        or stat.S_IMODE(marker_info.st_mode) & 0o077
    ):
        raise RuntimeError("phase-one bridge venv ownership marker is unsafe")
    with open(marker, encoding="utf-8") as stream:
        marker_payload = json.load(stream)
    expected_marker = {
        "schema_version": 1,
        "kind": "defenseclaw-phase-one-bridge-venv",
        "plan_id": expected_plan_id,
        "bridge_wheel_sha256": payload.get("bridge_wheel_sha256"),
    }
    if marker_payload != expected_marker:
        raise RuntimeError("phase-one bridge venv ownership marker changed")
else:
    identity_namespace = {"__name__": "defenseclaw_venv_identity"}
    exec(identity_parser, identity_namespace)
    if identity_namespace["venv_identity"](active_venv) != payload.get("source_venv_identity_sha256"):
        raise RuntimeError("phase-one restored source venv identity changed before journal closure")

# The journal must remain recovery authority until the newly installed
# controller tree and every directory entry leading to it are durable.
directories = []
node_count = 0
byte_count = 0
for current, names, files in os.walk(active_venv, topdown=True, followlinks=False):
    directories.append(current)
    for name in sorted((*names, *files)):
        path = os.path.join(current, name)
        info = os.lstat(path)
        node_count += 1
        if node_count > 100000:
            raise RuntimeError("phase-one bridge venv exceeds its durability node bound")
        if info.st_uid != os.geteuid():
            raise RuntimeError("phase-one bridge venv contains a foreign-owned member")
        if stat.S_ISREG(info.st_mode):
            byte_count += info.st_size
            if byte_count > 4 * 1024 * 1024 * 1024:
                raise RuntimeError("phase-one bridge venv exceeds its durability byte bound")
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        elif stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            continue
        else:
            raise RuntimeError("phase-one bridge venv contains an unsupported member")
for directory in reversed(directories):
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
descriptor = os.open(os.path.dirname(active_venv), os.O_RDONLY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
quarantine = os.path.join(root, f".{expected_plan_id}.complete-{secrets.token_hex(16)}")
os.rename(journal, quarantine)
os.unlink(quarantine)
descriptor = os.open(root, os.O_RDONLY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
if terminal_controller == "bridge":
    os.unlink(marker)
    descriptor = os.open(active_venv, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
PY
}

recover_interrupted_bridge_phase1() {
    local journal="${UPGRADE_RECOVERY_ROOT}/phase-one-active.json"
    local recovery_result terminal_controller terminal_version terminal_plan_id
    [[ -e "${journal}" || -L "${journal}" ]] || return 0
    if [[ "${PLAN_ONLY}" -eq 1 ]]; then
        die "An interrupted phase-one upgrade requires recovery. Re-run without --plan; no new upgrade changes were made."
    fi

    section "Recovering Interrupted Bridge Upgrade"
    warn "Found durable phase-one recovery state; reconciling its bound controller before detecting installed versions."
    if ! recovery_result="$(python3 - \
        "${CONTROLLER_HOME}" \
        "${DEFENSECLAW_VENV}" \
        "${INSTALL_DIR}" \
        "${UPGRADE_RECOVERY_ROOT}" \
        "${GATEWAY_PID_PARSER}" \
        "${DEFENSECLAW_CONFIG:-}" \
        "${BRIDGE_PHASE1_STATE_NAMES_JSON}" \
        "${VENV_IDENTITY_PARSER}" <<'PY'
import ctypes
import errno
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

recovery_home, active_venv, install_dir, recovery_root = map(os.path.abspath, sys.argv[1:5])
pid_parser_namespace = {"__name__": "defenseclaw_gateway_pid_parser"}
exec(sys.argv[5], pid_parser_namespace)
inspect_gateway_pid = pid_parser_namespace["inspect_gateway_pid"]
ambient_config_override = sys.argv[6]
canonical_state_names = json.loads(sys.argv[7])
venv_identity_namespace = {"__name__": "defenseclaw_venv_identity"}
exec(sys.argv[8], venv_identity_namespace)
venv_identity = venv_identity_namespace["venv_identity"]
journal = os.path.join(recovery_root, "phase-one-active.json")
uid = os.geteuid()


def inject_recovery_crash(point: str) -> None:
    if os.environ.get("DEFENSECLAW_TEST_PHASE1_RECOVERY_CRASH") == point:
        os.kill(os.getpid(), 9)


def digest(path: str) -> str:
    value = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def require_directory(path: str, *, private: bool) -> None:
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise RuntimeError(f"recovery path is not a real directory: {path}")
    if info.st_uid != uid:
        raise RuntimeError(f"recovery path is not current-user-owned: {path}")
    if private and stat.S_IMODE(info.st_mode) & 0o077:
        raise RuntimeError(f"recovery path is not private: {path}")


def require_file(path: str, *, private: bool = False) -> None:
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise RuntimeError(f"recovery path is not a real file: {path}")
    if info.st_uid != uid:
        raise RuntimeError(f"recovery path is not current-user-owned: {path}")
    if private and stat.S_IMODE(info.st_mode) & 0o077:
        raise RuntimeError(f"recovery file is not private: {path}")


def fsync_directory(path: str) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def fsync_path_tree(path: str) -> None:
    if os.path.islink(path):
        fsync_directory(os.path.dirname(path))
        return
    if os.path.isfile(path):
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        fsync_directory(os.path.dirname(path))
        return
    directories = []
    for current, _names, files in os.walk(path, topdown=True, followlinks=False):
        directories.append(current)
        for name in files:
            member = os.path.join(current, name)
            if os.path.islink(member):
                continue
            descriptor = os.open(member, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    for directory in reversed(directories):
        fsync_directory(directory)
    fsync_directory(os.path.dirname(path))


def remove_path(path: str) -> None:
    if not os.path.lexists(path):
        return
    if os.path.islink(path) or not os.path.isdir(path):
        os.unlink(path)
    else:
        shutil.rmtree(path)


def copy_path(source: str, destination: str) -> str:
    source_info = os.lstat(source)
    if stat.S_ISLNK(source_info.st_mode):
        os.symlink(os.readlink(source), destination)
        return "symlink"
    if stat.S_ISREG(source_info.st_mode):
        shutil.copy2(source, destination, follow_symlinks=False)
        return "file"
    if stat.S_ISDIR(source_info.st_mode):
        shutil.copytree(source, destination, symlinks=True, copy_function=shutil.copy2)
        return "directory"
    raise RuntimeError(f"unsupported recovery state type: {source}")


def path_inventory(path):
    inventory = []

    def visit(current: str, relative: str) -> None:
        info = os.lstat(current)
        item = {
            "path": relative,
            "mode": stat.S_IMODE(info.st_mode),
        }
        if stat.S_ISLNK(info.st_mode):
            item["kind"] = "symlink"
            item["target"] = os.readlink(current)
        elif stat.S_ISREG(info.st_mode):
            item["kind"] = "file"
            item["size"] = info.st_size
            item["sha256"] = digest(current)
        elif stat.S_ISDIR(info.st_mode):
            item["kind"] = "directory"
        else:
            raise RuntimeError(f"unsupported recovery state type: {current}")
        inventory.append(item)
        if item["kind"] == "directory":
            with os.scandir(current) as entries:
                children = sorted(entries, key=lambda entry: entry.name)
            for child in children:
                child_relative = child.name if relative == "." else f"{relative}/{child.name}"
                visit(child.path, child_relative)

    visit(path, ".")
    return inventory


def rename_no_replace(source: str, destination: str) -> None:
    source_parent = os.path.dirname(source) or "."
    destination_parent = os.path.dirname(destination) or "."
    source_parent_fd = os.open(source_parent, os.O_RDONLY)
    destination_parent_fd = -1
    try:
        destination_parent_fd = os.open(destination_parent, os.O_RDONLY)
        library = ctypes.CDLL(None, use_errno=True)
        if sys.platform == "darwin":
            function = library.renameatx_np
            flag = 0x4
        elif sys.platform.startswith("linux"):
            function = library.renameat2
            flag = 0x1
        else:
            raise RuntimeError("phase-one no-replace recovery is unsupported")
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        function.restype = ctypes.c_int
        if function(
            source_parent_fd,
            os.fsencode(os.path.basename(source)),
            destination_parent_fd,
            os.fsencode(os.path.basename(destination)),
            flag,
        ) != 0:
            code = ctypes.get_errno()
            if code in {errno.EEXIST, errno.ENOTEMPTY}:
                raise RuntimeError(
                    f"phase-one recovery destination appeared concurrently: {destination}"
                )
            raise RuntimeError(f"phase-one no-replace recovery failed with errno {code}")
        os.fsync(source_parent_fd)
        os.fsync(destination_parent_fd)
    finally:
        if destination_parent_fd >= 0:
            os.close(destination_parent_fd)
        os.close(source_parent_fd)


def same_state(path: str, entry: dict) -> bool:
    exists = os.path.lexists(path)
    if exists != bool(entry.get("existed")):
        return False
    if not exists:
        return True
    inventory = entry.get("inventory")
    return isinstance(inventory, list) and path_inventory(path) == inventory


def validate_entries(entries: object, expected_targets: list[str], *, label: str) -> list[dict]:
    if not isinstance(entries, list) or len(entries) != len(expected_targets):
        raise RuntimeError(f"invalid phase-one {label} entry set")
    if [entry.get("target") for entry in entries if isinstance(entry, dict)] != expected_targets:
        raise RuntimeError(f"phase-one {label} target set changed")
    for entry in entries:
        if not isinstance(entry.get("existed"), bool):
            raise RuntimeError(f"invalid phase-one {label} existence flag")
        if entry["existed"] and (
            entry.get("kind") not in {"file", "directory", "symlink"}
            or not isinstance(entry.get("inventory"), list)
        ):
            raise RuntimeError(f"invalid phase-one {label} inventory")
    return entries


def active_manifest_auth_tag(document: dict) -> str:
    unsigned = dict(document)
    unsigned.pop("plan_hmac_sha256", None)
    raw = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(plan_id.encode(), raw, hashlib.sha256).hexdigest()


def validate_active_manifest_document(document: object) -> dict:
    if not isinstance(document, dict) or set(document) != {
        "schema",
        "plan_id",
        "entries",
        "root_modes",
        "root_identities",
        "plan_hmac_sha256",
    }:
        raise RuntimeError("invalid phase-one active manifest fields")
    if document.get("schema") != 2 or document.get("plan_id") != plan_id:
        raise RuntimeError("unsupported phase-one active manifest")
    tag = document.get("plan_hmac_sha256")
    if (
        not isinstance(tag, str)
        or not hmac.compare_digest(tag, active_manifest_auth_tag(document))
    ):
        raise RuntimeError("phase-one active manifest authentication failed")
    return document


def quarantine_root(target: str) -> str:
    token = plan_id.removeprefix("phase-one-")
    parent = os.path.dirname(target) or "."
    if not openclaw_home_existed and os.path.commonpath((target, openclaw_home)) == openclaw_home:
        parent = os.path.dirname(openclaw_home) or "."
    return os.path.join(parent, f".defenseclaw-phase-one-custody-{token}")


def require_quarantine_root(target: str, *, create: bool = False) -> str:
    root = quarantine_root(target)
    created = False
    if create:
        try:
            os.mkdir(root, 0o700)
            created = True
        except FileExistsError:
            pass
    info = os.lstat(root)
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != uid
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise RuntimeError(f"phase-one custody root is unsafe: {root}")
    if created:
        fsync_directory(os.path.dirname(root) or ".")
    return root


def quarantine_path(target: str, index: int) -> str:
    name = os.path.basename(target)
    if not openclaw_home_existed and os.path.commonpath((target, openclaw_home)) == openclaw_home:
        name = f"{os.path.basename(openclaw_home)}-{name}"
    return os.path.join(quarantine_root(target), f"{index}-{name}")


def restore_candidate_path(target: str, index: int) -> str:
    token = plan_id.removeprefix("phase-one-")
    parent = os.path.dirname(target) or "."
    return os.path.join(
        parent,
        f".{os.path.basename(target)}.phase-one-restore-{token}-{index}",
    )


def root_state():
    modes = {}
    identities = {}
    for root in (data_home, openclaw_home):
        try:
            info = os.stat(root, follow_symlinks=False)
        except FileNotFoundError:
            modes[root] = None
            identities[root] = None
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise RuntimeError(f"phase-one recovery root is unsafe: {root}")
        modes[root] = stat.S_IMODE(info.st_mode)
        identities[root] = {"device": info.st_dev, "inode": info.st_ino}
    return modes, identities


def command_version(command):
    probe_environment = os.environ.copy()
    probe_environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        command,
        env=probe_environment,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    match = re.search(r"(?<![\d.])(\d+\.\d+\.\d+)(?![\d.])", (completed.stdout or "") + (completed.stderr or ""))
    if completed.returncode != 0 or match is None:
        raise RuntimeError(f"could not verify restored command: {command[0]}")
    return match.group(1)


require_directory(recovery_root, private=True)
require_file(journal, private=True)
if os.path.getsize(journal) > 64 * 1024:
    raise RuntimeError("phase-one recovery journal is too large")
with open(journal, "rb") as stream:
    payload = json.load(stream)
expected_keys = {
    "schema_version",
    "kind",
    "plan_id",
    "recovery_home",
    "data_dir",
    "config_path",
    "openclaw_home_existed",
    "path_identities",
    "source_version",
    "bridge_version",
    "source_was_running",
    "source_health_url",
    "backup_directory",
    "gateway_sha256",
    "bridge_gateway_sha256",
    "bridge_wheel_sha256",
    "source_venv_identity_sha256",
    "state_snapshot_ready",
    "state_manifest_sha256",
    "state_mutation_started",
    "active_snapshot_ready",
    "active_manifest_sha256",
    "openclaw_home",
    "config_override",
}
if set(payload) != expected_keys or payload.get("schema_version") != 4:
    raise RuntimeError("unsupported phase-one recovery journal")
if payload.get("kind") != "defenseclaw-phase-one-recovery":
    raise RuntimeError("invalid phase-one recovery journal kind")
plan_id = payload.get("plan_id")
source_version = payload.get("source_version")
bridge_version = payload.get("bridge_version")
backup_name = payload.get("backup_directory")
source_was_running = payload.get("source_was_running")
source_health_url = payload.get("source_health_url")
state_snapshot_ready = payload.get("state_snapshot_ready")
state_mutation_started = payload.get("state_mutation_started")
active_snapshot_ready = payload.get("active_snapshot_ready")
recorded_recovery_home = payload.get("recovery_home")
data_home = payload.get("data_dir")
config_path = payload.get("config_path")
path_identities = payload.get("path_identities")
openclaw_home_existed = payload.get("openclaw_home_existed")
if not isinstance(plan_id, str) or re.fullmatch(r"phase-one-[0-9a-f]{32}", plan_id) is None:
    raise RuntimeError("invalid phase-one recovery plan identifier")
if not isinstance(source_version, str) or re.fullmatch(r"\d+\.\d+\.\d+", source_version) is None:
    raise RuntimeError("invalid phase-one recovery source version")
if not isinstance(bridge_version, str) or re.fullmatch(r"\d+\.\d+\.\d+", bridge_version) is None:
    raise RuntimeError("invalid phase-one recovery bridge version")
if not isinstance(backup_name, str) or re.fullmatch(r"upgrade-[A-Za-z0-9T._-]+", backup_name) is None:
    raise RuntimeError("invalid phase-one recovery backup name")
if not isinstance(source_was_running, bool):
    raise RuntimeError("invalid phase-one recovery running-state flag")
if not isinstance(source_health_url, str):
    raise RuntimeError("invalid phase-one recovery health endpoint")
health = urlsplit(source_health_url)
try:
    health_port = health.port
except ValueError as exc:
    raise RuntimeError("invalid phase-one recovery health endpoint") from exc
if (
    health.scheme != "http"
    or health.hostname is None
    or health_port is None
    or not 1 <= health_port <= 65535
    or health.username is not None
    or health.password is not None
    or health.path != "/health"
    or health.query
    or health.fragment
):
    raise RuntimeError("invalid phase-one recovery health endpoint")
if not isinstance(state_snapshot_ready, bool):
    raise RuntimeError("invalid phase-one state snapshot flag")
if not isinstance(state_mutation_started, bool):
    raise RuntimeError("invalid phase-one mutation-started flag")
if not isinstance(active_snapshot_ready, bool):
    raise RuntimeError("invalid phase-one active snapshot flag")
if not isinstance(recorded_recovery_home, str) or not os.path.isabs(recorded_recovery_home):
    raise RuntimeError("invalid phase-one recovery home")
if os.path.abspath(recorded_recovery_home) != recovery_home:
    raise RuntimeError("phase-one recovery journal targets a different controller home")
if not isinstance(data_home, str) or not os.path.isabs(data_home):
    raise RuntimeError("invalid phase-one data directory")
data_home = os.path.abspath(data_home)
if not isinstance(config_path, str) or not os.path.isabs(config_path):
    raise RuntimeError("invalid phase-one config path")
config_path = os.path.abspath(config_path)
if not isinstance(payload.get("gateway_sha256"), str) or re.fullmatch(r"[0-9a-f]{64}", payload["gateway_sha256"]) is None:
    raise RuntimeError("invalid phase-one gateway digest")
for key in ("bridge_gateway_sha256", "bridge_wheel_sha256"):
    if not isinstance(payload.get(key), str) or re.fullmatch(r"[0-9a-f]{64}", payload[key]) is None:
        raise RuntimeError("invalid phase-one bridge activation digest")
source_venv_identity = payload.get("source_venv_identity_sha256")
if not isinstance(source_venv_identity, str) or re.fullmatch(r"[0-9a-f]{64}", source_venv_identity) is None:
    raise RuntimeError("invalid phase-one source venv identity")
if state_snapshot_ready:
    if not isinstance(payload.get("state_manifest_sha256"), str) or re.fullmatch(r"[0-9a-f]{64}", payload["state_manifest_sha256"]) is None:
        raise RuntimeError("invalid phase-one state manifest digest")
elif payload.get("state_manifest_sha256") is not None:
    raise RuntimeError("unsealed phase-one state has an unexpected digest")
if state_mutation_started and not state_snapshot_ready:
    raise RuntimeError("phase-one mutation started without source state custody")
if active_snapshot_ready:
    if not state_mutation_started:
        raise RuntimeError("phase-one active snapshot exists without mutation authority")
    if not isinstance(payload.get("active_manifest_sha256"), str) or re.fullmatch(r"[0-9a-f]{64}", payload["active_manifest_sha256"]) is None:
        raise RuntimeError("invalid phase-one active manifest digest")
elif payload.get("active_manifest_sha256") is not None:
    raise RuntimeError("unsealed phase-one active state has an unexpected digest")
openclaw_home = payload.get("openclaw_home")
config_override = payload.get("config_override")
if not isinstance(openclaw_home, str) or not os.path.isabs(openclaw_home):
    raise RuntimeError("invalid phase-one OpenClaw home")
if not isinstance(openclaw_home_existed, bool):
    raise RuntimeError("invalid phase-one OpenClaw existence state")
if config_override is not None and (not isinstance(config_override, str) or not os.path.isabs(config_override)):
    raise RuntimeError("invalid phase-one config override")
expected_config_path = config_override or os.path.join(recovery_home, "config.yaml")
if config_path != expected_config_path:
    raise RuntimeError("phase-one config path is inconsistent with its recorded source")
if ambient_config_override:
    ambient_config_override = os.path.abspath(os.path.expanduser(ambient_config_override))
    if ambient_config_override != config_path:
        raise RuntimeError("ambient DEFENSECLAW_CONFIG differs from the interrupted phase-one plan")

expected_identity_names = {"recovery_home", "data_dir", "openclaw_home", "config_parent"}
if not isinstance(path_identities, dict) or set(path_identities) != expected_identity_names:
    raise RuntimeError("invalid phase-one path identity set")
identity_paths = {
    "recovery_home": recovery_home,
    "data_dir": data_home,
    "openclaw_home": (
        openclaw_home if openclaw_home_existed else (os.path.dirname(openclaw_home) or ".")
    ),
    "config_parent": os.path.dirname(config_path) or ".",
}
for name, identity_path in identity_paths.items():
    identity = path_identities[name]
    if (
        not isinstance(identity, dict)
        or set(identity) != {"device", "inode"}
        or isinstance(identity.get("device"), bool)
        or isinstance(identity.get("inode"), bool)
        or not isinstance(identity.get("device"), int)
        or not isinstance(identity.get("inode"), int)
    ):
        raise RuntimeError("invalid phase-one path identity")
    identity_info = os.lstat(identity_path)
    if (
        stat.S_ISLNK(identity_info.st_mode)
        or not stat.S_ISDIR(identity_info.st_mode)
        or identity_info.st_dev != identity["device"]
        or identity_info.st_ino != identity["inode"]
    ):
        raise RuntimeError(f"phase-one {name} identity changed before recovery")
if openclaw_home_existed:
    require_directory(openclaw_home, private=False)
elif os.path.lexists(openclaw_home):
    created_openclaw = os.lstat(openclaw_home)
    if (
        stat.S_ISLNK(created_openclaw.st_mode)
        or not stat.S_ISDIR(created_openclaw.st_mode)
        or created_openclaw.st_uid != uid
        or stat.S_IMODE(created_openclaw.st_mode) & 0o022
    ):
        raise RuntimeError("target-created OpenClaw home is unsafe during recovery")

if (
    not isinstance(canonical_state_names, list)
    or not canonical_state_names
    or any(not isinstance(name, str) or not name or "/" in name for name in canonical_state_names)
):
    raise RuntimeError("invalid phase-one state inventory contract")
require_directory(recovery_home, private=False)
require_directory(data_home, private=False)
backup_root = os.path.join(recovery_home, "backups")
require_directory(backup_root, private=True)

backup_dir = os.path.join(backup_root, backup_name)
if os.path.dirname(backup_dir) != backup_root:
    raise RuntimeError("phase-one recovery backup escaped the private root")
require_directory(backup_dir, private=True)
source_gateway = os.path.join(backup_dir, "phase1-source-gateway")
bridge_gateway = os.path.join(backup_dir, "phase1-bridge-gateway")
bridge_wheel = os.path.join(
    backup_dir, f"defenseclaw-{payload['bridge_version']}-2-py3-none-any.whl"
)
state_root = os.path.join(backup_dir, "phase1-state")
state_manifest = os.path.join(state_root, "manifest.json")
active_manifest = os.path.join(state_root, "active-manifest.json")
require_file(source_gateway)
if digest(source_gateway) != payload["gateway_sha256"]:
    raise RuntimeError("phase-one source gateway custody digest changed")
require_file(bridge_gateway)
require_file(bridge_wheel)
if digest(bridge_gateway) != payload["bridge_gateway_sha256"] or digest(bridge_wheel) != payload["bridge_wheel_sha256"]:
    raise RuntimeError("phase-one bridge activation custody digest changed")
if state_snapshot_ready:
    require_directory(state_root, private=True)
    require_file(state_manifest, private=True)
    if digest(state_manifest) != payload["state_manifest_sha256"]:
        raise RuntimeError("phase-one state manifest custody digest changed")
active_snapshot_available = active_snapshot_ready or os.path.lexists(active_manifest)
resume_unsealed_bridge = False
if active_snapshot_available:
    require_file(active_manifest, private=True)
    if active_snapshot_ready and digest(active_manifest) != payload["active_manifest_sha256"]:
        raise RuntimeError("phase-one active manifest custody digest changed")


def cleanup_owned_temporaries() -> None:
    token = plan_id.removeprefix("phase-one-")
    generic_prefix = f".tmp.upgrade-{token}."
    cursor_prefix = f".migration_state.upgrade-{token}."
    tagged_writer = re.compile(
        rf"^\..+\.upgrade-{re.escape(token)}\.[A-Za-z0-9_-]+\.tmp$"
    )
    cleanup_quarantine = re.compile(
        rf"^\.defenseclaw-cleanup-{re.escape(token)}-"
        r"([0-9a-f]+)-([0-9a-f]+)-[0-9a-f]{32}\.quarantine$"
    )
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )

    def expected_identity(name: str) -> dict:
        expected = path_identities.get(name)
        if (
            not isinstance(expected, dict)
            or set(expected) != {"device", "inode"}
            or isinstance(expected.get("device"), bool)
            or isinstance(expected.get("inode"), bool)
            or not isinstance(expected.get("device"), int)
            or not isinstance(expected.get("inode"), int)
        ):
            raise RuntimeError("phase-one cleanup root identity changed")
        return expected

    def validate_bound_descriptor(
        name: str,
        path: str,
        descriptor: int,
        opened: os.stat_result,
    ) -> None:
        expected = expected_identity(name)
        try:
            named = os.lstat(path)
        except OSError as exc:
            raise RuntimeError(f"phase-one {name} disappeared during temporary cleanup") from exc
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(opened.st_mode)
            or opened.st_dev != expected["device"]
            or opened.st_ino != expected["inode"]
            or not os.path.samestat(named, opened)
            or not os.path.samestat(os.fstat(descriptor), opened)
        ):
            raise RuntimeError(f"phase-one {name} identity changed during temporary cleanup")

    def quarantine_no_replace(
        descriptor: int,
        source_name: str,
        inspected: os.stat_result,
    ) -> str:
        library = ctypes.CDLL(None, use_errno=True)
        if sys.platform == "darwin":
            function = library.renameatx_np
            flag = 0x4  # RENAME_EXCL
        elif sys.platform.startswith("linux"):
            function = library.renameat2
            flag = 0x1  # RENAME_NOREPLACE
        else:
            raise RuntimeError("phase-one temporary quarantine is unsupported")
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        function.restype = ctypes.c_int
        for _attempt in range(16):
            quarantine_name = (
                f".defenseclaw-cleanup-{token}-"
                f"{inspected.st_dev:x}-{inspected.st_ino:x}-"
                f"{secrets.token_hex(16)}.quarantine"
            )
            result = function(
                descriptor,
                os.fsencode(source_name),
                descriptor,
                os.fsencode(quarantine_name),
                flag,
            )
            if result == 0:
                os.fsync(descriptor)
                return quarantine_name
            code = ctypes.get_errno()
            if code in {errno.EEXIST, errno.ENOTEMPTY}:
                continue
            raise RuntimeError(
                f"phase-one temporary quarantine failed with errno {code}"
            )
        raise RuntimeError("phase-one temporary quarantine name allocation was exhausted")

    def cleanup_descriptor(descriptor: int) -> None:
        with os.scandir(descriptor) as entries:
            members = []
            for entry in entries:
                if len(members) == 100000:
                    raise RuntimeError(
                        "phase-one temporary cleanup exceeded its scan bound"
                    )
                members.append(entry)
        for entry in members:
            quarantine_match = cleanup_quarantine.fullmatch(entry.name)
            owned = (
                entry.name.startswith(generic_prefix)
                or (entry.name.startswith(cursor_prefix) and entry.name.endswith(".tmp"))
                or tagged_writer.fullmatch(entry.name) is not None
                or quarantine_match is not None
            )
            if not owned:
                continue
            info = entry.stat(follow_symlinks=False)
            if entry.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != uid:
                raise RuntimeError("phase-one owned temporary has an unsafe identity")
            if quarantine_match is not None and (
                info.st_dev != int(quarantine_match.group(1), 16)
                or info.st_ino != int(quarantine_match.group(2), 16)
            ):
                os.fsync(descriptor)
                raise RuntimeError(
                    "phase-one cleanup quarantine identity changed before replay"
                )
            quarantine_name = quarantine_no_replace(descriptor, entry.name, info)
            quarantined = os.stat(
                quarantine_name,
                dir_fd=descriptor,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(quarantined.st_mode)
                or stat.S_ISLNK(quarantined.st_mode)
                or quarantined.st_uid != uid
                or not os.path.samestat(quarantined, info)
            ):
                os.fsync(descriptor)
                raise RuntimeError(
                    "phase-one owned temporary identity changed during quarantine"
                )
            os.unlink(quarantine_name, dir_fd=descriptor)
        os.fsync(descriptor)

    def cleanup_bound_root(name: str, path: str) -> None:
        descriptor = os.open(path, directory_flags)
        try:
            opened = os.fstat(descriptor)
            validate_bound_descriptor(name, path, descriptor, opened)
            cleanup_descriptor(descriptor)
            validate_bound_descriptor(name, path, descriptor, opened)
        finally:
            os.close(descriptor)

    cleanup_bound_root("data_dir", data_home)
    cleanup_bound_root("config_parent", os.path.dirname(config_path) or ".")
    if openclaw_home_existed:
        cleanup_bound_root("openclaw_home", openclaw_home)
        return

    # When OpenClaw did not exist at snapshot time, its recorded identity is
    # the parent. Open the target-created child through that bound parent so a
    # concurrent name replacement cannot redirect cleanup outside custody.
    parent = os.path.dirname(openclaw_home) or "."
    child_name = os.path.basename(openclaw_home)
    if not child_name:
        raise RuntimeError("phase-one absent OpenClaw path has no child name")
    parent_descriptor = os.open(parent, directory_flags)
    try:
        parent_opened = os.fstat(parent_descriptor)
        validate_bound_descriptor(
            "openclaw_home", parent, parent_descriptor, parent_opened
        )
        try:
            child_descriptor = os.open(
                child_name,
                directory_flags,
                dir_fd=parent_descriptor,
            )
        except FileNotFoundError:
            child_descriptor = -1
        if child_descriptor >= 0:
            try:
                child_opened = os.fstat(child_descriptor)
                child_named = os.stat(
                    child_name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISDIR(child_opened.st_mode)
                    or stat.S_ISLNK(child_opened.st_mode)
                    or child_opened.st_uid != uid
                    or stat.S_IMODE(child_opened.st_mode) & 0o022
                    or not os.path.samestat(child_named, child_opened)
                ):
                    raise RuntimeError(
                        "target-created OpenClaw home is unsafe during temporary cleanup"
                    )
                cleanup_descriptor(child_descriptor)
                child_named = os.stat(
                    child_name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if (
                    not os.path.samestat(child_named, child_opened)
                    or not os.path.samestat(os.fstat(child_descriptor), child_opened)
                ):
                    raise RuntimeError(
                        "target-created OpenClaw home changed during temporary cleanup"
                    )
            finally:
                os.close(child_descriptor)
        validate_bound_descriptor(
            "openclaw_home", parent, parent_descriptor, parent_opened
        )
    finally:
        os.close(parent_descriptor)


def restore_state_before_artifacts() -> None:
    global resume_unsealed_bridge

    if not state_snapshot_ready:
        return
    if os.path.getsize(state_manifest) > 4 * 1024 * 1024:
        raise RuntimeError("phase-one state manifest is too large")
    with open(state_manifest, encoding="utf-8") as stream:
        source_state = json.load(stream)
    expected_targets = [
        config_path,
        config_path + ".pre-observability-migration.bak",
        config_path + ".lock",
        config_path + ".tmp-f3395",
    ]
    expected_targets.extend(os.path.join(data_home, name) for name in canonical_state_names)
    expected_targets.extend(
        os.path.join(openclaw_home, name)
        for name in ("openclaw.json", "openclaw.json.pre-0.3.0-migration")
    )
    source_entries = validate_entries(
        source_state.get("entries"), expected_targets, label="source snapshot"
    )
    for index, entry in enumerate(source_entries):
        if not entry["existed"]:
            continue
        if entry.get("backup") != f"item-{index}":
            raise RuntimeError("invalid phase-one source backup name")
        if path_inventory(os.path.join(state_root, entry["backup"])) != entry["inventory"]:
            raise RuntimeError(f"phase-one state backup changed for {entry['target']}")
    source_root_modes = source_state.get("root_modes")
    if not isinstance(source_root_modes, dict):
        raise RuntimeError("invalid phase-one source root modes")

    source_state_is_exact = all(
        same_state(entry["target"], entry) for entry in source_entries
    )
    current_root_modes, _current_root_identities = root_state()
    source_roots_are_exact = all(
        current_root_modes.get(root) == source_root_modes.get(root)
        for root in (data_home, openclaw_home)
    )
    if (
        not active_snapshot_available
        and state_mutation_started
        and not (source_state_is_exact and source_roots_are_exact)
    ):
        # Mutation authority was armed before the first canonical write, but
        # no exact active manifest was sealed.  The current bytes can include
        # user edits made after the crash, so they may not be inferred as
        # plan-owned or moved out of their canonical names.  Keep the complete
        # bridge controller in custody and let the caller resume it instead.
        resume_unsealed_bridge = True
        return
    active_root_identities = {}
    if active_snapshot_available:
        with open(active_manifest, encoding="utf-8") as stream:
            active_state = validate_active_manifest_document(json.load(stream))
        active_entries = validate_entries(
            active_state.get("entries"), expected_targets, label="active snapshot"
        )
        active_root_modes = active_state.get("root_modes")
        active_root_identities = active_state.get("root_identities")
        if (
            not isinstance(active_root_modes, dict)
            or set(active_root_modes) != {data_home, openclaw_home}
            or not isinstance(active_root_identities, dict)
            or set(active_root_identities) != {data_home, openclaw_home}
        ):
            raise RuntimeError("invalid phase-one active root contract")
    else:
        active_entries = source_entries
        active_root_modes = source_state.get("root_modes")
        if not isinstance(active_root_modes, dict):
            raise RuntimeError("invalid phase-one source root modes")
    partial_restore = any(
        os.path.lexists(quarantine_path(source_entry["target"], index))
        or (
            same_state(source_entry["target"], source_entry)
            and not same_state(source_entry["target"], active_entry)
        )
        for index, (source_entry, active_entry) in enumerate(
            zip(source_entries, active_entries)
        )
    )
    current_modes, current_identities = root_state()
    for root in (data_home, openclaw_home):
        allowed_modes = {active_root_modes.get(root)}
        if partial_restore:
            allowed_modes.add(source_root_modes.get(root))
        if current_modes.get(root) not in allowed_modes:
            raise RuntimeError(f"phase-one state root mode diverged after migration: {root}")
        expected_identity = active_root_identities.get(root)
        source_absent = partial_restore and source_root_modes.get(root) is None
        if (
            expected_identity is not None
            and current_identities.get(root) != expected_identity
            and not (source_absent and current_identities.get(root) is None)
        ):
            raise RuntimeError(f"phase-one state root identity diverged after migration: {root}")
    for index, (source_entry, active_entry) in enumerate(
        zip(source_entries, active_entries)
    ):
        target = source_entry["target"]
        quarantine = quarantine_path(target, index)
        if os.path.lexists(quarantine):
            require_quarantine_root(target)
            if not same_state(quarantine, active_entry) and not same_state(target, source_entry):
                raise RuntimeError(f"phase-one quarantine diverged for {target}")
            if os.path.lexists(target) and not same_state(target, source_entry):
                raise RuntimeError(f"phase-one state target reappeared during rollback: {target}")
            continue
        if not same_state(target, active_entry) and not same_state(target, source_entry):
            raise RuntimeError(
                f"phase-one state diverged after migration; preserved without overwrite: {target}"
            )

    # Move the exact sealed bridge state out of every canonical name and
    # restore source state before controller artifacts are switched back.
    # This ordering prevents a recovery-time concurrent edit from leaving an
    # old source controller installed over bridge-format state.
    for index, (source_entry, active_entry) in enumerate(
        zip(source_entries, active_entries)
    ):
        target = source_entry["target"]
        quarantine = quarantine_path(target, index)
        if (
            not os.path.lexists(quarantine)
            and active_entry["existed"]
            and same_state(target, active_entry)
            and not same_state(target, source_entry)
        ):
            require_quarantine_root(target, create=True)
            rename_no_replace(target, quarantine)
            if not same_state(quarantine, active_entry):
                raise RuntimeError(f"phase-one state changed while quarantining {target}")
        if os.path.lexists(target) and not same_state(target, source_entry):
            raise RuntimeError(f"phase-one state target appeared during rollback: {target}")

    for index, entry in enumerate(source_entries):
        target = entry["target"]
        if not entry["existed"]:
            if os.path.lexists(target):
                raise RuntimeError(f"phase-one absent source target appeared during rollback: {target}")
            continue
        if not os.path.lexists(target):
            parent = os.path.dirname(target)
            os.makedirs(parent, mode=0o700, exist_ok=True)
            candidate = restore_candidate_path(target, index)
            if os.path.lexists(candidate):
                info = os.lstat(candidate)
                if info.st_uid != uid:
                    raise RuntimeError(f"unsafe phase-one restore candidate: {candidate}")
                if not same_state(candidate, entry):
                    raise RuntimeError(
                        f"phase-one restore candidate diverged and was preserved: {candidate}"
                    )
            if not os.path.lexists(candidate):
                backup = os.path.join(state_root, entry["backup"])
                restored_kind = copy_path(backup, candidate)
                if restored_kind != entry["kind"] or path_inventory(candidate) != entry["inventory"]:
                    raise RuntimeError(f"phase-one restore candidate mismatch for {target}")
                fsync_path_tree(candidate)
            rename_no_replace(candidate, target)
        if not same_state(target, entry):
            raise RuntimeError(f"phase-one source state restore mismatch for {target}")
        fsync_path_tree(target)

    for entry in source_entries:
        parent = os.path.dirname(entry["target"])
        while not os.path.lexists(parent):
            next_parent = os.path.dirname(parent)
            if next_parent == parent:
                raise RuntimeError("phase-one state target has no stable existing parent")
            parent = next_parent
        if os.path.islink(parent) or not os.path.isdir(parent):
            raise RuntimeError("phase-one state target parent is unsafe")
        fsync_directory(parent)
    for root, mode in source_root_modes.items():
        if root not in (data_home, openclaw_home):
            raise RuntimeError("phase-one state contains an unexpected root mode")
        if mode is None and root == openclaw_home and os.path.lexists(root):
            if os.path.islink(root) or not os.path.isdir(root) or os.listdir(root):
                raise RuntimeError("target-created OpenClaw home contains unexpected rollback residue")
            os.rmdir(root)
            fsync_directory(os.path.dirname(root) or ".")
        elif mode is not None and os.path.isdir(root) and not os.path.islink(root):
            os.chmod(root, mode)
            fsync_directory(root)
    fsync_directory(data_home)

    retained_paths = [
        quarantine_path(entry["target"], index)
        for index, entry in enumerate(source_entries)
        if os.path.lexists(quarantine_path(entry["target"], index))
    ]
    retained_index = os.path.join(state_root, "retained-quarantines.json")
    retained_document = {
        "schema": 1,
        "plan_id": plan_id,
        "paths": retained_paths,
    }
    if os.path.lexists(retained_index):
        require_file(retained_index, private=True)
        with open(retained_index, encoding="utf-8") as stream:
            if json.load(stream) != retained_document:
                raise RuntimeError("phase-one retained-quarantine index changed")
    else:
        raw = (
            json.dumps(retained_document, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode()
        candidate = os.path.join(
            state_root,
            f".retained-quarantines-{plan_id}-{secrets.token_hex(16)}.tmp",
        )
        descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            rename_no_replace(candidate, retained_index)
        finally:
            if os.path.lexists(candidate):
                os.unlink(candidate)
        fsync_directory(state_root)


active_gateway = os.path.join(install_dir, "defenseclaw-gateway")
pid_path = os.path.join(data_home, "gateway.pid")
if os.path.isfile(active_gateway) and not os.path.islink(active_gateway):
    require_file(active_gateway)
    if digest(active_gateway) not in {payload["gateway_sha256"], payload["bridge_gateway_sha256"]}:
        raise RuntimeError("refusing to execute or overwrite an unrecognized phase-one gateway activation")
    stop_environment = os.environ.copy()
    stop_environment["DEFENSECLAW_HOME"] = data_home
    stop_environment["DEFENSECLAW_CONFIG"] = config_path
    stop_environment["OPENCLAW_HOME"] = openclaw_home
    subprocess.run(
        [active_gateway, "stop"],
        env=stop_environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=20,
        check=False,
    )
for _attempt in range(6):
    pid_state, _pid = inspect_gateway_pid(pid_path, active_gateway)
    if pid_state != "live":
        break
    time.sleep(1)
else:
    raise RuntimeError("gateway did not quiesce during phase-one recovery")

curl = shutil.which("curl")
if not curl:
    raise RuntimeError("curl is required for phase-one recovery health verification")
health_probe = subprocess.run(
    [
        curl,
        "-s",
        "-o",
        os.devnull,
        "-w",
        "%{http_code}",
        "--max-time",
        "2",
        source_health_url,
    ],
    capture_output=True,
    text=True,
    timeout=5,
    check=False,
)
if health_probe.returncode != 7 or (health_probe.stdout or "").strip() != "000":
    raise RuntimeError(
        "gateway health endpoint was not proven unreachable during phase-one recovery"
    )

restore_state_before_artifacts()

if resume_unsealed_bridge:
    if digest(active_gateway) != payload["bridge_gateway_sha256"]:
        raise RuntimeError("unsealed phase-one state is not paired with the bridge gateway")
    marker = os.path.join(active_venv, ".defenseclaw-phase-one-owner.json")
    require_directory(active_venv, private=False)
    require_file(marker, private=True)
    with open(marker, encoding="utf-8") as stream:
        marker_payload = json.load(stream)
    expected_marker = {
        "schema_version": 1,
        "kind": "defenseclaw-phase-one-bridge-venv",
        "plan_id": plan_id,
        "bridge_wheel_sha256": payload["bridge_wheel_sha256"],
    }
    if marker_payload != expected_marker:
        raise RuntimeError("unsealed phase-one state is not paired with the bridge CLI")
    cli_path = os.path.join(active_venv, "bin", "defenseclaw")
    if command_version([cli_path, "--version"]) != bridge_version:
        raise RuntimeError("unsealed phase-one bridge CLI version mismatch")
    if command_version([active_gateway, "--version"]) != bridge_version:
        raise RuntimeError("unsealed phase-one bridge gateway version mismatch")

    environment = os.environ.copy()
    environment["DEFENSECLAW_HOME"] = data_home
    environment["DEFENSECLAW_CONFIG"] = config_path
    environment["OPENCLAW_HOME"] = openclaw_home
    bridge_python = os.path.join(active_venv, "bin", "python")
    bridge_health_resolution = subprocess.run(
        [
            bridge_python,
            "-I",
            "-B",
            "-c",
            "from defenseclaw.config import load\n"
            "cfg = load()\n"
            "bind = getattr(cfg.gateway, 'api_bind', '')\n"
            "if not bind:\n"
            "    if cfg.openshell.is_standalone() and cfg.guardrail.host not in ('', 'localhost', '127.0.0.1'):\n"
            "        bind = cfg.guardrail.host\n"
            "    else:\n"
            "        bind = '127.0.0.1'\n"
            "print(f'http://{bind}:{cfg.gateway.api_port}/health')\n",
        ],
        env=environment,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    bridge_health_url = (bridge_health_resolution.stdout or "").strip()
    if (
        bridge_health_resolution.returncode != 0
        or not bridge_health_url
        or "\n" in bridge_health_url
        or len(bridge_health_url) > 2048
    ):
        raise RuntimeError("could not resolve the resumed bridge health endpoint")
    bridge_health = urlsplit(bridge_health_url)
    try:
        bridge_health_port = bridge_health.port
    except ValueError as exc:
        raise RuntimeError("resumed bridge health endpoint is invalid") from exc
    if (
        bridge_health.scheme != "http"
        or bridge_health.hostname is None
        or bridge_health_port is None
        or not 1 <= bridge_health_port <= 65535
        or bridge_health.username is not None
        or bridge_health.password is not None
        or bridge_health.path != "/health"
        or bridge_health.query
        or bridge_health.fragment
    ):
        raise RuntimeError("resumed bridge health endpoint is invalid")
    started = subprocess.run(
        [active_gateway, "start"],
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    if started.returncode != 0:
        raise RuntimeError(
            "unsealed bridge state was preserved, but the bridge gateway did not resume"
        )
    resumed_pid_state, _resumed_pid = inspect_gateway_pid(pid_path, active_gateway)
    if resumed_pid_state != "live":
        raise RuntimeError("resumed bridge lacks verified live PID custody")
    curl = shutil.which("curl", path=environment.get("PATH"))
    if not curl:
        raise RuntimeError("curl is required for resumed bridge health verification")
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        response_path = None
        try:
            descriptor, response_path = tempfile.mkstemp(
                prefix="defenseclaw-phase-one-bridge-health-"
            )
            os.close(descriptor)
            probe = subprocess.run(
                [
                    curl,
                    "-s",
                    "-o",
                    response_path,
                    "-w",
                    "%{http_code}",
                    "--max-time",
                    "2",
                    bridge_health_url,
                ],
                env=environment,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if os.path.getsize(response_path) > 1024 * 1024:
                raise RuntimeError("resumed bridge health response is too large")
            with open(response_path, "rb") as response_file:
                health_payload = json.load(response_file)
            gateway_health = (
                health_payload.get("gateway")
                if isinstance(health_payload, dict)
                else None
            )
            provenance = (
                health_payload.get("provenance")
                if isinstance(health_payload, dict)
                else None
            )
            if (
                probe.returncode == 0
                and (probe.stdout or "").strip() == "200"
                and isinstance(gateway_health, dict)
                and gateway_health.get("state") in {"running", "disabled"}
                and isinstance(provenance, dict)
                and provenance.get("binary_version") == bridge_version
            ):
                break
        except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError):
            pass
        finally:
            if response_path is not None:
                try:
                    os.unlink(response_path)
                except OSError:
                    pass
        time.sleep(1)
    else:
        raise RuntimeError(
            "unsealed bridge state was preserved, but bridge health did not recover"
        )

    for target in [
        config_path,
        config_path + ".pre-observability-migration.bak",
        config_path + ".lock",
        config_path + ".tmp-f3395",
        *(os.path.join(data_home, name) for name in canonical_state_names),
        os.path.join(openclaw_home, "openclaw.json"),
        os.path.join(openclaw_home, "openclaw.json.pre-0.3.0-migration"),
    ]:
        if os.path.lexists(target):
            fsync_path_tree(target)
    if os.path.isdir(openclaw_home) and not os.path.islink(openclaw_home):
        fsync_directory(openclaw_home)
    fsync_directory(data_home)
    # A crash after a plan-owned atomic writer published its canonical file
    # can leave the displaced pre-write bytes in the authenticated temporary.
    # Remove those owner-checked, token-bound files before the caller closes
    # recovery custody around the resumed bridge.
    cleanup_owned_temporaries()
    with open(journal, "rb") as stream:
        if json.load(stream).get("plan_id") != plan_id:
            raise RuntimeError("phase-one recovery journal changed before bridge resumption")
    print(f"bridge\t{bridge_version}\t{plan_id}")
    raise SystemExit(0)

removed_activation_temp = False
for entry in os.scandir(install_dir):
    if re.fullmatch(r"\.defenseclaw-gateway\.(?:upgrade|rollback)\.[A-Za-z0-9]+", entry.name) is None:
        continue
    info = entry.stat(follow_symlinks=False)
    if entry.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != uid:
        raise RuntimeError("unsafe stale gateway activation path during recovery")
    os.unlink(entry.path)
    removed_activation_temp = True
if removed_activation_temp:
    fsync_directory(install_dir)

source_venv = os.path.join(backup_dir, "phase1-source-venv")
if os.path.lexists(source_venv):
    require_directory(source_venv, private=False)
    if venv_identity(source_venv) != source_venv_identity:
        raise RuntimeError("phase-one source venv custody identity changed")
    if os.path.lexists(active_venv):
        require_directory(active_venv, private=False)
        marker = os.path.join(active_venv, ".defenseclaw-phase-one-owner.json")
        require_file(marker, private=True)
        with open(marker, encoding="utf-8") as stream:
            marker_payload = json.load(stream)
        if set(marker_payload) != {"schema_version", "kind", "plan_id", "bridge_wheel_sha256"} or marker_payload != {
            "schema_version": 1,
            "kind": "defenseclaw-phase-one-bridge-venv",
            "plan_id": plan_id,
            "bridge_wheel_sha256": payload["bridge_wheel_sha256"],
        }:
            raise RuntimeError("active phase-one venv is not owned by this recovery plan")
        quarantine = os.path.join(backup_dir, f"phase1-failed-bridge-venv-{plan_id}")
        if os.path.lexists(quarantine):
            raise RuntimeError("phase-one bridge venv quarantine is already occupied")
        os.rename(active_venv, quarantine)
        fsync_directory(recovery_home)
        fsync_directory(backup_dir)
    os.rename(source_venv, active_venv)
    fsync_directory(recovery_home)
    fsync_directory(backup_dir)
else:
    require_directory(active_venv, private=False)
    if venv_identity(active_venv) != source_venv_identity:
        raise RuntimeError("active source venv does not match the bound recovery identity")

os.makedirs(install_dir, mode=0o700, exist_ok=True)
gateway_mode = stat.S_IMODE(os.lstat(source_gateway).st_mode)
gateway_candidate = os.path.join(install_dir, f".defenseclaw-gateway.phase-one-{plan_id}")
gateway_displaced = os.path.join(install_dir, f".defenseclaw-gateway.phase-one-displaced-{plan_id}")
source_gateway_digest = payload["gateway_sha256"]
allowed_gateway_digests = {source_gateway_digest, payload["bridge_gateway_sha256"]}

if os.path.lexists(gateway_candidate):
    require_file(gateway_candidate)
    if digest(gateway_candidate) != source_gateway_digest:
        raise RuntimeError("phase-one recovery candidate has an unrecognized identity")
else:
    descriptor = os.open(gateway_candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, gateway_mode)
    with open(source_gateway, "rb") as source, os.fdopen(descriptor, "wb", closefd=True) as destination:
        shutil.copyfileobj(source, destination)
        destination.flush()
        os.fsync(destination.fileno())
    os.chmod(gateway_candidate, gateway_mode)
    if digest(gateway_candidate) != source_gateway_digest:
        raise RuntimeError("staged phase-one gateway digest mismatch")

active_digest = None
if os.path.lexists(active_gateway):
    require_file(active_gateway)
    active_digest = digest(active_gateway)
    if active_digest not in allowed_gateway_digests:
        raise RuntimeError("refusing to displace an unrecognized phase-one gateway activation")

displaced_digest = None
if os.path.lexists(gateway_displaced):
    require_file(gateway_displaced)
    displaced_digest = digest(gateway_displaced)
    if displaced_digest not in allowed_gateway_digests:
        raise RuntimeError("phase-one gateway quarantine has an unrecognized identity")

if active_digest == source_gateway_digest:
    # A previous recovery attempt already published the source. Finish only
    # the idempotent cleanup that may have been interrupted.
    if os.path.lexists(gateway_candidate):
        os.unlink(gateway_candidate)
    if os.path.lexists(gateway_displaced):
        os.unlink(gateway_displaced)
    fsync_directory(install_dir)
else:
    if active_digest is not None:
        if displaced_digest is not None:
            raise RuntimeError("phase-one gateway publication has conflicting active and quarantine state")
        os.rename(active_gateway, gateway_displaced)
        if digest(gateway_displaced) != active_digest:
            os.rename(gateway_displaced, active_gateway)
            raise RuntimeError("phase-one gateway changed while it was quarantined")
        displaced_digest = active_digest
        fsync_directory(install_dir)
        inject_recovery_crash("after-gateway-displace")
    elif displaced_digest is None:
        raise RuntimeError("phase-one gateway publication lost both active and quarantined identities")
    try:
        os.rename(gateway_candidate, active_gateway)
    except BaseException:
        if not os.path.lexists(active_gateway) and os.path.lexists(gateway_displaced):
            os.rename(gateway_displaced, active_gateway)
        raise
    if digest(active_gateway) != source_gateway_digest:
        raise RuntimeError("published source gateway digest mismatch")
    fsync_directory(install_dir)
    inject_recovery_crash("after-gateway-publish")
    if os.path.lexists(gateway_displaced):
        require_file(gateway_displaced)
        if digest(gateway_displaced) not in allowed_gateway_digests:
            raise RuntimeError("phase-one gateway quarantine changed before cleanup")
        os.unlink(gateway_displaced)
        fsync_directory(install_dir)


cleanup_owned_temporaries()

cli_path = os.path.join(active_venv, "bin", "defenseclaw")
python_path = os.path.join(active_venv, "bin", "python")
if command_version([cli_path, "--version"]) != source_version:
    raise RuntimeError("restored phase-one CLI version mismatch")
if command_version([active_gateway, "--version"]) != source_version:
    raise RuntimeError("restored phase-one gateway version mismatch")

environment = os.environ.copy()
environment["DEFENSECLAW_HOME"] = data_home
environment["OPENCLAW_HOME"] = openclaw_home
environment["DEFENSECLAW_CONFIG"] = config_path
if source_was_running:
    started = subprocess.run(
        [active_gateway, "start"],
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    if started.returncode != 0:
        raise RuntimeError("restored source gateway did not start")
    restored_pid_state, _restored_pid = inspect_gateway_pid(pid_path, active_gateway)
    if restored_pid_state != "live":
        raise RuntimeError("restored source gateway lacks verified live PID custody")
    health_url = source_health_url
    curl = shutil.which("curl", path=environment.get("PATH"))
    if not curl:
        raise RuntimeError("curl is required for restored source health verification")
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            descriptor, response_path = tempfile.mkstemp(prefix="defenseclaw-phase-one-health-")
            os.close(descriptor)
            probe = subprocess.run(
                [curl, "-s", "-o", response_path, "-w", "%{http_code}", "--max-time", "2", health_url],
                env=environment,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if os.path.getsize(response_path) > 1024 * 1024:
                raise RuntimeError("restored source health response is too large")
            with open(response_path, "rb") as response_file:
                health = json.load(response_file)
            gateway = health.get("gateway") if isinstance(health, dict) else None
            provenance = health.get("provenance") if isinstance(health, dict) else None
            if (
                probe.returncode == 0
                and (probe.stdout or "").strip() == "200"
                and isinstance(gateway, dict)
                and gateway.get("state") in {"running", "disabled"}
                and isinstance(provenance, dict)
                and provenance.get("binary_version") == source_version
            ):
                break
        except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError):
            pass
        finally:
            try:
                os.unlink(response_path)
            except (NameError, OSError):
                pass
        time.sleep(1)
    else:
        raise RuntimeError("restored source failed version-bound health verification")
else:
    restored_pid_state, _restored_pid = inspect_gateway_pid(pid_path, active_gateway)
    if restored_pid_state == "live":
        raise RuntimeError("restored stopped source unexpectedly has a live gateway PID")

openclaw = shutil.which("openclaw", path=environment.get("PATH"))
if openclaw:
    subprocess.run(
        [openclaw, "gateway", "restart"],
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )

if os.path.lexists(gateway_displaced):
    require_file(gateway_displaced)
    if digest(gateway_displaced) not in {payload["gateway_sha256"], payload["bridge_gateway_sha256"]}:
        raise RuntimeError("phase-one gateway quarantine changed before cleanup")
    os.unlink(gateway_displaced)
    fsync_directory(install_dir)

with open(journal, "rb") as stream:
    current = json.load(stream)
if current.get("plan_id") != plan_id:
    raise RuntimeError("phase-one recovery journal changed during restoration")
os.unlink(journal)
fsync_directory(recovery_root)
print(f"source\t{source_version}\t{plan_id}")
PY
    )"; then
        die "Interrupted phase-one recovery is incomplete. Private custody was preserved; no new upgrade was started."
    fi
    IFS=$'\t' read -r terminal_controller terminal_version terminal_plan_id <<< "${recovery_result}"
    if [[ ! "${terminal_controller}" =~ ^(source|bridge)$ \
          || ! "${terminal_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ \
          || ! "${terminal_plan_id}" =~ ^phase-one-[0-9a-f]{32}$ ]]; then
        die "Interrupted phase-one recovery returned an invalid terminal-controller receipt. Private custody was preserved."
    fi
    if [[ "${terminal_controller}" == "bridge" ]]; then
        complete_bridge_phase1_recovery_journal "${terminal_plan_id}" bridge \
            || die "Recovered bridge health, but could not durably close phase-one recovery custody."
    fi
    BRIDGE_PHASE1_RECOVERY_TERMINAL_CONTROLLER="${terminal_controller}"
    BRIDGE_PHASE1_RECOVERY_TERMINAL_VERSION="${terminal_version}"
    ok "Recovered the interrupted phase-one release and verified its bound running state"
}

ensure_upgrade_lock_before_mutation() {
    local observed_version="unknown" observed_gateway_version="unknown"
    if [[ -z "${UPGRADE_LOCK_TOKEN:-}" ]]; then
        acquire_upgrade_lock
    fi
    recover_interrupted_phase_two
    recover_interrupted_bridge_phase1
    if [[ -x "${DEFENSECLAW_VENV}/bin/python" ]]; then
        observed_version="$("${DEFENSECLAW_VENV}/bin/python" -I -B -c \
            'from defenseclaw import __version__; print(__version__)' 2>/dev/null \
            | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
    elif has defenseclaw; then
        observed_version="$(defenseclaw --version 2>/dev/null \
            | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 \
            || true)"
    fi
    if [[ -x "${INSTALL_DIR}/defenseclaw-gateway" && ! -L "${INSTALL_DIR}/defenseclaw-gateway" ]]; then
        observed_gateway_version="$("${INSTALL_DIR}/defenseclaw-gateway" --version 2>/dev/null \
            | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
    fi
    observed_version="${observed_version:-unknown}"
    observed_gateway_version="${observed_gateway_version:-unknown}"
    if [[ "${observed_version}" != "${CURRENT_VERSION}" \
          || "${observed_gateway_version}" != "${CURRENT_GATEWAY_VERSION}" ]]; then
        die "Installed components changed while the upgrade was being prepared (CLI ${CURRENT_VERSION} → ${observed_version}; gateway ${CURRENT_GATEWAY_VERSION} → ${observed_gateway_version}). No services were stopped; re-run the release-owned resolver."
    fi
}

# ── Argument Parsing ──────────────────────────────────────────────────────────

YES=0
PLAN_ONLY=0
RELEASE_VERSION="${VERSION:-}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes|-y)   YES=1; shift ;;
        --plan)     PLAN_ONLY=1; shift ;;
        --version)
            [[ $# -lt 2 ]] && die "--version requires a value"
            RELEASE_VERSION="$2"; shift 2 ;;
        --help|-h)
            cat <<EOF

  DefenseClaw Upgrade Script

  Usage: $(basename "$0") [OPTIONS]

  Options:
    --yes, -y             Skip confirmation prompts
    --version VERSION     Select a specific final release; required bridges are still staged
    --plan                Verify release contracts and print the path; make no changes
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

if [[ -e "${UPGRADE_RECOVERY_ROOT}/phase-one-active.json" \
      || -L "${UPGRADE_RECOVERY_ROOT}/phase-one-active.json" \
      || -e "${UPGRADE_RECOVERY_ROOT}/phase-two-active.json" \
      || -L "${UPGRADE_RECOVERY_ROOT}/phase-two-active.json" ]]; then
    acquire_upgrade_lock
    trap release_upgrade_lock EXIT
    recover_interrupted_phase_two
    recover_interrupted_bridge_phase1
    if [[ "${BRIDGE_PHASE1_RECOVERY_TERMINAL_CONTROLLER}" == "bridge" \
          && -n "${RELEASE_VERSION}" \
          && "${RELEASE_VERSION#v}" == "${BRIDGE_PHASE1_RECOVERY_TERMINAL_VERSION}" ]]; then
        section "Upgrade Complete"
        ok "Recovered and verified DefenseClaw ${BRIDGE_PHASE1_RECOVERY_TERMINAL_VERSION}"
        release_upgrade_lock
        trap - EXIT
        exit 0
    fi
fi

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

REQUESTED_RELEASE_VERSION="${RELEASE_VERSION}"
STAGED_FINAL_VERSION=""
STAGED_FINAL_MIN_PROTOCOL=""
POST_HARD_CUT_FINAL_VERSION=""
FRESH_HARD_CUT_HANDOFF=0

# ── Detect currently installed version ───────────────────────────────────────

CURRENT_VERSION="unknown"
if [[ -x "${DEFENSECLAW_VENV}/bin/python" ]]; then
    CURRENT_VERSION="$("${DEFENSECLAW_VENV}/bin/python" -I -B -c \
        'from defenseclaw import __version__; print(__version__)' 2>/dev/null \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
elif has defenseclaw; then
    CURRENT_VERSION="$(defenseclaw --version 2>/dev/null \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
fi
CURRENT_VERSION="${CURRENT_VERSION:-unknown}"

if [[ "${CURRENT_VERSION}" != "unknown" && -x "${DEFENSECLAW_VENV}/bin/defenseclaw" ]] \
    && has defenseclaw; then
    python3 - "$(command -v defenseclaw)" "${DEFENSECLAW_VENV}/bin/defenseclaw" <<'PY' \
        || die "PATH resolves defenseclaw outside the canonical controller-home venv. No changes were made; invoke the release-owned resolver with the managed launcher first on PATH."
import os
import sys

observed, expected = sys.argv[1:]
if os.path.realpath(observed) != os.path.realpath(expected):
    raise SystemExit(1)
PY
fi

CURRENT_GATEWAY_VERSION="unknown"
if [[ -x "${INSTALL_DIR}/defenseclaw-gateway" && ! -L "${INSTALL_DIR}/defenseclaw-gateway" ]]; then
    CURRENT_GATEWAY_VERSION="$("${INSTALL_DIR}/defenseclaw-gateway" --version 2>/dev/null \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
fi
CURRENT_GATEWAY_VERSION="${CURRENT_GATEWAY_VERSION:-unknown}"

ok "Installed version : ${CURRENT_VERSION}"
ok "Gateway version   : ${CURRENT_GATEWAY_VERSION}"
ok "Upgrade target    : ${RELEASE_VERSION}"

if [[ "${CURRENT_VERSION}" == "unknown" ]] \
    && { has defenseclaw \
        || [[ -e "${DEFENSECLAW_HOME}" || -L "${DEFENSECLAW_HOME}" ]] \
        || [[ -e "${DEFENSECLAW_VENV}" || -L "${DEFENSECLAW_VENV}" ]] \
        || [[ -e "${INSTALL_DIR}/defenseclaw" || -L "${INSTALL_DIR}/defenseclaw" ]] \
        || [[ -e "${INSTALL_DIR}/defenseclaw-gateway" || -L "${INSTALL_DIR}/defenseclaw-gateway" ]]; }; then
    die "Could not determine the installed DefenseClaw version from existing managed state. No changes were made.
  Repair the current installation until 'defenseclaw --version' works, then re-run this release-owned resolver. Do not copy target artifacts over the existing installation."
fi

if [[ "${CURRENT_VERSION}" != "unknown" && "${CURRENT_GATEWAY_VERSION}" == "unknown" ]]; then
    die "Could not determine the installed gateway version while CLI ${CURRENT_VERSION} is present. No changes were made.
  Recovery path: restore the gateway artifact from the same signed ${CURRENT_VERSION} release, verify both --version outputs match, then run this release-owned resolver without --version."
fi
COMPONENT_VERSION_SPLIT=0
if [[ "${CURRENT_VERSION}" != "unknown" && "${CURRENT_GATEWAY_VERSION}" != "unknown" \
      && "${CURRENT_VERSION}" != "${CURRENT_GATEWAY_VERSION}" ]]; then
    COMPONENT_VERSION_SPLIT=1
fi

# The managed Python environment belongs to CONTROLLER_HOME, while an
# operator may place mutable DefenseClaw state elsewhere with config.data_dir.
# Resolve and validate that split once, before any service stop, then carry the
# exact lexical absolute paths through recovery instead of consulting ambient
# configuration again.
if [[ "${CURRENT_VERSION}" != "unknown" && -x "${DEFENSECLAW_VENV}/bin/python" ]]; then
    runtime_paths="$(
        DEFENSECLAW_HOME="${CONTROLLER_HOME}" \
        DEFENSECLAW_CONFIG="${CONFIG_PATH}" \
        "${DEFENSECLAW_VENV}/bin/python" -I -B - \
            "${CONTROLLER_HOME}" \
            "${CONFIG_PATH}" \
            "${OPENCLAW_HOME_EXPLICIT}" \
            "${OPENCLAW_HOME}" <<'PY'
import os
import stat
import sys

from defenseclaw.config import load

controller_home, config_path, openclaw_explicit, requested_openclaw = sys.argv[1:]
controller_home = os.path.abspath(os.path.expanduser(controller_home))
config_path = os.path.abspath(os.path.expanduser(config_path))
cfg = load()
configured_data_dir = os.path.expanduser(cfg.data_dir or controller_home)
if not os.path.isabs(configured_data_dir):
    raise RuntimeError("configured data_dir must be absolute for a staged upgrade")
data_dir = os.path.abspath(configured_data_dir)
openclaw_home = os.path.abspath(
    os.path.expanduser(requested_openclaw if openclaw_explicit == "1" else cfg.claw.home_dir)
)
for label, value in (
    ("configured data_dir", data_dir),
    ("active config path", config_path),
    ("resolved OpenClaw home", openclaw_home),
):
    if any(character in value for character in ("\n", "\r", "\t")):
        raise RuntimeError(f"{label} contains an unsafe control character")
data_info = os.lstat(data_dir)
if (
    stat.S_ISLNK(data_info.st_mode)
    or not stat.S_ISDIR(data_info.st_mode)
    or data_info.st_uid != os.geteuid()
    or stat.S_IMODE(data_info.st_mode) & 0o022
):
    raise RuntimeError("configured data_dir must be a stable current-user-owned real directory")
try:
    openclaw_info = os.lstat(openclaw_home)
except FileNotFoundError:
    openclaw_parent_info = os.lstat(os.path.dirname(openclaw_home) or ".")
    if (
        stat.S_ISLNK(openclaw_parent_info.st_mode)
        or not stat.S_ISDIR(openclaw_parent_info.st_mode)
        or openclaw_parent_info.st_uid != os.geteuid()
        or stat.S_IMODE(openclaw_parent_info.st_mode) & 0o022
    ):
        raise RuntimeError("absent OpenClaw home must have a stable current-user-owned parent")
else:
    if (
        stat.S_ISLNK(openclaw_info.st_mode)
        or not stat.S_ISDIR(openclaw_info.st_mode)
        or openclaw_info.st_uid != os.geteuid()
        or stat.S_IMODE(openclaw_info.st_mode) & 0o022
    ):
        raise RuntimeError("resolved OpenClaw home must be a stable current-user-owned real directory")
config_parent = os.path.dirname(config_path) or "."
config_parent_info = os.lstat(config_parent)
if (
    stat.S_ISLNK(config_parent_info.st_mode)
    or not stat.S_ISDIR(config_parent_info.st_mode)
    or config_parent_info.st_uid != os.geteuid()
    or stat.S_IMODE(config_parent_info.st_mode) & 0o022
):
    raise RuntimeError("active config parent must be a stable current-user-owned real directory")
config_info = os.lstat(config_path)
if (
    stat.S_ISLNK(config_info.st_mode)
    or not stat.S_ISREG(config_info.st_mode)
    or config_info.st_uid != os.geteuid()
):
    raise RuntimeError("active config path must be a stable current-user-owned real file")
print("\t".join((data_dir, config_path, openclaw_home)))
PY
    )" || die "Could not resolve a stable controller-home/data-dir/config-path split from the installed source controller. No changes were made."
    IFS=$'\t' read -r DATA_DIR CONFIG_PATH RESOLVED_OPENCLAW_HOME <<< "${runtime_paths}"
    [[ -n "${DATA_DIR}" && -n "${CONFIG_PATH}" && -n "${RESOLVED_OPENCLAW_HOME}" ]] \
        || die "Installed source returned an incomplete runtime path contract. No changes were made."
    OPENCLAW_HOME="${RESOLVED_OPENCLAW_HOME}"
else
    CONFIG_PATH="$(python3 - "${CONFIG_PATH}" <<'PY'
import os
import sys

print(os.path.abspath(os.path.expanduser(sys.argv[1])))
PY
)" || die "Could not canonicalize the active config path; no changes were made."
    if [[ "${OPENCLAW_HOME_EXPLICIT}" -eq 1 ]]; then
        OPENCLAW_HOME="$(python3 - "${OPENCLAW_HOME}" <<'PY'
import os
import sys

print(os.path.abspath(os.path.expanduser(sys.argv[1])))
PY
)" || die "Could not canonicalize explicit OPENCLAW_HOME; no changes were made."
    fi
fi
[[ -n "${DATA_DIR}" && "${DATA_DIR}" == /* \
   && -n "${CONFIG_PATH}" && "${CONFIG_PATH}" == /* \
   && -n "${OPENCLAW_HOME}" && "${OPENCLAW_HOME}" == /* ]] \
    || die "Resolved runtime paths are invalid; no changes were made."

if [[ "${COMPONENT_VERSION_SPLIT}" -eq 1 ]]; then
    split_recovery="invalid"
    if [[ "${CURRENT_GATEWAY_VERSION}" == "${RELEASE_VERSION}" \
          && -x "${DEFENSECLAW_VENV}/bin/python" ]] \
        && version_lt "${CURRENT_VERSION}" "${CURRENT_GATEWAY_VERSION}"; then
        split_recovery="$(
            DEFENSECLAW_HOME="${DATA_DIR}" "${DEFENSECLAW_VENV}/bin/python" -I -B - \
                "${DATA_DIR}" "${CURRENT_VERSION}" "${RELEASE_VERSION}" <<'PY'
from datetime import datetime
import os
from pathlib import Path
import stat
import sys
import uuid

from defenseclaw.upgrade_receipt import (
    MAX_UPGRADE_RECEIPTS,
    UPGRADE_RECEIPT_DIRECTORY,
    load_upgrade_receipt,
)

data_dir, source_version, target_version = sys.argv[1:]
root = Path(os.path.abspath(os.path.expanduser(data_dir)))
receipt_dir = root / UPGRADE_RECEIPT_DIRECTORY
try:
    root_info = root.lstat()
    receipt_info = receipt_dir.lstat()
except FileNotFoundError:
    print("invalid")
    raise SystemExit(0)
if (
    stat.S_ISLNK(root_info.st_mode)
    or not stat.S_ISDIR(root_info.st_mode)
    or stat.S_ISLNK(receipt_info.st_mode)
    or not stat.S_ISDIR(receipt_info.st_mode)
):
    raise SystemExit("unsafe upgrade receipt directory")
if os.name == "posix":
    geteuid = getattr(os, "geteuid", None)
    if (
        (geteuid is not None and (root_info.st_uid != geteuid() or receipt_info.st_uid != geteuid()))
        or stat.S_IMODE(receipt_info.st_mode) & 0o077
    ):
        raise SystemExit("upgrade receipt directory is not private")

entries = sorted(receipt_dir.glob("*.json"))
if len(entries) > MAX_UPGRADE_RECEIPTS:
    raise SystemExit("upgrade receipt queue exceeds its bound")
authorities = []
for path in entries:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise SystemExit("upgrade receipt queue contains an unsafe entry")
    if os.name == "posix" and (
        (geteuid is not None and info.st_uid != geteuid())
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise SystemExit("upgrade receipt record is not private")
    receipt = load_upgrade_receipt(path)
    phase_matches = (
        receipt.migration_status == "pending"
        and receipt.migration_count is None
        and (
            (receipt.status == "pending" and receipt.failure_code == "")
            or (receipt.status == "failed" and receipt.failure_code == "interrupted")
        )
    )
    if (
        receipt.from_version == source_version
        and receipt.target_version == target_version
        and receipt.artifacts_verified
        and uuid.UUID(receipt.receipt_id).version == 4
        and phase_matches
    ):
        created_at = datetime.fromisoformat(receipt.created_at.replace("Z", "+00:00"))
        authorities.append((created_at, path))
if not authorities:
    print("invalid")
else:
    latest_created_at = max(created_at for created_at, _path in authorities)
    latest = [path for created_at, path in authorities if created_at == latest_created_at]
    print("recover" if len(latest) == 1 else "invalid")
PY
        )" || split_recovery="invalid"
    fi
    if [[ "${split_recovery}" != "recover" ]]; then
        die "Installed component versions are inconsistent: CLI ${CURRENT_VERSION}, gateway ${CURRENT_GATEWAY_VERSION}. No changes were made.
  This commonly means a package manager or manual artifact copy bypassed the staged upgrade.
  Recovery path: restore the CLI from the same signed ${CURRENT_GATEWAY_VERSION} release as the gateway, verify both --version outputs match, then run this release-owned resolver without --version."
    fi
    warn "Found an authenticated interrupted ${CURRENT_VERSION} → ${RELEASE_VERSION} artifact activation; the resolver will re-verify the release and resume it."
fi

if [[ "${CURRENT_VERSION}" != "unknown" ]] && version_gte "${CURRENT_VERSION}" "0.8.5"; then
    hard_cut_state="$("${DEFENSECLAW_VENV}/bin/python" -I -B - "${CONFIG_PATH}" \
        "${DATA_DIR}/.migration_state.json" <<'PY' 2>/dev/null || true
import json
import os
import stat
import sys

import yaml


def bounded_regular(path, limit):
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
        raise ValueError("unsafe state file")
    return info


config_path, cursor_path = sys.argv[1:]
bounded_regular(config_path, 4 * 1024 * 1024)
with open(config_path, encoding="utf-8") as stream:
    config = yaml.safe_load(stream)
bounded_regular(cursor_path, 1024 * 1024)
with open(cursor_path, encoding="utf-8") as stream:
    cursor = json.load(stream)
valid = (
    isinstance(config, dict)
    and config.get("config_version") == 8
    and isinstance(cursor, dict)
    and cursor.get("schema") == 1
    and isinstance(cursor.get("applied"), list)
    and "0.8.5" in cursor["applied"]
)
print("valid" if valid else "invalid")
PY
)"
    if [[ "${hard_cut_state}" != "valid" ]]; then
        die "CLI and gateway report hard-cut version ${CURRENT_VERSION}, but config-v8 migration state is absent or invalid and no recoverable journal is active. No changes were made.
  Unsupported manual overwrite detected.
  Recovery path: restore the exact 0.8.4 CLI, gateway, config, environment, and migration cursor from the pre-hard-cut backup, verify 0.8.4 health, then run this release-owned resolver without --version."
    fi
fi

if [[ "${CURRENT_VERSION}" != "unknown" ]]; then
    validate_version "${CURRENT_VERSION}"
    if version_lt "${RELEASE_VERSION}" "${CURRENT_VERSION}"; then
        die "Refusing to downgrade ${CURRENT_VERSION} to ${RELEASE_VERSION} through the upgrade path. No changes were made."
    fi
fi

# ── Same-version contract verification ───────────────────────────────────────

if [[ "${CURRENT_VERSION}" == "${RELEASE_VERSION}" ]]; then
    info "Installed version ${RELEASE_VERSION} is already current; authenticating its release contract before a no-change exit"
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

configure_release() {
    TARBALL_NAME="defenseclaw_${RELEASE_VERSION}_${OS}_${ARCH_NORM}.tar.gz"
    WHL_NAME="defenseclaw-${RELEASE_VERSION}-py3-none-any.whl"
    TARBALL_URL="https://github.com/${REPO}/releases/download/${RELEASE_VERSION}/${TARBALL_NAME}"
    WHL_URL="https://github.com/${REPO}/releases/download/${RELEASE_VERSION}/${WHL_NAME}"
    CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${RELEASE_VERSION}/checksums.txt"
    CHECKSUMS_SIG_URL="${CHECKSUMS_URL}.sig"
    CHECKSUMS_CERT_URL="${CHECKSUMS_URL}.pem"
    UPGRADE_MANIFEST_URL="https://github.com/${REPO}/releases/download/${RELEASE_VERSION}/${UPGRADE_MANIFEST_NAME}"
    RELEASE_PROVENANCE_URL="https://github.com/${REPO}/releases/download/${RELEASE_VERSION}/${RELEASE_PROVENANCE_NAME}"
    MATERIALIZED_TARBALL_NAME="${TARBALL_NAME}"
    MATERIALIZED_WHL_NAME="${WHL_NAME}"
}

configure_materialized_release_names() {
    if [[ "${WHL_NAME}" == *.dcwheel ]]; then
        MATERIALIZED_WHL_NAME="${WHL_NAME%.dcwheel}.whl"
    else
        MATERIALIZED_WHL_NAME="${WHL_NAME}"
    fi
    if [[ "${TARBALL_NAME}" == *.dcgateway ]]; then
        MATERIALIZED_TARBALL_NAME="${TARBALL_NAME%.dcgateway}.tar.gz"
    else
        MATERIALIZED_TARBALL_NAME="${TARBALL_NAME}"
    fi
}

materialize_protected_artifact() {
    local source="$1" destination="$2" expected_outer_sha256="$3"
    if [[ "${source}" == "${destination}" ]]; then
        return 0
    fi
    python3 - "${source}" "${destination}" "${expected_outer_sha256}" <<'PY'
import hashlib
import os
import re
import stat
import sys

source, destination = map(os.path.abspath, sys.argv[1:3])
expected_outer_sha256 = sys.argv[3].lower()
if not re.fullmatch(r"[0-9a-f]{64}", expected_outer_sha256):
    raise RuntimeError("protected release artifact lacks an authenticated outer digest")
magic = b"DEFENSECLAW-PROTECTED-ARTIFACT-V1\n"
source_info = os.lstat(source)
if (
    stat.S_ISLNK(source_info.st_mode)
    or not stat.S_ISREG(source_info.st_mode)
    or not len(magic) < source_info.st_size <= 2 * 1024 * 1024 * 1024
):
    raise RuntimeError("protected release artifact is unsafe or outside its size bound")
parent = os.path.dirname(destination)
parent_info = os.lstat(parent)
if (
    stat.S_ISLNK(parent_info.st_mode)
    or not stat.S_ISDIR(parent_info.st_mode)
    or parent_info.st_uid != os.geteuid()
    or stat.S_IMODE(parent_info.st_mode) & 0o077
):
    raise RuntimeError("protected artifact materialization directory is not private")
read_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
write_flags = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
source_fd = os.open(source, read_flags)
created = False
try:
    opened = os.fstat(source_fd)
    if not os.path.samestat(source_info, opened):
        raise RuntimeError("protected release artifact changed while opening")
    observed_magic = os.read(source_fd, len(magic))
    if observed_magic != magic:
        raise RuntimeError("protected release artifact magic is invalid")
    consumed_digest = hashlib.sha256(observed_magic)
    destination_fd = os.open(destination, write_flags, 0o600)
    created = True
    try:
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            consumed_digest.update(chunk)
            payload = bytes(value ^ 0xA5 for value in chunk)
            view = memoryview(payload)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise RuntimeError("protected artifact materialization write failed")
                view = view[written:]
        if consumed_digest.hexdigest() != expected_outer_sha256:
            raise RuntimeError(
                "protected release artifact changed after checksum authentication"
            )
        os.fsync(destination_fd)
    finally:
        os.close(destination_fd)
except BaseException:
    if created:
        try:
            os.unlink(destination)
        except FileNotFoundError:
            pass
    raise
finally:
    os.close(source_fd)
directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
PY
}

preflight_release_artifacts() {
    local artifact_url http_code
    for artifact_url in "${TARBALL_URL}" "${WHL_URL}"; do
        http_code=$(curl -sSo /dev/null -w "%{http_code}" -L --head "${artifact_url}" 2>/dev/null || echo "000")
        if [[ "${http_code}" -ge 400 || "${http_code}" == "000" ]]; then
            die "Artifact not found (HTTP ${http_code}): ${artifact_url}
  Version ${RELEASE_VERSION} may not exist or is missing platform artifacts. No changes were made."
        fi
    done
    ok "Release ${RELEASE_VERSION} artifacts verified"
}

configure_release

# ── Download artifacts to staging (gateway still running) ─────────────────────

section "Downloading Artifacts"

STAGING_DIR="$(mktemp -d)"
BRIDGE_PHASE1=0
BRIDGE_ROLLBACK_ARMED=0
BRIDGE_ROLLBACK_RUNNING=0
BRIDGE_SOURCE_VENV_MOVED=0
BRIDGE_CANDIDATE_VENV=""
BRIDGE_SOURCE_WAS_RUNNING=0
BRIDGE_SOURCE_HEALTH_URL=""
BRIDGE_GATEWAY_INSTALL_TEMP=""
BRIDGE_RECOVERY_PLAN_ID=""
BRIDGE_STATE_SNAPSHOT_READY=0
BRIDGE_EXPECTED_GATEWAY_SHA256=""
BRIDGE_EXPECTED_WHEEL_SHA256=""
BRIDGE_WHEEL_CUSTODY_PATH=""
BRIDGE_SOURCE_VENV_IDENTITY_SHA256=""
UPGRADE_RECEIPT_PATH=""
UPGRADE_RECEIPT_FAILURE_CODE="install_failed"
UPGRADE_RECEIPT_TERMINAL=0

upgrade_exit_trap() {
    local status=$?
    local rollback_status=0
    trap - EXIT
    set +e
    if [[ "${BRIDGE_ROLLBACK_ARMED:-0}" -eq 1 ]]; then
        rollback_bridge_phase1 || rollback_status=$?
    fi
    if [[ "${status}" -ne 0 && -n "${UPGRADE_RECEIPT_PATH:-}" \
        && "${UPGRADE_RECEIPT_TERMINAL:-0}" -eq 0 \
        && -x "${DEFENSECLAW_VENV}/bin/python" ]]; then
        VENV_PYTHON="${DEFENSECLAW_VENV}/bin/python"
        finish_release_upgrade_receipt failed "${UPGRADE_RECEIPT_FAILURE_CODE:-install_failed}" \
            || true
    fi
    [[ -z "${BRIDGE_GATEWAY_INSTALL_TEMP:-}" ]] || rm -f "${BRIDGE_GATEWAY_INSTALL_TEMP}"
    [[ -z "${BRIDGE_CANDIDATE_VENV:-}" ]] || rm -rf "${BRIDGE_CANDIDATE_VENV}"
    [[ -z "${STAGING_DIR:-}" ]] || rm -rf "${STAGING_DIR}"
    release_upgrade_lock
    if [[ "${rollback_status}" -ne 0 ]]; then
        err "Automatic source rollback was incomplete. Recovery evidence was preserved at ${BACKUP_DIR:-unknown}."
        status=2
    fi
    exit "${status}"
}
trap upgrade_exit_trap EXIT

# Pull checksums.txt FIRST so every downloaded artifact is verified against
# the published goreleaser manifest. Old releases may not publish one; in
# that case we proceed with a clear warning rather than blocking the
# upgrade. ``CHECKSUMS_FILE=""`` signals "no manifest available" downstream.
CHECKSUMS_FILE=""
CHECKSUMS_SIG_FILE=""
CHECKSUMS_CERT_FILE=""
CHECKSUMS_SIGNATURE_VERIFIED=0
COSIGN_BIN=""
ASSET_DIGESTS_FILE=""
UPGRADE_MANIFEST_FILE=""
RELEASE_PROVENANCE_FILE=""
RELEASE_PROVENANCE_BRIDGE_CHECKSUMS_SHA256=""
FINAL_RELEASE_PROVENANCE_BRIDGE_CHECKSUMS_SHA256=""
FINAL_RELEASE_VERSION=""
FINAL_RELEASE_WHL_NAME=""
FINAL_RELEASE_WHL_URL=""
FINAL_RELEASE_MATERIALIZED_WHL_NAME=""
FINAL_RELEASE_WHL_SHA256=""
TARGET_CONTROLLER_PROTECTED_WHEEL=""
TARGET_CONTROLLER_VENV=""
TARGET_CONTROLLER_CLI=""
HISTORICAL_BOOTSTRAP_CONSTRAINTS_FILE=""
CONTRACT_DIR=""
MIGRATION_FAILURE_POLICY="warn"
REQUIRED_MIGRATIONS_MISSING=""
UPGRADE_INCOMPLETE=0

download_release_contract_files() {
    CONTRACT_DIR="${STAGING_DIR}/contract-${RELEASE_VERSION}"
    mkdir -p "${CONTRACT_DIR}"
    CHECKSUMS_FILE=""
    CHECKSUMS_SIG_FILE=""
    CHECKSUMS_CERT_FILE=""
    CHECKSUMS_SIGNATURE_VERIFIED=0
    ASSET_DIGESTS_FILE=""
    UPGRADE_MANIFEST_FILE=""
    RELEASE_PROVENANCE_FILE=""
    RELEASE_PROVENANCE_BRIDGE_CHECKSUMS_SHA256=""
    MIGRATION_FAILURE_POLICY="warn"

    if fetch_optional_artifact "${CHECKSUMS_URL}" "${CONTRACT_DIR}/checksums.txt"; then
        CHECKSUMS_FILE="${CONTRACT_DIR}/checksums.txt"
        ok "Checksum manifest downloaded (checksums.txt)"
    elif version_gte "${RELEASE_VERSION}" "0.8.4"; then
        die "Release ${RELEASE_VERSION} has no checksum manifest. Refusing before services are stopped; no changes were made."
    else
        warn "checksums.txt unavailable — legacy release artifacts cannot be integrity-verified"
    fi

    if [[ -n "${CHECKSUMS_FILE}" ]]; then
        if fetch_optional_artifact "${CHECKSUMS_SIG_URL}" "${CONTRACT_DIR}/checksums.txt.sig"; then
            CHECKSUMS_SIG_FILE="${CONTRACT_DIR}/checksums.txt.sig"
        fi
        if fetch_optional_artifact "${CHECKSUMS_CERT_URL}" "${CONTRACT_DIR}/checksums.txt.pem"; then
            CHECKSUMS_CERT_FILE="${CONTRACT_DIR}/checksums.txt.pem"
        fi
    fi
}

fetch_asset_digests() {
    [[ -n "${ASSET_DIGESTS_FILE}" ]] && return 0
    command -v python3 &>/dev/null || return 1

    local release_json="${CONTRACT_DIR}/release-assets.json"
    local digests="${CONTRACT_DIR}/asset-digests.txt"
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
VERIFIED_CHECKSUM=""
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
    VERIFIED_CHECKSUM=""
    [[ -z "${CHECKSUMS_FILE}" ]] && ! fetch_asset_digests && return 0
    local expected actual
    expected=""
    if [[ -n "${CHECKSUMS_FILE}" ]]; then
        expected="$(awk -v f="${filename}" '$2 == f || $2 == "./" f {print $1; exit}' "${CHECKSUMS_FILE}")"
    fi
    if [[ -z "${expected}" ]] && version_lt "${RELEASE_VERSION}" "0.8.4" && fetch_asset_digests; then
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
    VERIFIED_CHECKSUM="${actual}"
}

resolve_cosign() {
    if command -v cosign >/dev/null 2>&1; then
        COSIGN_BIN="$(command -v cosign)"
        return 0
    fi

    local expected filename verifier_url verifier_path actual size
    case "${OS}/${ARCH_NORM}" in
        darwin/amd64) expected="5715d61dd00a9b6dcb344de14910b434145855b7f82690b94183c553ac1b68be" ;;
        darwin/arm64) expected="ff497a698f125f3130b04f000b2cb0dd163bcaf00b5e776ef536035e6d0b3f3e" ;;
        linux/amd64) expected="7c78a7f2efc00088bd788a758db6e0928e79f3e0eb83eb5d3c499ed98da4c4f4" ;;
        linux/arm64) expected="b7c23659a50a59fd8eec44b87188e9062157d0c87796cac7b38727e5390c4917" ;;
        *) die "Automatic Cosign bootstrap is unavailable for ${OS}/${ARCH_NORM}. No changes were made." ;;
    esac
    filename="cosign-${OS}-${ARCH_NORM}"
    verifier_url="https://github.com/sigstore/cosign/releases/download/v${COSIGN_BOOTSTRAP_VERSION}/${filename}"
    verifier_path="${CONTRACT_DIR}/${filename}"
    info "Cosign was not found; authenticating temporary Cosign ${COSIGN_BOOTSTRAP_VERSION}..."
    curl --fail --silent --show-error --location \
        --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --max-filesize "${COSIGN_BOOTSTRAP_MAX_BYTES}" \
        --output "${verifier_path}" "${verifier_url}" \
        || die "Could not download the pinned Cosign verifier. No changes were made."
    [[ -f "${verifier_path}" && ! -L "${verifier_path}" && -O "${verifier_path}" ]] \
        || die "Temporary Cosign verifier lost private file custody. No changes were made."
    if [[ "${OS}" == "darwin" ]]; then
        size="$(stat -f '%z' "${verifier_path}")"
    else
        size="$(stat -c '%s' "${verifier_path}")"
    fi
    [[ "${size}" -gt 0 && "${size}" -le "${COSIGN_BOOTSTRAP_MAX_BYTES}" ]] \
        || die "Temporary Cosign verifier exceeded its authenticated size boundary. No changes were made."
    actual="$(${SHA256_CMD} "${verifier_path}" | awk '{print $1}')"
    [[ "${actual}" == "${expected}" ]] \
        || die "Temporary Cosign verifier SHA-256 authentication failed. No changes were made."
    chmod 700 "${verifier_path}" \
        || die "Could not make the authenticated temporary Cosign verifier executable. No changes were made."
    actual="$(${SHA256_CMD} "${verifier_path}" | awk '{print $1}')"
    [[ "${actual}" == "${expected}" ]] \
        || die "Temporary Cosign verifier changed before execution. No changes were made."
    COSIGN_BIN="${verifier_path}"
    ok "Temporary Cosign verifier authenticated"
}

verify_checksums_sigstore() {
    [[ -z "${CHECKSUMS_FILE}" ]] && return 0
    if [[ -z "${CHECKSUMS_SIG_FILE}" && -z "${CHECKSUMS_CERT_FILE}" ]]; then
        if version_gte "${RELEASE_VERSION}" "0.8.4"; then
            die "Release ${RELEASE_VERSION} checksum manifest is unsigned. Refusing before services are stopped; no changes were made."
        fi
        return 0
    fi
    if [[ -z "${CHECKSUMS_SIG_FILE}" || -z "${CHECKSUMS_CERT_FILE}" ]]; then
        if version_gte "${RELEASE_VERSION}" "0.8.4"; then
            die "Release ${RELEASE_VERSION} checksum signature assets are incomplete. Refusing before services are stopped; no changes were made."
        fi
        warn "checksums.txt Sigstore signature assets are incomplete for this legacy release."
        return 0
    fi
    if ! command -v cosign >/dev/null 2>&1 && version_lt "${RELEASE_VERSION}" "0.8.4"; then
        warn "checksums.txt Sigstore signature is present, but cosign was not found on PATH for this legacy release."
        return 0
    fi
    resolve_cosign

    local cosign_output
    if ! cosign_output="$("${COSIGN_BIN}" verify-blob \
        --certificate "${CHECKSUMS_CERT_FILE}" \
        --signature "${CHECKSUMS_SIG_FILE}" \
        --certificate-identity "https://github.com/${REPO}/.github/workflows/release.yaml@refs/heads/main" \
        --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
        "${CHECKSUMS_FILE}" 2>&1)"; then
        err "checksums.txt Sigstore signature verification failed."
        printf '%s\n' "${cosign_output}" | head -5 >&2
        exit 1
    fi
    CHECKSUMS_SIGNATURE_VERIFIED=1
    ok "Checksum signature verified (Sigstore)"
}

print_new_upgrade_script_hint() {
    local mode="${1:-explicit}" invoke_args asset_base
    invoke_args="--yes --version ${RELEASE_VERSION}"
    [[ "${mode}" == "latest" ]] && invoke_args="--yes"
    asset_base="https://github.com/${REPO}/releases/download/${RELEASE_VERSION}"
    info "    Authenticate and run the upgrade resolver asset shipped with that release:"
    cat >&2 <<EOF
    (
      set -eu
      unset VERSION
      umask 077
      d="\$(mktemp -d "\${TMPDIR:-/tmp}/defenseclaw-upgrade.XXXXXX")"
      trap 'rm -rf "\$d"' EXIT
      cosign_bin="\$(command -v cosign || true)"
      if [ -z "\$cosign_bin" ]; then
        platform="\$(uname -s | tr '[:upper:]' '[:lower:]')/\$(uname -m)"
        case "\$platform" in
          darwin/x86_64) cosign_asset='cosign-darwin-amd64'; cosign_sha='5715d61dd00a9b6dcb344de14910b434145855b7f82690b94183c553ac1b68be' ;;
          darwin/arm64) cosign_asset='cosign-darwin-arm64'; cosign_sha='ff497a698f125f3130b04f000b2cb0dd163bcaf00b5e776ef536035e6d0b3f3e' ;;
          linux/x86_64|linux/amd64) cosign_asset='cosign-linux-amd64'; cosign_sha='7c78a7f2efc00088bd788a758db6e0928e79f3e0eb83eb5d3c499ed98da4c4f4' ;;
          linux/aarch64|linux/arm64) cosign_asset='cosign-linux-arm64'; cosign_sha='b7c23659a50a59fd8eec44b87188e9062157d0c87796cac7b38727e5390c4917' ;;
          *) echo 'Unsupported platform for automatic Cosign verification.' >&2; exit 1 ;;
        esac
        cosign_bin="\$d/\$cosign_asset"
        curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 --max-filesize 209715200 --output "\$cosign_bin" 'https://github.com/sigstore/cosign/releases/download/v${COSIGN_BOOTSTRAP_VERSION}/'"\$cosign_asset"
        if command -v sha256sum >/dev/null; then cosign_actual="\$(sha256sum "\$cosign_bin" | awk '{print \$1}')"; else cosign_actual="\$(shasum -a 256 "\$cosign_bin" | awk '{print \$1}')"; fi
        [ "\$cosign_actual" = "\$cosign_sha" ]
        chmod 700 "\$cosign_bin"
      fi
      for name in defenseclaw-upgrade.sh checksums.txt checksums.txt.sig checksums.txt.pem; do
        curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 --output "\$d/\$name" '${asset_base}/'"\$name"
      done
      # cosign verify-blob uses the existing or digest-authenticated temporary verifier.
      "\$cosign_bin" verify-blob --certificate "\$d/checksums.txt.pem" --signature "\$d/checksums.txt.sig" \
        --certificate-identity 'https://github.com/${REPO}/.github/workflows/release.yaml@refs/heads/main' \
        --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' "\$d/checksums.txt"
      line="\$(grep -E '^[0-9a-f]{64}  defenseclaw-upgrade[.]sh$' "\$d/checksums.txt")"
      [ "\$(printf '%s\n' "\$line" | wc -l | tr -d ' ')" = 1 ]
      expected="\${line%% *}"
      if command -v sha256sum >/dev/null; then
        actual="\$(sha256sum "\$d/defenseclaw-upgrade.sh" | awk '{print \$1}')"
      else
        actual="\$(shasum -a 256 "\$d/defenseclaw-upgrade.sh" | awk '{print \$1}')"
      fi
      [ "\$actual" = "\$expected" ]
      [ "\$(tail -n 1 "\$d/defenseclaw-upgrade.sh")" = '# DefenseClaw upgrade resolver complete v1' ]
      bash -n "\$d/defenseclaw-upgrade.sh"
      bash "\$d/defenseclaw-upgrade.sh" ${invoke_args}
    )
EOF
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

manifest_array_values() {
    local key="$1" path="$2"
    python3 - "${key}" "${path}" <<'PY'
import json
import re
import sys

key = sys.argv[1]
with open(sys.argv[2], encoding="utf-8") as fh:
    values = json.load(fh).get(key, [])
if not isinstance(values, list):
    raise SystemExit(1)
seen = set()
for value in values:
    if not isinstance(value, str) or not re.fullmatch(r"\d+\.\d+\.\d+", value) or value in seen:
        raise SystemExit(1)
    seen.add(value)
    print(value)
PY
}

manifest_array_contains() {
    local key="$1" expected="$2" path="$3"
    local values
    values="$(manifest_array_values "${key}" "${path}")" || return 1
    grep -Fxq "${expected}" <<<"${values}"
}

manifest_tested_source_contract() {
    local path="$1" target_version="$2"
    python3 - "${path}" "${target_version}" <<'PY'
import json
import re
import sys

path, target_version = sys.argv[1:]


def version_tuple(value):
    return tuple(map(int, value.split(".")))


with open(path, encoding="utf-8") as stream:
    document = json.load(stream)

tested = document.get("tested_source_versions")
platform_tested = document.get("platform_tested_source_versions")
if not isinstance(tested, list) or not tested:
    raise SystemExit("tested_source_versions must be a non-empty list")
if not isinstance(platform_tested, dict) or set(platform_tested) != {"windows"}:
    raise SystemExit(
        "platform_tested_source_versions must contain exactly the Windows source list"
    )
windows = platform_tested["windows"]
if not isinstance(windows, list):
    raise SystemExit("platform_tested_source_versions.windows must be a list")


def validate_versions(label, values):
    if any(
        not isinstance(value, str) or re.fullmatch(r"\d+\.\d+\.\d+", value) is None
        for value in values
    ):
        raise SystemExit(f"{label} must contain canonical versions")
    if len(values) != len(set(values)):
        raise SystemExit(f"{label} must not contain duplicates")
    if values != sorted(values, key=version_tuple, reverse=True):
        raise SystemExit(f"{label} must be strictly descending")


validate_versions("tested_source_versions", tested)
validate_versions("platform_tested_source_versions.windows", windows)
if any(value not in tested for value in windows):
    raise SystemExit("the Windows tested-source matrix must be a subset of the global matrix")
target = version_tuple(target_version)
if any(version_tuple(value) >= target for value in tested):
    raise SystemExit("tested sources must be older than the target release")
print(tested[-1])
PY
}

manifest_runtime_config_contract() {
    local path="$1" target_version="$2" schema_version="$3"
    python3 - "${path}" "${target_version}" "${schema_version}" <<'PY'
import json
import sys

path, target_version, schema_version_raw = sys.argv[1:]
schema_version = int(schema_version_raw)
with open(path, encoding="utf-8") as stream:
    document = json.load(stream)

if schema_version == 1:
    if "runtime_config_version" in document:
        raise SystemExit("schema-1 manifests must not declare runtime_config_version")
    raise SystemExit(0)

value = document.get("runtime_config_version")
expected = 7 if target_version == "0.8.4" else 8
if type(value) is not int or value != expected:
    raise SystemExit(
        f"runtime_config_version must be integer {expected} for release {target_version}"
    )
PY
}

manifest_release_artifact_contract() {
    local path="$1" target_version="$2" schema_version="$3" os_name="$4" arch_name="$5"
    python3 - \
        "${path}" "${target_version}" "${schema_version}" "${os_name}" "${arch_name}" <<'PY'
import json
import sys

path, version, schema_version_raw, os_name, arch_name = sys.argv[1:]
schema_version = int(schema_version_raw)
with open(path, encoding="utf-8") as stream:
    document = json.load(stream)

if schema_version == 1:
    if "release_artifacts" in document:
        raise SystemExit("schema-1 manifests must not declare release_artifacts")
    raise SystemExit(0)

artifacts = document.get("release_artifacts")
if not isinstance(artifacts, dict) or set(artifacts) != {"wheel", "gateways"}:
    raise SystemExit("release_artifacts must contain exactly wheel and gateways")
gateways = artifacts["gateways"]
if not isinstance(gateways, dict) or set(gateways) != {"darwin", "linux", "windows"}:
    raise SystemExit("release_artifacts.gateways has an incomplete platform matrix")

expected_wheel = f"defenseclaw-{version}-2-py3-none-any.dcwheel"
expected_gateways = {
    platform: {
        arch: f"defenseclaw_{version}_protocol2_{platform}_{arch}.dcgateway"
        for arch in ("amd64", "arm64")
    }
    for platform in ("darwin", "linux", "windows")
}

if artifacts["wheel"] != expected_wheel:
    raise SystemExit("release_artifacts.wheel is not the canonical protected filename")
all_names = [artifacts["wheel"]]
for platform, expected_arches in expected_gateways.items():
    actual_arches = gateways[platform]
    if not isinstance(actual_arches, dict) or set(actual_arches) != {"amd64", "arm64"}:
        raise SystemExit(f"release_artifacts.gateways.{platform} has an incomplete architecture matrix")
    for arch, expected_name in expected_arches.items():
        actual_name = actual_arches[arch]
        if actual_name != expected_name:
            raise SystemExit(
                f"release_artifacts.gateways.{platform}.{arch} is not the canonical protected filename"
            )
        all_names.append(actual_name)
if any("/" in name or "\\" in name or name in ("", ".", "..") for name in all_names):
    raise SystemExit("release_artifacts filenames must be non-empty basenames")
if len(all_names) != len(set(all_names)):
    raise SystemExit("release_artifacts filenames must be unique")
if os_name not in ("darwin", "linux") or arch_name not in ("amd64", "arm64"):
    raise SystemExit("the current POSIX platform is absent from release_artifacts")

print(artifacts["wheel"])
print(gateways[os_name][arch_name])
PY
}

load_release_provenance() {
    RELEASE_PROVENANCE_FILE=""
    RELEASE_PROVENANCE_BRIDGE_CHECKSUMS_SHA256=""
    version_gte "${RELEASE_VERSION}" "0.8.5" || return 0

    local provenance_path="${CONTRACT_DIR}/${RELEASE_PROVENANCE_NAME}"
    fetch_optional_artifact "${RELEASE_PROVENANCE_URL}" "${provenance_path}" \
        || die "Release ${RELEASE_VERSION} has no bounded ${RELEASE_PROVENANCE_NAME}. Refusing before services are stopped; no changes were made."
    verify_checksum "${provenance_path}" "${RELEASE_PROVENANCE_NAME}"
    RELEASE_PROVENANCE_BRIDGE_CHECKSUMS_SHA256="$(python3 - \
        "${provenance_path}" "${RELEASE_VERSION}" <<'PY'
import json
import os
from pathlib import Path
import re
import stat
import sys

path = Path(sys.argv[1])
target = sys.argv[2]
info = path.lstat()
if (
    stat.S_ISLNK(info.st_mode)
    or not stat.S_ISREG(info.st_mode)
    or info.st_uid != os.geteuid()
    or not 0 < info.st_size <= 16 * 1024
):
    raise SystemExit("release provenance is not a bounded current-user file")
raw = path.read_bytes()
try:
    document = json.loads(raw)
except (UnicodeError, json.JSONDecodeError) as exc:
    raise SystemExit("release provenance is invalid JSON") from exc
top = {
    "schema_version", "release_version", "source_commit", "source_tree",
    "policy_commit", "policy_tree", "release_source_map_sha256",
    "source_install_identity", "bridge",
}
identity_keys = {
    "schema_version", "source_release", "source_install_compatibility_epoch",
    "runtime_config_version",
}
bridge_keys = {"version", "commit", "tree", "checksums_sha256"}
if not isinstance(document, dict) or set(document) != top or document.get("schema_version") != 1:
    raise SystemExit("release provenance is not closed schema 1")
identity = document.get("source_install_identity")
bridge = document.get("bridge")
if not isinstance(identity, dict) or set(identity) != identity_keys:
    raise SystemExit("release provenance source identity is not closed")
if not isinstance(bridge, dict) or set(bridge) != bridge_keys:
    raise SystemExit("release provenance bridge identity is not closed")
if document.get("release_version") != target or identity.get("source_release") != target:
    raise SystemExit("release provenance target identity differs")
if identity.get("schema_version") != 1 or bridge.get("version") != "0.8.4":
    raise SystemExit("release provenance bridge/source identity differs")
sha1_values = (
    document.get("source_commit"), document.get("source_tree"),
    document.get("policy_commit"), document.get("policy_tree"),
    bridge.get("commit"), bridge.get("tree"),
)
sha256_values = (
    document.get("release_source_map_sha256"), bridge.get("checksums_sha256"),
)
if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value) for value in sha1_values):
    raise SystemExit("release provenance Git identity is noncanonical")
if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in sha256_values):
    raise SystemExit("release provenance SHA-256 identity is noncanonical")
epoch = identity.get("source_install_compatibility_epoch")
runtime = identity.get("runtime_config_version")
if isinstance(epoch, bool) or not isinstance(epoch, int) or isinstance(runtime, bool) or not isinstance(runtime, int):
    raise SystemExit("release provenance source-install identity is invalid")
if target == "0.8.5":
    if epoch != 2 or runtime != 8:
        raise SystemExit("release provenance lacks the exact 0.8.5 source identity")
elif epoch < 2 or runtime < 8:
    raise SystemExit("release provenance reuses a pre-hard-cut source identity")
canonical = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
if raw != canonical:
    raise SystemExit("release provenance JSON is not canonical")
print(bridge["checksums_sha256"])
PY
    )" || die "${RELEASE_PROVENANCE_NAME} failed its closed identity contract before services were stopped."
    [[ "${RELEASE_PROVENANCE_BRIDGE_CHECKSUMS_SHA256}" =~ ^[0-9a-f]{64}$ ]] \
        || die "${RELEASE_PROVENANCE_NAME} lacks a canonical bridge checksum identity."
    RELEASE_PROVENANCE_FILE="${provenance_path}"
    ok "Hard-cut release provenance authenticated"
}

require_bridge_checksums_provenance() {
    local expected="$1" checksums_path="$2" actual
    [[ "${expected}" =~ ^[0-9a-f]{64}$ ]] \
        || die "Hard-cut release provenance was not retained before bridge selection; no changes were made."
    actual="$(python3 - "${checksums_path}" <<'PY'
import hashlib
from pathlib import Path
import sys

path = Path(sys.argv[1])
payload = path.read_bytes()
if not 0 < len(payload) <= 4 * 1024 * 1024:
    raise SystemExit("bridge checksums are outside their size bound")
print(hashlib.sha256(payload).hexdigest())
PY
    )" || die "Could not hash authenticated bridge checksums before stopping services."
    [[ "${actual}" == "${expected}" ]] \
        || die "Authenticated 0.8.4 checksums do not match ${RELEASE_PROVENANCE_NAME}. Refusing before services are stopped; no changes were made."
    ok "Authenticated 0.8.4 checksum identity matches the hard-cut release"
}

load_upgrade_manifest() {
    local manifest_path="${CONTRACT_DIR}/${UPGRADE_MANIFEST_NAME}"
    if ! fetch_optional_artifact "${UPGRADE_MANIFEST_URL}" "${manifest_path}"; then
        if version_gte "${RELEASE_VERSION}" "0.8.4"; then
            die "Release ${RELEASE_VERSION} has no mandatory upgrade manifest. Refusing before services are stopped; no changes were made."
        fi
        return 0
    fi

    verify_checksum "${manifest_path}" "${UPGRADE_MANIFEST_NAME}"

    local schema_version release_version min_protocol policy expected_schema
    local controller_protocol minimum_source required_bridge oldest_tested_source
    local release_artifact_names
    schema_version="$(manifest_value "schema_version" "${manifest_path}")" \
        || die "Could not parse ${UPGRADE_MANIFEST_NAME}"
    release_version="$(manifest_value "release_version" "${manifest_path}")" \
        || die "Could not parse ${UPGRADE_MANIFEST_NAME}"
    min_protocol="$(manifest_value "min_upgrade_protocol" "${manifest_path}")" \
        || die "Could not parse ${UPGRADE_MANIFEST_NAME}"
    policy="$(manifest_value "migration_failure_policy" "${manifest_path}")" \
        || die "Could not parse ${UPGRADE_MANIFEST_NAME}"
    controller_protocol="$(manifest_value "controller_upgrade_protocol" "${manifest_path}")" \
        || die "Could not parse ${UPGRADE_MANIFEST_NAME}"
    minimum_source="$(manifest_value "minimum_source_version" "${manifest_path}")" \
        || die "Could not parse ${UPGRADE_MANIFEST_NAME}"
    required_bridge="$(manifest_value "required_bridge_version" "${manifest_path}")" \
        || die "Could not parse ${UPGRADE_MANIFEST_NAME}"

    [[ -z "${schema_version}" ]] \
        && die "${UPGRADE_MANIFEST_NAME} missing integer schema_version"
    [[ "${schema_version}" =~ ^[0-9]+$ ]] \
        || die "${UPGRADE_MANIFEST_NAME} schema_version must be an integer"
    expected_schema=1
    version_gte "${RELEASE_VERSION}" "0.8.4" && expected_schema=2
    if [[ "${schema_version}" -ne "${expected_schema}" ]]; then
        warn "Release ${RELEASE_VERSION} uses upgrade manifest schema ${schema_version}, which this upgrader does not understand."
        print_new_upgrade_script_hint
        exit 1
    fi
    manifest_runtime_config_contract "${manifest_path}" "${RELEASE_VERSION}" "${schema_version}" \
        || die "${UPGRADE_MANIFEST_NAME} has an invalid runtime_config_version contract"
    release_artifact_names="$(manifest_release_artifact_contract \
        "${manifest_path}" "${RELEASE_VERSION}" "${schema_version}" "${OS}" "${ARCH_NORM}")" \
        || die "${UPGRADE_MANIFEST_NAME} has an invalid release_artifacts contract"
    if [[ "${schema_version}" -eq 2 ]]; then
        WHL_NAME="$(printf '%s\n' "${release_artifact_names}" | sed -n '1p')"
        TARBALL_NAME="$(printf '%s\n' "${release_artifact_names}" | sed -n '2p')"
        [[ -n "${WHL_NAME}" && -n "${TARBALL_NAME}" ]] \
            || die "${UPGRADE_MANIFEST_NAME} did not select protected artifacts for this platform"
        WHL_URL="https://github.com/${REPO}/releases/download/${RELEASE_VERSION}/${WHL_NAME}"
        TARBALL_URL="https://github.com/${REPO}/releases/download/${RELEASE_VERSION}/${TARBALL_NAME}"
        configure_materialized_release_names
    fi

    [[ "${release_version}" == "${RELEASE_VERSION}" ]] \
        || die "${UPGRADE_MANIFEST_NAME} release_version mismatch: expected ${RELEASE_VERSION}, got ${release_version:-<missing>}"

    [[ -z "${min_protocol}" ]] && min_protocol=1
    [[ "${min_protocol}" =~ ^[0-9]+$ ]] \
        || die "${UPGRADE_MANIFEST_NAME} min_upgrade_protocol must be an integer"
    [[ "${min_protocol}" -ge 1 ]] \
        || die "${UPGRADE_MANIFEST_NAME} min_upgrade_protocol must be positive"
    if [[ "${min_protocol}" -gt "${UPGRADE_PROTOCOL_VERSION}" ]]; then
        warn "Release ${RELEASE_VERSION} requires upgrade protocol ${min_protocol}, but this upgrader supports ${UPGRADE_PROTOCOL_VERSION}."
        print_new_upgrade_script_hint
        exit 1
    fi

    [[ -z "${controller_protocol}" ]] && controller_protocol=1
    [[ "${controller_protocol}" =~ ^[0-9]+$ ]] \
        || die "${UPGRADE_MANIFEST_NAME} controller_upgrade_protocol must be an integer"
    [[ "${controller_protocol}" -ge 1 ]] \
        || die "${UPGRADE_MANIFEST_NAME} controller_upgrade_protocol must be positive"

    if [[ -n "${minimum_source}" ]]; then
        validate_version "${minimum_source}"
        version_gte "${RELEASE_VERSION}" "${minimum_source}" \
            || die "${UPGRADE_MANIFEST_NAME} minimum_source_version cannot exceed its release_version"
        [[ -n "${required_bridge}" ]] \
            || die "${UPGRADE_MANIFEST_NAME} minimum_source_version requires required_bridge_version"
        validate_version "${required_bridge}"
        [[ "${required_bridge}" == "${minimum_source}" ]] \
            || die "${UPGRADE_MANIFEST_NAME} required_bridge_version must equal minimum_source_version"
        manifest_array_values "auto_bridge_from" "${manifest_path}" >/dev/null \
            || die "${UPGRADE_MANIFEST_NAME} auto_bridge_from must contain unique canonical versions"
    elif [[ -n "${required_bridge}" ]]; then
        die "${UPGRADE_MANIFEST_NAME} required_bridge_version requires minimum_source_version"
    fi

    if version_gte "${RELEASE_VERSION}" "0.8.5"; then
        [[ "${min_protocol}" -ge 2 && -n "${minimum_source}" && -n "${required_bridge}" ]] \
            || die "Release ${RELEASE_VERSION} is a hard-cut target but its complete protocol-2 bridge contract is missing"
    fi
    if [[ "${RELEASE_VERSION}" == "0.8.4" && "${controller_protocol}" -lt 2 ]]; then
        die "Release 0.8.4 does not provide the protocol-2 bridge controller"
    fi

    oldest_tested_source=""
    if [[ "${schema_version}" -eq 2 ]]; then
        oldest_tested_source="$(manifest_tested_source_contract "${manifest_path}" "${RELEASE_VERSION}")" \
            || die "${UPGRADE_MANIFEST_NAME} lacks a complete valid tested-source contract"
    fi

    [[ -z "${policy}" ]] && policy="warn"
    case "${policy}" in
        warn|fail) MIGRATION_FAILURE_POLICY="${policy}" ;;
        *) die "${UPGRADE_MANIFEST_NAME} has invalid migration_failure_policy: ${policy}" ;;
    esac

    UPGRADE_MANIFEST_FILE="${manifest_path}"
    MANIFEST_MIN_PROTOCOL="${min_protocol}"
    MANIFEST_CONTROLLER_PROTOCOL="${controller_protocol}"
    MANIFEST_MINIMUM_SOURCE="${minimum_source}"
    MANIFEST_REQUIRED_BRIDGE="${required_bridge}"
    MANIFEST_OLDEST_TESTED_SOURCE="${oldest_tested_source}"
    ok "Upgrade manifest loaded"
}

enforce_tested_source_matrix() {
    local supported
    [[ -n "${MANIFEST_OLDEST_TESTED_SOURCE:-}" ]] || return 0
    [[ "${CURRENT_VERSION}" != "unknown" ]] || return 0
    [[ "${CURRENT_VERSION}" != "${RELEASE_VERSION}" ]] || return 0
    if manifest_array_contains "tested_source_versions" "${CURRENT_VERSION}" "${UPGRADE_MANIFEST_FILE}"; then
        return 0
    fi
    supported="$(manifest_array_values "tested_source_versions" "${UPGRADE_MANIFEST_FILE}" \
        | paste -sd ',' - | sed 's/,/, /g')"
    die "Installed version ${CURRENT_VERSION} is outside the published-baseline test matrix for ${RELEASE_VERSION}. No changes were made.
  Tested sources: ${supported:-none}.
  There is no tested in-place upgrade path from ${CURRENT_VERSION}; do not infer a hop by installing one of the listed versions.
  Remain on ${CURRENT_VERSION} and contact DefenseClaw support for a validated recovery path."
}

prepare_release_contract() {
    download_release_contract_files
    verify_checksums_sigstore
    load_release_provenance
    load_upgrade_manifest
    enforce_tested_source_matrix
    preflight_release_artifacts
}

capture_hard_cut_target_controller_contract() {
    local expected matches
    [[ "${RELEASE_VERSION}" == "${MANIFEST_REQUIRED_BRIDGE:-}" ]] \
        && die "The hard-cut target controller cannot be the bridge release. No changes were made."
    [[ -n "${CHECKSUMS_FILE}" && "${CHECKSUMS_SIGNATURE_VERIFIED}" -eq 1 ]] \
        || die "The hard-cut target controller lacks an authenticated checksum manifest. No changes were made."
    [[ -n "${WHL_NAME}" && -n "${WHL_URL}" && -n "${MATERIALIZED_WHL_NAME}" ]] \
        || die "The hard-cut target controller wheel contract is incomplete. No changes were made."
    matches="$(awk -v f="${WHL_NAME}" '$2 == f || $2 == "./" f {print $1}' "${CHECKSUMS_FILE}")"
    [[ "$(printf '%s\n' "${matches}" | sed '/^$/d' | wc -l | tr -d ' ')" == "1" ]] \
        || die "The hard-cut target controller wheel has no unique authenticated digest. No changes were made."
    expected="$(printf '%s\n' "${matches}" | sed -n '1p' | tr '[:upper:]' '[:lower:]')"
    [[ "${expected}" =~ ^[0-9a-f]{64}$ ]] \
        || die "The hard-cut target controller wheel digest is invalid. No changes were made."

    FINAL_RELEASE_VERSION="${RELEASE_VERSION}"
    FINAL_RELEASE_WHL_NAME="${WHL_NAME}"
    FINAL_RELEASE_WHL_URL="${WHL_URL}"
    FINAL_RELEASE_MATERIALIZED_WHL_NAME="${MATERIALIZED_WHL_NAME}"
    FINAL_RELEASE_WHL_SHA256="${expected}"
}

select_hard_cut_bootstrap_contract() {
    # The 0.8.5 release owns the one supported v7 -> v8 dependency cut.  A
    # later target must not try to perform that cut while preserving the 0.8.4
    # environment: the two authenticated dependency graphs are intentionally
    # incompatible.  Authenticate 0.8.5 now, finish that transaction first,
    # then continue from the healthy 0.8.5 installation to the requested tag.
    version_lt "${OBSERVABILITY_V8_HARD_CUT_VERSION}" "${RELEASE_VERSION}" \
        || return 0

    POST_HARD_CUT_FINAL_VERSION="${RELEASE_VERSION}"
    RELEASE_VERSION="${OBSERVABILITY_V8_HARD_CUT_VERSION}"
    section "Hard-Cut Bootstrap"
    ok "Authenticated upgrade path will stage ${RELEASE_VERSION} before ${POST_HARD_CUT_FINAL_VERSION}"
    configure_release
    prepare_release_contract
    FINAL_RELEASE_PROVENANCE_BRIDGE_CHECKSUMS_SHA256="${RELEASE_PROVENANCE_BRIDGE_CHECKSUMS_SHA256}"
}

resolve_staged_upgrade() {
    local supported
    [[ -n "${MANIFEST_MINIMUM_SOURCE:-}" ]] || return 0
    [[ "${CURRENT_VERSION}" != "unknown" ]] \
        || die "Cannot determine the installed version required by release ${RELEASE_VERSION}. No changes were made."
    validate_version "${CURRENT_VERSION}"
    if version_gte "${CURRENT_VERSION}" "${MANIFEST_MINIMUM_SOURCE}"; then
        if [[ "${CURRENT_VERSION}" == "${MANIFEST_REQUIRED_BRIDGE}" ]] \
            && version_lt "${CURRENT_VERSION}" "${RELEASE_VERSION}"; then
            select_hard_cut_bootstrap_contract
            if [[ -n "${POST_HARD_CUT_FINAL_VERSION}" ]]; then
                section "Staged Upgrade Plan"
                ok "${CURRENT_VERSION} → ${RELEASE_VERSION} → ${POST_HARD_CUT_FINAL_VERSION}"
            fi
            capture_hard_cut_target_controller_contract
            FRESH_HARD_CUT_HANDOFF=1
            STAGED_FINAL_MIN_PROTOCOL="${MANIFEST_MIN_PROTOCOL}"
        fi
        return 0
    fi

    # A version override selects the final release; it never authorizes a
    # direct hard-cut install.  Legacy controllers that cannot parse schema 2
    # hand off to the target resolver with exactly this override, so the
    # release-owned resolver must preserve that target intent while still
    # inserting every manifest-required bridge.
    select_hard_cut_bootstrap_contract
    if ! manifest_array_contains "auto_bridge_from" "${CURRENT_VERSION}" "${UPGRADE_MANIFEST_FILE}"; then
        supported="$(manifest_array_values "auto_bridge_from" "${UPGRADE_MANIFEST_FILE}" | paste -sd ',' - | sed 's/,/, /g')"
        die "Installed version ${CURRENT_VERSION} is outside the tested automatic bridge matrix. No changes were made.
  Supported staged sources: ${supported:-none}.
  Do not force ${MANIFEST_REQUIRED_BRIDGE} or infer an intermediate hop from another source's path.
  Remain on ${CURRENT_VERSION} and contact DefenseClaw support for a validated state-aware recovery path."
    fi

    capture_hard_cut_target_controller_contract
    STAGED_FINAL_VERSION="${RELEASE_VERSION}"
    STAGED_FINAL_MIN_PROTOCOL="${MANIFEST_MIN_PROTOCOL}"
    RELEASE_VERSION="${MANIFEST_REQUIRED_BRIDGE}"
    section "Staged Upgrade Plan"
    if [[ -n "${POST_HARD_CUT_FINAL_VERSION}" ]]; then
        ok "${CURRENT_VERSION} → ${RELEASE_VERSION} bridge → fresh controller → ${STAGED_FINAL_VERSION} → ${POST_HARD_CUT_FINAL_VERSION}"
    else
        ok "${CURRENT_VERSION} → ${RELEASE_VERSION} bridge → fresh controller → ${STAGED_FINAL_VERSION}"
    fi

    configure_release
    prepare_release_contract
    require_bridge_checksums_provenance \
        "${FINAL_RELEASE_PROVENANCE_BRIDGE_CHECKSUMS_SHA256}" \
        "${CHECKSUMS_FILE}"
    if [[ "${MANIFEST_CONTROLLER_PROTOCOL}" -lt "${STAGED_FINAL_MIN_PROTOCOL}" ]]; then
        die "Bridge ${RELEASE_VERSION} only provides upgrade protocol ${MANIFEST_CONTROLLER_PROTOCOL}; ${STAGED_FINAL_VERSION} requires ${STAGED_FINAL_MIN_PROTOCOL}. No changes were made."
    fi
}

preflight_bridge_rollback_capability() {
    local wheel="$1"
    python3 - "${wheel}" <<'PY'
import ast
import sys
import zipfile

wheel = sys.argv[1]
member = "defenseclaw/commands/cmd_upgrade.py"
try:
    with zipfile.ZipFile(wheel) as archive:
        matches = [name for name in archive.namelist() if name == member]
        if len(matches) != 1:
            raise ValueError("bridge wheel has no unique upgrade controller")
        info = archive.getinfo(matches[0])
        if info.file_size <= 0 or info.file_size > 8 * 1024 * 1024:
            raise ValueError("bridge upgrade controller has invalid size")
        tree = ast.parse(archive.read(matches[0]), filename=matches[0])
except (OSError, ValueError, zipfile.BadZipFile, SyntaxError) as exc:
    raise SystemExit(f"bridge rollback capability preflight failed: {exc}")

functions = {
    node.name
    for node in tree.body
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
}
if "_prepare_hard_cut_rollback_plan" not in functions:
    raise SystemExit("bridge controller lacks hard-cut rollback preparation")
calls = [
    node
    for node in ast.walk(tree)
    if isinstance(node, ast.Call)
    and isinstance(node.func, ast.Name)
    and node.func.id == "_prepare_hard_cut_rollback_plan"
]
if not calls:
    raise SystemExit("bridge controller never invokes hard-cut rollback preparation")
assignments = {
    target.id: node.value.value
    for node in tree.body
    if isinstance(node, ast.Assign)
    and isinstance(node.value, ast.Constant)
    and isinstance(node.value.value, str)
    for target in node.targets
    if isinstance(target, ast.Name)
}
if assignments.get("_STAGED_BRIDGE_ARTIFACT_DIR_ENV") != "DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR":
    raise SystemExit("bridge controller lacks the staged artifact handoff contract")
PY
    ok "Bridge controller rollback capability verified"
}

create_bridge_handoff_directory() {
    local destination="$1"
    mkdir -p "${destination}"
    chmod 700 "${destination}"
    cp "${CHECKSUMS_FILE}" "${destination}/checksums.txt"
    cp "${CHECKSUMS_SIG_FILE}" "${destination}/checksums.txt.sig"
    cp "${CHECKSUMS_CERT_FILE}" "${destination}/checksums.txt.pem"
    cp "${UPGRADE_MANIFEST_FILE}" "${destination}/${UPGRADE_MANIFEST_NAME}"
    cp "${STAGING_DIR}/${WHL_NAME}" "${destination}/${WHL_NAME}"
    cp "${STAGING_DIR}/${TARBALL_NAME}" "${destination}/${TARBALL_NAME}"
    chmod 600 \
        "${destination}/checksums.txt" \
        "${destination}/checksums.txt.sig" \
        "${destination}/checksums.txt.pem" \
        "${destination}/${UPGRADE_MANIFEST_NAME}" \
        "${destination}/${WHL_NAME}" \
        "${destination}/${TARBALL_NAME}"
    printf '%s\n' "${destination}"
}

restore_bridge_config_comments() {
    local original_config
    local result

    [[ "${BRIDGE_PHASE1}" -eq 1 ]] || return 0
    original_config="$(bridge_phase1_state_transaction config-comment-source)" \
        || die "Could not authenticate the phase-one configuration snapshot for comment continuity"
    [[ -n "${original_config}" ]] || return 0
    [[ -e "${CONFIG_PATH}" || -L "${CONFIG_PATH}" ]] \
        || die "The bridge configuration disappeared before comment continuity could be verified"

    result="$("${VENV_PYTHON}" -I -B - \
        "${original_config}" \
        "${CONFIG_PATH}" \
        "${BRIDGE_RECOVERY_PLAN_ID#phase-one-}" <<'PY'
# BEGIN BRIDGE_COMMENT_RESTORE_PY
from __future__ import annotations

import collections
import ctypes
import os
import re
import stat
import sys
import tempfile

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

MAX_CONFIG_BYTES = 4 * 1024 * 1024
source_path, active_path = (os.path.abspath(path) for path in sys.argv[1:3])
mutation_token = sys.argv[3]
if re.fullmatch(r"[0-9a-f]{32}", mutation_token) is None:
    raise RuntimeError("comment continuity mutation token is invalid")


def fail(message: str) -> None:
    raise RuntimeError(message)


def identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def require_private_parent(path: str) -> str:
    parent = os.path.dirname(path)
    info = os.lstat(parent)
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        fail("configuration parent is not private current-user custody")
    return parent


def read_stable(path: str) -> tuple[bytes, os.stat_result]:
    require_private_parent(path)
    named_before = os.lstat(path)
    if (
        stat.S_ISLNK(named_before.st_mode)
        or not stat.S_ISREG(named_before.st_mode)
        or named_before.st_uid != os.geteuid()
        or named_before.st_nlink != 1
        or named_before.st_size <= 0
        or named_before.st_size > MAX_CONFIG_BYTES
    ):
        fail("configuration source is not one bounded current-user-owned regular file")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags)
    try:
        opened_before = os.fstat(descriptor)
        if identity(opened_before) != identity(named_before):
            fail("configuration source changed while opening")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, MAX_CONFIG_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_CONFIG_BYTES:
                fail("configuration source exceeds its size bound")
        opened_after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    named_after = os.lstat(path)
    if identity(opened_after) != identity(opened_before) or identity(named_after) != identity(named_before):
        fail("configuration source changed while reading")
    payload = b"".join(chunks)
    if len(payload) != named_before.st_size:
        fail("configuration source length changed while reading")
    return payload, named_before


def scalar_ranges(node: Node) -> tuple[tuple[int, int], ...]:
    if isinstance(node, ScalarNode):
        return ((node.start_mark.index, node.end_mark.index),)
    if isinstance(node, MappingNode):
        children = [child for pair in node.value for child in pair]
    elif isinstance(node, SequenceNode):
        children = list(node.value)
    else:
        children = []
    return tuple(item for child in children for item in scalar_ranges(child))


def parsed_mapping(text: str, label: str) -> dict[object, object]:
    try:
        value = yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError, UnicodeError) as exc:
        fail(f"{label} is not safe YAML: {exc}")
    if not isinstance(value, dict):
        fail(f"{label} must contain one YAML mapping")
    return value


def comments(payload: bytes, label: str) -> tuple[str, ...]:
    try:
        text = payload.decode("utf-8")
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except (yaml.YAMLError, RecursionError, UnicodeError) as exc:
        fail(f"{label} comments could not be parsed safely: {exc}")
    if not isinstance(root, MappingNode):
        fail(f"{label} must contain one YAML mapping")

    ranges = sorted(scalar_ranges(root))
    range_index = 0
    found: list[str] = []
    cursor = 0
    for raw_line in text.splitlines(keepends=True):
        for index, character in enumerate(raw_line):
            absolute = cursor + index
            if character != "#" or (index > 0 and not raw_line[index - 1].isspace()):
                continue
            while range_index < len(ranges) and ranges[range_index][1] <= absolute:
                range_index += 1
            inside_scalar = (
                range_index < len(ranges)
                and ranges[range_index][0] <= absolute < ranges[range_index][1]
            )
            if not inside_scalar:
                found.append(raw_line[index:].rstrip("\r\n"))
                break
        cursor += len(raw_line)
    return tuple(found)


def named_inode_matches(path: str, expected: os.stat_result) -> bool:
    try:
        observed = os.lstat(path)
    except OSError:
        return False
    return os.path.samestat(observed, expected)


def atomic_exchange(left: str, right: str) -> None:
    parent = os.path.dirname(left)
    if parent != os.path.dirname(right):
        fail("comment continuity exchange crossed configuration directories")
    descriptor = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        library = ctypes.CDLL(None, use_errno=True)
        if sys.platform == "darwin":
            function = library.renameatx_np
        elif sys.platform.startswith("linux"):
            function = library.renameat2
        else:
            fail("atomic comment continuity exchange is unsupported")
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        function.restype = ctypes.c_int
        result = function(
            descriptor,
            os.fsencode(os.path.basename(left)),
            descriptor,
            os.fsencode(os.path.basename(right)),
            0x2,  # RENAME_EXCHANGE on Linux, RENAME_SWAP on macOS.
        )
        if result != 0:
            fail(f"atomic comment continuity exchange failed with errno {ctypes.get_errno()}")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def same_cas_source(
    payload: bytes,
    observed: os.stat_result,
    expected_payload: bytes,
    expected: os.stat_result,
) -> bool:
    return payload == expected_payload and (
        observed.st_dev,
        observed.st_ino,
        observed.st_mode,
        observed.st_uid,
        observed.st_gid,
        observed.st_nlink,
        observed.st_size,
        observed.st_mtime_ns,
    ) == (
        expected.st_dev,
        expected.st_ino,
        expected.st_mode,
        expected.st_uid,
        expected.st_gid,
        expected.st_nlink,
        expected.st_size,
        expected.st_mtime_ns,
    )


source, _ = read_stable(source_path)
active, active_snapshot = read_stable(active_path)
source_comments = comments(source, "pre-bridge configuration")
active_comments = collections.Counter(comments(active, "bridge configuration"))
missing: list[str] = []
for comment in source_comments:
    if active_comments[comment] > 0:
        active_comments[comment] -= 1
    else:
        missing.append(comment)

if not missing:
    print(0)
    raise SystemExit(0)

active_text = active.decode("utf-8")
newline = "\r\n" if "\r\n" in active_text else "\n"
prefix = "".join(comment + newline for comment in missing).encode("utf-8")
candidate = prefix + active
if len(candidate) > MAX_CONFIG_BYTES:
    fail("comment-preserving bridge configuration exceeds its size bound")
try:
    before = parsed_mapping(active_text, "bridge configuration")
    after = parsed_mapping(candidate.decode("utf-8"), "comment-preserving bridge configuration")
    semantically_equal = before == after
except (RecursionError, TypeError, ValueError) as exc:
    fail(f"comment continuity comparison failed safely: {exc}")
if not semantically_equal:
    fail("restoring comments changed bridge configuration semantics")

parent = require_private_parent(active_path)
descriptor, temporary = tempfile.mkstemp(
    prefix=f".{os.path.basename(active_path)}.upgrade-{mutation_token}.",
    suffix=".tmp",
    dir=parent,
)
swapped = False
try:
    os.fchmod(descriptor, stat.S_IMODE(active_snapshot.st_mode))
    os.fchown(descriptor, active_snapshot.st_uid, active_snapshot.st_gid)
    view = memoryview(candidate)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            fail("comment-preserving bridge configuration write stalled")
        view = view[written:]
    os.fsync(descriptor)
    candidate_snapshot = os.fstat(descriptor)
    atomic_exchange(active_path, temporary)
    swapped = True
    try:
        previous, previous_snapshot = read_stable(temporary)
        if not same_cas_source(previous, previous_snapshot, active, active_snapshot):
            fail("bridge configuration changed before comment continuity activation")
        committed, committed_snapshot = read_stable(active_path)
        if not same_cas_source(
            committed,
            committed_snapshot,
            candidate,
            candidate_snapshot,
        ):
            fail("comment-preserving bridge configuration was not committed exactly")
        os.unlink(temporary)
        directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        if named_inode_matches(active_path, candidate_snapshot) and os.path.lexists(temporary):
            atomic_exchange(active_path, temporary)
            swapped = False
        raise
    temporary = ""
finally:
    os.close(descriptor)
    if temporary and not swapped:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass

committed, committed_snapshot = read_stable(active_path)
if not same_cas_source(
    committed,
    committed_snapshot,
    candidate,
    candidate_snapshot,
):
    fail("comment-preserving bridge configuration was not committed exactly")
print(len(missing))
# END BRIDGE_COMMENT_RESTORE_PY
PY
    )" || die "Could not preserve pre-bridge YAML comments without changing bridge semantics"

    [[ "${result}" =~ ^[0-9]+$ ]] \
        || die "Bridge comment continuity verifier returned an invalid result"
    if [[ "${result}" -gt 0 ]]; then
        ok "Preserved ${result} pre-bridge YAML comment(s) in the verified bridge state"
    fi
}

bridge_phase1_state_transaction() {
    local operation="$1"
    local snapshot_root="${BACKUP_DIR}/phase1-state"
    python3 - \
        "${operation}" \
        "${DATA_DIR}" \
        "${OPENCLAW_HOME}" \
        "${snapshot_root}" \
        "${CONFIG_PATH}" \
        "${BRIDGE_PHASE1_STATE_NAMES_JSON}" \
        "${UPGRADE_RECOVERY_ROOT}" \
        "${BRIDGE_RECOVERY_PLAN_ID}" \
        "${CONTROLLER_HOME}" <<'PY'
import ctypes
import errno
import hashlib
import hmac
import json
import os
import secrets
import shutil
import stat
import sys

(
    operation,
    data_home,
    openclaw_home,
    snapshot_root,
    config_path,
    state_names_json,
    recovery_root,
    plan_id,
    recovery_home,
) = sys.argv[1:]
data_home = os.path.abspath(os.path.expanduser(data_home))
openclaw_home = os.path.abspath(os.path.expanduser(openclaw_home))
snapshot_root = os.path.abspath(snapshot_root)
config_path = os.path.abspath(os.path.expanduser(config_path))
state_names = json.loads(state_names_json)
if (
    not isinstance(state_names, list)
    or not state_names
    or any(not isinstance(name, str) or not name or "/" in name for name in state_names)
):
    raise RuntimeError("invalid phase-one state inventory contract")

with open(os.path.join(recovery_root, "phase-one-active.json"), encoding="utf-8") as journal_file:
    journal = json.load(journal_file)
if journal.get("schema_version") != 4 or journal.get("plan_id") != plan_id:
    raise RuntimeError("phase-one state transaction journal identity changed")
path_identities = journal.get("path_identities")
openclaw_home_existed = journal.get("openclaw_home_existed")
if not isinstance(openclaw_home_existed, bool):
    raise RuntimeError("phase-one state transaction OpenClaw existence state changed")
identity_paths = {
    "recovery_home": os.path.abspath(recovery_home),
    "data_dir": data_home,
    "openclaw_home": (
        openclaw_home if openclaw_home_existed else (os.path.dirname(openclaw_home) or ".")
    ),
    "config_parent": os.path.dirname(config_path) or ".",
}
if not isinstance(path_identities, dict) or set(path_identities) != set(identity_paths):
    raise RuntimeError("phase-one state transaction path identity set changed")
for name, path in identity_paths.items():
    identity = path_identities[name]
    info = os.lstat(path)
    if (
        not isinstance(identity, dict)
        or set(identity) != {"device", "inode"}
        or info.st_dev != identity.get("device")
        or info.st_ino != identity.get("inode")
        or stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
    ):
        raise RuntimeError(f"phase-one {name} identity changed during state transaction")
if not openclaw_home_existed:
    if operation == "snapshot" and os.path.lexists(openclaw_home):
        raise RuntimeError("OpenClaw home appeared before the phase-one snapshot")
    if operation != "snapshot" and os.path.lexists(openclaw_home):
        created_info = os.lstat(openclaw_home)
        if (
            stat.S_ISLNK(created_info.st_mode)
            or not stat.S_ISDIR(created_info.st_mode)
            or created_info.st_uid != os.geteuid()
            or stat.S_IMODE(created_info.st_mode) & 0o022
        ):
            raise RuntimeError("target-created OpenClaw home is unsafe")

targets = [
    config_path,
    config_path + ".pre-observability-migration.bak",
    config_path + ".lock",
    config_path + ".tmp-f3395",
]
targets.extend(os.path.join(data_home, name) for name in state_names)
targets.extend(
    os.path.join(openclaw_home, name)
    for name in ("openclaw.json", "openclaw.json.pre-0.3.0-migration")
)
for index, left in enumerate(targets):
    for right in targets[index + 1 :]:
        if left == right or os.path.commonpath((left, right)) in {left, right}:
            raise RuntimeError(f"overlapping phase-one state targets are unsafe: {left}, {right}")
def remove_path(path: str) -> None:
    if not os.path.lexists(path):
        return
    if os.path.islink(path) or not os.path.isdir(path):
        os.unlink(path)
    else:
        shutil.rmtree(path)


def copy_path(source: str, destination: str) -> str:
    source_stat = os.lstat(source)
    if stat.S_ISLNK(source_stat.st_mode):
        os.symlink(os.readlink(source), destination)
        return "symlink"
    if stat.S_ISREG(source_stat.st_mode):
        shutil.copy2(source, destination, follow_symlinks=False)
        return "file"
    if stat.S_ISDIR(source_stat.st_mode):
        shutil.copytree(source, destination, symlinks=True, copy_function=shutil.copy2)
        return "directory"
    raise RuntimeError(f"unsupported mutable path type: {source}")


def sha256_file(path: str) -> str:
    value = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def path_inventory(path):
    inventory = []

    def visit(current: str, relative: str) -> None:
        info = os.lstat(current)
        item = {
            "path": relative,
            "mode": stat.S_IMODE(info.st_mode),
        }
        if stat.S_ISLNK(info.st_mode):
            item["kind"] = "symlink"
            item["target"] = os.readlink(current)
        elif stat.S_ISREG(info.st_mode):
            item["kind"] = "file"
            item["size"] = info.st_size
            item["sha256"] = sha256_file(current)
        elif stat.S_ISDIR(info.st_mode):
            item["kind"] = "directory"
        else:
            raise RuntimeError(f"unsupported mutable path type: {current}")
        inventory.append(item)
        if item["kind"] == "directory":
            with os.scandir(current) as entries:
                children = sorted(entries, key=lambda entry: entry.name)
            for child in children:
                child_relative = child.name if relative == "." else f"{relative}/{child.name}"
                visit(child.path, child_relative)

    visit(path, ".")
    return inventory


def fsync_directory(path: str) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def fsync_path_tree(path: str) -> None:
    if os.path.islink(path):
        fsync_directory(os.path.dirname(path))
        return
    if os.path.isfile(path):
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        fsync_directory(os.path.dirname(path))
        return
    directories = []
    for current, _names, files in os.walk(path, topdown=True, followlinks=False):
        directories.append(current)
        for name in files:
            member = os.path.join(current, name)
            if os.path.islink(member):
                continue
            descriptor = os.open(member, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    for directory in reversed(directories):
        fsync_directory(directory)
    fsync_directory(os.path.dirname(path))


manifest_path = os.path.join(snapshot_root, "manifest.json")
active_manifest_path = os.path.join(snapshot_root, "active-manifest.json")


def entry_for_path(target: str) -> dict:
    entry = {"target": target, "existed": os.path.lexists(target)}
    if entry["existed"]:
        entry["inventory"] = path_inventory(target)
        entry["kind"] = entry["inventory"][0]["kind"]
    return entry


def root_state():
    modes = {}
    identities = {}
    for root in (data_home, openclaw_home):
        try:
            info = os.stat(root, follow_symlinks=False)
        except FileNotFoundError:
            modes[root] = None
            identities[root] = None
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise RuntimeError(f"phase-one state root is unsafe: {root}")
        modes[root] = stat.S_IMODE(info.st_mode)
        identities[root] = {"device": info.st_dev, "inode": info.st_ino}
    return modes, identities


def write_private_json_no_replace(path: str, document: dict) -> None:
    candidate = f"{path}.{secrets.token_hex(16)}.tmp"
    descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", closefd=True) as stream:
            json.dump(document, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        rename_no_replace(candidate, path)
    finally:
        if os.path.lexists(candidate):
            os.unlink(candidate)


def rename_no_replace(source: str, destination: str) -> None:
    source_parent = os.path.dirname(source) or "."
    destination_parent = os.path.dirname(destination) or "."
    source_parent_fd = os.open(source_parent, os.O_RDONLY)
    destination_parent_fd = -1
    try:
        destination_parent_fd = os.open(destination_parent, os.O_RDONLY)
        library = ctypes.CDLL(None, use_errno=True)
        if sys.platform == "darwin":
            function = library.renameatx_np
            flag = 0x4  # RENAME_EXCL
        elif sys.platform.startswith("linux"):
            function = library.renameat2
            flag = 0x1  # RENAME_NOREPLACE
        else:
            raise RuntimeError("phase-one no-replace rename is unsupported")
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        function.restype = ctypes.c_int
        result = function(
            source_parent_fd,
            os.fsencode(os.path.basename(source)),
            destination_parent_fd,
            os.fsencode(os.path.basename(destination)),
            flag,
        )
        if result != 0:
            code = ctypes.get_errno()
            if code in {errno.EEXIST, errno.ENOTEMPTY}:
                raise RuntimeError(
                    f"phase-one state destination appeared concurrently: {destination}"
                )
            raise RuntimeError(f"phase-one no-replace rename failed with errno {code}")
        os.fsync(source_parent_fd)
        os.fsync(destination_parent_fd)
    finally:
        if destination_parent_fd >= 0:
            os.close(destination_parent_fd)
        os.close(source_parent_fd)


def same_state(path: str, entry: dict) -> bool:
    exists = os.path.lexists(path)
    if exists != bool(entry.get("existed")):
        return False
    if not exists:
        return True
    inventory = entry.get("inventory")
    return isinstance(inventory, list) and path_inventory(path) == inventory


def validate_entry_set(entries: object, *, label: str) -> list[dict]:
    if not isinstance(entries, list) or len(entries) != len(targets):
        raise RuntimeError(f"invalid phase-one {label} entry set")
    if [entry.get("target") for entry in entries if isinstance(entry, dict)] != targets:
        raise RuntimeError(f"phase-one {label} target set changed")
    for entry in entries:
        if not isinstance(entry.get("existed"), bool):
            raise RuntimeError(f"invalid phase-one {label} existence flag")
        if entry["existed"]:
            if entry.get("kind") not in {"file", "directory", "symlink"}:
                raise RuntimeError(f"invalid phase-one {label} kind")
            if not isinstance(entry.get("inventory"), list):
                raise RuntimeError(f"invalid phase-one {label} inventory")
    return entries


def active_manifest_auth_tag(document: dict) -> str:
    unsigned = dict(document)
    unsigned.pop("plan_hmac_sha256", None)
    payload = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(plan_id.encode(), payload, hashlib.sha256).hexdigest()


def validate_active_manifest_document(document: object) -> dict:
    if not isinstance(document, dict) or set(document) != {
        "schema",
        "plan_id",
        "entries",
        "root_modes",
        "root_identities",
        "plan_hmac_sha256",
    }:
        raise RuntimeError("invalid phase-one active manifest fields")
    if document.get("schema") != 2 or document.get("plan_id") != plan_id:
        raise RuntimeError("unsupported phase-one active manifest")
    tag = document.get("plan_hmac_sha256")
    if (
        not isinstance(tag, str)
        or not hmac.compare_digest(tag, active_manifest_auth_tag(document))
    ):
        raise RuntimeError("phase-one active manifest authentication failed")
    return document


def quarantine_root(target: str) -> str:
    token = plan_id.removeprefix("phase-one-")
    parent = os.path.dirname(target) or "."
    if not openclaw_home_existed and os.path.commonpath((target, openclaw_home)) == openclaw_home:
        parent = os.path.dirname(openclaw_home) or "."
    return os.path.join(parent, f".defenseclaw-phase-one-custody-{token}")


def require_quarantine_root(target: str, *, create: bool = False) -> str:
    root = quarantine_root(target)
    created = False
    if create:
        try:
            os.mkdir(root, 0o700)
            created = True
        except FileExistsError:
            pass
    info = os.lstat(root)
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise RuntimeError(f"phase-one custody root is unsafe: {root}")
    if created:
        fsync_directory(os.path.dirname(root) or ".")
    return root


def quarantine_path(target: str, index: int) -> str:
    name = os.path.basename(target)
    if not openclaw_home_existed and os.path.commonpath((target, openclaw_home)) == openclaw_home:
        name = f"{os.path.basename(openclaw_home)}-{name}"
    return os.path.join(quarantine_root(target), f"{index}-{name}")


def restore_candidate_path(target: str, index: int) -> str:
    token = plan_id.removeprefix("phase-one-")
    parent = os.path.dirname(target) or "."
    return os.path.join(
        parent,
        f".{os.path.basename(target)}.phase-one-restore-{token}-{index}",
    )


def load_source_manifest() -> tuple[list[dict], dict]:
    if journal.get("state_snapshot_ready") is not True:
        raise RuntimeError("phase-one source snapshot is not sealed")
    expected_sha256 = journal.get("state_manifest_sha256")
    if not isinstance(expected_sha256, str) or sha256_file(manifest_path) != expected_sha256:
        raise RuntimeError("phase-one source manifest custody changed")
    if os.path.getsize(manifest_path) > 4 * 1024 * 1024:
        raise RuntimeError("phase-1 state snapshot manifest is too large")
    with open(manifest_path, encoding="utf-8") as manifest_file:
        manifest = json.load(manifest_file)
    if manifest.get("schema") != 1:
        raise RuntimeError("unsupported phase-1 state snapshot schema")
    entries = validate_entry_set(manifest.get("entries"), label="source snapshot")
    for index, entry in enumerate(entries):
        if not entry["existed"]:
            continue
        if entry.get("backup") != f"item-{index}":
            raise RuntimeError("invalid phase-one source backup name")
        backup = os.path.join(snapshot_root, entry["backup"])
        if path_inventory(backup) != entry["inventory"]:
            raise RuntimeError(f"phase-1 state backup changed for {entry['target']}")
    return entries, manifest


def load_expected_active(source_entries: list[dict], source_manifest: dict) -> tuple[list[dict], dict, dict]:
    active_ready = journal.get("active_snapshot_ready")
    active_digest = journal.get("active_manifest_sha256")
    if not isinstance(active_ready, bool):
        raise RuntimeError("phase-one active snapshot readiness changed")
    if not active_ready:
        if active_digest is not None:
            raise RuntimeError("unsealed phase-one active state has a digest")
        if not os.path.lexists(active_manifest_path):
            modes = source_manifest.get("root_modes")
            if not isinstance(modes, dict):
                raise RuntimeError("invalid phase-one source root modes")
            return source_entries, modes, {}
    elif not isinstance(active_digest, str) or sha256_file(active_manifest_path) != active_digest:
        raise RuntimeError("phase-one active manifest custody changed")
    info = os.lstat(active_manifest_path)
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise RuntimeError("phase-one active manifest is unsafe")
    if os.path.getsize(active_manifest_path) > 4 * 1024 * 1024:
        raise RuntimeError("phase-one active manifest is too large")
    with open(active_manifest_path, encoding="utf-8") as active_file:
        active = validate_active_manifest_document(json.load(active_file))
    entries = validate_entry_set(active.get("entries"), label="active snapshot")
    modes = active.get("root_modes")
    identities = active.get("root_identities")
    if not isinstance(modes, dict) or set(modes) != {data_home, openclaw_home}:
        raise RuntimeError("invalid phase-one active root modes")
    if not isinstance(identities, dict) or set(identities) != {data_home, openclaw_home}:
        raise RuntimeError("invalid phase-one active root identities")
    return entries, modes, identities


if operation == "snapshot":
    if os.path.lexists(snapshot_root):
        raise RuntimeError("phase-1 state snapshot already exists")
    os.makedirs(snapshot_root, mode=0o700)
    os.chmod(snapshot_root, 0o700)
    entries = []
    for index, target in enumerate(targets):
        entry = {"target": target, "existed": os.path.lexists(target)}
        if entry["existed"]:
            backup_name = f"item-{index}"
            entry["backup"] = backup_name
            backup_path = os.path.join(snapshot_root, backup_name)
            entry["inventory"] = path_inventory(target)
            entry["kind"] = copy_path(target, backup_path)
            if (
                path_inventory(target) != entry["inventory"]
                or path_inventory(backup_path) != entry["inventory"]
            ):
                raise RuntimeError(f"phase-1 state snapshot mismatch for {target}")
            fsync_path_tree(backup_path)
        entries.append(entry)
    root_modes = {}
    for root in (data_home, openclaw_home):
        try:
            root_modes[root] = stat.S_IMODE(os.stat(root, follow_symlinks=False).st_mode)
        except FileNotFoundError:
            root_modes[root] = None
    with open(manifest_path, "x", encoding="utf-8") as manifest_file:
        json.dump({"schema": 1, "entries": entries, "root_modes": root_modes}, manifest_file, sort_keys=True)
        manifest_file.write("\n")
        manifest_file.flush()
        os.fsync(manifest_file.fileno())
    os.chmod(manifest_path, 0o600)
    fsync_path_tree(manifest_path)
    fsync_directory(snapshot_root)
elif operation == "config-comment-source":
    source_entries, _source_manifest = load_source_manifest()
    config_entry = source_entries[0]
    if config_entry.get("target") != config_path:
        raise RuntimeError("phase-one configuration snapshot target changed")
    if not config_entry["existed"]:
        print("")
    else:
        if config_entry.get("kind") != "file" or config_entry.get("backup") != "item-0":
            raise RuntimeError("phase-one configuration snapshot is not one regular file")
        print(os.path.join(snapshot_root, "item-0"))
elif operation == "seal-active":
    source_entries, source_manifest = load_source_manifest()
    if journal.get("state_snapshot_ready") is not True:
        raise RuntimeError("phase-one source snapshot is not sealed")
    if journal.get("state_mutation_started") is not True:
        raise RuntimeError("phase-one state mutation authority is not armed")
    if sha256_file(manifest_path) != journal.get("state_manifest_sha256"):
        raise RuntimeError("phase-one source manifest custody changed")
    if journal.get("active_snapshot_ready") is not False or journal.get("active_manifest_sha256") is not None:
        raise RuntimeError("phase-one active snapshot is already sealed")
    if os.path.lexists(active_manifest_path):
        raise RuntimeError("phase-one active manifest appeared before sealing")
    modes, identities = root_state()
    active_entries = []
    for target in targets:
        entry = entry_for_path(target)
        if entry["existed"]:
            fsync_path_tree(target)
        if entry_for_path(target) != entry:
            raise RuntimeError(f"phase-one active state changed while sealing: {target}")
        active_entries.append(entry)
    for root in (data_home, openclaw_home):
        if os.path.isdir(root) and not os.path.islink(root):
            fsync_directory(root)
    if root_state() != (modes, identities):
        raise RuntimeError("phase-one active root metadata changed while sealing")
    active_document = {
        "schema": 2,
        "plan_id": plan_id,
        "entries": active_entries,
        "root_modes": modes,
        "root_identities": identities,
    }
    active_document["plan_hmac_sha256"] = active_manifest_auth_tag(active_document)
    write_private_json_no_replace(active_manifest_path, active_document)
    if os.environ.get("DEFENSECLAW_TEST_PHASE1_ACTIVE_SEAL_CRASH") == "after-active-manifest":
        parent = os.getppid()
        os.kill(parent, 9)
        os.kill(os.getpid(), 9)
    active_sha256 = sha256_file(active_manifest_path)
    journal["active_snapshot_ready"] = True
    journal["active_manifest_sha256"] = active_sha256
    journal_path = os.path.join(recovery_root, "phase-one-active.json")
    raw = (json.dumps(journal, sort_keys=True, separators=(",", ":")) + "\n").encode()
    candidate = os.path.join(recovery_root, f".{plan_id}.active-{secrets.token_hex(16)}.tmp")
    descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(candidate, journal_path)
        fsync_directory(recovery_root)
        with open(journal_path, "rb") as stream:
            if stream.read() != raw:
                raise RuntimeError("phase-one active journal readback mismatch")
    finally:
        if os.path.lexists(candidate):
            os.unlink(candidate)
elif operation in ("restore", "fsync-active"):
    entries, manifest = load_source_manifest()
    active_entries, active_root_modes, active_root_identities = load_expected_active(entries, manifest)
    if operation == "restore":
        # Refuse before moving anything when a managed root was replaced or
        # its mode changed after the active snapshot.  This is the coarse CAS
        # for directory metadata; each managed child receives its own atomic
        # no-replace quarantine below.
        source_root_modes = manifest.get("root_modes")
        if not isinstance(source_root_modes, dict):
            raise RuntimeError("invalid phase-one source root modes")
        partial_restore = any(
            os.path.lexists(quarantine_path(source_entry["target"], index))
            or (
                same_state(source_entry["target"], source_entry)
                and not same_state(source_entry["target"], active_entry)
            )
            for index, (source_entry, active_entry) in enumerate(
                zip(entries, active_entries)
            )
        )
        current_modes, current_identities = root_state()
        for root in (data_home, openclaw_home):
            expected_mode = active_root_modes.get(root)
            expected_identity = active_root_identities.get(root)
            allowed_modes = {expected_mode}
            if partial_restore:
                allowed_modes.add(source_root_modes.get(root))
            if current_modes.get(root) not in allowed_modes:
                raise RuntimeError(f"phase-one state root mode diverged after migration: {root}")
            source_absent = partial_restore and source_root_modes.get(root) is None
            if (
                expected_identity is not None
                and current_identities.get(root) != expected_identity
                and not (source_absent and current_identities.get(root) is None)
            ):
                raise RuntimeError(f"phase-one state root identity diverged after migration: {root}")

        # Validate the entire target set before the first rename.  A recovery
        # replay also accepts exact source state plus plan-owned quarantines,
        # which is the durable shape left by a crash during restoration.
        for index, (source_entry, active_entry) in enumerate(zip(entries, active_entries)):
            target = source_entry["target"]
            quarantine = quarantine_path(target, index)
            if os.path.lexists(quarantine):
                require_quarantine_root(target)
            if os.path.lexists(quarantine) and not same_state(quarantine, active_entry):
                if same_state(target, source_entry):
                    # Source is already restored; a crash may have interrupted
                    # deletion of this plan-owned quarantine.
                    continue
                raise RuntimeError(f"phase-one quarantine diverged for {target}")
            if os.path.lexists(quarantine):
                if os.path.lexists(target) and not same_state(target, source_entry):
                    raise RuntimeError(f"phase-one state target reappeared during rollback: {target}")
                continue
            if not same_state(target, active_entry) and not same_state(target, source_entry):
                raise RuntimeError(
                    f"phase-one state diverged after migration; preserved without overwrite: {target}"
                )

        for index, (source_entry, active_entry) in enumerate(zip(entries, active_entries)):
            target = source_entry["target"]
            quarantine = quarantine_path(target, index)
            if (
                not os.path.lexists(quarantine)
                and active_entry["existed"]
                and same_state(target, active_entry)
                and not same_state(target, source_entry)
            ):
                require_quarantine_root(target, create=True)
                rename_no_replace(target, quarantine)
                if not same_state(quarantine, active_entry):
                    raise RuntimeError(f"phase-one state changed while quarantining {target}")
            if os.path.lexists(target) and not same_state(target, source_entry):
                raise RuntimeError(f"phase-one state target appeared during rollback: {target}")

        for index, entry in enumerate(entries):
            target = entry["target"]
            if not entry["existed"]:
                if os.path.lexists(target):
                    raise RuntimeError(f"phase-one absent source target appeared during rollback: {target}")
                continue
            if not os.path.lexists(target):
                parent = os.path.dirname(target)
                os.makedirs(parent, mode=0o700, exist_ok=True)
                candidate = restore_candidate_path(target, index)
                if os.path.lexists(candidate):
                    info = os.lstat(candidate)
                    if info.st_uid != os.geteuid():
                        raise RuntimeError(f"unsafe phase-one restore candidate: {candidate}")
                    if not same_state(candidate, entry):
                        raise RuntimeError(
                            f"phase-one restore candidate diverged and was preserved: {candidate}"
                        )
                if not os.path.lexists(candidate):
                    backup = os.path.join(snapshot_root, entry["backup"])
                    restored_kind = copy_path(backup, candidate)
                    if restored_kind != entry["kind"] or path_inventory(candidate) != entry["inventory"]:
                        raise RuntimeError(f"phase-one restore candidate mismatch for {target}")
                    fsync_path_tree(candidate)
                rename_no_replace(candidate, target)
            if not same_state(target, entry):
                raise RuntimeError(f"phase-one source state restore mismatch for {target}")
            fsync_path_tree(target)

        # Only transaction-owned quarantines are removed, and only after the
        # complete source target set is present and byte-for-byte verified.
        for index, (source_entry, active_entry) in enumerate(zip(entries, active_entries)):
            target = source_entry["target"]
            quarantine = quarantine_path(target, index)
            if not os.path.lexists(quarantine):
                continue
            if not same_state(target, source_entry):
                raise RuntimeError(f"source state changed before quarantine retention: {target}")
            # Preserve the plan-scoped sibling even when it still matches the
            # sealed active inventory.  Name ownership alone never authorizes
            # recursive deletion because open descriptors can add user bytes
            # after the atomic rename.
            fsync_directory(os.path.dirname(quarantine) or ".")

        retained_paths = [
            quarantine_path(entry["target"], index)
            for index, entry in enumerate(entries)
            if os.path.lexists(quarantine_path(entry["target"], index))
        ]
        retained_index = os.path.join(snapshot_root, "retained-quarantines.json")
        retained_document = {
            "schema": 1,
            "plan_id": plan_id,
            "paths": retained_paths,
        }
        if os.path.lexists(retained_index):
            info = os.lstat(retained_index)
            if (
                not stat.S_ISREG(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077
            ):
                raise RuntimeError("phase-one retained-quarantine index is unsafe")
            with open(retained_index, encoding="utf-8") as stream:
                if json.load(stream) != retained_document:
                    raise RuntimeError("phase-one retained-quarantine index changed")
        else:
            write_private_json_no_replace(retained_index, retained_document)
        fsync_directory(snapshot_root)
    else:
        for entry in entries:
            target = entry["target"]
            if os.path.lexists(target):
                fsync_path_tree(target)
    for entry in entries:
        parent = os.path.dirname(entry["target"])
        while not os.path.lexists(parent):
            next_parent = os.path.dirname(parent)
            if next_parent == parent:
                raise RuntimeError("phase-one state target has no stable existing parent")
            parent = next_parent
        if os.path.islink(parent) or not os.path.isdir(parent):
            raise RuntimeError("phase-one state target parent is unsafe")
        fsync_directory(parent)
    for root, mode in manifest.get("root_modes", {}).items():
        if mode is None and operation == "restore" and root == openclaw_home and os.path.lexists(root):
            if os.path.islink(root) or not os.path.isdir(root) or os.listdir(root):
                raise RuntimeError("target-created OpenClaw home contains unexpected rollback residue")
            os.rmdir(root)
            fsync_directory(os.path.dirname(root) or ".")
        elif mode is not None and os.path.isdir(root) and not os.path.islink(root):
            if operation == "restore":
                os.chmod(root, mode)
            fsync_directory(root)
else:
    raise RuntimeError(f"unknown phase-1 state operation: {operation}")
PY
}

bridge_phase1_cleanup_owned_temporaries() {
    local mutation_token="${BRIDGE_RECOVERY_PLAN_ID#phase-one-}"
    [[ "${mutation_token}" =~ ^[0-9a-f]{32}$ ]] \
        || { err "Phase-one mutation token is invalid"; return 1; }
    python3 - \
        "${DATA_DIR}" \
        "${OPENCLAW_HOME}" \
        "${CONFIG_PATH}" \
        "${UPGRADE_RECOVERY_ROOT}/phase-one-active.json" \
        "${BRIDGE_RECOVERY_PLAN_ID}" \
        "${mutation_token}" <<'PY'
import json
import os
import re
import stat
import sys

data_dir, openclaw_home, config_path, journal_path, plan_id, token = sys.argv[1:]
with open(journal_path, encoding="utf-8") as stream:
    journal = json.load(stream)
if journal.get("schema_version") != 4 or journal.get("plan_id") != plan_id:
    raise RuntimeError("phase-one temporary cleanup journal identity changed")
identity_paths = {
    "recovery_home": os.path.abspath(journal["recovery_home"]),
    "data_dir": os.path.abspath(data_dir),
    "openclaw_home": (
        os.path.abspath(openclaw_home)
        if journal.get("openclaw_home_existed") is True
        else (os.path.dirname(os.path.abspath(openclaw_home)) or ".")
    ),
    "config_parent": os.path.dirname(os.path.abspath(config_path)) or ".",
}
identities = journal.get("path_identities")
if not isinstance(identities, dict) or set(identities) != set(identity_paths):
    raise RuntimeError("phase-one temporary cleanup path identity set changed")
for name, path in identity_paths.items():
    info = os.lstat(path)
    identity = identities[name]
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_dev != identity.get("device")
        or info.st_ino != identity.get("inode")
    ):
        raise RuntimeError(f"phase-one {name} identity changed before temporary cleanup")

generic_prefix = f".tmp.upgrade-{token}."
tagged_writer = re.compile(rf"^\..+\.upgrade-{re.escape(token)}\.[A-Za-z0-9_-]+\.tmp$")
cursor_prefix = f".migration_state.upgrade-{token}."
roots = {identity_paths["data_dir"], identity_paths["config_parent"]}
if os.path.isdir(openclaw_home) and not os.path.islink(openclaw_home):
    roots.add(os.path.abspath(openclaw_home))
roots = sorted(roots)
seen = 0
for root in roots:
    with os.scandir(root) as entries:
        members = list(entries)
    if len(members) > 100000:
        raise RuntimeError("phase-one temporary cleanup exceeded its scan bound")
    for entry in members:
        name = entry.name
        owned = (
            name.startswith(generic_prefix)
            or (name.startswith(cursor_prefix) and name.endswith(".tmp"))
            or tagged_writer.fullmatch(name) is not None
        )
        if not owned:
            continue
        info = entry.stat(follow_symlinks=False)
        if entry.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise RuntimeError("phase-one owned temporary has an unsafe identity")
        os.unlink(entry.path)
    descriptor = os.open(root, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
PY
}

prepare_historical_bootstrap_constraints() {
    [[ -z "${HISTORICAL_BOOTSTRAP_CONSTRAINTS_FILE:-}" ]] || return 0
    [[ -n "${STAGING_DIR:-}" && -d "${STAGING_DIR}" && ! -L "${STAGING_DIR}" ]] \
        || die "Private staging is unavailable for the historical dependency constraints. No services changed."

    local constraints="${STAGING_DIR}/historical-bootstrap-constraints.txt"
    [[ ! -e "${constraints}" && ! -L "${constraints}" ]] \
        || die "Historical dependency-constraint custody is occupied. No services changed."
    printf '%s\n%s\n' \
        "${HISTORICAL_BOOTSTRAP_MCP_SCANNER_CONSTRAINT}" \
        "${HISTORICAL_BOOTSTRAP_LITELLM_CONSTRAINT}" >"${constraints}" \
        || die "Could not materialize the signed historical dependency constraints. No services changed."
    chmod 600 "${constraints}" \
        || die "Could not protect the signed historical dependency constraints. No services changed."
    HISTORICAL_BOOTSTRAP_CONSTRAINTS_FILE="${constraints}"
}

verify_python_dependency_metadata() {
    local uv_bin="$1" python="$2" context="$3"
    env -u UV_CONSTRAINT -u UV_OVERRIDE -u UV_EXCLUDE_NEWER \
        "${uv_bin}" --no-config pip check \
        --python "${python}" --quiet \
        || die "${context} has inconsistent installed dependency metadata; refusing the next handoff."
}

prepare_bridge_phase1_cli_preflight() {
    local uv_bin preflight_venv preflight_version
    [[ -n "${whl_name:-}" && -f "${STAGING_DIR}/${whl_name}" ]] \
        || die "Bridge CLI artifact is unavailable for preflight; no services changed."
    uv_bin="$(command -v uv 2>/dev/null || true)"
    [[ -n "${uv_bin}" ]] \
        || die "uv not found on PATH — cannot prepare the 0.8.4 bridge without a rollback-safe CLI replacement. No services changed."

    [[ -d "${DEFENSECLAW_VENV}" && ! -L "${DEFENSECLAW_VENV}" ]] \
        || die "The installed CLI environment is not a managed regular directory at ${DEFENSECLAW_VENV}. No services changed."
    [[ -x "${DEFENSECLAW_VENV}/bin/python" && -x "${DEFENSECLAW_VENV}/bin/defenseclaw" ]] \
        || die "The installed CLI environment is incomplete; refusing the bridge because exact rollback is unavailable. No services changed."
    [[ -f "${INSTALL_DIR}/defenseclaw-gateway" && ! -L "${INSTALL_DIR}/defenseclaw-gateway" ]] \
        || die "The installed gateway is not a managed regular file; refusing the bridge because exact rollback is unavailable. No services changed."
    python3 - "${INSTALL_DIR}/defenseclaw" "${DEFENSECLAW_VENV}/bin/defenseclaw" <<'PY' \
        || die "The installed DefenseClaw launcher is not the managed CLI symlink; exact rollback is unavailable. No services changed."
import os
import sys

launcher, expected = sys.argv[1:]
if not os.path.islink(launcher) or os.path.realpath(launcher) != os.path.realpath(expected):
    raise SystemExit(
        "installed DefenseClaw launcher is not the managed CLI symlink; "
        "refusing because exact rollback is unavailable"
    )
PY

    BRIDGE_PYTHON_INTERPRETER="$("${DEFENSECLAW_VENV}/bin/python" -I -B -c 'import os,sys; print(os.path.realpath(getattr(sys, "_base_executable", "") or sys.executable))')" \
        || die "Could not resolve the source Python interpreter; no services changed."
    [[ -x "${BRIDGE_PYTHON_INTERPRETER}" ]] \
        || die "The source Python interpreter is unavailable; no services changed."
    python3 - "${BRIDGE_PYTHON_INTERPRETER}" "${DEFENSECLAW_VENV}" <<'PY' \
        || die "The bridge base Python resolves inside the source venv and would disappear during activation. No services changed."
import os
import sys

interpreter, source_venv = (os.path.realpath(value) for value in sys.argv[1:])
try:
    inside_source = os.path.commonpath((interpreter, source_venv)) == source_venv
except ValueError:
    inside_source = False
raise SystemExit(1 if inside_source else 0)
PY

    preflight_venv="${STAGING_DIR}/bridge-cli-preflight"
    prepare_historical_bootstrap_constraints
    env -u UV_CONSTRAINT -u UV_OVERRIDE -u UV_EXCLUDE_NEWER \
        "${uv_bin}" --no-config venv "${preflight_venv}" --python "${BRIDGE_PYTHON_INTERPRETER}" --quiet \
        || die "Could not create the bridge CLI preflight environment; no services changed."
    env -u UV_CONSTRAINT -u UV_OVERRIDE -u UV_EXCLUDE_NEWER \
        "${uv_bin}" --no-config pip install \
        --python "${preflight_venv}/bin/python" --quiet \
        --constraints "${HISTORICAL_BOOTSTRAP_CONSTRAINTS_FILE}" \
        --exclude-newer "${HISTORICAL_BOOTSTRAP_EXCLUDE_NEWER}" \
        --only-binary litellm "${STAGING_DIR}/${whl_name}" \
        || die "Could not install the bridge CLI in its preflight environment; no services changed."
    verify_python_dependency_metadata \
        "${uv_bin}" "${preflight_venv}/bin/python" "Bridge CLI preflight environment"
    preflight_version="$("${preflight_venv}/bin/python" -I -B -c 'from defenseclaw import __version__; print(__version__)')" \
        || die "Could not import the preflighted bridge CLI; no services changed."
    [[ "${preflight_version}" == "${RELEASE_VERSION}" ]] \
        || die "Bridge CLI preflight version mismatch: expected ${RELEASE_VERSION}, got ${preflight_version}. No services changed."
    ok "Rollback-safe bridge CLI replacement preflight passed"
}

bridge_source_health_observation() {
    local response_file http_code curl_status health_fields
    response_file="$(mktemp "${STAGING_DIR}/phase1-source-health.XXXXXX")" || return 1
    if http_code="$(DEFENSECLAW_HOME="${DATA_DIR}" DEFENSECLAW_CONFIG="${CONFIG_PATH}" \
        curl -s -o "${response_file}" -w "%{http_code}" --max-time 2 \
        "${BRIDGE_SOURCE_HEALTH_URL}" 2>/dev/null)"; then
        curl_status=0
    else
        curl_status=$?
    fi
    health_fields="$(python3 - "${response_file}" <<'PY' 2>/dev/null || true
import json
import os
import sys

try:
    if os.path.getsize(sys.argv[1]) > 1024 * 1024:
        raise ValueError("oversized health response")
    with open(sys.argv[1], encoding="utf-8") as response_file:
        payload = json.load(response_file)
except (OSError, TypeError, ValueError):
    raise SystemExit
gateway = payload.get("gateway") if isinstance(payload, dict) else None
provenance = payload.get("provenance") if isinstance(payload, dict) else None
state = gateway.get("state", "invalid") if isinstance(gateway, dict) else "invalid"
version = provenance.get("binary_version", "missing") if isinstance(provenance, dict) else "missing"
if not isinstance(state, str) or not isinstance(version, str):
    raise SystemExit
print(f"{state}\t{version}")
PY
)"
    rm -f "${response_file}"
    if [[ "${curl_status}" -eq 7 && "${http_code}" == "000" ]]; then
        printf 'unreachable\tmissing\n'
    elif [[ "${curl_status}" -ne 0 ]]; then
        printf 'indeterminate\tmissing\n'
    elif [[ "${http_code}" != "200" ]]; then
        printf 'reachable\tmissing\n'
    elif [[ -z "${health_fields}" ]]; then
        printf 'invalid\tmissing\n'
    else
        printf '%s\n' "${health_fields}"
    fi
}

prepare_bridge_phase1_custody() {
    local source_gateway_version source_gateway_semver pid_path pid_fields pid_state pid
    local health_fields health_state health_version
    source_gateway_version="$("${INSTALL_DIR}/defenseclaw-gateway" --version 2>&1 || true)"
    source_gateway_semver="$(printf '%s' "${source_gateway_version}" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
    [[ "${source_gateway_semver}" == "${CURRENT_VERSION}" ]] \
        || die "Installed gateway version does not match detected CLI ${CURRENT_VERSION}; refusing the bridge before stopping services."

    cp -p "${INSTALL_DIR}/defenseclaw-gateway" "${BACKUP_DIR}/phase1-source-gateway" \
        || die "Could not retain the source gateway for phase-1 rollback; no services changed."
    cmp -s "${INSTALL_DIR}/defenseclaw-gateway" "${BACKUP_DIR}/phase1-source-gateway" \
        || die "The retained source gateway is not byte-exact; no services changed."

    cp "${STAGING_DIR}/defenseclaw" "${BACKUP_DIR}/phase1-bridge-gateway" \
        || die "Could not retain the verified bridge gateway activation; no services changed."
    chmod 700 "${BACKUP_DIR}/phase1-bridge-gateway"
    if [[ "${OS}" == "darwin" ]]; then
        /usr/bin/codesign -f -s - -i com.cisco.defenseclaw.gateway \
            "${BACKUP_DIR}/phase1-bridge-gateway" 2>/dev/null \
            || die "Could not normalize the verified bridge gateway for rollback identity; no services changed."
    fi
    BRIDGE_WHEEL_CUSTODY_PATH="${BACKUP_DIR}/${whl_name}"
    [[ "${whl_name}" == "defenseclaw-${RELEASE_VERSION}-2-py3-none-any.whl" ]] \
        || die "Verified bridge wheel has a noncanonical materialized filename; no services changed."
    cp "${STAGING_DIR}/${whl_name}" "${BRIDGE_WHEEL_CUSTODY_PATH}" \
        || die "Could not retain the verified bridge wheel activation; no services changed."
    chmod 600 "${BRIDGE_WHEEL_CUSTODY_PATH}"
    read -r BRIDGE_EXPECTED_GATEWAY_SHA256 BRIDGE_EXPECTED_WHEEL_SHA256 < <(python3 - \
        "${BACKUP_DIR}/phase1-bridge-gateway" \
        "${BRIDGE_WHEEL_CUSTODY_PATH}" <<'PY'
import hashlib
import sys


def digest(path):
    value = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


print(digest(sys.argv[1]), digest(sys.argv[2]))
PY
) || die "Could not bind the verified bridge activation digests; no services changed."
    [[ "${BRIDGE_EXPECTED_GATEWAY_SHA256}" =~ ^[0-9a-f]{64}$ \
       && "${BRIDGE_EXPECTED_WHEEL_SHA256}" =~ ^[0-9a-f]{64}$ ]] \
        || die "Verified bridge activation digests are invalid; no services changed."

    BRIDGE_SOURCE_HEALTH_URL="$(DEFENSECLAW_HOME="${DATA_DIR}" \
        DEFENSECLAW_CONFIG="${CONFIG_PATH}" \
        "${DEFENSECLAW_VENV}/bin/python" -I -B - <<'PY' 2>/dev/null || true
from defenseclaw.config import load

cfg = load()
gateway = getattr(cfg, "gateway", None)
guardrail = getattr(cfg, "guardrail", None)
openshell = getattr(cfg, "openshell", None)
bind = getattr(gateway, "api_bind", "")
port = getattr(gateway, "api_port", 18970)
if not bind:
    standalone_check = getattr(openshell, "is_standalone", None)
    standalone = callable(standalone_check) and standalone_check()
    guardrail_host = getattr(guardrail, "host", "")
    if standalone and guardrail_host not in ("", "localhost", "127.0.0.1"):
        bind = guardrail_host
    else:
        bind = "127.0.0.1"
print(f"http://{bind}:{port}/health")
PY
)"
    [[ -n "${BRIDGE_SOURCE_HEALTH_URL}" ]] || BRIDGE_SOURCE_HEALTH_URL="http://127.0.0.1:18970/health"

    pid_path="${DATA_DIR}/gateway.pid"
    pid_fields="$(gateway_pid_status "${pid_path}" "${INSTALL_DIR}/defenseclaw-gateway")" \
        || die "Gateway PID custody is invalid or identifies an unrelated process; refusing the bridge before stopping services."
    pid_state="${pid_fields%%$'\t'*}"
    pid="${pid_fields#*$'\t'}"
    health_fields="$(bridge_source_health_observation)" \
        || die "Could not inspect source gateway health before stopping services."
    health_state="${health_fields%%$'\t'*}"
    health_version="${health_fields#*$'\t'}"
    if [[ "${health_state}" == "running" || "${health_state}" == "disabled" ]]; then
        [[ "${health_version}" == "${CURRENT_VERSION}" ]] \
            || die "A gateway is healthy but reports ${health_version:-missing}, not source ${CURRENT_VERSION}; refusing before stopping services."
        [[ "${pid_state}" == "live" ]] \
            || die "The source gateway is healthy without verified live PID custody; refusing before stopping services."
        BRIDGE_SOURCE_WAS_RUNNING=1
    elif [[ "${pid_state}" == "live" ]]; then
        die "Verified source gateway PID ${pid} is live but version-bound health is ${health_state}; refusing before stopping services."
    elif [[ "${health_state}" != "unreachable" ]]; then
        die "The source health endpoint is not proven unreachable (${health_state}) without verified live PID custody; refusing before stopping services."
    fi
    register_bridge_phase1_recovery_journal
    # The durable journal is the recovery authority. Arm the ordinary EXIT
    # rollback at the same boundary so every caught failure after registration
    # clears or preserves that authority consistently.
    BRIDGE_ROLLBACK_ARMED=1
    ok "Exact source custody and durable crash recovery prepared for automatic bridge rollback"
}

activate_bridge_phase1_cli() {
    local uv_bin source_venv_backup bridge_version bridge_seed
    [[ -n "${whl_name:-}" && -f "${BRIDGE_WHEEL_CUSTODY_PATH}" ]] \
        || die "Bridge CLI artifact is unavailable during activation"
    uv_bin="$(command -v uv 2>/dev/null || true)"
    source_venv_backup="${BACKUP_DIR}/phase1-source-venv"
    [[ ! -e "${source_venv_backup}" && ! -L "${source_venv_backup}" ]] \
        || die "Phase-1 source CLI custody path already exists"
    bridge_seed="$(mktemp -d "${BACKUP_DIR}/phase1-bridge-venv-seed.XXXXXX")" \
        || die "Could not create the resolver-owned bridge venv seed"
    chmod 700 "${bridge_seed}"
    python3 - "${bridge_seed}" "${BRIDGE_RECOVERY_PLAN_ID}" "${BRIDGE_EXPECTED_WHEEL_SHA256}" <<'PY' \
        || die "Could not commit bridge venv activation ownership"
import json
import os
import sys

root, plan_id, wheel_sha256 = sys.argv[1:]
marker = os.path.join(root, ".defenseclaw-phase-one-owner.json")
payload = {
    "schema_version": 1,
    "kind": "defenseclaw-phase-one-bridge-venv",
    "plan_id": plan_id,
    "bridge_wheel_sha256": wheel_sha256,
}
descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
    json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
    stream.write("\n")
    stream.flush()
    os.fsync(stream.fileno())
directory = os.open(root, os.O_RDONLY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
    mv "${DEFENSECLAW_VENV}" "${source_venv_backup}" \
        || die "Could not move the source CLI into rollback custody"
    BRIDGE_SOURCE_VENV_MOVED=1
    python3 - "${source_venv_backup}" "${BRIDGE_SOURCE_VENV_IDENTITY_SHA256}" \
        "${VENV_IDENTITY_PARSER}" <<'PY' \
        || die "Source CLI identity changed while entering rollback custody"
import sys

namespace = {"__name__": "defenseclaw_venv_identity"}
exec(sys.argv[3], namespace)
if namespace["venv_identity"](sys.argv[1]) != sys.argv[2]:
    raise SystemExit(1)
PY
    mv "${bridge_seed}" "${DEFENSECLAW_VENV}" \
        || die "Could not publish the resolver-owned bridge venv seed"
    python3 - "${CONTROLLER_HOME}" "${BACKUP_DIR}" <<'PY' \
        || die "Could not durably retain the source CLI in rollback custody"
import os
import sys

for path in sys.argv[1:]:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
PY

    env -u UV_CONSTRAINT -u UV_OVERRIDE -u UV_EXCLUDE_NEWER \
        "${uv_bin}" --no-config venv "${DEFENSECLAW_VENV}" --allow-existing --python "${BRIDGE_PYTHON_INTERPRETER}" --quiet \
        || die "Could not create the bridge CLI environment"
    prepare_historical_bootstrap_constraints
    env -u UV_CONSTRAINT -u UV_OVERRIDE -u UV_EXCLUDE_NEWER \
        "${uv_bin}" --no-config pip install \
        --python "${DEFENSECLAW_VENV}/bin/python" --quiet --offline \
        --constraints "${HISTORICAL_BOOTSTRAP_CONSTRAINTS_FILE}" \
        --exclude-newer "${HISTORICAL_BOOTSTRAP_EXCLUDE_NEWER}" \
        --only-binary litellm "${BRIDGE_WHEEL_CUSTODY_PATH}" \
        || die "Failed to install the bridge CLI wheel"
    verify_python_dependency_metadata \
        "${uv_bin}" "${DEFENSECLAW_VENV}/bin/python" "Installed bridge CLI environment"
    bridge_version="$("${DEFENSECLAW_VENV}/bin/python" -I -B -c 'from defenseclaw import __version__; print(__version__)')" \
        || die "Could not import the installed bridge CLI"
    [[ "${bridge_version}" == "${RELEASE_VERSION}" ]] \
        || die "Installed bridge CLI version mismatch: expected ${RELEASE_VERSION}, got ${bridge_version}"
    ok "Python CLI installed with exact source rollback custody"
}

bridge_source_health_check() {
    local elapsed=0 health_fields state version
    while [[ "${elapsed}" -lt 30 ]]; do
        health_fields="$(bridge_source_health_observation)" || return 1
        state="${health_fields%%$'\t'*}"
        version="${health_fields#*$'\t'}"
        if [[ ( "${state}" == "running" || "${state}" == "disabled" ) \
              && "${version}" == "${CURRENT_VERSION}" ]]; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

bridge_phase1_gateway_quiesced() {
    local pid_path="${DATA_DIR}/gateway.pid" pid_fields pid_state health_fields health_state
    pid_fields="$(gateway_pid_status "${pid_path}" "${INSTALL_DIR}/defenseclaw-gateway")" || return 1
    pid_state="${pid_fields%%$'\t'*}"
    [[ "${pid_state}" != "live" ]] || return 1
    health_fields="$(bridge_source_health_observation)" || return 1
    health_state="${health_fields%%$'\t'*}"
    [[ "${health_state}" == "unreachable" ]]
}

bridge_phase1_gateway_activation_owned() {
    python3 - \
        "${INSTALL_DIR}/defenseclaw-gateway" \
        "${BACKUP_DIR}/phase1-source-gateway" \
        "${BRIDGE_EXPECTED_GATEWAY_SHA256}" <<'PY'
import hashlib
import os
import stat
import sys

active, source, bridge_sha256 = sys.argv[1:]
if not os.path.lexists(active):
    raise SystemExit(0)
info = os.lstat(active)
if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid():
    raise SystemExit(1)


def digest(path):
    value = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


raise SystemExit(0 if digest(active) in {digest(source), bridge_sha256} else 1)
PY
}

rollback_bridge_phase1() {
    local rollback_failed=0 source_venv_backup="${BACKUP_DIR}/phase1-source-venv"
    local restored_gateway_version restored_cli_version attempt pid_fields pid_state
    local health_fields health_state
    [[ "${BRIDGE_ROLLBACK_RUNNING}" -eq 0 ]] || return 1
    BRIDGE_ROLLBACK_RUNNING=1
    BRIDGE_ROLLBACK_ARMED=0
    section "Restoring Source After Bridge Failure"

    if ! bridge_phase1_gateway_activation_owned; then
        err "Refusing to execute or overwrite an unrecognized phase-one gateway activation"
        return 1
    fi
    if [[ -x "${INSTALL_DIR}/defenseclaw-gateway" ]]; then
        DEFENSECLAW_HOME="${DATA_DIR}" DEFENSECLAW_CONFIG="${CONFIG_PATH}" \
            "${INSTALL_DIR}/defenseclaw-gateway" stop >/dev/null 2>&1 || true
    fi
    for attempt in 1 2 3 4 5; do
        bridge_phase1_gateway_quiesced && break
        sleep 1
    done
    if ! bridge_phase1_gateway_quiesced; then
        err "Bridge gateway could not be quiesced; refusing to overwrite live state during rollback"
        return 1
    fi

    # Restore state while the authenticated bridge artifacts are still in
    # place.  If a concurrent process changed any managed path, the state CAS
    # fails before controller artifacts are switched back, leaving one
    # coherent (stopped) bridge recovery point rather than an old controller
    # over new-format state.
    if ! bridge_phase1_cleanup_owned_temporaries; then
        err "Could not safely clean resolver-owned bridge temporaries"
        return 1
    fi
    if [[ "${BRIDGE_STATE_SNAPSHOT_READY}" -eq 1 ]] \
        && ! bridge_phase1_state_transaction restore
    then
        err "Managed state changed after the bridge snapshot; preserving it under bridge recovery custody"
        return 1
    fi
    if [[ "${DEFENSECLAW_TEST_PHASE1_ROLLBACK_CRASH:-}" == "after-state-restore" ]]; then
        kill -KILL "$$"
    fi

    if [[ "${BRIDGE_SOURCE_VENV_MOVED}" -eq 1 ]]; then
        if [[ -d "${source_venv_backup}" && ! -L "${source_venv_backup}" ]]; then
            python3 - \
                "${DEFENSECLAW_VENV}" \
                "${source_venv_backup}" \
                "${BACKUP_DIR}" \
                "${BRIDGE_RECOVERY_PLAN_ID}" \
                "${BRIDGE_EXPECTED_WHEEL_SHA256}" \
                "${BRIDGE_SOURCE_VENV_IDENTITY_SHA256}" \
                "${VENV_IDENTITY_PARSER}" <<'PY' \
                || rollback_failed=1
import json
import os
import stat
import sys

active, source, backup = map(os.path.abspath, sys.argv[1:4])
plan_id, wheel_sha256, expected_source_identity, identity_parser = sys.argv[4:]
identity_namespace = {"__name__": "defenseclaw_venv_identity"}
exec(identity_parser, identity_namespace)
if identity_namespace["venv_identity"](source) != expected_source_identity:
    raise RuntimeError("source venv custody identity changed before rollback")
if not os.path.isdir(source) or os.path.islink(source):
    raise RuntimeError("source venv custody is unsafe")
if os.path.lexists(active):
    info = os.lstat(active)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid():
        raise RuntimeError("active bridge venv is unsafe")
    marker = os.path.join(active, ".defenseclaw-phase-one-owner.json")
    marker_info = os.lstat(marker)
    if not stat.S_ISREG(marker_info.st_mode) or stat.S_ISLNK(marker_info.st_mode) or marker_info.st_uid != os.geteuid() or stat.S_IMODE(marker_info.st_mode) & 0o077:
        raise RuntimeError("active bridge venv ownership marker is unsafe")
    with open(marker, encoding="utf-8") as stream:
        payload = json.load(stream)
    expected = {"schema_version": 1, "kind": "defenseclaw-phase-one-bridge-venv", "plan_id": plan_id, "bridge_wheel_sha256": wheel_sha256}
    if payload != expected:
        raise RuntimeError("active bridge venv is not owned by this rollback plan")
    quarantine = os.path.join(backup, f"phase1-failed-bridge-venv-{plan_id}")
    if os.path.lexists(quarantine):
        raise RuntimeError("bridge venv quarantine is already occupied")
    os.rename(active, quarantine)
os.rename(source, active)
for path in (os.path.dirname(active), backup):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
PY
        else
            err "Source CLI custody is missing"
            rollback_failed=1
        fi
    fi

    if [[ -f "${BACKUP_DIR}/phase1-source-gateway" && ! -L "${BACKUP_DIR}/phase1-source-gateway" ]]; then
        BRIDGE_GATEWAY_INSTALL_TEMP="$(mktemp "${INSTALL_DIR}/.defenseclaw-gateway.rollback.XXXXXX")" \
            || rollback_failed=1
        if [[ -n "${BRIDGE_GATEWAY_INSTALL_TEMP}" ]] \
            && cp -p "${BACKUP_DIR}/phase1-source-gateway" "${BRIDGE_GATEWAY_INSTALL_TEMP}" \
            && python3 - "${BRIDGE_GATEWAY_INSTALL_TEMP}" <<'PY'
import os
import sys

descriptor = os.open(sys.argv[1], os.O_RDONLY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
        then
            if python3 - \
                "${BRIDGE_GATEWAY_INSTALL_TEMP}" \
                "${INSTALL_DIR}/defenseclaw-gateway" \
                "${BACKUP_DIR}/phase1-source-gateway" \
                "${BRIDGE_EXPECTED_GATEWAY_SHA256}" \
                "${BRIDGE_RECOVERY_PLAN_ID}" <<'PY'
import hashlib
import os
import stat
import sys

candidate, active, source, bridge_sha256, plan_id = sys.argv[1:]


def digest(path):
    value = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


source_sha256 = digest(source)
if digest(candidate) != source_sha256:
    raise RuntimeError("source gateway restore candidate changed")
displaced = f"{active}.phase-one-displaced-{plan_id}"
had_active = os.path.lexists(active)
if had_active:
    info = os.lstat(active)
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid():
        raise RuntimeError("active phase-one gateway is unsafe")
    before = digest(active)
    if before not in {source_sha256, bridge_sha256}:
        raise RuntimeError("active phase-one gateway is unrecognized")
    if os.path.lexists(displaced):
        raise RuntimeError("phase-one gateway quarantine is occupied")
    os.rename(active, displaced)
    if digest(displaced) != before:
        os.rename(displaced, active)
        raise RuntimeError("phase-one gateway changed while quarantining")
try:
    os.rename(candidate, active)
except BaseException:
    if had_active and not os.path.lexists(active) and os.path.lexists(displaced):
        os.rename(displaced, active)
    raise
if digest(active) != source_sha256:
    raise RuntimeError("restored source gateway digest mismatch")
if os.path.lexists(displaced):
    os.unlink(displaced)
descriptor = os.open(os.path.dirname(active), os.O_RDONLY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
            then
                BRIDGE_GATEWAY_INSTALL_TEMP=""
            else
                rollback_failed=1
            fi
        else
            rollback_failed=1
        fi
    else
        err "Source gateway custody is missing"
        rollback_failed=1
    fi

    restored_gateway_version="$("${INSTALL_DIR}/defenseclaw-gateway" --version 2>&1 \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
    [[ "${restored_gateway_version}" == "${CURRENT_VERSION}" ]] || rollback_failed=1
    restored_cli_version="$(PYTHONDONTWRITEBYTECODE=1 "${DEFENSECLAW_VENV}/bin/defenseclaw" --version 2>&1 \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
    [[ "${restored_cli_version}" == "${CURRENT_VERSION}" ]] || rollback_failed=1

    if [[ "${BRIDGE_SOURCE_WAS_RUNNING}" -eq 1 && "${rollback_failed}" -eq 0 ]]; then
        DEFENSECLAW_HOME="${DATA_DIR}" DEFENSECLAW_CONFIG="${CONFIG_PATH}" \
            OPENCLAW_HOME="${OPENCLAW_HOME}" \
            "${INSTALL_DIR}/defenseclaw-gateway" start 9>&- >/dev/null 2>&1 || rollback_failed=1
        if [[ "${rollback_failed}" -eq 0 ]]; then
            pid_fields="$(gateway_pid_status "${DATA_DIR}/gateway.pid" "${INSTALL_DIR}/defenseclaw-gateway")" \
                || rollback_failed=1
            pid_state="${pid_fields%%$'\t'*}"
            [[ "${pid_state}" == "live" ]] || rollback_failed=1
        fi
        if [[ "${rollback_failed}" -eq 0 ]]; then
            bridge_source_health_check || rollback_failed=1
        fi
    else
        pid_fields="$(gateway_pid_status "${DATA_DIR}/gateway.pid" "${INSTALL_DIR}/defenseclaw-gateway")" \
            || rollback_failed=1
        pid_state="${pid_fields%%$'\t'*}"
        [[ "${pid_state}" != "live" ]] || rollback_failed=1
        health_fields="$(bridge_source_health_observation)" || rollback_failed=1
        health_state="${health_fields%%$'\t'*}"
        [[ "${health_state}" == "unreachable" ]] || rollback_failed=1
    fi
    if [[ "${rollback_failed}" -eq 0 ]] && command -v openclaw >/dev/null 2>&1; then
        OPENCLAW_HOME="${OPENCLAW_HOME}" openclaw gateway restart 9>&- >/dev/null 2>&1 \
            || warn "Could not restart OpenClaw after source rollback"
    fi

    if [[ "${rollback_failed}" -eq 0 ]]; then
        complete_bridge_phase1_recovery_journal "${BRIDGE_RECOVERY_PLAN_ID}" source \
            || rollback_failed=1
    fi

    if [[ "${rollback_failed}" -eq 0 ]]; then
        if [[ "${BRIDGE_SOURCE_WAS_RUNNING}" -eq 1 ]]; then
            ok "Source ${CURRENT_VERSION} artifacts and state restored; source health rechecked"
        else
            ok "Source ${CURRENT_VERSION} artifacts and state restored"
        fi
        return 0
    fi
    err "Source rollback did not pass every restoration and health check"
    return 1
}

prepare_hard_cut_target_controller() {
    local protected_wheel wheel_root materialized_wheel uv_bin base_python observed actual
    [[ -z "${TARGET_CONTROLLER_CLI:-}" ]] || return 0
    [[ -n "${FINAL_RELEASE_VERSION}" \
       && -n "${FINAL_RELEASE_WHL_NAME}" \
       && -n "${FINAL_RELEASE_WHL_URL}" \
       && -n "${FINAL_RELEASE_MATERIALIZED_WHL_NAME}" \
       && "${FINAL_RELEASE_WHL_SHA256}" =~ ^[0-9a-f]{64}$ ]] \
        || die "The authenticated hard-cut target-controller contract is unavailable. No services changed."
    [[ "${FINAL_RELEASE_VERSION}" == "${OBSERVABILITY_V8_HARD_CUT_VERSION}" ]] \
        || die "Historical dependency custody is restricted to the authenticated ${OBSERVABILITY_V8_HARD_CUT_VERSION} hard-cut controller. No services changed."

    section "Preparing Fresh Target Controller"
    protected_wheel="${STAGING_DIR}/target-controller-${FINAL_RELEASE_WHL_NAME}"
    step "Downloading authenticated ${FINAL_RELEASE_VERSION} target controller ..."
    fetch_artifact "${FINAL_RELEASE_WHL_URL}" "${protected_wheel}"
    chmod 600 "${protected_wheel}" \
        || die "Could not establish private target-controller wheel custody. No services changed."
    actual="$(${SHA256_CMD} "${protected_wheel}" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')"
    [[ "${actual}" == "${FINAL_RELEASE_WHL_SHA256}" ]] \
        || die "The hard-cut target controller wheel failed its authenticated digest check. No services changed."

    wheel_root="${STAGING_DIR}/target-controller-wheel"
    mkdir "${wheel_root}" \
        || die "Could not create private target-controller wheel custody. No services changed."
    chmod 700 "${wheel_root}"
    materialized_wheel="${wheel_root}/${FINAL_RELEASE_MATERIALIZED_WHL_NAME}"
    materialize_protected_artifact \
        "${protected_wheel}" "${materialized_wheel}" "${FINAL_RELEASE_WHL_SHA256}" \
        || die "Could not materialize the authenticated hard-cut target controller. No services changed."
    preflight_python_wheel "${materialized_wheel}"

    uv_bin="$(command -v uv 2>/dev/null || true)"
    [[ -n "${uv_bin}" ]] \
        || die "uv not found on PATH — cannot prepare the fresh target controller. No services changed."
    [[ -x "${DEFENSECLAW_VENV}/bin/python" ]] \
        || die "The installed bridge Python environment is unavailable. No services changed."
    base_python="$("${DEFENSECLAW_VENV}"/bin/python -I -B -c \
        'import os,sys; print(os.path.realpath(getattr(sys, "_base_executable", "") or sys.executable))')" \
        || die "Could not resolve the bridge base Python interpreter. No services changed."
    [[ -x "${base_python}" ]] \
        || die "The bridge base Python interpreter is unavailable. No services changed."
    python3 - "${base_python}" "${DEFENSECLAW_VENV}" <<'PY' \
        || die "The target controller cannot use a Python interpreter inside the active bridge venv. No services changed."
import os
import sys

interpreter, installed_venv = (os.path.realpath(value) for value in sys.argv[1:])
try:
    inside = os.path.commonpath((interpreter, installed_venv)) == installed_venv
except ValueError:
    inside = False
raise SystemExit(1 if inside else 0)
PY

    TARGET_CONTROLLER_VENV="${STAGING_DIR}/target-controller-venv"
    prepare_historical_bootstrap_constraints
    env -u UV_CONSTRAINT -u UV_OVERRIDE -u UV_EXCLUDE_NEWER \
        "${uv_bin}" --no-config venv "${TARGET_CONTROLLER_VENV}" --python "${base_python}" --quiet \
        || die "Could not create the private target-controller venv. No services changed."
    chmod 700 "${TARGET_CONTROLLER_VENV}"
    env -u UV_CONSTRAINT -u UV_OVERRIDE -u UV_EXCLUDE_NEWER \
        "${uv_bin}" --no-config pip install \
        --python "${TARGET_CONTROLLER_VENV}/bin/python" --quiet \
        --constraints "${HISTORICAL_BOOTSTRAP_CONSTRAINTS_FILE}" \
        --exclude-newer "${HISTORICAL_BOOTSTRAP_EXCLUDE_NEWER}" \
        --only-binary litellm "${materialized_wheel}" \
        || die "Could not install the authenticated target controller in private custody. No services changed."
    verify_python_dependency_metadata \
        "${uv_bin}" "${TARGET_CONTROLLER_VENV}/bin/python" \
        "Authenticated hard-cut target-controller environment"
    observed="$(PYTHONDONTWRITEBYTECODE=1 "${TARGET_CONTROLLER_VENV}/bin/python" -I -B -c \
        'from defenseclaw import __version__; print(__version__)')" \
        || die "Could not import the fresh target controller. No services changed."
    [[ "${observed}" == "${FINAL_RELEASE_VERSION}" ]] \
        || die "Fresh target controller version mismatch: expected ${FINAL_RELEASE_VERSION}, got ${observed:-missing}. No services changed."
    TARGET_CONTROLLER_CLI="${TARGET_CONTROLLER_VENV}/bin/defenseclaw"
    [[ -x "${TARGET_CONTROLLER_CLI}" && ! -L "${TARGET_CONTROLLER_CLI}" ]] \
        || die "The fresh target-controller entrypoint lost private custody. No services changed."
    TARGET_CONTROLLER_PROTECTED_WHEEL="${protected_wheel}"
    ok "Fresh ${FINAL_RELEASE_VERSION} target controller prepared in private custody"
}

verify_hard_cut_target_controller_handoff() {
    local bridge_version="$1" target_version="$2" handoff_dir="$3"
    python3 - \
        "${TARGET_CONTROLLER_VENV}" \
        "${TARGET_CONTROLLER_CLI}" \
        "${DEFENSECLAW_VENV}" \
        "${INSTALL_DIR}/defenseclaw" \
        "${INSTALL_DIR}/defenseclaw-gateway" \
        "${handoff_dir}" \
        "${TARGET_CONTROLLER_PROTECTED_WHEEL}" \
        "${FINAL_RELEASE_WHL_SHA256}" \
        "${bridge_version}" \
        "${target_version}" <<'PY'
import hashlib
import os
import re
import stat
import subprocess
import sys

path_values = tuple(map(os.path.abspath, sys.argv[1:7]))
(
    target_venv,
    target_cli,
    installed_venv,
    installed_launcher,
    installed_gateway,
    handoff_dir,
    protected_wheel,
    protected_sha256,
    bridge_version,
    target_version,
) = (*path_values, *sys.argv[7:])


def private_directory(path: str, *, exact_mode: int = 0o700) -> None:
    info = os.lstat(path)
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != exact_mode
    ):
        raise RuntimeError(f"private handoff directory is unsafe: {os.path.basename(path)}")


def managed_executable(path: str, *, require_single_link: bool = False) -> None:
    info = os.lstat(path)
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or (require_single_link and info.st_nlink != 1)
        or stat.S_IMODE(info.st_mode) & 0o022
        or not stat.S_IMODE(info.st_mode) & stat.S_IXUSR
    ):
        raise RuntimeError(f"handoff executable is unsafe: {os.path.basename(path)}")


def reported_version(path: str) -> str:
    completed = subprocess.run(
        [path, "--version"],
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    values = re.findall(
        r"(?<![0-9A-Za-z.])((?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))(?![0-9A-Za-z.])",
        (completed.stdout or "") + (completed.stderr or ""),
    )
    if completed.returncode != 0 or len(values) != 1:
        raise RuntimeError(f"handoff executable version is unverifiable: {os.path.basename(path)}")
    return values[0]


private_directory(target_venv)
private_directory(handoff_dir)
managed_executable(target_cli, require_single_link=True)
installed_cli = os.path.realpath(os.path.join(installed_venv, "bin", "defenseclaw"))
managed_executable(installed_cli)
managed_executable(installed_gateway)
launcher_info = os.lstat(installed_launcher)
if (
    not stat.S_ISLNK(launcher_info.st_mode)
    or launcher_info.st_uid != os.geteuid()
    or os.path.realpath(installed_launcher) != installed_cli
):
    raise RuntimeError("installed bridge launcher is not the canonical managed symlink")
try:
    target_inside_installed = os.path.commonpath(
        (os.path.realpath(target_venv), os.path.realpath(installed_venv))
    ) == os.path.realpath(installed_venv)
except ValueError:
    target_inside_installed = False
if target_inside_installed:
    raise RuntimeError("target controller is not out-of-place from the installed bridge")

wheel_info = os.lstat(protected_wheel)
if (
    stat.S_ISLNK(wheel_info.st_mode)
    or not stat.S_ISREG(wheel_info.st_mode)
    or wheel_info.st_uid != os.geteuid()
    or wheel_info.st_nlink != 1
    or stat.S_IMODE(wheel_info.st_mode) & 0o077
    or not 0 < wheel_info.st_size <= 256 * 1024 * 1024
):
    raise RuntimeError("authenticated target-controller wheel lost private custody")
value = hashlib.sha256()
with open(protected_wheel, "rb") as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        value.update(chunk)
if value.hexdigest() != protected_sha256:
    raise RuntimeError("authenticated target-controller wheel changed before handoff")
if reported_version(target_cli) != target_version:
    raise RuntimeError("fresh target-controller version changed before handoff")
if reported_version(installed_launcher) != bridge_version:
    raise RuntimeError("installed bridge CLI changed before target handoff")
if reported_version(installed_gateway) != bridge_version:
    raise RuntimeError("installed bridge gateway changed before target handoff")
PY
}

continue_post_hard_cut_upgrade() {
    local final_version="${POST_HARD_CUT_FINAL_VERSION:-}"
    local installed_version gateway_version final_status=0
    [[ -n "${final_version}" ]] || return 0
    validate_version "${final_version}"
    version_lt "${OBSERVABILITY_V8_HARD_CUT_VERSION}" "${final_version}" \
        || die "Invalid post-hard-cut target ${final_version}; the healthy ${OBSERVABILITY_V8_HARD_CUT_VERSION} installation was preserved."

    [[ -x "${DEFENSECLAW_VENV}/bin/python" \
       && -x "${DEFENSECLAW_VENV}/bin/defenseclaw" \
       && -x "${INSTALL_DIR}/defenseclaw-gateway" ]] \
        || die "The ${OBSERVABILITY_V8_HARD_CUT_VERSION} bootstrap completed without a canonical controller/gateway pair; ${final_version} was not attempted."
    installed_version="$("${DEFENSECLAW_VENV}/bin/python" -I -B -c \
        'from defenseclaw import __version__; print(__version__)')" \
        || die "Could not verify the installed hard-cut controller; ${final_version} was not attempted."
    gateway_version="$("${INSTALL_DIR}/defenseclaw-gateway" --version 2>&1 \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)" \
        || die "Could not verify the installed hard-cut gateway; ${final_version} was not attempted."
    [[ "${installed_version}" == "${OBSERVABILITY_V8_HARD_CUT_VERSION}" \
       && "${gateway_version}" == "${OBSERVABILITY_V8_HARD_CUT_VERSION}" ]] \
        || die "Hard-cut bootstrap component mismatch (CLI ${installed_version:-unknown}, gateway ${gateway_version:-unknown}); ${final_version} was not attempted."

    section "Hard Cut Verified"
    ok "${OBSERVABILITY_V8_HARD_CUT_VERSION} is healthy; continuing to ${final_version}"

    # The authenticated bootstrap controller is now installed outside the
    # private target staging directory.  Drop the completed hard-cut handoff
    # custody, but keep this resolver's cross-process lock until the ordinary
    # post-cut child and any inherited mutators have exited.  The completed
    # 0.8.4 hard-cut rollback is not re-armed for this later transaction.
    unset DEFENSECLAW_STAGED_UPGRADE
    unset DEFENSECLAW_STAGED_BRIDGE_VERSION
    unset DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR
    unset DEFENSECLAW_STAGED_TARGET_CONTROLLER_VERSION
    [[ -z "${STAGING_DIR:-}" ]] || rm -rf "${STAGING_DIR}"
    STAGING_DIR=""
    # The immutable 0.8.5 controller gives child commands 30 seconds but owns
    # a separate 60-second, version-aware gateway health poll. Current gateway
    # binaries consume this process-scoped handoff marker after safe launch so
    # that the controller, rather than both layers, owns the readiness wait.
    env -u UV_CONSTRAINT -u UV_OVERRIDE -u UV_EXCLUDE_NEWER \
        DEFENSECLAW_UPGRADE_FRESH_PROCESS=1 \
        "${DEFENSECLAW_VENV}/bin/defenseclaw" upgrade --yes --version "${final_version}" \
        || final_status=$?
    exit "${final_status}"
}

handoff_existing_bridge_to_hard_cut() {
    local final_version="${RELEASE_VERSION}"
    local final_min_protocol="${STAGED_FINAL_MIN_PROTOCOL}"
    local handoff_dir

    prepare_hard_cut_target_controller
    RELEASE_VERSION="${CURRENT_VERSION}"
    configure_release
    prepare_release_contract
    require_bridge_checksums_provenance \
        "${FINAL_RELEASE_PROVENANCE_BRIDGE_CHECKSUMS_SHA256}" \
        "${CHECKSUMS_FILE}"
    if [[ "${MANIFEST_CONTROLLER_PROTOCOL}" -lt "${final_min_protocol}" ]]; then
        die "Installed bridge ${CURRENT_VERSION} cannot drive ${final_version}. No changes were made."
    fi

    step "Retaining verified bridge gateway for rollback ..."
    fetch_artifact "${TARBALL_URL}" "${STAGING_DIR}/${TARBALL_NAME}"
    verify_checksum "${STAGING_DIR}/${TARBALL_NAME}" "${TARBALL_NAME}"
    materialize_protected_artifact \
        "${STAGING_DIR}/${TARBALL_NAME}" "${STAGING_DIR}/${MATERIALIZED_TARBALL_NAME}" "${VERIFIED_CHECKSUM}" \
        || die "Could not materialize the authenticated protected bridge gateway"
    validate_tarball_members "${STAGING_DIR}/${MATERIALIZED_TARBALL_NAME}"
    step "Retaining verified bridge CLI for rollback ..."
    fetch_artifact "${WHL_URL}" "${STAGING_DIR}/${WHL_NAME}"
    verify_checksum "${STAGING_DIR}/${WHL_NAME}" "${WHL_NAME}"
    materialize_protected_artifact \
        "${STAGING_DIR}/${WHL_NAME}" "${STAGING_DIR}/${MATERIALIZED_WHL_NAME}" "${VERIFIED_CHECKSUM}" \
        || die "Could not materialize the authenticated protected bridge CLI"
    preflight_python_wheel "${STAGING_DIR}/${MATERIALIZED_WHL_NAME}"
    preflight_bridge_rollback_capability "${STAGING_DIR}/${MATERIALIZED_WHL_NAME}"

    handoff_dir="${STAGING_DIR}/bridge-handoff"
    create_bridge_handoff_directory "${handoff_dir}" >/dev/null
    verify_hard_cut_target_controller_handoff \
        "${CURRENT_VERSION}" "${final_version}" "${handoff_dir}" \
        || die "Fresh target-controller handoff verification failed; the healthy bridge was preserved."
    section "Fresh Controller Handoff"
    ok "Verified ${CURRENT_VERSION} rollback artifacts retained; launching the authenticated ${final_version} controller"
    export DEFENSECLAW_STAGED_UPGRADE=1
    export DEFENSECLAW_STAGED_BRIDGE_VERSION="${CURRENT_VERSION}"
    export DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR="${handoff_dir}"
    export DEFENSECLAW_STAGED_TARGET_CONTROLLER_VERSION="${final_version}"
    export DEFENSECLAW_HOME="${CONTROLLER_HOME}"
    export DEFENSECLAW_CONFIG="${CONFIG_PATH}"
    export OPENCLAW_HOME="${OPENCLAW_HOME}"
    local target_status=0
    env -u UV_OVERRIDE \
        UV_CONSTRAINT="${HISTORICAL_BOOTSTRAP_CONSTRAINTS_FILE}" \
        UV_EXCLUDE_NEWER="${HISTORICAL_BOOTSTRAP_EXCLUDE_NEWER}" \
        "${TARGET_CONTROLLER_CLI}" upgrade --yes --version "${final_version}" \
        || target_status=$?
    if [[ "${target_status}" -eq 0 ]]; then
        continue_post_hard_cut_upgrade
    fi
    exit "${target_status}"
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

prepare_release_contract
FINAL_RELEASE_PROVENANCE_BRIDGE_CHECKSUMS_SHA256="${RELEASE_PROVENANCE_BRIDGE_CHECKSUMS_SHA256}"
resolve_staged_upgrade

if [[ "${CURRENT_VERSION}" != "unknown" \
      && "${CURRENT_VERSION}" == "${RELEASE_VERSION}" \
      && -z "${STAGED_FINAL_VERSION}" ]]; then
    same_version_recovery="clean"
    if [[ -n "${RELEASE_PROVENANCE_FILE}" ]]; then
        [[ -x "${DEFENSECLAW_VENV}/bin/python" \
            && -x "${DEFENSECLAW_VENV}/bin/defenseclaw" ]] \
            || die "The installed target controller is incomplete; authenticated recovery cannot continue."
        same_version_recovery="$(
            DEFENSECLAW_HOME="${DATA_DIR}" "${DEFENSECLAW_VENV}/bin/python" -I -B - \
                "${DATA_DIR}" "${RELEASE_VERSION}" <<'PY'
import sys

from defenseclaw.bundle_refresh import installed_local_observability_bundle_version
from defenseclaw.upgrade_receipt import (
    find_resumable_upgrade_receipt,
    find_verified_installed_upgrade_receipt,
)

data_dir, target_version = sys.argv[1:]
receipt = find_resumable_upgrade_receipt(data_dir, target_version=target_version)
bundle_version = installed_local_observability_bundle_version(data_dir)
needs_bundle_repair = bundle_version is not None and bundle_version != target_version
installed_receipt = None
if receipt is None and needs_bundle_repair:
    installed_receipt = find_verified_installed_upgrade_receipt(
        data_dir,
        target_version=target_version,
    )
if receipt is not None or installed_receipt is not None:
    print("recover")
elif needs_bundle_repair:
    print("untrusted-bundle-drift")
else:
    print("clean")
PY
        )" || die "Could not inspect authenticated same-version recovery state; no mutation was attempted."
        [[ "${same_version_recovery}" == "clean" \
            || "${same_version_recovery}" == "recover" \
            || "${same_version_recovery}" == "untrusted-bundle-drift" ]] \
            || die "The installed target controller returned invalid recovery state; no mutation was attempted."
    fi
    if [[ "${same_version_recovery}" == "untrusted-bundle-drift" ]]; then
        die "The installed local-observability bundle differs from ${RELEASE_VERSION}, but no verified target-install receipt remains. No changes were made.
  The resolver will not trust a version string alone. Use an isolated fresh install or contact DefenseClaw support for state-aware recovery."
    fi
    if [[ "${same_version_recovery}" == "recover" ]]; then
        section "Recovering Incomplete Upgrade"
        if [[ "${PLAN_ONLY}" -eq 1 ]]; then
            ok "Authenticated recovery authority exists for ${RELEASE_VERSION}"
            info "Re-run without --plan to reconcile the receipt, bundle, and target health."
            exit 0
        fi
        recovery_status=0
        env -u UV_CONSTRAINT -u UV_OVERRIDE -u UV_EXCLUDE_NEWER \
            DEFENSECLAW_HOME="${DATA_DIR}" DEFENSECLAW_CONFIG="${CONFIG_PATH}" \
            OPENCLAW_HOME="${OPENCLAW_HOME}" \
            "${DEFENSECLAW_VENV}/bin/defenseclaw" upgrade --yes \
                --version "${RELEASE_VERSION}" --health-timeout 60 \
            || recovery_status=$?
        exit "${recovery_status}"
    fi
    section "Version Already Verified"
    if [[ "${CHECKSUMS_SIGNATURE_VERIFIED}" -eq 1 ]]; then
        ok "Authenticated the ${RELEASE_VERSION} release contract; installed version ${CURRENT_VERSION} is already current"
    else
        warn "Installed version ${CURRENT_VERSION} is already current, but this legacy release has no authenticated Sigstore provenance"
    fi
    info "No backup, receipt, service stop, artifact install, or migration was performed."
    exit 0
fi

if [[ "${CURRENT_VERSION}" != "unknown" ]] \
    && [[ "${RELEASE_VERSION}" == "0.8.4" ]] \
    && version_lt "${CURRENT_VERSION}" "${RELEASE_VERSION}"; then
    BRIDGE_PHASE1=1
fi

if [[ "${PLAN_ONLY}" -eq 1 ]]; then
    section "Upgrade Plan Verified"
    if [[ -n "${STAGED_FINAL_VERSION}" && -n "${POST_HARD_CUT_FINAL_VERSION}" ]]; then
        ok "${CURRENT_VERSION} → ${RELEASE_VERSION} → fresh controller → ${STAGED_FINAL_VERSION} → ${POST_HARD_CUT_FINAL_VERSION}"
    elif [[ -n "${POST_HARD_CUT_FINAL_VERSION}" ]]; then
        ok "${CURRENT_VERSION} → ${RELEASE_VERSION} → ${POST_HARD_CUT_FINAL_VERSION}"
    elif [[ -n "${STAGED_FINAL_VERSION}" ]]; then
        ok "${CURRENT_VERSION} → ${RELEASE_VERSION} → fresh controller → ${STAGED_FINAL_VERSION}"
    else
        ok "${CURRENT_VERSION} → ${RELEASE_VERSION}"
    fi
    ok "No changes were made"
    exit 0
fi

if [[ "${FRESH_HARD_CUT_HANDOFF}" -eq 1 ]]; then
    ensure_upgrade_lock_before_mutation
    handoff_existing_bridge_to_hard_cut
fi

step "Downloading gateway binary ..."
fetch_artifact "${TARBALL_URL}" "${STAGING_DIR}/${TARBALL_NAME}"
verify_checksum "${STAGING_DIR}/${TARBALL_NAME}" "${TARBALL_NAME}"
materialize_protected_artifact \
    "${STAGING_DIR}/${TARBALL_NAME}" "${STAGING_DIR}/${MATERIALIZED_TARBALL_NAME}" "${VERIFIED_CHECKSUM}" \
    || die "Could not materialize the authenticated protected gateway artifact"
validate_tarball_members "${STAGING_DIR}/${MATERIALIZED_TARBALL_NAME}"
tar -xzf "${STAGING_DIR}/${MATERIALIZED_TARBALL_NAME}" -C "${STAGING_DIR}" \
    || die "Could not extract gateway tarball"
[[ -f "${STAGING_DIR}/defenseclaw" ]] \
    || die "Gateway tarball did not contain the expected defenseclaw binary"
if [[ "${OS}" == "darwin" ]]; then
    /usr/bin/codesign -f -s - -i com.cisco.defenseclaw.gateway \
        "${STAGING_DIR}/defenseclaw" 2>/dev/null \
        || die "Could not ad-hoc sign the staged macOS gateway; no services changed."
fi
ok "Gateway binary downloaded"

step "Downloading Python CLI wheel ..."
fetch_artifact "${WHL_URL}" "${STAGING_DIR}/${WHL_NAME}"
verify_checksum "${STAGING_DIR}/${WHL_NAME}" "${WHL_NAME}"
materialize_protected_artifact \
    "${STAGING_DIR}/${WHL_NAME}" "${STAGING_DIR}/${MATERIALIZED_WHL_NAME}" "${VERIFIED_CHECKSUM}" \
    || die "Could not materialize the authenticated protected CLI artifact"
whl_name="${MATERIALIZED_WHL_NAME}"
ok "Python CLI wheel downloaded"
preflight_python_wheel "${STAGING_DIR}/${whl_name}"
if [[ -n "${STAGED_FINAL_VERSION}" ]]; then
    preflight_bridge_rollback_capability "${STAGING_DIR}/${whl_name}"
fi
if [[ "${BRIDGE_PHASE1}" -eq 1 ]]; then
    staged_gateway_version="$("${STAGING_DIR}/defenseclaw" --version 2>&1 || true)"
    printf '%s' "${staged_gateway_version}" | grep -Fq "${RELEASE_VERSION}" \
        || die "Bridge gateway preflight version mismatch: expected ${RELEASE_VERSION}; binary reported: $(printf '%s' "${staged_gateway_version}" | head -n1 | cut -c1-200). No services changed."
    prepare_bridge_phase1_cli_preflight
fi

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

ensure_upgrade_lock_before_mutation

section "Creating Backup"

TIMESTAMP=$(date +%Y%m%dT%H%M%S)
BACKUP_DIR="$(python3 - "${BACKUP_ROOT}" "${TIMESTAMP}" <<'PY'
import os
import stat
import sys
import tempfile

root = os.path.abspath(os.path.expanduser(sys.argv[1]))
timestamp = sys.argv[2]
parent = os.path.dirname(root)
parent_stat = os.lstat(parent)
if not stat.S_ISDIR(parent_stat.st_mode) or stat.S_ISLNK(parent_stat.st_mode):
    raise SystemExit("backup parent must be a real directory")
if parent_stat.st_uid != os.geteuid() or stat.S_IMODE(parent_stat.st_mode) & 0o022:
    raise SystemExit("backup parent must be current-user-owned and not group/other writable")
try:
    os.mkdir(root, 0o700)
except FileExistsError:
    pass
root_stat = os.lstat(root)
if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
    raise SystemExit("backup root must be a real directory")
if root_stat.st_uid != os.geteuid():
    raise SystemExit("backup root is not owned by the current user")
os.chmod(root, 0o700)
directory = tempfile.mkdtemp(prefix=f"upgrade-{timestamp}-", dir=root)
os.chmod(directory, 0o700)
directory_stat = os.lstat(directory)
if not stat.S_ISDIR(directory_stat.st_mode) or stat.S_ISLNK(directory_stat.st_mode):
    raise SystemExit("backup custody directory is not a real directory")
print(directory)
PY
)" || die "Could not create a private collision-safe backup custody directory; no services changed."

if [[ -f "${CONFIG_PATH}" && ! -L "${CONFIG_PATH}" ]]; then
    cp "${CONFIG_PATH}" "${BACKUP_DIR}/config.yaml" && ok "Backed up: config.yaml"
fi
if [[ -d "${DATA_DIR}" ]]; then
    for f in .env .migration_state.json guardrail_runtime.json device.key \
        active_connector.json codex_backup.json claudecode_backup.json \
        zeptoclaw_backup.json codex_config_backup.json; do
        src="${DATA_DIR}/$f"
        [[ -f "${src}" ]] && cp "${src}" "${BACKUP_DIR}/" && ok "Backed up: $f"
    done
    if [[ -d "${DATA_DIR}/policies" ]]; then
        cp -r "${DATA_DIR}/policies" "${BACKUP_DIR}/policies"
        ok "Backed up: policies/"
    fi
    if [[ -d "${DATA_DIR}/connector_backups" ]]; then
        cp -r "${DATA_DIR}/connector_backups" "${BACKUP_DIR}/connector_backups"
        ok "Backed up: connector_backups/"
    fi
fi

OPENCLAW_JSON="${OPENCLAW_HOME}/openclaw.json"
if [[ -f "${OPENCLAW_JSON}" ]]; then
    cp "${OPENCLAW_JSON}" "${BACKUP_DIR}/openclaw.json"
    ok "Backed up: openclaw.json"
fi

ok "Backup saved to: ${BACKUP_DIR}"

# Provenance-authenticated direct upgrades commit their receipt before the
# first service or installed-file mutation. Staged hard cuts keep receipt and
# rollback custody in the fresh target controller instead.
begin_release_upgrade_receipt

if [[ "${BRIDGE_PHASE1}" -eq 1 ]]; then
    prepare_bridge_phase1_custody
fi

# ── Stop services ─────────────────────────────────────────────────────────────

assert_gateway_quiesced() {
    local pid_path="${DATA_DIR}/gateway.pid" pid_fields pid_state pid
    pid_fields="$(gateway_pid_status "${pid_path}" "${INSTALL_DIR}/defenseclaw-gateway")" \
        || die "Gateway PID custody is invalid after stop; refusing to replace installed artifacts"
    pid_state="${pid_fields%%$'\t'*}"
    pid="${pid_fields#*$'\t'}"
    if [[ "${pid_state}" == "live" ]]; then
        die "Gateway process ${pid} is still running after stop; refusing to replace installed artifacts"
    fi
}

section "Stopping Services"

step "Stopping defenseclaw-gateway ..."
if [[ "${BRIDGE_PHASE1}" -eq 1 ]]; then
    # Arm rollback before the stop: even a stop command that exits non-zero may
    # already have terminated the source process.
    BRIDGE_ROLLBACK_ARMED=1
fi
DEFENSECLAW_HOME="${DATA_DIR}" DEFENSECLAW_CONFIG="${CONFIG_PATH}" \
    "${INSTALL_DIR}/defenseclaw-gateway" stop 2>/dev/null \
    && ok "Gateway stopped" || warn "Gateway was not running"
assert_gateway_quiesced
if [[ "${BRIDGE_PHASE1}" -eq 1 ]]; then
    post_stop_health="$(bridge_source_health_observation)" \
        || die "Could not verify source health quiescence after stop; the source will be restored."
    post_stop_state="${post_stop_health%%$'\t'*}"
    [[ "${post_stop_state}" == "unreachable" ]] \
        || die "The source health endpoint remains live without PID custody after stop; the source will be restored."
    bridge_phase1_state_transaction snapshot \
        || die "Could not create an exact quiesced phase-one state snapshot; the source will be restored."
    seal_bridge_phase1_state_snapshot_journal \
        || die "Could not durably seal the quiesced phase-one state snapshot; the source will be restored."
fi

# ── Install from staging (fast, no network) ───────────────────────────────────

section "Installing Artifacts"

mkdir -p "${INSTALL_DIR}"

# Snapshot the previous gateway binary so the operator can roll back
# manually if the new binary fails health check. Keeps the upgrade
# truly non-destructive — even in the worst case the previous binary
# is one ``cp`` away.
if [[ "${BRIDGE_PHASE1}" -ne 1 && -f "${INSTALL_DIR}/defenseclaw-gateway" ]]; then
    cp "${INSTALL_DIR}/defenseclaw-gateway" "${BACKUP_DIR}/defenseclaw-gateway.previous" \
        && chmod +x "${BACKUP_DIR}/defenseclaw-gateway.previous" \
        && ok "Snapshotted previous gateway → ${BACKUP_DIR}/defenseclaw-gateway.previous" \
        || warn "Could not snapshot previous gateway binary"
fi

BRIDGE_GATEWAY_INSTALL_TEMP="$(mktemp "${INSTALL_DIR}/.defenseclaw-gateway.upgrade.XXXXXX")" \
    || die "Could not create a collision-safe gateway activation file"
if [[ "${BRIDGE_PHASE1}" -eq 1 ]]; then
    cp "${BACKUP_DIR}/phase1-bridge-gateway" "${BRIDGE_GATEWAY_INSTALL_TEMP}"
else
    cp "${STAGING_DIR}/defenseclaw" "${BRIDGE_GATEWAY_INSTALL_TEMP}"
fi
chmod +x "${BRIDGE_GATEWAY_INSTALL_TEMP}"

if [[ "${BRIDGE_PHASE1}" -eq 1 ]]; then
    python3 - \
        "${BRIDGE_GATEWAY_INSTALL_TEMP}" \
        "${INSTALL_DIR}/defenseclaw-gateway" \
        "${BACKUP_DIR}/phase1-source-gateway" \
        "${BRIDGE_EXPECTED_GATEWAY_SHA256}" \
        "${BRIDGE_RECOVERY_PLAN_ID}" <<'PY' \
        || die "Could not atomically publish the resolver-owned bridge gateway"
import hashlib
import os
import stat
import sys

candidate, active, source, bridge_sha256, plan_id = sys.argv[1:]


def digest(path):
    value = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


source_sha256 = digest(source)
if digest(candidate) != bridge_sha256:
    raise RuntimeError("bridge gateway activation candidate changed")
info = os.lstat(active)
if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid() or digest(active) != source_sha256:
    raise RuntimeError("source gateway identity changed before bridge activation")
displaced = f"{active}.phase-one-displaced-{plan_id}"
if os.path.lexists(displaced):
    raise RuntimeError("bridge gateway activation quarantine is occupied")
os.rename(active, displaced)
if digest(displaced) != source_sha256:
    os.rename(displaced, active)
    raise RuntimeError("source gateway changed while quarantining")
try:
    os.rename(candidate, active)
except BaseException:
    if not os.path.lexists(active) and os.path.lexists(displaced):
        os.rename(displaced, active)
    raise
if digest(active) != bridge_sha256:
    raise RuntimeError("published bridge gateway digest mismatch")
os.unlink(displaced)
descriptor = os.open(os.path.dirname(active), os.O_RDONLY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
else
    mv -f "${BRIDGE_GATEWAY_INSTALL_TEMP}" "${INSTALL_DIR}/defenseclaw-gateway"
    # A graceful failure from this point until target CLI activation must
    # remain eligible for exact receipt-bound component-split recovery. A
    # process crash in the same window leaves the pending receipt authoritative.
    UPGRADE_RECEIPT_FAILURE_CODE="interrupted"
fi
BRIDGE_GATEWAY_INSTALL_TEMP=""
ok "Gateway binary installed"

# Verify the freshly-installed binary reports the expected version. A
# truncated tarball or failed copy surfaces here as a warning instead of
# as a confusing post-deploy bug report.
gw_version_output="$("${INSTALL_DIR}/defenseclaw-gateway" --version 2>&1 || true)"
if printf '%s' "${gw_version_output}" | grep -Fq "${RELEASE_VERSION}"; then
    ok "Gateway binary verified (${RELEASE_VERSION})"
else
    die "Gateway version verification failed: expected ${RELEASE_VERSION}; binary reported: $(printf '%s' "${gw_version_output}" | head -n1 | cut -c1-200)"
fi

UV_BIN="$(command -v uv 2>/dev/null || true)"
[[ -z "${UV_BIN}" ]] \
    && die "uv not found on PATH — cannot update Python CLI. Install: curl -LsSf https://astral.sh/uv/install.sh | sh"

if [[ "${BRIDGE_PHASE1}" -eq 1 ]]; then
    activate_bridge_phase1_cli
else
    if [[ ! -d "${DEFENSECLAW_VENV}" ]]; then
        step "Creating venv at ${DEFENSECLAW_VENV} ..."
        env -u UV_CONSTRAINT -u UV_OVERRIDE -u UV_EXCLUDE_NEWER \
            "${UV_BIN}" --no-config venv "${DEFENSECLAW_VENV}" --python 3.12
    fi
    VENV_PYTHON="${DEFENSECLAW_VENV}/bin/python"
    env -u UV_CONSTRAINT -u UV_OVERRIDE -u UV_EXCLUDE_NEWER \
        "${UV_BIN}" --no-config pip install \
        --python "${VENV_PYTHON}" --quiet --only-binary litellm \
        "${STAGING_DIR}/${whl_name}" \
        || die "Failed to install CLI wheel"
    verify_python_dependency_metadata \
        "${UV_BIN}" "${VENV_PYTHON}" "Installed target CLI environment"
    "${DEFENSECLAW_VENV}/bin/defenseclaw" --help >/dev/null 2>&1 \
        || die "CLI validation failed before launcher publication"
    ln -sf "${DEFENSECLAW_VENV}/bin/defenseclaw" "${INSTALL_DIR}/defenseclaw"
    ok "Python CLI installed"
fi
VENV_PYTHON="${DEFENSECLAW_VENV}/bin/python"

# ── Run migrations ────────────────────────────────────────────────────────────

if [[ "${BRIDGE_PHASE1}" -eq 1 ]]; then
    mark_bridge_phase1_state_mutation_started \
        || die "Could not durably arm phase-one state mutation recovery before migrations"
fi

section "Running Migrations"

# Run migrations with the freshly-installed CLI environment. The Python
# helper is intentionally verbose (click.echo); redirect that progress to
# stderr so command substitution captures only the numeric count.
TARGET_PYTHON_STDIN_ARGS=(-)
if [[ "${BRIDGE_PHASE1}" -ne 1 ]]; then
    TARGET_PYTHON_STDIN_ARGS=(-I -B -)
fi
MIGRATION_FAILED=0
UPGRADE_RECEIPT_FAILURE_CODE="migration_failed"
if ! MIGRATION_COUNT=$(MIGRATION_FROM_VERSION="${CURRENT_VERSION}" \
    MIGRATION_TO_VERSION="${RELEASE_VERSION}" \
    MIGRATION_OPENCLAW_HOME="${OPENCLAW_HOME}" \
    MIGRATION_DEFENSECLAW_HOME="${DATA_DIR}" \
    DEFENSECLAW_HOME="${DATA_DIR}" \
    DEFENSECLAW_CONFIG="${CONFIG_PATH}" \
    OPENCLAW_HOME="${OPENCLAW_HOME}" \
    DEFENSECLAW_UPGRADE_MUTATION_TOKEN="${BRIDGE_RECOVERY_PLAN_ID#phase-one-}" \
    "${VENV_PYTHON}" "${TARGET_PYTHON_STDIN_ARGS[@]}" "${UPGRADE_RECEIPT_PATH}" <<'PY'
import contextlib
import os
from pathlib import Path
import sys

from defenseclaw.migrations import run_migrations

receipt_path = sys.argv[1]
kwargs = {"upgrade_handles_local_bundle": True} if receipt_path else {}
if receipt_path:
    from defenseclaw.upgrade_receipt import delegate_prior_upgrade_receipts

    delegate_prior_upgrade_receipts(Path(receipt_path))
with contextlib.redirect_stdout(sys.stderr):
    count = run_migrations(
        os.environ["MIGRATION_FROM_VERSION"],
        os.environ["MIGRATION_TO_VERSION"],
        os.environ["MIGRATION_OPENCLAW_HOME"],
        os.environ["MIGRATION_DEFENSECLAW_HOME"],
        **kwargs,
    )
if receipt_path:
    from defenseclaw.upgrade_receipt import record_upgrade_migrations

    record_upgrade_migrations(
        Path(receipt_path),
        migration_count=count,
        degraded=False,
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
        MIGRATION_DEFENSECLAW_HOME="${DATA_DIR}" \
        DEFENSECLAW_HOME="${DATA_DIR}" \
        DEFENSECLAW_CONFIG="${CONFIG_PATH}" \
        DEFENSECLAW_UPGRADE_MUTATION_TOKEN="${BRIDGE_RECOVERY_PLAN_ID#phase-one-}" \
        "${VENV_PYTHON}" "${TARGET_PYTHON_STDIN_ARGS[@]}" "${UPGRADE_MANIFEST_FILE}" <<'PY'
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

UPGRADE_RECEIPT_FAILURE_CODE="required_migration_failed"

if [[ "${MIGRATION_FAILURE_POLICY}" == "fail" && "${MIGRATION_FAILED}" -eq 1 ]]; then
    UPGRADE_INCOMPLETE=1
fi

if version_gte "${RELEASE_VERSION}" "0.8.4" && [[ "${MIGRATION_FAILED}" -eq 1 ]]; then
    UPGRADE_INCOMPLETE=1
fi

if [[ "${UPGRADE_INCOMPLETE}" -eq 1 ]]; then
    section "Upgrade Incomplete"
    if [[ "${BRIDGE_PHASE1}" -eq 1 ]]; then
        warn "Bridge ${RELEASE_VERSION} did not complete its migration contract; the source will be restored automatically."
    else
        warn "Release ${RELEASE_VERSION} did not complete its migration contract. Target services remain stopped."
    fi
    printf "\n"
    printf "  Backup saved to: ${DIM}${BACKUP_DIR}${NC}\n"
    info "Run: defenseclaw migrations status"
    info "Then re-run the staged upgrade after resolving the reported failure"
    printf "\n"
    exit 1
fi

if [[ "${BRIDGE_PHASE1}" -eq 1 ]]; then
    restore_bridge_config_comments
    bridge_phase1_cleanup_owned_temporaries \
        || die "Could not remove resolver-owned mutation temporaries before sealing bridge state"
    bridge_phase1_state_transaction seal-active \
        || die "Could not durably bind the exact post-migration bridge state; the source will be restored."
fi

# ── Start services ────────────────────────────────────────────────────────────

section "Starting Services"

UPGRADE_RECEIPT_FAILURE_CODE="startup_failed"
step "Starting defenseclaw-gateway ..."
DEFENSECLAW_HOME="${DATA_DIR}" DEFENSECLAW_CONFIG="${CONFIG_PATH}" \
    OPENCLAW_HOME="${OPENCLAW_HOME}" \
    "${INSTALL_DIR}/defenseclaw-gateway" start 9>&- \
    && ok "Gateway started" \
    || die "Could not start gateway; upgrade failed and no success receipt will be emitted"

step "Restarting OpenClaw gateway ..."
OPENCLAW_HOME="${OPENCLAW_HOME}" openclaw gateway restart 9>&- 2>/dev/null \
    && ok "OpenClaw gateway restarted" \
    || warn "Could not restart OpenClaw gateway automatically. Run: openclaw gateway restart"

# ── Health verification ───────────────────────────────────────────────────────

UPGRADE_RECEIPT_FAILURE_CODE="health_check_failed"
section "Verifying Gateway Health"

HEALTH_TIMEOUT=60
HEALTH_INTERVAL=2
ELAPSED=0
HEALTH_OK=0
HEALTH_URL="$(DEFENSECLAW_HOME="${DATA_DIR}" DEFENSECLAW_CONFIG="${CONFIG_PATH}" \
    OPENCLAW_HOME="${OPENCLAW_HOME}" \
    "${VENV_PYTHON}" "${TARGET_PYTHON_STDIN_ARGS[@]}" <<'PY' 2>/dev/null || true
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
HEALTH_RESPONSE_FILE="${STAGING_DIR}/gateway-health.json"
while [[ "${ELAPSED}" -lt "${HEALTH_TIMEOUT}" ]]; do
    HTTP_CODE=$(DEFENSECLAW_HOME="${DATA_DIR}" \
        DEFENSECLAW_CONFIG="${CONFIG_PATH}" \
        OPENCLAW_HOME="${OPENCLAW_HOME}" \
        curl -s -o "${HEALTH_RESPONSE_FILE}" -w "%{http_code}" "${HEALTH_URL}" 2>/dev/null || echo "000")
    STATUS=$(cat "${HEALTH_RESPONSE_FILE}" 2>/dev/null || echo "")
    rm -f "${HEALTH_RESPONSE_FILE}"

    if [[ "${HTTP_CODE}" == "200" && -n "${STATUS}" ]]; then
        HEALTH_FIELDS="$(printf '%s' "${STATUS}" | python3 -c '
import json
import sys

try:
    payload = json.load(sys.stdin)
except (TypeError, ValueError):
    print("unknown\tmissing")
    raise SystemExit
gateway = payload.get("gateway")
provenance = payload.get("provenance")
state = gateway.get("state", "unknown") if isinstance(gateway, dict) else "unknown"
version = provenance.get("binary_version", "missing") if isinstance(provenance, dict) else "missing"
if not isinstance(state, str):
    state = "unknown"
if not isinstance(version, str) or not version:
    version = "missing"
print(f"{state}\t{version}")
' 2>/dev/null || printf 'unknown\tmissing')"
        GW_STATE="${HEALTH_FIELDS%%$'\t'*}"
        GW_VERSION="${HEALTH_FIELDS#*$'\t'}"
    else
        GW_STATE="unreachable"
        GW_VERSION="missing"
    fi

    if [[ "${GW_STATE}" != "${LAST_STATE}" ]]; then
        info "    gateway: ${GW_STATE}"
        LAST_STATE="${GW_STATE}"
    fi

    if [[ ( "${GW_STATE}" == "running" || "${GW_STATE}" == "disabled" ) \
          && "${GW_VERSION}" != "${RELEASE_VERSION}" ]]; then
        info "    gateway version: ${GW_VERSION} (expected ${RELEASE_VERSION})"
    fi

    if [[ ( "${GW_STATE}" == "running" || "${GW_STATE}" == "disabled" ) \
          && "${GW_VERSION}" == "${RELEASE_VERSION}" ]]; then
        if [[ "${GW_STATE}" == "disabled" ]]; then
            ok "Gateway API is healthy; fleet uplink is disabled by configuration"
        else
            ok "Gateway is healthy"
        fi
        HEALTH_OK=1
        break
    fi
    sleep "${HEALTH_INTERVAL}"
    ELAPSED=$((ELAPSED + HEALTH_INTERVAL))
done

if [[ "${HEALTH_OK}" -eq 0 ]]; then
    err "Gateway did not become healthy within ${HEALTH_TIMEOUT}s"
    info "Check ${DATA_DIR}/gateway.log (process log); gateway.jsonl exists only when an optional JSONL destination is configured"
    info "Run:  defenseclaw-gateway status"
    exit 1
fi

if [[ -n "${UPGRADE_RECEIPT_PATH}" ]]; then
    # Target health is already proven. If the final receipt write itself
    # fails, preserve the pending recovery authority instead of letting the
    # exit trap rewrite this healthy attempt as a failed upgrade.
    UPGRADE_RECEIPT_TERMINAL=1
    finish_release_upgrade_receipt succeeded \
        || die "Could not commit the successful upgrade receipt after target health verification."
    ok "Successful upgrade receipt committed"
fi

if [[ "${BRIDGE_PHASE1}" -eq 1 \
      && "${DEFENSECLAW_TEST_PHASE1_POST_HEALTH_CRASH:-}" == "after-health" ]]; then
    kill -KILL "$$"
fi

if [[ "${BRIDGE_PHASE1}" -eq 1 ]]; then
    # A provenance-checked, healthy 0.8.4 is itself a safe recovery point.
    # Later handoff preparation failures leave that bridge running for retry.
    bridge_phase1_cleanup_owned_temporaries \
        || die "Could not remove resolver-owned bridge mutation temporaries before closing phase-one recovery"
    bridge_phase1_state_transaction fsync-active \
        || die "Could not durably flush the healthy bridge state before closing phase-one recovery"
    complete_bridge_phase1_recovery_journal "${BRIDGE_RECOVERY_PLAN_ID}" \
        || die "Could not durably close phase-one recovery after bridge health verification"
    BRIDGE_ROLLBACK_ARMED=0
fi

# ── Done ──────────────────────────────────────────────────────────────────────

if [[ -n "${STAGED_FINAL_VERSION}" ]]; then
    section "Bridge Verified"
    ok "${RELEASE_VERSION} is healthy; handing off to its freshly installed controller"
    final_version="${STAGED_FINAL_VERSION}"
    bridge_backup="${BACKUP_DIR}"
    handoff_dir="${bridge_backup}/staged-handoff"
    create_bridge_handoff_directory "${handoff_dir}" >/dev/null
    prepare_hard_cut_target_controller
    verify_hard_cut_target_controller_handoff \
        "${RELEASE_VERSION}" "${final_version}" "${handoff_dir}" \
        || die "Fresh target-controller handoff verification failed; the healthy bridge was preserved."
    export DEFENSECLAW_STAGED_UPGRADE=1
    export DEFENSECLAW_STAGED_BRIDGE_VERSION="${RELEASE_VERSION}"
    export DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR="${handoff_dir}"
    export DEFENSECLAW_STAGED_TARGET_CONTROLLER_VERSION="${final_version}"
    export DEFENSECLAW_HOME="${CONTROLLER_HOME}"
    export DEFENSECLAW_CONFIG="${CONFIG_PATH}"
    export OPENCLAW_HOME="${OPENCLAW_HOME}"
    target_status=0
    env -u UV_OVERRIDE \
        UV_CONSTRAINT="${HISTORICAL_BOOTSTRAP_CONSTRAINTS_FILE}" \
        UV_EXCLUDE_NEWER="${HISTORICAL_BOOTSTRAP_EXCLUDE_NEWER}" \
        "${TARGET_CONTROLLER_CLI}" upgrade --yes --version "${final_version}" \
        || target_status=$?
    if [[ "${target_status}" -eq 0 ]]; then
        continue_post_hard_cut_upgrade
    fi
    exit "${target_status}"
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
# DefenseClaw upgrade resolver complete v1
