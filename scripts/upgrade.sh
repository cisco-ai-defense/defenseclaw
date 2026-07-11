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
#   --version VERSION     Upgrade to a specific release (default: latest)
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

readonly DEFENSECLAW_HOME="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
readonly DEFENSECLAW_VENV="${DEFENSECLAW_HOME}/.venv"
readonly INSTALL_DIR="${HOME}/.local/bin"
readonly OPENCLAW_HOME="${OPENCLAW_HOME:-${HOME}/.openclaw}"
readonly BACKUP_ROOT="${DEFENSECLAW_HOME}/backups"
readonly REPO="cisco-ai-defense/defenseclaw"
readonly UPGRADE_PROTOCOL_VERSION=2
readonly UPGRADE_MANIFEST_NAME="upgrade-manifest.json"
readonly UPGRADE_RECOVERY_ROOT="${DEFENSECLAW_HOME}/.upgrade-recovery"
readonly UPGRADE_LOCK_FILE="${UPGRADE_RECOVERY_ROOT}/upgrade.lock"
readonly UPGRADE_ADVISORY_LOCK_FILE="${UPGRADE_RECOVERY_ROOT}/upgrade.advisory.lock"
UPGRADE_LOCK_TOKEN=""
UPGRADE_ADVISORY_LOCK_HELD=0

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

recover_interrupted_phase_two() {
    local journal_root="${DEFENSECLAW_HOME}/.upgrade-recovery"
    local journal="${journal_root}/phase-two-active.json"
    [[ -e "${journal}" || -L "${journal}" ]] || return 0
    [[ "${PLAN_ONLY}" -eq 0 ]] \
        || die "An interrupted hard-cut recovery is active. Re-run without --plan so the authenticated 0.8.4 bridge can be restored first."

    section "Recovering Interrupted Hard-Cut Upgrade"
    local recovery_fields wheel expected_digest receipt_status uv_bin venv_python
    recovery_fields="$(python3 - "${journal}" "${DEFENSECLAW_HOME}" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import stat
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
    "schema_version", "source_version", "target_version", "os_name", "data_dir",
    "backup_dir", "receipt_path", "rollback_wheel_path", "rollback_wheel_sha256",
    "rollback_gateway_path", "rollback_gateway_sha256", "active_gateway_path",
    "gateway_snapshot", "state_files",
}
if not isinstance(document, dict) or set(document) != required or document.get("schema_version") != 1:
    raise SystemExit("phase-two recovery journal schema is invalid")
semver = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
source = document.get("source_version")
target = document.get("target_version")
data_dir = document.get("data_dir")
backup_dir = document.get("backup_dir")
receipt_path = document.get("receipt_path")
wheel = document.get("rollback_wheel_path")
digest = document.get("rollback_wheel_sha256")
values = (source, target, data_dir, backup_dir, receipt_path, wheel, digest)
if not all(isinstance(value, str) and value and "\n" not in value and "\r" not in value for value in values):
    raise SystemExit("phase-two recovery journal contains invalid scalar values")
if not semver.fullmatch(source) or not semver.fullmatch(target) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
    raise SystemExit("phase-two recovery journal contains invalid identities")
data_dir = Path(os.path.abspath(os.path.expanduser(data_dir)))
backup_dir = Path(os.path.abspath(os.path.expanduser(backup_dir)))
receipt_path = Path(os.path.abspath(os.path.expanduser(receipt_path)))
wheel = Path(os.path.abspath(os.path.expanduser(wheel)))
if backup_dir.parent != data_dir / "backups":
    raise SystemExit("phase-two recovery backup escaped the managed backup root")
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
status = receipt.get("status")
if status in {"succeeded", "rolled_back"}:
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
PY
)" || die "Could not validate the interrupted phase-two recovery journal; no recovery mutation was attempted."

    wheel="$(printf '%s\n' "${recovery_fields}" | sed -n '1p')"
    if [[ "${wheel}" == "terminal" ]]; then
        ok "Removed a stale terminal phase-two recovery journal"
        return 0
    fi
    expected_digest="$(printf '%s\n' "${recovery_fields}" | sed -n '2p')"
    receipt_status="$(printf '%s\n' "${recovery_fields}" | sed -n '3p')"
    [[ "${receipt_status}" == "pending" && -n "${wheel}" && -n "${expected_digest}" ]] \
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
        subprocess.run(
            [str(uv), "--no-config", "venv", "--clear", str(venv), "--python", "3.12"],
            check=True,
            pass_fds=(descriptor,),
        )
    subprocess.run(
        [
            str(uv), "--no-config", "pip", "install", "--python",
            str(venv_python), "--quiet", "--reinstall", str(wheel),
        ],
        check=True,
        pass_fds=(descriptor,),
    )
finally:
    os.close(descriptor)
PY
    DEFENSECLAW_HOME="${DEFENSECLAW_HOME}" "${venv_python}" -I -c \
        'from defenseclaw.commands.cmd_upgrade import _recover_interrupted_hard_cut; raise SystemExit(0 if _recover_interrupted_hard_cut() else 1)' \
        || die "The retained 0.8.4 controller could not complete interrupted hard-cut recovery."
    ok "Interrupted phase two rolled back to a healthy authenticated bridge"
}

acquire_upgrade_lock() {
    UPGRADE_LOCK_TOKEN="$(python3 - "${DEFENSECLAW_HOME}" "${UPGRADE_RECOVERY_ROOT}" "${UPGRADE_LOCK_FILE}" "$$" <<'PY'
import hashlib
import json
import os
import secrets
import stat
import sys
import time

data_home, recovery_root, lock_path, shell_pid_raw = sys.argv[1:]
shell_pid = int(shell_pid_raw)
uid = os.geteuid()


def require_private_directory(path: str, *, create: bool = False) -> None:
    if create:
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise RuntimeError(f"upgrade recovery path is not a real directory: {path}")
    if info.st_uid != uid or stat.S_IMODE(info.st_mode) & 0o077:
        raise RuntimeError(f"upgrade recovery path is not private to the current user: {path}")


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
require_private_directory(recovery_root, create=True)

token = secrets.token_hex(32)
payload = json.dumps(
    {"schema_version": 1, "pid": shell_pid, "token": token},
    sort_keys=True,
    separators=(",", ":"),
).encode() + b"\n"

for _attempt in range(4):
    try:
        descriptor = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        try:
            info = os.lstat(lock_path)
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise RuntimeError("upgrade lock is not a real file")
            if info.st_uid != uid or stat.S_IMODE(info.st_mode) & 0o077:
                raise RuntimeError("upgrade lock is not private to the current user")
            with open(lock_path, "rb") as stream:
                raw = stream.read(4097)
            if len(raw) > 4096:
                raise RuntimeError("upgrade lock is too large")
            current = json.loads(raw)
            pid = current.get("pid")
            current_token = current.get("token")
            if (
                current.get("schema_version") != 1
                or not isinstance(pid, int)
                or isinstance(pid, bool)
                or pid < 1
                or not isinstance(current_token, str)
                or len(current_token) != 64
            ):
                raise ValueError("invalid upgrade lock")
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            # A claimant may be between O_EXCL and fsync. Never steal a fresh
            # partial claim; an abandoned partial file becomes recoverable
            # after the short initialization window.
            if time.time() - os.lstat(lock_path).st_mtime < 10:
                raise RuntimeError("another upgrade is acquiring the recovery lock") from exc
            pid = 0

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
        if live:
            raise RuntimeError(f"another DefenseClaw upgrade is active (pid {pid})")

        quarantine = f"{lock_path}.stale-{secrets.token_hex(16)}"
        try:
            os.rename(lock_path, quarantine)
        except FileNotFoundError:
            continue
        try:
            os.unlink(quarantine)
        finally:
            directory_fd = os.open(recovery_root, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        continue

    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        info = os.lstat(lock_path)
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise RuntimeError("created upgrade lock is not a real file")
        if info.st_uid != uid or stat.S_IMODE(info.st_mode) & 0o077:
            raise RuntimeError("created upgrade lock is not private")
        directory_fd = os.open(recovery_root, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            os.unlink(lock_path)
        except OSError:
            pass
        raise
    print(token)
    break
else:
    raise RuntimeError("could not acquire the DefenseClaw upgrade lock")
PY
)" || die "Could not acquire the private upgrade lock. No installed state changed."

    # Keep a kernel lock on a stable inode in addition to the diagnostic PID
    # record above. Descriptor 9 is inherited by external children, so killing
    # only this shell cannot let a retry race an in-flight uv/copy helper. The
    # kernel releases it only after the last surviving process closes the
    # shared open-file description (or after a reboot kills the whole tree).
    exec 9>>"${UPGRADE_ADVISORY_LOCK_FILE}"
    if ! python3 - "${UPGRADE_ADVISORY_LOCK_FILE}" 9 <<'PY'
import fcntl
import os
import stat
import sys

path, descriptor_raw = sys.argv[1:]
descriptor = int(descriptor_raw)
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
try:
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError as exc:
    raise RuntimeError("a surviving upgrade process still holds the mutation lease") from exc
PY
    then
        exec 9>&-
        release_upgrade_lock
        die "Another upgrade process or surviving mutation child is still active. No installed state changed."
    fi
    UPGRADE_ADVISORY_LOCK_HELD=1
}

release_upgrade_lock() {
    if [[ "${UPGRADE_ADVISORY_LOCK_HELD:-0}" -eq 1 ]]; then
        exec 9>&-
        UPGRADE_ADVISORY_LOCK_HELD=0
    fi
    [[ -n "${UPGRADE_LOCK_TOKEN:-}" ]] || return 0
    python3 - "${UPGRADE_RECOVERY_ROOT}" "${UPGRADE_LOCK_FILE}" "${UPGRADE_LOCK_TOKEN}" <<'PY' >/dev/null 2>&1 || true
import json
import os
import secrets
import stat
import sys

root, lock_path, expected_token = sys.argv[1:]
info = os.lstat(lock_path)
if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
    raise SystemExit(1)
with open(lock_path, "rb") as stream:
    payload = json.load(stream)
if payload.get("schema_version") != 1 or payload.get("token") != expected_token:
    raise SystemExit(1)
quarantine = f"{lock_path}.released-{secrets.token_hex(16)}"
os.rename(lock_path, quarantine)
os.unlink(quarantine)
directory_fd = os.open(root, os.O_RDONLY)
try:
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
PY
    UPGRADE_LOCK_TOKEN=""
}

register_bridge_phase1_recovery_journal() {
    BRIDGE_RECOVERY_PLAN_ID="$(python3 - \
        "${DEFENSECLAW_HOME}" \
        "${OPENCLAW_HOME}" \
        "${BACKUP_ROOT}" \
        "${BACKUP_DIR}" \
        "${UPGRADE_RECOVERY_ROOT}" \
        "${CURRENT_VERSION}" \
        "${BRIDGE_SOURCE_WAS_RUNNING}" \
        "${BRIDGE_SOURCE_HEALTH_URL}" \
        "${DEFENSECLAW_CONFIG:-}" <<'PY'
import hashlib
import json
import os
import secrets
import stat
import sys
from urllib.parse import urlsplit

(
    data_home,
    openclaw_home,
    backup_root,
    backup_dir,
    recovery_root,
    source_version,
    source_was_running_raw,
    source_health_url,
    config_override,
) = sys.argv[1:]
uid = os.geteuid()


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


data_home = os.path.abspath(os.path.expanduser(data_home))
openclaw_home = os.path.abspath(os.path.expanduser(openclaw_home))
backup_root = os.path.abspath(backup_root)
backup_dir = os.path.abspath(backup_dir)
recovery_root = os.path.abspath(recovery_root)
config_override = os.path.abspath(os.path.expanduser(config_override)) if config_override else ""
require_directory(data_home, private=False)
require_directory(recovery_root, private=True)
require_directory(backup_root, private=True)
require_directory(backup_dir, private=True)
if os.path.dirname(backup_dir) != backup_root:
    raise RuntimeError("phase-one backup escaped the private backup root")
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
gateway_descriptor = os.open(gateway, os.O_RDONLY)
try:
    os.fsync(gateway_descriptor)
finally:
    os.close(gateway_descriptor)
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
    "schema_version": 1,
    "kind": "defenseclaw-phase-one-recovery",
    "plan_id": plan_id,
    "source_version": source_version,
    "source_was_running": source_was_running_raw == "1",
    "source_health_url": source_health_url,
    "backup_directory": backup_name,
    "gateway_sha256": digest(gateway),
    "state_snapshot_ready": False,
    "state_manifest_sha256": None,
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
    payload.get("schema_version") != 1
    or payload.get("kind") != "defenseclaw-phase-one-recovery"
    or payload.get("plan_id") != expected_plan_id
    or payload.get("state_snapshot_ready") is not False
    or payload.get("state_manifest_sha256") is not None
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

complete_bridge_phase1_recovery_journal() {
    local expected_plan_id="$1"
    python3 - "${UPGRADE_RECOVERY_ROOT}" "${expected_plan_id}" <<'PY'
import json
import os
import secrets
import stat
import sys

root, expected_plan_id = sys.argv[1:]
journal = os.path.join(root, "phase-one-active.json")
info = os.lstat(journal)
if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
    raise RuntimeError("phase-one recovery journal is not a real file")
with open(journal, "rb") as stream:
    payload = json.load(stream)
if (
    payload.get("schema_version") != 1
    or payload.get("kind") != "defenseclaw-phase-one-recovery"
    or payload.get("plan_id") != expected_plan_id
):
    raise RuntimeError("refusing to clear a different phase-one recovery journal")
quarantine = os.path.join(root, f".{expected_plan_id}.complete-{secrets.token_hex(16)}")
os.rename(journal, quarantine)
os.unlink(quarantine)
descriptor = os.open(root, os.O_RDONLY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

recover_interrupted_bridge_phase1() {
    local journal="${UPGRADE_RECOVERY_ROOT}/phase-one-active.json"
    [[ -e "${journal}" || -L "${journal}" ]] || return 0
    if [[ "${PLAN_ONLY}" -eq 1 ]]; then
        die "An interrupted phase-one upgrade requires recovery. Re-run without --plan; no new upgrade changes were made."
    fi

    section "Recovering Interrupted Bridge Upgrade"
    warn "Found durable phase-one recovery state; restoring the prior release before detecting installed versions."
    if ! python3 - \
        "${DEFENSECLAW_HOME}" \
        "${DEFENSECLAW_VENV}" \
        "${INSTALL_DIR}" \
        "${BACKUP_ROOT}" \
        "${UPGRADE_RECOVERY_ROOT}" <<'PY'
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

data_home, active_venv, install_dir, backup_root, recovery_root = map(os.path.abspath, sys.argv[1:])
journal = os.path.join(recovery_root, "phase-one-active.json")
uid = os.geteuid()


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


def command_version(command):
    completed = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
    match = re.search(r"(?<![\d.])(\d+\.\d+\.\d+)(?![\d.])", (completed.stdout or "") + (completed.stderr or ""))
    if completed.returncode != 0 or match is None:
        raise RuntimeError(f"could not verify restored command: {command[0]}")
    return match.group(1)


require_directory(data_home, private=False)
require_directory(recovery_root, private=True)
require_directory(backup_root, private=True)
require_file(journal, private=True)
if os.path.getsize(journal) > 64 * 1024:
    raise RuntimeError("phase-one recovery journal is too large")
with open(journal, "rb") as stream:
    payload = json.load(stream)
expected_keys = {
    "schema_version",
    "kind",
    "plan_id",
    "source_version",
    "source_was_running",
    "source_health_url",
    "backup_directory",
    "gateway_sha256",
    "state_snapshot_ready",
    "state_manifest_sha256",
    "openclaw_home",
    "config_override",
}
if set(payload) != expected_keys or payload.get("schema_version") != 1:
    raise RuntimeError("unsupported phase-one recovery journal")
if payload.get("kind") != "defenseclaw-phase-one-recovery":
    raise RuntimeError("invalid phase-one recovery journal kind")
plan_id = payload.get("plan_id")
source_version = payload.get("source_version")
backup_name = payload.get("backup_directory")
source_was_running = payload.get("source_was_running")
source_health_url = payload.get("source_health_url")
state_snapshot_ready = payload.get("state_snapshot_ready")
if not isinstance(plan_id, str) or re.fullmatch(r"phase-one-[0-9a-f]{32}", plan_id) is None:
    raise RuntimeError("invalid phase-one recovery plan identifier")
if not isinstance(source_version, str) or re.fullmatch(r"\d+\.\d+\.\d+", source_version) is None:
    raise RuntimeError("invalid phase-one recovery source version")
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
if not isinstance(payload.get("gateway_sha256"), str) or re.fullmatch(r"[0-9a-f]{64}", payload["gateway_sha256"]) is None:
    raise RuntimeError("invalid phase-one gateway digest")
if state_snapshot_ready:
    if not isinstance(payload.get("state_manifest_sha256"), str) or re.fullmatch(r"[0-9a-f]{64}", payload["state_manifest_sha256"]) is None:
        raise RuntimeError("invalid phase-one state manifest digest")
elif payload.get("state_manifest_sha256") is not None:
    raise RuntimeError("unsealed phase-one state has an unexpected digest")
openclaw_home = payload.get("openclaw_home")
config_override = payload.get("config_override")
if not isinstance(openclaw_home, str) or not os.path.isabs(openclaw_home):
    raise RuntimeError("invalid phase-one OpenClaw home")
if config_override is not None and (not isinstance(config_override, str) or not os.path.isabs(config_override)):
    raise RuntimeError("invalid phase-one config override")

backup_dir = os.path.join(backup_root, backup_name)
if os.path.dirname(backup_dir) != backup_root:
    raise RuntimeError("phase-one recovery backup escaped the private root")
require_directory(backup_dir, private=True)
source_gateway = os.path.join(backup_dir, "phase1-source-gateway")
state_root = os.path.join(backup_dir, "phase1-state")
state_manifest = os.path.join(state_root, "manifest.json")
require_file(source_gateway)
if digest(source_gateway) != payload["gateway_sha256"]:
    raise RuntimeError("phase-one source gateway custody digest changed")
if state_snapshot_ready:
    require_directory(state_root, private=True)
    require_file(state_manifest, private=True)
    if digest(state_manifest) != payload["state_manifest_sha256"]:
        raise RuntimeError("phase-one state manifest custody digest changed")

active_gateway = os.path.join(install_dir, "defenseclaw-gateway")
pid_path = os.path.join(data_home, "gateway.pid")
if os.path.isfile(active_gateway) and not os.path.islink(active_gateway):
    subprocess.run([active_gateway, "stop"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20, check=False)
for _attempt in range(6):
    if not os.path.lexists(pid_path):
        break
    require_file(pid_path)
    with open(pid_path, encoding="utf-8") as stream:
        pid_raw = stream.read(64).strip()
    if re.fullmatch(r"[1-9]\d*", pid_raw) is None:
        raise RuntimeError("gateway PID custody is malformed during recovery")
    try:
        os.kill(int(pid_raw), 0)
    except ProcessLookupError:
        break
    except PermissionError as exc:
        raise RuntimeError("gateway process ownership cannot be verified during recovery") from exc
    time.sleep(1)
else:
    raise RuntimeError("gateway did not quiesce during phase-one recovery")

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
    if os.path.lexists(active_venv):
        require_directory(active_venv, private=False)
        shutil.rmtree(active_venv)
        fsync_directory(data_home)
    os.rename(source_venv, active_venv)
    fsync_directory(data_home)
    fsync_directory(backup_dir)
else:
    require_directory(active_venv, private=False)

os.makedirs(install_dir, mode=0o700, exist_ok=True)
gateway_mode = stat.S_IMODE(os.lstat(source_gateway).st_mode)
gateway_candidate = os.path.join(install_dir, f".defenseclaw-gateway.phase-one-{plan_id}")
try:
    descriptor = os.open(gateway_candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, gateway_mode)
except FileExistsError:
    os.unlink(gateway_candidate)
    descriptor = os.open(gateway_candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, gateway_mode)
try:
    with open(source_gateway, "rb") as source, os.fdopen(descriptor, "wb", closefd=True) as destination:
        shutil.copyfileobj(source, destination)
        destination.flush()
        os.fsync(destination.fileno())
    os.chmod(gateway_candidate, gateway_mode)
    if digest(gateway_candidate) != payload["gateway_sha256"]:
        raise RuntimeError("staged phase-one gateway digest mismatch")
    os.replace(gateway_candidate, active_gateway)
    fsync_directory(install_dir)
finally:
    if os.path.lexists(gateway_candidate):
        os.unlink(gateway_candidate)

def restore_state_snapshot() -> None:
    if os.path.getsize(state_manifest) > 4 * 1024 * 1024:
        raise RuntimeError("phase-one state manifest is too large")
    with open(state_manifest, encoding="utf-8") as stream:
        state = json.load(stream)
    if state.get("schema") != 1 or not isinstance(state.get("entries"), list):
        raise RuntimeError("unsupported phase-one state snapshot")
    data_names = (
        "config.yaml",
        ".env",
        ".migration_state.json",
        "guardrail_runtime.json",
        "device.key",
        "active_connector.json",
        "codex_backup.json",
        "claudecode_backup.json",
        "zeptoclaw_backup.json",
        "codex_config_backup.json",
        "codex_env.sh",
        "codex.env",
        "policies",
        "connector_backups",
        ".upgrade-shims",
    )
    expected_targets = [os.path.join(data_home, name) for name in data_names]
    expected_targets.extend(
        os.path.join(openclaw_home, name)
        for name in ("openclaw.json", "openclaw.json.pre-0.3.0-migration")
    )
    if config_override and config_override not in expected_targets:
        expected_targets.append(config_override)
    entries = state["entries"]
    if [entry.get("target") for entry in entries if isinstance(entry, dict)] != expected_targets:
        raise RuntimeError("phase-one state target set changed")
    for entry in entries:
        if not entry.get("existed"):
            continue
        backup_name = entry.get("backup")
        inventory = entry.get("inventory")
        if (
            not isinstance(backup_name, str)
            or re.fullmatch(r"item-\d+", backup_name) is None
            or not isinstance(inventory, list)
        ):
            raise RuntimeError("invalid phase-one state backup inventory")
        backup = os.path.join(state_root, backup_name)
        if path_inventory(backup) != inventory:
            raise RuntimeError(f"phase-one state backup changed for {entry['target']}")
    for entry in entries:
        target = entry["target"]
        remove_path(target)
        if not entry.get("existed"):
            continue
        backup_name = entry.get("backup")
        if not isinstance(backup_name, str) or re.fullmatch(r"item-\d+", backup_name) is None:
            raise RuntimeError("invalid phase-one state backup name")
        backup = os.path.join(state_root, backup_name)
        parent = os.path.dirname(target)
        os.makedirs(parent, mode=0o700, exist_ok=True)
        restored_kind = copy_path(backup, target)
        if restored_kind != entry.get("kind"):
            raise RuntimeError(f"phase-one state type mismatch while restoring {target}")
        if path_inventory(target) != entry["inventory"]:
            raise RuntimeError(f"phase-one state bytes or modes changed while restoring {target}")
        fsync_path_tree(target)
    for entry in entries:
        fsync_directory(os.path.dirname(entry["target"]))
    for root, mode in state.get("root_modes", {}).items():
        if root not in (data_home, openclaw_home):
            raise RuntimeError("phase-one state contains an unexpected root mode")
        if mode is not None and os.path.isdir(root) and not os.path.islink(root):
            os.chmod(root, mode)
    fsync_directory(data_home)
    if os.path.isdir(openclaw_home) and not os.path.islink(openclaw_home):
        fsync_directory(openclaw_home)


if state_snapshot_ready:
    restore_state_snapshot()

cli_path = os.path.join(active_venv, "bin", "defenseclaw")
python_path = os.path.join(active_venv, "bin", "python")
if command_version([cli_path, "--version"]) != source_version:
    raise RuntimeError("restored phase-one CLI version mismatch")
if command_version([active_gateway, "--version"]) != source_version:
    raise RuntimeError("restored phase-one gateway version mismatch")

environment = os.environ.copy()
environment["DEFENSECLAW_HOME"] = data_home
environment["OPENCLAW_HOME"] = openclaw_home
if config_override:
    environment["DEFENSECLAW_CONFIG"] = config_override
else:
    environment.pop("DEFENSECLAW_CONFIG", None)
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
                and gateway.get("state") == "running"
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

with open(journal, "rb") as stream:
    current = json.load(stream)
if current.get("plan_id") != plan_id:
    raise RuntimeError("phase-one recovery journal changed during restoration")
os.unlink(journal)
fsync_directory(recovery_root)
print(source_version)
PY
    then
        die "Interrupted phase-one recovery is incomplete. Private custody was preserved; no new upgrade was started."
    fi
    ok "Recovered the interrupted source release and verified its prior running state"
}

ensure_upgrade_lock_before_mutation() {
    local observed_version="unknown"
    if [[ -z "${UPGRADE_LOCK_TOKEN:-}" ]]; then
        acquire_upgrade_lock
    fi
    recover_interrupted_phase_two
    recover_interrupted_bridge_phase1
    if has defenseclaw; then
        observed_version="$(defenseclaw --version 2>/dev/null \
            | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 \
            || python3 -c "from defenseclaw import __version__; print(__version__)" 2>/dev/null \
            || echo "unknown")"
    fi
    observed_version="${observed_version:-unknown}"
    if [[ "${observed_version}" != "${CURRENT_VERSION}" ]]; then
        die "Installed version changed while the upgrade was being prepared (${CURRENT_VERSION} → ${observed_version}). No services were stopped; re-run the upgrade."
    fi
}

# ── Argument Parsing ──────────────────────────────────────────────────────────

YES=0
PLAN_ONLY=0
RELEASE_VERSION="${VERSION:-}"
TARGET_VERSION_EXPLICIT=0
[[ -n "${RELEASE_VERSION}" ]] && TARGET_VERSION_EXPLICIT=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes|-y)   YES=1; shift ;;
        --plan)     PLAN_ONLY=1; shift ;;
        --version)
            [[ $# -lt 2 ]] && die "--version requires a value"
            RELEASE_VERSION="$2"; TARGET_VERSION_EXPLICIT=1; shift 2 ;;
        --help|-h)
            cat <<EOF

  DefenseClaw Upgrade Script

  Usage: $(basename "$0") [OPTIONS]

  Options:
    --yes, -y             Skip confirmation prompts
    --version VERSION     Upgrade to a specific release (e.g. 0.2.0)
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
FRESH_HARD_CUT_HANDOFF=0

# ── Detect currently installed version ───────────────────────────────────────

CURRENT_VERSION="unknown"
if has defenseclaw; then
    CURRENT_VERSION="$(defenseclaw --version 2>/dev/null \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
fi
if [[ -z "${CURRENT_VERSION}" || "${CURRENT_VERSION}" == "unknown" ]] \
    && [[ -x "${DEFENSECLAW_VENV}/bin/python" ]]; then
    CURRENT_VERSION="$("${DEFENSECLAW_VENV}/bin/python" -I -c \
        'from defenseclaw import __version__; print(__version__)' 2>/dev/null \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
fi
CURRENT_VERSION="${CURRENT_VERSION:-unknown}"

ok "Installed version : ${CURRENT_VERSION}"
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

if [[ "${CURRENT_VERSION}" != "unknown" ]]; then
    validate_version "${CURRENT_VERSION}"
    if version_lt "${RELEASE_VERSION}" "${CURRENT_VERSION}"; then
        die "Refusing to downgrade ${CURRENT_VERSION} to ${RELEASE_VERSION} through the upgrade path. No changes were made."
    fi
fi

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

configure_release() {
    TARBALL_NAME="defenseclaw_${RELEASE_VERSION}_${OS}_${ARCH_NORM}.tar.gz"
    WHL_NAME="defenseclaw-${RELEASE_VERSION}-py3-none-any.whl"
    TARBALL_URL="https://github.com/${REPO}/releases/download/${RELEASE_VERSION}/${TARBALL_NAME}"
    WHL_URL="https://github.com/${REPO}/releases/download/${RELEASE_VERSION}/${WHL_NAME}"
    CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${RELEASE_VERSION}/checksums.txt"
    CHECKSUMS_SIG_URL="${CHECKSUMS_URL}.sig"
    CHECKSUMS_CERT_URL="${CHECKSUMS_URL}.pem"
    UPGRADE_MANIFEST_URL="https://github.com/${REPO}/releases/download/${RELEASE_VERSION}/${UPGRADE_MANIFEST_NAME}"
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
preflight_release_artifacts

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

upgrade_exit_trap() {
    local status=$?
    local rollback_status=0
    trap - EXIT
    set +e
    if [[ "${BRIDGE_ROLLBACK_ARMED:-0}" -eq 1 ]]; then
        rollback_bridge_phase1 || rollback_status=$?
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
ASSET_DIGESTS_FILE=""
UPGRADE_MANIFEST_FILE=""
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
    ASSET_DIGESTS_FILE=""
    UPGRADE_MANIFEST_FILE=""
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
    if ! command -v cosign >/dev/null 2>&1; then
        if version_gte "${RELEASE_VERSION}" "0.8.4"; then
            die "Release ${RELEASE_VERSION} requires Sigstore provenance verification, but cosign was not found on PATH. No changes were made.
  Install cosign and retry the upgrade."
        fi
        warn "checksums.txt Sigstore signature is present, but cosign was not found on PATH for this legacy release."
        return 0
    fi

    local cosign_output
    if ! cosign_output="$(cosign verify-blob \
        --certificate "${CHECKSUMS_CERT_FILE}" \
        --signature "${CHECKSUMS_SIG_FILE}" \
        --certificate-identity "https://github.com/${REPO}/.github/workflows/release.yaml@refs/heads/main" \
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
    manifest_array_values "${key}" "${path}" | grep -Fxq "${expected}"
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

    local schema_version release_version min_protocol policy
    local controller_protocol minimum_source required_bridge
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
    if [[ "${schema_version}" -ne 1 ]]; then
        warn "Release ${RELEASE_VERSION} uses upgrade manifest schema ${schema_version}, which this upgrader does not understand."
        print_new_upgrade_script_hint
        exit 1
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
    ok "Upgrade manifest loaded"
}

prepare_release_contract() {
    download_release_contract_files
    verify_checksums_sigstore
    load_upgrade_manifest
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
            FRESH_HARD_CUT_HANDOFF=1
            STAGED_FINAL_MIN_PROTOCOL="${MANIFEST_MIN_PROTOCOL}"
        fi
        return 0
    fi

    if [[ "${TARGET_VERSION_EXPLICIT}" -eq 1 ]]; then
        die "${RELEASE_VERSION} requires the ${MANIFEST_REQUIRED_BRIDGE} upgrade bridge. No changes were made.
  Run the release-owned updater without --version to complete the staged upgrade."
    fi
    if ! manifest_array_contains "auto_bridge_from" "${CURRENT_VERSION}" "${UPGRADE_MANIFEST_FILE}"; then
        supported="$(manifest_array_values "auto_bridge_from" "${UPGRADE_MANIFEST_FILE}" | paste -sd ',' - | sed 's/,/, /g')"
        die "Installed version ${CURRENT_VERSION} is outside the tested automatic bridge matrix. No changes were made.
  Supported staged sources: ${supported:-none}.
  Re-run this release-owned updater with --version ${MANIFEST_REQUIRED_BRIDGE}.
  After ${MANIFEST_REQUIRED_BRIDGE} is healthy, re-run it without --version to reach ${RELEASE_VERSION}."
    fi

    STAGED_FINAL_VERSION="${RELEASE_VERSION}"
    STAGED_FINAL_MIN_PROTOCOL="${MANIFEST_MIN_PROTOCOL}"
    RELEASE_VERSION="${MANIFEST_REQUIRED_BRIDGE}"
    section "Staged Upgrade Plan"
    ok "${CURRENT_VERSION} → ${RELEASE_VERSION} bridge → fresh controller → ${STAGED_FINAL_VERSION}"

    configure_release
    preflight_release_artifacts
    prepare_release_contract
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

bridge_phase1_state_transaction() {
    local operation="$1"
    local snapshot_root="${BACKUP_DIR}/phase1-state"
    python3 - \
        "${operation}" \
        "${DEFENSECLAW_HOME}" \
        "${OPENCLAW_HOME}" \
        "${snapshot_root}" \
        "${DEFENSECLAW_CONFIG:-}" <<'PY'
import hashlib
import json
import os
import shutil
import stat
import sys

operation, data_home, openclaw_home, snapshot_root, config_override = sys.argv[1:]
data_home = os.path.abspath(os.path.expanduser(data_home))
openclaw_home = os.path.abspath(os.path.expanduser(openclaw_home))
snapshot_root = os.path.abspath(snapshot_root)

data_names = (
    "config.yaml",
    ".env",
    ".migration_state.json",
    "guardrail_runtime.json",
    "device.key",
    "active_connector.json",
    "codex_backup.json",
    "claudecode_backup.json",
    "zeptoclaw_backup.json",
    "codex_config_backup.json",
    "codex_env.sh",
    "codex.env",
    "policies",
    "connector_backups",
    ".upgrade-shims",
)
targets = [os.path.join(data_home, name) for name in data_names]
targets.extend(
    os.path.join(openclaw_home, name)
    for name in ("openclaw.json", "openclaw.json.pre-0.3.0-migration")
)
if config_override:
    custom_config = os.path.abspath(os.path.expanduser(config_override))
    if custom_config not in targets:
        targets.append(custom_config)


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
elif operation in ("restore", "fsync-active"):
    if os.path.getsize(manifest_path) > 4 * 1024 * 1024:
        raise RuntimeError("phase-1 state snapshot manifest is too large")
    with open(manifest_path, encoding="utf-8") as manifest_file:
        manifest = json.load(manifest_file)
    if manifest.get("schema") != 1:
        raise RuntimeError("unsupported phase-1 state snapshot schema")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or [entry.get("target") for entry in entries] != targets:
        raise RuntimeError("phase-1 state snapshot target set changed")
    for entry in entries:
        if not entry.get("existed"):
            continue
        backup = os.path.join(snapshot_root, entry["backup"])
        inventory = entry.get("inventory")
        if not isinstance(inventory, list) or path_inventory(backup) != inventory:
            raise RuntimeError(f"phase-1 state backup changed for {entry['target']}")
    if operation == "restore":
        for entry in entries:
            target = entry["target"]
            remove_path(target)
            if not entry.get("existed"):
                continue
            parent = os.path.dirname(target)
            os.makedirs(parent, mode=0o700, exist_ok=True)
            backup = os.path.join(snapshot_root, entry["backup"])
            restored_kind = copy_path(backup, target)
            if restored_kind != entry.get("kind"):
                raise RuntimeError(f"phase-1 state type mismatch while restoring {target}")
            if path_inventory(target) != entry["inventory"]:
                raise RuntimeError(f"phase-1 state bytes or modes changed while restoring {target}")
            fsync_path_tree(target)
    else:
        for entry in entries:
            target = entry["target"]
            if os.path.lexists(target):
                fsync_path_tree(target)
    for entry in entries:
        fsync_directory(os.path.dirname(entry["target"]))
    for root, mode in manifest.get("root_modes", {}).items():
        if mode is not None and os.path.isdir(root) and not os.path.islink(root):
            if operation == "restore":
                os.chmod(root, mode)
            fsync_directory(root)
else:
    raise RuntimeError(f"unknown phase-1 state operation: {operation}")
PY
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

    BRIDGE_PYTHON_INTERPRETER="$(${DEFENSECLAW_VENV}/bin/python -c 'import os,sys; print(os.path.realpath(getattr(sys, "_base_executable", "") or sys.executable))')" \
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
    "${uv_bin}" --no-config venv "${preflight_venv}" --python "${BRIDGE_PYTHON_INTERPRETER}" --quiet \
        || die "Could not create the bridge CLI preflight environment; no services changed."
    "${uv_bin}" --no-config pip install --python "${preflight_venv}/bin/python" --quiet "${STAGING_DIR}/${whl_name}" \
        || die "Could not install the bridge CLI in its preflight environment; no services changed."
    preflight_version="$("${preflight_venv}/bin/python" -c 'from defenseclaw import __version__; print(__version__)')" \
        || die "Could not import the preflighted bridge CLI; no services changed."
    [[ "${preflight_version}" == "${RELEASE_VERSION}" ]] \
        || die "Bridge CLI preflight version mismatch: expected ${RELEASE_VERSION}, got ${preflight_version}. No services changed."
    ok "Rollback-safe bridge CLI replacement preflight passed"
}

prepare_bridge_phase1_custody() {
    local source_gateway_version source_gateway_semver pid_path pid
    source_gateway_version="$("${INSTALL_DIR}/defenseclaw-gateway" --version 2>&1 || true)"
    source_gateway_semver="$(printf '%s' "${source_gateway_version}" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
    [[ "${source_gateway_semver}" == "${CURRENT_VERSION}" ]] \
        || die "Installed gateway version does not match detected CLI ${CURRENT_VERSION}; refusing the bridge before stopping services."

    cp -p "${INSTALL_DIR}/defenseclaw-gateway" "${BACKUP_DIR}/phase1-source-gateway" \
        || die "Could not retain the source gateway for phase-1 rollback; no services changed."
    cmp -s "${INSTALL_DIR}/defenseclaw-gateway" "${BACKUP_DIR}/phase1-source-gateway" \
        || die "The retained source gateway is not byte-exact; no services changed."

    BRIDGE_SOURCE_HEALTH_URL="$("${DEFENSECLAW_VENV}/bin/python" - <<'PY' 2>/dev/null || true
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

    pid_path="${DEFENSECLAW_HOME}/gateway.pid"
    if [[ -e "${pid_path}" || -L "${pid_path}" ]]; then
        [[ -f "${pid_path}" && ! -L "${pid_path}" ]] \
            || die "Gateway PID custody is not a regular file; refusing the bridge before stopping services."
        IFS= read -r pid < "${pid_path}" || pid=""
        [[ "${pid}" =~ ^[1-9][0-9]*$ ]] \
            || die "Gateway PID custody is malformed; refusing the bridge before stopping services."
        if [[ "${pid}" =~ ^[1-9][0-9]*$ ]] && kill -0 "${pid}" >/dev/null 2>&1; then
            BRIDGE_SOURCE_WAS_RUNNING=1
        fi
    fi
    register_bridge_phase1_recovery_journal
    # The durable journal is the recovery authority. Arm the ordinary EXIT
    # rollback at the same boundary so every caught failure after registration
    # clears or preserves that authority consistently.
    BRIDGE_ROLLBACK_ARMED=1
    ok "Exact source custody and durable crash recovery prepared for automatic bridge rollback"
}

activate_bridge_phase1_cli() {
    local uv_bin source_venv_backup bridge_version
    [[ -n "${whl_name:-}" && -f "${STAGING_DIR}/${whl_name}" ]] \
        || die "Bridge CLI artifact is unavailable during activation"
    uv_bin="$(command -v uv 2>/dev/null || true)"
    source_venv_backup="${BACKUP_DIR}/phase1-source-venv"
    [[ ! -e "${source_venv_backup}" && ! -L "${source_venv_backup}" ]] \
        || die "Phase-1 source CLI custody path already exists"
    mv "${DEFENSECLAW_VENV}" "${source_venv_backup}" \
        || die "Could not move the source CLI into rollback custody"
    BRIDGE_SOURCE_VENV_MOVED=1
    python3 - "${DEFENSECLAW_HOME}" "${BACKUP_DIR}" <<'PY' \
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

    "${uv_bin}" --no-config venv "${DEFENSECLAW_VENV}" --python "${BRIDGE_PYTHON_INTERPRETER}" --quiet \
        || die "Could not create the bridge CLI environment"
    "${uv_bin}" --no-config pip install --python "${DEFENSECLAW_VENV}/bin/python" --quiet "${STAGING_DIR}/${whl_name}" \
        || die "Failed to install the bridge CLI wheel"
    bridge_version="$("${DEFENSECLAW_VENV}/bin/python" -c 'from defenseclaw import __version__; print(__version__)')" \
        || die "Could not import the installed bridge CLI"
    [[ "${bridge_version}" == "${RELEASE_VERSION}" ]] \
        || die "Installed bridge CLI version mismatch: expected ${RELEASE_VERSION}, got ${bridge_version}"
    ok "Python CLI installed with exact source rollback custody"
}

bridge_source_health_check() {
    local elapsed=0 response_file="${STAGING_DIR}/phase1-rollback-health.json" http_code health_fields state version
    while [[ "${elapsed}" -lt 30 ]]; do
        http_code="$(curl -s -o "${response_file}" -w "%{http_code}" "${BRIDGE_SOURCE_HEALTH_URL}" 2>/dev/null || echo "000")"
        health_fields="$(python3 - "${response_file}" <<'PY' 2>/dev/null || true
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as response_file:
        payload = json.load(response_file)
except (OSError, TypeError, ValueError):
    raise SystemExit
gateway = payload.get("gateway")
provenance = payload.get("provenance")
state = gateway.get("state", "unknown") if isinstance(gateway, dict) else "unknown"
version = provenance.get("binary_version", "missing") if isinstance(provenance, dict) else "missing"
print(f"{state}\t{version}")
PY
)"
        rm -f "${response_file}"
        state="${health_fields%%$'\t'*}"
        version="${health_fields#*$'\t'}"
        if [[ "${http_code}" == "200" && "${state}" == "running" && "${version}" == "${CURRENT_VERSION}" ]]; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

bridge_phase1_gateway_quiesced() {
    local pid_path="${DEFENSECLAW_HOME}/gateway.pid" pid
    [[ -e "${pid_path}" || -L "${pid_path}" ]] || return 0
    [[ -f "${pid_path}" && ! -L "${pid_path}" ]] || return 1
    IFS= read -r pid < "${pid_path}" || pid=""
    [[ "${pid}" =~ ^[1-9][0-9]*$ ]] || return 1
    ! kill -0 "${pid}" >/dev/null 2>&1
}

rollback_bridge_phase1() {
    local rollback_failed=0 source_venv_backup="${BACKUP_DIR}/phase1-source-venv"
    local restored_gateway_version restored_cli_version attempt
    [[ "${BRIDGE_ROLLBACK_RUNNING}" -eq 0 ]] || return 1
    BRIDGE_ROLLBACK_RUNNING=1
    BRIDGE_ROLLBACK_ARMED=0
    section "Restoring Source After Bridge Failure"

    if [[ -x "${INSTALL_DIR}/defenseclaw-gateway" ]]; then
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

    if [[ "${BRIDGE_SOURCE_VENV_MOVED}" -eq 1 ]]; then
        rm -rf "${DEFENSECLAW_VENV}" || rollback_failed=1
        if [[ -d "${source_venv_backup}" && ! -L "${source_venv_backup}" ]]; then
            if mv "${source_venv_backup}" "${DEFENSECLAW_VENV}"; then
                python3 - "${DEFENSECLAW_HOME}" "${BACKUP_DIR}" <<'PY' \
                    || rollback_failed=1
import os
import sys

for path in sys.argv[1:]:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
PY
            else
                rollback_failed=1
            fi
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
            if mv -f "${BRIDGE_GATEWAY_INSTALL_TEMP}" "${INSTALL_DIR}/defenseclaw-gateway" \
                && python3 - "${INSTALL_DIR}" <<'PY'
import os
import sys

descriptor = os.open(sys.argv[1], os.O_RDONLY)
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

    if [[ "${BRIDGE_STATE_SNAPSHOT_READY}" -eq 1 ]]; then
        bridge_phase1_state_transaction restore || rollback_failed=1
    fi

    restored_gateway_version="$("${INSTALL_DIR}/defenseclaw-gateway" --version 2>&1 \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
    [[ "${restored_gateway_version}" == "${CURRENT_VERSION}" ]] || rollback_failed=1
    restored_cli_version="$("${DEFENSECLAW_VENV}/bin/defenseclaw" --version 2>&1 \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
    [[ "${restored_cli_version}" == "${CURRENT_VERSION}" ]] || rollback_failed=1

    if [[ "${BRIDGE_SOURCE_WAS_RUNNING}" -eq 1 ]]; then
        "${INSTALL_DIR}/defenseclaw-gateway" start >/dev/null 2>&1 || rollback_failed=1
        if [[ "${rollback_failed}" -eq 0 ]]; then
            bridge_source_health_check || rollback_failed=1
        fi
    fi
    if command -v openclaw >/dev/null 2>&1; then
        openclaw gateway restart >/dev/null 2>&1 || warn "Could not restart OpenClaw after source rollback"
    fi

    if [[ "${rollback_failed}" -eq 0 ]]; then
        complete_bridge_phase1_recovery_journal "${BRIDGE_RECOVERY_PLAN_ID}" \
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

handoff_existing_bridge_to_hard_cut() {
    local final_version="${RELEASE_VERSION}"
    local final_min_protocol="${STAGED_FINAL_MIN_PROTOCOL}"
    local handoff_dir

    RELEASE_VERSION="${CURRENT_VERSION}"
    configure_release
    preflight_release_artifacts
    prepare_release_contract
    if [[ "${MANIFEST_CONTROLLER_PROTOCOL}" -lt "${final_min_protocol}" ]]; then
        die "Installed bridge ${CURRENT_VERSION} cannot drive ${final_version}. No changes were made."
    fi

    step "Retaining verified bridge gateway for rollback ..."
    fetch_artifact "${TARBALL_URL}" "${STAGING_DIR}/${TARBALL_NAME}"
    verify_checksum "${STAGING_DIR}/${TARBALL_NAME}" "${TARBALL_NAME}"
    validate_tarball_members "${STAGING_DIR}/${TARBALL_NAME}"
    step "Retaining verified bridge CLI for rollback ..."
    fetch_artifact "${WHL_URL}" "${STAGING_DIR}/${WHL_NAME}"
    verify_checksum "${STAGING_DIR}/${WHL_NAME}" "${WHL_NAME}"
    preflight_python_wheel "${STAGING_DIR}/${WHL_NAME}"
    preflight_bridge_rollback_capability "${STAGING_DIR}/${WHL_NAME}"

    handoff_dir="${STAGING_DIR}/bridge-handoff"
    create_bridge_handoff_directory "${handoff_dir}" >/dev/null
    section "Fresh Controller Handoff"
    ok "Verified ${CURRENT_VERSION} rollback artifacts retained; launching its installed controller"
    trap - EXIT
    export DEFENSECLAW_STAGED_UPGRADE=1
    export DEFENSECLAW_STAGED_BRIDGE_VERSION="${CURRENT_VERSION}"
    export DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR="${handoff_dir}"
    exec "${INSTALL_DIR}/defenseclaw" upgrade --yes --version "${final_version}"
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
resolve_staged_upgrade

if [[ "${CURRENT_VERSION}" != "unknown" ]] \
    && [[ "${RELEASE_VERSION}" == "0.8.4" ]] \
    && version_lt "${CURRENT_VERSION}" "${RELEASE_VERSION}"; then
    BRIDGE_PHASE1=1
fi

if [[ "${PLAN_ONLY}" -eq 1 ]]; then
    section "Upgrade Plan Verified"
    if [[ -n "${STAGED_FINAL_VERSION}" ]]; then
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

if [[ -d "${DEFENSECLAW_HOME}" ]]; then
    for f in config.yaml .env .migration_state.json guardrail_runtime.json device.key \
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

if [[ "${BRIDGE_PHASE1}" -eq 1 ]]; then
    prepare_bridge_phase1_custody
fi

# ── Stop services ─────────────────────────────────────────────────────────────

assert_gateway_quiesced() {
    local pid_path="${DEFENSECLAW_HOME}/gateway.pid"
    [[ -e "${pid_path}" || -L "${pid_path}" ]] || return 0
    [[ ! -L "${pid_path}" && -f "${pid_path}" ]] \
        || die "Gateway PID path is not a regular file after stop; refusing to replace installed artifacts"
    local pid
    IFS= read -r pid < "${pid_path}" || pid=""
    [[ "${pid}" =~ ^[1-9][0-9]*$ ]] \
        || die "Gateway PID file is malformed after stop; refusing to replace installed artifacts"
    if kill -0 "${pid}" >/dev/null 2>&1; then
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
"${INSTALL_DIR}/defenseclaw-gateway" stop 2>/dev/null && ok "Gateway stopped" || warn "Gateway was not running"
assert_gateway_quiesced
if [[ "${BRIDGE_PHASE1}" -eq 1 ]]; then
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
cp "${STAGING_DIR}/defenseclaw" "${BRIDGE_GATEWAY_INSTALL_TEMP}"
chmod +x "${BRIDGE_GATEWAY_INSTALL_TEMP}"

if [[ "${OS}" == "darwin" ]]; then
    codesign -f -s - "${BRIDGE_GATEWAY_INSTALL_TEMP}" 2>/dev/null || true
fi
mv -f "${BRIDGE_GATEWAY_INSTALL_TEMP}" "${INSTALL_DIR}/defenseclaw-gateway"
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
        "${UV_BIN}" --no-config venv "${DEFENSECLAW_VENV}" --python 3.12
    fi
    VENV_PYTHON="${DEFENSECLAW_VENV}/bin/python"
    "${UV_BIN}" --no-config pip install --python "${VENV_PYTHON}" --quiet "${STAGING_DIR}/${whl_name}" \
        || die "Failed to install CLI wheel"
    ln -sf "${DEFENSECLAW_VENV}/bin/defenseclaw" "${INSTALL_DIR}/defenseclaw"
    ok "Python CLI installed"
fi
VENV_PYTHON="${DEFENSECLAW_VENV}/bin/python"

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

# ── Start services ────────────────────────────────────────────────────────────

section "Starting Services"

step "Starting defenseclaw-gateway ..."
"${INSTALL_DIR}/defenseclaw-gateway" start \
    && ok "Gateway started" \
    || die "Could not start gateway; upgrade failed and no success receipt will be emitted"

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
HEALTH_RESPONSE_FILE="${STAGING_DIR}/gateway-health.json"
while [[ "${ELAPSED}" -lt "${HEALTH_TIMEOUT}" ]]; do
    HTTP_CODE=$(curl -s -o "${HEALTH_RESPONSE_FILE}" -w "%{http_code}" "${HEALTH_URL}" 2>/dev/null || echo "000")
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

    if [[ "${GW_STATE}" == "running" && "${GW_VERSION}" != "${RELEASE_VERSION}" ]]; then
        info "    gateway version: ${GW_VERSION} (expected ${RELEASE_VERSION})"
    fi

    if [[ "${GW_STATE}" == "running" && "${GW_VERSION}" == "${RELEASE_VERSION}" ]]; then
        ok "Gateway is healthy"
        HEALTH_OK=1
        break
    fi
    sleep "${HEALTH_INTERVAL}"
    ELAPSED=$((ELAPSED + HEALTH_INTERVAL))
done

if [[ "${HEALTH_OK}" -eq 0 ]]; then
    err "Gateway did not become healthy within ${HEALTH_TIMEOUT}s"
    info "Check ~/.defenseclaw/gateway.log (process log); gateway.jsonl exists only when an optional JSONL destination is configured"
    info "Run:  defenseclaw-gateway status"
    exit 1
fi

if [[ "${BRIDGE_PHASE1}" -eq 1 ]]; then
    # A provenance-checked, healthy 0.8.4 is itself a safe recovery point.
    # Later handoff preparation failures leave that bridge running for retry.
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
    rm -rf "${STAGING_DIR}"
    trap - EXIT
    export DEFENSECLAW_STAGED_UPGRADE=1
    export DEFENSECLAW_STAGED_BRIDGE_VERSION="${RELEASE_VERSION}"
    export DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR="${handoff_dir}"
    exec "${INSTALL_DIR}/defenseclaw" upgrade --yes --version "${final_version}"
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
