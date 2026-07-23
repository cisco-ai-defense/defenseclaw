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
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPGRADE_SCRIPT="${ROOT}/scripts/upgrade.sh"
PYTHON_REQUEST="${HISTORICAL_BOOTSTRAP_PYTHON:-3.12}"
KEEP_WORKDIR="${KEEP_WORKDIR:-0}"
WORKDIR=""

log() { printf '==> %s\n' "$*"; }
ok() { printf 'OK: %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

cleanup() {
    local status=$?
    if [[ "${KEEP_WORKDIR}" == "1" && -n "${WORKDIR}" ]]; then
        printf 'Historical bootstrap workdir: %s\n' "${WORKDIR}" >&2
    elif [[ -n "${WORKDIR}" && -d "${WORKDIR}" ]]; then
        rm -rf "${WORKDIR}"
    fi
    return "${status}"
}
trap cleanup EXIT

upgrade_constant() {
    local name="$1" value
    value="$(sed -n "s|^readonly ${name}='\(.*\)'$|\1|p" "${UPGRADE_SCRIPT}")"
    [[ -n "${value}" && "${value}" != *$'\n'* ]] \
        || die "${UPGRADE_SCRIPT} must define exactly one single-line ${name}"
    printf '%s\n' "${value}"
}

download() {
    local url="$1" destination="$2" _attempt
    for _attempt in 1 2 3; do
        if curl --fail --silent --show-error --location \
            --proto '=https' --proto-redir '=https' --tlsv1.2 \
            --output "${destination}" "${url}"; then
            return 0
        fi
    done
    die "Could not download ${url}"
}

sha256() {
    local path="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "${path}" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "${path}" | awk '{print $1}'
    else
        die "sha256sum or shasum is required"
    fi
}

materialize_protected_wheel() {
    local source="$1" destination="$2" expected_sha256="$3"
    python3 - "${source}" "${destination}" "${expected_sha256}" <<'PY'
import hashlib
import os
import stat
import sys

source, destination, expected_sha256 = sys.argv[1:]
magic = b"DEFENSECLAW-PROTECTED-ARTIFACT-V1\n"
source_info = os.lstat(source)
if stat.S_ISLNK(source_info.st_mode) or not stat.S_ISREG(source_info.st_mode):
    raise RuntimeError("protected historical wheel is not a regular file")

digest = hashlib.sha256()
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
source_fd = os.open(source, flags)
created = False
try:
    opened = os.fstat(source_fd)
    if not os.path.samestat(source_info, opened):
        raise RuntimeError("protected historical wheel changed while opening")
    observed_magic = os.read(source_fd, len(magic))
    if observed_magic != magic:
        raise RuntimeError("protected historical wheel magic is invalid")
    digest.update(observed_magic)
    destination_fd = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    created = True
    try:
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            payload = bytes(value ^ 0xA5 for value in chunk)
            view = memoryview(payload)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise RuntimeError("historical wheel materialization stalled")
                view = view[written:]
        os.fsync(destination_fd)
    finally:
        os.close(destination_fd)
finally:
    os.close(source_fd)

if digest.hexdigest() != expected_sha256:
    if created:
        os.unlink(destination)
    raise RuntimeError("protected historical wheel checksum mismatch")
PY
}

verify_constraint_scope() {
    python3 - "${UPGRADE_SCRIPT}" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8")


def function(name: str, following: str) -> str:
    start = source.index(f"{name}() {{")
    end = source.index(f"\n}}\n\n{following}() {{", start)
    return source[start:end]


post_cut = function("continue_post_hard_cut_upgrade", "handoff_existing_bridge_to_hard_cut")
if not (
    "env -u UV_CONSTRAINT -u UV_OVERRIDE -u UV_EXCLUDE_NEWER \\\n"
    "        DEFENSECLAW_UPGRADE_FRESH_PROCESS=1 \\\n"
    '        "${DEFENSECLAW_VENV}/bin/defenseclaw" upgrade'
) in post_cut:
    raise SystemExit("post-hard-cut final hop does not clear historical resolver constraints")

install_start = source.index("# ── Install from staging (fast, no network)")
install_end = source.index("# ── Run migrations", install_start)
ordinary_install = source[install_start:install_end]
if not (
    "env -u UV_CONSTRAINT -u UV_OVERRIDE -u UV_EXCLUDE_NEWER \\\n"
    '        "${UV_BIN}" --no-config pip install'
) in ordinary_install:
    raise SystemExit("ordinary target installation does not clear historical resolver constraints")

historical_handoff = (
    'env -u UV_OVERRIDE \\\n'
    '        UV_CONSTRAINT="${HISTORICAL_BOOTSTRAP_CONSTRAINTS_FILE}" \\\n'
    '        UV_EXCLUDE_NEWER="${HISTORICAL_BOOTSTRAP_EXCLUDE_NEWER}" \\\n'
    '        "${TARGET_CONTROLLER_CLI}" upgrade'
)
if source.count(historical_handoff) != 2:
    raise SystemExit("historical constraints are not scoped to both authenticated hard-cut handoffs")
if "UV_CONSTRAINT=''" in source or "UV_OVERRIDE=''" in source or "UV_EXCLUDE_NEWER=''" in source:
    raise SystemExit("empty uv environment assignments are parsed as values by current uv releases")

clean_prefix = "env -u UV_CONSTRAINT -u UV_OVERRIDE -u UV_EXCLUDE_NEWER \\"
lines = source.splitlines()
direct_uv_commands = [
    index
    for index, line in enumerate(lines)
    if ('"${uv_bin}" --no-config' in line or '"${UV_BIN}" --no-config' in line)
]
if len(direct_uv_commands) != 11:
    raise SystemExit(f"unexpected direct uv command count: {len(direct_uv_commands)}")
for index in direct_uv_commands:
    if index == 0 or lines[index - 1].strip() != clean_prefix:
        raise SystemExit(f"direct uv command is not environment-sanitized: {lines[index]!r}")
PY
    ok "Historical constraints are cleared before the current/final candidate path"
}

verify_uv_environment_isolation() {
    local probe_venv="${WORKDIR}/uv-environment-probe"
    local poison_constraint="${WORKDIR}/ambient-constraint.txt"
    local poison_override="${WORKDIR}/ambient-override.txt"
    local poison_cutoff="not-an-rfc3339-timestamp"

    printf '%s\n' 'this is not a valid requirement @@@' >"${poison_constraint}"
    printf '%s\n' 'this is not a valid override @@@' >"${poison_override}"
    UV_CONSTRAINT="${poison_constraint}" \
        UV_OVERRIDE="${poison_override}" \
        UV_EXCLUDE_NEWER="${poison_cutoff}" \
        env -u UV_CONSTRAINT -u UV_OVERRIDE -u UV_EXCLUDE_NEWER \
        "${UV_BIN}" --no-config venv "${probe_venv}" --python "${PYTHON_REQUEST}" --quiet \
        || die "Could not create the uv environment-isolation probe"

    # Exercise the ordinary-install cleanup prefix against a real uv command.
    # Each ambient value is deliberately unparsable; success therefore proves
    # that current uv never receives an empty or poisoned inherited value.
    UV_CONSTRAINT="${poison_constraint}" \
        UV_OVERRIDE="${poison_override}" \
        UV_EXCLUDE_NEWER="${poison_cutoff}" \
        env -u UV_CONSTRAINT -u UV_OVERRIDE -u UV_EXCLUDE_NEWER \
        "${UV_BIN}" --no-config pip check --python "${probe_venv}/bin/python" --quiet \
        || die "Ordinary resolver command parsed a poisoned ambient UV_* value"

    # Interrupted phase-two recovery invokes uv from an embedded Python
    # mutator while it owns the recovery lease. Exercise that distinct process
    # boundary with the same poisoned parent environment.
    UV_CONSTRAINT="${poison_constraint}" \
        UV_OVERRIDE="${poison_override}" \
        UV_EXCLUDE_NEWER="${poison_cutoff}" \
        python3 - "${UV_BIN}" "${probe_venv}/bin/python" <<'PY'
import os
import subprocess
import sys

uv, python = sys.argv[1:]
uv_environment = os.environ.copy()
for name in ("UV_CONSTRAINT", "UV_OVERRIDE", "UV_EXCLUDE_NEWER"):
    uv_environment.pop(name, None)
subprocess.run(
    [uv, "--no-config", "pip", "check", "--python", python, "--quiet"],
    check=True,
    env=uv_environment,
)
PY

    # The final controller is not itself uv, so assert the inherited process
    # environment directly: any nested resolver it starts must see no UV_*
    # policy unless the authenticated historical handoff sets it explicitly.
    UV_CONSTRAINT="${poison_constraint}" \
        UV_OVERRIDE="${poison_override}" \
        UV_EXCLUDE_NEWER="${poison_cutoff}" \
        env -u UV_CONSTRAINT -u UV_OVERRIDE -u UV_EXCLUDE_NEWER \
        python3 - <<'PY'
import os

names = ("UV_CONSTRAINT", "UV_OVERRIDE", "UV_EXCLUDE_NEWER")
leaked = {name: os.environ[name] for name in names if name in os.environ}
if leaked:
    raise SystemExit(f"final controller inherited poisoned uv policy: {leaked!r}")
PY

    # Conversely, the authenticated 0.8.5 target-controller handoff keeps its
    # nonempty constraint/cutoff custody while removing an ambient override.
    UV_CONSTRAINT="${poison_constraint}" \
        UV_OVERRIDE="${poison_override}" \
        UV_EXCLUDE_NEWER="${poison_cutoff}" \
        env -u UV_OVERRIDE \
        UV_CONSTRAINT="${CONSTRAINTS_FILE}" \
        UV_EXCLUDE_NEWER="${EXCLUDE_NEWER}" \
        python3 - "${CONSTRAINTS_FILE}" "${EXCLUDE_NEWER}" <<'PY'
import os
import sys

expected_constraint, expected_cutoff = sys.argv[1:]
observed = {
    "UV_CONSTRAINT": os.environ.get("UV_CONSTRAINT"),
    "UV_EXCLUDE_NEWER": os.environ.get("UV_EXCLUDE_NEWER"),
}
expected = {
    "UV_CONSTRAINT": expected_constraint,
    "UV_EXCLUDE_NEWER": expected_cutoff,
}
if observed != expected or "UV_OVERRIDE" in os.environ:
    raise SystemExit(
        "historical handoff uv policy changed: "
        f"observed={observed!r}, override={os.environ.get('UV_OVERRIDE')!r}"
    )
PY
    ok "Poisoned ambient UV_* policy is removed from ordinary/final commands"
}

verify_frozen_start_readiness_contract() {
    local frozen_python="$1" fixture_root="$2"
    "${frozen_python}" -I -B - "${fixture_root}" "${ROOT}" <<'PY'
import ast
import inspect
import os
from pathlib import Path
import subprocess
import sys
import textwrap
import types

from defenseclaw import config as config_module
from defenseclaw.commands import cmd_upgrade

fixture_root, source_root = sys.argv[1:3]
timeout = inspect.signature(cmd_upgrade._run_silent).parameters["timeout_seconds"].default
if timeout != 30:
    raise SystemExit(f"immutable 0.8.5 child timeout changed: {timeout!r}")
health_options = [parameter for parameter in cmd_upgrade.upgrade.params if parameter.name == "health_timeout"]
if len(health_options) != 1 or health_options[0].default != 60:
    raise SystemExit("immutable 0.8.5 controller health timeout is not 60 seconds")

marker = "DEFENSECLAW_UPGRADE_FRESH_PROCESS"
os.environ[marker] = "1"
data_dir = os.path.join(fixture_root, "frozen-data")
config_path = os.path.join(fixture_root, "frozen-config.yaml")
gateway_environment = cmd_upgrade._gateway_process_environment(
    data_dir,
    config_path=config_path,
)
if gateway_environment.get(marker) != "1":
    raise SystemExit("immutable 0.8.5 controller dropped the fresh-process marker")

observed = {}


def fake_mutator(command, **kwargs):
    observed["command"] = command
    observed["kwargs"] = kwargs
    return subprocess.CompletedProcess(command, 0, "", "")


cmd_upgrade._run_phase_two_mutator = fake_mutator
if not cmd_upgrade._run_silent(
    ["candidate-defenseclaw-gateway", "start"],
    "fixture gateway launched",
    "fixture gateway failed",
    env=gateway_environment,
):
    raise SystemExit("immutable 0.8.5 start wrapper rejected the delegated fixture")
if observed.get("command") != ["candidate-defenseclaw-gateway", "start"]:
    raise SystemExit("immutable 0.8.5 start wrapper changed the gateway command")
kwargs = observed.get("kwargs", {})
if kwargs.get("timeout") != 30 or kwargs.get("env", {}).get(marker) != "1":
    raise SystemExit("immutable 0.8.5 start wrapper did not propagate its 30s marked contract")

service_tree = ast.parse(textwrap.dedent(inspect.getsource(cmd_upgrade._start_and_verify_services)))
version_aware_polls = [
    node
    for node in ast.walk(service_tree)
    if isinstance(node, ast.Call)
    and isinstance(node.func, ast.Name)
    and node.func.id == "_poll_health"
    and any(
        keyword.arg == "expected_version"
        and isinstance(keyword.value, ast.Name)
        and keyword.value.id == "expected_version"
        for keyword in node.keywords
    )
]
if not version_aware_polls:
    raise SystemExit("immutable 0.8.5 controller lost its version-aware post-start health poll")
if "_poll_health(cfg, int(sys.argv[2]), expected_version=sys.argv[3])" not in cmd_upgrade._INSTALLED_HEALTH_SCRIPT:
    raise SystemExit("immutable 0.8.5 installed health child lost expected-version verification")

# Execute the immutable script against a replacement module to prove that the
# separately budgeted child resolves _poll_health from installed state at run
# time rather than retaining the frozen controller function object.
imported_health = {}
current_health_module = types.ModuleType("defenseclaw.commands.cmd_upgrade")


def current_poll_health(cfg, timeout_seconds, *, expected_version=None):
    imported_health.update(
        cfg=cfg,
        timeout_seconds=timeout_seconds,
        expected_version=expected_version,
    )


current_health_module._poll_health = current_poll_health
sys.modules["defenseclaw.commands.cmd_upgrade"] = current_health_module
config_sentinel = object()
config_module._load_dotenv_into_os = lambda _path: None
config_module.load = lambda: config_sentinel
sys.argv = ["installed-health", data_dir, "60", "9.9.9"]
exec(cmd_upgrade._INSTALLED_HEALTH_SCRIPT, {})
if imported_health != {
    "cfg": config_sentinel,
    "timeout_seconds": 60,
    "expected_version": "9.9.9",
}:
    raise SystemExit(f"immutable installed-health import boundary changed: {imported_health!r}")

root = Path(source_root)
current_upgrade = (root / "cli/defenseclaw/commands/cmd_upgrade.py").read_text(encoding="utf-8")
current_gateway = (root / "internal/cli/daemon.go").read_text(encoding="utf-8")
current_contract = (
    'os.environ.get(_UPGRADE_HANDOFF_ENV) == "1"',
    "_poll_handoff_gateway_readiness(cfg, timeout_seconds, expected_version)",
    '"upgrade-wait-ready"',
    '"--expected-version"',
    "timeout=readiness_timeout + 5",
)
if any(fragment not in current_upgrade for fragment in current_contract):
    raise SystemExit("current installed-health implementation lost its one-budget strict handoff")
gateway_contract = (
    'Use:               "upgrade-wait-ready"',
    "waitForRunningDaemonReadinessWithVersion(",
    "inspectConfiguredListener(d, cfg, client)",
    "status.Provenance.BinaryVersion != requirements.expectedBinaryVersion",
    "ManagedProcessStartedAt(pid)",
)
if any(fragment not in current_gateway for fragment in gateway_contract):
    raise SystemExit("current gateway lost strict handoff readiness enforcement")

print("verified immutable 0.8.5 30s launch / one 60s current strict readiness handoff")
PY
    ok "Immutable 0.8.5 delegates marked launch to one current strict, version-aware health budget"
}

install_and_check() {
    local version="$1" outer_sha256="$2"
    local protected_name="defenseclaw-${version}-2-py3-none-any.dcwheel"
    local wheel_name="defenseclaw-${version}-2-py3-none-any.whl"
    local release_dir="${WORKDIR}/${version}"
    local protected_wheel="${release_dir}/${protected_name}"
    local wheel="${release_dir}/${wheel_name}"
    local venv="${release_dir}/venv"
    local install_log="${release_dir}/install.log"

    mkdir "${release_dir}"
    log "Downloading immutable ${version} bootstrap wheel"
    download \
        "https://github.com/cisco-ai-defense/defenseclaw/releases/download/${version}/${protected_name}" \
        "${protected_wheel}"
    [[ "$(sha256 "${protected_wheel}")" == "${outer_sha256}" ]] \
        || die "${protected_name} does not match its release checksum"
    materialize_protected_wheel "${protected_wheel}" "${wheel}" "${outer_sha256}"

    env -u UV_CONSTRAINT -u UV_OVERRIDE -u UV_EXCLUDE_NEWER \
        "${UV_BIN}" --no-config venv "${venv}" --python "${PYTHON_REQUEST}" --quiet \
        || die "Could not create the ${version} bootstrap test environment"
    log "Installing the resolver-derived ${version} dependency graph"
    if ! env -u UV_CONSTRAINT -u UV_OVERRIDE -u UV_EXCLUDE_NEWER \
        UV_CACHE_DIR="${WORKDIR}/uv-cache" \
        "${UV_BIN}" --no-config pip install \
            --python "${venv}/bin/python" --quiet \
            --constraints "${CONSTRAINTS_FILE}" --only-binary litellm \
            --exclude-newer "${EXCLUDE_NEWER}" \
            "${wheel}" 2>"${install_log}"; then
        tail -100 "${install_log}" >&2 || true
        die "Could not install the ${version} historical bootstrap graph"
    fi

    # This is the regression gate that a resolver dry-run cannot replace:
    # overrides may produce an install plan while leaving package METADATA
    # mutually contradictory. Check the fully installed environment instead.
    env -u UV_CONSTRAINT -u UV_OVERRIDE -u UV_EXCLUDE_NEWER \
        UV_CACHE_DIR="${WORKDIR}/uv-cache" \
        "${UV_BIN}" --no-config pip check --python "${venv}/bin/python"
    "${venv}/bin/python" -I -B - "${version}" <<'PY'
from importlib.metadata import version
import sys

expected = {
    "defenseclaw": sys.argv[1],
    "cisco-ai-mcp-scanner": "4.7.2",
    "litellm": "1.83.7",
}
observed = {distribution: version(distribution) for distribution in expected}
if observed != expected:
    raise SystemExit(f"historical bootstrap versions changed: {observed!r} != {expected!r}")

from defenseclaw import __version__

if __version__ != sys.argv[1]:
    raise SystemExit(f"historical bootstrap import reported {__version__!r}")
print(
    "verified "
    + ", ".join(f"{distribution}=={release}" for distribution, release in observed.items())
)
PY
    if [[ "${version}" == "0.8.5" ]]; then
        verify_frozen_start_readiness_contract "${venv}/bin/python" "${release_dir}"
    fi
    ok "${version} historical bootstrap metadata is consistent"
}

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v python3 >/dev/null 2>&1 || die "python3 is required"
UV_BIN="$(command -v uv 2>/dev/null || true)"
[[ -n "${UV_BIN}" ]] || die "uv is required"
[[ -f "${UPGRADE_SCRIPT}" ]] || die "upgrade resolver not found: ${UPGRADE_SCRIPT}"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-historical-bootstrap.XXXXXX")"
CONSTRAINTS_FILE="${WORKDIR}/historical-bootstrap-constraints.txt"
EXCLUDE_NEWER="$(upgrade_constant HISTORICAL_BOOTSTRAP_EXCLUDE_NEWER)"
[[ "${EXCLUDE_NEWER}" == "2026-07-18T19:02:08Z" ]] \
    || die "historical transitive cutoff must match the immutable 0.8.5 publication time"
printf '%s\n%s\n' \
    "$(upgrade_constant HISTORICAL_BOOTSTRAP_MCP_SCANNER_CONSTRAINT)" \
    "$(upgrade_constant HISTORICAL_BOOTSTRAP_LITELLM_CONSTRAINT)" \
    >"${CONSTRAINTS_FILE}"
chmod 600 "${CONSTRAINTS_FILE}"

verify_constraint_scope
verify_uv_environment_isolation
# These outer digests are the unique entries in each release's Sigstore-signed
# checksums.txt; the test therefore exercises the same protected controllers as
# the production resolver, not a wheel rebuilt from the corresponding tag.
install_and_check \
    "0.8.4" \
    "0e478af0f0f1a038043501e094048ac47dda08ffe129fb533a775f11ed04c808"
install_and_check \
    "0.8.5" \
    "34f5abf8cd5d5104df2f27a12ce8cd36675b3c8c99b8eafccc0b922ef94d1901"

ok "All immutable historical bootstrap environments are installable and metadata-consistent"
