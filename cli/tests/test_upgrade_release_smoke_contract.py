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

"""Offline contracts for the single historical release-upgrade harness."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from defenseclaw.migrations import run_migrations
from defenseclaw.observability.v8_config import load_validate_v8
from defenseclaw.upgrade_receipt import begin_upgrade_receipt

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "test-upgrade-release.sh"
PROTOCOL_SCRIPT = ROOT / "scripts" / "test-upgrade-protocol-release.sh"
DEVELOPER_ACTIVATION_SCRIPT = ROOT / "scripts" / "test-developer-target-activation.sh"
INSTALL_SCRIPT = ROOT / "scripts" / "install.sh"
UPGRADE_SCRIPT = ROOT / "scripts" / "upgrade.sh"
MAKEFILE = ROOT / "Makefile"
BASELINE_POLICY = ROOT / "release" / "upgrade-baselines.json"
PRE_RELEASE_CERTIFICATION = ROOT / ".github" / "workflows" / "pre-release-certification.yml"
RECEIPT_CHECK = ROOT / "scripts" / "check_upgrade_receipt.py"
POSIX_UPGRADE_CUSTODY = pytest.mark.skipif(
    os.name == "nt",
    reason="descriptor-relative POSIX ownership, mode, exchange, and quarantine contract",
)


def _bash_executable() -> str:
    """Select a real Bash runtime without invoking Windows' WSL app alias."""

    if os.name != "nt":
        return shutil.which("bash") or "bash"

    candidates: list[Path] = []
    git = shutil.which("git")
    if git:
        git_path = Path(git).resolve()
        # A normal Git for Windows install exposes git.exe from either cmd/ or
        # bin/.  Its Bash runtime is always under the sibling bin directory.
        candidates.append(git_path.parent.parent / "bin" / "bash.exe")
    for variable in ("ProgramFiles", "ProgramFiles(x86)", "LocalAppData"):
        root = os.environ.get(variable)
        if root:
            candidates.append(Path(root) / "Git" / "bin" / "bash.exe")

    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    pytest.skip("Git Bash is required for the POSIX upgrade-smoke contract on Windows")


def _source_script(command: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            _bash_executable(),
            "-c",
            f'source "$1"; {command}',
            "upgrade-smoke-contract",
            str(SCRIPT),
            *arguments,
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_posix_install_upgrade_and_smoke_pin_private_umask() -> None:
    for path in (INSTALL_SCRIPT, UPGRADE_SCRIPT, SCRIPT):
        text = path.read_text(encoding="utf-8")
        assert re.search(r"^set -euo pipefail\n(?:.*\n){0,8}umask 077$", text, re.MULTILINE), path


def test_developer_activation_is_isolated_from_every_production_upgrade_surface() -> None:
    source = DEVELOPER_ACTIVATION_SCRIPT.read_text(encoding="utf-8")

    assert 'source "${ROOT}/scripts/test-upgrade-release.sh"' in source
    assert "run_migrations(" in source
    assert "upgrade_handles_local_bundle=True" in source
    assert "controller_owns_local_bundle_transaction=True" in source
    assert "_poll_health(configuration" in source
    assert '[[ -n "${RELEASE_ROOT}" ]]' in source
    assert '[[ "${BASELINE_MODE}" == "seed" ]]' in source
    assert '[[ "${CANDIDATE_SCHEMA_VERSION}" == "2" ]]' in source
    assert '-e "${release_dir}/checksums.txt.sig" || -L "${release_dir}/checksums.txt.sig"' in source
    assert '-e "${release_dir}/checksums.txt.pem" || -L "${release_dir}/checksums.txt.pem"' in source
    assert "developer activation HOME escaped its private workdir" in source
    assert "select_private_api_port" in source
    assert 'gateway.get("api_port") != developer_api_port' in source
    assert "must not claim a production upgrade receipt" in source
    assert "No production resolver, provenance, bridge, receipt, or rollback success was claimed" in source

    production_paths = (
        ROOT / "scripts/install.sh",
        ROOT / "scripts/install.ps1",
        ROOT / "scripts/upgrade.sh",
        ROOT / "scripts/upgrade.ps1",
        ROOT / "cli/defenseclaw/commands/cmd_upgrade.py",
    )
    for path in production_paths:
        assert DEVELOPER_ACTIVATION_SCRIPT.name not in path.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (["--baseline-mode", "seed"], "requires --release-root"),
        (["--release-root", "/tmp/does-not-exist"], "requires --baseline-mode seed"),
    ],
)
def test_developer_activation_rejects_nonisolated_invocations_before_network(
    arguments: list[str],
    message: str,
) -> None:
    completed = subprocess.run(
        [_bash_executable(), str(DEVELOPER_ACTIVATION_SCRIPT), *arguments],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode != 0
    assert message in completed.stderr


def test_developer_activation_removes_ambient_runtime_overrides() -> None:
    completed = subprocess.run(
        [
            _bash_executable(),
            "-c",
            'source "$1"; '
            "export DEFENSECLAW_DISABLE_REDACTION=true "
            "DEFENSECLAW_GATEWAY_BIN=/ambient/gateway "
            "OPENCLAW_HOME=/ambient/openclaw DOCKER_HOST=tcp://ambient:2375 "
            "PYTHONPATH=/ambient/python VIRTUAL_ENV=/ambient/venv; "
            "sanitize_developer_activation_environment; "
            "for name in DEFENSECLAW_DISABLE_REDACTION DEFENSECLAW_GATEWAY_BIN "
            "OPENCLAW_HOME DOCKER_HOST PYTHONPATH VIRTUAL_ENV; do "
            '[[ -z "${!name+x}" ]] || exit 19; done',
            "developer-environment-contract",
            str(DEVELOPER_ACTIVATION_SCRIPT),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize(
    ("reported", "expected_success"),
    [
        ("defenseclaw, version 0.8.5", True),
        ("defenseclaw, version 0.8.50", False),
        ("defenseclaw, version 0.8.5-rc1", False),
        ("defenseclaw, version 0.8.5+dirty", False),
        ("defenseclaw, version v0.8.5", False),
        ("defenseclaw 0.8.5 (dependency 0.8.5)", False),
    ],
)
def test_version_canary_requires_one_exact_semver_token(
    reported: str,
    expected_success: bool,
) -> None:
    completed = _source_script(
        'assert_exact_reported_version "fixture" "0.8.5" "$2"',
        reported,
    )

    assert (completed.returncode == 0) is expected_success, completed.stderr


def test_source_gateway_canary_waits_for_exact_version_bound_health() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    canary = source[source.index("start_source_gateway_canary()") : source.index("parse_args()")]

    assert "http://127.0.0.1:18970/health" in canary
    assert 'gateway.get("state") not in {"running", "disabled"}' in canary
    assert 'provenance.get("binary_version") != sys.argv[2]' in canary
    assert "version-bound healthy before resolver handoff" in canary
    assert "did not reach version-bound health" in canary


def test_audit_event_probe_is_policy_independent_and_satisfies_gateway_contract() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    start = source.index("probe_id = str(uuid.uuid4())")
    end = source.index("\nlocal = (config.get(\"observability\")", start)
    request = source[start:end]

    assert '"action": "policy-reload"' in request
    assert '"id": probe_id' in request
    assert '"target": "release-upgrade-smoke:" + probe_id' in request
    assert '"actor": "release-upgrade-smoke"' in request
    assert '"details": "synthetic post-status SQLite continuity probe; no policy state changed"' in request
    assert '"severity": "INFO"' in request
    assert 'f"http://127.0.0.1:{port}/audit/event"' in request
    assert "data=body" in request
    assert '"Authorization": "Bearer " + token' in request
    assert '"Content-Type": "application/json"' in request
    assert '"X-DefenseClaw-Client": "release-upgrade-smoke"' in request
    assert '"X-DefenseClaw-Token": token' in request
    assert "/policy/reload" not in request
    assert "response.status != 200" in request
    assert 'result != {"status": "ok"}' in request

    persistence = source[end : source.index('print("post_status_mandatory_sqlite_write=ok")', end)]
    assert "WHERE id = ? AND action = 'policy-reload'" in persistence
    assert "AND event_name = 'policy.updated' AND mandatory = 1" in persistence
    assert "(probe_id,)" in persistence
    assert 'getattr(sqlite3, "SQLITE_BUSY", 5)' in persistence
    assert 'getattr(sqlite3, "SQLITE_LOCKED", 6)' in persistence
    assert 'message == "database is busy"' in persistence
    assert '"database table is locked"' in persistence
    assert "timeout=0.2" in persistence
    assert "if after == 1:" in persistence


def test_posix_resolver_owns_dynamic_receipt_and_bundle_phases() -> None:
    source = UPGRADE_SCRIPT.read_text(encoding="utf-8")

    receipt_function = source[
        source.index("begin_release_upgrade_receipt() {") : source.index(
            "\n}\n\nfinish_release_upgrade_receipt()", source.index("begin_release_upgrade_receipt() {")
        )
    ]
    backup = source.index('ok "Backup saved to: ${BACKUP_DIR}"')
    receipt = source.index("begin_release_upgrade_receipt\n", backup)
    stop = source.index('# ── Stop services', receipt)
    gateway_activation = source.index('mv -f "${BRIDGE_GATEWAY_INSTALL_TEMP}"', stop)
    target_activation = source.index(
        'UPGRADE_RECEIPT_FAILURE_CODE="interrupted"', gateway_activation
    )
    launcher = source.index('ln -sf "${DEFENSECLAW_VENV}/bin/defenseclaw"', target_activation)
    migration = source.index('kwargs = {"upgrade_handles_local_bundle": True}', stop)
    required = source.index('if [[ "${UPGRADE_INCOMPLETE}" -eq 1 ]]', migration)
    start = source.index('# ── Start services', required)
    health = source.index('if [[ "${HEALTH_OK}" -eq 0 ]]', start)
    suppress_failed_trap = source.index("UPGRADE_RECEIPT_TERMINAL=1", health)
    complete = source.index("finish_release_upgrade_receipt succeeded", suppress_failed_trap)

    assert (
        backup
        < receipt
        < stop
        < gateway_activation
        < target_activation
        < launcher
        < migration
        < required
        < start
        < health
        < suppress_failed_trap
        < complete
    )
    assert receipt_function.index('local receipt_path receipt_name') < receipt_function.index(
        'UPGRADE_RECEIPT_PATH="${receipt_path}"'
    )
    assert "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}" in receipt_function
    migration_phase = source[stop:required]
    assert "TARGET_PYTHON_STDIN_ARGS=(-)" in migration_phase
    assert "TARGET_PYTHON_STDIN_ARGS=(-I -B -)" in migration_phase
    assert (
        '"${VENV_PYTHON}" "${TARGET_PYTHON_STDIN_ARGS[@]}" "${UPGRADE_RECEIPT_PATH}"'
        in migration_phase
    )
    assert "delegate_prior_upgrade_receipts(Path(receipt_path))" in migration_phase
    assert 'os.environ["MIGRATION_TO_VERSION"]' in migration_phase
    assert "record_upgrade_migrations(" in migration_phase
    assert (
        '"${VENV_PYTHON}" "${TARGET_PYTHON_STDIN_ARGS[@]}" "${UPGRADE_MANIFEST_FILE}"'
        in source[migration:required]
    )
    assert '"${VENV_PYTHON}" "${TARGET_PYTHON_STDIN_ARGS[@]}" <<\'PY\'' in source[start:health]

    same_version = source.index('same_version_recovery="clean"')
    recovery = source.index('section "Recovering Incomplete Upgrade"', same_version)
    clean_noop = source.index('section "Version Already Verified"', recovery)
    assert same_version < recovery < clean_noop < backup
    same_version_phase = source[same_version:clean_noop]
    assert "find_resumable_upgrade_receipt" in same_version_phase
    assert "find_verified_installed_upgrade_receipt" in same_version_phase
    assert "installed_local_observability_bundle_version" in same_version_phase
    assert 'print("untrusted-bundle-drift")' in same_version_phase
    assert '"${DEFENSECLAW_VENV}/bin/defenseclaw" upgrade --yes' in same_version_phase

    split = source.index('if [[ "${COMPONENT_VERSION_SPLIT}" -eq 1 ]]')
    hard_cut_state = source.index('hard_cut_state="$(', split)
    split_phase = source[split:hard_cut_state]
    assert "find_resumable_upgrade_receipt" not in split_phase
    assert "MAX_UPGRADE_RECEIPTS" in split_phase
    assert "UPGRADE_RECEIPT_DIRECTORY" in split_phase
    assert "load_upgrade_receipt" in split_phase
    assert 'receipt.from_version == source_version' in split_phase
    assert 'receipt.target_version == target_version' in split_phase
    assert 'receipt.artifacts_verified' in split_phase
    assert 'receipt.migration_status == "pending"' in split_phase
    assert "receipt.migration_count is None" in split_phase
    assert 'receipt.status == "pending" and receipt.failure_code == ""' in split_phase
    assert 'receipt.status == "failed" and receipt.failure_code == "interrupted"' in split_phase
    assert "latest_created_at = max(" in split_phase
    assert "if created_at == latest_created_at" in split_phase
    assert 'print("recover" if len(latest) == 1 else "invalid")' in split_phase


@pytest.mark.parametrize(("baseline", "config_version"), [("0.8.3", 7), ("0.4.0", 5)])
def test_historical_canary_fixture_is_hermetic_before_gateway_start(
    tmp_path: Path,
    baseline: str,
    config_version: int,
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    completed = _source_script(
        'SMOKE_HOME="$2"; FROM_VERSION="$3"; seed_v8_observability_fixture',
        str(home),
        baseline,
    )

    assert completed.returncode == 0, completed.stderr
    config = yaml.safe_load((home / ".defenseclaw/config.yaml").read_text(encoding="utf-8"))
    assert config["config_version"] == config_version
    assert config["gateway"] == {
        "fleet_mode": "disabled",
        "watcher": {"enabled": False},
    }
    openclaw_home = home / ".openclaw"
    assert openclaw_home.is_dir()
    assert not openclaw_home.is_symlink()
    if os.name != "nt":
        assert stat.S_IMODE(openclaw_home.stat().st_mode) == 0o700


@pytest.mark.skipif(os.name == "nt", reason="private POSIX mode/ownership contract")
def test_protected_release_test_artifact_is_authenticated_before_private_decode(
    tmp_path: Path,
) -> None:
    magic = b"DEFENSECLAW-PROTECTED-ARTIFACT-V1\n"
    payload = b"authenticated test wheel payload"
    protected = magic + bytes(value ^ 0xA5 for value in payload)
    source = tmp_path / "defenseclaw-0.8.4-2-py3-none-any.dcwheel"
    source.write_bytes(protected)
    checksums = tmp_path / "checksums.txt"
    checksums.write_text(f"{hashlib.sha256(protected).hexdigest()}  {source.name}\n")
    custody = tmp_path / "custody"
    custody.mkdir(mode=0o700)
    destination = custody / "defenseclaw-0.8.4-2-py3-none-any.whl"

    completed = _source_script(
        'materialize_authenticated_artifact "$2" "$3" "$4"',
        str(source),
        str(checksums),
        str(destination),
    )

    assert completed.returncode == 0, completed.stderr
    assert destination.read_bytes() == payload
    assert destination.stat().st_mode & 0o077 == 0


@pytest.mark.skipif(os.name == "nt", reason="private POSIX mode/ownership contract")
def test_protected_release_test_artifact_rejects_checksum_mismatch_without_output(
    tmp_path: Path,
) -> None:
    source = tmp_path / "defenseclaw-0.8.4-2-py3-none-any.dcwheel"
    source.write_bytes(b"DEFENSECLAW-PROTECTED-ARTIFACT-V1\n" + bytes(value ^ 0xA5 for value in b"wheel"))
    checksums = tmp_path / "checksums.txt"
    checksums.write_text(f"{'0' * 64}  {source.name}\n")
    custody = tmp_path / "custody"
    custody.mkdir(mode=0o700)
    destination = custody / "defenseclaw-0.8.4-2-py3-none-any.whl"

    completed = _source_script(
        'materialize_authenticated_artifact "$2" "$3" "$4"',
        str(source),
        str(checksums),
        str(destination),
    )

    assert completed.returncode != 0
    assert not destination.exists()


def test_upgrade_failure_guidance_does_not_restore_gateway_jsonl_ownership() -> None:
    lines = [line for line in UPGRADE_SCRIPT.read_text(encoding="utf-8").splitlines() if "gateway.jsonl" in line]
    assert lines
    for line in lines:
        normalized = line.lower()
        assert "optional" in normalized, line
        assert "destination" in normalized, line


def _bridge_comment_restore_program() -> str:
    source = UPGRADE_SCRIPT.read_text(encoding="utf-8")
    start_marker = "# BEGIN BRIDGE_COMMENT_RESTORE_PY"
    end_marker = "# END BRIDGE_COMMENT_RESTORE_PY"
    start = source.index(start_marker)
    end = source.index(end_marker, start) + len(end_marker)
    return source[start:end] + "\n"


def _phase_one_recovery_cleanup_program() -> str:
    source = UPGRADE_SCRIPT.read_text(encoding="utf-8")
    recovery_start = source.index("recover_interrupted_bridge_phase1()")
    cleanup_start = source.index("def cleanup_owned_temporaries() -> None:", recovery_start)
    cleanup_end = source.index("\n\ndef restore_state_before_artifacts()", cleanup_start)
    cleanup = source[cleanup_start:cleanup_end]
    return (
        "import ctypes\n"
        "import errno\n"
        "import os\n"
        "import re\n"
        "import secrets\n"
        "import stat\n"
        "import sys\n\n"
        "data_home, openclaw_home, config_path, plan_id, openclaw_existed = sys.argv[1:]\n"
        "openclaw_home_existed = openclaw_existed == '1'\n"
        "uid = os.geteuid()\n\n"
        "def identity(path: str) -> dict[str, int]:\n"
        "    info = os.lstat(path)\n"
        "    return {'device': info.st_dev, 'inode': info.st_ino}\n\n"
        "path_identities = {\n"
        "    'data_dir': identity(data_home),\n"
        "    'config_parent': identity(os.path.dirname(config_path) or '.'),\n"
        "    'openclaw_home': identity(\n"
        "        openclaw_home if openclaw_home_existed else (os.path.dirname(openclaw_home) or '.')\n"
        "    ),\n"
        "}\n\n"
        f"{cleanup}\n\n"
        "cleanup_owned_temporaries()\n"
    )


def _run_bridge_comment_restore(
    source_path: Path,
    active_path: Path,
    *,
    program: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-",
            str(source_path),
            str(active_path),
            "a" * 32,
        ],
        input=program or _bridge_comment_restore_program(),
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )


def _run_phase_one_recovery_cleanup(
    data_home: Path,
    openclaw_home: Path,
    config_path: Path,
    plan_id: str,
    *,
    openclaw_home_existed: bool = True,
    program: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-",
            str(data_home),
            str(openclaw_home),
            str(config_path),
            plan_id,
            "1" if openclaw_home_existed else "0",
        ],
        input=program or _phase_one_recovery_cleanup_program(),
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )


def test_bridge_comment_restore_is_ordered_before_seal_and_uses_source_snapshot() -> None:
    source = UPGRADE_SCRIPT.read_text(encoding="utf-8")
    migration = source.index("# ── Run migrations")
    restore = source.index("    restore_bridge_config_comments\n", migration)
    cleanup = source.index("    bridge_phase1_cleanup_owned_temporaries", restore)
    seal = source.index("    bridge_phase1_state_transaction seal-active", cleanup)
    start = source.index("# ── Start services", seal)
    restore_function = source[
        source.index("restore_bridge_config_comments()") : source.index("bridge_phase1_state_transaction()")
    ]

    assert migration < restore < cleanup < seal < start
    assert "bridge_phase1_state_transaction config-comment-source" in restore_function
    assert "${BACKUP_DIR}/config.yaml" not in restore_function
    assert "pre-bridge-config.yaml" not in source
    assert "DEFENSECLAW_OBSERVABILITY_V8_PRESERVED_COMMENTS_PATH" not in source
    assert restore_function.count("same_cas_source(") == 4
    assert "committed != candidate" not in restore_function
    assert "os.path.samestat(committed_snapshot" not in restore_function

    recovery_start = source.index("recover_interrupted_bridge_phase1()")
    resume = source[
        source.index("if resume_unsealed_bridge:", recovery_start) : source.index(
            "removed_activation_temp = False", recovery_start
        )
    ]
    assert resume.index("cleanup_owned_temporaries()") < resume.index('print(f"bridge\\t{bridge_version}\\t{plan_id}")')
    cleanup_start = source.index("def cleanup_owned_temporaries() -> None:")
    cleanup_end = source.index("\n\ndef restore_state_before_artifacts()", cleanup_start)
    cleanup = source[cleanup_start:cleanup_end]
    assert "members = list(entries)" not in cleanup
    assert "if len(members) == 100000:" in cleanup


@POSIX_UPGRADE_CUSTODY
def test_bridge_comment_restore_keeps_semantics_order_and_mode(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    source = tmp_path / "source.yaml"
    active = tmp_path / "active.yaml"
    source.write_text(
        """# operator guide
config_version: 7
guardrail:
  enabled: true # keep this explanation
notes:
  quoted: "# scalar hash is not a comment"
  block: |
    # block hash is not a comment
# already present
otel:
  endpoint: https://collector.example.test
""",
        encoding="utf-8",
    )
    active.write_text(
        """# already present
config_version: 7
guardrail:
  enabled: false
otel:
  enabled: false
  destinations: []
""",
        encoding="utf-8",
    )
    source.chmod(0o600)
    active.chmod(0o640)
    before = yaml.safe_load(active.read_text(encoding="utf-8"))

    completed = _run_bridge_comment_restore(source, active)

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "2"
    final = active.read_text(encoding="utf-8")
    preamble = final[: final.index("config_version:")]
    assert preamble == "# operator guide\n# keep this explanation\n# already present\n"
    assert "# scalar hash is not a comment" not in final
    assert "# block hash is not a comment" not in final
    assert final.count("# already present") == 1
    assert yaml.safe_load(final) == before
    assert stat.S_IMODE(active.stat().st_mode) == 0o640


@pytest.mark.parametrize("unsafe_kind", ["source-symlink", "source-hardlink", "source-oversize", "active-symlink"])
@POSIX_UPGRADE_CUSTODY
def test_bridge_comment_restore_rejects_unsafe_leaves(tmp_path: Path, unsafe_kind: str) -> None:
    tmp_path.chmod(0o700)
    source = tmp_path / "source.yaml"
    active = tmp_path / "active.yaml"
    source.write_text("# guide\nconfig_version: 7\n", encoding="utf-8")
    active.write_text("config_version: 7\n", encoding="utf-8")
    source.chmod(0o600)
    active.chmod(0o600)

    if unsafe_kind == "source-symlink":
        actual = tmp_path / "source-actual.yaml"
        source.replace(actual)
        source.symlink_to(actual)
    elif unsafe_kind == "source-hardlink":
        os.link(source, tmp_path / "source-alias.yaml")
    elif unsafe_kind == "source-oversize":
        with source.open("wb") as stream:
            stream.truncate(4 * 1024 * 1024 + 1)
    else:
        actual = tmp_path / "active-actual.yaml"
        active.replace(actual)
        active.symlink_to(actual)

    completed = _run_bridge_comment_restore(source, active)

    assert completed.returncode != 0
    assert "configuration source" in completed.stderr


@POSIX_UPGRADE_CUSTODY
def test_bridge_comment_restore_cas_rejects_concurrent_active_edit(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    source = tmp_path / "source.yaml"
    active = tmp_path / "active.yaml"
    source.write_text("# guide\nconfig_version: 7\n", encoding="utf-8")
    active.write_text("config_version: 7\n", encoding="utf-8")
    source.chmod(0o600)
    active.chmod(0o600)
    program = _bridge_comment_restore_program().replace(
        "    atomic_exchange(active_path, temporary)",
        '    with open(active_path, "ab") as concurrent:\n'
        '        concurrent.write(b"# concurrent edit\\n")\n'
        "    atomic_exchange(active_path, temporary)",
        1,
    )

    completed = _run_bridge_comment_restore(source, active, program=program)

    assert completed.returncode != 0
    assert "changed before comment continuity activation" in completed.stderr
    assert active.read_bytes().endswith(b"# concurrent edit\n")


@pytest.mark.parametrize("commit_check", ["pre-unlink", "final-readback"])
@POSIX_UPGRADE_CUSTODY
def test_bridge_comment_restore_commit_checks_include_metadata(
    tmp_path: Path,
    commit_check: str,
) -> None:
    tmp_path.chmod(0o700)
    source = tmp_path / "source.yaml"
    active = tmp_path / "active.yaml"
    source.write_text("# guide\nconfig_version: 7\n", encoding="utf-8")
    active.write_text("config_version: 7\n", encoding="utf-8")
    source.chmod(0o600)
    active.chmod(0o640)
    program = _bridge_comment_restore_program()
    if commit_check == "pre-unlink":
        needle = "        committed, committed_snapshot = read_stable(active_path)"
        replacement = f"        os.chmod(active_path, 0o600)\n{needle}"
    else:
        needle = "\ncommitted, committed_snapshot = read_stable(active_path)"
        replacement = f"\nos.chmod(active_path, 0o600){needle}"
    assert program.count(needle) == 1
    program = program.replace(needle, replacement, 1)

    completed = _run_bridge_comment_restore(source, active, program=program)

    assert completed.returncode != 0
    assert "was not committed exactly" in completed.stderr


@POSIX_UPGRADE_CUSTODY
def test_bridge_comment_restore_crash_temp_is_cleaned_before_resumed_custody_closes(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    data_home = tmp_path / "data"
    openclaw_home = tmp_path / "openclaw"
    data_home.mkdir(mode=0o700)
    openclaw_home.mkdir(mode=0o700)
    source = tmp_path / "source.yaml"
    active = tmp_path / "active.yaml"
    source.write_text("# operator guide\nconfig_version: 7\n", encoding="utf-8")
    original_active = b"config_version: 7\nsecret: old-value\n"
    active.write_bytes(original_active)
    source.chmod(0o600)
    active.chmod(0o600)
    token = "a" * 32
    program = _bridge_comment_restore_program()
    needle = "    atomic_exchange(active_path, temporary)\n    swapped = True"
    assert program.count(needle) == 1
    program = program.replace(
        needle,
        "    atomic_exchange(active_path, temporary)\n    os.kill(os.getpid(), 9)\n    swapped = True",
        1,
    )

    crashed = _run_bridge_comment_restore(source, active, program=program)

    assert crashed.returncode < 0
    assert active.read_bytes() == b"# operator guide\n" + original_active
    displaced = list(tmp_path.glob(f".active.yaml.upgrade-{token}.*.tmp"))
    assert len(displaced) == 1
    assert displaced[0].read_bytes() == original_active

    cleaned = _run_phase_one_recovery_cleanup(
        data_home,
        openclaw_home,
        active,
        f"phase-one-{token}",
        openclaw_home_existed=False,
    )

    assert cleaned.returncode == 0, cleaned.stderr
    assert not displaced[0].exists()
    assert active.read_bytes() == b"# operator guide\n" + original_active


@POSIX_UPGRADE_CUSTODY
def test_resumed_cleanup_root_replacement_cannot_redirect_unlink(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    token = "a" * 32
    data_home = tmp_path / "data"
    openclaw_home = tmp_path / "openclaw"
    config_parent = tmp_path / "config-root"
    data_home.mkdir(mode=0o700)
    openclaw_home.mkdir(mode=0o700)
    config_parent.mkdir(mode=0o700)
    config_path = config_parent / "active.yaml"
    config_path.write_text("config_version: 7\n", encoding="utf-8")
    temporary_name = f".active.yaml.upgrade-{token}.owned.tmp"
    (config_parent / temporary_name).write_text("bound-sensitive-bytes\n", encoding="utf-8")
    displaced_parent = Path(f"{config_parent}.bound")
    program = _phase_one_recovery_cleanup_program()
    needle = "            cleanup_descriptor(descriptor)\n            validate_bound_descriptor("
    assert program.count(needle) == 1
    program = program.replace(
        needle,
        "            if name == 'config_parent':\n"
        "                os.rename(path, path + '.bound')\n"
        "                os.mkdir(path, 0o700)\n"
        f"                with open(os.path.join(path, {temporary_name!r}), 'w', encoding='utf-8') as stream:\n"
        "                    stream.write('replacement-must-survive\\n')\n"
        "            cleanup_descriptor(descriptor)\n"
        "            validate_bound_descriptor(",
        1,
    )

    completed = _run_phase_one_recovery_cleanup(
        data_home,
        openclaw_home,
        config_path,
        f"phase-one-{token}",
        program=program,
    )

    assert completed.returncode != 0
    assert "config_parent identity changed during temporary cleanup" in completed.stderr
    assert not (displaced_parent / temporary_name).exists()
    replacement = config_parent / temporary_name
    assert replacement.read_text(encoding="utf-8") == "replacement-must-survive\n"


@POSIX_UPGRADE_CUSTODY
def test_resumed_cleanup_entry_replacement_is_quarantined_not_deleted(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    token = "a" * 32
    data_home = tmp_path / "data"
    openclaw_home = tmp_path / "openclaw"
    config_parent = tmp_path / "config-root"
    data_home.mkdir(mode=0o700)
    openclaw_home.mkdir(mode=0o700)
    config_parent.mkdir(mode=0o700)
    config_path = config_parent / "active.yaml"
    config_path.write_text("config_version: 7\n", encoding="utf-8")
    temporary_name = f".active.yaml.upgrade-{token}.owned.tmp"
    temporary = config_parent / temporary_name
    temporary.write_text("inspected-sensitive-bytes\n", encoding="utf-8")
    program = _phase_one_recovery_cleanup_program()
    needle = "            quarantine_name = quarantine_no_replace(descriptor, entry.name, info)"
    assert program.count(needle) == 1
    program = program.replace(
        needle,
        f"            if entry.name == {temporary_name!r}:\n"
        "                os.rename(\n"
        "                    entry.name,\n"
        "                    entry.name + '.inspected',\n"
        "                    src_dir_fd=descriptor,\n"
        "                    dst_dir_fd=descriptor,\n"
        "                )\n"
        "                replacement = os.open(\n"
        "                    entry.name,\n"
        "                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,\n"
        "                    0o600,\n"
        "                    dir_fd=descriptor,\n"
        "                )\n"
        "                try:\n"
        "                    os.write(replacement, b'replacement-must-survive\\n')\n"
        "                    os.fsync(replacement)\n"
        "                finally:\n"
        "                    os.close(replacement)\n"
        f"{needle}",
        1,
    )

    completed = _run_phase_one_recovery_cleanup(
        data_home,
        openclaw_home,
        config_path,
        f"phase-one-{token}",
        program=program,
    )

    assert completed.returncode != 0
    assert "identity changed during quarantine" in completed.stderr
    inspected = config_parent / f"{temporary_name}.inspected"
    assert inspected.read_text(encoding="utf-8") == "inspected-sensitive-bytes\n"
    assert not temporary.exists()
    quarantines = list(config_parent.glob(f".defenseclaw-cleanup-{token}-*.quarantine"))
    assert len(quarantines) == 1
    assert quarantines[0].read_text(encoding="utf-8") == "replacement-must-survive\n"

    replay = _run_phase_one_recovery_cleanup(
        data_home,
        openclaw_home,
        config_path,
        f"phase-one-{token}",
    )

    assert replay.returncode != 0
    assert "quarantine identity changed before replay" in replay.stderr
    assert quarantines[0].read_text(encoding="utf-8") == "replacement-must-survive\n"


@POSIX_UPGRADE_CUSTODY
def test_resumed_cleanup_replays_matching_crash_left_quarantine(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    token = "a" * 32
    data_home = tmp_path / "data"
    openclaw_home = tmp_path / "openclaw"
    config_parent = tmp_path / "config-root"
    data_home.mkdir(mode=0o700)
    openclaw_home.mkdir(mode=0o700)
    config_parent.mkdir(mode=0o700)
    config_path = config_parent / "active.yaml"
    config_path.write_text("config_version: 7\n", encoding="utf-8")
    temporary_name = f".active.yaml.upgrade-{token}.owned.tmp"
    temporary = config_parent / temporary_name
    temporary.write_text("crash-left-sensitive-bytes\n", encoding="utf-8")
    program = _phase_one_recovery_cleanup_program()
    needle = "            quarantine_name = quarantine_no_replace(descriptor, entry.name, info)"
    assert program.count(needle) == 1
    program = program.replace(
        needle,
        f"{needle}\n            os.kill(os.getpid(), 9)",
        1,
    )

    crashed = _run_phase_one_recovery_cleanup(
        data_home,
        openclaw_home,
        config_path,
        f"phase-one-{token}",
        program=program,
    )

    assert crashed.returncode < 0
    assert not temporary.exists()
    quarantines = list(config_parent.glob(f".defenseclaw-cleanup-{token}-*.quarantine"))
    assert len(quarantines) == 1
    assert quarantines[0].read_text(encoding="utf-8") == "crash-left-sensitive-bytes\n"

    replay = _run_phase_one_recovery_cleanup(
        data_home,
        openclaw_home,
        config_path,
        f"phase-one-{token}",
    )

    assert replay.returncode == 0, replay.stderr
    assert not list(config_parent.glob(f".defenseclaw-cleanup-{token}-*.quarantine"))


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("0.8.3", False),
        ("0.8.4", False),
        ("0.8.5", True),
        ("0.9.0", True),
        ("1.0.0", True),
    ],
)
def test_only_hard_cut_targets_select_the_forward_v8_contract(target: str, expected: bool) -> None:
    completed = _source_script(
        'TARGET_VERSION="$2"; target_uses_observability_v8',
        target,
    )
    assert (completed.returncode == 0) is expected, completed.stderr


def _seed_fixture(tmp_path: Path, version: str) -> Path:
    home = tmp_path / "home"
    completed = _source_script(
        'SMOKE_HOME="$2"; FROM_VERSION="$3"; mkdir -p "$SMOKE_HOME"; seed_v8_observability_fixture',
        str(home),
        version,
    )
    assert completed.returncode == 0, completed.stderr
    return home / ".defenseclaw"


@pytest.mark.parametrize(
    ("version", "config_version"),
    [("0.8.3", 7), ("0.8.2", 6), ("0.6.6", 5)],
)
def test_v8_fixture_covers_each_historical_config_family(
    tmp_path: Path,
    version: str,
    config_version: int,
) -> None:
    data_dir = _seed_fixture(tmp_path, version)
    document = yaml.safe_load((data_dir / "config.yaml").read_text(encoding="utf-8"))

    assert document["config_version"] == config_version
    assert document["otel"]["endpoint"] == "127.0.0.1:4317"
    assert {item["name"] for item in document["otel"]["destinations"]} == {
        "existing-otlp",
        "galileo",
    }
    assert document["otel"]["logs"]["enabled"] is True
    assert document["otel"]["traces"]["enabled"] is True
    assert document["otel"]["metrics"]["enabled"] is True
    assert {item["kind"] for item in document["audit_sinks"]} == {
        "splunk_hec",
        "http_jsonl",
        "otlp_logs",
    }
    assert document["observability"]["connectors"]["codex"]["audit_sinks"] == []
    assert document["privacy"]["disable_redaction"] is False
    assert document["ai_discovery"]["emit_otel"] is False
    assert document["audit_db"].endswith("/state/audit-custom.db")
    assert document["judge_bodies_db"].endswith("/state/judge-custom.db")
    assert (data_dir / "observability-stack/operator/volume-continuity.txt").is_file()
    assert (data_dir / "observability-stack/grafana/dashboards/team-upgrade-smoke.json").is_file()
    assert (tmp_path / "home/fixture-evidence/config.historical.source").read_bytes() == (
        data_dir / "config.yaml"
    ).read_bytes()


@pytest.mark.parametrize(
    ("version", "config_version"),
    [("0.8.4", "7"), ("0.8.3", "7"), ("0.8.2", "6"), ("0.6.6", "5")],
)
def test_reviewed_baseline_config_version_lookup(
    version: str,
    config_version: str,
) -> None:
    completed = _source_script('published_baseline_config_version "$2"', version)

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == config_version


def test_baseline_config_policy_fails_closed_and_allows_pre_bridge_topology(
    tmp_path: Path,
) -> None:
    valid = {
        "schema_version": 2,
        "published_baselines": ["0.8.3", "0.8.2"],
        "published_baseline_config_versions": {"0.8.3": 7, "0.8.2": 6},
        "platform_published_baselines": {"windows": ["0.8.3", "0.8.2"]},
    }
    policy = tmp_path / "upgrade-baselines.json"
    policy.write_text(json.dumps(valid), encoding="utf-8")
    completed = _source_script(
        'UPGRADE_BASELINE_POLICY="$2"; published_baseline_config_version "$3"',
        str(policy),
        "0.8.3",
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "7"

    invalid_policies = []
    schema_one = dict(valid, schema_version=1)
    invalid_policies.append(schema_one)
    missing_map = dict(valid)
    missing_map.pop("published_baseline_config_versions")
    invalid_policies.append(missing_map)
    extra_map = json.loads(json.dumps(valid))
    extra_map["published_baseline_config_versions"]["0.8.1"] = 6
    invalid_policies.append(extra_map)
    boolean_version = json.loads(json.dumps(valid))
    boolean_version["published_baseline_config_versions"]["0.8.2"] = True
    invalid_policies.append(boolean_version)

    for index, document in enumerate(invalid_policies):
        policy.write_text(json.dumps(document), encoding="utf-8")
        completed = _source_script(
            'UPGRADE_BASELINE_POLICY="$2"; published_baseline_config_version "$3"',
            str(policy),
            "0.8.3",
        )
        assert completed.returncode != 0, (index, completed.stdout, completed.stderr)

    policy.write_text(json.dumps(valid), encoding="utf-8")
    unsupported = _source_script(
        'UPGRADE_BASELINE_POLICY="$2"; published_baseline_config_version "$3"',
        str(policy),
        "0.8.1",
    )
    assert unsupported.returncode != 0


def test_materialized_policy_accepts_config_8_but_not_newer_than_candidate(
    tmp_path: Path,
) -> None:
    effective = json.loads(BASELINE_POLICY.read_text(encoding="utf-8"))
    effective["published_baselines"].insert(0, "0.8.5")
    effective["published_baseline_config_versions"]["0.8.5"] = 8
    policy = tmp_path / "effective-upgrade-baselines.json"
    policy.write_text(json.dumps(effective), encoding="utf-8")

    accepted = _source_script(
        'UPGRADE_BASELINE_POLICY="$2"; CANDIDATE_RUNTIME_CONFIG_VERSION=8; published_baseline_config_version "$3"',
        str(policy),
        "0.8.5",
    )
    assert accepted.returncode == 0, accepted.stderr
    assert accepted.stdout.strip() == "8"

    effective["published_baseline_config_versions"]["0.8.5"] = 9
    policy.write_text(json.dumps(effective), encoding="utf-8")
    rejected = _source_script(
        'UPGRADE_BASELINE_POLICY="$2"; CANDIDATE_RUNTIME_CONFIG_VERSION=8; published_baseline_config_version "$3"',
        str(policy),
        "0.8.5",
    )
    assert rejected.returncode != 0
    assert "no newer than the candidate runtime" in rejected.stderr


def _policy_with_baseline(
    tmp_path: Path,
    version: str,
    config_version: int,
) -> Path:
    effective = json.loads(BASELINE_POLICY.read_text(encoding="utf-8"))
    effective["published_baselines"].insert(0, version)
    effective["published_baseline_config_versions"][version] = config_version
    policy = tmp_path / f"effective-{version}.json"
    policy.write_text(json.dumps(effective), encoding="utf-8")
    return policy


@pytest.mark.parametrize(
    ("source_version", "source_config", "expected_fixture"),
    [("0.8.4", 7, "legacy"), ("0.8.5", 8, "native-v8")],
)
def test_future_candidate_dispatches_fixture_by_authenticated_source_family(
    tmp_path: Path,
    source_version: str,
    source_config: int,
    expected_fixture: str,
) -> None:
    policy = (
        BASELINE_POLICY if source_version == "0.8.4" else _policy_with_baseline(tmp_path, source_version, source_config)
    )
    completed = _source_script(
        'UPGRADE_BASELINE_POLICY="$2"; CANDIDATE_RUNTIME_CONFIG_VERSION=8; '
        'TARGET_VERSION=0.8.6; FROM_VERSION="$3"; '
        'seed_v8_observability_fixture() { printf "legacy\\n"; }; '
        'seed_native_v8_observability_fixture() { printf "native-v8\\n"; }; '
        "seed_upgrade_fixture",
        str(policy),
        source_version,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == expected_fixture


def test_future_candidate_fails_closed_for_unreviewed_source_config_family(
    tmp_path: Path,
) -> None:
    policy = _policy_with_baseline(tmp_path, "0.8.6", 9)
    completed = _source_script(
        'UPGRADE_BASELINE_POLICY="$2"; CANDIDATE_RUNTIME_CONFIG_VERSION=9; '
        "TARGET_VERSION=0.8.7; FROM_VERSION=0.8.6; "
        "seed_v8_observability_fixture() { exit 91; }; "
        "seed_native_v8_observability_fixture() { exit 92; }; "
        "seed_upgrade_fixture",
        str(policy),
    )

    assert completed.returncode != 0
    assert "no reviewed upgrade fixture exists for config-v9 baseline 0.8.6" in completed.stderr


@POSIX_UPGRADE_CUSTODY
def test_native_v8_fixture_is_strict_and_later_migration_preserves_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _policy_with_baseline(tmp_path, "0.8.5", 8)
    home = tmp_path / "home"
    baseline_python = home / ".defenseclaw/.venv/bin/python"
    baseline_python.parent.mkdir(parents=True)
    interpreter = "python" if os.name == "nt" else shlex.quote(sys.executable)
    baseline_python.write_text(
        f"#!/bin/sh\nexec {interpreter} \"$@\"\n",
        encoding="utf-8",
    )
    baseline_python.chmod(0o700)

    completed = _source_script(
        'UPGRADE_BASELINE_POLICY="$2"; CANDIDATE_RUNTIME_CONFIG_VERSION=8; '
        'TARGET_VERSION=0.8.6; FROM_VERSION=0.8.5; SMOKE_HOME="$3"; '
        "seed_native_v8_observability_fixture",
        str(policy),
        str(home),
    )
    assert completed.returncode == 0, completed.stderr

    data_dir = home / ".defenseclaw"
    openclaw_home = home / ".openclaw"
    assert openclaw_home.is_dir()
    assert not openclaw_home.is_symlink()
    if os.name != "nt":
        assert stat.S_IMODE(openclaw_home.stat().st_mode) == 0o700
    config_path = data_dir / "config.yaml"
    environment_path = data_dir / ".env"
    config_before = config_path.read_bytes()
    environment_before = environment_path.read_bytes()
    gateway_token_match = re.search(
        rb"^DEFENSECLAW_GATEWAY_TOKEN=([0-9a-f]{64})$",
        environment_before,
        re.MULTILINE,
    )
    assert gateway_token_match is not None
    source = load_validate_v8(config_before, source_name=str(config_path)).source
    assert source["config_version"] == 8
    assert not {"otel", "audit_sinks", "privacy"}.intersection(source)
    destinations = {item["name"]: item for item in source["observability"]["destinations"]}
    assert set(destinations) == {"existing-otlp", "v8-http-protected"}
    assert destinations["existing-otlp"]["headers"] == {
        "Authorization": {"env": "DEFENSECLAW_V8_FIXTURE_OTLP_AUTHORIZATION"}
    }
    if os.name != "nt":
        assert stat.S_IMODE(environment_path.stat().st_mode) == 0o600
    assert (home / "fixture-evidence/config.historical.source").read_bytes() == config_before
    assert (home / "fixture-evidence/environment.historical.source").read_bytes() == environment_before
    baseline_bundle_manifest = json.loads(
        (data_dir / "observability-stack/.defenseclaw-bundle-manifest.json").read_text(encoding="utf-8")
    )
    assert baseline_bundle_manifest["bundle_version"] == "0.8.5"

    monkeypatch.setenv("DEFENSECLAW_HOME", str(data_dir))
    begin_upgrade_receipt(
        str(data_dir),
        from_version="0.8.5",
        target_version="0.8.6",
        artifacts_verified=True,
    )
    count = run_migrations(
        "0.8.5",
        "0.8.6",
        str(home / ".openclaw"),
        str(data_dir),
        upgrade_handles_local_bundle=True,
    )
    assert count == 0
    assert config_path.read_bytes() == config_before
    assert environment_path.read_bytes() == environment_before
    refreshed_bundle_manifest = json.loads(
        (data_dir / "observability-stack/.defenseclaw-bundle-manifest.json").read_text(encoding="utf-8")
    )
    assert refreshed_bundle_manifest["bundle_version"] == "0.8.6"
    cursor = json.loads((data_dir / ".migration_state.json").read_text(encoding="utf-8"))
    assert "0.8.5" in cursor["applied"]


def test_harnesses_accept_one_materialized_policy_snapshot() -> None:
    posix = SCRIPT.read_text(encoding="utf-8")
    windows = (ROOT / "scripts/test-upgrade-release-windows.ps1").read_text(encoding="utf-8")

    assert 'UPGRADE_BASELINE_POLICY="${UPGRADE_BASELINE_POLICY:-' in posix
    assert "[string]$BaselinePolicy" in windows
    assert "$env:UPGRADE_BASELINE_POLICY" in windows
    assert "$script:UpgradeBaselinePolicy" in windows


def test_v8_verifier_proves_historical_and_bridge_backup_layers() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    for contract in (
        "config.historical.source",
        "phase1-source-gateway",
        "phase two retained no distinct byte-exact config-v7 bridge backup",
        'receipt_from="${REQUIRED_BRIDGE_VERSION}"',
    ):
        assert contract in text
    assert 'facts.get("from_version") != source' in RECEIPT_CHECK.read_text(encoding="utf-8")


def test_hard_cut_source_tree_ships_the_v8_runtime_and_forward_keyed_migration() -> None:
    package = ROOT / "cli" / "defenseclaw"
    assert (package / "observability" / "v8_migration.py").is_file()
    assert (package / "observability" / "v8_activation.py").is_file()

    migrations = (package / "migrations.py").read_text(encoding="utf-8")
    assert "SUPPORTED_CONFIG_VERSIONS: tuple[int, ...] = (8,)" in migrations
    migration_key = migrations.index('"0.8.5",')
    migration_handler = migrations.index("_migrate_observability_v8,", migration_key)
    assert migration_key < migration_handler


def test_matrix_matches_every_reviewed_published_baseline_and_schema() -> None:
    line = next(
        line for line in MAKEFILE.read_text(encoding="utf-8").splitlines() if line.startswith("UPGRADE_SMOKE_FROM")
    )
    policy = json.loads(BASELINE_POLICY.read_text(encoding="utf-8"))
    baselines = policy["published_baselines"]

    assert policy["schema_version"] == 2
    assert line.strip() == "UPGRADE_SMOKE_FROM ?="
    makefile = MAKEFILE.read_text(encoding="utf-8")
    assert "target_version=''" in makefile
    assert "dynamic upgrade matrix requires" in makefile
    assert '--target-version "$$target_version"' in makefile
    assert '--target-version=*) target_version="$${1#--target-version=}"' in makefile
    assert baselines[0] == "0.8.4"
    assert policy["published_baseline_config_versions"] == {
        "0.8.4": 7,
        "0.8.3": 7,
        "0.8.2": 6,
        "0.8.1": 6,
        "0.8.0": 6,
        "0.7.2": 6,
        "0.7.1": 6,
        "0.6.6": 5,
        "0.6.5": 5,
        "0.6.4": 5,
        "0.6.3": 5,
        "0.6.2": 5,
        "0.6.1": 5,
        "0.6.0": 5,
        "0.5.0": 5,
        "0.4.0": 5,
    }
    assert policy["platform_published_baselines"]["windows"] == [
        "0.8.3",
        "0.8.2",
        "0.8.1",
        "0.8.0",
    ]


def test_bridge_harness_keeps_v8_source_contracts_strictly_target_gated() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    assert "run_v8_source_contract_tests" in script
    assert 'WORKDIR="$(abs_path "$(mktemp -d ' in script
    function_start = script.index("run_v8_source_contract_tests()")
    gate = script.index("target_uses_observability_v8 || return 0", function_start)
    resource_stage = script.index("scripts/telemetry_runtime_assets.py", function_start)
    pytest_call = script.index("uv run python -m pytest", function_start)
    failure_tail = script.index('tail_log "${result_log}"', pytest_call)
    assert gate < resource_stage < pytest_call < failure_tail
    assert 'if [[ "${BASH_SOURCE[0]}" == "$0" ]]' in script


def test_historical_release_matrices_do_not_repeat_source_contract_suite() -> None:
    workflow = PRE_RELEASE_CERTIFICATION.read_text(encoding="utf-8")
    linux = workflow[workflow.index("  linux-upgrade:") : workflow.index("  macos-upgrade:")]
    macos = workflow[workflow.index("  macos-upgrade:") : workflow.index("  windows-unpublished-refusal:")]
    for job in (linux, macos):
        assert job.count('UPGRADE_SMOKE_SKIP_SOURCE_CONTRACTS: "1"') == 1


def test_success_receipt_verifier_uses_canonical_audit_and_queue_acknowledgement() -> None:
    harness = SCRIPT.read_text(encoding="utf-8")
    protocol = PROTOCOL_SCRIPT.read_text(encoding="utf-8")
    verifier = RECEIPT_CHECK.read_text(encoding="utf-8")

    assert "scripts/check_upgrade_receipt.py" in harness
    assert 'REQUIRED_BRIDGE_VERSION="${REQUIRED_BRIDGE_VERSION:-}"' in harness
    assert "expected exactly one terminal target receipt" not in harness
    assert "expected one native-v8 target receipt" not in harness
    assert "assert_staged_success_receipt" not in protocol
    assert "FROM audit_events" in verifier
    assert "canonical target receipt" in verifier
    assert "if not queued_target and remaining > 0:" in verifier


def test_harness_embedded_python_and_v8_verifier_contract_are_static_valid() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    assert 'cosign_command="$(command -v cosign)"' in script
    assert 'cosign_path="$(abs_path "${cosign_command}")"' in script
    for path in (SCRIPT, DEVELOPER_ACTIVATION_SCRIPT):
        lines = path.read_text(encoding="utf-8").splitlines()
        programs: list[str] = []
        index = 0
        while index < len(lines):
            if re.search(r"<<'PY'\s*$", lines[index]):
                end = index + 1
                while end < len(lines) and lines[end] != "PY":
                    end += 1
                assert end < len(lines), f"unterminated Python heredoc after line {index + 1}"
                programs.append("\n".join(lines[index + 1 : end]) + "\n")
                index = end
            index += 1

        assert programs
        for program in programs:
            compile(program, str(path), "exec")
    for verifier_contract in (
        'config.get("config_version") != 8',
        'for legacy in ("otel", "audit_sinks", "privacy")',
        '"DEFENSECLAW_MIGRATED_SPLUNK_PROTECTED_TOKEN"',
        'glob("observability-v8-*/manifest.json")',
        'bundle_manifest.get("bundle_version") != target_version',
        "defenseclaw-gateway status",
        "DOCKER_HOST=",
        "prepare_isolated_docker_path",
        "upgrade smoke docker isolation forbids mutating operations",
        "tail_v8_upgrade_log_secret_safe",
        "config_v8_native_fixture=byte_exact",
        "native-v8 source unexpectedly ran the v7-to-v8 activation",
        "native-v8 fixture OpenClaw home mode changed across the upgrade",
        "local bundle manifest differs from the complete target package",
    ):
        assert verifier_contract in script

    developer = DEVELOPER_ACTIVATION_SCRIPT.read_text(encoding="utf-8")
    assert "legacy_source = source_config_version < 8" in developer
    assert "native-v8 source unexpectedly ran the v7-to-v8 activation" in developer
    assert "developer fixture OpenClaw home mode changed across target activation" in developer
    assert "developer_target_native_v8_continuity=" in developer


def test_prepare_only_windows_candidate_validates_zip_and_plain_refusal_envelope() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert "windows/amd64|windows/arm64" in script
    assert 'extension = "zip" if os_name == "windows" else "tar.gz"' in script
    assert "with zipfile.ZipFile(gateway_source) as archive:" in script
    assert 'Path(member.filename.replace("\\\\", "/")).is_absolute()' in script
    assert 'Path(member.filename.replace("\\\\", "/")).name == "defenseclaw.exe"' in script
    assert "canonical Windows gateway refusal envelope became installable" in script


def test_bridge_candidate_refusal_contract_uses_bridge_specific_message() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert 'if version == "0.8.4":' in script
    assert "DefenseClaw 0.8.4 must be installed by the release-owned staged upgrade resolver." in script


def test_retired_named_otel_backup_is_checked_only_for_pre_v8_targets() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    assert script.count("config.yaml.pre-observability-migration.bak") == 1


@pytest.mark.skipif(
    os.name == "nt",
    reason="the isolated Docker shim exercises the POSIX upgrade harness",
)
def test_docker_isolation_reports_stopped_fixture_and_forbids_mutation(tmp_path: Path) -> None:
    home = tmp_path / "home"
    completed = _source_script(
        'SMOKE_HOME="$2"; mkdir -p "$SMOKE_HOME"; prepare_isolated_docker_path; '
        'PATH="$SMOKE_HOME/.upgrade-test-bin:$PATH"; docker ps; docker compose down',
        str(home),
    )

    assert completed.returncode == 125
    assert "forbids mutating operations" in completed.stderr


def test_v8_failure_tail_redacts_every_fixture_value(tmp_path: Path) -> None:
    gateway_token = "a" * 64
    protected = (
        "upgrade-smoke-flat-protected-value",
        "upgrade-smoke-splunk-protected-value",
        "upgrade-smoke-http-protected-value",
        "Bearer upgrade-smoke-otlp-protected-value",
        gateway_token,
    )
    smoke_home = tmp_path / "home"
    evidence = smoke_home / "fixture-evidence"
    evidence.mkdir(parents=True)
    (evidence / "environment.historical.source").write_text(
        f"DEFENSECLAW_GATEWAY_TOKEN={gateway_token}\n",
        encoding="utf-8",
    )
    log = tmp_path / "upgrade.log"
    log.write_text("\n".join(protected) + "\nordinary diagnostic\n", encoding="utf-8")

    completed = _source_script(
        'SMOKE_HOME="$2"; tail_v8_upgrade_log_secret_safe "$3"',
        str(smoke_home),
        str(log),
    )

    assert completed.returncode == 0
    assert "ordinary diagnostic" in completed.stderr
    assert "[REDACTED]" in completed.stderr
    assert all(value not in completed.stderr for value in protected)


def test_v8_known_regression_marker_uses_redacted_tail() -> None:
    """A successful command with a regression marker must not leak v8 secrets."""
    script = SCRIPT.read_text(encoding="utf-8")
    function_start = script.index("run_upgrade()")
    function_end = script.index("\nverify_upgrade()", function_start)
    function_body = script[function_start:function_end]
    marker_start = function_body.index('if grep -E "Traceback|AttributeError|Required migration')
    marker_failure = function_body[marker_start:]

    assert (
        'if target_uses_observability_v8; then\n            tail_v8_upgrade_log_secret_safe "${SMOKE_HOME}/upgrade.log"'
        in marker_failure
    )
    assert 'else\n            tail_log "${SMOKE_HOME}/upgrade.log"' in marker_failure
