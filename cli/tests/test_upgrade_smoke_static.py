# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
UPGRADE_SMOKE_BASELINES = (
    "0.8.4",
    "0.8.3",
    "0.8.2",
    "0.8.1",
    "0.8.0",
    "0.7.2",
    "0.7.1",
    "0.6.6",
    "0.6.5",
    "0.6.4",
    "0.6.3",
    "0.6.2",
    "0.6.1",
    "0.6.0",
    "0.5.0",
    "0.4.0",
)


def test_makefile_upgrade_smoke_matrix_tracks_supported_baselines() -> None:
    text = (ROOT / "Makefile").read_text()
    match = re.search(r"^UPGRADE_SMOKE_FROM \?= (.+)$", text, re.MULTILINE)
    assert match is not None
    assert tuple(match.group(1).split()) == UPGRADE_SMOKE_BASELINES

    policy = json.loads((ROOT / "release" / "upgrade-baselines.json").read_text())
    assert tuple(policy["published_baselines"]) == UPGRADE_SMOKE_BASELINES

    assert "upgrade-refusal-contract-matrix: upgrade-smoke-matrix" in text
    assert (
        'scripts/test-upgrade-protocol-release.sh --from-versions "$(UPGRADE_SMOKE_FROM)" '
        "--refusal-contract-only $(ARGS)"
    ) in text
    assert "upgrade-legacy-smoke-matrix:" in text
    assert 'scripts/test-upgrade-release.sh --from-versions "$(UPGRADE_SMOKE_FROM)" $(ARGS)' in text
    assert "upgrade-signed-protocol-matrix:" in text


def test_upgrade_smoke_docs_cover_default_matrix() -> None:
    text = (ROOT / "docs" / "TESTING.md").read_text()
    default_line = next(line for line in text.splitlines() if line.startswith("The default matrix covers"))
    for version in UPGRADE_SMOKE_BASELINES:
        assert f"`{version}`" in default_line


def test_upgrade_smoke_help_example_includes_latest_0_8_releases() -> None:
    text = (ROOT / "scripts" / "test-upgrade-release.sh").read_text()
    assert "0.8.3,0.8.2,0.8.1,0.8.0" in text


def test_future_release_smoke_builds_from_isolated_version_stamped_source() -> None:
    text = (ROOT / "scripts" / "test-upgrade-release.sh").read_text()
    build_start = text.index("build_candidate_release() {")
    build_end = text.index("\n}\n\nprepare_release_root()", build_start)
    build = text[build_start:build_end]

    assert 'build_root="${WORKDIR}/stamped-source"' in build
    assert "shutil.copytree(source, destination, symlinks=True, ignore=ignore)" in build
    assert '"${build_root}/scripts/stamp-version.sh" "${TARGET_VERSION}"' in build
    assert 'make -C "${build_root}" check-version-sync' in build
    assert 'make -C "${build_root}" dist-cli' in build
    assert 'make -C "${build_root}" dist-plugin' in build
    assert '"${build_root}/scripts/generate-upgrade-manifest.py"' in build
    assert '"${build_root}/scripts/release_candidate.py" prepare-runtime' in build
    assert '"${build_root}/scripts/release_candidate.py" verify-runtime' in build
    assert '"${build_root}/scripts/release_candidate.py" stage-resolvers' in build
    assert "for fixture_os in darwin linux windows; do" in build
    assert 'GOOS="${fixture_os}" GOARCH="${fixture_arch}"' in build
    assert 'make -C "${ROOT}" dist-cli' not in build

    assert "fresh_install_tool_path()" in text
    assert 'baseline_path="$(fresh_install_tool_path)"' in text
    assert 'PATH="${SMOKE_HOME}/.local/bin:${baseline_path}"' in text


def test_historical_baselines_are_authenticated_and_real_dependency_mode_is_explicit() -> None:
    smoke = (ROOT / "scripts" / "test-upgrade-release.sh").read_text()
    protocol = (ROOT / "scripts" / "test-upgrade-protocol-release.sh").read_text()

    assert "stage_authenticated_baseline" in smoke
    assert 'scripts/historical_release_auth.py"' in smoke
    assert "checksums.txt.sig" in smoke
    assert "checksums.txt.pem" in smoke
    assert "--proto '=https'" in smoke
    assert 'BASELINE_DEPENDENCIES="${BASELINE_DEPENDENCIES:-target}"' in smoke
    assert 'if [[ "${BASELINE_DEPENDENCIES}" == "published" ]]' in smoke
    assert 'pip install --python "${venv_python}" --quiet "${installed_old_wheel}"' in smoke
    assert 'pip check --python "${venv_python}"' in smoke
    assert "Resolved the published ${FROM_VERSION} wheel's own dependency graph" in smoke
    assert "start_source_gateway_canary" in smoke
    assert "is version-bound healthy before resolver handoff" in smoke
    assert 'stage_authenticated_baseline "${baseline}"' in protocol
    assert "required bridge authentication failed" in protocol
    assert 'if [[ "${SUCCESS_PATH_ONLY}" == "1" ]]' in protocol


def test_pre_v8_positive_upgrade_fixture_is_hermetic_and_non_mutating() -> None:
    smoke = (ROOT / "scripts" / "test-upgrade-release.sh").read_text()
    start = smoke.index("seed_pre_v8_otel_fixture() {")
    end = smoke.index("\n}\n\nseed_v8_observability_fixture()", start)
    fixture = smoke[start:end]

    assert "guardrail:\n  enabled: false" in fixture
    assert "gateway:\n  fleet_mode: disabled" in fixture
    assert "watcher:\n    enabled: false" in fixture

    resolver = (ROOT / "scripts" / "upgrade.sh").read_text()
    assert '"${GW_STATE}" == "running" || "${GW_STATE}" == "disabled"' in resolver
    assert '"${GW_VERSION}" == "${RELEASE_VERSION}"' in resolver
    assert "fleet uplink is disabled by configuration" in resolver
    assert 'gateway_health.get("state") in {"running", "disabled"}' in resolver
    assert 'gateway.get("state") in {"running", "disabled"}' in resolver
    assert '"${health_state}" == "running" || "${health_state}" == "disabled"' in resolver
    assert '[[ "${health_state}" == "unreachable" ]]' in resolver
    assert "health_probe.returncode != 7" in resolver
    assert "gateway health endpoint was not proven unreachable during phase-one recovery" in resolver
    assert "The source health endpoint is not proven unreachable (${health_state})" in resolver
    post_stop = resolver[
        resolver.index('post_stop_health="$(bridge_source_health_observation)"') : resolver.index(
            "bridge_phase1_state_transaction snapshot"
        )
    ]
    assert 'post_stop_state="${post_stop_health%%$\'\\t\'*}"' in post_stop
    assert '[[ "${post_stop_state}" == "unreachable" ]]' in post_stop
    assert "remains live without PID custody after stop" in post_stop


def _posix_protected_materializer_program() -> str:
    resolver = (ROOT / "scripts" / "upgrade.sh").read_text(encoding="utf-8")
    function = resolver.index("materialize_protected_artifact() {")
    start = resolver.index("<<'PY'\n", function) + len("<<'PY'\n")
    end = resolver.index("\nPY\n}", start)
    return resolver[start:end]


def test_posix_production_materializer_binds_opened_outer_bytes_to_signed_digest(
    tmp_path: Path,
) -> None:
    program = _posix_protected_materializer_program()
    magic = b"DEFENSECLAW-PROTECTED-ARTIFACT-V1\n"
    payload = b"release wheel payload"
    source = tmp_path / "artifact.dcwheel"
    source.write_bytes(magic + bytes(value ^ 0xA5 for value in payload))
    destination = tmp_path / "artifact.whl"
    expected = hashlib.sha256(source.read_bytes()).hexdigest()

    completed = subprocess.run(
        [sys.executable, "-c", program, str(source), str(destination), expected],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert destination.read_bytes() == payload

    mismatch_destination = tmp_path / "mismatch.whl"
    refused = subprocess.run(
        [sys.executable, "-c", program, str(source), str(mismatch_destination), "0" * 64],
        capture_output=True,
        text=True,
        check=False,
    )
    assert refused.returncode != 0
    assert "changed after checksum authentication" in refused.stderr
    assert not mismatch_destination.exists()


def test_posix_resolver_bootstraps_recovery_under_fixed_mutator_lease() -> None:
    text = (ROOT / "scripts" / "upgrade.sh").read_text()
    header = text.index("# ── Platform Detection")
    recovery_call = text.rfind("recover_interrupted_phase_two", 0, header)
    version_detection = text.index('CURRENT_VERSION="unknown"')

    assert recovery_call != -1
    assert recovery_call < version_detection
    assert "phase-two-mutator.lease" in text
    assert "fcntl.flock(descriptor, fcntl.LOCK_EX)" in text
    assert 'document.get("schema_version") != 4' in text
    assert '"source_gateway_was_running"' in text
    assert '"local_bundle_mutation_intent"' in text
    assert '"--offline", "--no-deps", "--reinstall", str(wheel)' in text
    assert "_recover_interrupted_hard_cut" in text


def test_posix_same_version_noop_reports_actual_provenance_before_mutation() -> None:
    text = (ROOT / "scripts" / "upgrade.sh").read_text(encoding="utf-8")
    contract = text.rindex(
        'FINAL_RELEASE_PROVENANCE_BRIDGE_CHECKSUMS_SHA256="${RELEASE_PROVENANCE_BRIDGE_CHECKSUMS_SHA256}"'
    )
    no_op = text.index('section "Version Already Verified"', contract)
    backup = text.index('section "Creating Backup"', no_op)
    block = text[no_op:backup]

    assert contract < no_op < backup
    assert "release contract" in block
    assert 'if [[ "${CHECKSUMS_SIGNATURE_VERIFIED}" -eq 1 ]]' in block
    assert "legacy release has no authenticated Sigstore provenance" in block
    assert "No backup, receipt, service stop, artifact install, or migration was performed" in block
    assert "exit 0" in block
    assert "continuing to re-apply" not in text
    assert "Do not force ${MANIFEST_REQUIRED_BRIDGE}" in text
    assert "Remain on ${CURRENT_VERSION} and contact DefenseClaw support" in text


def test_bridge_controller_hard_cut_establishes_rollback_custody_before_mutation() -> None:
    command = (ROOT / "cli/defenseclaw/commands/cmd_upgrade.py").read_text(encoding="utf-8")
    gate_call = command.index("_require_release_owned_hard_cut_handoff(", command.index("def upgrade("))
    acquisition = command.index("_acquire_bridge_rollback_artifacts(", gate_call)
    backup = command.index('ux.banner("Creating Backup")', acquisition)
    assert gate_call < acquisition < backup

    main = (ROOT / "cli/defenseclaw/main.py").read_text(encoding="utf-8")
    journal_guard = main.index("if any(os.path.lexists(path) for path in recovery_journals):")
    guard_end = main.index("if invoked in SKIP_LOAD_COMMANDS", journal_guard)
    guarded = main[journal_guard:guard_end]
    assert '"phase-one-active.json"' in main[:journal_guard]
    assert '"phase-two-active.json"' in main[:journal_guard]
    assert "_recover_interrupted_hard_cut" not in guarded
    assert "no recovery mutation was attempted" in guarded
    assert "--version/-Version" in guarded
    assert "upgrade.sh | bash" not in guarded
    assert "authenticated_resolver_instructions" in guarded
    config_load = main.index("app.cfg = cfg_mod.load()", guard_end)
    storeless_upgrade = main.index('if invoked == "upgrade":', config_load)
    store_import = main.index("from defenseclaw.db import Store", storeless_upgrade)
    assert config_load < storeless_upgrade < store_import
    assert "a refused direct upgrade must not create or alter audit.db" in main

    posix_resolver = (ROOT / "scripts/upgrade.sh").read_text(encoding="utf-8")
    windows_resolver = (ROOT / "scripts/upgrade.ps1").read_text(encoding="utf-8")
    marker = "# DefenseClaw upgrade resolver complete v1"
    assert posix_resolver.rstrip().endswith(marker)
    assert windows_resolver.rstrip().endswith(marker)


@pytest.mark.skipif(os.name == "nt", reason="POSIX resolver terminal proof")
@pytest.mark.parametrize(
    ("status", "source_running", "gateway_status", "should_clear"),
    [
        ("succeeded", True, 0, True),
        ("rolled_back", True, 0, True),
        ("rolled_back", False, 1, True),
        ("rolled_back", False, 0, False),
    ],
)
def test_posix_terminal_journal_is_cleared_only_after_exact_state_proof(
    tmp_path: Path,
    status: str,
    source_running: bool,
    gateway_status: int,
    should_clear: bool,
) -> None:
    resolver = (ROOT / "scripts/upgrade.sh").read_text(encoding="utf-8")
    marker = 'recovery_fields="$(python3 - "${journal}" "${DEFENSECLAW_HOME}" <<\'PY\'\n'
    start = resolver.index(marker) + len(marker)
    end = resolver.index('\nPY\n)" || die', start)
    parser = resolver[start:end]

    home = tmp_path / "home"
    controller_home = home / "controller-home"
    data = home / "managed-data"
    recovery = controller_home / ".upgrade-recovery"
    backup = data / "backups/upgrade-test"
    custody = backup / "hard-cut-rollback"
    receipts = data / ".upgrade-receipts"
    gateway = home / ".local/bin/defenseclaw-gateway"
    config = controller_home / "config.yaml"
    venv_python = controller_home / ".venv/bin/python"
    for directory in (recovery, custody, receipts, gateway.parent, venv_python.parent):
        directory.mkdir(parents=True, exist_ok=True)
    recovery.chmod(0o700)

    source = "0.8.4"
    target = "0.8.5"
    expected = target if status == "succeeded" else source
    gateway.write_text(
        "#!/bin/sh\n"
        f'[ "${{DEFENSECLAW_HOME:-}}" = {str(data)!r} ] || exit 91\n'
        f'[ "${{DEFENSECLAW_CONFIG:-}}" = {str(config)!r} ] || exit 92\n'
        f'if [ "${{1:-}}" = status ]; then exit {gateway_status}; fi\n'
        f"echo 'defenseclaw-gateway version {expected}'\n",
        encoding="utf-8",
    )
    gateway.chmod(0o755)
    venv_python.write_text(f"#!/bin/sh\necho '{expected}'\n", encoding="utf-8")
    venv_python.chmod(0o755)
    config.write_text(f"config_version: 8\ndata_dir: {data}\n", encoding="utf-8")
    wheel = custody / "bridge.whl"
    wheel.write_bytes(b"authenticated bridge wheel")
    wheel_digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    receipt_id = "12345678-1234-4234-8234-123456789abc"
    receipt = receipts / "receipt.json"
    receipt.write_text(
        json.dumps(
            {
                "receipt_id": receipt_id,
                "from_version": source,
                "target_version": target,
                "status": status,
            }
        ),
        encoding="utf-8",
    )
    journal = recovery / "phase-two-active.json"
    state_paths = [
        str(config),
        str(config) + ".pre-observability-migration.bak",
        str(config) + ".lock",
        str(config) + ".tmp-f3395",
        str(data / ".env"),
        str(data / ".env.lock"),
        str(data / ".migration_state.json"),
    ]
    state_files = [
        {
            "active_path": path,
            "backup_path": None,
            "existed": False,
            "sha256": None,
            "mode": None,
            "windows_security": None,
        }
        for path in state_paths
    ]
    provenance = {
        "schema_version": 1,
        "release_version": target,
        "source_commit": "1" * 40,
        "source_tree": "2" * 40,
        "policy_commit": "3" * 40,
        "policy_tree": "4" * 40,
        "release_source_map_sha256": "5" * 64,
        "source_install_identity": {
            "schema_version": 1,
            "source_release": target,
            "source_install_compatibility_epoch": 2,
            "runtime_config_version": 8,
        },
        "bridge": {
            "version": source,
            "commit": "6" * 40,
            "tree": "7" * 40,
            "checksums_sha256": "8" * 64,
        },
    }
    provenance_sha256 = hashlib.sha256((json.dumps(provenance, indent=2, sort_keys=True) + "\n").encode()).hexdigest()
    receipt_binding = hashlib.sha256(
        json.dumps(
            {
                "schema_version": 1,
                "receipt_id": receipt_id,
                "source_version": source,
                "target_version": target,
                "release_provenance_sha256": provenance_sha256,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    journal.write_text(
        json.dumps(
            {
                "schema_version": 4,
                "source_version": source,
                "source_gateway_was_running": source_running,
                "local_bundle_mutation_intent": False,
                "target_version": target,
                "os_name": "darwin" if sys.platform == "darwin" else "linux",
                "recovery_home": str(controller_home),
                "data_dir": str(data),
                "backup_dir": str(backup),
                "receipt_path": str(receipt),
                "release_provenance_sha256": provenance_sha256,
                "release_provenance": provenance,
                "receipt_provenance_binding_sha256": receipt_binding,
                "rollback_wheel_path": str(wheel),
                "rollback_wheel_sha256": wheel_digest,
                "rollback_gateway_path": str(custody / "gateway"),
                "rollback_gateway_sha256": "0" * 64,
                "active_gateway_path": str(gateway),
                "gateway_snapshot": {},
                "state_files": state_files,
                "backup_root_snapshot": {
                    "active_path": str(backup.parent),
                    "device": backup.parent.stat().st_dev,
                    "inode": backup.parent.stat().st_ino,
                    "mode": stat.S_IMODE(backup.parent.stat().st_mode),
                    "preexisting_recovery_entries": [],
                    "windows_security": None,
                },
            }
        ),
        encoding="utf-8",
    )
    journal.chmod(0o600)

    completed = subprocess.run(
        [sys.executable, "-c", parser, str(journal), str(controller_home)],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "HOME": str(home)},
    )

    if should_clear:
        assert completed.returncode == 0, completed.stderr
        assert completed.stdout.strip() == "terminal"
        assert not journal.exists()
    else:
        assert completed.returncode != 0
        assert journal.exists()
