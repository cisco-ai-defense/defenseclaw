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
    text = (ROOT / "Makefile").read_text(encoding="utf-8")
    match = re.search(r"^UPGRADE_SMOKE_FROM \?= (.+)$", text, re.MULTILINE)
    assert match is not None
    assert tuple(match.group(1).split()) == UPGRADE_SMOKE_BASELINES

    policy = json.loads(
        (ROOT / "release" / "upgrade-baselines.json").read_text(encoding="utf-8")
    )
    assert tuple(policy["published_baselines"]) == UPGRADE_SMOKE_BASELINES

    assert "upgrade-refusal-contract-matrix: upgrade-smoke-matrix" in text
    assert "upgrade-developer-activation:" in text
    assert "scripts/test-developer-target-activation.sh $(ARGS)" in text
    assert (
        'scripts/test-upgrade-protocol-release.sh --from-versions "$(UPGRADE_SMOKE_FROM)" '
        "--refusal-contract-only $(ARGS)"
    ) in text
    assert "upgrade-legacy-smoke-matrix:" in text
    assert 'scripts/test-upgrade-release.sh --from-versions "$(UPGRADE_SMOKE_FROM)" $(ARGS)' in text
    assert "upgrade-signed-protocol-matrix:" in text


def test_upgrade_smoke_docs_cover_default_matrix() -> None:
    text = (ROOT / "docs" / "TESTING.md").read_text(encoding="utf-8")
    default_line = next(line for line in text.splitlines() if line.startswith("The default matrix covers"))
    for version in UPGRADE_SMOKE_BASELINES:
        assert f"`{version}`" in default_line


def test_upgrade_smoke_help_example_includes_latest_0_8_releases() -> None:
    text = (ROOT / "scripts" / "test-upgrade-release.sh").read_text(encoding="utf-8")
    assert "0.8.5,0.8.4,0.8.3,0.8.2,0.8.1,0.8.0" in text


def test_future_release_smoke_builds_from_isolated_version_stamped_source() -> None:
    text = (ROOT / "scripts" / "test-upgrade-release.sh").read_text(encoding="utf-8")
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
    smoke = (ROOT / "scripts" / "test-upgrade-release.sh").read_text(encoding="utf-8")
    protocol = (ROOT / "scripts" / "test-upgrade-protocol-release.sh").read_text(
        encoding="utf-8"
    )

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


def test_unsigned_refusal_contract_distinguishes_modern_provenance_from_legacy_schema() -> None:
    protocol = (ROOT / "scripts" / "test-upgrade-protocol-release.sh").read_text(
        encoding="utf-8"
    )

    assert 'installed_refusal_mode="artifact-provenance"' in protocol
    assert 'elif [[ "${REFUSAL_CONTRACT_ONLY}" == "1" ]] && ! candidate_has_checksum_signature' in protocol
    assert (
        "--allow-unverified cannot bypass mandatory 0.8.4+ manifest or artifact provenance checks"
        in protocol
    )
    assert "checksums.txt is not signed (no Sigstore signature/certificate assets were published)" in protocol
    assert "Modern release provenance is mandatory; --allow-unverified cannot override it." in protocol


def test_live_continuity_local_candidate_models_strict_sigstore_boundary_only() -> None:
    continuity = (
        ROOT / "scripts" / "test-observability-v8-upgrade-continuity.sh"
    ).read_text(encoding="utf-8")

    fixture_start = continuity.index("prepare_local_candidate_provenance_fixture() {")
    fixture_end = continuity.index(
        "\n}\n\nassert_local_candidate_provenance_verified()", fixture_start
    )
    fixture = continuity[fixture_start:fixture_end]
    main = continuity[continuity.index("main_continuity() {") :]

    assert '[[ "${LOCAL_CANDIDATE_PROVENANCE_FIXTURE}" == "1" ]]' in fixture
    assert 'if [[ -z "${RELEASE_ROOT}" && -z "${RELEASE_DIR}" ]]' in main
    assert 'LOCAL_CANDIDATE_PROVENANCE_FIXTURE="1"' in main
    assert "--certificate-identity" in fixture
    assert (
        "https://github.com/cisco-ai-defense/defenseclaw/.github/workflows/"
        "release.yaml@refs/heads/main"
    ) in fixture
    assert "--certificate-oidc-issuer" in fixture
    assert "https://token.actions.githubusercontent.com" in fixture
    assert '[[ "$#" -eq 10 ]]' in fixture
    assert "assert_local_candidate_provenance_verified" in main


def test_live_continuity_reopens_v8_database_with_actual_published_bridge_binary() -> None:
    continuity = (
        ROOT / "scripts" / "test-observability-v8-upgrade-continuity.sh"
    ).read_text(encoding="utf-8")
    start = continuity.index(
        "assert_published_bridge_binary_sqlite_rollback_compatibility() {"
    )
    end = continuity.index("\n}\n\nresolve_continuity_upgrade_contract()", start)
    compatibility = continuity[start:end]
    main = continuity[continuity.index("main_continuity() {") :]

    # The gate is specifically bound to the immutable POSIX 0.8.4 bridge and
    # the material retained only after historical_release_auth.py succeeds.
    assert '[[ "${FROM_VERSION}" == "0.8.4" ]]' in compatibility
    assert 'darwin|linux) ;;' in compatibility
    assert (
        'bridge_gateway="${WORKDIR}/old-gateway/${FROM_VERSION}/defenseclaw"'
        in compatibility
    )
    assert (
        'auth_marker="${WORKDIR}/published-release/${FROM_VERSION}/'
        '.authenticated-${OS_NAME}-${ARCH_NAME}"'
        in compatibility
    )
    assert '"${bridge_gateway}" --version | grep -F "${FROM_VERSION}"' in compatibility

    # It restores the byte-preserved source config while keeping one exact DB
    # path, then proves target-created correlation tables exist before boot.
    assert 'v7_config="${SMOKE_HOME}/fixture-evidence/config.v7.source"' in compatibility
    assert 'audit_db="${data_dir}/state/audit.db"' in compatibility
    for table in (
        "correlation_events",
        "correlation_identifiers",
        "correlation_identity_claims",
        "correlation_observations",
        "correlation_relationships",
        "correlation_relationship_evidence",
        "correlation_cursors",
        "correlation_pending_operations",
        "correlation_receipts",
    ):
        assert f'"{table}"' in compatibility
    assert 'stop_smoke_gateway\n    cp -p "${v7_config}"' in compatibility

    # Health is provenance-bound, and the old API itself performs both the
    # authenticated write and read. SQLite then verifies exact old-binary
    # provenance without putting the token in argv or evidence files.
    assert 'provenance.get("binary_version") != sys.argv[2]' in compatibility
    assert '"http://127.0.0.1:18970/audit/event"' in compatibility
    assert '"http://127.0.0.1:18970/alerts?limit=500"' in compatibility
    assert '"X-DefenseClaw-Client": "upgrade-continuity-gate"' in compatibility
    assert 'event.get("binary_version") == "0.8.4"' in compatibility
    assert "SELECT COUNT(*), COALESCE(MAX(binary_version), '')" in compatibility

    # The target config and binary are restored and health-checked before the
    # ordinary post-upgrade history/dashboard assertions continue.
    assert 'cp -p "${v8_config}" "${data_dir}/config.yaml"' in compatibility
    assert '"${target_gateway}" start' in compatibility
    activation = main.index("verify_target_activation")
    old_binary_probe = main.index(
        "assert_published_bridge_binary_sqlite_rollback_compatibility"
    )
    post_emit = main.index("emit_continuity_phase post")
    assert activation < old_binary_probe < post_emit


def test_pre_v8_positive_upgrade_fixture_is_hermetic_and_non_mutating() -> None:
    smoke = (ROOT / "scripts" / "test-upgrade-release.sh").read_text(encoding="utf-8")
    start = smoke.index("seed_pre_v8_otel_fixture() {")
    end = smoke.index("\n}\n\nfinalize_observability_upgrade_fixture()", start)
    fixture = smoke[start:end]

    assert "guardrail:\n  enabled: false" in fixture
    assert "gateway:\n  fleet_mode: disabled" in fixture
    assert "watcher:\n    enabled: false" in fixture

    resolver = (ROOT / "scripts" / "upgrade.sh").read_text(encoding="utf-8")
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


def test_v8_historical_fixture_disables_fleet_and_preseeds_rollback_root() -> None:
    smoke = (ROOT / "scripts" / "test-upgrade-release.sh").read_text(encoding="utf-8")
    start = smoke.index("seed_v8_observability_fixture() {")
    end = smoke.index("\n}\n\nseed_native_v8_observability_fixture()", start)
    fixture = smoke[start:end]

    assert 'local openclaw_home="${SMOKE_HOME}/.openclaw"' in fixture
    assert 'mkdir -p "${data_dir}/state" "${openclaw_home}" "${evidence_dir}"' in fixture
    assert 'chmod 700 "${data_dir}" "${data_dir}/state" "${openclaw_home}"' in fixture
    assert "gateway:\n  fleet_mode: disabled\n  watcher:\n    enabled: false" in fixture

    verify_start = smoke.index("verify_upgrade() {")
    verify_end = smoke.index("\n}\n\nrun_one_upgrade_smoke()", verify_start)
    verification = smoke[verify_start:verify_end]
    assert "hermetic gateway connectivity policy was not preserved" in verification
    assert "openclaw_home.lstat()" in verification
    assert "except FileNotFoundError:" in verification
    assert "fixture OpenClaw home disappeared across the staged upgrade" in verification
    assert "fixture OpenClaw home mode changed across the staged upgrade" in verification


def test_live_continuity_uses_low_cardinality_metric_boundary() -> None:
    harness = (ROOT / "scripts" / "test-observability-v8-upgrade-continuity.sh").read_text(
        encoding="utf-8"
    )
    wait_start = harness.index("wait_for_pre_upgrade_metrics() {")
    wait_end = harness.index("\n}\n\nrun_live_upgrade()", wait_start)
    wait = harness[wait_start:wait_end]

    assert "gen_ai_agent_id" not in wait
    assert 'gen_ai_agent_type=~"root|direct|nested"' in wait
    assert "minimum_fixture_time" in wait
    assert 'METRIC_CUTOVER_SECONDS="$(python3 -c' in harness
    assert '--metric-cutover-seconds "${METRIC_CUTOVER_SECONDS}"' in harness

    pre_emit = harness.index('emit_continuity_phase pre "${PRE_STAMP}"')
    pre_metrics = harness.index('wait_for_pre_upgrade_metrics "${PRE_STAMP}"')
    cutover = harness.index('METRIC_CUTOVER_SECONDS="$(python3 -c')
    upgrade = harness.index("run_live_upgrade", cutover)
    post_emit = harness.index('emit_continuity_phase post "${POST_STAMP}"')
    assert pre_emit < pre_metrics < cutover < upgrade < post_emit


def _posix_protected_materializer_program() -> str:
    resolver = (ROOT / "scripts" / "upgrade.sh").read_text(encoding="utf-8")
    function = resolver.index("materialize_protected_artifact() {")
    start = resolver.index("<<'PY'\n", function) + len("<<'PY'\n")
    end = resolver.index("\nPY\n}", start)
    return resolver[start:end]


def _posix_target_controller_handoff_verifier_program() -> str:
    resolver = (ROOT / "scripts" / "upgrade.sh").read_text(encoding="utf-8")
    function = resolver.index("verify_hard_cut_target_controller_handoff() {")
    start = resolver.index("<<'PY'\n", function) + len("<<'PY'\n")
    end = resolver.index("\nPY\n}", start)
    return resolver[start:end]


@pytest.mark.skipif(os.name == "nt", reason="POSIX protected-artifact materializer")
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


@pytest.mark.skipif(os.name == "nt", reason="POSIX target-controller handoff")
def test_posix_target_controller_handoff_verifier_executes_exact_custody_contract(
    tmp_path: Path,
) -> None:
    program = _posix_target_controller_handoff_verifier_program()
    target_venv = tmp_path / "target-controller-venv"
    installed_venv = tmp_path / "installed-bridge-venv"
    target_cli = target_venv / "bin" / "defenseclaw"
    installed_cli = installed_venv / "bin" / "defenseclaw"
    install_dir = tmp_path / "bin"
    installed_launcher = install_dir / "defenseclaw"
    installed_gateway = install_dir / "defenseclaw-gateway"
    gateway_source = tmp_path / "gateway-source"
    handoff_dir = tmp_path / "bridge-handoff"
    protected_wheel = tmp_path / "defenseclaw-0.8.5-2-py3-none-any.dcwheel"
    for directory in (target_cli.parent, installed_cli.parent, install_dir):
        directory.mkdir(parents=True, exist_ok=True)
    target_venv.chmod(0o700)
    handoff_dir.mkdir(mode=0o700)
    target_cli.write_text("#!/bin/sh\necho 'DefenseClaw 0.8.5'\n", encoding="utf-8")
    installed_cli.write_text("#!/bin/sh\necho 'DefenseClaw 0.8.4'\n", encoding="utf-8")
    gateway_source.write_text(
        "#!/bin/sh\necho 'DefenseClaw gateway 0.8.4'\n",
        encoding="utf-8",
    )
    for executable in (target_cli, installed_cli, gateway_source):
        executable.chmod(0o755)
    installed_launcher.symlink_to(installed_cli)
    os.link(gateway_source, installed_gateway)
    protected_wheel.write_bytes(b"authenticated target controller")
    protected_wheel.chmod(0o600)
    protected_sha256 = hashlib.sha256(protected_wheel.read_bytes()).hexdigest()
    arguments = (
        str(target_venv),
        str(target_cli),
        str(installed_venv),
        str(installed_launcher),
        str(installed_gateway),
        str(handoff_dir),
        str(protected_wheel),
        protected_sha256,
        "0.8.4",
        "0.8.5",
    )

    completed = subprocess.run(
        [sys.executable, "-c", program, *arguments],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert installed_gateway.stat().st_nlink == 2

    protected_wheel.chmod(0o644)
    exposed = subprocess.run(
        [sys.executable, "-c", program, *arguments],
        capture_output=True,
        text=True,
        check=False,
    )
    assert exposed.returncode != 0
    assert "authenticated target-controller wheel lost private custody" in exposed.stderr
    protected_wheel.chmod(0o600)

    refused = subprocess.run(
        [sys.executable, "-c", program, *arguments[:-3], "0" * 64, *arguments[-2:]],
        capture_output=True,
        text=True,
        check=False,
    )
    assert refused.returncode != 0
    assert "authenticated target-controller wheel changed before handoff" in refused.stderr


@pytest.mark.skipif(os.name == "nt", reason="POSIX target-controller handoff")
def test_real_target_controller_enters_upgrade_command_with_bridge_v7_config(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    recovery_home = home / ".defenseclaw"
    staged = tmp_path / "bridge-handoff"
    recovery_home.mkdir(parents=True)
    staged.mkdir(mode=0o700)
    (recovery_home / "config.yaml").write_text(
        f"config_version: 7\ndata_dir: {recovery_home}\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment.update(
        {
            "HOME": str(home),
            "DEFENSECLAW_HOME": str(recovery_home),
            "DEFENSECLAW_STAGED_UPGRADE": "1",
            "DEFENSECLAW_STAGED_BRIDGE_VERSION": "0.8.4",
            "DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR": str(staged),
            "DEFENSECLAW_STAGED_TARGET_CONTROLLER_VERSION": "0.8.6",
            "PYTHONDONTWRITEBYTECODE": "1",
            "NO_COLOR": "1",
        }
    )
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "from defenseclaw.main import main; main()",
            "upgrade",
            "--yes",
            "--version",
            "0.8.6",
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    output = completed.stdout + completed.stderr

    assert completed.returncode != 0
    assert "DefenseClaw Upgrade" in output
    assert "Installed version" in output and "0.8.4" in output
    assert "Target version" in output and "0.8.6" in output
    assert "Failed to load config" not in output
    assert "release-owned target controller did not receive one complete, exact bridge handoff" in output


def test_posix_resolver_bootstraps_recovery_under_fixed_mutator_lease() -> None:
    text = (ROOT / "scripts" / "upgrade.sh").read_text(encoding="utf-8")
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


def test_posix_resolver_hands_both_hard_cut_paths_to_authenticated_target_controller() -> None:
    resolver = (ROOT / "scripts" / "upgrade.sh").read_text(encoding="utf-8")

    capture = resolver.index("capture_hard_cut_target_controller_contract")
    bridge_switch = resolver.index('RELEASE_VERSION="${MANIFEST_REQUIRED_BRIDGE}"', capture)
    assert capture < bridge_switch
    assert resolver.count('exec "${TARGET_CONTROLLER_CLI}" upgrade --yes --version "${final_version}"') == 2
    assert resolver.count(
        'export DEFENSECLAW_STAGED_TARGET_CONTROLLER_VERSION="${final_version}"'
    ) == 2
    assert 'exec "${INSTALL_DIR}/defenseclaw" upgrade --yes --version "${final_version}"' not in resolver
    assert "verify_hard_cut_target_controller_handoff" in resolver
    assert 'TARGET_CONTROLLER_VENV="${STAGING_DIR}/target-controller-venv"' in resolver


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
