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

import ast
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
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
    match = re.search(r"^UPGRADE_SMOKE_FROM \?=\s*$", text, re.MULTILINE)
    assert match is not None

    policy = json.loads(
        (ROOT / "release" / "upgrade-baselines.json").read_text(encoding="utf-8")
    )
    assert tuple(policy["published_baselines"]) == UPGRADE_SMOKE_BASELINES
    assert "scripts/resolve_upgrade_baselines.py" in text
    assert "from_versions='$(strip $(UPGRADE_SMOKE_FROM))'" in text
    assert "target_version=''" in text
    assert "dynamic upgrade matrix requires" in text
    assert '--target-version "$$target_version"' in text
    assert '--target-version=*) target_version="$${1#--target-version=}"' in text

    assert "upgrade-refusal-contract-matrix: upgrade-smoke-matrix" in text
    assert "upgrade-developer-activation:" in text
    assert "scripts/test-developer-target-activation.sh $(ARGS)" in text
    assert "$(call run_upgrade_matrix,scripts/test-upgrade-protocol-release.sh,--refusal-contract-only)" in text
    assert "upgrade-legacy-smoke-matrix:" in text
    assert "$(call run_upgrade_matrix,scripts/test-upgrade-release.sh,)" in text
    assert "upgrade-signed-protocol-matrix:" in text


def test_makefile_upgrade_matrix_executes_dynamic_and_explicit_baselines(tmp_path: Path) -> None:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    resolver = scripts / "resolve_upgrade_baselines.py"
    resolver.write_text(
        """import json, pathlib, sys
args = sys.argv[1:]
target = args[args.index('--target-version') + 1]
output = pathlib.Path(args[args.index('--output') + 1])
pathlib.Path('resolver-observed.json').write_text(json.dumps({'target': target, 'output': str(output)}))
output.write_text(json.dumps({'published_baselines': ['0.8.5', '0.8.4']}))
""",
        encoding="utf-8",
    )
    runner = scripts / "test-upgrade-protocol-release.sh"
    runner.write_text(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > runner-args.txt\n",
        encoding="utf-8",
    )
    runner.chmod(0o700)

    environment = os.environ.copy()
    environment.pop("UPGRADE_SMOKE_FROM", None)

    subprocess.run(
        [
            "make",
            "-s",
            "-f",
            str(ROOT / "Makefile"),
            "upgrade-smoke-matrix",
            "ARGS=--target-version 0.8.6 --health-timeout 3",
        ],
        cwd=tmp_path,
        env=environment,
        timeout=30,
        check=True,
    )
    observed = json.loads((tmp_path / "resolver-observed.json").read_text(encoding="utf-8"))
    assert observed["target"] == "0.8.6"
    assert not Path(observed["output"]).parent.exists()
    assert (tmp_path / "runner-args.txt").read_text(encoding="utf-8").splitlines() == [
        "--from-versions",
        "0.8.5 0.8.4",
        "--refusal-contract-only",
        "--target-version",
        "0.8.6",
        "--health-timeout",
        "3",
    ]

    (tmp_path / "resolver-observed.json").unlink()
    subprocess.run(
        [
            "make",
            "-s",
            "-f",
            str(ROOT / "Makefile"),
            "upgrade-smoke-matrix",
            "ARGS=--target-version=0.8.6 --health-timeout 4",
        ],
        cwd=tmp_path,
        env=environment,
        timeout=30,
        check=True,
    )
    observed = json.loads((tmp_path / "resolver-observed.json").read_text(encoding="utf-8"))
    assert observed["target"] == "0.8.6"
    assert not Path(observed["output"]).parent.exists()
    assert (tmp_path / "runner-args.txt").read_text(encoding="utf-8").splitlines() == [
        "--from-versions",
        "0.8.5 0.8.4",
        "--refusal-contract-only",
        "--target-version=0.8.6",
        "--health-timeout",
        "4",
    ]

    (tmp_path / "resolver-observed.json").unlink()
    subprocess.run(
        [
            "make",
            "-s",
            "-f",
            str(ROOT / "Makefile"),
            "upgrade-smoke-matrix",
            "UPGRADE_SMOKE_FROM=0.8.3 0.8.2",
            "ARGS=--target-version=0.8.6",
        ],
        cwd=tmp_path,
        env=environment,
        timeout=30,
        check=True,
    )
    assert not (tmp_path / "resolver-observed.json").exists()
    assert (tmp_path / "runner-args.txt").read_text(encoding="utf-8").splitlines() == [
        "--from-versions",
        "0.8.3 0.8.2",
        "--refusal-contract-only",
        "--target-version=0.8.6",
    ]


def test_upgrade_smoke_docs_cover_default_matrix() -> None:
    text = (ROOT / "docs" / "TESTING.md").read_text(encoding="utf-8")
    default_line = next(line for line in text.splitlines() if "default matrix covers" in line)
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
    assert "prepare_required_bridge_assets()" in smoke
    assert 'cosign_command="$(command -v cosign)"' in smoke
    assert 'cosign_path="$(abs_path "${cosign_command}")"' in smoke
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
    assert "required bridge authentication failed" in smoke
    assert 'if [[ "${SUCCESS_PATH_ONLY}" == "1" ]]' in protocol


@pytest.mark.skipif(os.name == "nt", reason="executes the POSIX release shell and symlink contract")
def test_bridge_auth_resolves_a_symlinked_cosign_binary(tmp_path: Path) -> None:
    real_bin = tmp_path / "real-bin"
    command_dir = tmp_path / "commands"
    real_bin.mkdir()
    command_dir.mkdir()
    real_cosign = real_bin / "cosign"
    real_cosign.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    real_cosign.chmod(0o700)
    (command_dir / "cosign").symlink_to(real_cosign)

    completed = subprocess.run(
        [
            "bash",
            "-c",
            "source scripts/test-upgrade-release.sh; trap - EXIT; "
            'PATH="$1:$PATH"; resolved="$(abs_path "$(command -v cosign)")"; '
            'test "$resolved" = "$2"',
            "bridge-cosign-resolution",
            str(command_dir),
            str(real_cosign.resolve()),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_unsigned_refusal_contract_distinguishes_modern_provenance_from_legacy_schema() -> None:
    protocol = (ROOT / "scripts" / "test-upgrade-protocol-release.sh").read_text(
        encoding="utf-8"
    )

    assert 'installed_refusal_mode="artifact-provenance"' in protocol
    assert 'elif [[ "${REFUSAL_CONTRACT_ONLY}" == "1" ]] && ! candidate_has_checksum_signature' in protocol
    assert "--allow-unverified cannot bypass mandatory 0.8.4+ manifest or artifact provenance checks" in protocol
    assert "checksums.txt is not signed (no Sigstore signature/certificate assets were published)" in protocol
    assert "Modern release provenance is mandatory; --allow-unverified cannot override it." in protocol


def test_live_continuity_local_candidate_models_strict_sigstore_boundary_only() -> None:
    continuity = (
        ROOT / "scripts" / "test-observability-v8-upgrade-continuity.sh"
    ).read_text(encoding="utf-8")

    fixture_start = continuity.index("prepare_local_candidate_provenance_fixture() {")
    fixture_end = continuity.index("\n}\n\nassert_local_candidate_provenance_verified()", fixture_start)
    fixture = continuity[fixture_start:fixture_end]
    main = continuity[continuity.index("main_continuity() {") :]

    assert '[[ "${LOCAL_CANDIDATE_PROVENANCE_FIXTURE}" == "1" ]]' in fixture
    assert 'if [[ -z "${RELEASE_ROOT}" && -z "${RELEASE_DIR}" ]]' in main
    assert 'LOCAL_CANDIDATE_PROVENANCE_FIXTURE="1"' in main
    assert "--certificate-identity" in fixture
    assert ("https://github.com/cisco-ai-defense/defenseclaw/.github/workflows/release.yaml@refs/heads/main") in fixture
    assert "--certificate-oidc-issuer" in fixture
    assert "https://token.actions.githubusercontent.com" in fixture
    assert '[[ "$#" -eq 10 ]]' in fixture
    assert "RELEASE_PROVENANCE_FILENAME" in fixture
    assert "RELEASE_SOURCE_MAP_FILENAME" in fixture
    assert "_release_identity_documents" in fixture
    assert "bridge_checksums_sha256=hashlib.sha256(bridge_payload).hexdigest()" in fixture
    assert 'excluded = {"checksums.txt", "checksums.txt.pem", "checksums.txt.sig"}' in fixture
    assert "prepare_required_bridge_assets" in main
    assert main.index("prepare_required_bridge_assets") < main.index("prepare_local_candidate_provenance_fixture")
    assert "assert_local_candidate_provenance_verified" in main


def test_live_continuity_fixture_binds_provenance_into_checksums(tmp_path: Path) -> None:
    continuity = (ROOT / "scripts" / "test-observability-v8-upgrade-continuity.sh").read_text(encoding="utf-8")
    function_start = continuity.index("prepare_local_candidate_provenance_fixture() {")
    marker = 'python3 - "${release_dir}" "${bridge_checksums}" "${TARGET_VERSION}" <<\'PY\'\n'
    program_start = continuity.index(marker, function_start) + len(marker)
    program_end = continuity.index("\nPY\n", program_start)
    program = continuity[program_start:program_end]

    release_dir = tmp_path / "0.8.5"
    release_dir.mkdir()
    artifact = release_dir / "candidate.bin"
    artifact.write_bytes(b"candidate bytes")
    initial_checksum = hashlib.sha256(artifact.read_bytes()).hexdigest()
    (release_dir / "checksums.txt").write_text(f"{initial_checksum}  {artifact.name}\n", encoding="utf-8")
    bridge_checksums = tmp_path / "bridge-checksums.txt"
    bridge_checksums.write_text(f"{'a' * 64}  bridge.bin\n", encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            "-",
            str(release_dir),
            str(bridge_checksums),
            "0.8.5",
        ],
        cwd=ROOT,
        input=program,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr

    provenance_path = release_dir / "release-provenance.json"
    source_map_path = release_dir / "release-source-map.json"
    assert provenance_path.is_file()
    assert source_map_path.is_file()
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    assert provenance["release_version"] == "0.8.5"
    assert provenance["bridge"]["version"] == "0.8.4"
    assert provenance["bridge"]["checksums_sha256"] == hashlib.sha256(bridge_checksums.read_bytes()).hexdigest()
    checksums = (release_dir / "checksums.txt").read_text(encoding="utf-8")
    checksum_rows = {name: digest for row in checksums.splitlines() for digest, name in [row.split()]}
    assert checksum_rows[provenance_path.name] == hashlib.sha256(provenance_path.read_bytes()).hexdigest()
    assert checksum_rows[source_map_path.name] == hashlib.sha256(source_map_path.read_bytes()).hexdigest()


@pytest.mark.skipif(os.name == "nt", reason="executes generated POSIX cosign shims")
def test_live_continuity_cosign_fixture_delegates_published_signatures(
    tmp_path: Path,
) -> None:
    continuity = (ROOT / "scripts" / "test-observability-v8-upgrade-continuity.sh").read_text(encoding="utf-8")
    function_start = continuity.index("prepare_local_candidate_provenance_fixture() {")
    marker = 'python3 - "${fixture_bin}/cosign" "${verifier_log}" "${real_cosign}" <<\'PY\'\n'
    program_start = continuity.index(marker, function_start) + len(marker)
    program_end = continuity.index("\nPY\n", program_start)
    program = continuity[program_start:program_end]

    wrapper = tmp_path / "cosign"
    verifier_log = tmp_path / "fixture-verifier.log"
    delegated_log = tmp_path / "delegated.log"
    real_cosign = tmp_path / "real-cosign"
    real_cosign.write_text(
        f"#!/bin/sh\nprintf '%s\\n' delegated > {str(delegated_log)!r}\n",
        encoding="utf-8",
    )
    real_cosign.chmod(0o700)
    generated = subprocess.run(
        [sys.executable, "-", str(wrapper), str(verifier_log), str(real_cosign)],
        cwd=ROOT,
        input=program,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert generated.returncode == 0, generated.stdout + generated.stderr

    certificate = tmp_path / "checksums.txt.pem"
    certificate.write_text(
        "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n",
        encoding="utf-8",
    )
    signature = tmp_path / "checksums.txt.sig"
    checksums = tmp_path / "checksums.txt"
    checksums.write_text(f"{'a' * 64}  candidate.bin\n", encoding="utf-8")
    command = [
        str(wrapper),
        "verify-blob",
        "--certificate",
        str(certificate),
        "--signature",
        str(signature),
        "--certificate-identity",
        "https://github.com/cisco-ai-defense/defenseclaw/.github/workflows/release.yaml@refs/heads/main",
        "--certificate-oidc-issuer",
        "https://token.actions.githubusercontent.com",
        str(checksums),
    ]

    signature.write_text("defenseclaw-continuity-fixture-signature-v1\n", encoding="utf-8")
    target = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    assert target.returncode == 0, target.stdout + target.stderr
    assert verifier_log.read_text(encoding="utf-8").splitlines() == [
        "verified exact release workflow identity and issuer"
    ]
    assert not delegated_log.exists()

    signature.write_text("published bridge signature\n", encoding="utf-8")
    bridge = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    assert bridge.returncode == 0, bridge.stdout + bridge.stderr
    assert delegated_log.read_text(encoding="utf-8") == "delegated\n"


def test_live_continuity_uses_the_release_owned_resolver_for_the_positive_path() -> None:
    continuity = (ROOT / "scripts" / "test-observability-v8-upgrade-continuity.sh").read_text(encoding="utf-8")
    release_gate = (ROOT / "scripts" / "test-upgrade-release.sh").read_text(encoding="utf-8")
    start = continuity.index("run_live_upgrade() {")
    end = continuity.index("\n}\n\nprepare_local_candidate_provenance_fixture()", start)
    upgrade = continuity[start:end]

    assert 'resolver="${RELEASE_ROOT}/${TARGET_VERSION}/defenseclaw-upgrade.sh"' in upgrade
    assert 'bash "${resolver}" --yes --version "${TARGET_VERSION}"' in upgrade
    assert 'DEFENSECLAW_UPGRADE_TEST_RELEASE_BASE_URL="${RELEASE_URL}"' in upgrade
    assert 'real_curl="$(install_curl_rewrite_probe "${curl_shim}")"' in upgrade
    assert 'UPGRADE_GATE_REAL_CURL="${real_curl}"' in upgrade
    assert 'UPGRADE_GATE_RELEASE_URL="${RELEASE_URL}"' in upgrade
    assert 'UPGRADE_GATE_TARGET_VERSION="${TARGET_VERSION}"' in upgrade
    assert 'PATH="${curl_shim}:${SMOKE_HOME}/.local/bin:${PATH}"' in upgrade
    assert "PYTHONDONTWRITEBYTECODE=1" in upgrade
    assert 'defenseclaw "${args[@]}"' not in upgrade
    assert 'curl_command="$(type -P curl)"' in release_gate
    assert 'real_curl="$(abs_path "${curl_command}")"' in release_gate
    assert '[[ -f "${real_curl}" && -x "${real_curl}" ]]' in release_gate


def test_live_continuity_reopens_v8_database_with_actual_published_bridge_binary() -> None:
    continuity = (ROOT / "scripts" / "test-observability-v8-upgrade-continuity.sh").read_text(encoding="utf-8")
    start = continuity.index("assert_published_bridge_binary_sqlite_rollback_compatibility() {")
    end = continuity.index("\n}\n\nresolve_continuity_upgrade_contract()", start)
    compatibility = continuity[start:end]
    main = continuity[continuity.index("main_continuity() {") :]

    # The gate is specifically bound to the immutable POSIX 0.8.4 bridge and
    # the material retained only after historical_release_auth.py succeeds.
    assert '[[ "${FROM_VERSION}" == "0.8.4" ]]' in compatibility
    assert "darwin|linux) ;;" in compatibility
    assert 'bridge_gateway="${WORKDIR}/old-gateway/${FROM_VERSION}/defenseclaw"' in compatibility
    assert (
        'auth_marker="${WORKDIR}/published-release/${FROM_VERSION}/'
        '.authenticated-${OS_NAME}-${ARCH_NAME}"' in compatibility
    )
    assert 'bridge_probe_name="dcb084probe${POST_STAMP}"' in compatibility
    assert '[[ "${bridge_probe_name}" =~ ^[A-Za-z0-9]+$' in compatibility
    assert '"${bridge_probe_name}" != *defenseclaw*' in compatibility
    assert 'ln "${bridge_gateway}" "${bridge_probe}"' in compatibility
    assert "source_stat.st_ino" in compatibility
    assert "probe_stat.st_ino" in compatibility
    assert "hashlib.sha256(source.read_bytes()).digest()" in compatibility
    assert '"${bridge_probe}" --version | grep -F "${FROM_VERSION}"' in compatibility
    assert '"${bridge_probe}" start' in compatibility
    assert '"${bridge_probe}" stop' in compatibility
    assert '"${bridge_gateway}" start' not in compatibility
    assert '"${bridge_gateway}" stop' not in compatibility

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
    assert '"SELECT COUNT(*) FROM audit_events WHERE target = ?"' in compatibility
    assert 'event.get("target") == probe_target' in compatibility
    assert 'event.get("details") == marker' not in compatibility
    api_read_start = compatibility.index("read = urllib.request.Request(")
    api_read_end = compatibility.index("\nPY\n", api_read_start)
    assert 'event.get("binary_version")' not in compatibility[api_read_start:api_read_end]
    assert "SELECT COUNT(*), COALESCE(MAX(binary_version), '')" in compatibility

    # The target config and binary are restored and health-checked before the
    # ordinary post-upgrade history/dashboard assertions continue.
    assert 'cp -p "${v8_config}" "${data_dir}/config.yaml"' in compatibility
    assert '"${target_gateway}" start' in compatibility
    activation = main.index("verify_target_activation")
    old_binary_probe = main.index("assert_published_bridge_binary_sqlite_rollback_compatibility")
    post_emit = main.index("emit_continuity_phase post")
    assert activation < old_binary_probe < post_emit


def test_live_continuity_fixture_has_no_implicit_openclaw_fleet_dependency() -> None:
    continuity = (ROOT / "scripts" / "test-observability-v8-upgrade-continuity.sh").read_text(encoding="utf-8")
    start = continuity.index("write_continuity_v7_config() {")
    end = continuity.index("\n}\n\nstart_baseline_stack()", start)
    fixture = continuity[start:end]
    verify_start = continuity.index("verify_target_activation() {")
    verify_end = continuity.index(
        "\n}\n\nassert_published_bridge_binary_sqlite_rollback_compatibility()",
        verify_start,
    )
    verification = continuity[verify_start:verify_end]

    assert '"claw:\\n"' in fixture
    assert "\"  mode: ''\\n\"" in fixture
    assert '"  connector:' not in fixture
    assert '"gateway:\\n"' in fixture
    assert '"  fleet_mode: disabled\\n"' in fixture
    assert '"    enabled: false\\n"' in fixture
    assert 'gateway.get("fleet_mode") != "disabled"' in verification
    assert 'gateway.get("watcher") or {}' in verification
    assert '(config.get("claw") or {}).get("mode") != ""' in verification
    assert '(config.get("guardrail") or {}).get("connector") or ""' in verification


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
    assert "post_stop_state=\"${post_stop_health%%$'\\t'*}\"" in post_stop
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


def test_release_resolver_isolated_python_never_writes_bytecode() -> None:
    posix = (ROOT / "scripts" / "upgrade.sh").read_text(encoding="utf-8")
    windows = (ROOT / "scripts" / "upgrade.ps1").read_text(encoding="utf-8")

    # Isolated mode ignores PYTHONDONTWRITEBYTECODE. Every installed-runtime
    # probe must therefore pass -B explicitly so a pre-mutation refusal cannot
    # create __pycache__ entries inside snapshotted state.
    for source in (posix, windows):
        normalized = re.sub(r'["\'`,()]', " ", source)
        normalized = re.sub(r"\s+", " ", normalized)
        assert re.search(r"(?<!\S)-I\s+(?!-B(?:\s|$))\S+", normalized) is None
    assert "-I -B -" in posix
    assert "-I -B -c" in posix
    assert "-I -B -c" in windows
    assert '"${DEFENSECLAW_VENV}"/bin/python -I -B -c' in posix
    assert "${DEFENSECLAW_VENV}/bin/python -c" not in posix
    assert '"${preflight_venv}/bin/python" -c' not in posix
    assert '"${DEFENSECLAW_VENV}/bin/python" -c' not in posix
    assert '"${DEFENSECLAW_VENV}/bin/python" - <<' not in posix

    installed_version = windows[
        windows.index("function Get-InstalledVersion") : windows.index("function Get-CanonicalVersionOutput")
    ]
    assert "[void](Get-Cli)" in installed_version
    assert '-Arguments @("-I", "-B", "-c"' in installed_version
    assert "Get-CanonicalVersionOutput -Command $cli" not in installed_version
    assert 'Assert-VersionOutput (Get-Cli) $SourceVersion "source CLI"' not in windows


def test_release_owned_embedded_python_remains_apple_python39_compatible() -> None:
    paths = (
        ROOT / "scripts" / "upgrade.sh",
        ROOT / "scripts" / "test-upgrade-release.sh",
        ROOT / "scripts" / "test-upgrade-protocol-release.sh",
        ROOT / "scripts" / "test-observability-v8-upgrade-continuity.sh",
        ROOT / "scripts" / "test-fresh-install-release.sh",
    )
    programs: list[tuple[Path, str]] = []
    marker_count = 0
    for path in paths:
        lines = path.read_text(encoding="utf-8").splitlines()
        marker_count += sum("<<'PY'" in line for line in lines)
        index = 0
        while index < len(lines):
            if "<<'PY'" in lines[index]:
                body_start = index + 1
                while body_start < len(lines) and lines[body_start - 1].rstrip().endswith("\\"):
                    body_start += 1
                end = body_start
                while end < len(lines) and lines[end] != "PY":
                    end += 1
                assert end < len(lines), f"unterminated Python heredoc in {path} after line {index + 1}"
                programs.append((path, "\n".join(lines[body_start:end]) + "\n"))
                index = end
            index += 1

    assert len(programs) == marker_count
    incompatible_annotations: list[str] = []
    incompatible_calls: list[str] = []
    for path, program in programs:
        # Release recovery/certification can run before the managed venv is
        # trustworthy, so these programs support stock Apple Python 3.9.
        tree = ast.parse(program, filename=str(path), feature_version=(3, 9))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "zip"
                and any(keyword.arg == "strict" for keyword in node.keywords)
            ):
                incompatible_calls.append(f"{path.name}: {ast.unparse(node)}")
            annotations: list[ast.expr | None] = []
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                arguments = (
                    *node.args.posonlyargs,
                    *node.args.args,
                    *node.args.kwonlyargs,
                )
                annotations.extend(argument.annotation for argument in arguments)
                annotations.append(node.returns)
                if node.args.vararg is not None:
                    annotations.append(node.args.vararg.annotation)
                if node.args.kwarg is not None:
                    annotations.append(node.args.kwarg.annotation)
            elif isinstance(node, ast.AnnAssign):
                annotations.append(node.annotation)

            for annotation in (value for value in annotations if value is not None):
                if any(
                    isinstance(candidate, ast.BinOp) and isinstance(candidate.op, ast.BitOr)
                    for candidate in ast.walk(annotation)
                ):
                    incompatible_annotations.append(f"{path.name}: {ast.unparse(annotation)}")

    assert not incompatible_annotations, (
        "release-owned embedded Python may execute under bare python3 and must remain compatible "
        f"with Apple Python 3.9: {incompatible_annotations}"
    )
    assert not incompatible_calls, (
        f"release-owned embedded Python cannot use zip(strict=...) before Python 3.10: {incompatible_calls}"
    )


def test_posix_upgrade_fixture_seeds_gateway_token_before_historical_evidence() -> None:
    smoke = (ROOT / "scripts" / "test-upgrade-release.sh").read_text(encoding="utf-8")
    legacy_start = smoke.index("seed_v8_observability_fixture() {")
    legacy_end = smoke.index("\n}\n\nseed_native_v8_observability_fixture()", legacy_start)
    native_start = legacy_end
    native_end = smoke.index("\n}\n\nseed_upgrade_fixture()", native_start)

    legacy_fixture = smoke[legacy_start:legacy_end]
    native_fixture = smoke[native_start:native_end]
    assert "python3 -I -B -c 'import secrets" in legacy_fixture
    assert legacy_fixture.index("DEFENSECLAW_GATEWAY_TOKEN=${gateway_token}") < legacy_fixture.index(
        "finalize_observability_upgrade_fixture"
    )
    assert "python3 -I -B -c 'import secrets" in native_fixture
    assert native_fixture.index("DEFENSECLAW_GATEWAY_TOKEN=${gateway_token}") < native_fixture.index(
        "environment.historical.source"
    )
    invariant_start = smoke.index("assert_source_gateway_canary_preserved_fixture() {")
    invariant_end = smoke.index("\n}\n", invariant_start)
    invariant = smoke[invariant_start:invariant_end]
    assert 'cmp -s "${evidence_dir}/config.historical.source" "${data_dir}/config.yaml"' in invariant
    assert 'cmp -s "${evidence_dir}/environment.historical.source" "${data_dir}/.env"' in invariant
    run_one = smoke[smoke.index("run_one_upgrade_smoke() {") : smoke.index("\n}\n\nmain()")]
    assert (
        run_one.index("start_source_gateway_canary")
        < run_one.index("assert_source_gateway_canary_preserved_fixture")
        < run_one.index("patch_installed_upgrade_endpoint")
    )
    assert 'actual_environment.get("DEFENSECLAW_GATEWAY_TOKEN") != historical_gateway_token' in smoke
    assert 'raise SystemExit("gateway token changed across the staged upgrade")' in smoke
    assert "historical_gateway_token," in smoke
    assert '"DEFENSECLAW_GATEWAY_TOKEN": historical_gateway_token' in smoke
    assert '"${SMOKE_HOME}/fixture-evidence/environment.historical.source"' in smoke


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
    migration_preflight = command.index("_preflight_hard_cut_observability_migration(", acquisition)
    backup = command.index('ux.banner("Creating Backup")', acquisition)
    assert gate_call < acquisition < migration_preflight < backup
    pre_stop = command[migration_preflight:backup]
    assert pre_stop.count("_preflight_hard_cut_observability_migration(") == 2
    assert "gateway_binary=gw_binary_path" in pre_stop
    assert "config_path=active_config_path" in pre_stop
    assert "expected_binding=hard_cut_preflight_binding" in pre_stop
    assert "including --yes" in pre_stop
    assert "No backup, receipt, service stop, artifact install, or migration was performed" in command

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
    target_command = '"${TARGET_CONTROLLER_CLI}" upgrade --yes --version "${final_version}"'
    assert resolver.count(target_command) == 2
    assert f"exec {target_command}" not in resolver
    assert resolver.count("|| target_status=$?") == 2
    assert resolver.count('exit "${target_status}"') == 2
    assert resolver.count('export DEFENSECLAW_STAGED_TARGET_CONTROLLER_VERSION="${final_version}"') == 2
    assert 'exec "${INSTALL_DIR}/defenseclaw" upgrade --yes --version "${final_version}"' not in resolver
    assert "verify_hard_cut_target_controller_handoff" in resolver
    assert 'TARGET_CONTROLLER_VENV="${STAGING_DIR}/target-controller-venv"' in resolver


def _posix_resolver_lock_functions() -> str:
    resolver = (ROOT / "scripts" / "upgrade.sh").read_text(encoding="utf-8")
    functions_start = resolver.index("acquire_upgrade_lock() {")
    release_start = resolver.index("release_upgrade_lock() {", functions_start)
    functions_end = resolver.index(
        "\n}\n\nregister_bridge_phase1_recovery_journal() {",
        release_start,
    ) + len("\n}\n")
    return resolver[functions_start:functions_end]


def _posix_resolver_lock_harness() -> str:
    return f"""
set -euo pipefail
umask 077
DEFENSECLAW_HOME="$TEST_DATA_HOME"
UPGRADE_RECOVERY_ROOT="${{DEFENSECLAW_HOME}}/.upgrade-recovery"
UPGRADE_LOCK_FILE="${{UPGRADE_RECOVERY_ROOT}}/upgrade.lock"
UPGRADE_ADVISORY_LOCK_FILE="${{UPGRADE_RECOVERY_ROOT}}/upgrade.advisory.lock"
UPGRADE_LOCK_TOKEN=""
UPGRADE_ADVISORY_LOCK_HELD=0
UPGRADE_ADVISORY_LOCK_OPEN=0
UPGRADE_RECOVERY_ROOT_CREATED=0
UPGRADE_ADVISORY_LOCK_CREATED=0
UPGRADE_RECOVERY_ROOT_DEVICE=""
UPGRADE_RECOVERY_ROOT_INODE=""
UPGRADE_ADVISORY_LOCK_DEVICE=""
UPGRADE_ADVISORY_LOCK_INODE=""
die() {{ printf '%s\n' "$*" >&2; exit 1; }}
{_posix_resolver_lock_functions()}
"""


@pytest.mark.skipif(os.name == "nt", reason="POSIX resolver lock cleanup")
@pytest.mark.parametrize("preexisting_recovery_root", (False, True))
def test_posix_resolver_releases_only_the_lock_custody_it_created(
    tmp_path: Path,
    preexisting_recovery_root: bool,
) -> None:
    data_home = tmp_path / "data"
    data_home.mkdir(mode=0o700)
    recovery_root = data_home / ".upgrade-recovery"
    advisory_lock = recovery_root / "upgrade.advisory.lock"
    if preexisting_recovery_root:
        recovery_root.mkdir(mode=0o700)
        advisory_lock.write_bytes(b"")
        advisory_lock.chmod(0o600)

    script = (
        _posix_resolver_lock_harness()
        + """
acquire_upgrade_lock
test -f "${UPGRADE_LOCK_FILE}"
test -f "${UPGRADE_ADVISORY_LOCK_FILE}"
release_upgrade_lock
test ! -e "${UPGRADE_LOCK_FILE}"
"""
    )
    if preexisting_recovery_root:
        script += """
test -d "${UPGRADE_RECOVERY_ROOT}"
test -f "${UPGRADE_ADVISORY_LOCK_FILE}"
"""
    else:
        script += 'test ! -e "${UPGRADE_RECOVERY_ROOT}"\n'

    environment = os.environ.copy()
    environment["TEST_DATA_HOME"] = str(data_home)
    completed = subprocess.run(
        ["bash", "-c", script],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr


@pytest.mark.skipif(os.name == "nt", reason="POSIX resolver lock cleanup")
def test_posix_resolver_parent_wait_refusal_runs_exit_cleanup(tmp_path: Path) -> None:
    data_home = tmp_path / "data"
    data_home.mkdir(mode=0o700)
    script = (
        _posix_resolver_lock_harness()
        + """
trap release_upgrade_lock EXIT
acquire_upgrade_lock
target_status=0
bash -c 'exit 42' || target_status=$?
exit "${target_status}"
"""
    )
    environment = os.environ.copy()
    environment["TEST_DATA_HOME"] = str(data_home)
    completed = subprocess.run(
        ["bash", "-c", script],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 42, completed.stdout + completed.stderr
    assert not (data_home / ".upgrade-recovery").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX resolver lock cleanup")
def test_posix_resolver_never_deletes_replacement_advisory_inode(tmp_path: Path) -> None:
    data_home = tmp_path / "data"
    data_home.mkdir(mode=0o700)
    script = (
        _posix_resolver_lock_harness()
        + """
acquire_upgrade_lock
mv "${UPGRADE_ADVISORY_LOCK_FILE}" "${UPGRADE_ADVISORY_LOCK_FILE}.displaced"
printf 'replacement\n' >"${UPGRADE_ADVISORY_LOCK_FILE}"
chmod 600 "${UPGRADE_ADVISORY_LOCK_FILE}"
release_upgrade_lock
test ! -e "${UPGRADE_LOCK_FILE}"
test -f "${UPGRADE_ADVISORY_LOCK_FILE}"
test -f "${UPGRADE_ADVISORY_LOCK_FILE}.displaced"
"""
    )
    environment = os.environ.copy()
    environment["TEST_DATA_HOME"] = str(data_home)
    completed = subprocess.run(
        ["bash", "-c", script],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    recovery_root = data_home / ".upgrade-recovery"
    assert (recovery_root / "upgrade.advisory.lock").read_bytes() == b"replacement\n"
    assert (recovery_root / "upgrade.advisory.lock.displaced").read_bytes() == b""


@pytest.mark.skipif(os.name == "nt", reason="POSIX resolver lock cleanup")
def test_posix_resolver_keeps_kernel_lease_until_created_path_is_removed(
    tmp_path: Path,
) -> None:
    data_home = tmp_path / "data"
    data_home.mkdir(mode=0o700)
    ready = tmp_path / "observer-ready"
    result = tmp_path / "observer-result"
    script = (
        _posix_resolver_lock_harness()
        + """
acquire_upgrade_lock
(
    exec 9>&-
    python3 - "${UPGRADE_ADVISORY_LOCK_FILE}" "$TEST_READY" "$TEST_RESULT" <<'PY'
import fcntl
import os
from pathlib import Path
import sys
import time

path, ready, result = sys.argv[1:]
descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
try:
    Path(ready).write_text("ready\\n", encoding="utf-8")
    deadline = time.monotonic() + 5
    while True:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise SystemExit("timed out waiting for resolver lease")
            time.sleep(0.005)
    Path(result).write_text(
        "present\\n" if os.path.lexists(path) else "absent\\n",
        encoding="utf-8",
    )
finally:
    os.close(descriptor)
PY
) &
observer_pid=$!
for _attempt in $(seq 1 500); do
    [[ -f "$TEST_READY" ]] && break
    sleep 0.01
done
test -f "$TEST_READY"
release_upgrade_lock
wait "${observer_pid}"
    # Cleanup and this fresh descriptor can acquire immediately after the
    # parent releases FD 9 in either order. If this observer wins first it sees
    # the name; otherwise it observes an already-unlinked inode. In both cases
    # cleanup must finish by reclaiming the resolver-created inode/root.
    case "$(cat "$TEST_RESULT")" in
        present|absent) ;;
        *) exit 1 ;;
    esac
    test ! -e "${UPGRADE_RECOVERY_ROOT}"
"""
    )
    environment = os.environ.copy()
    environment.update(
        {
            "TEST_DATA_HOME": str(data_home),
            "TEST_READY": str(ready),
            "TEST_RESULT": str(result),
        }
    )
    completed = subprocess.run(
        ["bash", "-c", script],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr


@pytest.mark.skipif(os.name == "nt", reason="POSIX resolver lock cleanup")
def test_posix_resolver_retry_waits_for_surviving_mutation_child(tmp_path: Path) -> None:
    data_home = tmp_path / "data"
    data_home.mkdir(mode=0o700)
    ready = tmp_path / "parent-ready"
    child_pid_path = tmp_path / "child-pid"
    parent_script = (
        _posix_resolver_lock_harness()
        + """
acquire_upgrade_lock
bash -c 'sleep 4' &
child_pid=$!
printf '%s\n' "${child_pid}" >"$TEST_CHILD_PID"
printf 'ready\n' >"$TEST_READY"
wait "${child_pid}"
"""
    )
    environment = os.environ.copy()
    environment.update(
        {
            "TEST_DATA_HOME": str(data_home),
            "TEST_READY": str(ready),
            "TEST_CHILD_PID": str(child_pid_path),
        }
    )
    parent = subprocess.Popen(
        ["bash", "-c", parent_script],
        cwd=ROOT,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 5
    while not ready.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert ready.exists()
    child_pid = int(child_pid_path.read_text(encoding="utf-8"))

    parent.kill()
    assert parent.wait(timeout=5) != 0
    os.kill(child_pid, 0)

    retry_script = (
        _posix_resolver_lock_harness()
        + """
trap release_upgrade_lock EXIT
acquire_upgrade_lock
"""
    )
    refused = subprocess.run(
        ["bash", "-c", retry_script],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert refused.returncode != 0
    assert "surviving mutation child" in refused.stderr

    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    else:
        pytest.fail("mutation child did not exit")

    completed = subprocess.run(
        ["bash", "-c", retry_script],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


@pytest.mark.skipif(os.name == "nt", reason="POSIX resolver lock cleanup")
def test_posix_resolver_exit_cleanup_keeps_surviving_child_advisory_lease(tmp_path: Path) -> None:
    """Exit cleanup must not unlink an inode still locked by an inherited FD."""
    data_home = tmp_path / "data"
    data_home.mkdir(mode=0o700)
    ready = tmp_path / "parent-ready"
    child_pid_path = tmp_path / "child-pid"
    parent_script = (
        _posix_resolver_lock_harness()
        + """
trap release_upgrade_lock EXIT
acquire_upgrade_lock
bash -c 'sleep 4' &
child_pid=$!
printf '%s\n' "${child_pid}" >"$TEST_CHILD_PID"
printf 'ready\n' >"$TEST_READY"
exit 0
"""
    )
    environment = os.environ.copy()
    environment.update(
        {
            "TEST_DATA_HOME": str(data_home),
            "TEST_READY": str(ready),
            "TEST_CHILD_PID": str(child_pid_path),
        }
    )
    parent = subprocess.Popen(
        ["bash", "-c", parent_script],
        cwd=ROOT,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 5
    while not ready.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert ready.exists()
    child_pid = int(child_pid_path.read_text(encoding="utf-8"))
    assert parent.wait(timeout=5) == 0
    os.kill(child_pid, 0)

    advisory_lock = data_home / ".upgrade-recovery" / "upgrade.advisory.lock"
    assert advisory_lock.is_file()
    retry_script = (
        _posix_resolver_lock_harness()
        + """
trap release_upgrade_lock EXIT
acquire_upgrade_lock
"""
    )
    refused = subprocess.run(
        ["bash", "-c", retry_script],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert refused.returncode != 0
    assert "surviving mutation child" in refused.stderr
    assert advisory_lock.is_file()

    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    else:
        pytest.fail("mutation child did not exit")

    completed = subprocess.run(
        ["bash", "-c", retry_script],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux /proc process-start identity")
def test_posix_resolver_reclaims_reused_pid_schema_v2_claim(tmp_path: Path) -> None:
    """A reused PID must not permanently block a stale diagnostic claim."""
    data_home = tmp_path / "data"
    data_home.mkdir(mode=0o700)
    script = (
        _posix_resolver_lock_harness()
        + """
mkdir -p "${UPGRADE_RECOVERY_ROOT}"
chmod 700 "${UPGRADE_RECOVERY_ROOT}"
python3 - "${UPGRADE_LOCK_FILE}" "$$" <<'PY'
import json
import sys

path, pid = sys.argv[1:]
with open(path, "w", encoding="utf-8") as stream:
    json.dump(
        {
            "schema_version": 2,
            "pid": int(pid),
            "process_start": "linux:0",
            "token": "a" * 64,
        },
        stream,
        sort_keys=True,
        separators=(",", ":"),
    )
    stream.write("\\n")
PY
chmod 600 "${UPGRADE_LOCK_FILE}"
acquire_upgrade_lock
python3 - "${UPGRADE_LOCK_FILE}" <<'PY'
import json
import sys

claim = json.loads(open(sys.argv[1], encoding="utf-8").read())
assert claim["schema_version"] == 2
assert claim["process_start"] != "linux:0"
PY
release_upgrade_lock
"""
    )
    environment = os.environ.copy()
    environment["TEST_DATA_HOME"] = str(data_home)
    completed = subprocess.run(
        ["bash", "-c", script],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr


@pytest.mark.skipif(os.name == "nt", reason="POSIX resolver lock cleanup")
def test_posix_resolver_schema1_live_pid_claim_fails_closed(tmp_path: Path) -> None:
    """Platforms without a precise start identity never reclaim a live PID."""

    data_home = tmp_path / "data"
    data_home.mkdir(mode=0o700)
    script = (
        _posix_resolver_lock_harness()
        + """
mkdir -p "${UPGRADE_RECOVERY_ROOT}"
chmod 700 "${UPGRADE_RECOVERY_ROOT}"
python3 - "${UPGRADE_LOCK_FILE}" "$$" <<'PY'
import json
import sys

path, pid = sys.argv[1:]
with open(path, "w", encoding="utf-8") as stream:
    json.dump(
        {"schema_version": 1, "pid": int(pid), "token": "a" * 64},
        stream,
        sort_keys=True,
        separators=(",", ":"),
    )
    stream.write("\\n")
PY
chmod 600 "${UPGRADE_LOCK_FILE}"
acquire_upgrade_lock
"""
    )
    environment = os.environ.copy()
    environment["TEST_DATA_HOME"] = str(data_home)
    completed = subprocess.run(
        ["bash", "-c", script],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode != 0
    assert (data_home / ".upgrade-recovery" / "upgrade.lock").is_file()


@pytest.mark.skipif(os.name == "nt", reason="POSIX resolver lock cleanup")
def test_posix_resolver_legacy_schema2_live_pid_claim_fails_closed(tmp_path: Path) -> None:
    """Legacy second-resolution claims are not reclaimed while their PID lives."""

    data_home = tmp_path / "data"
    data_home.mkdir(mode=0o700)
    script = (
        _posix_resolver_lock_harness()
        + """
mkdir -p "${UPGRADE_RECOVERY_ROOT}"
chmod 700 "${UPGRADE_RECOVERY_ROOT}"
python3 - "${UPGRADE_LOCK_FILE}" "$$" <<'PY'
import json
import sys

path, pid = sys.argv[1:]
with open(path, "w", encoding="utf-8") as stream:
    json.dump(
        {
            "schema_version": 2,
            "pid": int(pid),
            "process_start": "Thu Jul 17 12:34:56 2026",
            "token": "a" * 64,
        },
        stream,
        sort_keys=True,
        separators=(",", ":"),
    )
    stream.write("\\n")
PY
chmod 600 "${UPGRADE_LOCK_FILE}"
acquire_upgrade_lock
"""
    )
    environment = os.environ.copy()
    environment["TEST_DATA_HOME"] = str(data_home)
    completed = subprocess.run(
        ["bash", "-c", script],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode != 0
    assert (data_home / ".upgrade-recovery" / "upgrade.lock").is_file()


@pytest.mark.skipif(os.name == "nt", reason="POSIX resolver lock cleanup")
def test_posix_resolver_preserves_nonempty_created_recovery_root_in_place(
    tmp_path: Path,
) -> None:
    data_home = tmp_path / "data"
    data_home.mkdir(mode=0o700)
    script = (
        _posix_resolver_lock_harness()
        + """
acquire_upgrade_lock
printf '{"schema_version":4}\n' >"${UPGRADE_RECOVERY_ROOT}/phase-two-active.json"
chmod 600 "${UPGRADE_RECOVERY_ROOT}/phase-two-active.json"
release_upgrade_lock
test -d "${UPGRADE_RECOVERY_ROOT}"
test -f "${UPGRADE_RECOVERY_ROOT}/phase-two-active.json"
test ! -e "${UPGRADE_LOCK_FILE}"
test ! -e "${UPGRADE_ADVISORY_LOCK_FILE}"
"""
    )
    environment = os.environ.copy()
    environment["TEST_DATA_HOME"] = str(data_home)
    completed = subprocess.run(
        ["bash", "-c", script],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    recovery_root = data_home / ".upgrade-recovery"
    assert (recovery_root / "phase-two-active.json").is_file()
    assert not list(data_home.glob(".upgrade-recovery.released-*"))


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
