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
import re
import stat
import subprocess
from pathlib import Path

import pytest
import yaml
from defenseclaw.migrations import run_migrations
from defenseclaw.observability.v8_config import load_validate_v8

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "test-upgrade-release.sh"
DEVELOPER_ACTIVATION_SCRIPT = ROOT / "scripts" / "test-developer-target-activation.sh"
INSTALL_SCRIPT = ROOT / "scripts" / "install.sh"
UPGRADE_SCRIPT = ROOT / "scripts" / "upgrade.sh"
MAKEFILE = ROOT / "Makefile"
BASELINE_POLICY = ROOT / "release" / "upgrade-baselines.json"


def _source_script(command: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-c", f'source "$1"; {command}', "upgrade-smoke-contract", str(SCRIPT), *arguments],
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
        [str(DEVELOPER_ACTIVATION_SCRIPT), *arguments],
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
            "bash",
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
    canary = source[
        source.index("start_source_gateway_canary()") : source.index("parse_args()")
    ]

    assert "http://127.0.0.1:18970/health" in canary
    assert 'gateway.get("state") not in {"running", "disabled"}' in canary
    assert 'provenance.get("binary_version") != sys.argv[2]' in canary
    assert "version-bound healthy before resolver handoff" in canary
    assert "did not reach version-bound health" in canary


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
    assert stat.S_IMODE(openclaw_home.stat().st_mode) == 0o700


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


def test_protected_release_test_artifact_rejects_checksum_mismatch_without_output(
    tmp_path: Path,
) -> None:
    source = tmp_path / "defenseclaw-0.8.4-2-py3-none-any.dcwheel"
    source.write_bytes(
        b"DEFENSECLAW-PROTECTED-ARTIFACT-V1\n" + bytes(value ^ 0xA5 for value in b"wheel")
    )
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
    lines = [
        line
        for line in UPGRADE_SCRIPT.read_text(encoding="utf-8").splitlines()
        if "gateway.jsonl" in line
    ]
    assert lines
    for line in lines:
        normalized = line.lower()
        assert "optional" in normalized, line
        assert "destination" in normalized, line


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
        'SMOKE_HOME="$2"; FROM_VERSION="$3"; mkdir -p "$SMOKE_HOME"; '
        "seed_v8_observability_fixture",
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
    [("0.8.3", "7"), ("0.8.2", "6"), ("0.6.6", "5")],
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
        'UPGRADE_BASELINE_POLICY="$2"; CANDIDATE_RUNTIME_CONFIG_VERSION=8; '
        'published_baseline_config_version "$3"',
        str(policy),
        "0.8.5",
    )
    assert accepted.returncode == 0, accepted.stderr
    assert accepted.stdout.strip() == "8"

    effective["published_baseline_config_versions"]["0.8.5"] = 9
    policy.write_text(json.dumps(effective), encoding="utf-8")
    rejected = _source_script(
        'UPGRADE_BASELINE_POLICY="$2"; CANDIDATE_RUNTIME_CONFIG_VERSION=8; '
        'published_baseline_config_version "$3"',
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
        BASELINE_POLICY
        if source_version == "0.8.4"
        else _policy_with_baseline(tmp_path, source_version, source_config)
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
        'TARGET_VERSION=0.8.7; FROM_VERSION=0.8.6; '
        'seed_v8_observability_fixture() { exit 91; }; '
        'seed_native_v8_observability_fixture() { exit 92; }; '
        "seed_upgrade_fixture",
        str(policy),
    )

    assert completed.returncode != 0
    assert "no reviewed upgrade fixture exists for config-v9 baseline 0.8.6" in completed.stderr


def test_native_v8_fixture_is_strict_and_later_migration_preserves_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _policy_with_baseline(tmp_path, "0.8.5", 8)
    home = tmp_path / "home"
    baseline_python = home / ".defenseclaw/.venv/bin/python"
    baseline_python.parent.mkdir(parents=True)
    baseline_python.write_text(
        f"""#!/bin/sh
exec "{ROOT / '.venv/bin/python'}" "$@"
""",
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
    config_path = data_dir / "config.yaml"
    environment_path = data_dir / ".env"
    config_before = config_path.read_bytes()
    environment_before = environment_path.read_bytes()
    source = load_validate_v8(config_before, source_name=str(config_path)).source
    assert source["config_version"] == 8
    assert not {"otel", "audit_sinks", "privacy"}.intersection(source)
    destinations = {
        item["name"]: item for item in source["observability"]["destinations"]
    }
    assert set(destinations) == {"existing-otlp", "v8-http-protected"}
    assert destinations["existing-otlp"]["headers"] == {
        "Authorization": {"env": "DEFENSECLAW_V8_FIXTURE_OTLP_AUTHORIZATION"}
    }
    assert stat.S_IMODE(environment_path.stat().st_mode) == 0o600
    assert (home / "fixture-evidence/config.historical.source").read_bytes() == config_before
    assert (home / "fixture-evidence/environment.historical.source").read_bytes() == environment_before
    baseline_bundle_manifest = json.loads(
        (data_dir / "observability-stack/.defenseclaw-bundle-manifest.json").read_text(
            encoding="utf-8"
        )
    )
    assert baseline_bundle_manifest["bundle_version"] == "0.8.5"

    monkeypatch.setenv("DEFENSECLAW_HOME", str(data_dir))
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
    assert not list((data_dir / "backups").glob("observability-v8-*/manifest.json"))
    cursor = json.loads((data_dir / ".migration_state.json").read_text(encoding="utf-8"))
    assert "0.8.5" in cursor["applied"]


def test_harnesses_accept_one_materialized_policy_snapshot() -> None:
    posix = SCRIPT.read_text(encoding="utf-8")
    windows = (ROOT / "scripts/test-upgrade-release-windows.ps1").read_text(
        encoding="utf-8"
    )

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
        'terminal_receipt.get("from_version") != bridge_version',
    ):
        assert contract in text


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
    assert line.split("?=", 1)[1].split() == baselines


def test_bridge_harness_keeps_v8_source_contracts_strictly_target_gated() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    assert "run_v8_source_contract_tests" in script
    assert 'WORKDIR="$(abs_path "$(mktemp -d ' in script
    function_start = script.index("run_v8_source_contract_tests()")
    gate = script.index("target_uses_observability_v8 || return 0", function_start)
    pytest_call = script.index("uv run python -m pytest", function_start)
    assert gate < pytest_call
    assert 'if [[ "${BASH_SOURCE[0]}" == "$0" ]]' in script


def test_harness_embedded_python_and_v8_verifier_contract_are_static_valid() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
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
    ):
        assert verifier_contract in script

    developer = DEVELOPER_ACTIVATION_SCRIPT.read_text(encoding="utf-8")
    assert "legacy_source = source_config_version < 8" in developer
    assert "native-v8 source unexpectedly ran the v7-to-v8 activation" in developer
    assert "developer_target_native_v8_continuity=" in developer


def test_prepare_only_windows_candidate_validates_zip_and_plain_refusal_envelope() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert "windows/amd64|windows/arm64" in script
    assert 'extension = "zip" if os_name == "windows" else "tar.gz"' in script
    assert 'with zipfile.ZipFile(gateway_source) as archive:' in script
    assert 'Path(member.filename.replace("\\\\", "/")).is_absolute()' in script
    assert 'Path(member.filename.replace("\\\\", "/")).name == "defenseclaw.exe"' in script
    assert "canonical Windows gateway refusal envelope became installable" in script


def test_bridge_candidate_refusal_contract_uses_bridge_specific_message() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert 'if version == "0.8.4":' in script
    assert (
        "DefenseClaw 0.8.4 must be installed by the release-owned staged upgrade resolver."
        in script
    )


def test_retired_named_otel_backup_is_checked_only_for_pre_v8_targets() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    assert script.count("config.yaml.pre-observability-migration.bak") == 1


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
    protected = (
        "upgrade-smoke-flat-protected-value",
        "upgrade-smoke-splunk-protected-value",
        "upgrade-smoke-http-protected-value",
        "Bearer upgrade-smoke-otlp-protected-value",
    )
    log = tmp_path / "upgrade.log"
    log.write_text("\n".join(protected) + "\nordinary diagnostic\n", encoding="utf-8")

    completed = _source_script('tail_v8_upgrade_log_secret_safe "$2"', str(log))

    assert completed.returncode == 0
    assert "ordinary diagnostic" in completed.stderr
    assert "[REDACTED]" in completed.stderr
    assert all(value not in completed.stderr for value in protected)
