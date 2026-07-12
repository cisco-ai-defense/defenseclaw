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
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "test-upgrade-release.sh"
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


def test_source_gateway_canary_waits_for_exact_version_bound_health() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    canary = source[
        source.index("start_source_gateway_canary()") : source.index("parse_args()")
    ]

    assert "http://127.0.0.1:18970/health" in canary
    assert 'gateway.get("state") != "running"' in canary
    assert 'provenance.get("binary_version") != sys.argv[2]' in canary
    assert "did not reach version-bound health" in canary


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


def test_v8_verifier_proves_historical_and_bridge_backup_layers() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    for contract in (
        "config.historical.source",
        "phase1-source-gateway",
        "phase two retained no distinct byte-exact config-v7 bridge backup",
        'terminal_receipt.get("from_version") != bridge_version',
    ):
        assert contract in text


def test_bridge_source_tree_does_not_ship_the_v8_runtime_or_migration() -> None:
    package = ROOT / "cli" / "defenseclaw"
    assert not (package / "observability" / "v8_migration.py").exists()
    assert not (package / "observability" / "v8_activation.py").exists()
    assert "SUPPORTED_CONFIG_VERSIONS = (8,)" not in (package / "config.py").read_text(
        encoding="utf-8"
    )


def test_matrix_matches_every_reviewed_published_baseline_and_schema() -> None:
    line = next(
        line for line in MAKEFILE.read_text(encoding="utf-8").splitlines() if line.startswith("UPGRADE_SMOKE_FROM")
    )
    policy = json.loads(BASELINE_POLICY.read_text(encoding="utf-8"))
    baselines = policy["published_baselines"]

    assert policy["schema_version"] == 2
    assert baselines[0] == "0.8.3"
    assert policy["published_baseline_config_versions"] == {
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
    lines = script.splitlines()
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
        compile(program, str(SCRIPT), "exec")
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
    ):
        assert verifier_contract in script


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
