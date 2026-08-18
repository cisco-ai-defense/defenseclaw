# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from scripts import release_certification

ROOT = Path(__file__).resolve().parents[2]
COMMIT = "a" * 40
DIGEST = "b" * 64
CERTIFIED_AT = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)


def _versions(selection: dict[str, Any]) -> list[str]:
    return [item["version"] for item in selection["baselines"]]


def _selection() -> dict[str, Any]:
    return release_certification.select_cases("0.8.5", "full")


def _candidate(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "candidate"
    root.mkdir()
    (root / "release-candidate.json").write_text('{"schema_version":1,"sealed":true}\n', encoding="utf-8")
    workflow = tmp_path / "pre-release-certification.yml"
    workflow.write_text("name: Pre-release certification\n", encoding="utf-8")
    return root, workflow


def _metadata(tmp_path: Path) -> tuple[dict[str, Any], dict[str, Any], Path, Path]:
    selection = _selection()
    root, workflow = _candidate(tmp_path)
    metadata = release_certification.create_metadata(
        selection=selection,
        repository="cisco-ai-defense/defenseclaw",
        commit=COMMIT,
        candidate_root=root,
        artifact_id="123",
        artifact_name="release-candidate-123-1",
        artifact_digest=DIGEST,
        run_id="456",
        run_attempt=2,
        workflow_file=workflow,
        tested_baselines=_versions(selection),
        completed_at=CERTIFIED_AT,
    )
    return metadata, selection, root, workflow


def test_pr_selection_covers_five_risk_classes_without_duplicate_execution() -> None:
    selection = release_certification.select_cases("0.8.5", "pr")

    covered = {behavior_class for item in selection["cases"] for behavior_class in item["classes"]}
    assert covered == {
        "latest_stable",
        "previous_stable",
        "bridge_boundary",
        "explicit_skip_refusal",
        "oldest_supported",
    }
    assert len(selection["cases"]) == 4
    assert selection["cases"][0]["classes"] == ["latest_stable", "bridge_boundary"]
    assert _versions(selection) == ["0.8.4", "0.8.3", "0.4.0"]
    refusal = selection["cases"][2]
    assert refusal == {
        "class": "explicit_skip_refusal",
        "classes": ["explicit_skip_refusal"],
        "baseline": "0.8.3",
        "mode": "explicit-direct-target",
        "expected": "refusal-before-mutation",
        "start_source_gateway": False,
    }


def test_full_selection_uses_behavior_and_derived_boundary_classes() -> None:
    selection = _selection()

    assert _versions(selection) == [
        "0.8.4",
        "0.8.3",
        "0.8.2",
        "0.7.1",
        "0.6.6",
        "0.6.1",
        "0.6.0",
        "0.4.0",
    ]
    classes = {item["version"]: set(item["classes"]) for item in selection["baselines"]}
    assert {"latest_stable", "bridge_boundary"}.issubset(classes["0.8.4"])
    assert {
        "previous_stable",
        "explicit_skip_refusal",
        "pre_v8_hard_cut_source",
    }.issubset(classes["0.8.3"])
    assert "protocol_installer_boundaries" in classes["0.8.2"]
    assert "protocol_installer_boundaries" in classes["0.6.1"]
    assert "protocol_installer_boundaries" in classes["0.6.0"]
    assert classes["0.4.0"] == {"oldest_supported"}


def test_live_latest_stable_is_used_before_lagging_reviewed_inventory() -> None:
    selection = release_certification.select_cases(
        "0.8.6",
        "pr",
        latest_stable="0.8.5",
    )

    assert _versions(selection) == ["0.8.5", "0.8.4", "0.8.3", "0.4.0"]
    classes = {item["version"]: set(item["classes"]) for item in selection["baselines"]}
    assert classes["0.8.5"] == {"latest_stable"}
    assert classes["0.8.4"] == {"previous_stable", "bridge_boundary"}
    assert classes["0.8.3"] == {"explicit_skip_refusal"}
    assert len(selection["cases"]) == 4
    previous = next(item for item in selection["cases"] if item["baseline"] == "0.8.4")
    assert previous["classes"] == ["previous_stable", "bridge_boundary"]


def test_selector_rejects_stale_or_nonpreceding_latest_stable_claim() -> None:
    with pytest.raises(release_certification.CertificationError, match="newest eligible"):
        release_certification.select_cases(
            "0.8.6",
            "pr",
            latest_stable="0.8.3",
        )
    with pytest.raises(release_certification.CertificationError, match="must precede"):
        release_certification.select_cases(
            "0.8.6",
            "pr",
            latest_stable="0.8.6",
        )


def test_posix_bridge_policy_never_claims_windows_runtime() -> None:
    policy = release_certification.load_policy()
    full = policy["profile_platform_sets"]["full"]

    assert "windows-resolver-refusal" in full
    assert all(not item.startswith("windows-") or item == "windows-resolver-refusal" for item in full)
    baselines = release_certification.load_baseline_policy()
    assert "0.8.4" not in baselines["platform_published_baselines"]["windows"]


def test_first_windows_release_allows_no_historical_windows_baseline(
    tmp_path: Path,
) -> None:
    policy = json.loads((ROOT / "release" / "upgrade-baselines.json").read_text(encoding="utf-8"))
    policy["platform_published_baselines"]["windows"] = []
    path = tmp_path / "effective-upgrade-baselines.json"
    path.write_text(json.dumps(policy), encoding="utf-8")

    loaded = release_certification.load_baseline_policy(path)

    assert loaded["published_baselines"]
    assert loaded["platform_published_baselines"] == {"windows": []}

    policy["published_baselines"] = []
    policy["published_baseline_config_versions"] = {}
    path.write_text(json.dumps(policy), encoding="utf-8")
    with pytest.raises(release_certification.CertificationError, match="must be non-empty"):
        release_certification.load_baseline_policy(path)


def test_resolve_version_prefers_request_or_next_live_stable_patch() -> None:
    releases = [
        {"tag_name": "0.8.5", "draft": False, "prerelease": False},
        {"tag_name": "0.8.4", "draft": False, "prerelease": False},
        {"tag_name": "0.9.0-rc1", "draft": False, "prerelease": True},
    ]

    assert release_certification.resolve_version(
        requested=None,
        source_version="0.8.5",
        published_releases=releases,
    ) == ("0.8.6", "0.8.5")
    assert release_certification.resolve_version(
        requested=None,
        source_version="0.9.0",
        published_releases=releases,
    ) == ("0.9.0", "0.8.5")
    assert release_certification.resolve_version(
        requested="1.0.0",
        source_version="0.8.5",
        published_releases=releases,
    ) == ("1.0.0", "0.8.5")


def test_release_version_resolution_rejects_v_prefixed_tags() -> None:
    releases = [{"tag_name": "v0.8.5", "draft": False, "prerelease": False}]

    with pytest.raises(release_certification.CertificationError, match="no canonical stable"):
        release_certification.resolve_version(
            requested=None,
            source_version="0.8.5",
            published_releases=releases,
        )


def test_workflow_version_is_automatic_digest_of_helper_and_policies(tmp_path: Path) -> None:
    policy = tmp_path / "policy.json"
    policy.write_bytes(release_certification.DEFAULT_POLICY.read_bytes())
    first = release_certification.workflow_version(policy_path=policy)

    document = json.loads(policy.read_text())
    document["max_age_hours"] = 48
    policy.write_text(json.dumps(document), encoding="utf-8")
    second = release_certification.workflow_version(policy_path=policy)

    assert first.startswith("sha256:")
    assert second.startswith("sha256:")
    assert first != second


def test_certification_round_trip_binds_full_candidate_custody(tmp_path: Path) -> None:
    metadata, selection, root, workflow = _metadata(tmp_path)

    outputs = release_certification.verify_metadata(
        metadata,
        selection=selection,
        repository="cisco-ai-defense/defenseclaw",
        commit=COMMIT,
        candidate_root=root,
        workflow_file=workflow,
        now=CERTIFIED_AT + timedelta(hours=1),
    )

    assert outputs["artifact_id"] == "123"
    assert outputs["artifact_name"] == "release-candidate-123-1"
    assert outputs["artifact_digest"] == f"sha256:{DIGEST}"
    assert outputs["certification_run_id"] == "456"
    assert outputs["certification_run_attempt"] == "2"
    assert outputs["valid_until"] == "2026-07-19T12:00:00Z"
    assert json.loads(outputs["tested_baselines"]) == _versions(selection)
    assert metadata["workflow_version"].startswith("sha256:")
    assert metadata["workflow_file_sha256"].startswith("sha256:")
    assert metadata["certification_key"].startswith("sha256:")


def test_metadata_creation_refuses_partial_or_reordered_matrix(tmp_path: Path) -> None:
    selection = _selection()
    root, workflow = _candidate(tmp_path)

    with pytest.raises(release_certification.CertificationError, match="exactly match"):
        release_certification.create_metadata(
            selection=selection,
            repository="cisco-ai-defense/defenseclaw",
            commit=COMMIT,
            candidate_root=root,
            artifact_id="123",
            artifact_name="release-candidate-123-1",
            artifact_digest=DIGEST,
            run_id="456",
            run_attempt=1,
            workflow_file=workflow,
            tested_baselines=list(reversed(_versions(selection))),
            completed_at=CERTIFIED_AT,
        )


@pytest.mark.parametrize("value", (None, 7, [], {}))
def test_digest_normalization_rejects_non_string_metadata(value: object) -> None:
    with pytest.raises(release_certification.CertificationError, match="lowercase SHA-256"):
        release_certification._normalize_digest(value, "candidate artifact digest")


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("candidate_version", "0.8.6", "candidate version"),
        ("workflow_version", f"sha256:{'c' * 64}", "content digest"),
        ("platform_set", ["linux-amd64"], "content digest"),
        ("tested_baselines", [], "content digest"),
        ("tested_cases", [], "content digest"),
        ("completed_at", "2026-07-15T12:00:00Z", "content digest"),
    ],
)
def test_verify_rejects_tampered_metadata(
    tmp_path: Path,
    field: str,
    value: object,
    message: str,
) -> None:
    metadata, selection, root, workflow = _metadata(tmp_path)
    tampered = copy.deepcopy(metadata)
    tampered[field] = value

    with pytest.raises(release_certification.CertificationError, match=message):
        release_certification.verify_metadata(
            tampered,
            selection=selection,
            repository="cisco-ai-defense/defenseclaw",
            commit=COMMIT,
            candidate_root=root,
            workflow_file=workflow,
            now=CERTIFIED_AT + timedelta(hours=1),
        )


def test_verify_rejects_stale_or_different_workflow(tmp_path: Path) -> None:
    metadata, selection, root, workflow = _metadata(tmp_path)

    with pytest.raises(release_certification.CertificationError, match="stale"):
        release_certification.verify_metadata(
            metadata,
            selection=selection,
            repository="cisco-ai-defense/defenseclaw",
            commit=COMMIT,
            candidate_root=root,
            workflow_file=workflow,
            now=CERTIFIED_AT + timedelta(hours=73),
        )

    workflow.write_text("name: changed certification\n", encoding="utf-8")
    with pytest.raises(release_certification.CertificationError, match="workflow file digest"):
        release_certification.verify_metadata(
            metadata,
            selection=selection,
            repository="cisco-ai-defense/defenseclaw",
            commit=COMMIT,
            candidate_root=root,
            workflow_file=workflow,
            now=CERTIFIED_AT + timedelta(hours=1),
        )


def test_cli_outputs_github_matrices_version_and_policy_identity(tmp_path: Path) -> None:
    releases = tmp_path / "releases.json"
    releases.write_text(
        json.dumps([{"tag_name": "0.8.5", "draft": False, "prerelease": False}]),
        encoding="utf-8",
    )
    version_output = tmp_path / "version-output"
    resolved = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/release_certification.py"),
            "resolve-version",
            "--source-version",
            "0.8.5",
            "--published-releases",
            str(releases),
            "--github-output",
            str(version_output),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert resolved.returncode == 0, resolved.stderr
    assert "candidate_version=0.8.6" in version_output.read_text()
    assert "latest_stable=0.8.5" in version_output.read_text()

    selection_output = tmp_path / "selection-output"
    selected = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/release_certification.py"),
            "select-baselines",
            "--scope",
            "pr",
            "--candidate-version",
            "0.8.6",
            "--latest-stable",
            "0.8.5",
            "--github-output",
            str(selection_output),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert selected.returncode == 0, selected.stderr
    outputs = dict(line.split("=", 1) for line in selection_output.read_text().splitlines())
    matrix = json.loads(outputs["matrix"])
    assert len(matrix["include"]) == 4
    assert {behavior_class for item in matrix["include"] for behavior_class in item["classes"]} == {
        "latest_stable",
        "previous_stable",
        "bridge_boundary",
        "explicit_skip_refusal",
        "oldest_supported",
    }
    assert outputs["workflow_version"].startswith("sha256:")


def test_path_classification_does_not_require_release_network_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        release_certification,
        "_changed_paths",
        lambda _base, _head: ["scripts/upgrade.sh"],
    )
    github_output = tmp_path / "path-output"

    assert (
        release_certification.main(
            [
                "paths",
                "--base",
                "base",
                "--head",
                "head",
                "--github-output",
                str(github_output),
            ]
        )
        == 0
    )

    assert json.loads(capsys.readouterr().out) == {
        "paths": ["scripts/upgrade.sh"],
        "sensitive": True,
    }
    outputs = dict(line.split("=", 1) for line in github_output.read_text().splitlines())
    assert outputs == {
        "sensitive": "true",
        "matrix": '{"include":[]}',
        "versions": "[]",
    }


@pytest.mark.parametrize(
    "changed_path",
    [
        "cli/defenseclaw/migration_state.py",
        "cli/defenseclaw/upgrade_receipt.py",
        "cli/defenseclaw/observability/v8_activation.py",
        "cli/defenseclaw/observability/v8_config.py",
        "internal/config/observability_v8_types.go",
        "internal/cli/status.go",
        "bundles/local_observability_stack/docker-compose.yml",
        "schemas/config/v8/defenseclaw-config.schema.json",
        "scripts/check_observability_v8_upgrade_continuity.py",
    ],
)
def test_paths_command_classifies_every_upgrade_runtime_boundary_as_sensitive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    changed_path: str,
) -> None:
    monkeypatch.setattr(
        release_certification,
        "_changed_paths",
        lambda _base, _head: [changed_path],
    )
    output = tmp_path / "github-output"

    assert (
        release_certification.main(
            [
                "paths",
                "--base",
                "base",
                "--head",
                "head",
                "--github-output",
                str(output),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == {
        "paths": [changed_path],
        "sensitive": True,
    }
    values = dict(line.split("=", 1) for line in output.read_text().splitlines())
    assert values["sensitive"] == "true"


def test_changed_paths_keeps_deletions_and_both_rename_sides(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[list[str]] = []

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        observed.append(argv)
        assert kwargs == {"check": True, "text": True, "capture_output": True}
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=("D\0scripts/upgrade.sh\0R100\0scripts/install.sh\0docs/old-installer.md\0M\0README.md\0"),
            stderr="",
        )

    monkeypatch.setattr(release_certification.subprocess, "run", run)

    assert release_certification._changed_paths("base", "head") == [
        "scripts/upgrade.sh",
        "scripts/install.sh",
        "docs/old-installer.md",
        "README.md",
    ]
    assert observed[0][-2:] == ["--diff-filter=ACDMRTUXB", "base...head"]
    assert "--find-renames" in observed[0]


def test_cli_records_and_verifies_artifact_identity_for_github_output(tmp_path: Path) -> None:
    selection = _selection()
    candidate, workflow = _candidate(tmp_path)
    metadata = tmp_path / "certification.json"
    record = [
        sys.executable,
        str(ROOT / "scripts/release_certification.py"),
        "write-metadata",
        "--scope",
        "full",
        "--candidate-version",
        "0.8.5",
        "--repository",
        "cisco-ai-defense/defenseclaw",
        "--commit",
        COMMIT,
        "--candidate-root",
        str(candidate),
        "--artifact-id",
        "123",
        "--artifact-name",
        "release-candidate-123-1",
        "--artifact-digest",
        DIGEST,
        "--run-id",
        "456",
        "--run-attempt",
        "2",
        "--workflow-file",
        str(workflow),
        "--completed-at",
        "2026-07-16T12:00:00Z",
        "--output",
        str(metadata),
    ]
    for version in _versions(selection):
        record.extend(("--tested-baseline", version))
    recorded = subprocess.run(
        record,
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert recorded.returncode == 0, recorded.stderr

    github_output = tmp_path / "verify-output"
    verified = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/release_certification.py"),
            "verify-metadata",
            "--scope",
            "full",
            "--candidate-version",
            "0.8.5",
            "--repository",
            "cisco-ai-defense/defenseclaw",
            "--commit",
            COMMIT,
            "--candidate-root",
            str(candidate),
            "--workflow-file",
            str(workflow),
            "--metadata",
            str(metadata),
            "--now",
            "2026-07-16T13:00:00Z",
            "--github-output",
            str(github_output),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert verified.returncode == 0, verified.stderr
    outputs = dict(line.split("=", 1) for line in github_output.read_text().splitlines())
    assert outputs["artifact_id"] == "123"
    assert outputs["artifact_name"] == "release-candidate-123-1"
    assert outputs["artifact_digest"] == f"sha256:{DIGEST}"
    assert outputs["certification_run_id"] == "456"
