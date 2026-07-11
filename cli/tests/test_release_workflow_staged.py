# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/release.yaml"
PROTOCOL_GATE = ROOT / "scripts/test-upgrade-protocol-release.sh"
MACOS_BUILD = ROOT / "scripts/build-macos-app-release.sh"
POSIX_INSTALLER = ROOT / "scripts/install.sh"


def _workflow() -> dict[str, object]:
    return yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def test_release_is_manual_and_default_permissions_are_read_only() -> None:
    workflow = _workflow()
    assert workflow["on"] == {
        "workflow_dispatch": {
            "inputs": {
                "version": {
                    "description": "Version to release (X.Y.Z, no v prefix). Tag must not already exist.",
                    "required": "true",
                    "type": "string",
                }
            }
        }
    }
    assert workflow["permissions"] == {"contents": "read"}


def test_release_requires_protected_main_and_non_bypassable_environment() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert 'GITHUB_REF" != "refs/heads/main' in text
    assert "is not the current origin/main tip" in text
    assert "can_admins_bypass" in text
    assert "required_reviewers" in text
    assert "protected_branches" in text
    assert "custom_branch_policies" in text
    assert "refs/heads/release/" not in text


def test_publish_job_is_downstream_of_every_native_upgrade_gate() -> None:
    jobs = _workflow()["jobs"]
    publish = jobs["publish-release"]
    assert set(publish["needs"]) == {
        "release-preflight",
        "assemble-release-candidate",
        "linux-upgrade",
        "macos-upgrade",
        "windows-upgrade",
        "live-continuity",
    }
    assert publish["environment"] == "release"
    assert publish["permissions"] == {"contents": "write"}
    for name, job in jobs.items():
        if name != "publish-release":
            assert job.get("permissions") != {"contents": "write"}


def test_build_once_candidate_is_reused_by_tests_and_publisher() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert text.count("goreleaser/goreleaser-action@") == 1
    assert text.count("make dist-cli") == 1
    assert text.count("make dist-plugin") == 1
    assert text.count("make extensions") == 1
    assert text.count("scripts/release_candidate.py assemble") == 1
    assert "steps.upload.outputs.artifact-digest" not in text

    macos_job = str(_workflow()["jobs"]["macos-app"])
    assert "scripts/release_candidate.py extract-gateway" in macos_job
    assert "MACOS_GATEWAY_INPUT" in macos_job
    assert "make extensions" not in macos_job

    jobs = _workflow()["jobs"]
    for name in (
        "linux-upgrade",
        "macos-upgrade",
        "windows-upgrade",
        "live-continuity",
        "publish-release",
    ):
        rendered = str(jobs[name])
        assert "needs.assemble-release-candidate.outputs.artifact_name" in rendered
        assert "scripts/release_candidate.py verify" in rendered


def test_macos_app_consumes_and_validates_sealed_runtime_gateway() -> None:
    text = MACOS_BUILD.read_text(encoding="utf-8")
    assert 'GATEWAY_INPUT="${MACOS_GATEWAY_INPUT:-}"' in text
    assert "regular non-symlink candidate binary" in text
    assert 'cmp -s "${GATEWAY_INPUT}" "${GATEWAY}"' in text
    assert "Mach-O 64-bit executable arm64" in text
    assert '"${GATEWAY}" --version' in text
    assert "gateway candidate version mismatch" in text


def test_posix_installer_cannot_bypass_upgrade_graph_on_existing_install() -> None:
    text = POSIX_INSTALLER.read_text(encoding="utf-8")
    assert "An existing DefenseClaw installation was detected. No changes were made." in text
    assert "release-owned upgrade resolver" in text
    guard = text.index("An existing DefenseClaw installation was detected")
    assert guard < text.index("detect_platform", guard)


def test_upgrade_matrix_is_manifest_and_reviewed_data_driven() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    jobs = _workflow()["jobs"]
    assert "release/upgrade-baselines.json" in text
    assert 'json.dumps(older, separators=(",", ":"))' in text
    for name in ("linux-upgrade", "macos-upgrade"):
        assert jobs[name]["strategy"]["matrix"]["baseline"] == (
            "${{ fromJSON(needs.release-preflight.outputs.baselines) }}"
        )
    assert jobs["windows-upgrade"]["strategy"]["matrix"]["baseline"] == (
        "${{ fromJSON(needs.assemble-release-candidate.outputs.windows_baselines) }}"
    )
    assert "-SourceVersion \"$env:BASELINE\"" in text
    assert "scripts/test-upgrade-protocol-release.sh" in text
    assert "scripts/test-upgrade-release-windows.ps1" in text
    assert "required_bridge_version" in text
    assert "min_upgrade_protocol" in text
    assert "auto_bridge_from does not match the reviewed pre-bridge matrix" in text
    assert "Require immutable published bridge" in text
    assert 'release.get("isImmutable") is not True' in text
    assert "set(published_asset_names(expected))" in text
    assert not re.search(r"\b0\.8\.[45]\b", text)


def test_only_final_step_can_create_remote_release_or_tag() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert text.count("gh release create") == 1
    assert "gh release upload" not in text
    assert "git push" not in text
    assert "push:\n" not in text
    assert "Publish tag and all sealed assets" in text
    assert "verify-published" in text


def test_every_remote_action_is_commit_pinned() -> None:
    uses = re.findall(r"^\s*- uses:\s*([^\s#]+)", WORKFLOW.read_text(encoding="utf-8"), re.MULTILINE)
    assert uses
    for action in uses:
        assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", action), action


def test_protocol_gate_proves_both_refusal_paths_and_full_success() -> None:
    text = PROTOCOL_GATE.read_text(encoding="utf-8")
    assert 'receipt.get("migration_status") != "completed"' in text
    for contract in (
        "CANDIDATE_MIN_PROTOCOL",
        "MINIMUM_SOURCE_VERSION",
        "REQUIRED_BRIDGE_VERSION",
        "baseline_protocol",
        "run_installed_controller_refusal",
        "run_candidate_updater_refusal",
        "run_candidate_updater_staged_success",
        "prepare_required_bridge_assets",
        "DEFENSECLAW_UPGRADE_TEST_RELEASE_BASE_URL",
        "assert_staged_success_receipt",
        "UPGRADE_GATE_STOP_MARKER",
        "gateway sentinel PID changed",
        "assert_no_success_receipt",
        "run_one_upgrade_smoke",
        "upgrade bridge|without --version",
    ):
        assert contract in text
    assert "scripts/upgrade.sh\" --yes --version" in text
    assert 'scripts/upgrade.sh\" --yes >"${log_file}"' in text
    assert not re.search(r"TARGET_VERSION[^\n]*0\.8\.", text)


def test_protocol_cleanup_accepts_an_empty_sentinel_array() -> None:
    completed = subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; REFUSAL_SENTINEL_PIDS=(); WORKDIR=""; SERVER_PID=""; protocol_cleanup',
            "protocol-cleanup-test",
            str(PROTOCOL_GATE),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
