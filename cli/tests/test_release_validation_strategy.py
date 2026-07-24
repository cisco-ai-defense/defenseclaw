# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from scripts import release_certification

ROOT = Path(__file__).resolve().parents[2]
CI_PATH = ROOT / ".github/workflows/ci.yml"
RELEASE_PATH = ROOT / ".github/workflows/release.yaml"
CERTIFICATION_PATH = ROOT / ".github/workflows/pre-release-certification.yml"
POLICY_PATH = ROOT / "release/certification-policy.json"


def _workflow(path: Path) -> dict[str, Any]:
    return yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def _render(value: object) -> str:
    return str(value)


def test_ordinary_ci_is_deterministic_and_selective_not_full_certification() -> None:
    workflow = _workflow(CI_PATH)
    jobs = workflow["jobs"]
    text = CI_PATH.read_text(encoding="utf-8")

    deterministic = jobs["upgrade-smoke"]
    assert "if" not in deterministic
    assert deterministic["name"] == "Release Regression (deterministic)"
    assert "test_release_certification.py" in _render(deterministic)
    assert "test_release_api_retry.py" in _render(deterministic)

    plan = _render(jobs["release-validation-plan"])
    assert "scripts/release_certification.py paths" in plan
    assert "--scope pr" in plan
    selective = jobs["selective-upgrade-smoke"]
    assert "pull_request" in selective["if"]
    assert "outputs.sensitive == 'true'" in selective["if"]
    assert "fromJSON(needs.release-validation-plan.outputs.pr_matrix)" in _render(selective["strategy"])
    rendered_selective = _render(selective)
    assert rendered_selective.count('--target-version "$CANDIDATE_VERSION"') == 2
    assert rendered_selective.count("scripts/test-developer-target-activation.sh") == 1
    assert rendered_selective.count("scripts/test-upgrade-protocol-release.sh") == 1
    assert 'case "$EXPECTED_RESULT" in' in rendered_selective
    assert "success-and-refusal) run_success; run_refusal" in rendered_selective
    assert "Unknown selective validation result" in rendered_selective
    assert "--scope full" not in text
    assert "unsigned-upgrade-candidate" in selective["needs"]
    pr = release_certification.select_cases("0.8.6", "pr", latest_stable="0.8.5")
    assert {behavior_class for item in pr["cases"] for behavior_class in item["classes"]} == {
        "latest_stable",
        "previous_stable",
        "bridge_boundary",
        "explicit_skip_refusal",
        "oldest_supported",
    }
    assert len(pr["cases"]) == 4

    # A PR may exercise deterministic resolver models, but it may not construct,
    # sign, or run the expensive live certification candidate.
    assert "cosign sign-blob" not in text
    assert "uses: ./.github/workflows/pre-release-certification.yml" not in text
    assert "scripts/test-observability-v8-upgrade-continuity.sh" not in text
    assert "historical-dependency-canary:" not in text

    sensitive = set(json.loads(POLICY_PATH.read_text())["release_sensitive_paths"])
    assert {
        ".gitattributes",
        ".goreleaser.yaml",
        "MANIFEST.in",
        "go.mod",
        "go.sum",
        "pyproject.toml",
        "setup.py",
        "uv.lock",
        "cli/defenseclaw/__init__.py",
        "cli/defenseclaw/migration_state.py",
        "cli/defenseclaw/upgrade_receipt.py",
        "cli/defenseclaw/observability/v8_activation.py",
        "cli/defenseclaw/observability/v8_config.py",
        "internal/config/**",
        "internal/cli/**",
        "internal/daemon/**",
        "bundles/local_observability_stack/**",
        "schemas/config/v8/**",
        "extensions/defenseclaw/package.json",
        "extensions/defenseclaw/package-lock.json",
        "macos/DefenseClawMac/DefenseClawMac.xcodeproj/project.pbxproj",
        "scripts/resolve_upgrade_baselines.py",
        "scripts/release_api_retry.py",
        "scripts/generate-upgrade-manifest.py",
        "scripts/test-historical-bootstrap-dependencies.sh",
        "scripts/verify-sigstore-blob.py",
        "scripts/check_observability_v8_upgrade_continuity.py",
        "scripts/test-developer-target-activation.sh",
        "scripts/test-fresh-install-release.sh",
        "scripts/build-windows-installer.ps1",
        "scripts/windows-native-ci.ps1",
        "scripts/build-macos-app-release.sh",
        ".github/workflows/macos-app.yml",
        "scripts/export-uv-overrides.py",
        "scripts/telemetry_runtime_assets.py",
        "scripts/validate_packaged_v8_resources.py",
    }.issubset(sensitive)
    assert release_certification._is_sensitive(
        ["scripts/validate_packaged_v8_resources.py"],
        list(sensitive),
    )
    assert release_certification._is_sensitive(
        ["scripts/test-historical-bootstrap-dependencies.sh"],
        list(sensitive),
    )
    assert release_certification._is_sensitive(
        ["internal/daemon/daemon.go"],
        list(sensitive),
    )


def test_no_pull_request_workflow_can_run_full_or_signed_certification() -> None:
    pull_request_workflows: list[Path] = []
    for path in sorted((ROOT / ".github/workflows").glob("*.y*ml")):
        workflow = _workflow(path)
        triggers = workflow.get("on", {})
        if isinstance(triggers, dict):
            trigger_names = set(triggers)
        elif isinstance(triggers, list):
            trigger_names = set(triggers)
        elif isinstance(triggers, str):
            trigger_names = {triggers}
        else:
            trigger_names = set()
        if {
            "pull_request",
            "pull_request_target",
        }.intersection(trigger_names):
            pull_request_workflows.append(path)

    assert pull_request_workflows
    forbidden = (
        "uses: ./.github/workflows/pre-release-certification.yml",
        "--scope full",
        "scripts/test-observability-v8-upgrade-continuity.sh",
        "cosign sign-blob",
        "historical-dependency-canary:",
    )
    for path in pull_request_workflows:
        text = path.read_text(encoding="utf-8")
        for contract in forbidden:
            assert contract not in text, (path, contract)

        for job in (_workflow(path).get("jobs") or {}).values():
            for step in job.get("steps", []):
                rendered = _render(step)
                if "scripts/test-upgrade-protocol-release.sh" in rendered:
                    assert "--refusal-contract-only" in rendered, path


def test_main_smoke_is_bound_to_exact_sha_and_runs_representative_canary() -> None:
    workflow = _workflow(CI_PATH)
    jobs = workflow["jobs"]
    main = jobs["main-release-smoke"]
    rendered = _render(main)

    assert "github.event.pull_request.number || github.sha" in workflow["concurrency"]["group"]
    assert "github.event_name == 'push'" in main["if"]
    assert "github.ref == 'refs/heads/main'" in main["if"]
    assert "ref': '${{ github.sha }}" in rendered
    assert 'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"' in rendered
    assert "--baseline-dependencies published" in rendered
    assert '--target-version "$CANDIDATE_VERSION"' in rendered
    assert 'release-root "$GITHUB_WORKSPACE/unsigned-candidate"' in rendered
    assert "scripts/test-developer-target-activation.sh" in rendered
    assert "scripts/test-upgrade-release.sh" not in rendered
    assert "unsigned-upgrade-candidate" in main["needs"]
    assert "--refusal-contract-only" not in rendered


def test_release_builds_tests_and_publishes_in_one_dispatch() -> None:
    workflow = _workflow(RELEASE_PATH)
    jobs = workflow["jobs"]
    triggers = workflow["on"]
    text = RELEASE_PATH.read_text(encoding="utf-8")

    assert set(triggers) == {"workflow_dispatch"}
    assert set(triggers["workflow_dispatch"]["inputs"]) == {
        "version",
        "immutable_releases_confirmed",
    }
    assert workflow["concurrency"] == {
        "group": "release-${{ github.repository }}",
        "cancel-in-progress": "false",
    }
    assert set(jobs) == {
        "release-preflight",
        "build-runtime-candidate",
        "macos-app",
        "windows-installer",
        "windows-real-client-certification",
        "assemble-release-candidate",
        "release-smoke",
        "publish-release",
    }

    build = jobs["build-runtime-candidate"]
    assert build["needs"] == "release-preflight"
    assert "if" not in build
    assert "scripts/release_candidate.py prepare-runtime" in _render(build)

    assemble = jobs["assemble-release-candidate"]
    assert assemble["needs"] == [
        "release-preflight",
        "build-runtime-candidate",
        "macos-app",
        "windows-real-client-certification",
    ]
    assert "scripts/release_candidate.py seal" in _render(assemble)
    assert assemble["outputs"]["artifact_name"] == ("${{ steps.names.outputs.candidate }}")

    smoke = jobs["release-smoke"]
    assert smoke["needs"] == [
        "release-preflight",
        "assemble-release-candidate",
    ]
    assert smoke["uses"] == "./.github/workflows/pre-release-certification.yml"
    assert smoke["with"]["candidate_artifact"] == ("${{ needs.assemble-release-candidate.outputs.artifact_name }}")

    publish = jobs["publish-release"]
    assert publish["needs"] == [
        "release-preflight",
        "assemble-release-candidate",
        "release-smoke",
    ]
    assert publish["permissions"] == {"contents": "write"}
    assert "scripts/release_candidate.py verify" in _render(publish)
    assert "scripts/release_candidate.py list-assets" in _render(publish)
    for name, job in jobs.items():
        if name != "publish-release":
            assert job.get("permissions") != {"contents": "write"}

    for retired in (
        "schedule:",
        "lookup-certification:",
        "record-certification:",
        "platform-readiness:",
        "full-certification:",
        "select-candidate:",
        "operation=certify",
        "operation=release",
        "verify-metadata",
        "certification_run_attempt",
        "CI_WAIT_ATTEMPTS",
    ):
        assert retired not in text


def test_release_smoke_is_exact_candidate_install_and_upgrade_only() -> None:
    workflow = _workflow(CERTIFICATION_PATH)
    jobs = workflow["jobs"]
    text = CERTIFICATION_PATH.read_text(encoding="utf-8")

    assert set(workflow["on"]) == {"workflow_call"}
    assert set(workflow["on"]["workflow_call"]["inputs"]) == {
        "candidate_artifact",
        "version",
        "commit",
        "baselines",
    }
    assert set(jobs) == {
        "posix-fresh-install",
        "posix-upgrade",
        "windows-fresh-install",
    }

    posix_fresh = _render(jobs["posix-fresh-install"])
    assert "scripts/release_candidate.py verify" in posix_fresh
    assert "scripts/verify-sigstore-blob.py" in posix_fresh
    assert "scripts/test-fresh-install-release.sh" in posix_fresh

    upgrade = jobs["posix-upgrade"]
    assert upgrade["strategy"]["matrix"] == {
        "baseline": "${{ fromJSON(inputs.baselines) }}",
        "platform": [
            {
                "runner": "ubuntu-latest",
                "name": "linux-amd64",
                "runner_arch": "X64",
            },
            {
                "runner": "macos-15",
                "name": "darwin-arm64",
                "runner_arch": "ARM64",
            },
        ],
    }
    rendered_upgrade = _render(upgrade)
    assert "scripts/release_candidate.py verify" in rendered_upgrade
    assert "scripts/test-upgrade-protocol-release.sh" in rendered_upgrade
    assert "--success-path-only" in rendered_upgrade

    windows = _render(jobs["windows-fresh-install"])
    assert "scripts/release_candidate.py verify" in windows
    assert "scripts/test-fresh-install-release-windows.ps1" in windows
    for retired in (
        "windows-upgrade",
        "test-upgrade-release-windows.ps1",
        "live-continuity",
        "test-observability-v8-upgrade-continuity.sh",
        "release-certification",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
    ):
        assert retired not in text


def test_effective_baselines_are_authenticated_once_and_bound_to_candidate() -> None:
    workflow = _workflow(RELEASE_PATH)
    preflight = workflow["jobs"]["release-preflight"]
    resolve = next(
        step for step in preflight["steps"] if step.get("name") == "Resolve authenticated POSIX upgrade baselines"
    )
    script = resolve["run"]

    assert "scripts/resolve_upgrade_baselines.py" in script
    assert "required_families = ((0, 7), (0, 6), (0, 5))" in script
    assert "upgrade_baselines = [max(older, key=key)]" in script
    assert "selected = max(family_versions, key=key)" in script
    assert 'document["platform_published_baselines"]["windows"] = []' in script
    assert "upgrade_baselines=" in script

    release = RELEASE_PATH.read_text(encoding="utf-8")
    assert "effective-upgrade-baselines.json" in release
    assert release.count("scripts/resolve_upgrade_baselines.py") == 1
    assert (
        workflow["jobs"]["release-smoke"]["with"]["baselines"]
        == "${{ needs.release-preflight.outputs.upgrade_baselines }}"
    )
    assert "--omit-windows-binaries" not in release
