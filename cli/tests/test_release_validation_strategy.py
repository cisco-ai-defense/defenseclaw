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
        ".goreleaser.yaml",
        "go.mod",
        "go.sum",
        "pyproject.toml",
        "uv.lock",
        "cli/defenseclaw/__init__.py",
        "cli/defenseclaw/migration_state.py",
        "cli/defenseclaw/upgrade_receipt.py",
        "cli/defenseclaw/observability/v8_activation.py",
        "cli/defenseclaw/observability/v8_config.py",
        "internal/config/**",
        "internal/cli/**",
        "bundles/local_observability_stack/**",
        "schemas/config/v8/**",
        "extensions/defenseclaw/package.json",
        "extensions/defenseclaw/package-lock.json",
        "macos/DefenseClawMac/DefenseClawMac.xcodeproj/project.pbxproj",
        "scripts/resolve_upgrade_baselines.py",
        "scripts/release_api_retry.py",
        "scripts/generate-upgrade-manifest.py",
        "scripts/verify-sigstore-blob.py",
        "scripts/check_observability_v8_upgrade_continuity.py",
        "scripts/test-developer-target-activation.sh",
        "scripts/test-fresh-install-release.sh",
        "scripts/build-macos-app-release.sh",
        ".github/workflows/macos-app.yml",
        "scripts/export-uv-overrides.py",
    }.issubset(sensitive)


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


def test_release_is_certified_promotion_with_full_fallback_and_no_inline_matrix() -> None:
    workflow = _workflow(RELEASE_PATH)
    jobs = workflow["jobs"]
    triggers = workflow["on"]
    text = RELEASE_PATH.read_text(encoding="utf-8")

    assert "schedule" in triggers
    assert "workflow_dispatch" in triggers
    operation = triggers["workflow_dispatch"]["inputs"]["operation"]
    assert set(operation["options"]) == {"certify", "release"}
    assert workflow["concurrency"] == {
        "group": "release-promotion-${{ github.repository }}",
        "cancel-in-progress": "false",
    }

    lookup = _render(jobs["lookup-certification"])
    assert "reuse=false" in lookup
    assert "verify-metadata" in lookup
    assert "stale, invalid, or unavailable" in lookup
    assert "if ! (" not in lookup
    assert "|| reject_cache" in lookup
    assert "certification_run_attempt" in lookup
    assert 'run.get("run_attempt")' in lookup
    assert "github.workflow_sha" in lookup
    assert "--workflow-file executed-pre-release-certification.yml" in lookup
    assert "git cat-file -e" in lookup
    assert "git fetch" not in lookup
    assert 'if [[ "$RELEASE_OPERATION" != "release" ]]; then' in lookup
    assert jobs["lookup-certification"]["steps"][0]["with"]["fetch-depth"] == "0"
    full = jobs["full-certification"]
    assert full["uses"] == "./.github/workflows/pre-release-certification.yml"
    assert "lookup-certification.outputs.reuse != 'true'" in full["if"]
    assert "lookup-certification.result != 'success'" in full["if"]

    selection = jobs["select-candidate"]
    condition = selection["if"]
    assert "lookup-certification.outputs.reuse == 'true'" in condition
    assert "lookup-certification.result == 'success'" in condition
    assert "full-certification.result == 'success'" in condition
    assert "record-certification.result == 'success'" in condition
    record = _render(jobs["record-certification"])
    assert "github.workflow_sha" in record
    assert "--workflow-file executed-pre-release-certification.yml" in record
    assert "git cat-file -e" in record
    assert "git fetch" not in record
    assert jobs["record-certification"]["steps"][0]["with"]["fetch-depth"] == "0"
    publish = jobs["publish-release"]
    assert set(publish["needs"]) == {
        "release-mode",
        "release-preflight",
        "select-candidate",
    }
    assert "needs.select-candidate.result == 'success'" in publish["if"]
    assert publish["permissions"] == {"contents": "write"}
    rendered_publish = _render(publish)
    assert "scripts/release_api_retry.py reconcile-create" in rendered_publish
    preflight = next(
        step["run"]
        for step in publish["steps"]
        if step.get("name") == "Recheck remote release namespace"
    )
    assert "scripts/release_api_retry.py reconcile-create" in preflight
    assert '--commit "$RELEASE_COMMIT"' in preflight
    assert "--candidate-root release-candidate" in preflight
    assert "--check-main" in preflight
    create = next(
        step
        for step in publish["steps"]
        if step.get("name") == "Publish tag and selected sealed assets"
    )
    assert create["if"] == "steps.release-namespace.outputs.create_required == 'true'"

    # Release owns the unchanged Fulcio identity and candidate construction,
    # while expensive test implementations stay in the reusable workflow.
    assert ".github/workflows/release.yaml@refs/heads/main" in text
    assert text.count("uses: ./.github/workflows/pre-release-certification.yml") == 1
    assert "scripts/test-observability-v8-upgrade-continuity.sh" not in text
    assert "scripts/test-upgrade-protocol-release.sh" not in text
    assert "scripts/test-developer-target-activation.sh" not in text


def test_nightly_manual_reusable_workflow_retains_every_expensive_gate() -> None:
    workflow = _workflow(CERTIFICATION_PATH)
    jobs = workflow["jobs"]
    text = CERTIFICATION_PATH.read_text(encoding="utf-8")

    assert set(workflow["on"]) == {"workflow_call"}
    assert {
        "posix-fresh-install",
        "linux-upgrade",
        "macos-upgrade",
        "windows-unpublished-refusal",
        "live-continuity",
        "certification-complete",
    }.issubset(jobs)
    assert "scripts/test-upgrade-protocol-release.sh" in text
    assert "scripts/test-developer-target-activation.sh" not in text
    assert text.count("--baseline-dependencies published") == 1
    assert '"$BASELINE" == "$REQUIRED_BRIDGE_VERSION"' in text
    assert "matrix.start_source_gateway" in text
    assert "--start-source-gateway" in text
    assert "scripts/test-observability-v8-upgrade-continuity.sh" in text
    assert "scripts/test-upgrade-release-windows.ps1" in text
    assert "scripts/verify-sigstore-blob.py" in text
    complete = jobs["certification-complete"]
    assert set(complete["needs"]) == {
        "posix-fresh-install",
        "linux-upgrade",
        "macos-upgrade",
        "windows-unpublished-refusal",
        "live-continuity",
    }


def test_effective_baseline_snapshot_is_bound_across_selection_record_and_verify() -> None:
    release = RELEASE_PATH.read_text(encoding="utf-8")

    # The effective snapshot includes live stable state without requiring a
    # workflow-authored commit. Every selector/receipt boundary must consume
    # that same file so certification cannot silently prove a different matrix.
    assert "effective-upgrade-baselines.json" in release
    assert release.count("--baselines effective-upgrade-baselines.json") >= 3
    assert "effective-upgrade-baselines.json" in _render(_workflow(RELEASE_PATH)["jobs"]["record-certification"])
