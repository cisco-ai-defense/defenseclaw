# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Static fail-closed contracts for shared Windows live package evidence."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/connector-live-e2e.yml"
HARNESS = ROOT / "scripts/live-connector-e2e/run-windows.ps1"
WORKFLOW_RUN_PATH_HELPER = ROOT / "scripts/live-connector-e2e/workflow-run-path.ps1"
WINDOWS_HARNESS_TEST = ROOT / "scripts/live-connector-e2e/test-windows.ps1"


def _job(source: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\r?\n.*?(?=^  [A-Za-z0-9_-]+:\r?$|\Z)",
        source,
    )
    assert match is not None, name
    return match.group(0)


def _function(source: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^function {re.escape(name)}\b.*?(?=^function |\Z)",
        source,
    )
    assert match is not None, name
    return match.group(0)


def test_shared_windows_live_rejects_wrong_or_stale_package_run() -> None:
    windows_live = _job(WORKFLOW.read_text(encoding="utf-8"), "windows-live")

    assert "[long]$run.workflow_id -ne [long]$workflow.id" in windows_live
    assert "Test-CanonicalWindowsWorkflowRunPath ([string]$run.path)" in windows_live
    assert "[string]$run.repository.full_name -cne $env:GITHUB_REPOSITORY" in windows_live
    assert ("@('pull_request', 'push', 'workflow_dispatch') -cnotcontains [string]$run.event") in windows_live
    assert "[string]$run.status -cne 'completed'" in windows_live
    assert "[string]$run.conclusion -cne 'success'" in windows_live
    assert "[string]$run.head_sha -cne $env:EXPECTED_HEAD_SHA" in windows_live


def test_windows_package_run_path_parser_is_exact_and_ref_compatible() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    helper = WORKFLOW_RUN_PATH_HELPER.read_text(encoding="utf-8")
    parser = _function(helper, "Test-CanonicalWindowsWorkflowRunPath")
    harness_test = WINDOWS_HARNESS_TEST.read_text(encoding="utf-8")

    assert workflow.count("Test-CanonicalWindowsWorkflowRunPath ([string]$run.path)") == 4
    assert workflow.count(". ./scripts/live-connector-e2e/workflow-run-path.ps1") == 4
    assert "[string]$run.path -cne '.github/workflows/windows-native.yml'" not in workflow
    assert "$separator = $Path.IndexOf('@')" in parser
    assert "$pathComponent -cne $expectedPath" in parser
    assert "$Path.IndexOf('@', $separator + 1)" not in parser
    assert "$maximumReferenceLength = 4096" in parser
    assert "$maximumComponentLength = 255" in parser
    assert "$reference -ceq '@'" in parser
    assert "$reference.Contains('//')" in parser
    assert "$reference.Contains('..')" in parser
    assert "$reference.Contains('@{')" in parser
    for runtime_escape in ("Get-Command", "Start-Process", "Invoke-", "$env:"):
        assert runtime_escape not in parser
    assert ".github/workflows/windows-native.yml@main" in harness_test
    assert ".github/workflows/windows-native.yml@refs/heads/main" in harness_test
    assert ".github/workflows/windows-native.yml@refs/heads/feature@beta" in harness_test
    assert ".github/workflows/windows-native.yml@main@other" in harness_test
    for rejected in (
        "@main",
        ".github/workflows/windows-native.yml@",
        ".github/workflows/windows-native.yml@@",
        ".github/workflows/windows-native.yml@refs/heads/feature@{beta",
        ".github/workflows/windows-native.yml.backup@main",
        "prefix/.github/workflows/windows-native.yml@main",
        ".github/workflows/windows.yml@main",
        ".github/workflows/windows-native.yml@refs/heads//main",
        ".github/workflows/windows-native.yml@refs/heads/../main",
    ):
        assert rejected in harness_test


def test_shared_windows_live_rejects_expired_or_multiple_package_artifacts() -> None:
    windows_live = _job(WORKFLOW.read_text(encoding="utf-8"), "windows-live")

    assert "[long]$artifacts.total_count -gt 100" in windows_live
    assert "$packages.Count -ne 1" in windows_live
    assert "[bool]$packages[0].expired" in windows_live
    assert "[long]$packages[0].size_in_bytes -le 0" in windows_live
    assert "[string]$packages[0].digest -cnotmatch '^sha256:[0-9a-f]{64}$'" in windows_live
    assert "[string]$packages[0].expires_at" in windows_live
    assert "$expiresAt -le [DateTimeOffset]::UtcNow" in windows_live


def test_shared_windows_live_download_is_bound_to_artifact_id_and_digest() -> None:
    windows_live = _job(WORKFLOW.read_text(encoding="utf-8"), "windows-live")

    assert "actions/artifacts/$env:ARTIFACT_ID/zip" in windows_live
    assert "Get-FileHash -LiteralPath $archive -Algorithm SHA256" in windows_live
    assert "$actualDigest -cne $env:EXPECTED_ARTIFACT_DIGEST" in windows_live
    assert "Assert-ExactPackagedSetup" in windows_live
    assert "DC_WINDOWS_PACKAGE_ROOT: D:\\" in windows_live


def test_package_authorization_and_download_do_not_receive_provider_credentials() -> None:
    windows_live = _job(WORKFLOW.read_text(encoding="utf-8"), "windows-live")
    authority_steps = windows_live.split("- name: Native Windows live harness", 1)[0]

    for secret in (
        "secrets.OPENAI_API_KEY",
        "secrets.ANTHROPIC_API_KEY",
        "secrets.AMP_API_KEY",
        "secrets.CURSOR_API_KEY",
        "secrets.LLM_API_KEY",
    ):
        assert secret not in authority_steps


def test_package_live_harness_rejects_missing_setup_provenance() -> None:
    harness = HARNESS.read_text(encoding="utf-8")
    exact_setup = _function(harness, "Assert-ExactPackagedSetup")

    assert '$provenancePath = "$setup.provenance.json"' in exact_setup
    assert "-AllowedRoot $artifactRoot -RequireExists" in exact_setup
    assert "ConvertFrom-Json -ErrorAction Stop" in exact_setup
    assert "[string]$provenance.artifact_sha256 -cne $setupHash" in exact_setup
    assert "[string]$provenance.source_commit -cne $ExpectedSourceCommit" in exact_setup


def test_package_live_harness_rejects_source_built_binary_substitution() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    windows_live = _job(workflow, "windows-live")
    harness = HARNESS.read_text(encoding="utf-8")
    installed_identity = _function(harness, "Assert-PackageLiveInstalledIdentity")

    for source_build_marker in (
        "actions/setup-go@",
        "go build",
        "uv sync",
        ".venv\\Scripts",
    ):
        assert source_build_marker not in windows_live
    assert "-PackageLiveEvidence" in windows_live
    assert "Get-Command $product.Command -CommandType Application" in installed_identity
    assert "[IO.Path]::GetFullPath([string]$resolved[0].Source)" in installed_identity
    assert "[IO.Path]::GetFullPath([string]$product.Path)" in installed_identity
    assert "packageProvenance.authenticode.files.($product.Provenance).sha256" in installed_identity
    assert "$actualHash -cne $expectedHash" in installed_identity
    assert "source-built or foreign binary substitution rejected" in installed_identity
    assert "[string]$report.commit -cne $ExpectedPackageSourceCommit" in installed_identity


def test_shared_package_evidence_does_not_expand_release_claims() -> None:
    workflow = " ".join(line.removeprefix("#").strip() for line in WORKFLOW.read_text(encoding="utf-8").splitlines())

    assert "remain evidence-producing checks rather than release certification" in workflow
    assert "They do not change public availability or claim" in workflow
