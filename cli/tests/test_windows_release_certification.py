# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Fail-closed contracts for the signed Windows real-client release gate."""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HARNESS = (ROOT / "scripts" / "windows-native-ci.ps1").read_text(encoding="utf-8")
LIVE = (ROOT / "scripts" / "live-connector-e2e" / "run-windows.ps1").read_text(encoding="utf-8")
RELEASE = (ROOT / ".github" / "workflows" / "release.yaml").read_text(encoding="utf-8")


def _function(name: str) -> str:
    match = re.search(rf"(?ms)^function {re.escape(name)}\b.*?(?=^function |\Z)", HARNESS)
    assert match, f"missing PowerShell function {name}"
    return match.group(0)


def test_release_clients_are_both_official_and_exactly_pinned() -> None:
    specs = _function("Get-WindowsReleaseClientSpecifications")
    assert "@openai/codex" in specs and "Version = '0.144.3'" in specs
    assert "@anthropic-ai/claude-code" in specs and "Version = '2.1.208'" in specs
    assert "latest" not in specs.lower()
    installer = _function("Install-PinnedWindowsReleaseClient")
    assert "Assert-ExactWindowsReleaseClientVersion" in installer
    assert "package.json" not in installer  # the immutable manifest path comes from the spec
    assert "manifest.version -cne" in installer
    assert "GetEnvironmentVariables('Process')" in installer
    assert "_API_KEY$" in installer
    assert "SetEnvironmentVariable($name, $null, 'Process')" in installer
    assert "'install', '--package-lock-only', '--ignore-scripts', '--save-exact'" in installer
    assert "'ci', '--no-audit', '--no-fund'" in installer
    assert installer.count("Get-FileHash -LiteralPath $lockPath") == 2
    assert "npm ci mutated the exact official-client dependency lock" in installer


def test_release_gate_uses_only_the_exact_signed_setup_bytes() -> None:
    gate = _function("Invoke-WindowsReleaseCertification")
    assert "DefenseClawSetup-x64.exe" in gate
    assert gate.count("Assert-CiscoAuthenticodeSignature $setup") >= 2
    assert gate.count("Get-FileHash -LiteralPath $setup") >= 2
    assert "release setup SHA-256 sidecar mismatch" in gate
    assert "provenance.artifact_sha256" in gate
    assert "provenance.source_commit -cne [string]$env:GITHUB_SHA" in gate
    assert "Assert-WindowsReleaseSbom" in gate
    assert "installedStatePath" in gate and "installedPayloadPath" in gate
    assert "installedIdentity.source_commit -cne [string]$env:GITHUB_SHA" in gate
    assert "the signed DefenseClawSetup-x64.exe bytes changed" in gate
    assert "release metadata changed during real-client certification" in gate
    assert gate.count("Get-FileHash -LiteralPath $metadataPath") == 2
    assert "Invoke-WindowsNativeProcess $setup" in gate
    for forbidden in ("go build", "uv sync", "Install-PackagedArtifacts", "Invoke-BuildArtifacts"):
        assert forbidden.lower() not in gate.lower()


def test_release_sbom_binds_setup_bytes_version_and_source_commit() -> None:
    sbom = _function("Assert-WindowsReleaseSbom")
    assert "SPDX-2.3" in sbom and "CC0-1.0" in sbom
    assert "spdx/windows/$escapedVersion/$SetupHash" in sbom
    assert 'sbom.comment -cne "DefenseClaw source commit: $SourceCommit"' in sbom
    assert "DefenseClaw Windows Setup" in sbom
    assert "./DefenseClawSetup-x64.exe" in sbom
    assert "pkg:github/cisco-ai-defense/defenseclaw@$escapedVersion" in sbom
    assert "documentDescribes" in sbom
    assert "DESCRIBES" in sbom and "CONTAINS" in sbom


def test_release_version_is_independently_bound_end_to_end() -> None:
    gate = _function("Invoke-WindowsReleaseCertification")
    workflow = (ROOT / ".github" / "workflows" / "release.yaml").read_text(encoding="utf-8")
    assert "WINDOWS_RELEASE_VERSION: ${{ needs.release.outputs.tag }}" in workflow
    assert "needs: [release, windows-installer]" in workflow
    assert "provenance.version -cne $releaseVersion" in gate
    assert "installedIdentity.version -cne $releaseVersion" in gate
    assert "$sbomPath $setupHash $releaseVersion" in gate


def test_certification_evidence_derives_versions_from_installed_specs() -> None:
    gate = _function("Invoke-WindowsReleaseCertification")
    evidence = gate.split("$evidence = [ordered]@{", 1)[1]
    assert "[string]$clients['codex'].Specification.Version" in evidence
    assert "[string]$clients['claudecode'].Specification.Version" in evidence
    assert "codex = '0.144.3'" not in evidence
    assert "claudecode = '2.1.208'" not in evidence


def test_release_gate_cannot_skip_a_connector_or_manual_trust() -> None:
    gate = _function("Invoke-WindowsReleaseCertification")
    results = _function("Assert-WindowsReleaseRealClientResults")
    assert "@('codex', 'claudecode')" in gate
    assert "@('codex', 'claudecode')" in results
    for event in (
        "lifecycle:fires",
        "tool-allow:fires",
        "tool-block:enforced",
        "audit-correlation",
        "telemetry",
        "teardown",
        "codex:auto-trust",
    ):
        assert event in results
    assert "Assert-DoctorWindowsHookRegistration" in LIVE
    assert "Assert-CodexHooksListTrusted" in LIVE
    assert "hooks/list verified every setup-created handler enabled and trusted" in LIVE
    assert "without manual approval" in LIVE


def test_release_uninstall_preserves_unrelated_codex_hooks_and_checks_all_sources() -> None:
    gate = _function("Invoke-WindowsReleaseCertification")
    clean = _function("Assert-WindowsReleaseCleanUninstall")
    assert "'.codex\\hooks.json'" in gate
    assert "cmd.exe /d /c exit 0" in gate
    assert "$connectorConfigs = @($codexConfigPath, $codexHooksPath, $claudeConfigPath)" in gate
    assert "Assert-NoDefenseClawRegistration $ConnectorConfigs" in clean
    assert "release uninstall did not preserve the unrelated Codex hook byte-for-byte" in clean


def test_release_gate_fails_closed_without_secrets_or_exact_clients() -> None:
    environment = _function("Assert-WindowsReleaseCertificationEnvironment")
    assert "OPENAI_API_KEY" in environment and "ANTHROPIC_API_KEY" in environment
    assert "required for non-advisory" in environment
    assert "WINDOWS_RELEASE_ARTIFACT_DIGEST" in environment
    assert "immutable uploaded Windows artifact digest" in environment
    install_agent = re.search(r"(?ms)^function Install-Agent\b.*?(?=^function |\Z)", LIVE)
    assert install_agent
    body = install_agent.group(0)
    assert "release certification requires an explicit preinstalled agent path and exact version" in body
    assert "release client must be installed below" in body
    release_branch = body.split("if ($ReleaseCertification)", 1)[1].split("return", 1)[0]
    assert "latest" not in release_branch.lower()


def test_publish_has_a_non_advisory_real_client_dependency() -> None:
    certification = re.search(r"(?ms)^  windows-real-client-certification:.*?(?=^  publish:)", RELEASE)
    publish = re.search(r"(?ms)^  publish:.*", RELEASE)
    assert certification and publish
    job = certification.group(0)
    assert "needs: [release, windows-installer]" in job
    assert "continue-on-error" not in job
    assert "-Operation release-certification" in job
    assert "secrets.OPENAI_API_KEY" in job and "secrets.ANTHROPIC_API_KEY" in job
    assert "artifact-ids: ${{ needs.windows-installer.outputs.artifact-id }}" in job
    assert "WINDOWS_RELEASE_ARTIFACT_DIGEST" in job
    assert "artifact-digest: ${{ steps.windows-installer-artifact.outputs.artifact-digest }}" in RELEASE
    assert "DefenseClawSetup-x64.exe.certification.json" in job
    assert job.index("-Operation release-certification") < job.index(
        "Upload certified native Windows installer artifacts"
    )
    assert "needs: [release, windows-real-client-certification]" in publish.group(0)
    assert "name: release-dist-windows-certified" in publish.group(0)
    assert "dist/*.certification.json" in publish.group(0)
    timeout = re.search(r"timeout-minutes:\s*(\d+)", job)
    assert timeout and int(timeout.group(1)) >= 90


def test_certification_evidence_is_not_faked_in_validated_versions() -> None:
    registry = json.loads(
        (ROOT / "cli" / "defenseclaw" / "inventory" / "validated_versions.json").read_text(encoding="utf-8")
    )
    for connector in ("codex", "claudecode"):
        windows = registry["connectors"][connector]["os"]["windows"]
        assert windows["run_url"] == ""


def test_release_documentation_matches_the_enforced_gate() -> None:
    installer = (ROOT / "docs" / "WINDOWS-NATIVE-INSTALLER.md").read_text(encoding="utf-8")
    ci = (ROOT / "docs" / "WINDOWS-NATIVE-CI.md").read_text(encoding="utf-8")
    ci_flat = " ".join(ci.split())
    for claim in (
        "Codex CLI `0.144.3`",
        "Claude Code `2.1.208`",
        "without a manual\n`/hooks` approval",
        "DefenseClawSetup-x64.exe.certification.json",
    ):
        assert claim in installer
    assert "`publish` depends on that cell" in ci_flat
    assert "never builds or installs DefenseClaw from the source checkout" in ci_flat
