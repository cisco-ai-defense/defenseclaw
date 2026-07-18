# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Fail-closed contracts for the signed Windows real-client release gate."""

import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
HARNESS = (ROOT / "scripts" / "windows-native-ci.ps1").read_text(encoding="utf-8")
LIVE = (ROOT / "scripts" / "live-connector-e2e" / "run-windows.ps1").read_text(encoding="utf-8")
RELEASE = (ROOT / ".github" / "workflows" / "release.yaml").read_text(encoding="utf-8")


def _workflow() -> dict[str, object]:
    return yaml.load(RELEASE, Loader=yaml.BaseLoader)


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
    certification = _workflow()["jobs"]["windows-real-client-certification"]
    assert certification["needs"] == ["release-preflight", "windows-installer"]
    certify_step = next(
        step for step in certification["steps"] if "-Operation release-certification" in step.get("run", "")
    )
    assert certify_step["env"]["WINDOWS_RELEASE_VERSION"] == ("${{ needs.release-preflight.outputs.tag }}")
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
    for path in (
        "$codexConfigPath",
        "$codexManagedConfigPath",
        "$codexHooksPath",
        "$claudeConfigPath",
    ):
        assert path in gate
    assert "Assert-NoDefenseClawRegistration $ConnectorConfigs" in clean
    assert "release uninstall did not preserve the unrelated Codex hook byte-for-byte" in clean
    assert "release uninstall did not preserve the unrelated Codex managed config byte-for-byte" in clean


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


def test_publish_has_non_advisory_real_client_certification_custody() -> None:
    jobs = _workflow()["jobs"]
    certification = jobs["windows-real-client-certification"]
    assemble = jobs["assemble-release-candidate"]
    full = jobs["full-certification"]
    select = jobs["select-candidate"]
    publish = jobs["publish-release"]
    rendered = str(certification)

    assert certification["needs"] == ["release-preflight", "windows-installer"]
    assert "continue-on-error" not in rendered
    assert "-Operation release-certification" in rendered
    assert "secrets.OPENAI_API_KEY" in rendered
    assert "secrets.ANTHROPIC_API_KEY" in rendered
    assert "${{ needs.windows-installer.outputs.artifact_id }}" in rendered
    assert "${{ needs.windows-installer.outputs.artifact_digest }}" in rendered
    assert "DefenseClawSetup-x64.exe.certification.json" in rendered
    certification_index = next(
        index
        for index, step in enumerate(certification["steps"])
        if "-Operation release-certification" in step.get("run", "")
    )
    upload_index = next(
        index for index, step in enumerate(certification["steps"]) if step.get("id") == "windows-certified-artifact"
    )
    assert certification_index < upload_index
    assert int(certification["timeout-minutes"]) >= 90

    assert "windows-real-client-certification" in assemble["needs"]
    assert "windows-real-client-certification" in full["needs"]
    assert "needs.windows-real-client-certification.result == 'success'" in full["if"]
    assert {
        "lookup-certification",
        "assemble-release-candidate",
        "full-certification",
        "record-certification",
    }.issubset(select["needs"])
    assert "needs.lookup-certification.outputs.reuse == 'true'" in select["if"]
    assert "needs.full-certification.result == 'success'" in select["if"]
    assert "select-candidate" in publish["needs"]
    assert "needs.select-candidate.result == 'success'" in publish["if"]


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
    assert "`publish-release` job depends directly on that cell" in ci_flat
    assert "never builds or installs DefenseClaw from the source checkout" in ci_flat


def test_native_wheel_stages_and_verifies_v8_runtime_assets() -> None:
    stage = _function("Stage-PackageData")
    build = _function("Invoke-BuildArtifacts")

    for source in (
        "schemas\\config\\v8\\defenseclaw-config.schema.json",
        "schemas\\config\\v8\\reference\\$name",
        "scripts/telemetry_runtime_assets.py",
    ):
        assert source in stage

    for packaged in (
        "defenseclaw/_data/config/v8/defenseclaw-config.schema.json",
        "defenseclaw/_data/config/v8/observability.yaml",
        "defenseclaw/_data/config/v8/observability.md",
        "defenseclaw/_data/telemetry/v8/telemetry.schema.json",
        "defenseclaw/_data/telemetry/v8/catalog.json",
        "defenseclaw/_data/telemetry/v8/v7-exporter-selection.json",
        "defenseclaw/_data/telemetry/v8/galileo-rich-v2.json",
        "defenseclaw/_data/telemetry/v8/local-observability-v1.json",
        "defenseclaw/_data/telemetry/v8/openinference-v1.json",
    ):
        assert packaged in build


def test_setup_acceptance_exercises_atomic_observability_v8_upgrade() -> None:
    acceptance = _function("Invoke-SetupAcceptance")

    for contract in (
        "installedState.version = '0.8.0'",
        "FROMVERSION=0.8.0",
        "config_version: 7",
        "temporality: delta",
        '(otlp.get("tls") or {}).get("insecure") is True',
        '(otlp.get("network_safety") or {}).get("allow_private_networks") is True',
        "config-v8', 'validate'",
        "setup-seeded-v8-contract.log",
        "'0.8.5' -notin @($migrationCursor.applied)",
        "Get-GatewayIdentity $dataRoot",
        "Get-WatchdogIdentity $dataRoot",
        "seeded upgrade-restored gateway",
        "seeded upgrade-restored watchdog",
    ):
        assert contract in acceptance


def test_setup_uninstall_acceptance_uses_validated_roster_and_backup_markers() -> None:
    acceptance = _function("Invoke-SetupAcceptance")
    authority = _function("Assert-NativeConnectorCleanupAuthorityPresent")
    consumed = _function("Assert-NativeConnectorBackupMarkersConsumed")

    assert "[string[]]$ConfiguredConnectors" in authority
    assert "$configured.Contains($connector)" in authority
    assert "Get-NativeConnectorBackupMarkers" in authority
    assert "Get-NativeConnectorBackupMarkers" in consumed
    assert "Assert-NativeConnectorCleanupAuthorityPresent $dataRoot $repairedRoster" in acceptance
    assert "Assert-NativeConnectorBackupMarkersConsumed $dataRoot" in acceptance
