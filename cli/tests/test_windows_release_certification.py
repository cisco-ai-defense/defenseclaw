# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Contracts for the first native Windows release."""

from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
HARNESS = (ROOT / "scripts" / "windows-native-ci.ps1").read_text(encoding="utf-8")
PACKAGED_V8_VALIDATOR = (ROOT / "scripts" / "validate_packaged_v8_resources.py").read_text(encoding="utf-8")
RELEASE_PATH = ROOT / ".github" / "workflows" / "release.yaml"
SMOKE_PATH = ROOT / ".github" / "workflows" / "pre-release-certification.yml"
FRESH_INSTALL = (ROOT / "scripts" / "test-fresh-install-release-windows.ps1").read_text(encoding="utf-8")
DISPOSABLE_LAUNCHER = (ROOT / "scripts" / "invoke-windows-setup-standard-user-ci.ps1").read_text(encoding="utf-8")
STANDARD_USER_PROCESS_LAUNCHER = (ROOT / "scripts" / "windows-disposable-standard-user-launcher.cs").read_text(
    encoding="utf-8"
)


def _workflow(path: Path) -> dict[str, object]:
    return yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def _function(name: str) -> str:
    match = re.search(
        rf"(?ms)^function {re.escape(name)}\b.*?(?=^function |\Z)",
        HARNESS,
    )
    assert match, f"missing PowerShell function {name}"
    return match.group(0)


def _step(job: dict[str, object], name: str) -> dict[str, object]:
    matches = [step for step in job["steps"] if step.get("name") == name]
    assert len(matches) == 1, f"missing unique step: {name}"
    return matches[0]


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows Authenticode")
def test_release_verifier_accepts_a_genuine_timestamped_authenticode_pe() -> None:
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell is required for the native Authenticode positive test")
    helper = ROOT / "scripts" / "windows-authenticode.ps1"
    command = r"""
Set-StrictMode -Version Latest
. $env:DEFENSECLAW_AUTHENTICODE_HELPER
$evidence = Get-DefenseClawAuthenticodeEvidence `
    -Path $env:DEFENSECLAW_SIGNED_PE `
    -InstalledPath 'fixtures/pwsh.exe' `
    -SbomFileName './fixtures/pwsh.exe'
if ([string]$evidence.observed.status -cne 'Valid' -or
    [string]$evidence.observed.signature_type -cne 'Authenticode' -or
    $null -eq $evidence.observed.signer -or
    -not [bool]$evidence.observed.timestamp.present -or
    [string]$evidence.observed.timestamp.format -cne 'rfc3161' -or
    [string]::IsNullOrWhiteSpace([string]$evidence.observed.timestamp.token_sha256)) {
    throw 'the genuine signed fixture lacks signer or RFC3161 evidence'
}
Assert-DefenseClawAuthenticodeEvidence $env:DEFENSECLAW_SIGNED_PE $evidence | Out-Null
"""
    env = os.environ.copy()
    env["DEFENSECLAW_AUTHENTICODE_HELPER"] = str(helper)
    env["DEFENSECLAW_SIGNED_PE"] = pwsh
    subprocess.run(
        [pwsh, "-NoProfile", "-NonInteractive", "-Command", command],
        check=True,
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows Authenticode")
def test_release_verifier_rejects_malformed_win_certificate_bytes(tmp_path: Path) -> None:
    go = shutil.which("go")
    pwsh = shutil.which("pwsh")
    if not go or not pwsh:
        pytest.skip("Go and PowerShell are required for the malformed Authenticode test")
    source = tmp_path / "main.go"
    source.write_text("package main\nfunc main() {}\n", encoding="utf-8")
    executable = tmp_path / "malformed.exe"
    build_env = os.environ.copy()
    build_env["CGO_ENABLED"] = "0"
    subprocess.run(
        [go, "build", "-o", executable, source],
        check=True,
        capture_output=True,
        text=True,
        env=build_env,
        timeout=120,
    )
    payload = bytearray(executable.read_bytes())
    pe_offset = struct.unpack_from("<I", payload, 0x3C)[0]
    optional_offset = pe_offset + 24
    directories = optional_offset + (112 if struct.unpack_from("<H", payload, optional_offset)[0] == 0x20B else 96)
    certificate_offset = (len(payload) + 7) & ~7
    payload.extend(b"\0" * (certificate_offset - len(payload)))
    payload.extend(struct.pack("<IHH", 32, 0x0200, 0x0002) + b"\x30\x06fixture")
    struct.pack_into("<II", payload, directories + 32, certificate_offset, 16)
    executable.write_bytes(payload)

    helper = ROOT / "scripts" / "windows-authenticode.ps1"
    command = (
        ". $env:DEFENSECLAW_AUTHENTICODE_HELPER; "
        "Get-DefenseClawEmbeddedAuthenticodeCms $env:DEFENSECLAW_MALFORMED_PE"
    )
    env = os.environ.copy()
    env["DEFENSECLAW_AUTHENTICODE_HELPER"] = str(helper)
    env["DEFENSECLAW_MALFORMED_PE"] = str(executable)
    result = subprocess.run(
        [pwsh, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )
    assert result.returncode != 0
    assert "malformed WIN_CERTIFICATE" in result.stdout + result.stderr


def test_release_requires_signed_setup_and_release_owned_authenticode_attestation() -> None:
    workflow = _workflow(RELEASE_PATH)
    jobs = workflow["jobs"]
    windows = jobs["windows-installer"]
    certification = jobs["windows-real-client-certification"]
    rendered = str(windows)

    assert windows["needs"] == [
        "release-preflight",
        "build-runtime-candidate",
    ]
    assert windows["runs-on"] == "windows-latest"
    assert windows["environment"] == "release"
    assert "WINDOWS_SIGNING_CERT_BASE64" in rendered
    assert "WINDOWS_SIGNING_CERT_PASSWORD" in rendered
    assert "Require real Authenticode release credentials" in rendered
    assert "Build and Authenticode-sign native Setup" in rendered
    assert "Windows Setup provenance must be fully Authenticode signed for release" in rendered
    assert "publishing an explicitly unverified Windows Setup" not in rendered

    assert "invoke-windows-setup-standard-user-ci.ps1" in rendered
    assert "-Mode setup-acceptance" in rendered
    assert "-AllowCurrentUserSetupAcceptance" not in rendered

    acceptance = _step(windows, "Validate the exact signed installer lifecycle")
    acceptance_run = acceptance["run"]
    assert "-ArtifactRoot windows-installer-output" in acceptance_run
    assert "-StateRoot (Join-Path $env:RUNNER_TEMP" in acceptance_run
    assert "-DiagnosticsRoot (Join-Path $env:RUNNER_TEMP" in acceptance_run
    assert "-TimeoutSeconds 2400" in acceptance_run

    diagnostics = _step(windows, "Upload native Setup diagnostics on failure")
    assert diagnostics["if"] == "${{ failure() || cancelled() }}"
    assert diagnostics["with"]["path"] == ("${{ runner.temp }}/defenseclaw-release-setup-diagnostics/**")
    assert diagnostics["with"]["if-no-files-found"] == "warn"

    upload = next(step for step in windows["steps"] if step.get("id") == "windows-installer-artifact")
    assert windows["steps"].index(acceptance) < windows["steps"].index(diagnostics)
    assert windows["steps"].index(diagnostics) < windows["steps"].index(upload)
    assert upload["with"]["path"] == (
        "windows-installer-output/DefenseClawSetup-x64.exe\n"
        "windows-installer-output/DefenseClawSetup-x64.exe.sha256\n"
        "windows-installer-output/DefenseClawSetup-x64.exe.provenance.json\n"
        "windows-installer-output/DefenseClawSetup-x64.exe.sbom.json\n"
    )
    assert ".certification.json" not in rendered

    assert certification["needs"] == ["release-preflight", "windows-installer"]
    assert certification["runs-on"] == "windows-latest"
    assert certification["environment"] == "release"
    assert certification["timeout-minutes"] == "180"
    certified = str(certification)
    assert "OPENAI_API_KEY" in certified
    assert "ANTHROPIC_API_KEY" in certified
    assert "-Operation release-certification" in certified
    assert "needs.windows-installer.outputs.artifact_id" in certified
    certified_upload = next(
        step for step in certification["steps"] if step.get("id") == "windows-certified-artifact"
    )
    assert certified_upload["with"]["path"].endswith(
        "windows-certified/DefenseClawSetup-x64.exe.certification.json\n"
    )
    assert "Get-DefenseClawAuthenticodeEvidence" in HARNESS
    assert "Assert-DefenseClawAuthenticodeEvidence" in HARNESS
    assert "schema_version = 2" in HARNESS
    assert "authenticode = $certifiedAuthenticode" in HARNESS
    assert "provenance_sha256 = $releaseMetadataHashes[$provenancePath]" in HARNESS


def test_certified_windows_setup_bytes_are_bound_into_the_single_sealed_candidate() -> None:
    jobs = _workflow(RELEASE_PATH)["jobs"]
    windows = jobs["windows-installer"]
    certification = jobs["windows-real-client-certification"]
    assemble = jobs["assemble-release-candidate"]

    assert "artifact-id" in windows["outputs"]["artifact_id"]
    assert "artifact-digest" in windows["outputs"]["artifact_digest"]
    assert "artifact-id" in certification["outputs"]["artifact_id"]
    assert "artifact-digest" in certification["outputs"]["artifact_digest"]
    assert "windows-real-client-certification" in assemble["needs"]
    download = next(step for step in assemble["steps"] if step.get("with", {}).get("path") == "candidate-input/windows")
    assert download["with"]["artifact-ids"] == (
        "${{ needs.windows-real-client-certification.outputs.artifact_id }}"
    )
    assert download["with"]["merge-multiple"] == "true"
    custody = _step(assemble, "Require immutable certified Windows Setup custody")
    assert custody["env"]["WINDOWS_CERTIFIED_ARTIFACT_DIGEST"] == (
        "${{ needs.windows-real-client-certification.outputs.artifact_digest }}"
    )
    assert custody["env"]["WINDOWS_SOURCE_ARTIFACT_DIGEST"] == (
        "${{ needs.windows-real-client-certification.outputs.source_artifact_digest }}"
    )
    assert "Missing Windows custody digest" in custody["run"]
    assert "staging_artifact_digest" in custody["run"]
    assert "--windows-dir candidate-input/windows" in str(assemble)


def test_windows_release_is_fresh_install_only_and_uses_public_install_ps1() -> None:
    smoke_workflow = _workflow(SMOKE_PATH)
    assert set(smoke_workflow["jobs"]) == {
        "posix-fresh-install",
        "posix-upgrade",
        "windows-fresh-install",
    }
    job = smoke_workflow["jobs"]["windows-fresh-install"]
    rendered = str(job)

    assert job["runs-on"] == "windows-latest"
    assert int(job["timeout-minutes"]) >= 45
    assert "inputs.candidate_artifact" in rendered
    assert "scripts/release_candidate.py verify" in rendered
    assert "scripts/verify-sigstore-blob.py" in rendered
    assert "scripts/test-fresh-install-release-windows.ps1" in rendered
    assert "-TargetVersion" in rendered
    assert "-SuccessPathOnly" not in rendered
    assert "defenseclaw-release-bootstrap-diagnostics" in rendered
    diagnostics = _step(job, "Upload Windows bootstrap diagnostics on failure")
    assert diagnostics["if"] == "${{ failure() || cancelled() }}"
    assert diagnostics["with"]["path"] == ("${{ runner.temp }}/defenseclaw-release-bootstrap-diagnostics/**")
    assert diagnostics["with"]["if-no-files-found"] == "warn"

    smoke_text = SMOKE_PATH.read_text(encoding="utf-8")
    for retired in (
        "windows-upgrade:",
        "test-upgrade-release-windows.ps1",
        "windows-real-client-certification",
        "live-connector-e2e",
        "-Operation release-certification",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
    ):
        assert retired not in smoke_text

    assert "invoke-windows-setup-standard-user-ci.ps1" in FRESH_INSTALL
    assert "-Mode bootstrap-acceptance" in FRESH_INSTALL
    assert "-ArtifactRoot $ReleaseDir" in FRESH_INSTALL
    assert "-TargetVersion $TargetVersion" in FRESH_INSTALL
    assert "$env:RUNNER_TEMP" in FRESH_INSTALL
    assert "$env:DC_WINDOWS_NATIVE_BASE_ROOT" in FRESH_INSTALL
    assert "Refusing to clean unexpected bootstrap acceptance state" in FRESH_INSTALL
    assert "'bootstrap-acceptance'" in DISPOSABLE_LAUNCHER
    assert "test-fresh-install-release-windows.ps1" in DISPOSABLE_LAUNCHER
    assert "install.ps1" in DISPOSABLE_LAUNCHER
    for asset in (
        "DefenseClawSetup-x64.exe",
        "DefenseClawSetup-x64.exe.provenance.json",
        "upgrade-manifest.json",
        "checksums.txt",
        "checksums.txt.sig",
        "checksums.txt.pem",
        "checksums.txt.bundle",
        "cosign-windows-amd64.exe",
    ):
        assert asset in DISPOSABLE_LAUNCHER
    assert "disposable-user bootstrap copy does not match the exact input" in DISPOSABLE_LAUNCHER
    for compact_argument in (
        r"..\workspace\scripts\invoke-windows-setup-standard-user-ci.ps1",
        r"..\artifacts",
        r"..\diagnostics",
        r"..\results\result.json",
    ):
        assert compact_argument in DISPOSABLE_LAUNCHER
    assert "commandLine.Length > 1024" in STANDARD_USER_PROCESS_LAUNCHER
    assert "CreateProcessWithLogonW 1024-character limit" in STANDARD_USER_PROCESS_LAUNCHER

    assert "GetFolderPath([Environment+SpecialFolder]::UserProfile)" in FRESH_INSTALL
    assert "[Environment+SpecialFolder]::LocalApplicationData" in FRESH_INSTALL
    assert "Programs\\DefenseClaw" in FRESH_INSTALL
    assert "DefenseClaw\\InstallerCache" in FRESH_INSTALL
    assert "Uninstall\\DefenseClaw" in FRESH_INSTALL
    assert re.search(r"""['"]-Local['"]""", FRESH_INSTALL)
    assert re.search(r"""['"]-Version['"]""", FRESH_INSTALL)
    assert re.search(r"""['"]-CosignPath['"]""", FRESH_INSTALL)
    assert "Native DefenseClaw Setup completed successfully" in FRESH_INSTALL
    assert "Assert-ExactVersion -Executable $launcher" in FRESH_INSTALL
    assert "Assert-ExactVersion -Executable $gateway" in FRESH_INSTALL
    assert "$first = Invoke-CapturedProcess" in FRESH_INSTALL
    assert "$second = Invoke-CapturedProcess" in FRESH_INSTALL
    assert "Out-String -Width 32768" in FRESH_INSTALL
    assert "DELETEUSERDATA=1" in FRESH_INSTALL
    assert 'GetEnvironmentVariable("Path", "User")' in FRESH_INSTALL
    assert "uninstall did not restore the original user PATH exactly" in FRESH_INSTALL
    assert FRESH_INSTALL.rindex("$installed = $false") > FRESH_INSTALL.index(
        "uninstall did not restore the original user PATH exactly"
    )
    canonical_version = "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$"
    assert canonical_version in FRESH_INSTALL
    assert canonical_version in DISPOSABLE_LAUNCHER

    for obsolete in (
        "$env:USERPROFILE = $HomeRoot",
        "$env:DEFENSECLAW_HOME = Join-Path $HomeRoot",
        '".defenseclaw/.venv/Scripts/defenseclaw.exe"',
        '".local\\bin\\defenseclaw-gateway.exe"',
        "Second fresh-installer invocation unexpectedly succeeded",
        "InjectFailureBeforeShim",
        "InjectPolicyCleanupFailure",
    ):
        assert obsolete not in FRESH_INSTALL


def test_disposable_setup_failure_preserves_bounded_native_log_before_profile_cleanup() -> None:
    fixed_source = r"DefenseClaw\InstallerState\setup.log"
    fixed_destination = "native-setup.log"
    capture = "Copy-DisposableNativeSetupLog"
    generic_handoff = "Copy-BoundedDisposableDiagnostics"
    profile_cleanup = "Remove-DisposableProfileAndAccount $accountName $accountSid"

    assert fixed_source in DISPOSABLE_LAUNCHER
    assert fixed_destination in DISPOSABLE_LAUNCHER
    assert "[Environment+SpecialFolder]::LocalApplicationData" in DISPOSABLE_LAUNCHER
    assert "DisposableFileGuard]::CopyBoundedRegularFile(" in DISPOSABLE_LAUNCHER
    assert re.search(
        r"(?s)CopyBoundedRegularFile\(\s*\$source,\s*\$destination,\s*65536\s*\)",
        DISPOSABLE_LAUNCHER,
    )
    assert "-AllowedRoot $localAppData -RequireExists" in DISPOSABLE_LAUNCHER
    assert "-AllowedRoot $SandboxRoot -RequireExists" in DISPOSABLE_LAUNCHER
    assert "native Setup log preservation failed" in DISPOSABLE_LAUNCHER
    assert DISPOSABLE_LAUNCHER.rindex(capture) < DISPOSABLE_LAUNCHER.rindex(generic_handoff)
    assert DISPOSABLE_LAUNCHER.rindex(generic_handoff) < DISPOSABLE_LAUNCHER.index(profile_cleanup)
    assert "Copy-Item" not in DISPOSABLE_LAUNCHER


def test_publish_includes_windows_binaries_without_an_omission_mode() -> None:
    workflow = _workflow(RELEASE_PATH)
    jobs = workflow["jobs"]
    publish = jobs["publish-release"]
    release_text = RELEASE_PATH.read_text(encoding="utf-8")

    assert publish["needs"] == [
        "release-preflight",
        "assemble-release-candidate",
        "release-smoke",
    ]
    assert "scripts/release_candidate.py list-assets" in str(publish)
    assert "--omit-windows-binaries" not in release_text
    assert "DefenseClawSetup-x64.exe.certification.json" in release_text
    assert "every sealed Linux, macOS, and Windows runtime asset" in release_text


def test_release_documentation_matches_the_fresh_only_gate() -> None:
    installer = (ROOT / "docs" / "WINDOWS-NATIVE-INSTALLER.md").read_text(encoding="utf-8")
    ci = (ROOT / "docs" / "WINDOWS-NATIVE-CI.md").read_text(encoding="utf-8")
    release = (ROOT / "docs" / "RELEASE_VALIDATION.md").read_text(encoding="utf-8")

    assert "one-dispatch Release workflow" in installer
    assert "Authenticode-signed" in installer
    assert "explicitly unverified" not in installer
    assert "first native Windows release" in installer
    assert "fresh-install-only" in installer
    assert ".certification.json" in installer
    assert "A merge to `main` is the review-and-CI boundary" in ci
    assert "does not poll or replay `Windows Native CI`" in ci
    assert "indirectly on `windows-real-client-certification`" in ci
    assert "first native Windows release" in release
    assert "has no older native Windows baseline" in release
    assert "fresh-install only" in release


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


def test_setup_acceptance_validates_packaged_resources_before_first_run() -> None:
    resource_contract = _function("Assert-PackagedV8ResourceContract")
    acceptance = _function("Invoke-SetupAcceptance")

    for resource in (
        "defenseclaw-config.schema.json",
        "observability.yaml",
        "observability.md",
        "telemetry.schema.json",
        "catalog.json",
        "v7-exporter-selection.json",
        "galileo-rich-v2.json",
        "local-observability-v1.json",
        "openinference-v1.json",
    ):
        assert resource in PACKAGED_V8_VALIDATOR
    assert "runtime unexpectedly contains a Lib/schemas fallback tree" in (PACKAGED_V8_VALIDATOR)
    assert "scripts\\validate_packaged_v8_resources.py" in resource_contract
    assert "'--site-packages', $sitePackages" in resource_contract
    assert "'--runtime-root', $RuntimeRoot" in resource_contract

    probe = "Assert-PackagedV8ResourceContract $python (Join-Path $installRoot 'runtime\\python')"
    assert acceptance.index(probe) < acceptance.index("'init', '--skip-install'")


def test_setup_uninstall_acceptance_retains_connector_cleanup_authority() -> None:
    acceptance = _function("Invoke-SetupAcceptance")
    authority = _function("Assert-NativeConnectorCleanupAuthorityPresent")
    consumed = _function("Assert-NativeConnectorBackupMarkersConsumed")

    assert "[string[]]$ConfiguredConnectors" in authority
    assert "$configured.Contains($connector)" in authority
    assert "Get-NativeConnectorBackupMarkers" in authority
    assert "Get-NativeConnectorBackupMarkers" in consumed
    assert "Assert-NativeConnectorCleanupAuthorityPresent $dataRoot $repairedRoster" in acceptance
    assert "Assert-NativeConnectorBackupMarkersConsumed $dataRoot" in acceptance
