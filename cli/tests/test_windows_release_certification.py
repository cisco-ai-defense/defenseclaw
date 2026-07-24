# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Contracts for the first native Windows release."""

from __future__ import annotations

import re
from pathlib import Path

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


def test_release_accepts_signed_or_explicitly_unverified_setup_and_exact_four_sidecars() -> None:
    workflow = _workflow(RELEASE_PATH)
    jobs = workflow["jobs"]
    windows = jobs["windows-installer"]
    rendered = str(windows)

    assert windows["needs"] == [
        "release-preflight",
        "build-runtime-candidate",
    ]
    assert windows["runs-on"] == "windows-latest"
    assert windows["environment"] == "release"
    assert "WINDOWS_SIGNING_CERT_BASE64" in rendered
    assert "WINDOWS_SIGNING_CERT_PASSWORD" in rendered
    assert "Build native Setup with optional Authenticode" in rendered
    assert "Windows Setup provenance has an inconsistent signing state" in rendered
    assert "publishing an explicitly unverified Windows Setup" in rendered

    assert "invoke-windows-setup-standard-user-ci.ps1" in rendered
    assert "-Mode setup-acceptance" in rendered
    assert "-AllowCurrentUserSetupAcceptance" not in rendered

    acceptance = _step(windows, "Validate the exact installer lifecycle")
    acceptance_run = acceptance["run"]
    assert "-ArtifactRoot windows-installer-output" in acceptance_run
    assert "-StateRoot (Join-Path $env:RUNNER_TEMP" in acceptance_run
    assert "-DiagnosticsRoot (Join-Path $env:RUNNER_TEMP" in acceptance_run
    assert "-TimeoutSeconds 2400" in acceptance_run

    upload = next(step for step in windows["steps"] if step.get("id") == "windows-installer-artifact")
    assert windows["steps"].index(acceptance) < windows["steps"].index(upload)
    assert upload["with"]["path"] == (
        "windows-installer-output/DefenseClawSetup-x64.exe\n"
        "windows-installer-output/DefenseClawSetup-x64.exe.sha256\n"
        "windows-installer-output/DefenseClawSetup-x64.exe.provenance.json\n"
        "windows-installer-output/DefenseClawSetup-x64.exe.sbom.json\n"
    )
    assert ".certification.json" not in rendered


def test_windows_setup_bytes_are_bound_into_the_single_sealed_candidate() -> None:
    jobs = _workflow(RELEASE_PATH)["jobs"]
    windows = jobs["windows-installer"]
    assemble = jobs["assemble-release-candidate"]

    assert "artifact-id" in windows["outputs"]["artifact_id"]
    assert "artifact-digest" in windows["outputs"]["artifact_digest"]
    assert "windows-installer" in assemble["needs"]
    download = next(step for step in assemble["steps"] if step.get("with", {}).get("path") == "candidate-input/windows")
    assert download["with"]["artifact-ids"] == ("${{ needs.windows-installer.outputs.artifact_id }}")
    assert download["with"]["merge-multiple"] == "true"
    custody = _step(assemble, "Require immutable Windows Setup artifact identity")
    assert custody["env"]["WINDOWS_INSTALLER_ARTIFACT_DIGEST"] == (
        "${{ needs.windows-installer.outputs.artifact_digest }}"
    )
    assert "Missing Windows custody digest" in custody["run"]
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
    assert "DefenseClawSetup-x64.exe.certification.json" not in release_text
    assert "every sealed Linux, macOS, and Windows runtime asset" in release_text


def test_release_documentation_matches_the_fresh_only_gate() -> None:
    installer = (ROOT / "docs" / "WINDOWS-NATIVE-INSTALLER.md").read_text(encoding="utf-8")
    ci = (ROOT / "docs" / "WINDOWS-NATIVE-CI.md").read_text(encoding="utf-8")
    release = (ROOT / "docs" / "RELEASE_VALIDATION.md").read_text(encoding="utf-8")

    assert "one-dispatch Release workflow" in installer
    assert "Authenticode signed" in installer
    assert "explicitly unverified" in installer
    assert "first native Windows release" in installer
    assert "fresh-install-only" in installer
    assert ".certification.json" not in installer
    assert "A merge to `main` is the review-and-CI boundary" in ci
    assert "does not poll or replay `Windows Native CI`" in ci
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
