# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Fail-closed contracts for native Windows release and Amp validation."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from tests.windows_release_contracts import (
    DEFERRED_UNINSTALL_FORBIDDEN_MARKERS,
    DEFERRED_UNINSTALL_REQUIRED_MARKERS,
)

ROOT = Path(__file__).resolve().parents[2]
HARNESS = (ROOT / "scripts" / "windows-native-ci.ps1").read_text(encoding="utf-8")
PACKAGED_V8_VALIDATOR = (ROOT / "scripts" / "validate_packaged_v8_resources.py").read_text(encoding="utf-8")
RELEASE_PATH = ROOT / ".github" / "workflows" / "release.yaml"
SMOKE_PATH = ROOT / ".github" / "workflows" / "release-candidate-smoke.yml"
WINDOWS_NATIVE_PATH = ROOT / ".github" / "workflows" / "windows-native.yml"
FRESH_INSTALL = (ROOT / "scripts" / "test-fresh-install-release-windows.ps1").read_text(encoding="utf-8")
DISPOSABLE_LAUNCHER = (ROOT / "scripts" / "invoke-windows-setup-standard-user-ci.ps1").read_text(encoding="utf-8")
DISPOSABLE_FILE_GUARD = (ROOT / "scripts" / "windows-disposable-file-guard.cs").read_text(encoding="utf-8")
STANDARD_USER_PROCESS_LAUNCHER = (ROOT / "scripts" / "windows-disposable-standard-user-launcher.cs").read_text(
    encoding="utf-8"
)
OWNER_RIGHTS_FULL_CONTROL_ACE = "(A;OICI;FA;;;OW)"
SYSTEM_FULL_CONTROL_ACE = "(A;OICI;FA;;;SY)"
CREATOR_OWNER_INHERIT_ONLY_FULL_CONTROL_ACE = "(A;OICIIO;FA;;;CO)"
BUILTIN_USERS_FULL_CONTROL_ACE = "(A;OICI;FA;;;S-1-5-32-545)"
LIVE = (ROOT / "scripts" / "live-connector-e2e" / "run-windows.ps1").read_text(encoding="utf-8")


def _workflow(path: Path) -> dict[str, object]:
    return yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def _function(name: str) -> str:
    match = re.search(
        rf"(?ms)^function {re.escape(name)}\b.*?(?=^function |\Z)",
        HARNESS,
    )
    assert match, f"missing PowerShell function {name}"
    return match.group(0)


def _fresh_install_function(name: str) -> str:
    match = re.search(
        rf"(?ms)^function {re.escape(name)}\b.*?(?=^function |\Z)",
        FRESH_INSTALL,
    )
    assert match, f"missing PowerShell function {name}"
    return match.group(0)


def _run_powershell(
    command: str,
    environment_overrides: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    powershell = shutil.which("powershell.exe") or shutil.which("pwsh")
    assert powershell is not None
    environment = {
        **os.environ,
        "POWERSHELL_TELEMETRY_OPTOUT": "1",
        **environment_overrides,
    }
    if Path(powershell).name.casefold() == "powershell.exe":
        environment["PSModulePath"] = str(Path(powershell).parent / "Modules")
    return subprocess.run(
        [
            powershell,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            command,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )


def _set_private_custody_acl(path: Path, *extra_rules: str) -> None:
    _replace_private_custody_acl(
        path,
        OWNER_RIGHTS_FULL_CONTROL_ACE,
        SYSTEM_FULL_CONTROL_ACE,
        *extra_rules,
    )


def _replace_private_custody_acl(path: Path, *rules: str) -> None:
    command = """
$ErrorActionPreference = 'Stop'
$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$dacl = [Environment]::GetEnvironmentVariable('DC_TEST_DACL_SDDL')
$descriptor = [Security.AccessControl.DirectorySecurity]::new()
$descriptor.SetSecurityDescriptorSddlForm(('O:{0}{1}' -f $currentSid, $dacl))
Set-Acl -LiteralPath ([Environment]::GetEnvironmentVariable('DC_TEST_CUSTODY_PATH')) `
    -AclObject $descriptor
"""
    completed = _run_powershell(
        command,
        {
            "DC_TEST_CUSTODY_PATH": str(path),
            "DC_TEST_DACL_SDDL": "D:P" + "".join(rules),
        },
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def _restore_inherited_test_acl(path: Path) -> None:
    subprocess.run(
        ["icacls.exe", str(path), "/inheritance:e"],
        check=True,
        capture_output=True,
        text=True,
    )


def _run_private_custody_assertion(path: Path) -> subprocess.CompletedProcess[str]:
    functions = "\n\n".join(
        _fresh_install_function(name)
        for name in (
            "Assert-NoReparsePathChain",
            "Assert-PrivatePathCustody",
        )
    )
    command = (
        "$ErrorActionPreference = 'Stop'\n"
        f"{functions}\n"
        "try {\n"
        "    Assert-PrivatePathCustody "
        "-Path ([Environment]::GetEnvironmentVariable('DC_TEST_CUSTODY_PATH')) "
        "-Directory\n"
        "} catch {\n"
        "    [Console]::Error.WriteLine($_.Exception.Message)\n"
        "    exit 1\n"
        "}\n"
    )
    return _run_powershell(command, {"DC_TEST_CUSTODY_PATH": str(path)})


def _run_optional_json_property(
    json_value: str,
    property_name: str,
) -> subprocess.CompletedProcess[str]:
    functions = "\n\n".join(
        _fresh_install_function(name)
        for name in (
            "Get-OptionalJsonPropertyValue",
            "Get-OptionalJsonStringValue",
            "Get-OptionalJsonStringArrayValue",
        )
    )
    command = (
        "$ErrorActionPreference = 'Stop'\n"
        "Set-StrictMode -Version Latest\n"
        f"{functions}\n"
        "$record = [Environment]::GetEnvironmentVariable('DC_TEST_JSON') | "
        "ConvertFrom-Json\n"
        "$propertyName = [Environment]::GetEnvironmentVariable('DC_TEST_PROPERTY')\n"
        "$isStringArray = $propertyName -in @('previous_connectors', 'verified_connectors')\n"
        "if ($isStringArray) {\n"
        "    $values = @(Get-OptionalJsonStringArrayValue "
        "-InputObject $record -PropertyName $propertyName)\n"
        "} else {\n"
        "    $value = Get-OptionalJsonStringValue "
        "-InputObject $record -PropertyName $propertyName\n"
        "    $values = @($value)\n"
        "}\n"
        "[Console]::Out.WriteLine('count={0}' -f $values.Count)\n"
        "[Console]::Out.WriteLine('value=<{0}>' -f ($values -join ','))\n"
        "if (-not $isStringArray) {\n"
        "    [Console]::Out.WriteLine('is_null={0}' -f ($null -eq $value))\n"
        "    [Console]::Out.WriteLine('equals_empty={0}' -f ($value -ceq ''))\n"
        "}\n"
    )
    return _run_powershell(
        command,
        {
            "DC_TEST_JSON": json_value,
            "DC_TEST_PROPERTY": property_name,
        },
    )


def _step(job: dict[str, object], name: str) -> dict[str, object]:
    matches = [step for step in job["steps"] if step.get("name") == name]
    assert len(matches) == 1, f"missing unique step: {name}"
    return matches[0]


@pytest.mark.skipif(
    os.name != "nt" or not (shutil.which("pwsh") or shutil.which("powershell.exe")),
    reason="validates native Windows release-custody ACLs",
)
@pytest.mark.allow_subprocess
@pytest.mark.parametrize(
    ("extra_rules", "expected_returncode", "expected_error"),
    [
        ((), 0, ""),
        (
            (BUILTIN_USERS_FULL_CONTROL_ACE,),
            1,
            "unexpected SID (S-1-5-32-545)",
        ),
    ],
)
def test_deferred_uninstall_custody_accepts_only_owner_rights_and_system(
    tmp_path: Path,
    extra_rules: tuple[str, ...],
    expected_returncode: int,
    expected_error: str,
) -> None:
    custody = tmp_path / "custody"
    custody.mkdir()
    subprocess.run(
        [
            "icacls.exe",
            str(custody),
            "/grant:r",
            "*S-1-5-32-544:(OI)(CI)F",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    try:
        _set_private_custody_acl(custody, *extra_rules)
        completed = _run_private_custody_assertion(custody)
        output = completed.stdout + completed.stderr

        assert completed.returncode == expected_returncode, output
        assert expected_error in output
    finally:
        _restore_inherited_test_acl(custody)


@pytest.mark.skipif(
    os.name != "nt" or not (shutil.which("pwsh") or shutil.which("powershell.exe")),
    reason="validates native Windows release-custody ACLs",
)
@pytest.mark.allow_subprocess
def test_deferred_uninstall_custody_rejects_inherit_only_creator_owner(
    tmp_path: Path,
) -> None:
    custody = tmp_path / "custody"
    custody.mkdir()
    _replace_private_custody_acl(
        custody,
        CREATOR_OWNER_INHERIT_ONLY_FULL_CONTROL_ACE,
        SYSTEM_FULL_CONTROL_ACE,
    )

    try:
        completed = _run_private_custody_assertion(custody)
        output = completed.stdout + completed.stderr

        assert completed.returncode == 1, output
        assert "lacks required owner and SYSTEM access" in output
    finally:
        _restore_inherited_test_acl(custody)


@pytest.mark.skipif(
    os.name != "nt" or not (shutil.which("pwsh") or shutil.which("powershell.exe")),
    reason="validates PowerShell JSON handling under StrictMode",
)
@pytest.mark.allow_subprocess
@pytest.mark.parametrize(
    ("json_value", "property_name", "expected"),
    [
        (
            '{"status":"pending-reboot"}',
            "cleanup_boot_identifier",
            "count=1\nvalue=<>\nis_null=False\nequals_empty=True",
        ),
        (
            '{"cleanup_boot_identifier":""}',
            "cleanup_boot_identifier",
            "count=1\nvalue=<>\nis_null=False\nequals_empty=True",
        ),
        (
            '{"cleanup_boot_identifier":null}',
            "cleanup_boot_identifier",
            "count=1\nvalue=<>\nis_null=False\nequals_empty=True",
        ),
        (
            '{"cleanup_boot_identifier":"next-boot"}',
            "cleanup_boot_identifier",
            "count=1\nvalue=<next-boot>\nis_null=False\nequals_empty=False",
        ),
        (
            '{"action":"uninstall"}',
            "maintenance_sha256",
            "count=1\nvalue=<>\nis_null=False\nequals_empty=True",
        ),
        ('{"target_connector":"none"}', "previous_connectors", "count=0\nvalue=<>"),
        ('{"verified_connectors":null}', "verified_connectors", "count=0\nvalue=<>"),
        ('{"verified_connectors":[]}', "verified_connectors", "count=0\nvalue=<>"),
        (
            '{"previous_connectors":["codex","claudecode"]}',
            "previous_connectors",
            "count=2\nvalue=<codex,claudecode>",
        ),
        (
            '{"verified_connectors":["codex","claudecode"]}',
            "verified_connectors",
            "count=2\nvalue=<codex,claudecode>",
        ),
        (
            '{"status":"disabled"}',
            "data_root",
            "count=1\nvalue=<>\nis_null=False\nequals_empty=True",
        ),
        (
            '{"status":"disabled"}',
            "gateway_path",
            "count=1\nvalue=<>\nis_null=False\nequals_empty=True",
        ),
        (
            '{"status":"disabled"}',
            "gateway_sha256",
            "count=1\nvalue=<>\nis_null=False\nequals_empty=True",
        ),
        (
            '{"launcher_signed":false}',
            "signer_thumbprint_sha256",
            "count=1\nvalue=<>\nis_null=False\nequals_empty=True",
        ),
        (
            '{"signer_thumbprint_sha256":"aaaaaaaa"}',
            "signer_thumbprint_sha256",
            "count=1\nvalue=<aaaaaaaa>\nis_null=False\nequals_empty=False",
        ),
    ],
)
def test_optional_release_state_property_is_strict_mode_safe(
    json_value: str,
    property_name: str,
    expected: str,
) -> None:
    completed = _run_optional_json_property(json_value, property_name)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert completed.stdout.strip().replace("\r\n", "\n") == expected


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
    windows_jobs = {
        name
        for name, candidate in smoke_workflow["jobs"].items()
        if "windows" in str(candidate.get("runs-on", "")).lower()
    }
    assert windows_jobs == {
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
    assert "-UninstallContract deferred" in rendered
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
        "AMP_API_KEY",
    ):
        assert retired not in smoke_text

    assert "invoke-windows-setup-standard-user-ci.ps1" in FRESH_INSTALL
    assert "-Mode bootstrap-acceptance" in FRESH_INSTALL
    assert "-ArtifactRoot $ReleaseDir" in FRESH_INSTALL
    assert "-TargetVersion $TargetVersion" in FRESH_INSTALL
    assert "-BootstrapUninstallContract $UninstallContract" in FRESH_INSTALL
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
    for marker in DEFERRED_UNINSTALL_REQUIRED_MARKERS:
        assert marker in FRESH_INSTALL
    for marker in DEFERRED_UNINSTALL_FORBIDDEN_MARKERS:
        assert marker not in FRESH_INSTALL
    for optional_property in (
        "cleanup_boot_identifier",
        "maintenance_sha256",
        "previous_connectors",
        "verified_connectors",
        "data_root",
        "gateway_path",
        "gateway_sha256",
        "signer_thumbprint_sha256",
    ):
        assert f'-PropertyName "{optional_property}"' in FRESH_INSTALL
    for unsafe_access in (
        "$cleanupRecord.cleanup_boot_identifier",
        "$cleanupRecord.signer_thumbprint_sha256",
        "$transaction.maintenance_sha256",
        "$transaction.previous_connectors",
        "$hookState.data_root",
        "$hookState.gateway_path",
        "$hookState.gateway_sha256",
    ):
        assert unsafe_access not in FRESH_INSTALL
    for precise_cleanup_record_failure in (
        "unsupported cleanup record schema",
        "cleanup record is not pending reboot",
        "invalid transaction identity",
        "prematurely names a cleanup boot",
        "invalid uninstall boot identity",
    ):
        assert precise_cleanup_record_failure in FRESH_INSTALL
    assert "did not retain the exact pending cleanup record" not in FRESH_INSTALL
    assert 'GetEnvironmentVariable("Path", "User")' in FRESH_INSTALL
    assert "uninstall did not restore the original user PATH exactly" in FRESH_INSTALL
    assert FRESH_INSTALL.rindex("$installed = $false") > FRESH_INSTALL.index(
        "$uninstall.ExitCode -ne $expectedUninstallExitCode"
    )
    assert FRESH_INSTALL.rindex("$installed = $false") < FRESH_INSTALL.index("Assert-ExactDeferredUninstallState `")
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


def test_windows_release_validator_can_replay_an_exact_failed_candidate() -> None:
    workflow = _workflow(WINDOWS_NATIVE_PATH)
    dispatch_inputs = workflow["on"]["workflow_dispatch"]["inputs"]
    assert set(dispatch_inputs) == {
        "release_candidate_replay_run_id",
        "release_candidate_replay_artifact",
        "release_candidate_replay_version",
        "release_candidate_replay_commit",
    }
    assert all(value["required"] == "false" for value in dispatch_inputs.values())
    assert all(value["type"] == "string" for value in dispatch_inputs.values())

    replay = workflow["jobs"]["release-validator-replay"]
    rendered = str(replay)
    assert replay["runs-on"] == "windows-latest"
    assert int(replay["timeout-minutes"]) >= 45
    assert replay["permissions"] == {
        "actions": "read",
        "contents": "read",
    }
    assert replay["env"] == {
        "REPLAY_RUN_ID": "${{ inputs.release_candidate_replay_run_id }}",
        "REPLAY_ARTIFACT": "${{ inputs.release_candidate_replay_artifact }}",
        "REPLAY_VERSION": "${{ inputs.release_candidate_replay_version }}",
        "REPLAY_COMMIT": "${{ inputs.release_candidate_replay_commit }}",
    }
    assert "github.event_name == 'workflow_dispatch'" in replay["if"]
    assert "inputs.release_candidate_replay_run_id != ''" in replay["if"]

    identity = _step(replay, "Validate exact replay identity")["run"]
    assert "^[1-9][0-9]*$" in identity
    assert "^release-candidate-${escapedRunID}-[1-9][0-9]*$" in identity
    assert "^[0-9a-f]{40}$" in identity

    download = _step(replay, "Download exact sealed release candidate")
    assert download["with"]["repository"] == "cisco-ai-defense/defenseclaw"
    assert download["with"]["run-id"] == ("${{ inputs.release_candidate_replay_run_id }}")
    assert download["with"]["github-token"] == "${{ github.token }}"

    authentication = _step(replay, "Restore and authenticate exact release candidate")["run"]
    assert "release_candidate.py unpack-transport" in authentication
    assert "release_candidate.py verify" in authentication
    assert "verify-sigstore-blob.py" in authentication
    assert "release.yaml@refs/heads/main" in authentication

    exercise = _step(replay, "Replay current validator against exact failed candidate")["run"]
    assert "test-fresh-install-release-windows.ps1" in exercise
    assert "-TargetVersion $env:REPLAY_VERSION" in exercise
    assert "-UninstallContract deferred" in exercise
    assert "-StateRoot $replayState" in exercise
    assert "-DiagnosticsRoot $env:DC_DIAGNOSTICS" in exercise
    assert "release-candidate-30488158730-1" not in rendered
    assert "10a998fbff1b4d77be8629b3099d8b868219dc4c" not in rendered


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


def test_native_diagnostic_capture_is_bound_to_verified_file_handles() -> None:
    selection = _function("Get-WindowsNativeCaptureFiles")
    capture = _function("Invoke-Capture")

    assert "SortedDictionary[string, IO.FileInfo]" in selection
    assert "$selectionLimit = 30" in selection
    assert "$matches" not in selection.casefold()
    assert "$visited" not in selection
    assert "OpenRootedReader($root)" in capture
    assert "ReadBoundedUtf8($file.FullName, 1048576)" in capture
    assert "ReadAllText($file.FullName)" not in capture

    for contract in (
        "FILE_FLAG_OPEN_REPARSE_POINT",
        "GetFileInformationByHandle",
        "GetFinalPathNameByHandleW",
        "sealed class RootedReader",
        "guarded file resolved outside its retained root",
    ):
        assert contract in DISPOSABLE_FILE_GUARD
    assert "leaf replaced by a reparse point after enumeration" in HARNESS
    assert "replaced ancestor outside its retained root" in HARNESS


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
    assert "Windows acceptance is" in release
    assert "fresh-install-only" in release
    assert re.search(
        r"no historical Windows baseline is inferred or\s+required",
        release,
    )
    assert "first native Windows release" not in release


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
    for loader in (
        "_schema_validator()",
        "telemetry_v8_schema_bytes()",
        "telemetry_v8_catalog_bytes()",
        "v7_exporter_selection_bytes()",
        '"galileo-rich-v2"',
        '"local-observability-v1"',
        '"openinference-v1"',
    ):
        assert loader in PACKAGED_V8_VALIDATOR
    assert "runtime unexpectedly contains a Lib/schemas fallback tree" in (PACKAGED_V8_VALIDATOR)
    assert "scripts\\validate_packaged_v8_resources.py" in resource_contract
    assert "Test-Path -LiteralPath $validator -PathType Leaf" in resource_contract
    assert "'-I', $validator" in resource_contract
    assert "'--site-packages', $sitePackages" in resource_contract
    assert "'--runtime-root', $RuntimeRoot" in resource_contract
    assert "'--label', 'packaged'" in resource_contract

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


def test_setup_uninstall_acceptance_separates_signed_cli_from_unsigned_fixture() -> None:
    acceptance = _function("Invoke-SetupAcceptance")

    assert "if ($requireSignedProduct)" in acceptance
    assert "'uninstall', '--all', '--yes'" in acceptance
    assert "restart required.*3010" in acceptance
    assert "Native installer state is not an authenticated signed user installation" in acceptance
    assert "unsigned native CLI refusal mutated installed state" in acceptance
    assert "Invoke-WindowsSetupStandardUserProcess $cachedSetup" in acceptance
    assert "'/uninstall', '/quiet', 'DELETEUSERDATA=1'" in acceptance
    assert acceptance.count("-AllowedExitCodes @(3010)") >= 3
    assert "RegistryValueOptions]::DoNotExpandEnvironmentNames" in acceptance
    assert "RegistryValueKind]::String" in acceptance
    assert "Run value is not the exact absolute cached Setup command" in acceptance


def test_amp_native_windows_coverage_is_separate_from_the_release_channel() -> None:
    release = RELEASE_PATH.read_text(encoding="utf-8")
    windows_native = (ROOT / ".github" / "workflows" / "windows-native.yml").read_text(encoding="utf-8")
    connector_live = (ROOT / ".github" / "workflows" / "connector-live-e2e.yml").read_text(encoding="utf-8")

    assert "windows-real-client-certification:" not in release
    for secret in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AMP_API_KEY"):
        assert secret not in release

    assert "connector: [codex, claudecode, amp]" in windows_native
    assert "connector: [codex, claudecode, amp]" in connector_live
    assert "AMP_API_KEY: ${{ secrets.AMP_API_KEY }}" in connector_live
    assert "AMP_VERSION: ${{ inputs.version }}" in connector_live
    assert "-Layer live" in connector_live

    for contract in (
        'amp.on("session.start"',
        'amp.on("agent.start"',
        'amp.on("tool.call"',
        'amp.on("tool.result"',
        'amp.on("agent.end"',
        "subagent_tool_call.json",
        "amp:plugin-contract",
        "amp:private-plugin",
        "amp:self-heal",
        "doctor:windows-hook-tamper",
        "doctor:windows-hook-recovery",
        "gateway-generated connector telemetry",
    ):
        assert contract in LIVE


def test_amp_windows_live_prompts_invoke_native_pwsh_explicitly() -> None:
    helper = re.search(
        r"(?ms)^function Get-AmpWindowsPowerShellToolCommand\b.*?(?=^function |\Z)",
        LIVE,
    )
    result_gate = re.search(
        r"(?ms)^function Assert-AmpAuthenticatedToolResultGate\b.*?(?=^function |\Z)",
        LIVE,
    )
    live_run = re.search(
        r"(?ms)^function Invoke-LiveRun\b.*?(?=^function |\Z)",
        LIVE,
    )
    assert helper is not None
    assert result_gate is not None
    assert live_run is not None
    assert "(Get-Process -Id $PID).Path.Replace('\\', '/')" in helper.group(0)
    assert "-NoLogo -NoProfile -NonInteractive -Command" in helper.group(0)
    assert "cannot contain double quotes" in helper.group(0)
    assert "Get-AmpWindowsPowerShellToolCommand(" in result_gate.group(0)
    assert result_gate.group(0).count("Get-Content -Raw -LiteralPath") == 1
    assert live_run.group(0).count("Get-AmpWindowsPowerShellToolCommand") == 2
    assert "if ($Connector -eq 'amp')" in live_run.group(0)
    assert "blocked-remove-target" in live_run.group(0)
    assert "Remove-Item -LiteralPath '$escapedBlockTarget' -Recurse -Force" in live_run.group(0)
    assert "blocked Amp action modified its disposable destructive target" in live_run.group(0)
    assert live_run.group(0).count(r"C:\Windows\System32\config\SAM") == 1


def test_amp_windows_validation_evidence_is_not_faked() -> None:
    registry = json.loads(
        (ROOT / "cli" / "defenseclaw" / "inventory" / "validated_versions.json").read_text(encoding="utf-8")
    )
    windows = registry["connectors"]["amp"]["os"]["windows"]
    assert windows["run_url"] == ""


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


def test_minimal_gateway_fixture_disables_external_v8_destinations() -> None:
    minimal = _function("Set-MinimalGatewayAcceptanceConfig")

    for contract in (
        "config_path_for_data_dir",
        "load_validate_v8",
        "mutate_v8_config",
        "V8YAMLMutation.set",
        '("observability", "destinations", index, "enabled")',
        'frozenset({"http_jsonl", "otlp", "splunk_hec"})',
        'destination.get("enabled", True)',
    ):
        assert contract in minimal
    assert minimal.index("cfg.save()") < minimal.index("mutate_v8_config(")


def test_packaged_rotation_probes_only_owned_gateway_without_secret_output() -> None:
    process = _function("Invoke-WindowsNativeProcess")
    rotation = _function("Assert-PackagedClaudeTokenRotation")
    authentication = _function("Assert-ClaudeNativeOtlpRotationAuthentication")
    authority = _function("Assert-ClaudeNativeOtlpProbeAuthority")
    listener = _function("Assert-OwnedGatewayApiListener")
    owned_process = _function("Assert-OwnedManagedProcess")
    stale_identity = _function("Assert-StaleGatewayProcessIdentityRejected")
    port = _function("Get-PackagedGatewayApiPort")
    posture = _function("Get-PackagedRotationConnectorPosture")
    posture_assertion = _function("Assert-PackagedRotationActionClosedPosture")

    assert "[switch]$SuppressOutput" in process
    assert "if ($combined -and -not $SuppressOutput -and -not $goTestFailureSummary)" in process
    assert "[credential-bearing process output intentionally suppressed]" in process
    assert 'if ($SuppressOutput) { throw "$FilePath $reason" }' in process
    assert rotation.count("-SuppressOutput") == 5
    for operation in (
        "setup-codex",
        "setup-claudecode",
        "status-before",
        "rotate-token",
        "status-after",
    ):
        assert f"packaged token rotation {operation} failed:" in rotation
    assert "'setup', 'codex', '--yes', '--mode', 'action', '--fail-mode', 'closed', '--restart'" in rotation
    assert "'setup', 'claude-code', '--yes', '--mode', 'action', '--fail-mode', 'closed', '--restart'" in rotation
    assert "Get-PackagedRotationConnectorPosture $statusBefore" in rotation
    assert "Get-PackagedRotationConnectorPosture $status" in rotation
    assert "$postureAfterJson -cne $postureBeforeJson" in rotation
    assert "changed the exact connector roster or effective mode/fail-mode posture" in rotation
    assert "Get-WindowsNativeGatewayTokenFromDotenvState $tokenAState" in rotation
    assert "Get-WindowsNativeGatewayTokenFromDotenvState $tokenBState" in rotation
    assert "[string]::Equals($tokenA, $tokenB" in rotation
    assert "Assert-WindowsNativeCredentialValuesAbsent" in rotation
    assert "Get-ClaudeNativeOtlpRotationProbes $ClaudeHome" in rotation
    assert "Assert-ClaudeNativeOtlpForeignPortRejected" in rotation
    assert "substituted a gateway master token for scoped credentials" in rotation
    assert "$scopedTokens[0], $scopedTokens[1]" in rotation

    assert "os.environ.pop('DEFENSECLAW_CONFIG', None)" in port
    assert "cfg = load(data_dir=root)" in port
    assert "Path(cfg.data_dir).resolve() != root" in port
    assert "$endpoint.Port -ne $GatewayPort" in authority
    assert "Get-NetTCPConnection -State Listen -LocalPort $GatewayPort" in listener
    assert "OwningProcess -ne [int]$GatewayIdentity.ProcessId" in listener
    assert "Assert-OwnedManagedProcess $GatewayIdentity $GatewayPath" in listener
    assert "$liveStartIdentity -cne [string]$Identity.StartIdentity" in owned_process
    assert "Assert-OwnedManagedProcess $stale $GatewayPath" in stale_identity
    assert "accepted a stale or reused gateway process identity" in stale_identity
    assert "Assert-StaleGatewayProcessIdentityRejected" in rotation
    for field in (
        "fail_effective",
        "fail_configured",
        "fail_desired",
        "fail_runtime",
        "fail_current",
        "fail_drift",
    ):
        assert field in posture
        assert field in posture_assertion
    assert "[Net.IPAddress]::IsLoopback($address)" in listener
    assert authentication.index("Assert-ClaudeNativeOtlpProbeAuthority") < authentication.index(
        "[Net.Http.HttpClientHandler]::new()"
    )
    assert authentication.index("Assert-OwnedGatewayApiListener") < authentication.index(
        "[Net.Http.HttpClientHandler]::new()"
    )
