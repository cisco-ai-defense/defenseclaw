# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Contracts for the Windows standalone enterprise profile.

The standalone profile shares the lifecycle module and installer with the
production Cisco Secure Client deployment. These checks keep the Secure
Client roots in one place, keep the two profile-root helpers in lockstep,
and pin the standalone-only guards, pins, and per-user refusals.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"
INSTALLER = ROOT / "packaging" / "windows" / "install-enterprise.ps1"
PER_USER_INSTALLER = ROOT / "scripts" / "install.ps1"
WINPATH_LAYOUT = ROOT / "internal" / "winpath" / "enterprise_layout.go"
HOOK_CONTRACTS = ROOT / "internal" / "gateway" / "connector" / "hook_contract.go"

SECURE_CLIENT = "Cisco Secure Client"

# Code (not comments) may name the Secure Client vendor directory only in
# these functions: the two profile-root helpers, the CMID provider root the
# Secure Client credential broker loads from, and the cross-profile refusal
# message.
ALLOWED_MODULE_FUNCTIONS = {
    "Get-DefenseClawProfileRoots",
    "Assert-DefenseClawExactScopeService",
    "Assert-DefenseClawNoOtherProfileDeployment",
}
ALLOWED_INSTALLER_FUNCTIONS = {"Get-DefenseClawBootstrapProfileRoots"}


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig")


def _code_lines_by_function(text: str) -> list[tuple[str | None, int, str]]:
    """Yield (enclosing top-level function, line number, code) for every line
    that is not a comment. Here-strings are treated as code."""

    rows: list[tuple[str | None, int, str]] = []
    current: str | None = None
    in_block_comment = False
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if in_block_comment:
            if "#>" in stripped:
                in_block_comment = False
            continue
        if stripped.startswith("<#"):
            in_block_comment = "#>" not in stripped
            continue
        match = re.match(r"^function ([A-Za-z0-9-]+) \{", line)
        if match:
            current = match.group(1)
        elif line.startswith("}"):
            rows.append((current, number, line))
            current = None
            continue
        if stripped.startswith("#"):
            continue
        rows.append((current, number, line))
    return rows


def _functions_naming(text: str, literal: str) -> dict[str | None, list[int]]:
    found: dict[str | None, list[int]] = {}
    for function, number, line in _code_lines_by_function(text):
        if literal in line:
            found.setdefault(function, []).append(number)
    return found


def _function_body(text: str, name: str) -> str:
    start = text.index(f"function {name} {{\n")
    end = text.index("\n}\n", start)
    return text[start : end + 3]


def test_upgrade_restores_owner_rewritten_account_state_before_guardian_activation() -> None:
    # GAP-0513: the signed-out account's old hook lock must be readable before
    # the new guardian classifies its hooks as awaiting the next sign-in.
    body = _function_body(_text(MODULE), "Invoke-DefenseClawInstallLikeLifecycle")
    stopped = body.index("Stop-DefenseClawService -Name $GuardianServiceName")
    guarded = body.index("if ($Action -eq 'Upgrade' -and $priorDeploymentActive -and", stopped)
    restored = body.index("Invoke-DefenseClawManagedUserStateOwnerRightsRestore", guarded)
    classified = body.index("Get-DefenseClawManagedHooksLegacyActivationClassification", restored)
    activated = body.index("Wait-DefenseClawFreshGuardianReconcile", classified)
    assert stopped < guarded < restored < classified < activated
    assert "([string]$metadata.product_version) -match '^1\\.0\\.6(?:$|[+-])'" in body[guarded:restored]
    assert "Test-DefenseClawUpgradeOwnerRightsRestoreNeeded" in body[guarded:restored]
    assert "-UpgradeOnly" in body[restored : restored + 220]
    probe = _function_body(_text(MODULE), "Test-DefenseClawUpgradeOwnerRightsRestoreNeeded")
    assert "'--probe', '--upgrade-only', '--json'" in probe
    assert "[int]$report.succeeded_count -gt 0" in probe


def test_fresh_install_rebinds_adopted_hook_manifest_before_retiring_its_journal() -> None:
    # rel-1-0-4:GAP-0686: an enumerator may publish targets after the
    # install's activation proof, before journal retirement.
    install = _function_body(_text(MODULE), "Invoke-DefenseClawInstallLikeLifecycle")
    committed = install.rfind("Complete-DefenseClawTransaction -SnapshotPath $snapshot -Layout $Layout")
    retired = install.rfind("-Action retire)")
    rebound = install.find("Sync-DefenseClawStandaloneManagedHooksActivationBinding", committed)
    assert 0 <= committed < rebound < retired


def test_activation_rebind_uses_protected_metadata_publication() -> None:
    # GAP-0655: a changed manifest updates the deployment record through the
    # same protected, staged publication path as other metadata writers.
    module = _text(MODULE)
    rebind = _function_body(module, "Sync-DefenseClawStandaloneManagedHooksActivationBinding")
    staged = rebind.index("$json = $document.ToJsonString")
    published = rebind.index("Write-DefenseClawDeploymentMetadataBytes", staged)
    verified = rebind.index("$rebound = Get-DefenseClawDeploymentMetadata", published)
    assert staged < published < verified
    assert "Microsoft.PowerShell.Management\\Move-Item" not in rebind

    writer = _function_body(module, "Write-DefenseClawDeploymentMetadataBytes")
    protected = writer.index("Set-DefenseClawPathAcl")
    moved = writer.index("Move-DefenseClawNonImageFileReplacing", protected)
    assert protected < moved


def test_deployment_metadata_entry_and_reader_retry_the_validated_lookup() -> None:
    # GAP-0655: a changed metadata body may briefly hide its pathname from a
    # concurrent reader. Both the entry probe and the full read must retry.
    module = _text(MODULE)
    entry = _function_body(module, "Invoke-DefenseClawEnterpriseLifecycle")
    rebind = _function_body(module, "Sync-DefenseClawStandaloneManagedHooksActivationBinding")
    reader = _function_body(module, "Get-DefenseClawDeploymentMetadata")
    entry_probe = _function_body(module, "Test-DefenseClawDeploymentMetadataPresent")
    once = _function_body(module, "Get-DefenseClawDeploymentMetadataOnce")
    assert "Test-DefenseClawDeploymentMetadataPresent -Path $layout.MetadataPath" in entry
    assert "Test-DefenseClawDeploymentMetadataPresent -Path $Layout.MetadataPath" in rebind
    assert "Get-DefenseClawDeploymentMetadataOnce" in reader
    assert "Test-DefenseClawTransientDeploymentMetadataError" in reader
    assert "Test-DefenseClawTransientDeploymentMetadataError" in entry_probe
    assert "Start-Sleep -Milliseconds $delays[$attempt]" in entry_probe
    assert "-not (Test-DefenseClawStandaloneProfile)" in reader
    assert once.index("Assert-DefenseClawNoReparsePath") < once.index("Get-Content")
    assert once.rindex("Assert-DefenseClawCanonicalPathAcl") > once.index("Get-Content")


def test_deployment_metadata_retry_keeps_permanent_failures_and_secure_client_single_pass() -> None:
    module = _text(MODULE)
    reader = _function_body(module, "Get-DefenseClawDeploymentMetadata")
    transient = _function_body(module, "Test-DefenseClawTransientDeploymentMetadataError")
    assert reader.index("if (-not (Test-DefenseClawStandaloneProfile))") < reader.index("for ($attempt")
    assert "return Get-DefenseClawDeploymentMetadataOnce -Layout $Layout -Required:$Required" in reader
    assert "if (-not (Test-DefenseClawTransientDeploymentMetadataError" in reader
    assert "$exception -is [Management.Automation.ItemNotFoundException]" in transient
    assert "NativeErrorCode -in @(2, 3, 32, 33)" in transient
    assert "$exception.HResult -band 0xffff) -in @(2, 3, 32, 33)" in transient


def test_deployment_metadata_retry_recovers_only_a_transient_name(tmp_path: Path) -> None:
    import json

    engine = _portable_pwsh()
    if engine is None:
        pytest.skip("PowerShell 7 (pwsh) is not installed")
    module = _text(MODULE)
    functions = "\n".join(
        _function_body(module, name)
        for name in (
            "Test-DefenseClawTransientDeploymentMetadataError",
            "Get-DefenseClawDeploymentMetadata",
        )
    )
    harness = tmp_path / "metadata-transient-read.ps1"
    harness.write_text(
        "param([string]$MetadataPath)\n$ErrorActionPreference = 'Stop'\nSet-StrictMode -Version Latest\n"
        + functions
        + r"""
$script:Standalone = $true
$script:Mode = 'transient'
$script:Attempts = 0
function Test-DefenseClawStandaloneProfile { return $script:Standalone }
function Get-DefenseClawDeploymentMetadataOnce {
    param([hashtable]$Layout, [switch]$Required)
    $script:Attempts++
    if ($script:Mode -eq 'absent' -or
        ($script:Mode -eq 'transient' -and $script:Attempts -eq 1)) {
        throw [IO.FileNotFoundException]::new('metadata is missing', $Layout.MetadataPath)
    }
    if ($script:Mode -eq 'sharing' -and $script:Attempts -eq 1) {
        throw [ComponentModel.Win32Exception]::new(32)
    }
    if ($script:Mode -eq 'lock_win32' -and $script:Attempts -eq 1) {
        throw [ComponentModel.Win32Exception]::new(33)
    }
    if ($script:Mode -eq 'lock_io' -and $script:Attempts -eq 1) {
        throw [IO.IOException]::new('metadata is locked', 0x80070021)
    }
    if ($script:Mode -eq 'denied') {
        throw [UnauthorizedAccessException]::new('metadata access denied')
    }
    return [pscustomobject]@{ installed = $true }
}
$layout = @{ MetadataPath = $MetadataPath }
[IO.File]::WriteAllText($MetadataPath, '{}')
$accepted = Get-DefenseClawDeploymentMetadata -Layout $layout -Required
$transientAttempts = $script:Attempts
$script:Mode = 'sharing'; $script:Attempts = 0
$shared = Get-DefenseClawDeploymentMetadata -Layout $layout -Required
$sharingAttempts = $script:Attempts
$script:Mode = 'lock_win32'; $script:Attempts = 0
$lockedWin32 = Get-DefenseClawDeploymentMetadata -Layout $layout -Required
$lockWin32Attempts = $script:Attempts
$script:Mode = 'lock_io'; $script:Attempts = 0
$lockedIO = Get-DefenseClawDeploymentMetadata -Layout $layout -Required
$lockIOAttempts = $script:Attempts
$script:Mode = 'denied'; $script:Attempts = 0
$denied = $false
try { [void](Get-DefenseClawDeploymentMetadata -Layout $layout -Required) }
catch { $denied = $_.Exception -is [UnauthorizedAccessException] }
$deniedAttempts = $script:Attempts
[IO.File]::Delete($MetadataPath)
$script:Mode = 'absent'; $script:Attempts = 0
$missing = Get-DefenseClawDeploymentMetadata -Layout $layout
$missingAttempts = $script:Attempts
$script:Standalone = $false; $script:Mode = 'transient'; $script:Attempts = 0
$secureClientThrew = $false
try { [void](Get-DefenseClawDeploymentMetadata -Layout $layout -Required) }
catch { $secureClientThrew = $_.Exception -is [IO.FileNotFoundException] }
[pscustomobject]@{
    accepted = [bool]$accepted.installed
    transient_attempts = $transientAttempts
    sharing_accepted = [bool]$shared.installed
    sharing_attempts = $sharingAttempts
    lock_win32_accepted = [bool]$lockedWin32.installed
    lock_win32_attempts = $lockWin32Attempts
    lock_io_accepted = [bool]$lockedIO.installed
    lock_io_attempts = $lockIOAttempts
    denied = $denied
    denied_attempts = $deniedAttempts
    missing = ($null -eq $missing)
    missing_attempts = $missingAttempts
    secure_client_threw = $secureClientThrew
    secure_client_attempts = $script:Attempts
} | ConvertTo-Json -Compress
""",
        encoding="utf-8",
    )
    result = subprocess.run(
        [engine, "-NoProfile", "-File", str(harness), str(tmp_path / "deployment.json")],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == {
        "accepted": True,
        "transient_attempts": 2,
        "sharing_accepted": True,
        "sharing_attempts": 2,
        "lock_win32_accepted": True,
        "lock_win32_attempts": 2,
        "lock_io_accepted": True,
        "lock_io_attempts": 2,
        "denied": True,
        "denied_attempts": 1,
        "missing": True,
        "missing_attempts": 7,
        "secure_client_threw": True,
        "secure_client_attempts": 1,
    }


def test_deployment_metadata_entry_retries_first_lock_violation(tmp_path: Path) -> None:
    import json

    engine = _portable_pwsh()
    if engine is None:
        pytest.skip("PowerShell 7 (pwsh) is not installed")
    module = _text(MODULE)
    classifier = _function_body(module, "Test-DefenseClawTransientDeploymentMetadataError")
    entry_probe = _function_body(module, "Test-DefenseClawDeploymentMetadataPresent")
    # The production probe qualifies Test-Path. Replace only that command in
    # this harness so each first open can report a controlled Windows error.
    entry_probe = entry_probe.replace(
        "Microsoft.PowerShell.Management\\Test-Path", "Test-TransientProbePath"
    )
    harness = tmp_path / "metadata-entry-lock.ps1"
    harness.write_text(
        "$ErrorActionPreference = 'Stop'\nSet-StrictMode -Version Latest\n"
        + classifier
        + entry_probe
        + r"""
$script:Standalone = $true
$script:Mode = 'lock_win32'
$script:Attempts = 0
function Test-DefenseClawStandaloneProfile { return $script:Standalone }
function Test-TransientProbePath {
    param([string]$LiteralPath, [string]$PathType)
    if ($PathType -eq 'Container') { return $true }
    $script:Attempts++
    if ($script:Attempts -eq 1) {
        if ($script:Mode -eq 'probe_false') {
            return $false
        }
        if ($script:Mode -eq 'lock_win32') {
            throw [ComponentModel.Win32Exception]::new(33)
        }
        if ($script:Mode -eq 'lock_io') {
            throw [IO.IOException]::new('metadata is locked', 0x80070021)
        }
        if ($script:Mode -eq 'denied') {
            throw [UnauthorizedAccessException]::new('metadata access denied')
        }
    }
    if ($script:Mode -eq 'absent') { return $false }
    return $true
}
$path = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'deployment.json')
$win32Present = Test-DefenseClawDeploymentMetadataPresent -Path $path
$win32Attempts = $script:Attempts
$script:Mode = 'lock_io'; $script:Attempts = 0
$ioPresent = Test-DefenseClawDeploymentMetadataPresent -Path $path
$ioAttempts = $script:Attempts
$script:Mode = 'probe_false'; $script:Attempts = 0
$falseThenPresent = Test-DefenseClawDeploymentMetadataPresent -Path $path
$falseThenPresentAttempts = $script:Attempts
$script:Mode = 'absent'; $script:Attempts = 0
$absent = Test-DefenseClawDeploymentMetadataPresent -Path $path
$absentAttempts = $script:Attempts
$script:Mode = 'denied'; $script:Attempts = 0
$denied = $false
try { [void](Test-DefenseClawDeploymentMetadataPresent -Path $path) }
catch { $denied = $_.Exception -is [UnauthorizedAccessException] }
$deniedAttempts = $script:Attempts
$script:Standalone = $false; $script:Mode = 'lock_win32'; $script:Attempts = 0
$secureClientThrew = $false
try { [void](Test-DefenseClawDeploymentMetadataPresent -Path $path) }
catch { $secureClientThrew = $_.Exception -is [ComponentModel.Win32Exception] }
$secureClientAttempts = $script:Attempts
$script:Mode = 'probe_false'; $script:Attempts = 0
$secureClientFalse = Test-DefenseClawDeploymentMetadataPresent -Path $path
[pscustomobject]@{
    win32_present = $win32Present
    win32_attempts = $win32Attempts
    io_present = $ioPresent
    io_attempts = $ioAttempts
    false_then_present = $falseThenPresent
    false_then_present_attempts = $falseThenPresentAttempts
    absent = $absent
    absent_attempts = $absentAttempts
    denied = $denied
    denied_attempts = $deniedAttempts
    secure_client_threw = $secureClientThrew
    secure_client_attempts = $secureClientAttempts
    secure_client_false = $secureClientFalse
    secure_client_false_attempts = $script:Attempts
} | ConvertTo-Json -Compress
""",
        encoding="utf-8",
    )
    result = subprocess.run(
        [engine, "-NoProfile", "-File", str(harness)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == {
        "win32_present": True,
        "win32_attempts": 2,
        "io_present": True,
        "io_attempts": 2,
        "false_then_present": True,
        "false_then_present_attempts": 2,
        "absent": False,
        "absent_attempts": 7,
        "denied": True,
        "denied_attempts": 1,
        "secure_client_threw": True,
        "secure_client_attempts": 1,
        "secure_client_false": False,
        "secure_client_false_attempts": 1,
    }


def test_profile_roots_are_named_in_one_place_and_agree() -> None:
    module = _functions_naming(_text(MODULE), SECURE_CLIENT)
    assert set(module) <= ALLOWED_MODULE_FUNCTIONS, {
        name: lines for name, lines in module.items() if name not in ALLOWED_MODULE_FUNCTIONS
    }
    installer = _functions_naming(_text(INSTALLER), SECURE_CLIENT)
    assert set(installer) <= ALLOWED_INSTALLER_FUNCTIONS, {
        name: lines for name, lines in installer.items() if name not in ALLOWED_INSTALLER_FUNCTIONS
    }
    # The module, the bootstrap and internal/winpath name the same vendor
    # roots for each profile.
    for body in (
        _function_body(_text(MODULE), "Get-DefenseClawProfileRoots"),
        _function_body(_text(INSTALLER), "Get-DefenseClawBootstrapProfileRoots"),
    ):
        assert "'Cisco\\Cisco Secure Client'" in body and "'Cisco'" in body
    layout = _text(WINPATH_LAYOUT)
    assert 'vendor, powerShell = `Cisco\\Cisco Secure Client`, "SecureClient"' in layout
    assert 'vendor, powerShell = `Cisco`, "Standalone"' in layout


def test_standalone_host_guards_run_before_the_bootstrap() -> None:
    text = _text(INSTALLER)
    guard = text.index("if ($EnterpriseProfile -ceq 'Standalone') {")
    assert text.index("Microsoft.PowerShell.Core\\Set-StrictMode -Version Latest") < guard
    first_function = text.index("\nfunction ")
    assert guard < first_function
    block = text[guard:first_function]
    for code in (
        "powershell7_required:",
        "powershell_32bit_host:",
        "unsupported_architecture:",
        "powershell_constrained_language:",
    ):
        assert code in block, code
    assert "$PSVersionTable.PSVersion.Major -lt 7" in block
    assert "[Environment]::Is64BitProcess" in block
    assert "OSArchitecture" in block
    assert "[Management.Automation.PSLanguageMode]::FullLanguage" in block
    # The Secure Client path refuses the standalone-only arguments instead of
    # silently ignoring them.
    assert "apply only to -EnterpriseProfile Standalone" in block


def test_profile_pin_is_written_only_for_standalone_services() -> None:
    text = _text(MODULE)
    pin = "DEFENSECLAW_ENTERPRISE_PROFILE=standalone"
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if pin not in line:
            continue
        window = "\n".join(lines[max(0, index - 12) : index + 1])
        assert (
            "Test-DefenseClawStandaloneProfile" in window
            or "-not [bool]$Layout.BrokerEnabled" in window
            or "Test-DefenseClawLayoutBrokerEnabled" in window
        ), f"profile pin at line {index + 1} is not gated to the standalone profile"


def test_secure_client_layout_keeps_its_historical_shape() -> None:
    layout = _function_body(_text(MODULE), "Get-DefenseClawLayout")
    # Only standalone layouts carry profile keys.
    assert "$layout['Profile'] = 'Standalone'" in layout
    assert "$layout['BrokerEnabled'] = $false" in layout
    assert "Profile = " not in layout.split("$layout = @{", 1)[1].split("\n    }\n", 1)[0]


def test_per_user_installer_refuses_a_managed_host_before_any_change() -> None:
    text = _text(PER_USER_INSTALLER)
    check = text.index('OpenSubKey("SOFTWARE\\Cisco\\DefenseClaw\\Enterprise")')
    assert "A managed DefenseClaw enterprise deployment" in text
    assert check < text.index("return Invoke-ReleaseInstaller") < text.index("# Lock and log.")
    assert check < text.index("if ($Rollback) { return Invoke-Rollback }")


def test_hash_pinned_manifest_contract_is_shared() -> None:
    module = _text(MODULE)
    installer = _text(INSTALLER)
    for text in (module, installer):
        assert "schema_version" in text and "PayloadManifest" in text
    assert "'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'" in module
    go = _text(ROOT / "internal" / "cli" / "windows_enterprise_profile.go")
    assert "`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`" in go
    setup = _text(ROOT / "cmd" / "defenseclaw-enterprise-setup" / "platform_windows.go")
    assert '"schema_version": 1, "files": files' in setup


def test_fresh_install_rollback_removes_its_sensor_helper_on_every_profile() -> None:
    # Transaction snapshots do not record the sensor helper, which a fresh
    # install registers first on both profiles. A failed first install must
    # remove that owned service before the service-absence gate, or root
    # cleanup refuses ("rollback also failed and pending recovery was
    # retained") and every later ensure/uninstall is wedged. Secure Client
    # registers it too, so the removal is not gated on the standalone profile.
    module = _text(MODULE)
    body = module[
        module.index("function Publish-DefenseClawInstallRollbackIntent") : module.index(
            "function Assert-DefenseClawInstallRollbackRootDescriptor"
        )
    ]
    no_authority = body.index("if (-not $createdAny -and $null -eq $existing)")
    helper = body.index("$sensorHelperName = Get-DefenseClawSensorHelperServiceName `", no_authority)
    owned = body.index("Assert-DefenseClawStandaloneSensorHelperOwned `", helper)
    remove = body.index("Remove-DefenseClawService -Name $sensorHelperName", owned)
    absence = body.index("Get-DefenseClawManagedServiceNames `", remove)
    assert no_authority < helper < owned < remove < absence
    assert "Test-DefenseClawStandaloneProfile" not in body[no_authority:helper]


def test_rollback_quiesces_the_sensor_helper_before_restoring_files_on_every_profile() -> None:
    module = _text(MODULE)
    start = module.index("function Restore-DefenseClawTransaction {")
    body = module[start : module.index("\nfunction ", start + 10)]
    # Both profiles register the sensor helper, so the quiesce is not gated on
    # the standalone profile (a Secure Client rollback found it running).
    gate = body.index("$standaloneSensorHelper = Get-DefenseClawSensorHelperServiceName `")
    assert "Test-DefenseClawStandaloneProfile" not in body[:gate]
    owned = body.index("Assert-DefenseClawStandaloneSensorHelperOwned `", gate)
    disabled = body.index("Set-DefenseClawServiceStartMode -Name $standaloneSensorHelper -StartMode 4", owned)
    # The standalone gateway depends on the sensor helper, and Stop-Service
    # without -Force refuses to stop a service with a running dependent. The
    # helper therefore stops only after the loop that stops the gateway, or
    # every rollback with a running gateway aborts before restoring anything.
    service_stops = body.index("Stop-DefenseClawService -Name $name", disabled)
    gateway_in_stop_loop = body.rindex("[string]$snapshot.gateway_service,", disabled, service_stops)
    stop = body.index("Stop-DefenseClawService -Name $standaloneSensorHelper", disabled)
    assert body.count("Stop-DefenseClawService -Name $standaloneSensorHelper") == 1
    ready = body.index("Assert-DefenseClawRestoredTransactionReadyForActivation", stop)
    restart = body.index("Start-DefenseClawService -Name $standaloneSensorHelper", ready)
    services_restart = body.index("Start-DefenseClawTransactionServices `", restart)
    boot_policy = body.index("-Name $standaloneSensorHelper `", services_restart)
    assert gate < owned < disabled < gateway_in_stop_loop < service_stops < stop
    assert stop < ready < restart < services_restart < boot_policy


def test_standalone_uninstall_removes_the_ipc_directory_before_retiring_the_tree() -> None:
    # Removal happens after the sensor helper service is gone and before the
    # install tree is retired.
    uninstall = _function_body(_text(MODULE), "Invoke-DefenseClawUninstallLifecycle")
    helper = uninstall.index("Remove-DefenseClawService -Name $Layout.SensorHelperServiceName")
    removal = uninstall.index("Remove-DefenseClawStandaloneManagedIPCDirectory -Layout $Layout", helper)
    retire = uninstall.index("Set-DefenseClawInstallTreeRetirementAcls -Layout $Layout", removal)
    assert helper < removal < retire


def test_standalone_default_uninstall_removes_the_machine_state() -> None:
    # GAP-1277 (owner decision 2026-10-01): a standalone uninstall removes the
    # machine state; -Purge adds the per-user data. The user-state flag reads
    # the caller's -Purge first, and the Secure Client profile is unchanged.
    entry = _function_body(_text(MODULE), "Invoke-DefenseClawEnterpriseLifecycle")
    user_state = entry.index("$script:DefenseClawUninstallPurgeUserState = (")
    machine = entry.index(
        "if ($Action -eq 'Uninstall' -and (Test-DefenseClawStandaloneProfile)) {\n        $Purge = [switch]$true\n    }"
    )
    first_use = min(entry.index(":$Purge"), entry.index("if ($Purge -and $Action -ne 'Uninstall')"))
    assert user_state < machine < first_use
    assert entry.count("$Purge = ") == 1


def test_standalone_setup_uninstall_docs_say_it_removes_the_machine_state() -> None:
    # GAP-2647: the standalone Setup pages describe the GAP-1277 behavior
    # above (machine state always removed; PURGE=1 adds the per-user data).
    # The Secure Client page keeps its own wording (state kept unless
    # PURGE=1) and says how the standalone profile differs.
    standalone = {
        "windows": ROOT / "docs-site" / "content" / "docs" / "enterprise" / "windows.mdx",
        "cli": ROOT / "docs-site" / "content" / "docs" / "reference" / "cli.mdx",
        "setup-design": ROOT / "docs" / "WINDOWS-ENTERPRISE-SETUP.md",
        "intune": ROOT / "docs-site" / "content" / "docs" / "enterprise" / "mdm" / "intune-windows.mdx",
    }
    for name, page in standalone.items():
        text = " ".join(_text(page).split())
        assert "PURGE=1` to also remove the config" not in text, name
        assert "`/uninstall`, also remove managed state." not in text, name
        assert "remove state on uninstall" not in text, name
    # The Secure Client page moved from setup/enterprise-deployment.mdx to
    # enterprise/install/secure-client.mdx in the 1.0 docs-site layout.
    docs = ROOT / "docs-site" / "content" / "docs"
    secure_client_page = next(
        page
        for page in (docs / "enterprise" / "secure-client.mdx", docs / "setup" / "enterprise-deployment.mdx")
        if page.exists()
    )
    secure_client = " ".join(_text(secure_client_page).split())
    assert "It keeps runtime state, logs and guardian evidence." in secure_client
    assert "the standalone Setup's `/uninstall` always removes its machine state" in secure_client


def test_standalone_uninstall_retry_binds_the_receipt_to_the_retrying_cli() -> None:
    # GAP-1684/GAP-1679: when the first self-uninstall could not rename
    # InstallRoot aside, its retry by the installed CLI runs from InstallRoot.
    # The recovery binds the prepared receipt to that caller (same CLI file)
    # before the rename, so the detached finalizer waits for it, and the
    # retry finishes the committed cleanup and machine-state purge. Secure
    # Client recovery is unchanged.
    module = _text(MODULE)
    recovery = _function_body(module, "Invoke-DefenseClawSelfUninstallRecovery")
    rebind = recovery.index("$receipt = Set-DefenseClawSelfUninstallReceiptCaller")
    guard = recovery.rindex("if ($SelfUninstallCallerPID -gt 0 -and", 0, rebind)
    assert "(Test-DefenseClawStandaloneProfile)" in recovery[guard:rebind]
    move = recovery.index(
        "Move-DefenseClawInstallRootForRetirement -Source $Layout.InstallRoot -Destination $retiredRoot"
    )
    cleanup = recovery.index("$result = Invoke-DefenseClawCommittedUninstallCleanup")
    assert rebind < move < cleanup
    assert recovery.rindex("if ($reboundCaller) {", 0, cleanup) > move
    caller = _function_body(module, "Set-DefenseClawSelfUninstallReceiptCaller")
    assert "Get-DefenseClawSelfUninstallCallerIdentity" in caller
    assert "caller_file_identity" in caller and "caller_sha256" in caller
    assert "'prepared_install_retirement'" in caller
    prelayout = _function_body(module, "Invoke-DefenseClawPreLayoutRecovery")
    assert "-SelfUninstallCallerPID $SelfUninstallCallerPID" in prelayout
    entry = _function_body(module, "Invoke-DefenseClawEnterpriseLifecycle")
    call = entry[entry.index("$preLayoutRecovery = Invoke-DefenseClawPreLayoutRecovery") :]
    call = call[: call.index("if ([bool]$preLayoutRecovery.handled)")]
    assert "-SelfUninstallCallerPID $SelfUninstallCallerPID" in call


def test_lifecycles_retire_a_stale_committed_journal_through_the_fallback() -> None:
    # GAP-1322: a journal the installed gateway cannot retire no longer
    # blocks every later upgrade, ensure and uninstall (behaviour in
    # enterprise-standalone-stale-lifecycle-journal-smoke.ps1).
    module = _text(MODULE)
    for name in ("Invoke-DefenseClawInstallLikeLifecycle", "Invoke-DefenseClawUninstallLifecycle"):
        assert "Invoke-DefenseClawCommittedManagedHooksLifecycleRetire" in _function_body(module, name)


def test_lifecycles_classify_runtime_bundles_before_the_transaction() -> None:
    # GAP-0822 (refix round 1): with no committed journal, an upgrade or
    # repair classifies the per-user runtime bundles with the replacement
    # gateway before New-DefenseClawTransaction; only a classification refusal
    # stops it (behaviour in
    # enterprise-standalone-pretransaction-bundle-classification-smoke.ps1).
    body = _function_body(_text(MODULE), "Invoke-DefenseClawInstallLikeLifecycle")
    check = body.index("Assert-DefenseClawStagedRuntimeBundleClassification")
    assert check < body.index("New-DefenseClawTransaction")


def test_standalone_purge_keeps_the_launching_cli_powershell_temp() -> None:
    """GAP-1853: install-enterprise.ps1 moves TEMP into its bootstrap folder,
    so the stale-temp sweep learns the launching CLI's protected folder from
    -LauncherTemp, which only the standalone profile passes."""

    installer = _text(INSTALLER)
    standalone = installer[installer.index("if ($EnterpriseProfile -ceq 'Standalone') {") :]
    standalone = standalone[: standalone.index("Invoke-DefenseClawEnterpriseLifecycle @arguments")]
    assert "$arguments['LauncherTemp'] = [string]$bootstrapEnvironment.OriginalEnvironment['TEMP']" in standalone
    module = _text(MODULE)
    assert "$script:DefenseClawLauncherTemp = [string]$LauncherTemp" in _function_body(
        module, "Invoke-DefenseClawEnterpriseLifecycle"
    )
    assert "$script:DefenseClawLauncherTemp" in _function_body(
        module, "Remove-DefenseClawStaleRunDirectories"
    )


def test_compliant_ensure_verify_collects_old_runtime_generations() -> None:
    """GAP-0211: a compliant ensure runs no retire, so its Verify collects the
    old runtime copies a retire left in a per-user folder it could not trust
    and names each folder still untrusted. The CLI asks through the strict
    environment (not a parameter of the Secure Client command line), only a
    standalone Verify accepts it, the collect runs under the lifecycle lock
    between transactions, and a failure is reported in the result instead of
    failing the Verify."""

    installer = _text(INSTALLER)
    standalone = installer[installer.index("if ($EnterpriseProfile -ceq 'Standalone') {") :]
    standalone = standalone[: standalone.index("Invoke-DefenseClawEnterpriseLifecycle @arguments")]
    variable = "DEFENSECLAW_STANDALONE_COLLECT_RUNTIME_GENERATIONS"
    assert f"[Environment]::SetEnvironmentVariable('{variable}', $null, 'Process')" in standalone
    assert "if ($Action -eq 'Verify' -and $collectRequest -ceq '1') {" in standalone
    assert "$arguments['CollectRuntimeGenerations'] = $true" in standalone

    module = _text(MODULE)
    lifecycle = _function_body(module, "Invoke-DefenseClawEnterpriseLifecycle")
    assert "throw '-CollectRuntimeGenerations is valid only with a standalone Verify'" in lifecycle
    verify = lifecycle[lifecycle.index("if ($Action -eq 'Verify') {") :]
    verify = verify[: verify.index("return Get-DefenseClawLifecycleStatus")]
    assert "Invoke-DefenseClawStandaloneRuntimeGenerationCollect" in verify

    collect = _function_body(module, "Invoke-DefenseClawStandaloneRuntimeGenerationCollect")
    assert "Test-DefenseClawStandaloneProfile" in collect and "Test-DefenseClawAdministrator" in collect
    assert collect.index("Enter-DefenseClawLifecycleLock") < collect.index("-Action collect")
    assert "$Layout.PendingPath" in collect and "Exit-DefenseClawLifecycleLock" in collect
    assert "$script:DefenseClawRuntimeGenerationCollectError = ConvertTo-DefenseClawBoundedDiagnostic" in collect

    snapshot = _function_body(module, "Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand")
    assert "'collect'," in snapshot and "'collect' { 'collected' }" in snapshot
    assert "$report.PSObject.Properties['collected']" in snapshot

    status = _function_body(module, "Get-DefenseClawLifecycleStatus")
    assert "$status['lifecycle_retire_skipped']" in status
    assert "$status['lifecycle_generations_collected']" in status
    assert "$status['lifecycle_collect_error']" in status

    go = (ROOT / "internal" / "cli" / "windows_enterprise_standalone.go").read_text(encoding="utf-8")
    assert f'windowsEnterpriseCollectGenerationsVariable = "{variable}"' in go
    lifecycle_go = (ROOT / "internal" / "cli" / "windows_managed_hooks_lifecycle.go").read_text(encoding="utf-8")
    assert (
        '"capture", "classify-activation", "collect", "prune-orphaned-selectors",\n'
        '\t\t"restore", "retire", "retire-committed",'
    ) in lifecycle_go


def test_standalone_first_enumeration_has_a_longer_named_budget() -> None:
    """GAP-0561: the first run of a new gateway on a cold device took more
    than the default 300 seconds and the install failed with only "native
    process timed out". The standalone profile allows 900 seconds for the
    synchronous enumeration and names the step and the remedy; the Secure
    Client profile keeps 300."""

    module = _text(MODULE)
    assert "$script:StandaloneEnumeratorRefreshTimeoutSeconds = 900" in module
    body = _function_body(module, "Invoke-DefenseClawEnumeratorRefresh")
    assert "$timeoutSeconds = 300" in body
    assert "-TimeoutSeconds $timeoutSeconds" in body
    assert "run the install again" in body
    gateway = _function_body(module, "Invoke-DefenseClawGatewayCommand")
    assert "-TimeoutSeconds $TimeoutSeconds" in gateway


def test_standalone_purge_refuses_open_data_files_before_teardown() -> None:
    """GAP-0136: a read-only reader of runtime\\audit.db made the purge fail
    after it had removed the binaries and the hook wiring. The purge checks
    the files it deletes before the uninstall transaction starts, and the
    deletion after the services stopped retries a file in use before it
    refuses with uninstall_in_use (behaviour in
    enterprise-standalone-state-files-in-use-smoke.ps1)."""

    module = _text(MODULE)
    body = _function_body(module, "Invoke-DefenseClawUninstallLifecycle")
    tree = body.index("Assert-DefenseClawStandaloneInstallTreeNotInUse")
    data = body.index("Assert-DefenseClawStandaloneStateFilesNotInUse")
    assert tree < data < body.index("$snapshot = New-DefenseClawTransaction")
    assert "if ($Purge) {" in body[tree:data]
    purge = _function_body(module, "Complete-DefenseClawStatePurge")
    assert "Remove-DefenseClawPurgedStateRoot -Layout $Layout" in purge
    assert "Remove-DefenseClawManagedTree" not in purge
    assert "$script:StateRootRemovalRetryMilliseconds = 15000" in module
    native = _function_body(module, "Initialize-DefenseClawNativeSecurity")
    for name in ("RmStartSession", "RmRegisterResources", "RmGetList", "RmEndSession"):
        assert 'DllImport("rstrtmgr.dll"' in native and name in native


def test_restart_manager_is_never_asked_about_a_file_the_account_cannot_open() -> None:
    """GAP-0878: Restart Manager opens each file as the calling account, and
    one SYSTEM-only DefenseClaw file (hook-guardian\\opencode-service-ports.json)
    failed the holder list of the whole batch with access denied, so an
    Administrator purge and Setup /uninstall were refused 1603 uninstall_in_use
    with nothing held. The one native query (every in-use check goes through it)
    sets such a file aside, asks the purge's own question (an open for DELETE)
    and reports a sharing violation as a holder with no process id; the three
    consumers keep that holder past their process and service exclusions
    (behaviour in enterprise-standalone-state-files-in-use-smoke.ps1)."""

    module = _text(MODULE)
    native = _function_body(module, "Initialize-DefenseClawNativeSecurity")
    gate = native.index("GetFileHolders(string[] paths)")
    first = native.index("GetPlainOpenError(path, FILE_READ_ATTRIBUTES)", gate)
    delete = native.index("GetDirectoryOpenError(path, DELETE)", first)
    query = native.index("QueryRestartManager(queryable.ToArray())", delete)
    assert gate < first < delete < query
    assert "RmRegisterResources" not in native[gate:query]
    # The probe's answer is classified in one place: gone (2, 3) and deletable
    # (0) are no holder, a sharing violation (32) is one, anything else throws
    # and so fails closed (behaviour in the smoke's classification rows).
    classify = native.index("public static bool DeleteProbeFindsHolder(int answer, string path, string privilegeNote)")
    classified = native[classify : native.index("private static FileHolder[] QueryRestartManager", classify)]
    assert "answer == ERROR_FILE_NOT_FOUND" in classified and "answer == ERROR_PATH_NOT_FOUND" in classified
    assert "throw new Win32Exception(" in classified and "this account cannot delete" in classified
    # The probe's open now runs inside the call-scoped privilege block (GAP-0890).
    assert "answer = GetDirectoryOpenError(path, DELETE);" in native[first:query]
    assert "DeleteProbeFindsHolder(answer, path, missing)" in native[delete:query]
    # An unnamed holder is told how to be found, and the hook probe never
    # prints it as process id 0.
    assert "Associated Handles" in module and "$script:UnnamedFileHolderHint" in _function_body(
        module, "Get-DefenseClawStateFileHolderText"
    )
    assert "[int]$_.Id -le 0" in _function_body(module, "Assert-DefenseClawHookNotHeld")
    for name in (
        "Get-DefenseClawStateFileHolders",
        "Get-DefenseClawStateFileHolderText",
        "Get-DefenseClawInstallRootHolders",
    ):
        body = _function_body(module, name)
        assert "UnnamedFileHolder" in body or "FileHolderKey" in body, name
    # Process id 0 is what a stopped service reports, so the exclusions must
    # not be what drops the unnamed holder.
    holders = _function_body(module, "Get-DefenseClawStateFileHolders")
    assert holders.index("Test-DefenseClawUnnamedFileHolder") < holders.index("$Excluded.Contains")
    install = _function_body(module, "Get-DefenseClawInstallRootHolders")
    assert install.count("foreach ($id in @($ExcludedProcessIds))") == 0


def test_the_unreadable_file_probe_and_the_state_deletion_enable_privileges_for_one_call_only() -> None:
    """GAP-0890: an elevated Administrator and a CI runner hold backup and
    restore disabled, so the backup-semantics DELETE probe and the plain
    deletion of a SYSTEM-only file were denied. Both now run under the
    existing thread-bound privilege scope (a duplicate of the token that the
    using block drops, the process token never changed), take-ownership is not
    enabled for the probe, and the standalone-only deletion fallback acts only
    after access denied, on the exact StateRoot or InstallRoot, and logs each
    deleted path (behaviour in enterprise-standalone-state-files-in-use-smoke.ps1
    and the native cells)."""

    module = _text(MODULE)
    native = _function_body(module, "Initialize-DefenseClawNativeSecurity")
    probe = native.index("DeleteProbeFindsHolder(answer, path, missing)")
    scope = native.rindex("using (UninstallFilePrivilegeScope scope = new UninstallFilePrivilegeScope(true, true))", 0, probe)
    assert "GetDirectoryOpenError(path, DELETE)" in native[scope:probe]
    assert "MissingPrivilegeSuffix(scope)" in native[scope:probe]
    # No process-wide enable: the scope works on SetThreadToken with a duplicate.
    scope_class = native[native.index("class UninstallFilePrivilegeScope") : native.index("[DllImport", native.index("class UninstallFilePrivilegeScope"))]
    assert "SetThreadToken(IntPtr.Zero, privilegedToken)" in scope_class and "privilegedToken" in scope_class
    assert "if (!skipTakeOwnership)" in scope_class
    # A failed revert of the thread token stops the process with a named reason
    # (review S1); the privileged branch of the native query is standalone only
    # (review S4); the deletion fallback enables backup and restore only (S3).
    assert "FailClosedAfterRevertFailure(restoreError)" in scope_class
    assert "Environment.FailFast(message)" in native and "privilege_revert_failed" in native
    gate_off = native.index("if (!StandaloneHolderProbe)")
    assert native.index("return QueryRestartManager(paths);", gate_off) < native.index("GetPlainOpenError(path, FILE_READ_ATTRIBUTES)", gate_off)
    init = _function_body(module, "Initialize-DefenseClawNativeSecurity")
    assert init.count("StandaloneHolderProbe = [bool](Test-DefenseClawStandaloneProfile)") == 2
    assert "public static string[] DeleteTreePrivileged(string root, List<string> deleted)" in native
    assert "DeleteTreePrivilegedCore(root, deleted, true)" in native and "DeleteTreePrivilegedCore(root, null, false)" in native
    assert "new UninstallFilePrivilegeScope(true, backupRestoreOnly)" in native
    # The two-argument probe classifier is gone (nothing in production called it).
    assert "DeleteProbeFindsHolder(int answer, string path)" not in native
    deleter = _function_body(module, "Remove-DefenseClawStateTreePrivileged")
    for guard in (
        "Test-DefenseClawStandaloneProfile",
        "$Label -cne 'StateRoot' -and $Label -cne 'InstallRoot'",
        "Test-DefenseClawAccessDeniedError",
        "[StringComparison]::OrdinalIgnoreCase",
        "defenseclaw_repair",
        "Write-DefenseClawLifecycleLogDiagnostic",
        "DeleteTreePrivileged($Target, $deleted)",
    ):
        assert guard in deleter, guard
    assert deleter.index("Test-DefenseClawStandaloneProfile") < deleter.index("Initialize-DefenseClawNativeSecurity")
    tree = _function_body(module, "Remove-DefenseClawManagedTree")
    assert tree.index("Assert-DefenseClawManagedTreeNoReparse") < tree.index("Remove-DefenseClawStateTreePrivileged")
    assert tree.index("Remove-Item") < tree.index("Remove-DefenseClawStateTreePrivileged")
    # The rollback retry root is checked again right before the privileged pass (S6).
    before_fallback = tree[: tree.index("Remove-DefenseClawStateTreePrivileged -Root")]
    assert before_fallback.rindex("Test-DefenseClawManagedTreeRetryRoot") > before_fallback.index("$lastError")
    # The path passed to the native call is the checked root (S3).
    assert "$targetPlain" in deleter and deleter.index("$targetPlain") < deleter.index("DeleteTreePrivileged($Target, $deleted)")


def test_the_purge_walks_of_state_root_retry_with_call_scoped_privileges_for_a_default_token() -> None:
    """GAP-0890 r2: an Administrator whose backup and restore privileges are
    present but disabled cannot list a folder only SYSTEM may open, so the purge
    failed at its first walk of StateRoot (the junction scan) with a generic
    lifecycle_error, long before the delete that the earlier fallback guards.
    The three walks of the purge path (junction scan and removal, the reparse
    veto and the name scan of the managed-tree delete) now run through one
    wrapper that retries a walk once, only after access denied, only for the
    standalone profile and only on the exact StateRoot or InstallRoot, with
    backup and restore enabled on a thread-bound duplicate of the token for that
    walk alone; a token without them is refused with privileges_required, the
    reason and the way out (behaviour in
    enterprise-standalone-state-files-in-use-smoke.ps1 and the native cells)."""

    module = _text(MODULE)
    native = _function_body(module, "Initialize-DefenseClawNativeSecurity")
    scope = native[native.index("public sealed class TreeWalkScope") : native.index("public static TreeWalkScope EnterTreeWalkPrivileges()")]
    assert "new UninstallFilePrivilegeScope(true, true)" in scope and "Dispose()" in scope
    wrapper = _function_body(module, "Invoke-DefenseClawStateRootWalk")
    first = wrapper.index("& $Walk")
    for guard in (
        "Test-DefenseClawStandaloneProfile",
        "$WalkLabel -cne 'StateRoot' -and $WalkLabel -cne 'InstallRoot'",
        "Test-DefenseClawAccessDeniedError",
        "[StringComparison]::OrdinalIgnoreCase",
        "EnterTreeWalkPrivileges()",
        "privileges_required: ",
        "Run the same uninstall as SYSTEM",
        "$walkScope.Dispose()",
        "Write-DefenseClawLifecycleLogDiagnostic",
    ):
        assert guard in wrapper, guard
    # The first attempt is plain; the privileged one comes after the guards, and
    # the scope is released in a finally block.
    assert first < wrapper.index("EnterTreeWalkPrivileges()") and wrapper.index("finally") > wrapper.index("EnterTreeWalkPrivileges()")
    links = _function_body(module, "Remove-DefenseClawUninstallStateTreeLinks")
    assert "Invoke-DefenseClawStateRootWalk -WalkRoot $stateRoot -WalkLabel StateRoot -NothingChanged" in links
    purge = _function_body(module, "Complete-DefenseClawStatePurge")
    assert "$stateCleanup = Invoke-DefenseClawNamespaceRootCleanup" in purge and "entries_removed" in purge
    assert purge.index("entries_removed") < purge.index("Write-DefenseClawLifecycleLogDiagnostic")
    tree = _function_body(module, "Remove-DefenseClawManagedTree")
    assert tree.count("Invoke-DefenseClawStateRootWalk -WalkRoot $safe -WalkLabel $Label") == 2
    assert tree.index("Invoke-DefenseClawStateRootWalk") < tree.index("Remove-Item")


# The standalone PowerShell smokes run inside disposable scratch directories
# and never touch a service or a real machine root, so Windows CI runs every
# one of them on each installed engine (Windows PowerShell 5.1 and 7).
STANDALONE_SMOKES = (
    "enterprise-profile-lifecycle-lock-smoke.ps1",
    "enterprise-profile-deployment-record-smoke.ps1",
    "enterprise-standalone-claude-policy-binding-smoke.ps1",
    "enterprise-standalone-codex-vendor-folder-smoke.ps1",
    "enterprise-standalone-config-acl-repair-smoke.ps1",
    "enterprise-standalone-held-file-restamp-smoke.ps1",
    "enterprise-standalone-cowork-delivery-smoke.ps1",
    "enterprise-standalone-enumerator-environment-smoke.ps1",
    "enterprise-standalone-forced-uninstall-residue-smoke.ps1",
    "enterprise-standalone-guardian-first-reconcile-wait-smoke.ps1",
    "enterprise-standalone-guardian-readiness-older-gateway-smoke.ps1",
    "enterprise-standalone-guardian-state-identity-smoke.ps1",
    "enterprise-standalone-hook-keep-smoke.ps1",
    "enterprise-standalone-hook-swap-launch-smoke.ps1",
    "enterprise-standalone-install-tree-smoke.ps1",
    "enterprise-standalone-machine-leftovers-purge-smoke.ps1",
    "enterprise-standalone-manifest-adoption-smoke.ps1",
    "enterprise-standalone-mdm-rotation-journal-smoke.ps1",
    "enterprise-standalone-native-otlp-rollback-smoke.ps1",
    "enterprise-standalone-pretransaction-bundle-classification-smoke.ps1",
    "enterprise-standalone-recorded-trust-smoke.ps1",
    "enterprise-standalone-recovery-activation-deferral-smoke.ps1",
    "enterprise-standalone-recovery-gateway-smoke.ps1",
    "enterprise-standalone-rollback-sensor-helper-smoke.ps1",
    "enterprise-standalone-root-squat-smoke.ps1",
    "enterprise-standalone-runtime-env-acl-smoke.ps1",
    "enterprise-standalone-w2b-lifecycle-smoke.ps1",
    "enterprise-standalone-secrets-acl-smoke.ps1",
    "enterprise-standalone-service-logged-error-smoke.ps1",
    "enterprise-standalone-stale-lifecycle-journal-smoke.ps1",
    "enterprise-standalone-state-files-in-use-smoke.ps1",
    "enterprise-standalone-uninstall-hook-commit-smoke.ps1",
    "enterprise-standalone-uninstall-lifecycle-lock-smoke.ps1",
    "enterprise-standalone-purge-bundle-lock-smoke.ps1",
    "enterprise-standalone-uninstall-cleanup-trust-smoke.ps1",
    "enterprise-standalone-user-cleanup-report-smoke.ps1",
)


def _standalone_smoke_engines() -> list[str]:
    import os

    if sys.platform != "win32":
        return []
    import winreg

    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion",
        0,
        winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
    ) as current_version:
        program_files_raw, _ = winreg.QueryValueEx(current_version, "ProgramFilesDir")
    candidates = (
        system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe",
        Path(str(program_files_raw)) / "PowerShell" / "7" / "pwsh.exe",
    )
    return [str(path) for path in candidates if path.is_file()]


def test_every_standalone_smoke_is_wired() -> None:
    tests = MODULE.parent / "tests"
    present = {
        path.name
        for path in tests.glob("enterprise-*-smoke.ps1")
        if path.name.startswith(("enterprise-standalone-", "enterprise-profile-"))
    }
    assert present == set(STANDALONE_SMOKES)
    for name in STANDALONE_SMOKES:
        assert f"{name.removesuffix('.ps1')}: OK" in _text(tests / name)


def test_runtime_env_acl_smoke_is_in_native_workflow() -> None:
    name = "enterprise-standalone-runtime-env-acl-smoke.ps1"
    assert name in STANDALONE_SMOKES
    workflow = _text(ROOT / ".github" / "workflows" / "windows-native.yml")
    assert f"./packaging/windows/tests/{name}" in workflow


@pytest.mark.skipif(sys.platform != "win32", reason="requires native Windows PowerShell")
@pytest.mark.parametrize("smoke", STANDALONE_SMOKES)
@pytest.mark.parametrize(
    "engine",
    _standalone_smoke_engines() or (None,),
    ids=lambda engine: Path(engine).stem if engine else "missing",
)
def test_standalone_smokes_run_on_every_engine(engine: str | None, smoke: str) -> None:
    assert engine, "Windows CI must provide Windows PowerShell 5.1 or PowerShell 7"
    script = MODULE.parent / "tests" / smoke
    if "#Requires -Version 7" in _text(script) and Path(engine).stem.lower() != "pwsh":
        pytest.skip(f"{smoke} requires PowerShell 7")
    # Each smoke creates, and removes, its own uniquely named scratch tree
    # under the engine's temporary directory. Keep that prefix short: the IPC
    # smoke binds AF_UNIX sockets, whose paths are limited to 108 characters.
    completed = subprocess.run(
        [
            engine,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8-sig",
        errors="replace",
        timeout=600,
        check=False,
    )
    assert completed.returncode == 0, (
        f"{smoke} failed under {engine}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
    )
    marker = smoke.removesuffix(".ps1")
    if f"{marker}: SKIP" in completed.stdout:
        pytest.skip(completed.stdout.strip())
    assert f"{marker}: OK" in completed.stdout


# The standalone Claude client floor the module records equals the lowest
# Claude hook contract (the Go guardian enforces the same floor).


def _version_key(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split("."))


def _lowest_contract(connector: str) -> str:
    text = HOOK_CONTRACTS.read_text(encoding="utf-8")
    start = text.index(f'\t"{connector}": {{')
    following = re.search(r'\n\t"[a-z]+": \{', text[start + 1 :])
    block = text[start : start + 1 + following.start()] if following else text[start:]
    versions = re.findall(r'MinAgentVersion:\s+"([0-9.]+)"', block)
    assert versions, f"no {connector} hook contracts found"
    return min(versions, key=_version_key)


def _floor_function() -> str:
    text = MODULE.read_text(encoding="utf-8-sig")
    match = re.search(
        r"^function Get-DefenseClawClaudeMinimumClientVersion \{\n(.*?)^\}",
        text,
        re.MULTILINE | re.DOTALL,
    )
    assert match, "Get-DefenseClawClaudeMinimumClientVersion is missing"
    return match.group(1)


def test_standalone_claude_floor_is_the_lowest_claude_hook_contract() -> None:
    body = _floor_function()
    standalone = re.search(
        r"if \(Test-DefenseClawStandaloneProfile\) \{\s*return '([0-9.]+)'", body
    )
    assert standalone, body
    assert standalone.group(1) == _lowest_contract("claudecode")


def test_secure_client_claude_floor_is_unchanged() -> None:
    body = _floor_function()
    returns = re.findall(r"return '([0-9.]+)'", body)
    assert returns[-1] == "2.1.152"


# GAP-0046: the installed CLI's self-uninstall retires InstallRoot to a
# receipt-bound sibling and a detached finalizer deletes it. The standalone
# tree also holds lib\defenseclaw\policy_compiler.py. Cleanup deleted the
# compiler but never the two compiler directories, so the final non-recursive
# Remove-Item of the retired root prompted ("has children"), which a
# -NonInteractive engine turns into a terminating error. The receipt survived
# and every later Setup recovery (1.0.2 included) failed the same way with
# lifecycle_error 1603. The cleanup must remove every allowlisted directory
# bottom-up, only when empty, and must never delete unexpected content.
_RETIRED_TREE_CLEANUP_HARNESS = r"""
param([string]$ModulePath, [string]$Scratch, [string]$Case)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw "module parse failed: $($errors[0].Message)" }
foreach ($name in @(
    'Get-DefenseClawRetiredInstallTreeAllowlist',
    'Test-DefenseClawLayoutBrokerEnabled',
    'Assert-DefenseClawNoReparsePath',
    'Remove-DefenseClawEmptyRetiredInstallDirectory',
    'Remove-DefenseClawRetiredInstallTree'
)) {
    $definition = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
    }, $true)
    if ($null -ne $definition) {
        . ([ScriptBlock]::Create($definition.Extent.Text))
    }
}
# ACL and ownership validation is Windows-only and covered elsewhere; the
# allowlist itself stays the module's.
function Test-DefenseClawStandaloneProfile { return $true }
function Assert-DefenseClawRetiredInstallTree {
    param([hashtable]$Layout, [string]$RetiredRoot, [switch]$SkipAclValidation)
}
$retired = Join-Path $Scratch 'DefenseClaw.retired-0123456789abcdef0123456789abcdef'
$allowlist = Get-DefenseClawRetiredInstallTreeAllowlist -Layout @{} -RetiredRoot $retired
foreach ($directory in $allowlist.directories) {
    [void](New-Item -ItemType Directory -Path $directory -Force)
}
$modulePathInTree = [IO.Path]::GetFullPath((Join-Path $retired 'libexec\DefenseClawEnterprise.psm1'))
switch ($Case) {
    'full' {
        foreach ($file in $allowlist.files) {
            if ($file -like '*defenseclaw_ipc.sock') { continue }
            [IO.File]::WriteAllText($file, "payload $file")
        }
    }
    'compiler-residue' {
        # What a 1.0.2 (or older candidate) self-uninstall left on dc-ent-win:
        # only the two empty compiler directories.
        $compilerDirectories = @(
            [IO.Path]::GetFullPath((Join-Path $retired 'lib')).TrimEnd('\'),
            [IO.Path]::GetFullPath((Join-Path $retired 'lib\defenseclaw')).TrimEnd('\')
        )
        foreach ($directory in $allowlist.directories) {
            if ($directory -notin $compilerDirectories) {
                [IO.Directory]::Delete($directory)
            }
        }
    }
    'unexpected' {
        [IO.File]::WriteAllText((Join-Path $retired 'lib\defenseclaw\operator-notes.txt'), 'keep me')
    }
}
$moduleHash = ''
if ([IO.File]::Exists($modulePathInTree)) {
    $moduleHash = (Get-FileHash -LiteralPath $modulePathInTree -Algorithm SHA256).Hash.ToLowerInvariant()
}
$receipt = [pscustomobject]@{
    retired_install_root = $retired
    retired_module_sha256 = $moduleHash
}
$threw = ''
try {
    Remove-DefenseClawRetiredInstallTree -Layout @{} -Receipt $receipt
}
catch {
    $threw = $_.Exception.Message
}
[pscustomobject]@{
    threw = $threw
    retired_exists = [IO.Directory]::Exists($retired)
    unexpected_kept = [IO.File]::Exists((Join-Path $retired 'lib\defenseclaw\operator-notes.txt'))
} | ConvertTo-Json -Compress
"""


def _portable_pwsh() -> str | None:
    import os
    import shutil

    return os.environ.get("DEFENSECLAW_TEST_PWSH") or shutil.which("pwsh") or shutil.which("pwsh.exe")


def test_installed_verifier_refuses_untrusted_redaction_key_before_compliance(tmp_path: Path) -> None:
    engine = _portable_pwsh()
    if engine is None:
        pytest.skip("PowerShell 7 (pwsh) is not installed")
    harness = tmp_path / "verify-redaction-key.ps1"
    harness.write_text(
        r"""
param([string]$ModulePath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$null, [ref]$errors)
if ($errors.Count -gt 0) { throw $errors[0].Message }
$definition = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Assert-DefenseClawEnterpriseDeployment'
}, $true)
. ([ScriptBlock]::Create($definition.Extent.Text))
$script:Standalone = $true
$script:KeyChecks = 0
function Test-DefenseClawStandaloneProfile { return $script:Standalone }
function Get-DefenseClawAcceptedGatewayServiceAccounts { return @('gateway') }
function Get-DefenseClawServiceSID { return 'service sid from OS' }
function Get-DefenseClawDeploymentMetadata { return [pscustomobject]@{} }
function Test-DefenseClawMetadataInstalled { return $true }
function Assert-DefenseClawMetadataIdentity {}
# Native capture/classification has a separate Windows ACL smoke. Model its
# refusal here and require the installed-host verifier to propagate it.
function Get-DefenseClawRedactionKeySecuritySnapshot {
    $script:KeyChecks++
    throw 'untrusted_key_reader'
}
try {
    Assert-DefenseClawEnterpriseDeployment -Layout @{} -GatewayServiceName gateway -GuardianServiceName guardian
    throw 'verifier accepted the untrusted key'
}
catch {
    if ($_.Exception.Message -cne 'untrusted_key_reader') { throw }
}
$script:Standalone = $false
try {
    Assert-DefenseClawEnterpriseDeployment -Layout @{} -GatewayServiceName gateway -GuardianServiceName guardian
}
catch {
    # The empty fixture has no activation metadata. Secure Client must reach
    # its existing validation without adding the standalone key check.
    if ($_.Exception.Message -ceq 'untrusted_key_reader') { throw }
}
if ($script:KeyChecks -ne 1) { throw 'standalone-only key validation was skipped or reached Secure Client' }
""",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(harness), "-ModulePath", str(MODULE)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


@pytest.mark.parametrize("case", ["full", "compiler-residue", "unexpected"])
def test_standalone_retired_tree_cleanup_removes_empty_compiler_directories(
    tmp_path: Path, case: str
) -> None:
    import json

    engine = _portable_pwsh()
    if engine is None:
        pytest.skip("PowerShell 7 (pwsh) is not installed")
    harness = tmp_path / "retired-tree-cleanup.ps1"
    harness.write_text(_RETIRED_TREE_CLEANUP_HARNESS, encoding="utf-8")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    completed = subprocess.run(
        [
            engine,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(harness),
            "-ModulePath",
            str(MODULE),
            "-Scratch",
            str(scratch),
            "-Case",
            case,
        ],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    result = json.loads(completed.stdout.strip().splitlines()[-1])
    if case == "unexpected":
        # Content outside the allowlist is never deleted, and the refusal
        # names it instead of surfacing a NonInteractive prompt error.
        assert result["unexpected_kept"] is True, result
        assert result["retired_exists"] is True, result
        assert "not empty" in result["threw"], result
        assert "NonInteractive" not in result["threw"], result
    else:
        assert result["threw"] == "", result
        assert result["retired_exists"] is False, result


def test_signed_out_untrusted_folder_is_classified_alike() -> None:
    """#1105, GAP-0211: the 1.0.2 -> 1.0.3 upgrade with a signed-out account
    whose hooks folder had one extra permission entry returned 1603. The
    manifest adoption (PowerShell) and the lifecycle's guardian check (Go)
    excuse exactly the same failure, report it, and nothing else."""

    module = _text(MODULE)
    block = module[module.index("$script:SignedOutUntrustedFolderPattern = [regex]::new(") :]
    block = block[: block.index("[Text.RegularExpressions.RegexOptions]::CultureInvariant")]
    powershell = "".join(part.replace("''", "'") for part in re.findall(r"'((?:[^']|'')*)'", block))
    go_source = (ROOT / "internal" / "cli" / "enterprise_hooks_signed_out_folder.go").read_text(encoding="utf-8")
    go_block = go_source[go_source.index("enterpriseHookSignedOutUntrustedFolderPattern = regexp.MustCompile(") :]
    go_block = go_block[: go_block.index("\n)\n")]
    go = "".join(re.findall(r"`([^`]*)`", go_block))
    assert powershell == go
    live = (
        "enterprise hooks: protected target requires repair but its exact active Windows session is unavailable "
        "(verification: enterprise hooks: managed hook directory verification failed: enterprise hooks: "
        "managed Windows DACL on C:\\Users\\r103gb13-u1\\.defenseclaw\\hooks has 8 ACEs, expected 7)"
    )
    found = re.fullmatch(go, live)
    assert found and found.group(1) == "hook" and found.group(2) == "C:\\Users\\r103gb13-u1\\.defenseclaw\\hooks"
    assert not re.fullmatch(go, live + "; more")
    # GAP-2516: the Codex and Copilot rows of the same account fail the
    # runtime generation check on the same folder.
    generation = live.replace(
        "managed hook directory verification failed", "managed runtime generation directory is untrusted"
    )
    found = re.fullmatch(go, generation)
    assert found and found.group(1) is None and found.group(2) == "C:\\Users\\r103gb13-u1\\.defenseclaw\\hooks"
    assert "-not $found.Groups[1].Success" in _function_body(module, "Get-DefenseClawSignedOutUntrustedFolder")

    adoption = _function_body(module, "Get-DefenseClawStandaloneManifestAdoption")
    assert "Get-DefenseClawSignedOutUntrustedFolder -Row $row" in adoption
    assert "$excused = $folderRows + $waitingRows" in adoption
    for name in ("Assert-DefenseClawEnterpriseDeployment", "Sync-DefenseClawStandaloneManagedHooksActivationBinding"):
        assert "Add-DefenseClawSignedOutUntrustedFolders -Adoption $adoption" in _function_body(module, name)
    assert "$status['signed_out_untrusted_folders']" in _function_body(module, "Get-DefenseClawLifecycleStatus")

    lifecycle = (ROOT / "internal" / "cli" / "windows_managed_hooks_lifecycle.go").read_text(encoding="utf-8")
    assert "enterpriseHookSignedOutUntrustedFolder(row, target.DataDir)" in lifecycle
    standalone = (ROOT / "internal" / "cli" / "windows_enterprise_standalone.go").read_text(encoding="utf-8")
    assert 'json:"signed_out_untrusted_folders"' in standalone


def _run_lifecycle_functions(tmp_path, names, body, replacements=()) -> None:
    import shutil

    shell = shutil.which("pwsh") or shutil.which("pwsh.exe")
    if not shell:
        pytest.skip("PowerShell is unavailable")
    functions = "\n".join(_function_body(_text(MODULE), name) for name in names)
    for old, new in replacements:
        functions = functions.replace(old, new)
    script = tmp_path / "lifecycle.ps1"
    script.write_text("$ErrorActionPreference = 'Stop'\n" + functions + "\n" + body, encoding="utf-8")
    result = subprocess.run([shell, "-NoProfile", "-File", str(script)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr



_TIMEOUT_RECOVERY_HARNESS = r"""
class FakeTimeoutNative {
    static [object] GetRegularFileSecuritySnapshotNoFollowIfExists([string]$Path) {
        if ([IO.File]::Exists($Path)) { return 'file' }
        return $null
    }
    static [object] GetDirectorySecuritySnapshotNoFollowIfExists([string]$Path) {
        if ([IO.Directory]::Exists($Path)) { return 'directory' }
        return $null
    }
}
function Initialize-DefenseClawNativeSecurity { return [FakeTimeoutNative] }
# These cases are the shared record checks. The standalone committed-uninstall
# replay has its own smoke (enterprise-uninstall-postcommit-recovery-smoke.ps1).
function Test-DefenseClawStandaloneProfile { return $false }
$script:DefenseClawUnfinishedTransactionDirectory = 'unfinished transaction directory'
$root = '__ROOT__'
$layout = @{
    PendingPath = [IO.Path]::Combine($root, 'install', 'pending.json')
    ManagedHooksLifecycleJournalPath = [IO.Path]::Combine($root, 'install', 'managed-hooks-lifecycle-journal.json')
    ManagedHooksTeardownJournalPath = [IO.Path]::Combine($root, 'install', 'managed-hooks-teardown-journal.json')
    PurgeIntentPath = [IO.Path]::Combine($root, 'lock', 'purge-scope.json')
    SelfUninstallReceiptPath = [IO.Path]::Combine($root, 'lock', 'self-uninstall.json')
    InstallRollbackIntentPath = [IO.Path]::Combine($root, 'lock', 'install-rollback-scope.json')
    ManagedHookContractCleanupReceiptPath = [IO.Path]::Combine($root, 'lock', 'managed-hook-contract-cleanup-scope.json')
    TransactionsDirectory = [IO.Path]::Combine($root, 'install', 'transactions')
}
function Recover-DefenseClawPendingTransaction {
    param($Layout, $GatewayServiceName, $GuardianServiceName, [switch]$AllowDeferredActivation)
    if ($AllowDeferredActivation) { throw 'timeout recovery must reactivate the restored release' }
    $global:Replays++
    if ($global:ReplayClears) { [IO.File]::Delete($Layout.PendingPath) }
}
function Get-DefenseClawLifecycleStatus {
    param($Action, $Layout, $GatewayServiceName, $GuardianServiceName)
    [pscustomobject]@{ action = $Action.ToLowerInvariant(); ok = $true; transaction_pending = [IO.File]::Exists($Layout.PendingPath) }
}
function Invoke-DefenseClawExactScopeRecoveryPurge { return 'purged' }
function Invoke-Case([string]$Name, [string[]]$Records, [bool]$Transaction, [bool]$ReplayClears) {
    if ([IO.Directory]::Exists($root)) { [IO.Directory]::Delete($root, $true) }
    foreach ($folder in 'install', 'lock') { [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($root, $folder)) }
    foreach ($record in $Records) { [IO.File]::WriteAllText($layout[$record], '{}') }
    if ($Transaction) { [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($layout.TransactionsDirectory, 'txn-1')) }
    $global:Replays = 0
    $global:ReplayClears = $ReplayClears
    $outcome = 'settled'
    try {
        $status = Invoke-DefenseClawTimeoutRecovery -Layout $layout -GatewayServiceName gateway -GuardianServiceName guardian
        if ($status.action -cne 'recover' -or [bool]$status.transaction_pending) { $outcome = 'wrong status' }
    }
    catch { $outcome = $_.Exception.Message }
    $purge = 'purged'
    try {
        [void](Invoke-DefenseClawUntrustedMetadataRecoveryPurge -Layout $layout -Sources @{} -GatewayServiceName gateway -GuardianServiceName guardian -Reason test)
    }
    catch { $purge = $_.Exception.Message }
    $kept = @($Records | Where-Object { [IO.File]::Exists($layout[$_]) })
    [pscustomobject]@{ name = $Name; outcome = $outcome; replays = $global:Replays; kept = $kept; purge = $purge } |
        ConvertTo-Json -Compress
}
Invoke-Case 'replayed' @('PendingPath') $false $true
Invoke-Case 'replay kept pending' @('PendingPath') $false $false
Invoke-Case 'nothing left' @() $false $false
Invoke-Case 'purge intent' @('PurgeIntentPath') $false $false
Invoke-Case 'pending and rollback intent' @('PendingPath', 'InstallRollbackIntentPath') $false $true
Invoke-Case 'journals' @('ManagedHooksTeardownJournalPath', 'SelfUninstallReceiptPath') $false $false
Invoke-Case 'transaction directory' @() $true $false
"""


def test_timeout_recovery_reports_settled_only_when_no_lifecycle_record_remains(tmp_path: Path) -> None:
    """Finding 4 of the r104 Windows re-fix review, executed: Setup's timeout
    recovery replays only pending.json, so it reports a settled deployment only
    when neither that journal nor any other lifecycle record remains, keeps
    every record it cannot replay and names it. The untrusted-metadata purge
    refuses on the same records, from the same list."""
    import json

    engine = _portable_pwsh()
    if engine is None:
        pytest.skip("PowerShell 7 (pwsh) is not installed")
    module = _text(MODULE)
    functions = "\n".join(
        _function_body(module, name)
        for name in (
            "Get-DefenseClawUnfinishedLifecycleEvidence",
            "Invoke-DefenseClawTimeoutRecovery",
            "Invoke-DefenseClawUntrustedMetadataRecoveryPurge",
        )
    )
    harness = tmp_path / "timeout-recovery.ps1"
    harness.write_text(
        "$ErrorActionPreference = 'Stop'\nSet-StrictMode -Version Latest\n"
        + functions
        + "\n"
        + _TIMEOUT_RECOVERY_HARNESS.replace("__ROOT__", str(tmp_path / "state")),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(harness)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    cases = {case["name"]: case for case in map(json.loads, completed.stdout.strip().splitlines())}

    def kept(name: str) -> list[str]:
        value = cases[name]["kept"]
        return [value] if isinstance(value, str) else list(value or [])

    assert cases["replayed"]["outcome"] == "settled" and cases["replayed"]["replays"] == 1
    assert cases["nothing left"]["outcome"] == "settled" and cases["nothing left"]["replays"] == 0
    assert "still pending" in cases["replay kept pending"]["outcome"]
    assert kept("replay kept pending") == ["PendingPath"]
    assert cases["purge intent"]["outcome"].endswith("as LocalSystem: state-purge intent")
    assert cases["purge intent"]["replays"] == 0 and kept("purge intent") == ["PurgeIntentPath"]
    rollback = cases["pending and rollback intent"]
    assert rollback["replays"] == 1 and rollback["outcome"].endswith(": install-rollback intent")
    assert kept("pending and rollback intent") == ["InstallRollbackIntentPath"]
    assert cases["journals"]["outcome"].endswith(": managed-hook teardown journal, self-uninstall receipt")
    assert cases["transaction directory"]["outcome"].endswith(": unfinished transaction directory")
    for name in ("purge intent", "pending and rollback intent", "journals", "transaction directory"):
        assert "did not settle the deployment" in cases[name]["outcome"], name
    for name in ("nothing left", "replayed"):
        assert cases[name]["purge"] == "purged", cases[name]
    assert "requires authenticated recovery of the existing state-purge intent" in cases["purge intent"]["purge"]
    assert "unfinished transaction directory; exact-scope fallback" in cases["transaction directory"]["purge"]
    assert "existing pending transaction" in cases["replay kept pending"]["purge"]


_STATUS_ARTIFACT_HARNESS = r"""
# The status collaborators are healthy; any other one is a no-op.
$ExecutionContext.InvokeCommand.CommandNotFoundAction = {
    param($name, $event)
    $event.CommandScriptBlock = {}
    $event.StopSearch = $true
}
function Get-DefenseClawServiceState { 'running' }
function Test-DefenseClawMetadataInstalled { $true }
function Test-DefenseClawStandaloneProfile { $true }
function Test-DefenseClawAdministrator { $true }
function Test-DefenseClawGatewayReady { $true }
function Test-DefenseClawGuardianReady { $true }
function Invoke-DefenseClawCodexRequirementsCommand { [pscustomobject]@{ ok = $true } }
$root = '__ROOT__'
$layout = @{ PendingPath = (Join-Path $root 'pending.json') }
$hashes = [ordered]@{}
foreach ($name in 'cli', 'gateway') {
    $path = Join-Path $root "$name.exe"
    [IO.File]::WriteAllText($path, $name)
    $layout[$(if ($name -eq 'cli') { 'CLIPath' } else { 'GatewayPath' })] = $path
    $hashes[$name] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
}
$global:Metadata = [pscustomobject]@{ hashes = [pscustomobject]$hashes }
function Get-DefenseClawDeploymentMetadata { $global:Metadata }
function Get-Case([string]$Name) {
    $status = Get-DefenseClawLifecycleStatus -Action Status -Layout $layout -GatewayServiceName gateway -GuardianServiceName guardian
    [pscustomobject]@{ name = $Name; ok = [bool]$status.ok; errors = [string[]]@($status.errors) } | ConvertTo-Json -Compress
}
Get-Case 'healthy'
[IO.File]::WriteAllText($layout.GatewayPath, 'replaced')
Get-Case 'gateway replaced'
[IO.File]::WriteAllText($layout.GatewayPath, 'gateway')
[IO.File]::Move($layout.CLIPath, "$($layout.CLIPath).quarantined")
Get-Case 'cli missing'
"""


def test_standalone_status_fails_while_a_recorded_payload_file_is_missing(tmp_path: Path) -> None:
    """GAP-0665: with bin\\defenseclaw.exe quarantined, verify failed naming
    cli while status stayed ok. Status checks every payload file the metadata
    records, as verify does."""
    import json

    engine = _portable_pwsh()
    if engine is None:
        pytest.skip("PowerShell 7 (pwsh) is not installed")
    module = _text(MODULE)
    names = ["Get-DefenseClawLifecycleStatus", "Assert-DefenseClawInstalledArtifacts"]
    functions = "\n".join(_function_body(module, name) for name in names if f"function {name} {{\n" in module)
    harness = tmp_path / "status-artifacts.ps1"
    harness.write_text(
        "$ErrorActionPreference = 'Stop'\n"
        + functions
        + "\n"
        + _STATUS_ARTIFACT_HARNESS.replace("__ROOT__", str(tmp_path)),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(harness)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    cases = {case["name"]: case for case in map(json.loads, completed.stdout.strip().splitlines())}
    assert cases["healthy"]["ok"] is True and not cases["healthy"]["errors"], cases["healthy"]
    for name, artifact in (("gateway replaced", "gateway"), ("cli missing", "cli")):
        assert cases[name]["ok"] is False, cases[name]
        assert any(error.endswith(f": {artifact}") for error in cases[name]["errors"]), cases[name]


_FAKE_RENAME_NATIVE = r"""
class FakeNative {
    static [object[]] GetFileHolders([string[]]$Paths) {
        if ($global:RmThrows) { throw 'Restart Manager session start failed' }
        return $global:RmHolders
    }
    static [int] GetDirectoryOpenError([string]$Path, [uint32]$Access) {
        if ($global:OpenThrows) { throw 'CreateFileW is unavailable' }
        $code = $global:OpenErrors[[int]$Access]
        if ($null -eq $code) { return 0 }
        return [int]$code
    }
}
$global:OpenErrors = @{}
$global:OpenThrows = $false
"""


def test_a_failed_exact_root_cleanup_names_the_programs_that_hold_its_files(tmp_path) -> None:
    # GAP-0848: the printed FORCE=1 uninstall failed on a product file another
    # program kept open, and its error named only the file. The refusal now
    # names the programs that hold files in the cleanup root (an image run
    # from it, or a Restart Manager holder), so "end or close each program
    # the error names" can be done as printed; when none is left it says the
    # holder closed the file. Any other refusal is unchanged.
    module = _text(MODULE)
    cleanup = _function_body(module, "Invoke-DefenseClawNamespaceRootCleanup")
    assert "Get-DefenseClawNamespaceRootCleanupHolderText `" in cleanup
    root = tmp_path / "DefenseClaw"
    _run_lifecycle_functions(
        tmp_path,
        [
            "ConvertTo-DefenseClawBoundedDiagnostic",
            "Format-DefenseClawProcessInUse",
            "Get-DefenseClawInstallRootHolders",
            "Test-DefenseClawUnnamedFileHolder",
            "Get-DefenseClawNamespaceRootCleanupHolderText",
        ],
        _FAKE_RENAME_NATIVE
        + r"""
function Initialize-DefenseClawNativeSecurity { return [FakeNative] }
$script:StateFileInUseCheckLimit = 16384
$root = '""" + str(root) + r"""'
[void][IO.Directory]::CreateDirectory([IO.Path]::Combine($root, 'bin'))
[IO.File]::WriteAllText([IO.Path]::Combine($root, 'bin', 'defenseclaw-hook.exe'), 'stand-in')
function Get-DefenseClawProcessImages { return $global:Images }
$held = 'enterprise hooks: pin Windows namespace purge child "defenseclaw-hook.exe" without following: ' + $root + '\bin\defenseclaw-hook.exe is held open by another program (still open after waiting 30s; close or end that program and run the same command again): A file cannot be opened because the share access flags are incompatible.'
$hook = [pscustomobject]@{ Id = 4242; Path = ($root + '\bin\defenseclaw-hook.exe'); UserName = 'CORP\alice'; Parent = 'claude' }
$elsewhere = [pscustomobject]@{ Id = 31; Path = 'C:\Windows\explorer.exe'; UserName = ''; Parent = '' }
$scanner = [pscustomobject]@{ ProcessId = 5151; AppName = 'Scanner'; ServiceName = '' }
function Invoke-Case([string]$Name, [string]$Failure, $Images, $RmHolders, [bool]$RmThrows, [string[]]$Want, [string[]]$Unwanted = @()) {
    $global:Images = @($Images)
    $global:RmHolders = [object[]]@($RmHolders)
    $global:RmThrows = $RmThrows
    $text = Get-DefenseClawNamespaceRootCleanupHolderText -Root $root -Failure $Failure
    foreach ($item in $Want) {
        if (-not $text.Contains($item)) { throw "${Name}: '$text' does not say '$item'" }
    }
    foreach ($item in $Unwanted) {
        if ($text.Contains($item)) { throw "${Name}: '$text' says '$item'" }
    }
    if ($Want.Count -eq 0 -and $text -ne '') { throw "${Name}: '$text', want nothing" }
    Write-Host "${Name}: $text"
}
Invoke-Case 'a hook process from the root' $held @($hook, $elsewhere) @() $false @("programs that hold files in $root now: ", 'defenseclaw-hook.exe (pid 4242, account CORP\alice, started by claude)') @('explorer')
Invoke-Case 'a Restart Manager holder' $held @($elsewhere) @($scanner) $false @('Scanner (pid 5151)')
Invoke-Case 'the holder has gone' $held @($elsewhere) @() $false @("no program holds a file in $root now, so the one that held it has closed it")
Invoke-Case 'Restart Manager failed' $held @() @() $true @('no program holds a file')
Invoke-Case 'another refusal' 'enterprise hooks: Windows namespace purge root identity changed' @($hook) @($scanner) $false @()
""",
    )


def test_a_committed_retirement_defers_only_to_a_holder_it_finds(tmp_path) -> None:
    # W4 review, loop round 1: access denied is what both a program holding
    # a file in InstallRoot and an access list (a deny on InstallRoot or its
    # parent) answer to the rename. Every such refusal was deferred to the
    # finalizer, so a self-uninstall reported ok with InstallRoot in place
    # and a finalizer that could never finish. Only a holder found after the
    # refusal (an image run from InstallRoot or a Restart Manager holder,
    # other than this lifecycle and the calling CLI) defers now; any other
    # refusal fails the committed uninstall, and other errors are unchanged.
    source = tmp_path / "DefenseClaw"
    _run_lifecycle_functions(
        tmp_path,
        [
            "Test-DefenseClawInstallRootInUseException",
            "Format-DefenseClawProcessInUse",
            "Get-DefenseClawInstallRootHolders",
            "Test-DefenseClawUnnamedFileHolder",
            "Get-DefenseClawInstallRootRenameDenial",
            "Invoke-DefenseClawCommittedInstallRootRetirement",
        ],
        _FAKE_RENAME_NATIVE
        + r"""
function Initialize-DefenseClawNativeSecurity { return [FakeNative] }
$script:StateFileInUseCheckLimit = 16384
$source = '""" + str(source) + r"""'
$destination = $source + '.retired'
function Get-DefenseClawProcessImages { return $global:Images }
function Move-DefenseClawInstallRootForRetirement([string]$Source, [string]$Destination) {
    switch ($global:Failure) {
        'denied' { throw [UnauthorizedAccessException]::new("Access to the path '$Source' is denied.") }
        'sharing' { throw [IO.IOException]::new('The process cannot access the file because it is being used by another process.', -2147024864) }
        'missing' { throw [IO.DirectoryNotFoundException]::new('Could not find a part of the path.') }
        default { [IO.Directory]::Move($Source, $Destination) }
    }
}
function Invoke-Case([string]$Name, [string]$Failure, $Images, $RmHolders, [bool]$RmThrows, [string]$Expect, [string]$Text,
    [hashtable]$OpenErrors = @{}, [bool]$OpenThrows = $false) {
    $global:OpenErrors = $OpenErrors
    $global:OpenThrows = $OpenThrows
    if ([IO.Directory]::Exists($destination)) { [IO.Directory]::Delete($destination, $true) }
    if ([IO.Directory]::Exists($source)) { [IO.Directory]::Delete($source, $true) }
    [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($source, 'bin'))
    [IO.File]::WriteAllText([IO.Path]::Combine($source, 'bin', 'defenseclaw-hook.exe'), 'stand-in')
    $global:Failure = $Failure
    $global:Images = @($Images)
    $global:RmHolders = [object[]]@($RmHolders)
    $global:RmThrows = $RmThrows
    $outcome = 'retired'
    $message = ''
    try {
        $message = Invoke-DefenseClawCommittedInstallRootRetirement -Source $source -Destination $destination -SelfUninstallCallerPID 777
        if (-not [string]::IsNullOrEmpty($message)) { $outcome = 'deferred' }
    }
    catch {
        $outcome = 'failed'
        $message = $_.Exception.Message
    }
    if ($outcome -ne $Expect -or ($Text -and $message -notlike "*$Text*")) {
        throw "${Name}: $outcome, '$message' (want $Expect, *$Text*)"
    }
    if ($outcome -ne 'retired' -and (-not [IO.Directory]::Exists($source) -or [IO.Directory]::Exists($destination))) {
        throw "${Name}: InstallRoot was not left in place"
    }
    Write-Host "${Name}: $outcome"
}
$hook = [pscustomobject]@{ Id = 4242; Path = ($source + '\bin\defenseclaw-hook.exe'); UserName = 'CORP\alice'; Parent = 'claude' }
$self = [pscustomobject]@{ Id = $PID; Path = ($source + '\bin\pwsh.exe'); UserName = ''; Parent = '' }
$caller = [pscustomobject]@{ Id = 777; Path = ($source + '\bin\defenseclaw.exe'); UserName = ''; Parent = '' }
$elsewhere = [pscustomobject]@{ Id = 31; Path = 'C:\Windows\explorer.exe'; UserName = ''; Parent = '' }
$scanner = [pscustomobject]@{ ProcessId = 5151; AppName = 'Scanner'; ServiceName = '' }
$callerHolder = [pscustomobject]@{ ProcessId = 777; AppName = 'defenseclaw'; ServiceName = '' }
$selfHolder = [pscustomobject]@{ ProcessId = $PID; AppName = 'pwsh'; ServiceName = '' }
Invoke-Case 'denied with no holder' 'denied' @($elsewhere) @() $false 'failed' 'no program holds a file in it'
Invoke-Case 'sharing with no holder' 'sharing' @() @() $false 'failed' 'no program holds a file in it'
Invoke-Case 'only this lifecycle and the caller' 'denied' @($self, $caller) @($callerHolder, $selfHolder) $false 'failed' 'run the uninstall again'
Invoke-Case 'Restart Manager failed' 'denied' @() @() $true 'failed' 'is denied'
Invoke-Case 'an image from InstallRoot' 'denied' @($hook, $caller) @() $false 'deferred' 'defenseclaw-hook.exe (pid 4242, account CORP\alice, started by claude)'
Invoke-Case 'a Restart Manager holder' 'sharing' @($elsewhere) @($scanner, $callerHolder) $false 'deferred' 'Scanner (pid 5151)'
Invoke-Case 'another error' 'missing' @($hook) @() $false 'failed' 'Could not find a part of the path'
Invoke-Case 'a free InstallRoot' 'none' @() @() $false 'retired' ''
# W4 review, loop round 2: a holder defers only a rename this account has
# the rights for. DELETE is 0x10000 on InstallRoot, add-subfolder 0x4 on
# its parent; 5 is access denied, 19 a read-only volume, 32 a sharing
# violation (a window on InstallRoot, which ends when it closes).
Invoke-Case 'a deny on InstallRoot with a holder' 'denied' @($hook) @() $false 'failed' 'may not rename' @{ 65536 = 5 }
Invoke-Case 'a deny in the parent with a holder' 'denied' @($hook) @($scanner) $false 'failed' 'may not create a folder in' @{ 4 = 5 }
Invoke-Case 'a deny in the parent with a sharing holder' 'sharing' @($elsewhere) @($scanner) $false 'failed' 'does not end when a program exits' @{ 4 = 5 }
Invoke-Case 'a read-only volume with a holder' 'denied' @($hook) @() $false 'failed' 'may not rename' @{ 65536 = 19 }
Invoke-Case 'the rights check fails with a holder' 'denied' @($hook) @() $false 'failed' 'could not be checked' @{} $true
Invoke-Case 'a window on InstallRoot with a holder' 'denied' @($hook) @() $false 'deferred' 'defenseclaw-hook.exe (pid 4242' @{ 65536 = 32 }
""",
    )
    module = _text(MODULE)
    uninstall = _function_body(module, "Invoke-DefenseClawUninstallLifecycle")
    call = uninstall.index("$retirementDeferred = Invoke-DefenseClawCommittedInstallRootRetirement `")
    assert "-SelfUninstallCallerPID $SelfUninstallCallerPID" in uninstall[call : call + 300]


def test_an_uninstall_refuses_a_lasting_install_root_holder_before_its_commit(tmp_path) -> None:
    # GAP-0625: a program that held bin\defenseclaw-hook.exe open past the
    # rename retry made the CLI uninstall fail after its commit, with the
    # services and hooks already removed. The standalone uninstall now looks
    # for InstallRoot holders before it changes anything, while the services
    # and hooks still enforce, and refuses only a holder seen at every look;
    # the services, hook calls with new pids and a holder that exits pass.
    source = tmp_path / "DefenseClaw"
    _run_lifecycle_functions(
        tmp_path,
        [
            "Format-DefenseClawProcessInUse",
            "Get-DefenseClawInstallRootHolders",
            "Test-DefenseClawUnnamedFileHolder",
            "Assert-DefenseClawStandaloneInstallRootNotHeld",
        ],
        _FAKE_RENAME_NATIVE
        + r"""
function Initialize-DefenseClawNativeSecurity { return [FakeNative] }
function Test-DefenseClawStandaloneProfile { return $true }
function Get-DefenseClawUninstallOwnProcessIds { return , [Collections.Generic.HashSet[int]]@([int]$PID, 777, 900) }
$script:StateFileInUseCheckLimit = 16384
$script:InstallRootRetirementRetryMilliseconds = 400
$script:InstallTreeUseRecheckMilliseconds = 20
$layout = @{ InstallRoot = '""" + str(source) + r"""' }
[void][IO.Directory]::CreateDirectory([IO.Path]::Combine($layout.InstallRoot, 'bin'))
[IO.File]::WriteAllText([IO.Path]::Combine($layout.InstallRoot, 'bin', 'defenseclaw-hook.exe'), 'stand-in')
$global:RmThrows = $false
function Get-DefenseClawProcessImages {
    $global:Look++
    $global:RmHolders = [object[]]@(& $global:Holders $global:Look | Where-Object { $_.ProcessId })
    return @(& $global:Holders $global:Look | Where-Object { $_.Path })
}
function Invoke-Case([string]$Name, [scriptblock]$Holders, [string]$Expect) {
    $global:Look = 0
    $global:Holders = $Holders
    $outcome = 'passed'
    try { Assert-DefenseClawStandaloneInstallRootNotHeld -Layout $layout -GatewayServiceName gateway -GuardianServiceName guardian -SelfUninstallCallerPID 777 }
    catch { $outcome = $_.Exception.Message }
    if ($outcome -notlike $Expect) { throw "${Name}: '$outcome' (want $Expect)" }
    Write-Host "${Name}: $outcome"
}
$hook = $layout.InstallRoot + '\bin\defenseclaw-hook.exe'
Invoke-Case 'no holder' { param($n) } 'passed'
Invoke-Case 'only the caller' { param($n) [pscustomobject]@{ ProcessId = 777; AppName = 'defenseclaw' } } 'passed'
Invoke-Case 'a service' { param($n) [pscustomobject]@{ ProcessId = 900; AppName = 'DefenseClawGateway' } } 'passed'
Invoke-Case 'hook calls' { param($n) [pscustomobject]@{ Id = 4000 + $n; Path = $hook; UserName = 'CORP\alice'; Parent = 'claude' } } 'passed'
Invoke-Case 'a holder that exits' { param($n) if ($n -lt 4) { [pscustomobject]@{ ProcessId = 5151; AppName = 'Scanner' } } } 'passed'
Invoke-Case 'a lasting holder' { param($n) [pscustomobject]@{ ProcessId = 5151; AppName = 'pwsh' } } 'uninstall_in_use: pwsh (pid 5151)*nothing was changed*'
""",
    )
    uninstall = _function_body(_text(MODULE), "Invoke-DefenseClawUninstallLifecycle")
    check = uninstall.index("Assert-DefenseClawStandaloneInstallRootNotHeld `")
    assert check < uninstall.index("$snapshot = New-DefenseClawTransaction")
    assert check < uninstall.index("Invoke-DefenseClawManagedHooksTeardownCommand")
    assert check < uninstall.index("Remove-DefenseClawService -Name")
    assert "-SelfUninstallCallerPID $SelfUninstallCallerPID" in uninstall[check : check + 300]


def test_the_deferred_retirement_stops_at_once_on_a_rename_this_account_may_not_do(tmp_path) -> None:
    # W4 review, loop round 2: the finalizer waited out its deadline on any
    # access denied, though a deny entry set after the deferral does not end
    # when the holder exits. It stops at once on a missing right; a holder
    # alone is still waited for, and a free InstallRoot is retired.
    install_root = tmp_path / "DefenseClaw"
    _run_lifecycle_functions(
        tmp_path,
        [
            "Test-DefenseClawInstallRootInUseException",
            "Get-DefenseClawInstallRootRenameDenial",
            "Complete-DefenseClawDeferredSelfUninstallRetirement",
        ],
        _FAKE_RENAME_NATIVE
        + r"""
function Initialize-DefenseClawNativeSecurity { return [FakeNative] }
function Enter-DefenseClawLifecycleLock($Layout) { return 'lock' }
function Exit-DefenseClawLifecycleLock($Lock) {}
function Test-DefenseClawSelfUninstallCallerRunning($Layout, $Receipt) { return $false }
function Assert-DefenseClawDeferredRetirementState($Layout, $Receipt) {}
function Complete-DefenseClawCommittedManagedHooksFinalization($Layout, $GatewayServiceName, $GuardianServiceName, [switch]$Purge) {}
function Assert-DefenseClawInstallRootNameReserved($InstallRoot) {}
function Complete-DefenseClawRetiredSelfUninstallCommit($Layout, $Receipt) {}
$installRoot = '""" + str(install_root) + r"""'
$retired = $installRoot + '.retired'
$layout = @{ InstallRoot = $installRoot }
$receipt = [pscustomobject]@{ phase = 'prepared_install_retirement'; retired_install_root = $retired; purge_requested = $false; gateway_service = 'g'; guardian_service = 'h' }
function Get-DefenseClawSelfUninstallReceipt($Layout, $GatewayServiceName, $GuardianServiceName) { return $receipt }
function Invoke-TestRename([string]$From, [string]$To) {
    $global:Renames++
    if ($global:Renames -le $global:Refusals) { throw [UnauthorizedAccessException]::new("Access to the path '$From' is denied.") }
    [IO.Directory]::Move($From, $To)
}
function Invoke-Case([string]$Name, [int]$Refusals, [hashtable]$OpenErrors, [int]$Seconds, [string]$Expect, [string]$Text) {
    if ([IO.Directory]::Exists($retired)) { [IO.Directory]::Delete($retired, $true) }
    [void][IO.Directory]::CreateDirectory($installRoot)
    $global:Renames = 0
    $global:Refusals = $Refusals
    $global:OpenErrors = $OpenErrors
    $clock = [Diagnostics.Stopwatch]::StartNew()
    try {
        $outcome = Complete-DefenseClawDeferredSelfUninstallRetirement -Layout $layout -Receipt $receipt `
            -Deadline ([DateTime]::UtcNow.AddSeconds($Seconds)) -RetryIntervalMilliseconds 50
        $message = ''
    }
    catch {
        $outcome = 'failed'
        $message = $_.Exception.Message
    }
    if ($outcome -ne $Expect -or ($Text -and $message -notlike "*$Text*")) {
        throw "${Name}: $outcome, '$message' (want $Expect, *$Text*)"
    }
    if ($Name -like 'a deny*' -and ($global:Renames -ne 1 -or $clock.Elapsed.TotalSeconds -ge 5)) {
        throw "${Name}: waited ($global:Renames renames, $($clock.Elapsed.TotalSeconds) s)"
    }
    Write-Host "${Name}: $outcome"
}
Invoke-Case 'a deny in the parent' 99 @{ 4 = 5 } 20 'failed' 'may not create a folder in'
Invoke-Case 'a deny on InstallRoot' 99 @{ 65536 = 5 } 20 'failed' 'may not rename'
Invoke-Case 'a holder past the deadline' 99 @{} 1 'failed' 'a program still holds a file in InstallRoot'
Invoke-Case 'a holder that lets go' 3 @{} 20 'retired' ''
""",
        replacements=[("[IO.Directory]::Move($Layout.InstallRoot, $retiredRoot)", "Invoke-TestRename $Layout.InstallRoot $retiredRoot")],
    )


def test_install_preparation_keeps_existing_service_read_access(tmp_path) -> None:
    _run_lifecycle_functions(tmp_path, ["Initialize-DefenseClawTransactionManagedRoot"], r"""
function Test-DefenseClawStandaloneProfile { return $true }
function Get-DefenseClawInstallRollbackIntent { return @{ install_root_marker_sid = '' } }
function Set-DefenseClawInstallPreparationRootIdentity {}
function Initialize-DefenseClawManagedRoot {
    param($Path, $Label, $RequiredBase, [switch]$AllowUsersRead, [switch]$PassThruCreationResult,
        $StagingMarkerSID, [switch]$DeferFinalAcl, [switch]$KeepProtectedAcl)
    if (-not $KeepProtectedAcl) { throw 'preparation removed the existing gateway read ACE' }
    return @{ created = $false }
}
Initialize-DefenseClawTransactionManagedRoot -Layout @{} -GatewayServiceName Gateway `
    -GuardianServiceName Guardian -Root install_root -Path existing -Label InstallRoot -RequiredBase base
""")



def test_standalone_replacement_retries_transient_hook_readers(tmp_path) -> None:
    # Holders come and go under registered hook traffic. Retry the atomic
    # operation while keeping the launcher present on every attempt.
    _run_lifecycle_functions(tmp_path, [
        "Install-DefenseClawFileAtomic",
        "Invoke-DefenseClawTransientFileRetry",
        "Clear-DefenseClawRestrictiveFileAttributes",
    ], r"""
function Test-DefenseClawStandaloneProfile { return $true }
function Assert-DefenseClawNoReparsePath {}
function New-DefenseClawDirectory { param($Path) [void][IO.Directory]::CreateDirectory($Path) }
function Remove-DefenseClawStaleReplacementBackups {}
function Remove-DefenseClawReplacementBackup { param($Path) [IO.File]::Delete($Path); return $true }
# A volume that refuses the one-step swap (GAP-0240) keeps File.Replace.
function Invoke-DefenseClawLaunchableFileSwap { param($Temporary, $Destination, $Backup, [switch]$KeepReplacementAccess) return $false }
function ConvertTo-DefenseClawBoundedDiagnostic { param($Value, $MaxLength) return $Value }
$script:attempts = 0
function Invoke-TestMappedImageReplace {
    $script:attempts++
    if (-not [IO.File]::Exists($Destination)) { throw 'launcher missing during replacement' }
    if ($script:attempts -lt 3) { throw [IO.IOException]::new('transient hook reader', -2147024864) }
    [IO.File]::Replace($temporary, $Destination, $backup, $true)
}
$root = Split-Path -Parent $PSCommandPath
$source = Join-Path $root 'new.exe'
$destination = Join-Path $root 'hook.exe'
[IO.File]::WriteAllText($source, 'new verified executable')
[IO.File]::WriteAllText($destination, 'old mapped executable')
Install-DefenseClawFileAtomic -Source $source -Destination $destination
if ($script:attempts -ne 3) { throw 'hook reader was not retried' }
if ([IO.File]::ReadAllText($destination) -cne 'new verified executable') { throw 'replacement failed' }
if (@(Get-ChildItem $root -Filter 'hook.exe.backup.*').Count) { throw 'replacement left a backup' }
""", replacements=[("[IO.File]::Replace($temporary, $Destination, $backup, $true)", "Invoke-TestMappedImageReplace")])


_PURGE_DELETED_ACCOUNT_HARNESS = r"""
$script:UninstallDeletedAccountWaitSeconds = 20
$script:UninstallDeletedAccountPollSeconds = 0
$script:log = [Collections.Generic.List[string]]::new()
$script:checks = [Collections.Generic.Queue[string]]::new()
$script:syncs = [Collections.Generic.Queue[string]]::new()
function Write-DefenseClawLifecyclePhase { param($Stage) $script:log.Add("phase: $Stage") }
function Get-DefenseClawEnumeratorServiceName { param($GuardianServiceName) return 'Enum' }
$script:enumeratorExists = $true
function Test-DefenseClawServiceExists { param($Name) return $script:enumeratorExists }
function Stop-DefenseClawService { param($Name) $script:log.Add("stop $Name") }
function Start-DefenseClawService { param($Name) $script:log.Add("start $Name") }
function Invoke-DefenseClawManagedHooksTeardownCommand {
    param($Layout, $GatewayServiceName, $GuardianServiceName, $Action, $TimeoutSeconds)
    $answer = if ($script:checks.Count) { $script:checks.Dequeue() } else { 'ok' }
    $script:log.Add("check $answer")
    if ($answer -cne 'ok') { throw $answer }
}
function Sync-DefenseClawStandaloneManagedHooksActivationBinding {
    param($Layout, $GatewayServiceName, $GatewaySource)
    $answer = if ($script:syncs.Count) { $script:syncs.Dequeue() } else { 'same' }
    $script:log.Add("sync $answer")
    if ($answer -ceq 'rebound') { return $true }
    if ($answer -cne 'same') { throw $answer }
    return $false
}
$deleted = 'managed-hook teardown check failed: protected Guardian state still lists an enrolled local account that no longer exists; the hook enumerator revokes its rows on its next pass: claudecode target S-1-5-21-1-2-3-1137'
function Invoke-Case([string[]]$Checks, [string[]]$Syncs) {
    $script:log.Clear(); $script:checks.Clear(); $script:syncs.Clear()
    foreach ($c in $Checks) { $script:checks.Enqueue($c) }
    foreach ($c in $Syncs) { $script:syncs.Enqueue($c) }
    try {
        $script:rebound = @(Invoke-DefenseClawUninstallPrecommitHookCheck -Layout @{} -GatewayServiceName Gateway -GuardianServiceName Guardian)[-1]
        return 'passed'
    }
    catch { return "refused: $($_.Exception.Message)" }
}
"""


def test_uninstall_after_a_deleted_enrolled_account_passes_on_the_first_call(tmp_path) -> None:
    # rel-1-0-6:GAP-0346: the enumerator pass the check starts drops the
    # deleted account's rows and publishes a new targets.yaml; until the
    # guardian adopts it and the activation evidence is rebound, the check
    # refuses the old binding. That state is asked again (and rebound), so
    # the PURGE passes without Setup /repair.
    _run_lifecycle_functions(tmp_path, [
        "Test-DefenseClawDeletedAccountTeardownRefusal",
        "Test-DefenseClawManifestCatchUpTeardownRefusal",
        "Invoke-DefenseClawUninstallPrecommitHookCheck",
    ], _PURGE_DELETED_ACCOUNT_HARNESS + r"""
$stale = 'managed-hook teardown check failed: protected managed-hook activation evidence does not match the current manifest'
$outside = 'managed-hook teardown check failed: protected Guardian state contains a target outside the deployment manifest'
$notAdopted = 'deployment managed-hook activation evidence does not bind installed targets.yaml (guardian has not activated it)'
$result = Invoke-Case @($deleted, $deleted, $outside, 'ok') @($notAdopted, 'same', 'rebound')
if ($result -cne 'passed') { throw "catch-up states were not asked again: $result / $($script:log -join ' | ')" }
if ($script:rebound -ne $true) { throw 'the check did not report that it rebound the activation evidence' }
$order = $script:log -join ' | '
if ($order -notmatch 'stop Enum \| start Enum') { throw "the enumerator was not restarted: $order" }
if ($order -notmatch 'sync rebound \| phase: hook targets changed: activation evidence rebound') { throw "the rebinding was not reported: $order" }
if (@($script:log | Where-Object { $_ -like 'sync *' }).Count -ne 4) { throw "sync did not run in every wait round: $order" }
# The stale binding after the guardian adopted the manifest: rebound, then passes.
$result = Invoke-Case @($deleted, $stale, 'ok') @('same', 'rebound')
if ($result -cne 'passed' -or $script:rebound -ne $true) { throw "a stale activation binding was not rebound: $result" }
# A first check that passes rebinds nothing.
$result = Invoke-Case @('ok') @()
if ($result -cne 'passed' -or $script:rebound -ne $false) { throw "a passing first check reported a rebinding: $result" }
# rel-1-0-6:GAP-0319: the scheduled enumerator pass ran before the check, so
# the first refusal is the stale binding: rebound and asked again, no restart.
$result = Invoke-Case @($stale, 'ok') @('rebound')
if ($result -cne 'passed' -or $script:rebound -ne $true -or ($script:log -join '|') -match 'stop Enum') { throw "a stale first binding was not rebound without a restart: $result / $($script:log -join ' | ')" }
# Still stale at the deadline: the first refusal comes back.
$script:UninstallDeletedAccountWaitSeconds = 1
$script:UninstallDeletedAccountPollSeconds = 1
$result = Invoke-Case @($outside, $outside, $outside, $outside) @()
if ($result -notlike 'refused: *outside the deployment manifest*' -or ($script:log -join '|') -match 'stop Enum') { throw "a catch-up refusal was not given back at the deadline: $result" }
$script:UninstallDeletedAccountWaitSeconds = 20
$script:UninstallDeletedAccountPollSeconds = 0
# Any other first refusal is given back at once, nothing restarted.
$result = Invoke-Case @('managed-hook teardown check failed: runtime selector is untrusted') @()
if ($result -notlike 'refused: *runtime selector is untrusted*' -or ($script:log -join '|') -match 'stop Enum|sync') { throw "an unrelated first refusal was retried: $result" }
# Another refusal during the wait is given back at once.
$result = Invoke-Case @($deleted, 'managed-hook teardown check failed: runtime selector is untrusted') @()
if ($result -notlike 'refused: *runtime selector is untrusted*') { throw "an unrelated refusal was swallowed: $result" }
# Rows still listed at the deadline: the deleted-account refusal comes back.
$script:UninstallDeletedAccountWaitSeconds = 1
$script:UninstallDeletedAccountPollSeconds = 1
$result = Invoke-Case @($deleted, $deleted, $deleted, $deleted, $deleted) @()
if ($result -notlike 'refused: *no longer exists*') { throw "the deadline did not give back the deleted-account refusal: $result" }
""")



def test_uninstall_restarts_the_enumerator_on_a_later_deleted_account(tmp_path) -> None:
    # rel-1-0-6:GAP-0450: when the first refusal is the stale binding and a
    # deleted-account refusal comes only inside the wait, the enumerator is
    # still restarted (once), instead of the wait resting on the scheduled pass.
    _run_lifecycle_functions(tmp_path, [
        "Test-DefenseClawDeletedAccountTeardownRefusal",
        "Test-DefenseClawManifestCatchUpTeardownRefusal",
        "Invoke-DefenseClawUninstallPrecommitHookCheck",
    ], _PURGE_DELETED_ACCOUNT_HARNESS + r"""
$stale = 'managed-hook teardown check failed: protected managed-hook activation evidence does not match the current manifest'
$result = Invoke-Case @($stale, $deleted, $deleted, 'ok') @()
$order = $script:log -join ' | '
if ($result -cne 'passed') { throw "a later deleted account did not pass: $result / $order" }
if ($order -notmatch "check $([regex]::Escape($deleted)) \| phase: deleted enrolled account: running a hook enumerator pass before the uninstall \| stop Enum \| start Enum") { throw "the enumerator was not restarted on the later deleted-account refusal: $order" }
if (@($script:log | Where-Object { $_ -ceq 'stop Enum' }).Count -ne 1) { throw "the enumerator was restarted more than once: $order" }
# A deleted account first: one restart, not one per deleted-account refusal.
$result = Invoke-Case @($deleted, $deleted, $deleted, 'ok') @()
if ($result -cne 'passed' -or @($script:log | Where-Object { $_ -ceq 'stop Enum' }).Count -ne 1) { throw "a first deleted account was not restarted exactly once: $result / $($script:log -join ' | ')" }
# A stale binding that clears without a deleted account: no restart.
$result = Invoke-Case @($stale, $stale, 'ok') @()
if ($result -cne 'passed' -or ($script:log -join '|') -match 'stop Enum') { throw "a stale binding alone restarted the enumerator: $result" }
# No enumerator service: the later deleted-account refusal comes back at once.
$script:enumeratorExists = $false
$result = Invoke-Case @($stale, $deleted, 'ok') @()
$script:enumeratorExists = $true
if ($result -notlike 'refused: *no longer exists*' -or ($script:log -join '|') -match 'stop Enum') { throw "a later deleted account without an enumerator was not refused at once: $result / $($script:log -join ' | ')" }
# Still listed at the deadline after the later restart: the deleted-account refusal comes back.
$script:UninstallDeletedAccountWaitSeconds = 1
$script:UninstallDeletedAccountPollSeconds = 1
$result = Invoke-Case @($stale, $deleted, $deleted, $deleted, $deleted) @()
if ($result -notlike 'refused: *no longer exists*' -or @($script:log | Where-Object { $_ -ceq 'stop Enum' }).Count -ne 1) { throw "the deadline after a later restart did not give back the deleted-account refusal: $result / $($script:log -join ' | ')" }
""")


def test_uninstall_precommit_wait_rebinds_like_the_lifecycle() -> None:
    module = _text(MODULE)
    check = _function_body(module, "Invoke-DefenseClawUninstallPrecommitHookCheck")
    assert check.index("Sync-DefenseClawStandaloneManagedHooksActivationBinding") < check.index("-TimeoutSeconds $left")
    assert "Test-DefenseClawManifestCatchUpTeardownRefusal -Message $message" in check
    # rel-1-0-6:GAP-0450: a deleted-account refusal inside the wait asks for the one restart.
    assert check.index("Stop-DefenseClawService -Name $enumerator") > check.index("while ($true) {")
    assert "$restartEnumerator = $true" in check
    assert "$script:UninstallDeletedAccountWaitSeconds = 180" in module
    # The tombstone is written from metadata read after a rebinding check.
    uninstall = _function_body(module, "Invoke-DefenseClawUninstallLifecycle")
    reread = uninstall.index("if ($precheckRebound) {")
    assert uninstall.index("$precheckRebound = [bool](Invoke-DefenseClawUninstallPrecommitHookCheck") < reread
    block = uninstall[reread: uninstall.index("\n    }\n", reread)]
    assert "$metadata = Get-DefenseClawDeploymentMetadata -Layout $Layout -Required" in block
    assert "$managedHooksActivation =" in block
    assert reread < uninstall.index("-ManagedHooksActivation $managedHooksActivation")
    catchup = _function_body(module, "Test-DefenseClawManifestCatchUpTeardownRefusal")
    for needle in (
        "protected managed-hook activation evidence does not match the current manifest",
        "contains a target outside the deployment manifest",
        "does not exactly bind the legacy deployment manifest and authorization",
        "deployment managed-hook activation evidence does not bind installed targets.yaml",
    ):
        assert needle in catchup
        assert needle in module.replace(catchup, "") or needle in _text(ROOT / "internal" / "cli" / "windows_managed_hooks_teardown.go") or needle in _text(ROOT / "internal" / "cli" / "windows_managed_hooks_lifecycle.go")


def test_standalone_replacement_swaps_the_launcher_in_one_step(tmp_path) -> None:
    # GAP-0240: File.Replace held the new hook open for writing and had a
    # moment with no file at the name; agents starting the hook then got a
    # sharing violation and ran the tool call with no decision. Standalone
    # swaps through Invoke-DefenseClawLaunchableFileSwap and never reaches
    # File.Replace when the swap succeeds (behaviour on a real image in
    # enterprise-standalone-hook-swap-launch-smoke.ps1).
    _run_lifecycle_functions(tmp_path, ["Install-DefenseClawFileAtomic"], r"""
function Test-DefenseClawStandaloneProfile { return $true }
function Assert-DefenseClawNoReparsePath {}
function Clear-DefenseClawRestrictiveFileAttributes { param($Path) return $false }
function Write-DefenseClawResilienceEvent { param([string]$Marker, [hashtable]$Fields) }
function New-DefenseClawDirectory { param($Path) [void][IO.Directory]::CreateDirectory($Path) }
function Remove-DefenseClawStaleReplacementBackups {}
function Remove-DefenseClawReplacementBackup { param($Path) [IO.File]::Delete($Path); return $true }
function ConvertTo-DefenseClawBoundedDiagnostic { param($Value, $MaxLength) return $Value }
$script:swaps = 0
function Invoke-DefenseClawLaunchableFileSwap {
    param($Temporary, $Destination, $Backup, [switch]$KeepReplacementAccess)
    $script:swaps++
    if (-not $Backup.StartsWith("$Destination.backup.")) { throw "unexpected backup name $Backup" }
    [IO.File]::Copy($Destination, $Backup)
    [IO.File]::Copy($Temporary, $Destination, $true)
    [IO.File]::Delete($Temporary)
    return $true
}
function Invoke-TestFileReplace { throw 'File.Replace ran although the one-step swap succeeded' }
$root = Split-Path -Parent $PSCommandPath
$source = Join-Path $root 'new.exe'
$destination = Join-Path $root 'hook.exe'
[IO.File]::WriteAllText($source, 'new verified executable')
[IO.File]::WriteAllText($destination, 'old running executable')
Install-DefenseClawFileAtomic -Source $source -Destination $destination
if ($script:swaps -ne 1) { throw "the one-step swap ran $($script:swaps) times" }
if ([IO.File]::ReadAllText($destination) -cne 'new verified executable') { throw 'replacement failed' }
if (@(Get-ChildItem $root -Filter 'hook.exe.backup.*').Count) { throw 'replacement left a backup' }
if (@(Get-ChildItem $root -Filter 'hook.exe.new.*').Count) { throw 'replacement left a staging copy' }
""", replacements=[("[IO.File]::Replace($temporary, $Destination, $backup, $true)", "Invoke-TestFileReplace")])


def test_launchable_swap_retries_busy_files_and_refuses_unsupported_volumes(tmp_path) -> None:
    # GAP-0240: SwapLaunchableFile answers "" or "<stage>:<win32 error>".
    # A sharing or access refusal (an antivirus scan) is retried; a volume
    # without hard links or POSIX renames falls back to File.Replace; any
    # other error, or a backup link it could not remove, is thrown.
    _run_lifecycle_functions(tmp_path, ["Invoke-DefenseClawLaunchableFileSwap"], r"""
class FakeSwapNative {
    static [System.Collections.Generic.Queue[string]] $Answers = [System.Collections.Generic.Queue[string]]::new()
    static [int] $Calls = 0
    static [string] SwapLaunchableFile([string]$Replacement, [string]$Destination, [string]$Backup) {
        [FakeSwapNative]::Calls++
        return [FakeSwapNative]::Answers.Dequeue()
    }
}
function Initialize-DefenseClawNativeSecurity { return [FakeSwapNative] }
$script:phases = [Collections.Generic.List[string]]::new()
function Write-DefenseClawLifecyclePhase { param($Stage) $script:phases.Add($Stage) }
function Invoke-Case([string[]]$Answers) {
    [FakeSwapNative]::Answers.Clear()
    foreach ($answer in $Answers) { [FakeSwapNative]::Answers.Enqueue($answer) }
    [FakeSwapNative]::Calls = 0
    return Invoke-DefenseClawLaunchableFileSwap -Temporary 'C:\b\hook.exe.new.1' -Destination 'C:\b\hook.exe' -Backup 'C:\b\hook.exe.backup.1'
}
if (-not (Invoke-Case @('rename:32', 'link:5', 'rename:33', ''))) { throw 'busy files were not retried to success' }
if ([FakeSwapNative]::Calls -ne 4) { throw "busy retry made $([FakeSwapNative]::Calls) calls" }
foreach ($refusal in @('link:1', 'link:17', 'link:50', 'link:1142', 'rename:1', 'rename:50', 'rename:87', 'dacl:null')) {
    $script:phases.Clear()
    if (Invoke-Case @($refusal)) { throw "$refusal did not fall back to File.Replace" }
    # GAP-0369: the fallback is in the lifecycle log, with the file and the refusal.
    if (@($script:phases | Where-Object { $_ -like "*C:\b\hook.exe ($refusal)*File.Replace*" }).Count -ne 1) { throw "$refusal fallback was not logged: $($script:phases -join ' | ')" }
}
if (-not (Invoke-Case @('open:32', ''))) { throw 'a busy replacement open was not retried' }
foreach ($fatal in @('dacl:1307', 'open:2', 'rename:2', 'link:183')) {
    $thrown = $null
    try { [void](Invoke-Case @($fatal)) } catch { $thrown = $_.Exception }
    if ($null -eq $thrown -or $thrown -isnot [IO.IOException]) { throw "$fatal was not thrown as an IOException" }
    if ($thrown.Message -notlike "*$fatal*") { throw "$fatal message lost the stage and code: $($thrown.Message)" }
}
# A backup link the swap could not remove is not an IOException, so the
# GAP-0852 catch does not call it a file another program holds open.
$thrown = $null
try { [void](Invoke-Case @('rename:32;backup-kept')) } catch { $thrown = $_.Exception }
if ($null -eq $thrown -or $thrown -is [IO.IOException] -or $thrown -isnot [InvalidOperationException]) { throw 'backup-kept was not thrown as its own error' }
if ($thrown.Message -notlike '*rename:32;backup-kept*C:\b\hook.exe.backup.1*') { throw "backup-kept message lost the result or the backup: $($thrown.Message)" }
""")


def test_launchable_swap_links_the_old_file_before_one_posix_rename() -> None:
    # GAP-0240: Windows refuses to remove the last name of a running image,
    # so the swap gives the old file a second name first; only standalone
    # uses it, Secure Client keeps File.Replace.
    module = _text(MODULE)
    native = _function_body(module, "Initialize-DefenseClawNativeSecurity")
    swap = native[native.index("public static string SwapLaunchableFile"):]
    swap = swap[: swap.index("\n        }\n", swap.index("return \"\";"))]
    for needle in (
        "GetSecurityInfo(current, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION",
        "SetSecurityInfo(file, SE_FILE_OBJECT, information",
        "CreateHardLinkNative(backup, destination, IntPtr.Zero)",
        "FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS",
        "const int FileRenameInfoEx = 22;",
        'return "open:" + Marshal.GetLastWin32Error()',
        "FILE_SHARE_READ | FILE_SHARE_DELETE,",
    ):
        assert needle in swap, needle
    assert swap.index("SetSecurityInfo(file") < swap.index("CreateHardLinkNative(") < swap.index(
        "SetFileInformationByHandleNative(file, FileRenameInfoEx"
    )
    # GAP-0656 review M2: a drifted destination's access list is not copied
    # onto the fresh object; the link and the rename are the same steps.
    keeping = swap[swap.index("public static string SwapLaunchableFileKeepingAccess(") :]
    assert "return SwapLaunchableFileCore(replacement, destination, backup, false);" in keeping
    core = swap[swap.index("private static string SwapLaunchableFileCore(") :]
    assert core.index("if (!copyDestinationAccess)") < core.index("return LinkBackupAndRename(own, destination, backup);") < core.index(
        "GetSecurityInfo(current, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION"
    )
    atomic = _function_body(module, "Install-DefenseClawFileAtomic")
    gate = atomic.index("if (Test-DefenseClawStandaloneProfile) {\n                    $swapped = Invoke-DefenseClawLaunchableFileSwap")
    assert gate < atomic.index("while (-not $swapped) {") < atomic.index(
        "[IO.File]::Replace($temporary, $Destination, $backup, $true)"
    )


def test_service_start_mode_refusal_names_the_modes(tmp_path) -> None:
    import shutil

    shell = shutil.which("pwsh") or shutil.which("pwsh.exe")
    if not shell:
        pytest.skip("PowerShell is unavailable")
    module = _text(MODULE)
    body = _function_body(module, "Assert-DefenseClawServiceConfiguration")
    # Stub registry reads only; run the real configuration checker.
    body = body.replace("Microsoft.PowerShell.Management\\Get-ItemProperty", "Get-TestServiceProperties")
    helpers = "\n".join(
        _function_body(module, name)
        for name in ("ConvertTo-DefenseClawServiceStartModeName", "Test-DefenseClawTrustStrictAncestors")
    )
    script = tmp_path / "service-modes.ps1"
    script.write_text(helpers + "\n" + body + r"""
$ErrorActionPreference = 'Stop'
$script:ServiceDescription = 'test service'
$script:TrustStrictAncestorsEnv = 'DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS'
function Test-DefenseClawServiceExists { return $true }
function Test-DefenseClawStandaloneProfile { return $true }
function Get-TestServiceProperties {
    return [pscustomobject]@{ ImagePath='image'; ObjectName='account'; DisplayName='test';
        Description='test service'; Type=16; Start=4 }
}
try {
    Assert-DefenseClawServiceConfiguration -Name test -ExpectedImage image -ExpectedAccount account `
        -ExpectedDisplayName test -ExpectedSidType 1 -ExpectedPrivileges @('priv') -ExpectedEnvironment @()
    throw 'disabled service passed verification'
} catch {
    if ($_.Exception.Message -notmatch 'startup mode drift: disabled, expected auto') { throw }
}
""", encoding="utf-8")
    result = subprocess.run([shell, "-NoProfile", "-File", str(script)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr


def test_a_snapshot_directory_left_after_the_commit_never_rolls_the_deployment_back(tmp_path) -> None:
    # fix/r104-windows: Complete-DefenseClawTransaction removed pending.json
    # (the commit) and then the snapshot directory; a removal that failed
    # part-way (a scanner holding one copy) threw into the lifecycle's catch,
    # which restored the proven deployment from the half-deleted snapshot
    # with no pending record left to recover it. Now the commit stands and
    # the directory left behind is named in a warning.
    state = tmp_path / "state"
    _run_lifecycle_functions(
        tmp_path,
        ["Complete-DefenseClawTransaction"],
        r"""
$state = '""" + str(state) + r"""'
$transaction = Join-Path (Join-Path $state 'transactions') 'abc'
[void][IO.Directory]::CreateDirectory($transaction)
$snapshot = Join-Path $transaction 'transaction.json'
[IO.File]::WriteAllText($snapshot, '{"gateway_service":"g","guardian_service":"h"}')
[IO.File]::WriteAllText((Join-Path $transaction 'copy.bin'), 'held')
$pending = Join-Path $state 'pending.json'
$Layout = @{ PendingPath = $pending; StateRoot = $state }
function Assert-DefenseClawNoReparsePath([string]$Path) {}
function Assert-DefenseClawDescendant { param($Path, $Root, $Label) return $Path }
function Set-DefenseClawInstallRollbackIntentCommitted { return $null }
function Publish-DefenseClawInstallRollbackIntent { return $null }
function Remove-Item {
    param([string]$LiteralPath, [switch]$Recurse, [switch]$Force, $ErrorAction)
    if ($Recurse) { throw 'The process cannot access the file copy.bin because it is being used by another process.' }
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $LiteralPath -Force
}
foreach ($rollback in @($false, $true)) {
    [IO.File]::WriteAllText($pending, '{}')
    $warnings = @()
    Complete-DefenseClawTransaction -SnapshotPath $snapshot -Layout $Layout -Rollback:$rollback -WarningVariable warnings -WarningAction SilentlyContinue
    if (Test-Path -LiteralPath $pending) { throw "rollback=${rollback}: the commit did not remove pending.json" }
    if (-not (Test-Path -LiteralPath $transaction)) { throw "rollback=${rollback}: the stub did not hold the directory" }
    if (-not ($warnings -join ' ').Contains($transaction)) { throw "rollback=${rollback}: the warning does not name the directory: $warnings" }
}
""",
        replacements=[
            ("Microsoft.PowerShell.Management\\Remove-Item -LiteralPath $directory", "Remove-Item -LiteralPath $directory"),
        ],
    )


def test_an_admin_file_json_write_is_stamped_before_it_is_published(tmp_path: Path) -> None:
    """GAP-0899: a lifecycle write of deployment.json (and the other install
    records the hook guardian enforces) published the file first and stamped
    it after. In that gap it carried the owner of the creating account (SYSTEM)
    and the access list of its folder, a guardian pass inside it repaired the
    file, and the next ensure warned guardian_repaired_drift and was not a
    no-op. With -Kind AdminFile the staging file is stamped, then replaces
    the destination, so the published file is never unprotected. A write
    without -Kind keeps the plain publish."""
    import json

    engine = _portable_pwsh()
    if engine is None:
        pytest.skip("PowerShell 7 (pwsh) is not installed")
    module = _text(MODULE)
    functions = "\n".join(
        _function_body(module, name)
        for name in (
            "Write-DefenseClawJsonAtomic",
            "Clear-DefenseClawRestrictiveFileAttributes",
        )
    )
    harness = tmp_path / "admin-file-publish.ps1"
    harness.write_text(
        "$ErrorActionPreference = 'Stop'\nSet-StrictMode -Version Latest\n"
        + functions
        + r"""
$script:AdministratorsSID = 'S-1-5-32-544'
$root = '__ROOT__'
$destination = Join-Path $root 'deployment.json'
$global:Events = [System.Collections.Generic.List[string]]::new()
function New-DefenseClawDirectory { param([string]$Path) }
function Assert-DefenseClawNoReparsePath { param([string]$Path) }
function Set-DefenseClawPathAcl {
    param([string]$Path, [string]$Kind, [string]$GatewayServiceSID)
    $held = ([IO.File]::ReadAllText($destination) | ConvertFrom-Json).generation
    $global:Events.Add("stamp kind=$Kind sid=$GatewayServiceSID staging=$($Path -ne $destination) destination=$held")
}
function Move-DefenseClawNonImageFileReplacing {
    param([string]$Source, [string]$Destination)
    $global:Events.Add('publish')
    [IO.File]::Move($Source, $Destination, $true)
}
[IO.File]::WriteAllText($destination, '{"generation": "old"}')
Write-DefenseClawJsonAtomic -Value ([ordered]@{ generation = 'new' }) -Path $destination -Kind AdminFile
Write-DefenseClawJsonAtomic -Value ([ordered]@{ generation = 'plain' }) -Path $destination
[pscustomobject]@{
    events = @($global:Events)
    content = ([IO.File]::ReadAllText($destination) | ConvertFrom-Json).generation
    leftovers = @(Get-ChildItem -LiteralPath $root -Filter 'deployment.json.new.*' -Force).Count
} | ConvertTo-Json -Compress
""".replace("__ROOT__", str(tmp_path)),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(harness)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    result = json.loads(completed.stdout.strip().splitlines()[-1])
    assert result["events"] == [
        "stamp kind=AdminFile sid=S-1-5-32-544 staging=True destination=old",
        "publish",
        "publish",
    ], result
    assert result["content"] == "plain" and result["leftovers"] == 0, result


def test_repair_rebuilds_deployment_metadata_that_is_not_json(tmp_path: Path) -> None:
    """GAP-0629: deployment.json overwritten with text. Reading it refused
    nothing: it ran takeown + icacls /reset, which left the file's DACL
    inherited, and reported no deployment, after which every status, ensure
    and repair refused the DACL. The read now refuses the file as unreadable,
    with its DACL as found or drifted, and Repair from Setup rebuilds it with
    the canonical DACL. A drifted file that parses is still refused."""
    import json

    engine = _portable_pwsh()
    if engine is None:
        pytest.skip("PowerShell 7 (pwsh) is not installed")
    module = _text(MODULE)
    functions = "\n".join(
        _function_body(module, name)
        for name in (
            "ConvertFrom-DefenseClawDeploymentMetadataText",
            "Test-DefenseClawTransientDeploymentMetadataError",
            "Test-DefenseClawDeploymentMetadataPresent",
            "Get-DefenseClawDeploymentMetadata",
            "Get-DefenseClawDeploymentMetadataOnce",
            "Repair-DefenseClawUnreadableDeploymentMetadata",
            "Format-DefenseClawSetupAction",
            "Write-DefenseClawJsonAtomic",
            "Clear-DefenseClawRestrictiveFileAttributes",
        )
    )
    harness = tmp_path / "unreadable-metadata.ps1"
    harness.write_text(
        "$ErrorActionPreference = 'Stop'\nSet-StrictMode -Version Latest\n"
        + functions
        + r"""
$script:SchemaVersion = 1
$script:AdministratorsSID = 'S-1-5-32-544'
$script:UnreadableMetadataMessage = 'could not read the installed deployment metadata'
$script:System32 = '__ROOT__'
$global:Resets = 0
$script:IcaclsExe = { $global:Resets++ }
$root = '__ROOT__'
$Layout = @{
    MetadataPath = Join-Path $root 'deployment.json'; PendingPath = Join-Path $root 'pending.json'
    InstallRoot = Join-Path $root 'install'; StateRoot = Join-Path $root 'state'
    CLIPath = Join-Path $root 'defenseclaw.exe'; GatewayPath = Join-Path $root 'gateway.exe'
    CertificationCodexHome = ''; CoreHardeningCertification = $false
}
foreach ($key in @('CodexMachinePolicyPath', 'CodexManagedHooksDirectory', 'CodexManagedHooksStatePath',
        'CodexRequirementsOwnershipPath', 'CodexRequirementsAclBackupPath',
        'AgentApplicationControlAttestationPath', 'ManagedHooksTeardownJournalPath')) {
    $Layout[$key] = Join-Path $root $key
}
function Assert-DefenseClawNoReparsePath { param([string]$Path) }
function New-DefenseClawDirectory { param([string]$Path) }
function New-DefenseClawCanonicalPathAcl { return 'canonical' }
function Assert-DefenseClawCanonicalPathAcl {
    param([string]$Path, $Expected)
    if ($global:Drifted) { throw "managed DACL is not protected after exact ACL replacement: $Path" }
}
function Set-DefenseClawPathAcl { param([string]$Path, [string]$Kind, [string]$GatewayServiceSID) $global:Drifted = $false; $global:Stamps++ }
function Move-DefenseClawNonImageFileReplacing {
    param([string]$Source, [string]$Destination)
    [IO.File]::Move($Source, $Destination, $true)
}
function Test-DefenseClawTrustStrictAncestors { return $false }
function Write-DefenseClawAclSelfHealAdvisory { param($Path, $Reason) }
# Setup reads the metadata elevated, so the authenticated ACL repair runs
# first. Like a file another principal could have written, a drifted one is
# refused there, and the standalone profile keeps the canonical check.
function Test-DefenseClawAdministrator { $true }
function Test-DefenseClawStandaloneProfile { $true }
function Repair-DefenseClawUninstallAdminFileAcl {
    param($Layout, [string]$Kind)
    if ($global:Drifted) { throw "refusing to re-stamp the $Kind metadata: another principal could have written it" }
}
function Test-DefenseClawMetadataInstalled { param($Metadata) return [bool]$Metadata.installed }
function Resolve-DefenseClawCertificationCodexHome { param($Path, $GatewayServiceName, $GuardianServiceName) return $Path }
function Test-DefenseClawLayoutBrokerEnabled { param($Layout) return $false }
function Test-DefenseClawServiceExists { param([string]$Name) return $true }
function Assert-DefenseClawOwnedServiceOrAbsent { param($Name, $ExpectedGatewayPath) }
$full = @('gateway', 'acp', 'hook', 'sensor_helper', 'installer', 'module')
function Invoke-Case([string]$Name, [string]$Text, [bool]$Drifted, [string[]]$Sources) {
    [IO.File]::WriteAllText($Layout.MetadataPath, $Text)
    $global:Drifted = $Drifted
    $global:Stamps = 0
    $global:Resets = 0
    $sourceTable = @{}
    foreach ($source in $Sources) { $sourceTable[$source] = @{} }
    $read = ''
    try { $read = [string]((Get-DefenseClawDeploymentMetadata -Layout $Layout -Required) -ne $null) }
    catch { $read = $_.Exception.Message }
    $repair = ''
    try {
        $rebuilt = Repair-DefenseClawUnreadableDeploymentMetadata -Layout $Layout -Sources $sourceTable `
            -GatewayServiceName 'DefenseClawGateway' -GuardianServiceName 'DefenseClawHookGuardian' -WarningAction SilentlyContinue
        $metadata = Get-DefenseClawDeploymentMetadata -Layout $Layout -Required
        $repair = "rebuilt=$rebuilt installed=$($metadata.installed) stamps=$($global:Stamps) drifted=$($global:Drifted)"
    }
    catch { $repair = $_.Exception.Message }
    [pscustomobject]@{ name = $Name; read = $read; repair = $repair; resets = $global:Resets } | ConvertTo-Json -Compress
}
$valid = '{"schema_version":1,"installed":true,"install_root":"' + $Layout.InstallRoot.Replace('\', '\\') +
    '","state_root":"' + $Layout.StateRoot.Replace('\', '\\') + '","profile":"standalone","hashes":{}}'
Invoke-Case 'garbage' 'this is not json at all, 30 b' $false $full
Invoke-Case 'garbage drifted' 'this is not json at all, 30 b' $true $full
Invoke-Case 'empty' '' $false $full
Invoke-Case 'garbage without payload' 'this is not json at all, 30 b' $false @('gateway')
Invoke-Case 'valid drifted' $valid $true $full
""".replace("__ROOT__", str(tmp_path)),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(harness)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    cases = {case["name"]: case for case in map(json.loads, completed.stdout.strip().splitlines())}
    for name in ("garbage", "garbage drifted", "empty"):
        assert cases[name]["read"].startswith("could not read the installed deployment metadata"), cases[name]
        assert cases[name]["resets"] == 0, cases[name]
        assert cases[name]["repair"] == "rebuilt=True installed=True stamps=1 drifted=False", cases[name]
    # GAP-0095: Setup is not installed on the computer; the hint runs it from its folder and says where it comes from.
    assert (
        "only the installed release's Setup carries every artifact it must re-record (acp, hook, sensor_helper, installer, module); "
        "run & '.\\DefenseClawSetup-Enterprise-Standalone-x64.exe' /repair (Setup is not installed on this computer: "
        "use the copy in your MDM package or the release download)"
    ) in cases["garbage without payload"]["repair"], cases["garbage without payload"]
    assert cases["valid drifted"]["read"].startswith("managed DACL is not protected")
    assert cases["valid drifted"]["repair"].startswith("managed DACL is not protected")


def _repair_rollback_config_cases(tmp_path: Path) -> dict[str, dict]:
    """A running gateway can hold the last good policy after config.yaml is edited.

    Repair must ask the authenticated replacement gateway to check the
    rollback config before rebuilding deployment.json or opening a transaction.
    An ACL drift that Repair can heal must not block that check.
    """
    import json

    engine = _portable_pwsh()
    if engine is None:
        pytest.skip("PowerShell 7 (pwsh) is not installed")
    module = _text(MODULE)
    entry = _function_body(module, "Invoke-DefenseClawEnterpriseLifecycle")
    assert entry.index("Assert-DefenseClawRepairRollbackConfig `") < entry.index(
        "[void](Repair-DefenseClawUnreadableDeploymentMetadata `"
    )
    assert entry.index("Assert-DefenseClawRepairRollbackConfig `") < entry.index(
        "return Invoke-DefenseClawInstallLikeLifecycle `"
    )
    install = _function_body(module, "Invoke-DefenseClawInstallLikeLifecycle")
    # Standalone Repair has two blocks (GAP-0568). The first, after the
    # recorded artifact hashes are checked, rewrites drifted policy from the
    # recorded approved sources. The second, inside the transaction with the
    # services stopped, re-stamps the managed and secrets ACLs.
    repair_anchor = "if ($Action -eq 'Repair' -and (Test-DefenseClawStandaloneProfile)) {"
    assert install.count(repair_anchor) == 2
    snapshot = install.index("$snapshot = New-DefenseClawTransaction `")
    recovery = install.index(repair_anchor)
    recovery_end = install.index("\n    }\n", recovery)
    assert "Invoke-DefenseClawRepairApprovedPolicyRecovery" in install[recovery:recovery_end]
    assert "Set-DefenseClawManagedAcls" not in install[recovery:recovery_end]
    assert install.index("Assert-DefenseClawRecordedArtifactHashes `") < recovery < snapshot
    repair_stamp = install.index(repair_anchor, recovery_end)
    stamp_end = install.index("\n        }\n", repair_stamp)
    stamp = install[repair_stamp:stamp_end]
    assert "Set-DefenseClawManagedAcls" in stamp and "-SkipCodexMachineState" in stamp
    assert "Set-DefenseClawStandaloneSecretsAcls" in stamp
    assert snapshot < repair_stamp
    assert install.index("Stop-DefenseClawService -Name $GatewayServiceName") < repair_stamp
    assert repair_stamp < install.index("Assert-DefenseClawInstalledConfig -Layout $Layout")
    assert "[string]$GatewayPath" in _function_body(module, "Invoke-DefenseClawGatewayCommand")
    functions = "\n".join(
        _function_body(module, name)
        for name in (
            "Assert-DefenseClawInstalledConfig",
            "Assert-DefenseClawRepairRollbackConfig",
            "Repair-DefenseClawUnreadableDeploymentMetadata",
            "Get-DefenseClawRepairRollbackApprovedConfigSource",
            "Get-DefenseClawRecordedConfigGeneration",
            "Get-DefenseClawRecordedConfigGenerationHash",
            "Test-DefenseClawSignedBundleStoreHoldsVersions",
            "Get-DefenseClawHandEditApprovedConfigSource",
            "Get-DefenseClawApprovedPolicySource",
            "Get-DefenseClawApprovedPolicyHash",
            "Get-DefenseClawApprovedPolicyPath",
            "Get-DefenseClawStandaloneBundleRepairCommand",
            "Format-DefenseClawSetupAction",
            "Format-DefenseClawRepairAction",
        )
    )
    harness = tmp_path / "repair-rollback-config.ps1"
    harness.write_text(
        "$ErrorActionPreference = 'Stop'\nSet-StrictMode -Version Latest\n"
        + functions
        + r"""
function Test-DefenseClawStandaloneProfile { return $true }
$script:SchemaVersion = 1
$script:AdministratorsSID = 'S-1-5-32-544'
$script:SystemSID = 'S-1-5-18'
$script:TrustedInstallerSID = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$script:UnreadableMetadataMessage = 'could not read the installed deployment metadata'
$root = '__ROOT__'
$Layout = @{
    ConfigPath = Join-Path $root 'config.yaml'; MetadataPath = Join-Path $root 'deployment.json'
    PendingPath = Join-Path $root 'pending.json'; GatewayPath = Join-Path $root 'installed-gateway.exe'
    RuntimeDirectory = Join-Path $root 'runtime'; CLIPath = Join-Path $root 'defenseclaw.exe'
    InstallRoot = Join-Path $root 'install'; StateRoot = Join-Path $root 'state'
    ConfigDirectory = $root; InstallStateDirectory = Join-Path $root 'install-state'
}
$Sources = @{ gateway = @{ path = 'authenticated-replacement-gateway.exe' } }
foreach ($name in @('acp', 'hook', 'sensor_helper', 'installer', 'module')) { $Sources[$name] = @{} }
function Get-DefenseClawServiceChecked { param($Name) return [pscustomobject]@{ Status = $global:ServiceStatus } }
function Assert-DefenseClawSourceDescriptorCurrent { param($Source) $global:SourceChecks++ }
function Invoke-DefenseClawGatewayCommand {
    param($Layout, $GatewayServiceName, $Arguments, $GatewayPath)
    $global:GatewayCalls++
    if ($GatewayPath -cne $Sources.gateway.path -or $Arguments -notcontains 'validate-service-config' -or
        $Arguments -contains '--record-lifecycle' -or $Arguments -notcontains $Layout.ConfigPath) {
        throw 'repair did not use the authenticated gateway read-only config check'
    }
    if ($global:TrustProblem -and ($Arguments -notcontains '--repair-rollback' -or
        $global:TrustProblem.Contains("outside Repair's ACL scope"))) {
        throw $global:TrustProblem
    }
    if ([IO.File]::ReadAllText($Layout.ConfigPath).Contains('0.0.0.0')) {
        throw 'gateway.api_bind must bind to exact canonical 127.0.0.1'
    }
    return 0
}
function Get-DefenseClawDeploymentMetadata {
    param($Layout, [switch]$Required)
    $raw = [IO.File]::ReadAllText($Layout.MetadataPath)
    if (-not $raw.StartsWith('{')) { throw "$($script:UnreadableMetadataMessage) $($Layout.MetadataPath)" }
    return $raw | ConvertFrom-Json
}
function Test-DefenseClawDeploymentMetadataPresent {
    param([string]$Path)
    return Test-Path -LiteralPath $Path -PathType Leaf
}
function Test-DefenseClawServiceExists { param($Name) return $true }
function Assert-DefenseClawOwnedServiceOrAbsent { param($Name, $ExpectedGatewayPath) }
function Write-DefenseClawJsonAtomic {
    param($Path, $Value, $Kind)
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 10))
    # GAP-0899: the rebuilt record is stamped by its own publish, not after it.
    if ($Kind -eq 'AdminFile') { $global:Stamps++ }
}
function Set-DefenseClawPathAcl { param($Path, $Kind, $GatewayServiceSID) $global:Stamps++ }
function Assert-DefenseClawPathAcl {
    param($Path, $AllowedWriterSIDs, $AllowedReaderSIDs, [switch]$RejectUntrustedRead,
        [switch]$AllowInheritance, [switch]$IgnoreCreatorTemplates)
}
function Assert-DefenseClawNoReparsePath { param($Path, [switch]$AllowMissingLeaf) }
function Get-DefenseClawServiceSID { param($ServiceName) return 'S-1-5-80-0' }
function Get-DefenseClawSourceDescriptor {
    param($Path, $Label)
    # Get-FileHash returns upper-case hex, as the production descriptor does.
    return @{ path = $Path; sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
}
function Install-DefenseClawFileAtomic {
    param($Source, $Destination, $ExpectedSHA256)
    if ((Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash -ne $ExpectedSHA256) { throw 'copy digest changed' }
    [IO.File]::Copy($Source, $Destination, $true)
}
function Invoke-Case([string]$Name, [string]$Metadata, [string]$Bind, [string]$Status,
        [bool]$Pending, [string]$TrustProblem = '') {
    [IO.File]::WriteAllText($Layout.MetadataPath, $Metadata)
    [IO.File]::WriteAllText($Layout.ConfigPath, "gateway:`n  api_bind: $Bind`n")
    if ($Pending) { [IO.File]::WriteAllText($Layout.PendingPath, '{}') }
    elseif (Test-Path -LiteralPath $Layout.PendingPath) { Remove-Item -LiteralPath $Layout.PendingPath }
    $global:ServiceStatus = $Status
    $global:TrustProblem = $TrustProblem
    $global:GatewayCalls = 0
    $global:SourceChecks = 0
    $global:Stamps = 0
    $errorText = ''
    try {
        Assert-DefenseClawRepairRollbackConfig -Layout $Layout -Sources $Sources -GatewayServiceName 'DefenseClawGateway'
        [void](Repair-DefenseClawUnreadableDeploymentMetadata -Layout $Layout -Sources $Sources `
            -GatewayServiceName 'DefenseClawGateway' -GuardianServiceName 'DefenseClawHookGuardian' `
            -WarningAction SilentlyContinue)
    }
    catch { $errorText = $_.Exception.Message }
    [pscustomobject]@{
        name = $Name; error = $errorText; metadata = [IO.File]::ReadAllText($Layout.MetadataPath)
        pending = (Test-Path -LiteralPath $Layout.PendingPath); gateway_calls = $global:GatewayCalls
        source_checks = $global:SourceChecks; stamps = $global:Stamps
        config = [IO.File]::ReadAllText($Layout.ConfigPath)
        candidates = @(Get-ChildItem -LiteralPath $root -Filter 'config.repair-rollback.*').Count
    } | ConvertTo-Json -Compress
}
Invoke-Case 'invalid malformed' 'broken metadata' '0.0.0.0' 'Running' $false
Invoke-Case 'invalid valid' '{"installed":true}' '0.0.0.0' 'Running' $false
Invoke-Case 'valid malformed' 'broken metadata' '127.0.0.1' 'Running' $false
Invoke-Case 'runtime ACL drift' 'broken metadata' '127.0.0.1' 'Running' $false 'managed data_dir trust check failed'
Invoke-Case 'bundle service read ACL drift' 'broken metadata' '127.0.0.1' 'Running' $false 'gateway service cannot read bundle rule pack'
Invoke-Case 'external policy ACL drift' 'broken metadata' '127.0.0.1' 'Running' $false "policy_dir is outside Repair's ACL scope"
Invoke-Case 'transitional service' 'broken metadata' '127.0.0.1' 'StartPending' $false
Invoke-Case 'pending recovery' 'broken metadata' '0.0.0.0' 'Running' $true
Invoke-Case 'stopped deferred' 'broken metadata' '0.0.0.0' 'Stopped' $false
# GAP-0568: a config edited after the recorded generation is checked through a
# temporary copy of the recorded approved bytes; the installed file is not
# changed and the copy is removed. A stale approved copy is refused and the
# refusal still names the installed config's failing setting.
[void][IO.Directory]::CreateDirectory($Layout.InstallStateDirectory)
$approvedPath = Join-Path $Layout.InstallStateDirectory 'approved-config.yaml'
[IO.File]::WriteAllText($approvedPath, "gateway:`n  api_bind: 127.0.0.1`n")
$approvedHash = (Get-FileHash -LiteralPath $approvedPath -Algorithm SHA256).Hash.ToLowerInvariant()
$generationPath = Join-Path $Layout.ConfigDirectory 'config.generation.json'
$approvedMetadata = '{"installed":true,"approved_policy_sources":{"config":"' + $approvedHash + '"}}'
[IO.File]::WriteAllText($generationPath, '{"config_sha256":"' + $approvedHash + '"}')
Invoke-Case 'approved current' $approvedMetadata '0.0.0.0' 'Running' $false
[IO.File]::WriteAllText($generationPath, '{"config_sha256":"' + ('a' * 64) + '"}')
Invoke-Case 'approved stale' $approvedMetadata '0.0.0.0' 'Running' $false
""".replace("__ROOT__", str(tmp_path)),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(harness)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    cases = {case["name"]: case for case in map(json.loads, completed.stdout.strip().splitlines())}
    return cases


def test_repair_checks_the_running_gateway_rollback_config_before_rebuilding_metadata(tmp_path: Path) -> None:
    import json

    cases = _repair_rollback_config_cases(tmp_path)
    for name, original in (("invalid malformed", "broken metadata"), ("invalid valid", '{"installed":true}')):
        assert "gateway.api_bind" in cases[name]["error"], cases[name]
        assert cases[name]["metadata"] == original, cases[name]
        assert cases[name]["gateway_calls"] == 1, cases[name]
        assert cases[name]["source_checks"] == 2, cases[name]
        assert cases[name]["stamps"] == 0, cases[name]
    assert cases["valid malformed"]["error"] == "", cases["valid malformed"]
    assert json.loads(cases["valid malformed"]["metadata"])["installed"] is True
    assert cases["valid malformed"]["stamps"] == 1
    for name in ("runtime ACL drift", "bundle service read ACL drift"):
        assert cases[name]["error"] == "", cases[name]
        assert json.loads(cases[name]["metadata"])["installed"] is True, cases[name]
        assert cases[name]["stamps"] == 1, cases[name]
    assert "outside Repair's ACL scope" in cases["external policy ACL drift"]["error"]
    assert cases["external policy ACL drift"]["metadata"] == "broken metadata"
    assert cases["external policy ACL drift"]["stamps"] == 0
    assert cases["transitional service"]["gateway_calls"] == 0
    assert cases["transitional service"]["metadata"] == "broken metadata"
    assert cases["pending recovery"]["metadata"] == "broken metadata"
    assert cases["pending recovery"]["gateway_calls"] == 0
    assert cases["stopped deferred"]["gateway_calls"] == 0
    approved = cases["approved current"]
    assert approved["error"] == "", approved
    assert approved["gateway_calls"] == 2, approved
    assert "0.0.0.0" in approved["config"] and approved["candidates"] == 0, approved
    stale = cases["approved stale"]
    assert "gateway.api_bind" in stale["error"] and "cannot prove" in stale["error"], stale
    assert stale["gateway_calls"] == 1 and stale["candidates"] == 0, stale
    assert "0.0.0.0" in stale["config"], stale


_SETUP_HINT_FUNCTIONS = (
    "Test-DefenseClawStandaloneProfile",
    "Format-DefenseClawSetupAction",
    "Format-DefenseClawRepairAction",
    "Format-DefenseClawRerunStep",
    "Get-DefenseClawStandaloneBundleRepairCommand",
)


def test_module_hints_do_not_name_setup_as_a_bare_command() -> None:
    # cowork-1-0-8 GAP-0095: Setup is not installed on a managed computer, so a
    # hint reaches it only through Format-DefenseClawSetupAction (the command
    # run from its folder, with where it comes from) or, for a repair, the
    # installed CLI. The two literals left name it for a profile that is not
    # standalone (Secure Client), which keeps the text it always had.
    module = re.sub(r"<#.*?#>", "", _text(MODULE), flags=re.DOTALL)
    named = [
        line.strip()
        for line in module.splitlines()
        if not line.lstrip().startswith("#")
        and re.search(r"\bSetup\s+/(?:repair|ensure|uninstall|install|upgrade|verify)\b", line)
    ]
    assert len(named) == 2, named
    assert "return 'Setup /repair'" in named[0], named
    assert "only Setup /repair carries every artifact" in named[1], named
    assert "DefenseClawSetup-Enterprise-Standalone-x64.exe" not in re.sub(r"<#.*?#>", "", module.replace(
        "\"& '.\\DefenseClawSetup-Enterprise-Standalone-x64.exe' $arguments\"", ""))
    # "Run Setup again" names Setup with no command and no source. It is said
    # only by Format-DefenseClawRerunStep, for a profile that is not standalone
    # (the standalone profile asks for "the same command").
    phrases = [
        line.strip()
        for line in module.splitlines()
        if not line.lstrip().startswith("#")
        and re.search(r"\b[Rr]un\s+(?:the\s+(?:same\s+)?)?Setup(?:\s+command)?\s+again\b|\bSetup\s+again\b", line)
    ]
    assert phrases == [
        "if ($SameSetupCommand) { return 'run the same Setup command again' }",
        "return 'run Setup again'",
    ], phrases


@pytest.mark.skipif(not _portable_pwsh(), reason="PowerShell 7 (pwsh) is not installed")
def test_setup_hints_run_the_setup_from_its_folder_and_repair_through_the_cli(tmp_path: Path) -> None:
    import json

    module = _text(MODULE)
    functions = "\n".join(_function_body(module, name) for name in _SETUP_HINT_FUNCTIONS)
    harness = tmp_path / "hints.ps1"
    harness.write_text(
        functions
        + r"""
$Layout = @{ CLIPath = 'C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw.exe' }
$script:DefenseClawEnterpriseProfile = 'Standalone'
$standalone = [ordered]@{
    ensure = Format-DefenseClawSetupAction -Action '/ensure'
    config = Format-DefenseClawSetupAction -Action '/ensure CONFIG=<approved absolute config path>'
    either = Format-DefenseClawSetupAction -Action @('/install', '/uninstall PURGE=1')
    repair = Format-DefenseClawRepairAction -Layout $Layout
    rerun = Format-DefenseClawRerunStep
    rerunSetup = Format-DefenseClawRerunStep -SameSetupCommand
}
$script:DefenseClawEnterpriseProfile = 'SecureClient'
$other = [ordered]@{
    ensure = Format-DefenseClawSetupAction -Action '/ensure'
    config = Format-DefenseClawSetupAction -Action '/ensure CONFIG=<approved config>'
    either = Format-DefenseClawSetupAction -Action @('/install', '/uninstall PURGE=1')
    repair = Format-DefenseClawRepairAction -Layout $Layout
    rerun = Format-DefenseClawRerunStep
    rerunSetup = Format-DefenseClawRerunStep -SameSetupCommand
}
[ordered]@{ standalone = $standalone; other = $other } | ConvertTo-Json -Compress
""",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [_portable_pwsh(), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(harness)],
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    result = json.loads(completed.stdout.strip().splitlines()[-1])
    source = "Setup is not installed on this computer: use the copy in your MDM package or the release download"
    setup = "& '.\\DefenseClawSetup-Enterprise-Standalone-x64.exe'"
    assert result["standalone"]["ensure"] == f"{setup} /ensure ({source})"
    # A placeholder is quoted as the Go hints quote it: unquoted, PowerShell reads "<" as an error.
    assert result["standalone"]["config"] == f"{setup} /ensure 'CONFIG=<approved absolute config path>' ({source})"
    # Alternatives are separate commands, not one command with "or" as an argument.
    assert result["standalone"]["either"] == f"{setup} /install or {setup} /uninstall PURGE=1 ({source})"
    assert result["standalone"]["rerun"] == result["standalone"]["rerunSetup"] == "run the same command again"
    assert result["standalone"]["repair"] == (
        "& 'C:\\Program Files\\Cisco\\DefenseClaw\\bin\\defenseclaw.exe' enterprise windows repair --profile standalone --json"
    )
    # Another profile keeps "Setup /..." as it was, byte for byte.
    assert result["other"] == {
        "ensure": "Setup /ensure",
        "config": "Setup /ensure CONFIG=<approved config>",
        "either": "Setup /install or /uninstall PURGE=1",
        "repair": "Setup /repair",
        "rerun": "run Setup again",
        "rerunSetup": "run the same Setup command again",
    }


def test_repair_rollback_refusal_names_the_supported_next_step(tmp_path: Path) -> None:
    cases = _repair_rollback_config_cases(tmp_path)
    for name in ("invalid malformed", "invalid valid", "approved stale"):
        assert "Next step:" in cases[name]["error"], cases[name]
        # The placeholder is quoted, as the Go hints quote it (PowerShell reads an unquoted "<" as an error).
        assert "/ensure 'CONFIG=" in cases[name]["error"], cases[name]
    assert "enterprise windows repair --profile standalone --json" in cases["approved stale"]["error"]
    assert "administrator-selected path permissions" in cases["external policy ACL drift"]["error"]
    assert "Next step:" in cases["transitional service"]["error"]
    # GAP-0095: the installed CLI repairs, by its full path; Setup is not on the computer.
    assert "then retry & '" in cases["transitional service"]["error"], cases["transitional service"]
    assert "enterprise windows repair --profile standalone --json" in cases["transitional service"]["error"]
    assert "Setup /repair" not in cases["transitional service"]["error"]


def _csharp_method_body(text: str, name: str) -> str:
    start = text.index(f" {name}(string path)\n")
    end = text.index("\n        }\n", start)
    return text[start : end + 11]


def test_a_hand_edited_config_is_replaced_by_the_approved_source_before_the_gateway_starts() -> None:
    # GAP-0743: a hand edit is recorded in config.generation.json for the
    # installed bytes, so Repair must not treat installed == recorded as
    # approved, and a rollback must not restore bytes managed startup refuses.
    module = _text(MODULE)
    install = _function_body(module, "Invoke-DefenseClawInstallLikeLifecycle")
    recovery = install.index("-ApprovedConfig $repairApprovedConfig")
    assert recovery < install.index("Stop-DefenseClawService -Name $GatewayServiceName")
    assert recovery < install.index("$approvedConfigSHA256 = [string]$repairApprovedConfig['config']")
    restore = _function_body(module, "Restore-DefenseClawTransaction")
    approved = restore.index("Restore-DefenseClawApprovedConfigOverHandEdit")
    assert approved < restore.index("Register-DefenseClawRestoredConfigGeneration")
    assert approved < restore.index("Start-DefenseClawTransactionServices")
    generation = _function_body(module, "Get-DefenseClawRecordedConfigGeneration")
    assert "hand-edit:*" in generation


def test_squatted_root_messages_name_the_link_owner() -> None:
    # GAP-0618: a junction a standard user planted at C:\ProgramData\Cisco was
    # reported as created by "an account DefenseClaw could not read" although
    # its owner resolved: the planter lookup used the managed-directory
    # snapshot, which refuses a reparse point. The owner of the path itself
    # (folder, file, junction or symbolic link) is read with the link opened
    # as a link, before the path is removed or moved.
    module = _text(MODULE)
    native = _csharp_method_body(module, "GetPathSecurityDescriptorNoFollow")
    assert "FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS" in native
    assert "GetFileSecurityDescriptorFromHandle(handle, path)" in native
    assert "REPARSE_POINT) != 0" not in native and "refusing" not in native

    planter = _function_body(module, "Get-DefenseClawSquattedRootPlanter")
    assert "$nativeSecurity::GetPathSecurityDescriptorNoFollow($Path)" in planter
    assert "GetDirectorySecuritySnapshotNoFollow" not in planter
    translate = planter.index("Translate([Security.Principal.NTAccount])")
    sid_fallback = planter.index("return $owner.Value", translate)
    generic = planter.index("'an account DefenseClaw could not read'")
    assert translate < sid_fallback < generic

    move = _function_body(module, "Move-DefenseClawStandaloneSquattedRoots")
    captured = move.index("$planter = Get-DefenseClawSquattedRootPlanter -Path $path")
    for change in ("[IO.Directory]::Delete(", "[IO.File]::Delete(", "[IO.Directory]::Move(", "[IO.File]::Move("):
        assert captured < move.index(change), change
    assert "removed the link $path that $planter created" in move
    assert "that $planter created aside to $quarantine" in move

    # Every root_squatted refusal names the account through the same lookup,
    # never a bare SID or a category in place of an owner.
    cause = _function_body(module, "Format-DefenseClawSquattedRootCause")
    assert "Get-DefenseClawSquattedRootPlanter -Path" in cause
    assert "is owned by $($entry.owner)" not in module
    assert "$($squattedRoots[0].owner)" not in module
    assert move.count("root_squatted: $path $cause,") == 3
    assert "$(Format-DefenseClawSquattedRootCause -Entry $squattedRoots[0])" in module


_PRE_LAYOUT_RECOVERY_PENDING_HARNESS = r"""
$root = '__ROOT__'
$layout = @{
    PendingPath = [IO.Path]::Combine($root, 'state', 'install', 'pending.json')
    PurgeIntentPath = [IO.Path]::Combine($root, 'lifecycle', 'purge-scope.json')
    SelfUninstallReceiptPath = [IO.Path]::Combine($root, 'lifecycle', 'self-uninstall-scope.json')
    InstallRollbackIntentPath = [IO.Path]::Combine($root, 'lifecycle', 'install-rollback-scope.json')
    ManagedHookContractCleanupReceiptPath = [IO.Path]::Combine($root, 'lifecycle', 'managed-hook-contract-cleanup-scope.json')
    MetadataPath = [IO.Path]::Combine($root, 'state', 'install', 'deployment.json')
}
foreach ($path in $layout.Values) { [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path)) }
[IO.File]::WriteAllText($layout.MetadataPath, '{}')
foreach ($record in @('', 'PendingPath', 'PurgeIntentPath', 'SelfUninstallReceiptPath', 'InstallRollbackIntentPath',
        'ManagedHookContractCleanupReceiptPath', 'MetadataPath', 'PendingPath:dir')) {
    foreach ($name in @('PendingPath', 'PurgeIntentPath', 'SelfUninstallReceiptPath', 'InstallRollbackIntentPath',
            'ManagedHookContractCleanupReceiptPath')) {
        if ([IO.File]::Exists($layout[$name])) { [IO.File]::Delete($layout[$name]) }
        if ([IO.Directory]::Exists($layout[$name])) { [IO.Directory]::Delete($layout[$name]) }
    }
    if ($record -ceq 'PendingPath:dir') { [void][IO.Directory]::CreateDirectory($layout.PendingPath) }
    elseif ($record -cne '' -and $record -cne 'MetadataPath') { [IO.File]::WriteAllText($layout[$record], '{}') }
    [pscustomobject]@{
        record = $record
        pending = [bool](Test-DefenseClawPreLayoutRecoveryPending -Layout $layout)
    } | ConvertTo-Json -Compress
}
"""


def test_deferred_install_freshness_waits_for_pre_layout_recovery(tmp_path: Path) -> None:
    """S2 review (loop round 2): a first deferred Install interrupted after it
    wrote the installed deployment record but before it cleared pending.json
    is retried, not refused from that partial record: the pre-lock freshness
    check runs only without a record Invoke-DefenseClawPreLayoutRecovery
    recovers first (a pending transaction, a state-purge intent, a
    self-uninstall receipt or an install-rollback intent), whose recovery can
    change the record; the check after that recovery, under the lock, still
    refuses a deferred Install over an installed deployment. Executed for the
    predicate, read for where it guards."""
    import json

    module = _text(MODULE)
    entry = _function_body(module, "Invoke-DefenseClawEnterpriseLifecycle")
    lock = entry.index("$lifecycleLock = Enter-DefenseClawLifecycleLock -Layout $layout")
    recovery = entry.index("$preLayoutRecovery = Invoke-DefenseClawPreLayoutRecovery")
    checks = [i for i in range(len(entry)) if entry.startswith("Assert-DefenseClawDeferredInstallIsFresh -Layout $layout", i)]
    assert len(checks) == 2, checks
    before, after = checks
    assert before < lock < recovery < after
    guard = entry[entry.rindex("if ($Action -eq 'Install' -and $DeferredConfig", 0, before) : before]
    assert "-not (Test-DefenseClawPreLayoutRecoveryPending -Layout $layout)" in guard
    guard = entry[entry.rindex("if ($Action -eq 'Install' -and $DeferredConfig", 0, after) : after]
    assert "Test-DefenseClawPreLayoutRecoveryPending" not in guard
    prelayout = _function_body(module, "Invoke-DefenseClawPreLayoutRecovery")
    for name in ("PendingPath", "PurgeIntentPath"):
        assert f"$Layout.{name}" in prelayout, name
    assert "Get-DefenseClawInstallRollbackIntent" in prelayout and "Invoke-DefenseClawSelfUninstallRecovery" in prelayout

    engine = _portable_pwsh()
    if engine is None:
        pytest.skip("PowerShell 7 (pwsh) is not installed")
    harness = tmp_path / "pre-layout-recovery-pending.ps1"
    harness.write_text(
        "$ErrorActionPreference = 'Stop'\nSet-StrictMode -Version Latest\n"
        + _function_body(module, "Test-DefenseClawPreLayoutRecoveryPending")
        + "\n"
        + _PRE_LAYOUT_RECOVERY_PENDING_HARNESS.replace("__ROOT__", str(tmp_path / "root")),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(harness)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    pending = {case["record"]: case["pending"] for case in map(json.loads, completed.stdout.strip().splitlines())}
    assert pending == {
        "": False,
        "PendingPath": True,
        "PurgeIntentPath": True,
        "SelfUninstallReceiptPath": True,
        "InstallRollbackIntentPath": True,
        "ManagedHookContractCleanupReceiptPath": False,
        "MetadataPath": False,
        "PendingPath:dir": False,
    }, pending


def test_lifecycle_scope_hash_matches_the_cli(tmp_path: Path) -> None:
    """S2 review (loop round 2): the CLI leaves a deferred-install refusal to
    the installer only for a recovery record of this run's own deployment
    scope, at the exact paths Get-DefenseClawLayout names (the scope's
    pending.json, purge-, self-uninstall- and install-rollback-<scope>.json),
    so another scope's record no longer skips the CLI's refusal. The
    CLI's scope
    is Get-DefenseClawStableScopeSHA256 of the same four values, with the
    installer's default service names."""
    import hashlib

    module = _text(MODULE)
    pending = _function_body(module, "Test-DefenseClawPreLayoutRecoveryPending")
    assert "@('PendingPath', 'PurgeIntentPath', 'SelfUninstallReceiptPath', 'InstallRollbackIntentPath')" in pending
    layout = _function_body(module, "Get-DefenseClawLayout")
    for record in ("purge", "self-uninstall", "install-rollback"):
        assert f'"{record}-$purgeScope.json"' in layout, record
    assert "PendingPath = (Microsoft.PowerShell.Management\\Join-Path $installState 'pending.json')" in layout
    scope_values = layout[layout.index("$purgeScope = Get-DefenseClawStableScopeSHA256 -Values @(") :]
    scope_values = scope_values[: scope_values.index("\n    )\n")]
    assert re.findall(r"\$(InstallRoot|StateRoot|GatewayServiceName|GuardianServiceName)\b", scope_values) == [
        "InstallRoot",
        "StateRoot",
        "GatewayServiceName",
        "GuardianServiceName",
    ]
    installer = _text(INSTALLER)
    assert "[string]$GatewayServiceName = 'DefenseClawGateway'," in installer
    assert "[string]$GuardianServiceName = 'DefenseClawHookGuardian'," in installer
    go = (ROOT / "internal" / "cli" / "windows_enterprise_config_preflight_windows.go").read_text(encoding="utf-8")
    assert 'windowsEnterpriseInstallerGatewayService  = "DefenseClawGateway"' in go
    assert 'windowsEnterpriseInstallerGuardianService = "DefenseClawHookGuardian"' in go
    assert '[]string{"purge", "self-uninstall", "install-rollback"}' in go
    go_test = (ROOT / "internal" / "cli" / "windows_enterprise_config_preflight_windows_test.go").read_text(encoding="utf-8")
    golden = re.search(r'windowsEnterpriseProductionScopeSHA256 = "([0-9a-f]{64})"', go_test).group(1)
    values = [r"C:\Program Files\Cisco\DefenseClaw", r"C:\ProgramData\Cisco\DefenseClaw", "DefenseClawGateway", "DefenseClawHookGuardian"]
    assert hashlib.sha256("\0".join(v.lower() for v in values).encode("utf-8")).hexdigest() == golden

    engine = _portable_pwsh()
    if engine is None:
        pytest.skip("PowerShell 7 (pwsh) is not installed")
    harness = tmp_path / "scope.ps1"
    quoted = ", ".join("'" + v.replace("'", "''") + "'" for v in values)
    harness.write_text(
        "$ErrorActionPreference = 'Stop'\nSet-StrictMode -Version Latest\n"
        + _function_body(module, "Get-DefenseClawStableScopeSHA256")
        + f"\nGet-DefenseClawStableScopeSHA256 -Values @({quoted})\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(harness)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert completed.stdout.strip() == golden


def test_cowork_policy_key_defaults_are_pinned() -> None:
    """The Cowork delivery writes HKLM SOFTWARE\\Policies\\Claude; only the
    smoke repoints the two module variables; the module assigns each once."""
    text = _text(MODULE)
    hive = re.findall(r"^\s*\$script:CoworkPolicyHive\s*=\s*(.+?)\s*$", text, re.M)
    key = re.findall(r"^\s*\$script:CoworkPolicyKey\s*=\s*(.+?)\s*$", text, re.M)
    assert hive == ["[Microsoft.Win32.RegistryHive]::LocalMachine"]
    assert key == ["'SOFTWARE\\Policies\\Claude'"]


def test_cowork_source_plan_reaches_the_runtime_acl_repair() -> None:
    """Setup /ensure reads the Cowork source plan before its transaction
    re-stamps the runtime ACL. That read passes --before-acl-repair (only a
    data_dir ACL refusal falls back to the preflight checks), so a drifted
    runtime ACL no longer fails ensure 1603 before the repair (CI step 04,
    GAP-0561). Delivery inspects again after the ACLs are re-stamped, strictly."""
    text = _text(MODULE)
    plan = text[text.index("function Get-DefenseClawCoworkPlan"):]
    plan = plan[: plan.index("\nfunction ", 1)]
    assert "[switch]$BeforeAclRepair" in plan
    assert "if ($BeforeAclRepair) { $args += @('--before-acl-repair') }" in plan
    life = text[text.index("function Invoke-DefenseClawInstallLikeLifecycle"):]
    life = life[: life.index("\nfunction ", 1)]
    source = life.index("$coworkSourcePlan = Get-DefenseClawCoworkPlan")
    transaction = life.index("$snapshot = New-DefenseClawTransaction", source)
    assert "-BeforeAclRepair" in life[source:transaction]
    delivery = life.index("Invoke-DefenseClawCoworkDelivery -Layout $Layout")
    restamp = life.index("Set-DefenseClawManagedAcls", transaction)
    assert transaction < restamp < delivery
    deliver = text[text.index("function Invoke-DefenseClawCoworkDelivery"):]
    deliver = deliver[: deliver.index("\nfunction ", 1)]
    assert "Get-DefenseClawCoworkPlan" in deliver
    assert "BeforeAclRepair" not in deliver
    assert text.count("-BeforeAclRepair") == 1
    go = _text(ROOT / "internal" / "cli" / "windows_enterprise_cowork_windows.go")
    assert '"before-acl-repair"' in go
    fallback = go[go.index("func loadWindowsCoworkSourceConfig"):]
    fallback = fallback[: fallback.index("\n}\n") + 3]
    assert "loadWindowsEnterpriseStandaloneConfig(path)" in fallback
    assert "errors.As(err, &drift)" in fallback
    assert "config.ValidateManagedStandaloneRuntimeCandidate(candidate)" in fallback


_GAP_0583_TOMBSTONE_HARNESS = r"""
$ErrorActionPreference = 'Stop'
$root = '__ROOT__'
$G = ('b' * 32)
$script:AdministratorsSID = 'S-1-5-32-544'
$layout = @{
    MetadataPath = [IO.Path]::Combine($root, 'install', 'deployment.json')
    PendingPath = [IO.Path]::Combine($root, 'install', 'pending.json')
    ManifestPath = [IO.Path]::Combine($root, 'hook-guardian', 'targets.yaml')
    ManagedHooksTeardownJournalPath = [IO.Path]::Combine($root, 'install', 'managed-hooks-teardown-journal.json')
    ManagedHookContractCleanupReceiptPath = [IO.Path]::Combine($root, 'lock', 'managed-hook-contract-cleanup-scope.json')
    LifecycleLockDirectory = [IO.Path]::Combine($root, 'lock')
    PurgeScopeSHA256 = ('e' * 64)
}
function Test-DefenseClawStandaloneProfile { return $true }
function Test-DefenseClawDeploymentMetadataPresent {
    param([string]$Path)
    return Test-Path -LiteralPath $Path -PathType Leaf
}
function Get-DefenseClawDeploymentMetadata {
    param($Layout, [switch]$Required)
    return ([IO.File]::ReadAllText($Layout.MetadataPath) | ConvertFrom-Json)
}
function Assert-DefenseClawNoReparsePath { param($Path) }
function Test-DefenseClawInstalledGatewayRecorded { return $true }
function Get-DefenseClawStandaloneManifestAdoption {
    param($Layout, $GatewayServiceName, $Activation, $InstalledManifestSHA256, $GatewaySource)
    return [pscustomobject]@{ ok = $global:Adopted; reason = 'guardian last activated another manifest'; target_count = 2; untrusted_folders = @() }
}
function Add-DefenseClawSignedOutUntrustedFolders { param($Adoption) }
function Set-DefenseClawPathAcl { param($Path, $Kind, $GatewayServiceSID) }
function Write-DefenseClawDeploymentMetadataBytes {
    param([string]$Path, [byte[]]$Bytes)
    [IO.File]::WriteAllBytes($Path, $Bytes)
}
function Test-DefenseClawPathPresentNoFollow { param($Path) return (Test-Path -LiteralPath $Path) }
function Write-DefenseClawLifecyclePhase { param($Stage) $global:Phases += $Stage }
function Assert-DefenseClawDescendant { param($Path, $Root, $Label) return $Path }
function Get-DefenseClawTargetRuntimeExchangeValue { param($Path, $TransactionDirectory) return ([IO.File]::ReadAllText($Path) | ConvertFrom-Json) }
function Assert-DefenseClawMetadataIdentity { param($Metadata, $GatewayServiceName, $GuardianServiceName) }

function Write-Json([string]$Path, $Value) {
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 8))
}
function New-Case([string]$ReceiptManifest, [string]$ReceiptGeneration, [bool]$Adopted) {
    if ([IO.Directory]::Exists($root)) { [IO.Directory]::Delete($root, $true) }
    foreach ($folder in 'install', 'lock', 'hook-guardian') { [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($root, $folder)) }
    # The enumerator pass after the deleted account dropped its rows: 2 targets now, 4 activated.
    [IO.File]::WriteAllText($layout.ManifestPath, "targets: [claudecode r108-kept, codex r108-kept]`n")
    $script:Live = (Get-FileHash -LiteralPath $layout.ManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ReceiptManifest -ceq 'LIVE') { $ReceiptManifest = $script:Live }
    Write-Json $layout.MetadataPath ([ordered]@{
        schema_version = 6
        installed = $false
        managed_hooks_activation = [ordered]@{
            schema_version = 1; deployment_generation_id = $G; state = 'activated'
            manifest_sha256 = ('a' * 64); target_count = 4
        }
    })
    Write-Json $layout.ManagedHooksTeardownJournalPath ([ordered]@{
        schema_version = 6; phase = 'prepared'; manifest_sha256 = $script:Live; deployment_generation_id = $G
    })
    $claims = @(
        foreach ($connector in 'claudecode', 'codex') {
            [ordered]@{ connector = $connector; sid = 'S-1-5-21-1-2-3-1001'; data_dir = 'C:\Users\r108-kept\.defenseclaw'
                gateway_service_name = 'DefenseClawGateway'; entry_present = $false; entry_sha256 = '' }
        }
    )
    Write-Json $layout.ManagedHookContractCleanupReceiptPath ([ordered]@{
        schema_version = 1; phase = 'prepared'; identity_sha256 = 'sha256:' + ('c' * 64)
        scope_sha256 = $layout.PurgeScopeSHA256; manifest_sha256 = $ReceiptManifest
        manifest_fingerprint = 'sha256:' + ('d' * 64); deployment_generation_id = $ReceiptGeneration
        gateway_service_name = 'DefenseClawGateway'; claims = $claims
    })
    $global:Adopted = $Adopted
    $global:Phases = @()
}
function Test-Receipt {
    try {
        [void](Get-DefenseClawManagedHookContractCleanupReceipt -Layout $layout -GatewayServiceName DefenseClawGateway `
            -GuardianServiceName DefenseClawHookGuardian -Metadata (Get-DefenseClawDeploymentMetadata -Layout $layout -Required) -Required)
        return 'ok'
    }
    catch { return $_.Exception.Message }
}
function Invoke-Case([string]$Name, [string]$ReceiptManifest, [string]$ReceiptGeneration, [bool]$Adopted) {
    New-Case $ReceiptManifest $ReceiptGeneration $Adopted
    $before = Test-Receipt
    $plain = Sync-DefenseClawStandaloneManagedHooksActivationBinding -Layout $layout -GatewayServiceName DefenseClawGateway
    $first = Sync-DefenseClawStandaloneUninstallTombstoneBinding -Layout $layout -GatewayServiceName DefenseClawGateway
    $bytes = [IO.File]::ReadAllText($layout.MetadataPath)
    $second = Sync-DefenseClawStandaloneUninstallTombstoneBinding -Layout $layout -GatewayServiceName DefenseClawGateway
    $activation = (Get-DefenseClawDeploymentMetadata -Layout $layout -Required).managed_hooks_activation
    [pscustomobject]@{
        name = $Name; before = $before; plain = [bool]$plain; first = [bool]$first; second = [bool]$second
        unchanged_after_second = ($bytes -ceq [IO.File]::ReadAllText($layout.MetadataPath))
        bound_live = ([string]$activation.manifest_sha256 -ceq $script:Live)
        target_count = [int64]$activation.target_count; generation = [string]$activation.deployment_generation_id
        state = [string]$activation.state; after = Test-Receipt; phases = @($global:Phases)
    } | ConvertTo-Json -Compress -Depth 4
}
Invoke-Case 'deleted account' 'LIVE' $G $true
Invoke-Case 'tampered receipt' ('f' * 64) $G $true
Invoke-Case 'other deployment' 'LIVE' ('9' * 32) $true
Invoke-Case 'not adopted' 'LIVE' $G $false
"""


def test_gap_0583_deleted_account_tombstone_rebinds_only_adopted_matching_artifacts(tmp_path: Path) -> None:
    """rel-1-0-6:GAP-0583: the enumerator pass after a deleted enrolled
    account republished targets.yaml after the uninstall's pre-commit check,
    so the tombstone kept the old activation manifest while the teardown
    journal and the contract cleanup receipt named the new one. Every retry
    and Setup /ensure then failed 1603 ("contract cleanup receipt does not
    match the inactive deployment tombstone") until FORCE=1. The committed
    finalization and the Install recovery now rebind the tombstone to the
    manifest the guardian adopted, once, when every artifact already names it
    and the deployment generation. A tampered receipt, a receipt of another
    deployment and an unadopted manifest still refuse."""
    import json
    import shutil

    shell = _portable_pwsh() or shutil.which("pwsh")
    if not shell:
        pytest.skip("PowerShell 7 (pwsh) is not installed")
    module = _text(MODULE)
    functions = "\n".join(
        _function_body(module, name)
        for name in (
            "Test-DefenseClawMetadataInstalled",
            "Assert-DefenseClawManagedHooksActivationRecord",
            "Get-DefenseClawManagedHookContractCleanupReceipt",
            "Test-DefenseClawTombstoneTeardownArtifactsBindManifest",
            "Sync-DefenseClawStandaloneUninstallTombstoneBinding",
            "Sync-DefenseClawStandaloneManagedHooksActivationBinding",
        )
    )
    script = tmp_path / "gap0583.ps1"
    root = tmp_path / "state"
    script.write_text(
        functions + "\n" + _GAP_0583_TOMBSTONE_HARNESS.replace("__ROOT__", str(root)), encoding="utf-8"
    )
    result = subprocess.run([shell, "-NoProfile", "-File", str(script)], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    rows = {row["name"]: row for row in (json.loads(line) for line in result.stdout.splitlines() if line.startswith("{"))}
    mismatch = "contract cleanup receipt does not match the inactive deployment tombstone"

    deleted = rows["deleted account"]
    assert deleted["before"] == mismatch  # the field symptom
    assert deleted["plain"] is False  # installed-only callers never touch a tombstone
    assert deleted["first"] is True and deleted["after"] == "ok"
    assert deleted["bound_live"] and deleted["target_count"] == 2
    assert deleted["generation"] == "b" * 32 and deleted["state"] == "activated"
    assert deleted["second"] is False and deleted["unchanged_after_second"]  # repeated uninstall: idempotent
    assert any("enrolled account was deleted" in phase for phase in deleted["phases"])

    for name in ("tampered receipt", "other deployment"):
        row = rows[name]
        assert row["first"] is False and row["second"] is False and not row["bound_live"], name
        assert row["target_count"] == 4 and row["after"] == mismatch, name

    unadopted = rows["not adopted"]
    assert unadopted["first"] is False and not unadopted["bound_live"]
    assert unadopted["after"] == mismatch
    assert any("has not adopted" in phase for phase in unadopted["phases"])


def test_gap_0583_standalone_teardown_refuses_activation_drift_before_the_commit() -> None:
    """rel-1-0-6:GAP-0583: the 26.8.4 forward-port made the native teardown
    accept a republished manifest on every profile, so the standalone
    uninstall pre-commit check passed over a stale activation binding. The
    standalone refusal is the catch-up refusal the check waits on
    (GAP-0319/GAP-0346); Secure Client keeps accept-and-log. Both the
    committed finalization and the Install (ensure) recovery rebind the
    tombstone before their first binding check."""
    go = _text(ROOT / "internal" / "cli" / "windows_managed_hooks_teardown.go")
    validator = go[go.index("func validateWindowsManagedHooksTeardownActivation(") :]
    validator = validator[: validator.index("\n}\n") + 3]
    strict = validator.index("if windowsManagedHooksTeardownStandaloneProcess() {")
    assert strict < validator.index("acceptWindowsManagedHooksActivationDrift(activation, manifestSHA256, targetCount)")
    refusal = "protected managed-hook activation evidence does not match the current manifest"
    assert validator[strict:].count(refusal) == 1
    module = _text(MODULE)
    assert f"'{refusal}'" in _function_body(module, "Test-DefenseClawManifestCatchUpTeardownRefusal")

    finalization = _function_body(module, "Complete-DefenseClawCommittedManagedHooksFinalization")
    rebind = finalization.index("Sync-DefenseClawStandaloneUninstallTombstoneBinding")
    assert finalization.index("throw 'managed-hook finalization requires an uninstall tombstone'") < rebind
    assert rebind < finalization.index("Get-DefenseClawManagedHooksTeardownJournalPhase")
    assert rebind < finalization.index("Get-DefenseClawManagedHookContractCleanupReceipt")

    recovery = _function_body(module, "Invoke-DefenseClawPreLayoutRecovery")
    rebind = recovery.index("Sync-DefenseClawStandaloneUninstallTombstoneBinding")
    assert rebind < recovery.index("$retiredContractReceipt =")
    assert "$committedMetadata = Get-DefenseClawDeploymentMetadata" in recovery[rebind : rebind + 400]


def test_the_config_step_records_over_a_hand_edit_only_for_this_runs_config_source() -> None:
    # GAP-0646: the transaction's config step records a hand-edit record of
    # the installed bytes as the lifecycle's generation only for the approved
    # source this run installed (CONFIG=). The sha256 comes from that source
    # descriptor alone, never from config.yaml or config.generation.json, and
    # rides only on the recording call: verify, status, the Repair rollback
    # preflight and Secure Client (validate-only) never pass it.
    module = _text(MODULE)
    check = _function_body(module, "Assert-DefenseClawInstalledConfig")
    record = check.index("if ($RecordLifecycle) {")
    record_end = check.index("\n    }\n", record)
    assert check.count("--approved-config-sha256") == 1
    assert "'--approved-config-sha256'" in check[record:record_end]
    assert module.count("-ApprovedConfigSHA256") == 1
    install = _function_body(module, "Invoke-DefenseClawInstallLikeLifecycle")
    call = install.index("-ApprovedConfigSHA256 $approvedConfigSHA256")
    source = install.rindex("# The approved source this run installed as config.yaml (CONFIG=):", 0, call)
    block = install[source:call]
    assert "if ($Sources.ContainsKey('config') -and $Sources['config'] -is [System.Collections.IDictionary]) {" in block
    assert "$approvedConfigSHA256 = ([string]$Sources['config']['sha256']).ToLowerInvariant()" in block
    assert "if ($approvedConfigSHA256 -cnotmatch '^[0-9a-f]{64}$') {" in block
    assert "-RecordLifecycle:(-not (Test-DefenseClawLayoutBrokerEnabled -Layout $Layout))" in block
    assert "config.generation.json" not in block and "Get-FileHash" not in block


def test_bundle_repair_hint_names_the_installed_cli_without_a_bare_fallback() -> None:
    # GAP-0081: Setup puts no DefenseClaw command on PATH, so the hint must never
    # fall back to a bare defenseclaw.exe. Get-DefenseClawLayout is the only
    # producer of a layout and always sets CLIPath, so the fallback was dead.
    module = _text(MODULE)
    hint = _function_body(module, "Get-DefenseClawStandaloneBundleRepairCommand")
    assert "$cli = [string]$Layout['CLIPath']" in hint
    assert "'defenseclaw.exe'" not in hint
    assert "IsNullOrWhiteSpace" not in hint
    layout = _function_body(module, "Get-DefenseClawLayout")
    assert "CLIPath = (Microsoft.PowerShell.Management\\Join-Path $bin 'defenseclaw.exe')" in layout


def _function_body(text: str, name: str) -> str:
    start = text.index(f"function {name} ")
    return text[start : text.index("\nfunction ", start + 1)]


def test_lazy_lock_files_are_standalone_only_and_name_every_product_lock() -> None:
    # GAP-0766: Setup repair and verify stamp and judge the lazily created
    # lock files of the standalone profile, including the runtime .env lock;
    # the Secure Client profile keeps the objects it handled before.
    body = _function_body(_text(MODULE), "Get-DefenseClawLazyLockFiles")
    guard = body.index("Test-DefenseClawStandaloneProfile")
    assert guard < body.index("pscustomobject"), "the standalone guard must come first"
    for name in ("config.yaml.lock", ".enterprise-credentials.lock", ".enterprise-enrollment.lock", ".env.lock"):
        assert f"{name}" in body, name
    callers = [
        line for line in _text(MODULE).splitlines() if "Get-DefenseClawLazyLockFiles -Layout" in line
    ]
    assert len(callers) == 2, "stamp (repair) and verify both read the one list"


def test_a_lazy_lock_file_with_an_untrusted_owner_is_still_refused() -> None:
    # g877b review S5: StandaloneContentGateOutOfClass names the lazily created
    # lock files out of the content gate because "the stamp still refuses an
    # untrusted owner". Pin that: the verify judges every lock with the
    # untrusted-read rejection and the self-heal that refuses a foreign owner,
    # the smoke drives each real lock entry with a foreign owner, and the
    # exemption stays the only way a lock avoids the gate.
    module = _text(MODULE)
    start = module.index("foreach ($lockFile in @(Get-DefenseClawLazyLockFiles -Layout $Layout)) {\n        if (-not (")
    verify = module[start : module.index("\n    }\n", start + 400)]
    assert "Assert-DefenseClawPathAcl" in verify
    assert "-RejectUntrustedRead" in verify
    assert "-SelfHealKind $lockFile.Kind" in verify
    exemption = module[module.index("$script:StandaloneContentGateOutOfClass = @("):]
    exemption = exemption[: exemption.index("\n)\n")]
    assert "the stamp still refuses an untrusted owner" in exemption
    assert exemption.count("'LazyLockFiles'") == 1
    smoke = (ROOT / "packaging" / "windows" / "tests" / "enterprise-path-acl-verdict-smoke.ps1").read_text(encoding="utf-8")
    assert "Get-DefenseClawLazyLockFiles -Layout $layout" in smoke
    assert "untrusted owner, re-stamp does nothing" in smoke
    assert "untrusted owner, re-stamp fails" in smoke
    # ... and with a real file that BUILTIN\\Users owns, for every lock kind.
    assert "/setowner" in smoke and "real owner: $kind lock" in smoke


def test_codex_vendor_folder_adoption_runs_before_the_snapshot_and_tolerates_defenseclaws_own_lock() -> None:
    # g582 round 9 (the g091 round 4 integrated case): a Repair over an empty
    # administrator-made OpenAI\\Codex failed 1603 and left the transaction
    # pending, because the lifecycle snapshot wrote the Codex selector lock
    # into the folder before the adoption of its parent ran, so the folder was
    # no longer empty. The adoption now runs in the preflight, before anything
    # is written and before any service stops, and the emptiness test lets
    # DefenseClaw's own lock and state names through.
    module = _text(MODULE)
    lifecycle = _function_body(module, "Invoke-DefenseClawInstallLikeLifecycle")
    preflight = lifecycle.index("if ($priorCodexTargetEnabled) {")
    adopt = lifecycle.index("Assert-DefenseClawCodexMachinePolicyDirectory -Path $codexVendorFolder -Adopt", preflight)
    files = lifecycle.index("Assert-DefenseClawCodexMachinePolicyFilePreflight -Layout $Layout", preflight)
    snapshot = lifecycle.index("Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand", preflight)
    stopped = lifecycle.index("Stop-DefenseClawService -Name $GuardianServiceName", preflight)
    assert preflight < adopt < files < snapshot < stopped
    assert "Test-DefenseClawStandaloneProfile" in lifecycle[preflight:adopt]
    # Only install, ensure and repair adopt: the preflight and the parent
    # initialization, never the checks of verify, the guardian or a rollback.
    callers = [
        match.start()
        for match in re.finditer(r"Assert-DefenseClawCodexMachinePolicyDirectory[^\n]*-Adopt", module)
    ]
    assert len(callers) == 2

    emptiness = _function_body(module, "Test-DefenseClawEmptyAdministratorVendorFolder")
    assert "Test-DefenseClawCodexOwnFileName -Name $child.Name" in emptiness
    names = _function_body(module, "Test-DefenseClawCodexOwnFileName")
    for name in (
        ".defenseclaw-managed-runtime-selector.lock",
        ".defenseclaw-managed-hooks.writer.lock",
        ".defenseclaw-managed-hooks.state.committed",
    ):
        assert f"'{name}'" in names
    assert "'requirements.toml'" not in names
    assert r"'^\.defenseclaw-managed-hooks\.state\.[1-9][0-9]{0,7}$'" in names
