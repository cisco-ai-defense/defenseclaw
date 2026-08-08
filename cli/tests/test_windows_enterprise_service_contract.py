# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Platform-neutral release-contract checks for native Windows enterprise mode.

The destructive behavior is certified by scripts/test-windows-enterprise-
hardening.ps1 on a disposable Windows endpoint. These tests keep the critical
operator and trust-boundary wiring visible in ordinary Linux/macOS/Windows CI.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "packaging" / "windows" / "install-enterprise.ps1"
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"
HARNESS = ROOT / "scripts" / "test-windows-enterprise-hardening.ps1"
MODULE_SMOKE = ROOT / "packaging" / "windows" / "tests" / "enterprise-module-smoke.ps1"
BOOTSTRAP_SMOKE = ROOT / "packaging" / "windows" / "tests" / "enterprise-bootstrap-smoke.ps1"
BOOTSTRAP_ENVIRONMENT_SMOKE = (
    ROOT
    / "packaging"
    / "windows"
    / "tests"
    / "enterprise-bootstrap-environment-smoke.ps1"
)
UNINSTALL_TRANSACTION_SMOKE = ROOT / "packaging" / "windows" / "tests" / "enterprise-uninstall-transaction-smoke.ps1"
SELF_UNINSTALL_HELPER_CAPTURE_SMOKE = (
    ROOT
    / "packaging"
    / "windows"
    / "tests"
    / "enterprise-detached-helper-smoke.ps1"
)
DEPLOYMENT_DOC = ROOT / "docs-site" / "content" / "docs" / "setup" / "enterprise-deployment.mdx"
MATRIX_TEST = ROOT / "internal" / "gateway" / "enterprise_mode_matrix_test.go"
WINDOWS_LIFECYCLE_CLI = ROOT / "internal" / "cli" / "windows_enterprise_service.go"
DEFENSECLAW_MAIN = ROOT / "cmd" / "defenseclaw" / "main.go"
DEFENSECLAW_MAIN_TEST = ROOT / "cmd" / "defenseclaw" / "main_test.go"
WINDOWS_SERVICE_HOST = ROOT / "cmd" / "defenseclaw" / "service_windows.go"
WINDOWS_SERVICE_HOST_TEST = ROOT / "cmd" / "defenseclaw" / "service_windows_test.go"
WINDOWS_CODEX_MACHINE_POLICY = ROOT / "internal" / "gateway" / "connector" / "codex_machine_requirements_windows.go"
CODEX_MACHINE_POLICY = ROOT / "internal" / "gateway" / "connector" / "codex_machine_requirements.go"
POWERSHELL = shutil.which("pwsh.exe") or shutil.which("powershell.exe")


def read(path: Path) -> str:
    assert path.is_file(), f"required Windows enterprise artifact is missing: {path}"
    return path.read_text(encoding="utf-8")


def windows_powershell_engines() -> list[str]:
    """Return each installed Windows PowerShell/Core engine exactly once."""

    candidates: list[str | None] = [
        shutil.which("powershell.exe"),
        shutil.which("pwsh.exe"),
    ]
    windows_root = os.environ.get("SystemRoot")
    if windows_root:
        candidates.append(str(Path(windows_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"))

    engines: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate)
        if not path.is_file():
            continue
        resolved = str(path.resolve())
        key = os.path.normcase(resolved)
        if key in seen:
            continue
        seen.add(key)
        engines.append(resolved)
    return engines


def test_public_installer_exposes_complete_truthful_lifecycle() -> None:
    installer = read(INSTALLER)

    actions = re.search(r"\[ValidateSet\((?P<actions>[^)]+)\)\]", installer)
    assert actions, "installer must constrain lifecycle actions"
    for action in (
        "Install",
        "Upgrade",
        "Repair",
        "Reconcile",
        "Status",
        "Verify",
        "Uninstall",
    ):
        assert f"'{action}'" in actions.group("actions")

    assert "[switch]$AllowUnsigned" in installer
    assert "[switch]$AttestAgentApplicationControl" in installer
    assert "[switch]$AttestClaudeEffectivePolicy" in installer
    assert "[switch]$AttestCodexTrustedHookLauncher" in installer
    assert "[string]$CodexTrustedHookLauncherBinary" in installer
    assert "[switch]$CoreHardeningCertification" in installer
    assert "[switch]$Json" in installer
    assert "$exitCode = 1" in installer
    assert "if ($exitCode -ne 0)" in installer
    assert "exit $exitCode" in installer
    assert "ok = $false" in installer


def test_public_windows_lifecycle_cli_preserves_every_security_option() -> None:
    source = read(WINDOWS_LIFECYCLE_CLI)

    expected_mappings = {
        "attest-agent-application-control": "-AttestAgentApplicationControl",
        "attest-claude-effective-policy": "-AttestClaudeEffectivePolicy",
        "attest-codex-trusted-hook-launcher": "-AttestCodexTrustedHookLauncher",
        "codex-trusted-hook-launcher-binary": "-CodexTrustedHookLauncherBinary",
        "certification-codex-home": "-CertificationCodexHome",
        "core-hardening-certification": "-CoreHardeningCertification",
    }
    for cli_flag, powershell_parameter in expected_mappings.items():
        assert f'"{cli_flag}"' in source
        assert f'"{powershell_parameter}"' in source

    assert "validateWindowsEnterpriseLifecycleSecurityOptions" in source
    assert "valid only with install, upgrade, or repair" in source
    assert (
        "--attest-codex-trusted-hook-launcher and --codex-trusted-hook-launcher-binary must be supplied together"
    ) in source
    assert "They do not affect the existing per-user Windows" in source
    assert "unless an administrator explicitly invokes a lifecycle action" in source
    assert "--allow-unsigned requires --certification-codex-home" in source
    assert (
        "--core-hardening-certification requires --allow-unsigned and --certification-codex-home"
    ) in source
    assert (
        "--core-hardening-certification cannot be combined with production application-control"
    ) in source


def test_codex_machine_policy_uses_protected_bounded_file_lock() -> None:
    windows_source = read(WINDOWS_CODEX_MACHINE_POLICY)
    shared_source = read(CODEX_MACHINE_POLICY)

    assert '".defenseclaw-managed-hooks.lock"' in shared_source
    assert "windowsCodexMachineTrustedDirCheck" in windows_source
    assert "windowsCodexMachineTrustedFileCheck" in windows_source
    assert "windows.FILE_FLAG_OPEN_REPARSE_POINT" in windows_source
    assert "info.NumberOfLinks != 1" in windows_source
    assert "windows.LockFileEx(" in windows_source
    assert "windows.LOCKFILE_FAIL_IMMEDIATELY" in windows_source
    assert "windowsCodexMachineLockTimeout" in windows_source
    assert "timed out waiting %s for Codex machine policy lock" in windows_source
    assert "windows.CreateMutex" not in windows_source
    assert "DefenseClaw-CodexRequirements-" not in windows_source


def test_packaging_defaults_to_protected_scm_identities_and_roots() -> None:
    installer = read(INSTALLER)
    module = read(MODULE)

    assert "DefenseClawGateway" in installer
    assert "DefenseClawHookGuardian" in installer
    assert "[Environment+SpecialFolder]::ProgramFiles" in installer
    assert "[Environment+SpecialFolder]::CommonApplicationData" in installer
    assert "$env:ProgramFiles" not in installer
    assert "$env:ProgramData" not in installer
    assert "[Environment+SpecialFolder]::ProgramFiles" in module
    assert "[Environment+SpecialFolder]::CommonApplicationData" in module
    assert "$env:ProgramFiles" not in module
    assert "$env:ProgramData" not in module
    assert "Assert-DefenseClawBootstrapModuleTrust" in installer
    assert "DefenseClaw enterprise installer rejected its module before import" in installer
    assert "AllowUnsigned = [bool](" in installer
    assert (
        "$AllowUnsigned -and $Action -in @('Install', 'Upgrade', 'Repair', 'Uninstall')"
        in installer
    )
    # The config directory carries a gateway-service read ACE, so the verifier
    # must assert it against the gateway reader set. Listing it as
    # administrator-only rejects the ACE the installer just wrote.
    assert "-RequiredRights $configDirectoryRights" in module
    assert (
        "        -Path $Layout.ConfigDirectory `\n"
        "        -AllowedWriterSIDs $adminWriters `\n"
        "        -AllowedReaderSIDs $gatewayReaders `\n"
        "        -RequiredRights $configDirectoryRights `\n"
        "        -RejectUntrustedRead" in module
    )
    assert (
        "    foreach ($path in @(\n"
        "        $Layout.GuardianDirectory,\n"
        "        $Layout.InstallStateDirectory,\n"
        "        $Layout.ManifestPath,\n"
        "        $Layout.LogDirectory,\n"
        "        $Layout.GuardianLogDirectory,\n"
        "        $Layout.MetadataPath,\n"
        "        $Layout.CodexTrustedShellAttestationPath\n"
        "    )) {" in module
    )
    assert "Initialize-DefenseClawCodexMachinePolicyParent" in module
    assert "Invoke-DefenseClawCodexRequirementsCommand" in module
    assert "codex-requirements-ownership.json" in module
    assert ".defenseclaw-managed-hooks.state" in module
    assert "agent-application-control-attestation.json" in module
    assert "[switch]$AttestAgentApplicationControl" in installer
    assert "[switch]$AttestCodexTrustedHookLauncher" in installer
    assert "AttestCodexTrustedShellEnforcement" not in installer
    assert "AttestCodexApplicationControl" not in installer
    assert "$script:AgentApplicationControlAttestationSchemaVersion = 2" in module
    assert "agent_application_control_enforced = [bool]$Layout.AgentApplicationControlAttested" in module
    assert "codex_trusted_hook_launcher_prerequisite" in module
    assert "codex_trusted_hook_launcher_verified" in module
    assert "stock_codex_supported = $false" in module
    attestation_writer = module[
        module.index("function Write-DefenseClawCodexTrustedShellAttestation") : module.index(
            "function Initialize-DefenseClawCodexMachinePolicyParent"
        )
    ]
    assert "trusted_shell_enforced" not in attestation_writer
    assert "minimum_codex_version" not in attestation_writer
    assert "DEFENSECLAW_WINDOWS_CODEX_TRUSTED_SHELL_ENFORCED" not in module
    assert "DEFENSECLAW_WINDOWS_CODEX_TRUSTED_HOOK_LAUNCHER_VERIFIED=1" in module
    assert "DEFENSECLAW_WINDOWS_CODEX_APPROVED_CLIENT_ENFORCED=1" in module
    assert "DEFENSECLAW_WINDOWS_APPROVED_AGENT_CLIENTS_ENFORCED=1" in module
    assert "DEFENSECLAW_WINDOWS_CLAUDE_EFFECTIVE_POLICY_VERIFIED=1" in module
    service_environment = module[
        module.index("function Get-DefenseClawServiceEnvironmentValues") : module.index(
            "function Set-DefenseClawServiceEnvironment"
        )
    ]
    assert "CODEX_HOME" not in service_environment
    assert "created_shared_directories" in module
    assert "Remove-DefenseClawTransactionCreatedSharedDirectories" in module
    assert "shared global vendor state" in module
    assert "'obj=', 'LocalSystem'" in module
    assert '"NT SERVICE\\$GatewayServiceName"' in module
    assert "DEFENSECLAW_DEPLOYMENT_MODE=managed_enterprise" in module
    assert "$configuredStart = if ($DeferAutomaticStart) { 'disabled' } else { 'auto' }" in module
    assert "'start=', $configuredStart" in module
    assert "Set-DefenseClawServiceStartMode" in module
    assert "$expectedStartMode = if ($ServicingTransaction)" in module
    assert "elseif ($PendingTransaction)" in module
    assert "[switch]$ServicingTransaction" in module
    assert "-StartMode 4" in module
    assert "-StartMode 3" in module
    assert "-StartMode 2" in module
    assert "'failureflag', $service, '1'" in module
    assert "'sdset', $service, $script:ServiceSDDL" in module


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
def test_poisoned_program_root_environment_cannot_redirect_defaults(
    tmp_path: Path,
) -> None:
    assert POWERSHELL
    common = [
        POWERSHELL,
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
    ]
    known = subprocess.run(
        [
            *common,
            "-Command",
            (
                "[pscustomobject]@{"
                "program_files=[Environment]::GetFolderPath("
                "[Environment+SpecialFolder]::ProgramFiles);"
                "program_data=[Environment]::GetFolderPath("
                "[Environment+SpecialFolder]::CommonApplicationData);"
                "windows=[Environment]::GetFolderPath("
                "[Environment+SpecialFolder]::Windows)"
                "}|ConvertTo-Json -Compress"
            ),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
    )
    assert known.returncode == 0, known.stderr
    expected = json.loads(known.stdout)

    poison_program_files = tmp_path / "poison-program-files"
    poison_program_data = tmp_path / "poison-program-data"
    poison_files_ps = str(poison_program_files).replace("'", "''")
    poison_data_ps = str(poison_program_data).replace("'", "''")
    installer_ps = str(INSTALLER).replace("'", "''")
    harness_ps = str(HARNESS).replace("'", "''")
    payload_binary = Path(expected["windows"]) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    assert payload_binary.is_file()
    payload_binary_ps = str(payload_binary).replace("'", "''")
    evidence_ps = str(tmp_path / "evidence").replace("'", "''")

    installer_status = subprocess.run(
        [
            *common,
            "-Command",
            (
                "Import-Module Microsoft.PowerShell.Security -ErrorAction Stop;"
                f"$env:ProgramFiles='{poison_files_ps}';"
                    f"$env:ProgramData='{poison_data_ps}';"
                    f"& '{installer_ps}' -Action Status "
                    "-GatewayServiceName DefenseClawGateway "
                    "-GuardianServiceName DefenseClawHookGuardian -Json"
                ),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
    )
    if installer_status.returncode == 0:
        status = json.loads(installer_status.stdout)
        assert Path(status["install_root"]) == (Path(expected["program_files"]) / "Cisco" / "DefenseClaw")
        assert Path(status["state_root"]) == (Path(expected["program_data"]) / "Cisco" / "DefenseClaw")
    else:
        # A repository checkout is normally user-writable and unsigned. The
        # bootstrap must reject that adjacent module before import; production
        # callers first copy both files to protected approved staging.
        diagnostic = installer_status.stdout + "\n" + installer_status.stderr
        assert re.search(
            r"(?i)rejected its module before import|Authenticode|untrusted owner|"
            r"replacement access|write-like access",
            diagnostic,
        )

    harness_plan = subprocess.run(
        [
            *common,
            "-Command",
            (
                "Import-Module Microsoft.PowerShell.Security -ErrorAction Stop;"
                f"$env:ProgramFiles='{poison_files_ps}';"
                f"$env:ProgramData='{poison_data_ps}';"
                f"& '{harness_ps}' "
                f"-GatewayBinary '{payload_binary_ps}' "
                f"-HookBinary '{payload_binary_ps}' "
                f"-CLIBinary '{payload_binary_ps}' "
                f"-CodexBinary '{payload_binary_ps}' "
                f"-CodexTrustedHookLauncherBinary '{payload_binary_ps}' "
                f"-ClaudeBinary '{payload_binary_ps}' "
                f"-RejectedCodexBinary '{payload_binary_ps}' "
                f"-RejectedClaudeBinary '{payload_binary_ps}' "
                f"-InstallerPath '{installer_ps}' "
                f"-EvidenceRoot '{evidence_ps}'"
            ),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
    )
    assert harness_plan.returncode == 0, harness_plan.stderr
    plan = json.loads(harness_plan.stdout)
    assert Path(plan["install_root"]).parent == (Path(expected["program_files"]) / "Cisco" / "DefenseClaw-Cert")
    assert Path(plan["state_root"]).parent == (Path(expected["program_data"]) / "Cisco" / "DefenseClaw-Cert")
    assert Path(plan["staging_root"]).parent == (Path(expected["program_data"]) / "Cisco" / "DefenseClaw-Cert-Staging")
    assert Path(plan["work_root"]).parent == (Path(expected["program_data"]) / "Cisco" / "DefenseClaw-Cert-Work")
    assert Path(plan["codex_vendor_directory"]) == (Path(expected["program_data"]) / "OpenAI")
    assert Path(plan["codex_machine_policy_directory"]) == (Path(expected["program_data"]) / "OpenAI" / "Codex")
    assert plan["lifecycle_scope_matrix"] == {
        "full_unsigned": {
            "action": "install|upgrade|repair",
            "certification_codex_home": True,
            "allow_unsigned": True,
            "core_hardening_certification": False,
        },
        "claude_only_unsigned": {
            "action": "install|upgrade|repair",
            "certification_codex_home": True,
            "allow_unsigned": True,
            "core_hardening_certification": True,
        },
        "signed_production": {
            "action": "install|upgrade|repair",
            "certification_codex_home": False,
            "allow_unsigned": False,
            "core_hardening_certification": False,
        },
        "read_only": {
            "action": "status|verify|reconcile|uninstall",
            "certification_codex_home": False,
            "allow_unsigned": False,
            "core_hardening_certification": False,
        },
    }
    assert not poison_program_files.exists()
    assert not poison_program_data.exists()


def test_certification_uses_active_token_without_requesting_user_password() -> None:
    harness = read(HARNESS)

    assert "[string]$ProtectedUserSID" in harness
    assert "ProtectedUserCredential" not in harness
    assert "WTSConnectState]::Active" in harness
    assert "New-ActiveUserScheduledTaskPrincipal" in harness
    assert "-UserId $script:PrimarySID" in harness
    assert "-LogonType Interactive" in harness
    assert "-RunLevel Limited" in harness
    assert "$task.RunEx(" in harness
    assert "[int]0x0C" in harness
    assert "[int]$script:PrimarySessionID" in harness
    assert harness.count(
        "Start-CertificationScheduledTaskInActiveSession $taskName"
    ) == 6
    assert "Start-ScheduledTask -TaskName $taskName" not in harness
    assert "no active interactive session token" not in harness


def test_active_user_results_use_pid_bound_administrator_owned_pipe() -> None:
    harness = read(HARNESS)
    capture = harness[
        harness.index("function Initialize-ActiveUserCapturePipeNative") :
        harness.index("function Start-ActiveUserFakeGatewayListener")
    ]

    assert "GetNamedPipeClientProcessId" in capture
    assert "NamedPipeServerStreamAcl" in capture
    assert "$security.SetOwner($administrators)" in capture
    assert "'S-1-5-18'" in capture
    assert "'S-1-5-32-544'" in capture
    assert "Get-ScheduledTaskEngineProcessIDs" in capture
    assert "Assert-ProtectedActiveUserCaptureTaskSecurity" in capture
    assert "'O:BAG:BAD:P'" in capture
    assert "'(A;;FA;;;SY)'" in capture
    assert "'(A;;FA;;;BA)'" in capture
    assert '"(A;;FRFX;;;$($script:PrimarySID))"' in capture
    assert "$task.GetSecurityDescriptor(7)" in capture
    assert "$aces.Count -ne 3" in capture
    assert "$enginePIDs[0] -ne $clientPID" in capture
    assert "[uint32]$launch.EnginePID -ne $clientPID" in capture
    assert "[string]$clientProcess.ExecutablePath" in capture
    assert "$script:PrimarySessionID" in capture
    assert "[string]$done.nonce -cne $nonce" in capture
    assert "[string]$done.sid -ne $script:PrimarySID" in capture
    assert "[uint32]$done.pid -ne $clientPID" in capture
    assert "$maximumCaptureBytes = 8 * 1024 * 1024" in capture
    assert "$capturedBytes +=" in capture
    assert "$captureExceeded = $true" in capture
    assert "ReadToEndAsync" not in capture
    assert "CaptureTaskPIDBound = $true" in capture
    assert "CaptureUserWritableFilesTrusted = $false" in capture
    assert "exit 251" in capture
    assert harness.count(
        "[uint32]$readyJSON.pid -ne [uint32]$launch.EnginePID"
    ) == 5

    # High-stakes probe output must cross the authenticated pipe directly.
    # The tested standard user must not be able to forge an elevated reader's
    # completion marker or stdout/stderr file. Large input scripts may use
    # administrator-owned, target-read-only files so the scheduled-task and
    # nested process command lines remain bounded.
    invocation = capture[
        capture.index("function Invoke-ActiveUserPowerShell") :
    ]
    assert "Read-ExactActiveUserCapturePipe" in invocation
    assert "Get-Content" not in invocation
    assert ".stdout.log" not in invocation
    assert ".stderr.log" not in invocation
    assert ".complete.json" not in invocation
    assert '"*$($script:PrimarySID):(OI)(CI)RX"' in invocation
    assert "Assert-NoStandardUserAccess" in invocation
    assert "-DenyWrite" in invocation
    assert "script_sha256 = $scriptSHA256" in invocation
    assert "active-user task command line exceeds its bound" in invocation
    assert "-EncodedCommand $wrapperEncoded" not in invocation


def test_certification_scheduled_tasks_are_removed_fail_closed() -> None:
    harness = read(HARNESS)
    helper = harness[
        harness.index("function Assert-CertificationScheduledTaskName") :
        harness.index("function Assert-ProtectedActiveUserCaptureTaskSecurity")
    ]

    assert "$script:RunToken -cnotmatch '^[a-f0-9]{10}$'" in helper
    assert "[regex]::Escape($script:RunToken)" in helper
    assert "$TaskName.Length -gt 238" in helper
    assert "$TaskName -cnotmatch $pattern" in helper
    assert "$script:ScheduledTasks.Contains($safeTaskName)" in helper
    assert helper.count("Stop-ScheduledTask") == 1
    assert helper.count("Unregister-ScheduledTask") == 1
    assert helper.count("-TaskPath '\\'") == 3
    assert "-ErrorAction SilentlyContinue" not in helper
    assert "Stopping is best-effort" in helper
    assert "Get-ScheduledTask -ErrorAction Stop" in helper
    assert "[string]$_.TaskName -ceq $safeTaskName" in helper
    assert "[string]$_.TaskPath -ceq '\\'" in helper
    assert "$remaining.Count -ne 0" in helper
    assert helper.index("Unregister-ScheduledTask") < helper.index("$remaining = @(")
    assert helper.index("$remaining = @(") < helper.index(
        "$script:ScheduledTasks.Remove($safeTaskName)"
    )

    # Individual fixtures must not be able to bypass the central fail-closed
    # teardown path.
    assert harness.count("Stop-ScheduledTask") == 1
    assert harness.count("Unregister-ScheduledTask") == 1
    assert harness.count("$script:ScheduledTasks.Remove(") == 1
    assert "Remove-CertificationScheduledTask ([string]$Listener.TaskName)" in harness
    assert "Remove-CertificationScheduledTask ([string]$Squatter.TaskName)" in harness
    assert "Remove-CertificationScheduledTask ([string]$Holder.TaskName)" in harness
    assert "Remove-CertificationScheduledTask ([string]$Attack.TaskName)" in harness
    assert "Remove-CertificationScheduledTask ([string]$Probe.TaskName)" in harness

    cleanup = harness[
        harness.index("function Invoke-BoundedCleanup") :
        harness.index("function Write-FinalEvidence")
    ]
    assert "Remove-CertificationScheduledTask $taskName" in cleanup
    assert (
        '$certificationTaskPrefix = "DefenseClawCert_$($script:RunToken)_"'
        in cleanup
    )
    assert "Get-ScheduledTask -ErrorAction Stop" in cleanup
    assert ".StartsWith(" in cleanup
    assert "[StringComparison]::Ordinal" in cleanup
    assert "certification scheduled tasks remain after cleanup" in cleanup
    assert "$script:ScheduledTasks.Count -ne 0" in cleanup
    assert "scheduled-task final sweep" in cleanup
    assert cleanup.index("Remove-CertificationScheduledTask $taskName") < cleanup.index(
        "$remainingCertificationTasks = @("
    )


def test_certification_preserves_canonical_user_trees_exactly() -> None:
    harness = read(HARNESS)

    assert "[Environment+SpecialFolder]::ProgramFiles" in harness
    assert "[Environment+SpecialFolder]::CommonApplicationData" in harness
    assert "$env:ProgramFiles" not in harness
    assert "$env:ProgramData" not in harness
    assert "(Join-Path $script:PrimaryProfile '.defenseclaw')" in harness
    assert ".defenseclaw-cert-$($script:RunToken)" not in harness
    assert "New-ProtectedUserTreeSnapshot" in harness
    assert "Restore-ProtectedUserTreeSnapshot" in harness
    assert "GetSecurityDescriptorSddlForm" in harness
    assert "SetSecurityDescriptorSddlForm" in harness
    assert "contains a reparse point that cannot be snapshotted safely" in harness
    assert "snapshot stability" in harness
    assert "Assert-SameUserTreeInventory" in harness
    assert "preinstall-normal-mode-is-no-op" in harness
    assert "deployment_mode: unmanaged_byod" in harness
    assert "enabled=false" in harness
    assert "Get-DefenseClawServiceInventory" in harness


def test_certification_routes_generic_mutation_through_localsystem_guardian() -> None:
    harness = read(HARNESS)

    assert "Invoke-GuardianServiceReconcile" in harness
    assert "-Action Reconcile" in harness
    assert "administrator-direct-generic-reconcile-denied" in harness
    assert "LocalSystem|guardian" in harness

    # The only direct elevated generic reconcile is the negative authorization
    # probe. Successful mutation must never use Invoke-GatewayJSON reconcile.
    assert not re.search(
        r"Invoke-GatewayJSON\s+`\s*\r?\n\s*-Arguments\s+@\("
        r"'enterprise',\s*'hooks',\s*'reconcile'",
        harness,
    )


def test_certification_activates_disabled_staging_only_through_public_repair() -> None:
    harness = read(HARNESS)

    assert "function Start-CertificationServicesAfterIsolationProof" not in harness
    assert "function Invoke-CertificationActivationRepairAfterIsolationProof" in harness
    activation = harness[
        harness.index("function Invoke-CertificationActivationRepairAfterIsolationProof") : harness.index(
            "function Get-ServiceControlSnapshot"
        )
    ]
    assert "[string]$service.StartMode -ne 'Disabled'" in harness
    assert "gateway became startable before the public Repair guardian" in activation
    assert "Start-Service -Name $script:GatewayServiceName -ErrorAction Stop" in activation
    assert "Start-Service -Name $script:GuardianServiceName" not in activation
    assert "libexec\\install-enterprise.ps1" in activation
    assert "libexec\\DefenseClawEnterprise.psm1" in activation
    assert "bin\\defenseclaw.exe" in activation
    assert "'enterprise', 'windows', 'repair'" in activation
    assert "$arguments.Add('--core-hardening-certification')" in activation
    assert "if ($ClaudeOnly)" in activation
    assert "installed-public-repair-first-activation" in activation
    assert "guardian_generation" in activation
    assert "replacement_sources_supplied = @()" in activation
    for replacement_flag in (
        "'--gateway-binary'",
        "'--hook-binary'",
        "'--cli-binary'",
        "'--config'",
        "'--manifest'",
    ):
        assert replacement_flag not in activation
    assert "Invoke-EnterpriseLifecycleCLIJSON" in activation
    assert "elevated_powershell_temp_boundary" in activation
    assert "Get-EnterprisePowerShellTempSnapshot" in harness
    assert "Start-ActiveUserEnterprisePowerShellTempProbe" in harness
    assert "DefenseClaw-PowerShell-[a-f0-9]{32}" in harness
    assert "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" in harness
    for operation in ("'read'", "'create'", "'change_dacl'", "'delete'"):
        assert f"operation = {operation}" in harness
    assert "exact_residual_snapshot_preserved = $true" in harness
    assert "medium_user_all_denied = $true" in harness
    assert "secret_material_recorded = $false" in harness

    install_check = harness[
        harness.index("Invoke-Check 'enterprise-installer-install'") : harness.index(
            "Invoke-Check 'codex-shared-parent-provisioning'"
        )
    ]
    assert "-NoStart" in install_check
    assert "core_hardening_complete=false" in install_check
    assert "Invoke-CertificationActivationRepairAfterIsolationProof" in install_check


def test_certification_exercises_tamper_and_full_scm_denial_surface() -> None:
    harness = read(HARNESS)

    for operation in (
        "'stop'",
        "'pause'",
        "'control128'",
        "'config'",
        "'failure'",
        "'sdset'",
        "'delete'",
    ):
        assert f"name = {operation}" in harness
    assert "ERROR_ACCESS_DENIED=5" in harness
    assert "name = 'suspend_resume'" in harness
    assert "name = 'inject_thread_vm'" in harness
    assert "name = 'all_access'" in harness
    assert "0x001F0FFF" in harness
    assert "OpenProcessToken(" in harness
    assert "name = 'all_mutation'" in harness
    assert "0x000C00E7" in harness
    assert "open_process_query_limited_" in harness
    assert "taskkill_process_" in harness
    assert "hostile process-termination probe" in harness
    assert "CreateFileW DELETE error" in harness
    assert "Test-DeleteHandle ('delete_handle_'" in harness
    assert "write_service_token" in harness
    assert "Assert-SameServiceControlSnapshot" in harness
    assert "hostile unregister probe changed the protected authorization ledger" in harness

    assert "deleted_hook_token" in harness
    assert "deleted_connector_hookcfg" in harness
    assert "modified_hookcfg" in harness
    assert "modified_contract_lock" in harness
    assert "previously-authorized-root-obstruction-repair" in harness
    assert "Invoke-ActiveUserCanonicalRootObstruction" in harness
    assert "authorized-obstruction-outside" in harness
    assert "canonical root junction" in harness
    assert "Assert-SameUserTreeInventory" in harness
    assert "Copy-CertificationSourceToProtectedStaging" in harness
    assert "stage-enterprise-installer" in harness
    assert "stage-enterprise-module" in harness
    assert "Protect-AdministratorFile" in harness
    assert "post-snapshot-activation-failure-rolls-back" in harness
    assert "api_bind: 0.0.0.0" in harness
    assert "Assert-SameServiceControlSnapshot" in harness
    assert "evidence-secret-hygiene" in harness
    assert "Protect-TreeFromRegisteredSecretLeak" in harness


def test_certification_exercises_bounded_sparse_runtime_recovery() -> None:
    harness = read(HARNESS)

    assert "Test-ManagedSparseOversizedArtifactRecovery" in harness
    assert "Start-ActiveUserSparseArtifactAttack" in harness
    assert "Stop-ActiveUserSparseArtifactAttack" in harness
    assert "FSCTL_SET_SPARSE" in harness
    assert "$script:SparseAttackLogicalBytes = [int64]1099511627776" in harness
    assert "$script:SparseAttackMaxAllocatedBytes = [int64]1048576" in harness
    assert "$script:SparseAttackMaxGuardianWorkingSetGrowthBytes = [int64]268435456" in harness
    assert "PeakWorkingSet64" in harness
    assert "guardian_lifetime_peak_working_set_growth_bytes" in harness
    assert "guardian_lifetime_peak_working_set_growth_limit_bytes" in harness
    assert "$encoded.Length -gt 30000" in harness
    assert "Task Scheduler argument budget" in harness
    for artifact in (
        "managed_token",
        "hookcfg_json",
        "flat_sidecar",
        "hook_contract_lock",
        "hook_helper_script",
    ):
        assert f"name = '{artifact}'" in harness
    assert "status_unhealthy_during_attack = $true" in harness
    assert "verify_unhealthy_during_attack = $true" in harness
    assert "guardian_pid_unchanged = $true" in harness
    assert "quarantine_rename_observed" in harness
    assert "exact_bytes_restored = $true" in harness
    assert "exact_owner_and_dacl_restored = $true" in harness
    assert "secret_material_recorded = $false" in harness
    assert "guardian-sparse-oversized-runtime-auto-heal" in harness
    hardlink_probe = harness[
        harness.index("function Test-GuardianRepairsManagedHardLink") : harness.index(
            "function Get-GuardianResourceObservation"
        )
    ]
    assert "$ClaudeOnly" in hardlink_probe
    assert "'hooks\\.hook-claudecode.token'" in hardlink_probe
    assert "'hooks\\.hook-codex.token'" in hardlink_probe


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
@pytest.mark.parametrize(
    ("script", "required_fields"),
    (
        (
            MODULE_SMOKE,
            (
                "ambient_cmdlet_shadow_ignored",
                "fixed_native_helper_spoof_ignored",
                "certification_scope_rejections",
            ),
        ),
        (
            BOOTSTRAP_SMOKE,
            (
                "untrusted_module_rejected_before_import",
                "fixed_helper_spoof_ignored",
                "production_unsigned_scope_rejected_before_import",
                "raw_dos_device_medium_user",
                "raw_dos_device_cases",
                "raw_dos_device_rejected_before_import",
                "raw_dos_device_no_roots_or_temp",
                "raw_dos_device_cleanup_verified",
                "canonical_system_drive_accepted",
                "raw_dos_device_native_probe_rejected",
                "whole_volume_alias_native_probe_rejected",
                "whole_volume_alias_cleanup_verified",
                "module_canonical_system_drive_accepted",
                "module_raw_subdirectory_alias_rejected",
                "module_raw_whole_volume_alias_rejected",
            ),
        ),
        (
            BOOTSTRAP_ENVIRONMENT_SMOKE,
            (
                "engine",
                "elevated",
                "exact_acl",
                "all_environment_paths_pinned",
                "module_analysis_cache_disabled",
                "nested_cleanup_verified",
                "environment_restore_verified",
                "hostile_fixture_cleanup_verified",
                "existing_collision_rejected_without_acl_seizure",
                "concurrent_workers",
                "concurrent_roots_unique",
                "concurrent_cleanup_verified",
            ),
        ),
        (
            UNINSTALL_TRANSACTION_SMOKE,
            (
                "recovery_cases",
                "quiescing_cases",
                "uninstall_cases",
                "shared_directory_cases",
            ),
        ),
        (
            SELF_UNINSTALL_HELPER_CAPTURE_SMOKE,
            (
                "engine",
                "capture_elapsed_ms",
                "capture_deadline_ms",
                "helper_pid",
                "helper_alive_after_capture",
                "no_inherited_capture_handles",
                "protected_environment_pinned",
                "module_analysis_cache_disabled",
                "environment_root_retired",
            ),
        ),
    ),
    ids=(
        "module",
        "bootstrap",
        "bootstrap-environment",
        "uninstall-transaction",
        "helper-capture",
    ),
)
@pytest.mark.parametrize(
    "engine",
    windows_powershell_engines() or (None,),
    ids=lambda engine: Path(engine).stem if engine else "missing",
)
def test_windows_packaging_smokes_run_on_every_available_engine(
    engine: str | None,
    script: Path,
    required_fields: tuple[str, ...],
) -> None:
    assert engine, "Windows CI must provide Windows PowerShell 5.1 or PowerShell 7"
    if script == BOOTSTRAP_SMOKE and os.environ.get("GITHUB_ACTIONS") == "true":
        pytest.skip(
            "the required public-bootstrap-acceptance job runs under a real "
            "disposable standard user"
        )
    repository_cache = ROOT / "Microsoft"
    assert not repository_cache.exists(), (
        f"PowerShell smoke started with repository cache residue: {repository_cache}"
    )
    with tempfile.TemporaryDirectory(
        prefix="DefenseClaw-PowerShellSmoke-",
        dir=os.environ.get("TEMP"),
    ) as temporary_profile:
        profile_root = str(Path(temporary_profile).resolve())
        volume, home_path = os.path.splitdrive(profile_root)
        smoke_environment = os.environ.copy()
        for name in (
            "TEMP",
            "TMP",
            "TMPDIR",
            "LOCALAPPDATA",
            "APPDATA",
            "USERPROFILE",
            "HOME",
            "XDG_CACHE_HOME",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "DOTNET_CLI_HOME",
            "NUGET_PACKAGES",
        ):
            smoke_environment[name] = profile_root
        smoke_environment["HOMEDRIVE"] = volume
        smoke_environment["HOMEPATH"] = home_path
        smoke_environment["PSModuleAnalysisCachePath"] = "NUL"
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
            env=smoke_environment,
            capture_output=True,
            text=True,
            encoding="utf-8-sig",
            errors="replace",
            timeout=600,
            check=False,
        )
    assert not repository_cache.exists(), (
        f"{Path(engine).name} {script.name} wrote outside its disposable "
        f"profile: {repository_cache}"
    )
    assert completed.returncode == 0, (
        f"{Path(engine).name} {script.name} failed with "
        f"{completed.returncode}\nstdout:\n{completed.stdout}\n"
        f"stderr:\n{completed.stderr}"
    )
    try:
        report = json.loads(completed.stdout.strip())
    except json.JSONDecodeError as error:
        raise AssertionError(f"{Path(engine).name} {script.name} emitted invalid JSON: {completed.stdout!r}") from error
    assert report["schema_version"] == 1
    assert report["ok"] is True
    for field in required_fields:
        assert field in report, f"{Path(engine).name} {script.name} omitted {field}"
    if script == UNINSTALL_TRANSACTION_SMOKE:
        assert report["recovery_cases"]
        assert report["quiescing_cases"]
        assert report["uninstall_cases"]
        shared_directory_cases = {
            case["name"]: case for case in report["shared_directory_cases"]
        }
        # Rollback must clear a directory holding only the transaction's own
        # serialization lock, and must still refuse one holding anything else.
        assert shared_directory_cases["empty"]["removed"] is True
        assert shared_directory_cases["serialization-lock-only"]["removed"] is True
        retained = shared_directory_cases["foreign-content-retained"]
        assert retained["removed"] is False
        assert "non-empty transaction-created shared directory" in retained["failure"]
    if script == BOOTSTRAP_SMOKE:
        assert report["raw_dos_device_medium_user"] is True
        assert [case["name"] for case in report["raw_dos_device_cases"]] == [
            "installer_module_path",
            "whole_volume_installer_module_path",
            "install_root",
            "state_root",
            "certification_home",
        ]
        assert all(
            case["rejected_before_module_import"] is True
            and case["managed_roots_absent"] is True
            for case in report["raw_dos_device_cases"]
        )
        assert report["raw_dos_device_rejected_before_import"] is True
        assert report["raw_dos_device_no_roots_or_temp"] is True
        assert report["raw_dos_device_cleanup_verified"] is True
        assert report["canonical_system_drive_accepted"] is True
        assert report["raw_dos_device_native_probe_rejected"] is True
        assert report["whole_volume_alias_native_probe_rejected"] is True
        assert report["whole_volume_alias_cleanup_verified"] is True
        assert report["module_canonical_system_drive_accepted"] is True
        assert report["module_raw_subdirectory_alias_rejected"] is True
        assert report["module_raw_whole_volume_alias_rejected"] is True
    if script == BOOTSTRAP_ENVIRONMENT_SMOKE:
        assert report["exact_acl"] is True
        assert report["all_environment_paths_pinned"] is True
        assert report["module_analysis_cache_disabled"] is True
        assert report["nested_cleanup_verified"] is True
        assert report["environment_restore_verified"] is True
        assert report["hostile_fixture_cleanup_verified"] is True
        assert report["existing_collision_rejected_without_acl_seizure"] is True
        assert int(report["concurrent_workers"]) == 6
        assert report["concurrent_roots_unique"] is True
        assert report["concurrent_cleanup_verified"] is True
    if script == SELF_UNINSTALL_HELPER_CAPTURE_SMOKE:
        assert 0 < int(report["capture_elapsed_ms"]) < int(report["capture_deadline_ms"])
        assert int(report["helper_pid"]) > 0
        assert report["helper_alive_after_capture"] is True
        assert report["no_inherited_capture_handles"] is True
        assert report["protected_environment_pinned"] is True
        assert report["module_analysis_cache_disabled"] is True
        assert report["environment_root_retired"] is True


def test_bootstrap_rejects_raw_per_logon_dos_device_aliases() -> None:
    bootstrap = read(INSTALLER)
    module = read(MODULE)
    smoke = read(BOOTSTRAP_SMOKE)

    assert "GetVolumeNameForVolumeMountPointW" in bootstrap
    assert "GetVolumePathNamesForVolumeNameW" in bootstrap
    assert "QueryDosDeviceW" in bootstrap
    assert "public static void AssertCanonicalDriveRoot" in bootstrap
    assert 'QueryDevice(@"Global\\" + drive)' in bootstrap
    assert "bootstrap DOS drive target differs from its global authoritative volume" in bootstrap
    assert "bootstrap DOS drive root is not registered with Mount Manager" in bootstrap
    assert bootstrap.count("::AssertCanonicalDriveRoot($driveRoot, $driveID)") >= 4
    assert bootstrap.count("[Guid]::NewGuid().ToString('N')") >= 1

    assert "public static string AssertCanonicalDriveRoot" in module
    assert 'QueryDevice(@"Global\\" + drive)' in module
    assert "managed DOS drive target differs from its global authoritative volume" in module
    logical_disk = module[
        module.index("function Get-DefenseClawLogicalDisk") : module.index(
            "function Resolve-DefenseClawFullPath"
        )
    ]
    assert logical_disk.count("::AssertCanonicalDriveRoot($root, $drive)") == 2
    assert "managed path drive identity changed during validation" in logical_disk

    assert "DefineDosDeviceW" in smoke
    assert "DDD_RAW_TARGET_PATH" in smoke
    assert "DDD_EXACT_MATCH_ON_REMOVE" in smoke
    assert "DDD_NO_BROADCAST_SYSTEM" in smoke
    assert "S-1-16-8192" in smoke
    assert "effective medium-integrity non-admin user" in smoke
    assert "Get-ProductionBootstrapNativePathType" in smoke
    assert "$productionNativePathType::AssertCanonicalDriveRoot" in smoke
    assert "canonical_system_drive_accepted = $canonicalSystemDriveAccepted" in smoke
    assert "raw_dos_device_native_probe_rejected = $rawAliasNativeProbeRejected" in smoke
    assert "whole_volume_alias_native_probe_rejected" in smoke
    assert "whole_volume_alias_cleanup_verified" in smoke
    assert "Invoke-ProductionModuleLogicalDiskAliasProbe" in smoke
    assert "module_canonical_system_drive_accepted" in smoke
    assert "module_raw_subdirectory_alias_rejected" in smoke
    assert "module_raw_whole_volume_alias_rejected" in smoke
    for case in (
        "installer_module_path",
        "whole_volume_installer_module_path",
        "install_root",
        "state_root",
        "certification_home",
    ):
        assert f"name = '{case}'" in smoke
    assert "rejected_before_module_import = $true" in smoke
    assert "managed_roots_absent = $true" in smoke
    assert "Get-RawAliasFixtureInventory" in smoke
    assert "raw_dos_device_no_roots_or_temp = $true" in smoke
    assert "[DefenseClaw.Windows.Tests.RawDosDeviceNative]::RemoveRaw" in smoke
    assert "[DefenseClaw.Windows.Tests.RawDosDeviceNative]::RemoveAny" in smoke
    assert "raw_dos_device_cleanup_verified = $rawAliasCleanupVerified" in smoke


def test_bootstrap_compiler_environment_is_one_shot_and_protected() -> None:
    bootstrap = read(INSTALLER)
    smoke = read(BOOTSTRAP_ENVIRONMENT_SMOKE)

    assert "function New-DefenseClawBootstrapEnvironment" in bootstrap
    assert "function Remove-DefenseClawBootstrapEnvironment" in bootstrap
    assert "function Restore-DefenseClawBootstrapEnvironment" in bootstrap
    assert "DefenseClaw-Bootstrap-$capability" in bootstrap
    assert "[Security.Cryptography.RandomNumberGenerator]::Create()" in bootstrap
    assert "$bytes = [byte[]]::new(16)" in bootstrap
    assert "$security.SetAccessRuleProtection($true, $false)" in bootstrap
    assert "[Security.AccessControl.FileSystemRights]::FullControl" in bootstrap
    assert "Assert-DefenseClawBootstrapOneShotRoot" in bootstrap
    assert "Assert-DefenseClawBootstrapCleanupEntry" in bootstrap
    assert "refusing bootstrap cleanup through a reparse point" in bootstrap
    for variable in (
        "TEMP",
        "TMP",
        "TMPDIR",
        "LOCALAPPDATA",
        "APPDATA",
        "USERPROFILE",
        "HOME",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "DOTNET_CLI_HOME",
        "NUGET_PACKAGES",
    ):
        assert f"'{variable}'" in bootstrap
    assert "'PSModuleAnalysisCachePath'" in bootstrap
    assert "'NUL'" in bootstrap
    assert "$bootstrapEnvironment = New-DefenseClawBootstrapEnvironment" in bootstrap
    cleanup = bootstrap[bootstrap.index("finally {", bootstrap.index("$bootstrapEnvironment = $null")) :]
    assert cleanup.index("Remove-DefenseClawBootstrapEnvironment") < cleanup.index(
        "Restore-DefenseClawBootstrapEnvironment"
    )

    assert "existing_collision_rejected_without_acl_seizure" in smoke
    assert "concurrent_workers = 6" in smoke
    assert "concurrent_roots_unique = $true" in smoke
    assert "concurrent_cleanup_verified = $true" in smoke
    assert "nested_cleanup_verified" in smoke
    assert "environment_restore_verified" in smoke
    assert "DefenseClaw-BootstrapHostile-$probeToken" in smoke
    assert "$originalEnvironment[$name]" in smoke
    assert "[IO.Directory]::Delete($hostileRoot, $true)" in smoke
    assert "hostile_fixture_cleanup_verified" in smoke
    assert '"hostile-*-$name"' in smoke
    assert "$pinned" not in bootstrap
    assert "Restore-DefenseClawBootstrapEnvironment -Context $context" in bootstrap


def test_lifecycle_reauthenticates_volumes_and_sources_at_last_use() -> None:
    module = read(MODULE)

    descriptor = module[
        module.index("function Get-DefenseClawSourceDescriptor") : module.index(
            "function Install-DefenseClawSourceDescriptor"
        )
    ]
    for field in (
        "sha256",
        "signature_status",
        "signer_thumbprint",
        "signer_subject",
        "file_version",
    ):
        assert field in descriptor
    assert "function Assert-DefenseClawSourceDescriptorCurrent" in descriptor

    copy = module[
        module.index("function Install-DefenseClawSourceDescriptor") : module.index(
            "function Invoke-DefenseClawNative"
        )
    ]
    assert copy.index("Assert-DefenseClawSourceDescriptorCurrent") < copy.index(
        "Install-DefenseClawFileAtomic"
    )

    lifecycle = module[module.index("function Invoke-DefenseClawEnterpriseLifecycle") :]
    metadata_phase = lifecycle[
        lifecycle.index("$layout = Get-DefenseClawLayout") : lifecycle.index(
            "if ($Action -eq 'Status')"
        )
    ]
    assert metadata_phase.index("Assert-DefenseClawLayoutVolumeIdentity") < metadata_phase.index(
        "$layout.MetadataPath"
    )

    status_phase = lifecycle[
        lifecycle.index("if ($Action -eq 'Status')") : lifecycle.index(
            "if ($Action -eq 'Verify')"
        )
    ]
    assert status_phase.index("Assert-DefenseClawLayoutVolumeIdentity") < status_phase.index(
        "Get-DefenseClawLifecycleStatus"
    )
    verify_start = lifecycle.index("if ($Action -eq 'Verify')")
    verify_phase = lifecycle[
        verify_start : lifecycle.index(
            "Assert-DefenseClawAdministrator",
            verify_start,
        )
    ]
    assert verify_phase.index("Assert-DefenseClawLayoutVolumeIdentity") < verify_phase.index(
        "$layout.PendingPath"
    )

    sources_phase = lifecycle[
        lifecycle.index("$sources = Get-DefenseClawLifecycleSources") : lifecycle.index(
            "$lifecycleLock = Enter-DefenseClawLifecycleLock"
        )
    ]
    assert (
        sources_phase.index("Assert-DefenseClawLayoutVolumeIdentity")
        < sources_phase.index("Assert-DefenseClawLifecycleSourcesCurrent")
        < sources_phase.index("Initialize-DefenseClawManagedRoot")
    )

    lock_start = lifecycle.index("$lifecycleLock = Enter-DefenseClawLifecycleLock")
    locked_phase = lifecycle[
        lock_start : lifecycle.index(
            "if ([bool]$preLayoutRecovery.handled)",
            lock_start,
        )
    ]
    assert (
        locked_phase.index("Assert-DefenseClawLayoutVolumeIdentity")
        < locked_phase.index("Assert-DefenseClawLifecycleSourcesCurrent")
        < locked_phase.index("$preLayoutRecovery")
    )

    reconcile_start = lifecycle.index("if ($Action -eq 'Reconcile')", lock_start)
    reconcile_phase = lifecycle[
        reconcile_start : lifecycle.index(
            "Initialize-DefenseClawManagedRoot",
            reconcile_start,
        )
    ]
    assert reconcile_phase.index("Assert-DefenseClawLayoutVolumeIdentity") < reconcile_phase.index(
        "$layout.InstallRoot"
    )

    reconcile_return = lifecycle.index(
        "return Invoke-DefenseClawReconcileLifecycle",
        reconcile_start,
    )
    root_creation_start = lifecycle.index(
        "Assert-DefenseClawLayoutVolumeIdentity",
        reconcile_return,
    )
    root_creation_phase = lifecycle[
        root_creation_start : lifecycle.index(
            "New-DefenseClawLayoutDirectories",
            root_creation_start,
        )
    ]
    assert root_creation_phase.index("Assert-DefenseClawLayoutVolumeIdentity") < (
        root_creation_phase.index("Initialize-DefenseClawManagedRoot")
    )
    assert "-Path $layout.InstallRoot" in root_creation_phase
    assert "-Path $layout.StateRoot" in root_creation_phase

    retirement = module[
        module.index("function Complete-DefenseClawSelfUninstallRetirement") : module.index(
            "function Invoke-DefenseClawEnterpriseLifecycle"
        )
    ]
    assert retirement.index("Assert-DefenseClawCanonicalVolumePath") < retirement.index(
        "$bootstrapReceipt = Microsoft.PowerShell.Management\\Get-Content"
    )
    locked_retirement = retirement[
        retirement.index("$lock = Enter-DefenseClawLifecycleLock") :
    ]
    assert locked_retirement.index("Assert-DefenseClawLayoutVolumeIdentity") < (
        locked_retirement.index("$receipt = Get-DefenseClawSelfUninstallReceipt")
    )


def test_certification_inspects_actual_live_service_tokens() -> None:
    harness = read(HARNESS)

    assert "ServiceTokenNative" in harness
    assert "OpenProcessToken(TOKEN_QUERY) failed" in harness
    assert "TokenIntegrityLevel" in harness
    assert "TokenRestrictedSids" in harness
    assert "IsTokenRestricted" in harness
    assert "S-1-16-16384" in harness
    for privilege in (
        "SeChangeNotifyPrivilege",
        "SeTcbPrivilege",
        "SeImpersonatePrivilege",
        "SeDebugPrivilege",
        "SeTakeOwnershipPrivilege",
        "SeRestorePrivilege",
        "SeBackupPrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeCreateTokenPrivilege",
    ):
        assert privilege in harness
    assert "live-service-token-least-privilege" in harness
    assert "service_tokens = @($serviceTokenSnapshot)" in harness


def test_certification_proves_repeated_scm_recovery_and_planned_stop() -> None:
    harness = read(HARNESS)

    assert "Get-CertificationFailureActionContract" in harness
    assert "$byteLength -ne 44" in harness
    assert "5000,15000,60000" in harness
    assert "FailureActionsOnNonCrashFailures" in harness
    assert "$delays = @(5, 15, 60, 60)" in harness
    assert "Stop-Process -Id $oldPID -Force" in harness
    assert "ExecutablePath" in harness
    assert "Wait-ForEnterpriseServiceReadiness" in harness
    assert "-Action Verify" in harness
    assert "gateway_ready" in harness
    assert "guardian_ready" in harness
    assert "authenticated_readiness = $readiness" in harness
    assert "post_explicit_start_readiness" in harness
    assert "Assert-ExplicitServiceStopDoesNotRecover" in harness
    assert "-ObservationSeconds 70" in harness
    assert "scm-repeated-restart-and-explicit-stop" in harness


def test_certification_proves_real_queued_restart_servicing_drain() -> None:
    harness = read(HARNESS)
    proof = harness[
        harness.index("function Test-QueuedFailureRestartDuringServicing") :
        harness.index("function Assert-SameServiceControlSnapshot")
    ]

    assert "Stop-Process -Id $failedPID -Force" in proof
    assert "final repeated SC_ACTION_RESTART after 60 seconds" in proof
    assert "-Action Repair" in proof
    assert "-NoStart" in proof
    assert "-DuringExecution $observeDisabledServicing" in proof
    assert "start_mode -ne 'Disabled'" in proof
    assert "post_quiescence_samples" in proof
    assert "post_quiescence_violations" in proof
    assert "$watch.Elapsed.TotalSeconds -lt 63" in proof
    assert "fresh_drain_required_seconds = 65" in proof
    assert "guardian_first_reactivation_ready = $true" in proof
    assert "queued-scm-restart-during-servicing" in harness
    assert harness.index("scm-repeated-restart-and-explicit-stop") < harness.index(
        "queued-scm-restart-during-servicing"
    )


def test_execute_requires_a_separately_built_successful_upgrade() -> None:
    harness = read(HARNESS)
    upgrade = harness[
        harness.index("function Test-UpgradeTransaction") :
        harness.index("function Get-ManagedUserPathSecurityFingerprint")
    ]

    assert "full execution requires -UpgradeGatewayBinary" in harness
    assert "full execution requires all three -Upgrade*Binary inputs" in upgrade
    assert "Add-SkippedResult" not in upgrade
    assert "external-release-public-cli-versioned-upgrade" in upgrade
    assert "Invoke-PublicEnterpriseLifecycleCLIJSON" in upgrade
    assert "-FilePath $script:UpgradeCLISource" in upgrade
    assert "separately version-stamped upgrade $name bytes do not" in upgrade
    for name in ("gateway", "hook", "cli"):
        assert f"{name} = [string]$script:SourceDigests['upgrade_{name}']" in upgrade
        assert f"exact_{name}_sha256 = $true" in upgrade
    assert "versioned public Upgrade installed the wrong $name bytes" in upgrade
    assert "installed-v2-public-verify-immediately-after-upgrade" in upgrade
    assert "-FilePath $installedV2CLI" in upgrade
    assert "installed v2 public Verify was not exactly healthy immediately" in upgrade
    assert "$serviceContract = Assert-ServiceContract" in upgrade
    assert "$expectedConfigSHA256 = Get-FileDigest $script:ConfigSource" in upgrade
    assert "$expectedManifestSHA256 = Get-FileDigest $script:ManifestSource" in upgrade
    assert "exact_config_source_sha256 = $true" in upgrade
    assert "exact_manifest_source_sha256 = $true" in upgrade
    assert upgrade.index("installed-v2-public-verify-immediately-after-upgrade") < (
        upgrade.index("$serviceContract = Assert-ServiceContract")
    )
    assert upgrade.index("$serviceContract = Assert-ServiceContract") < upgrade.index(
        "$after = Get-DeploymentDigests"
    )
    assert "before = $before" in upgrade
    assert "expected = [pscustomobject]$expected" in upgrade
    assert "after = $after" in upgrade
    assert "upgrade-activation-and-rollback" in upgrade


def test_certification_manually_drives_every_public_windows_lifecycle_verb() -> None:
    harness = read(HARNESS)
    lifecycle_cli = read(WINDOWS_LIFECYCLE_CLI)

    assert "function Get-EnterpriseLifecycleCLIArguments" in harness
    assert "function Invoke-PublicEnterpriseLifecycleCLIJSON" in harness
    for action in (
        "Install",
        "Upgrade",
        "Repair",
        "Reconcile",
        "Status",
        "Verify",
        "Uninstall",
    ):
        assert f"-Action {action}" in harness

    for label in (
        "external-release-public-initial-install-no-start",
        "external-release-public-reinstall-preserved-state",
        "external-release-public-cli-versioned-upgrade",
        "installed-public-repair-first-activation",
        "external-release-public-default-uninstall",
        "installed-public-self-uninstall-purge",
    ):
        assert label in harness
    assert "'installed-public-' + $action.ToLowerInvariant()" in harness
    assert "foreach ($action in @('Status', 'Verify', 'Reconcile'))" in harness

    initial_install = harness[
        harness.index("Invoke-Check 'enterprise-installer-install'") : harness.index(
            "Invoke-Check 'windows-service-contract'"
        )
    ]
    assert "Invoke-PublicEnterpriseLifecycleCLIJSON" in initial_install
    assert "-FilePath $script:CLISource" in initial_install
    assert "-InstallerPath $script:Installer" in initial_install
    assert "-GatewaySource $script:GatewaySource" in initial_install
    assert "-HookSource $script:HookSource" in initial_install
    assert "-CLISource $script:CLISource" in initial_install
    assert "-ConfigSource $script:ConfigSource" in initial_install
    assert "-ManifestSource $script:ManifestSource" in initial_install
    assert "-NoStart" in initial_install
    assert "Invoke-EnterpriseInstallerJSON" not in initial_install

    truthful = harness[
        harness.index("function Test-TruthfulUnhealthyJSON") :
        harness.index("function Test-PreviouslyAuthorizedRootObstructionRepair")
    ]
    assert "tampered-public-windows-$command" in truthful
    assert "-AllowedExitCodes @(1)" in truthful
    assert "[int]$public.Process.ExitCode -ne 1" in truthful

    assert "windowsEnterpriseSelfUpgradeConflict" in lifecycle_cli
    assert "the installed Windows enterprise CLI cannot replace its own running image" in (
        lifecycle_cli
    )
    assert "run upgrade from the new release's protected staged defenseclaw.exe" in (
        lifecycle_cli
    )
    assert "os.SameFile(executableInfo, expectedInfo)" in lifecycle_cli


def test_default_uninstall_proves_real_retention_and_inactive_machine_wiring() -> None:
    harness = read(HARNESS)
    proof = harness[
        harness.index(
            "function Stop-CertificationServicesForDefaultUninstallSnapshot"
        ) : harness.index("function Get-ManagedUserPathSecurityFingerprint")
    ]
    default_uninstall = proof[
        proof.index("function Test-PublicDefaultUninstallAndReinstall") :
    ]

    for role_path in (
        "runtime\\audit.db",
        "logs\\gateway\\gateway.log",
        "logs\\guardian\\hook-guardian.log",
        "runtime\\hook_guardian_state.json",
        "hook-guardian-state\\protected_targets.json",
        "install\\deployment.json",
    ):
        assert role_path in proof
    assert "Get-DefaultUninstallRetainedEvidenceSnapshot" in proof
    assert "Assert-DefaultUninstallRetainedEvidenceContent" in proof
    assert "did not preserve exact real $role content" in proof
    assert "inactive tombstone" in proof
    assert "Get-DefaultUninstallRetainedDirectorySecuritySnapshot" in proof
    assert "Assert-DefaultUninstallRetainedDirectoryTransition" in proof
    assert "Administrators-owned with a protected DACL" in proof
    assert "obsolete gateway service SID" in proof
    assert "Test-DefaultUninstallRetainedStateMediumUserDenial" in proof
    assert "S-1-16-8192" in proof
    assert "whoami = Join-Path $script:System32 'whoami.exe'" in proof
    assert "$groups = & ([string]$inputObject.whoami)" in proof
    assert "$env:SystemRoot" not in proof
    assert "[uint32]0x40000000" in proof
    assert "[uint32]0x00010000" in proof
    assert "($errorCode -eq 5)" in proof
    assert "services_absent" in proof
    assert "secret_material_recorded = $false" in proof

    assert "Assert-EnterpriseMachinePolicyAbsent" in default_uninstall
    assert "Test-FreshClientsHaveNoEnterpriseHookAfterUninstall" in default_uninstall
    assert "machine_policy_absent_before_fresh_clients" in default_uninstall
    assert "machine_policy_absent_after_fresh_clients" in default_uninstall
    assert "fresh_clients_without_enterprise_hook" in default_uninstall
    assert default_uninstall.index(
        "after public default Uninstall and before fresh client processes"
    ) < default_uninstall.index(
        "-Label 'external-release-public-reinstall-preserved-state'"
    )
    assert default_uninstall.index(
        "Test-DefaultUninstallRetainedStateMediumUserDenial"
    ) < default_uninstall.index(
        "-Label 'external-release-public-reinstall-preserved-state'"
    )


def test_certification_covers_shared_codex_parent_transaction_boundary() -> None:
    harness = read(HARNESS)
    probe = harness[
        harness.index("function Invoke-StandardUserControlProbe") :
        harness.index("function Assert-ProtectedUserTamperToken")
    ]

    assert "C:\\ProgramData\\OpenAI" not in harness
    assert "Join-Path $script:KnownProgramData 'OpenAI'" in harness
    assert "preinstall-installer-status-noop" in harness
    assert "codex-shared-parent-creation-rollback" in harness
    assert "codex-shared-parent-provisioning" in harness
    assert "read_traverse_codex_machine_policy_directory" not in harness
    assert "Test-CodexSharedDirectoryBoundary" in harness
    assert "codex_target_enabled = -not [bool]$ClaudeOnly" in probe
    assert "if ([bool]$input.codex_target_enabled)" in probe
    assert "create_child_" in harness
    assert "delete_directory_handle_" in harness
    assert "change_acl_" in harness
    assert "enterprise purge shared Codex parent identity/security" in harness
    assert "preexisting-codex-parent-persists-through-failed-install" in harness
    assert "unsafe-codex-parent-owner-dacl-fails-closed" in harness
    assert "reparse-codex-parent-fails-closed" in harness
    assert "refusing shared-directory cleanup because Codex is not empty" in harness


def test_claude_only_standard_user_probe_targets_only_live_artifacts() -> None:
    harness = read(HARNESS)
    probe = harness[
        harness.index("function Invoke-StandardUserControlProbe") :
        harness.index("function Assert-ProtectedUserTamperToken")
    ]
    unregistered = harness[
        harness.index("function Test-UnregisteredInteractiveSIDFailsClosed") :
        harness.index("function Test-DisabledClaudeTargetDeenrollsExactly")
    ]

    assert "service_tokens = @(" in probe
    assert "if (-not $ClaudeOnly)" in probe
    assert "name = 'claudecode'" in probe
    assert "runtime\\hooks\\.hook-claudecode.token" in probe
    assert "claude_machine_paths = @(" in probe
    for artifact in ("policy", "state", "lock"):
        assert f"name = '{artifact}'" in probe
        assert "write_claude_machine_' + $name" in probe
    assert "Test-ChangeACLDenied" in probe
    assert "want ERROR_ACCESS_DENIED=5" in probe
    assert "--connector ([string]$input.connector)" in probe
    assert "connector = if ($ClaudeOnly) { 'claudecode' } else { 'codex' }" in probe
    assert "--connector ([string]$inputObject.connector)" in unregistered


def test_certification_purges_through_installed_cli_without_retirement_leaks() -> None:
    harness = read(HARNESS)
    module = read(MODULE)
    lifecycle_cli = read(WINDOWS_LIFECYCLE_CLI)
    helper_capture_smoke = read(SELF_UNINSTALL_HELPER_CAPTURE_SMOKE)
    purge = harness[
        harness.index("function Test-CodexSharedDirectoriesPersistThroughPurge") : harness.index(
            "function Restore-CodexSharedDirectoryFixture"
        )
    ]

    assert "bin\\defenseclaw.exe" in purge
    assert "bin\\defenseclaw-hook.exe" in purge
    assert "libexec\\install-enterprise.ps1" in purge
    assert "libexec\\DefenseClawEnterprise.psm1" in purge
    assert "'enterprise', 'windows', 'uninstall'" in purge
    assert "'--purge'" in purge
    assert "Invoke-EnterpriseLifecycleCLIJSON" in purge
    assert "Invoke-EnterpriseInstallerJSON" not in purge
    assert "installed-public-self-uninstall-purge" in purge
    assert "self-uninstall-standard-user-no-delete-handle" in purge
    assert "-TimeoutSeconds 600" in purge
    assert purge.index("Start-ActiveUserFileLockHolder") < purge.index(
        "Invoke-EnterpriseLifecycleCLIJSON"
    )
    assert "Get-SelfUninstallFinalizerProcessObservation" in purge
    assert purge.index("Invoke-EnterpriseLifecycleCLIJSON") < purge.index(
        "Get-SelfUninstallFinalizerProcessObservation"
    )
    assert purge.index("Get-SelfUninstallFinalizerProcessObservation") < purge.index(
        "Stop-ActiveUserFileLockHolder $retirementLocker"
    )
    assert "live_artifact_count -ne 4" in purge
    assert "retired no-delete handle target" in purge
    assert purge.index("Stop-ActiveUserFileLockHolder $retirementLocker") < purge.index(
        "installed public self-Uninstall finalizer retirement"
    )
    assert "retirement_pending_until_handle_release = $true" in purge
    assert "finalizer_completed_after_handle_release = $true" in purge
    assert "finalizer_process_after_captured_cli_return" in purge
    assert "no_inherited_finalizer_capture_handles = $true" in purge
    assert "protected_finalizer_environment" in purge
    assert "finalizer_environment_retired_without_recreation = $true" in purge
    assert "finalizer_process_exited_before_recreation_recheck = $true" in purge
    assert "lifecycle_sibling_artifacts_absent = $true" in purge
    assert "standard_user_no_delete_retirement_lock" in purge
    assert "Get-CertificationLifecycleReceiptPaths" in harness
    assert "purge_intent_retired = $true" in purge
    assert "self_uninstall_finalizer_retired = $true" in purge
    assert "install_and_state_roots_absent = $true" in purge
    assert "sibling_tombstones_absent = $true" in purge
    assert "protected_user_trees_restored = $true" in purge
    assert "Get-CertificationUninstallSiblingSnapshot" in purge
    assert "Assert-SameUserTreeInventory" in purge
    assert "installed public self-Uninstall left service" in purge
    assert "elevated_powershell_temp_boundary" in purge
    assert "$script:Installed = $false" in purge
    for field in (
        "cached_enterprise_clients_require_reload",
        "self_uninstall_cleanup_pending",
        "canonical_install_root_absent",
        "self_uninstall_receipt_path",
        "self_uninstall_environment_root",
        "retired_install_root",
    ):
        assert field in purge
    assert "installed public self-Uninstall finalizer retirement" in purge
    assert "self-uninstall-$scope.json" in harness
    assert "self-uninstall-$scope.ps1" in harness
    assert "\\.retired-[0-9a-f]{32}$" in purge
    assert "Get-CertificationRetirementArtifactObservation" in harness
    assert "Get-CertificationSelfUninstallEnvironmentObservation" in harness
    assert "self-uninstall-$scope.environment" in harness
    assert "exact_lifecycle_child = $true" in harness
    assert "administrators_system_only = $true" in harness
    assert "no_reparse_points = $true" in harness
    assert "standard_users_denied_read_write = $true" in harness
    assert "pre-uninstall lifecycle siblings" in purge
    assert "post-uninstall lifecycle siblings" in purge
    assert "installed public self-Uninstall lifecycle sibling artifacts" in purge
    assert "installed public self-Uninstall finalizer process exit" in purge
    assert purge.index("installed public self-Uninstall finalizer process exit") < purge.index(
        "Start-Sleep -Milliseconds 750"
    )
    assert "Start-Sleep -Milliseconds 750" in purge
    assert "Assert-NoStandardUserAccess" in harness
    assert "secret_material_recorded = $false" in harness
    finalizer_process_observation = harness[
        harness.index("function Get-SelfUninstallFinalizerProcessObservation") : harness.index(
            "function Assert-EnterpriseMachinePolicyAbsent"
        )
    ]
    assert "WindowsPowerShell\\v1.0\\powershell.exe" in finalizer_process_observation
    assert "Get-CimInstance Win32_Process" in finalizer_process_observation
    assert "Name='powershell.exe'" in finalizer_process_observation
    assert "expected exactly one live fixed-engine finalizer" in finalizer_process_observation
    assert "Get-Process" in finalizer_process_observation
    assert "creation_filetime" in finalizer_process_observation
    assert "exact_command_line = $true" in finalizer_process_observation
    assert "captured_cli_returned = $true" in finalizer_process_observation
    assert "helper_remained_alive_after_capture = $true" in finalizer_process_observation
    assert "no_inherited_capture_handles = $true" in finalizer_process_observation
    assert "secret_material_recorded = $false" in finalizer_process_observation
    file_lock_holder = harness[
        harness.index("function Start-ActiveUserFileLockHolder") :
        harness.index("function Start-ActiveUserSparseArtifactAttack")
    ]
    assert "[IO.FileShare]::ReadWrite" in file_lock_holder
    assert "[IO.FileShare]::Delete" not in file_lock_holder
    assert "delete_sharing_enabled = $false" in file_lock_holder
    finalizer = module[
        module.index("function Complete-DefenseClawSelfUninstallRetirement") :
        module.index("function Get-DefenseClawStatePurgeIntent")
    ]
    assert "[int]$CleanupTimeoutSeconds = 300" in finalizer
    assert "$cleanupDeadline = [DateTime]::UtcNow.AddSeconds(" in finalizer
    assert "$retryDelayMilliseconds = 200" in finalizer
    assert "while ($true)" in finalizer
    assert "Enter-DefenseClawLifecycleLock" in finalizer
    assert "Get-DefenseClawSelfUninstallReceipt" in finalizer
    assert "Assert-DefenseClawSelfUninstallCommittedState" in finalizer
    assert "Assert-DefenseClawRetiredInstallTree" in finalizer
    assert "Assert-DefenseClawSelfUninstallHelper" in finalizer
    assert "Exit-DefenseClawLifecycleLock -Lock $lock" in finalizer
    assert finalizer.index("Exit-DefenseClawLifecycleLock -Lock $lock") < finalizer.index(
        "Start-Sleep"
    )
    assert "$CleanupTimeoutSeconds-second retry window" in finalizer
    assert "$retryDelayMilliseconds * 2" in finalizer
    assert "2000" in finalizer

    create_process_declaration = module[
        module.index("private static extern bool CreateProcessW(") : module.index(
            "private static extern IntPtr LocalFree"
        )
    ]
    assert "[MarshalAs(UnmanagedType.Bool)] bool inheritHandles" in create_process_declaration
    native_launcher = module[
        module.index("public static uint StartDetachedProcess(") : module.index(
            '"@ -Language CSharp',
            module.index("public static uint StartDetachedProcess("),
        )
    ]
    assert "SortedDictionary<string, string>" in native_launcher
    assert "StringComparer.OrdinalIgnoreCase" in native_launcher
    assert "entry.IndexOf('\\0')" in native_launcher
    assert native_launcher.count("environmentBlock.Append('\\0');") >= 2
    assert "Encoding.Unicode.GetBytes" in native_launcher
    assert "STARTUPINFO startup = new STARTUPINFO();" in native_launcher
    assert "CREATE_UNICODE_ENVIRONMENT = 0x00000400" in native_launcher
    assert "CREATE_NO_WINDOW = 0x08000000" in native_launcher
    assert "CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW" in native_launcher
    assert "STARTF_USESTDHANDLES" not in native_launcher
    assert re.search(
        r"CreateProcessW\(\s*applicationPath,\s*new StringBuilder\(commandLine\),"
        r"\s*IntPtr\.Zero,\s*IntPtr\.Zero,\s*false,\s*"
        r"CREATE_UNICODE_ENVIRONMENT \| CREATE_NO_WINDOW,",
        native_launcher,
        re.DOTALL,
    )
    assert "CloseHandle(processInformation.hThread)" in native_launcher
    assert "CloseHandle(processInformation.hProcess)" in native_launcher
    assert "Marshal.FreeHGlobal(environmentPointer)" in native_launcher
    helper_launcher = module[
        module.index("function Start-DefenseClawSelfUninstallHelper") : module.index(
            "function Remove-DefenseClawRetiredInstallTree"
        )
    ]
    assert "WindowsPowerShell\\v1.0\\powershell.exe" in helper_launcher
    assert "$nativeSecurityType::StartDetachedProcess(" in helper_launcher
    assert "('\"' + $powerShell + '\" ' + $arguments)" in helper_launcher
    for variable in (
        "TEMP",
        "TMP",
        "LOCALAPPDATA",
        "APPDATA",
        "USERPROFILE",
        "HOME",
    ):
        assert f"@('{variable}', $environmentRoot)" in helper_launcher
    assert "@('PSModuleAnalysisCachePath', 'NUL')" in helper_launcher
    assert "Initialize-DefenseClawSelfUninstallEnvironment" in helper_launcher
    assert "[Diagnostics.ProcessStartInfo]" not in helper_launcher
    assert "Microsoft.PowerShell.Management\\Start-Process" not in helper_launcher
    environment_lifecycle = module[
        module.index("function Initialize-DefenseClawSelfUninstallEnvironment") : module.index(
            "function Get-DefenseClawSelfUninstallHelperContent"
        )
    ]
    assert "Assert-DefenseClawDescendant" in environment_lifecycle
    assert "-Root $Layout.LifecycleLockDirectory" in environment_lifecycle
    assert "Initialize-DefenseClawManagedRoot" in environment_lifecycle
    assert "Assert-DefenseClawManagedTreeNoReparse" in environment_lifecycle
    assert "Get-ChildItem" in environment_lifecycle
    assert "-Recurse" in environment_lifecycle
    assert "$script:SystemSID" in environment_lifecycle
    assert "$script:AdministratorsSID" in environment_lifecycle
    assert "$script:TrustedInstallerSID" in environment_lifecycle
    assert "-RejectUntrustedRead" in environment_lifecycle
    assert "Remove-DefenseClawManagedTree" in environment_lifecycle
    receipt_validation = module[
        module.index("function Get-DefenseClawSelfUninstallReceipt") : module.index(
            "function Publish-DefenseClawSelfUninstallReceipt"
        )
    ]
    assert "'helper_environment_root'" in receipt_validation
    assert "$Layout.SelfUninstallEnvironmentRoot" in receipt_validation
    evidence_cleanup = module[
        module.index("function Remove-DefenseClawSelfUninstallEvidence") : module.index(
            "function Wait-DefenseClawSelfUninstallCallerExit"
        )
    ]
    assert evidence_cleanup.index("Remove-DefenseClawSelfUninstallEnvironment") < evidence_cleanup.index(
        "$Layout.SelfUninstallHelperPath"
    )
    assert evidence_cleanup.index("$Layout.SelfUninstallHelperPath") < evidence_cleanup.index(
        "$Layout.SelfUninstallReceiptPath"
    )
    assert "'self_uninstall_environment_root'" in module
    assert "[string]$Layout.SelfUninstallEnvironmentRoot" in module

    assert "Start-DefenseClawSelfUninstallHelper" in helper_capture_smoke
    assert "[int]$WaitSeconds = 6" in helper_capture_smoke
    assert "$startInfo.RedirectStandardOutput = $true" in helper_capture_smoke
    assert "$startInfo.RedirectStandardError = $true" in helper_capture_smoke
    assert "$nestedProcess.StandardOutput.ReadToEnd()" in helper_capture_smoke
    assert "$nestedProcess.StandardError.ReadToEnd()" in helper_capture_smoke
    assert "$nestedProcess.WaitForExit()" in helper_capture_smoke
    assert "DEFENSECLAW_DETACHED_HELPER_READY_V1" in helper_capture_smoke
    assert helper_capture_smoke.index("$nestedProcess.StandardOutput.ReadLine()") < helper_capture_smoke.index(
        "$stopwatch = [Diagnostics.Stopwatch]::StartNew()"
    )
    assert "$captureDeadlineMilliseconds = [int64](" in helper_capture_smoke
    assert "($WaitSeconds * 1000) -" in helper_capture_smoke
    assert "$elapsedMilliseconds -ge $captureDeadlineMilliseconds" in helper_capture_smoke
    assert "capture_deadline_ms = $captureDeadlineMilliseconds" in helper_capture_smoke
    assert "helper_alive_after_capture = $helperAlive" in helper_capture_smoke
    assert "no_inherited_capture_handles = $true" in helper_capture_smoke
    assert "protected_environment_pinned = $true" in helper_capture_smoke
    assert "module_analysis_cache_disabled = $true" in helper_capture_smoke
    assert "environment_root_retired = $environmentRootRetired" in helper_capture_smoke
    for variable in (
        "TEMP",
        "TMP",
        "LOCALAPPDATA",
        "APPDATA",
        "USERPROFILE",
        "HOME",
    ):
        assert f"'{variable}'" in helper_capture_smoke
    assert "[string]$observation.PSModuleAnalysisCachePath -cne 'NUL'" in helper_capture_smoke
    assert "$helperProcess.Kill()" in helper_capture_smoke

    assert "Assert-EnterpriseMachinePolicyAbsent" in purge
    assert "immediately after installed public self-Uninstall returned" in purge
    assert "machine_policies_absent_before_finalizer_wait = $true" in purge
    assert purge.index("immediately after installed public self-Uninstall returned") < purge.index(
        "installed public self-Uninstall finalizer retirement"
    )
    for policy_path in (
        "$script:CodexRequirementsPath",
        "$script:CodexManagedStatePath",
        "$script:CodexMachineLockPath",
        "$script:ClaudeManagedPolicyPath",
        "$script:ClaudeManagedStatePath",
        "$script:ClaudeManagedLockPath",
    ):
        assert policy_path in harness[
            harness.index("function Assert-EnterpriseMachinePolicyAbsent") :
            harness.index("function Test-FreshClientsHaveNoEnterpriseHookAfterUninstall")
        ]

    fresh_clients = harness[
        harness.index("function Test-FreshClientsHaveNoEnterpriseHookAfterUninstall") :
        harness.index("function Test-CodexSharedDirectoriesPersistThroughPurge")
    ]
    assert "fresh-post-uninstall-codex-no-enterprise-hook" in fresh_clients
    assert "fresh-post-uninstall-claude-no-enterprise-hook" in fresh_clients
    assert "-ExpectFreshUnmanagedClient" in fresh_clients
    assert "Invoke-ActualCodexCertificationRun" in fresh_clients
    assert "Invoke-ActualClaudeCertificationRun" in fresh_clients
    assert "Assert-SameUserTreeInventory" in fresh_clients
    assert "machine_policy_absent_before_start = $true" in fresh_clients
    assert "enterprise_hook_configured = $false" in fresh_clients
    assert "cached_enterprise_command_noop_asserted = $false" in fresh_clients
    assert "cached_process_semantics_tested = $false" in fresh_clients
    assert "fresh_clients_no_enterprise_hook = $freshClients" in purge
    assert "cached_enterprise_command_noop_asserted = $false" in purge
    assert "cached_enterprise_clients_require_reload = $true" in purge

    codex_client = harness[
        harness.index("function Invoke-ActualCodexCertificationRun") :
        harness.index("function Invoke-ActualClaudeCertificationRun")
    ]
    claude_client = harness[
        harness.index("function Invoke-ActualClaudeCertificationRun") :
        harness.index("function Assert-ServiceContract")
    ]
    for client in (codex_client, claude_client):
        assert "ExpectFreshUnmanagedClient" in client
        assert "process_fresh = $true" in client
        assert "configuration_fresh = $true" in client
        assert "enterprise_hook_configured = $false" in client
        assert "cached_enterprise_command_noop_asserted = $false" in client
        assert "provider_reached = $true" in client
        assert "secret_material_recorded = $false" in client

    assert "windowsEnterpriseSelfUninstallCaller" in lifecycle_cli
    assert '"-SelfUninstallCallerPID"' in lifecycle_cli
    assert '!strings.EqualFold(strings.TrimSpace(action), "uninstall")' in lifecycle_cli
    assert '"install-enterprise.ps1"' in lifecycle_cli
    assert '"libexec"' in lifecycle_cli
    assert 'filepath.Join(installRoot, "bin", "defenseclaw.exe")' in lifecycle_cli
    assert "uint64(processID) > uint64(^uint32(0))" in lifecycle_cli


def test_certification_uses_fixed_clean_windows_powershell_bootstrap() -> None:
    harness = read(HARNESS)

    assert "[string]$InstallerPath = ''" in harness
    assert "$resolvedInstallerPath = if ([string]::IsNullOrWhiteSpace($InstallerPath))" in harness
    assert "Join-Path (Split-Path -Parent $PSScriptRoot)" not in harness
    assert "[Environment]::ProcessPath" not in harness
    assert "[Environment].GetProperty(" in harness
    assert "Get-Process -Id $PID -ErrorAction Stop" in harness
    assert "foreach ($name in @('powershell.exe', 'pwsh.exe'))" in harness
    assert "WindowsPowerShell\\v1.0\\powershell.exe" in harness
    assert "BootstrapPowerShellExecutable" in harness
    assert "$start.Environment.Clear()" in harness
    assert "StrictWindowsBootstrapEnvironment" in harness
    assert "PSModulePath" in harness
    assert "-FilePath $script:BootstrapPowerShellExecutable" in harness


def test_enterprise_is_opt_in_without_disabling_normal_mode_repair() -> None:
    matrix = read(MATRIX_TEST)
    documentation = read(DEPLOYMENT_DOC)
    harness = read(HARNESS)
    service_host = read(WINDOWS_SERVICE_HOST)
    service_host_test = read(WINDOWS_SERVICE_HOST_TEST)
    main = read(DEFENSECLAW_MAIN)
    main_test = read(DEFENSECLAW_MAIN_TEST)

    for mode in (
        "legacy default",
        "unmanaged BYOD",
        "CI/CD",
        "sandboxed",
        "server",
        "SaaS",
        "managed enterprise",
    ):
        assert mode in matrix

    assert "The matrix is an ownership switch, not an auto-heal switch." in documentation
    assert "normal mode uses the existing per-user repair loop" in documentation
    assert "Enterprise service enforcement is opt-in." in documentation
    assert (
        "Installing a release that contains Windows enterprise support does not create a machine service"
        in documentation
    )
    assert "Test-NormalModePreinstallNoOp" in harness
    assert "Test-NormalModeLiveAutoHeal" in harness
    assert "normal-mode-live-hook-auto-heal-preserved" in harness
    assert "normal-mode active user did not prove existing hook auto-heal" in harness
    assert "known-folder APIs" in documentation
    assert "Environment poisoning therefore cannot redirect" in documentation

    run_service = service_host[
        service_host.index("func runWindowsService(") : service_host.index(
            "func validWindowsServiceName("
        )
    ]
    assert 'windowsServiceNameEnv = "DEFENSECLAW_WINDOWS_SERVICE_NAME"' in service_host
    assert 'if name == "" {' in run_service
    assert "return false, 0" in run_service
    assert run_service.index('if name == "" {') < run_service.index("isWindowsService()")
    assert "must not even" in run_service
    assert "TestRunWindowsServiceIsStrictNoOpWithoutEnterpriseMarker" in service_host_test
    assert "TestRunWindowsServiceConsultsDetectorOnlyWithEnterpriseMarker" in service_host_test

    assert 'if strings.EqualFold(base, "defenseclaw")' in main
    assert 'return "defenseclaw"' in main
    release_name = main[
        main.index("func releaseCommandNameForPath(") :
    ]
    assert "defenseclaw-gateway" not in release_name
    assert '{path: "defenseclaw-gateway.exe"}' in main_test
    assert '{path: "renamed-by-user.exe"}' in main_test


def test_normal_mode_live_repair_uses_an_absent_enterprise_baseline() -> None:
    harness = read(HARNESS)

    live_repair = harness[
        harness.index("function Test-NormalModeLiveAutoHeal") : harness.index(
            "function Test-CandidateCodexHomeResolverContract"
        )
    ]
    assert "[switch]$RequireEnterpriseAbsent" in live_repair
    assert "Get-NormalModeEnterpriseMachineSnapshot" in live_repair
    assert "requires an absent enterprise" in live_repair
    assert "$script:LifecycleLockDirectory" in live_repair
    assert "$script:CodexVendorDirectory" in live_repair
    assert "$script:ClaudeManagedPolicyPath" in live_repair
    assert "Assert-SameObjectJSON" in live_repair
    assert "enterprise_absent_before = [bool]$RequireEnterpriseAbsent" in live_repair
    assert "machine_before = $machineBefore" in live_repair
    assert "machine_after = $machineAfter" in live_repair

    preinstall_live = harness.index(
        "'preinstall-normal-mode-live-hook-auto-heal-is-no-op'"
    )
    preinstall_status = harness.index("'preinstall-normal-mode-is-no-op'")
    enterprise_install = harness.index("Invoke-Check 'enterprise-installer-install'")
    assert preinstall_live < preinstall_status < enterprise_install
    assert "-RequireEnterpriseAbsent" in harness[
        preinstall_live - 300 : preinstall_live + 300
    ]


def test_non_admin_file_denials_require_access_denied_not_generic_io() -> None:
    harness = read(HARNESS)
    probe = harness[
        harness.index("function Invoke-StandardUserControlProbe") : harness.index(
            "function Assert-ProtectedUserTamperToken"
        )
    ]

    assert "CreateFileW GENERIC_WRITE error" in probe
    assert "CreateFileW GENERIC_READ error" in probe
    assert probe.count("($errorCode -eq 5)") >= 2
    assert "($credentialError -eq 5)" in probe
    assert "non-authorization I/O failure" in probe
    assert "writable key returned null without an ACCESS_DENIED exception" in probe
    assert "Add-Probe $Name $true $_.Exception.Message" not in probe
    assert "Add-Probe 'read_service_scoped_credential' $true" not in probe


def test_certification_separates_core_health_from_production_security() -> None:
    harness = read(HARNESS)
    module = read(MODULE)

    assert "[switch]$ClaudeOnly" in harness
    assert "$script:ClaudeEffectivePolicyAttested = $false" in harness
    assert "initial_security_complete = $false" in harness
    assert "core_mode_security_complete = $false" in harness
    assert "Invoke-ActualClaudeCertificationRun" in harness
    assert "repair-attest-live-claude-effective-policy" in harness
    assert "-AttestClaudeEffectivePolicy" in harness
    assert "persisted_production_attestation = $false" in harness
    assert "production_certified = $productionCertified" in harness
    assert "claude_effective_policy_persisted" in harness
    assert "$passed = $Status -eq 'passed'" in harness
    assert "failed exact restoration is retained as diagnostic evidence" in harness
    assert "CertificationCodexHome must accompany only unsigned mutating" in harness
    assert "certification transactions in full and Claude-only modes" in harness
    assert "production and read-only actions must omit it" in harness
    assert "CoreHardeningCertification must accompany only unsigned" in harness
    assert "Claude-only mutating certification actions" in harness
    assert "lifecycle_scope_matrix" in harness
    assert "function Get-CertificationLifecycleScopeArguments" in harness
    assert "if ($Action -notin @('Install', 'Upgrade', 'Repair'))" in harness
    assert "if (-not $script:CertificationCodexHomeInitialized)" in harness
    assert "-UnsignedCertification ([bool]$AllowUnsigned)" in harness
    assert "[bool]($AllowUnsigned -and $ClaudeOnly)" in harness

    assert "[switch]$AttestClaudeEffectivePolicy" in module
    assert "-AttestClaudeEffectivePolicy is forbidden in core-hardening certification mode" in module
    assert "claude_effective_policy_verified" in module
    assert "core_hardening_complete" in module
    assert "security_complete" in module
    assert "manifest_sha256" in module


def test_certification_requires_a_real_distinct_trusted_codex_launcher() -> None:
    harness = read(HARNESS)

    assert "[string]$CodexTrustedHookLauncherBinary" in harness
    assert "Get-CodexTrustedHookLauncherIdentity" in harness
    assert "a separately signed fail-closed drop-in launcher" in harness
    assert "must have bytes distinct from both" in harness
    assert "codex-trusted-hook-launcher.exe" in harness
    assert "full Codex lifecycle attestation requires the protected" in harness
    assert "$arguments.Add('-CodexTrustedHookLauncherBinary')" in harness
    assert "$arguments.Add($script:CodexTrustedHookLauncherRuntimeBinary)" in harness
    assert "[ValidateSet('stock', 'trusted_launcher')]" in harness
    assert "stock-codex-0.144.3-blocked-shell-fail-open-negative" in harness
    assert "stock_codex_supported = $false" in harness
    assert "trusted_codex_launcher_identity" in harness


def test_certification_covers_effective_policy_revocation_and_lock_squatting() -> None:
    harness = read(HARNESS)

    assert "application-control-is-not-claude-effective-policy" in harness
    assert "Test-ClaudeManagedPolicyDeletionAutoHeal" in harness
    assert "Test-DisabledClaudeTargetDeenrollsExactly" in harness
    assert "enabled = $false" in harness
    assert "disabled Claude SID survived in guardian state or protected" in harness
    assert "removed_manifest_exact_deenrollment" in harness
    assert "removed Claude target produced authenticated managed-hook audit" in harness
    assert "recovery_runtime_retained_exact" in harness
    assert "disabled Claude target produced authenticated managed-hook audit" in harness
    assert "Test-ProtectedLifecycleLockSquattingDenied" in harness
    assert "Start-ActiveUserMutexSquatter" in harness
    assert "Global\\DefenseClaw-CodexRequirements-" in harness
    assert "Test-CodexMachineLockSquattingBoundaries" in harness
    assert "Start-ActiveUserFileLockHolder" in harness
    assert ".defenseclaw-managed-hooks.lock" in harness
    assert "legacy_named_objects_ignored = $true" in harness
    assert "protected_file_lock_bounded_fail_closed = $true" in harness
