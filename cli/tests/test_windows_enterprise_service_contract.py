# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Platform-neutral release-contract checks for native Windows enterprise mode.

The destructive behavior is certified by scripts/test-windows-enterprise-
hardening.ps1 on a disposable Windows endpoint. These tests keep the critical
operator and trust-boundary wiring visible in ordinary Linux/macOS/Windows CI.
"""

from __future__ import annotations

import base64
import ctypes
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
WINDOWS_CODEX_REQUIREMENTS = ROOT / "internal" / "cli" / "windows_codex_requirements.go"
WINDOWS_CODEX_MACHINE_POLICY = ROOT / "internal" / "gateway" / "connector" / "codex_machine_requirements_windows.go"
CODEX_MACHINE_POLICY = ROOT / "internal" / "gateway" / "connector" / "codex_machine_requirements.go"
WINDOWS_CLAUDE_POLICY = ROOT / "internal" / "gateway" / "connector" / "claudecode_policy_windows.go"
WINDOWS_MACHINE_ROOTS = ROOT / "internal" / "winpath" / "machine_roots_windows.go"
WINDOWS_ENV_CONFIG = ROOT / "internal" / "config" / "env_config_windows.go"
WINDOWS_CODEX_POLICY = ROOT / "internal" / "gateway" / "connector" / "codex_policy_windows.go"
WINDOWS_MANAGED_RUNTIME = ROOT / "internal" / "enterprisehooks" / "managed_runtime_windows.go"
WINDOWS_MANAGED_POLICY = ROOT / "internal" / "enterprisehooks" / "managed_policy_windows.go"
WINDOWS_MANAGED_BUNDLE_BUILDER = ROOT / "packaging" / "scripts" / "build-managed-windows-bundle.sh"
POWERSHELL = shutil.which("pwsh.exe") or shutil.which("powershell.exe")


def read(path: Path) -> str:
    assert path.is_file(), f"required Windows enterprise artifact is missing: {path}"
    return path.read_text(encoding="utf-8")


def test_windows_shorthand_targets_require_metadata_versions() -> None:
    installer = read(INSTALLER)
    smoke = read(BOOTSTRAP_ENVIRONMENT_SMOKE)
    config_renderer_start = installer.index(
        "function Get-DefenseClawRenderedEnterpriseConfig"
    )
    discovery_start = installer.index(
        "function Get-DefenseClawConnectorMetadataVersion"
    )
    renderer_start = installer.index(
        "function Get-DefenseClawRenderedEnterpriseTargets"
    )
    execution_start = installer.index("$bootstrapEnvironment = $null")
    config_renderer = installer[config_renderer_start:discovery_start]
    discovery = installer[discovery_start:renderer_start]
    renderer = installer[renderer_start:execution_start]

    assert 'rule_pack_dir: ""' in config_renderer
    assert "Get-DefenseClawConnectorJsonMetadataVersion" in discovery
    assert "AppData\\Roaming\\npm\\node_modules" in discovery
    assert "AppData\\Local\\Programs\\cursor\\resources\\app\\package.json" in discovery
    assert "anthropic.claude-code-*" in discovery
    assert "$userHomeFull =" in discovery
    assert "$home =" not in discovery.casefold()
    assert "Get-DefenseClawConnectorMetadataVersion" in renderer
    assert "$users = @(" in renderer
    assert "agent_version:" in renderer
    assert "enabled: false" in renderer
    assert renderer.index("agent_version:") < renderer.index("enabled: true")
    assert "@attacker/not-amp" in smoke
    assert "target renderer emitted an enabled/version contract mismatch" in smoke
    assert "shorthand config did not explicitly select embedded rule-pack defaults" in smoke


def test_unsigned_windows_bundle_instructions_are_claude_only() -> None:
    builder = read(WINDOWS_MANAGED_BUNDLE_BUILDER)
    unsigned_instructions = builder[
        builder.index("Local unsigned build ready") :
        builder.index("See cmd/defenseclaw-enterprise-setup/platform_windows.go")
    ]

    assert "--core-hardening-certification --mode action" in unsigned_instructions
    assert "--connector claudecode" in unsigned_instructions
    assert "The full profile requires real" in unsigned_instructions
    assert "WDAC/AppLocker" in unsigned_instructions


def test_windows_enterprise_uses_cisco_secure_client_roots() -> None:
    installer = read(INSTALLER)
    module = read(MODULE)
    harness = read(HARNESS)
    smoke = read(MODULE_SMOKE)
    documentation = read(DEPLOYMENT_DOC)
    env_config = read(WINDOWS_ENV_CONFIG)

    production_suffix = r"Cisco\Cisco Secure Client\DefenseClaw"
    lifecycle_suffix = r"Cisco\Cisco Secure Client\DefenseClaw-Lifecycle"
    certification_suffix = r"Cisco\Cisco Secure Client\DefenseClaw-Cert"

    for source in (installer, module, harness, smoke, documentation):
        assert r"Cisco\DefenseClaw" not in source
    for source in (installer, module, harness, smoke):
        assert "Cisco Secure Client" in source
    assert production_suffix in installer
    assert production_suffix in module
    assert production_suffix in harness
    assert production_suffix in smoke
    assert lifecycle_suffix in module
    assert lifecycle_suffix in harness
    assert certification_suffix in harness

    assert "winpath.TrustedProgramData()" in env_config
    assert '"Cisco Secure Client"' in env_config
    assert "const DefaultEnvConfigPath" not in env_config
    assert r"C:\ProgramData\Cisco" not in env_config
    # The trust-check env var was refactored into a shouldEnforceEnvConfigTrust()
    # gate that composes with envConfigTrustWaived() (slice-1 CR feedback), so
    # the raw os.Getenv comparison is no longer inline in env_config_windows.go.
    # Bind to the gate helper and to the env var name so the test still
    # verifies the effective contract rather than a specific implementation.
    assert "DEFENSECLAW_ENV_CONFIG_SKIP_TRUST" in env_config
    assert "shouldEnforceEnvConfigTrust()" in env_config


def windows_powershell_engines() -> list[str]:
    """Return each installed Windows PowerShell/Core engine exactly once."""

    if os.name != "nt":
        return []

    system_buffer = ctypes.create_unicode_buffer(32768)
    system_length = ctypes.windll.kernel32.GetSystemDirectoryW(
        system_buffer,
        len(system_buffer),
    )
    assert 0 < system_length < len(system_buffer), (
        "GetSystemDirectoryW did not return a safe machine-wide PowerShell root"
    )
    system32 = Path(system_buffer.value).resolve()

    import winreg

    with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion",
        0,
        winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
    ) as current_version:
        program_files_raw, _ = winreg.QueryValueEx(current_version, "ProgramFilesDir")
    program_files = Path(str(program_files_raw)).resolve()
    assert program_files.is_absolute() and program_files.is_dir(), (
        "64-bit Program Files registration is not an existing absolute directory"
    )

    # Certification must execute a fixed machine-wide engine. A per-user
    # WindowsApps app-execution alias can resolve through PATH while failing
    # before script startup in the deliberately restricted environment.
    candidates: list[str | None] = [
        str(system32 / "WindowsPowerShell" / "v1.0" / "powershell.exe"),
        str(program_files / "PowerShell" / "7" / "pwsh.exe"),
    ]

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


def restricted_windows_bootstrap_environment(profile_root: str) -> dict[str, str]:
    """Mirror the certification launcher's minimal native environment."""

    assert os.name == "nt"
    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))
    assert 0 < length < len(buffer), "GetSystemDirectoryW did not return a safe path"
    system32 = Path(buffer.value).resolve()
    windows_root = system32.parent
    environment = {
        "ComSpec": str(system32 / "cmd.exe"),
        "PATH": os.pathsep.join(
            (
                str(system32),
                str(system32 / "WindowsPowerShell" / "v1.0"),
                str(windows_root),
            )
        ),
        "PSModulePath": os.environ.get("PSModulePath", ""),
        # Windows PowerShell 5.1 consumes SystemRoot during CLR/engine startup.
        # Pin it to the root obtained through GetSystemDirectoryW rather than
        # inheriting a caller-controlled environment value.
        "SystemRoot": str(windows_root),
        "TEMP": profile_root,
        "TMP": profile_root,
    }
    assert set(environment) == {
        "ComSpec",
        "PATH",
        "PSModulePath",
        "SystemRoot",
        "TEMP",
        "TMP",
    }
    assert not {
        "programdata",
        "programfiles",
        "windir",
        "home",
        "userprofile",
        "appdata",
        "localappdata",
    }.intersection(name.casefold() for name in environment)
    return environment


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
    assert "error = $failureMessage" in installer
    assert "errors = @($failureMessage)" in installer


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
    assert "Get-DefenseClawTrustedMachineRoots" in installer
    assert "[Environment]::SystemDirectory" in installer
    assert "[Microsoft.Win32.RegistryHive]::LocalMachine" in installer
    assert "[Microsoft.Win32.RegistryView]::Registry64" in installer
    assert "[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames" in installer
    assert "'ProgramFilesDir'" in installer
    assert "'Common AppData'" in installer
    assert "trusted $Label root is empty, relative" in installer
    assert "[string]$InstallRoot," in installer
    assert "[string]$StateRoot," in installer
    assert "$env:ProgramFiles" not in installer
    assert "$env:ProgramData" not in installer
    assert "Get-DefenseClawTrustedMachineRoots" in module
    assert "[Environment]::SystemDirectory" in module
    assert "[Microsoft.Win32.RegistryHive]::LocalMachine" in module
    assert "[Microsoft.Win32.RegistryView]::Registry64" in module
    assert "'ProgramFilesDir'" in module
    assert "'Common AppData'" in module
    assert "[Environment+SpecialFolder]::CommonApplicationData" not in module
    assert "$env:ProgramFiles" not in module
    assert "$env:ProgramData" not in module
    assert "Assert-DefenseClawBootstrapModuleTrust" in installer
    assert "DefenseClaw enterprise installer rejected its module before import" in installer
    assert "AllowUnsigned = [bool]$AllowUnsigned" in installer
    assert "action is outside the enterprise lifecycle" in installer
    assert "every certification lifecycle action" in installer
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
        "        $Layout.MetadataPath\n"
        "    )) {" in module
    )
    assert (
        "Microsoft.PowerShell.Management\\Test-Path `\n"
        "        -LiteralPath $Layout.CodexTrustedShellAttestationPath `\n"
        "        -PathType Leaf" in module
    )
    assert "core-hardening certification must not publish external application-control attestation evidence" in module
    assert "core-hardening deployment retains false external application-control evidence" in module
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


def test_enterprise_process_json_and_machine_root_contracts() -> None:
    module = read(MODULE)
    module_smoke = read(MODULE_SMOKE)
    codex_requirements = read(WINDOWS_CODEX_REQUIREMENTS)
    claude_policy = read(WINDOWS_CLAUDE_POLICY)
    machine_roots = read(WINDOWS_MACHINE_ROOTS)

    assert "$LASTEXITCODE" not in module
    for contract in (
        "[Diagnostics.ProcessStartInfo]::new()",
        "$start.UseShellExecute = $false",
        "$start.RedirectStandardOutput = $true",
        "$start.RedirectStandardError = $true",
        "$process.WaitForExit($TimeoutSeconds * 1000)",
        "exit_code = [int]$process.ExitCode",
        "ConvertTo-DefenseClawWindowsCommandLine",
    ):
        assert contract in module
    command_line_encoder = module[
        module.index("function ConvertTo-DefenseClawWindowsCommandLine {") :
        module.index("function ConvertFrom-DefenseClawProcessText")
    ]
    assert "[AllowEmptyString()]" in command_line_encoder
    assert "[ValidateNotNull()]" in command_line_encoder
    assert "[object[]]$Arguments" in command_line_encoder
    assert "$null -eq $argument -or $argument -isnot [string]" in command_line_encoder
    assert "CharSet = CharSet.Unicode" in module_smoke
    assert "ExactSpelling = true" in module_smoke
    # Spec 005 D1 (docs/specs/005-windows-per-user-hook-lifecycle/):
    # third `Assert-DefenseClawServiceImagePath` call pins the
    # DefenseClawHookEnumerator SCM service's ImagePath alongside
    # the existing gateway + guardian.
    assert module.count("Assert-DefenseClawServiceImagePath `") == 3
    assert "[Text.UTF8Encoding]::new($false)" in module

    requirements_report = module[
        module.index("function Invoke-DefenseClawCodexRequirementsCommand") :
        module.index("function Complete-DefenseClawCodexRequirementsRemoval")
    ]
    assert requirements_report.index("if ([int]$probe.exit_code -ne 0") < requirements_report.index(
        "@('requirements_path'"
    )
    teardown_report = module[
        module.index("function Invoke-DefenseClawManagedHooksTeardownCommand") :
        module.index("function Assert-DefenseClawInstalledConfig")
    ]
    assert teardown_report.index("if ([int]$probe.exit_code -ne 0") < teardown_report.index(
        "@('manifest_path'"
    )
    assert "ConvertTo-DefenseClawBoundedDiagnostic -Value $detail" in teardown_report
    assert "body = trimWindowsJSONBOM(body)" in codex_requirements
    assert "bytes.TrimPrefix(body, []byte{0xef, 0xbb, 0xbf})" in codex_requirements

    for contract in (
        "registry.QUERY_VALUE|registry.WOW64_64KEY",
        '"Common AppData"',
        "valueType != registry.SZ",
        "ValidateFixedNTFSMountedPath(clean)",
        "windows.FILE_ATTRIBUTE_REPARSE_POINT",
    ):
        assert contract in machine_roots
    assert "winpath.TrustedProgramData()" in codex_requirements
    assert "winpath.TrustedProgramData()" in read(WINDOWS_CODEX_POLICY)
    assert "winpath.TrustedProgramData()" in read(WINDOWS_MANAGED_RUNTIME)
    assert "winpath.TrustedProgramFiles()" in read(WINDOWS_MANAGED_POLICY)
    assert "winpath.TrustedProgramData" in read(WINDOWS_CODEX_MACHINE_POLICY)

    assert "winpath.TrustedProgramFiles" in claude_policy
    assert "windows.KnownFolderPath(" not in claude_policy
    assert "CurrentUserKnownFolderPath" not in claude_policy


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
        secure_client_program_files = (
            Path(expected["program_files"]) / "Cisco" / "Cisco Secure Client"
        )
        secure_client_program_data = (
            Path(expected["program_data"]) / "Cisco" / "Cisco Secure Client"
        )
        assert Path(status["install_root"]) == secure_client_program_files / "DefenseClaw"
        assert Path(status["state_root"]) == secure_client_program_data / "DefenseClaw"
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
    secure_client_program_files = (
        Path(expected["program_files"]) / "Cisco" / "Cisco Secure Client"
    )
    secure_client_program_data = (
        Path(expected["program_data"]) / "Cisco" / "Cisco Secure Client"
    )
    assert Path(plan["install_root"]).parent == (
        secure_client_program_files / "DefenseClaw-Cert"
    )
    assert Path(plan["state_root"]).parent == (
        secure_client_program_data / "DefenseClaw-Cert"
    )
    assert Path(plan["staging_root"]).parent == (
        secure_client_program_data / "DefenseClaw-Cert-Staging"
    )
    assert Path(plan["work_root"]).parent == (
        secure_client_program_data / "DefenseClaw-Cert-Work"
    )
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
            "certification_codex_home": True,
            "allow_unsigned": True,
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
    assert "Where-Object { $_ -gt 0 }" in capture
    assert "$taskAbsent = $true" in capture
    assert "[void]$script:ScheduledTasks.Remove($safeTaskName)" in capture
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

    assert "$home =" not in harness.lower()
    assert "$certificationhome =" in harness.lower()
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
    temp_snapshot = harness[
        harness.index("function Get-EnterprisePowerShellTempSnapshot") : harness.index(
            "function Update-EnterprisePowerShellTempObservation"
        )
    ]
    assert "$script:KnownProgramData" in temp_snapshot
    assert "$script:WindowsDirectory 'Temp'" not in temp_snapshot
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
    assert "Get-StableGuardianAuthorizationSemanticSnapshot" in harness
    assert "hostile unregister probe authorization semantics" in harness
    assert "$controlLedgerDigest" not in harness

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
    assert "$maximumTextFileBytes = 8MB" in harness
    assert "$maximumTotalTextBytes = 64MB" in harness
    assert "Test-CertificationEvidenceTextFile" in harness
    assert "Get-CertificationTreeEntriesNoFollow" in harness
    assert "$maximumEntries = 100000" in harness
    assert "-IncludeReparse" in harness
    assert "staged-binary-digests.json" in harness
    assert "Copy-Item -LiteralPath $entry.FullName -Destination $logRoot -Recurse" not in harness


def test_certification_exercises_bounded_sparse_runtime_recovery() -> None:
    harness = read(HARNESS)

    sparse = harness[
        harness.index("function Start-ActiveUserSparseArtifactAttack") : harness.index(
            "function Stop-ActiveUserSparseArtifactAttack"
        )
    ]
    sparse_stop = harness[
        harness.index("function Stop-ActiveUserSparseArtifactAttack") : harness.index(
            "function Get-EnterprisePowerShellTempSnapshot"
        )
    ]

    assert "Test-ManagedSparseOversizedArtifactRecovery" in harness
    assert "Start-ActiveUserSparseArtifactAttack" in harness
    assert "Stop-ActiveUserSparseArtifactAttack" in harness
    assert "FSCTL_SET_SPARSE" in harness
    assert "$script:SparseAttackLogicalBytes = [int64]1099511627776" in harness
    assert "$script:SparseAttackMaxAllocatedBytes = [int64]1048576" in harness
    assert "$script:SparseAttackMaxGuardianWorkingSetGrowthBytes = [int64]268435456" in harness
    assert "$script:ManagedArtifactDigestMaxBytes = [int64]4194304" in harness
    assert "PeakWorkingSet64" in harness
    assert "guardian_lifetime_peak_working_set_growth_bytes" in harness
    assert "guardian_lifetime_peak_working_set_growth_limit_bytes" in harness
    assert "$taskArguments.Length -gt 30000" in sparse
    assert "Task Scheduler argument budget" in sparse
    assert "-File \"' + $payload" in sparse
    assert "$payloadSHA256 = Get-FileDigest $payload" in sparse
    assert "$encoded" not in sparse
    assert "repair_observation_seconds = $RepairTimeoutSeconds" in sparse
    assert "if ($canonicalRecreated)" in sparse
    assert "$renamedToQuarantine -and $canonicalRecreated" not in sparse
    assert "-TimeoutSeconds ($RepairTimeoutSeconds + 15)" in sparse_stop
    assert "RetainedEvidencePath" in sparse_stop
    assert "retained-sparse-recovery-evidence" in sparse_stop
    assert "-not [bool]$evidence.renamed_to_quarantine" not in sparse_stop
    assert "-not [bool]$evidence.canonical_recreated" not in sparse_stop
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
    assert "canonical_recreation_observed" in harness
    assert "watcher_observation_authoritative = $false" in harness
    assert "retained_evidence_path" in harness
    assert "exact_bytes_restored = $true" in harness
    assert "exact_owner_and_dacl_restored = $true" in harness
    assert "secret_material_recorded = $false" in harness
    assert "guardian-sparse-oversized-runtime-auto-heal" in harness
    bounded_match = harness[
        harness.index("function Test-BoundedArtifactSnapshotMatch") : harness.index(
            "function Assert-SameArtifactSnapshots"
        )
    ]
    repair_wait = harness[
        harness.index("function Wait-ForArtifactRepair") : harness.index(
            "function Assert-ArtifactSetSettles"
        )
    ]
    assert "$stream.Length -gt $script:ManagedArtifactDigestMaxBytes" in bounded_match
    assert "$total -gt $script:ManagedArtifactDigestMaxBytes" in bounded_match
    assert "$sha256.TransformBlock(" in bounded_match
    assert "Test-BoundedArtifactSnapshotMatch $snapshot" in repair_wait
    assert "Get-FileDigest" not in repair_wait
    hardlink_probe = harness[
        harness.index("function Test-GuardianRepairsManagedHardLink") : harness.index(
            "function Get-GuardianResourceObservation"
        )
    ]
    assert "$ClaudeOnly" in hardlink_probe
    assert "'hooks\\.hook-claudecode.token'" in hardlink_probe
    assert "'hooks\\.hook-codex.token'" in hardlink_probe


def test_latest_windows_retest_harness_repairs_are_scoped_and_fail_closed() -> None:
    harness = read(HARNESS)

    def function(name: str) -> str:
        match = re.search(
            rf"(?ms)^function {re.escape(name)}\b.*?(?=^function |\Z)",
            harness,
        )
        assert match is not None, name
        return match.group(0)

    acl_denial = function("Test-ChangeACLDenied")
    assert "$code -ne 0 -and $beforeSDDL -ceq $afterSDDL" in acl_denial
    assert "want nonzero denial" in acl_denial
    assert "$code -eq 5" not in acl_denial

    managed_environment = function("Get-ManagedCLIEnvironment")
    assert "DEFENSECLAW_HOME = Join-Path $script:StateRoot 'runtime'" in managed_environment
    assert 'DEFENSECLAW_WINDOWS_SERVICE_ACCOUNT = "NT SERVICE\\$($script:GatewayServiceName)"' in managed_environment
    assert "DEFENSECLAW_WINDOWS_GATEWAY_SERVICE_NAME = $script:GatewayServiceName" in managed_environment
    assert "DEFENSECLAW_WINDOWS_SERVICE_NAME = $script:GatewayServiceName" in managed_environment

    temp_observer = function("Update-EnterprisePowerShellTempObservation")
    assert "catch {" in temp_observer
    assert "$aclError = $_" in temp_observer
    assert "$pathExists = Test-Path" in temp_observer
    assert "if (-not $pathExists)" in temp_observer
    assert "throw $aclError" in temp_observer

    normal_attribution = function("Get-NormalModeEnterpriseAttributionSnapshot")
    assert "$immutableDigestPaths.Contains(" in normal_attribution
    assert "last_write_utc_ticks = 0" in normal_attribution
    assert "state = [string]$service.state" not in normal_attribution
    assert "sddl = [string]$row.sddl" in normal_attribution

    ledger_semantics = function("Get-GuardianAuthorizationSemanticSnapshot")
    assert "PSObject.Properties['updated_at']" in ledger_semantics
    assert "PSObject.Properties.Remove('updated_at')" in ledger_semantics
    assert "Assert-PathBelow" in ledger_semantics

    stable_ledger = function("Get-StableGuardianAuthorizationSemanticSnapshot")
    assert "AddSeconds(10)" in stable_ledger
    assert "Start-Sleep -Milliseconds 100" in stable_ledger
    assert "ConvertTo-Json -Compress -Depth 8" in stable_ledger

    healthy = function("Assert-HealthyGuardianJSON")
    assert "$result.JSON.PSObject.Properties['manifest']" in healthy

    access = function("Assert-NoStandardUserAccess")
    for mutation_right in (
        "WriteData",
        "AppendData",
        "WriteAttributes",
        "WriteExtendedAttributes",
        "DeleteSubdirectoriesAndFiles",
        "ChangePermissions",
        "TakeOwnership",
    ):
        assert f"FileSystemRights]::{mutation_right}" in access
    assert "FileSystemRights]::Modify" not in access
    assert "FileSystemRights]::FullControl" not in access

    lock_probe = function("Test-ProtectedLifecycleLockSquattingDenied")
    assert "while ($null -ne $rootException.InnerException)" in lock_probe
    assert "$rootException.GetType().FullName" in lock_probe
    assert "-notin @(5, 32, 33)" in lock_probe

    credential_output = function("Read-CredentialedProcessOutputFile")
    assert "AddMilliseconds" in credential_output
    assert "catch [IO.IOException]" in credential_output
    assert "Start-Sleep -Milliseconds 50" in credential_output

    unregistered = function("Test-UnregisteredInteractiveSIDFailsClosed")
    assert "[Diagnostics.ProcessStartInfo]::new()" in unregistered
    assert "$hookProcess.ExitCode" in unregistered
    assert "$LASTEXITCODE" not in unregistered
    assert "enterprise_managed_sid_(?:not_enrolled|unregistered)" in unregistered

    audit = function("Get-ClaudeHookAuditRows")
    assert "Invoke-GatewayCommand" in audit
    assert "Invoke-GatewayProcess" not in audit

    service_snapshot = function("Get-CertificationServiceProcessSnapshot")
    assert "process_created_at = $process.StartTime.ToUniversalTime().ToString('o')" in service_snapshot
    assert "$hostileProcessBaseline = Get-CertificationServiceProcessSnapshot" in harness
    assert "$hostileProcessAfter = Get-CertificationServiceProcessSnapshot" in harness

    restore = function("Restore-ProtectedUserTreeSnapshot")
    assert "'/save'" in function("New-ProtectedUserTreeSnapshot")
    assert "'/restore'" in restore
    assert "$Snapshot.acl_backup" in restore

    self_deny = function("Test-GuardianRepairsPreexistingSelfDenyDACL")
    assert "if ($ClaudeOnly)" in self_deny
    assert "'hookcfg_claudecode'" in self_deny
    assert "'hookcfg_codex'" in self_deny


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
@pytest.mark.parametrize(
    ("script", "required_fields"),
    (
        (
            MODULE_SMOKE,
            (
                "ambient_cmdlet_shadow_ignored",
                "fixed_native_helper_spoof_ignored",
                "command_line_empty_argument_round_trip",
                "command_line_invalid_arguments_rejected",
                "certification_scope_rejections",
                "lifecycle_file_lock_reuse_stable",
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
                "empty_environment_known_folders_recovered",
                "restricted_environment_certification_status_scope",
                "restricted_environment_module_status",
                "all_environment_paths_pinned",
                "module_analysis_cache_disabled",
                "nested_cleanup_verified",
                "environment_restore_verified",
                "hostile_fixture_cleanup_verified",
                "existing_collision_rejected_without_acl_seizure",
                "rendered_targets_version_contract",
                "rendered_config_embedded_rule_pack",
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
                "purge_cases",
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
    if script == BOOTSTRAP_SMOKE:
        launcher_source = str(
            ROOT / "scripts" / "windows-setup-standard-user-launcher.cs"
        ).replace("'", "''")
        capability = subprocess.run(
            [
                engine,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                (
                    "$identity=[Security.Principal.WindowsIdentity]::GetCurrent();"
                    "$principal=[Security.Principal.WindowsPrincipal]::new($identity);"
                    "$whoami=[IO.Path]::Combine("
                    "[Environment]::SystemDirectory,'whoami.exe');"
                    "$groups=(& $whoami /groups /fo csv /nh 2>$null|Out-String);"
                    "if((-not $principal.IsInRole("
                    "[Security.Principal.WindowsBuiltInRole]::Administrator))"
                    "-and $groups -match 'S-1-16-8192'){exit 0};"
                    f"Add-Type -Path '{launcher_source}' -ErrorAction Stop;"
                    "if([DefenseClaw.SetupStandardUserLauncher]::"
                    "IsCurrentProcessElevated()-and "
                    "[DefenseClaw.SetupStandardUserLauncher]::"
                    "CurrentElevatedTokenHasLinkedLimitedToken())"
                    "{exit 0};exit 3"
                ),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8-sig",
            errors="replace",
            timeout=120,
            check=False,
        )
        if capability.returncode == 3:
            pytest.skip(
                "bootstrap smoke requires a real medium standard-user token or "
                "an elevated token with a linked limited half"
            )
        assert capability.returncode == 0, (
            "could not verify bootstrap-smoke token capability\n"
            f"stdout:\n{capability.stdout}\nstderr:\n{capability.stderr}"
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
        if script == BOOTSTRAP_ENVIRONMENT_SMOKE:
            smoke_environment = restricted_windows_bootstrap_environment(
                profile_root
            )
        else:
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
        assert report["purge_cases"]
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
        assert report["empty_environment_known_folders_recovered"] is True
        assert report["restricted_environment_certification_status_scope"] is True
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
    assert "Assert-DefenseClawBootstrapLifecycleScope" in smoke
    assert "-LifecycleAction 'Status'" in smoke
    assert "restricted_environment_certification_status_scope = $true" in smoke
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


def test_activation_rollback_and_guardian_failure_contracts_are_durable() -> None:
    module = read(MODULE)
    restore = module[
        module.index("function Restore-DefenseClawTransaction") : module.index(
            "function Assert-DefenseClawRestoredTransactionReadyForActivation"
        )
    ]
    atomic_install = module[
        module.index("function Install-DefenseClawFileAtomic") : module.index(
            "function Write-DefenseClawJsonAtomic"
        )
    ]
    assert "[IO.File]::Replace($temporary, $Destination, $backup, $true)" in atomic_install
    assert "[IO.File]::Replace($temporary, $Destination, $null, $true)" not in atomic_install
    assert "atomic replacement verification failed" in atomic_install
    assert "[switch]$SkipIfContentMatches" in atomic_install
    assert "-SkipIfContentMatches" in restore
    assert (
        "Move-Item -LiteralPath $temporary -Destination $Destination -Force"
        not in atomic_install
    )

    diagnostic = module[
        module.index("function ConvertTo-DefenseClawBoundedDiagnostic") : module.index(
            "function Get-DefenseClawGuardianStatusReport"
        )
    ]
    for contract in (
        "[ValidateRange(64, 4096)][int]$MaxLength = 2048",
        "Bearer <redacted>",
        "$text.Substring(0, $MaxLength - 3) + '...'",
    ):
        assert contract in diagnostic

    report = module[
        module.index("function Get-DefenseClawGuardianStatusReport") : module.index(
            "function Get-DefenseClawLifecycleStatus"
        )
    ]
    lifecycle_status = module[
        module.index("function Get-DefenseClawLifecycleStatus") : module.index(
            "function Wait-DefenseClawFreshGuardianReconcile"
        )
    ]
    wait = module[
        module.index("function Wait-DefenseClawFreshGuardianReconcile") : module.index(
            "function Assert-DefenseClawManagedInstallTree"
        )
    ]
    assert "without a valid JSON report" in report
    assert "guardianReport.PSObject.Properties['errors']" in lifecycle_status
    assert '"guardian status: $(ConvertTo-DefenseClawBoundedDiagnostic' in lifecycle_status
    assert "PSObject.Properties['errors']" in wait
    assert "last_status=$lastStatus" in wait

    install_like = module[
        module.index("function Invoke-DefenseClawInstallLikeLifecycle") : module.index(
            "function Invoke-DefenseClawUninstallLifecycle"
        )
    ]
    service_preparation = module[
        module.index("function Set-DefenseClawManagedServicesForTransaction") : module.index(
            "function Get-DefenseClawLayout"
        )
    ]
    service_registration = service_preparation.index(
        "Set-DefenseClawManagedServices `"
    )
    core_acl_grant = service_preparation.index(
        "Set-DefenseClawManagedCoreAcls `"
    )
    assert service_registration < core_acl_grant
    assert "-DeferAutomaticStart" in service_preparation

    transaction = install_like.index("$snapshot = New-DefenseClawTransaction `")
    fresh_install = install_like.index(
        "if ($Action -eq 'Install') {\n"
        "            # A clean install has no NT SERVICE identities"
    )
    fresh_service_registration = install_like.index(
        "Set-DefenseClawManagedServicesForTransaction `",
        fresh_install,
    )
    fresh_snapshot = install_like.index(
        "Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand `",
        fresh_service_registration,
    )
    assert transaction < fresh_service_registration < fresh_snapshot

    upgrade_snapshot = install_like.index(
        "if ($Action -ne 'Install') {\n"
        "            [void](Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand `"
    )
    upgrade_service_registration = install_like.index(
        "if ($Action -ne 'Install') {\n"
        "            # Upgrade/Repair deliberately capture"
    )
    assert upgrade_snapshot < upgrade_service_registration

    assert "ManagedHooksLifecycleJournalPath" in module
    assert "managed-hooks-lifecycle-snapshot" in module
    assert restore.index("-Action restore") < restore.index("foreach ($file in $snapshot.files)")
    assert restore.index("-Action retire") < restore.index("foreach ($file in $snapshot.files)")
    assert "if (-not [bool]$service.existed)" in restore
    assert "Remove-DefenseClawService -Name ([string]$service.name)" in restore
    assert "$deferredPolicySources" in install_like
    assert install_like.index("-Action capture") < install_like.index(
        "$attestationNeedsRefresh"
    )
    assert "the exact prior machine enrollment was restored" in install_like
    assert "could not be retired" in install_like


def test_certification_inspects_actual_live_service_tokens() -> None:
    harness = read(HARNESS)
    token_probe = harness[
        harness.index("function Get-CertificationServiceTokenSnapshot") : harness.index(
            "function Get-CertificationFailureActionContract"
        )
    ]

    assert "ServiceTokenNative" in harness
    assert "OpenProcessToken(TOKEN_QUERY) failed" in harness
    assert "TokenIntegrityLevel" in harness
    assert "TokenRestrictedSids" in harness
    assert "IsTokenRestricted" in harness
    assert "'S-1-16-12288'" in token_probe
    assert "'S-1-16-16384'" in token_probe
    assert "$expectedIntegritySID = if ($gateway)" in token_probe
    assert "integrity $($token.IntegritySid), want $expectedIntegrityName" in token_probe
    assert "expected_integrity_sid = $expectedIntegritySID" in token_probe
    assert "if (-not $gateway -and" in token_probe
    assert "service_sid_group_required = -not $gateway" in token_probe
    assert "service_sid_group_count = $serviceGroups.Count" in token_probe
    assert "foreach ($requiredSID in @($serviceSID, 'S-1-1-0', 'S-1-5-33'))" in token_probe
    assert "restricted SID list lacks one exact service-logon SID" in token_probe
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
    assert "High gateway/System guardian integrity" in harness
    assert "service-SID identity/group semantics" in harness
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
    assert "present = Test-Path" in probe
    assert "requires WTSActive guardian reconciliation" in probe
    assert "Add-NotApplicableProbe" in probe
    assert "Test-ChangeACLDenied" in probe
    assert "want ERROR_ACCESS_DENIED=5" in probe
    assert "--connector ([string]$input.connector)" in probe
    assert "connector = if ($ClaudeOnly) { 'claudecode' } else { 'codex' }" in probe
    assert "[Diagnostics.ProcessStartInfo]::new()" in unregistered
    assert "'hook --connector ' + [string]$inputObject.connector" in unregistered
    assert "$hookProcess.ExitCode" in unregistered
    assert "$LASTEXITCODE" not in unregistered


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
    # Both pipes are now drained via ReadToEndAsync so the parent cannot
    # deadlock on a large stderr burst that exceeds the pipe buffer, and
    # WaitForExit uses a bounded budget so a hung child fails the smoke
    # rather than the CI job (slice-3 CR feedback + follow-up).
    assert "$nestedProcess.StandardOutput.ReadToEndAsync()" in helper_capture_smoke
    assert "$nestedProcess.StandardError.ReadToEndAsync()" in helper_capture_smoke
    assert "$nestedProcess.WaitForExit($detachedHelperWaitBudgetMs)" in helper_capture_smoke
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
    selector = harness[
        harness.index("function Assert-MachineWidePowerShellPath") : harness.index(
            "function Invoke-NativeProcess"
        )
    ]

    assert "[string]$InstallerPath = ''" in harness
    assert "$resolvedInstallerPath = if ([string]::IsNullOrWhiteSpace($InstallerPath))" in harness
    assert "Join-Path (Split-Path -Parent $PSScriptRoot)" not in harness
    assert "ProcessPath" not in selector
    assert "Get-Process -Id $PID" not in selector
    assert "[Environment+SpecialFolder]::ProgramFiles" in selector
    assert "Assert-MachineWidePowerShellPath" in selector
    assert "credentialed child PowerShell must be machine-wide" in selector
    assert "PowerShell\\7\\pwsh.exe" in selector
    assert "WindowsPowerShell\\v1.0\\powershell.exe" in harness
    assert "Ensure Read & Execute access" in harness
    assert "-Credential $Credential" in harness
    assert "target_execution_succeeded = $true" in harness
    assert "load_user_profile_requested = $false" in harness
    assert "BootstrapPowerShellExecutable" in harness
    assert "$start.Environment.Clear()" in harness
    assert "StrictWindowsBootstrapEnvironment" in harness
    assert "PSModulePath" in harness
    assert "'/noconfig'" in harness
    assert "-FilePath $script:BootstrapPowerShellExecutable" in harness
    native_runner = harness[
        harness.index("function Invoke-NativeProcess") : harness.index(
            "function Set-ICaclsOwnerAndDacl"
        )
    ]
    assert "$process.WaitForExit()" in native_runner
    assert "Stop-NativeProcessTree" in native_runner
    assert "IsNullOrWhiteSpace($stderrText)" in native_runner
    assert "Protect-SensitiveDisplayText $failureText" in native_runner
    strict_environment = harness[
        harness.index("if ($StrictWindowsBootstrapEnvironment)") : harness.index(
            "foreach ($argument in $ArgumentList)"
        )
    ]
    assert "SystemRoot = $script:WindowsDirectory" in strict_environment
    for poisoned_name in ("windir", "ProgramFiles", "ProgramData"):
        assert f"{poisoned_name} =" not in strict_environment


def test_restricted_environment_status_uses_trusted_machine_roots() -> None:
    module = read(MODULE)
    smoke = read(BOOTSTRAP_ENVIRONMENT_SMOKE)

    resolver = module[
        module.index("function Get-DefenseClawTrustedMachineRoots") : module.index(
            "# Bind privileged cmdlets"
        )
    ]
    assert "[Environment]::SystemDirectory" in resolver
    assert "[Microsoft.Win32.RegistryView]::Registry64" in resolver
    assert "'ProgramFilesDir'" in resolver
    assert "'Common AppData'" in resolver
    assert "DoNotExpandEnvironmentNames" in resolver
    assert "[Environment]::GetFolderPath" not in resolver

    volume_identity = module[
        module.index("function Assert-DefenseClawLayoutVolumeIdentity") : module.index(
            "function New-DefenseClawLayoutDirectories"
        )
    ]
    assert "[switch]$AllowMissingCertificationCodexHome" in volume_identity
    assert "-AllowMissing:$AllowMissingCertificationCodexHome" in volume_identity
    assert "-AllowMissingCertificationCodexHome:($Action -in @('Status', 'Verify'))" in module

    assert "Invoke-DefenseClawEnterpriseLifecycle" in smoke
    assert "-Action Status" in smoke
    assert "-CertificationCodexHome $certificationCodexHome" in smoke
    assert "-AllowUnsigned" in smoke
    assert "restricted_environment_module_status = $true" in smoke
    assert "module Status did not remain a read-only absent deployment" in smoke


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

    service_names = harness[
        harness.index("function Get-NormalModeServiceNames") : harness.index(
            "function Test-NormalModeLiveAutoHeal"
        )
    ]
    assert "[AllowEmptyCollection()]" in service_names
    assert "$Services |" in service_names
    assert "ForEach-Object { [string]$_.name }" in service_names
    assert ".services.name" not in harness

    live_repair = harness[
        harness.index("function Test-NormalModeLiveAutoHeal") : harness.index(
            "function Test-CandidateCodexHomeResolverContract"
        )
    ]
    assert "[switch]$RequireEnterpriseAbsent" in live_repair
    assert "Get-NormalModeEnterpriseMachineSnapshot" in live_repair
    assert "requires an absent run-scoped" in live_repair
    assert "Get-CertificationPersistentLifecycleLockBaseline" in live_repair
    absent_paths = live_repair[
        live_repair.index("$requiredAbsentPaths = @(") : live_repair.index(
            ") | ForEach-Object { ConvertTo-CanonicalPath $_ }"
        )
    ]
    assert "$script:LifecycleLockDirectory" not in absent_paths
    assert "$script:CodexVendorDirectory" in live_repair
    assert "$script:ClaudeManagedPolicyPath" in live_repair
    assert "Assert-SameObjectJSON" in live_repair
    assert "enterprise_absent_before = [bool]$RequireEnterpriseAbsent" in live_repair
    assert "run_scoped_enterprise_absent_before" in live_repair
    assert "persistent_lifecycle_lock_allowed = $true" in live_repair
    assert "persistent_lifecycle_lock_baseline = $persistentLockBaseline" in live_repair
    assert "machine_before = $machineBefore" in live_repair
    assert "machine_after = $machineAfter" in live_repair
    clear_environment = live_repair.index(
        "[Environment]::GetEnvironmentVariables('Process').Keys"
    )
    exact_trust = live_repair.index("-Label 'trusted-path-add'")
    init = live_repair.index("-Label 'init'")
    assert clear_environment < exact_trust < init
    assert "'setup', 'trusted-paths', 'add', $runtimeRoot, '--json'" in live_repair
    assert "-Label 'trusted-path-list-before-init'" in live_repair
    assert "-Label 'trusted-path-list-after-init'" in live_repair
    assert live_repair.index("-Label 'trusted-path-list-after-init'") > init
    assert "init did not retain exactly the canonical trusted runtime root" in live_repair
    assert "Join-Path $syntheticHome '.local\\bin'" in live_repair
    assert "Assert-ExactNormalModeRuntimeRoot" in live_repair
    assert "trusted runtime root escaped the exact synthetic" in live_repair
    assert "trusted_prefix_escape_rejections = $trustedPrefixEscapeRejections" in live_repair
    assert "trusted_prefix_escape_rejections -ne 3" in live_repair
    assert "$env:DEFENSECLAW_TRUSTED_BIN_PREFIXES" not in live_repair
    assert "config.yaml does not contain exactly the canonical runtime root" in live_repair
    assert "[string]$_.source -ceq 'config'" in live_repair
    assert "agent_selection.json does not contain exactly one Codex selection" in live_repair
    assert "expected Codex path, version, and SHA-256" in live_repair
    assert "trusted_bin_prefix_persisted = $true" in live_repair
    assert "agent_selection_verified = $true" in live_repair
    assert "Assert-NormalModeRuntimeFileSecurity" in live_repair
    assert '-Owner "*$($script:PrimarySID)"' in live_repair
    assert '"*$($script:PrimarySID):F"' in live_repair
    assert "runtime_files_target_owned = $true" in live_repair
    assert "trusted_bin_prefix_exact = $true" in live_repair
    assert "function Invoke-NormalModeProcess" in live_repair
    assert "function Stop-NormalModeProcessTree" in live_repair
    assert "timed out after $TimeoutSeconds seconds" in live_repair
    assert "diagnostics: stdout=$stdoutPath stderr=$stderrPath" in live_repair
    assert "[normal-mode] starting $Label" in live_repair
    assert "[normal-mode] completed $Label" in live_repair
    gateway_setup = live_repair.index("-Label 'gateway-config-offline'")
    assert gateway_setup > init
    assert "'gateway'," in live_repair[gateway_setup - 400 : gateway_setup]
    assert "'--api-port'," in live_repair[gateway_setup - 400 : gateway_setup]
    assert "'--non-interactive'," in live_repair[gateway_setup - 400 : gateway_setup]
    assert "'--no-verify'" in live_repair[gateway_setup - 400 : gateway_setup]
    assert "'config', 'show', '--source', '--format', 'json'" in live_repair
    assert "apiPortMatches" not in live_repair
    assert "hook_self_heal:" not in live_repair
    assert "function Get-CodexManagedHookFingerprint" in live_repair
    assert "$managedConfig = Join-Path $codexHome 'managed_config.toml'" in live_repair
    assert "$baselineText = Read-SharedText $managedConfig" in live_repair
    assert "command_windows_count = $commandLiterals.Count" in live_repair
    assert "Microsoft\\.PowerShell\\.Management\\\\Start-Process" in live_repair
    assert "-ArgumentList\\s+@\\(''hook'',''--connector'',''codex''\\)" in live_repair
    assert "$actualHook" in live_repair
    assert "$expectedCanonicalHook" in live_repair
    assert "$privateTrustHashes.Count -ne 0" in live_repair
    assert "synthesized private trusted_hash state" in live_repair
    assert "trust_model = 'managed_source'" in live_repair
    assert "hook_registration_source = 'managed_config.toml'" in live_repair
    assert "Select-Object events, trusted_hashes" not in live_repair
    assert "WriteAllText(\n        $managedConfig," in live_repair
    assert "wrote the managed hook matrix into user config.toml" in live_repair
    assert "return ,$memory.ToArray()" in live_repair
    assert "Get-NormalModeReadinessSnapshot" in live_repair
    assert "last_error=" in live_repair
    assert "final_snapshot=" in live_repair
    for field in (
        "gateway",
        "watchdog",
        "managed_config",
        "event_tables",
        "command_windows",
        "private_trusted_hashes",
        "sha256",
    ):
        assert field in live_repair

    preinstall_live = harness.index(
        "'preinstall-normal-mode-live-hook-auto-heal-is-no-op'"
    )
    preinstall_status = harness.index("'preinstall-normal-mode-is-no-op'")
    enterprise_install = harness.index("Invoke-Check 'enterprise-installer-install'")
    assert preinstall_live < preinstall_status < enterprise_install
    assert "-RequireEnterpriseAbsent" in harness[
        preinstall_live - 300 : preinstall_live + 300
    ]


def test_certification_accepts_only_the_canonical_persistent_lifecycle_lock() -> None:
    harness = read(HARNESS)
    module = read(MODULE)
    baseline = harness[
        harness.index(
            "function Get-CertificationPersistentLifecycleLockBaseline"
        ) : harness.index("function Test-NormalModePreinstallNoOp")
    ]
    for contract in (
        "$children.Count -ne 1",
        "[int64]$lockItem.Length -ne 0",
        "[IO.FileAttributes]::ReparsePoint",
        "$rules.Count -ne 2",
        "'S-1-5-18'",
        "'S-1-5-32-544'",
        "[Security.AccessControl.FileSystemRights]::FullControl",
        "exact_single_child = $true",
        "zero_bytes = $true",
        "canonical_acl = $true",
    ):
        assert contract in baseline

    cleanup = harness[
        harness.index("function Invoke-BoundedCleanup") : harness.index(
            "function Write-FinalEvidence"
        )
    ]
    assert "Get-CertificationPersistentLifecycleLockBaseline" in cleanup
    assert "persistent lifecycle lock baseline" in cleanup
    assert "persistent_lifecycle_lock_preinstall" in harness
    assert "persistent_lifecycle_lock_cleanup" in harness

    exit_lock = module[
        module.index("function Exit-DefenseClawLifecycleLock") : module.index(
            "function Test-DefenseClawWriteLikeRights"
        )
    ]
    assert "lock identity intentionally persists across" in exit_lock
    assert "deleting/recreating" in exit_lock

    smoke = read(MODULE_SMOKE)
    assert smoke.count("Enter-DefenseClawLifecycleLock `") >= 2
    assert "persistent lifecycle file lock changed across consecutive acquisitions" in smoke
    assert "lifecycle_file_lock_reuse_stable = $elevated" in smoke


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
@pytest.mark.parametrize(
    "engine",
    windows_powershell_engines() or (None,),
    ids=lambda engine: Path(engine).stem if engine else "missing",
)
def test_normal_mode_empty_service_inventory_is_strict_mode_safe(
    engine: str | None,
    tmp_path: Path,
) -> None:
    assert engine, "Windows CI must provide Windows PowerShell 5.1 or PowerShell 7"
    harness = read(HARNESS)
    helper = harness[
        harness.index("function Get-NormalModeServiceNames") : harness.index(
            "function Test-NormalModeLiveAutoHeal"
        )
    ]
    probe = tmp_path / f"empty-service-inventory-{Path(engine).stem}.ps1"
    probe.write_text(
        "Set-StrictMode -Version Latest\n"
        "$ErrorActionPreference = 'Stop'\n"
        + helper
        + "\n$names = @(Get-NormalModeServiceNames -Services @())\n"
        + "if ($names.Count -ne 0) { throw 'empty inventory produced a name' }\n"
        + "'ok'\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            engine,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(probe),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8-sig",
        errors="replace",
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, (
        f"empty service inventory failed under {engine}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert result.stdout.strip() == "ok"


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
@pytest.mark.parametrize(
    "engine",
    windows_powershell_engines() or (None,),
    ids=lambda engine: Path(engine).stem if engine else "missing",
)
def test_atomic_managed_file_replacement_is_idempotent_on_every_engine(
    engine: str | None,
    tmp_path: Path,
) -> None:
    assert engine, "Windows CI must provide Windows PowerShell 5.1 or PowerShell 7"
    module = read(MODULE)
    atomic_install = module[
        module.index("function Install-DefenseClawFileAtomic") : module.index(
            "function Write-DefenseClawJsonAtomic"
        )
    ]
    probe = tmp_path / f"atomic-file-replacement-{Path(engine).stem}.ps1"
    probe.write_text(
        "Set-StrictMode -Version Latest\n"
        "$ErrorActionPreference = 'Stop'\n"
        "$utilityModule = [IO.Path]::Combine(\n"
        "    $PSHOME, 'Modules', 'Microsoft.PowerShell.Utility',\n"
        "    'Microsoft.PowerShell.Utility.psd1'\n"
        ")\n"
        "if (-not [IO.File]::Exists($utilityModule)) {\n"
        "    throw \"trusted engine-local module is missing: $utilityModule\"\n"
        "}\n"
        "Microsoft.PowerShell.Core\\Import-Module -Name $utilityModule "
        "-Force -ErrorAction Stop\n"
        "function Assert-DefenseClawNoReparsePath {\n"
        "    param([Parameter(Mandatory)][string]$Path, "
        "[switch]$AllowMissingLeaf)\n"
        "}\n"
        "function New-DefenseClawDirectory {\n"
        "    param([Parameter(Mandatory)][string]$Path)\n"
        "    [void][IO.Directory]::CreateDirectory($Path)\n"
        "}\n"
        + atomic_install
        + r'''
$root = [IO.Path]::Combine(
    [IO.Path]::GetTempPath(),
    "DefenseClaw-AtomicFile-$([Guid]::NewGuid().ToString('N'))"
)
[void][IO.Directory]::CreateDirectory($root)
try {
    $source = [IO.Path]::Combine($root, 'source.txt')
    $destination = [IO.Path]::Combine($root, 'destination.txt')
    [IO.File]::WriteAllText($source, 'first')
    $created = [IO.Path]::Combine($root, 'created.txt')
    Install-DefenseClawFileAtomic -Source $source -Destination $created
    if ([IO.File]::ReadAllText($created) -cne 'first') {
        throw 'initial destination creation was not exact'
    }
    [IO.File]::WriteAllText($destination, 'old')
    Install-DefenseClawFileAtomic -Source $source -Destination $destination
    if ([IO.File]::ReadAllText($destination) -cne 'first') {
        throw 'first existing-destination replacement was not exact'
    }
    [IO.File]::WriteAllText($source, 'second')
    Install-DefenseClawFileAtomic -Source $source -Destination $destination
    if ([IO.File]::ReadAllText($destination) -cne 'second') {
        throw 'repeated existing-destination replacement was not exact'
    }
    $sameContentHandle = [IO.File]::Open(
        $destination,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        Install-DefenseClawFileAtomic `
            -Source $source `
            -Destination $destination `
            -SkipIfContentMatches
    }
    finally {
        $sameContentHandle.Dispose()
    }
    if ([IO.File]::ReadAllText($destination) -cne 'second') {
        throw 'same-content rollback changed its protected destination'
    }
    if (@([IO.Directory]::GetFiles($root, '*.new.*')).Count -ne 0 -or
        @([IO.Directory]::GetFiles($root, '*.backup.*')).Count -ne 0) {
        throw 'atomic replacement left a staging or backup file behind'
    }
    'ok'
}
finally {
    if ([IO.Directory]::Exists($root)) {
        [IO.Directory]::Delete($root, $true)
    }
}
''',
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            engine,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(probe),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8-sig",
        errors="replace",
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, (
        f"atomic managed file replacement failed under {engine}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert result.stdout.strip() == "ok"


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
@pytest.mark.parametrize(
    "engine",
    windows_powershell_engines() or (None,),
    ids=lambda engine: Path(engine).stem if engine else "missing",
)
def test_normal_mode_shared_stream_reader_preserves_empty_byte_arrays(
    engine: str | None,
    tmp_path: Path,
) -> None:
    assert engine, "Windows CI must provide Windows PowerShell 5.1 or PowerShell 7"
    harness = read(HARNESS)
    functions = harness[
        harness.index("function Read-SharedBytes") : harness.index(
            "function Get-BytesSHA256"
        )
    ]
    probe = tmp_path / f"shared-stream-{Path(engine).stem}.ps1"
    probe.write_text(
        functions
        + r'''
$root = [IO.Path]::Combine(
    [IO.Path]::GetTempPath(),
    "DefenseClaw-SharedStream-$([Guid]::NewGuid().ToString('N'))"
)
[IO.Directory]::CreateDirectory($root) | Out-Null
try {
    $empty = [IO.Path]::Combine($root, 'empty.log')
    [IO.File]::WriteAllBytes($empty, [byte[]]::new(0))
    $emptyBytes = Read-SharedBytes $empty
    if ($emptyBytes -isnot [byte[]] -or $emptyBytes.Length -ne 0) {
        throw 'zero-byte read did not preserve the byte[] contract'
    }
    if ((Read-SharedText $empty) -cne '') {
        throw 'zero-byte text did not decode to the empty string'
    }

    $nonempty = [IO.Path]::Combine($root, 'nonempty.log')
    [IO.File]::WriteAllText(
        $nonempty,
        'DefenseClaw stream probe',
        [Text.UTF8Encoding]::new($false)
    )
    if ((Read-SharedText $nonempty) -cne 'DefenseClaw stream probe') {
        throw 'non-empty redirected text changed during read'
    }

    $openPath = [IO.Path]::Combine($root, 'concurrently-open.log')
    [IO.File]::WriteAllText(
        $openPath,
        'open stream probe',
        [Text.UTF8Encoding]::new($false)
    )
    $open = [IO.FileStream]::new(
        $openPath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
    )
    try {
        if ((Read-SharedText $openPath) -cne 'open stream probe') {
            throw 'concurrently-open redirected file could not be read'
        }
    } finally {
        $open.Dispose()
    }

    $stdout = [IO.Path]::Combine($root, 'child.stdout.log')
    $stderr = [IO.Path]::Combine($root, 'child.stderr.log')
    $enginePath = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $enginePath
    $start.Arguments = '-NoLogo -NoProfile -NonInteractive -Command "exit 0"'
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $child = [Diagnostics.Process]::new()
    $child.StartInfo = $start
    try {
        if (-not $child.Start()) {
            throw 'empty-output child did not start'
        }
        $stdoutTask = $child.StandardOutput.ReadToEndAsync()
        $stderrTask = $child.StandardError.ReadToEndAsync()
        if (-not $child.WaitForExit(30000)) {
            try { $child.Kill() } catch {}
            throw 'empty-output child exceeded its bounded timeout'
        }
        $child.WaitForExit()
        $stdoutText = [string]$stdoutTask.GetAwaiter().GetResult()
        $stderrText = [string]$stderrTask.GetAwaiter().GetResult()
        $exitCode = $child.ExitCode
        if ($exitCode -isnot [int] -or [int]$exitCode -ne 0) {
            throw "empty-output child exited $exitCode"
        }
    } finally {
        $child.Dispose()
    }
    [IO.File]::WriteAllText(
        $stdout,
        $stdoutText,
        [Text.UTF8Encoding]::new($false)
    )
    [IO.File]::WriteAllText(
        $stderr,
        $stderrText,
        [Text.UTF8Encoding]::new($false)
    )
    foreach ($redirectedPath in @($stdout, $stderr)) {
        $redirectedBytes = Read-SharedBytes $redirectedPath
        if ($redirectedBytes -isnot [byte[]] -or
            $redirectedBytes.Length -ne 0 -or
            (Read-SharedText $redirectedPath) -cne '') {
            throw 'empty-output child produced unexpected redirected bytes'
        }
    }
    [pscustomobject]@{
        ok = $true
        engine = $PSVersionTable.PSVersion.ToString()
        zero_byte = $true
        nonempty = $true
        concurrently_open = $true
        bounded_empty_child = $true
        exact_exit_code = [int]$exitCode
    } | ConvertTo-Json -Compress
} finally {
    if ([IO.Directory]::Exists($root)) {
        [IO.Directory]::Delete($root, $true)
    }
}
''',
        encoding="utf-8",
    )
    completed = subprocess.run(
        [
            engine,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(probe),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8-sig",
        errors="replace",
        timeout=90,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["ok"] is True
    assert result["zero_byte"] is True
    assert result["nonempty"] is True
    assert result["concurrently_open"] is True
    assert result["bounded_empty_child"] is True
    assert result["exact_exit_code"] == 0


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
@pytest.mark.parametrize(
    "engine",
    windows_powershell_engines() or (None,),
    ids=lambda engine: Path(engine).stem if engine else "missing",
)
def test_normal_mode_readiness_diagnostics_cover_each_failure_boundary(
    engine: str | None,
    tmp_path: Path,
) -> None:
    assert engine, "Windows CI must provide Windows PowerShell 5.1 or PowerShell 7"
    harness = read(HARNESS)
    functions = harness[
        harness.index("function Read-SharedBytes") : harness.index(
            "function ConvertTo-NormalModeProcessArgument"
        )
    ]
    probe = tmp_path / f"readiness-diagnostics-{Path(engine).stem}.ps1"
    probe.write_text(
        functions
        + r'''
function Get-ProcessExecutable([int]$PIDValue) {
    if ($PIDValue -eq 424242) {
        throw 'authorization: Bearer diagnostic-secret'
    }
    return "C:\fixture\gateway-$PIDValue.exe"
}

$root = [IO.Path]::Combine(
    [IO.Path]::GetTempPath(),
    "DefenseClaw-Readiness-$([Guid]::NewGuid().ToString('N'))"
)
[IO.Directory]::CreateDirectory($root) | Out-Null
try {
    $gatewayPID = [IO.Path]::Combine($root, 'gateway.pid')
    $watchdogPID = [IO.Path]::Combine($root, 'watchdog.pid')
    $managed = [IO.Path]::Combine($root, 'managed_config.toml')

    $missing = Get-NormalModeReadinessSnapshot `
        $gatewayPID $watchdogPID $managed
    if ($missing.gateway.exists -or $missing.watchdog.exists -or
        $missing.managed_config.exists) {
        throw 'missing readiness components were not reported as absent'
    }

    [IO.File]::WriteAllText($gatewayPID, 'token=pid-secret')
    [IO.File]::WriteAllText($watchdogPID, '{"pid":1234}')
    $pidState = Get-NormalModeReadinessSnapshot `
        $gatewayPID $watchdogPID $managed
    if ([string]::IsNullOrWhiteSpace($pidState.gateway.error) -or
        $pidState.gateway.content -match 'pid-secret' -or
        $pidState.gateway.content -notmatch '<redacted>' -or
        $pidState.watchdog.pid -ne 1234 -or
        $pidState.watchdog.executable -cne 'C:\fixture\gateway-1234.exe') {
        throw 'PID parsing or resolved process-path diagnostics are incomplete'
    }

    [IO.File]::WriteAllText($gatewayPID, '424242')
    $processState = Get-NormalModeReadinessSnapshot `
        $gatewayPID $watchdogPID $managed
    if ($processState.gateway.error -match 'diagnostic-secret' -or
        $processState.gateway.error -notmatch 'authorization=<redacted>') {
        throw 'process-path lookup diagnostic was not safely retained'
    }

    $managedText = @'
[hooks]
[[hooks.PreToolUse]]
command_windows = "private full command"
trusted_hash = "private hash"
[[hooks.Stop]]
command_windows = "second private command"
'@
    [IO.File]::WriteAllText(
        $managed,
        $managedText,
        [Text.UTF8Encoding]::new($false)
    )
    $configState = Get-NormalModeReadinessSnapshot `
        $gatewayPID $watchdogPID $managed
    if (-not $configState.managed_config.exists -or
        $configState.managed_config.size -le 0 -or
        $configState.managed_config.sha256 -cnotmatch '^[a-f0-9]{64}$' -or
        -not $configState.managed_config.hook_table -or
        $configState.managed_config.event_tables -ne 2 -or
        $configState.managed_config.command_windows -ne 2 -or
        $configState.managed_config.private_trusted_hashes -ne 1) {
        throw 'managed-config fingerprint counts are incomplete'
    }
    $snapshotJSON = $configState | ConvertTo-Json -Compress -Depth 6
    if ($snapshotJSON -match 'private full command|private hash') {
        throw 'readiness snapshot disclosed private hook registration data'
    }

    $fingerprintRejected = $false
    try {
        $null = Get-CodexManagedHookFingerprint 'not a hook table' 'fixture.exe'
    } catch {
        $fingerprintRejected = (
            $_.Exception.Message -match 'has no owned \[hooks\] table'
        )
    }
    if (-not $fingerprintRejected) {
        throw 'hook fingerprint validation failure was not actionable'
    }

    function Read-SharedBytes([string]$Path) {
        throw 'password=config-read-secret'
    }
    $configFailure = Get-NormalModeReadinessSnapshot `
        ([IO.Path]::Combine($root, 'missing-gateway.pid')) `
        ([IO.Path]::Combine($root, 'missing-watchdog.pid')) `
        $managed
    if ($configFailure.managed_config.error -match 'config-read-secret' -or
        $configFailure.managed_config.error -notmatch 'password=<redacted>') {
        throw 'config-read failure was not safely retained'
    }

    [pscustomobject]@{
        ok = $true
        missing = $true
        pid_parse = $true
        process_path = $true
        config_read = $true
        fingerprint = $true
        redacted = $true
    } | ConvertTo-Json -Compress
} finally {
    if ([IO.Directory]::Exists($root)) {
        [IO.Directory]::Delete($root, $true)
    }
}
''',
        encoding="utf-8",
    )
    completed = subprocess.run(
        [
            engine,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(probe),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8-sig",
        errors="replace",
        timeout=90,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result == {
        "ok": True,
        "missing": True,
        "pid_parse": True,
        "process_path": True,
        "config_read": True,
        "fingerprint": True,
        "redacted": True,
    }


def test_normal_mode_timeout_and_acl_cleanup_are_bounded_and_exact() -> None:
    harness = read(HARNESS)

    active_user = harness[
        harness.index("function Invoke-ActiveUserPowerShell") : harness.index(
            "function Start-ActiveUserFakeGatewayListener"
        )
    ]
    assert "function Stop-CaptureDescendantTree" in active_user
    assert 'killerStart.Arguments = "/PID $($Target.Id) /T /F"' in active_user
    assert active_user.count("Stop-CaptureDescendantTree $process") == 2

    cleanup = harness[
        harness.index("function Get-NormalModeProcessStartIdentity") : harness.index(
            "function Write-FinalEvidence"
        )
    ]
    assert "function Stop-NormalModeFixtureProcesses" in cleanup
    assert "@('gateway.pid', 'watchdog.pid')" in cleanup
    assert "start_identity" in cleanup
    assert "live identity does not match the protected PID record" in cleanup
    assert "@('/PID', [string]$processID, '/T', '/F')" in cleanup
    assert "-TimeoutSeconds 20" in cleanup
    assert "normal-mode cleanup target is not the exact registered" in cleanup
    assert "-Owner '*S-1-5-32-544'" in cleanup
    assert "-Options @('/T', '/C', '/L')" in cleanup
    stop_fixture = cleanup.index("Stop-NormalModeFixtureProcesses $safeNormalHome")
    assert stop_fixture < cleanup.index("Remove-Item `", stop_fixture)


def test_uninstall_transaction_smoke_keeps_receipt_paths_powershell_51_compatible() -> None:
    smoke = read(UNINSTALL_TRANSACTION_SMOKE)

    assert "failed-teardown-self-restored" in smoke
    assert "rollback_verification_only" in smoke
    assert "disconnected target teardown incomplete" in smoke

    assert "('dcut-' + [Guid]::NewGuid().ToString('N'))" in smoke
    assert "function New-HarnessCaseRoot" in smoke
    assert "$receiptProbe.Length -ge 240" in smoke
    assert "legacy MAX_PATH boundary" in smoke
    assert smoke.count("New-HarnessCaseRoot") == 11
    assert "fresh-install-service-bootstrap-rollback-retry" in smoke
    assert "snapshot capture ran before both service identities existed" in smoke
    assert "repeated-first-activation-failure-exact-rollback" in smoke
    assert "lifecycle-snapshot:capture" in smoke
    assert "lifecycle-snapshot:restore" in smoke
    assert "lifecycle-snapshot:retire" in smoke
    assert "purge_cases = @($purgeResults)" in smoke


def test_certification_cleanup_handles_partial_profiles_and_empty_parents() -> None:
    harness = read(HARNESS)
    profile_cleanup = harness[
        harness.index("function Remove-CertificationProfile") : harness.index(
            "function Remove-CertificationRoot"
        )
    ]
    cleanup = harness[
        harness.index("function Invoke-BoundedCleanup") : harness.index(
            "function Write-FinalEvidence"
        )
    ]

    assert "profile cleanup requires the exact local account to be removed first" in profile_cleanup
    assert "$script:HostileProfileExpected" in profile_cleanup
    assert "$script:HostileProfileExpectedWasAbsent" in profile_cleanup
    assert "[bool]$profile.Loaded" in profile_cleanup
    assert "[bool]$profile.Special" in profile_cleanup
    assert "Remove-CimInstance" in profile_cleanup
    assert "residual profile contains a reparse point" in profile_cleanup
    assert cleanup.index("Remove-LocalUser") < cleanup.index(
        "Remove-CertificationProfile"
    )

    parent_cleanup = harness[
        harness.index("function Remove-EmptyCertificationParentRoot") : harness.index(
            "function Register-CertificationSecretFile"
        )
    ]
    assert "$script:ProgramDataStagingRoot" in parent_cleanup
    assert "$script:ProgramDataWorkRoot" in parent_cleanup
    assert "existed_before" in parent_cleanup
    assert "[IO.FileAttributes]::ReparsePoint" in parent_cleanup
    assert "$children = @(" in parent_cleanup
    assert "Remove-Item -LiteralPath $safe -Force" in parent_cleanup
    assert "Remove-EmptyCertificationParentRoot $parentState" in cleanup

    install = harness.index("Invoke-Check 'enterprise-installer-install'")
    for checkpoint in ("fixture", "normal-mode-noop", "certification-isolation"):
        call = harness.index(f"Invoke-CertificationFailureInjection '{checkpoint}'")
        assert call < install


def test_certification_restores_user_tree_security_without_root_recreation_drift() -> None:
    harness = read(HARNESS)
    restore = harness[
        harness.index("function Restore-ProtectedUserTreeSnapshot") : harness.index(
            "function Get-DeploymentDigests"
        )
    ]

    assert "'/MIR'" in restore
    assert "'/COPY:DAT'" in restore
    assert "Restore owner/group without rewriting the DACL" in restore
    assert "$securityRows" in restore
    assert "$metadataRows" in restore
    assert restore.index("foreach ($row in $securityRows)") < restore.index(
        "foreach ($row in $metadataRows)"
    )
    assert "Remove-Item -LiteralPath $safe -Recurse" not in restore
    assert "SetSecurityDescriptorSddlForm" in restore
    assert "$ownerGroupSections" in restore
    assert "'/restore'" in restore
    assert "$Snapshot.acl_backup" in restore
    assert "Assert-SameUserTreeInventory" in restore

    matrix = harness[
        harness.index("function Test-ProtectedUserTreeSecurityRoundTrip") : harness.index(
            "function Get-DeploymentDigests"
        )
    ]
    assert "protected_inheritance = $true" in matrix
    assert "unprotected_inheritance = $true" in matrix
    assert "owner_and_group = $true" in matrix
    assert "canonical_ace_order = $true" in matrix
    assert "inherited_aces = $true" in matrix
    assert "empty_and_nonempty_files = $true" in matrix
    assert "exact_inventory_restored = $true" in matrix
    assert "absent_baseline_removed = $true" in matrix
    assert "acl-roundtrip-absent-baseline-drift" in matrix
    assert "protected-user-acl-round-trip-matrix" in harness


def test_certification_retains_structured_failure_location_and_strictmode_arrays() -> None:
    harness = read(HARNESS)
    error_evidence = harness[
        harness.index("function ConvertTo-CertificationErrorEvidence") : harness.index(
            "function ConvertTo-CanonicalPath"
        )
    ]
    resolver = harness[
        harness.index("function Resolve-ProtectedActiveUser") : harness.index(
            "function Initialize-ActiveUserHandoff"
        )
    ]

    for field in (
        "exception_type",
        "script_stack_trace",
        "script_line_number",
        "offset_in_line",
        "invocation_position",
    ):
        assert field in error_evidence
    assert "Protect-SensitiveDisplayText" in error_evidence
    assert "failure_detail = $script:FailureEvidence" in harness
    assert "wrapper_error_type" in harness
    assert "wrapper_script_stack_trace" in harness
    assert "wrapper_script_line_number" in harness
    assert "$matches = @(" in resolver
    assert "$matches.Count -ne 1" in resolver


def test_non_admin_file_denials_require_access_denied_not_generic_io() -> None:
    harness = read(HARNESS)
    probe = harness[
        harness.index("function Invoke-StandardUserControlProbe") : harness.index(
            "function Assert-ProtectedUserTamperToken"
        )
    ]

    assert "CreateFileW GENERIC_WRITE error" in probe
    assert "CreateFileW GENERIC_READ error" in probe
    assert "public const UInt32 GENERIC_READ = 0x80000000U;" in probe
    assert "[DefenseClawHostileNative]::GENERIC_READ" in probe
    assert "\n        0x80000000," not in probe
    assert probe.count("($errorCode -eq 5)") >= 2
    assert "($credentialError -eq 5)" in probe
    assert "non-authorization I/O failure" in probe
    assert "writable key returned null without an ACCESS_DENIED exception" in probe
    assert "Add-Probe $Name $true $_.Exception.Message" not in probe
    assert "Add-Probe 'read_service_scoped_credential' $true" not in probe


def test_stricter_process_query_denial_is_a_secure_probe_result() -> None:
    harness = read(HARNESS)
    probe = harness[
        harness.index("function Invoke-StandardUserControlProbe") : harness.index(
            "function Assert-ProtectedUserTamperToken"
        )
    ]
    process_checks = probe[
        probe.index("foreach ($process in @(") : probe.index(
            "foreach ($service in @(",
            probe.index("foreach ($process in @("),
        )
    ]

    assert "$queryDenied = $queryError -eq 5" in process_checks
    assert "the service process DACL provides stronger isolation" in process_checks
    assert "Add-NotApplicableProbe" in process_checks
    assert "the process DACL denied the prerequisite" in process_checks
    assert "foreach ($tokenAccess in $tokenAccesses)" in process_checks
    assert "name = 'terminate'" in process_checks
    assert "name = 'inject_thread_vm'" in process_checks
    assert "name = 'vm_write'" in process_checks
    assert "name = 'suspend_resume'" in process_checks
    assert "name = 'write_dac'" in process_checks
    assert "name = 'write_owner'" in process_checks
    assert "name = 'all_access'" in process_checks
    assert "standard user crossed protected boundary" not in probe
    assert "standard-user boundary probe failed or was incomplete" in probe


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
@pytest.mark.parametrize(
    "engine",
    tuple(
        engine
        for engine in windows_powershell_engines()
        if Path(engine).name.casefold() == "pwsh.exe"
    )
    or (None,),
    ids=lambda engine: Path(engine).stem if engine else "missing-pwsh7",
)
def test_generated_standard_user_native_calls_bind_under_powershell_7(
    engine: str | None,
    tmp_path: Path,
) -> None:
    assert engine, "Windows CI must provide PowerShell 7"
    harness = read(HARNESS)
    function = harness[
        harness.index("function Invoke-StandardUserControlProbe") : harness.index(
            "function Assert-ProtectedUserTamperToken"
        )
    ]
    start_marker = "    $probe = @'\n"
    end_marker = "\n'@.Replace('__INPUT__', $inputBase64)"
    start = function.index(start_marker) + len(start_marker)
    generated_probe = function[start : function.index(end_marker, start)]

    fixture_paths: dict[str, str] = {}
    for name in ("gateway", "hook", "config", "manifest", "ledger", "token"):
        path = tmp_path / f"{name}.fixture"
        path.write_text(f"{name}\n", encoding="utf-8")
        fixture_paths[name] = str(path)
    fake_gateway = tmp_path / "gateway.cmd"
    fake_gateway.write_text("@exit /b 1\r\n", encoding="ascii")
    fixture_paths["gateway"] = str(fake_gateway)

    sleeper_arguments = [
        engine,
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "Start-Sleep -Seconds 120",
    ]
    sleepers = [
        subprocess.Popen(
            sleeper_arguments,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        for _ in range(2)
    ]
    try:
        input_object = {
            "gateway_service": "DefenseClawNativeBindingGatewayMissing",
            "guardian_service": "DefenseClawNativeBindingGuardianMissing",
            "gateway_binary": fixture_paths["gateway"],
            "hook_binary": fixture_paths["hook"],
            "config": fixture_paths["config"],
            "manifest": fixture_paths["manifest"],
            "ledger": fixture_paths["ledger"],
            "service_tokens": [
                {"name": "binding", "path": fixture_paths["token"]}
            ],
            "claude_machine_paths": [],
            "connector": "codex",
            "codex_target_enabled": False,
            "codex_vendor_directory": str(tmp_path),
            "codex_machine_policy_directory": str(tmp_path),
            "probe_nonce": "native-binding",
            "probe_sid": "S-1-5-21-0-0-0-1000",
            "target_user": "binding-user",
            "target_home": str(tmp_path),
            "target_sid": "S-1-5-21-0-0-0-1000",
            "gateway_pid": sleepers[0].pid,
            "guardian_pid": sleepers[1].pid,
        }
        encoded_input = base64.b64encode(
            json.dumps(input_object, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        probe = tmp_path / "standard-user-native-binding-pwsh7.ps1"
        probe.write_text(
            generated_probe.replace("__INPUT__", encoded_input),
            encoding="utf-8",
        )
        completed = subprocess.run(
            [
                engine,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(probe),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8-sig",
            errors="replace",
            timeout=90,
            check=False,
        )
    finally:
        for sleeper in sleepers:
            if sleeper.poll() is None:
                sleeper.terminate()
            try:
                sleeper.wait(timeout=10)
            except subprocess.TimeoutExpired:
                sleeper.kill()
                sleeper.wait(timeout=10)

    assert completed.returncode == 17, (
        "the generated standard-user probe stopped before completing its native "
        f"call matrix under {engine}\nstdout:\n{completed.stdout}\n"
        f"stderr:\n{completed.stderr}"
    )
    assert "Cannot convert value \"-2147483648\" to type \"System.UInt32\"" not in (
        completed.stderr
    )


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
    assert "CertificationCodexHome must accompany every unsigned" in harness
    assert "certification lifecycle action" in harness
    assert "signed production actions omit" in harness
    assert "CoreHardeningCertification must accompany only unsigned" in harness
    assert "Claude-only mutating certification actions" in harness
    assert "lifecycle_scope_matrix" in harness
    assert "function Get-CertificationLifecycleScopeArguments" in harness
    assert "$mutation = $Action -in @('Install', 'Upgrade', 'Repair')" in harness
    assert "unsigned stateful lifecycle scope requires the exact initialized" in harness
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


def test_uninstall_returns_shared_vendor_directories_to_their_prior_state() -> None:
    """Uninstall leaves nothing of ours in directories other vendors own."""
    module = read(MODULE)

    # Both serialization locks outlive the policy files they guard.
    assert "CodexManagedHooksLockPath" in module
    assert "ClaudeManagedHooksLockPath" in module
    assert "Remove-DefenseClawCommittedManagedHooksSerializationLocks -Layout $Layout" in module

    # The traverse grant names a virtual account that only exists while the
    # service does, so it is dropped by the caller that deleted the service.
    assert "function Revoke-DefenseClawStateAncestorTraverse" in module
    assert "Revoke-DefenseClawStateAncestorTraverse `" in module
    assert "-GatewayServiceSID $gatewaySID" in module
