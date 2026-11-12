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
import hashlib
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
INSTALL_RECONCILE_SMOKE = (
    ROOT
    / "packaging"
    / "windows"
    / "tests"
    / "enterprise-install-reconcile-smoke.ps1"
)
UNINSTALL_ACL_RECOVERY_SMOKE = (
    ROOT
    / "packaging"
    / "windows"
    / "tests"
    / "enterprise-uninstall-acl-recovery-smoke.ps1"
)
UNINSTALL_NATIVE_CONTRACT_SMOKE = (
    ROOT
    / "packaging"
    / "windows"
    / "tests"
    / "enterprise-uninstall-native-contract-smoke.ps1"
)
UNTRUSTED_METADATA_FALLBACK_SMOKE = (
    ROOT
    / "packaging"
    / "windows"
    / "tests"
    / "enterprise-untrusted-metadata-fallback-smoke.ps1"
)
SELF_UNINSTALL_HELPER_CAPTURE_SMOKE = (
    ROOT
    / "packaging"
    / "windows"
    / "tests"
    / "enterprise-detached-helper-smoke.ps1"
)
INSTALL_ACL_SELF_HEAL_SMOKE = (
    ROOT
    / "packaging"
    / "windows"
    / "tests"
    / "enterprise-install-acl-self-heal-smoke.ps1"
)
DEPLOYMENT_DOC = ROOT / "docs-site" / "content" / "docs" / "enterprise" / "secure-client.mdx"
CERTIFICATION_DOC = ROOT / "docs" / "WINDOWS-ENTERPRISE-CERTIFICATION.md"
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


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell 7 is not installed")
@pytest.mark.allow_subprocess
def test_install_name_reservation_does_not_trust_the_current_account(tmp_path: Path) -> None:
    """Execute the reservation classifier with only its OS ACL reads stubbed.

    The native lifecycle smoke also exercises these cases with real ACLs.
    An account SID keeps its create/owner rights under an unelevated token.
    """
    module = read(MODULE)
    function = _module_function(module, "Get-DefenseClawUntrustedFolderCreator")
    function = function.replace(
        "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value", "$CurrentAccountSID"
    ).replace("Microsoft.PowerShell.Security\\Get-Acl", "Get-TestAcl")
    rights = module[module.index("$script:InstallRootParentChangeRights =") : module.index(
        "function Get-DefenseClawUntrustedFolderCreator"
    )]
    script = tmp_path / "reservation.ps1"
    script.write_text(
        r"""
$ErrorActionPreference = 'Stop'
$script:SystemSID = 'S-1-5-18'
$script:AdministratorsSID = 'S-1-5-32-544'
$script:TrustedInstallerSID = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$CurrentAccountSID = 'S-1-5-21-1000-2000-3000-1234'
$script:OwnerSID = $script:AdministratorsSID
$script:Rules = @()
function Get-TestAcl {
    param([string]$LiteralPath)
    $acl = [pscustomobject]@{}
    $acl | Add-Member ScriptMethod GetSecurityDescriptorSddlForm { param($section) 'D:P' }
    $acl | Add-Member ScriptMethod GetOwner { param($type) [pscustomobject]@{ Value = $script:OwnerSID } }
    $acl | Add-Member ScriptMethod GetAccessRules { param($explicit, $inherited, $type) $script:Rules }
    return $acl
}
"""
        + rights
        + function
        + r"""
$script:Rules = @([pscustomobject]@{
    AccessControlType = [Security.AccessControl.AccessControlType]::Allow
    PropagationFlags = [Security.AccessControl.PropagationFlags]::None
    IdentityReference = [pscustomobject]@{ Value = $CurrentAccountSID }
    FileSystemRights = [Security.AccessControl.FileSystemRights]::CreateDirectories
})
if (-not (Get-DefenseClawUntrustedFolderCreator -Path 'parent')) { throw 'current account create rights were trusted' }
$script:Rules = @()
$script:OwnerSID = $CurrentAccountSID
if (-not (Get-DefenseClawUntrustedFolderCreator -Path 'parent')) { throw 'current account ownership was trusted' }
$script:OwnerSID = $script:AdministratorsSID
if (Get-DefenseClawUntrustedFolderCreator -Path 'parent') { throw 'administrator group owner was refused' }
""",
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script)],
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_bundle_acl_repair_verify_and_uninstall_use_the_same_store_tree() -> None:
    module = read(MODULE)
    contract = module[
        module.index("function Invoke-DefenseClawBundleAclContract"):
        module.index("function Set-DefenseClawManagedAcls")
    ]
    setter = module[
        module.index("function Set-DefenseClawManagedAcls"):
        module.index("function Get-DefenseClawLayout")
    ]
    verifier = module[
        module.index("function Assert-DefenseClawEnterpriseDeployment"):
        module.index("function Get-DefenseClawLifecycleStatus")
    ]
    assert "Get-DefenseClawBundlePathKind -RelativePath $relative" in contract
    assert "Set-DefenseClawPathAcl -Path $item.Path -Kind $item.Kind" in contract
    assert "Assert-DefenseClawCanonicalPathAcl -Path $item.Path -Expected $expected" in contract
    assert "Invoke-DefenseClawBundleAclContract -Layout $Layout -GatewayServiceSID $gatewaySID -Repair" in setter
    assert "Invoke-DefenseClawBundleAclContract -Layout $Layout -GatewayServiceSID $gatewaySID" in verifier
    # Uninstall and purge remove StateRoot as a tree, so nested receipt-named
    # directories do not need another fixed-name parser.
    assert "Remove-DefenseClawManagedTree" in module
    assert "-Path $Layout.StateRoot" in module


def test_windows_shorthand_targets_require_metadata_versions() -> None:
    installer = read(INSTALLER)
    smoke = read(BOOTSTRAP_ENVIRONMENT_SMOKE)
    config_renderer_start = installer.index(
        "function Get-DefenseClawRenderedEnterpriseConfig"
    )
    winget_start = installer.index(
        "function ConvertTo-DefenseClawClaudeWinGetVersion"
    )
    discovery_start = installer.index(
        "function Get-DefenseClawConnectorMetadataVersion"
    )
    renderer_start = installer.index(
        "function Get-DefenseClawRenderedEnterpriseTargets"
    )
    execution_start = installer.index("$bootstrapEnvironment = $null")
    config_renderer = installer[config_renderer_start:discovery_start]
    winget_discovery = installer[winget_start:discovery_start]
    discovery = installer[discovery_start:renderer_start]
    renderer = installer[renderer_start:execution_start]
    shorthand_render_start = installer.index(
        "$renderedManifestBody = Get-DefenseClawRenderedEnterpriseTargets"
    )
    shorthand_render_end = installer.index(
        "$renderRoot = $bootstrapEnvironment.Path", shorthand_render_start
    )
    shorthand_render = installer[shorthand_render_start:shorthand_render_end]

    assert 'rule_pack_dir: ""' in config_renderer
    assert "Get-DefenseClawConnectorJsonMetadataVersion" in discovery
    assert "AppData\\Roaming\\npm\\node_modules" in discovery
    assert "AppData\\Local\\Programs\\cursor\\resources\\app\\package.json" in discovery
    assert "anthropic.claude-code-*" in discovery
    assert "$userHomeFull =" in discovery
    assert "$home =" not in discovery.casefold()
    assert "Get-DefenseClawClaudeWinGetMetadataVersion" in discovery
    assert "Get-DefenseClawCodexWinGetMetadataVersion" in discovery
    assert discovery.index("$machinePackage") < discovery.index(
        "Get-DefenseClawCodexWinGetMetadataVersion"
    )
    assert discovery.index("$machinePackage") < discovery.index(
        "Get-DefenseClawClaudeWinGetMetadataVersion"
    )
    assert discovery.index(
        "Get-DefenseClawClaudeWinGetMetadataVersion"
    ) < discovery.index("foreach ($relativeExtensionRoot")
    assert "AppData\\Local\\Microsoft\\WinGet\\Packages" in winget_discovery
    assert (
        "Anthropic.ClaudeCode_Microsoft.Winget.Source_*"
        in winget_discovery
    )
    assert "OpenAI.Codex_Microsoft.Winget.Source_*" in winget_discovery
    assert "codex-x86_64-pc-windows-msvc.exe" in winget_discovery
    assert "OpenAI OpCo, LLC" in winget_discovery
    assert "Get-DefenseClawCodexWinGetEmbeddedVersion" in winget_discovery
    assert "[IO.SearchOption]::TopDirectoryOnly" in winget_discovery
    assert "[IO.SearchOption]::AllDirectories" not in winget_discovery
    assert (
        "Microsoft.PowerShell.Security\\Get-AuthenticodeSignature"
        in winget_discovery
    )
    assert "[Diagnostics.FileVersionInfo]::GetVersionInfo" in winget_discovery
    assert "@('Anthropic PBC', 'Anthropic, PBC')" in winget_discovery
    assert "[string]$ProductName -cne 'Claude Code'" in winget_discovery
    assert "[IO.FileShare]::Read" in winget_discovery
    assert "$maximumBytes = 512MB" in winget_discovery
    assert "$examined -gt 256" in winget_discovery
    assert "$matched -gt 32" in winget_discovery
    assert "Get-DefenseClawConnectorMetadataVersion" in renderer
    assert "Resolve-DefenseClawConnectorMetadataVersion" in renderer
    assert "Select-DefenseClawActiveInteractiveUserProfiles" in renderer
    assert "-DeferInactiveProfiles:" in shorthand_render
    assert "'Install', 'Upgrade', 'Repair'" in shorthand_render
    assert "-not $NoStart" in shorthand_render
    assert "-NativeCandidateObserved $nativeCandidateObserved" in renderer
    assert "-DiscoveryFailed $metadataDiscoveryFailed" in renderer
    assert "$users = @(" in renderer
    assert "$Profiles" in renderer
    assert "agent_version:" in renderer
    assert "enabled: false" in renderer
    assert renderer.index('AppendLine("    agent_version:') < renderer.index(
        "AppendLine('    enabled: true')"
    )
    assert renderer.index("AppendLine('    enabled: true')") < renderer.index(
        "if ($deferTarget)"
    ) < renderer.index("AppendLine('    deferred: true')")
    assert "@attacker/not-amp" in smoke
    assert "target renderer emitted an enabled/version contract mismatch" in smoke
    assert "GetActiveSessionSIDs" in installer
    assert "WTSEnumerateSessionsW" in installer
    assert "row.State != WTSConnectState.Active" in installer
    assert "native_active_session_discovery_verified" in smoke
    assert "-ActiveSessionSIDs $ActiveSessionSIDs" in renderer
    assert (
        "disconnected WTS user did not receive exactly three deferred enabled targets"
        in smoke
    )
    assert (
        "active WTS user did not receive exactly three immediate enabled targets"
        in smoke
    )
    assert "missing-version target was enabled or marked deferred" in smoke
    assert "no-start shorthand silently omitted a planned user" in smoke
    assert "no-start shorthand marked a planned user deferred" in smoke
    assert (
        "official WinGet Claude package was not discovered exactly once"
        in smoke
    )
    assert "WinGet Claude discovery followed a package reparse point" in smoke
    assert (
        "eligible Claude user did not receive exactly one enabled target"
        in smoke
    )
    assert (
        "official WinGet Codex package was not discovered exactly once"
        in smoke
    )
    assert "WinGet Codex owner identity did not reject a foreign owner" in smoke
    assert "WinGet Codex discovery followed a package reparse point" in smoke
    assert "below-minimum native Codex was replaced by fallback metadata" in smoke
    assert "WinGet Codex fallback decision did not remain fail closed" in smoke
    assert "shorthand config did not explicitly select embedded rule-pack defaults" in smoke


def test_unsigned_windows_bundle_instructions_describe_optional_hardening() -> None:
    builder = read(WINDOWS_MANAGED_BUNDLE_BUILDER)
    unsigned_instructions = builder[
        builder.index("Local unsigned build ready") :
        builder.index("See cmd/defenseclaw-enterprise-setup/platform_windows.go")
    ]

    assert "--core-hardening-certification --mode action" in unsigned_instructions
    assert "--connector claudecode" in unsigned_instructions
    assert "A full profile uses the shared" in unsigned_instructions
    assert "WDAC/AppLocker is optional defense in depth" in unsigned_instructions
    assert "-component acp-guard" in builder
    assert "-component acp -version" not in builder


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

    # The standalone profile's vendor-neutral roots exist only in the
    # lifecycle's profile-root helpers (see
    # test_windows_enterprise_standalone_contract.py); the Secure Client
    # harness, smoke tests, and deployment guide never name them.
    for source in (harness, smoke, documentation):
        assert r"Cisco\DefenseClaw" not in source
    for source in (installer, module, harness, smoke):
        assert "Cisco Secure Client" in source
    assert production_suffix in installer
    assert production_suffix in harness
    assert production_suffix in smoke
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
    assert "[switch]$CoreHardeningCertification" in installer
    assert "[switch]$Json" in installer
    assert "$exitCode = 1" in installer
    assert "if ($exitCode -ne 0)" in installer
    assert "exit $exitCode" in installer
    assert "ok = $false" in installer
    assert "error = $failureMessage" in installer
    assert "errors = @(@($failureMessage) + $bootstrapResilienceEvents)" in installer


def test_enterprise_module_install_is_idempotent_over_active_metadata() -> None:
    """AVC's Windows installer runs -Action Install unconditionally after its
    own preinstall has removed machine-wide state. Refusing on a still-present
    active deployment aborted a legitimate reinstall on hosts where metadata
    survived (see the AVC 5.1.21.3862 DART for the macOS twin). The psm1 must
    reconcile in place: emit the reconcile warning and drive the same
    downstream artifact-hash rewrites Upgrade does, without touching the
    inactive-metadata tombstone lane (which refuses to adopt active metadata
    and would abort the run)."""
    body = read(MODULE)

    # Old refusal must NOT reappear.
    assert (
        "'DefenseClaw enterprise mode is already installed; use Upgrade or Repair'"
        not in body
    ), "idempotent-Install regression: the pre-reconcile refusal string is back"
    assert (
        "throw 'DefenseClaw enterprise mode is already installed" not in body
    ), "idempotent-Install regression: any throw of the already-installed text"

    # Reconcile branch must be present.
    assert "reconciling existing installation" in body, (
        "psm1 must emit the reconcile warning when Install runs over active metadata"
    )
    assert "$reconcileInstall = $false" in body, (
        "reconcile-Install selector must be declared before the Install/Upgrade dispatch"
    )
    assert "$reconcileInstall = $true" in body, (
        "reconcile-Install selector must be flipped when metadata is installed"
    )
    assert "-not $reconcileInstall" in body, (
        "inactive-metadata tombstone adoption must be gated on -not $reconcileInstall so "
        "it never fires under reconcile-Install"
    )

    # -DeferredConfig against an active deployment leaves services stopped
    # and placeholder policy on disk (see reconcile-Install throw in the psm1).
    # The refusal must live INSIDE the reconcile branch so a fresh install can
    # still legitimately use -DeferredConfig.
    assert "refusing -DeferredConfig against an active DefenseClaw" in body, (
        "reconcile-Install must refuse -DeferredConfig combined with active metadata"
    )

    # Structural: verify branch ownership directly — the reconcile clause must
    # hold the $reconcileInstall = $true assignment AND the DeferredConfig
    # refusal, and its elseif clause must hold the tombstone-teardown call.
    # Anchor the search inside an `if ($Action -eq 'Install')` block so a
    # future refactor cannot silently move the reconcile branch under a
    # different action (Upgrade / Repair / Reconcile) and keep the tests
    # green while Install regresses to the old throw.
    # The public lifecycle has multiple `if ($Action -eq 'Install')` sites; the
    # one that carries the reconcile branch is the one whose body gates on
    # Test-DefenseClawMetadataInstalled. Walk each candidate with a balanced-
    # brace scan so nested `{...}` blocks (there are many in the Install body)
    # don't confuse a naïve regex.
    install_body = None
    for m in re.finditer(
        r"if\s*\(\s*\$Action\s+-eq\s+'Install'\s*\)\s*\{",
        body,
    ):
        start = m.end()
        depth = 1
        i = start
        while i < len(body) and depth > 0:
            ch = body[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            i += 1
        candidate = body[start:i - 1]
        if "Test-DefenseClawMetadataInstalled" in candidate:
            install_body = candidate
            break
    assert install_body is not None, (
        "psm1 must contain an `if ($Action -eq 'Install')` block whose body "
        "gates on Test-DefenseClawMetadataInstalled — reconcile-Install must "
        "be bound to the Install dispatch, not siphoned to another action"
    )

    branch = re.search(
        r"""if\s*\(
            \s*\$null\s+-ne\s+\$metadata\s+-and\s+
            \(\s*Test-DefenseClawMetadataInstalled\s+-Metadata\s+\$metadata\s*\)\s*
        \)\s*\{
            (?P<reconcile>(?:[^{}]|\{[^{}]*\})*)
        \}\s*
        elseif\s*\(\s*\$null\s+-ne\s+\$metadata\s*\)\s*\{
            (?P<tombstone>(?:[^{}]|\{[^{}]*\})*)
        \}""",
        install_body,
        re.S | re.X,
    )
    assert branch is not None, (
        "the `if ($Action -eq 'Install')` block must have an if/elseif pair "
        "rooted at `if ($null -ne $metadata -and "
        "(Test-DefenseClawMetadataInstalled ...))` followed by "
        "`elseif ($null -ne $metadata)` — reconcile-Install and "
        "tombstone-teardown must be sibling clauses of the same construct, "
        "and that construct must live inside the Install dispatch"
    )
    reconcile_clause = branch.group("reconcile")
    tombstone_clause = branch.group("tombstone")
    assert "$reconcileInstall = $true" in reconcile_clause, (
        "reconcile clause must flip $reconcileInstall to $true"
    )
    assert (
        "refusing -DeferredConfig against an active DefenseClaw" in reconcile_clause
    ), "reconcile clause must contain the -DeferredConfig refusal"
    assert "reconciling existing installation" in reconcile_clause, (
        "reconcile clause must emit the reconcile-in-place warning"
    )
    assert (
        "Remove-DefenseClawCommittedManagedHooksTeardownJournal" in tombstone_clause
    ), (
        "tombstone-teardown call must live in the elseif ($null -ne $metadata) "
        "clause (fires only for a tombstone, never for active metadata)"
    )
    assert "$reconcileInstall = $true" not in tombstone_clause, (
        "reconcile-Install selector must never be flipped in the tombstone clause"
    )


def test_public_windows_lifecycle_cli_preserves_every_security_option() -> None:
    source = read(WINDOWS_LIFECYCLE_CLI)

    expected_mappings = {
        "attest-agent-application-control": "-AttestAgentApplicationControl",
        "attest-claude-effective-policy": "-AttestClaudeEffectivePolicy",
        "certification-codex-home": "-CertificationCodexHome",
        "core-hardening-certification": "-CoreHardeningCertification",
    }
    for cli_flag, powershell_parameter in expected_mappings.items():
        assert f'"{cli_flag}"' in source
        assert f'"{powershell_parameter}"' in source

    assert "validateWindowsEnterpriseLifecycleSecurityOptions" in source
    assert "valid only with install, upgrade, or repair" in source
    assert "codex-trusted-hook-launcher" not in source
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
    # GAP-0650: writers take an Administrators/SYSTEM-only lock that standard
    # users may read only the attributes of, and the hook reads lock-free
    # against its transaction counter.
    assert '".defenseclaw-managed-hooks.writer.lock"' in shared_source
    assert '"O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x120080;;;BU)"' in windows_source
    assert "resolveWindowsCodexManagedRuntimeRegistryStable" in windows_source
    assert "timed out waiting %s for a Codex machine policy transaction to finish" in windows_source
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
        "        $Layout.BrokerLogDirectory,\n"
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
        "        -LiteralPath $Layout.AgentApplicationControlAttestationPath `\n"
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
    assert "AttestCodexTrustedShellEnforcement" not in installer
    assert "AttestCodexApplicationControl" not in installer
    assert "$script:AgentApplicationControlAttestationSchemaVersion = 2" in module
    assert "agent_application_control_enforced = [bool]$Layout.AgentApplicationControlAttested" in module
    attestation_writer = module[
        module.index("function Write-DefenseClawAgentApplicationControlAttestation") : module.index(
            "function Initialize-DefenseClawCodexMachinePolicyParent"
        )
    ]
    assert "trusted_shell_enforced" not in attestation_writer
    assert "minimum_codex_version" not in attestation_writer
    assert "DEFENSECLAW_WINDOWS_CODEX_TRUSTED_SHELL_ENFORCED" not in module
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
    # The third `Assert-DefenseClawServiceImagePath` call pins the
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


def test_windows_enterprise_upgrade_treats_acp_as_replaceable() -> None:
    module = read(MODULE)
    replacement_start = module.index("$replaced = @($Sources.Keys")
    replacement_end = module.index("Assert-DefenseClawRecordedArtifactHashes", replacement_start)
    replacement = module[replacement_start:replacement_end]

    assert "'acp'," in replacement


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
                f"-BrokerBinary '{payload_binary_ps}' "
                f"-ProviderLibrary '{payload_binary_ps}' "
                f"-GatewayBinary '{payload_binary_ps}' "
                f"-ACPBinary '{payload_binary_ps}' "
                f"-HookBinary '{payload_binary_ps}' "
                f"-SensorHelperBinary '{payload_binary_ps}' "
                f"-CLIBinary '{payload_binary_ps}' "
                f"-CodexBinary '{payload_binary_ps}' "
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
                "service_empty_environment_binding",
                "service_missing_array_properties_normalized",
                "certification_scope_rejections",
                "lifecycle_file_lock_reuse_stable",
                "guardian_failure_diagnostic_preserved",
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
                "native_active_session_discovery_verified",
                "nested_cleanup_verified",
                "environment_restore_verified",
                "hostile_fixture_cleanup_verified",
                "existing_collision_rejected_without_acl_seizure",
                "rendered_targets_version_contract",
                "rendered_targets_active_session_contract",
                "claude_winget_metadata_contract",
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
            INSTALL_RECONCILE_SMOKE,
            (
                "reconcileInstall",
                "Test-DefenseClawMetadataInstalled",
                "tombstone",
            ),
        ),
        (
            UNINSTALL_ACL_RECOVERY_SMOKE,
            (
                "canonical_noop",
                "inherited_acl_repaired",
                "metadata_bytes_preserved",
                "hashed_attestation_repaired",
                "changed_attestation_rejected",
                "trusted_admin_deny_repaired",
                "purge_skipped_denied_state_child",
                "non_purge_rejected_denied_state_child",
                "foreign_writer_rejected",
                "explorer_full_control_rejected",
            ),
        ),
        (
            UNINSTALL_NATIVE_CONTRACT_SMOKE,
            (
                "seal_and_delete_bound",
                "internal_helper_rejected",
                "absent_delete_idempotent",
            ),
        ),
        (
            UNTRUSTED_METADATA_FALLBACK_SMOKE,
            (
                "partial_dispatch",
                "protected_evidence_blocks_fallback",
            ),
        ),
        (
            SELF_UNINSTALL_HELPER_CAPTURE_SMOKE,
            (
                "engine",
                "capture_elapsed_ms",
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
        "install-reconcile",
        "uninstall-acl-recovery",
        "uninstall-native-contract",
        "untrusted-metadata-fallback",
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
    profile_prefix = (
        "dc-ps-"
        if script == BOOTSTRAP_ENVIRONMENT_SMOKE
        else "DefenseClaw-PowerShellSmoke-"
    )
    with tempfile.TemporaryDirectory(
        prefix=profile_prefix,
        dir=os.environ.get("TEMP"),
    ) as temporary_profile:
        profile_root = str(Path(temporary_profile).resolve())
        volume, home_path = os.path.splitdrive(profile_root)
        if script == BOOTSTRAP_ENVIRONMENT_SMOKE:
            # Windows PowerShell 5.1 still exercises legacy MAX_PATH behavior.
            # Keep the real WinGet package/executable leaves while bounding the
            # disposable prefixes that precede them.
            longest_codex_fixture = (
                Path(profile_root)
                / ("cw-" + "0" * 32)
                / "i3"
                / "AppData"
                / "Local"
                / "Microsoft"
                / "WinGet"
                / "Packages"
                / "OpenAI.Codex_Microsoft.Winget.Source_8wekyb3d8bbwe_hostile"
                / "codex-x86_64-pc-windows-msvc.exe"
            )
            assert len(str(longest_codex_fixture)) < 260, (
                "bootstrap metadata fixture exceeds the PowerShell 5.1 "
                f"MAX_PATH boundary: {longest_codex_fixture}"
            )
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
        assert report["native_active_session_discovery_verified"] is True
        assert report["nested_cleanup_verified"] is True
        assert report["environment_restore_verified"] is True
        assert report["hostile_fixture_cleanup_verified"] is True
        assert report["existing_collision_rejected_without_acl_seizure"] is True
        assert report["rendered_targets_version_contract"] is True
        assert report["rendered_targets_active_session_contract"] is True
        assert int(report["concurrent_workers"]) == 6
        assert report["concurrent_roots_unique"] is True
        assert report["concurrent_cleanup_verified"] is True
    if script == SELF_UNINSTALL_HELPER_CAPTURE_SMOKE:
        assert int(report["capture_elapsed_ms"]) > 0
        assert int(report["helper_pid"]) > 0
        assert report["helper_alive_after_capture"] is True
        assert report["no_inherited_capture_handles"] is True
        assert report["protected_environment_pinned"] is True
        assert report["module_analysis_cache_disabled"] is True
        assert report["environment_root_retired"] is True


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
@pytest.mark.parametrize(
    "engine",
    windows_powershell_engines() or (None,),
    ids=lambda engine: Path(engine).stem if engine else "missing",
)
def test_enterprise_install_acl_self_heal_smoke_runs_on_every_available_engine(
    engine: str | None,
) -> None:
    """Regression gate for the orphan NT SERVICE per-service SID install
    blocker. The smoke stages the exact SID shape that reproduced the QA
    failure, drives Set-DefenseClawPathAcl -Kind ManagedIPCDirectory, and
    asserts (a) the orphan ACE is stripped, (b) SE_DACL_PROTECTED is set.

    Its output is a single PASS line, not JSON, so it is not part of the
    JSON smoke matrix. It still must run on every Windows PowerShell
    engine the CI exposes (PowerShell 5.1 and PowerShell 7)."""
    assert engine, "Windows CI must provide Windows PowerShell 5.1 or PowerShell 7"
    completed = subprocess.run(
        [
            engine,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(INSTALL_ACL_SELF_HEAL_SMOKE),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8-sig",
        errors="replace",
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, (
        f"install ACL self-heal smoke failed (exit {completed.returncode})\n"
        f"stdout:\n{completed.stdout}\n"
        f"stderr:\n{completed.stderr}"
    )
    assert "enterprise-install-acl-self-heal-smoke: PASS" in completed.stdout, (
        "expected PASS line not in stdout\n"
        f"stdout:\n{completed.stdout}\n"
        f"stderr:\n{completed.stderr}"
    )


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


def test_bootstrap_smoke_expects_the_installers_certification_action_message() -> None:
    message = (
        "CoreHardeningCertification is valid only with Install, Upgrade, "
        "Repair, or Recover"
    )
    assert f"'-{message}'" in read(INSTALLER)
    assert f"'-{message}'" in read(MODULE)
    smoke = read(BOOTSTRAP_SMOKE)
    assert f"-ExpectedError '{message}'" in smoke
    assert "Upgrade, or Repair'" not in smoke


def test_bootstrap_smoke_throwaway_route_trusts_only_its_own_result() -> None:
    smoke = read(BOOTSTRAP_SMOKE)
    # The staging folder breaks ProgramData inheritance, and the parent takes
    # only a result the throwaway user owns that carries this run's nonce.
    assert "$security.SetAccessRuleProtection($true, $false)" in smoke
    assert "$resultOwner -cne $smokeUser.Sid" in smoke
    assert "-BasicUserResultNonce '$resultNonce'" in smoke
    assert "-BasicUserResultNonce '$Nonce'" in smoke
    assert "$parts[0] -cne $Nonce" in smoke
    # Only the two launcher shapes GAP-0661 names fall back.
    assert "$ErrorCode -eq 1346" in smoke
    # Windows PowerShell 5.1 sends Write-Warning to redirected stdout, which
    # would break the JSON report; the password must not be a cmdlet parameter.
    assert "Write-Warning (" not in smoke
    assert "Register-ScheduledTask -TaskName" not in smoke
    assert "'^dcsmoke[0-9a-f]{8}$'" in smoke


def test_bootstrap_cleanup_drains_compiler_scratch_finalizers_first() -> None:
    """Windows PowerShell 5.1 Add-Type retires its CodeDom scratch folder only
    from a finalizer; a finalizer that ran in the middle of the exact cleanup
    walk failed the 5.1 race worker with Access denied (Windows Native CI,
    Python shard 8). The cleanup queues the finalizers before the walk and
    treats an Access denied entry below the root as retired only when it is
    gone within a bounded wait; anything still there stays refused. It must
    never call GC.WaitForPendingFinalizers: in PowerShell that can block for
    good (it hung the smoke on dc-win2)."""
    bootstrap = read(INSTALLER)
    remove = bootstrap[bootstrap.index("function Remove-DefenseClawBootstrapEnvironment"):]
    remove = remove[: remove.index("\nfunction ")]
    assert remove.index("Complete-DefenseClawBootstrapCompilerScratch") < remove.index(
        "EnumerateFileSystemEntries"
    )
    assert "Test-DefenseClawBootstrapRetiredCompilerScratch" in remove
    assert "[GC]::WaitForPendingFinalizers()" not in bootstrap
    assert "[GC]::WaitForPendingFinalizers()" not in read(BOOTSTRAP_ENVIRONMENT_SMOKE)
    smoke = read(BOOTSTRAP_ENVIRONMENT_SMOKE)
    assert "[DefenseClawSmoke.RetiringScratch]::new($scratch)" in smoke
    assert "Invoke-RetiringScratchCleanup -KeepScratch $true" in smoke


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


def test_guardian_state_identity_uses_runtime_directory() -> None:
    module = read(MODULE)
    guardian_identity = module[
        module.index("function Get-DefenseClawGuardianStateIdentity") : module.index(
            "function Wait-DefenseClawServiceFailureRestartQuiescence"
        )
    ]
    assert "$Layout.RuntimeDirectory" in guardian_identity
    assert "$Layout.StateRoot" not in guardian_identity


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
            "function Test-DefenseClawGuardianCoverageReport"
        )
    ]
    coverage = module[
        module.index("function Test-DefenseClawGuardianCoverageReport") : module.index(
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
    assert "PSObject.Properties['errors']" in coverage
    assert "guardian status is missing protected activation coverage" in coverage
    assert "Rollback may have restored the prior strict v1 binary" in coverage
    assert "reconcile_id" in coverage
    assert "manifest_sha256" in coverage
    assert "$PriorReconcileID" in coverage
    assert "$PriorGeneration" in coverage
    assert "$PriorStateIdentity" in coverage
    assert "$CurrentStateIdentity" in coverage
    assert "$ExpectedManifestSHA256" in coverage
    assert "Test-DefenseClawGuardianCoverageReport `" in wait
    assert "boundaryDeadline" not in wait
    assert "Get-DefenseClawGuardianStateIdentity" in wait
    assert "last_status=$lastStatus" in wait
    # GAP-0044: standalone starts a status process only when the guardian
    # state file changed or 2 s after the last one, not every 0.25 s.
    assert "$probeOnChange = Test-DefenseClawStandaloneProfile" in wait
    assert "TotalMilliseconds -lt 2000" in wait
    assert "$probedStateIdentity = $currentStateIdentity" in wait
    guardian_failure = module[
        module.index(
            "function Get-DefenseClawGuardianVerificationFailureDiagnostic"
        ) : module.index("function Get-DefenseClawGuardianReadinessProbe")
    ]
    guardian_probe = module[
        module.index("function Get-DefenseClawGuardianReadinessProbe") :
        module.index("function Test-DefenseClawGuardianReady")
    ]
    guardian_boolean = module[
        module.index("function Test-DefenseClawGuardianReady") :
        module.index("function Wait-DefenseClawEnterpriseReadiness")
    ]
    deployment_assertion = module[
        module.index("function Assert-DefenseClawEnterpriseDeployment") :
        module.index("function Get-DefenseClawArtifactPath")
    ]
    assert "PSObject.Properties['results']" in guardian_failure
    assert "PSObject.Properties['authorization_error']" in guardian_failure
    assert "ConvertTo-DefenseClawBoundedDiagnostic" in guardian_failure
    assert "verification failed without a target error" in guardian_failure
    # GAP-1940: pending rows of signed-out accounts are counted, not failures.
    assert "PSObject.Properties['pending']" in guardian_failure
    assert "are pending " in guardian_failure
    # GAP-2290: a row's SID is named as its account, "DOMAIN\user (SID)".
    assert "Get-DefenseClawGuardianDiagnosticAccountLabel" in guardian_failure
    account_label = module[
        module.index("function Get-DefenseClawGuardianDiagnosticAccountLabel") :
        module.index("function Get-DefenseClawGuardianVerificationFailureDiagnostic")
    ]
    assert "Translate(" in account_label
    assert '"$account ($Sid)"' in account_label
    assert "ready = $ready" in guardian_probe
    assert "return [bool]$readiness.ready" in guardian_boolean
    assert "Get-DefenseClawGuardianReadinessProbe `" in deployment_assertion
    assert "[string]$guardianReadiness.diagnostic" in deployment_assertion
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
    enumerator_refresh = install_like.index("Invoke-DefenseClawEnumeratorRefresh `")
    target_plan = install_like.index("Invoke-DefenseClawTargetRuntimePreparation `")
    fresh_bind = install_like.index("-BindInstallPreparationSID", transaction)
    fresh_service_registration = install_like.rfind(
        "Set-DefenseClawManagedServicesForTransaction `",
        transaction,
        fresh_bind,
    )
    fresh_snapshot = install_like.index(
        "Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand `",
        target_plan,
    )
    guardian_wait = install_like.index("Wait-DefenseClawFreshGuardianReconcile `")
    gateway_demand_start = install_like.index(
        "Set-DefenseClawServiceStartMode `\n"
        "                -Name $GatewayServiceName `\n"
        "                -StartMode 3",
        guardian_wait,
    )
    assert (
        transaction
        < fresh_service_registration
        < enumerator_refresh
        < target_plan
        < fresh_snapshot
        < guardian_wait
        < gateway_demand_start
    )
    assert "$expectedGuardianManifestSHA256" in install_like
    assert "-ExpectedManifestSHA256 $expectedGuardianManifestSHA256" in install_like

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


def test_legacy_captured_lifecycle_journal_has_transactional_upgrade_recovery() -> None:
    module = read(MODULE)
    smoke = read(UNINSTALL_TRANSACTION_SMOKE)

    publish = module[
        module.index(
            "function Publish-DefenseClawManagedHooksLifecycleRecoveryBinding"
        ) : module.index(
            "function Resolve-DefenseClawManagedHooksLifecycleRecoveryBinding"
        )
    ]
    resolve = module[
        module.index(
            "function Resolve-DefenseClawManagedHooksLifecycleRecoveryBinding"
        ) : module.index("function Assert-DefenseClawInstalledConfig")
    ]
    install_like = module[
        module.index("function Invoke-DefenseClawInstallLikeLifecycle") : module.index(
            "function Invoke-DefenseClawUninstallLifecycle"
        )
    ]
    assert "schema-3 journal" in publish
    assert "state = 'recorded'" in publish
    assert "-Action retire-committed" in publish
    assert "$binding.state = 'adopted'" in publish
    assert "journal_file_identity" in publish
    assert "journal_sha256" in publish
    assert "durable legacy preimage marker" in publish
    assert "state -notin @('recorded', 'adopted')" in resolve
    assert "The helper committed its handle-bound quarantine" in resolve
    assert "Write-DefenseClawJsonAtomic -Value $snapshot" in resolve
    restore = module[
        module.index("function Restore-DefenseClawTransaction {") : module.index(
            "function Assert-DefenseClawRestoredTransactionReadyForActivation"
        )
    ]
    assert "Assert-DefenseClawUnboundLegacyLifecycleRecoveryPreimage `" in restore
    assert "$null -eq $unboundLegacyLifecyclePreimage" in restore
    assert "$skipAdoptedStaleLifecyclePreimage" in restore
    recovery_publish = install_like.index(
        "Publish-DefenseClawManagedHooksLifecycleRecoveryBinding `"
    )
    transaction_open = install_like.index("$snapshot = New-DefenseClawTransaction `")
    assert "Get-DefenseClawManagedHooksLifecycleJournalCompatibilityState `" in (
        install_like[:transaction_open]
    )
    assert "journalCompatibility -ceq 'current'" in install_like[:transaction_open]
    assert "-Action retire" in install_like[:transaction_open]
    assert "-RecoverLegacyManagedHooksLifecycleJournal:" in install_like
    current_capture = install_like.index(
        "if ($Action -ne 'Install') {\n"
        "            [void](Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand `",
        recovery_publish,
    )
    assert recovery_publish < current_capture

    upgrade_case = smoke[
        smoke.index("function Invoke-HarnessLegacyCapturedJournalUpgradeSequence") :
        smoke.index("function Invoke-HarnessLegacyRecoveryCrashPrefixCases")
    ]
    crash_cases = smoke[
        smoke.index("function Invoke-HarnessLegacyRecoveryCrashPrefixCases") :
        smoke.index("$purgeResults =")
    ]
    assert "legacy_activation_missing = $true" in upgrade_case
    assert '"schema_version":3,"phase":"captured"' in upgrade_case
    assert "-Action Upgrade `" in upgrade_case
    assert "-NoStart" in upgrade_case
    for ordered_event in (
        "lifecycle-recovery-binding-recorded",
        "lifecycle-snapshot:retire-committed",
        "lifecycle-recovery-binding-adopted",
        "lifecycle-snapshot:capture",
        "lifecycle-snapshot:classify-activation",
    ):
        assert ordered_event in upgrade_case
    for crash_prefix in (
        "replacement-staged-before-binding",
        "binding-recorded-before-rename",
        "rename-before-adoption-receipt",
        "adoption-receipt-before-current-capture",
    ):
        assert crash_prefix in crash_cases
    assert "HarnessRealRestoreTransaction" in crash_cases
    assert "-DeferServiceRestart" in crash_cases
    assert "lifecycle-generation-gc" in crash_cases
    assert "lifecycle-journal-quarantined" in crash_cases
    assert "violated GC-before-adoption recovery ordering" in crash_cases
    assert "restore the gateway and exact unbound legacy preimage" in crash_cases
    assert "legacy-gateway-preimage" in crash_cases
    assert "staged-fixed-gateway" in crash_cases
    assert "current-schema4-post-commit-direct-retirement" in upgrade_case

    teardown_writer = smoke[
        smoke.index("function Write-HarnessJournal") :
        smoke.index("function Get-HarnessJournalPhase")
    ]
    lifecycle_mock_start = smoke.index(
        "function script:Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand"
    )
    lifecycle_mock = smoke[
        lifecycle_mock_start : smoke.index(
            "function script:Restore-DefenseClawTransaction",
            lifecycle_mock_start,
        )
    ]
    assert 'schema_version":5' in teardown_writer
    assert 'schema_version":4' in lifecycle_mock


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
    # Every service, the gateway included, runs as LocalSystem at System
    # integrity and must carry its own service SID as a group.
    assert "$expectedUserSID = 'S-1-5-18'" in token_probe
    assert "$expectedIntegritySID = 'S-1-16-16384'" in token_probe
    assert "'S-1-16-12288'" not in token_probe
    assert "$broker = $serviceName -eq $script:BrokerServiceName" in token_probe
    assert "$sensorHelper = $serviceName -eq $script:SensorHelperServiceName" in token_probe
    assert "$expectedPrivileges = if ($gateway -or $broker -or $sensorHelper)" in token_probe
    assert "integrity $($token.IntegritySid), want $expectedIntegrityName" in token_probe
    assert "expected_integrity_sid = $expectedIntegritySID" in token_probe
    assert "if (-not $gateway -and -not $broker -and -not $sensorHelper)" in token_probe
    assert "-not [bool]$serviceGroups[0].Enabled -or" in token_probe
    assert "[bool]$serviceGroups[0].DenyOnly) {" in token_probe
    assert "service_sid_group_required = $true" in token_probe
    assert "service_sid_group_count = $serviceGroups.Count" in token_probe
    assert "foreach ($requiredSID in @($serviceSID, 'S-1-1-0', 'S-1-5-33'))" in token_probe
    assert "restricted SID list lacks one exact service-logon SID" in token_probe
    assert "'broker'" in token_probe
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
    assert "LocalSystem TokenUser, System integrity for every service" in harness
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

    assert "full execution requires -UpgradeBrokerBinary" in harness
    assert "-UpgradeGatewayBinary" in harness
    assert "-UpgradeACPBinary" in harness
    assert "full execution requires all six -Upgrade*Binary inputs" in upgrade
    assert "Add-SkippedResult" not in upgrade
    assert "external-release-public-cli-versioned-upgrade" in upgrade
    assert "Invoke-PublicEnterpriseLifecycleCLIJSON" in upgrade
    assert "-FilePath $script:UpgradeCLISource" in upgrade
    assert "separately version-stamped upgrade $name bytes do not" in upgrade
    for name in ("broker", "gateway", "acp", "hook", "sensor_helper", "cli"):
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


def test_certification_threads_broker_and_vendor_provider_through_lifecycle() -> None:
    harness = read(HARNESS)
    lifecycle_cli = read(WINDOWS_LIFECYCLE_CLI)
    module = read(MODULE)

    assert "@('BrokerBinary', $BrokerBinary)" in module
    # -ProviderLibrary is deliberately NOT a required source for Install or
    # Upgrade. A full XDR deployment installs Cloud Management after
    # DefenseClaw, so cmidapi.dll routinely does not exist at lifecycle time;
    # the broker discovers it at runtime instead. Requiring it here is what
    # used to make that install order fail outright, so assert its absence
    # rather than merely dropping the old assertion.
    assert "@('ProviderLibrary', $ProviderLibrary)" not in module
    assert "-ProviderLibrary, -GatewayBinary" not in module
    # The ACP guard and sensor helper are unrelated to CMID and stay
    # required sources on main, so the requirements message lists them
    # alongside the other three. It names exactly what the condition tests.
    assert (
        "Upgrade requires -BrokerBinary, -GatewayBinary, -ACPBinary, "
        "-HookBinary, and -SensorHelperBinary" in module
    )
    assert "@('sensor_helper', $SensorHelperBinary" in module
    assert "'privs', $sensorHelperServiceName, 'SeChangeNotifyPrivilege'" in module
    # A path that *is* supplied still has to be described and trusted like
    # every other artifact; only the requirement relaxed, not the validation.
    assert "@('provider_library', $ProviderLibrary" in module
    assert "$Layout.ProviderLibraryPath = [string]$Sources['provider_library'].path" in (
        module
    )
    assert "$metadata.PSObject.Properties['provider_library_path']" in module

    parameter_block = harness[: harness.index("Set-StrictMode -Version Latest")]
    for parameter in (
        "[string]$BrokerBinary",
        "[string]$ProviderLibrary",
        "[string]$ACPBinary",
        "[string]$SensorHelperBinary",
        "[string]$UpgradeBrokerBinary",
        "[string]$UpgradeACPBinary",
        "[string]$UpgradeSensorHelperBinary",
    ):
        assert parameter in parameter_block

    source_initialization = harness[
        harness.index("$script:OriginalGatewaySource") : harness.index(
            "$script:RunToken ="
        )
    ]
    assert (
        "$script:OriginalBrokerSource = ConvertTo-CanonicalPath $BrokerBinary"
        in source_initialization
    )
    assert (
        "$script:OriginalProviderLibrarySource = ConvertTo-CanonicalPath "
        "$ProviderLibrary" in source_initialization
    )
    assert "broker = Get-FileDigest $script:OriginalBrokerSource" in source_initialization
    assert "acp = Get-FileDigest $script:OriginalACPSource" in source_initialization
    assert (
        "sensor_helper = Get-FileDigest $script:OriginalSensorHelperSource"
        in source_initialization
    )
    assert (
        "provider_library = Get-FileDigest "
        "$script:OriginalProviderLibrarySource" in source_initialization
    )
    provider_validation = harness[
        harness.index("function Assert-CertificationProviderLibraryCurrent") :
        harness.index("function Test-PublicCLIProviderLibrarySelection")
    ]
    assert "Get-AuthenticodeSignature -LiteralPath $full" in provider_validation
    assert "[Management.Automation.SignatureStatus]::Valid" in provider_validation
    assert "[Security.Cryptography.X509Certificates.X509NameType]::SimpleName" in (
        provider_validation
    )
    assert "$signerName -cne 'Cisco Systems, Inc.'" in provider_validation
    assert "signer is not the exact Cisco Systems, Inc. identity" in provider_validation

    resolver_probe = harness[
        harness.index("function Test-PublicCLIProviderLibrarySelection") : harness.index(
            "function Copy-CertificationSourceToProtectedStaging"
        )
    ]
    assert "'enterprise', 'windows', 'repair'" in resolver_probe
    assert "'--broker-binary', $script:BrokerSource" in resolver_probe
    assert "Win32_Process" in resolver_probe
    assert '"ParentProcessId=$($RunningProcess.Id)"' in resolver_probe
    assert "-ProviderLibrary" in resolver_probe
    assert "-AllowedExitCodes @(1)" in resolver_probe
    assert "-AllowedExitCodes @(1, 1603)" not in resolver_probe
    assert (
        "certification-scoped Install, Upgrade, or Repair requires -AllowUnsigned"
        in resolver_probe
    )
    assert "ConvertFrom-SingleJSONDocument" in resolver_probe
    assert "$probeJSON.action -cne 'repair'" in resolver_probe
    assert "$probeJSON.error -cne $expectedFailure" in resolver_probe
    assert "$observedChildPIDs.Count -ne 1" in resolver_probe
    assert "$selectedPaths.Count -ne 1" in resolver_probe
    assert "supplied ProviderLibrary does not match the exact public CLI" in resolver_probe
    assert "post-probe managed credential provider library" in resolver_probe
    assert "identity changed during resolver probe" in resolver_probe
    assert "Assert-SameObjectJSON" in resolver_probe
    assert "Get-NormalModeEnterpriseMachineSnapshot" in resolver_probe
    assert "machine_state_unchanged = $true" in resolver_probe
    assert "Deliberately omit --allow-unsigned" in resolver_probe
    assert "'--allow-unsigned'" not in resolver_probe
    provider_preflight_call = "Invoke-Check 'public-cli-provider-discovery-preflight'"
    assert provider_preflight_call in harness
    assert harness.index(provider_preflight_call) < harness.index(
        "$script:Phase = 'normal-mode-noop'"
    )
    assert harness.index(provider_preflight_call) < harness.index(
        "Invoke-Check 'enterprise-installer-install'"
    )

    protected_staging = harness[
        harness.index("function Initialize-ProtectedCertificationSources") :
        harness.index("function Get-AgentBinaryTrustIdentity")
    ]
    assert "$script:BrokerSource = Copy-CertificationSourceToProtectedStaging" in (
        protected_staging
    )
    assert "$script:OriginalBrokerSource" in protected_staging
    assert "$script:UpgradeBrokerSource = Copy-CertificationSourceToProtectedStaging" in (
        protected_staging
    )
    # The Cisco provider DLL remains bound to its trusted vendor installation
    # path. Copying it into certification staging would test a different path
    # than the public CLI's trusted discovery and the broker's final image.
    assert "Copy-CertificationSourceToProtectedStaging `\n            $script:OriginalProviderLibrarySource" not in (
        protected_staging
    )

    direct_arguments = harness[
        harness.index("function Get-InstallerArguments") : harness.index(
            "function Get-EnterpriseLifecycleCLIArguments"
        )
    ]
    for parameter in ("[string]$BrokerSource", "[string]$ProviderLibrarySource"):
        assert parameter in direct_arguments
    assert "if ($Action -in @('Install', 'Upgrade'))" in direct_arguments
    for required in ("BrokerBinary", "ProviderLibrary", "GatewayBinary", "ACPBinary", "HookBinary"):
        assert f"@('{required}'," in direct_arguments
    assert "$arguments.Add('-BrokerBinary')" in direct_arguments
    assert "$arguments.Add('-ProviderLibrary')" in direct_arguments
    assert "if ($Action -eq 'Install'" in direct_arguments
    assert "throw 'Install requires -Config and -Manifest'" in direct_arguments
    assert "@('-Config', $ConfigSource)" in direct_arguments
    assert "@('-Manifest', $ManifestSource)" in direct_arguments

    public_arguments = harness[
        harness.index("function Get-EnterpriseLifecycleCLIArguments") : harness.index(
            "function Test-AllowUnsignedHarnessContract"
        )
    ]
    assert "[string]$BrokerSource" in public_arguments
    assert "if ($Action -in @('Install', 'Upgrade'))" in public_arguments
    for required in ("--broker-binary", "--gateway-binary", "--acp-binary", "--hook-binary"):
        assert f"@('{required}'," in public_arguments
    assert "@('--broker-binary', $BrokerSource)" in public_arguments
    assert "if ($Action -eq 'Install'" in public_arguments
    assert "throw 'public Install requires --config and --manifest'" in public_arguments
    assert "@('--config', $ConfigSource)" in public_arguments
    assert "@('--manifest', $ManifestSource)" in public_arguments
    assert "--provider-library" not in public_arguments
    assert '"provider-library"' not in lifecycle_cli
    assert '"broker-binary"' in lifecycle_cli
    assert "windowsEnterpriseProviderLibraryResolver()" in lifecycle_cli

    initial_install = harness[
        harness.index("Invoke-Check 'enterprise-installer-install'") : harness.index(
            "Invoke-Check 'windows-service-contract'"
        )
    ]
    assert "-BrokerSource $script:BrokerSource" in initial_install
    assert "'initial public Install' `" in initial_install
    assert "([string]$script:SourceDigests['broker'])" in initial_install

    upgrade = harness[
        harness.index("function Test-UpgradeTransaction") : harness.index(
            "function Get-ManagedUserPathSecurityFingerprint"
        )
    ]
    assert "-BrokerSource $script:UpgradeBrokerSource" in upgrade
    assert "broker = [string]$script:SourceDigests['upgrade_broker']" in upgrade
    assert "exact_broker_sha256 = $true" in upgrade
    assert "'versioned public Upgrade' `" in upgrade
    assert "([string]$script:SourceDigests['upgrade_broker'])" in upgrade

    source_free_repair = harness[
        harness.index("function Invoke-CertificationActivationRepairAfterIsolationProof") :
        harness.index("function Get-CertificationServiceProcessSnapshot")
    ]
    assert "--broker-binary" not in source_free_repair
    assert "-BrokerBinary" not in source_free_repair
    assert "-ProviderLibrary" not in source_free_repair
    assert "Deliberately omit every artifact replacement" in source_free_repair
    assert "'source-free installed public Repair' `" in source_free_repair
    assert "([string]$script:SourceDigests['broker'])" in source_free_repair

    installed_provider = harness[
        harness.index("function Assert-InstalledProviderLibraryIdentity") :
        harness.index("function Assert-SameDigests")
    ]
    for contract in (
        "[string]$ExpectedBrokerSHA256 = ''",
        "$brokerSHA256 = Get-FileDigest $brokerBinary",
        "$ExpectedBrokerSHA256 -cnotmatch '^[0-9a-f]{64}$'",
        "exact protected source digest",
        "expected_broker_sha256 = $ExpectedBrokerSHA256",
        "exact_broker_sha256 = $brokerDigestVerified",
    ):
        assert contract in installed_provider

    direct_wrapper = harness[
        harness.index("function Invoke-EnterpriseInstaller") : harness.index(
            "function Get-ManagedCLIEnvironment"
        )
    ]
    for source in (
        "BrokerSource",
        "ProviderLibrarySource",
        "GatewaySource",
        "ACPSource",
        "HookSource",
        "SensorHelperSource",
        "CLISource",
        "ConfigSource",
        "ManifestSource",
    ):
        assert f"[string]${source} = ''" in direct_wrapper


def test_certification_broker_collision_cleanup_and_docs_stay_complete() -> None:
    harness = read(HARNESS)
    certification_doc = read(CERTIFICATION_DOC)

    assert (
        '$script:BrokerServiceName = "DefenseClawCMIDBroker_$($script:RunToken)"'
        in harness
    )
    service_name_guard = harness[
        harness.index("function Assert-CertificationServiceName") : harness.index(
            "function Assert-CertificationUserName"
        )
    ]
    assert "'broker' { \"DefenseClawCMIDBroker_$($script:RunToken)\" }" in (
        service_name_guard
    )
    assert "Assert-CertificationServiceName $script:BrokerServiceName 'broker'" in (
        harness
    )
    assert (
        '$script:EnumeratorServiceName = '
        '"DefenseClawCertEnumerator_$($script:RunToken)"' in harness
    )
    assert (
        '$script:SensorHelperServiceName = '
        '"DefenseClawSensorHelper_$($script:RunToken)"' in harness
    )
    assert (
        "'enumerator' { \"DefenseClawCertEnumerator_$($script:RunToken)\" }"
        in service_name_guard
    )
    assert (
        "Assert-CertificationServiceName "
        "$script:EnumeratorServiceName 'enumerator'" in harness
    )
    assert (
        "Assert-CertificationServiceName "
        "$script:SensorHelperServiceName 'sensor_helper'" in harness
    )

    execution_preflight_start = harness.index(
        "if (-not (Test-IsElevatedAdministrator))"
    )
    execution_preflight = harness[
        execution_preflight_start : harness.index(
            "$failure = ''", execution_preflight_start
        )
    ]
    assert "$script:BrokerServiceName" in execution_preflight
    assert "$script:SensorHelperServiceName" in execution_preflight
    assert "$script:EnumeratorServiceName" in execution_preflight
    assert "refusing pre-existing certification service" in execution_preflight

    bounded_cleanup = harness[
        harness.index("function Invoke-BoundedCleanup") : harness.index(
            "function Write-FinalEvidence"
        )
    ]
    assert bounded_cleanup.count("$script:BrokerServiceName") >= 5
    assert bounded_cleanup.count("$script:SensorHelperServiceName") >= 5
    assert bounded_cleanup.count("$script:EnumeratorServiceName") >= 5
    assert "'broker'" in bounded_cleanup
    assert "'enumerator'" in bounded_cleanup
    assert "Assert-CertificationServiceName $serviceName $serviceRole" in bounded_cleanup
    assert "@('delete', $serviceName)" in bounded_cleanup

    upgrade_start = certification_doc.index("-BrokerBinary .\\v1\\")
    certification_invocation = certification_doc[
        upgrade_start : certification_doc.index("-DisposableHost", upgrade_start)
    ]
    for parameter in (
        "-BrokerBinary",
        "-ProviderLibrary",
        "-ACPBinary",
        "-SensorHelperBinary",
        "-UpgradeBrokerBinary",
        "-UpgradeACPBinary",
        "-UpgradeSensorHelperBinary",
    ):
        assert parameter in certification_invocation


def test_certification_treats_broker_as_a_first_class_service_boundary() -> None:
    harness = read(HARNESS)

    service_contract = harness[
        harness.index("function Assert-ServiceContract") : harness.index(
            "function Assert-CertificationServiceCodexHomeAbsent"
        )
    ]
    for contract in (
        "$broker = Get-CimInstance Win32_Service",
        "$sensorHelper = Get-CimInstance Win32_Service",
        "$null -eq $sensorHelper -or $null -eq $guardian",
        "$broker.StartName",
        "$sensorHelper.StartName",
        "want LocalSystem",
        "foreach ($service in @($gateway, $broker, $sensorHelper, $guardian))",
        "bin\\defenseclaw-cmid-broker.exe",
        "bin\\defenseclaw-sensor-helper.exe",
        "Assert-InstalledProviderLibraryIdentity 'service contract'",
        "broker=$($broker.State)/$($broker.StartName)",
    ):
        assert contract in service_contract

    environment_contract = harness[
        harness.index("function Assert-CertificationServiceCodexHomeAbsent") :
        harness.index("function Assert-CertificationServicesStoppedAndIndependent")
    ]
    assert "role = 'broker'" in environment_contract
    assert "if ($role -eq 'broker' -and $null -ne $environmentProperty)" in (
        environment_contract
    )
    assert "if ($role -ne 'broker' -and $null -eq $environmentProperty)" in (
        environment_contract
    )

    stopped_contract = harness[
        harness.index("function Assert-CertificationServicesStoppedAndIndependent") :
        harness.index("function Invoke-EnterpriseLifecycleCLIJSON")
    ]
    assert "$script:BrokerServiceName" in stopped_contract
    assert "State -ne 'Stopped'" in stopped_contract
    assert "StartMode -ne 'Disabled'" in stopped_contract

    control_snapshot = harness[
        harness.index("function Get-ServiceControlSnapshot") : harness.index(
            "function Get-CertificationServiceProcessSnapshot"
        )
    ]
    process_snapshot = harness[
        harness.index("function Get-CertificationServiceProcessSnapshot") :
        harness.index("function Initialize-ServiceTokenProbeType")
    ]
    for snapshot in (control_snapshot, process_snapshot):
        assert "$script:BrokerServiceName" in snapshot

    failure_contract = harness[
        harness.index("function Get-CertificationFailureActionContract") :
        harness.index("function Wait-ForEnterpriseServiceReadiness")
    ]
    readiness = harness[
        harness.index("function Wait-ForEnterpriseServiceReadiness") :
        harness.index("function Invoke-ControlledServiceFailure")
    ]
    controlled_failure = harness[
        harness.index("function Invoke-ControlledServiceFailure") : harness.index(
            "function Assert-ExplicitServiceStopDoesNotRecover"
        )
    ]
    recovery = harness[
        harness.index("function Test-ServiceFailureRecovery") : harness.index(
            "function Test-QueuedFailureRestartDuringServicing"
        )
    ]
    queued = harness[
        harness.index("function Test-QueuedFailureRestartDuringServicing") :
        harness.index("function Assert-SameServiceControlSnapshot")
    ]
    for section in (failure_contract, recovery, queued):
        assert "$script:BrokerServiceName" in section
    assert "broker_service_state" in readiness
    assert "'broker'" in controlled_failure
    assert "'controlled-failure'" not in controlled_failure
    assert "bin\\defenseclaw-cmid-broker.exe" in controlled_failure
    assert "$dependentGatewayStopped = $true" in recovery
    assert "dependent_gateway_quiesced = $dependentGatewayStopped" in recovery
    assert "broker_service_state -cne 'stopped'" in queued
    assert "broker_service_state -cne 'running'" in queued

    wait = harness[
        harness.index("function Wait-ForServicesRunning") : harness.index(
            "function Get-AccessRules"
        )
    ]
    assert "$broker = Get-Service -Name $script:BrokerServiceName" in wait
    assert "$broker.Status -eq" in wait

    standard_user_probe = harness[
        harness.index("function Invoke-StandardUserControlProbe") : harness.index(
            "function Assert-ProtectedUserTamperToken"
        )
    ]
    for contract in (
        "broker_service = $script:BrokerServiceName",
        "broker_binary = Join-Path $script:InstallRoot",
        "cmid-broker\\broker-auth.key",
        "broker_pid = [uint32]$brokerProcess[0].process_id",
        "write_broker_binary",
        "[string]$input.broker_service",
        "[uint32]$input.broker_pid",
    ):
        assert contract in standard_user_probe

    normal_snapshot = harness[
        harness.index("function Get-NormalModeEnterpriseMachineSnapshot") :
        harness.index("function Get-NormalModeEnterpriseAttributionSnapshot")
    ]
    assert "bin\\defenseclaw-cmid-broker.exe" in normal_snapshot

    public_json_checks = (
        "function Test-CodexSharedDirectoriesPersistThroughPurge",
        "function Invoke-CertificationActivationRepairAfterIsolationProof",
        "function Test-QueuedFailureRestartDuringServicing",
        "function Test-PublicLifecycleInspectionAndReconcile",
        "function Test-UpgradeTransaction",
        "function Test-PublicDefaultUninstallAndReinstall",
    )
    for function_name in public_json_checks:
        start = harness.index(function_name)
        next_function = harness.find("\nfunction ", start + len(function_name))
        section = harness[start:] if next_function < 0 else harness[start:next_function]
        assert "gateway_service_state" in section
        assert "broker_service_state" in section

    default_retention = harness[
        harness.index("function Get-DefaultUninstallRetainedEvidenceSnapshot") :
        harness.index("function Test-PublicDefaultUninstallAndReinstall")
    ]
    for retained in (
        "broker_auth_key",
        "broker_log",
        "cmid-broker\\broker-auth.key",
        "logs\\cmid-broker\\cmid-broker.log",
    ):
        assert retained in default_retention
    assert "'broker_auth_key'" in default_retention
    assert "'broker_log'" in default_retention

    # PowerShell 5.1 has no String.Contains(value, comparisonType) overload.
    assert not re.search(
        r"\.Contains\(\s*[^\n,]+,\s*\[StringComparison\]::",
        harness,
    )


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
    assert "-BrokerSource $script:BrokerSource" in initial_install
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
        "cmid-broker\\broker-auth.key",
        "logs\\cmid-broker\\cmid-broker.log",
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
    assert "enumerator_service = $script:EnumeratorServiceName" in proof
    assert "$null -eq $enumerator" in proof
    assert "secret_material_recorded = $false" in proof

    assert "Assert-EnterpriseMachinePolicyAbsent" in default_uninstall
    assert "Test-FreshClientsHaveNoEnterpriseHookAfterUninstall" in default_uninstall
    assert "machine_policy_absent_before_fresh_clients" in default_uninstall
    assert "machine_policy_absent_after_fresh_clients" in default_uninstall
    assert "fresh_clients_without_enterprise_hook" in default_uninstall
    assert "'public reinstall' `" in default_uninstall
    assert "([string]$script:SourceDigests['upgrade_broker'])" in default_uninstall
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
    # The helper lives exactly as long as the owning smoke, so captured EOF
    # while it is alive is a causal no-inheritance proof, and no failure path
    # can orphan it.
    assert "`$owner = [Diagnostics.Process]::GetProcessById($OwnerProcessId)" in helper_capture_smoke
    assert "`$owner.StartTime.ToUniversalTime().Ticks -eq $OwnerStartTicks" in helper_capture_smoke
    assert "`$owner.WaitForExit()" in helper_capture_smoke
    assert "-OwnerProcessId $ownerProcessId -OwnerStartTicks $ownerStartTicks" in helper_capture_smoke
    assert "Timeout]::Infinite" not in helper_capture_smoke
    assert "WaitSeconds" not in helper_capture_smoke
    assert "AddSeconds(" not in helper_capture_smoke
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
    assert "-AllowMissingCertificationCodexHome:($Action -in @('Status', 'Verify', 'Recover'))" in module
    assert "-AllowMissing:($Action -in @('Status', 'Verify', 'Recover'))" in module
    assert re.search(
        r"\$allowMissingCertificationHome = \$LifecycleAction -in @\(\s*'Status',\s*'Verify',\s*'Recover'\s*\)",
        read(INSTALLER),
    )

    assert "Invoke-DefenseClawEnterpriseLifecycle" in smoke
    assert "-Action Status" in smoke
    assert "-CertificationCodexHome $certificationCodexHome" in smoke
    assert "-AllowUnsigned" in smoke
    assert "restricted_environment_module_status = $true" in smoke
    assert "module Status did not remain a read-only absent deployment" in smoke


def test_timeout_recovery_replays_the_pending_journal_under_the_lifecycle_lock() -> None:
    module = read(MODULE)
    setup = read(ROOT / "cmd" / "defenseclaw-enterprise-setup" / "platform_windows.go")
    lifecycle = module[module.index("function Invoke-DefenseClawEnterpriseLifecycle") :]
    lock = lifecycle.index("$lifecycleLock = Enter-DefenseClawLifecycleLock -Layout $layout")
    recovery = lifecycle.index("if ($Action -eq 'Recover') {")
    next_action = lifecycle.index("if ($Action -in @('Install', 'Upgrade', 'Repair')", recovery)
    replay = lifecycle[recovery:next_action]
    assert lock < recovery
    assert "Invoke-DefenseClawTimeoutRecovery" in replay
    # The replay and its report are executed by
    # test_timeout_recovery_reports_settled_only_when_no_lifecycle_record_remains
    # and the Setup kill and recovery by
    # TestTimeoutKillsTheLifecycleChildThenRecoversBeforeReturning.
    # Each step of the standalone /ensure plan (one, or install then bundle
    # for the single app) runs the lifecycle child with its recovery; the
    # staged CLI is cleaned up only after the whole plan returns.
    run_child = setup.index("runChild := func(runOpts enterpriseSetupOptions) (enterpriseLifecycleChildRun, error) {")
    plan = setup.index("lifecycle, last, err := runStandaloneEnsurePlan(plan, runChild)")
    assert run_child < setup.index("return runEnterpriseLifecycleChild(parent, runOpts,", run_child) < plan
    # The staged files stay pinned until then too.
    assert plan < setup.index("\n\tstage.releaseFiles()", plan)
    assert plan < setup.index("\n\tstage.cleanupAndAccept()", plan)


def test_enterprise_is_opt_in_without_disabling_normal_mode_repair() -> None:
    matrix = read(MATRIX_TEST)
    # The deployment page and its reference page together hold the contract.
    documentation = " ".join(
        (
            read(DEPLOYMENT_DOC) + read(DEPLOYMENT_DOC)
        ).split()
    )
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

    assert "normal mode uses the existing per-user repair loop" in documentation
    assert "Enterprise enforcement is opt-in" in documentation
    assert "installing a release does not create a machine service" in documentation
    assert "Test-NormalModePreinstallNoOp" in harness
    assert "Test-NormalModeLiveAutoHeal" in harness
    assert "normal-mode-live-hook-auto-heal-preserved" in harness
    assert "normal-mode active user did not prove existing hook auto-heal" in harness
    assert "protected 64-bit machine registration in HKLM" in documentation
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
    assert "function Get-AwaitedHookBridge" in live_repair
    assert "$bridge = Get-AwaitedHookBridge $decoded" in live_repair
    assert "(@($bridge.Arguments) -join ' ') -cne 'hook --connector codex'" in live_repair
    assert "\\$hookProcess=\\[System\\.Diagnostics\\.Process\\]::Start\\(\\$hookStart\\)" in live_repair
    assert "if \\(\\$null -eq \\$LASTEXITCODE\\) \\{ exit 1 \\}" in live_repair
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
    assert "legacy residual lifecycle lock did not inherit before reinstall" in smoke
    assert (
        "persistent lifecycle file lock was not canonically repaired in place for reinstall"
        in smoke
    )
    assert "writable inherited lifecycle lock was not repaired in place" in smoke
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
    # The replacement helpers branch on the enterprise profile (Standalone
    # retires stale replacement backups); run the probe under both profiles.
    profile_check = module[
        module.index("function Test-DefenseClawStandaloneProfile") : module.index(
            "function Get-DefenseClawClaudeMinimumClientVersion"
        )
    ]
    helpers = ""
    for helper in (
        "Clear-DefenseClawRestrictiveFileAttributes",
        "Invoke-DefenseClawTransientFileRetry",
    ):
        start = module.index(f"\nfunction {helper} ") + 1
        helpers += module[start : module.index("\nfunction ", start) + 1]
    # Get-DefenseClawKeptFileDrift reads the module's SID constants, which
    # only the module load sets (rel-1-0-6 GAP-0656 CI).
    sid_constants = _module_sid_constants(module)
    # Install-DefenseClawFileAtomic and Get-DefenseClawKeptFileDrift write
    # their notices with Write-DefenseClawLifecyclePhase, which sits after the
    # cut above. The probe takes the module's own function, as it does for
    # every other helper, so a drifted kept file reaches the replacement it is
    # meant to reach (rel-1-0-6 GAP-0815: "The term
    # 'Write-DefenseClawLifecyclePhase' is not recognized" on the CI runner).
    lifecycle_phase = _module_function(module, "Write-DefenseClawLifecyclePhase")
    # Standalone swaps the file with the native SwapLaunchableFile (GAP-0240),
    # so the probe compiles the module's own native helper.
    native_security = _module_function(module, "Initialize-DefenseClawNativeSecurity")
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
        "function Write-DefenseClawResilienceEvent {\n"
        "    param([string]$Marker, [hashtable]$Fields)\n"
        "}\n"
        "$script:DefenseClawNativeSecurityType = $null\n"
        "$script:WindowsDirectory = [Environment]::GetFolderPath('Windows')\n"
        + sid_constants
        + native_security
        + "\n"
        + profile_check
        + helpers
        + lifecycle_phase
        + "\n"
        + atomic_install
        + r'''
try {
foreach ($profileName in @('SecureClient', 'Standalone')) {
$script:DefenseClawEnterpriseProfile = $profileName
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
    # Standalone keeps a same-bytes file only when its object is one Setup
    # could have made (GAP-0656 review M2): the file the probe wrote inherits
    # the runner account's write access from the temp folder, which is drift,
    # and drift is replaced, not kept. Give the destination the protected
    # access list Setup gives it so the reader below meets a kept file.
    $icacls = [IO.Path]::Combine($script:WindowsDirectory, 'System32', 'icacls.exe')
    $null = & $icacls $destination /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)'
    if ($LASTEXITCODE -ne 0) {
        throw "icacls could not protect the destination (exit code $LASTEXITCODE)"
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
    # A same-bytes file that is not a kept object (the inherited access list
    # the runner gave it): Standalone replaces it with a fresh copy and says so
    # through Write-DefenseClawLifecyclePhase; Secure Client keeps it. Either
    # way the bytes are exact and nothing is left beside it.
    $drifted = [IO.Path]::Combine($root, 'drifted.txt')
    [IO.File]::WriteAllText($drifted, 'second')
    Install-DefenseClawFileAtomic `
        -Source $source `
        -Destination $drifted `
        -SkipIfContentMatches
    if ([IO.File]::ReadAllText($drifted) -cne 'second') {
        throw "$profileName replacement of a same-bytes file that is not a kept object was not exact"
    }
    if (@([IO.Directory]::GetFiles($root, '*.new.*')).Count -ne 0 -or
        @([IO.Directory]::GetFiles($root, '*.backup.*')).Count -ne 0) {
        throw "$profileName atomic replacement left a staging or backup file behind"
    }
}
finally {
    if ([IO.Directory]::Exists($root)) {
        [IO.Directory]::Delete($root, $true)
    }
}
}
}
catch {
    # First line of the run: the reason, so a CI log shows it whatever the
    # engine does with its error stream (rel-1-0-6 GAP-0815).
    [Console]::Out.WriteLine("PROBE FAILED: $($_.Exception.Message) at $($_.ScriptStackTrace)")
    exit 1
}
'ok'
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


def test_recovery_readiness_and_deferred_activation_order_are_fail_closed() -> None:
    module = read(MODULE).replace("\r\n", "\n")

    transaction_start = module[
        module.index("function Start-DefenseClawTransactionServices") :
        module.index("function Restore-DefenseClawTransactionWithManagedHooksRollback")
    ]
    enumerator_start = transaction_start.index(
        "Start-DefenseClawService -Name $enumeratorServiceName"
    )
    enumerator_demand = transaction_start.index(
        "-Name $enumeratorServiceName `\n                -StartMode 3"
    )
    readiness = transaction_start.index("Wait-DefenseClawEnterpriseReadiness `")
    enumerator_final_mode = transaction_start.index(
        "-StartMode $enumeratorTargetStartMode"
    )
    assert enumerator_demand < enumerator_start < readiness < enumerator_final_mode
    assert "-RequireEnumerator:$enumeratorShouldRun" in transaction_start
    assert "-Enumerator" in transaction_start[
        transaction_start.index("-Name $enumeratorServiceName `") :
        transaction_start.index(
            "Set-DefenseClawServiceStartMode -Name $name -StartMode 4"
        )
    ]

    restore = module[
        module.index("function Restore-DefenseClawTransaction {") :
        module.index("function Assert-DefenseClawRestoredTransactionReadyForActivation")
    ]
    assert "-Enumerator" in restore[
        restore.index("-Name $enumeratorServiceName `") :
        restore.index("Set-DefenseClawServiceStartMode -Name $name -StartMode 4")
    ]

    quiescing_recovery = module[
        module.index("function Recover-DefenseClawQuiescingIntent") :
        module.index("function Recover-DefenseClawPendingTransaction")
    ]
    assert "-Enumerator" in quiescing_recovery[
        quiescing_recovery.index("-Name $enumeratorServiceName `") :
        quiescing_recovery.index(
            "foreach ($name in @($GatewayServiceName, $brokerServiceName, $GuardianServiceName, $enumeratorServiceName))"
        )
    ]

    readiness_function = module[
        module.index("function Wait-DefenseClawEnterpriseReadiness") :
        module.index("function Get-DefenseClawOptionalPropertyValues")
    ]
    assert "[bool]$RequireEnumerator = $true" in readiness_function
    assert "(-not $RequireEnumerator -or $enumeratorReady)" in readiness_function

    reconcile = module[
        module.index("function Invoke-DefenseClawReconcileLifecycle") :
        module.index("function Invoke-DefenseClawEnterpriseLifecycle")
    ]
    deferred_gate = reconcile.index(
        "deferred configuration must be completed with Repair before Reconcile"
    )
    assert reconcile.index("Assert-DefenseClawMetadataIdentity `") < deferred_gate
    assert deferred_gate < reconcile.index(
        "Invoke-DefenseClawCodexRequirementsCommand `"
    )

    status = module[
        module.index("function Get-DefenseClawLifecycleStatus") :
        module.index("function Test-DefenseClawGuardianCoverageReport")
    ]
    assert "-not $deferredConfigPending -and" in status

    install_like = module[
        module.index("function Invoke-DefenseClawInstallLikeLifecycle") :
        module.index("function Invoke-DefenseClawUninstallLifecycle")
    ]
    assert "$DeferredConfig -or $priorDeferredConfigPending" in install_like
    clear_marker = install_like.index(
        "$newMetadata.deferred_config_pending = $false"
    )
    assert install_like.rindex("-RequireReadiness", 0, clear_marker) < clear_marker
    assert clear_marker < install_like.index(
        "Complete-DefenseClawTransaction `", clear_marker
    )


def test_legacy_service_recovery_restores_only_authenticated_preimage() -> None:
    module = read(MODULE).replace("\r\n", "\n")

    states = module[
        module.index("function Get-DefenseClawTransactionServiceStates") :
        module.index("function Restore-DefenseClawTransactionServiceStartModes")
    ]
    assert states.count("recorded_in_transaction = $false") == 2
    assert "$states[$enumeratorServiceName]" in states
    assert "$states[$brokerServiceName]" in states

    configure = module[
        module.index("function Set-DefenseClawManagedServices") :
        module.index("function Get-DefenseClawServiceStartMode")
    ]
    assert "[switch]$RestoreTransactionWithoutBroker" in configure
    assert "[switch]$RestoreTransactionWithoutEnumerator" in configure
    assert "-not $DeferAutomaticStart" in configure
    assert "$gatewayDependency = if ($RestoreTransactionWithoutBroker)" in configure
    assert "legacy transaction restore requires the Broker absent" in configure
    assert "legacy transaction restore requires the Enumerator absent" in configure
    assert "if (-not $RestoreTransactionWithoutBroker)" in configure
    assert "if (-not $RestoreTransactionWithoutEnumerator)" in configure
    assert (
        "[Parameter(Mandatory)][AllowEmptyString()][string]$ProviderLibraryPath"
        in configure
    )

    managed_acls = module[
        module.index("function Set-DefenseClawManagedAcls") :
        module.index("function Set-DefenseClawRetainedRuntimeAcls")
    ]
    assert "[switch]$AllowTransactionRecordedBrokerAbsence" in managed_acls
    assert "if (-not $AllowTransactionRecordedBrokerAbsence -or" in managed_acls

    gateway_restore = module[
        module.index("function Restore-DefenseClawTransactionGatewayWithoutBroker") :
        module.index("function Set-DefenseClawCMIDBrokerAuthKey")
    ]
    ownership = gateway_restore.index("Assert-DefenseClawOwnedServiceOrAbsent `")
    dependency = gateway_restore.index("'config', $GatewayServiceName, 'depend=', '/'")
    environment = gateway_restore.index("Set-DefenseClawServiceEnvironment `")
    assert ownership < dependency < environment
    assert "exact absent Broker preimage" in gateway_restore
    assert "-BrokerPipeName" not in gateway_restore
    assert "-BrokerServiceName" not in gateway_restore
    assert "-BrokerAuthKeyPath" not in gateway_restore

    restore = module[
        module.index("function Restore-DefenseClawTransaction {") :
        module.index("function Assert-DefenseClawRestoredTransactionReadyForActivation")
    ]
    legacy_gateway = restore.index(
        "Restore-DefenseClawTransactionGatewayWithoutBroker `"
    )
    broker_recheck = restore.index(
        "Assert-DefenseClawCMIDBrokerServiceOrAbsent `", legacy_gateway
    )
    broker_remove = restore.index(
        "Remove-DefenseClawService -Name $Layout.BrokerServiceName",
        broker_recheck,
    )
    managed_services = restore.index("Set-DefenseClawManagedServices `", broker_remove)
    assert legacy_gateway < broker_recheck < broker_remove < managed_services
    assert "-RestoreTransactionWithoutBroker:(" in restore
    assert "-RestoreTransactionWithoutEnumerator:(" in restore
    assert "-AllowTransactionRecordedBrokerAbsence:(" in restore

    activation = module[
        module.index("function Assert-DefenseClawRestoredTransactionReadyForActivation") :
        module.index("function Start-DefenseClawTransactionServices")
    ]
    assert "-AllowTransactionRecordedBrokerAbsence:$brokerAbsentPreimage" in activation
    assert "-AllowTransactionRecordedEnumeratorAbsence:$enumeratorAbsentPreimage" in activation

    start = module[
        module.index("function Start-DefenseClawTransactionServices") :
        module.index("function Restore-DefenseClawTransactionWithManagedHooksRollback")
    ]
    first_mutation = start.index("Set-DefenseClawServiceStartMode -Name $name -StartMode 4")
    assert start.index("Assert-DefenseClawCMIDBrokerServiceOrAbsent `") < first_mutation
    assert start.index("Restore-DefenseClawTransactionGatewayWithoutBroker `") < start.index(
        "Remove-DefenseClawService -Name $brokerServiceName"
    )
    assert "if ([bool]$gateway.running)" in start
    assert "Restore-DefenseClawTransactionServiceStartModes `" in start
    assert "-RequireBroker:([bool]$broker.existed)" in start

    deployment = module[
        module.index("function Assert-DefenseClawEnterpriseDeployment") :
        module.index("function Get-DefenseClawLifecycleStatus")
    ]
    assert "[switch]$AllowTransactionRecordedBrokerAbsence" in deployment
    assert "-not $ServicingTransaction" in deployment
    assert "authenticated servicing preimage requires Broker to remain absent" in deployment
    assert "-ExpectedDependencies $gatewayDependencies" in deployment

    smoke = read(
        ROOT / "packaging/windows/tests/enterprise-uninstall-transaction-smoke.ps1"
    )
    managed_acls_mock = smoke[
        smoke.index("function script:Set-DefenseClawManagedAcls") :
        smoke.index("function script:Invoke-DefenseClawEnumeratorRefresh")
    ]
    assert "[switch]$AllowTransactionRecordedBrokerAbsence" in managed_acls_mock
    readiness_mock = smoke[
        smoke.index("function script:Wait-DefenseClawEnterpriseReadiness") :
        smoke.index("function script:Wait-DefenseClawFreshGuardianReconcile")
    ]
    assert "[bool]$RequireBroker = $true" in readiness_mock
    assert "readiness-require-broker:{0}" in readiness_mock


def test_uninstall_transaction_smoke_keeps_receipt_paths_powershell_51_compatible() -> None:
    module = read(MODULE)
    smoke = read(UNINSTALL_TRANSACTION_SMOKE)

    assert "failed-teardown-self-restored" in smoke
    assert "rollback_verification_only" in smoke
    assert "disconnected target teardown incomplete" in smoke

    # UUID is truncated to 8 hex chars so the fixture path stays under
    # Windows MAX_PATH once the module's staging suffix (.new.<32-hex>) is
    # appended. See enterprise-uninstall-transaction-smoke.ps1 comment.
    assert "('dcut-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))" in smoke
    assert "function New-HarnessCaseRoot" in smoke
    assert "$stagedProbe.Length -ge 255" in smoke
    assert "legacy MAX_PATH boundary" in smoke
    assert smoke.count("New-HarnessCaseRoot") == 14
    assert "fresh-install-service-bootstrap-rollback-retry" in smoke
    assert "snapshot capture ran before all five service identities existed" in smoke
    assert "repeated-first-activation-failure-exact-rollback" in smoke
    assert "-IsDirectory $true `" in smoke
    bare_directory_argument = re.compile(
        r"(?m)^[ \t]*-IsDirectory[ \t]+`[ \t]*$"
    )
    assert bare_directory_argument.search(module) is None
    assert bare_directory_argument.search(smoke) is None
    rollback_descriptor = module[
        module.index("function Assert-DefenseClawInstallRollbackRootDescriptor") :
        module.index("function Complete-DefenseClawInstallRollbackIntent")
    ]
    assert "-IsDirectory $true `" in rollback_descriptor
    assert "[void](Recover-DefenseClawPendingTransaction `" in smoke
    assert re.search(
        r"(?m)^[ \t]*Recover-DefenseClawPendingTransaction[ \t]+`[ \t]*$",
        smoke,
    ) is None
    assert "$resultItems = @($result)" in smoke
    assert "$resultItems.Count -ne 1" in smoke
    assert "lifecycle-snapshot:capture" in smoke
    assert "lifecycle-snapshot:restore" in smoke
    assert "lifecycle-snapshot:retire" in smoke
    assert "purge_cases = @($purgeResults)" in smoke

    uninstall_case = smoke[
        smoke.index("function Invoke-HarnessUninstallCase") : smoke.index(
            "function Invoke-HarnessDirectReinstallSequence"
        )
    ]
    committed_cleanup = uninstall_case[
        uninstall_case.index("elseif ($CrashAt -ceq 'post-binary-delete')") :
        uninstall_case.index("elseif ($ExpectSuccess)", uninstall_case.index(
            "elseif ($CrashAt -ceq 'post-binary-delete')"
        ))
    ]
    assert "$script:HarnessState.rollback_calls -eq 0" in committed_cleanup
    assert "$script:HarnessState.complete_calls -eq 1" in committed_cleanup
    assert "retry Uninstall to finish cleanup" in committed_cleanup

    dispatch_start = smoke.index(
        "# Quiescing recovery exercises the production disabled"
    )
    dispatch = smoke[dispatch_start : smoke.index(
        "$quiescingResults =", dispatch_start
    )]
    assert "$script:HarnessState.ContainsKey('operation')" in dispatch
    assert "if (-not $hasOperation)" in dispatch
    assert "operation -ceq 'uninstall'" in dispatch
    assert "& $script:HarnessRealStartTransactionServices `" in dispatch


def test_fresh_install_commit_and_root_rollback_authority_is_phase_bound() -> None:
    module = read(MODULE)
    smoke = read(UNINSTALL_TRANSACTION_SMOKE)

    timestamp_validator = module[
        module.index("function Assert-DefenseClawInstallRollbackIntentCommitTimestamp") : module.index(
            "function Get-DefenseClawInstallRollbackIntent"
        )
    ]
    assert "$Intent.PSObject.Properties['committed_at']" in timestamp_validator
    assert "committed install receipt is missing its commit timestamp" in timestamp_validator
    assert "Microsoft.PowerShell.Utility\\Add-Member `" in timestamp_validator
    assert "-Name committed_at `" in timestamp_validator
    assert "-Value '' `" in timestamp_validator
    assert "-Force" in timestamp_validator
    assert "[DateTime]::ParseExact(" in timestamp_validator
    assert "[DateTimeKind]::Unspecified" in timestamp_validator
    assert "uncommitted install receipt contains a commit timestamp" in timestamp_validator

    intent_reader = module[
        module.index("function Get-DefenseClawInstallRollbackIntent") : module.index(
            "function ConvertTo-DefenseClawInstallRollbackIntentJson"
        )
    ]
    first_authentication = intent_reader.index("Assert-DefenseClawCanonicalRawPathAcl `")
    authenticated_again = intent_reader.index(
        "Assert-DefenseClawCanonicalRawPathAcl `", first_authentication + 1
    )
    timestamp_check = intent_reader.index("Assert-DefenseClawInstallRollbackIntentCommitTimestamp `")
    assert authenticated_again < timestamp_check

    preparation_intent = module[
        module.index("function New-DefenseClawInstallPreparationIntent") : module.index(
            "function Set-DefenseClawInstallPreparationRootIdentity"
        )
    ]
    rollback_intent = module[
        module.index("function Publish-DefenseClawInstallRollbackIntent") : module.index(
            "function Assert-DefenseClawInstallRollbackRootDescriptor"
        )
    ]
    assert "committed_at = ''" in preparation_intent
    assert "committed_at = ''" in rollback_intent
    runtime_claims = rollback_intent.index(
        "$runtimeRootsProperty = $Snapshot.PSObject.Properties["
    )
    assert "$createdAny = $createdAny -or @($runtimeRoots).Count -gt 0" in rollback_intent
    assert "$runtimeRoots.Count" not in rollback_intent
    existing_receipt = rollback_intent.index(
        "$existing = Get-DefenseClawInstallRollbackIntent `", runtime_claims
    )
    no_cleanup_authority = rollback_intent.index(
        "if (-not $createdAny -and $null -eq $existing)", existing_receipt
    )
    service_absence_gate = rollback_intent.index(
        "Get-DefenseClawManagedServiceNames `", no_cleanup_authority
    )
    service_sid = rollback_intent.index(
        "Get-DefenseClawServiceSIDForRecovery `", service_absence_gate
    )
    rollback_receipt = rollback_intent.index("$intent = [ordered]@{", service_sid)
    assert (
        runtime_claims
        < existing_receipt
        < no_cleanup_authority
        < service_absence_gate
        < service_sid
        < rollback_receipt
    )

    commit_state = module[
        module.index("function Set-DefenseClawInstallRollbackIntentCommitState") : module.index(
            "function Set-DefenseClawInstallRollbackIntentCommitted"
        )
    ]
    assert "[string]$Intent.phase -cne 'preparing_layout'" in commit_state
    assert "'^S-1-5-80-(?:[0-9]+-){4}[0-9]+$'" in commit_state
    assert "$Intent.gateway_service_sid = $GatewayServiceSID" in commit_state
    assert "$Intent.phase = 'committed'" in commit_state
    assert "Microsoft.PowerShell.Utility\\Add-Member `" in commit_state
    assert "-Name committed_at `" in commit_state
    assert "-Force" in commit_state
    assert "$Intent.committed_at =" not in commit_state

    commit = module[
        module.index("function Set-DefenseClawInstallRollbackIntentCommitted") : module.index(
            "function Complete-DefenseClawCommittedInstallIntent"
        )
    ]
    set_commit_state = commit.index("Set-DefenseClawInstallRollbackIntentCommitState `")
    write_committed_intent = commit.index("Write-DefenseClawInstallRollbackIntent `", set_commit_state)
    assert set_commit_state < write_committed_intent

    service_setup = module[
        module.index("function Set-DefenseClawManagedServicesForTransaction") : module.index(
            "function Get-DefenseClawLayout"
        )
    ]
    create_services = service_setup.index("Set-DefenseClawManagedServices `")
    bind_service_sid = service_setup.index("Set-DefenseClawInstallPreparationGatewayServiceSID `")
    initialize_ipc = service_setup.index("Initialize-DefenseClawManagedIPCDirectory `")
    apply_runtime_acls = service_setup.index("Set-DefenseClawRetainedRuntimeAcls `")
    apply_core_acls = service_setup.index("Set-DefenseClawManagedCoreAcls `")
    assert "if ($BindInstallPreparationSID)" in service_setup
    assert create_services < bind_service_sid < initialize_ipc < apply_runtime_acls < apply_core_acls

    lifecycle = module[
        module.index("function Invoke-DefenseClawInstallLikeLifecycle") : module.index(
            "function Invoke-DefenseClawUninstallLifecycle"
        )
    ]
    enumerator_refresh = lifecycle.index("Invoke-DefenseClawEnumeratorRefresh `")
    target_preparation = lifecycle.index("Invoke-DefenseClawTargetRuntimePreparation `")
    fresh_bind = lifecycle.index("-BindInstallPreparationSID")
    fresh_service_gate = lifecycle.rfind(
        "if ($Action -eq 'Install') {", 0, fresh_bind
    )
    fresh_service_setup = lifecycle[fresh_service_gate:enumerator_refresh]
    assert "Set-DefenseClawManagedServicesForTransaction `" in fresh_service_setup
    assert "-BindInstallPreparationSID" in fresh_service_setup
    assert fresh_service_gate < fresh_bind < enumerator_refresh < target_preparation

    fresh_snapshot_gate = lifecycle.index(
        "if ($Action -eq 'Install') {", target_preparation
    )
    fresh_snapshot_end = lifecycle.index("$attestationNeedsRefresh", fresh_snapshot_gate)
    fresh_snapshot = lifecycle[fresh_snapshot_gate:fresh_snapshot_end]
    assert "Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand `" in fresh_snapshot
    assert "Set-DefenseClawManagedServicesForTransaction `" not in fresh_snapshot

    existing_service_gate = lifecycle.index("if ($Action -ne 'Install') {", fresh_snapshot_end)
    existing_service_end = lifecycle.index("$targetReport =", existing_service_gate)
    existing_service_setup = lifecycle[existing_service_gate:existing_service_end]
    assert "Set-DefenseClawManagedServicesForTransaction `" in existing_service_setup
    assert "-BindInstallPreparationSID" not in existing_service_setup

    descriptor = module[
        module.index("function Assert-DefenseClawInstallRollbackRootDescriptor") : module.index(
            "function Complete-DefenseClawInstallRollbackIntent"
        )
    ]
    assert "[ValidateSet('planned', 'staged', 'canonical', 'quarantined')]" in descriptor
    assert "[ValidateSet('InstallDirectory', 'AdminDirectory')]" in descriptor
    assert "rollback root descriptor received an invalid gateway service SID" in descriptor
    assert "if ($CreationState -ceq 'planned')" in descriptor
    assert "if ($CreationState -ceq 'staged')" in descriptor
    assert "if ($CreationState -ceq 'quarantined')" in descriptor
    assert "$CreationState -cne 'canonical' -or -not $AllowPostManagedAcl" in descriptor
    assert "$liveKind = if ($ExpectedKind -ceq 'InstallDirectory')" in descriptor
    assert descriptor.count("'ServiceInstallDirectory'") == 1
    assert descriptor.count("'StateDirectory'") == 1
    assert "-GatewayServiceSID $GatewayServiceSID" in descriptor
    assert descriptor.count("Assert-DefenseClawCanonicalRawPathAcl `") >= 3
    assert descriptor.count("Test-DefenseClawCanonicalRawPathAcl `") == 2
    bootstrap_match = descriptor.index("Test-DefenseClawCanonicalRawPathAcl `")
    post_managed_gate = descriptor.index("$CreationState -cne 'canonical' -or -not $AllowPostManagedAcl")
    quarantine_match = descriptor.index("Test-DefenseClawCanonicalRawPathAcl `", bootstrap_match + 1)
    live_kind = descriptor.index("$liveKind = if ($ExpectedKind -ceq 'InstallDirectory')")
    live_exact_match = descriptor.index("Assert-DefenseClawCanonicalRawPathAcl `", live_kind)
    assert bootstrap_match < quarantine_match < post_managed_gate < live_kind < live_exact_match

    cleanup = module[
        module.index("function Complete-DefenseClawInstallRollbackIntent") : module.index(
            "function Set-DefenseClawInstallRollbackIntentCommitState"
        )
    ]
    assert "Get-DefenseClawServiceSIDForRecovery `" in cleanup
    assert "fresh-install rollback gateway service SID changed" in cleanup
    assert "legacy install rollback SID migration requires a transaction binding" in cleanup
    assert "$transactionAuthorityBound = (" in cleanup
    assert "-AllowPostManagedAcl:($creationState -ceq 'canonical' -and" in cleanup
    assert "$transactionAuthorityBound -and $serviceSIDBound)" in cleanup

    service_absence = cleanup.index("Assert-DefenseClawServicesAbsentChecked `")
    current_snapshot = cleanup.index(
        "$current = $nativeSecurity::GetDirectorySecuritySnapshotNoFollowIfExists("
    )
    identity_check = cleanup.index("identity changed before rollback cleanup", current_snapshot)
    descriptor_check = cleanup.index("Assert-DefenseClawInstallRollbackRootDescriptor `", identity_check)
    pre_quarantine_no_reparse = cleanup.index(
        "Assert-DefenseClawManagedTreeNoReparse -Root $path", descriptor_check
    )
    quarantine = cleanup.index("SetDirectoryDaclNoFollow(", pre_quarantine_no_reparse)
    quarantine_identity = cleanup.index("identity changed during quarantine", quarantine)
    quarantine_acl_check = cleanup.index("Assert-DefenseClawCanonicalRawPathAcl `", quarantine_identity)
    quarantine_journal = cleanup.index("$intent.$creationStateName = 'quarantined'", quarantine_acl_check)
    quarantine_receipt = cleanup.index("Write-DefenseClawInstallRollbackIntent `", quarantine_journal)
    requery = cleanup.index("$rechecked =", quarantine_receipt)
    requery_identity = cleanup.index("identity changed after quarantine", requery)
    requery_acl_check = cleanup.index("Assert-DefenseClawCanonicalRawPathAcl `", requery_identity)
    post_quarantine_no_reparse = cleanup.index(
        "Assert-DefenseClawManagedTreeNoReparse -Root $path", requery_acl_check
    )
    holder_retry_gate = cleanup.index(
        "if ([string]$claim[0] -ceq 'InstallRoot' -and", post_quarantine_no_reparse
    )
    holder_retry = cleanup[holder_retry_gate:]
    assert "(Test-DefenseClawStandaloneProfile)" in holder_retry
    assert "$removalOptions.RetryHeldFileMilliseconds = 60000" in holder_retry
    assert "$removalOptions.ExpectedRootIdentity = [string]$rechecked.Identity" in holder_retry
    assert "$removalOptions.ExpectedRootSecurityDescriptor = [byte[]]$rechecked.SecurityDescriptor" in holder_retry
    removal = cleanup.index("Remove-DefenseClawManagedTree `", post_quarantine_no_reparse)
    assert "@removalOptions" in cleanup[removal:]
    absence_requery = cleanup.index("GetDirectorySecuritySnapshotNoFollowIfExists(", removal)
    assert (
        service_absence
        < current_snapshot
        < identity_check
        < descriptor_check
        < pre_quarantine_no_reparse
        < quarantine
        < quarantine_identity
        < quarantine_acl_check
        < quarantine_journal
        < quarantine_receipt
        < requery
        < requery_identity
        < requery_acl_check
        < post_quarantine_no_reparse
        < holder_retry_gate
        < removal
        < absence_requery
    )
    quarantine_call = cleanup[quarantine:quarantine_identity]
    assert "[string]$current.Identity" in quarantine_call

    for case_name in (
        "fresh-install-service-bootstrap-rollback-retry",
        "legacy-v2-commit-timestamp-migration",
        "phase-bound-live-root-descriptor-matrix",
        "same-path-manifest-remains-validation-only",
        "existing-deployment-rollback-skips-fresh-root-absence-gate",
        "fresh-root-authority-still-requires-service-absence",
    ):
        assert f"name = '{case_name}'" in smoke
    for event in (
        "install-service-sid-bound",
        "install-receipt:committed",
    ):
        assert event in smoke
    for rejected_case in (
        "planned_staging_only",
        "staged_live_rejected",
        "unbound_live_rejected",
        "wrong_sid_rejected",
        "swapped_kind_rejected",
        "staged_quarantine_reentry_exact",
        "canonical_quarantine_reentry_exact",
        "quarantined_live_rejected",
        "inherited_acl_rejected",
    ):
        assert rejected_case in smoke
    assert "'O:BAG:BAD:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'" in smoke
    assert "'O:BAG:BA(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'" not in smoke


def test_fresh_install_binds_service_identity_before_managed_config_loads() -> None:
    module = read(MODULE)
    smoke = read(UNINSTALL_TRANSACTION_SMOKE)

    transaction_factory_start = module.index("function New-DefenseClawTransaction")
    transaction_factory = module[
        transaction_factory_start : module.index(
            "function Restore-DefenseClawTransaction", transaction_factory_start
        )
    ]
    service_inventory = transaction_factory.index(
        "$services = [Collections.Generic.List[object]]::new()"
    )
    durable_intent = transaction_factory.index(
        "Write-DefenseClawJsonAtomic `\n"
        "            -Value $quiescingIntent `\n"
        "            -Path $Layout.PendingPath",
        service_inventory,
    )
    assert service_inventory < durable_intent
    assert "services = $services" in transaction_factory[service_inventory:durable_intent]

    lifecycle = module[
        module.index("function Invoke-DefenseClawInstallLikeLifecycle") : module.index(
            "function Invoke-DefenseClawUninstallLifecycle"
        )
    ]
    transaction = lifecycle.index("$snapshot = New-DefenseClawTransaction `")
    transaction_binding = lifecycle.index(
        "Set-DefenseClawInstallPreparationTransactionBinding `", transaction
    )
    enumerator_refresh = lifecycle.index("Invoke-DefenseClawEnumeratorRefresh `")
    target_preparation = lifecycle.index("Invoke-DefenseClawTargetRuntimePreparation `")

    service_setup_call = "Set-DefenseClawManagedServicesForTransaction `"
    bind_argument = "-BindInstallPreparationSID"
    fresh_bind = lifecycle.index(bind_argument, transaction_binding)
    fresh_service_setup = lifecycle.rfind(
        service_setup_call, transaction_binding, fresh_bind
    )
    fresh_gate = lifecycle.rfind(
        "if ($Action -eq 'Install') {", transaction_binding, fresh_service_setup
    )
    assert (
        transaction
        < transaction_binding
        < fresh_gate
        < fresh_service_setup
        < fresh_bind
        < enumerator_refresh
        < target_preparation
    )

    # Fresh Install has exactly one SID-binding service publication, and it is
    # not repeated after a helper has loaded the managed configuration.
    assert lifecycle.count(bind_argument) == 1
    assert lifecycle.count(service_setup_call) == 2
    assert service_setup_call not in lifecycle[fresh_bind:enumerator_refresh]
    assert bind_argument not in lifecycle[enumerator_refresh:]

    # Repair/Upgrade keep their existing ordering: capture the installed hook
    # generation, validate the enumerated target runtime, then reconfigure the
    # already-existing service identities without rebinding fresh-install SID
    # authority.
    existing_snapshot_gate = lifecycle.index(
        "if ($Action -ne 'Install') {", transaction_binding
    )
    existing_snapshot = lifecycle.index(
        "Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand `",
        existing_snapshot_gate,
    )
    existing_service_setup = lifecycle.index(service_setup_call, enumerator_refresh)
    existing_service_gate = lifecycle.rfind(
        "if ($Action -ne 'Install') {", target_preparation, existing_service_setup
    )
    assert (
        existing_snapshot_gate
        < existing_snapshot
        < enumerator_refresh
        < target_preparation
        < existing_service_gate
        < existing_service_setup
    )
    existing_service_block = lifecycle[
        existing_service_gate : lifecycle.index("$targetReport =", existing_service_setup)
    ]
    assert bind_argument not in existing_service_block

    # Moving service/SID publication ahead of enumeration creates a new
    # rollback boundary. Retained-state ACL restoration belongs to the shared
    # idempotent restore path, so both synchronous rollback and reboot recovery
    # complete it before authenticated transaction authority can be retired.
    restore_body = module[
        module.index("function Restore-DefenseClawTransaction {") : module.index(
            "function Assert-DefenseClawRestoredTransactionReadyForActivation"
        )
    ]
    ipc_revoke = restore_body.index("Revoke-DefenseClawManagedIPCServiceAccess `")
    service_delete = restore_body.index(
        "Remove-DefenseClawService -Name ([string]$service.name)", ipc_revoke
    )
    shared_cleanup = restore_body.index(
        "Remove-DefenseClawTransactionCreatedSharedDirectories `", service_delete
    )
    retained_restore = restore_body.index(
        "Restore-DefenseClawRetainedStateAclsFromTransaction `", shared_cleanup
    )
    restart_gate = restore_body.index("if (-not $DeferServiceRestart)", retained_restore)
    assert ipc_revoke < service_delete < shared_cleanup < retained_restore < restart_gate

    retained_helper = module[
        module.index("function Restore-DefenseClawRetainedStateAclsFromTransaction") :
        module.index("function Remove-DefenseClawManagedTree")
    ]
    for contract in (
        "state_root_created",
        "state_root_identity",
        "prior_deployment_active",
        "$gatewayServiceRows.Count -ne 1",
        "$priorGatewayExisted -and -not $priorDeploymentActive",
        "$priorDeploymentActive -or",
        "[string]$Snapshot.state_root",
        "[string]$Layout.StateRoot",
        "Assert-DefenseClawServicesAbsentChecked `",
        "Get-DefenseClawServiceSIDForRecovery `",
        "Set-DefenseClawPreservedStateAcls `",
        "retained StateRoot identity changed before ACL rollback",
        "retained StateRoot identity changed during ACL rollback",
        "-Kind AdminDirectory",
    ):
        assert contract in retained_helper
    assert retained_helper.count("Assert-DefenseClawServicesAbsentChecked `") == 2
    assert "$Action" not in retained_helper
    assert "$StateRootCreatedForTransaction" not in retained_helper

    lifecycle_rollback = lifecycle[
        lifecycle.index("catch {\n        $operationError = $_", target_preparation) :
    ]
    restore = lifecycle_rollback.index("Restore-DefenseClawTransaction -SnapshotPath")
    rollback_complete = lifecycle_rollback.index(
        "Complete-DefenseClawTransaction `", restore
    )
    assert restore < rollback_complete
    assert "Set-DefenseClawPreservedStateAcls" not in lifecycle_rollback[
        :rollback_complete
    ]

    # The native smoke injects failure inside enumeration, before target
    # planning or lifecycle capture, and proves exact rollback for gateway,
    # broker, Guardian, and Enumerator before a successful retry.
    for marker in (
        "fail_fresh_install_enumeration = $true",
        "injected fresh-install enumeration failure",
        "enumerator-refresh-enter",
        "DefenseClawGateway",
            "DefenseClawCMIDBroker",
            "DefenseClawSensorHelper",
            "DefenseClawHookGuardian",
        "DefenseClawHookEnumerator",
        "preserved-state-acls:S-1-5-80-1-2-3-4-5",
    ):
        assert marker in smoke
    assert "$targetPlan -lt 0" in smoke
    assert "$capture -lt 0" in smoke
    assert "$preservedStateAcls -gt $finalServiceDelete" in smoke
    assert "$transactionComplete -gt $preservedStateAcls" in smoke
    assert "$script:HarnessState.transaction_calls -eq 3" in smoke
    assert "$script:HarnessState.restore_calls -eq 2" in smoke
    assert "$script:HarnessState.removed_services -eq 10" in smoke


def test_install_like_replacement_manifest_is_hardened_before_target_runtime() -> None:
    module = read(MODULE)
    smoke = read(UNINSTALL_TRANSACTION_SMOKE)

    lifecycle = module[
        module.index("function Invoke-DefenseClawInstallLikeLifecycle") : module.index(
            "function Invoke-DefenseClawUninstallLifecycle"
        )
    ]
    transaction = lifecycle.index("$snapshot = New-DefenseClawTransaction")
    source_publish = lifecycle.index("Install-DefenseClawSourceDescriptor `")
    manifest_replacement = lifecycle.index(
        "$publishedManifestReplacement = [bool](", source_publish
    )
    manifest_acl = lifecycle.index("Set-DefenseClawPathAcl `", manifest_replacement)
    capture = lifecycle.index(
        "Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand `", manifest_acl
    )
    deferred_source_publish = lifecycle.index(
        "Install-DefenseClawSourceDescriptor `", capture
    )
    deferred_manifest_replacement = lifecycle.index(
        "$publishedManifestReplacement = [bool](", deferred_source_publish
    )
    deferred_manifest_acl = lifecycle.index(
        "Set-DefenseClawPathAcl `", deferred_manifest_replacement
    )
    enumerator_refresh = lifecycle.index("Invoke-DefenseClawEnumeratorRefresh `")
    target_plan = lifecycle.index("Invoke-DefenseClawTargetRuntimePreparation `")
    assert (
        transaction
        < source_publish
        < manifest_replacement
        < manifest_acl
        < capture
        < deferred_source_publish
        < deferred_manifest_replacement
        < deferred_manifest_acl
        < enumerator_refresh
        < target_plan
    )
    for acl_contract in (
        lifecycle[manifest_replacement:capture],
        lifecycle[deferred_manifest_replacement:target_plan],
    ):
        assert "$name -ceq 'manifest'" in acl_contract
        assert "Test-DefenseClawSourceDescriptorPublishesReplacement `" in acl_contract
        assert "-Path $destination `" in acl_contract
        assert "-Kind AdminFile `" in acl_contract
        assert "-GatewayServiceSID $script:AdministratorsSID" in acl_contract

    replacement_helper = module[
        module.index("function Test-DefenseClawSourceDescriptorPublishesReplacement") :
        module.index("function ConvertTo-DefenseClawWindowsCommandLineArgument")
    ]
    assert "$Source.ContainsKey('path')" in replacement_helper
    assert "[IO.Path]::GetFullPath([string]$Source.path)" in replacement_helper
    assert "[IO.Path]::GetFullPath($Destination)" in replacement_helper
    assert "[StringComparison]::OrdinalIgnoreCase" in replacement_helper

    preparation_mode = module[
        module.index("function Get-DefenseClawTargetRuntimePreparationMode") :
        module.index("function Invoke-DefenseClawInstallLikeLifecycle")
    ]
    assert "if ($Action -eq 'Install') { return 'prepare' }" in preparation_mode
    assert "return 'validate'" in preparation_mode

    failure_message = module[
        module.index("function Get-DefenseClawTargetRuntimeProbeFailureMessage") :
        module.index("function Invoke-DefenseClawTargetRuntimePreparation")
    ]
    assert "ConvertTo-DefenseClawBoundedDiagnostic -Value $Probe.output" in failure_message
    target_runtime = module[
        module.index("function Invoke-DefenseClawTargetRuntimePreparation") :
        module.index("function Assert-DefenseClawTargetRuntimeProductionChildrenExclusive")
    ]
    for phase in ("planning", "staging", "finalization"):
        assert f"-Phase {phase} `" in target_runtime
    stage_journal = target_runtime.index("-StageReport $stage `")
    stage_failure = target_runtime.index("-Phase staging `")
    assert stage_journal < stage_failure

    for event in (
        "manifest-published",
        "manifest-admin-acl",
        "enumerator-refresh",
        "target-runtime:plan-enter",
        "target-runtime:plan",
        "target-runtime:stage",
        "target-runtime:finalize",
    ):
        assert event in smoke
    assert "& $script:HarnessRealSetPathAcl @PSBoundParameters" in smoke
    assert "Assert-DefenseClawCanonicalPathAcl `" in smoke
    assert "target-runtime plan preceded the replacement manifest ACL" in smoke
    assert "target-runtime planning preceded synchronous enumeration" in smoke
    assert "'Repair'" in smoke
    assert "'Upgrade'" in smoke
    assert "$manifestPublished -gt $capture" in smoke
    assert "$manifestAcl -gt $manifestPublished" in smoke
    assert "$targetPlan -gt $manifestAcl" in smoke
    assert "'O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)'" in smoke
    assert "$samePathSources['manifest']" in smoke
    assert "path = $layout.ManifestPath" in smoke
    assert "name = 'no-source'" in smoke
    assert "sources = $noManifestSources" in smoke
    assert "'managed DACL is not protected'" in smoke
    assert "same_path_manifest_drift_rejected" in smoke
    assert "no_source_manifest_drift_rejected" in smoke
    target_runtime_mock = smoke[
        smoke.index("function Invoke-HarnessTargetRuntimeGatewayCommand") :
        smoke.index("function Assert-HarnessTargetRuntimeCleanupScopeExclusive")
    ]
    plan_enter = target_runtime_mock.index("'target-runtime:plan-enter'")
    manifest_validation = target_runtime_mock.index(
        "Assert-DefenseClawCanonicalPathAcl `",
        target_runtime_mock.index("$manifestWasReplaced = [bool]("),
    )
    plan_event = target_runtime_mock.index(
        "$script:HarnessState.events.Add('target-runtime:plan')"
    )
    assert plan_enter < manifest_validation < plan_event
    activation_failure = smoke[
        smoke.index("function Invoke-HarnessFirstActivationFailureSequence") :
        smoke.index("Invoke-HarnessUninstallCase `", smoke.index(
            "function Invoke-HarnessFirstActivationFailureSequence"
        ))
    ]
    drift_boundary = activation_failure[
        activation_failure.index("$validationOnlyManifestDriftRejected") :
        activation_failure.index("for ($attempt = 1; $attempt -le 2; $attempt++)")
    ]
    assert "'target-runtime:plan-enter'" in drift_boundary
    assert ") -lt 0 -and" in drift_boundary
    assert "'target-runtime:plan'" in drift_boundary
    assert "lowercase Install action skipped target preparation" in smoke
    assert "bounded-redacted-target-runtime-diagnostic" in smoke
    assert "diagnostic-secret" in smoke
    assert "$targetRuntimeDiagnostic -notlike '*diagnostic-secret*'" in smoke
    assert "target runtime finalization failed with exit 7: unavailable" in smoke


def test_non_purge_tombstone_is_transactionally_adopted_on_reinstall() -> None:
    module = read(MODULE)
    smoke = read(UNINSTALL_TRANSACTION_SMOKE)

    helper_start = module.index(
        "function Remove-DefenseClawInactiveDeploymentMetadataForInstall"
    )
    helper_end = module.index(
        "function Assert-DefenseClawMetadataIdentity", helper_start
    )
    helper = module[helper_start:helper_end]
    assert "transaction snapshot does not contain exactly one" in helper
    assert "Get-FileHash" in helper
    assert "changed after its transaction snapshot" in helper
    assert "Remove-Item" in helper

    lifecycle_start = module.index(
        "function Invoke-DefenseClawInstallLikeLifecycle"
    )
    lifecycle_end = module.index(
        "function Invoke-DefenseClawUninstallLifecycle", lifecycle_start
    )
    lifecycle = module[lifecycle_start:lifecycle_end]
    transaction = lifecycle.index("$snapshot = New-DefenseClawTransaction")
    adoption = lifecycle.index(
        "Remove-DefenseClawInactiveDeploymentMetadataForInstall"
    )
    inspection = lifecycle.index(
        "Invoke-DefenseClawCodexRequirementsCommand", adoption
    )
    active_metadata = lifecycle.index(
        "Write-DefenseClawJsonAtomic -Value $newMetadata", inspection
    )
    assert transaction < adoption < inspection < active_metadata

    assert "codex-requirements:inspect:metadata-absent" in smoke
    assert (
        "direct reinstall did not transactionally replace the inactive tombstone"
        in smoke
    )
    direct_reinstall = smoke[
        smoke.index("function Invoke-HarnessDirectReinstallSequence") : smoke.index(
            "function Invoke-HarnessFirstActivationFailureSequence"
        )
    ]
    old_journal = direct_reinstall[
        direct_reinstall.index("$oldJournal = [ordered]@{") :
        direct_reinstall.index("[IO.File]::WriteAllText(", direct_reinstall.index(
            "$oldJournal = [ordered]@{"
        ))
    ]
    assert "schema_version = 4" in old_journal
    assert "phase = 'finalized'" in old_journal
    assert "managed_hooks_activation" not in direct_reinstall[
        direct_reinstall.index("[IO.File]::WriteAllText(") :
        direct_reinstall.index("$oldJournal = [ordered]@{")
    ]
    assert "[switch]$AllowLegacyInactive" in module[
        module.index("function Get-DefenseClawManagedHooksTeardownJournalPhase") :
        module.index("function Remove-DefenseClawCommittedManagedHooksTeardownJournal")
    ]
    assert "-AllowLegacyInactive" in module[
        module.index("function Remove-DefenseClawCommittedManagedHooksTeardownJournal") :
        module.index("function Recover-DefenseClawQuiescingIntent")
    ]
    pre_layout = module[
        module.index("function Invoke-DefenseClawPreLayoutRecovery") :
        module.index("function Get-DefenseClawTargetRuntimePreparationMode")
    ]
    assert "$Action -eq 'Install'" in pre_layout
    assert "Invoke-DefenseClawCommittedUninstallCleanup `" in pre_layout
    assert "the only helper authorized to finalize its own journal" in pre_layout
    assert "service_exists = @{" in direct_reinstall
    assert "ipc_service_sids = @('S-1-5-80-1-2-3-4-5')" in direct_reinstall
    assert "second uninstall retained its shared IPC service SID" in direct_reinstall
    revoke_mock = smoke[
        smoke.index("function script:Revoke-DefenseClawManagedIPCServiceAccess") : smoke.index(
            "function script:Set-DefenseClawManagedAcls"
        )
    ]
    assert "Test-DefenseClawServiceExists -Name $GatewayServiceName" in revoke_mock
    assert ".service_exists.ContainsKey" not in revoke_mock


def test_schema_six_managed_hook_teardown_retirement_is_exact_and_retryable() -> None:
    module = read(MODULE)
    smoke = read(UNINSTALL_TRANSACTION_SMOKE)

    validator = module[
        module.index("function Assert-DefenseClawManagedHooksTeardownJsonObject") :
        module.index("function Get-DefenseClawManagedHooksTeardownJournalPhase")
    ]
    assert "$Label contains an unexpected property" in validator
    assert "schema-6 managed-hook teardown journal has an invalid schema type" in validator
    assert "schema-6 managed-hook teardown target has an invalid property type" in validator
    assert "managed_hooks_activation" in validator
    assert "manifest_sha256" in validator
    assert "deployment_generation_id" in validator
    assert "pending_targets" in validator
    assert "deferred" in validator
    assert "invalid pending target binding" in validator
    assert "pending target changed from the manifest target" in validator
    assert "never-activated journal contains pending target evidence" in validator
    assert "Get-DefenseClawManagedHooksTeardownTargetFingerprint" in validator
    assert "target fingerprint is invalid" in validator
    assert "machine enrollment count is invalid" not in validator
    assert "managed runtime selector snapshot is invalid" not in validator
    assert validator.count(
        "Assert-DefenseClawManagedHooksTeardownProtectedAdminFile"
    ) == 3
    protected_acl = validator[
        validator.index(
            "function Assert-DefenseClawManagedHooksTeardownProtectedAdminFile"
        ) : validator.index(
            "function Get-DefenseClawManagedHooksTeardownJsonArray"
        )
    ]
    assert "Assert-DefenseClawPathAcl" in protected_acl
    assert "-AllowInheritance" not in protected_acl

    reader = module[
        module.index("function Get-DefenseClawManagedHooksTeardownJournalPhase") :
        module.index("function Remove-DefenseClawCommittedManagedHooksTeardownJournal")
    ]
    assert "if ($schemaVersion -eq 6)" in reader
    assert "if ($schemaVersion -ge 6)" not in reader
    assert "if ($schemaVersion -eq 5)" in reader
    assert "$schemaProperty.Value -isnot [int]" in reader
    assert "schema-5 managed-hook teardown journal contains pending targets" in reader
    assert "schema-5 managed-hook teardown target is deferred" in reader
    assert "$schemaVersion -ne 4" in reader
    assert "[switch]$AllowLegacyInactive" in reader
    assert "33554432-byte limit" in reader

    schema_six_fixture = smoke[
        smoke.index("function Write-HarnessSchema6TeardownJournal") :
        smoke.index("function Get-HarnessJournalPhase")
    ]
    assert "schema_version = 6" in schema_six_fixture
    assert "[string]$Disposition = 'active'" in schema_six_fixture
    assert "pending_targets = $pendingTargets" in schema_six_fixture
    fingerprint_body = json.dumps(
        [
            {
                "connector": "claudecode",
                "sid": "S-1-5-21-111-222-333-1009",
                "data_dir": r"C:\Users\Deferred\.defenseclaw",
                "agent_version": "2.1.240",
                "deferred": True,
            }
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()
    assert hashlib.sha256(fingerprint_body).hexdigest() in schema_six_fixture
    assert "deferred = $true" in schema_six_fixture
    assert "managed_hooks_activation" not in schema_six_fixture

    purge_case = smoke[
        smoke.index("function New-HarnessCommittedPurgeCase") :
        smoke.index("function Publish-HarnessPurgeReceipt")
    ]
    assert "-Phase 'captured'" in purge_case
    assert "$capturedPhase -ceq 'captured'" in purge_case
    assert "Set-HarnessJournalPhase" in purge_case
    assert "$preparedPhase -ceq 'prepared'" in purge_case
    assert "schema_version = 7" in purge_case
    assert "$invalidPendingTarget.deferred = $false" in purge_case
    assert "foreach ($disposition in @('pending', 'never'))" in purge_case
    assert "false target fingerprint" in purge_case
    assert "pending target accepted a selector enrollment" not in purge_case
    assert "accepted mismatched Claude enrollment" not in purge_case
    assert "schema-5 teardown reader accepted $legacyCase state" in purge_case
    assert "schema-5 non-deferred compatibility was rejected" in purge_case
    assert "schema-5 reader contract" in purge_case

    finalize_mock = smoke[
        smoke.index("'finalize' {") :
        smoke.index(
            "function script:Complete-DefenseClawCommittedManagedHooksFinalization"
        )
    ]
    assert "Set-HarnessJournalPhase" in finalize_mock
    assert "-Phase 'finalized'" in finalize_mock
    assert "scope A purge retained its shared IPC service SID" in smoke
    assert "did not idempotently resume IPC SID cleanup" in smoke


def test_uninstall_tombstone_preserves_authenticated_activation_identity() -> None:
    module = read(MODULE)
    smoke = read(UNINSTALL_TRANSACTION_SMOKE)

    metadata_writer = module[
        module.index("function New-DefenseClawDeploymentMetadata") : module.index(
            "function Test-DefenseClawMetadataInstalled"
        )
    ]
    assert "deployment metadata requires managed-hook activation evidence" in metadata_writer
    assert "managed_hooks_activation" in metadata_writer

    uninstall = module[
        module.index("function Invoke-DefenseClawUninstallLifecycle") : module.index(
            "function Invoke-DefenseClawReconcileLifecycle"
        )
    ]
    inactive_retry = uninstall.index(
        "if (-not (Test-DefenseClawMetadataInstalled -Metadata $metadata))"
    )
    activation_authentication = uninstall.index(
        "$managedHooksActivationProperty = $metadata.PSObject.Properties["
    )
    tombstone = uninstall.index("$tombstone = New-DefenseClawDeploymentMetadata")
    tombstone_activation = uninstall.index(
        "-ManagedHooksActivation $managedHooksActivation", tombstone
    )
    assert inactive_retry < activation_authentication < tombstone < tombstone_activation

    teardown_mock = smoke[
        smoke.index("function script:Invoke-DefenseClawManagedHooksTeardownCommand", 1000) :
        smoke.index("function script:Complete-DefenseClawCommittedManagedHooksFinalization")
    ]
    assert "teardown $Action lost protected activation evidence" in teardown_mock
    assert "teardown finalize did not observe an inactive tombstone" in teardown_mock
    assert "teardown $Action did not observe active deployment metadata" in teardown_mock

    metadata_mock_start = smoke.index(
        "function script:New-DefenseClawDeploymentMetadata"
    )
    metadata_mock = smoke[
        metadata_mock_start : smoke.index(
            "function script:Set-DefenseClawPreservedStateAcls",
            metadata_mock_start,
        )
    ]
    assert "updated_at = [DateTime]::UtcNow.ToString('o')" in metadata_mock


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
    # The allowlist is the one list the recorded states are built from.
    assert "@($script:CertificationParentRootPaths)" in parent_cleanup
    shared = harness[harness.index("$script:CertificationParentRootPaths = @(\n    $script:") :]
    shared = shared[: shared.index("\n)\n")]
    assert "$script:ProgramDataStagingRoot" in shared
    assert "$script:ProgramDataWorkRoot" in shared
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
    assert ".defenseclaw-managed-hooks.writer.lock" in harness
    assert "legacy_named_objects_ignored = $true" in harness
    # GAP-0650: a standard user is refused the writer lock, so verification
    # completes instead of failing closed behind that user.
    assert "-ExpectDenied" in harness
    assert "standard_user_cannot_hold_file_lock = $true" in harness
    assert "protected_file_lock_bounded_fail_closed" not in harness


def test_uninstall_returns_shared_vendor_directories_to_their_prior_state() -> None:
    """Uninstall leaves nothing of ours in directories other vendors own."""
    module = read(MODULE)

    # Both serialization locks outlive the policy files they guard.
    assert "CodexManagedHooksLockPath" in module
    assert "ClaudeManagedHooksLockPath" in module
    assert "Remove-DefenseClawCommittedManagedHooksSerializationLocks -Layout $Layout" in module
    # A standalone purge then removes the runtime selector state (GAP-0262)
    # and stale protected PowerShell temp folders (GAP-1734), and reports
    # what it kept (behaviour in
    # enterprise-standalone-machine-leftovers-purge-smoke.ps1). The Claude
    # Code folders go with the other recorded vendor folders, last
    # (GAP-0091, test_purge_removes_only_the_vendor_folders_it_recorded).
    assert (
        "Remove-DefenseClawCommittedManagedHooksSerializationLocks -Layout $Layout\n"
        "    $machineStateRemaining = [string[]]@()\n"
        "    if ($Purge -and (Test-DefenseClawStandaloneProfile)) {\n"
        "        $machineStateRemaining = [string[]]@(\n"
        "            @(Remove-DefenseClawRuntimeSelectorState -HookPath ([string]$Layout.HookPath) -Directories @("
    ) in module
    # GAP-2057: stale installer staging and bootstrap folders go too.
    assert (
        "@(Remove-DefenseClawStaleRunDirectories -ProgramData $script:ProgramData "
        "-WindowsTemp ([IO.Path]::Combine($script:WindowsDirectory, 'Temp')))"
    ) in module
    sweep = module[module.index("function Remove-DefenseClawStaleRunDirectories") :]
    sweep = sweep[: sweep.index("\nfunction ", 1)]
    for prefix in ("DefenseClaw-PowerShell-", "DefenseClaw-Installer-", "DefenseClaw-Bootstrap-"):
        assert f"'{prefix}'" in sweep
    assert "[string]$PSScriptRoot" in sweep
    assert "-Name machine_state_remaining" in module
    # GAP-0029: with StateRoot gone, the purge also removes the contract
    # cleanup receipt a forced uninstall left in the lifecycle folder.
    assert "@(Remove-DefenseClawStandaloneOrphanedContractCleanupReceipt -Layout $Layout)" in module

    # The traverse grant names a virtual account that only exists while the
    # service does, so it is dropped by the caller that deleted the service.
    assert "function Revoke-DefenseClawStateAncestorTraverse" in module
    assert "Revoke-DefenseClawStateAncestorTraverse `" in module
    assert "-GatewayServiceSID $gatewaySID" in module

    # The fixed AVC IPC directory is also shared. Retire only the exact
    # deleted gateway's service-SID ACE, including when purge resumes after
    # the SCM row and captured SID are gone.
    assert "function Revoke-DefenseClawManagedIPCServiceAccess" in module
    assert "Remove-DefenseClawSIDFromRawDACL" in module
    assert "Get-DefenseClawServiceSIDForRecovery" in module
    assert "GetDirectorySecuritySnapshotNoFollow" in module
    assert "SetDirectoryDaclNoFollow" in module


def _psm1_function(module: str, name: str) -> str:
    body = module[module.index(f"function {name} {{") :]
    return body[: body.index("\nfunction ", 1)]


def test_purge_removes_only_the_vendor_folders_it_recorded() -> None:
    """GAP-0091: a purge removes a vendor folder only when DefenseClaw recorded
    creating it and it is empty, last, deepest first. Setup and the Go writer
    share one write-once record; nothing removes a vendor folder by name."""
    module = read(MODULE)
    go = read(ROOT / "internal" / "enterprisehooks" / "created_folders_windows.go")
    ensure = read(ROOT / "internal" / "enterprisehooks" / "managed_policy_windows.go")

    # One record format on both sides: folder name, schema, file name, ACL.
    assert "[IO.Path]::Combine(\n        [string](Get-DefenseClawProfileRoots -EnterpriseProfile Standalone).LifecycleDirectory,\n        'created-folders'" in module
    assert 'windowsCreatedFolderRecordDirName = "created-folders"' in go
    assert "$script:CreatedFolderRecordSchema = 1" in module
    assert "windowsCreatedFolderRecordSchema  = 1" in go
    # Both sides fold only A-Z (review L3); the smoke and the Go test pin one
    # name for the same non-ASCII path.
    assert "(ConvertTo-DefenseClawAsciiLowerCase -Value $full)" in _psm1_function(module, "Get-DefenseClawCreatedFolderRecordName")
    assert "if ($code -ge 0x41 -and $code -le 0x5A) {" in _psm1_function(module, "ConvertTo-DefenseClawAsciiLowerCase")
    assert "sha256.Sum256([]byte(asciiLowerCase(filepath.Clean(path))))" in go
    assert "if 'A' <= r && r <= 'Z' {" in go
    pinned = "cb0ed1e34f5e1961147f1101c3b7a237146fc893cc261ebfaaadb52ada704767"
    path = "C:\\ProgramData\\\u00dcn\u00efcode \u0130\\Codex"
    folded = "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in path)
    assert hashlib.sha256(folded.encode("utf-8")).hexdigest() == pinned
    assert pinned in read(ROOT / "internal" / "enterprisehooks" / "created_folders_windows_test.go")
    assert pinned in read(ROOT / "packaging" / "windows" / "tests" / "enterprise-standalone-machine-leftovers-purge-smoke.ps1")
    protected = _psm1_function(module, "New-DefenseClawProtectedDirectory")
    assert "$sddl = 'O:BAG:BAD:P'" in protected and "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" in protected
    assert '"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"' in go
    assert "windows.CREATE_NEW" in go

    # Every writer records only what it created, and only on standalone.
    root = _psm1_function(module, "Initialize-DefenseClawManagedRoot")
    assert "if (-not $isLeaf -and $createdThisComponent) {" in root
    assert "$null = Add-DefenseClawStandaloneCreatedFolderRecord -Path $createdAncestors.ToArray()" in root
    codex = _psm1_function(module, "Initialize-DefenseClawCodexMachinePolicyParent")
    assert "$null = Add-DefenseClawStandaloneCreatedFolderRecord -Path @($directory)" in codex
    record = _psm1_function(module, "Add-DefenseClawStandaloneCreatedFolderRecord")
    assert "if (-not (Test-DefenseClawStandaloneProfile) -or @($Path).Count -eq 0) {" in record
    # Review 4 S1: the writer says whether every folder was recorded.
    assert "return [bool](@($Path).Count -eq 0)" in record and "return $complete" in record and "return $false" in record
    assert "$null = Write-DefenseClawCreatedFolderRecordFile -Path $recordPath -Body $body" in record
    assert "Write-DefenseClawCreatedFolderRecordFile -Path $recordPath -Body $body" in record
    assert "[IO.FileMode]::CreateNew" in _psm1_function(module, "Write-DefenseClawCreatedFolderRecordFile")
    assert "_ = windowsCreatedFolderRecorder(created)" in ensure
    assert "!windowsEnterpriseStandaloneProcess()" in go

    # The consumer: only with no deployment, no pending finalizer and no
    # other scope's state in the lifecycle folder, under the lock (review
    # L2); a record goes only once its folder is gone (L1).
    consumer = _psm1_function(module, "Invoke-DefenseClawStandaloneCreatedFolderRemoval")
    assert "Test-DefenseClawStandaloneNoDeploymentLeft -Layout $Layout" in consumer
    assert "SelfUninstallReceiptPath" in consumer
    assert "$entry.Name -cne 'lifecycle.lock' -and $entry.Name -cne $recordName" in consumer
    assert "@(Get-DefenseClawStandaloneCreatedFolderRecords -RecordDirectory $RecordDirectory)" in consumer
    # The Go scanner step removes DefenseClaw-ScannerRuntime only after this
    # script returned, so a Setup /uninstall found the Cisco folder holding it
    # (created_folders_kept in the install and upgrade lanes) and left the
    # folder and its record: the purge retires the runtime first, under its
    # lock, never through a link.
    assert consumer.index(
        "Remove-DefenseClawStandaloneScannerRuntimeLeftover -LifecycleFolder $lifecycle"
    ) < consumer.index("@(Get-DefenseClawStandaloneCreatedFolderRecords -RecordDirectory $RecordDirectory)")
    assert consumer.index("$entry.Name -cne 'lifecycle.lock'") < consumer.index(
        "Remove-DefenseClawStandaloneScannerRuntimeLeftover -LifecycleFolder $lifecycle"
    )
    scanner = _psm1_function(module, "Remove-DefenseClawStandaloneScannerRuntimeLeftover")
    assert "'DefenseClaw-ScannerRuntime'" in scanner
    assert "scanner-runtime.lock" in scanner
    assert "[IO.FileShare]::None" in scanner
    assert scanner.index("Assert-DefenseClawNoReparsePath -Path $root") < scanner.index("Assert-DefenseClawPathAcl")
    assert scanner.index("Assert-DefenseClawPathAcl") < scanner.index("[IO.FileShare]::None")
    # The Go step opens the lock with FILE_FLAG_OPEN_REPARSE_POINT; a FileStream
    # follows a link and delete-on-close would delete its target, so a lock file
    # that is a link or junction is refused before the open.
    assert "[IO.File]::GetAttributes($lock) -band [IO.FileAttributes]::ReparsePoint" in scanner
    assert scanner.index("[IO.FileAttributes]::ReparsePoint") < scanner.index("[IO.FileShare]::None")
    assert scanner.index("[IO.FileShare]::None") < scanner.index("Remove-DefenseClawNoFollowTree")
    assert "[IO.Directory]::Delete($root, $false)" in scanner
    assert "Remove-Item" not in scanner
    reader = _psm1_function(module, "Get-DefenseClawStandaloneCreatedFolderRecords")
    assert "(Get-DefenseClawCreatedFolderRecordName -Path $recorded) -cne $item.Name" in reader
    # Review 2 L1: the record of the folder above the lifecycle folder goes
    # only when that folder holds nothing but the way to the lifecycle folder.
    assert consumer.index("Get-DefenseClawCreatedFolderOtherEntry -Folder $record.Folder -Toward $lifecycleFull") < consumer.index(
        "foreach ($record in $deferred) {\n        [IO.File]::Delete($record.File)"
    )
    assert (
        "if ([string]::IsNullOrEmpty((Remove-DefenseClawStandaloneCreatedFolder -Path $record.Folder -Roots $Roots))) {\n"
        "            [IO.File]::Delete($record.File)"
    ) in consumer
    assert "Pop-DefenseClawStandaloneCreatedFolderRecords" not in module
    leftover = _psm1_function(module, "Remove-DefenseClawStandaloneLifecycleLockLeftover")
    assert leftover.index("[IO.FileOptions]::DeleteOnClose") < leftover.index("Invoke-DefenseClawStandaloneCreatedFolderRemoval")
    assert leftover.index("Invoke-DefenseClawStandaloneCreatedFolderRemoval") < leftover.index("$stream.Dispose()")
    # One folder: the whole chain is free of reparse points, the folder and
    # its parent are administrator-only (review M1), it is empty, and the
    # delete is non-recursive. A folder that stays is logged.
    one = _psm1_function(module, "Remove-DefenseClawStandaloneCreatedFolder")
    assert one.index("Assert-DefenseClawCreatedFolderRemovable -Path $folder -Roots $Roots") < one.index("[IO.Directory]::Delete($folder, $false)")
    assert "Add-DefenseClawCreatedFolderKept -Folder $folder -Note $stays" in one
    kept = _psm1_function(module, "Add-DefenseClawCreatedFolderKept")
    assert "Write-DefenseClawResilienceEvent -Marker defenseclaw_skip" in kept
    # The finalizer runs after the CLI wrote the lifecycle log, so the folder
    # that stays is named there by the module itself, in a line without an
    # event record (the event check skips it); a lifecycle run puts it in the
    # result (created_folders_kept, review 2 L3), which the CLI logs.
    assert "if ($script:DefenseClawCreatedFolderLogToLifecycleLog) {" in kept
    assert 'Write-DefenseClawLifecycleLogDiagnostic -Message "defenseclaw_skip path=${Folder}: $Note"' in kept
    assert "$script:DefenseClawCreatedFoldersKept.Add($prefix + $Note)" in kept
    note = _psm1_function(module, "Write-DefenseClawLifecycleLogDiagnostic")
    assert "'enterprise-lifecycle.log'" in note and "[IO.Directory]::Exists($directory)" in note
    assert "event" not in note.split("$line = [ordered]@{", 1)[1].split("}", 1)[0]
    assert "Remove-Item" not in one
    removable = _psm1_function(module, "Assert-DefenseClawCreatedFolderRemovable")
    assert "$null = Assert-DefenseClawNoReparsePath -Path $Path\n" in removable
    assert removable.count("Assert-DefenseClawPathAcl -Path") == 2
    # Review 2 L2: every folder above it up to the root, the root strictly.
    assert "$null = Assert-DefenseClawPathAcl -Path $ancestor -AllowedWriterSIDs $writers" in removable
    assert "$ancestor = [IO.Path]::GetDirectoryName($ancestor)" in removable
    assert "Assert-DefenseClawTrustedAncestor -Path $ancestor -Strict" in removable
    remove = _psm1_function(module, "Remove-DefenseClawStandaloneCreatedFolders")
    assert "Sort-Object -Property Length -Descending" in remove
    assert "Remove-DefenseClawStandaloneCreatedFolder -Path $folder -Roots $Roots" in remove
    # A rollback that removes a Codex folder it created retracts its record.
    rollback = _psm1_function(module, "Remove-DefenseClawTransactionCreatedSharedDirectories")
    assert rollback.count("Remove-DefenseClawStandaloneCreatedFolderRecord -Path $directory") == 3
    # The upgrade back-fill: only the two Cisco folders, only with Setup's
    # exact descriptor and nothing but DefenseClaw folders inside.
    backfill = _psm1_function(module, "Add-DefenseClawStandaloneUpgradeVendorFolderRecords")
    assert "GetDirectoryName([string]$profileRoots.StateRoot)" in backfill
    assert "GetDirectoryName([string]$profileRoots.InstallRoot)" in backfill
    refusal = _psm1_function(module, "Get-DefenseClawVendorFolderBackfillRefusal")
    assert "DiscretionaryAclProtected" in refusal and "Get-DefenseClawVendorUsersReadGrantRecord -Path $Path" in refusal
    assert "'^DefenseClaw(-[A-Za-z]+)?$'" in refusal
    lifecycle_body = _psm1_function(module, "Invoke-DefenseClawEnterpriseLifecycle")
    assert (
        "if ($Action -in @('Install', 'Upgrade', 'Repair')) {\n"
        "                    # A computer installed before 1.0.9 has no record of the\n"
        "                    # two Cisco folders Setup created (GAP-0526, GAP-0091).\n"
        "                    Add-DefenseClawStandaloneUpgradeVendorFolderRecords"
    ) in lifecycle_body

    # Both last steps remove the recorded folders after the lock folder; in
    # the lifecycle the MDM journal goes first (a journal kept in
    # C:\\ProgramData\\Cisco keeps that folder and its record, review 2 L1).
    lifecycle = _psm1_function(module, "Invoke-DefenseClawEnterpriseLifecycle")
    tail = lifecycle[lifecycle.index("$script:DefenseClawCreatedFoldersKept.Clear()") :]
    assert tail.index("Remove-DefenseClawMdmRotationJournal -Purge") < tail.index(
        "$createdFolders = [string[]]@(Remove-DefenseClawStandaloneLifecycleLockLeftover -Layout $layout)"
    ) < tail.index("Remove-DefenseClawStandaloneCreatedFolders -Path $createdFolders") < tail.index(
        "Write-DefenseClawUninstallCreatedFolderReport -Layout $layout -Touched $touchedVendorFolders"
    )
    finalizer = _psm1_function(module, "Complete-DefenseClawSelfUninstallRetirement")
    assert (
        "$script:DefenseClawCreatedFolderLogToLifecycleLog = $true\n"
        "                try {\n"
        "                    Remove-DefenseClawStandaloneCreatedFolders -Path @(\n"
        "                        Remove-DefenseClawStandaloneLifecycleLockLeftover -Layout $layout)"
    ) in finalizer
    # Review 2 L3: Setup and the CLI JSON name each kept folder.
    installer = read(ROOT / "packaging" / "windows" / "install-enterprise.ps1")
    assert "DefenseClawEnterprise\\Get-DefenseClawCreatedFoldersKept" in installer
    assert "-Name created_folders_kept" in installer
    assert "Get-DefenseClawCreatedFoldersKept" in module.split("Export-ModuleMember -Function", 1)[1].splitlines()[0]
    standalone_go = read(ROOT / "internal" / "cli" / "windows_enterprise_standalone.go")
    assert 'CreatedFoldersKept []string `json:"created_folders_kept"`' in standalone_go
    assert 'result.AddWarning("created_folders_kept", windowsEnterpriseBoundedDiagnostic(note))' in standalone_go
    # Review 2 S1: no Go path removes a recorded folder and keeps its
    # record. The Claude publish creates no folder (its rollback removes
    # none), DefenseClaw's own folders get no record, and the CLI removes
    # C:\\Program Files\\Cisco only through its record.
    assert "removeCreatedDirs" not in ensure
    assert "return !windowsDefenseClawOwnFolder(path, root)" in go
    assert "if err := os.Remove(recordPath); err != nil" in go
    registration = read(ROOT / "internal" / "cli" / "windows_enterprise_registration.go")
    assert "enterprisehooks.RemoveWindowsCreatedFolderIfEmpty(filepath.Dir(root))" in registration
    # Review 3 L2: the CLI process carries no profile pin, so the removal
    # does not test one (its caller is the standalone result handler).
    removal = go[go.index("func RemoveWindowsCreatedFolderIfEmpty") :]
    removal = removal[: removal.index("\n}\n")]
    assert "windowsEnterpriseStandaloneProcess" not in removal and "if !filepath.IsAbs(path) {" in removal
    assert 'strings.EqualFold(filepath.Base(parent), "Cisco")' not in registration

    # GAP-0704: the agent folders are back-filled with "origin":"upgrade"
    # only with all three proofs; a purge names what it left unproven once,
    # and a Cisco folder shaped like Secure Client is never back-filled.
    assert "-Origin upgrade" in backfill and backfill.count("-Origin upgrade") == 2
    agent = _psm1_function(module, "Get-DefenseClawAgentFolderBackfillRefusal")
    assert "if ($created -lt $stateCreated) {" in agent
    assert "[IO.Directory]::GetCreationTimeUtc($StateRoot)" in agent
    descriptor = _psm1_function(module, "Get-DefenseClawAgentFolderDescriptorRefusal")
    assert "Get-DefenseClawAgentFolderDescriptorRefusal -Path $Path" in agent
    assert "$dacl.Count -ne 3" in descriptor and "$ace.AceFlags -ne $inherit" in descriptor
    # GAP-0767: ProgramData\ampcode (empty, 1.0.2 descriptor) joins the same
    # one-shot back-fill under the same three proofs, and a purge names it
    # once when it stays, whatever it holds, while it carries that descriptor.
    folders = _psm1_function(module, "Get-DefenseClawAgentFolders")
    assert "[IO.Path]::Combine($ProgramData, 'ampcode'); Kind = 'Amp'" in folders
    assert "Parent', 'Amp')" in agent and "if ($Kind -ceq 'Amp') {" in agent
    assert "$children.Count -ne 0" in agent
    touched_amp = _psm1_function(module, "Get-DefenseClawTouchedUnrecordedVendorFolders")
    assert "[string]$agent.Kind -ceq 'Amp'" in touched_amp and "Get-DefenseClawAgentFolderDescriptorRefusal -Path $folder" in touched_amp
    # GAP-0758 review S2: the selector purge never opens, creates or reads
    # behind a link at the folder.
    selector = _psm1_function(module, "Remove-DefenseClawOwnRuntimeSelector")
    assert selector.index("Assert-DefenseClawNoReparsePath -Path $Directory -AllowMissingLeaf") < selector.index("Test-Path -LiteralPath $state")
    committed = _psm1_function(module, "Remove-DefenseClawCommittedManagedHooksSerializationLocks")
    assert committed.index("Assert-DefenseClawNoReparsePath -Path ([IO.Path]::GetDirectoryName($path)) -AllowMissingLeaf") < committed.index(
        "Remove-DefenseClawManagedHooksSerializationLock"
    )
    assert "Add-DefenseClawCreatedFolderKept -Folder ([IO.Path]::GetDirectoryName($path))" in committed
    lock = _psm1_function(module, "Open-DefenseClawRuntimeSelectorLock")
    assert lock.index("Assert-DefenseClawNoReparsePath -Path ([IO.Path]::GetDirectoryName($Path))") < lock.index("[IO.FileMode]::CreateNew")
    assert "[bool]$ownership.preimage_existed" in agent and "[bool]$receipt.config_preexisting" in agent
    assert "$document['origin'] = $Origin" in _psm1_function(module, "Add-DefenseClawStandaloneCreatedFolderRecord")
    report = _psm1_function(module, "Write-DefenseClawUninstallCreatedFolderReport")
    assert "'left in place: not provably created by DefenseClaw'" in report
    # Review 3 L1: nothing in the report can replace the lifecycle's own
    # error or fail an uninstall that has finished: each step and each folder
    # has its own try/catch with Write-Warning, and the lifecycle `finally`
    # calls only this function for them.
    assert report.count("catch {") == 4 and report.count("try {") == 4
    assert "Get-DefenseClawUnprovenVendorFolders" not in lifecycle
    assert "Add-DefenseClawCreatedFolderKept -Folder $kept.Folder" not in lifecycle
    # Review 3 L4: the unproven list is the folders DefenseClaw touched,
    # taken before the uninstall (the snapshot precedes the lifecycle try).
    assert lifecycle.index("Get-DefenseClawTouchedUnrecordedVendorFolders") < lifecycle.index(
        "Remove-DefenseClawStandaloneLifecycleLockLeftover"
    )
    unproven = _psm1_function(module, "Get-DefenseClawUnprovenVendorFolders")
    assert "foreach ($folder in @($Touched))" in unproven and "Get-DefenseClawAgentFolders" not in unproven
    touched = _psm1_function(module, "Get-DefenseClawTouchedUnrecordedVendorFolders")
    assert "Test-DefenseClawAgentFolderOwnFileName" in touched and "'^DefenseClaw(-[A-Za-z]+)?$'" in touched
    # Review 3 L3: the origin is written, never read back by the module.
    assert "Origin =" not in _psm1_function(module, "Get-DefenseClawStandaloneCreatedFolderRecords")
    # Review 3 S1: the allow-list knows what the Codex machine-policy writer
    # adds, and requirements.toml is bound by any state copy.
    names = _psm1_function(module, "Test-DefenseClawAgentFolderOwnFileName")
    assert "'.defenseclaw-managed-hooks.writer.lock'" in names
    assert "'.defenseclaw-managed-hooks.state.committed'" in names
    assert "'^\\.defenseclaw-managed-hooks\\.state\\.[1-9][0-9]{0,7}$'" in names
    hashes = _psm1_function(module, "Get-DefenseClawCodexStateRequirementsHashes")
    assert "'.defenseclaw-managed-hooks.writer.lock'" in hashes and "'.defenseclaw-managed-hooks.state.committed'" in hashes
    assert "Get-DefenseClawCodexStateRequirementsHashes -Directory $Path" in agent
    # Review 3 S2: the agent-folder back-fill runs once per deployment, with
    # an administrator-only marker in the record folder that a purge removes.
    assert backfill.index("Test-DefenseClawAgentFolderBackfillDone -RecordDirectory $RecordDirectory") < backfill.index(
        "Get-DefenseClawAgentFolders"
    ) < backfill.index("Set-DefenseClawAgentFolderBackfillDone -RecordDirectory $RecordDirectory")
    assert "$script:AgentFolderBackfillMarker = 'agent-folder-backfill.done'" in module
    assert "$script:AgentFolderBackfillMarker" in consumer
    assert consumer.index("$script:AgentFolderBackfillMarker") < consumer.index("[IO.Directory]::Delete($RecordDirectory, $false)")
    assert "Set-DefenseClawAgentFolderBackfillDone" not in lifecycle
    # Review 4 S1: the marker follows only a back-fill in which every
    # candidate was recorded or refused by proof. A rollback keeps it (review
    # 5 M1): it does not undo an adoption.
    assert backfill.count("$null = Add-DefenseClawStandaloneCreatedFolderRecord") == 1
    assert "if (-not (Add-DefenseClawStandaloneCreatedFolderRecord -Path @($folder) -RecordDirectory $RecordDirectory -Roots $Roots -Origin upgrade)) {\n                $complete = $false" in backfill
    assert backfill.index("$complete = $false") < backfill.index("if ($complete) {\n            Set-DefenseClawAgentFolderBackfillDone -RecordDirectory $RecordDirectory")
    restore = _psm1_function(module, "Restore-DefenseClawTransaction")
    assert "AgentFolderBackfill" not in restore and "Remove-DefenseClawAgentFolderBackfillMarker" not in module
    # Review 4 L4: a failing report step warns.
    assert report.count("Write-Warning") == 4 and "Write-Verbose" not in report
    assert "'(?i)secure ?client|anyconnect'" in refusal
    assert 'Origin string `json:"origin,omitempty"`' in go

    # The by-name removals are gone (they deleted a folder that existed before).
    for retired in (
        "Remove-DefenseClawEmptyClaudeManagedSettingsFolders",
        "Remove-DefenseClawEmptyStandaloneInstallParent",
    ):
        assert retired not in module
    # GAP-0758 round 2: the CLI's Go twin of the by-name removal is gone too, so
    # the record is the only way a purge removes the ClaudeCode folders.
    for go_file in (ROOT / "internal" / "cli").glob("windows_managed_hooks_teardown*.go"):
        assert "removeEmptyWindowsClaudeManagedSettingsFolders" not in read(go_file), go_file.name


def test_vendor_folder_link_refusal_runs_first_for_standalone_install_like_actions() -> None:
    """GAP-0900: a link on the path of the Codex, Cursor or Claude Code machine
    folder stops Install, Upgrade and Repair before a root, a recovery lane or a
    service is touched, through the one link check the uninstall also uses. The
    uninstall and the reconcile do not call it, and the snapshot refuses the
    same links by name."""
    module = read(MODULE)
    assert "Get-DefenseClawCodexMachineFolderLink" not in module  # one check, not a Codex twin
    dispatcher = _psm1_function(module, "Invoke-DefenseClawEnterpriseLifecycle")
    call = "Assert-DefenseClawVendorMachineFoldersNotLinked -Layout $layout -Action $Action"
    assert dispatcher.count("Assert-DefenseClawVendorMachineFoldersNotLinked") == 1
    at = dispatcher.index(call)
    for later in (
        "$preLayoutRecovery = Invoke-DefenseClawPreLayoutRecovery",
        "$pendingRecovery = Recover-DefenseClawPendingTransaction",
        "Initialize-DefenseClawTransactionManagedRoot",
        "New-DefenseClawLayoutDirectories",
        "$installResult = Invoke-DefenseClawInstallLikeLifecycle",
    ):
        assert at < dispatcher.index(later), later
    assert dispatcher[:at].rstrip().endswith("if ($Action -in @('Install', 'Upgrade', 'Repair')) {")
    for name in (
        "Invoke-DefenseClawUninstallLifecycle",
        "Invoke-DefenseClawReconcileLifecycle",
        "New-DefenseClawTransaction",
    ):
        assert "Assert-DefenseClawVendorMachineFoldersNotLinked" not in _psm1_function(module, name), name
    refusal = _psm1_function(module, "Assert-DefenseClawVendorMachineFoldersNotLinked")
    assert refusal.count("Get-DefenseClawVendorMachineFolderLinks -Layout $Layout") == 1
    listing = _psm1_function(module, "Get-DefenseClawVendorMachineFolderLinks")
    assert listing.count("Get-DefenseClawVendorMachineFolderLink -Directory $folder.Path") == 1
    assert "if (-not (Test-DefenseClawStandaloneProfile)) {" in listing
    for folder in ("'Codex'", "'Cursor'", "'Claude Code'"):
        assert folder in listing
    assert 'cmd /c rmdir `"$($_.Link)`"' in _psm1_function(module, "Format-DefenseClawVendorMachineFolderLinkFix")
    walk = _psm1_function(module, "Get-DefenseClawVendorMachineFolderLink")
    assert "Get-DefenseClawLinkCheckAttributes -Path $current" in walk  # no-follow: a dangling junction is found
    assert "[IO.File]::GetAttributes($Path)" in _psm1_function(module, "Get-DefenseClawLinkCheckAttributes")
    assert "Test-Path" not in walk

    # The snapshot names the same links before it takes anything back.
    go = read(ROOT / "internal" / "cli" / "windows_managed_hooks_lifecycle.go")
    capture = go[go.index('case "capture":') :]
    assert capture.index("windowsManagedHooksRefuseLinkedVendorFolders()") < capture.index(
        "windowsManagedHooksVendorFolderTakeBack()"
    )
    assert "if !windowsManagedHooksStandaloneProcess() {" in go[go.index("var windowsManagedHooksRefuseLinkedVendorFolders") :]


def test_rollback_skips_codex_files_behind_a_link_and_reads_the_user_sid_label() -> None:
    """GAP-0900: a rollback never writes through a link that appeared on the Codex
    folder after the transaction opened (it names the link and goes on, so the
    services come back), and the acceptance of a completed guardian reconcile with
    failed accounts reads the "user (SID)" label Windows has used since 1.0.5. The
    skips are the rollback's alone (-RollbackRestore, passed by the restore check
    only): every forward path keeps failing closed on a link. Secure Client keeps
    the lines it had."""
    module = read(MODULE)
    restore = _psm1_function(module, "Restore-DefenseClawTransaction")
    shared = restore[restore.index("        if ($isSharedCodexFile) {") :]
    link = shared.index("Get-DefenseClawVendorMachineFolderLink")
    skip = shared.index("continue", link)
    assert link < skip < shared.index("Assert-DefenseClawCodexMachinePolicyDirectory")
    assert "Write-DefenseClawResilienceEvent -Marker defenseclaw_degraded" in shared[link:skip]
    assert 'cmd /c rmdir `"$restoreCodexLink`"' in shared[link:skip]
    assert "-SkipCodexMachineState:$restoreCodexLinked" in restore

    # The assertion: a dedicated switch, passed by one caller (the restore check),
    # not -ServicingTransaction, which the install commit and the static validation
    # of a forward run pass too.
    deployment = _psm1_function(module, "Assert-DefenseClawEnterpriseDeployment")
    assert "[switch]$RollbackRestore" in deployment
    assert "if ($RollbackRestore -and $codexTargetEnabled) {" in deployment
    assert "$ServicingTransaction -and $codexTargetEnabled" not in deployment
    assert deployment.count("Get-DefenseClawVendorMachineFolderLink") == 1
    assert module.count("-RollbackRestore `\n") == 1
    ready = _psm1_function(module, "Assert-DefenseClawRestoredTransactionReadyForActivation")
    assert "        -ServicingTransaction `\n        -RollbackRestore `\n" in ready
    # The lines Secure Client runs are the ones it always ran, byte for byte, with
    # the administrator-conflict skips of #1446 around the state check and the
    # ACL backup read; the new code only brackets them.
    for kept in (
        "    if ($codexTargetEnabled) {\n        Assert-DefenseClawCodexMachinePolicyDirectory `\n            -Path $Layout.CodexVendorDirectory\n"
        "        Assert-DefenseClawCodexMachinePolicyDirectory `\n            -Path $Layout.CodexMachinePolicyDirectory\n"
        "        Assert-DefenseClawCodexMachinePolicyFile -Layout $Layout\n"
        "        if (-not (Test-DefenseClawCodexStateAbsentByAdminConflict `\n            -Layout $Layout `\n"
        "            -GatewayServiceName $GatewayServiceName)) {\n"
        "            try {\n                Assert-DefenseClawCodexManagedHooksStateFile -Layout $Layout\n",
        "            [void](Get-DefenseClawCodexRequirementsAclBackup -Layout $Layout)\n        }\n    }\n    else {\n",
        "    if (-not $codexRequirementsDeferred) {\n"
        "        [void](Invoke-DefenseClawCodexRequirementsCommand `\n            -Layout $Layout `\n"
        "            -GatewayServiceName $GatewayServiceName `\n"
        "            -Action $(if ($codexTargetEnabled) { 'verify' } else { 'inspect' }))\n",
    ):
        assert kept in deployment, kept
    # REVIEW-g947 M1: the GAP-0947 flag is set outside the link brace (strict mode reads it
    # later on every path); its deferral logic and the GAP-0802 repair sit inside it.
    init = deployment.index("    $codexRequirementsDeferred = $false\n")
    brace = deployment.index("    if ($codexFolderLink -eq '') {\n")
    assert init < brace
    assert deployment.count("$codexRequirementsDeferred = $false") == 1
    assert "if ($codexFolderLink -eq '') {\n    if ($codexTargetEnabled) {" in deployment

    attributable = _psm1_function(module, "Test-DefenseClawGuardianReportErrorsAttributable")
    # One label parser for every profile (#1446): "connector@user (SID)" and
    # "connector@SID" both key on connector@SID.
    assert attributable.count("'^last guardian reconcile failed for (.+?)(?: \\((S-1-[0-9-]+)\\))?: '") == 1
    assert "Test-DefenseClawStandaloneProfile" not in attributable
    assert "(\\S+): '" not in attributable

    # The error of a failed action names the link the rollback met.
    lifecycle = _psm1_function(module, "Invoke-DefenseClawInstallLikeLifecycle")
    assert "$operationError = Add-DefenseClawVendorMachineFolderLinkFix -ErrorRecord $operationError -Layout $Layout" in lifecycle
    assert lifecycle.count("throw $operationError") == 2


def test_codex_machine_link_keep_belongs_to_the_uninstall_alone() -> None:
    """GAP-0773 / GAP-0758 round 4: only the uninstall keeps a link at the Codex
    machine-policy folder. The snapshot skip, the removal option and the kept
    disposition are each pinned to the uninstall; install, ensure, repair and
    the disabled-Codex reconcile keep the earlier refusal."""
    module = read(MODULE)

    # The uninstall's transaction alone skips the Codex files behind a link.
    assert module.count("-SkipLinkedCodexMachineState") == 1
    uninstall = _psm1_function(module, "Invoke-DefenseClawUninstallLifecycle")
    assert uninstall.count("-SkipLinkedCodexMachineState `") == 1
    transaction = _psm1_function(module, "New-DefenseClawTransaction")
    assert "[switch]$SkipLinkedCodexMachineState" in transaction
    assert "if ($SkipLinkedCodexMachineState) {" in transaction
    assert "$codexFolderLink = Get-DefenseClawVendorMachineFolderLink -Directory ([string]$Layout.CodexMachinePolicyDirectory)" in transaction
    # The loop skips only a destination that sits directly in the linked folder,
    # and still snapshots the others (the ownership and ACL-backup files).
    skip = transaction[transaction.index("if ($codexFolderLink -ne '' -and [string]::Equals("):]
    skip = skip[: skip.index("$destinations.Add([string]$destination)")]
    assert "[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath([string]$destination))" in skip
    assert "[IO.Path]::GetFullPath([string]$Layout.CodexMachinePolicyDirectory)" in skip
    assert "continue" in skip and "[StringComparison]::OrdinalIgnoreCase" in skip

    # The content gate (g582) does not judge the Codex files behind a kept link
    # on an uninstall, so a purge over an administrator's junction goes on;
    # install, ensure and repair (Lifecycle scope) still judge them and refuse.
    gate = _psm1_function(module, "Assert-DefenseClawStandaloneContentTrusted")
    codex_rows = gate[gate.index("CodexTargetEnabled) -eq 'True') {") :]
    codex_rows = codex_rows[: codex_rows.index("# Writer 'Gateway'")]
    assert "$Scope -ceq 'Lifecycle' -or" in codex_rows
    assert codex_rows.index("Get-DefenseClawVendorMachineFolderLink -Directory ([string]$Layout.CodexMachinePolicyDirectory)") < codex_rows.index("'CodexMachinePolicyPath'")

    # Only the uninstall's three removal call sites pass -Teardown, to the
    # command (which adds --uninstall to the remove action) and to the check
    # that accepts a kept link; the reconcile that turns Codex off passes none.
    invoke = _psm1_function(module, "Invoke-DefenseClawCodexRequirementsCommand")
    assert "[switch]$Teardown" in invoke and "$codexRequirementsArguments += '--uninstall'" in invoke
    assert "$Teardown -and $Action -cne 'remove'" in invoke
    # An installed gateway older than this build (1.0.3 and 1.0.8 define only
    # --json) refuses --uninstall with no JSON line, which would fail and roll
    # back the uninstall: the flag goes only to a gateway whose capabilities
    # report it, and it is the only new gateway argument of the branch.
    assert module.count("'--uninstall'") == 1
    guard = invoke[invoke.index("if ($Teardown -and (Test-DefenseClawManagedHooksCommittedTeardownSupported"):]
    guard = guard[: guard.index("$probe = Invoke-DefenseClawGatewayCommand")]
    assert "-Capability codex_requirements_uninstall" in guard
    assert guard.index("-Capability codex_requirements_uninstall") < guard.index("+= '--uninstall'")
    probe = _psm1_function(module, "Test-DefenseClawManagedHooksCommittedTeardownSupported")
    assert "'codex_requirements_uninstall'" in probe.split("param(")[1]
    complete = _psm1_function(module, "Complete-DefenseClawCodexRequirementsRemoval")
    assert "if ($Teardown -and $disposition -ceq 'link_kept'" in complete
    assert complete.index("link_kept") < complete.index("did not prove managed runtime state")
    assert len(re.findall(r"-Action remove `\n +-Teardown\n", module)) == 3
    assert module.count("-Action remove") == 3
    assert module.count("-Report $codexRemoval `\n") == 3
    assert len(re.findall(r"-Report \$codexRemoval `\n +-Teardown\n", module)) == 3
    reconcile_removal = module[module.index("-Action reconcile\n            Complete-DefenseClawCodexRequirementsRemoval"):]
    reconcile_removal = reconcile_removal[: reconcile_removal.index("# Secure Client keeps")]
    assert "-Teardown" not in reconcile_removal

    # Go: the plain removal is strict; the option reaches the connector from the
    # hidden --uninstall flag and the teardown caller only.
    connector_go = read(ROOT / "internal" / "gateway" / "connector" / "codex_machine_requirements_windows.go")
    assert "return removeWindowsCodexMachineRequirements(opts, false)" in connector_go
    assert "return removeWindowsCodexMachineRequirements(opts, true)" in connector_go
    assert connector_go.count("if keepLink {") == 1
    cli_go = read(ROOT / "internal" / "cli" / "windows_codex_requirements.go")
    assert 'if action == "remove" {' in cli_go and 'BoolVar(&uninstall, "uninstall"' in cli_go
    assert "windowsCodexRequirementsTeardownRemover(opts)" in cli_go
    teardown_go = read(ROOT / "internal" / "cli" / "windows_managed_hooks_teardown.go")
    assert "removeReport, err := windowsManagedHooksTeardownCodexRemover(opts)" in teardown_go
    assert "if !windowsManagedHooksTeardownCodexRemovalClean(removeReport) {" in teardown_go
    assert 'json:"codex_requirements_uninstall"' in teardown_go
    assert "CodexRequirementsUninstall: true," in teardown_go
    assert "RemoveWindowsCodexMachineRequirementsForTeardown" not in read(
        ROOT / "internal" / "cli" / "enterprise_hooks_platform_windows.go"
    )


def test_state_absent_purge_uses_only_exact_pinned_scope() -> None:
    """Missing metadata must never turn purge into a machine-wide wildcard."""
    module = read(MODULE)
    fallback = module[
        module.index("function Invoke-DefenseClawExactScopeRecoveryPurge") :
        module.index("function Invoke-DefenseClawPreLayoutRecovery")
    ]
    pre_layout = module[
        module.index("function Invoke-DefenseClawPreLayoutRecovery") :
        module.index("function Invoke-DefenseClawReconcileLifecycle")
    ]

    assert "namespace-root-cleanup" in fallback
    assert "validate_only = $true" in fallback
    assert "expected_identity" in fallback
    assert "gateway_service_sid = $gatewaySID" in fallback
    assert "allowed_directory_descriptors" not in fallback
    assert "allowed_file_descriptors" not in fallback
    assert "quarantine_descriptor" not in fallback
    assert "Get-DefenseClawManagedServiceNames" in fallback
    assert "$managedServiceNames.Count -ne 5" in fallback
    assert "SensorHelper = [string]$expectedServiceNames[2]" in fallback
    # The standalone profile has no broker row and resolves exactly four.
    assert "$managedServiceNames.Count -ne 4" in fallback
    assert "@('Enumerator', 'Guardian', 'Gateway', 'SensorHelper', 'Broker')" in fallback
    assert "Assert-DefenseClawOwnedServiceOrAbsent" in fallback
    assert "Revoke-DefenseClawManagedIPCServiceAccess" in fallback
    assert "exact_scope_recovery = $true" in fallback
    assert "unattributed_user_state_preserved = $true" in fallback
    source_reject = fallback.index("$cleanupSourcePath.StartsWith(")
    service_validation = fallback.index("Get-DefenseClawManagedServiceNames")
    assert source_reject < service_validation
    assert "rerun Uninstall -Purge from external Setup" in fallback
    validate_only = fallback.index(
        "# With exact services stopped, prove the whole root is canonical"
    )
    quiesce = fallback.index(
        "# Quiesce every surviving exact service"
    )
    ipc_revoke = fallback.index(
        "# Retire the exact shared-IPC writer"
    )
    destructive_root_cleanup = fallback.index("$request.validate_only = $false")
    service_delete = fallback.index(
        "# Root retirement succeeded. Reauthenticate each remaining exact SCM row"
    )
    assert quiesce < validate_only < ipc_revoke < destructive_root_cleanup
    assert destructive_root_cleanup < service_delete
    # GAP-0250: standalone removes its own IPC directory and OpenCode plugin,
    # which the native validator does not adopt, once the services are
    # stopped and before the root is validated.
    standalone_ipc = fallback.index("Remove-DefenseClawStandaloneManagedIPCDirectory -Layout $Layout")
    assert quiesce < standalone_ipc < validate_only
    assert "Remove-DefenseClawStandaloneOpenCodeManagedPlugin -Layout $Layout" in fallback[standalone_ipc:validate_only]
    quiesce_body = fallback[quiesce:ipc_revoke]
    assert "Set-DefenseClawServiceStartMode" in quiesce_body
    assert "Stop-DefenseClawService -Name $name" in quiesce_body
    assert "Remove-DefenseClawService" not in fallback[:service_delete]
    assert "Remove-DefenseClawService -Name $name" in fallback[service_delete:]
    assert "-Sources $Sources" in pre_layout

    forbidden = (
        "takeown.exe",
        "icacls.exe",
        "Get-Service -Name 'DefenseClaw*'",
        "HKLM:\\SYSTEM\\CurrentControlSet\\Services'",
        "*defenseclaw*",
        "hooks.json",
        "requirements.toml",
        "\\.defenseclaw'",
    )
    for token in forbidden:
        assert token not in fallback

    assert "Invoke-DefenseClawNamespaceSweep" not in module
    assert "Remove-DefenseClawSweepPath" not in module


def test_delayed_purge_contract_cleanup_is_crash_stable_and_scope_bound() -> None:
    """Retained connector entries need durable CAS authority across retries."""
    module = read(MODULE)
    cleanup = read(ROOT / "internal/cli/windows_managed_hook_contract_cleanup_windows.go")
    connector_cleanup = read(
        ROOT / "internal/gateway/connector/managed_hook_contract_purge_windows.go"
    )
    connector_state = read(ROOT / "internal/gateway/connector/connector_state.go")
    cursor_secure = read(
        ROOT / "internal/enterprisehooks/install_windows_cursor_secure.go"
    )
    connector_cleanup_test = read(
        ROOT / "internal/gateway/connector/managed_hook_contract_purge_windows_test.go"
    )

    state_purge = module[
        module.index("function Get-DefenseClawStatePurgeIntent") :
        module.index("function Invoke-DefenseClawCommittedUninstallCleanup")
    ]
    pre_layout = module[
        module.index("function Invoke-DefenseClawPreLayoutRecovery") :
        module.index("function Get-DefenseClawTargetRuntimePreparationMode")
    ]
    rollback = module[
        module.index("function Restore-DefenseClawTransactionWithManagedHooksRollback") :
        module.index("function Assert-DefenseClawInstallRollbackIntentCommitTimestamp")
    ]
    purge_writer = module[
        module.index("function Write-DefenseClawStatePurgeIntentAtomic") :
        module.index("function Get-DefenseClawSelfUninstallReceipt")
    ]
    smoke = read(
        ROOT / "packaging/windows/tests/enterprise-uninstall-transaction-smoke.ps1"
    )

    assert 'IdentitySHA256' in cleanup
    assert 'windowsManagedHookContractCleanupIdentitySHA256' in cleanup
    cleanup_identity_start = cleanup.index(
        "type windowsManagedHookContractCleanupIdentity struct"
    )
    cleanup_report_start = cleanup.index(
        "type windowsManagedHookContractCleanupReport struct"
    )
    assert cleanup_identity_start < cleanup_report_start, (
        "cleanup source reordered: identity struct must precede report struct "
        "for the negative-slice contract below to remain meaningful"
    )
    assert 'ApplicationStarted' not in cleanup[
        cleanup_identity_start : cleanup_report_start
    ]
    assert 'writeEnterpriseHookAdminOnlyFile(path, body)' in cleanup
    assert 'writeWindowsTargetRuntimeProtectedJSON(path, receipt)' not in cleanup
    assert 'errors.Is(' in cleanup
    assert 'ErrWindowsManagedHookContractCleanupSuperseded' in cleanup
    assert 'contract_cleanup_identity_sha256' in state_purge
    assert 'contract_cleanup_receipt_sha256' not in state_purge
    assert "'contract_locks_pending'" in state_purge
    assert "'contract_locks_finalized'" in state_purge
    assert "'state_root_removed'" in state_purge
    assert state_purge.count('Write-DefenseClawStatePurgeIntentAtomic `') == 3
    # File.Replace requires a non-empty backup path on both .NET Framework
    # and modern .NET; passing $null throws "path is not of a legal form".
    # The writer now stages a unique same-directory backup and retires it
    # after the swap completes.
    assert '[IO.File]::Replace($temporary, $destination, $backup, $true)' in purge_writer
    assert '[IO.File]::Move($temporary, $destination)' in purge_writer
    assert 'Microsoft.PowerShell.Management\\Move-Item' not in purge_writer
    assert purge_writer.index('Set-DefenseClawPathAcl `') < purge_writer.index(
        '[IO.File]::Replace('
    )
    assert 'Write-DefenseClawJsonAtomic `' not in state_purge
    assert "$phaseValue -ceq 'contract_locks_pending'" in state_purge
    assert "$phaseValue -ceq 'contract_locks_finalized'" in state_purge
    assert "$phaseValue -ceq 'state_root_removed'" in state_purge
    assert "-cin @(" not in state_purge
    assert '-NativeCleanupSource $nativeCleanupSource' in pre_layout
    assert "$Sources['gateway']" in pre_layout
    assert 'retained-state Install requires the authenticated' in pre_layout
    assert 'exact-scope purge requires the authenticated native cleanup' in module
    assert 'predates scope-bound connector cleanup ' in module
    assert 'authority; refusing Purge' in module
    assert 'legacy state-purge intent cannot authorize user contract cleanup' not in module
    assert 'Remove-DefenseClawManagedHookContractCleanupReceipt' in rollback
    assert '-AllowPrepared' in rollback
    assert 'windowsManagedHookContractEntrySHA256' in connector_cleanup
    entry_sha_start = connector_cleanup.index(
        "func windowsManagedHookContractEntrySHA256"
    )
    valid_sha_start = connector_cleanup.index(
        "func validManagedHookContractEntrySHA256"
    )
    assert entry_sha_start < valid_sha_start, (
        "connector cleanup reordered: entry-sha function must precede the "
        "validator for the negative-slice contract below to remain meaningful"
    )
    assert 'lock.UpdatedAt' not in connector_cleanup[
        entry_sha_start : valid_sha_start
    ]
    assert 'ManagedGatewayServiceName string' in connector_state
    assert 'json:"managed_gateway_service_name,omitempty"' in connector_state
    assert 'os.Getenv(WindowsGatewayServiceNameEnv)' in connector_state
    assert 'ValidateWindowsManagedHookContractGatewayServiceBinding' in connector_state
    assert 'NewHookContractLockEntryForMode(' in cursor_secure
    assert 'ValidateWindowsManagedHookContractGatewayServiceBinding(lock)' in cursor_secure
    assert 'identity.GatewayServiceName' in cleanup[
        cleanup.index("func captureWindowsManagedHookContractCleanupReceipt") :
        cleanup.index("func readWindowsManagedHookContractCleanupReceipt")
    ]
    assert 'Superseded' in connector_cleanup
    assert 'TestDelayedPurgePreservesSameContractPublishedByNewGatewayScope' in (
        connector_cleanup_test
    )
    assert 'TestCleanupCaptureDoesNotClaimCursorEntryFromNewGatewayScope' in (
        connector_cleanup_test
    )
    assert 'TestCleanupCaptureRemovesLegacyUnboundEntry' in connector_cleanup_test
    assert 'TestCleanupCaptureRejectsWhitespaceGatewayBinding' in connector_cleanup_test
    assert 'TestCleanupClaimMissingStateRequiresPersistedMutationBarrier' in (
        connector_cleanup_test
    )
    assert "'pending-native-finalized-crash-retry'" in smoke
    assert "'contract-cleanup-after-native'" in smoke
    assert "'legacy-schema1-before-state-delete'" in smoke
    assert 'HarnessRealManagedContractCleanup' in smoke


def test_uninstall_tombstone_names_the_removed_release() -> None:
    """GAP-1074: installed_version after an uninstall is the removed release."""
    module = read(MODULE)
    uninstall = module[
        module.index("function Invoke-DefenseClawUninstallLifecycle") :
        module.index("Write-DefenseClawJsonAtomic -Value $tombstone -Path $Layout.MetadataPath")
    ]
    tombstone = uninstall[uninstall.index("$tombstone = New-DefenseClawDeploymentMetadata") :]
    assert "$tombstone.Contains('product_version')" in tombstone
    assert "$metadata.PSObject.Properties['product_version']" in tombstone
    assert "$tombstone['product_version'] = [string]$removedVersion.Value" in tombstone
    assert "$tombstone.Remove('product_version')" in tombstone


def test_install_after_cli_purge_does_not_return_the_purge_result() -> None:
    """GAP-1079: only Uninstall reports a finished self-uninstall purge."""
    module = read(MODULE)
    recovery = module[
        module.index("function Invoke-DefenseClawSelfUninstallRecovery") :
        module.index("function Complete-DefenseClawSelfUninstallRetirement")
    ]
    tail = recovery[recovery.rindex("Remove-DefenseClawSelfUninstallEvidence") :]
    assert "if ($Action -eq 'Uninstall' -and\n        [bool]$receipt.purge_requested" in tail


def test_self_uninstall_finalizer_helper_keeps_its_call_on_one_line() -> None:
    # The helper is an expandable here-string, where a backtick before a
    # newline is an escape, not a continuation. A split call ran
    # Complete-DefenseClawSelfUninstallRetirement without -ReceiptPath, so
    # the finalizer exited and left the ARP entry, HKLM key and retired
    # install root behind (GAP-1373).
    module = read(MODULE)
    builder = module[
        module.index("function Get-DefenseClawSelfUninstallHelperContent") :
        module.index("function Assert-DefenseClawSelfUninstallHelper")
    ]
    helper = builder[builder.index('return @"') : builder.index('\n"@')]
    assert not [line for line in helper.splitlines() if line.rstrip().endswith("`")]
    call = next(line for line in helper.splitlines() if "Complete-DefenseClawSelfUninstallRetirement" in line)
    assert "-ReceiptPath `$ProtectedReceiptPath" in call
    assert "-WaitForCallerExit" in call


def test_only_the_lifecycle_transaction_records_the_installed_config() -> None:
    # validate-service-config migrates and records the config only when the
    # install-like lifecycle asks, after its snapshot; verify is read-only.
    module = read(MODULE)
    install_like = module[
        module.index("function Invoke-DefenseClawInstallLikeLifecycle") : module.index(
            "function Invoke-DefenseClawUninstallLifecycle"
        )
    ]
    start = module.index("function Assert-DefenseClawEnterpriseDeployment {")
    deployment = module[start : module.index("\nfunction ", start + 1)]
    after_snapshot = install_like[install_like.index("$snapshot = New-DefenseClawTransaction `") :]
    assert "-GatewayServiceName $GatewayServiceName `" in after_snapshot
    # Secure Client keeps its validate-only check (GAP-0136, issue #1092).
    assert "-RecordLifecycle:(-not (Test-DefenseClawLayoutBrokerEnabled -Layout $Layout))" in after_snapshot
    assert "Assert-DefenseClawInstalledConfig" in deployment and "-RecordLifecycle" not in deployment


def _module_function(module: str, name: str) -> str:
    start = module.index(f"function {name} {{")
    end = module.find("\nfunction ", start + 1)
    return module[start : end if end != -1 else len(module)]


def _module_sid_constants(module: str) -> str:
    """The module top-level well-known SID constants, verbatim.

    The module sets $script:SystemSID and its siblings once, when it loads. A
    probe that cuts functions out of the module never runs that load, and under
    StrictMode a function that reads one of them (Get-DefenseClawKeptFileDrift
    reads three) fails with "The variable cannot be retrieved because it has
    not been set". A probe whose extracted functions read a SID constant
    prepends this block, so it runs the module own values and not a copy.
    """

    constants = re.findall(r"(?m)^\$script:\w+SID = \x27S-1-[0-9-]+\x27$", module)
    names = {line.split(" = ", 1)[0] for line in constants}
    assert {
        "$script:SystemSID",
        "$script:AdministratorsSID",
        "$script:TrustedInstallerSID",
    } <= names, "the module no longer sets its SID constants at the top level"
    return "\n".join(constants) + "\n"


def test_gateway_service_logs_on_as_local_system() -> None:
    """The managed Windows gateway runs as LocalSystem, keeping its restricted
    service SID and single required privilege."""
    module = read(MODULE)
    assert "function Get-DefenseClawGatewayServiceAccount {\n    return 'LocalSystem'\n}" in module

    setter = _module_function(module, "Set-DefenseClawManagedServices")
    assert "Get-DefenseClawGatewayServiceAccount" in setter
    assert setter.count("'obj=', $gatewayAccount,") == 2  # sc config and sc create
    assert '$gatewayAccount = "NT SERVICE\\$GatewayServiceName"' not in setter
    # The writer proves the account it configured.
    assert "gateway service account is $writtenGatewayAccount after configuration" in setter

    configurations = _module_function(module, "Assert-DefenseClawManagedServiceConfigurations")
    deployment = _module_function(module, "Assert-DefenseClawEnterpriseDeployment")
    for body in (configurations, deployment):
        assert "-ExpectedAccount $ExpectedGatewayAccount" in body
        assert '-ExpectedAccount "NT SERVICE\\$GatewayServiceName"' not in body
        # Restricted service SID and least privilege are unchanged.
        assert "-ExpectedSidType 3" in body
        assert "-ExpectedPrivileges @('SeChangeNotifyPrivilege')" in body

    metadata_writer = _module_function(module, "New-DefenseClawDeploymentMetadata")
    assert "gateway_account = (Get-DefenseClawGatewayServiceAccount)" in metadata_writer
    # The service SID remains the gateway's ACL and trust identity.
    assert '"DEFENSECLAW_WINDOWS_SERVICE_ACCOUNT=NT SERVICE\\$GatewayServiceName"' in module


def test_gateway_needs_no_service_logon_right() -> None:
    """No code grants or asserts SeServiceLogonRight."""
    sources = [MODULE, INSTALLER, ROOT / "scripts" / "test-windows-enterprise-hardening.ps1"]
    sources += sorted((ROOT / "internal").rglob("*.go"))
    sources += sorted((ROOT / "cmd").rglob("*.go"))
    for path in sources:
        text = read(path)
        for needle in ("SeServiceLogonRight", "LsaAddAccountRights"):
            assert needle not in text, f"{path.relative_to(ROOT)} references {needle}"


def test_existing_virtual_account_gateway_migrates_in_place() -> None:
    """Installs whose gateway logs on as the virtual account are
    upgraded, repaired, reinstalled, rolled back and uninstalled in place."""
    module = read(MODULE)

    accepted = _module_function(module, "Get-DefenseClawAcceptedGatewayServiceAccounts")
    assert "Get-DefenseClawGatewayServiceAccount" in accepted
    assert "Get-DefenseClawLegacyGatewayServiceAccount" in accepted
    legacy = _module_function(module, "Get-DefenseClawLegacyGatewayServiceAccount")
    assert 'return "NT SERVICE\\$GatewayServiceName"' in legacy

    # Ownership: the old account is this deployment's own gateway, not foreign.
    owned = _module_function(module, "Assert-DefenseClawOwnedServiceOrAbsent")
    assert "Test-DefenseClawGatewayServiceAccount -Account $objectName -GatewayServiceName $Name" in owned

    # Verification and teardown accept both accounts unless narrowed.
    for name in ("Assert-DefenseClawManagedServiceConfigurations", "Assert-DefenseClawEnterpriseDeployment"):
        body = _module_function(module, name)
        assert "[string[]]$ExpectedGatewayAccount" in body
        assert "Get-DefenseClawAcceptedGatewayServiceAccounts" in body
    configuration = _module_function(module, "Assert-DefenseClawServiceConfiguration")
    assert "[Parameter(Mandatory)][string[]]$ExpectedAccount" in configuration

    # The transaction preimage records each service account.
    transaction = _module_function(module, "New-DefenseClawTransaction")
    assert "account = $account" in transaction
    assert "-Name ObjectName" in transaction

    # Rollback restores the recorded account and verifies exactly that one.
    reader = _module_function(module, "Get-DefenseClawTransactionGatewayAccount")
    assert "PSObject.Properties['account']" in reader
    assert "Get-DefenseClawLegacyGatewayServiceAccount" in reader  # preimages from earlier releases
    assert "transaction records an unsupported gateway service account" in reader
    restore = _module_function(module, "Restore-DefenseClawTransaction")
    assert "-RestoreGatewayAccount (\n                Get-DefenseClawTransactionGatewayAccount -Snapshot $snapshot\n            )" in restore
    ready = _module_function(module, "Assert-DefenseClawRestoredTransactionReadyForActivation")
    assert "-ExpectedGatewayAccount @(\n            Get-DefenseClawTransactionGatewayAccount -Snapshot $Snapshot\n        )" in ready

    setter = _module_function(module, "Set-DefenseClawManagedServices")
    assert "[string]$RestoreGatewayAccount" in setter
    assert "a recorded gateway account can be restored only while transaction services remain disabled" in setter
    assert "refusing to restore unsupported gateway service account" in setter


def test_secure_client_purge_removes_only_defenseclaw_user_runtime_entries() -> None:
    """A Secure Client --purge (nuclear and validated) removes DefenseClaw's
    own entries from every account's .defenseclaw, never through a link and
    never a per-user install's folder; what stays is a warning."""
    module = read(MODULE)

    names = _module_function(module, "Get-DefenseClawManagedUserRuntimeEntryNames")
    for name in (
        "'hooks'",
        "'hook_contract_lock.json'",
        "'hook_contract_lock.json.lock'",
        "'inventory.db'",
        "'inventory.db-journal'",
        "'inventory.db-shm'",
        "'inventory.db-wal'",
    ):
        assert name in names
    # Exactly the managed runtime cleanup contract's root leaves: never a
    # per-user install's data.
    for name in ("config.yaml", "audit.db", ".venv", "installer", "connector_backups", "acp"):
        assert f"'{name}'" not in names
    leftovers = _module_function(module, "Get-DefenseClawPerUserInstallLeftoverNames")
    assert "return @('config.yaml', 'audit.db', '.venv', 'installer')" in leftovers
    go_setup = read(ROOT / "internal" / "enterprisehooks" / "target_runtime_setup_windows.go")
    assert 'var windowsPerUserInstallLeftovers = []string{"config.yaml", "audit.db", ".venv", "installer"}' in go_setup
    for leaf in ("hook_contract_lock.json", "hook_contract_lock.json.lock", "inventory.db-wal"):
        assert f'"{leaf}":' in go_setup

    tree = _module_function(module, "Remove-DefenseClawNoFollowTree")
    assert "[IO.FileAttributes]::ReparsePoint" in tree
    assert "a link or junction; left as found" in tree
    assert "$nativeSecurity::OpenDirectoryPinNoFollow($Path)" in tree
    assert "$nativeSecurity::CloseDirectoryPin($pin)" in tree
    assert "[IO.Directory]::Delete($Path, $false)" in tree
    assert "Remove-Item" not in tree and "-Recurse" not in tree

    folder = _module_function(module, "Remove-DefenseClawManagedUserRuntimeFolder")
    assert "[IO.Path]::Combine($UserHome, '.defenseclaw')" in folder
    assert "$homePin = $nativeSecurity::OpenDirectoryPinNoFollow($UserHome)" in folder
    assert "$dataPin = $nativeSecurity::OpenDirectoryPinNoFollow($dataDir)" in folder
    assert "Get-DefenseClawPerUserInstallLeftoverNames" in folder
    assert "which a per-user DefenseClaw install leaves" in folder
    # The per-user install refusal comes before any removal.
    assert folder.index("Get-DefenseClawPerUserInstallLeftoverNames") < folder.index("Remove-DefenseClawNoFollowTree")
    # The folder itself goes only when empty, and otherwise names what stays.
    assert "if ($left.Count -eq 0) {" in folder
    assert "[IO.Directory]::Delete($dataDir, $false)" in folder
    assert "kept: it still holds" in folder
    assert "Remove-Item" not in folder

    native = _module_function(module, "Initialize-DefenseClawNativeSecurity")
    assert "public static IntPtr OpenDirectoryPinNoFollow(string path)" in native
    pin = native[native.index("public static IntPtr OpenDirectoryPinNoFollow") :]
    pin = pin[: pin.index("public static void CloseDirectoryPin")]
    assert "FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS" in pin
    # Held without FILE_SHARE_DELETE so the folder cannot be swapped.
    assert "FILE_SHARE_READ | FILE_SHARE_WRITE," in pin and "FILE_SHARE_DELETE" not in pin
    assert "FILE_ATTRIBUTE_REPARSE_POINT" in pin

    leftovers_all = _module_function(module, "Remove-DefenseClawManagedUserRuntimeLeftovers")
    assert "Get-DefenseClawManagedUserRuntimeHomes" in leftovers_all
    assert "Remove-DefenseClawManagedUserRuntimeFolder -UserHome" in leftovers_all
    assert "throw" not in leftovers_all

    nuclear = _module_function(module, "Invoke-DefenseClawNuclearUninstall")
    assert "$userRuntime = Remove-DefenseClawManagedUserRuntimeLeftovers" in nuclear
    assert '$warnings.Add("nuclear uninstall left per-user DefenseClaw runtime state: $entry")' in nuclear
    assert "user_runtime_removed                     = [string[]]@($userRuntime.removed)" in nuclear
    assert "user_runtime_remaining                   = [string[]]@($userRuntime.remaining)" in nuclear
    # Still reported as a successful purge: what stays in a profile is a
    # warning, never one of the incomplete items that clear ok.
    assert "ok                                       = ($incomplete.Count -eq 0)" in nuclear
    user_runtime_step = nuclear[
        nuclear.index("$userRuntime = Remove-DefenseClawManagedUserRuntimeLeftovers") : nuclear.index(
            "$serviceStateProbe = {"
        )
    ]
    assert "$incomplete.Add" not in user_runtime_step

    scope = _module_function(module, "Test-DefenseClawManagedUserRuntimeCleanupScope")
    assert "Test-DefenseClawStandaloneProfile" in scope
    assert "Get-DefenseClawNuclearSafeRootPattern" in scope
    uninstall = _module_function(module, "Invoke-DefenseClawUninstallLifecycle")
    assert (
        "if ($Purge -and (Test-DefenseClawManagedUserRuntimeCleanupScope -Layout $Layout)) {\n"
        "        $result = Add-DefenseClawManagedUserRuntimeCleanupResult -Result $result"
    ) in uninstall
    added = _module_function(module, "Add-DefenseClawManagedUserRuntimeCleanupResult")
    assert "-Name user_runtime_remaining" in added and "-Name warnings" in added
    assert "-Name ok" not in added


_USER_RUNTIME_BEHAVIOR_SCRIPT = r"""
param([string]$Module, [string]$UserHome)
$ErrorActionPreference = 'Stop'
$text = [IO.File]::ReadAllText($Module)
foreach ($name in @(
    'Get-DefenseClawManagedUserRuntimeEntryNames',
    'Get-DefenseClawPerUserInstallLeftoverNames',
    'Test-DefenseClawPathPresentNoFollow',
    'Remove-DefenseClawNoFollowTree',
    'Remove-DefenseClawManagedUserRuntimeFolder'
)) {
    $start = $text.IndexOf("function $name {")
    $end = $text.IndexOf("`nfunction ", $start + 1)
    . ([scriptblock]::Create($text.Substring($start, $end - $start)))
}
# The no-follow pin is native Windows code; this stand-in refuses a link or
# non-folder the same way so the walk can run on any engine.
Add-Type -TypeDefinition @"
public static class DefenseClawUserRuntimeTestPin {
    public static System.IntPtr OpenDirectoryPinNoFollow(string path) {
        var attributes = System.IO.File.GetAttributes(path);
        if ((attributes & System.IO.FileAttributes.ReparsePoint) != 0 ||
            (attributes & System.IO.FileAttributes.Directory) == 0)
            throw new System.InvalidOperationException("refusing a link, junction or non-folder: " + path);
        return new System.IntPtr(1);
    }
    public static void CloseDirectoryPin(System.IntPtr handle) {}
}
"@
function Initialize-DefenseClawNativeSecurity { return [DefenseClawUserRuntimeTestPin] }
$outcome = Remove-DefenseClawManagedUserRuntimeFolder -UserHome $UserHome
if ($null -eq $outcome) { 'null'; return }
$outcome | ConvertTo-Json -Depth 4 -Compress
"""


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell 7 is not installed")
def test_secure_client_user_runtime_cleanup_behavior(tmp_path: Path) -> None:
    script = tmp_path / "behavior.ps1"
    script.write_text(_USER_RUNTIME_BEHAVIOR_SCRIPT, encoding="utf-8")

    def run(user_home: Path) -> dict | None:
        completed = subprocess.run(
            ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(script),
             "-Module", str(MODULE), "-UserHome", str(user_home)],
            capture_output=True, text=True, timeout=120, check=False,
        )
        assert completed.returncode == 0, completed.stderr
        output = completed.stdout.strip().splitlines()[-1]
        return None if output == "null" else json.loads(output)

    # The field leftover: hooks, the contract lock and its lock file.
    managed = tmp_path / "managed"
    data = managed / ".defenseclaw"
    (data / "hooks" / "generations").mkdir(parents=True)
    for leaf in ("hook_contract_lock.json", "hook_contract_lock.json.lock"):
        (data / leaf).write_text("{}", encoding="utf-8")
    (data / "hooks" / ".hookcfg").write_text("x", encoding="utf-8")
    (data / "hooks" / "generations" / "bundle").write_text("x", encoding="utf-8")
    outcome = run(managed)
    assert outcome is not None and outcome["folder_removed"] is True
    assert outcome["remaining"] == []
    assert not data.exists() and managed.exists()

    # No folder: nothing to do.
    assert run(managed) is None

    # Anything else stays, with a warning naming it.
    mixed = tmp_path / "mixed"
    (mixed / ".defenseclaw" / "hooks").mkdir(parents=True)
    (mixed / ".defenseclaw" / "notes.txt").write_text("mine", encoding="utf-8")
    outcome = run(mixed)
    assert outcome is not None and outcome["folder_removed"] is False
    assert not (mixed / ".defenseclaw" / "hooks").exists()
    assert (mixed / ".defenseclaw" / "notes.txt").exists()
    assert any("kept: it still holds notes.txt" in entry for entry in outcome["remaining"])

    # A per-user install's folder is left exactly as found.
    peruser = tmp_path / "peruser"
    (peruser / ".defenseclaw" / "hooks").mkdir(parents=True)
    (peruser / ".defenseclaw" / "config.yaml").write_text("x", encoding="utf-8")
    outcome = run(peruser)
    assert outcome is not None and outcome["removed"] == []
    assert (peruser / ".defenseclaw" / "hooks").is_dir()
    assert any("per-user DefenseClaw install" in entry for entry in outcome["remaining"])

    # A link below the folder is never followed.
    linked = tmp_path / "linked"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_text("x", encoding="utf-8")
    (linked / ".defenseclaw" / "hooks").mkdir(parents=True)
    try:
        (linked / ".defenseclaw" / "hooks" / "link").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("this account cannot create symbolic links")
    outcome = run(linked)
    assert outcome is not None and outcome["folder_removed"] is False
    assert (outside / "keep").exists()
    assert any("a link or junction; left as found" in entry for entry in outcome["remaining"])


def test_production_uninstall_admits_native_cleanup_after_recorded_trust() -> None:
    """GAP-0023: a production uninstall reads its deployment metadata only
    under the lifecycle lock, so the unsigned installed CLI it passes as the
    native cleanup executable is admitted there, after the hash-pinned trust
    recorded in that metadata is loaded, and not by Authenticode at entry.
    Standalone only: Secure Client is out of scope and keeps the entry check."""
    module = read(MODULE)
    lifecycle = _module_function(module, "Invoke-DefenseClawEnterpriseLifecycle")
    # Secure Client keeps admitting it at entry (out of scope for GAP-0023).
    assert (
        "$entryNativeCleanupBinary = if ($recoverProductionUninstallAcl -and\n"
        "        (Test-DefenseClawStandaloneProfile)) {"
    ) in lifecycle
    entry = lifecycle.index("$sources = Get-DefenseClawLifecycleSources `")
    entry_call = lifecycle[entry : lifecycle.index("-DeferredConfig:$DeferredConfig", entry)]
    assert "-NativeCleanupBinary $entryNativeCleanupBinary `" in entry_call
    assert "-NativeCleanupBinary $NativeCleanupBinary `" not in entry_call
    repair = lifecycle.index("Repair-DefenseClawUninstallAdminFileAcl `")
    admit = lifecycle.index("Add-DefenseClawProductionUninstallNativeCleanupSource `")
    untrusted = lifecycle.index("return Invoke-DefenseClawUntrustedMetadataRecoveryPurge `")
    forced = lifecycle.index("return Invoke-DefenseClawForcedUninstall `")
    assert entry < repair < admit < untrusted < forced
    helper = _module_function(module, "Add-DefenseClawProductionUninstallNativeCleanupSource")
    assert helper.index("Initialize-DefenseClawRecordedPayloadTrust") < helper.index(
        "Add-DefenseClawNativeCleanupSource"
    )
    assert "$MetadataTrusted" in helper and "Test-DefenseClawStandaloneProfile" in helper


def _function_text(source: str, name: str) -> str:
    start = source.index(f"function {name} {{")
    following = source.find("\nfunction ", start + 1)
    return source[start:] if following < 0 else source[start:following]



def test_untrusted_config_acl_is_refused_before_the_transaction_stops_a_service() -> None:
    """GAP-0590: an untrusted owner or writer on a managed config path made the
    standalone ACL drift repair refuse after the transaction had stopped the
    services, and the rollback refused the same repair, so the gateway,
    guardian and enumerator stayed stopped with the transaction pending. The
    transaction now asks the same question read-only before any service
    changes; the repair after the stop and the rollback keep theirs."""

    module = read(MODULE).replace("\r\n", "\n")
    transaction = _function_text(module, "New-DefenseClawTransaction")
    check = transaction.index(
        "-RedactionKeyClass $precheckRedactionKeyClass `\n                -ContentGateScope $ContentGateScope `\n                -CheckOnly)"
    )
    assert check < transaction.index("Write-DefenseClawJsonAtomic `\n            -Value $quiescingIntent")
    assert check < transaction.index("Set-DefenseClawServiceStartMode -Name $name -StartMode 4")
    assert check < transaction.index("Stop-DefenseClawService -Name $enumeratorServiceName")
    guard = transaction[transaction.rindex("if (", 0, check) : check]
    assert "(Test-DefenseClawStandaloneProfile) -and $PriorDeploymentActive" in guard
    assert "Test-DefenseClawServiceExists -Name $GatewayServiceName" in guard
    assert transaction.count("Repair-DefenseClawDeploymentAclDrift `") == 3
    # g582 review 2 S1: every drift repair in the transaction gates with the
    # caller's scope, and the uninstall passes the scope its own gate ran, so
    # PURGE=1 is not refused for a credential it deletes unread.
    assert transaction.count("-ContentGateScope $ContentGateScope") == 3
    assert "[ValidateSet('Lifecycle', 'Retain', 'Purge')][string]$ContentGateScope = 'Lifecycle'" in transaction
    drift = _function_text(module, "Repair-DefenseClawDeploymentAclDrift")
    # g582 review 3 M4: only the read-only check keeps the caller's scope;
    # the re-stamps are judged with Lifecycle, and an uninstall whose
    # re-stamp that refuses skips it (no throw, no re-stamp) and hands the
    # refusal back.
    assert "$gateScope = if ($CheckOnly) { $ContentGateScope } else { 'Lifecycle' }" in drift
    assert "-GatewayServiceName $GatewayServiceName `\n                -Scope $gateScope" in drift
    assert "-Scope $ContentGateScope" not in drift
    skip = drift.index("if ($CheckOnly -or $ContentGateScope -ceq 'Lifecycle') {\n                throw\n            }")
    assert skip < drift.index("$GateRefusal.Value = $_.Exception.Message") < drift.index(
        "return $false\n        }\n    }\n    if ($CheckOnly) {\n        return $true"
    ) < drift.index("Set-DefenseClawRetainedRuntimeAcls `")
    # The snapshot-failure restart never runs on what the gate refused: the
    # refusal throws inside the restart's try, before the services start,
    # so the quiescing intent is retained.
    failure = transaction[transaction.index("$restoreServices = $services") :]
    refusal = failure.index("-GateRefusal ([ref]$gateRefusal))")
    assert refusal < failure.index("if ($gateRefusal) {") < failure.index(
        'throw "not restarting the services on paths the content gate refused: $gateRefusal"'
    ) < failure.index("Start-DefenseClawTransactionServices `")
    assert failure.index("Start-DefenseClawTransactionServices `") < failure.index("$restartErrors.Add($_.Exception.Message)")
    uninstall = _function_text(module, "Invoke-DefenseClawUninstallLifecycle")
    assert "-SkipRedactionKeySnapshot `\n            -ContentGateScope $(if ($Purge) { 'Purge' } else { 'Retain' })" in uninstall
    repair = _function_text(module, "Repair-DefenseClawDeploymentAclDrift")
    assert repair.index("Assert-DefenseClawRepairableConfigAcl -Layout $Layout") < repair.index(
        "if ($CheckOnly) {\n        return $true"
    ) < repair.index("Set-DefenseClawRetainedRuntimeAcls")
    refusal = _function_text(module, "Assert-DefenseClawRepairableConfigAcl")
    assert "(remove that entry, then ' +\n                (Format-DefenseClawRerunStep) + '; for config.yaml itself, run ' +" in refusal
    assert "(Format-DefenseClawSetupAction -Action '/ensure CONFIG=<the approved config>')" in refusal
    assert '" to write a new config.yaml from that administrator-only file instead): $($_.Exception.Message)")' in refusal

    # GAP-0603: the standalone self-heal never re-stamps an untrusted owner
    # or a null DACL; Setup's own account as owner is still repaired.
    heal = _function_text(module, "Assert-DefenseClawPathAcl")
    assert "$untrustedContract = @('Dacl', '')" in heal
    assert "if ([string]$currentOwner -cne [string](Get-DefenseClawCurrentProcessUserSID)) {" in heal
    assert "-not ($_.Kind -eq 'Contract' -and (Get-DefenseClawPathAclVerdictSeverity -Verdict $_) -in $untrustedContract)" in heal

    # The install-like lifecycle refuses every content path another account
    # can change before the transaction stops anything, and before Repair
    # re-stamps those paths in place (Set-DefenseClawManagedAcls).
    lifecycle = _function_text(module, "Invoke-DefenseClawInstallLikeLifecycle")
    gate = lifecycle.index("Assert-DefenseClawStandaloneContentTrusted `")
    assert gate < lifecycle.index("$snapshot = New-DefenseClawTransaction")
    assert gate < lifecycle.index("Set-DefenseClawManagedAcls `")
    # GAP-0590 review M3: a fresh install and a reinstall over a tombstone too.
    guard = lifecycle.rindex("\n    if (", 0, gate) + 1
    assert lifecycle[guard : lifecycle.index("\n", guard)] == "    if (Test-DefenseClawStandaloneProfile) {"
    content = _function_text(module, "Assert-DefenseClawStandaloneContentTrusted")
    restamped = _function_text(module, "Set-DefenseClawManagedAcls")
    for path in (
        "StateRoot", "ConfigDirectory", "GuardianDirectory", "InstallStateDirectory", "ConfigPath", "ManifestPath",
        "MetadataPath", "AgentApplicationControlAttestationPath", "CodexRequirementsOwnershipPath",
        "CodexRequirementsAclBackupPath", "ManagedHooksTeardownJournalPath", "CodexMachinePolicyPath",
        "CodexManagedHooksStatePath",
    ):
        assert f"'{path}'" in content and f"$Layout.{path}" in restamped, path
    assert "'ManagedHooksLifecycleJournalPath'" in content
    assert "-SelfHealKind" not in content and "Set-DefenseClawPathAcl" not in content
    assert "$ownerSIDs = @($adminWriters + @(Get-DefenseClawCurrentProcessUserSID))" in content
    assert "-AllowedOwnerSIDs $owners `" in content

_LAYOUT_PATH_KEY = r"(\w+(?:Path|Directory|Root|Ancestors))"


_RESTAMP_CALL = re.compile(
    r"(?:Set-DefenseClawPathAcl|Set-DefenseClawSharedPathAcl|Set-DefenseClawStandaloneSecretSddl)\s+(?:`\s+)?-Path\s+(\S+)"
)

# The variables the two re-stamp functions pass as -Path, by the layout keys
# or leaf names they hold. A new variable is unmapped and fails the contract
# until it is mapped here and gated or named out of class.
_RESTAMP_VARIABLES = {
    "$path": {"ACPPath", "HookPath", "SensorHelperPath", "InstallerPath", "ModulePath", "BrokerPath"},
    "$directory": {"CompilerLibDirectory", "CompilerDirectory"},
    "$compilerPath": {"CompilerPath"},
    "$runtimeEnv": {".env"},
    "$authorizationFile": {"AuthorizationLedgerPath", "activation.json"},
    "$approvedPath": {"ApprovedPolicyFiles"},
    "$secrets": {"CredentialStore"},
    "$item.FullName": {"CredentialFiles"},
    # The copy of the Codex state the hook reads (GAP-0650).
    "$codexStateCopy": {"CodexManagedHooksStatePath"},
    # The lazily created lock files (GAP-0766): named out of class, they hold no bytes DefenseClaw reads.
    "$lockFile.Path": {"LazyLockFiles"},
}


def _restamped_managed_paths(managed_acls: str, secrets_acls: str) -> set[str]:
    """The paths Set-DefenseClawManagedAcls and Set-DefenseClawStandaloneSecretsAcls
    re-stamp in place: the -Path of every re-stamp call (a layout key, or a
    mapped variable), every layout path key the function reads, the bundle
    tree, the state-root ancestors and the Secure Client marker."""

    names: set[str] = set()
    for body in (managed_acls, secrets_acls):
        for target in _RESTAMP_CALL.findall(body):
            layout = re.fullmatch(r"\$Layout\.(\w+)", target)
            names |= {layout.group(1)} if layout else _RESTAMP_VARIABLES.get(target, {f"<unmapped {target}>"})
    names |= set(re.findall(r"\$Layout\." + _LAYOUT_PATH_KEY + r"\b", managed_acls))
    names |= set(re.findall(r"-Name " + _LAYOUT_PATH_KEY + r"\b", managed_acls))
    for call, name in (
        ("Invoke-DefenseClawBundleAclContract -Layout $Layout", "BundleTree"),
        ("Set-DefenseClawSecureClientInstallMarker -Layout $Layout", "SecureClientInstallMarker"),
        ("Grant-DefenseClawStateAncestorTraverse -Path $ancestor", "StateRootAncestors"),
    ):
        if call in managed_acls:
            names.add(name)
    return names


def _gated_managed_paths(gate: str) -> set[str]:
    names = set(re.findall(r"@\('(\w+)', \$\w+, ", gate))
    names |= set(re.findall(r"-Name " + _LAYOUT_PATH_KEY + r"\b", gate))
    names |= set(re.findall(r"Combine\(\$\w+, '([.\w-]*\.\w+)'\)", gate))
    if "Combine($stateRoot, 'secrets')" in gate:
        names.add("CredentialStore")
    if "$item.Name -cmatch '^[a-z0-9][a-z0-9-]{0,62}\\z'" in gate:
        names.add("CredentialFiles")
    if "Get-DefenseClawBundleAclItems -Layout $Layout" in gate:
        names.add("BundleTree")
    if "Get-DefenseClawApprovedPolicyPath -Layout $Layout -Name $copy[0]" in gate:
        names.add("ApprovedPolicyFiles")
    walk = re.search(r"\$walkRoot = if \(\$Scope -ceq 'Retain'\) \{ '(\w+)' \} else \{ '(\w+)' \}", gate)
    if walk and "Get-DefenseClawContentGateWalk -Root" in gate:
        names |= {f"walk:{walk.group(1)}", f"walk:{walk.group(2)}"}
    return names


# The walking re-stamps (g582 review 2 S2): the -Path of every re-stamp call
# in each function, by what it holds. Set-DefenseClawPreservedStateAcls
# re-stamps every state-root descendant on a non-purge uninstall and the root
# and deployment.json on a purge; Set-DefenseClawRetainedRuntimeAcls adopts
# every runtime child. A new call is unmapped and fails the contract.
_WALK_RESTAMPS = {
    "Set-DefenseClawPreservedStateAcls": {
        "$Layout.StateRoot": "StateRoot",
        "$Layout.MetadataPath": "MetadataPath",
        "(Get-DefenseClawExactItemPath": "walk:StateRoot",
    },
    "Set-DefenseClawRetainedRuntimeAcls": {
        "$directory": "walk:RuntimeDirectory",
        "$path": "walk:RuntimeDirectory",
    },
}


def _ungated_walk_restamps(module: str) -> set[str]:
    gated = _gated_managed_paths(_function_text(module, "Assert-DefenseClawStandaloneContentTrusted"))
    ungated: set[str] = set()
    for function, mapping in _WALK_RESTAMPS.items():
        targets = _RESTAMP_CALL.findall(_function_text(module, function))
        assert targets, function
        for target in targets:
            name = mapping.get(target, f"<unmapped {target}>")
            if name not in gated:
                ungated.add(f"{function}: {name}")
    return ungated


def test_every_walking_restamp_is_gated() -> None:
    """g582 review 2 S2: a non-purge uninstall re-stamps every retained item
    administrator-only (Set-DefenseClawPreservedStateAcls) and the runtime
    adoption gives every runtime child back to the gateway
    (Set-DefenseClawRetainedRuntimeAcls), but the gate judged only a named
    subset. The gate now walks what each re-stamps, in the scope it runs in,
    and a re-stamp call it does not cover fails here."""

    module = read(MODULE).replace("\r\n", "\n")
    assert not _ungated_walk_restamps(module)
    gate = _function_text(module, "Assert-DefenseClawStandaloneContentTrusted")
    assert "$walkRoot = if ($Scope -ceq 'Retain') { 'StateRoot' } else { 'RuntimeDirectory' }" in gate
    assert "if ($Scope -ne 'Purge') {\n        $walkRoot" in gate
    assert "(& $under $full 'LogDirectory')" in gate
    assert "(& $under $full 'RuntimeDirectory') -or (& $under $full 'ManagedIPCDirectory')" in gate
    walk = _function_text(module, "Get-DefenseClawContentGateWalk")
    assert "[IO.FileAttributes]::ReparsePoint" in walk and "Set-DefenseClawPathAcl" not in walk

    # The other direction: without the walk, or with a new re-stamp call in
    # either function, the contract fails.
    without = module.replace(gate, gate.replace("Get-DefenseClawContentGateWalk -Root", "Get-Nothing -Root", 1), 1)
    assert _ungated_walk_restamps(without) == {
        "Set-DefenseClawPreservedStateAcls: walk:StateRoot",
        "Set-DefenseClawRetainedRuntimeAcls: walk:RuntimeDirectory",
    }
    preserved = _function_text(module, "Set-DefenseClawPreservedStateAcls")
    planted = module.replace(
        preserved,
        preserved.replace("    if ($Purge) {\n        Set-DefenseClawPathAcl", "    Set-DefenseClawPathAcl -Path $Layout.PolicyCachePath -Kind AdminFile\n    if ($Purge) {\n        Set-DefenseClawPathAcl", 1),
        1,
    )
    assert planted != module
    assert _ungated_walk_restamps(planted) == {"Set-DefenseClawPreservedStateAcls: <unmapped $Layout.PolicyCachePath>"}
    runtime = _function_text(module, "Set-DefenseClawRetainedRuntimeAcls")
    planted = module.replace(
        runtime,
        runtime.replace("    foreach ($file in $files) {", "    Set-DefenseClawPathAcl -Path $other -Kind RuntimeFile\n    foreach ($file in $files) {", 1),
        1,
    )
    assert planted != module
    assert _ungated_walk_restamps(planted) == {"Set-DefenseClawRetainedRuntimeAcls: <unmapped $other>"}


def test_the_quiescing_recovery_gates_before_it_restamps() -> None:
    """g582 review 2 S2: recovering a crashed transaction re-stamped the
    runtime folder, its children and the core folders after a config check
    only. The content gate now runs first, and a refusal leaves the services
    stopped and the transaction pending, as the config refusal does."""

    recovery = _function_text(read(MODULE).replace("\r\n", "\n"), "Recover-DefenseClawQuiescingIntent")
    gate = recovery.index("Assert-DefenseClawStandaloneContentTrusted -Layout $Layout -GatewayServiceName $GatewayServiceName")
    assert recovery.index("Assert-DefenseClawRepairableConfigAcl -Layout $Layout") < gate
    assert gate < recovery.index("Set-DefenseClawRetainedRuntimeAcls `") < recovery.index("Set-DefenseClawManagedCoreAcls `")


def test_the_content_gate_names_every_refused_path_once() -> None:
    """g582 review 2 S3: the gate threw on the first refused path, so after a
    broad change the admin fixed one path per run. It now collects every
    refusal and throws once, the first in the old form, the rest numbered,
    capped at 20."""

    gate = _function_text(read(MODULE).replace("\r\n", "\n"), "Assert-DefenseClawStandaloneContentTrusted")
    assert "$refusals.Add(" in gate and gate.count("throw") == 1
    assert "$shown = [Math]::Min($refusals.Count, 20)" in gate
    assert "'refusing to change the deployment, and nothing was changed (DefenseClaw does not give a file '" in gate


def _ungated_restamps(module: str) -> tuple[set[str], set[str], set[str]]:
    restamped = _restamped_managed_paths(
        _function_text(module, "Set-DefenseClawManagedAcls"),
        _function_text(module, "Set-DefenseClawStandaloneSecretsAcls"),
    )
    gated = _gated_managed_paths(_function_text(module, "Assert-DefenseClawStandaloneContentTrusted"))
    start = module.index("$script:StandaloneContentGateOutOfClass = @(")
    table = module[start : module.index("\n)\n", start)]
    out_of_class = set(re.findall(r"'(\w+)'", "\n".join(re.findall(r"Paths\s+= @\(([^)]*)\)", table))))
    assert len(re.findall(r"Reason = [\x27\x22]\S", table)) == table.count("Paths  = @(") > 0
    return restamped - gated - out_of_class, out_of_class - restamped, gated & out_of_class


def test_every_restamped_path_is_gated_or_named_out_of_class() -> None:
    """GAP-0590 review M2: the content gate judged only part of what Repair
    and every install-like action re-stamp in place, so a standard user's
    entry on a credential, protected_targets.json, the runtime .env or the
    bundle tree was re-stamped administrator-only with that user's bytes.
    Every path Set-DefenseClawManagedAcls and
    Set-DefenseClawStandaloneSecretsAcls re-stamp is now judged by the gate or
    named, with its reason, in $script:StandaloneContentGateOutOfClass; that
    list names nothing that is not re-stamped, and nothing on it is gated."""

    module = read(MODULE).replace("\r\n", "\n")
    ungated, stale, both = _ungated_restamps(module)
    assert not ungated, f"re-stamped in place but neither gated nor named out of class: {sorted(ungated)}"
    assert not stale, f"named out of class but not re-stamped: {sorted(stale)}"
    assert not both, f"gated and named out of class: {sorted(both)}"
    restamped = _restamped_managed_paths(
        _function_text(module, "Set-DefenseClawManagedAcls"),
        _function_text(module, "Set-DefenseClawStandaloneSecretsAcls"),
    )
    for name in (
        "CredentialStore", "CredentialFiles", "AuthorizationDirectory", "AuthorizationLedgerPath", "activation.json",
        "BrokerStateDirectory", "RuntimeDirectory", ".env", "ManagedIPCDirectory", "BundleTree", "ConfigPath",
        "ManifestPath", "MetadataPath", "GatewayPath", "LogDirectory",
    ):
        assert name in restamped, name

    # A path added to the re-stamp without the gate fails this check.
    managed = _function_text(module, "Set-DefenseClawManagedAcls")
    planted = module.replace(
        managed,
        managed.replace(
            "    Set-DefenseClawPathAcl -Path $Layout.ConfigPath -Kind ConfigFile",
            "    Set-DefenseClawPathAcl -Path $Layout.PolicyCachePath -Kind AdminFile -GatewayServiceSID $gatewaySID\n"
            "    Set-DefenseClawPathAcl -Path $Layout.ConfigPath -Kind ConfigFile",
            1,
        ),
        1,
    )
    assert planted != module
    assert _ungated_restamps(planted)[0] == {"PolicyCachePath"}
    planted = module.replace(
        managed,
        managed.replace(
            "    Set-DefenseClawPathAcl -Path $Layout.ConfigPath -Kind ConfigFile",
            "    Set-DefenseClawPathAcl -Path $policyCache -Kind AdminFile -GatewayServiceSID $gatewaySID\n"
            "    Set-DefenseClawPathAcl -Path $Layout.ConfigPath -Kind ConfigFile",
            1,
        ),
        1,
    )
    assert _ungated_restamps(planted)[0] == {"<unmapped $policyCache>"}

    # The gateway service writes the runtime and IPC folders and owns what it
    # creates there; every other path allows only SYSTEM, Administrators and
    # TrustedInstaller (and Setup's own account as owner).
    gate = _function_text(module, "Assert-DefenseClawStandaloneContentTrusted")
    assert len(re.findall(r"Writer\s+= 'Gateway'", gate)) == 2
    assert "foreach ($path in @($runtimeDirectory, [IO.Path]::Combine($runtimeDirectory, '.env'))) {" in gate
    assert "-Name ManagedIPCDirectory)\n            Writer   = 'Gateway'" in gate
    assert "$writers = @($adminWriters + @($gatewaySID))" in gate
    assert "$ownerSIDs = @($adminWriters + @(Get-DefenseClawCurrentProcessUserSID))" in gate
    assert "-SelfHealKind" not in gate and "Set-DefenseClawPathAcl" not in gate
    bundle = _function_text(module, "Invoke-DefenseClawBundleAclContract")
    assert "foreach ($item in @(Get-DefenseClawBundleAclItems -Layout $Layout)) {" in bundle

    # Repair re-stamps the credential store after the stop: the gate comes first.
    lifecycle = _function_text(module, "Invoke-DefenseClawInstallLikeLifecycle")
    gated = lifecycle.index("Assert-DefenseClawStandaloneContentTrusted")
    assert gated < lifecycle.index("Set-DefenseClawStandaloneSecretsAcls `")


def test_every_restamping_lifecycle_runs_the_content_gate_first() -> None:
    """GAP-0590 review M3: uninstall re-stamped in place after its stop (the
    ACL drift repair) and, without a purge, every retained item
    (Set-DefenseClawPreservedStateAcls); the next install took that state over
    a tombstone, where the gate was skipped because no deployment was active.
    The gate now runs first in every action that re-stamps or consumes
    managed content: the install-like lifecycle (fresh and over a tombstone
    too), the uninstall (Retain or Purge scope), reconcile, and the ACL drift
    repair itself, before its read-only answer."""

    module = read(MODULE).replace("\r\n", "\n")
    lifecycle = _function_text(module, "Invoke-DefenseClawInstallLikeLifecycle")
    gate = lifecycle.index(
        "Assert-DefenseClawStandaloneContentTrusted `\n"
        "            -Layout $Layout `\n"
        "            -GatewayServiceName $GatewayServiceName `\n"
        "            -Except $writtenFresh"
    )
    assert lifecycle.count("Assert-DefenseClawStandaloneContentTrusted") == 2
    # Install writes config.yaml and targets.yaml new from supplied sources;
    # Repair restores them from Setup's approved copies (GAP-0568) and judges
    # them right after that, before anything else reads them.
    written = lifecycle[lifecycle.rindex("$writtenFresh = @()", 0, gate) : gate]
    assert "$writtenFresh = @('ConfigPath', 'ManifestPath')" in written
    assert "if ($Sources.ContainsKey('config')) { $writtenFresh += 'ConfigPath' }" in written
    assert "if ($Sources.ContainsKey('manifest')) { $writtenFresh += 'ManifestPath' }" in written
    recovery = lifecycle.index("Invoke-DefenseClawRepairApprovedPolicyRecovery `")
    repaired = lifecycle.index("Assert-DefenseClawStandaloneContentTrusted -Layout $Layout -GatewayServiceName $GatewayServiceName")
    assert gate < recovery < repaired < lifecycle.index("Assert-DefenseClawCodexMachinePolicyFilePreflight -Layout $Layout")
    assert lifecycle.rindex("if ($Action -eq 'Repair' -and (Test-DefenseClawStandaloneProfile)) {", 0, recovery) > gate
    for consumer in (
        "Remove-DefenseClawUnclaimedInstallPreparationIntent `",
        "Remove-DefenseClawCommittedManagedHooksTeardownJournal `",
        "Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand `",
        "Invoke-DefenseClawCommittedManagedHooksLifecycleRetire `",
        "$snapshot = New-DefenseClawTransaction `",
        "Set-DefenseClawManagedAcls `",
        "Set-DefenseClawStandaloneSecretsAcls `",
    ):
        assert gate < lifecycle.index(consumer), consumer
    assert "$priorDeploymentActive" not in lifecycle[lifecycle.rindex("\n    if (Test-DefenseClawStandaloneProfile) {", 0, gate) : gate]

    uninstall = _function_text(module, "Invoke-DefenseClawUninstallLifecycle")
    gate = uninstall.index("Assert-DefenseClawStandaloneContentTrusted `")
    assert "-Scope $(if ($Purge) { 'Purge' } else { 'Retain' })" in uninstall[gate : gate + 200]
    assert uninstall[uninstall.rindex("\n    if (", 0, gate) :].startswith("\n    if (Test-DefenseClawStandaloneProfile) {")
    for consumer in (
        "Remove-DefenseClawStandaloneInstallTreeReplacementBackups -Layout $Layout",
        "Remove-DefenseClawUninstallStateTreeLinks -Layout $Layout",
        "Invoke-DefenseClawUninstallPrecommitHookCheck `",
        "Invoke-DefenseClawCommittedManagedHooksLifecycleRetire `",
        "$snapshot = New-DefenseClawTransaction `",
        "Set-DefenseClawPreservedStateAcls `",
    ):
        assert gate < uninstall.index(consumer), consumer
    for holder in ("Assert-DefenseClawStandaloneInstallRootNotHeld `", "Assert-DefenseClawStandaloneStateFilesNotInUse `"):
        assert uninstall.index(holder) < gate, holder

    reconcile = _function_text(module, "Invoke-DefenseClawReconcileLifecycle")
    gate = reconcile.index("Assert-DefenseClawStandaloneContentTrusted -Layout $Layout -GatewayServiceName $GatewayServiceName")
    assert gate < reconcile.index("Set-DefenseClawManagedAcls `") < reconcile.index("Set-DefenseClawStandaloneSecretsAcls `")

    repair = _function_text(module, "Repair-DefenseClawDeploymentAclDrift")
    gate = repair.index("Assert-DefenseClawStandaloneContentTrusted -Layout $Layout -GatewayServiceName $GatewayServiceName")
    assert repair.index("Assert-DefenseClawRepairableConfigAcl -Layout $Layout") < gate
    assert gate < repair.index("if ($CheckOnly) {\n        return $true") < repair.index("Set-DefenseClawRetainedRuntimeAcls")

    # Purge skips only what it deletes unread; Retain skips only the install
    # tree the uninstall removes.
    content = _function_text(module, "Assert-DefenseClawStandaloneContentTrusted")
    assert "[ValidateSet('Lifecycle', 'Retain', 'Purge')][string]$Scope = 'Lifecycle'," in content
    assert "if ($Scope -in $row[2] -and $row[0] -notin $Except) {" in content
    for name in ("InstallRoot", "BinDirectory", "LibexecDirectory", "CompilerLibDirectory", "CompilerDirectory"):
        assert f"@('{name}', $folder, @('Lifecycle'))," in content or f"@('{name}', $folder, @('Lifecycle'))\n" in content, name
    assert "@('BrokerStateDirectory', $state, $kept)," in content
    assert "if ($Scope -ne 'Purge') {" in content
    assert content.index("if ($Scope -ne 'Purge') {") < content.index("$runtimeDirectory = ") < content.index(
        "Combine($stateRoot, 'secrets')") < content.index("Get-DefenseClawBundleAclItems -Layout $Layout")
    for name in ("CodexRequirementsOwnershipPath", "CodexRequirementsAclBackupPath", "ManagedHooksTeardownJournalPath", "AuthorizationLedgerPath"):
        assert f"@('{name}', $record, $every)," in content, name


def test_standalone_self_heal_restamps_only_when_every_verdict_is_repairable() -> None:
    """GAP-0603 review M1: the standalone self-heal dropped only the untrusted
    owner and the missing DACL from the verdicts it repairs, so any other
    repairable verdict beside them (a deny entry, SYSTEM's or the gateway's
    rights removed) still ran the re-stamp, which writes the owner and the
    whole DACL, and the second reading found nothing left. On standalone the
    re-stamp now runs only when every verdict is repairable; otherwise the path
    is refused, named, and left as it is. Secure Client is unchanged."""

    module = read(MODULE).replace("\r\n", "\n")
    heal = _function_text(module, "Assert-DefenseClawPathAcl")
    guard = heal.index("if ($standalone -and $repairable.Count -gt 0) {")
    restamp = heal.index("if ($repairable.Count -gt 0) {", guard + 1)
    refusal = heal[guard:restamp]
    assert "$_.Kind -notin $repairableKinds -or" in refusal
    assert "($_.Kind -eq 'Contract' -and (Get-DefenseClawPathAclVerdictSeverity -Verdict $_) -in $untrustedContract)" in refusal
    assert "throw ('refusing to re-stamp a managed path in place" in refusal
    assert refusal.rstrip().endswith('"/ensure again): $([string]$unrepairable[0].Reason)")\n            }\n        }')
    assert restamp < heal.index("Set-DefenseClawPathAcl `")
    # Standalone never counts an Access verdict (an untrusted writer, reader or
    # a lost protected flag) as repairable; Secure Client still does.
    assert "@('Contract', 'Rights', 'Advisory')" in heal
    assert "@('Contract', 'Rights', 'Access')" in heal


def test_constrained_language_guards_run_before_any_dotnet_use() -> None:
    installer = read(INSTALLER).replace("\r\n", "\n")
    module = read(MODULE).replace("\r\n", "\n")
    guard = "if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {"

    installer_guard = installer.index(guard)
    assert installer.index("$ErrorActionPreference = 'Stop'") < installer_guard
    assert installer_guard < installer.index("function ConvertTo-DefenseClawTrustedMachineRoot")
    installer_block = installer[installer_guard : installer.index("function ConvertTo-DefenseClawTrustedMachineRoot")]
    # Constrained language refuses .NET types and [pscustomobject] conversion.
    for forbidden in ("[IO.", "[Environment]", "[pscustomobject]", "::"):
        assert forbidden not in installer_block
    for policy_source in (
        "__PSLockdownPolicy",
        r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Script",
        "Win32_DeviceGuard",
    ):
        assert policy_source in installer_block
    assert 'defenseclaw_prereq check="powershell_language_mode" ' in installer_block
    assert "ConvertTo-Json -Depth 6 -Compress" in installer_block
    assert "exit 1" in installer_block

    module_guard = module.index(guard)
    assert module_guard < module.index("function ConvertTo-DefenseClawTrustedMachineRoot")
    module_block = module[module_guard : module.index("function ConvertTo-DefenseClawTrustedMachineRoot")]
    for forbidden in ("[IO.", "[Environment]", "[pscustomobject]", "::"):
        assert forbidden not in module_block
    assert 'defenseclaw_prereq check="powershell_language_mode" ' in module_block
    assert "throw (" in module_block


def test_add_type_failures_are_classified_by_code_not_text() -> None:
    installer = read(INSTALLER).replace("\r\n", "\n")
    module = read(MODULE).replace("\r\n", "\n")
    for source, classifier, initializer in (
        (installer, "Get-DefenseClawBootstrapAddTypeFailure", "Initialize-DefenseClawBootstrapNativePath"),
        (module, "Get-DefenseClawAddTypeFailure", "Initialize-DefenseClawNativeSecurity"),
    ):
        body = _function_text(source, classifier)
        for code in ("1260", "4551", "225", "112", "ScriptContainedMaliciousContent", "[IO.IOException]"):
            assert code in body
        assert ".Message" not in body
        assert "csc.exe" in body
        init = _function_text(source, initializer)
        assert f"{classifier} -ErrorRecord $_" in init
    import_block = installer[
        installer.index("        Microsoft.PowerShell.Core\\Import-Module `\n            -Name $modulePath") :
    ]
    assert "-Check 'powershell_module_import'" in import_block[:1200]
    assert "Close-DefenseClawBootstrapModuleHandle" in import_block[:1200]


def test_bootstrap_trust_reads_sids_and_keeps_only_the_leaf_strict() -> None:
    installer = read(INSTALLER).replace("\r\n", "\n")
    rule = _function_text(installer, "Assert-DefenseClawBootstrapTrustedPath")
    assert "GetAccessRules(" in rule and "[Security.Principal.SecurityIdentifier]" in rule
    assert "GetOwner([Security.Principal.SecurityIdentifier])" in rule
    assert "ConvertTo-DefenseClawBootstrapSID" not in rule
    assert "Test-DefenseClawBootstrapAdminEquivalentSID" in rule
    assert "if ($Leaf) {\n        throw $findings[0]" in rule
    assert "ancestor drift is advisory" in rule
    for name in ("Assert-DefenseClawBootstrapExternalParentTrust", "Assert-DefenseClawBootstrapModuleTrust"):
        body = _function_text(installer, name)
        assert "ConvertTo-DefenseClawBootstrapSID" not in body
        assert "Assert-DefenseClawBootstrapTrustedPath" in body
        assert "contains a reparse point" in body
    module_trust = _function_text(installer, "Assert-DefenseClawBootstrapModuleTrust")
    assert "[IO.FileShare]::Read" in module_trust
    assert "-LeafWriteLike" in module_trust

    one_shot = _function_text(installer, "Assert-DefenseClawBootstrapOneShotRoot")
    assert "$actualSDDL -cne $expectedSDDL" not in one_shot
    assert "Get-DefenseClawBootstrapOneShotRootDrift" in one_shot
    assert "Set-DefenseClawBootstrapDirectorySecurity" in one_shot
    assert "RequireEmpty" in one_shot

    for rendered in ("$deferredConfigPath, $deferredManifestPath", "$renderedConfigPath, $renderedManifestPath"):
        loop = installer[installer.index(f"foreach ($renderedPath in @({rendered}))") :][:300]
        assert "Set-DefenseClawBootstrapRenderedFileOwner" in loop


def test_native_privilege_reparse_and_service_dacl_contract() -> None:
    module = read(MODULE).replace("\r\n", "\n")
    assert "public static string[] GetTokenPrivilegeNames()" in module
    assert "public static string GetServiceDaclSddl(string name)" in module
    assert "QueryServiceObjectSecurity(" in module
    assert "private static bool IsBenignFileReparseHandle(IntPtr handle, string path)" in module
    assert "const int FileAttributeTagInfo = 9;" in module
    assert module.count("IsBenignFileReparseHandle(") >= 6

    dacl = _function_text(module, "Get-DefenseClawServiceDacl")
    assert dacl.index("GetServiceDaclSddl($Name)") < dacl.index("'sdshow'")
    exact_scope = _function_text(module, "Assert-DefenseClawExactScopeServiceSecurity")
    assert "'sdshow'" not in exact_scope
    assert "Get-DefenseClawServiceDacl -Name $Name" in exact_scope

    lifecycle = _function_text(module, "Invoke-DefenseClawEnterpriseLifecycle")
    elevation = lifecycle.index("        Assert-DefenseClawAdministrator\n        Write-DefenseClawFilePrivilegePrerequisites")
    nuclear = lifecycle.index("        Write-DefenseClawFilePrivilegePrerequisites\n        return Invoke-DefenseClawNuclearUninstall")
    assert nuclear < elevation
    prerequisites = _function_text(module, "Write-DefenseClawFilePrivilegePrerequisites")
    assert "check     = 'token_privilege'" in prerequisites

    logon = _function_text(module, "Start-DefenseClawServiceWithLogonDiagnosis")
    assert "1069" in logon
    assert "check   = 'service_logon_right'" in logon
    assert "add NT SERVICE\\ALL SERVICES to 'Log on as a service'" in logon
    start = module[
        module.index("function Start-DefenseClawTransactionServices") :
        module.index("function Restore-DefenseClawTransactionWithManagedHooksRollback")
    ]
    assert "Start-DefenseClawServiceWithLogonDiagnosis `\n            -Name $GatewayServiceName" in start

    tree = _function_text(module, "Assert-DefenseClawManagedTreeNoReparse")
    assert "Test-DefenseClawBenignFileReparseTag -Item $item" in tree


def test_config_only_ensure_skips_the_restart_barrier_only_after_clean_stops() -> None:
    """cowork-1-0-8 GAP-0044: a config-only ensure (drift:config that the
    services read only at start) runs the upgrade transaction on the installed
    release, and spent the whole 65-second SCM failure-restart barrier with
    nothing to drain. The barrier is skipped only when this process proved, at
    the quiesce, that every service it stopped had run through the window and
    stopped cleanly (exit codes 0, nothing terminated); the disable and stop
    after the wait still run, and every other path keeps the full wait."""
    module = read(MODULE)
    assert "$script:ServiceFailureRestartQuiescenceSeconds = 65\n" in module
    assert "$script:DefenseClawCleanQuiescenceBarrier = $null\n" in module

    ran = _module_function(module, "Test-DefenseClawServiceRanThroughBarrier")
    assert "$null -eq $Identity -or $null -eq $Identity.StartTime" in ran
    assert "-ge $script:ServiceFailureRestartQuiescenceSeconds" in ran

    exit_state = _module_function(module, "Get-DefenseClawServiceExitState")
    assert "@('queryex', $Name)" in exit_state
    assert "WIN32_EXIT_CODE" in exit_state and "SERVICE_EXIT_CODE" in exit_state
    clean = _module_function(module, "Test-DefenseClawServiceStoppedCleanly")
    assert "$exit.state -ceq 'STOPPED'" in clean
    assert "$exit.win32_exit_code -eq 0" in clean
    assert "$exit.service_exit_code -eq 0" in clean

    transaction = _module_function(module, "New-DefenseClawTransaction")
    reset = transaction.index("$script:DefenseClawCleanQuiescenceBarrier = $null")
    identity = transaction.index("Test-DefenseClawServiceRanThroughBarrier -Identity $identity")
    disable = transaction.index("Write-DefenseClawLifecyclePhase -Stage 'transaction quiesce disable services'")
    stopped = transaction.index("Write-DefenseClawLifecyclePhase -Stage 'transaction services stopped'")
    proof = transaction.index("Test-DefenseClawServiceStoppedCleanly -Name $name")
    bound = transaction.index("$script:DefenseClawCleanQuiescenceBarrier =\n")
    assert reset < identity < disable < stopped < proof < bound
    assert "@($script:DefenseClawTerminatedServiceProcesses).Count -eq $terminatedBefore" in transaction

    wait = _module_function(module, "Wait-DefenseClawServiceFailureRestartQuiescence")
    assert "[switch]$CleanStopProven" in wait
    skip = wait.index("if ($CleanStopProven) {")
    sleep = wait.index("Start-Sleep -Milliseconds $milliseconds")
    redisable = wait.index("Set-DefenseClawServiceStartMode -Name $name -StartMode 4")
    restop = wait.index("Stop-DefenseClawService -Name $name")
    assert skip < sleep < redisable < restop

    barrier = _module_function(module, "Test-DefenseClawCleanQuiescenceBarrier")
    assert "ConvertFrom-DefenseClawServiceQuiescenceTimestamp -Value $ServicesQuiescedAt" in barrier
    assert ".Ticks -eq" in barrier

    # Only the in-process install-like activation passes the proof; the
    # rollback and recovery activation keeps the whole barrier.
    assert module.count("-CleanStopProven:") == 1
    install_like = _module_function(module, "Invoke-DefenseClawInstallLikeLifecycle")
    assert (
        "-CleanStopProven:(Test-DefenseClawCleanQuiescenceBarrier `\n"
        "                        -ServicesQuiescedAt $activationQuiescedAt)"
    ) in install_like


def test_install_like_run_keeps_a_byte_identical_release_binary() -> None:
    """cowork-1-0-8 GAP-0044: a config-only ensure runs the upgrade
    transaction on the installed release, and copied every release binary
    again (about 530 MB, rescanned by the antivirus) while the services were
    stopped. The install-like loop now keeps a binary whose installed bytes
    are the source's: both are hashed, a different one is still replaced, and
    the descriptor checks still run on the destination afterwards."""
    module = read(MODULE)
    install = _module_function(module, "Install-DefenseClawSourceDescriptor")
    assert "[switch]$SkipIfContentMatches" in install
    assert "-SkipIfContentMatches:$SkipIfContentMatches" in install
    # The destination is checked after the copy or the kept file alike.
    assert install.index("-SkipIfContentMatches:$SkipIfContentMatches") < install.index(
        "Assert-DefenseClawRegularSource `"
    )

    atomic = _module_function(module, "Install-DefenseClawFileAtomic")
    skip = atomic.index("if ($SkipIfContentMatches -and [IO.File]::Exists($Destination))")
    copy = atomic.index("Copy-Item -LiteralPath $Source -Destination $temporary")
    assert skip < copy
    kept = atomic[skip:copy]
    # Kept only when the source still has its authorized digest and the
    # destination has the same bytes.
    assert "throw \"source changed while checking managed artifact: $Source\"" in kept
    assert "$sourceHash,\n                $destinationHash" in kept

    lifecycle = _module_function(module, "Invoke-DefenseClawInstallLikeLifecycle")
    release = lifecycle.index("$_ -notin $deferredPolicySources -and $_ -ne 'provider_library'")
    policy = lifecycle.index("foreach ($name in @($deferredPolicySources")
    binaries = lifecycle[release:policy]
    assert "-Destination $destination `\n                -SkipIfContentMatches\n" in binaries
    # The config and manifest keep their unconditional install.
    assert "-SkipIfContentMatches" not in lifecycle[policy : policy + 600]
    # The transaction snapshot is taken before, as before: a rollback still
    # restores any binary the run replaced.
    assert lifecycle.index("$snapshot = New-DefenseClawTransaction") < release


def test_a_pinned_staged_source_is_admitted_once_per_lifecycle_run() -> None:
    """cowork-1-0-8 GAP-0044: every lifecycle source was hashed and its
    signature verified again before and after lifecycle.lock and before each
    copy, about 530 MB each time. A source Setup staged is now pinned (read
    handle, no write or delete sharing) before its digest and signature are
    read; a later check of the same source reuses them only while that pin
    holds the same file under the same trust policy, after the path,
    ancestry and ACL checks. Anything else reads the file again."""
    module = read(MODULE)
    eligible = _module_function(module, "Test-DefenseClawSourcePinEligible")
    assert "if (-not (Test-DefenseClawStandaloneProfile)) {\n        return $false" in eligible
    assert "'DefenseClaw-Enterprise-Setup-'" in eligible
    assert "$programData + '\\Cisco'" in eligible

    pin = _module_function(module, "Open-DefenseClawSourcePin")
    assert "[IO.FileAccess]::Read,\n            [IO.FileShare]::Read\n" in pin
    assert "FileShare]::ReadWrite" not in pin and "FileShare]::Delete" not in pin
    assert "identity = (Get-DefenseClawFileIdentity -Path $Path)" in pin

    describe = _module_function(module, "Get-DefenseClawSourceDescriptor")
    opened = describe.index("$pin = Open-DefenseClawSourcePin -Path $full")
    assert opened < describe.index("Assert-DefenseClawRegularSource `")
    assert opened < describe.index("Get-FileHash -LiteralPath $full")
    assert opened < describe.index("Get-AuthenticodeSignature `")
    # Recorded only after a successful admission; a refused one lets go.
    assert describe.index("policy = (Get-DefenseClawSourcePinTrustPolicy)") > describe.index(
        "VersionInfo.FileVersion"
    )
    assert "catch {\n        if ($null -ne $pin) {\n            $pin.stream.Dispose()\n        }\n        throw" in describe

    reuse = _module_function(module, "Get-DefenseClawPinnedSourceDescriptor")
    for condition in (
        "-not $pin.stream.CanRead",
        "[string]$pin.policy -cne (Get-DefenseClawSourcePinTrustPolicy)",
        "[bool]$cached.authenticode -ne [bool]$Source.authenticode",
        "[bool]$cached.allow_unsigned -ne [bool]$Source.allow_unsigned",
    ):
        assert condition in reuse
    assert reuse.index("Assert-DefenseClawTrustedSource") < reuse.index("return $cached.Clone()")
    assert "(Get-DefenseClawFileIdentity -Path $full) -cne [string]$pin.identity" in reuse

    policy = _module_function(module, "Get-DefenseClawSourcePinTrustPolicy")
    for part in ("DefenseClawTrustMode", "DefenseClawAllowedSignerSHA256", "DefenseClawPinnedPayloadSHA256"):
        assert part in policy

    current = _module_function(module, "Assert-DefenseClawSourceDescriptorCurrent")
    cached = current.index("$current = Get-DefenseClawPinnedSourceDescriptor -Source $Source")
    fallback = current.index("$current = Get-DefenseClawSourceDescriptor `")
    assert cached < fallback < current.index("foreach ($field in @('path', 'label', 'sha256'))")


def test_module_smoke_removes_the_certification_folders_it_creates() -> None:
    # GAP-0780: the elevated lifecycle-lock block makes smoke roots under
    # <root>\Cisco\Cisco Secure Client\DefenseClaw-Cert\<token>; its own cleanup
    # removes only the token folder, so the parents it created stayed on the host.
    # The smoke records which parents already exist, then removes only the empty
    # ones it created, in a finally that wraps the block. Nothing else may be
    # removed: no -Recurse, no pre-existing folder, no reparse point.
    smoke = read(MODULE_SMOKE)

    record = smoke.index("$certificationLayoutParents = @(")
    function = smoke.index("function Remove-CertificationLayoutParentsCreatedBySmoke {")
    block = smoke.index("if ($elevated) {")
    assert record < function < block
    recorded = smoke[record:function]
    for segment in ("'Cisco'", "'Cisco Secure Client'", "'DefenseClaw-Cert'"):
        assert segment in recorded
    assert "Existed = (Test-Path -LiteralPath $parent)" in recorded
    assert "$programFiles, $programData" in recorded

    cleanup = smoke[function : smoke.index("$tokens = $null", function)]
    assert "if ($entry.Existed) {" in cleanup
    assert "[IO.FileAttributes]::ReparsePoint" in cleanup
    assert "Select-Object -First 1" in cleanup
    # An atomic delete of an empty folder: no prompt, no recursion.
    assert "[IO.Directory]::Delete($entry.Path, $false)" in cleanup
    assert "Remove-Item" not in cleanup
    assert "-Recurse" not in cleanup
    # A created parent that is left because it is not empty is named once.
    assert "left the folder this smoke created because it is not empty: $($entry.Path)" in cleanup
    assert "$coveredByChild" in cleanup
    assert "$index--" in cleanup  # deepest parent first

    assert "try {\n    if ($elevated) {" in smoke
    final = "finally {\n    Remove-CertificationLayoutParentsCreatedBySmoke\n}\n"
    assert final in smoke
    # The finally closes the block that holds the lock test and its else branch.
    assert smoke.index("Remove-DefenseClawManagedTree", block) < smoke.index(final)


def test_hardening_harness_removes_the_cisco_folders_it_creates() -> None:
    # GAP-0780: the harness recorded and removed the DefenseClaw-Cert parents but
    # not the Cisco Secure Client and Cisco folders above them, so a host without
    # Secure Client kept an empty "Cisco Secure Client" after a run. Both roots are
    # recorded before anything is created, deepest first, and the cleanup accepts
    # only those paths and removes them only when empty, real and not pre-existing.
    harness = read(HARNESS)

    names = (
        "$script:ProgramFilesSecureClientRoot",
        "$script:ProgramFilesCiscoRoot",
        "$script:ProgramDataSecureClientRoot",
        "$script:ProgramDataCiscoRoot",
    )
    for name in names:
        assert f"{name} = ConvertTo-CanonicalPath (" in harness
    assert "Join-Path $script:KnownProgramFiles 'Cisco\\Cisco Secure Client'" in harness
    assert "Join-Path $script:KnownProgramData 'Cisco\\Cisco Secure Client'" in harness
    assert "Join-Path $script:KnownProgramFiles 'Cisco'\n" in harness
    assert "Join-Path $script:KnownProgramData 'Cisco'\n" in harness

    record = harness.index("$script:CertificationParentRootPaths = @(\n    $script:")
    recorded = harness[record : harness.index("$script:FixtureRoot =", record)]
    assert "foreach ($parentRoot in $script:CertificationParentRootPaths)" in recorded
    assert "existed_before = Test-Path -LiteralPath $parentRoot" in recorded
    positions = [
        recorded.index(name)
        for name in (
            "$script:ProgramFilesCertificationRoot",
            "$script:ProgramDataWorkRoot",
            *names,
        )
    ]
    assert positions == sorted(positions)  # each parent is listed after its children
    assert recorded.index(names[2]) < recorded.index(names[3])
    assert recorded.index(names[0]) < recorded.index(names[1])

    start = harness.index("function Remove-EmptyCertificationParentRoot(")
    cleanup = harness[start : harness.index("function Invoke-CertificationFailureInjection", start)]
    # The allowlist is the shared list, not a second copy of the eight paths.
    assert "@($script:CertificationParentRootPaths)" in cleanup
    for name in names:
        assert name not in cleanup
    assert "if ([bool]$State.existed_before" in cleanup
    assert "[IO.FileAttributes]::ReparsePoint" in cleanup
    assert "$children.Count -ne 0" in cleanup
    assert "-Recurse" not in cleanup


# GAP-0900 / REVIEW-g900 S7: the inserted lines of the Secure Client-shared rollback
# functions. Each entry is (the two lines before, the inserted block, the line after) as
# they sit in the module; taking the blocks out leaves the text rel had, line for line
# (checked once against rel in the round, evidence sc-text-diff-vs-rel109.txt).
_SC_SHARED_INSERTS = {
    'Assert-DefenseClawEnterpriseDeployment': [
        (
            '    Assert-DefenseClawMetadataIdentity `\n        -Metadata $metadata `\n        -GatewayServiceName $GatewayServiceName `\n        -GuardianServiceName $GuardianServiceName\n',
            "    if ($RollbackRestore -and (Test-DefenseClawStandaloneProfile) -and\n        (Test-DefenseClawRebuiltDeploymentRecord -Metadata $metadata)) {\n        # rel-1-0-6:GAP-0994: the transaction opened over a rebuilt record and\n        # failed. Its rollback puts that record back, and the record cannot\n        # carry what the full assertion below asks for; the next repair writes\n        # the full one. The services start again and the run ends with its error.\n        Assert-DefenseClawRebuiltRecordArtifacts -Layout $Layout -Metadata $metadata\n        Write-DefenseClawLifecyclePhase -Stage 'rollback restored the rebuilt deployment record; the next repair writes the full one'\n        return\n    }\n",
            '    if (Test-DefenseClawStandaloneProfile) {\n        # Verify also serves an installed-host ensure that would otherwise\n',
        ),
        (
            '        [switch]$PendingTransaction,\n        [switch]$ServicingTransaction,\n',
            '        # GAP-0900: set only by the rollback of a transaction (Restore). A link on\n        # the Codex folder is then named and not read through; every forward path\n        # (static validation, the install commit) still fails closed on it.\n        [switch]$RollbackRestore,\n',
            "        [string]$TransitionHookSHA256 = '',\n",
        ),
        (
            '    }\n    $codexRequirementsDeferred = $false\n',
            '    # GAP-0900: a rollback (-RollbackRestore) that finds a link on the Codex folder\n    # does not read the Codex machine policy through it. The checks below keep their\n    # lines; they are skipped by the braces around them.\n    $codexFolderLink = \'\'\n    if ($RollbackRestore -and $codexTargetEnabled) {\n        $codexFolderLink = Get-DefenseClawVendorMachineFolderLink `\n            -Directory ([string]$Layout.CodexMachinePolicyDirectory) `\n            -Tolerant\n    }\n    if ($codexFolderLink -ne \'\') {\n        Write-DefenseClawResilienceEvent -Marker defenseclaw_degraded -Fields @{\n            subsystem = \'rollback\'\n            path      = $codexFolderLink\n            reason    = "a link sits on the Codex machine-policy folder; its policy was not checked and Codex is not protected until the link is removed with: cmd /c rmdir `"$codexFolderLink`""\n        }\n    }\n    if ($codexFolderLink -eq \'\') {\n',
            '    if ($codexTargetEnabled) {\n',
        ),
        (
            '            }\n        }\n',
            '    }\n',
            '    }\n',
        ),
        (
            '    }\n    Assert-DefenseClawInstalledConfig -Layout $Layout -GatewayServiceName $GatewayServiceName\n',
            "    if ($codexFolderLink -eq '') {\n",
            '    if ($RepairRecoveredCodexRequirements -and $ServicingTransaction -and\n',
        ),
        (
            "            -GatewayServiceName $GatewayServiceName `\n            -Action $(if ($codexTargetEnabled) { 'verify' } else { 'inspect' }))\n",
            '    }\n',
            '    }\n',
        ),
    ],
    'Restore-DefenseClawTransaction': [
        (
            '        }\n        if ($isSharedCodexFile) {\n',
            '            # GAP-0900: a link that appeared on the Codex folder after the\n            # transaction opened. Nothing is written through it and the rollback\n            # goes on, so the services come back; the link stays for the\n            # administrator, who removes only the link. Standalone only.\n            $restoreCodexLink = Get-DefenseClawVendorMachineFolderLink `\n                -Directory ([string]$Layout.CodexMachinePolicyDirectory) `\n                -Tolerant\n            if ($restoreCodexLink -ne \'\') {\n                Write-DefenseClawResilienceEvent -Marker defenseclaw_degraded -Fields @{\n                    subsystem = \'rollback\'\n                    path      = $restoreCodexLink\n                    reason    = "a link sits on the Codex machine-policy folder; the rollback did not write through it. As an administrator, remove only the link with: cmd /c rmdir `"$restoreCodexLink`"; the next repair or ensure then finishes the work"\n                }\n                continue\n            }\n',
            '            $policyDirectoryExists = Microsoft.PowerShell.Management\\Test-Path `\n',
        ),
        (
            '        # The writer copy of the Codex state is back; the hook copy the\n        # counter names must say the same (GAP-0650).\n',
            '        # GAP-0900: the hook copy of the Codex state lives in the Codex machine-policy\n        # folder; with a link on its path the copy is not written through it (nothing\n        # ever writes through a link), the link is named, and the rollback goes on.\n        $stateCopyLink = Get-DefenseClawVendorMachineFolderLink `\n            -Directory ([string]$Layout.CodexMachinePolicyDirectory) `\n            -Tolerant\n        if ($stateCopyLink -ne \'\') {\n            Write-DefenseClawResilienceEvent -Marker defenseclaw_degraded -Fields @{\n                subsystem = \'rollback\'\n                path      = $stateCopyLink\n                reason    = "a link sits on the Codex machine-policy folder; the restored Codex state was not written for the hook through it. As an administrator, remove only the link with: cmd /c rmdir `"$stateCopyLink`"; the next repair or ensure then finishes the work"\n            }\n        }\n        if ($stateCopyLink -eq \'\') {\n',
            '        try {\n',
        ),
        (
            '                reason = "the restored Codex managed runtime state could not be written for the hook: $($_.Exception.Message); the next Codex transaction writes it"\n            }\n',
            '        }\n',
            '        }\n',
        ),
        (
            '                -GatewayServiceName ([string]$snapshot.gateway_service)\n        }\n',
            "        # GAP-0900: nothing is stamped through a link on the Codex folder either.\n        $restoreCodexLinked = (Get-DefenseClawVendorMachineFolderLink `\n                -Directory ([string]$Layout.CodexMachinePolicyDirectory) `\n                -Tolerant) -ne ''\n",
            '        Set-DefenseClawManagedAcls `\n',
        ),
        (
            '            -Layout $Layout `\n            -GatewayServiceName ([string]$snapshot.gateway_service) `\n',
            '            -SkipCodexMachineState:$restoreCodexLinked `\n',
            '            -AllowTransactionRecordedBrokerAbsence:(\n',
        ),
    ],
    'Assert-DefenseClawRestoredTransactionReadyForActivation': [
        (
            '        -GuardianServiceName ([string]$Snapshot.guardian_service) `\n        -ServicingTransaction `\n',
            '        -RollbackRestore `\n',
            "        -TransitionHookSHA256 (Get-DefenseClawEarlyHookField -Record $Snapshot -Name 'early_hook_guard_sha256') `\n",
        ),
    ],
}


def test_secure_client_shared_rollback_functions_only_gain_dead_gated_lines() -> None:
    """The three rollback functions Secure Client shares gain inserted lines only,
    and every inserted line is gated by the standalone-only link probe: with the
    blocks taken out no reference to the probe, the rollback switch or the link
    variables is left, and a Secure Client profile never gets a link from the probe,
    so every inserted branch is dead there and the path is rel's."""
    module = read(MODULE)
    probe = _psm1_function(module, "Get-DefenseClawVendorMachineFolderLink")
    assert "if (-not (Test-DefenseClawStandaloneProfile)) {" in probe
    assert probe.index("Test-DefenseClawStandaloneProfile") < probe.index("Get-DefenseClawLinkCheckAttributes")
    for name, blocks in _SC_SHARED_INSERTS.items():
        body = _psm1_function(module, name)
        for before, block, after in blocks:
            anchored = before + block + after
            assert body.count(anchored) == 1, (name, block[:60])
            body = body.replace(anchored, before + after, 1)
        for token in (
            "Get-DefenseClawVendorMachineFolderLink",
            "RollbackRestore",
            "restoreCodexLink",
            "codexFolderLink",
            "GAP-0900",
        ):
            assert token not in body, (name, token)
    # The only condition on any inserted branch is the probe, the switch only
    # Restore's readiness check passes, and the Codex target flag.
    assert module.count("-RollbackRestore `\n") == 1
    assert module.count("if ($RollbackRestore -and $codexTargetEnabled) {") == 1


def _powershell_approved_verbs() -> set[str]:
    """The approved verbs PowerShell itself lists (Get-Verb), when a PowerShell is on
    the machine; the Windows CI runners have one."""
    import shutil
    import subprocess

    for exe in ("pwsh", "powershell"):
        found = shutil.which(exe)
        if not found:
            continue
        try:
            out = subprocess.run(
                [found, "-NoProfile", "-NonInteractive", "-Command", "(Get-Verb).Verb"],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        verbs = {line.strip() for line in out.splitlines() if line.strip().isalpha()}
        if len(verbs) > 50:
            return verbs
    return set()


def test_every_defenseclaw_function_a_script_or_go_file_calls_is_defined() -> None:
    """GAP-0900: a function that is renamed while another change still calls its old
    name merges without a textual conflict and then fails at run time (the Windows
    uninstall answered 1603 for the old Codex link check). Every
    <Verb>-DefenseClaw<Noun> name that the module, a Windows script or a Go file
    (tests excluded) mentions must be a function some module or script of the
    Windows packaging defines. The verbs are the approved verbs Get-Verb lists plus
    the verbs of the functions the packaging defines (custom ones included), never
    a hand list."""
    import re

    sources = [
        path
        for root in (ROOT / "packaging" / "windows", ROOT / "packaging" / "mdm" / "windows")
        for path in root.rglob("*")
        if path.suffix in {".ps1", ".psm1"} and "tests" not in path.parts
    ]
    defined: set[str] = set()
    for path in sources:
        text = path.read_text(encoding="utf-8", errors="replace")
        defined |= set(re.findall(r"(?mi)^\s*function\s+([A-Za-z]+-DefenseClaw[A-Za-z0-9]*)", text))
        defined.add(path.stem)  # a kit script is invoked by its name
    assert len(defined) > 500
    assert "Get-DefenseClawVendorMachineFolderLink" in defined
    verbs = {name.split("-")[0] for name in defined if re.match(r"[A-Z][A-Za-z]*-DefenseClaw", name)} | _powershell_approved_verbs()
    for custom in ("Open", "Close", "Enter", "Exit", "Recover", "Hold", "Ensure", "Request"):
        assert custom in verbs or not _powershell_approved_verbs(), custom
    alternation = "|".join(sorted(map(re.escape, verbs), key=len, reverse=True))
    # A name followed by a dot, a dash or a slash is a file or path
    # (Invoke-DefenseClawEnterprise.ps1) or a wrapped name in a comment, not a call.
    pattern = re.compile(rf"\b(?:{alternation})-DefenseClaw[A-Za-z0-9]*(?![A-Za-z0-9.\\/-])")
    unknown: dict[str, set[str]] = {}
    scanned = list(sources)
    for root in (ROOT / "internal", ROOT / "cmd"):
        scanned += [
            path
            for path in root.rglob("*.go")
            if not path.name.endswith("_test.go") and "testdata" not in path.parts
        ]
    mentions = 0
    seen: set[str] = set()
    for path in scanned:
        for name in pattern.findall(path.read_text(encoding="utf-8", errors="replace")):
            mentions += 1
            seen.add(name)
            if name not in defined:
                unknown.setdefault(name, set()).add(str(path.relative_to(ROOT)))
    assert not unknown, unknown
    # The scan has to find the calls: a pattern that stops matching must not pass.
    assert mentions >= 4000, mentions
    assert len(seen) >= 700, len(seen)
    assert "Get-DefenseClawCodexMachineFolderLink" not in defined


def test_the_rollback_link_probes_are_tolerant_and_the_start_of_run_ones_are_not() -> None:
    """GAP-0900 review: an error other than not-found on the link walk fails the start
    of a run closed, but inside a rollback it is treated like a found link (the path is
    skipped, with a degraded event naming the path and the error) so the services come
    back."""
    module = read(MODULE)
    walk = _psm1_function(module, "Get-DefenseClawVendorMachineFolderLink")
    assert "[switch]$Tolerant" in walk
    assert "if (-not $Tolerant) {\n                throw\n            }" in walk
    assert "subsystem = 'rollback'" in walk and "return $current" in walk
    assert "Get-DefenseClawLinkCheckAttributes -Path $current" in walk
    # The three probes inside the rollback pass -Tolerant; no other caller does.
    restore = _psm1_function(module, "Restore-DefenseClawTransaction")
    assert restore.count("-Tolerant") == 3
    assert _psm1_function(module, "Assert-DefenseClawEnterpriseDeployment").count("-Tolerant") == 1
    assert module.count("-Tolerant") == 4  # the four rollback call sites


def test_the_restored_codex_state_is_not_written_for_the_hook_through_a_link() -> None:
    """GAP-0900 (delta-r3 S-E): Restore writes the hook copy of the Codex state into the
    Codex machine-policy folder (Sync-DefenseClawCodexManagedHooksStateCopy). With a link
    on that path nothing is written through it: the link is named in a degraded event
    with the rmdir fix and the rollback goes on."""
    module = read(MODULE)
    restore = _psm1_function(module, "Restore-DefenseClawTransaction")
    sync = restore.index("Sync-DefenseClawCodexManagedHooksStateCopy `\n")
    probe = restore.rindex("$stateCopyLink = Get-DefenseClawVendorMachineFolderLink", 0, sync)
    guard = restore.index("if ($stateCopyLink -eq '') {", probe)
    assert probe < guard < sync
    event = restore[probe:guard]
    assert "-Tolerant" in event
    assert "Write-DefenseClawResilienceEvent -Marker defenseclaw_degraded" in event
    assert 'cmd /c rmdir `\"$stateCopyLink`\"' in event
    assert restore.count("Sync-DefenseClawCodexManagedHooksStateCopy") == 1
    smoke = read(ROOT / "packaging" / "windows" / "tests" / "enterprise-standalone-recovery-gateway-smoke.ps1")
    assert "StateCopy = 'link'" in smoke and "state-copy-sync" in smoke
