# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$windowsDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$modulePath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1'))
$token = ([Guid]::NewGuid().ToString('N')).Substring(0, 10)
$installRoot = Join-Path $programFiles 'Cisco\Cisco Secure Client\DefenseClaw'
$stateRoot = Join-Path $programData 'Cisco\Cisco Secure Client\DefenseClaw'
$gatewayService = 'DefenseClawGateway'
$guardianService = 'DefenseClawHookGuardian'
$customInstallRoot = Join-Path `
    $programFiles `
    "Cisco\Cisco Secure Client\DefenseClaw-ModuleSmoke-$token\DefenseClaw"
$customStateRoot = Join-Path `
    $programData `
    "Cisco\Cisco Secure Client\DefenseClaw-ModuleSmoke-$token\DefenseClaw"
$customGatewayService = "DefenseClawGatewaySmoke_$token"
$customGuardianService = "DefenseClawGuardianSmoke_$token"
$codexMachinePolicyDirectory = Join-Path $programData 'OpenAI\Codex'
$codexParentExistedBeforeStatus = Test-Path -LiteralPath $codexMachinePolicyDirectory
$installRootExistedBeforeStatus = Test-Path -LiteralPath $installRoot
$stateRootExistedBeforeStatus = Test-Path -LiteralPath $stateRoot

$tokens = $null
$parseErrors = $null
$moduleAst = [Management.Automation.Language.Parser]::ParseFile(
    $modulePath,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -ne 0) {
    throw "module parser errors: $($parseErrors.Message -join '; ')"
}
$ambientSensitiveCommands = @(
    'Add-Type', 'ConvertFrom-Json', 'ConvertTo-Json', 'Copy-Item',
    'Export-ModuleMember', 'ForEach-Object', 'Get-Acl',
    'Get-AuthenticodeSignature', 'Get-ChildItem', 'Get-Content',
    'Get-FileHash', 'Get-Item', 'Get-ItemProperty',
    'Get-ItemPropertyValue', 'Get-Service', 'Join-Path', 'Move-Item',
    'New-Item', 'New-ItemProperty', 'Out-Null', 'Out-String',
    'Remove-Item', 'Select-Object', 'Set-Acl', 'Set-Content',
    'Set-StrictMode', 'Sort-Object', 'Start-Service', 'Start-Sleep',
    'Stop-Service', 'Test-Path', 'Where-Object'
)
$unqualifiedCommands = @(
    $moduleAst.FindAll(
        {
            param($node)
            $node -is [Management.Automation.Language.CommandAst]
        },
        $true
    ) |
        ForEach-Object { $_.GetCommandName() } |
        Where-Object { $_ -in $ambientSensitiveCommands } |
        Sort-Object -Unique
)
if ($unqualifiedCommands.Count -ne 0) {
    throw "enterprise module leaves ambient cmdlets unqualified: $($unqualifiedCommands -join ', ')"
}

[void](Microsoft.PowerShell.Utility\Add-Type -TypeDefinition @'
using System;
namespace DefenseClaw.Windows
{
    public static class NativeSecurity
    {
        public static uint GetDriveType(string root)
        {
            throw new InvalidOperationException("preloaded fixed native helper was used");
        }
        public static string GetFileSystem(string root)
        {
            throw new InvalidOperationException("preloaded fixed native helper was used");
        }
        public static string QueryDriveTarget(string drive)
        {
            throw new InvalidOperationException("preloaded fixed native helper was used");
        }
    }
}
'@ -Language CSharp -ErrorAction Stop)

# A module has its own script scope but can still see caller-global functions.
# The enterprise module must bind privileged primitives to built-in cmdlets.
function global:Get-Service {
    throw 'ambient Get-Service function was invoked by the enterprise module'
}

Microsoft.PowerShell.Core\Import-Module -Name $modulePath -Force
$module = Get-Module DefenseClawEnterprise
if ($null -eq $module) {
    throw 'DefenseClawEnterprise module was not imported'
}
$status = Invoke-DefenseClawEnterpriseLifecycle `
    -Action Status `
    -InstallRoot $installRoot `
    -StateRoot $stateRoot `
    -GatewayServiceName $gatewayService `
    -GuardianServiceName $guardianService
if (-not [bool]$status.ok -or
    (-not $stateRootExistedBeforeStatus -and [bool]$status.installed)) {
    throw 'read-only production Status did not report a consistent deployment'
}
if ((Test-Path -LiteralPath $installRoot) -ne $installRootExistedBeforeStatus -or
    (Test-Path -LiteralPath $stateRoot) -ne $stateRootExistedBeforeStatus) {
    throw 'read-only Status created a managed root'
}
if ((Test-Path -LiteralPath $codexMachinePolicyDirectory) -ne $codexParentExistedBeforeStatus) {
    throw 'read-only Status changed the Codex machine-policy parent'
}
foreach ($signedOverride in @(
    [pscustomobject]@{
        name = 'custom root'
        install = $customInstallRoot
        state = $stateRoot
        gateway = $gatewayService
        guardian = $guardianService
        expected = 'requires exact production roots'
    },
    [pscustomobject]@{
        # Exercise the custom StateRoot rejection path. Without this case
        # $customStateRoot was assigned but never read, and signed mode was
        # never actually tested against a non-production StateRoot — yet
        # signed_custom_roots_rejected in the report reads $true regardless.
        name = 'custom state root'
        install = $installRoot
        state = $customStateRoot
        gateway = $gatewayService
        guardian = $guardianService
        expected = 'requires exact production roots'
    },
    [pscustomobject]@{
        name = 'custom service names'
        install = $installRoot
        state = $stateRoot
        gateway = $customGatewayService
        guardian = $customGuardianService
        expected = 'requires exact production service names'
    }
)) {
    try {
        Invoke-DefenseClawEnterpriseLifecycle `
            -Action Status `
            -InstallRoot ([string]$signedOverride.install) `
            -StateRoot ([string]$signedOverride.state) `
            -GatewayServiceName ([string]$signedOverride.gateway) `
            -GuardianServiceName ([string]$signedOverride.guardian) |
                Out-Null
        throw "signed mode accepted $($signedOverride.name)"
    }
    catch {
        if ($_.Exception.Message -notmatch [regex]::Escape(
            [string]$signedOverride.expected
        )) {
            throw
        }
    }
}

$certificationCodexHome = Join-Path (
    [IO.Path]::GetTempPath()
) ".codex-defenseclaw-cert-$token"
$wrongCertificationCodexHome = Join-Path (
    [IO.Path]::GetTempPath()
) ".codex-defenseclaw-cert-$token-wrong"
$certificationInstallRoot = Join-Path `
    $programFiles `
    "Cisco\Cisco Secure Client\DefenseClaw-Cert\$token"
$certificationStateRoot = Join-Path `
    $programData `
    "Cisco\Cisco Secure Client\DefenseClaw-Cert\$token"
try {
    $missingCertificationStatus = Invoke-DefenseClawEnterpriseLifecycle `
        -Action Status `
        -InstallRoot $certificationInstallRoot `
        -StateRoot $certificationStateRoot `
        -GatewayServiceName "DefenseClawCertGateway_$token" `
        -GuardianServiceName "DefenseClawCertGuardian_$token" `
        -CertificationCodexHome $certificationCodexHome `
        -AllowUnsigned
    if (-not [bool]$missingCertificationStatus.ok -or
        [bool]$missingCertificationStatus.installed -or
        (Test-Path -LiteralPath $certificationCodexHome)) {
        throw 'unsigned pre-install Status did not preserve its absent certification CODEX_HOME'
    }
    [void](New-Item -ItemType Directory -Path $certificationCodexHome)
    [void](New-Item -ItemType Directory -Path $wrongCertificationCodexHome)
    $certificationStatus = Invoke-DefenseClawEnterpriseLifecycle `
        -Action Status `
        -InstallRoot $certificationInstallRoot `
        -StateRoot $certificationStateRoot `
        -GatewayServiceName "DefenseClawCertGateway_$token" `
        -GuardianServiceName "DefenseClawCertGuardian_$token" `
        -CertificationCodexHome $certificationCodexHome `
        -AllowUnsigned
    if (-not [bool]$certificationStatus.ok -or [bool]$certificationStatus.installed) {
        throw 'certification Status did not accept its exact isolated CODEX_HOME'
    }
    try {
        Invoke-DefenseClawEnterpriseLifecycle `
            -Action Status `
            -InstallRoot $installRoot `
            -StateRoot $stateRoot `
            -GatewayServiceName $gatewayService `
            -GuardianServiceName $guardianService `
            -CertificationCodexHome $certificationCodexHome | Out-Null
        throw 'production service names accepted certification CODEX_HOME'
    }
    catch {
        if ($_.Exception.Message -notmatch 'exact disposable DefenseClaw certification service names') {
            throw
        }
    }
    $otherToken = ([Guid]::NewGuid().ToString('N')).Substring(0, 10)
    while ($otherToken -ceq $token) {
        $otherToken = ([Guid]::NewGuid().ToString('N')).Substring(0, 10)
    }
    try {
        Invoke-DefenseClawEnterpriseLifecycle `
            -Action Status `
            -InstallRoot $installRoot `
            -StateRoot $stateRoot `
            -GatewayServiceName "DefenseClawCertGateway_$token" `
            -GuardianServiceName "DefenseClawCertGuardian_$otherToken" `
            -CertificationCodexHome $certificationCodexHome | Out-Null
        throw 'mismatched certification service run identifiers were accepted'
    }
    catch {
        if ($_.Exception.Message -notmatch 'same run identifier') {
            throw
        }
    }
    try {
        Invoke-DefenseClawEnterpriseLifecycle `
            -Action Status `
            -InstallRoot $installRoot `
            -StateRoot $stateRoot `
            -GatewayServiceName "DefenseClawCertGateway_$token" `
            -GuardianServiceName "DefenseClawCertGuardian_$token" `
            -CertificationCodexHome $wrongCertificationCodexHome | Out-Null
        throw 'wrong certification CODEX_HOME basename was accepted'
    }
    catch {
        if ($_.Exception.Message -notmatch 'basename must be exactly') {
            throw
        }
    }
}
finally {
    if (Test-Path -LiteralPath $certificationCodexHome) {
        # These are directories created with New-Item -ItemType Directory.
        # Without -Recurse, Remove-Item -Force refuses non-empty directories,
        # and a lifecycle write into the certification CODEX_HOME would fail
        # cleanup inside this $ErrorActionPreference='Stop' finally — masking
        # the actual test failure with a cleanup error.
        Remove-Item -LiteralPath $certificationCodexHome -Force -Recurse
    }
    if (Test-Path -LiteralPath $wrongCertificationCodexHome) {
        Remove-Item -LiteralPath $wrongCertificationCodexHome -Force -Recurse
    }
}

if (-not ('DefenseClaw.Windows.Tests.CommandLine' -as [type])) {
    [void](Microsoft.PowerShell.Utility\Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace DefenseClaw.Windows.Tests
{
    public static class CommandLine
    {
        [DllImport(
            "shell32.dll",
            CharSet = CharSet.Unicode,
            ExactSpelling = true,
            SetLastError = true)]
        private static extern IntPtr CommandLineToArgvW(
            string commandLine,
            out int argumentCount);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);

        public static string[] Parse(string commandLine)
        {
            int count;
            IntPtr values = CommandLineToArgvW(commandLine, out count);
            if (values == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            try
            {
                string[] result = new string[count];
                for (int index = 0; index < count; index++)
                {
                    IntPtr value = Marshal.ReadIntPtr(values, index * IntPtr.Size);
                    result[index] = Marshal.PtrToStringUni(value);
                }
                return result;
            }
            finally
            {
                LocalFree(values);
            }
        }
    }
}
'@ -Language CSharp -ErrorAction Stop)
}

& $module {
    $argumentFixture = [string[]]@(
        'config',
        'DefenseClawGateway',
        'binPath=',
        '"C:\Program Files\Cisco\Cisco Secure Client\DefenseClaw\defenseclaw-gateway.exe" enterprise hooks watch --manifest "C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw\targets.yaml" --interval 1m',
        'trailing-slash\',
        ''
    )
    $encodedFixture = ConvertTo-DefenseClawWindowsCommandLine `
        -Arguments $argumentFixture
    $decodedFixture = [DefenseClaw.Windows.Tests.CommandLine]::Parse(
        'fixture.exe ' + $encodedFixture
    )
    if ($decodedFixture.Count -ne $argumentFixture.Count + 1) {
        throw 'native command-line encoder changed the argument count'
    }
    for ($index = 0; $index -lt $argumentFixture.Count; $index++) {
        if (-not [string]::Equals(
            [string]$decodedFixture[$index + 1],
            [string]$argumentFixture[$index],
            [StringComparison]::Ordinal
        )) {
            throw "native command-line encoder changed argv[$index]"
        }
    }
    foreach ($invalidFixture in @(
        [pscustomobject]@{
            name = 'null'
            arguments = [object[]]@('safe', $null)
        },
        [pscustomobject]@{
            name = 'NUL'
            arguments = [object[]]@('safe', ('unsafe' + [char]0))
        }
    )) {
        $rejected = $false
        try {
            [void](ConvertTo-DefenseClawWindowsCommandLine `
                -Arguments $invalidFixture.arguments)
        }
        catch {
            $rejected = $true
        }
        if (-not $rejected) {
            throw "native command-line encoder accepted a $($invalidFixture.name) argument"
        }
    }

    $engine = Microsoft.PowerShell.Management\Join-Path `
        $script:System32 `
        'WindowsPowerShell\v1.0\powershell.exe'
    $success = Invoke-DefenseClawProcess `
        -File $engine `
        -Arguments @(
            '-NoLogo',
            '-NoProfile',
            '-NonInteractive',
            '-Command',
            '[Console]::Out.Write("fresh-success"); exit 0'
        ) `
        -TimeoutSeconds 15
    if ([int]$success.exit_code -ne 0 -or
        [string]$success.stdout -cne 'fresh-success') {
        throw 'fresh native success result was not captured exactly'
    }
    $failure = Invoke-DefenseClawProcess `
        -File $engine `
        -Arguments @(
            '-NoLogo',
            '-NoProfile',
            '-NonInteractive',
            '-Command',
            '[Console]::Error.Write("fresh-stderr"); exit 23'
        ) `
        -TimeoutSeconds 15
    if ([int]$failure.exit_code -ne 23 -or
        [string]$failure.stderr -cne 'fresh-stderr') {
        throw 'fresh native nonzero/stderr result was not captured exactly'
    }
    $timedOut = $false
    try {
        [void](Invoke-DefenseClawProcess `
            -File $engine `
            -Arguments @(
                '-NoLogo',
                '-NoProfile',
                '-NonInteractive',
                '-Command',
                'Start-Sleep -Seconds 5'
            ) `
            -TimeoutSeconds 1)
    }
    catch {
        $timedOut = $_.Exception.Message -match 'timed out after 1 seconds'
    }
    if (-not $timedOut) {
        throw 'bounded native process did not report its timeout'
    }

    $jsonRoot = Microsoft.PowerShell.Management\Join-Path `
        ([IO.Path]::GetTempPath()) `
        ('defenseclaw-json-smoke-' + [Guid]::NewGuid().ToString('N'))
    $jsonPath = Microsoft.PowerShell.Management\Join-Path `
        $jsonRoot `
        'state.json'
    try {
        [IO.Directory]::CreateDirectory($jsonRoot) |
            Microsoft.PowerShell.Core\Out-Null
        Write-DefenseClawJsonAtomic `
            -Value ([ordered]@{ schema_version = 1; ok = $true }) `
            -Path $jsonPath
        $jsonBytes = [IO.File]::ReadAllBytes($jsonPath)
        if ($jsonBytes.Length -lt 2 -or
            ($jsonBytes.Length -ge 3 -and
                $jsonBytes[0] -eq 0xEF -and
                $jsonBytes[1] -eq 0xBB -and
                $jsonBytes[2] -eq 0xBF)) {
            throw 'atomic JSON writer emitted an empty document or UTF-8 BOM'
        }
        $json = [Text.Encoding]::UTF8.GetString($jsonBytes) |
            Microsoft.PowerShell.Utility\ConvertFrom-Json
        if ([int]$json.schema_version -ne 1 -or -not [bool]$json.ok) {
            throw 'atomic JSON writer did not round-trip its payload'
        }
    }
    finally {
        if ([IO.Directory]::Exists($jsonRoot)) {
            [IO.Directory]::Delete($jsonRoot, $true)
        }
    }
}

& $module {
    $nativeSecurityType = Initialize-DefenseClawNativeSecurity
    if ($null -eq $nativeSecurityType -or
        -not ([string]$nativeSecurityType.FullName).StartsWith(
            'DefenseClaw.Windows.Generated_',
            [StringComparison]::Ordinal
        ) -or
        -not ([string]$nativeSecurityType.FullName).EndsWith(
            '.NativeSecurity',
            [StringComparison]::Ordinal
        )) {
        throw "Win32 native security helper did not use a generated type: $nativeSecurityType"
    }
    $failureActions = [byte[]](Get-DefenseClawFailureActionsBytes)
    if ($failureActions.Length -ne 44) {
        throw "failure action encoding length is $($failureActions.Length), expected 44"
    }
    $encodedActions = [BitConverter]::ToString($failureActions)
    if ($encodedActions -notmatch '03-00-00-00-14-00-00-00' -or
        $encodedActions -match '00-00-00-00-00-00-00-00$') {
        throw 'failure actions do not encode three repeating restarts'
    }
    $layout = Get-DefenseClawLayout `
        -InstallRoot (Join-Path $script:ProgramFiles 'Cisco\Cisco Secure Client\DefenseClaw') `
        -StateRoot (Join-Path $script:ProgramData 'Cisco\Cisco Secure Client\DefenseClaw')
    $expectedCodexParent = Join-Path $script:ProgramData 'OpenAI\Codex'
    if (-not [string]::Equals(
        [string]$layout.CodexMachinePolicyDirectory,
        $expectedCodexParent,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Codex machine-policy parent drift: $($layout.CodexMachinePolicyDirectory)"
    }
    $expectedManagedHooksState = Join-Path `
        $expectedCodexParent `
        '.defenseclaw-managed-hooks.state'
    if (-not [string]::Equals(
        [string]$layout.CodexManagedHooksStatePath,
        $expectedManagedHooksState,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Codex managed-hooks state path drift: $($layout.CodexManagedHooksStatePath)"
    }
    if (-not (Test-DefenseClawOwnedCodexSharedDirectoryPath `
        -Path $layout.CodexVendorDirectory `
        -Layout $layout)) {
        throw 'OpenAI vendor parent is not recognized as transaction-owned'
    }
    if (-not (Test-DefenseClawOwnedCodexSharedDirectoryPath `
        -Path $layout.CodexMachinePolicyDirectory `
        -Layout $layout)) {
        throw 'Codex policy parent is not recognized as transaction-owned'
    }
    if (Test-DefenseClawOwnedCodexSharedDirectoryPath `
        -Path $layout.StateRoot `
        -Layout $layout) {
        throw 'shared-directory rollback accepts a path outside its exact allowlist'
    }
    $unsignedRunID = '0123456789'
    $unsignedGateway = "DefenseClawCertGateway_$unsignedRunID"
    $unsignedGuardian = "DefenseClawCertGuardian_$unsignedRunID"
    $unsignedInstallRoot = Join-Path `
        $script:ProgramFiles `
        "Cisco\Cisco Secure Client\DefenseClaw-Cert\$unsignedRunID"
    $unsignedStateRoot = Join-Path `
        $script:ProgramData `
        "Cisco\Cisco Secure Client\DefenseClaw-Cert\$unsignedRunID"
    $unsignedCodexHome = "C:\Users\Certification\.codex-defenseclaw-cert-$unsignedRunID"
    Assert-DefenseClawUnsignedCertificationScope `
        -Action Install `
        -InstallRoot $unsignedInstallRoot `
        -StateRoot $unsignedStateRoot `
        -GatewayServiceName $unsignedGateway `
        -GuardianServiceName $unsignedGuardian `
        -CertificationCodexHome $unsignedCodexHome
    foreach ($negative in @(
        [pscustomobject]@{
            name = 'production names'
            gateway = 'DefenseClawGateway'
            guardian = 'DefenseClawHookGuardian'
            install = $unsignedInstallRoot
            state = $unsignedStateRoot
            expected = 'gateway service name is outside'
        },
        [pscustomobject]@{
            name = 'near-miss install root'
            gateway = $unsignedGateway
            guardian = $unsignedGuardian
            install = "$unsignedInstallRoot-near"
            state = $unsignedStateRoot
            expected = 'InstallRoot must be exactly'
        },
        [pscustomobject]@{
            name = 'near-miss state root'
            gateway = $unsignedGateway
            guardian = $unsignedGuardian
            install = $unsignedInstallRoot
            state = "$unsignedStateRoot-near"
            expected = 'StateRoot must be exactly'
        }
    )) {
        try {
            Assert-DefenseClawUnsignedCertificationScope `
                -Action Install `
                -InstallRoot ([string]$negative.install) `
                -StateRoot ([string]$negative.state) `
                -GatewayServiceName ([string]$negative.gateway) `
                -GuardianServiceName ([string]$negative.guardian) `
                -CertificationCodexHome $unsignedCodexHome
            throw "unsigned certification gate accepted $($negative.name)"
        }
        catch {
            if ($_.Exception.Message -notmatch [regex]::Escape(
                [string]$negative.expected
            )) {
                throw
            }
        }
    }
    $modeHome = Join-Path `
        ([IO.Path]::GetTempPath()) `
        ".codex-defenseclaw-cert-$unsignedRunID"
    $modeHomeCreated = $false
    if (-not (Test-Path -LiteralPath $modeHome)) {
        [void](New-Item -ItemType Directory -Path $modeHome)
        $modeHomeCreated = $true
    }
    $modeMetadataPath = Join-Path `
        ([IO.Path]::GetTempPath()) `
        "defenseclaw-core-mode-$([Guid]::NewGuid().ToString('N')).json"
    try {
        $fullUnsignedLayout = Get-DefenseClawLayout `
            -InstallRoot $unsignedInstallRoot `
            -StateRoot $unsignedStateRoot `
            -GatewayServiceName $unsignedGateway `
            -GuardianServiceName $unsignedGuardian `
            -CertificationCodexHome $modeHome
        $coreOnlyLayout = Get-DefenseClawLayout `
            -InstallRoot $unsignedInstallRoot `
            -StateRoot $unsignedStateRoot `
            -GatewayServiceName $unsignedGateway `
            -GuardianServiceName $unsignedGuardian `
            -CertificationCodexHome $modeHome `
            -CoreHardeningCertification
        if ([bool]$fullUnsignedLayout.CoreHardeningCertification -or
            -not [bool]$coreOnlyLayout.CoreHardeningCertification) {
            throw 'CertificationCodexHome still implicitly selects core-only mode'
        }
        $fullUnsignedMetadata = New-DefenseClawDeploymentMetadata `
            -Layout $fullUnsignedLayout `
            -GatewayServiceName $unsignedGateway `
            -GuardianServiceName $unsignedGuardian `
            -Installed:$false
        $coreOnlyMetadata = New-DefenseClawDeploymentMetadata `
            -Layout $coreOnlyLayout `
            -GatewayServiceName $unsignedGateway `
            -GuardianServiceName $unsignedGuardian `
            -Installed:$false
        if ([bool]$fullUnsignedMetadata.core_hardening_certification -or
            -not [bool]$coreOnlyMetadata.core_hardening_certification) {
            throw 'deployment metadata did not preserve the explicit core-only mode'
        }

        $adoptLayout = Get-DefenseClawLayout `
            -InstallRoot $unsignedInstallRoot `
            -StateRoot $unsignedStateRoot `
            -GatewayServiceName $unsignedGateway `
            -GuardianServiceName $unsignedGuardian
        $adoptLayout.MetadataPath = $modeMetadataPath
        [IO.File]::WriteAllText(
            $modeMetadataPath,
            (
                $coreOnlyMetadata |
                    ConvertTo-Json -Depth 16
            ),
            [Text.UTF8Encoding]::new($false)
        )
        [void](Get-DefenseClawDeploymentMetadata `
            -Layout $adoptLayout `
            -Required)
        if (-not [bool]$adoptLayout.CoreHardeningCertification -or
            -not [string]::Equals(
                [string]$adoptLayout.CertificationCodexHome,
                [string]$modeHome,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw 'read-only/removal metadata did not adopt protected certification mode'
        }

        $conversionLayout = Get-DefenseClawLayout `
            -InstallRoot $unsignedInstallRoot `
            -StateRoot $unsignedStateRoot `
            -GatewayServiceName $unsignedGateway `
            -GuardianServiceName $unsignedGuardian `
            -CertificationCodexHome $modeHome `
            -CoreHardeningCertification
        $conversionLayout.MetadataPath = $modeMetadataPath
        [IO.File]::WriteAllText(
            $modeMetadataPath,
            (
                $fullUnsignedMetadata |
                    ConvertTo-Json -Depth 16
            ),
            [Text.UTF8Encoding]::new($false)
        )
        $conversionRejected = $false
        try {
            [void](Get-DefenseClawDeploymentMetadata `
                -Layout $conversionLayout `
                -Required)
        }
        catch {
            $conversionRejected = $true
        }
        if (-not $conversionRejected) {
            throw 'protected full certification metadata was converted into core-only mode'
        }
    }
    finally {
        if (Test-Path -LiteralPath $modeMetadataPath) {
            # See rationale on the certificationCodexHome cleanup above.
            Remove-Item -LiteralPath $modeMetadataPath -Force -Recurse
        }
        if ($modeHomeCreated -and (Test-Path -LiteralPath $modeHome)) {
            Remove-Item -LiteralPath $modeHome -Force -Recurse
        }
    }
    $environmentArguments = @{
        Name = 'DefenseClawGateway'
        RuntimeDirectory = $layout.RuntimeDirectory
        ConfigPath = $layout.ConfigPath
        AuthorizationDirectory = $layout.AuthorizationDirectory
        GatewayServiceName = 'DefenseClawGateway'
        LogPath = $layout.GatewayLogPath
    }
    $productionEnvironment = @(
        Get-DefenseClawServiceEnvironmentValues @environmentArguments
    )
    if (@($productionEnvironment | Where-Object {
        ([string]$_).StartsWith('CODEX_HOME=', [StringComparison]::OrdinalIgnoreCase)
    }).Count -ne 0) {
        throw 'default production service environment unexpectedly contains CODEX_HOME'
    }
    # Prove that an operator-supplied certification CODEX_HOME in ambient
    # process env does NOT leak into the service environment values. Without
    # this the previous assertion compared two identical outputs of the
    # deterministic Get-DefenseClawServiceEnvironmentValues splat and always
    # passed, hiding a regression where the function grew a CODEX_HOME
    # pass-through.
    $certificationHome = 'C:\certification\.codex-defenseclaw-cert-0123456789'
    $priorCodexHome = $env:CODEX_HOME
    try {
        $env:CODEX_HOME = $certificationHome
        $certificationEnvironment = @(
            Get-DefenseClawServiceEnvironmentValues @environmentArguments
        )
    } finally {
        if ($null -eq $priorCodexHome) {
            [Environment]::SetEnvironmentVariable('CODEX_HOME', $null, 'Process')
        } else {
            $env:CODEX_HOME = $priorCodexHome
        }
    }
    $certificationEntries = @($certificationEnvironment | Where-Object {
        ([string]$_).StartsWith('CODEX_HOME=', [StringComparison]::OrdinalIgnoreCase)
    })
    if ($certificationEntries.Count -ne 0 -or
        ($productionEnvironment -join "`n") -cne
            ($certificationEnvironment -join "`n")) {
        throw 'certification scope changed a service environment or injected CODEX_HOME'
    }
    $attestedEnvironment = @(
        Get-DefenseClawServiceEnvironmentValues `
            @environmentArguments `
            -AgentApplicationControlAttested `
            -CodexTrustedHookLauncherVerified
    )
    if (@($attestedEnvironment | Where-Object {
        [string]$_ -ceq 'DEFENSECLAW_WINDOWS_CODEX_TRUSTED_HOOK_LAUNCHER_VERIFIED=1'
    }).Count -ne 1 -or
        @($attestedEnvironment | Where-Object {
            [string]$_ -ceq 'DEFENSECLAW_WINDOWS_CODEX_APPROVED_CLIENT_ENFORCED=1'
        }).Count -ne 1 -or
        @($attestedEnvironment | Where-Object {
            [string]$_ -ceq 'DEFENSECLAW_WINDOWS_APPROVED_AGENT_CLIENTS_ENFORCED=1'
        }).Count -ne 1 -or
        @($attestedEnvironment | Where-Object {
            [string]$_ -ceq 'DEFENSECLAW_WINDOWS_CLAUDE_EFFECTIVE_POLICY_VERIFIED=1'
        }).Count -ne 0 -or
        @($attestedEnvironment | Where-Object {
            ([string]$_).StartsWith(
                'CODEX_HOME=',
                [StringComparison]::OrdinalIgnoreCase
            )
        }).Count -ne 0) {
        throw 'split application-control/launcher environment evidence is missing or leaked CODEX_HOME'
    }
    $fullyAttestedEnvironment = @(
        Get-DefenseClawServiceEnvironmentValues `
            @environmentArguments `
            -AgentApplicationControlAttested `
            -ClaudeEffectivePolicyVerified `
            -CodexTrustedHookLauncherVerified
    )
    if (@($fullyAttestedEnvironment | Where-Object {
        [string]$_ -ceq 'DEFENSECLAW_WINDOWS_CLAUDE_EFFECTIVE_POLICY_VERIFIED=1'
    }).Count -ne 1) {
        throw 'independent Claude effective-policy evidence is missing'
    }
    $productionMetadata = New-DefenseClawDeploymentMetadata `
        -Layout $layout `
        -GatewayServiceName 'DefenseClawGateway' `
        -GuardianServiceName 'DefenseClawHookGuardian' `
        -Installed:$false
    if ($productionMetadata.Contains('certification_codex_home')) {
        throw 'production deployment metadata unexpectedly contains certification CODEX_HOME'
    }
    $certificationLayout = Get-DefenseClawLayout `
        -InstallRoot $unsignedInstallRoot `
        -StateRoot $unsignedStateRoot `
        -GatewayServiceName $unsignedGateway `
        -GuardianServiceName $unsignedGuardian `
        -CertificationCodexHome $certificationHome
    $certificationMetadata = New-DefenseClawDeploymentMetadata `
        -Layout $certificationLayout `
        -GatewayServiceName 'DefenseClawCertGateway_0123456789' `
        -GuardianServiceName 'DefenseClawCertGuardian_0123456789' `
        -Installed:$false
    if (-not $certificationMetadata.Contains('certification_codex_home') -or
        [string]$certificationMetadata['certification_codex_home'] -cne $certificationHome) {
        throw 'certification deployment metadata does not pin exact CODEX_HOME'
    }
    # A failing System32 tool must surface its exit code, not its stderr.
    $nativeFailure = $null
    try {
        Invoke-DefenseClawNative `
            -File (Join-Path $script:System32 'icacls.exe') `
            -Arguments @((Join-Path $script:System32 'DefenseClawMissing_0123456789'))
    }
    catch {
        $nativeFailure = [string]$_.Exception.Message
    }
    if ($null -eq $nativeFailure) {
        throw 'a failing native tool did not raise an error'
    }
    if ($nativeFailure -notmatch 'exited \d+ while running') {
        throw "native stderr escaped the exit-code check: $nativeFailure"
    }
    if ($ErrorActionPreference -cne 'Stop') {
        throw "native invocation left the error preference at $ErrorActionPreference"
    }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($elevated) {
    & $module {
        param(
            $SmokeInstallRoot,
            $SmokeStateRoot,
            $SmokeGatewayService,
            $SmokeGuardianService
        )
        $lockLayout = Get-DefenseClawLayout `
            -InstallRoot $SmokeInstallRoot `
            -StateRoot $SmokeStateRoot `
            -GatewayServiceName $SmokeGatewayService `
            -GuardianServiceName $SmokeGuardianService
        $lockLayout.LifecycleLockDirectory = Join-Path `
            $SmokeStateRoot `
            'lifecycle-lock'
        $lockLayout.LifecycleLockPath = Join-Path `
            $lockLayout.LifecycleLockDirectory `
            'lifecycle.lock'
        Initialize-DefenseClawManagedRoot `
            -Path $SmokeStateRoot `
            -Label 'smoke StateRoot' `
            -RequiredBase $script:ProgramData
        Initialize-DefenseClawManagedRoot `
            -Path $lockLayout.LifecycleLockDirectory `
            -Label 'smoke lifecycle lock' `
            -RequiredBase $script:ProgramData
        try {
            $lock = Enter-DefenseClawLifecycleLock `
                -Layout $lockLayout `
                -TimeoutSeconds 2
            try {
                if ($null -eq $lock) {
                    throw 'protected lifecycle file lock was not returned'
                }
            }
            finally {
                Exit-DefenseClawLifecycleLock -Lock $lock
            }
            $sections = (
                [Security.AccessControl.AccessControlSections]::Access -bor
                [Security.AccessControl.AccessControlSections]::Owner -bor
                [Security.AccessControl.AccessControlSections]::Group
            )
            $beforeItem = Get-Item `
                -LiteralPath $lockLayout.LifecycleLockPath `
                -Force `
                -ErrorAction Stop
            $beforeSDDL = (Get-Acl `
                -LiteralPath $lockLayout.LifecycleLockPath `
                -ErrorAction Stop).GetSecurityDescriptorSddlForm($sections)
            $beforeHash = (Get-FileHash `
                -LiteralPath $lockLayout.LifecycleLockPath `
                -Algorithm SHA256).Hash

            $lock = Enter-DefenseClawLifecycleLock `
                -Layout $lockLayout `
                -TimeoutSeconds 2
            try {
                if ($null -eq $lock) {
                    throw 'persistent lifecycle file lock was not reusable'
                }
            }
            finally {
                Exit-DefenseClawLifecycleLock -Lock $lock
            }
            $afterItem = Get-Item `
                -LiteralPath $lockLayout.LifecycleLockPath `
                -Force `
                -ErrorAction Stop
            $afterSDDL = (Get-Acl `
                -LiteralPath $lockLayout.LifecycleLockPath `
                -ErrorAction Stop).GetSecurityDescriptorSddlForm($sections)
            $afterHash = (Get-FileHash `
                -LiteralPath $lockLayout.LifecycleLockPath `
                -Algorithm SHA256).Hash
            if ([int64]$beforeItem.Length -ne 0 -or
                [int64]$afterItem.Length -ne 0 -or
                $afterHash -cne $beforeHash -or
                $afterSDDL -cne $beforeSDDL) {
                throw 'persistent lifecycle file lock changed across consecutive acquisitions'
            }
        }
        finally {
            Remove-DefenseClawManagedTree `
                -Path $SmokeStateRoot `
                -RequiredBase $script:ProgramData `
                -Label 'smoke StateRoot'
        }
    } `
        $certificationInstallRoot `
        $certificationStateRoot `
        "DefenseClawCertGateway_$token" `
        "DefenseClawCertGuardian_$token"
}
else {
    try {
        Invoke-DefenseClawEnterpriseLifecycle `
            -Action Install `
            -InstallRoot $installRoot `
            -StateRoot $stateRoot `
            -GatewayServiceName $gatewayService `
            -GuardianServiceName $guardianService
        throw 'non-admin Install unexpectedly succeeded'
    }
    catch {
        if ($_.Exception.Message -notmatch 'elevated administrator token') {
            throw
        }
    }
}

$teardownFailurePreserved = & $module {
    function script:Assert-DefenseClawAdministrator {}
    function script:Invoke-DefenseClawGatewayCommand {
        param(
            [hashtable]$Layout,
            [string]$GatewayServiceName,
            [object[]]$Arguments,
            [switch]$Capture,
            [switch]$AllowFailure
        )
        return [pscustomobject]@{
            exit_code = 1
            output = @(
                '{"schema_version":2,"action":"prepare","ok":false,"error":"resolve trusted ProgramData: restricted fixture"}'
            )
        }
    }
    $failureLayout = @{
        ManifestPath = 'C:\missing\targets.yaml'
        ManagedHooksTeardownJournalPath = 'C:\missing\managed-hooks-teardown.json'
    }
    $caught = $null
    try {
        [void](Invoke-DefenseClawManagedHooksTeardownCommand `
            -Layout $failureLayout `
            -GatewayServiceName 'DefenseClawGateway' `
            -Action prepare)
    }
    catch {
        $caught = [string]$_.Exception.Message
    }
    if ([string]::IsNullOrWhiteSpace($caught) -or
        $caught -notmatch 'resolve trusted ProgramData: restricted fixture' -or
        $caught -match 'missing (manifest_path|journal_path)') {
        throw "failed managed-hook teardown masked its original error: $caught"
    }
    return $true
}
if (-not [bool]$teardownFailurePreserved) {
    throw 'failed managed-hook teardown diagnostic regression did not execute'
}

[pscustomobject]@{
    schema_version = 1
    ok = $true
    engine = $PSVersionTable.PSVersion.ToString()
    elevated = $elevated
    windows_directory = $windowsDirectory
    lifecycle_file_lock_executed = $elevated
    lifecycle_file_lock_reuse_stable = $elevated
    ambient_cmdlet_shadow_ignored = $true
    fixed_native_helper_spoof_ignored = $true
    command_line_empty_argument_round_trip = $true
    command_line_invalid_arguments_rejected = $true
    teardown_failure_diagnostic_preserved = $teardownFailurePreserved
    production_codex_home_absent = $true
    certification_codex_home_exact = $true
    certification_scope_rejections = $true
    certification_metadata_pinned = $true
    unsigned_certification_scope_exact = $true
    production_unsigned_scope_rejected = $true
    near_miss_unsigned_roots_rejected = $true
    signed_custom_roots_rejected = $true
    signed_custom_service_names_rejected = $true
} | ConvertTo-Json -Compress
