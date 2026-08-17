# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$BasicUserResultPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$installerSource = [IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\install-enterprise.ps1')
)
$moduleSource = [IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1')
)
$engine = if ($PSVersionTable.PSEdition -eq 'Core') {
    Join-Path $PSHOME 'pwsh.exe'
}
else {
    Join-Path $PSHOME 'powershell.exe'
}

function Test-EffectiveMediumNonAdminUser {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $whoamiPath = Join-Path $env:SystemRoot 'System32\whoami.exe'
    $groupText = & $whoamiPath /groups /fo csv /nh 2>$null | Out-String
    return (-not $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator
        ) -and $groupText -match 'S-1-16-8192')
}

function Write-BasicUserResult {
    param([Parameter(Mandatory = $true)][string]$Json)
    $resultPath = [IO.Path]::GetFullPath($BasicUserResultPath)
    $tempPath = "$resultPath.$PID.tmp"
    [IO.File]::WriteAllText($tempPath, $Json)
    [IO.File]::Move($tempPath, $resultPath)
}

trap {
    $detail = ($_ | Out-String).Trim()
    if (-not [string]::IsNullOrWhiteSpace($BasicUserResultPath)) {
        Write-BasicUserResult -Json (
            [pscustomobject]@{ ok = $false; error = $detail } |
                ConvertTo-Json -Compress
        )
    }
    [Console]::Error.WriteLine($detail)
    exit 1
}

function Invoke-BasicUserBootstrapSmoke {
    $relayRoot = Join-Path (
        [IO.Path]::GetTempPath()
    ) "DefenseClaw-BootstrapRelay-$([Guid]::NewGuid().ToString('N'))"
    [void][IO.Directory]::CreateDirectory($relayRoot)
    $process = $null
    try {
        # Hosted runners may grant the elevated token workspace access only
        # through its Administrators SID. The filtered LUA child must not rely
        # on that SID, so stage the exact three-file bootstrap surface beneath
        # its user-accessible relay while preserving the production layout.
        $stagedWindowsRoot = Join-Path $relayRoot 'packaging\windows'
        $stagedTestsRoot = Join-Path $stagedWindowsRoot 'tests'
        [void][IO.Directory]::CreateDirectory($stagedTestsRoot)
        $stagedScriptPath = Join-Path $stagedTestsRoot 'enterprise-bootstrap-smoke.ps1'
        [IO.File]::WriteAllBytes(
            $stagedScriptPath,
            [IO.File]::ReadAllBytes($PSCommandPath)
        )
        [IO.File]::WriteAllBytes(
            (Join-Path $stagedWindowsRoot 'install-enterprise.ps1'),
            [IO.File]::ReadAllBytes($installerSource)
        )
        [IO.File]::WriteAllBytes(
            (Join-Path $stagedWindowsRoot 'DefenseClawEnterprise.psm1'),
            [IO.File]::ReadAllBytes($moduleSource)
        )
        $resultPath = Join-Path $relayRoot 'result.json'
        $scriptLiteral = $stagedScriptPath.Replace("'", "''")
        $resultLiteral = $resultPath.Replace("'", "''")
        $workerCommand = (
            "& '$scriptLiteral' -BasicUserResultPath '$resultLiteral'"
        )
        $encodedCommand = [Convert]::ToBase64String(
            [Text.Encoding]::Unicode.GetBytes($workerCommand)
        )
        $repoRoot = [IO.Path]::GetFullPath(
            (Join-Path $PSScriptRoot '..\..\..')
        )
        $launcherSource = Join-Path `
            $repoRoot 'scripts\windows-setup-standard-user-launcher.cs'
        if (-not ('DefenseClaw.SetupStandardUserLauncher' -as [type])) {
            Add-Type -Path $launcherSource -ErrorAction Stop
        }
        $environment = @(
            [Environment]::GetEnvironmentVariables('Process').GetEnumerator() |
                ForEach-Object {
                    '{0}={1}' -f [string]$_.Key, [string]$_.Value
                }
        )
        $arguments = [string[]]@(
            '-NoLogo', '-NoProfile', '-NonInteractive',
            '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encodedCommand
        )
        $process = [DefenseClaw.SetupStandardUserLauncher]::StartRestrictedWithCapture(
            $engine,
            $arguments,
            [IO.Path]::GetFullPath($stagedTestsRoot),
            [string[]]$environment,
            $false
        )
        $deadline = [DateTime]::UtcNow.AddMinutes(5)
        while (-not [IO.File]::Exists($resultPath) -and
            -not $process.HasExited -and
            [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 100
        }
        $timedOut = -not [IO.File]::Exists($resultPath) -and
            -not $process.HasExited
        if ($timedOut) {
            $process.Kill($true)
        }
        if (-not $process.WaitForExit(30000)) {
            throw 'Basic User bootstrap smoke child did not exit after completion'
        }
        $outputHealthy = $process.CompleteOutput(5000)
        $launchOutput = @(
            [string]$process.StdOut,
            [string]$process.StdErr,
            [string]$process.OutputCaptureError
        ) -join [Environment]::NewLine
        if (-not [IO.File]::Exists($resultPath)) {
            throw (
                $(if ($timedOut) {
                    'Basic User bootstrap smoke timed out; '
                } else {
                    "Basic User bootstrap smoke exited $($process.ExitCode); "
                }) +
                "launch output=$($launchOutput.Trim())"
            )
        }
        $reportJson = [IO.File]::ReadAllText($resultPath)
        $report = $reportJson | ConvertFrom-Json
        if (-not [bool]$report.ok) {
            throw (
                "Basic User bootstrap smoke failed: $($report.error); " +
                "output capture healthy=$outputHealthy; " +
                "launch output=$($launchOutput.Trim())"
            )
        }
        if (-not $outputHealthy) {
            Write-Warning (
                'Basic User bootstrap output capture failed despite a ' +
                "successful result: $launchOutput"
            )
        }
        Write-Output $reportJson
    }
    finally {
        if ($null -ne $process) {
            try {
                if (-not $process.HasExited) {
                    $process.Kill($true)
                    if (-not $process.WaitForExit(30000)) {
                        throw (
                            'Basic User bootstrap smoke process tree did not ' +
                            'exit during cleanup'
                        )
                    }
                }
            }
            finally {
                $process.Dispose()
            }
        }
        if ([IO.Directory]::Exists($relayRoot)) {
            [IO.Directory]::Delete($relayRoot, $true)
        }
    }
}

$effectiveMediumNonAdmin = Test-EffectiveMediumNonAdminUser
if (-not $effectiveMediumNonAdmin) {
    if (-not [string]::IsNullOrWhiteSpace($BasicUserResultPath)) {
        throw (
            'raw DOS-device bootstrap regression requires the executable ' +
            'test process to be an effective medium-integrity non-admin user'
        )
    }
    Invoke-BasicUserBootstrapSmoke
    exit 0
}
$testRoot = Join-Path (
    [IO.Path]::GetTempPath()
) "DefenseClaw-BootstrapSmoke-$([Guid]::NewGuid().ToString('N'))"
$scopeToken = ([Guid]::NewGuid().ToString('N')).Substring(0, 10)
$scopeGatewayService = "DefenseClawCertGateway_$scopeToken"
$scopeGuardianService = "DefenseClawCertGuardian_$scopeToken"
$scopeInstallRoot = [IO.Path]::Combine(
    [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles),
    'Cisco',
    'Cisco Secure Client',
    'DefenseClaw-Cert',
    $scopeToken
)
$scopeStateRoot = [IO.Path]::Combine(
    [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData),
    'Cisco',
    'Cisco Secure Client',
    'DefenseClaw-Cert',
    $scopeToken
)
$productionInstallRoot = [IO.Path]::Combine(
    [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles),
    'Cisco',
    'Cisco Secure Client',
    'DefenseClaw'
)
$productionStateRoot = [IO.Path]::Combine(
    [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData),
    'Cisco',
    'Cisco Secure Client',
    'DefenseClaw'
)
$scopeCertificationCodexHome = Join-Path (
    [IO.Path]::GetTempPath()
) ".codex-defenseclaw-cert-$scopeToken"
$markerPath = Join-Path $testRoot 'module-executed.marker'
$maliciousModule = @'
$marker = [Environment]::GetEnvironmentVariable('DEFENSECLAW_BOOTSTRAP_TEST_MARKER', 'Process')
if (-not [string]::IsNullOrWhiteSpace($marker)) {
    [IO.File]::WriteAllText($marker, 'module executed')
}
function Invoke-DefenseClawEnterpriseLifecycle {
    [pscustomobject]@{ ok = $true }
}
Export-ModuleMember -Function Invoke-DefenseClawEnterpriseLifecycle
'@

function Initialize-RawDosDeviceInterop {
    if ($null -ne (
        'DefenseClaw.Windows.Tests.RawDosDeviceNative' -as [type]
    )) {
        return
    }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace DefenseClaw.Windows.Tests
{
    public static class RawDosDeviceNative
    {
        private const uint DDD_RAW_TARGET_PATH = 0x00000001;
        private const uint DDD_REMOVE_DEFINITION = 0x00000002;
        private const uint DDD_EXACT_MATCH_ON_REMOVE = 0x00000004;
        private const uint DDD_NO_BROADCAST_SYSTEM = 0x00000008;
        private const int ERROR_FILE_NOT_FOUND = 2;

        [DllImport(
            "kernel32.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DefineDosDeviceW(
            uint flags,
            string deviceName,
            string targetPath);

        [DllImport(
            "kernel32.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        private static extern uint QueryDosDeviceW(
            string deviceName,
            StringBuilder targetPath,
            int maximumLength);

        public static string TryQuery(string deviceName)
        {
            StringBuilder target = new StringBuilder(32768);
            uint length = QueryDosDeviceW(
                deviceName,
                target,
                target.Capacity);
            if (length != 0)
                return target.ToString();
            int error = Marshal.GetLastWin32Error();
            if (error == ERROR_FILE_NOT_FOUND)
                return null;
            throw new Win32Exception(
                error,
                "QueryDosDeviceW failed for " + deviceName);
        }

        public static void DefineRaw(string deviceName, string targetPath)
        {
            if (!DefineDosDeviceW(
                DDD_RAW_TARGET_PATH | DDD_NO_BROADCAST_SYSTEM,
                deviceName,
                targetPath))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "DefineDosDeviceW raw alias creation failed");
        }

        public static void RemoveRaw(string deviceName, string targetPath)
        {
            if (!DefineDosDeviceW(
                DDD_RAW_TARGET_PATH |
                    DDD_REMOVE_DEFINITION |
                    DDD_EXACT_MATCH_ON_REMOVE |
                    DDD_NO_BROADCAST_SYSTEM,
                deviceName,
                targetPath))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "DefineDosDeviceW raw alias removal failed");
        }

        public static void RemoveAny(string deviceName)
        {
            if (!DefineDosDeviceW(
                DDD_REMOVE_DEFINITION | DDD_NO_BROADCAST_SYSTEM,
                deviceName,
                null))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "DefineDosDeviceW alias fallback removal failed");
        }
    }
}
'@ -Language CSharp -ErrorAction Stop
}

function Remove-RawDosDeviceFixtureAlias(
    [string]$Drive,
    [string]$Target
) {
    try {
        [DefenseClaw.Windows.Tests.RawDosDeviceNative]::RemoveRaw(
            $Drive,
            $Target
        )
    }
    catch {
        [DefenseClaw.Windows.Tests.RawDosDeviceNative]::RemoveAny($Drive)
    }
    $surviving =
        [DefenseClaw.Windows.Tests.RawDosDeviceNative]::TryQuery($Drive)
    if (-not [string]::IsNullOrWhiteSpace($surviving)) {
        throw "raw DOS-device alias survived cleanup: $Drive -> $surviving"
    }
    return $true
}

function Get-RawAliasFixtureInventory([string]$Root) {
    $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $rows = [Collections.Generic.List[object]]::new()
    foreach ($item in @(
        Get-ChildItem `
            -LiteralPath $fullRoot `
            -Recurse `
            -Force |
            Sort-Object FullName
    )) {
        $fullPath = [IO.Path]::GetFullPath(
            [string]$item.FullName
        ).TrimEnd('\')
        if (-not $fullPath.StartsWith(
                $fullRoot + '\',
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "raw DOS-device fixture inventory escaped its root: $fullPath"
        }
        $rows.Add([pscustomobject]@{
            relative_path = $fullPath.Substring($fullRoot.Length + 1)
            kind = if ($item.PSIsContainer) { 'directory' } else { 'file' }
            attributes = [int]$item.Attributes
            length = if ($item.PSIsContainer) {
                [int64]0
            } else {
                [int64]$item.Length
            }
            sha256 = if ($item.PSIsContainer) {
                ''
            } else {
                $stream = [IO.File]::Open(
                    $fullPath,
                    [IO.FileMode]::Open,
                    [IO.FileAccess]::Read,
                    (
                        [IO.FileShare]::Read -bor
                        [IO.FileShare]::Write -bor
                        [IO.FileShare]::Delete
                    )
                )
                $algorithm = [Security.Cryptography.SHA256]::Create()
                try {
                    [BitConverter]::ToString(
                        $algorithm.ComputeHash($stream)
                    ).Replace('-', '').ToLowerInvariant()
                }
                finally {
                    $algorithm.Dispose()
                    $stream.Dispose()
                }
            }
        })
    }
    return @($rows.ToArray())
}

function Get-ProductionBootstrapNativePathType {
    $tokens = $null
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        $installerSource,
        [ref]$tokens,
        [ref]$parseErrors
    )
    if (@($parseErrors).Count -ne 0) {
        throw 'could not parse the production enterprise bootstrap probe'
    }
    $definitions = @(
        $ast.FindAll(
            {
                param($node)
                return (
                    $node -is
                        [Management.Automation.Language.FunctionDefinitionAst] -and
                    [string]$node.Name -ceq
                        'Initialize-DefenseClawBootstrapNativePath'
                )
            },
            $true
        )
    )
    if ($definitions.Count -ne 1) {
        throw (
            'expected exactly one production bootstrap native-path ' +
            "initializer, found $($definitions.Count)"
        )
    }
    $script:DefenseClawBootstrapPathProbe = $null
    . ([scriptblock]::Create([string]$definitions[0].Extent.Text))
    $nativeType = Initialize-DefenseClawBootstrapNativePath
    if ($nativeType -isnot [type]) {
        throw 'production bootstrap native-path initializer did not return a CLR type'
    }
    return $nativeType
}

function Invoke-ProductionModuleLogicalDiskAliasProbe(
    [string]$NormalDrive,
    [string[]]$AliasDrives
) {
    $tokens = $null
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        $moduleSource,
        [ref]$tokens,
        [ref]$parseErrors
    )
    if (@($parseErrors).Count -ne 0) {
        throw 'could not parse the production enterprise module drive probe'
    }
    $requiredNames = @(
        'Initialize-DefenseClawNativeSecurity',
        'Get-DefenseClawLogicalDisk'
    )
    $definitions = @(
        $ast.FindAll(
            {
                param($node)
                return (
                    $node -is
                        [Management.Automation.Language.FunctionDefinitionAst] -and
                    [string]$node.Name -in $requiredNames
                )
            },
            $true
        )
    )
    if ($definitions.Count -ne $requiredNames.Count) {
        throw (
            'could not isolate both exact production module drive-probe ' +
            "functions; found $($definitions.Count)"
        )
    }
    $script:WindowsDirectory =
        [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
    $script:System32 = [IO.Path]::Combine(
        $script:WindowsDirectory,
        'System32'
    )
    $script:DefenseClawNativeSecurityType = $null
    foreach ($name in $requiredNames) {
        $definition = @(
            $definitions | Where-Object {
                [string]$_.Name -ceq $name
            }
        )
        if ($definition.Count -ne 1) {
            throw "production module drive probe has an ambiguous $name definition"
        }
        . ([scriptblock]::Create([string]$definition[0].Extent.Text))
    }
    $normal = Get-DefenseClawLogicalDisk -DriveID $NormalDrive
    if ([int]$normal.DriveType -ne 3 -or
        -not [string]::Equals(
            [string]$normal.FileSystem,
            'NTFS',
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        [string]::IsNullOrWhiteSpace([string]$normal.Target)) {
        throw 'production module drive probe rejected the canonical system drive'
    }
    $rejected = [Collections.Generic.List[string]]::new()
    foreach ($aliasDrive in $AliasDrives) {
        try {
            $null = Get-DefenseClawLogicalDisk -DriveID $aliasDrive
            throw "production module drive probe accepted raw alias $aliasDrive"
        }
        catch {
            if ($_.Exception.Message -notmatch (
                    'GetVolumeNameForVolumeMountPoint|' +
                    'QueryDosDevice failed for Global|authoritative volume|' +
                    'Mount Manager|canonical DOS drive root'
                )) {
                throw
            }
            $rejected.Add($aliasDrive)
        }
    }
    return [pscustomobject]@{
        canonical_system_drive_accepted = $true
        rejected_aliases = @($rejected.ToArray())
    }
}

function Invoke-RejectedBootstrap {
    param(
        [Parameter(Mandatory)][string]$InstallerPath,
        [Parameter(Mandatory)][string]$ExpectedError,
        [string[]]$InstallerArguments,
        [switch]$PreloadFixedHelperSpoof
    )
    if ($null -eq $InstallerArguments -or $InstallerArguments.Count -eq 0) {
        $InstallerArguments = @(
            '-Action', 'Install',
            '-GatewayServiceName', $scopeGatewayService,
            '-GuardianServiceName', $scopeGuardianService,
            '-InstallRoot', $scopeInstallRoot,
            '-StateRoot', $scopeStateRoot,
            '-CertificationCodexHome', $scopeCertificationCodexHome,
            '-AllowUnsigned',
            '-Json'
        )
    }
    if (Test-Path -LiteralPath $markerPath) {
        Remove-Item -LiteralPath $markerPath -Force
    }
    [Environment]::SetEnvironmentVariable(
        'DEFENSECLAW_BOOTSTRAP_TEST_MARKER',
        $markerPath,
        'Process'
    )
    $previousErrorAction = $ErrorActionPreference
    try {
        # Windows PowerShell 5.1 wraps native stderr as NativeCommandError when
        # the caller uses Stop. The non-zero child exit is the assertion here,
        # so capture it without converting expected stderr into a test abort.
        $ErrorActionPreference = 'Continue'
        if ($PreloadFixedHelperSpoof) {
            $quotedInstallerPath = $InstallerPath.Replace("'", "''")
            $quotedGatewayService = $scopeGatewayService.Replace("'", "''")
            $quotedGuardianService = $scopeGuardianService.Replace("'", "''")
            $quotedInstallRoot = $scopeInstallRoot.Replace("'", "''")
            $quotedStateRoot = $scopeStateRoot.Replace("'", "''")
            $quotedCertificationHome = $scopeCertificationCodexHome.Replace("'", "''")
            $preloadPath = Join-Path $testRoot 'preloaded-helper-spoof.ps1'
            Set-Content -LiteralPath $preloadPath -Encoding UTF8 -Value @"
`$ErrorActionPreference = 'Stop'
[void](Microsoft.PowerShell.Utility\Add-Type -TypeDefinition @'
using System;
namespace DefenseClaw.Windows
{
    public static class EnterpriseBootstrapPath
    {
        public static uint GetDriveType(string root)
        {
            throw new InvalidOperationException("fixed bootstrap helper spoof was used");
        }
        public static string GetFileSystem(string root)
        {
            throw new InvalidOperationException("fixed bootstrap helper spoof was used");
        }
        public static string QueryDriveTarget(string drive)
        {
            throw new InvalidOperationException("fixed bootstrap helper spoof was used");
        }
    }
}
'@ -Language CSharp -ErrorAction Stop)
& '$quotedInstallerPath' `
    -Action Install `
    -GatewayServiceName '$quotedGatewayService' `
    -GuardianServiceName '$quotedGuardianService' `
    -InstallRoot '$quotedInstallRoot' `
    -StateRoot '$quotedStateRoot' `
    -CertificationCodexHome '$quotedCertificationHome' `
    -AllowUnsigned `
    -Json
"@
            $output = & $engine `
                -NoLogo `
                -NoProfile `
                -NonInteractive `
                -ExecutionPolicy Bypass `
                -File $preloadPath 2>&1
        }
        else {
            $output = & $engine `
                -NoLogo `
                -NoProfile `
                -NonInteractive `
                -ExecutionPolicy Bypass `
                -File $InstallerPath `
                @InstallerArguments 2>&1
        }
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorAction
        [Environment]::SetEnvironmentVariable(
            'DEFENSECLAW_BOOTSTRAP_TEST_MARKER',
            $null,
            'Process'
        )
    }
    if ($exitCode -eq 0) {
        throw (
            "untrusted bootstrap fixture unexpectedly succeeded: $InstallerPath; " +
            "output=$(($output | Out-String).Trim())"
        )
    }
    if (Test-Path -LiteralPath $markerPath) {
        throw "rejected bootstrap imported and executed its malicious adjacent module: $InstallerPath"
    }
    $detail = ($output | Out-String).Trim()
    if ($detail -notmatch $ExpectedError) {
        throw "bootstrap rejection did not report '$ExpectedError': $detail"
    }
}

$junctionExecuted = $false
$rawAliasDefined = $false
$rawAliasCleanupVerified = $false
$rawAliasDrive = ''
$rawAliasTarget = ''
$wholeVolumeAliasDefined = $false
$wholeVolumeAliasCleanupVerified = $false
$wholeVolumeAliasDrive = ''
$wholeVolumeAliasTarget = ''
$rawAliasCases = [Collections.Generic.List[object]]::new()
$canonicalSystemDriveAccepted = $false
$rawAliasNativeProbeRejected = $false
$wholeVolumeAliasNativeProbeRejected = $false
$moduleLogicalDiskProbe = $null
try {
    [void](New-Item -ItemType Directory -Path $testRoot)
    [void](New-Item -ItemType Directory -Path $scopeCertificationCodexHome)

    $untrustedRoot = Join-Path $testRoot 'untrusted'
    [void](New-Item -ItemType Directory -Path $untrustedRoot)
    Copy-Item `
        -LiteralPath $installerSource `
        -Destination (Join-Path $untrustedRoot 'install-enterprise.ps1')
    Set-Content `
        -LiteralPath (Join-Path $untrustedRoot 'DefenseClawEnterprise.psm1') `
        -Value $maliciousModule `
        -Encoding UTF8
    Invoke-RejectedBootstrap `
        -InstallerPath (Join-Path $untrustedRoot 'install-enterprise.ps1') `
        -ExpectedError 'untrusted owner|replacement access|write-like access'
    Invoke-RejectedBootstrap `
        -InstallerPath (Join-Path $untrustedRoot 'install-enterprise.ps1') `
        -ExpectedError 'untrusted owner|replacement access|write-like access' `
        -InstallerArguments @(
            '-Action', 'Status',
            '-GatewayServiceName', $scopeGatewayService,
            '-GuardianServiceName', $scopeGuardianService,
            '-InstallRoot', $scopeInstallRoot,
            '-StateRoot', $scopeStateRoot,
            '-CertificationCodexHome', $scopeCertificationCodexHome,
            '-AllowUnsigned',
            '-Json'
        )
    Invoke-RejectedBootstrap `
        -InstallerPath (Join-Path $untrustedRoot 'install-enterprise.ps1') `
        -ExpectedError 'untrusted owner|replacement access|write-like access' `
        -PreloadFixedHelperSpoof
    Invoke-RejectedBootstrap `
        -InstallerPath (Join-Path $untrustedRoot 'install-enterprise.ps1') `
        -ExpectedError 'untrusted owner|replacement access|write-like access' `
        -InstallerArguments @(
            '-Action', 'Install',
            '-GatewayServiceName', $scopeGatewayService,
            '-GuardianServiceName', $scopeGuardianService,
            '-InstallRoot', $scopeInstallRoot,
            '-StateRoot', $scopeStateRoot,
            '-CertificationCodexHome', $scopeCertificationCodexHome,
            '-AllowUnsigned',
            '-AttestAgentApplicationControl',
            '-AttestClaudeEffectivePolicy',
            '-AttestCodexTrustedHookLauncher',
            '-CodexTrustedHookLauncherBinary', 'C:\approved\codex-fixed.exe',
            '-Json'
        )
    Invoke-RejectedBootstrap `
        -InstallerPath (Join-Path $untrustedRoot 'install-enterprise.ps1') `
        -ExpectedError 'untrusted owner|replacement access|write-like access' `
        -InstallerArguments @(
            '-Action', 'Install',
            '-GatewayServiceName', $scopeGatewayService,
            '-GuardianServiceName', $scopeGuardianService,
            '-InstallRoot', $scopeInstallRoot,
            '-StateRoot', $scopeStateRoot,
            '-CertificationCodexHome', $scopeCertificationCodexHome,
            '-AllowUnsigned',
            '-CoreHardeningCertification',
            '-Json'
        )
    Invoke-RejectedBootstrap `
        -InstallerPath (Join-Path $untrustedRoot 'install-enterprise.ps1') `
        -ExpectedError 'CoreHardeningCertification requires -AllowUnsigned and -CertificationCodexHome' `
        -InstallerArguments @(
            '-Action', 'Install',
            '-CoreHardeningCertification',
            '-Json'
        )
    Invoke-RejectedBootstrap `
        -InstallerPath (Join-Path $untrustedRoot 'install-enterprise.ps1') `
        -ExpectedError 'CoreHardeningCertification cannot be combined with production' `
        -InstallerArguments @(
            '-Action', 'Install',
            '-GatewayServiceName', $scopeGatewayService,
            '-GuardianServiceName', $scopeGuardianService,
            '-InstallRoot', $scopeInstallRoot,
            '-StateRoot', $scopeStateRoot,
            '-CertificationCodexHome', $scopeCertificationCodexHome,
            '-AllowUnsigned',
            '-CoreHardeningCertification',
            '-AttestAgentApplicationControl',
            '-Json'
        )
    Invoke-RejectedBootstrap `
        -InstallerPath (Join-Path $untrustedRoot 'install-enterprise.ps1') `
        -ExpectedError 'CoreHardeningCertification is valid only with Install, Upgrade, or Repair' `
        -InstallerArguments @(
            '-Action', 'Status',
            '-CoreHardeningCertification',
            '-Json'
        )
    Invoke-RejectedBootstrap `
        -InstallerPath (Join-Path $untrustedRoot 'install-enterprise.ps1') `
        -ExpectedError 'requires exact production roots' `
        -InstallerArguments @(
            '-Action', 'Status',
            '-GatewayServiceName', 'DefenseClawGateway',
            '-GuardianServiceName', 'DefenseClawHookGuardian',
            '-InstallRoot', $scopeInstallRoot,
            '-StateRoot', $productionStateRoot,
            '-Json'
        )
    Invoke-RejectedBootstrap `
        -InstallerPath (Join-Path $untrustedRoot 'install-enterprise.ps1') `
        -ExpectedError 'requires exact production service names' `
        -InstallerArguments @(
            '-Action', 'Status',
            '-GatewayServiceName', "DefenseClawGatewaySmoke_$scopeToken",
            '-GuardianServiceName', "DefenseClawGuardianSmoke_$scopeToken",
            '-InstallRoot', $productionInstallRoot,
            '-StateRoot', $productionStateRoot,
            '-Json'
        )
    Invoke-RejectedBootstrap `
        -InstallerPath (Join-Path $untrustedRoot 'install-enterprise.ps1') `
        -ExpectedError 'certification-scoped Install, Upgrade, or Repair requires -AllowUnsigned' `
        -InstallerArguments @(
            '-Action', 'Install',
            '-GatewayServiceName', $scopeGatewayService,
            '-GuardianServiceName', $scopeGuardianService,
            '-InstallRoot', $scopeInstallRoot,
            '-StateRoot', $scopeStateRoot,
            '-CertificationCodexHome', $scopeCertificationCodexHome,
            '-Json'
        )
    Invoke-RejectedBootstrap `
        -InstallerPath (Join-Path $untrustedRoot 'install-enterprise.ps1') `
        -ExpectedError '-AllowUnsigned is restricted to exact disposable' `
        -InstallerArguments @(
            '-Action', 'Install',
            '-AllowUnsigned',
            '-Json'
        )
    Invoke-RejectedBootstrap `
        -InstallerPath (Join-Path $untrustedRoot 'install-enterprise.ps1') `
        -ExpectedError 'certification services require exact run-scoped' `
        -InstallerArguments @(
            '-Action', 'Install',
            '-GatewayServiceName', $scopeGatewayService,
            '-GuardianServiceName', $scopeGuardianService,
            '-InstallRoot', "$scopeInstallRoot-near",
            '-StateRoot', $scopeStateRoot,
            '-CertificationCodexHome', $scopeCertificationCodexHome,
            '-AllowUnsigned',
            '-Json'
        )
    Invoke-RejectedBootstrap `
        -InstallerPath (Join-Path $untrustedRoot 'install-enterprise.ps1') `
        -ExpectedError 'certification services require exact run-scoped' `
        -InstallerArguments @(
            '-Action', 'Install',
            '-GatewayServiceName', $scopeGatewayService,
            '-GuardianServiceName', $scopeGuardianService,
            '-InstallRoot', $scopeInstallRoot,
            '-StateRoot', "$scopeStateRoot-near",
            '-CertificationCodexHome', $scopeCertificationCodexHome,
            '-AllowUnsigned',
            '-Json'
        )

    # A medium user can create a raw per-logon DOS-device alias without
    # SeCreateSymbolicLinkPrivilege. DriveInfo reports that alias as fixed
    # NTFS, and subst.exe does not enumerate it. Exercise the public bootstrap
    # in a child of this same logon so only authoritative mount-manager volume
    # identity can reject the redirected root.
    if (-not $effectiveMediumNonAdmin) {
        throw (
            'raw DOS-device bootstrap regression requires the executable ' +
            'test process to be an effective medium-integrity non-admin user'
        )
    }
    Initialize-RawDosDeviceInterop
    foreach ($candidate in @('Y:', 'X:', 'W:', 'V:', 'U:', 'T:', 'S:', 'R:')) {
        if ([string]::IsNullOrWhiteSpace(
                [DefenseClaw.Windows.Tests.RawDosDeviceNative]::TryQuery(
                    $candidate
                )
            ) -and
            -not (Test-Path -LiteralPath ($candidate + '\'))) {
            $rawAliasDrive = $candidate
            break
        }
    }
    if ([string]::IsNullOrWhiteSpace($rawAliasDrive)) {
        throw 'raw DOS-device bootstrap regression found no unused drive alias'
    }
    $rawAliasTargetDirectory = Join-Path $testRoot 'raw-dos-device-target'
    [void](New-Item -ItemType Directory -Path $rawAliasTargetDirectory)
    $sourceRoot = [IO.Path]::GetPathRoot(
        $rawAliasTargetDirectory
    )
    $sourceDrive = $sourceRoot.TrimEnd('\')
    $sourceDevice = [DefenseClaw.Windows.Tests.RawDosDeviceNative]::TryQuery(
        $sourceDrive
    )
    if ([string]::IsNullOrWhiteSpace($sourceDevice) -or
        $sourceDevice.StartsWith('\??\')) {
        throw 'raw DOS-device bootstrap fixture could not resolve its local source volume'
    }
    $sourceRelative = $rawAliasTargetDirectory.Substring(
        $sourceRoot.Length
    ).TrimStart('\')
    $rawAliasTarget = $sourceDevice.TrimEnd('\') + '\' + $sourceRelative
    [DefenseClaw.Windows.Tests.RawDosDeviceNative]::DefineRaw(
        $rawAliasDrive,
        $rawAliasTarget
    )
    $rawAliasDefined = $true
    $observedAliasTarget =
        [DefenseClaw.Windows.Tests.RawDosDeviceNative]::TryQuery(
            $rawAliasDrive
        )
    if (-not [string]::Equals(
            $observedAliasTarget,
            $rawAliasTarget,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw (
            'raw DOS-device bootstrap fixture did not create the exact ' +
            'per-logon alias'
        )
    }
    $rawAliasRoot = $rawAliasDrive + '\'
    $aliasDriveInfo = [IO.DriveInfo]::new($rawAliasRoot)
    if ($aliasDriveInfo.DriveType -ne [IO.DriveType]::Fixed -or
        -not [string]::Equals(
            $aliasDriveInfo.DriveFormat,
            'NTFS',
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'raw DOS-device alias did not reproduce the fixed-NTFS bypass precondition'
    }
    $productionNativePathType = Get-ProductionBootstrapNativePathType
    $productionNativePathType::AssertCanonicalDriveRoot(
        $sourceRoot,
        $sourceDrive
    )
    $canonicalSystemDriveAccepted = $true
    try {
        $productionNativePathType::AssertCanonicalDriveRoot(
            $rawAliasRoot,
            $rawAliasDrive
        )
        throw 'production bootstrap native probe accepted a raw DOS-device alias'
    }
    catch {
        if ($_.Exception.Message -notmatch (
                'GetVolumeNameForVolumeMountPoint|authoritative volume|' +
                'Mount Manager|canonical DOS drive root'
            )) {
            throw
        }
        $rawAliasNativeProbeRejected = $true
    }
    foreach ($candidate in @('X:', 'W:', 'V:', 'U:', 'T:', 'S:', 'R:', 'Q:')) {
        if (-not [string]::Equals(
                $candidate,
                $rawAliasDrive,
                [StringComparison]::OrdinalIgnoreCase
            ) -and
            [string]::IsNullOrWhiteSpace(
                [DefenseClaw.Windows.Tests.RawDosDeviceNative]::TryQuery(
                    $candidate
                )
            ) -and
            -not (Test-Path -LiteralPath ($candidate + '\'))) {
            $wholeVolumeAliasDrive = $candidate
            break
        }
    }
    if ([string]::IsNullOrWhiteSpace($wholeVolumeAliasDrive)) {
        throw 'whole-volume DOS-device regression found no second unused drive alias'
    }
    $wholeVolumeAliasTarget = $sourceDevice
    [DefenseClaw.Windows.Tests.RawDosDeviceNative]::DefineRaw(
        $wholeVolumeAliasDrive,
        $wholeVolumeAliasTarget
    )
    $wholeVolumeAliasDefined = $true
    $observedWholeVolumeTarget =
        [DefenseClaw.Windows.Tests.RawDosDeviceNative]::TryQuery(
            $wholeVolumeAliasDrive
        )
    if (-not [string]::Equals(
            $observedWholeVolumeTarget,
            $wholeVolumeAliasTarget,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'whole-volume DOS-device fixture did not create the exact alias'
    }
    $wholeVolumeAliasRoot = $wholeVolumeAliasDrive + '\'
    $wholeVolumeDriveInfo = [IO.DriveInfo]::new($wholeVolumeAliasRoot)
    if ($wholeVolumeDriveInfo.DriveType -ne [IO.DriveType]::Fixed -or
        -not [string]::Equals(
            $wholeVolumeDriveInfo.DriveFormat,
            'NTFS',
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'whole-volume DOS-device alias did not appear as fixed NTFS'
    }
    try {
        $productionNativePathType::AssertCanonicalDriveRoot(
            $wholeVolumeAliasRoot,
            $wholeVolumeAliasDrive
        )
        throw 'production bootstrap native probe accepted a whole-volume alias'
    }
    catch {
        if ($_.Exception.Message -notmatch (
                'QueryDosDevice failed for Global|authoritative volume|' +
                'Mount Manager|canonical DOS drive root'
            )) {
            throw
        }
        $wholeVolumeAliasNativeProbeRejected = $true
    }
    $moduleLogicalDiskProbe =
        Invoke-ProductionModuleLogicalDiskAliasProbe `
            -NormalDrive $sourceDrive `
            -AliasDrives @($rawAliasDrive, $wholeVolumeAliasDrive)
    if (-not [bool]$moduleLogicalDiskProbe.canonical_system_drive_accepted -or
        @($moduleLogicalDiskProbe.rejected_aliases).Count -ne 2 -or
        [string]$moduleLogicalDiskProbe.rejected_aliases[0] -cne
            $rawAliasDrive -or
        [string]$moduleLogicalDiskProbe.rejected_aliases[1] -cne
            $wholeVolumeAliasDrive) {
        throw 'production module logical-disk raw-alias evidence is incomplete'
    }
    $aliasBootstrapDirectory = Join-Path $rawAliasRoot 'bootstrap'
    $aliasBootstrapPhysicalDirectory = Join-Path `
        $rawAliasTargetDirectory `
        'bootstrap'
    [void](New-Item -ItemType Directory -Path $aliasBootstrapDirectory)
    Copy-Item `
        -LiteralPath $installerSource `
        -Destination (
            Join-Path $aliasBootstrapDirectory 'install-enterprise.ps1'
        )
    Set-Content `
        -LiteralPath (
            Join-Path $aliasBootstrapDirectory 'DefenseClawEnterprise.psm1'
        ) `
        -Value $maliciousModule `
        -Encoding UTF8
    $wholeVolumeAliasBootstrapDirectory = Join-Path `
        $wholeVolumeAliasRoot `
        $aliasBootstrapPhysicalDirectory.Substring($sourceRoot.Length)
    $wholeVolumeAliasInstaller = Join-Path `
        $wholeVolumeAliasBootstrapDirectory `
        'install-enterprise.ps1'
    $aliasCertificationHome = Join-Path `
        $rawAliasRoot `
        ".codex-defenseclaw-cert-$scopeToken"
    [void](New-Item -ItemType Directory -Path $aliasCertificationHome)
    $rawAliasInventoryBefore = @(
        Get-RawAliasFixtureInventory $rawAliasRoot
    )
    foreach ($case in @(
        [pscustomobject]@{
            name = 'installer_module_path'
            installer_path = Join-Path `
                $aliasBootstrapDirectory `
                'install-enterprise.ps1'
            install_root = $scopeInstallRoot
            state_root = $scopeStateRoot
            certification_home = $scopeCertificationCodexHome
            expected_error = (
                'GetVolumeNameForVolumeMountPoint|authoritative volume|' +
                'Mount Manager|canonical DOS drive root'
            )
        },
        [pscustomobject]@{
            name = 'whole_volume_installer_module_path'
            installer_path = $wholeVolumeAliasInstaller
            install_root = $scopeInstallRoot
            state_root = $scopeStateRoot
            certification_home = $scopeCertificationCodexHome
            expected_error = (
                'QueryDosDevice failed for Global|authoritative volume|' +
                'Mount Manager|canonical DOS drive root'
            )
        },
        [pscustomobject]@{
            name = 'install_root'
            installer_path = $installerSource
            install_root = Join-Path $rawAliasRoot 'install'
            state_root = $scopeStateRoot
            certification_home = $aliasCertificationHome
            expected_error = 'certification services require exact run-scoped'
        },
        [pscustomobject]@{
            name = 'state_root'
            installer_path = $installerSource
            install_root = $scopeInstallRoot
            state_root = Join-Path $rawAliasRoot 'state'
            certification_home = $aliasCertificationHome
            expected_error = 'certification services require exact run-scoped'
        },
        [pscustomobject]@{
            name = 'certification_home'
            installer_path = $installerSource
            install_root = $scopeInstallRoot
            state_root = $scopeStateRoot
            certification_home = $aliasCertificationHome
            expected_error = (
                'GetVolumeNameForVolumeMountPoint|canonical|mount-manager|' +
                'DOS.device|volume root|redirection'
            )
        }
    )) {
        Invoke-RejectedBootstrap `
            -InstallerPath ([string]$case.installer_path) `
            -ExpectedError ([string]$case.expected_error) `
            -InstallerArguments @(
                '-Action', 'Install',
                '-GatewayServiceName', $scopeGatewayService,
                '-GuardianServiceName', $scopeGuardianService,
                '-InstallRoot', ([string]$case.install_root),
                '-StateRoot', ([string]$case.state_root),
                '-CertificationCodexHome', ([string]$case.certification_home),
                '-AllowUnsigned',
                '-Json'
            )
        foreach ($unexpectedRoot in @(
            $scopeInstallRoot,
            $scopeStateRoot,
            (Join-Path $rawAliasRoot 'install'),
            (Join-Path $rawAliasRoot 'state')
        )) {
            if (Test-Path -LiteralPath $unexpectedRoot) {
                throw (
                    "raw DOS-device $($case.name) rejection created a " +
                    "managed root: $unexpectedRoot"
                )
            }
        }
        $rawAliasCases.Add([pscustomobject]@{
            name = [string]$case.name
            rejected_before_module_import = $true
            managed_roots_absent = $true
        })
    }
    $rawAliasInventoryAfter = @(
        Get-RawAliasFixtureInventory $rawAliasRoot
    )
    if (($rawAliasInventoryBefore | ConvertTo-Json -Compress -Depth 5) -cne
        ($rawAliasInventoryAfter | ConvertTo-Json -Compress -Depth 5)) {
        throw (
            'raw DOS-device bootstrap rejection changed its medium-user ' +
            'fixture or left temporary content'
        )
    }

    # Directory junctions do not require SeCreateSymbolicLinkPrivilege. Running
    # the copied installer through one proves an ancestor reparse is rejected
    # before the adjacent module can execute.
    $junctionTarget = Join-Path $testRoot 'junction-target'
    $junctionPath = Join-Path $testRoot 'junction'
    [void](New-Item -ItemType Directory -Path $junctionTarget)
    Copy-Item `
        -LiteralPath $installerSource `
        -Destination (Join-Path $junctionTarget 'install-enterprise.ps1')
    Set-Content `
        -LiteralPath (Join-Path $junctionTarget 'DefenseClawEnterprise.psm1') `
        -Value $maliciousModule `
        -Encoding UTF8
    try {
        [void](New-Item -ItemType Junction -Path $junctionPath -Target $junctionTarget)
        Invoke-RejectedBootstrap `
            -InstallerPath (Join-Path $junctionPath 'install-enterprise.ps1') `
            -ExpectedError 'reparse point'
        $junctionExecuted = $true
    }
    catch {
        if ($_.Exception.Message -match 'privilege|not supported|cannot find|reparse') {
            throw
        }
        throw
    }
}
finally {
    $rawAliasCleanupErrors = [Collections.Generic.List[string]]::new()
    if ($wholeVolumeAliasDefined) {
        try {
            $wholeVolumeAliasCleanupVerified =
                Remove-RawDosDeviceFixtureAlias `
                    -Drive $wholeVolumeAliasDrive `
                    -Target $wholeVolumeAliasTarget
            $wholeVolumeAliasDefined = $false
        }
        catch {
            $rawAliasCleanupErrors.Add(
                'whole-volume alias cleanup failed: ' +
                $_.Exception.Message
            )
        }
    }
    if ($rawAliasDefined) {
        try {
            $rawAliasCleanupVerified =
                Remove-RawDosDeviceFixtureAlias `
                    -Drive $rawAliasDrive `
                    -Target $rawAliasTarget
            $rawAliasDefined = $false
        }
        catch {
            $rawAliasCleanupErrors.Add(
                'subdirectory alias cleanup failed: ' +
                $_.Exception.Message
            )
        }
    }
    $fullTestRoot = [IO.Path]::GetFullPath($testRoot).TrimEnd('\')
    $fullTempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
    if (-not $fullTestRoot.StartsWith(
        $fullTempRoot + '\',
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "refusing to clean bootstrap fixture outside the temporary root: $fullTestRoot"
    }
    if (Test-Path -LiteralPath $fullTestRoot) {
        Remove-Item -LiteralPath $fullTestRoot -Recurse -Force
    }
    $fullCertificationHome = [IO.Path]::GetFullPath(
        $scopeCertificationCodexHome
    ).TrimEnd('\')
    if (-not [string]::Equals(
        [IO.Path]::GetDirectoryName($fullCertificationHome).TrimEnd('\'),
        $fullTempRoot,
        [StringComparison]::OrdinalIgnoreCase
    ) -or
        [IO.Path]::GetFileName($fullCertificationHome) -cne
            ".codex-defenseclaw-cert-$scopeToken") {
        throw "refusing to clean unexpected certification CODEX_HOME fixture: $fullCertificationHome"
    }
    if (Test-Path -LiteralPath $fullCertificationHome) {
        Remove-Item -LiteralPath $fullCertificationHome -Recurse -Force
    }
    if ($rawAliasCleanupErrors.Count -ne 0) {
        throw ($rawAliasCleanupErrors -join '; ')
    }
}

$reportJson = [pscustomobject]@{
    schema_version = 1
    ok = $true
    engine = $PSVersionTable.PSVersion.ToString()
    untrusted_module_rejected_before_import = $true
    fixed_helper_spoof_ignored = $true
    reparse_ancestor_rejected_before_import = $junctionExecuted
    exact_unsigned_scope_reached_bootstrap_trust = $true
    production_unsigned_scope_rejected_before_import = $true
    near_miss_unsigned_roots_rejected_before_import = $true
    signed_custom_roots_rejected_before_import = $true
    signed_custom_service_names_rejected_before_import = $true
    certification_mutation_requires_unsigned_before_import = $true
    raw_dos_device_medium_user = $true
    raw_dos_device_cases = @($rawAliasCases.ToArray())
    raw_dos_device_rejected_before_import = (
        $rawAliasCases.Count -eq 5
    )
    canonical_system_drive_accepted = $canonicalSystemDriveAccepted
    raw_dos_device_native_probe_rejected = $rawAliasNativeProbeRejected
    whole_volume_alias_native_probe_rejected =
        $wholeVolumeAliasNativeProbeRejected
    whole_volume_alias_cleanup_verified =
        $wholeVolumeAliasCleanupVerified
    module_canonical_system_drive_accepted =
        [bool]$moduleLogicalDiskProbe.canonical_system_drive_accepted
    module_raw_subdirectory_alias_rejected = (
        [string]$moduleLogicalDiskProbe.rejected_aliases[0] -cne ''
    )
    module_raw_whole_volume_alias_rejected = (
        [string]$moduleLogicalDiskProbe.rejected_aliases[1] -cne ''
    )
    raw_dos_device_no_roots_or_temp = $true
    raw_dos_device_cleanup_verified = $rawAliasCleanupVerified
} | ConvertTo-Json -Compress
if (-not [string]::IsNullOrWhiteSpace($BasicUserResultPath)) {
    Write-BasicUserResult -Json $reportJson
    exit 0
}
Write-Output $reportJson
