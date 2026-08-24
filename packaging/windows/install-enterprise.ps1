# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# Production interactive administrators enter through the signed defenseclaw
# CLI. That launcher supplies a strict environment before PowerShell/CLR
# startup; a script cannot retroactively neutralize profiler, startup-hook, or
# loader variables already consumed by its host process. Direct invocation of
# this file is therefore supported only from a trusted LocalSystem endpoint-
# management startup context. The one-shot isolation below protects all
# compiler and module-analysis activity after script execution begins.

[CmdletBinding()]
param(
    [ValidateSet('Install', 'Upgrade', 'Repair', 'Reconcile', 'Status', 'Verify', 'Uninstall')]
    [string]$Action = 'Install',

    [string]$BrokerBinary,
    [string]$ProviderLibrary,
    [string]$GatewayBinary,
    [string]$HookBinary,
    [string]$CLIBinary,
    [string]$Config,
    [string]$Manifest,

    # QA-friendly shorthand: when -Mode + -Connector are supplied and
    # -Config / -Manifest are empty, the installer renders a minimal
    # managed_enterprise config.yaml and per-user targets.yaml into the
    # protected bootstrap staging directory before the module import,
    # then continues the lifecycle as if those paths had been supplied
    # directly. Mirrors the macOS install.sh --mode/--connector
    # shorthand and the render_config / render_targets_manifest helpers
    # in packaging/macos/lib/installer_lib.sh.
    #
    # -Mode is passed verbatim to guardrail.mode; -Connector is a
    # comma-separated list whose first entry becomes guardrail.connector
    # (primary) and every entry becomes both a targets.yaml row (one per
    # eligible interactive-user profile) and a guardrail.connectors map
    # entry. Both are mutually exclusive with -Config / -Manifest and
    # with -DeferredConfig.
    [ValidateSet('', 'observe', 'action')]
    [string]$Mode = '',
    [string]$Connector = '',

    [string]$InstallRoot,
    [string]$StateRoot,
    [string]$GatewayServiceName = 'DefenseClawGateway',
    [string]$GuardianServiceName = 'DefenseClawHookGuardian',
    [string]$CertificationCodexHome,
    [switch]$CoreHardeningCertification,

    [switch]$NoStart,
    [switch]$Purge,
    [switch]$AllowUnsigned,
    [switch]$AttestAgentApplicationControl,
    [switch]$AttestClaudeEffectivePolicy,
    # Retained for command-line compatibility, but rejected before bootstrap
    # creation until late config publication can authenticate and prepare all
    # enrolled user runtimes before any service activation.
    [switch]$DeferredConfig,
    [int]$SelfUninstallCallerPID,
    [switch]$Json
)

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-DefenseClawTrustedMachineRoot {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Label
    )
    if ([string]::IsNullOrWhiteSpace($Value) -or
        $Value -match '[\x00-\x1f%]' -or
        -not [IO.Path]::IsPathRooted($Value)) {
        throw "trusted $Label root is empty, relative, or contains an invalid character"
    }
    $full = [IO.Path]::GetFullPath($Value).TrimEnd('\')
    $driveRoot = [IO.Path]::GetPathRoot($full)
    if ([string]::IsNullOrWhiteSpace($driveRoot) -or
        $driveRoot -notmatch '^[A-Za-z]:\\$' -or
        $full.StartsWith('\\') -or
        $full.StartsWith('//') -or
        $full.StartsWith('\\?\') -or
        $full.StartsWith('\\.\') -or
        -not [IO.Directory]::Exists($full)) {
        throw "trusted $Label root is not an existing canonical local directory: $full"
    }
    return $full
}

function Get-DefenseClawTrustedMachineRoots {
    # Environment.GetFolderPath can return an empty string when PowerShell is
    # launched with the deliberately reduced native-bootstrap environment.
    # Resolve machine roots from fixed HKLM registration plus the Win32-backed
    # Environment.SystemDirectory property, without consulting process HOME,
    # profile, ProgramFiles, ProgramData, SystemRoot, or windir variables.
    $windows = ConvertTo-DefenseClawTrustedMachineRoot `
        -Value ([IO.Path]::GetDirectoryName([Environment]::SystemDirectory)) `
        -Label 'Windows'
    $base = $null
    $shell = $null
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Registry64
        )
        $currentVersion = $base.OpenSubKey(
            'SOFTWARE\Microsoft\Windows\CurrentVersion',
            $false
        )
        if ($null -eq $currentVersion) {
            throw 'trusted Program Files machine registration is missing'
        }
        try {
            $programFilesRaw = [string]$currentVersion.GetValue(
                'ProgramFilesDir',
                $null,
                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
            )
        } finally {
            $currentVersion.Dispose()
        }
        $shell = $base.OpenSubKey(
            'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
            $false
        )
        if ($null -eq $shell) {
            throw 'trusted ProgramData machine registration is missing'
        }
        $programDataRaw = [string]$shell.GetValue(
            'Common AppData',
            $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        )
    } finally {
        if ($null -ne $shell) { $shell.Dispose() }
        if ($null -ne $base) { $base.Dispose() }
    }
    return [pscustomobject]@{
        Windows = $windows
        ProgramFiles = ConvertTo-DefenseClawTrustedMachineRoot `
            -Value $programFilesRaw `
            -Label 'Program Files'
        ProgramData = ConvertTo-DefenseClawTrustedMachineRoot `
            -Value $programDataRaw `
            -Label 'ProgramData'
    }
}

$trustedMachineRoots = Get-DefenseClawTrustedMachineRoots
$trustedWindows = [string]$trustedMachineRoots.Windows
$trustedProgramFiles = [string]$trustedMachineRoots.ProgramFiles
$trustedProgramData = [string]$trustedMachineRoots.ProgramData
$InstallRoot = if ([string]::IsNullOrWhiteSpace($InstallRoot)) {
    [IO.Path]::Combine(
        $trustedProgramFiles,
        'Cisco\Cisco Secure Client\DefenseClaw'
    )
} else { $InstallRoot }
$StateRoot = if ([string]::IsNullOrWhiteSpace($StateRoot)) {
    [IO.Path]::Combine(
        $trustedProgramData,
        'Cisco\Cisco Secure Client\DefenseClaw'
    )
} else { $StateRoot }
$trustedSystem32 = [IO.Path]::Combine($trustedWindows, 'System32')
[Environment]::SetEnvironmentVariable('SystemRoot', $trustedWindows, 'Process')
[Environment]::SetEnvironmentVariable('windir', $trustedWindows, 'Process')
[Environment]::SetEnvironmentVariable('ProgramFiles', $trustedProgramFiles, 'Process')
[Environment]::SetEnvironmentVariable('ProgramData', $trustedProgramData, 'Process')
# Pin module resolution to the running engine's own module directory so an
# ambient PSModulePath cannot inject a substitute module.
$trustedEngineModules = [IO.Path]::Combine($PSHOME, 'Modules')
if (-not [IO.Directory]::Exists($trustedEngineModules)) {
    throw "trusted engine module directory is missing: $trustedEngineModules"
}
[Environment]::SetEnvironmentVariable('PSModulePath', $trustedEngineModules, 'Process')
[Environment]::SetEnvironmentVariable(
    'PATH',
    (@(
        $trustedSystem32,
        $trustedWindows,
        ([IO.Path]::Combine($trustedSystem32, 'Wbem')),
        ([IO.Path]::Combine($trustedSystem32, 'WindowsPowerShell\v1.0'))
    ) -join [IO.Path]::PathSeparator),
    'Process'
)

$script:DefenseClawBootstrapPathProbe = $null

function Initialize-DefenseClawBootstrapNativePath {
    if ($null -ne $script:DefenseClawBootstrapPathProbe) {
        return $script:DefenseClawBootstrapPathProbe
    }
    # Add-Type is reached only after New-DefenseClawBootstrapEnvironment has
    # pinned every compiler/cache/home path to a capability-named protected
    # directory. The unpredictable namespace also prevents an ambient session
    # from preloading a class with the name trusted by this invocation.
    $nativeNamespace =
        'DefenseClaw.Windows.Bootstrap_' + [Guid]::NewGuid().ToString('N')
    $compiledTypes = @(Microsoft.PowerShell.Utility\Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace $nativeNamespace
{
    public static class NativePath
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern uint GetDriveTypeW(string rootPathName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetVolumeInformationW(
            string rootPathName,
            StringBuilder volumeName,
            int volumeNameSize,
            out uint volumeSerialNumber,
            out uint maximumComponentLength,
            out uint fileSystemFlags,
            StringBuilder fileSystemName,
            int fileSystemNameSize);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetVolumeNameForVolumeMountPointW(
            string volumeMountPoint,
            StringBuilder volumeName,
            int bufferLength);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetVolumePathNamesForVolumeNameW(
            string volumeName,
            [Out] char[] volumePathNames,
            uint bufferLength,
            out uint returnLength);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint QueryDosDeviceW(
            string deviceName,
            [Out] char[] targetPath,
            int maximumLength);

        private static string QueryDevice(string deviceName)
        {
            char[] target = new char[32768];
            uint length = QueryDosDeviceW(deviceName, target, target.Length);
            if (length == 0)
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "QueryDosDevice failed for " + deviceName);
            List<string> targets = ParseMultiString(
                target,
                checked((int)length),
                "QueryDosDevice " + deviceName);
            if (targets.Count != 1 ||
                String.IsNullOrEmpty(targets[0]) ||
                !targets[0].StartsWith(
                    @"\Device\",
                    StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(
                    "QueryDosDevice returned a malformed or multi-target mapping for " +
                    deviceName);
            return targets[0];
        }

        private static List<string> ParseMultiString(
            char[] buffer,
            int length,
            string operation)
        {
            if (length <= 0 || length > buffer.Length)
                throw new InvalidOperationException(
                    operation + " returned an invalid length");
            List<string> values = new List<string>();
            int start = 0;
            bool terminated = false;
            for (int index = 0; index < length; index++)
            {
                if (buffer[index] != '\0')
                    continue;
                if (index == start)
                {
                    terminated = true;
                    break;
                }
                values.Add(new string(buffer, start, index - start));
                start = index + 1;
            }
            if (!terminated || values.Count == 0)
                throw new InvalidOperationException(
                    operation + " returned a malformed MULTI_SZ value");
            return values;
        }

        public static uint GetDriveType(string root)
        {
            return GetDriveTypeW(root);
        }

        public static string GetFileSystem(string root)
        {
            StringBuilder volume = new StringBuilder(261);
            StringBuilder fileSystem = new StringBuilder(261);
            uint serial;
            uint maximumComponentLength;
            uint flags;
            if (!GetVolumeInformationW(
                root,
                volume,
                volume.Capacity,
                out serial,
                out maximumComponentLength,
                out flags,
                fileSystem,
                fileSystem.Capacity))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "GetVolumeInformation failed for " + root);
            return fileSystem.ToString();
        }

        public static void AssertCanonicalDriveRoot(string root, string drive)
        {
            if (String.IsNullOrEmpty(root) ||
                root.Length != 3 ||
                !Char.IsLetter(root[0]) ||
                root[1] != ':' ||
                root[2] != '\\' ||
                !String.Equals(
                    drive,
                    root.Substring(0, 2),
                    StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(
                    "bootstrap path root is not a canonical DOS drive root: " + root);

            StringBuilder volumeName = new StringBuilder(261);
            if (!GetVolumeNameForVolumeMountPointW(
                root,
                volumeName,
                volumeName.Capacity))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "GetVolumeNameForVolumeMountPoint failed for " + root);
            string volume = volumeName.ToString();
            if (!volume.StartsWith(
                    @"\\?\Volume{",
                    StringComparison.OrdinalIgnoreCase) ||
                !volume.EndsWith(@"}\", StringComparison.Ordinal) ||
                volume.Length <= 13)
                throw new InvalidOperationException(
                    "bootstrap path volume identity is not canonical: " + volume);
            Guid volumeGuid;
            string volumeGuidText =
                volume.Substring(11, volume.Length - 13);
            if (!Guid.TryParseExact(volumeGuidText, "D", out volumeGuid) ||
                !String.Equals(
                    volume,
                    @"\\?\Volume{" + volumeGuid.ToString("D") + @"}\",
                    StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(
                    "bootstrap path volume GUID identity is malformed: " + volume);

            string volumeDeviceName =
                volume.Substring(4, volume.Length - 5);
            string driveTarget = QueryDevice(drive);
            string globalDriveTarget = QueryDevice(@"Global\" + drive);
            string volumeTarget = QueryDevice(volumeDeviceName);
            if (!String.Equals(
                    driveTarget,
                    globalDriveTarget,
                    StringComparison.OrdinalIgnoreCase) ||
                !String.Equals(
                    driveTarget,
                    volumeTarget,
                    StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(
                    "bootstrap DOS drive target differs from its global authoritative volume");

            char[] paths = new char[32768];
            uint required;
            if (!GetVolumePathNamesForVolumeNameW(
                volume,
                paths,
                (uint)paths.Length,
                out required))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "GetVolumePathNamesForVolumeName failed for " + volume);

            List<string> mountPaths = ParseMultiString(
                paths,
                checked((int)required),
                "GetVolumePathNamesForVolumeName " + volume);
            int rootMatches = 0;
            foreach (string path in mountPaths)
            {
                if (String.Equals(path, root, StringComparison.OrdinalIgnoreCase))
                    rootMatches++;
            }
            if (rootMatches != 1)
                throw new InvalidOperationException(
                    "bootstrap DOS drive root is not registered with Mount Manager");
        }
    }
}
"@ -Language CSharp -PassThru -ErrorAction Stop)
    $expectedTypeName = "$nativeNamespace.NativePath"
    $nativeType = @(
        $compiledTypes | Microsoft.PowerShell.Core\Where-Object {
            $_.FullName -ceq $expectedTypeName
        }
    )
    if ($nativeType.Count -ne 1) {
        throw "could not bind exact generated bootstrap native path type $expectedTypeName"
    }
    $script:DefenseClawBootstrapPathProbe = $nativeType[0]
    return $script:DefenseClawBootstrapPathProbe
}

function Assert-DefenseClawBootstrapUnsignedCertificationScope {
    param(
        [Parameter(Mandatory)][string]$LifecycleAction,
        [Parameter(Mandatory)][string]$RequestedInstallRoot,
        [Parameter(Mandatory)][string]$RequestedStateRoot,
        [Parameter(Mandatory)][string]$RequestedGatewayServiceName,
        [Parameter(Mandatory)][string]$RequestedGuardianServiceName,
        [string]$RequestedCertificationCodexHome
    )
    $prefix = '-AllowUnsigned is restricted to exact disposable DefenseClaw certification scope'
    if ($LifecycleAction -notin @(
        'Install',
        'Upgrade',
        'Repair',
        'Reconcile',
        'Status',
        'Verify',
        'Uninstall'
    )) {
        throw "$prefix; action is outside the enterprise lifecycle"
    }
    if ($RequestedGatewayServiceName -cnotmatch '^DefenseClawCertGateway_([a-f0-9]{10})$') {
        throw "$prefix; gateway service name is outside the certification namespace"
    }
    $runID = [string]$Matches[1]
    $expectedGuardian = "DefenseClawCertGuardian_$runID"
    if ($RequestedGuardianServiceName -cne $expectedGuardian) {
        throw "$prefix; guardian service name must be exactly $expectedGuardian"
    }

    foreach ($entry in @(
        @('InstallRoot', $RequestedInstallRoot),
        @('StateRoot', $RequestedStateRoot),
        @('CertificationCodexHome', $RequestedCertificationCodexHome)
    )) {
        if ([string]::IsNullOrWhiteSpace([string]$entry[1]) -or
            ([string]$entry[1]).Contains('"') -or
            ([string]$entry[1]) -match '[\x00-\x1f]') {
            throw "$prefix; $($entry[0]) is empty or invalid"
        }
    }

    $install = [IO.Path]::GetFullPath($RequestedInstallRoot).TrimEnd('\')
    $state = [IO.Path]::GetFullPath($RequestedStateRoot).TrimEnd('\')
    $expectedInstall = [IO.Path]::Combine(
        $trustedProgramFiles,
        'Cisco',
        'Cisco Secure Client',
        'DefenseClaw-Cert',
        $runID
    ).TrimEnd('\')
    $expectedState = [IO.Path]::Combine(
        $trustedProgramData,
        'Cisco',
        'Cisco Secure Client',
        'DefenseClaw-Cert',
        $runID
    ).TrimEnd('\')
    if (-not [string]::Equals(
        $install,
        $expectedInstall,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "$prefix; InstallRoot must be exactly $expectedInstall"
    }
    if (-not [string]::Equals(
        $state,
        $expectedState,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "$prefix; StateRoot must be exactly $expectedState"
    }

    $certificationHome = [IO.Path]::GetFullPath(
        $RequestedCertificationCodexHome
    ).TrimEnd('\')
    if (-not [IO.Path]::IsPathRooted($certificationHome) -or
        $certificationHome.StartsWith('\\') -or
        $certificationHome.StartsWith('//') -or
        $certificationHome.StartsWith('\\?\') -or
        $certificationHome.StartsWith('\\.\') -or
        ($certificationHome.Length -gt 2 -and
            $certificationHome.Substring(2).Contains(':')) -or
        [IO.Path]::GetFileName($certificationHome) -cne
            ".codex-defenseclaw-cert-$runID") {
        throw "$prefix; CertificationCodexHome must be the exact local run-scoped directory"
    }
    $certificationHomeExists = Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $certificationHome `
        -PathType Container
    $allowMissingCertificationHome = $LifecycleAction -in @(
        'Status',
        'Verify'
    )
    if (-not $certificationHomeExists -and
        -not $allowMissingCertificationHome) {
        throw "$prefix; CertificationCodexHome must be an existing directory"
    }
    if ((Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $certificationHome) -and
        -not $certificationHomeExists) {
        throw "$prefix; CertificationCodexHome must be a directory when present"
    }

    $nativePathType = Initialize-DefenseClawBootstrapNativePath
    $driveRoot = [IO.Path]::GetPathRoot($certificationHome)
    $driveID = $driveRoot.TrimEnd('\')
    $driveType = $nativePathType::GetDriveType($driveRoot)
    $fileSystem = $nativePathType::GetFileSystem($driveRoot)
    $nativePathType::AssertCanonicalDriveRoot($driveRoot, $driveID)
    if ([int]$driveType -ne 3 -or
        -not [string]::Equals(
            $fileSystem,
            'NTFS',
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "$prefix; CertificationCodexHome must be on local fixed NTFS without redirection"
    }
    $current = if ($certificationHomeExists) {
        $certificationHome
    }
    else {
        [IO.Path]::GetDirectoryName($certificationHome)
    }
    while (-not [string]::IsNullOrWhiteSpace($current)) {
        $item = Microsoft.PowerShell.Management\Get-Item `
            -LiteralPath $current `
            -Force `
            -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$prefix; CertificationCodexHome path contains a reparse point: $current"
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrWhiteSpace($parent) -or
            $parent.Equals($current, [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $current = $parent
    }
    # Recheck at the last use boundary so a per-logon DOS device cannot be
    # retargeted between the initial volume authorization and path traversal.
    $nativePathType::AssertCanonicalDriveRoot($driveRoot, $driveID)
}

function Assert-DefenseClawBootstrapLifecycleScope {
    param(
        [Parameter(Mandatory)][string]$LifecycleAction,
        [Parameter(Mandatory)][string]$RequestedInstallRoot,
        [Parameter(Mandatory)][string]$RequestedStateRoot,
        [Parameter(Mandatory)][string]$RequestedGatewayServiceName,
        [Parameter(Mandatory)][string]$RequestedGuardianServiceName,
        [bool]$AllowUnsignedLifecycle
    )
    $install = [IO.Path]::GetFullPath($RequestedInstallRoot).TrimEnd('\')
    $state = [IO.Path]::GetFullPath($RequestedStateRoot).TrimEnd('\')
    $certificationMatch = [Text.RegularExpressions.Regex]::Match(
        $RequestedGatewayServiceName,
        '^DefenseClawCertGateway_([a-f0-9]{10})$',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if ($certificationMatch.Success) {
        $runID = [string]$certificationMatch.Groups[1].Value
        $expectedGuardian = "DefenseClawCertGuardian_$runID"
        if ($RequestedGuardianServiceName -cne $expectedGuardian) {
            throw (
                'certification service names must use the same exact run ' +
                "identifier; guardian must be $expectedGuardian"
            )
        }
        $expectedInstall = [IO.Path]::Combine(
            $trustedProgramFiles,
            'Cisco',
            'Cisco Secure Client',
            'DefenseClaw-Cert',
            $runID
        ).TrimEnd('\')
        $expectedState = [IO.Path]::Combine(
            $trustedProgramData,
            'Cisco',
            'Cisco Secure Client',
            'DefenseClaw-Cert',
            $runID
        ).TrimEnd('\')
        if (-not [string]::Equals(
                $install,
                $expectedInstall,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            -not [string]::Equals(
                $state,
                $expectedState,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw (
                'certification services require exact run-scoped managed ' +
                "roots: $expectedInstall ; $expectedState"
            )
        }
        if ($LifecycleAction -in @('Install', 'Upgrade', 'Repair') -and
            -not $AllowUnsignedLifecycle) {
            throw (
                'certification-scoped Install, Upgrade, or Repair requires ' +
                '-AllowUnsigned'
            )
        }
        return
    }
    if ($RequestedGuardianServiceName -cmatch
        '^DefenseClawCertGuardian_[a-f0-9]{10}$') {
        throw 'certification guardian service requires its exact certification gateway peer'
    }
    if ($RequestedGatewayServiceName -cne 'DefenseClawGateway' -or
        $RequestedGuardianServiceName -cne 'DefenseClawHookGuardian') {
        throw (
            'non-certification enterprise lifecycle requires exact ' +
            'production service names: DefenseClawGateway ; ' +
            'DefenseClawHookGuardian'
        )
    }
    $expectedInstall = [IO.Path]::Combine(
        $trustedProgramFiles,
        'Cisco',
        'Cisco Secure Client',
        'DefenseClaw'
    ).TrimEnd('\')
    $expectedState = [IO.Path]::Combine(
        $trustedProgramData,
        'Cisco',
        'Cisco Secure Client',
        'DefenseClaw'
    ).TrimEnd('\')
    if (-not [string]::Equals(
            $install,
            $expectedInstall,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            $state,
            $expectedState,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw (
            'non-certification enterprise lifecycle requires exact ' +
            "production roots: $expectedInstall ; $expectedState"
        )
    }
}

function ConvertTo-DefenseClawBootstrapSID {
    param([Parameter(Mandatory)]$Identity)
    if ($Identity -is [Security.Principal.SecurityIdentifier]) {
        return $Identity.Value
    }
    $text = [string]$Identity
    if ($text.StartsWith('S-', [StringComparison]::OrdinalIgnoreCase)) {
        return [Security.Principal.SecurityIdentifier]::new($text).Value
    }
    try {
        return [Security.Principal.NTAccount]::new($text).Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
    }
    catch {
        return "UNRESOLVED:$text"
    }
}

function Test-DefenseClawBootstrapReplacementRights {
    param([Parameter(Mandatory)][Security.AccessControl.FileSystemRights]$Rights)
    $replacement = [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles `
        -bor [Security.AccessControl.FileSystemRights]::Delete `
        -bor [Security.AccessControl.FileSystemRights]::ChangePermissions `
        -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    $value = [uint64]([int64]$Rights -band 0xffffffffL)
    return (($Rights -band $replacement) -ne 0 -or
        ($value -band [uint64]0x50000000) -ne 0)
}

function Test-DefenseClawBootstrapWriteLikeRights {
    param([Parameter(Mandatory)][Security.AccessControl.FileSystemRights]$Rights)
    $writeLike = [Security.AccessControl.FileSystemRights]::WriteData `
        -bor [Security.AccessControl.FileSystemRights]::AppendData `
        -bor [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes `
        -bor [Security.AccessControl.FileSystemRights]::WriteAttributes `
        -bor [Security.AccessControl.FileSystemRights]::Delete `
        -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles `
        -bor [Security.AccessControl.FileSystemRights]::ChangePermissions `
        -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    $value = [uint64]([int64]$Rights -band 0xffffffffL)
    return (($Rights -band $writeLike) -ne 0 -or
        ($value -band [uint64]0x50000000) -ne 0)
}

$script:DefenseClawBootstrapEnvironmentNames = @(
    'TEMP',
    'TMP',
    'TMPDIR',
    'LOCALAPPDATA',
    'APPDATA',
    'USERPROFILE',
    'HOME',
    'HOMEDRIVE',
    'HOMEPATH',
    'XDG_CACHE_HOME',
    'XDG_CONFIG_HOME',
    'XDG_DATA_HOME',
    'DOTNET_CLI_HOME',
    'NUGET_PACKAGES',
    'PSModuleAnalysisCachePath'
)

function Get-DefenseClawBootstrapDirectorySecurity {
    param(
        [Parameter(Mandatory)][IO.DirectoryInfo]$Directory,
        [Parameter(Mandatory)]
        [Security.AccessControl.AccessControlSections]$Sections
    )
    if ($PSVersionTable.PSEdition -eq 'Core') {
        return [IO.FileSystemAclExtensions]::GetAccessControl(
            $Directory,
            $Sections
        )
    }
    return $Directory.GetAccessControl($Sections)
}

function Get-DefenseClawBootstrapFileSecurity {
    param(
        [Parameter(Mandatory)][IO.FileInfo]$File,
        [Parameter(Mandatory)]
        [Security.AccessControl.AccessControlSections]$Sections
    )
    if ($PSVersionTable.PSEdition -eq 'Core') {
        return [IO.FileSystemAclExtensions]::GetAccessControl($File, $Sections)
    }
    return $File.GetAccessControl($Sections)
}

function New-DefenseClawBootstrapDirectorySecurity {
    param(
        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier]$CurrentSID,
        [Parameter(Mandatory)][bool]$Elevated
    )
    $systemSID = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administratorsSID =
        [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    if ($Elevated) {
        $security.SetOwner($administratorsSID)
        $security.SetGroup($administratorsSID)
    }
    else {
        $security.SetOwner($CurrentSID)
        $security.SetGroup($CurrentSID)
    }
    $accessSIDs = [Collections.Generic.List[
        Security.Principal.SecurityIdentifier
    ]]::new()
    $accessSIDs.Add($systemSID)
    $accessSIDs.Add($administratorsSID)
    if (-not $Elevated) {
        $accessSIDs.Add($CurrentSID)
    }
    foreach ($sid in $accessSIDs) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            (
                [Security.AccessControl.InheritanceFlags]::ContainerInherit `
                    -bor
                [Security.AccessControl.InheritanceFlags]::ObjectInherit
            ),
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$security.AddAccessRule($rule)
    }
    return $security
}

function Get-DefenseClawBootstrapSecuritySDDL {
    param(
        [Parameter(Mandatory)]
        [Security.AccessControl.FileSystemSecurity]$Security
    )
    $sections = [Security.AccessControl.AccessControlSections]::Owner `
        -bor [Security.AccessControl.AccessControlSections]::Group `
        -bor [Security.AccessControl.AccessControlSections]::Access
    return $Security.GetSecurityDescriptorSddlForm($sections)
}

function Assert-DefenseClawBootstrapOneShotRoot {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]
        [Security.AccessControl.DirectorySecurity]$ExpectedSecurity,
        [switch]$RequireEmpty
    )
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $windowsTemp = [IO.Path]::GetFullPath(
        [IO.Path]::Combine($trustedWindows, 'Temp')
    ).TrimEnd('\')
    if (-not [string]::Equals(
            [IO.Path]::GetDirectoryName($full),
            $windowsTemp,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        [IO.Path]::GetFileName($full) -cnotmatch
            '^DefenseClaw-Bootstrap-[a-f0-9]{32}$') {
        throw "bootstrap environment is outside its exact Windows Temp capability scope: $full"
    }
    if (-not [IO.Directory]::Exists($full)) {
        throw "bootstrap environment directory is missing: $full"
    }
    $attributes = [IO.File]::GetAttributes($full)
    if (($attributes -band [IO.FileAttributes]::Directory) -eq 0 -or
        ($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "bootstrap environment is not a regular non-reparse directory: $full"
    }
    $sections = [Security.AccessControl.AccessControlSections]::Owner `
        -bor [Security.AccessControl.AccessControlSections]::Group `
        -bor [Security.AccessControl.AccessControlSections]::Access
    $actual = Get-DefenseClawBootstrapDirectorySecurity `
        -Directory ([IO.DirectoryInfo]::new($full)) `
        -Sections $sections
    $actualSDDL = Get-DefenseClawBootstrapSecuritySDDL -Security $actual
    $expectedSDDL = Get-DefenseClawBootstrapSecuritySDDL `
        -Security $ExpectedSecurity
    if ($actualSDDL -cne $expectedSDDL -or
        -not $actual.AreAccessRulesProtected) {
        throw (
            'bootstrap environment security descriptor mismatch: ' +
            "$full; got $actualSDDL; expected $expectedSDDL"
        )
    }
    if ($RequireEmpty) {
        $enumerator = [IO.Directory]::EnumerateFileSystemEntries(
            $full
        ).GetEnumerator()
        try {
            if ($enumerator.MoveNext()) {
                throw "new bootstrap environment was not empty: $full"
            }
        }
        finally {
            $enumerator.Dispose()
        }
    }
    return $full
}

function Test-DefenseClawBootstrapPathExists {
    param([Parameter(Mandatory)][string]$Path)
    try {
        [void][IO.File]::GetAttributes($Path)
        return $true
    }
    catch [IO.FileNotFoundException] {
        return $false
    }
    catch [IO.DirectoryNotFoundException] {
        return $false
    }
}

function Assert-DefenseClawBootstrapCleanupEntry {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string[]]$AllowedAccessSIDs,
        [Parameter(Mandatory)][string[]]$AllowedOwnerSIDs,
        [Parameter(Mandatory)][bool]$Directory
    )
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    if (-not [string]::Equals(
            $full,
            $rootFull,
            [StringComparison]::OrdinalIgnoreCase
        ) -and
        -not $full.StartsWith(
            $rootFull + '\',
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "refusing bootstrap cleanup outside exact capability root: $full"
    }
    $attributes = [IO.File]::GetAttributes($full)
    if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "refusing bootstrap cleanup through a reparse point: $full"
    }
    $isDirectory =
        ($attributes -band [IO.FileAttributes]::Directory) -ne 0
    if ($isDirectory -ne $Directory) {
        throw "bootstrap cleanup object type changed: $full"
    }
    $sections = [Security.AccessControl.AccessControlSections]::Owner `
        -bor [Security.AccessControl.AccessControlSections]::Access
    $security = if ($Directory) {
        Get-DefenseClawBootstrapDirectorySecurity `
            -Directory ([IO.DirectoryInfo]::new($full)) `
            -Sections $sections
    }
    else {
        Get-DefenseClawBootstrapFileSecurity `
            -File ([IO.FileInfo]::new($full)) `
            -Sections $sections
    }
    $accessSDDL = $security.GetSecurityDescriptorSddlForm(
        [Security.AccessControl.AccessControlSections]::Access
    )
    if ([string]::IsNullOrWhiteSpace($accessSDDL) -or
        -not $accessSDDL.StartsWith(
            'D:',
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "refusing bootstrap cleanup of an object with a null DACL: $full"
    }
    $ownerSID = $security.GetOwner(
        [Security.Principal.SecurityIdentifier]
    ).Value
    if ($ownerSID -notin $AllowedOwnerSIDs) {
        throw "refusing bootstrap cleanup of untrusted owner $ownerSID`: $full"
    }
    $rules = $security.GetAccessRules(
        $true,
        $true,
        [Security.Principal.SecurityIdentifier]
    )
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne
            [Security.AccessControl.AccessControlType]::Allow) {
            continue
        }
        $sid = ConvertTo-DefenseClawBootstrapSID `
            -Identity $rule.IdentityReference
        if ($sid -notin $AllowedAccessSIDs) {
            throw "refusing bootstrap cleanup of untrusted access by $sid`: $full"
        }
    }
    return $full
}

function Test-DefenseClawBootstrapMissingPathError {
    # A .NET method failure reaches PowerShell wrapped in a
    # MethodInvocationException, so match on the inner chain, not the outer type.
    param([Parameter(Mandatory)]$Exception)
    $current = $Exception
    while ($null -ne $current) {
        if ($current -is [IO.FileNotFoundException] -or
            $current -is [IO.DirectoryNotFoundException]) {
            return $true
        }
        $current = $current.InnerException
    }
    return $false
}

function Get-DefenseClawBootstrapEntryAttributes {
    # Returns $null when the entry is already gone. TEMP is redirected into the
    # bootstrap tree, so entries can vanish between enumeration and inspection.
    param([Parameter(Mandatory)][string]$Path)
    try {
        return [IO.File]::GetAttributes($Path)
    }
    catch {
        if (Test-DefenseClawBootstrapMissingPathError -Exception $_.Exception) {
            return $null
        }
        throw
    }
}

function Remove-DefenseClawBootstrapEnvironment {
    param([Parameter(Mandatory)]$Context)
    $root = Assert-DefenseClawBootstrapOneShotRoot `
        -Path ([string]$Context.Path) `
        -ExpectedSecurity $Context.Security
    $directories = [Collections.Generic.List[string]]::new()
    $files = [Collections.Generic.List[string]]::new()
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($root)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        [void](Assert-DefenseClawBootstrapCleanupEntry `
            -Path $directory `
            -Root $root `
            -AllowedAccessSIDs $Context.AllowedAccessSIDs `
            -AllowedOwnerSIDs $Context.AllowedOwnerSIDs `
            -Directory $true)
        $directories.Add($directory)
        $enumerator = [IO.Directory]::EnumerateFileSystemEntries(
            $directory
        ).GetEnumerator()
        try {
            while ($enumerator.MoveNext()) {
                $entry = [IO.Path]::GetFullPath([string]$enumerator.Current)
                $attributes = Get-DefenseClawBootstrapEntryAttributes -Path $entry
                if ($null -eq $attributes) {
                    continue
                }
                if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne
                    0) {
                    throw "refusing bootstrap cleanup through a reparse point: $entry"
                }
                if (($attributes -band [IO.FileAttributes]::Directory) -ne
                    0) {
                    $pending.Push($entry)
                }
                else {
                    [void](Assert-DefenseClawBootstrapCleanupEntry `
                        -Path $entry `
                        -Root $root `
                        -AllowedAccessSIDs $Context.AllowedAccessSIDs `
                        -AllowedOwnerSIDs $Context.AllowedOwnerSIDs `
                        -Directory $false)
                    $files.Add($entry)
                }
            }
        }
        finally {
            $enumerator.Dispose()
        }
    }
    foreach ($file in $files) {
        [IO.File]::Delete($file)
    }
    $orderedDirectories = @(
        $directories | Microsoft.PowerShell.Utility\Sort-Object {
            $_.Length
        } -Descending
    )
    foreach ($directory in $orderedDirectories) {
        try {
            [IO.Directory]::Delete($directory, $false)
        }
        catch {
            if (-not (Test-DefenseClawBootstrapMissingPathError -Exception $_.Exception)) {
                throw
            }
        }
    }
    if (Test-DefenseClawBootstrapPathExists -Path $root) {
        throw "bootstrap environment remains after exact cleanup: $root"
    }
}

function Restore-DefenseClawBootstrapEnvironment {
    param([Parameter(Mandatory)]$Context)
    foreach ($name in $script:DefenseClawBootstrapEnvironmentNames) {
        [Environment]::SetEnvironmentVariable(
            $name,
            $Context.OriginalEnvironment[$name],
            'Process'
        )
    }
}

function New-DefenseClawBootstrapEnvironment {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $identity.User) {
        throw 'could not resolve the current Windows identity for bootstrap isolation'
    }
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $elevated = $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
    $security = New-DefenseClawBootstrapDirectorySecurity `
        -CurrentSID $identity.User `
        -Elevated $elevated
    $allowedAccessSIDs = [Collections.Generic.List[string]]::new()
    $allowedAccessSIDs.Add('S-1-5-18')
    $allowedAccessSIDs.Add('S-1-5-32-544')
    if (-not $elevated) {
        $allowedAccessSIDs.Add($identity.User.Value)
    }
    $allowedOwnerSIDs = [Collections.Generic.List[string]]::new()
    $allowedOwnerSIDs.Add('S-1-5-18')
    $allowedOwnerSIDs.Add('S-1-5-32-544')
    $allowedOwnerSIDs.Add($identity.User.Value)

    $windowsTemp = [IO.Path]::GetFullPath(
        [IO.Path]::Combine($trustedWindows, 'Temp')
    ).TrimEnd('\')
    foreach ($trustedDirectory in @($trustedWindows, $windowsTemp)) {
        if (-not [IO.Directory]::Exists($trustedDirectory)) {
            throw "trusted bootstrap parent directory is missing: $trustedDirectory"
        }
        $attributes = [IO.File]::GetAttributes($trustedDirectory)
        if (($attributes -band [IO.FileAttributes]::Directory) -eq 0 -or
            ($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "trusted bootstrap parent is not a regular directory: $trustedDirectory"
        }
    }

    $path = $null
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        for ($attempt = 0; $attempt -lt 8; $attempt++) {
            $bytes = [byte[]]::new(16)
            $random.GetBytes($bytes)
            $capability = [BitConverter]::ToString($bytes).Replace(
                '-',
                ''
            ).ToLowerInvariant()
            $candidate = [IO.Path]::Combine(
                $windowsTemp,
                "DefenseClaw-Bootstrap-$capability"
            )
            if (Test-DefenseClawBootstrapPathExists -Path $candidate) {
                continue
            }
            $directory = [IO.DirectoryInfo]::new($candidate)
            try {
                if ($PSVersionTable.PSEdition -eq 'Core') {
                    [IO.FileSystemAclExtensions]::Create($directory, $security)
                }
                else {
                    $directory.Create($security)
                }
            }
            catch [IO.IOException] {
                if (Test-DefenseClawBootstrapPathExists -Path $candidate) {
                    continue
                }
                throw
            }
            $path = Assert-DefenseClawBootstrapOneShotRoot `
                -Path $candidate `
                -ExpectedSecurity $security `
                -RequireEmpty
            break
        }
    }
    finally {
        $random.Dispose()
    }
    if ([string]::IsNullOrWhiteSpace($path)) {
        throw 'could not create a collision-free protected bootstrap environment'
    }

    $originalEnvironment = @{}
    foreach ($name in $script:DefenseClawBootstrapEnvironmentNames) {
        $originalEnvironment[$name] =
            [Environment]::GetEnvironmentVariable($name, 'Process')
    }
    $volume = [IO.Path]::GetPathRoot($path).TrimEnd('\')
    $homePath = $path.Substring($volume.Length)
    $context = [pscustomobject]@{
        Path = $path
        Security = $security
        Elevated = $elevated
        CurrentSID = $identity.User.Value
        AllowedAccessSIDs = $allowedAccessSIDs.ToArray()
        AllowedOwnerSIDs = $allowedOwnerSIDs.ToArray()
        OriginalEnvironment = $originalEnvironment
    }
    try {
        foreach ($name in @(
            'TEMP',
            'TMP',
            'TMPDIR',
            'LOCALAPPDATA',
            'APPDATA',
            'USERPROFILE',
            'HOME',
            'XDG_CACHE_HOME',
            'XDG_CONFIG_HOME',
            'XDG_DATA_HOME',
            'DOTNET_CLI_HOME',
            'NUGET_PACKAGES'
        )) {
            [Environment]::SetEnvironmentVariable($name, $path, 'Process')
        }
        [Environment]::SetEnvironmentVariable(
            'HOMEDRIVE',
            $volume,
            'Process'
        )
        [Environment]::SetEnvironmentVariable(
            'HOMEPATH',
            $homePath,
            'Process'
        )
        [Environment]::SetEnvironmentVariable(
            'PSModuleAnalysisCachePath',
            'NUL',
            'Process'
        )
        [void](Assert-DefenseClawBootstrapOneShotRoot `
            -Path $path `
            -ExpectedSecurity $security `
            -RequireEmpty)
        return $context
    }
    catch {
        $originalFailure = $_.Exception.Message
        $cleanupFailure = $null
        try {
            # The original map is complete before the first mutation. Restore
            # unconditionally so an exception halfway through environment
            # pinning cannot leave a partially redirected installer process.
            Restore-DefenseClawBootstrapEnvironment -Context $context
        }
        catch {
            $cleanupFailure = "environment restore failed: $($_.Exception.Message)"
        }
        try {
            Remove-DefenseClawBootstrapEnvironment -Context $context
        }
        catch {
            $detail = "protected directory cleanup failed: $($_.Exception.Message)"
            if ($null -eq $cleanupFailure) {
                $cleanupFailure = $detail
            }
            else {
                $cleanupFailure += "; $detail"
            }
        }
        if ($null -ne $cleanupFailure) {
            throw "$originalFailure; $cleanupFailure"
        }
        throw
    }
}

function Assert-DefenseClawBootstrapModuleTrust {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$AllowUnsignedModule
    )
    if ([string]::IsNullOrWhiteSpace($Path) -or
        $Path.Contains('"') -or
        $Path -match '[\x00-\x1f]') {
        throw "invalid DefenseClaw enterprise installer module path: $Path"
    }
    $full = [IO.Path]::GetFullPath($Path)
    if (-not [IO.Path]::IsPathRooted($full) -or
        $full.StartsWith('\\') -or
        $full.StartsWith('//') -or
        $full.StartsWith('\\?\') -or
        $full.StartsWith('\\.\') -or
        ($full.Length -gt 2 -and $full.Substring(2).Contains(':'))) {
        throw "DefenseClaw enterprise installer module must use an absolute local Win32 path: $full"
    }

    $nativePathType = Initialize-DefenseClawBootstrapNativePath
    $driveRoot = [IO.Path]::GetPathRoot($full)
    $driveID = $driveRoot.TrimEnd('\')
    $driveType = $nativePathType::GetDriveType($driveRoot)
    $fileSystem = $nativePathType::GetFileSystem($driveRoot)
    $nativePathType::AssertCanonicalDriveRoot($driveRoot, $driveID)
    if ([int]$driveType -ne 3 -or
        -not [string]::Equals($fileSystem, 'NTFS', [StringComparison]::OrdinalIgnoreCase)) {
        throw "DefenseClaw enterprise installer module must be on a local fixed NTFS volume without subst or redirection: $full"
    }

    $chain = [Collections.Generic.List[string]]::new()
    $current = $full
    while (-not [string]::IsNullOrWhiteSpace($current)) {
        $chain.Add($current)
        $parent = [IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrWhiteSpace($parent) -or
            [string]::Equals($parent, $current, [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $current = $parent
    }

    $trustedSIDs = @(
        'S-1-5-18',
        'S-1-5-32-544',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
    )
    # Inspect object type and reparse state across the complete chain before
    # ACL evaluation. This makes a junction/symlink fail as such even when a
    # higher ancestor is independently untrusted.
    for ($index = $chain.Count - 1; $index -ge 0; $index--) {
        $candidate = $chain[$index]
        $item = Microsoft.PowerShell.Management\Get-Item `
            -LiteralPath $candidate `
            -Force `
            -ErrorAction Stop
        $leaf = $index -eq 0
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "DefenseClaw enterprise installer module path contains a reparse point: $candidate"
        }
        if ($leaf) {
            if ($item.PSIsContainer) {
                throw "DefenseClaw enterprise installer module is not a regular file: $candidate"
            }
        }
        elseif (-not $item.PSIsContainer) {
            throw "DefenseClaw enterprise installer module ancestor is not a directory: $candidate"
        }
    }

    for ($index = $chain.Count - 1; $index -ge 0; $index--) {
        $candidate = $chain[$index]
        $leaf = $index -eq 0
        $acl = Microsoft.PowerShell.Security\Get-Acl `
            -LiteralPath $candidate `
            -ErrorAction Stop
        $accessSDDL = $acl.GetSecurityDescriptorSddlForm(
            [Security.AccessControl.AccessControlSections]::Access
        )
        if ([string]::IsNullOrWhiteSpace($accessSDDL) -or
            -not $accessSDDL.StartsWith('D:', [StringComparison]::OrdinalIgnoreCase)) {
            throw "DefenseClaw enterprise installer module path has an absent or null DACL: $candidate"
        }
        $ownerSID = ConvertTo-DefenseClawBootstrapSID -Identity $acl.Owner
        if ($ownerSID -notin $trustedSIDs) {
            throw "DefenseClaw enterprise installer module path has untrusted owner $ownerSID`: $candidate"
        }
        foreach ($rule in $acl.Access) {
            if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
                (($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0)) {
                continue
            }
            $sid = ConvertTo-DefenseClawBootstrapSID -Identity $rule.IdentityReference
            if ($sid -in $trustedSIDs) {
                continue
            }
            $unsafe = if ($leaf) {
                Test-DefenseClawBootstrapWriteLikeRights -Rights $rule.FileSystemRights
            }
            else {
                Test-DefenseClawBootstrapReplacementRights -Rights $rule.FileSystemRights
            }
            if ($unsafe) {
                $kind = if ($leaf) { 'write-like' } else { 'replacement' }
                throw "untrusted principal $sid has $kind access to DefenseClaw enterprise installer module path: $candidate"
            }
        }
    }

    if (-not $AllowUnsignedModule) {
        $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature `
            -LiteralPath $full `
            -ErrorAction Stop
        if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid) {
            throw "DefenseClaw enterprise installer module Authenticode signature is not valid ($($signature.Status)): $full; use -AllowUnsigned only for protected controlled test staging"
        }
    }
    # Keep the mount-manager authorization adjacent to the import boundary.
    $nativePathType::AssertCanonicalDriveRoot($driveRoot, $driveID)
    return $full
}

# ---------------------------------------------------------------------------
# QA shorthand renderer helpers (-Mode / -Connector). Mirror the macOS
# install.sh render_config + render_targets_manifest heredocs
# (packaging/macos/lib/installer_lib.sh:1061, :1336) closely enough for the
# resulting config.yaml + targets.yaml to satisfy the Windows lifecycle's
# managed_enterprise trust check. Kept minimal on purpose: only the fields
# the running gateway requires are emitted; the rest come from the Go
# config loader's defaults, so a mismatch between platforms cannot open a
# per-key drift regression during a QA install.
# ---------------------------------------------------------------------------

# Windows managed_enterprise supports only connectors with a complete native
# reconcile, trusted-runtime, rollback, and teardown lifecycle. Cursor uses its
# documented machine enterprise hook source while retaining per-user scoped
# DefenseClaw runtime and credentials.
$script:DefenseClawSupportedConnectors = @('codex', 'cursor', 'claudecode', 'amp')
$script:DefenseClawWindowsManagedEnterpriseSupportedConnectors = @('codex', 'claudecode', 'cursor')

function ConvertTo-DefenseClawConnectorList {
    param([Parameter(Mandatory)][string]$Connector)
    $raw = $Connector -split ','
    $normalized = [Collections.Generic.List[string]]::new()
    foreach ($entry in $raw) {
        $trimmed = $entry.Trim().ToLowerInvariant()
        if ([string]::IsNullOrEmpty($trimmed)) { continue }
        if ($trimmed -notin $script:DefenseClawSupportedConnectors) {
            throw "-Connector entry '$trimmed' is not a recognised connector; expected one or more of: $($script:DefenseClawSupportedConnectors -join ', ')"
        }
        if ($trimmed -notin $script:DefenseClawWindowsManagedEnterpriseSupportedConnectors) {
            throw "-Connector entry '$trimmed' is not supported on Windows managed_enterprise; supported: $($script:DefenseClawWindowsManagedEnterpriseSupportedConnectors -join ', ')."
        }
        if ($normalized -notcontains $trimmed) {
            $normalized.Add($trimmed) | Out-Null
        }
    }
    if ($normalized.Count -eq 0) {
        throw "-Connector produced no valid entries after trimming and deduplication: $Connector"
    }
    return $normalized.ToArray()
}

function Get-DefenseClawRenderedEnterpriseConfig {
    # Emit a minimal managed_enterprise config.yaml body. This is
    # intentionally NARROWER than the macOS render_config output —
    # data_dir, device_key_file, observability.local.path,
    # judge_bodies_path, and cisco_ai_defense.endpoint are all left to
    # the Windows Go loader's defaults so they land under the
    # canonical %ProgramData%\Cisco\Cisco Secure Client\DefenseClaw
    # tree without hard-coding drive letters here. env_config.json
    # remains the AVC-supplied endpoint override (see the packaging
    # doc); operators who need a non-default endpoint drop that
    # overlay after install and the gateway picks it up dynamically.
    # rule_pack_dir is the exception: omitting the key activates the
    # runtime-v8 data-dir migration, which points at an external policy
    # directory the Windows payload does not ship. An explicit empty
    # scalar selects the gateway's validated embedded rule-pack defaults.
    param(
        [Parameter(Mandatory)][string]$Mode,
        [Parameter(Mandatory)][string[]]$Connectors
    )
    $primary = $Connectors[0]
    $sb = [Text.StringBuilder]::new()
    [void]$sb.AppendLine('config_version: 8')
    [void]$sb.AppendLine('deployment_mode: managed_enterprise')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('observability:')
    [void]$sb.AppendLine('  defaults:')
    [void]$sb.AppendLine('    redaction_profile: sensitive')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('gateway:')
    [void]$sb.AppendLine('  api_bind: 127.0.0.1')
    [void]$sb.AppendLine('  api_port: 18970')
    [void]$sb.AppendLine('  watcher:')
    [void]$sb.AppendLine('    enabled: false')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('guardrail:')
    [void]$sb.AppendLine('  enabled: true')
    [void]$sb.AppendLine('  rule_pack_dir: ""')
    [void]$sb.AppendLine("  mode: $Mode")
    [void]$sb.AppendLine('  scanner_mode: both')
    [void]$sb.AppendLine('  detection_strategy: regex_only')
    [void]$sb.AppendLine('  judge:')
    [void]$sb.AppendLine('    enabled: false')
    [void]$sb.AppendLine("  connector: $primary")
    if ($Connectors.Count -gt 1) {
        [void]$sb.AppendLine('  connectors:')
        foreach ($c in $Connectors) {
            [void]$sb.AppendLine("    ${c}:")
            [void]$sb.AppendLine('      enabled: true')
            [void]$sb.AppendLine("      mode: $Mode")
        }
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('ai_discovery:')
    [void]$sb.AppendLine('  enabled: true')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('asset_policy:')
    [void]$sb.AppendLine('  enabled: false')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('application_protection:')
    [void]$sb.AppendLine('  enabled: false')
    return $sb.ToString()
}

function Get-DefenseClawEligibleInteractiveUserProfiles {
    # Walk HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList
    # and return one PSCustomObject per eligible interactive user
    # (SID starts with S-1-5-21-, has a resolvable ProfileImagePath
    # that exists on disk, and the SID translates to a live NTAccount).
    # Mirrors internal/enterprisehooks/enumerator_windows.go's
    # listWindowsUserProfiles filter chain — same rejection semantics
    # so the shorthand-rendered targets.yaml matches what the running
    # enumerator would re-render on its next tick.
    $rootKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $out = [Collections.Generic.List[psobject]]::new()
    if (-not (Test-Path -LiteralPath $rootKey)) {
        return $out.ToArray()
    }
    foreach ($sub in Get-ChildItem -LiteralPath $rootKey -ErrorAction SilentlyContinue) {
        $sid = $sub.PSChildName
        if (-not $sid.StartsWith('S-1-5-21-')) { continue }
        $image = $null
        try {
            $image = (Get-ItemProperty -LiteralPath $sub.PSPath `
                -Name ProfileImagePath -ErrorAction Stop).ProfileImagePath
        }
        catch { continue }
        if ([string]::IsNullOrWhiteSpace($image)) { continue }
        $image = [Environment]::ExpandEnvironmentVariables($image)
        if (-not [IO.Directory]::Exists($image)) { continue }
        $account = $null
        try {
            $account = ([Security.Principal.SecurityIdentifier]::new($sid)).Translate(
                [Security.Principal.NTAccount]
            ).Value
        }
        catch { continue }
        $userName = $account
        $backslash = $account.IndexOf('\')
        if ($backslash -ge 0) { $userName = $account.Substring($backslash + 1) }
        $out.Add([pscustomobject]@{
            SID = $sid
            NTAccount = $account
            UserName = $userName
            UserHome = ([IO.Path]::GetFullPath($image)).TrimEnd('\')
        }) | Out-Null
    }
    return $out.ToArray()
}

function ConvertTo-DefenseClawConnectorMetadataVersion {
    param([AllowNull()][object]$Value)

    if ($Value -isnot [string]) { return '' }
    $version = ([string]$Value).Trim()
    if ($version.Length -eq 0 -or $version.Length -gt 128 -or
        $version -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$') {
        return ''
    }
    return $version
}

function Test-DefenseClawConnectorMetadataPath {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Path,
        [switch]$Directory
    )

    try {
        $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\')
        $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
        $driveRoot = [IO.Path]::GetPathRoot($full)
        if ([string]::IsNullOrWhiteSpace($rootFull) -or
            [string]::IsNullOrWhiteSpace($driveRoot) -or
            $driveRoot -cnotmatch '^[A-Za-z]:\\$' -or
            $full.StartsWith('\\') -or
            $full.StartsWith('//') -or
            $full.StartsWith('\\?\') -or
            $full.StartsWith('\\.\') -or
            -not $full.StartsWith(
                $rootFull + '\',
                [StringComparison]::OrdinalIgnoreCase
            )) {
            return $false
        }

        $current = $full
        while ($true) {
            $attributes = [IO.File]::GetAttributes($current)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                return $false
            }
            if ([string]::Equals(
                    $current,
                    $full,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                $isDirectory =
                    ($attributes -band [IO.FileAttributes]::Directory) -ne 0
                if ($isDirectory -ne [bool]$Directory) { return $false }
            }
            if ([string]::Equals(
                    $current,
                    $rootFull,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                break
            }
            $parent = [IO.Path]::GetDirectoryName($current)
            if ([string]::IsNullOrWhiteSpace($parent) -or
                [string]::Equals(
                    $parent,
                    $current,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                return $false
            }
            $current = $parent.TrimEnd('\')
        }
        return $true
    }
    catch {
        return $false
    }
}

function Get-DefenseClawConnectorJsonMetadataVersion {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Path,
        [string[]]$ExpectedNames = @()
    )

    if (-not (Test-DefenseClawConnectorMetadataPath `
            -Root $Root -Path $Path)) {
        return ''
    }

    # Package metadata belongs to the target user and is therefore evidence,
    # not trusted code. Read a bounded UTF-8 JSON document and constrain the
    # only value that crosses into targets.yaml. Never invoke a user-installed
    # executable from this elevated installer merely to obtain --version.
    $stream = $null
    try {
        $stream = [IO.FileStream]::new(
            [IO.Path]::GetFullPath($Path),
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
        )
        $maximumBytes = 1MB
        $buffer = [byte[]]::new($maximumBytes + 1)
        $total = 0
        while ($total -lt $buffer.Length) {
            $read = $stream.Read($buffer, $total, $buffer.Length - $total)
            if ($read -eq 0) { break }
            $total += $read
        }
        if ($total -eq 0 -or $total -gt $maximumBytes) { return '' }
        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        $document = Microsoft.PowerShell.Utility\ConvertFrom-Json `
            -InputObject ($utf8.GetString($buffer, 0, $total))
        if ($null -eq $document) { return '' }
        $nameProperty = $document.PSObject.Properties['name']
        $versionProperty = $document.PSObject.Properties['version']
        if ($null -eq $versionProperty -or
            $versionProperty.Value -isnot [string]) {
            return ''
        }
        if ($ExpectedNames.Count -gt 0) {
            if ($null -eq $nameProperty -or
                $nameProperty.Value -isnot [string] -or
                ([string]$nameProperty.Value) -cnotin $ExpectedNames) {
                return ''
            }
        }
        return ConvertTo-DefenseClawConnectorMetadataVersion `
            -Value $versionProperty.Value
    }
    catch {
        return ''
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function ConvertTo-DefenseClawClaudeWinGetVersion {
    param([AllowNull()][object]$Value)

    if ($Value -isnot [string]) { return '' }
    $version = ([string]$Value).Trim()
    if ($version.Length -eq 0 -or $version.Length -gt 64 -or
        $version -cnotmatch '^([0-9]+)\.([0-9]+)\.([0-9]+)(?:\.([0-9]+))?$') {
        return ''
    }
    if ($Matches[4] -and $Matches[4] -cne '0') { return '' }
    try {
        $parsed = [Version]::new(
            [int]$Matches[1],
            [int]$Matches[2],
            [int]$Matches[3]
        )
    }
    catch {
        return ''
    }
    return ConvertTo-DefenseClawConnectorMetadataVersion `
        -Value $parsed.ToString(3)
}

function Test-DefenseClawClaudeWinGetIdentity {
    param(
        [AllowNull()][object]$SignatureStatus,
        [AllowNull()][object]$SignerSimpleName,
        [AllowNull()][object]$ProductName,
        [AllowNull()][object]$OriginalFilename,
        [AllowNull()][object]$FileVersion
    )

    if ([string]$SignatureStatus -cne 'Valid' -or
        [string]$SignerSimpleName -cnotin @('Anthropic PBC', 'Anthropic, PBC') -or
        [string]$ProductName -cne 'Claude Code') {
        return ''
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$OriginalFilename) -and
        [string]$OriginalFilename -cne 'claude.exe') {
        return ''
    }
    return ConvertTo-DefenseClawClaudeWinGetVersion -Value $FileVersion
}

function Get-DefenseClawClaudeWinGetExecutableVersion {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Path
    )

    if ([IO.Path]::GetFileName($Path) -cne 'claude.exe' -or
        -not (Test-DefenseClawConnectorMetadataPath `
            -Root $Root -Path $Path)) {
        return ''
    }

    # The WinGet package directory is user-owned and therefore only a hint.
    # Hold the executable open without write/delete sharing while its path,
    # Authenticode identity, PE identity, and version are inspected. Never run
    # a user-owned executable from this elevated installer to obtain --version.
    $stream = $null
    try {
        $full = [IO.Path]::GetFullPath($Path)
        $stream = [IO.FileStream]::new(
            $full,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        $maximumBytes = 512MB
        if ($stream.Length -le 0 -or $stream.Length -gt $maximumBytes) {
            return ''
        }
        if (-not (Test-DefenseClawConnectorMetadataPath `
                -Root $Root -Path $full)) {
            return ''
        }

        $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature `
            -LiteralPath $full `
            -ErrorAction Stop
        if ($signature.Status -ne
            [Management.Automation.SignatureStatus]::Valid -or
            $null -eq $signature.SignerCertificate) {
            return ''
        }
        $signer = $signature.SignerCertificate.GetNameInfo(
            [Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
            $false
        )
        $identity = [Diagnostics.FileVersionInfo]::GetVersionInfo($full)
        if ($null -eq $identity) { return '' }
        $version = Test-DefenseClawClaudeWinGetIdentity `
            -SignatureStatus $signature.Status `
            -SignerSimpleName $signer `
            -ProductName $identity.ProductName `
            -OriginalFilename $identity.OriginalFilename `
            -FileVersion $identity.FileVersion
        if ([string]::IsNullOrWhiteSpace($version)) { return '' }

        # Revalidate the complete ancestor chain while the no-delete-share
        # handle is still held so a candidate cannot be replaced mid-probe.
        if (-not (Test-DefenseClawConnectorMetadataPath `
                -Root $Root -Path $full)) {
            return ''
        }
        return $version
    }
    catch {
        return ''
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Get-DefenseClawClaudeWinGetMetadataVersion {
    param(
        [Parameter(Mandatory)][string]$UserHome,
        [scriptblock]$ExecutableVersionReader
    )

    try {
        $userHomeFull = [IO.Path]::GetFullPath($UserHome).TrimEnd('\')
        $packageRoot = [IO.Path]::Combine(
            $userHomeFull,
            'AppData\Local\Microsoft\WinGet\Packages'
        )
    }
    catch {
        return ''
    }
    if (-not (Test-DefenseClawConnectorMetadataPath `
            -Root $userHomeFull -Path $packageRoot -Directory)) {
        return ''
    }

    if ($null -eq $ExecutableVersionReader) {
        $ExecutableVersionReader = {
            param([string]$Root, [string]$Path)
            Get-DefenseClawClaudeWinGetExecutableVersion `
                -Root $Root -Path $Path
        }
    }

    $versions = [Collections.Generic.List[Version]]::new()
    $examined = 0
    $matched = 0
    try {
        foreach ($directory in [IO.Directory]::EnumerateDirectories(
                $packageRoot,
                'Anthropic.ClaudeCode_Microsoft.Winget.Source_*',
                [IO.SearchOption]::TopDirectoryOnly
            )) {
            $examined++
            if ($examined -gt 256) { return '' }
            $leaf = [IO.Path]::GetFileName($directory)
            if ($leaf -cnotmatch
                '^Anthropic\.ClaudeCode_Microsoft\.Winget\.Source_[0-9A-Za-z]{1,64}$') {
                continue
            }
            $matched++
            if ($matched -gt 32 -or
                -not (Test-DefenseClawConnectorMetadataPath `
                    -Root $packageRoot -Path $directory -Directory)) {
                return ''
            }
            $executable = [IO.Path]::Combine($directory, 'claude.exe')
            if (-not (Test-DefenseClawConnectorMetadataPath `
                    -Root $packageRoot -Path $executable)) {
                continue
            }
            $version = & $ExecutableVersionReader $packageRoot $executable
            $normalized = ConvertTo-DefenseClawClaudeWinGetVersion `
                -Value $version
            if ([string]::IsNullOrWhiteSpace($normalized)) { continue }
            try {
                $versions.Add([Version]::Parse($normalized))
            }
            catch {
                continue
            }
        }
    }
    catch {
        return ''
    }
    if ($versions.Count -eq 0) { return '' }
    return [string]($versions | Sort-Object -Descending | Select-Object -First 1)
}

function ConvertTo-DefenseClawCodexWinGetVersion {
    param([AllowNull()][object]$Value)

    if ($Value -isnot [string]) { return '' }
    $version = ([string]$Value).Trim()
    if ($version.Length -eq 0 -or $version.Length -gt 64) {
        return ''
    }
    # Do not depend on PowerShell's automatic $Matches variable here.
    # `-cnotmatch` does not provide stable capture state across PowerShell
    # editions, and a stale capture would make a valid signed PE fail closed.
    $versionMatch = [regex]::Match(
        $version,
        '^([0-9]+)\.([0-9]+)\.([0-9]+)(?:\.([0-9]+))?$',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if (-not $versionMatch.Success) { return '' }
    if ($versionMatch.Groups[4].Success -and
        $versionMatch.Groups[4].Value -cne '0') {
        return ''
    }
    try {
        $parsed = [Version]::new(
            [int]$versionMatch.Groups[1].Value,
            [int]$versionMatch.Groups[2].Value,
            [int]$versionMatch.Groups[3].Value
        )
    }
    catch {
        return ''
    }
    return ConvertTo-DefenseClawConnectorMetadataVersion `
        -Value $parsed.ToString(3)
}

function Read-DefenseClawCodexPEBytes {
    param(
        [Parameter(Mandatory)][IO.Stream]$Stream,
        [Parameter(Mandatory)][ValidateRange(1, 1048576)][int]$Count
    )

    $buffer = [byte[]]::new($Count)
    $total = 0
    while ($total -lt $Count) {
        $read = $Stream.Read($buffer, $total, $Count - $total)
        if ($read -eq 0) {
            throw 'unexpected end of Codex PE metadata'
        }
        $total += $read
    }
    # Prevent PowerShell's pipeline from unrolling byte arrays.
    Write-Output -NoEnumerate $buffer
}

function Get-DefenseClawCodexWinGetEmbeddedVersion {
    param([Parameter(Mandatory)][IO.Stream]$Stream)

    if (-not $Stream.CanRead -or -not $Stream.CanSeek) { return '' }
    try {
        if (-not [BitConverter]::IsLittleEndian) { return '' }
        $streamLength = [uint64]$Stream.Length
        if ($streamLength -le 0 -or $streamLength -gt 512MB) { return '' }

        # Authenticode deliberately excludes the certificate table and some PE
        # header fields from its digest. Parse the PE and scan only raw section
        # bytes, which are covered by the verified signature; never accept a
        # version marker injected into certificate padding or an unsigned tail.
        [void]$Stream.Seek(0, [IO.SeekOrigin]::Begin)
        [byte[]]$dos = Read-DefenseClawCodexPEBytes -Stream $Stream -Count 64
        if ($dos[0] -ne 0x4d -or $dos[1] -ne 0x5a) { return '' }
        $peOffset = [uint64][BitConverter]::ToUInt32($dos, 60)
        if ($peOffset -lt 64 -or $peOffset -gt 1MB -or
            $peOffset + 24 -gt $streamLength) {
            return ''
        }
        [void]$Stream.Seek([int64]$peOffset, [IO.SeekOrigin]::Begin)
        [byte[]]$signature = Read-DefenseClawCodexPEBytes `
            -Stream $Stream -Count 4
        if ($signature[0] -ne 0x50 -or $signature[1] -ne 0x45 -or
            $signature[2] -ne 0 -or $signature[3] -ne 0) {
            return ''
        }
        [byte[]]$coff = Read-DefenseClawCodexPEBytes -Stream $Stream -Count 20
        if ([BitConverter]::ToUInt16($coff, 0) -ne 0x8664) { return '' }
        $sectionCount = [uint32][BitConverter]::ToUInt16($coff, 2)
        $optionalSize = [uint32][BitConverter]::ToUInt16($coff, 16)
        if ($sectionCount -lt 1 -or $sectionCount -gt 96 -or
            $optionalSize -lt 152 -or $optionalSize -gt 4096) {
            return ''
        }
        [byte[]]$optional = Read-DefenseClawCodexPEBytes `
            -Stream $Stream -Count ([int]$optionalSize)
        if ([BitConverter]::ToUInt16($optional, 0) -ne 0x20b -or
            [BitConverter]::ToUInt32($optional, 108) -lt 5) {
            return ''
        }
        $sizeOfHeaders = [uint64][BitConverter]::ToUInt32($optional, 60)
        $certificateOffset = [uint64][BitConverter]::ToUInt32($optional, 144)
        $certificateSize = [uint64][BitConverter]::ToUInt32($optional, 148)
        $sectionTableEnd = (
            $peOffset + 24 + $optionalSize +
            ([uint64]$sectionCount * 40)
        )
        $certificateEnd = $certificateOffset + $certificateSize
        if ($sizeOfHeaders -lt $sectionTableEnd -or
            $sizeOfHeaders -gt $streamLength -or
            $certificateOffset -lt $sizeOfHeaders -or
            $certificateOffset % 8 -ne 0 -or
            $certificateSize -lt 8 -or
            $certificateSize % 8 -ne 0 -or
            $certificateEnd -ne $streamLength) {
            return ''
        }

        $sections = [Collections.Generic.List[object]]::new()
        $totalSectionBytes = [uint64]0
        for ($index = 0; $index -lt $sectionCount; $index++) {
            [byte[]]$sectionHeader = Read-DefenseClawCodexPEBytes `
                -Stream $Stream -Count 40
            $rawSize = [uint64][BitConverter]::ToUInt32($sectionHeader, 16)
            $rawOffset = [uint64][BitConverter]::ToUInt32($sectionHeader, 20)
            if ($rawSize -eq 0) { continue }
            $rawEnd = $rawOffset + $rawSize
            if ($rawEnd -lt $rawOffset -or
                $rawOffset -lt $sizeOfHeaders -or
                $rawEnd -gt $certificateOffset) {
                return ''
            }
            $totalSectionBytes += $rawSize
            if ($totalSectionBytes -gt 512MB) { return '' }
            $sections.Add([pscustomobject]@{
                Offset = $rawOffset
                Length = $rawSize
            })
        }
        if ($sections.Count -eq 0) { return '' }
        $ordered = @($sections | Sort-Object -Property Offset)
        $previousEnd = [uint64]0
        foreach ($signedSection in $ordered) {
            if ([uint64]$signedSection.Offset -lt $previousEnd) { return '' }
            $previousEnd = (
                [uint64]$signedSection.Offset +
                [uint64]$signedSection.Length
            )
        }

        $buffer = [byte[]]::new(1MB)
        $ascii = [Text.Encoding]::ASCII
        $sawCodexCLI = $false
        $versions = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal
        )
        foreach ($signedSection in $ordered) {
            [void]$Stream.Seek(
                [int64][uint64]$signedSection.Offset,
                [IO.SeekOrigin]::Begin
            )
            $remaining = [uint64]$signedSection.Length
            $carry = ''
            while ($remaining -gt 0) {
                $readLength = if ($remaining -gt $buffer.Length) {
                    $buffer.Length
                }
                else {
                    [int]$remaining
                }
                $read = $Stream.Read($buffer, 0, $readLength)
                if ($read -le 0) { return '' }
                $remaining -= [uint64]$read
                $text = $carry + $ascii.GetString($buffer, 0, $read)
                if ($text.IndexOf(
                        'codex-cli',
                        [StringComparison]::Ordinal
                    ) -ge 0) {
                    $sawCodexCLI = $true
                }
                foreach ($match in [regex]::Matches(
                        $text,
                        'buildversion: ([0-9]{1,10}\.[0-9]{1,10}\.[0-9]{1,10}(?:\.[0-9]{1,10})?)',
                        [Text.RegularExpressions.RegexOptions]::CultureInvariant
                    )) {
                    $normalized = ConvertTo-DefenseClawCodexWinGetVersion `
                        -Value $match.Groups[1].Value
                    if ([string]::IsNullOrWhiteSpace($normalized)) { return '' }
                    [void]$versions.Add($normalized)
                    if ($versions.Count -gt 1) { return '' }
                }
                $carryLength = [Math]::Min(256, $text.Length)
                $carry = $text.Substring($text.Length - $carryLength)
            }
        }
        if (-not $sawCodexCLI -or $versions.Count -ne 1) { return '' }
        return [string]($versions | Select-Object -First 1)
    }
    catch {
        return ''
    }
}

function Test-DefenseClawCodexWinGetIdentity {
    param(
        [AllowNull()][object]$SignatureStatus,
        [AllowNull()][object]$SignerSimpleName,
        [AllowNull()][object]$ProductName,
        [AllowNull()][object]$OriginalFilename,
        [AllowNull()][object]$FileVersion,
        [AllowNull()][object]$EmbeddedVersion
    )

    if ([string]$SignatureStatus -cne 'Valid' -or
        [string]$SignerSimpleName -cne 'OpenAI OpCo, LLC') {
        return ''
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$ProductName) -and
        [string]$ProductName -cnotin @('Codex', 'Codex CLI')) {
        return ''
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$OriginalFilename) -and
        [string]$OriginalFilename -cne 'codex-x86_64-pc-windows-msvc.exe') {
        return ''
    }
    $embedded = ConvertTo-DefenseClawCodexWinGetVersion `
        -Value $EmbeddedVersion
    if ([string]::IsNullOrWhiteSpace($embedded)) { return '' }
    if (-not [string]::IsNullOrWhiteSpace([string]$FileVersion)) {
        $file = ConvertTo-DefenseClawCodexWinGetVersion -Value $FileVersion
        if ([string]::IsNullOrWhiteSpace($file) -or $file -cne $embedded) {
            return ''
        }
    }
    return $embedded
}

function Test-DefenseClawConnectorMetadataTargetIsLocalAdmin {
    param([Parameter(Mandatory)][string]$ExpectedSID)

    # RID -500 is the built-in Administrator account (both on domain-joined
    # workstations and standalone hosts). Its token is always
    # BUILTIN\Administrators-owning by default, so any file it creates is
    # stamped with SID S-1-5-32-544 as owner. Match on the well-known RID
    # pattern first so the common QA case (logged in as local Administrator)
    # never pays for a CIM query.
    #
    # Anchor the pattern to the canonical shape: S-1-5-21 (domain identifier
    # authority) followed by exactly three non-empty numeric sub-authorities
    # (the machine or domain identifier) and then the terminal -500 RID.
    # A wider `[0-9-]+` sub-pattern would match e.g. `S-1-5-21---500` or
    # `S-1-5-21-1-500` (only one sub-authority), neither of which is a real
    # built-in Administrator SID.
    if ($ExpectedSID -cmatch '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-500$') {
        return $true
    }
    try {
        # Direct-membership walk of the local Administrators group
        # (SID S-1-5-32-544). Nested groups are deliberately NOT expanded —
        # a transitively-nested group containing Administrators must not
        # silently widen owner-acceptance. Any CIM query failure returns
        # $false so we never widen acceptance based on incomplete data.
        $adminGroup = CimCmdlets\Get-CimInstance `
            -ClassName Win32_Group `
            -Filter "SID='S-1-5-32-544' AND LocalAccount=True" `
            -ErrorAction Stop
        if ($null -eq $adminGroup) { return $false }
        $members = CimCmdlets\Get-CimAssociatedInstance `
            -InputObject $adminGroup `
            -Association Win32_GroupUser `
            -ErrorAction Stop
        foreach ($member in $members) {
            if ([string]::Equals(
                    [string]$member.SID,
                    $ExpectedSID,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                return $true
            }
        }
    }
    catch { return $false }
    return $false
}

function Test-DefenseClawConnectorMetadataOwnerIdentity {
    param(
        [Parameter(Mandatory)][string]$ExpectedSID,
        [Parameter(Mandatory)]$ActualOwner
    )

    try {
        $expected = [Security.Principal.SecurityIdentifier]::new(
            $ExpectedSID
        ).Value
        $actual = ConvertTo-DefenseClawBootstrapSID -Identity $ActualOwner
        if ([string]::Equals(
                $actual,
                $expected,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            return $true
        }
        # Windows stamps files created by an elevated-admin token with owner
        # BUILTIN\Administrators (SID S-1-5-32-544) rather than the user's
        # own SID. Every admin-owned WinGet install (`winget install ...`
        # from an elevated prompt) lands with Administrators-owned files,
        # so the strict "owner must equal target SID" check refuses to
        # detect Codex/etc. installed by any admin target — including
        # the built-in Administrator RID -500 that QA uses. Accept
        # Administrators as a valid owner iff the target SID is itself a
        # member of the local Administrators group; the file is then
        # functionally owned by the target. Regular non-admin users keep
        # the strict target-SID-only check.
        #
        # See docs/WINDOWS-ENTERPRISE-THREAT-MODEL.md § "Elevated target
        # relaxation" for the parallel runtime-side softening. A determined
        # admin attacker can always defeat DefenseClaw through uninstall or
        # direct hook-file edits — refusing to detect their tools does not
        # raise the trust boundary, it only denies inspection to legitimate
        # admin QA + admin-managed helpdesk workflows.
        if ([string]::Equals(
                $actual,
                'S-1-5-32-544',
                [StringComparison]::OrdinalIgnoreCase
            ) -and
            (Test-DefenseClawConnectorMetadataTargetIsLocalAdmin `
                -ExpectedSID $expected)) {
            return $true
        }
        return $false
    }
    catch {
        return $false
    }
}

function Test-DefenseClawConnectorMetadataOwner {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ExpectedSID
    )

    try {
        $acl = Microsoft.PowerShell.Security\Get-Acl `
            -LiteralPath ([IO.Path]::GetFullPath($Path)) `
            -ErrorAction Stop
        return Test-DefenseClawConnectorMetadataOwnerIdentity `
            -ExpectedSID $ExpectedSID -ActualOwner $acl.Owner
    }
    catch {
        return $false
    }
}

function Get-DefenseClawCodexWinGetExecutableVersion {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$OwnerSID
    )

    if ([IO.Path]::GetFileName($Path) -cne
            'codex-x86_64-pc-windows-msvc.exe' -or
        -not (Test-DefenseClawConnectorMetadataPath `
            -Root $Root -Path $Path)) {
        return ''
    }

    # The user-owned package directory is only a candidate hint. Keep the
    # exact executable open without write/delete sharing while validating its
    # owner, Authenticode signer, optional PE identity, and signed embedded
    # build provenance. Never execute it from this elevated installer.
    $stream = $null
    try {
        $full = [IO.Path]::GetFullPath($Path)
        $stream = [IO.FileStream]::new(
            $full,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        if ($stream.Length -le 0 -or $stream.Length -gt 512MB -or
            -not (Test-DefenseClawConnectorMetadataOwner `
                -Path $full -ExpectedSID $OwnerSID) -or
            -not (Test-DefenseClawConnectorMetadataPath `
                -Root $Root -Path $full)) {
            return ''
        }

        $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature `
            -LiteralPath $full `
            -ErrorAction Stop
        if ($signature.Status -ne
            [Management.Automation.SignatureStatus]::Valid -or
            $null -eq $signature.SignerCertificate) {
            return ''
        }
        $signer = $signature.SignerCertificate.GetNameInfo(
            [Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
            $false
        )
        $identity = [Diagnostics.FileVersionInfo]::GetVersionInfo($full)
        if ($null -eq $identity) { return '' }
        $embedded = Get-DefenseClawCodexWinGetEmbeddedVersion -Stream $stream
        $version = Test-DefenseClawCodexWinGetIdentity `
            -SignatureStatus $signature.Status `
            -SignerSimpleName $signer `
            -ProductName $identity.ProductName `
            -OriginalFilename $identity.OriginalFilename `
            -FileVersion $identity.FileVersion `
            -EmbeddedVersion $embedded
        if ([string]::IsNullOrWhiteSpace($version)) { return '' }

        if (-not (Test-DefenseClawConnectorMetadataOwner `
                -Path $full -ExpectedSID $OwnerSID) -or
            -not (Test-DefenseClawConnectorMetadataPath `
                -Root $Root -Path $full)) {
            return ''
        }
        return $version
    }
    catch {
        return ''
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Get-DefenseClawCodexWinGetMetadataVersion {
    param(
        [Parameter(Mandatory)][string]$UserHome,
        [Parameter(Mandatory)][AllowEmptyString()][string]$OwnerSID,
        [scriptblock]$ExecutableVersionReader,
        [scriptblock]$OwnerValidator,
        [ref]$CandidateObserved
    )

    if ($null -ne $CandidateObserved) { $CandidateObserved.Value = $false }
    try {
        $userHomeFull = [IO.Path]::GetFullPath($UserHome).TrimEnd('\')
        $packageRoot = [IO.Path]::Combine(
            $userHomeFull,
            'AppData\Local\Microsoft\WinGet\Packages'
        )
    }
    catch {
        return ''
    }
    $packageRootPresent = $false
    try {
        [void][IO.File]::GetAttributes($packageRoot)
        $packageRootPresent = $true
    }
    catch [IO.FileNotFoundException] {
        return ''
    }
    catch [IO.DirectoryNotFoundException] {
        return ''
    }
    catch {
        if ($null -ne $CandidateObserved) {
            $CandidateObserved.Value = $true
        }
        return ''
    }
    if (-not $packageRootPresent -or
        -not (Test-DefenseClawConnectorMetadataPath `
            -Root $userHomeFull -Path $packageRoot -Directory)) {
        # An existing but unsafe/unreadable WinGet root is evidence, not
        # absence. Prevent the caller from substituting a minimum version.
        if ($null -ne $CandidateObserved) {
            $CandidateObserved.Value = $true
        }
        return ''
    }

    if ($null -eq $ExecutableVersionReader) {
        $ExecutableVersionReader = {
            param([string]$Root, [string]$Path, [string]$ExpectedOwnerSID)
            Get-DefenseClawCodexWinGetExecutableVersion `
                -Root $Root -Path $Path -OwnerSID $ExpectedOwnerSID
        }
    }
    if ($null -eq $OwnerValidator) {
        $OwnerValidator = {
            param([string]$Path, [string]$ExpectedOwnerSID)
            Test-DefenseClawConnectorMetadataOwner `
                -Path $Path -ExpectedSID $ExpectedOwnerSID
        }
    }

    $versions = [Collections.Generic.List[Version]]::new()
    $examined = 0
    $matched = 0
    $invalidCandidate = $false
    try {
        foreach ($directory in [IO.Directory]::EnumerateDirectories(
                $packageRoot,
                'OpenAI.Codex_Microsoft.Winget.Source_*',
                [IO.SearchOption]::TopDirectoryOnly
            )) {
            $examined++
            if ($null -ne $CandidateObserved) {
                $CandidateObserved.Value = $true
            }
            if ($examined -gt 256) { return '' }
            $leaf = [IO.Path]::GetFileName($directory)
            if ($leaf -cnotmatch
                '^OpenAI\.Codex_Microsoft\.Winget\.Source_[0-9A-Za-z]{1,64}$') {
                $invalidCandidate = $true
                continue
            }
            $matched++
            if ($matched -gt 32 -or
                [string]::IsNullOrWhiteSpace($OwnerSID) -or
                -not (Test-DefenseClawConnectorMetadataPath `
                    -Root $packageRoot -Path $directory -Directory) -or
                -not (& $OwnerValidator $directory $OwnerSID)) {
                $invalidCandidate = $true
                continue
            }
            $executable = [IO.Path]::Combine(
                $directory,
                'codex-x86_64-pc-windows-msvc.exe'
            )
            if (-not (Test-DefenseClawConnectorMetadataPath `
                    -Root $packageRoot -Path $executable) -or
                -not (& $OwnerValidator $executable $OwnerSID)) {
                $invalidCandidate = $true
                continue
            }
            $version = & $ExecutableVersionReader `
                $packageRoot $executable $OwnerSID
            $normalized = ConvertTo-DefenseClawCodexWinGetVersion `
                -Value $version
            if ([string]::IsNullOrWhiteSpace($normalized)) {
                $invalidCandidate = $true
                continue
            }
            try {
                $versions.Add([Version]::Parse($normalized))
            }
            catch {
                $invalidCandidate = $true
            }
        }
    }
    catch {
        if ($null -ne $CandidateObserved) {
            $CandidateObserved.Value = $true
        }
        return ''
    }
    if ($invalidCandidate -or $versions.Count -eq 0) { return '' }
    return [string]($versions | Sort-Object -Descending | Select-Object -First 1)
}

function Get-DefenseClawConnectorMetadataVersion {
    param(
        [Parameter(Mandatory)][string]$Connector,
        [Parameter(Mandatory)][string]$UserHome,
        [string]$OwnerSID,
        [ref]$NativeCandidateObserved
    )

    if ($null -ne $NativeCandidateObserved) {
        $NativeCandidateObserved.Value = $false
    }

    try {
        $userHomeFull = [IO.Path]::GetFullPath($UserHome).TrimEnd('\')
    }
    catch {
        return ''
    }
    if (-not [IO.Directory]::Exists($userHomeFull)) { return '' }

    if ($Connector -eq 'cursor') {
        foreach ($candidate in @(
            [pscustomobject]@{
                Root = $userHomeFull
                Path = [IO.Path]::Combine(
                    $userHomeFull,
                    'AppData\Local\Programs\cursor\resources\app\package.json'
                )
            },
            [pscustomobject]@{
                Root = $trustedProgramFiles
                Path = [IO.Path]::Combine(
                    $trustedProgramFiles,
                    'Cursor\resources\app\package.json'
                )
            }
        )) {
            # Cursor's exact application-bundle path is the identity boundary;
            # upstream package names have varied, so do not key this probe on
            # an unstable JSON name field.
            $version = Get-DefenseClawConnectorJsonMetadataVersion `
                -Root $candidate.Root -Path $candidate.Path
            if (-not [string]::IsNullOrWhiteSpace($version)) {
                return $version
            }
        }
        return ''
    }

    $package = switch ($Connector) {
        'codex' { '@openai\codex'; break }
        'claudecode' { '@anthropic-ai\claude-code'; break }
        'amp' { '@ampcode\cli'; break }
        default { return '' }
    }
    $expectedName = $package -replace '\\', '/'
    foreach ($prefix in @(
        'AppData\Roaming\npm\node_modules',
        '.npm-global\node_modules',
        '.npm-global\lib\node_modules',
        '.local\lib\node_modules'
    )) {
        $candidate = [IO.Path]::Combine(
            $userHomeFull,
            $prefix,
            $package,
            'package.json'
        )
        $version = Get-DefenseClawConnectorJsonMetadataVersion `
            -Root $userHomeFull `
            -Path $candidate `
            -ExpectedNames @($expectedName)
        if (-not [string]::IsNullOrWhiteSpace($version)) {
            return $version
        }
    }

    $machinePackage = [IO.Path]::Combine(
        $trustedProgramFiles,
        'nodejs\node_modules',
        $package,
        'package.json'
    )
    $version = Get-DefenseClawConnectorJsonMetadataVersion `
        -Root $trustedProgramFiles `
        -Path $machinePackage `
        -ExpectedNames @($expectedName)
    if (-not [string]::IsNullOrWhiteSpace($version)) { return $version }

    if ($Connector -eq 'codex') {
        $codexCandidateObserved = $false
        $version = Get-DefenseClawCodexWinGetMetadataVersion `
            -UserHome $userHomeFull `
            -OwnerSID $OwnerSID `
            -CandidateObserved ([ref]$codexCandidateObserved)
        if ($codexCandidateObserved -and
            $null -ne $NativeCandidateObserved) {
            $NativeCandidateObserved.Value = $true
        }
        if (-not [string]::IsNullOrWhiteSpace($version)) {
            return $version
        }
        return ''
    }

    if ($Connector -eq 'claudecode') {
        $version = Get-DefenseClawClaudeWinGetMetadataVersion `
            -UserHome $userHomeFull
        if (-not [string]::IsNullOrWhiteSpace($version)) {
            return $version
        }

        foreach ($relativeExtensionRoot in @(
            '.cursor\extensions',
            '.vscode\extensions'
        )) {
            $extensionRoot = [IO.Path]::Combine(
                $userHomeFull,
                $relativeExtensionRoot
            )
            if (-not (Test-DefenseClawConnectorMetadataPath `
                    -Root $userHomeFull `
                    -Path $extensionRoot `
                    -Directory)) {
                continue
            }
            $examined = 0
            foreach ($extension in [IO.Directory]::EnumerateDirectories(
                    $extensionRoot,
                    'anthropic.claude-code-*',
                    [IO.SearchOption]::TopDirectoryOnly
                )) {
                $examined++
                if ($examined -gt 256) { break }
                $candidate = [IO.Path]::Combine($extension, 'package.json')
                $version = Get-DefenseClawConnectorJsonMetadataVersion `
                    -Root $userHomeFull `
                    -Path $candidate `
                    -ExpectedNames @('claude-code')
                if (-not [string]::IsNullOrWhiteSpace($version)) {
                    return $version
                }
            }
        }
    }
    return ''
}

function Resolve-DefenseClawConnectorMetadataVersion {
    param(
        [AllowNull()][object]$DiscoveredVersion,
        [AllowNull()][object]$MinimumVersion,
        [bool]$NativeCandidateObserved,
        [bool]$DiscoveryFailed
    )

    $version = ConvertTo-DefenseClawConnectorMetadataVersion `
        -Value $DiscoveredVersion
    if (-not [string]::IsNullOrWhiteSpace($version)) { return $version }
    if ($NativeCandidateObserved -or $DiscoveryFailed) { return '' }
    return ConvertTo-DefenseClawConnectorMetadataVersion -Value $MinimumVersion
}

function Get-DefenseClawRenderedEnterpriseTargets {
    param(
        [Parameter(Mandatory)][string[]]$Connectors,
        [object[]]$Profiles
    )
    $sb = [Text.StringBuilder]::new()
    [void]$sb.AppendLine('version: 1')
    [void]$sb.AppendLine('targets:')
    $users = @(
        if ($PSBoundParameters.ContainsKey('Profiles')) {
            $Profiles
        }
        else {
            Get-DefenseClawEligibleInteractiveUserProfiles
        }
    )
    if ($users.Count -eq 0) {
        # An empty manifest is valid YAML; the guardian re-scans on its
        # interval, so a new user appearing after install is picked up
        # by the enumerator without a reinstall. The bootstrap install
        # simply lands with no rows for now.
        return $sb.ToString()
    }
    # Windows managed_enterprise's manifest validator refuses any
    # `enabled: true` target without an `agent_version` that also meets
    # the connector's Windows minimum — see
    # requireWindowsEnterpriseManagedAgentVersion in
    # internal/enterprisehooks/install_windows.go (codex >= 0.131.0,
    # claudecode >= 2.1.152). When no agent metadata exists yet (the common
    # state on managed rollouts where AVC pushes DefenseClaw first), use the
    # exact minimum as a bootstrap placeholder. A detected native package
    # whose identity/version cannot be authenticated never receives that
    # fallback. A valid below-minimum version remains exact so downstream
    # manifest validation fails closed instead of certifying a placeholder.
    $script:DefenseClawWindowsAgentVersionMinimum = @{
        'codex'      = '0.131.0'
        'claudecode' = '2.1.152'
        'cursor'     = '1.7.0'
    }
    foreach ($u in $users) {
        foreach ($c in $Connectors) {
            $version = ''
            $nativeCandidateObserved = $false
            $metadataDiscoveryFailed = $false
            try {
                $version = Get-DefenseClawConnectorMetadataVersion `
                    -Connector $c `
                    -UserHome ([string]$u.UserHome) `
                    -OwnerSID ([string]$u.SID) `
                    -NativeCandidateObserved ([ref]$nativeCandidateObserved)
            }
            catch {
                # Unexpected discovery errors must not turn an unverified
                # installed native package into a certified minimum version.
                $version = ''
                $metadataDiscoveryFailed = $true
            }
            $minimumVersion = if (
                $script:DefenseClawWindowsAgentVersionMinimum.ContainsKey($c)
            ) {
                $script:DefenseClawWindowsAgentVersionMinimum[$c]
            }
            else {
                ''
            }
            $version = Resolve-DefenseClawConnectorMetadataVersion `
                -DiscoveredVersion $version `
                -MinimumVersion $minimumVersion `
                -NativeCandidateObserved $nativeCandidateObserved `
                -DiscoveryFailed $metadataDiscoveryFailed
            [void]$sb.AppendLine("  - user: `"$($u.UserName -replace '"','\"')`"")
            [void]$sb.AppendLine("    user_home: `"$($u.UserHome -replace '"','\"' -replace '\\','\\')`"")
            [void]$sb.AppendLine("    sid: `"$($u.SID)`"")
            [void]$sb.AppendLine("    connector: `"$c`"")
            if ([string]::IsNullOrWhiteSpace($version)) {
                [void]$sb.AppendLine('    enabled: false')
            }
            else {
                [void]$sb.AppendLine("    agent_version: `"$version`"")
                [void]$sb.AppendLine('    enabled: true')
            }
        }
    }
    return $sb.ToString()
}

$bootstrapEnvironment = $null
$result = $null
$failureMessage = $null
$exitCode = 0
try {
    # Deferred installation cannot authenticate or precreate per-user target
    # runtimes because targets.yaml does not exist yet. Fail before the
    # bootstrap environment creates its first protected staging directory;
    # the module repeats this check as defense in depth for direct callers.
    if ($DeferredConfig) {
        throw (
            '-DeferredConfig is temporarily unavailable: secure target ' +
            'runtime preparation requires authenticated targets.yaml during Install'
        )
    }
    $bootstrapEnvironment = New-DefenseClawBootstrapEnvironment
    $modulePath = [IO.Path]::GetFullPath(
        [IO.Path]::Combine($PSScriptRoot, 'DefenseClawEnterprise.psm1')
    )
    Assert-DefenseClawBootstrapLifecycleScope `
        -LifecycleAction $Action `
        -RequestedInstallRoot $InstallRoot `
        -RequestedStateRoot $StateRoot `
        -RequestedGatewayServiceName $GatewayServiceName `
        -RequestedGuardianServiceName $GuardianServiceName `
        -AllowUnsignedLifecycle ([bool]$AllowUnsigned)
    if ($SelfUninstallCallerPID -lt 0 -or
        ($SelfUninstallCallerPID -gt 0 -and $Action -ne 'Uninstall')) {
        throw '-SelfUninstallCallerPID is valid only as a positive PID with Uninstall'
    }
    if ($AllowUnsigned) {
        Assert-DefenseClawBootstrapUnsignedCertificationScope `
            -LifecycleAction $Action `
            -RequestedInstallRoot $InstallRoot `
            -RequestedStateRoot $StateRoot `
            -RequestedGatewayServiceName $GatewayServiceName `
            -RequestedGuardianServiceName $GuardianServiceName `
            -RequestedCertificationCodexHome $CertificationCodexHome
    }
    elseif (-not [string]::IsNullOrWhiteSpace($CertificationCodexHome)) {
        throw '-CertificationCodexHome requires -AllowUnsigned for every lifecycle action'
    }
    if ($CoreHardeningCertification -and
        $Action -notin @('Install', 'Upgrade', 'Repair')) {
        throw '-CoreHardeningCertification is valid only with Install, Upgrade, or Repair'
    }
    if ($CoreHardeningCertification -and
        (-not $AllowUnsigned -or
            [string]::IsNullOrWhiteSpace($CertificationCodexHome))) {
        throw '-CoreHardeningCertification requires -AllowUnsigned and -CertificationCodexHome'
    }
    if ($CoreHardeningCertification -and
        ($AttestAgentApplicationControl -or
            $AttestClaudeEffectivePolicy)) {
        throw (
            '-CoreHardeningCertification cannot be combined with production ' +
            'application-control or Claude-policy attestations'
        )
    }
    # -Mode / -Connector shorthand handling. Validated + rendered BEFORE
    # the module import so a bad grammar surfaces the error at the
    # bootstrap boundary rather than deep inside the transaction. The
    # rendered YAML lands in the bootstrap environment's protected
    # SYSTEM/Administrators-only directory (same path Setup.exe uses for
    # its embedded payload staging), so the module reads them under the
    # same trust invariants as an operator-supplied -Config / -Manifest.
    $modeSupplied = -not [string]::IsNullOrWhiteSpace($Mode)
    $connectorSupplied = -not [string]::IsNullOrWhiteSpace($Connector)
    if ($modeSupplied -xor $connectorSupplied) {
        throw '-Mode and -Connector must be supplied together (they are the QA shorthand pair)'
    }
    if ($modeSupplied -and (-not [string]::IsNullOrWhiteSpace($Config) -or
            -not [string]::IsNullOrWhiteSpace($Manifest))) {
        throw '-Mode / -Connector are mutually exclusive with -Config / -Manifest'
    }
    if ($modeSupplied -and [bool]$DeferredConfig) {
        throw '-Mode / -Connector cannot be combined with -DeferredConfig'
    }
    if ($modeSupplied -and $Action -ne 'Install' -and $Action -ne 'Upgrade' -and $Action -ne 'Repair') {
        throw '-Mode / -Connector are valid only with Install, Upgrade, or Repair'
    }
    if ($modeSupplied) {
        $renderedConnectors = ConvertTo-DefenseClawConnectorList -Connector $Connector
        $renderedConfigBody = Get-DefenseClawRenderedEnterpriseConfig `
            -Mode $Mode -Connectors $renderedConnectors
        $renderedManifestBody = Get-DefenseClawRenderedEnterpriseTargets `
            -Connectors $renderedConnectors
        $renderRoot = $bootstrapEnvironment.Path
        $renderedConfigPath = [IO.Path]::Combine($renderRoot, 'rendered-config.yaml')
        $renderedManifestPath = [IO.Path]::Combine($renderRoot, 'rendered-targets.yaml')
        [IO.File]::WriteAllText(
            $renderedConfigPath, $renderedConfigBody, [Text.UTF8Encoding]::new($false)
        )
        [IO.File]::WriteAllText(
            $renderedManifestPath, $renderedManifestBody, [Text.UTF8Encoding]::new($false)
        )
        $Config = $renderedConfigPath
        $Manifest = $renderedManifestPath
    }
    try {
        $modulePath = Assert-DefenseClawBootstrapModuleTrust `
            -Path $modulePath `
            -AllowUnsignedModule:$AllowUnsigned
    }
    catch {
        throw "DefenseClaw enterprise installer rejected its module before import: $($_.Exception.Message)"
    }
    # This is the last path-identity check before PowerShell opens the module.
    $importRoot = [IO.Path]::GetPathRoot($modulePath)
    $importDrive = $importRoot.TrimEnd('\')
    $bootstrapNativePath = Initialize-DefenseClawBootstrapNativePath
    $bootstrapNativePath::AssertCanonicalDriveRoot(
        $importRoot,
        $importDrive
    )
    Microsoft.PowerShell.Core\Import-Module `
        -Name $modulePath `
        -Force `
        -ErrorAction Stop

    $arguments = @{
        Action = $Action
        BrokerBinary = $BrokerBinary
        ProviderLibrary = $ProviderLibrary
        GatewayBinary = $GatewayBinary
        HookBinary = $HookBinary
        CLIBinary = $CLIBinary
        Config = $Config
        Manifest = $Manifest
        InstallRoot = $InstallRoot
        StateRoot = $StateRoot
        GatewayServiceName = $GatewayServiceName
        GuardianServiceName = $GuardianServiceName
        CertificationCodexHome = $CertificationCodexHome
        CoreHardeningCertification = [bool]$CoreHardeningCertification
        NoStart = [bool]$NoStart
        Purge = [bool]$Purge
        AttestAgentApplicationControl = [bool]$AttestAgentApplicationControl
        AttestClaudeEffectivePolicy = [bool]$AttestClaudeEffectivePolicy
        SelfUninstallCallerPID = $SelfUninstallCallerPID
        # The exact service/root/CODEX_HOME grammar scopes this relaxation for
        # every certification lifecycle action, including pre-install Status.
        AllowUnsigned = [bool]$AllowUnsigned
        # Retained in the module invocation shape for CLI compatibility. The
        # entry gate above rejects it before bootstrap creation, and the module
        # repeats that rejection for direct callers.
        DeferredConfig = [bool]$DeferredConfig
        InstallerSource = $PSCommandPath
        ModuleSource = $modulePath
    }
    $result = DefenseClawEnterprise\Invoke-DefenseClawEnterpriseLifecycle @arguments
    if ($null -ne $result.PSObject.Properties['ok'] -and -not [bool]$result.ok) {
        $exitCode = 1
    }
}
catch {
    $failureMessage = $_.Exception.Message
    $exitCode = 1
}
finally {
    if ($null -ne $bootstrapEnvironment) {
        $cleanupFailures = [Collections.Generic.List[string]]::new()
        # Restore TEMP/TMP and cache env vars BEFORE the tree they still
        # point into gets removed. Otherwise any temp file created during
        # the enumeration window of Remove-DefenseClawBootstrapEnvironment
        # can trip Directory.Delete or its final leftover-check. The
        # failure path inside New-DefenseClawBootstrapEnvironment already
        # uses this safer order.
        try {
            Restore-DefenseClawBootstrapEnvironment `
                -Context $bootstrapEnvironment
        }
        catch {
            $cleanupFailures.Add(
                "bootstrap environment restore failed: $($_.Exception.Message)"
            )
        }
        try {
            Remove-DefenseClawBootstrapEnvironment `
                -Context $bootstrapEnvironment
        }
        catch {
            $cleanupFailures.Add(
                "protected bootstrap cleanup failed: $($_.Exception.Message)"
            )
        }
        if ($cleanupFailures.Count -gt 0) {
            $cleanupDetail = $cleanupFailures -join '; '
            if ([string]::IsNullOrWhiteSpace($failureMessage)) {
                # Leave the action's own exit code alone: tidying our temp tree
                # is not part of its outcome, and ok:false already set the code.
                Microsoft.PowerShell.Utility\Write-Warning -Message $cleanupDetail
            }
            else {
                $failureMessage += "; $cleanupDetail"
                $exitCode = 1
            }
        }
    }
}

if (-not [string]::IsNullOrWhiteSpace($failureMessage)) {
    if ($Json) {
        [pscustomobject]@{
            schema_version = 1
            ok = $false
            action = $Action.ToLowerInvariant()
            error = $failureMessage
            errors = @($failureMessage)
        } | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 6 -Compress
    }
    else {
        Microsoft.PowerShell.Utility\Write-Error `
            -ErrorAction Continue `
            -Message (
                "DefenseClaw Windows enterprise {0} failed: {1}" -f
                $Action.ToLowerInvariant(),
                $failureMessage
            )
    }
}
elseif ($Json) {
    $result | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 12 -Compress
}
else {
    Microsoft.PowerShell.Utility\Write-Host (
        "DefenseClaw Windows enterprise {0}: OK" -f
        $Action.ToLowerInvariant()
    )
    if ($null -ne $result.gateway_service_state) {
        Microsoft.PowerShell.Utility\Write-Host (
            "  Gateway service: {0}" -f $result.gateway_service_state
        )
    }
    if ($null -ne $result.guardian_service_state) {
        Microsoft.PowerShell.Utility\Write-Host (
            "  Guardian service: {0}" -f $result.guardian_service_state
        )
    }
    if ($null -ne $result.gateway_ready) {
        Microsoft.PowerShell.Utility\Write-Host (
            "  Gateway health probe: {0}" -f $result.gateway_ready
        )
    }
    $selfCleanupProperty = $result.PSObject.Properties[
        'self_uninstall_cleanup_pending'
    ]
    if ($null -ne $selfCleanupProperty -and
        [bool]$selfCleanupProperty.Value) {
        Microsoft.PowerShell.Utility\Write-Host (
            '  Installed CLI cleanup: pending until this CLI process exits'
        )
    }
    $clientReloadProperty = $result.PSObject.Properties[
        'cached_enterprise_clients_require_reload'
    ]
    if ($null -ne $clientReloadProperty -and
        [bool]$clientReloadProperty.Value) {
        Microsoft.PowerShell.Utility\Write-Host (
            '  Enterprise clients already running during uninstall must reload'
        )
    }
    if ($null -ne $result.guardian_ready) {
        Microsoft.PowerShell.Utility\Write-Host (
            "  Guardian coverage: {0}" -f $result.guardian_ready
        )
    }
}
if ($exitCode -ne 0) {
    exit $exitCode
}
