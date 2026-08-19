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

    [string]$GatewayBinary,
    [string]$HookBinary,
    [string]$CLIBinary,
    [string]$Config,
    [string]$Manifest,

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
    [switch]$AttestCodexTrustedHookLauncher,
    [string]$CodexTrustedHookLauncherBinary,
    # Spec 003 (docs/specs/003-windows-deferred-config/): opt in to
    # the UCB-friendly late-config install. When set, -Config and
    # -Manifest may be omitted; the module's Get-DefenseClawLifecycleSources
    # + post-copy existence check both accept a missing source, the
    # canonical drop-point directories are provisioned with ACLs but
    # no file bodies, and both services are registered stopped so the
    # gateway daemon's and hook-guardian's fsnotify wait loops can
    # pick the files up when UCB atomically drops them.
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

$bootstrapEnvironment = $null
$result = $null
$failureMessage = $null
$exitCode = 0
try {
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
    $codexLauncherBinaryProvided = -not [string]::IsNullOrWhiteSpace(
        $CodexTrustedHookLauncherBinary
    )
    if ($CoreHardeningCertification -and
        ($AttestAgentApplicationControl -or
            $AttestClaudeEffectivePolicy -or
            $AttestCodexTrustedHookLauncher -or
            $codexLauncherBinaryProvided)) {
        throw (
            '-CoreHardeningCertification cannot be combined with production ' +
            'application-control, Claude-policy, or trusted-launcher attestations'
        )
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
        AttestCodexTrustedHookLauncher = [bool]$AttestCodexTrustedHookLauncher
        CodexTrustedHookLauncherBinary = $CodexTrustedHookLauncherBinary
        SelfUninstallCallerPID = $SelfUninstallCallerPID
        # The exact service/root/CODEX_HOME grammar scopes this relaxation for
        # every certification lifecycle action, including pre-install Status.
        AllowUnsigned = [bool]$AllowUnsigned
        # Spec 003 Workstream B — see the [switch]$DeferredConfig
        # param block above for the rationale. Only meaningful for
        # Install actions in managed-enterprise deployments; the
        # module's Get-DefenseClawLifecycleSources call ignores it
        # for other actions.
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
