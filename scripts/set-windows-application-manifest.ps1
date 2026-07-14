# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

<#
.SYNOPSIS
    Embeds and verifies the DefenseClaw setup Win32 application manifest.

.DESCRIPTION
    Uses only inbox Win32 resource APIs so release builds do not depend on mt.exe
    or a separately installed Windows SDK. The manifest is applied before
    Authenticode signing and read back byte-for-byte from RT_MANIFEST resource 1.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Executable,
    [Parameter(Mandatory)]
    [string]$Manifest,
    [switch]$VerifyOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $IsWindows) {
    throw 'Windows application manifests can only be embedded and verified on Windows.'
}

$executablePath = [IO.Path]::GetFullPath($Executable)
$manifestPath = [IO.Path]::GetFullPath($Manifest)
if (-not (Test-Path -LiteralPath $executablePath -PathType Leaf)) {
    throw "Setup executable not found: $executablePath"
}
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw "Setup manifest not found: $manifestPath"
}

$manifestBytes = [IO.File]::ReadAllBytes($manifestPath)
$manifestText = [Text.UTF8Encoding]::new($false, $true).GetString($manifestBytes)
$xml = [xml]$manifestText
$executionLevels = @($xml.SelectNodes("//*[local-name()='requestedExecutionLevel']"))
if ($executionLevels.Count -ne 1) {
    throw "Setup manifest must contain exactly one requestedExecutionLevel; found $($executionLevels.Count)."
}
$executionLevel = $executionLevels[0]
if ($executionLevel.level -ne 'asInvoker' -or $executionLevel.uiAccess -ne 'false') {
    throw 'Setup manifest must request level=asInvoker and uiAccess=false.'
}
foreach ($forbidden in @('requireAdministrator', 'highestAvailable', 'autoElevate')) {
    if ($manifestText.IndexOf($forbidden, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "Setup manifest contains forbidden elevation marker: $forbidden"
    }
}

if (-not ('DefenseClaw.SetupManifestResource' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace DefenseClaw
{
    public static class SetupManifestResource
    {
        private static readonly IntPtr ManifestResourceType = new IntPtr(24);
        private static readonly IntPtr CreateProcessManifestResourceId = new IntPtr(1);
        private const uint LoadLibraryAsDataFile = 0x00000002;
        private const uint LoadLibraryAsImageResource = 0x00000020;

        [DllImport("kernel32.dll", EntryPoint = "BeginUpdateResourceW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr BeginUpdateResource(string fileName, [MarshalAs(UnmanagedType.Bool)] bool deleteExistingResources);

        [DllImport("kernel32.dll", EntryPoint = "UpdateResourceW", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UpdateResource(
            IntPtr update,
            IntPtr type,
            IntPtr name,
            ushort language,
            byte[] data,
            uint dataLength);

        [DllImport("kernel32.dll", EntryPoint = "EndUpdateResourceW", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool EndUpdateResource(IntPtr update, [MarshalAs(UnmanagedType.Bool)] bool discard);

        [DllImport("kernel32.dll", EntryPoint = "LoadLibraryExW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibraryEx(string fileName, IntPtr file, uint flags);

        [DllImport("kernel32.dll", EntryPoint = "FindResourceW", SetLastError = true)]
        private static extern IntPtr FindResource(IntPtr module, IntPtr name, IntPtr type);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint SizeofResource(IntPtr module, IntPtr resource);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LoadResource(IntPtr module, IntPtr resource);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LockResource(IntPtr resourceData);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FreeLibrary(IntPtr module);

        public static void Write(string executable, byte[] manifest)
        {
            IntPtr update = BeginUpdateResource(executable, false);
            if (update == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "BeginUpdateResourceW failed");
            bool committed = false;
            try
            {
                if (!UpdateResource(
                    update,
                    ManifestResourceType,
                    CreateProcessManifestResourceId,
                    0,
                    manifest,
                    checked((uint)manifest.Length)))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "UpdateResourceW failed");
                }
                if (!EndUpdateResource(update, false))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "EndUpdateResourceW failed");
                committed = true;
            }
            finally
            {
                if (!committed)
                    EndUpdateResource(update, true);
            }
        }

        public static byte[] Read(string executable)
        {
            IntPtr module = LoadLibraryEx(
                executable,
                IntPtr.Zero,
                LoadLibraryAsDataFile | LoadLibraryAsImageResource);
            if (module == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "LoadLibraryExW failed");
            try
            {
                IntPtr resource = FindResource(
                    module,
                    CreateProcessManifestResourceId,
                    ManifestResourceType);
                if (resource == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "FindResourceW could not find RT_MANIFEST/1");
                uint size = SizeofResource(module, resource);
                if (size == 0)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "SizeofResource failed");
                IntPtr loaded = LoadResource(module, resource);
                if (loaded == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "LoadResource failed");
                IntPtr address = LockResource(loaded);
                if (address == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "LockResource failed");
                byte[] result = new byte[checked((int)size)];
                Marshal.Copy(address, result, 0, result.Length);
                return result;
            }
            finally
            {
                FreeLibrary(module);
            }
        }
    }
}
'@
}

if (-not $VerifyOnly) {
    [DefenseClaw.SetupManifestResource]::Write($executablePath, $manifestBytes)
}
$embedded = [DefenseClaw.SetupManifestResource]::Read($executablePath)
if ([Convert]::ToBase64String($manifestBytes) -cne [Convert]::ToBase64String($embedded)) {
    throw 'Embedded setup RT_MANIFEST resource does not exactly match setup.manifest.'
}

Write-Host "Verified asInvoker RT_MANIFEST resource: $executablePath"
