# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

<#
.SYNOPSIS
    DefenseClaw installer for Windows (PowerShell).

.DESCRIPTION
    Installs DefenseClaw from pre-built release artifacts on Windows. Legacy
    releases use a gateway ZIP and wheel; 0.8.4+ releases use signed,
    manifest-bound protected envelopes that are decoded only after provenance
    verification. This is the Windows counterpart to scripts/install.sh; it lands:

      * <home>\bin\defenseclaw-gateway.exe  (the Go gateway/sidecar binary)
      * <home>\bin\defenseclaw.cmd          (shim to the CLI in the venv)

    and adds that bin dir to the user PATH. Only Python + uv are required; no Go,
    Node.js, or git. Connector-specific wiring (Codex, Claude Code, ...) is done
    by the cross-platform CLI via `defenseclaw init` / `quickstart`.

    Layout matches scripts/install.sh and the managed upgrade path: binaries
    land in %USERPROFILE%\.local\bin and the CLI venv lives in
    %USERPROFILE%\.defenseclaw\.venv. This installer is fresh-install-only;
    existing installations must use scripts\upgrade.ps1 (or the supported CLI
    upgrade command) so release manifests and hard-cut bridge rules are applied.

.EXAMPLE
    $Version = "0.8.4"
    $InstallUrl = "https://raw.githubusercontent.com/cisco-ai-defense/defenseclaw/$Version/scripts/install.ps1"
    & ([scriptblock]::Create((irm $InstallUrl))) -Version $Version

.EXAMPLE
    # Pin a version and pick a connector, non-interactively:
    .\install.ps1 -Version 0.7.0 -Connector codex -Yes -Quickstart

.EXAMPLE
    # Install from a complete authenticated release-asset directory:
    .\install.ps1 -Local C:\path\to\release-assets
    # An unsigned directory produced by `make dist` is rejected for 0.8.4+.
#>

[CmdletBinding()]
param(
    [string]$Connector = "",
    [string]$Version = "",
    [string]$Local = "",
    [ValidateSet("observe", "action", "")]
    [string]$QuickstartMode = "",
    [switch]$Quickstart,
    [switch]$NoOpenclaw,
    [switch]$Yes,
    [switch]$Help,
    [Parameter(DontShow = $true)][switch]$TestMode,
    [Parameter(DontShow = $true)][switch]$InjectFailureBeforeShim,
    [Parameter(DontShow = $true)][switch]$InjectConcurrentShimBeforePublish,
    [Parameter(DontShow = $true)][switch]$InjectPolicyCleanupFailure
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Prefer TLS 1.2+ on older Windows PowerShell (5.1) where the default can still
# be TLS 1.0/1.1; PowerShell 7 already negotiates modern protocols.
try {
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {
    # Property is read-only / unavailable on this host; ignore.
}

# ── Configuration ─────────────────────────────────────────────────────────────

$Repo = "cisco-ai-defense/defenseclaw"
$DefenseClawHome = if ($env:DEFENSECLAW_HOME) { $env:DEFENSECLAW_HOME } else { Join-Path $env:USERPROFILE ".defenseclaw" }
$Venv = Join-Path $DefenseClawHome ".venv"
# Binaries go to %USERPROFILE%\.local\bin to match scripts/install.sh and
# `defenseclaw upgrade` (which replaces the gateway there). The venv stays under
# DEFENSECLAW_HOME so a custom home still relocates the heavy CLI environment.
$InstallDir = Join-Path $env:USERPROFILE ".local\bin"
$script:ModernRelease = $false
$script:PolicyDir = ""
$script:PolicyCleanupWarning = ""
$script:WheelArtifact = ""
$script:GatewayArtifact = ""
$script:WheelPath = ""
$script:ProtectedWheelPath = ""
$script:GatewayBinary = ""
$script:WheelInnerSha256 = ""
$script:GatewayArchiveInnerSha256 = ""
$script:GatewayBinarySha256 = ""
$script:FreshInstallAttemptActive = $false
$script:FreshInstallClaims = $null
$script:FreshInstallOriginalUserPath = $null
$script:FreshInstallPublishedUserPath = $null
$script:FreshInstallOriginalProcessPath = $null
$script:FreshInstallPublishedProcessPath = $null

# Fresh-install cleanup must never turn a pathname check followed by
# Remove-Item into authority to delete a different object.  These native
# claims pin the exact Windows file ID without FILE_SHARE_DELETE.  Rollback
# marks that same opened object for deletion; a concurrently substituted path
# therefore survives.  Directory-tree rollback takes an identity snapshot
# before deleting any child and refuses changed/new entries by leaving the
# claimed root (and its residue) in place.
$freshInstallClaimSource = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace DefenseClaw.Install.FreshV1 {
    public sealed class FreshPathClaim : IDisposable {
        private const uint DELETE = 0x00010000;
        private const uint FILE_READ_ATTRIBUTES = 0x00000080;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
        private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        private const int FILE_DISPOSITION_INFO_CLASS = 4;
        private const int ERROR_FILE_NOT_FOUND = 2;
        private const int ERROR_PATH_NOT_FOUND = 3;
        private const int ERROR_FILE_EXISTS = 80;
        private const int ERROR_DIR_NOT_EMPTY = 145;
        private const int ERROR_ALREADY_EXISTS = 183;
        private const uint MOVEFILE_WRITE_THROUGH = 0x00000008;
        private const int MAX_TREE_DEPTH = 64;
        private const int MAX_TREE_NODES = 500000;
        private const long MAX_TREE_BYTES = 16L * 1024L * 1024L * 1024L;

        [StructLayout(LayoutKind.Sequential)]
        private struct FILETIME {
            public uint Low;
            public uint High;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BY_HANDLE_FILE_INFORMATION {
            public uint FileAttributes;
            public FILETIME CreationTime;
            public FILETIME LastAccessTime;
            public FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FILE_DISPOSITION_INFO {
            [MarshalAs(UnmanagedType.Bool)]
            public bool DeleteFile;
        }

        private sealed class TreeEntry {
            public string Path;
            public uint Volume;
            public ulong Index;
            public bool IsDirectory;
            public bool IsReparse;
            public int Depth;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle file,
            out BY_HANDLE_FILE_INFORMATION information);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetFileInformationByHandle(
            SafeFileHandle file,
            int informationClass,
            ref FILE_DISPOSITION_INFO information,
            uint bufferSize);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool MoveFileEx(
            string existingFileName,
            string newFileName,
            uint flags);

        private SafeFileHandle handle;
        private readonly uint volume;
        private readonly ulong index;
        private readonly bool directory;
        private readonly string path;

        private FreshPathClaim(
            string claimedPath,
            SafeFileHandle claimedHandle,
            BY_HANDLE_FILE_INFORMATION information,
            bool expectedDirectory) {
            bool observedDirectory = (information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            bool observedReparse = (information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
            if (observedDirectory != expectedDirectory || observedReparse) {
                claimedHandle.Dispose();
                throw new InvalidOperationException(
                    "fresh-install claim is not an exact real " +
                    (expectedDirectory ? "directory: " : "file: ") + claimedPath);
            }
            path = Path.GetFullPath(claimedPath);
            handle = claimedHandle;
            volume = information.VolumeSerialNumber;
            index = ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow;
            directory = expectedDirectory;
        }

        public string PathValue { get { return path; } }
        public string Identity {
            get { return volume.ToString("x8") + ":" + index.ToString("x16"); }
        }

        public static FreshPathClaim Open(string path, bool directory, bool deleteAccess) {
            SafeFileHandle opened = OpenHandle(path, directory, deleteAccess, false);
            BY_HANDLE_FILE_INFORMATION information = Information(opened, path);
            return new FreshPathClaim(path, opened, information, directory);
        }

        public static FreshPathClaim TransitionOpenedFileCustody(
            SafeFileHandle source,
            string path,
            bool directory) {
            BY_HANDLE_FILE_INFORMATION expected = Information(source, path);
            source.Dispose();
            SafeFileHandle retained = OpenHandle(path, directory, true, false);
            BY_HANDLE_FILE_INFORMATION observed = Information(retained, path);
            if (!SameIdentity(
                observed,
                expected.VolumeSerialNumber,
                FileIndex(expected))) {
                retained.Dispose();
                throw new InvalidOperationException(
                    "fresh-install file changed while entering rollback custody and was preserved: " + path);
            }
            return new FreshPathClaim(path, retained, observed, directory);
        }

        public static bool DeleteOpenedFileExact(SafeFileHandle opened) {
            if (opened == null || opened.IsInvalid || opened.IsClosed) {
                return false;
            }
            return MarkDelete(opened, false);
        }

        public static bool MoveDirectoryNoReplace(string source, string destination) {
            if (MoveFileEx(
                Path.GetFullPath(source),
                Path.GetFullPath(destination),
                MOVEFILE_WRITE_THROUGH)) {
                return true;
            }
            int error = Marshal.GetLastWin32Error();
            if (error == ERROR_FILE_EXISTS || error == ERROR_ALREADY_EXISTS) {
                return false;
            }
            throw new Win32Exception(
                error,
                "could not atomically publish fresh-install directory: " + destination);
        }

        private static SafeFileHandle OpenHandle(
            string path,
            bool directory,
            bool deleteAccess,
            bool allowMissing) {
            uint access = FILE_READ_ATTRIBUTES | (deleteAccess ? DELETE : 0);
            uint flags = FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS;
            SafeFileHandle opened = CreateFile(
                Path.GetFullPath(path),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                IntPtr.Zero,
                OPEN_EXISTING,
                flags,
                IntPtr.Zero);
            if (!opened.IsInvalid) {
                return opened;
            }
            int error = Marshal.GetLastWin32Error();
            opened.Dispose();
            if (allowMissing && (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)) {
                return null;
            }
            throw new Win32Exception(error, "could not bind fresh-install path: " + path);
        }

        private static BY_HANDLE_FILE_INFORMATION Information(
            SafeFileHandle opened,
            string path) {
            BY_HANDLE_FILE_INFORMATION information;
            if (!GetFileInformationByHandle(opened, out information)) {
                int error = Marshal.GetLastWin32Error();
                opened.Dispose();
                throw new Win32Exception(error, "could not read fresh-install identity: " + path);
            }
            return information;
        }

        private static ulong FileIndex(BY_HANDLE_FILE_INFORMATION information) {
            return ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow;
        }

        private static bool SameIdentity(
            BY_HANDLE_FILE_INFORMATION information,
            uint expectedVolume,
            ulong expectedIndex) {
            return information.VolumeSerialNumber == expectedVolume &&
                FileIndex(information) == expectedIndex;
        }

        private static bool MarkDelete(SafeFileHandle opened, bool allowNotEmpty) {
            FILE_DISPOSITION_INFO information = new FILE_DISPOSITION_INFO();
            information.DeleteFile = true;
            if (SetFileInformationByHandle(
                opened,
                FILE_DISPOSITION_INFO_CLASS,
                ref information,
                (uint)Marshal.SizeOf(typeof(FILE_DISPOSITION_INFO)))) {
                return true;
            }
            int error = Marshal.GetLastWin32Error();
            if (allowNotEmpty && error == ERROR_DIR_NOT_EMPTY) {
                return false;
            }
            throw new Win32Exception(error, "could not delete exact fresh-install object");
        }

        public bool DeleteFileExact() {
            if (directory) {
                throw new InvalidOperationException("file rollback received a directory claim");
            }
            bool deleted = MarkDelete(handle, false);
            Dispose();
            return deleted;
        }

        public bool DeleteEmptyDirectoryExact() {
            if (!directory) {
                throw new InvalidOperationException("directory rollback received a file claim");
            }
            bool deleted = MarkDelete(handle, true);
            if (deleted) {
                Dispose();
            }
            return deleted;
        }

        private void SnapshotDirectory(
            string current,
            int depth,
            List<TreeEntry> entries,
            ref long bytes) {
            if (depth > MAX_TREE_DEPTH) {
                throw new InvalidOperationException("fresh-install tree exceeds rollback depth bound");
            }
            foreach (string child in Directory.GetFileSystemEntries(current)) {
                SafeFileHandle opened = OpenHandle(child, false, true, false);
                BY_HANDLE_FILE_INFORMATION information;
                try {
                    information = Information(opened, child);
                } catch {
                    opened.Dispose();
                    throw;
                }
                bool isDirectory = (information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
                bool isReparse = (information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
                if (isDirectory) {
                    opened.Dispose();
                    opened = OpenHandle(child, true, true, false);
                    information = Information(opened, child);
                    isDirectory = (information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
                    isReparse = (information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
                }
                TreeEntry entry = new TreeEntry();
                entry.Path = child;
                entry.Volume = information.VolumeSerialNumber;
                entry.Index = FileIndex(information);
                entry.IsDirectory = isDirectory;
                entry.IsReparse = isReparse;
                entry.Depth = depth;
                entries.Add(entry);
                bytes += ((long)information.FileSizeHigh << 32) | information.FileSizeLow;
                opened.Dispose();
                if (entries.Count > MAX_TREE_NODES || bytes > MAX_TREE_BYTES) {
                    throw new InvalidOperationException("fresh-install tree exceeds rollback size bound");
                }
                if (entry.Volume != volume) {
                    throw new InvalidOperationException("fresh-install tree crosses a volume boundary");
                }
                if (isDirectory && !isReparse) {
                    SnapshotDirectory(child, depth + 1, entries, ref bytes);
                }
            }
        }

        public bool DeleteTreeExact() {
            if (!directory) {
                throw new InvalidOperationException("tree rollback received a file claim");
            }
            List<TreeEntry> entries = new List<TreeEntry>();
            long bytes = 0;
            SnapshotDirectory(path, 1, entries, ref bytes);
            entries.Sort(delegate(TreeEntry left, TreeEntry right) {
                int depthOrder = right.Depth.CompareTo(left.Depth);
                if (depthOrder != 0) {
                    return depthOrder;
                }
                return StringComparer.OrdinalIgnoreCase.Compare(right.Path, left.Path);
            });
            foreach (TreeEntry entry in entries) {
                SafeFileHandle current = OpenHandle(
                    entry.Path,
                    entry.IsDirectory,
                    true,
                    true);
                if (current == null) {
                    continue;
                }
                try {
                    BY_HANDLE_FILE_INFORMATION information = Information(current, entry.Path);
                    bool isDirectory = (information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
                    bool isReparse = (information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
                    if (!SameIdentity(information, entry.Volume, entry.Index) ||
                        isDirectory != entry.IsDirectory || isReparse != entry.IsReparse) {
                        return false;
                    }
                    if (!MarkDelete(current, entry.IsDirectory)) {
                        return false;
                    }
                } finally {
                    current.Dispose();
                }
            }
            return DeleteEmptyDirectoryExact();
        }

        public void Dispose() {
            if (handle != null) {
                handle.Dispose();
                handle = null;
            }
            GC.SuppressFinalize(this);
        }

        ~FreshPathClaim() {
            Dispose();
        }
    }
}
'@

if (-not ("DefenseClaw.Install.FreshV1.FreshPathClaim" -as [type])) {
    Add-Type -TypeDefinition $freshInstallClaimSource -Language CSharp
}

function New-PrivateDirectoryAcl {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = New-Object Security.Principal.SecurityIdentifier("S-1-5-18")
    $administrators = New-Object Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner($current)
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in @($current, $system, $administrators)) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    return $acl
}

function Assert-PrivateDirectoryAcl {
    param(
        [string]$Path,
        [Security.AccessControl.DirectorySecurity]$Expected = (New-PrivateDirectoryAcl)
    )
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Die "Private install path must be a real directory: $Path"
    }
    $verified = Get-Acl -LiteralPath $Path
    $current = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $section = [Security.AccessControl.AccessControlSections]::Access
    if (
        -not $verified.AreAccessRulesProtected -or
        $verified.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $current.Value -or
        $verified.GetSecurityDescriptorSddlForm($section) -ne $Expected.GetSecurityDescriptorSddlForm($section)
    ) {
        Die "Private install directory DACL verification failed: $Path"
    }
}

function New-PrivateDirectory {
    param([string]$Path)
    if (Test-InstallMarker -Path $Path) { Die "Private install path already exists: $Path" }
    $acl = New-PrivateDirectoryAcl
    $created = $false
    try {
        if ($PSVersionTable.PSEdition -eq "Core") {
            $directory = New-Object IO.DirectoryInfo($Path)
            [IO.FileSystemAclExtensions]::Create($directory, $acl)
        } else {
            # Windows PowerShell 5.1 exposes the equivalent ACL-at-create-time
            # overload directly on Directory.
            [void][IO.Directory]::CreateDirectory($Path, $acl)
        }
        $created = $true
        Assert-PrivateDirectoryAcl -Path $Path -Expected $acl
        if (@(Get-ChildItem -LiteralPath $Path -Force).Count -ne 0) {
            Die "Private install directory was not empty immediately after creation: $Path"
        }
    } catch {
        if ($created -and (Test-Path -LiteralPath $Path -PathType Container)) {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
        }
        throw
    }
    return [IO.Path]::GetFullPath($Path)
}

function Remove-PrivateDirectory {
    param([string]$Path)
    if (-not $Path -or -not (Test-InstallMarker -Path $Path)) { return }
    Assert-PrivateDirectoryAcl -Path $Path
    Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
    if (Test-InstallMarker -Path $Path) { Die "Private install directory cleanup failed: $Path" }
}

function Close-ReleasePolicyCustody {
    if (-not $script:PolicyDir) { return }

    # Policy custody contains authenticated but decoded wheel/gateway bytes, so
    # close it before committing the public install. A transient Defender or
    # indexer handle must not, however, convert cleanup into authority to roll
    # back a fully healthy payload or replace the original install diagnostic.
    $policyToRemove = $script:PolicyDir
    $script:PolicyDir = ""
    $lastCleanupError = "private policy custody still exists after cleanup"
    $attemptCount = if ($InjectPolicyCleanupFailure) { 1 } else { 3 }
    for ($attempt = 1; $attempt -le $attemptCount; $attempt++) {
        try {
            if ($InjectPolicyCleanupFailure) {
                throw "Injected private release-policy cleanup failure"
            }
            Remove-PrivateDirectory -Path $policyToRemove
            if (-not (Test-InstallMarker -Path $policyToRemove)) { return }
            $lastCleanupError = "private policy custody remained after cleanup attempt $attempt"
        } catch {
            $lastCleanupError = [string]$_.Exception.Message
        }
        if ($attempt -lt $attemptCount) {
            try { Start-Sleep -Milliseconds (50 * $attempt) } catch {}
        }
    }

    $script:PolicyCleanupWarning = (
        "Private release-policy cleanup was incomplete; installer-owned custody " +
        "remains at '$policyToRemove'. Last cleanup error: $lastCleanupError"
    )
    try {
        Write-Warn2 $script:PolicyCleanupWarning
    } catch {
        try { [Console]::Error.WriteLine($script:PolicyCleanupWarning) } catch {}
    }
}

function Get-OwnerDaclSddl {
    param([string]$Path)
    $sections = [Security.AccessControl.AccessControlSections]::Owner -bor `
        [Security.AccessControl.AccessControlSections]::Access
    return (Get-Acl -LiteralPath $Path).GetSecurityDescriptorSddlForm($sections)
}

function New-PrivateFileAcl {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = New-Object Security.Principal.SecurityIdentifier("S-1-5-18")
    $administrators = New-Object Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetOwner($current)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($current, $system, $administrators)) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    return $acl
}

function Get-PrivateFileSddl {
    $sections = [Security.AccessControl.AccessControlSections]::Owner -bor `
        [Security.AccessControl.AccessControlSections]::Access
    return (New-PrivateFileAcl).GetSecurityDescriptorSddlForm($sections)
}

function Assert-PrivateFileAcl {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Die "Private install artifact must be a real file: $Path"
    }
    if ((Get-OwnerDaclSddl -Path $Path) -ne (Get-PrivateFileSddl)) {
        Die "Private install artifact DACL verification failed: $Path"
    }
}

function Set-PrivateFileAcl {
    param([string]$Path)
    $acl = New-PrivateFileAcl
    Set-Acl -LiteralPath $Path -AclObject $acl
    Assert-PrivateFileAcl -Path $Path
}

function New-PrivateFileStream {
    param([string]$Path)
    $acl = New-PrivateFileAcl
    if ($PSVersionTable.PSEdition -eq "Core") {
        $file = New-Object IO.FileInfo($Path)
        return [IO.FileSystemAclExtensions]::Create(
            $file,
            [IO.FileMode]::CreateNew,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [IO.FileShare]::None,
            65536,
            [IO.FileOptions]::WriteThrough,
            $acl
        )
    }
    return New-Object IO.FileStream(
        $Path,
        [IO.FileMode]::CreateNew,
        [Security.AccessControl.FileSystemRights]::FullControl,
        [IO.FileShare]::None,
        65536,
        [IO.FileOptions]::WriteThrough,
        $acl
    )
}

function Assert-ExactPrivateArtifactDigest {
    param([string]$Path, [string]$ExpectedSha256, [string]$Label)
    if ($ExpectedSha256 -notmatch '^[0-9a-fA-F]{64}$') {
        Die "Authenticated $Label lacks its decoded SHA-256 custody digest"
    }
    Assert-PrivateFileAcl -Path $Path
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $ExpectedSha256.ToLowerInvariant()) {
        Die "Authenticated $Label changed before consumption; refusing installation"
    }
}

function Copy-AuthenticatedPrivateArtifact {
    param(
        [string]$Source,
        [string]$Destination,
        [string]$ExpectedSha256 = "",
        [switch]$ProtectedEnvelope,
        [switch]$FreshInstallDestination
    )
    if (Test-InstallMarker -Path $Destination) {
        Die "Private materialization destination already exists: $Destination"
    }
    if($ProtectedEnvelope -and $ExpectedSha256 -notmatch '^[0-9a-fA-F]{64}$'){
        Die "Protected materialization requires one signed outer SHA-256 digest: $Source"
    }
    $sourceStream = $null
    $output = $null
    $outerHash = $null
    $innerHash = $null
    $created = $false
    $freshClaimRegistered = $false
    try {
        $sourceStream = [IO.File]::Open($Source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        if($ProtectedEnvelope){
            $outerHash=[Security.Cryptography.SHA256]::Create()
            $magic=[Text.Encoding]::ASCII.GetBytes("DEFENSECLAW-PROTECTED-ARTIFACT-V1`n")
            $observed=New-Object byte[] $magic.Length
            $headerRead=0
            while($headerRead -lt $magic.Length){
                $count=$sourceStream.Read($observed,$headerRead,$magic.Length-$headerRead)
                if($count -eq 0){break}
                $headerRead += $count
            }
            if($headerRead -ne $magic.Length -or [Convert]::ToBase64String($observed) -ne [Convert]::ToBase64String($magic)){
                throw "Protected release artifact envelope is invalid: $Source"
            }
            [void]$outerHash.TransformBlock($observed,0,$observed.Length,$observed,0)
            if($sourceStream.Length -le $magic.Length){throw "Protected release artifact payload is empty: $Source"}
        }
        $output = New-PrivateFileStream -Path $Destination
        $created = $true
        $innerHash = [Security.Cryptography.SHA256]::Create()
        $buffer=New-Object byte[] (1024 * 1024)
        while(($read=$sourceStream.Read($buffer,0,$buffer.Length)) -gt 0){
            if($ProtectedEnvelope){
                [void]$outerHash.TransformBlock($buffer,0,$read,$buffer,0)
                for($index=0;$index -lt $read;$index++){
                    $buffer[$index]=$buffer[$index] -bxor 0xA5
                }
            }
            $output.Write($buffer,0,$read)
            [void]$innerHash.TransformBlock($buffer,0,$read,$buffer,0)
        }
        if($ProtectedEnvelope){
            [void]$outerHash.TransformFinalBlock((New-Object byte[] 0),0,0)
            $observedOuter=[BitConverter]::ToString($outerHash.Hash).Replace('-','').ToLowerInvariant()
            if($observedOuter -ne $ExpectedSha256.ToLowerInvariant()){
                throw "Protected release artifact changed after checksum authentication"
            }
        }
        [void]$innerHash.TransformFinalBlock((New-Object byte[] 0),0,0)
        $observedInner=[BitConverter]::ToString($innerHash.Hash).Replace('-','').ToLowerInvariant()
        if(-not $ProtectedEnvelope -and $ExpectedSha256 -and $observedInner -ne $ExpectedSha256.ToLowerInvariant()){
            throw "Private materialized artifact digest mismatch"
        }
        $output.Flush($true)
        if ($FreshInstallDestination) {
            # Verify and retain the exact CreateNew handle before its exclusive
            # sharing window closes.  No pathname re-open can bind rollback to
            # a concurrently substituted gateway.
            $verificationHash = [Security.Cryptography.SHA256]::Create()
            try {
                $output.Position = 0
                $sameHandleDigest = [BitConverter]::ToString(
                    $verificationHash.ComputeHash($output)
                ).Replace('-','').ToLowerInvariant()
            } finally {
                $verificationHash.Dispose()
            }
            if ($sameHandleDigest -ne $observedInner) {
                throw "Private materialized artifact changed on its opened install handle"
            }
            Add-FreshInstallStreamClaim -Stream $output -Path $Destination
            $freshClaimRegistered = $true
        }
    } catch {
        if ($FreshInstallDestination -and $output -and -not $freshClaimRegistered) {
            try {
                [void][DefenseClaw.Install.FreshV1.FreshPathClaim]::DeleteOpenedFileExact(
                    $output.SafeFileHandle
                )
            } catch {
                # The exact opened object could not be retired. Preserve the
                # uncertain pathname rather than deleting through it.
            }
        }
        if ($output) { $output.Dispose(); $output = $null }
        if ($created -and -not $FreshInstallDestination) {
            Remove-Item -LiteralPath $Destination -Force -ErrorAction SilentlyContinue
        }
        Die "Could not materialize an authenticated private install artifact: $Destination"
    } finally {
        if ($output) { $output.Dispose() }
        if ($sourceStream) { $sourceStream.Dispose() }
        if ($outerHash) { $outerHash.Dispose() }
        if ($innerHash) { $innerHash.Dispose() }
    }
    if (-not $FreshInstallDestination) {
        Assert-PrivateFileAcl -Path $Destination
        $actual = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $observedInner) {
            Remove-Item -LiteralPath $Destination -Force -ErrorAction SilentlyContinue
            Die "Private materialized artifact changed after authenticated copy: $Destination"
        }
    }
    return $observedInner
}

# Keep in sync with cli/defenseclaw/connector_paths.py KNOWN_CONNECTORS.
# PowerShell runs on Windows, where OpenClaw/ZeptoClaw proxy connectors are
# intentionally hidden because the native Windows path is hook-only.
$ConnectorChoices = @(
    "codex", "claudecode", "hermes", "cursor",
    "windsurf", "geminicli", "copilot", "openhands",
    "antigravity", "opencode", "omnigent", "none"
)
$HookConnectors = $ConnectorChoices | Where-Object { $_ -notin @("codex", "claudecode", "none") }

# ── Logging ───────────────────────────────────────────────────────────────────

function Write-Info  { param([string]$Msg) Write-Host "  > $Msg" -ForegroundColor Blue }
function Write-Ok    { param([string]$Msg) Write-Host "  + $Msg" -ForegroundColor Green }
function Write-Warn2 { param([string]$Msg) Write-Host "  ! $Msg" -ForegroundColor Yellow }
function Write-Err2  { param([string]$Msg) Write-Host "  x $Msg" -ForegroundColor Red }
function Write-Step  { param([string]$Msg) Write-Host "`n--- $Msg" -ForegroundColor Cyan }
function Die         { param([string]$Msg) throw $Msg }

function Show-Help {
    @"

DefenseClaw Installer (Windows)

Usage:
  `$Version = "0.8.4"
  `$InstallUrl = "https://raw.githubusercontent.com/$Repo/`$Version/scripts/install.ps1"
  & ([scriptblock]::Create((irm `$InstallUrl))) -Version `$Version
  .\install.ps1 -Local C:\path\to\release-assets  # complete authenticated assets
  .\install.ps1 -Yes                          # non-interactive
  .\install.ps1 -Connector codex -Quickstart  # pick connector + bootstrap

Options:
  -Connector <name>    Pick agent connector ($($ConnectorChoices -join '|'))
  -NoOpenclaw          Install gateway/CLI only when no connector is selected
  -Version <x.y.z>     Install a specific release version
  -Local <dir>         Fresh install from a complete local release-asset directory
  -Quickstart          Run 'defenseclaw quickstart --non-interactive' post-install
  -QuickstartMode <m>  Pass --mode m to quickstart (observe|action)
  -Yes                 Skip confirmation prompts (for CI/automation)
  -Help                Show this help

Environment variables:
  DEFENSECLAW_HOME     Install root (default: %USERPROFILE%\.defenseclaw)

"@ | Write-Host
}

# ── Utilities ─────────────────────────────────────────────────────────────────

function Test-HasCommand {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Test-InstallMarker {
    param([string]$Path)

    if (Test-Path -LiteralPath $Path) { return $true }

    # Test-Path can report false for a dangling reparse point. Enumerating the
    # parent catches that entry without following it, so a broken installer
    # symlink cannot bypass the fresh-install-only boundary.
    $parent = Split-Path -Parent $Path
    $leaf = Split-Path -Leaf $Path
    if (-not $parent -or -not (Test-Path -LiteralPath $parent -PathType Container)) {
        return $false
    }
    try {
        return [bool](Get-ChildItem -LiteralPath $parent -Force -ErrorAction Stop |
            Where-Object { $_.Name -eq $leaf } |
            Select-Object -First 1)
    } catch {
        # An unreadable managed parent is not proof that the target is fresh.
        return $true
    }
}

function Add-FreshInstallClaim {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][ValidateSet("File", "Tree", "EmptyDirectory", "Guard")][string]$Kind
    )
    if (-not $script:FreshInstallAttemptActive -or $null -eq $script:FreshInstallClaims) {
        Die "Fresh-install claim registration occurred outside an active attempt"
    }
    $isDirectory = $Kind -ne "File"
    $deleteAccess = $Kind -ne "Guard"
    $claim = [DefenseClaw.Install.FreshV1.FreshPathClaim]::Open(
        [IO.Path]::GetFullPath($Path),
        $isDirectory,
        $deleteAccess
    )
    try {
        [void]$script:FreshInstallClaims.Add([pscustomobject]@{
            Kind = $Kind
            Path = [IO.Path]::GetFullPath($Path)
            Identity = $claim.Identity
            Native = $claim
        })
    } catch {
        $claim.Dispose()
        throw
    }
}

function Add-FreshInstallStreamClaim {
    param(
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)][string]$Path
    )
    if (-not $script:FreshInstallAttemptActive -or $null -eq $script:FreshInstallClaims) {
        Die "Fresh-install stream claim registration occurred outside an active attempt"
    }
    $full = [IO.Path]::GetFullPath($Path)
    $claim = [DefenseClaw.Install.FreshV1.FreshPathClaim]::TransitionOpenedFileCustody(
        $Stream.SafeFileHandle,
        $full,
        $false
    )
    try {
        [void]$script:FreshInstallClaims.Add([pscustomobject]@{
            Kind = "File"
            Path = $full
            Identity = $claim.Identity
            Native = $claim
        })
    } catch {
        $claim.Dispose()
        throw
    }
}

function Ensure-FreshInstallDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path)
    foreach ($entry in $script:FreshInstallClaims) {
        if ([string]::Equals($entry.Path, $full, [StringComparison]::OrdinalIgnoreCase)) {
            return
        }
    }
    if (Test-InstallMarker -Path $full) {
        Add-FreshInstallClaim -Path $full -Kind Guard
        return
    }
    $parent = Split-Path -Parent $full
    if (-not $parent -or $parent -eq $full) {
        Die "Fresh-install directory has no safe parent: $full"
    }
    Ensure-FreshInstallDirectory -Path $parent
    New-FreshInstallOwnedDirectory -Path $full -Kind EmptyDirectory
}

function New-FreshInstallOwnedDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [ValidateSet("Tree", "EmptyDirectory")][string]$Kind = "EmptyDirectory"
    )
    $full = [IO.Path]::GetFullPath($Path)
    $parent = Split-Path -Parent $full
    Ensure-FreshInstallDirectory -Path $parent
    $leaf = Split-Path -Leaf $full
    $stage = Join-Path $parent (".$leaf.fresh-install-" + [guid]::NewGuid().ToString("N"))
    $stageIdentity = ""
    $stageClaim = $null
    $publishedClaim = $null
    $moved = $false
    $registered = $false
    try {
        [void](New-PrivateDirectory -Path $stage)
        $stageClaim = [DefenseClaw.Install.FreshV1.FreshPathClaim]::Open(
            $stage,
            $true,
            $true
        )
        $stageIdentity = $stageClaim.Identity
        $stageClaim.Dispose()
        $stageClaim = $null

        $moved = [DefenseClaw.Install.FreshV1.FreshPathClaim]::MoveDirectoryNoReplace(
            $stage,
            $full
        )
        if (-not $moved) {
            Die "A fresh-install directory appeared concurrently and was preserved: $full"
        }
        $publishedClaim = [DefenseClaw.Install.FreshV1.FreshPathClaim]::Open(
            $full,
            $true,
            $true
        )
        if ($publishedClaim.Identity -cne $stageIdentity) {
            $publishedClaim.Dispose()
            $publishedClaim = $null
            Die "Fresh-install directory identity changed during publication and was preserved: $full"
        }
        [void]$script:FreshInstallClaims.Add([pscustomobject]@{
            Kind = $Kind
            Path = $full
            Identity = $publishedClaim.Identity
            Native = $publishedClaim
        })
        $registered = $true
    } catch {
        $publicationFailure = $_
        if ($publishedClaim -and -not $registered) {
            try { [void]$publishedClaim.DeleteEmptyDirectoryExact() } catch {}
            $publishedClaim.Dispose()
        }
        if (-not $moved -and (Test-InstallMarker -Path $stage)) {
            try {
                $cleanupClaim = [DefenseClaw.Install.FreshV1.FreshPathClaim]::Open(
                    $stage,
                    $true,
                    $true
                )
                try {
                    if ($cleanupClaim.Identity -ceq $stageIdentity) {
                        [void]$cleanupClaim.DeleteEmptyDirectoryExact()
                    }
                } finally {
                    $cleanupClaim.Dispose()
                }
            } catch {}
        }
        throw $publicationFailure
    } finally {
        if ($stageClaim) { $stageClaim.Dispose() }
    }
}

function Initialize-FreshInstallAttempt {
    if ($script:FreshInstallAttemptActive) {
        Die "Fresh-install transaction is already active"
    }
    $script:FreshInstallClaims = New-Object 'System.Collections.Generic.List[object]'
    $script:FreshInstallAttemptActive = $true
    $script:FreshInstallOriginalUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $script:FreshInstallPublishedUserPath = $null
    $script:FreshInstallOriginalProcessPath = $env:PATH
    $script:FreshInstallPublishedProcessPath = $null

    New-FreshInstallOwnedDirectory -Path $DefenseClawHome -Kind EmptyDirectory
    New-FreshInstallOwnedDirectory -Path $Venv -Kind Tree
    Ensure-FreshInstallDirectory -Path $InstallDir
}

function Remove-FreshInstallClaim {
    param([Parameter(Mandatory = $true)][object]$Entry)
    switch ($Entry.Kind) {
        "File" { return [bool]$Entry.Native.DeleteFileExact() }
        "Tree" { return [bool]$Entry.Native.DeleteTreeExact() }
        "EmptyDirectory" { return [bool]$Entry.Native.DeleteEmptyDirectoryExact() }
        default { return $true }
    }
}

function Undo-FreshInstallAttempt {
    $residue = New-Object 'System.Collections.Generic.List[string]'
    if (-not $script:FreshInstallAttemptActive -or $null -eq $script:FreshInstallClaims) {
        return @()
    }

    # Undo a PATH publication only when it still equals this attempt's exact
    # value.  A concurrent user/process edit is evidence to preserve.
    try {
        if ($null -ne $script:FreshInstallPublishedUserPath) {
            $currentUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
            if ($currentUserPath -ceq $script:FreshInstallPublishedUserPath) {
                [Environment]::SetEnvironmentVariable(
                    "Path",
                    $script:FreshInstallOriginalUserPath,
                    "User"
                )
            } else {
                [void]$residue.Add("the user PATH changed concurrently and was preserved")
            }
        }
        if ($null -ne $script:FreshInstallPublishedProcessPath) {
            if ($env:PATH -ceq $script:FreshInstallPublishedProcessPath) {
                $env:PATH = $script:FreshInstallOriginalProcessPath
            } else {
                [void]$residue.Add("the process PATH changed concurrently and was preserved")
            }
        }
    } catch {
        [void]$residue.Add("the installer could not restore its PATH publication: $($_.Exception.Message)")
    }

    foreach ($kind in @("File", "Tree", "EmptyDirectory")) {
        for ($index = $script:FreshInstallClaims.Count - 1; $index -ge 0; $index--) {
            $entry = $script:FreshInstallClaims[$index]
            if ($entry.Kind -ne $kind) { continue }
            try {
                if (-not (Remove-FreshInstallClaim -Entry $entry)) {
                    [void]$residue.Add(
                        "changed or nonempty attempt path was preserved: $($entry.Path)"
                    )
                }
            } catch {
                [void]$residue.Add(
                    "attempt path could not be rolled back and was preserved: $($entry.Path) ($($_.Exception.Message))"
                )
            } finally {
                $entry.Native.Dispose()
            }
        }
    }
    foreach ($entry in $script:FreshInstallClaims) {
        if ($entry.Kind -eq "Guard") { $entry.Native.Dispose() }
    }
    foreach ($marker in @(
        $DefenseClawHome,
        $Venv,
        (Join-Path $InstallDir "defenseclaw-gateway.exe"),
        (Join-Path $InstallDir "defenseclaw.cmd")
    )) {
        if (Test-InstallMarker -Path $marker) {
            $alreadyReported = @(
                $residue | Where-Object { $_.Contains($marker) }
            ).Count -ne 0
            if (-not $alreadyReported) {
                [void]$residue.Add("fresh-install marker remains and was preserved: $marker")
            }
        }
    }
    $script:FreshInstallClaims.Clear()
    $script:FreshInstallAttemptActive = $false
    return @($residue)
}

function Complete-FreshInstallAttempt {
    if (-not $script:FreshInstallAttemptActive -or $null -eq $script:FreshInstallClaims) {
        Die "Fresh-install transaction was not active at commit"
    }
    foreach ($entry in $script:FreshInstallClaims) {
        $entry.Native.Dispose()
    }
    $script:FreshInstallClaims.Clear()
    $script:FreshInstallAttemptActive = $false
}

function Assert-FreshInstall {
    # install.ps1 is deliberately fresh-install-only.  In particular, -Local
    # is a developer convenience for a *new* installation; it must never turn
    # into an unsigned/unmanifested upgrade path around the hard-cut resolver.
    $markers = @(
        $DefenseClawHome,
        $Venv,
        (Join-Path $Venv "Scripts\defenseclaw.exe"),
        (Join-Path $InstallDir "defenseclaw.cmd"),
        (Join-Path $InstallDir "defenseclaw-gateway.exe")
    )
    $existing = @($markers | Where-Object { Test-InstallMarker -Path $_ })
    $installedCli = Get-Command defenseclaw -CommandType Application, ExternalScript -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($installedCli) {
        $existing += [string]$installedCli.Source
    }
    $installedGateway = Get-Command defenseclaw-gateway -CommandType Application, ExternalScript -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($installedGateway) {
        $existing += [string]$installedGateway.Source
    }
    if ($existing.Count -eq 0) { return }

    Write-Err2 "An existing DefenseClaw installation was detected."
    Write-Host "  No changes were made." -ForegroundColor Yellow
    Write-Host "  Use scripts\upgrade.ps1 (or defenseclaw upgrade where supported) to upgrade safely." -ForegroundColor Yellow
    exit 1
}

# ── Platform detection ────────────────────────────────────────────────────────

function Get-Arch {
    Write-Step "Detecting platform"
    # PROCESSOR_ARCHITEW6432 is set when a 32-bit process runs on 64-bit Windows;
    # prefer it so we never mistake WOW64 for a real 32-bit OS.
    $raw = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    switch ($raw.ToUpper()) {
        "AMD64" { $arch = "amd64" }
        "ARM64" { $arch = "arm64" }
        "X86"   { Die "32-bit Windows is not supported (need amd64 or arm64)." }
        default { Die "Unsupported architecture: $raw" }
    }
    Write-Ok "Windows ($arch)"
    return $arch
}

# ── Dependency: uv ────────────────────────────────────────────────────────────

function Install-Uv {
    Write-Step "Checking uv"
    if (Test-HasCommand "uv") {
        Write-Ok "uv found"
        return
    }
    Write-Info "Installing uv..."
    try {
        Invoke-RestMethod -Uri "https://astral.sh/uv/install.ps1" | Invoke-Expression
    } catch {
        Die "Failed to install uv. Install manually: https://docs.astral.sh/uv/"
    }
    # uv's installer drops the binary in %USERPROFILE%\.local\bin; surface it on
    # PATH for the rest of this process so subsequent calls resolve.
    $uvDir = Join-Path $env:USERPROFILE ".local\bin"
    if (Test-Path $uvDir) { $env:PATH = "$uvDir;$env:PATH" }
    if (-not (Test-HasCommand "uv")) {
        Die "uv installed but not found on PATH. Open a new terminal and re-run."
    }
    Write-Ok "uv installed"
}

# ── Dependency: Python ────────────────────────────────────────────────────────

function Ensure-Python {
    Write-Step "Checking Python"
    # uv manages an interpreter for us; ask it for 3.12 and install on demand.
    # This avoids depending on a system Python being present or new enough.
    & uv python install 3.12 *> $null
    Write-Ok "Python 3.12 (managed by uv)"
}

# ── Resolve release version ───────────────────────────────────────────────────

function Resolve-Version {
    if ($Local) { return $null }
    Write-Step "Resolving version"
    if ($Version) {
        Write-Ok "Using specified version: $Version"
        return $Version
    }
    try {
        $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" `
            -Headers @{ "User-Agent" = "defenseclaw-installer" }
    } catch {
        Die "Failed to fetch latest release. Use -Version x.y.z or -Local <dir>."
    }
    $tag = $rel.tag_name
    if ($tag -notmatch '^\d+\.\d+\.\d+$') {
        Die "Could not parse release version from tag '$tag'."
    }
    Write-Ok "Latest release: $tag"
    return $tag
}

function Get-ManifestProperty {
    param([object]$Object,[string]$Name)
    return $Object.PSObject.Properties[$Name]
}

function Initialize-ReleasePolicy {
    param([string]$Arch)
    Write-Step "Authenticating release policy"
    $policyPath = Join-Path ([IO.Path]::GetTempPath()) ("defenseclaw-install-policy-" + [guid]::NewGuid().ToString("N"))
    $script:PolicyDir = New-PrivateDirectory -Path $policyPath
    $manifestPath=Join-Path $script:PolicyDir "upgrade-manifest.json"
    $checksumsPath=Join-Path $script:PolicyDir "checksums.txt"
    if($Local){
        foreach($name in @("upgrade-manifest.json","checksums.txt")){
            $source=Join-Path $Local $name
            if(-not(Test-Path -LiteralPath $source -PathType Leaf)){Die "Local installs require $name"}
            Copy-Item -LiteralPath $source -Destination (Join-Path $script:PolicyDir $name)
        }
    }else{
        [void](Get-Artifact -Name "upgrade-manifest.json" -Dest $manifestPath)
        [void](Get-Artifact -Name "checksums.txt" -Dest $checksumsPath)
    }
    try{$raw=Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8|ConvertFrom-Json}catch{Die "Invalid upgrade-manifest.json"}
    $releaseProperty=Get-ManifestProperty $raw "release_version"
    if(-not $releaseProperty -or [string]$releaseProperty.Value -notmatch '^\d+\.\d+\.\d+$'){Die "Manifest release_version is invalid"}
    $manifestVersion=[string]$releaseProperty.Value
    if($script:ReleaseVersion -and $script:ReleaseVersion -ne $manifestVersion){Die "Manifest release version mismatch"}
    if($Version -and $Version -ne $manifestVersion){Die "Local manifest release $manifestVersion does not match -Version $Version"}
    $script:ReleaseVersion=$manifestVersion
    $script:ModernRelease=([version]$manifestVersion -ge [version]"0.8.4")
    $script:ChecksumsFile=$checksumsPath

    if($script:ModernRelease){
        $cosign=Get-Command cosign -CommandType Application -ErrorAction SilentlyContinue|Select-Object -First 1
        if(-not $cosign){Die "cosign is required to authenticate DefenseClaw $manifestVersion before installation"}
        $signature=Join-Path $script:PolicyDir "checksums.txt.sig";$certificate=Join-Path $script:PolicyDir "checksums.txt.pem"
        if($Local){
            foreach($row in @(@("checksums.txt.sig",$signature),@("checksums.txt.pem",$certificate))){
                $source=Join-Path $Local $row[0]
                if(-not(Test-Path -LiteralPath $source -PathType Leaf)){Die "Local schema-2 installs require $($row[0])"}
                Copy-Item -LiteralPath $source -Destination $row[1]
            }
        }else{
            [void](Get-Artifact -Name "checksums.txt.sig" -Dest $signature)
            [void](Get-Artifact -Name "checksums.txt.pem" -Dest $certificate)
        }
        & $cosign.Source verify-blob --certificate $certificate --signature $signature `
            --certificate-identity "https://github.com/$Repo/.github/workflows/release.yaml@refs/heads/main" `
            --certificate-oidc-issuer "https://token.actions.githubusercontent.com" $checksumsPath *> $null
        if($LASTEXITCODE -ne 0){Die "Sigstore verification failed; no installation changes were made"}
    }

    Test-Checksum -File $manifestPath -FileName "upgrade-manifest.json"
    $schemaProperty=Get-ManifestProperty $raw "schema_version"
    $releaseArtifactsProperty=Get-ManifestProperty $raw "release_artifacts"
    if($script:ModernRelease){
        if(-not $schemaProperty -or [int]$schemaProperty.Value -ne 2 -or -not $releaseArtifactsProperty){Die "Modern install requires schema-2 release_artifacts"}
        $artifacts=$releaseArtifactsProperty.Value
        $artifactKeys=@($artifacts.PSObject.Properties.Name)
        $wheelProperty=Get-ManifestProperty $artifacts "wheel";$gatewaysProperty=Get-ManifestProperty $artifacts "gateways"
        $expectedWheel="defenseclaw-$manifestVersion-2-py3-none-any.dcwheel"
        if($artifactKeys.Count -ne 2 -or $artifactKeys -cnotcontains "wheel" -or $artifactKeys -cnotcontains "gateways" -or -not $wheelProperty -or [string]$wheelProperty.Value -cne $expectedWheel){Die "release_artifacts wheel is not the protected artifact"}
        $platformKeys=@($gatewaysProperty.Value.PSObject.Properties.Name)
        if($platformKeys.Count -ne 3 -or $platformKeys -cnotcontains "darwin" -or $platformKeys -cnotcontains "linux" -or $platformKeys -cnotcontains "windows"){Die "release_artifacts platform map is invalid"}
        foreach($platformName in @("darwin","linux","windows")){
            $platform=Get-ManifestProperty $gatewaysProperty.Value $platformName
            $archKeys=@($platform.Value.PSObject.Properties.Name)
            if($archKeys.Count -ne 2 -or $archKeys -cnotcontains "amd64" -or $archKeys -cnotcontains "arm64"){Die "release_artifacts architecture map is invalid"}
            foreach($artifactArch in @("amd64","arm64")){
                $name=[string](Get-ManifestProperty $platform.Value $artifactArch).Value
                if($name -cne "defenseclaw_$($manifestVersion)_protocol2_$($platformName)_$artifactArch.dcgateway" -or [IO.Path]::GetFileName($name) -cne $name){Die "release_artifacts gateway name is invalid"}
            }
        }
        $script:WheelArtifact=[string]$wheelProperty.Value
        $windows=Get-ManifestProperty $gatewaysProperty.Value "windows"
        $script:GatewayArtifact=[string](Get-ManifestProperty $windows.Value $Arch).Value
        $script:ProtectedWheelPath=Join-Path $script:PolicyDir $script:WheelArtifact
        $protectedGateway=Join-Path $script:PolicyDir $script:GatewayArtifact
        [void](Get-Artifact -Name $script:WheelArtifact -Dest $script:ProtectedWheelPath)
        [void](Get-Artifact -Name $script:GatewayArtifact -Dest $protectedGateway)
        Test-Checksum -File $script:ProtectedWheelPath -FileName $script:WheelArtifact
        Test-Checksum -File $protectedGateway -FileName $script:GatewayArtifact
        $script:WheelPath=Join-Path $script:PolicyDir "defenseclaw-$manifestVersion-py3-none-any.whl"
        $gatewayZip=Join-Path $script:PolicyDir "defenseclaw_$($manifestVersion)_windows_$Arch.zip"
        $script:WheelInnerSha256 = Copy-AuthenticatedPrivateArtifact -Source $script:ProtectedWheelPath -Destination $script:WheelPath -ExpectedSha256 (Get-RequiredChecksumDigest -FileName $script:WheelArtifact) -ProtectedEnvelope
        $script:GatewayArchiveInnerSha256 = Copy-AuthenticatedPrivateArtifact -Source $protectedGateway -Destination $gatewayZip -ExpectedSha256 (Get-RequiredChecksumDigest -FileName $script:GatewayArtifact) -ProtectedEnvelope
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $wheelZip=$null
        try{
            Assert-ExactPrivateArtifactDigest -Path $script:WheelPath -ExpectedSha256 $script:WheelInnerSha256 -Label "protected wheel"
            $wheelZip=[IO.Compression.ZipFile]::OpenRead($script:WheelPath)
            if(-not @($wheelZip.Entries|Where-Object{$_.FullName -like "*.dist-info/METADATA"})){Die "Protected wheel lacks package metadata"}
        }finally{if($wheelZip){$wheelZip.Dispose()}}
        $extract=New-PrivateDirectory -Path (Join-Path $script:PolicyDir "gateway")
        Assert-ExactPrivateArtifactDigest -Path $gatewayZip -ExpectedSha256 $script:GatewayArchiveInnerSha256 -Label "protected gateway archive"
        Expand-Archive -LiteralPath $gatewayZip -DestinationPath $extract
        $script:GatewayBinary=Join-Path $extract "defenseclaw.exe"
        if(-not(Test-Path -LiteralPath $script:GatewayBinary -PathType Leaf)){Die "Protected gateway archive lacks defenseclaw.exe"}
        Set-PrivateFileAcl -Path $script:GatewayBinary
        $script:GatewayBinarySha256=(Get-FileHash -LiteralPath $script:GatewayBinary -Algorithm SHA256).Hash.ToLowerInvariant()
    }else{
        if(-not $schemaProperty -or [int]$schemaProperty.Value -ne 1 -or $releaseArtifactsProperty){Die "Legacy release policy is invalid"}
    }
    Write-Ok "Release policy and protected artifacts verified ($manifestVersion)"
}

# ── Artifact fetch + checksum verification ────────────────────────────────────

function Get-Artifact {
    param([string]$Name, [string]$Dest)
    if ($Local) {
        $match = Get-ChildItem -Path (Join-Path $Local $Name) -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $match) { Die "Artifact not found: $Local\$Name" }
        Copy-Item $match.FullName $Dest -Force
        return $match.Name
    }
    $url = "https://github.com/$Repo/releases/download/$script:ReleaseVersion/$Name"
    try {
        Invoke-WebRequest -Uri $url -OutFile $Dest -UseBasicParsing
    } catch {
        Die "Failed to download: $url"
    }
    return $Name
}

# Verify a downloaded file against the release checksums.txt. Skipped for -Local
# installs (the operator built the artifacts themselves). Returns nothing; dies
# on mismatch so a corrupted or tampered download never gets installed.
function Test-Checksum {
    param([string]$File, [string]$FileName)
    if ($Local -and -not $script:ModernRelease) { return }
    if (-not $script:ChecksumsFile) {
        Die "Authenticated release checksum policy is unavailable"
    }
    $expected = $null
    foreach ($line in Get-Content $script:ChecksumsFile) {
        $parts = $line -split '\s+', 2
        if ($parts.Count -eq 2 -and $parts[1].Trim() -eq $FileName) {
            $expected = $parts[0].Trim().ToLower()
            break
        }
    }
    if (-not $expected) {
        if($script:ModernRelease){Die "Signed checksums do not cover required artifact $FileName"}
        Write-Warn2 "No checksum entry for $FileName - skipping verification"
        return
    }
    $actual = (Get-FileHash -Path $File -Algorithm SHA256).Hash.ToLower()
    if ($expected -ne $actual) {
        Die "Checksum mismatch for ${FileName}: expected $expected, got $actual"
    }
}

function Get-RequiredChecksumDigest {
    param([string]$FileName)
    $checksumDigests=@()
    foreach($line in Get-Content -LiteralPath $script:ChecksumsFile){
        $parts=$line -split '\s+',2
        if($parts.Count -eq 2 -and $parts[1].Trim() -ceq $FileName){$checksumDigests += $parts[0].Trim().ToLowerInvariant()}
    }
    if($checksumDigests.Count -ne 1 -or $checksumDigests[0] -notmatch '^[0-9a-f]{64}$'){
        Die "Signed checksums must contain exactly one valid digest for $FileName"
    }
    return [string]$checksumDigests[0]
}

# ── Install: gateway binary ───────────────────────────────────────────────────

function Install-Gateway {
    param([string]$Arch)
    Write-Step "Installing gateway"
    $gatewayDestination=Join-Path $InstallDir "defenseclaw-gateway.exe"
    if($script:ModernRelease){
        Assert-ExactPrivateArtifactDigest -Path $script:GatewayBinary -ExpectedSha256 $script:GatewayBinarySha256 -Label "protected gateway binary"
        [void](Copy-AuthenticatedPrivateArtifact -Source $script:GatewayBinary -Destination $gatewayDestination -ExpectedSha256 $script:GatewayBinarySha256 -FreshInstallDestination)
        Write-Ok "Gateway installed -> $InstallDir\defenseclaw-gateway.exe"
        return
    }
    $tmp = New-PrivateDirectory -Path (Join-Path ([System.IO.Path]::GetTempPath()) ("dc-gw-" + [guid]::NewGuid()))
    try {
        if ($Local) {
            # Accept either the zip or a raw defenseclaw.exe in the local dir.
            $zip = Get-ChildItem -Path (Join-Path $Local "defenseclaw_*_windows_$Arch.zip") -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($zip) {
                Expand-Archive -Path $zip.FullName -DestinationPath $tmp -Force
            } else {
                $exe = Get-ChildItem -Path (Join-Path $Local "defenseclaw*.exe") -ErrorAction SilentlyContinue | Select-Object -First 1
                if (-not $exe) { Die "No windows zip or defenseclaw.exe found in $Local" }
                Copy-Item $exe.FullName (Join-Path $tmp "defenseclaw.exe") -Force
            }
        } else {
            $zipName = "defenseclaw_${script:ReleaseVersion}_windows_${Arch}.zip"
            $zipPath = Join-Path $tmp $zipName
            $resolved = Get-Artifact -Name $zipName -Dest $zipPath
            Test-Checksum -File $zipPath -FileName $resolved
            Expand-Archive -Path $zipPath -DestinationPath $tmp -Force
        }
        $binary = Join-Path $tmp "defenseclaw.exe"
        if (-not (Test-Path $binary)) { Die "defenseclaw.exe missing from archive" }
        $gatewaySha=(Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
        [void](Copy-AuthenticatedPrivateArtifact -Source $binary -Destination $gatewayDestination -ExpectedSha256 $gatewaySha -FreshInstallDestination)
    } finally {
        Remove-PrivateDirectory -Path $tmp
    }
    Write-Ok "Gateway installed -> $InstallDir\defenseclaw-gateway.exe"
}

# ── Install: Python CLI (from wheel) ──────────────────────────────────────────

function Install-Cli {
    Write-Step "Installing DefenseClaw CLI"
    Write-Info "Creating Python environment..."
    & uv venv $Venv --python 3.12 --quiet 2>$null
    if ($LASTEXITCODE -ne 0) {
        & uv venv $Venv --quiet
        if ($LASTEXITCODE -ne 0) { Die "Failed to create Python virtual environment" }
    }
    $venvPython = Join-Path $Venv "Scripts\python.exe"

    Write-Info "Installing from wheel..."
    $tmp = New-PrivateDirectory -Path (Join-Path ([System.IO.Path]::GetTempPath()) ("dc-cli-" + [guid]::NewGuid()))
    try {
        if($script:ModernRelease){
            $whlPath=$script:WheelPath
        } elseif ($Local) {
            $whl = Get-ChildItem -Path (Join-Path $Local "defenseclaw-*.whl") -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $whl) { Die "No wheel found in $Local" }
            $whlPath = $whl.FullName
        } else {
            $whlName = "defenseclaw-${script:ReleaseVersion}-py3-none-any.whl"
            $whlPath = Join-Path $tmp $whlName
            $resolved = Get-Artifact -Name $whlName -Dest $whlPath
            Test-Checksum -File $whlPath -FileName $resolved
        }
        if($script:ModernRelease){
            Assert-ExactPrivateArtifactDigest -Path $whlPath -ExpectedSha256 $script:WheelInnerSha256 -Label "protected wheel"
        }
        & uv pip install --python $venvPython --quiet $whlPath
        if ($LASTEXITCODE -ne 0) { Die "Failed to install CLI from wheel" }
    } finally {
        Remove-PrivateDirectory -Path $tmp
    }

    if ($InjectFailureBeforeShim) {
        Die "Injected fresh-install failure before CLI shim publication"
    }

    # A .cmd shim on PATH is more robust than relying on the venv's Scripts dir
    # (which would also expose uv/python). PATHEXT includes .CMD, so
    # `defenseclaw` and shutil.which("defenseclaw") both resolve to it.
    $cliExe = Join-Path $Venv "Scripts\defenseclaw.exe"
    $shim = Join-Path $InstallDir "defenseclaw.cmd"
    if ($InjectConcurrentShimBeforePublish) {
        $unclaimed = [IO.File]::Open(
            $shim,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        try {
            $unclaimedBytes = [Text.Encoding]::ASCII.GetBytes(
                "@echo off`r`necho concurrent-unclaimed-shim`r`n"
            )
            $unclaimed.Write($unclaimedBytes, 0, $unclaimedBytes.Length)
            $unclaimed.Flush($true)
        } finally {
            $unclaimed.Dispose()
        }
    }
    $shimStream=$null
    $shimClaimRegistered=$false
    try{
        $shimStream=New-PrivateFileStream -Path $shim
        $shimBytes=[Text.Encoding]::ASCII.GetBytes("@echo off`r`n`"$cliExe`" %*`r`n")
        $shimStream.Write($shimBytes,0,$shimBytes.Length)
        $shimStream.Flush($true)
        Add-FreshInstallStreamClaim -Stream $shimStream -Path $shim
        $shimClaimRegistered=$true
    }catch [System.IO.IOException]{
        $shimError=[string]$_.Exception.Message
        if($shimStream -and -not $shimClaimRegistered){
            try{[void][DefenseClaw.Install.FreshV1.FreshPathClaim]::DeleteOpenedFileExact($shimStream.SafeFileHandle)}catch{}
        }
        if(Test-Path -LiteralPath $shim){Die "A DefenseClaw CLI appeared during installation; it was preserved and this installation was not activated"}
        Die "Could not create the CLI shim at ${shim}: $shimError"
    }catch{
        $shimError=[string]$_.Exception.Message
        if($shimStream -and -not $shimClaimRegistered){
            try{[void][DefenseClaw.Install.FreshV1.FreshPathClaim]::DeleteOpenedFileExact($shimStream.SafeFileHandle)}catch{}
        }
        Die "Could not create the CLI shim at ${shim}: $shimError"
    }finally{if($shimStream){$shimStream.Dispose()}}

    if (Test-Path $cliExe) {
        Write-Ok "CLI installed -> $shim"
    } else {
        Write-Warn2 "CLI installed but $cliExe not found - check dependencies"
    }
}

# ── Connector selection ───────────────────────────────────────────────────────

function Select-Connector {
    if ($script:PickedConnector) { return }
    if ($Yes) { $script:PickedConnector = "none"; return }

    Write-Step "Pick agent connector"
    Write-Info "DefenseClaw can guard several agent frameworks. Pick one to integrate now;"
    Write-Info "you can switch later with 'defenseclaw init --connector <name>'."
    Write-Host ""
    $i = 1
    foreach ($v in $ConnectorChoices) {
        switch ($v) {
            "codex"      { Write-Host "    $i) codex      - patch %USERPROFILE%\.codex\config.toml + hooks" }
            "claudecode" { Write-Host "    $i) claudecode - patch %USERPROFILE%\.claude\settings.json hooks" }
            "hermes"     { Write-Host "    $i) hermes     - configure Hermes Agent hooks" }
            "cursor"     { Write-Host "    $i) cursor     - configure Cursor hooks" }
            "windsurf"   { Write-Host "    $i) windsurf   - configure Windsurf hooks" }
            "geminicli"  { Write-Host "    $i) geminicli  - configure Gemini CLI hooks" }
            "copilot"    { Write-Host "    $i) copilot    - configure GitHub Copilot CLI hooks" }
            "openhands"  { Write-Host "    $i) openhands  - configure OpenHands hooks" }
            "antigravity" { Write-Host "    $i) antigravity - configure Antigravity hooks" }
            "opencode"   { Write-Host "    $i) opencode   - configure OpenCode hooks" }
            "omnigent"   { Write-Host "    $i) omnigent   - configure OmniGent hooks" }
            "none"       { Write-Host "    $i) none       - install gateway/CLI only; pick later" }
            default      { Write-Host "    $i) $v" }
        }
        $i++
    }
    Write-Host ""
    $choice = Read-Host "  Choice [1-$($ConnectorChoices.Count), default 1=codex]"
    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = "1" }
    $idx = 0
    if ([int]::TryParse($choice, [ref]$idx) -and $idx -ge 1 -and $idx -le $ConnectorChoices.Count) {
        $script:PickedConnector = $ConnectorChoices[$idx - 1]
    } else {
        Write-Warn2 "Invalid choice '$choice', defaulting to codex"
        $script:PickedConnector = "codex"
    }
    Write-Ok "Picked connector: $script:PickedConnector"
}

function Save-PickedConnector {
    if (-not $script:PickedConnector -or $script:PickedConnector -eq "none") { return }
    $marker = Join-Path $DefenseClawHome "picked_connector"
    $stream = $null
    $markerClaimRegistered = $false
    try {
        $stream = New-PrivateFileStream -Path $marker
        $bytes = [Text.Encoding]::UTF8.GetBytes("$($script:PickedConnector)`r`n")
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        Add-FreshInstallStreamClaim -Stream $stream -Path $marker
        $markerClaimRegistered = $true
    } catch {
        $markerFailure = $_
        if ($stream -and -not $markerClaimRegistered) {
            try {
                [void][DefenseClaw.Install.FreshV1.FreshPathClaim]::DeleteOpenedFileExact(
                    $stream.SafeFileHandle
                )
            } catch {}
        }
        throw $markerFailure
    } finally {
        if ($stream) { $stream.Dispose() }
    }
}

# ── Optional: quickstart ──────────────────────────────────────────────────────

function Invoke-Quickstart {
    if (-not $Quickstart) { return }
    Write-Step "Running quickstart"
    if (-not $script:PickedConnector -or $script:PickedConnector -eq "none") {
        Write-Warn2 "Quickstart skipped (no connector). Run 'defenseclaw init' when ready."
        return
    }
    $cliExe = Join-Path $Venv "Scripts\defenseclaw.exe"
    if (-not (Test-Path $cliExe)) { Write-Warn2 "CLI not found - skipping quickstart"; return }
    $args = @("quickstart", "--non-interactive", "--yes", "--connector", $script:PickedConnector)
    if ($QuickstartMode) { $args += @("--mode", $QuickstartMode) }
    & $cliExe @args
    if ($LASTEXITCODE -eq 0) { Write-Ok "Quickstart completed" } else { Write-Warn2 "Quickstart reported errors - run 'defenseclaw doctor'" }
}

# ── PATH configuration ────────────────────────────────────────────────────────

function Add-ToPath {
    # Persist InstallDir on the user PATH (idempotent) and add it to this
    # process so quickstart and `defenseclaw-gateway` resolve immediately.
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not $userPath) { $userPath = "" }
    $entries = $userPath -split ';' | Where-Object { $_ -ne "" }
    if ($entries -notcontains $InstallDir) {
        $newPath = if ($userPath) { "$userPath;$InstallDir" } else { $InstallDir }
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
        $script:FreshInstallPublishedUserPath = $newPath
        Write-Step "PATH updated"
        Write-Info "Added $InstallDir to your user PATH."
        Write-Info "Open a new terminal for it to take effect."
    }
    if (($env:PATH -split ';') -notcontains $InstallDir) {
        $publishedProcessPath = "$InstallDir;$env:PATH"
        $env:PATH = $publishedProcessPath
        $script:FreshInstallPublishedProcessPath = $publishedProcessPath
    }
}

# ── Success ───────────────────────────────────────────────────────────────────

function Write-Success {
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Green
    Write-Host "         DefenseClaw installed successfully!" -ForegroundColor Green
    Write-Host "  ============================================================" -ForegroundColor Green
    Write-Host ""
    switch ($script:PickedConnector) {
        "codex"      { Write-Host "  Get started (Codex):`n`n    defenseclaw init --connector codex`n" -ForegroundColor Cyan }
        "claudecode" { Write-Host "  Get started (Claude Code):`n`n    defenseclaw init --connector claudecode`n" -ForegroundColor Cyan }
        { $_ -in $HookConnectors } {
            Write-Host "  Get started ($script:PickedConnector):`n`n    defenseclaw init --connector $script:PickedConnector`n" -ForegroundColor Cyan
        }
        default      { Write-Host "  Get started (pick a connector later):`n`n    defenseclaw init`n" -ForegroundColor Cyan }
    }
}

# ── Entry point ───────────────────────────────────────────────────────────────

function Main {
    if ($Help) { Show-Help; return }

    if ((
        $InjectFailureBeforeShim -or
        $InjectConcurrentShimBeforePublish -or
        $InjectPolicyCleanupFailure
    ) -and -not $TestMode) {
        Die "Fresh-install fault injection requires -TestMode"
    }

    # This guard must precede platform/dependency discovery: Install-Uv and
    # Ensure-Python can mutate the host even before release artifacts are read.
    Assert-FreshInstall

    try {
        try {
            Write-Host ""
            Write-Host "  DefenseClaw Installer (Windows)" -ForegroundColor White
            Write-Host "  Enterprise Governance for Agentic AI" -ForegroundColor DarkGray

            $script:PickedConnector = ""
            $script:ChecksumsFile = $null
            $script:ReleaseVersion = $null

            # Validate -Connector and reconcile with -NoOpenclaw.
            if ($Connector) {
                if ($ConnectorChoices -notcontains $Connector) {
                    Die "Invalid -Connector '$Connector'. Choices: $($ConnectorChoices -join ', ')"
                }
                $script:PickedConnector = $Connector
            }
            if ($NoOpenclaw) {
                if (-not $script:PickedConnector) {
                    $script:PickedConnector = "none"
                }
            }

            if ($Local) {
                $Local = (Resolve-Path $Local).Path
                Write-Info "Installing from local directory: $Local"
            }

            $arch = Get-Arch
            $script:ReleaseVersion = Resolve-Version
            Initialize-ReleasePolicy -Arch $arch
            Install-Uv
            Ensure-Python
            Select-Connector
            Initialize-FreshInstallAttempt
            Install-Gateway -Arch $arch
            Install-Cli

            $cliWiredConnectors = @("codex", "claudecode") + $HookConnectors
            switch ($script:PickedConnector) {
                { $_ -in $cliWiredConnectors } {
                    Write-Info "Connector '$script:PickedConnector' wires up via the CLI (no OpenClaw runtime needed)."
                }
                default      { Write-Info "Skipping connector setup - run 'defenseclaw init' when ready" }
            }

            Save-PickedConnector
            Add-ToPath
            Invoke-Quickstart
        } finally {
            Close-ReleasePolicyCustody
        }
        Complete-FreshInstallAttempt
    } catch {
        $installFailure = [string]$_.Exception.Message
        $rollbackResidue = @(Undo-FreshInstallAttempt)
        $cleanupDiagnostic = if ($script:PolicyCleanupWarning) {
            "`n$($script:PolicyCleanupWarning)"
        } else { "" }
        if ($rollbackResidue.Count -ne 0) {
            Die "$installFailure$cleanupDiagnostic`nFresh-install rollback preserved changed or concurrent state:`n  - $($rollbackResidue -join "`n  - ")"
        }
        Die "$installFailure$cleanupDiagnostic`nFresh-install payload rollback completed; retry is safe."
    }
    Write-Success
}

try {
    Main
} catch {
    Write-Err2 ([string]$_.Exception.Message)
    exit 1
}
