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

    and prints explicit, operator-owned steps for adding that bin dir to the User
    PATH; it does not mutate persistent PATH state. Only Python + uv are required;
    no Go, Node.js, or git. Connector-specific wiring (Codex, Claude Code, ...) is
    done by the cross-platform CLI via `defenseclaw init` / `quickstart`.

    Layout matches scripts/install.sh and the managed upgrade path: binaries
    land in %USERPROFILE%\.local\bin and the CLI venv lives in
    %USERPROFILE%\.defenseclaw\.venv. This installer is fresh-install-only;
    existing installations are refused and directed to the authenticated
    target-release defenseclaw-upgrade.ps1 resolver asset in latest mode,
    without -Version, so release manifests and hard-cut bridge rules are
    applied. A coherent installed 0.8.4 bridge may also use its built-in upgrade
    command; pre-bridge controllers require the release resolver.

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
    [Parameter(DontShow = $true)][switch]$InjectPolicyCleanupFailure,
    [Parameter(DontShow = $true)][switch]$InjectPolicyCustodyMoveBeforeCleanup,
    [Parameter(DontShow = $true)][switch]$InjectFailureAfterFreshDirectoryMove,
    [Parameter(DontShow = $true)][string]$NativePrivateDirectorySelfTestRoot = ""
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

# -- Configuration ------------------------------------------------------------

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
$script:FreshInstallOriginalProcessPath = $null
$script:FreshInstallPublishedProcessPath = $null
$script:PrivateDirectoryClaims = @{}
$script:RollbackSafetyLedger = @{}
$script:FreshDirectoryFaultMode = ""
$script:FreshDirectoryFaultTarget = ""
$script:FreshDirectoryFaultDisplaced = ""

# Cleanup must never turn a pathname check into authority to delete a different
# object. Fresh-payload claims pin the exact Windows file ID without
# FILE_SHARE_DELETE. Private-directory creation claims remain open with
# share-delete but no DELETE access; cleanup acquires a second no-share-delete
# handle and proceeds only when its identity matches the retained creation
# claim. Directory-tree rollback snapshots identities before deleting children
# and leaves changed/new residue in place.
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
        private const uint SYNCHRONIZE = 0x00100000;
        private const uint FILE_LIST_DIRECTORY = 0x00000001;
        private const uint FILE_TRAVERSE = 0x00000020;
        private const uint FILE_READ_ATTRIBUTES = 0x00000080;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint FILE_SHARE_DELETE = 0x00000004;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_CREATE = 2;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
        private const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
        private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        private const uint FILE_DIRECTORY_FILE = 0x00000001;
        private const uint FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020;
        private const uint OBJ_CASE_INSENSITIVE = 0x00000040;
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

        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct OBJECT_ATTRIBUTES {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_STATUS_BLOCK {
            public IntPtr Status;
            public UIntPtr Information;
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

        [DllImport("ntdll.dll")]
        private static extern int NtCreateFile(
            out IntPtr fileHandle,
            uint desiredAccess,
            ref OBJECT_ATTRIBUTES objectAttributes,
            out IO_STATUS_BLOCK ioStatusBlock,
            IntPtr allocationSize,
            uint fileAttributes,
            uint shareAccess,
            uint createDisposition,
            uint createOptions,
            IntPtr eaBuffer,
            uint eaLength);

        [DllImport("ntdll.dll")]
        private static extern uint RtlNtStatusToDosError(int status);

        private SafeFileHandle handle;
        private readonly uint volume;
        private readonly ulong index;
        private readonly bool directory;
        private readonly bool deleteAccess;
        private readonly string path;
        private static string testMoveOutSource;
        private static string testMoveOutDestination;

        private FreshPathClaim(
            string claimedPath,
            SafeFileHandle claimedHandle,
            BY_HANDLE_FILE_INFORMATION information,
            bool expectedDirectory,
            bool claimedDeleteAccess) {
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
            deleteAccess = claimedDeleteAccess;
        }

        public string PathValue { get { return path; } }
        public string Identity {
            get { return volume.ToString("x8") + ":" + index.ToString("x16"); }
        }

        public static FreshPathClaim Open(string path, bool directory, bool deleteAccess) {
            SafeFileHandle opened = OpenHandle(path, directory, deleteAccess, false);
            BY_HANDLE_FILE_INFORMATION information = Information(opened, path);
            return new FreshPathClaim(path, opened, information, directory, deleteAccess);
        }

        public static FreshPathClaim OpenIfExists(
            string path,
            bool directory,
            bool deleteAccess) {
            SafeFileHandle opened = OpenHandle(path, directory, deleteAccess, true);
            if (opened == null) {
                return null;
            }
            BY_HANDLE_FILE_INFORMATION information = Information(opened, path);
            return new FreshPathClaim(path, opened, information, directory, deleteAccess);
        }

        // Create relative to an exact real parent handle and return the handle from the
        // FILE_CREATE operation.  There is no pathname re-open window in which a
        // same-user process can substitute a different directory and inherit the
        // installer's later cleanup authority.
        public static FreshPathClaim CreatePrivateDirectory(
            string path,
            byte[] securityDescriptor) {
            if (securityDescriptor == null || securityDescriptor.Length == 0) {
                throw new ArgumentException("private directory security descriptor is empty");
            }
            string full = Path.GetFullPath(path).TrimEnd(
                Path.DirectorySeparatorChar,
                Path.AltDirectorySeparatorChar);
            string parentPath = Path.GetDirectoryName(full);
            string leaf = Path.GetFileName(full);
            if (String.IsNullOrEmpty(parentPath) || String.IsNullOrEmpty(leaf) ||
                leaf == "." || leaf == ".." ||
                leaf.IndexOf(Path.DirectorySeparatorChar) >= 0 ||
                leaf.IndexOf(Path.AltDirectorySeparatorChar) >= 0) {
                throw new InvalidOperationException(
                    "private directory path has no safe parent/leaf: " + path);
            }

            SafeFileHandle parent = OpenParentHandle(parentPath);
            IntPtr nameBuffer = IntPtr.Zero;
            IntPtr nameStructure = IntPtr.Zero;
            GCHandle descriptorPin = default(GCHandle);
            bool parentPinned = false;
            IntPtr rawCreated = IntPtr.Zero;
            try {
                BY_HANDLE_FILE_INFORMATION parentInformation = Information(parent, parentPath);
                bool parentIsDirectory =
                    (parentInformation.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
                bool parentIsReparse =
                    (parentInformation.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
                if (!parentIsDirectory || parentIsReparse) {
                    throw new InvalidOperationException(
                        "private directory parent must be a real directory: " + parentPath);
                }
                int nameBytes = System.Text.Encoding.Unicode.GetByteCount(leaf);
                if (nameBytes > ushort.MaxValue - 2) {
                    throw new PathTooLongException("private directory leaf is too long");
                }
                nameBuffer = Marshal.StringToHGlobalUni(leaf);
                UNICODE_STRING name = new UNICODE_STRING();
                name.Length = (ushort)nameBytes;
                name.MaximumLength = (ushort)(nameBytes + 2);
                name.Buffer = nameBuffer;
                nameStructure = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
                Marshal.StructureToPtr(name, nameStructure, false);
                descriptorPin = GCHandle.Alloc(securityDescriptor, GCHandleType.Pinned);
                parent.DangerousAddRef(ref parentPinned);

                OBJECT_ATTRIBUTES attributes = new OBJECT_ATTRIBUTES();
                attributes.Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
                attributes.RootDirectory = parent.DangerousGetHandle();
                attributes.ObjectName = nameStructure;
                attributes.Attributes = OBJ_CASE_INSENSITIVE;
                attributes.SecurityDescriptor = descriptorPin.AddrOfPinnedObject();
                attributes.SecurityQualityOfService = IntPtr.Zero;
                IO_STATUS_BLOCK statusBlock;
                int status = NtCreateFile(
                    out rawCreated,
                    SYNCHRONIZE | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
                    ref attributes,
                    out statusBlock,
                    IntPtr.Zero,
                    FILE_ATTRIBUTE_NORMAL,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    FILE_CREATE,
                    FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                    IntPtr.Zero,
                    0);
                if (status < 0) {
                    int error = unchecked((int)RtlNtStatusToDosError(status));
                    throw new Win32Exception(
                        error,
                        "could not atomically create private install directory: " + full);
                }
                SafeFileHandle created = new SafeFileHandle(rawCreated, true);
                rawCreated = IntPtr.Zero;
                BY_HANDLE_FILE_INFORMATION information = Information(created, full);
                return new FreshPathClaim(full, created, information, true, false);
            } finally {
                if (rawCreated != IntPtr.Zero && rawCreated != new IntPtr(-1)) {
                    new SafeFileHandle(rawCreated, true).Dispose();
                }
                if (parentPinned) {
                    parent.DangerousRelease();
                }
                if (descriptorPin.IsAllocated) {
                    descriptorPin.Free();
                }
                if (nameStructure != IntPtr.Zero) {
                    Marshal.FreeHGlobal(nameStructure);
                }
                if (nameBuffer != IntPtr.Zero) {
                    Marshal.FreeHGlobal(nameBuffer);
                }
                parent.Dispose();
            }
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
            return new FreshPathClaim(path, retained, observed, directory, true);
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

        public static void ConfigureTestMoveOutAfterSnapshot(
            string source,
            string destination) {
            if (String.IsNullOrWhiteSpace(source) ||
                String.IsNullOrWhiteSpace(destination)) {
                throw new ArgumentException("test move-out paths must be non-empty");
            }
            testMoveOutSource = Path.GetFullPath(source);
            testMoveOutDestination = Path.GetFullPath(destination);
        }

        public static void ClearTestMoveOutAfterSnapshot() {
            testMoveOutSource = null;
            testMoveOutDestination = null;
        }

        private static void InvokeTestMoveOutAfterSnapshot() {
            string source = testMoveOutSource;
            string destination = testMoveOutDestination;
            ClearTestMoveOutAfterSnapshot();
            if (String.IsNullOrEmpty(source)) {
                return;
            }
            if (!MoveFileEx(source, destination, MOVEFILE_WRITE_THROUGH)) {
                int error = Marshal.GetLastWin32Error();
                throw new Win32Exception(
                    error,
                    "could not inject a snapshotted-child move-out");
            }
        }

        private static SafeFileHandle OpenHandle(
            string path,
            bool directory,
            bool deleteAccess,
            bool allowMissing) {
            uint access = FILE_READ_ATTRIBUTES |
                (directory ? FILE_TRAVERSE : 0) |
                (deleteAccess ? DELETE : 0);
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

        private static SafeFileHandle OpenParentHandle(string path) {
            // Relative NtCreateFile binds the child to this exact directory even
            // if its pathname changes. Share-delete is required so this short-
            // lived handle can coexist with an ancestor FreshPathClaim that
            // already holds DELETE access; the child creation handle supplies
            // the creation identity used for all later cleanup authority.
            SafeFileHandle opened = CreateFile(
                Path.GetFullPath(path),
                FILE_READ_ATTRIBUTES | FILE_TRAVERSE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                IntPtr.Zero);
            if (!opened.IsInvalid) {
                return opened;
            }
            int error = Marshal.GetLastWin32Error();
            opened.Dispose();
            throw new Win32Exception(error, "could not bind private directory parent: " + path);
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
            if (!deleteAccess) {
                throw new InvalidOperationException("file rollback claim lacks DELETE access");
            }
            bool deleted = MarkDelete(handle, false);
            Dispose();
            return deleted;
        }

        public bool DeleteEmptyDirectoryExact() {
            if (!directory) {
                throw new InvalidOperationException("directory rollback received a file claim");
            }
            if (!deleteAccess) {
                throw new InvalidOperationException("directory rollback claim lacks DELETE access");
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
            if (!deleteAccess) {
                throw new InvalidOperationException("tree rollback claim lacks DELETE access");
            }
            List<TreeEntry> entries = new List<TreeEntry>();
            long bytes = 0;
            SnapshotDirectory(path, 1, entries, ref bytes);
            InvokeTestMoveOutAfterSnapshot();
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
                    return false;
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

function Start-RollbackSafetyBoundary {
    param(
        [Parameter(Mandatory = $true)][string]$Boundary,
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Identity = "unavailable"
    )
    $full = [IO.Path]::GetFullPath($Path)
    foreach ($existingToken in @($script:RollbackSafetyLedger.Keys)) {
        $existing = $script:RollbackSafetyLedger[$existingToken]
        if ($existing.Boundary -ceq $Boundary -and
            [string]::Equals(
                $existing.Path,
                $full,
                [StringComparison]::OrdinalIgnoreCase
            ) -and
            $existing.Identity -ceq $Identity) {
            return [string]$existingToken
        }
    }
    $token = [guid]::NewGuid().ToString("N")
    $script:RollbackSafetyLedger[$token] = [pscustomobject]@{
        Boundary = $Boundary
        Path = $full
        Identity = $Identity
    }
    return $token
}

function Update-RollbackSafetyBoundary {
    param(
        [Parameter(Mandatory = $true)][string]$Token,
        [string]$Path = "",
        [string]$Identity = ""
    )
    if (-not $script:RollbackSafetyLedger.ContainsKey($Token)) { return }
    $entry = $script:RollbackSafetyLedger[$Token]
    if ($Path) { $entry.Path = [IO.Path]::GetFullPath($Path) }
    if ($Identity) { $entry.Identity = $Identity }
}

function Complete-RollbackSafetyBoundary {
    param([Parameter(Mandatory = $true)][string]$Token)
    [void]$script:RollbackSafetyLedger.Remove($Token)
}

function New-PrivateDirectory {
    param([string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    if (Test-InstallMarker -Path $full) { Die "Private install path already exists: $full" }
    $acl = New-PrivateDirectoryAcl
    $registrationSafety = Start-RollbackSafetyBoundary `
        -Boundary "private-directory-registration" `
        -Path $full
    $claim = $null
    $registered = $false
    try {
        $claim = [DefenseClaw.Install.FreshV1.FreshPathClaim]::CreatePrivateDirectory(
            $full,
            $acl.GetSecurityDescriptorBinaryForm()
        )
        Update-RollbackSafetyBoundary `
            -Token $registrationSafety `
            -Identity $claim.Identity
        if ($script:FreshDirectoryFaultMode -ceq "pre-registration" -and
            [string]::Equals(
                $full,
                [IO.Path]::GetFullPath($script:FreshDirectoryFaultTarget),
                [StringComparison]::OrdinalIgnoreCase
            )) {
            Die "Injected private-directory fault before claim registration: $full"
        }
        $script:PrivateDirectoryClaims[$full] = [pscustomobject]@{
            Path = $full
            Identity = $claim.Identity
            Native = $claim
            CleanupMode = "Tree"
        }
        $registered = $true
        $claim = $null
        Complete-RollbackSafetyBoundary -Token $registrationSafety
        Assert-PrivateDirectoryAcl -Path $full -Expected $acl
        if (@(Get-ChildItem -LiteralPath $full -Force).Count -ne 0) {
            Die "Private install directory was not empty immediately after creation: $full"
        }
    } catch {
        $creationFailure = $_
        $cleanupFailure = ""
        if ($registered) {
            try {
                Remove-PrivateDirectory -Path $full -RequireEmpty
            } catch {
                $cleanupFailure = [string]$_.Exception.Message
            }
        } elseif ($claim) {
            $cleanupClaim = $null
            $retired = $false
            try {
                $cleanupClaim = [DefenseClaw.Install.FreshV1.FreshPathClaim]::OpenIfExists(
                    $full,
                    $true,
                    $true
                )
                if ($cleanupClaim -and $cleanupClaim.Identity -ceq $claim.Identity) {
                    if ($cleanupClaim.DeleteEmptyDirectoryExact()) {
                        $claim.Dispose()
                        $claim = $null
                        $retired = $true
                    }
                }
            } catch {
                # Registration failed before the creation claim could enter the
                # custody table. Preserve any object whose exact identity cannot
                # be retired through its still-open creation handle.
                $cleanupFailure = [string]$_.Exception.Message
            } finally {
                if ($cleanupClaim) { $cleanupClaim.Dispose() }
            }
            if (-not $retired -and -not $cleanupFailure) {
                $cleanupFailure = "creation-bound directory could not be proven at its canonical path"
            }
        }
        if ($cleanupFailure) {
            Die (
                "$([string]$creationFailure.Exception.Message)`n" +
                "Private install directory cleanup was incomplete; creation-bound custody " +
                "remains unretired. Its canonical binding and current location are " +
                "unverified. Last expected path: '$full'. Last cleanup error: $cleanupFailure"
            )
        }
        throw $creationFailure
    } finally {
        if ($claim) { $claim.Dispose() }
    }
    return $full
}

function Get-PrivateDirectoryClaimKeys {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    $prefix = $full + [IO.Path]::DirectorySeparatorChar
    return @(
        $script:PrivateDirectoryClaims.Keys |
            Where-Object {
                [string]::Equals($_, $full, [StringComparison]::OrdinalIgnoreCase) -or
                $_.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
            } |
            Sort-Object -Property Length -Descending
    )
}

function Release-PrivateDirectoryClaim {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    if (-not $script:PrivateDirectoryClaims.ContainsKey($full)) { return }
    $entry = $script:PrivateDirectoryClaims[$full]
    [void]$script:PrivateDirectoryClaims.Remove($full)
    $entry.Native.Dispose()
}

function Move-PrivateDirectoryClaimRegistration {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    $sourceFull = [IO.Path]::GetFullPath($Source)
    $destinationFull = [IO.Path]::GetFullPath($Destination)
    if (-not $script:PrivateDirectoryClaims.ContainsKey($sourceFull)) {
        Die "Private install directory has no creation claim to transfer: $sourceFull"
    }
    if ($script:PrivateDirectoryClaims.ContainsKey($destinationFull)) {
        Die "Private install directory claim destination already exists: $destinationFull"
    }
    $entry = $script:PrivateDirectoryClaims[$sourceFull]
    $entry.Path = $destinationFull
    $entry.CleanupMode = "EmptyDirectory"
    $script:PrivateDirectoryClaims[$destinationFull] = $entry
    [void]$script:PrivateDirectoryClaims.Remove($sourceFull)
}

function Remove-PrivateDirectoryClaimAt {
    param(
        [Parameter(Mandatory = $true)][string]$ClaimKey,
        [Parameter(Mandatory = $true)][string]$CandidatePath,
        [switch]$RequireEmpty
    )
    $claimKeyFull = [IO.Path]::GetFullPath($ClaimKey)
    $candidateFull = [IO.Path]::GetFullPath($CandidatePath)
    $expectedIdentity = if ($script:PrivateDirectoryClaims.ContainsKey($claimKeyFull)) {
        [string]$script:PrivateDirectoryClaims[$claimKeyFull].Identity
    } else {
        "unavailable"
    }
    $cleanupSafety = Start-RollbackSafetyBoundary `
        -Boundary "private-directory-cleanup" `
        -Path $candidateFull `
        -Identity $expectedIdentity
    if (-not $script:PrivateDirectoryClaims.ContainsKey($claimKeyFull)) {
        Die (
            "Private install directory has no creation claim and was preserved; " +
            "canonical binding is unverified: $candidateFull"
        )
    }
    $entry = $script:PrivateDirectoryClaims[$claimKeyFull]
    $cleanupClaim = $null
    try {
        $cleanupClaim = [DefenseClaw.Install.FreshV1.FreshPathClaim]::OpenIfExists(
            $candidateFull,
            $true,
            $true
        )
        if (-not $cleanupClaim) {
            Die (
                "Private install directory canonical binding was lost; " +
                "creation-bound identity $($entry.Identity) remains unretired and its " +
                "current location is unknown. Last expected path: $candidateFull"
            )
        }
        if ($cleanupClaim.Identity -cne $entry.Identity) {
            Die (
                "Private install directory canonical path now names a different object " +
                "and was preserved; creation-bound identity $($entry.Identity) remains " +
                "unretired and its current location is unknown. Last expected path: " +
                $candidateFull
            )
        }
        Assert-PrivateDirectoryAcl -Path $candidateFull
        $removed = if ($RequireEmpty) {
            $cleanupClaim.DeleteEmptyDirectoryExact()
        } else {
            $cleanupClaim.DeleteTreeExact()
        }
        if (-not $removed) {
            Die (
                "Private install directory changed during exact cleanup; the verified " +
                "directory was preserved at '$candidateFull' (identity $($entry.Identity))"
            )
        }
        $entry.Native.Dispose()
        [void]$script:PrivateDirectoryClaims.Remove($claimKeyFull)
        Complete-RollbackSafetyBoundary -Token $cleanupSafety
    } finally {
        if ($cleanupClaim) { $cleanupClaim.Dispose() }
    }
}

function Remove-PrivateDirectory {
    param([string]$Path, [switch]$RequireEmpty)
    if (-not $Path) { return }
    $full = [IO.Path]::GetFullPath($Path)
    if (-not $script:PrivateDirectoryClaims.ContainsKey($full)) {
        Die "Private install directory has no creation claim and was preserved: $full"
    }
    $keys = if ($RequireEmpty) { @($full) } else { @(Get-PrivateDirectoryClaimKeys -Path $full) }
    foreach ($key in $keys) {
        if (-not $script:PrivateDirectoryClaims.ContainsKey($key)) { continue }
        $entry = $script:PrivateDirectoryClaims[$key]
        $entryRequiresEmpty = $RequireEmpty -or $entry.CleanupMode -ceq "EmptyDirectory"
        Remove-PrivateDirectoryClaimAt `
            -ClaimKey $key `
            -CandidatePath $entry.Path `
            -RequireEmpty:$entryRequiresEmpty
    }
}

function Close-ReleasePolicyCustody {
    if (-not $script:PolicyDir) { return }

    # Policy custody contains authenticated but decoded wheel/gateway bytes, so
    # close it before committing the public install. A transient Defender or
    # indexer handle must not, however, convert cleanup into authority to roll
    # back a fully healthy payload or replace the original install diagnostic.
    $policyToRemove = $script:PolicyDir
    $script:PolicyDir = ""
    if ($InjectPolicyCustodyMoveBeforeCleanup) {
        $displaced = "$policyToRemove.installer-owned-original"
        if (-not [DefenseClaw.Install.FreshV1.FreshPathClaim]::MoveDirectoryNoReplace(
            $policyToRemove,
            $displaced
        )) {
            Die "Injected private policy custody move unexpectedly collided: $displaced"
        }
    }
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

    $retainedIdentity = if ($script:PrivateDirectoryClaims.ContainsKey($policyToRemove)) {
        [string]$script:PrivateDirectoryClaims[$policyToRemove].Identity
    } else {
        "unavailable"
    }
    $script:PolicyCleanupWarning = (
        "Private release-policy cleanup was incomplete; its canonical binding is " +
        "unverified and the current location of installer-owned custody may be unknown. " +
        "Retained creation identity: $retainedIdentity. Last expected path: " +
        "'$policyToRemove'. Last cleanup error: $lastCleanupError"
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

function Invoke-NativeFreshDirectoryBoundarySelfTest {
    param([Parameter(Mandatory = $true)][string]$Root)
    $exactCleanupModes = @(
        "pre-registration",
        "pre-rekey",
        "open-failure",
        "list-add",
        "release"
    )
    $modes = $exactCleanupModes + @("identity-mismatch", "lost-binding")
    foreach ($mode in $modes) {
        $target = Join-Path $Root ("fresh-boundary-$mode-" + [guid]::NewGuid().ToString("N"))
        $script:FreshDirectoryFaultMode = $mode
        $script:FreshDirectoryFaultTarget = $target
        $script:FreshDirectoryFaultDisplaced = ""
        $failureMessage = ""
        if ($mode -ceq "pre-registration") {
            try {
                [void](New-PrivateDirectory -Path $target)
            } catch {
                $failureMessage = [string]$_.Exception.Message
            }
        } else {
            $script:FreshInstallClaims = New-Object 'System.Collections.Generic.List[object]'
            $script:FreshInstallAttemptActive = $true
            $script:FreshInstallOriginalProcessPath = $env:PATH
            $script:FreshInstallPublishedProcessPath = $null
            try {
                New-FreshInstallOwnedDirectory -Path $target -Kind EmptyDirectory
            } catch {
                $failureMessage = [string]$_.Exception.Message
            }
        }
        $rollbackResidue = @(Undo-FreshInstallAttempt)
        if (-not $failureMessage -or
            $rollbackResidue.Count -eq 0 -or
            -not @($rollbackResidue | Where-Object {
                $_ -match 'rollback safety boundary did not complete'
            })) {
            Die "Native fresh-directory boundary did not retain rollback residue: $mode"
        }

        $displaced = $script:FreshDirectoryFaultDisplaced
        if ($mode -ceq "identity-mismatch" -and
            (Test-Path -LiteralPath $target -PathType Container)) {
            [IO.Directory]::Delete($target)
        }
        if ($displaced) {
            if (-not $script:PrivateDirectoryClaims.ContainsKey(
                [IO.Path]::GetFullPath($target)
            )) {
                Die "Native fresh-directory boundary lost its retained claim: $mode"
            }
            Remove-PrivateDirectoryClaimAt `
                -ClaimKey $target `
                -CandidatePath $displaced `
                -RequireEmpty
        }
        if ($exactCleanupModes -contains $mode -and
            (Test-InstallMarker -Path $target)) {
            Die "Native fresh-directory boundary left public state after exact cleanup: $mode"
        }
        if ($script:PrivateDirectoryClaims.Count -ne 0) {
            Die "Native fresh-directory boundary left private claims after test cleanup: $mode"
        }
        $script:RollbackSafetyLedger.Clear()
        $script:FreshDirectoryFaultMode = ""
        $script:FreshDirectoryFaultTarget = ""
        $script:FreshDirectoryFaultDisplaced = ""
    }
    Write-Host "Native fresh directory fault boundaries passed" -ForegroundColor Green
}

function Invoke-NativePrivateDirectorySelfTest {
    param([Parameter(Mandatory = $true)][string]$Root)
    $rootFull = [IO.Path]::GetFullPath($Root)
    $rootItem = Get-Item -LiteralPath $rootFull -Force
    if (-not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Die "Native private-directory self-test root must be a real directory: $rootFull"
    }
    $private = Join-Path $rootFull ("private-lifecycle-" + [guid]::NewGuid().ToString("N"))
    $movePrivate = Join-Path $rootFull ("private-move-out-" + [guid]::NewGuid().ToString("N"))
    $movedMarker = Join-Path $rootFull ("moved-marker-" + [guid]::NewGuid().ToString("N"))
    $stream = $null
    $moveStream = $null
    try {
        [void](New-PrivateDirectory -Path $private)
        $marker = Join-Path $private "native-marker.bin"
        $stream = New-PrivateFileStream -Path $marker
        $bytes = [Text.Encoding]::ASCII.GetBytes("defenseclaw-native-private-lifecycle`r`n")
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        $stream.Dispose()
        $stream = $null
        Remove-PrivateDirectory -Path $private
        if ((Test-InstallMarker -Path $private) -or
            $script:PrivateDirectoryClaims.ContainsKey([IO.Path]::GetFullPath($private))) {
            Die "Native private-directory self-test cleanup reported false success: $private"
        }

        [void](New-PrivateDirectory -Path $movePrivate)
        $moveSource = Join-Path $movePrivate "move-out-marker.bin"
        $moveStream = New-PrivateFileStream -Path $moveSource
        $moveBytes = [Text.Encoding]::ASCII.GetBytes("defenseclaw-snapshot-move-out`r`n")
        $moveStream.Write($moveBytes, 0, $moveBytes.Length)
        $moveStream.Flush($true)
        $moveStream.Dispose()
        $moveStream = $null
        [DefenseClaw.Install.FreshV1.FreshPathClaim]::ConfigureTestMoveOutAfterSnapshot(
            $moveSource,
            $movedMarker
        )
        $moveOutRefused = $false
        try {
            Remove-PrivateDirectory -Path $movePrivate
        } catch {
            if (([string]$_.Exception.Message) -notmatch
                'changed during exact cleanup') {
                throw
            }
            $moveOutRefused = $true
        } finally {
            [DefenseClaw.Install.FreshV1.FreshPathClaim]::ClearTestMoveOutAfterSnapshot()
        }
        if (-not $moveOutRefused -or
            -not (Test-Path -LiteralPath $movePrivate -PathType Container) -or
            -not (Test-Path -LiteralPath $movedMarker -PathType Leaf) -or
            [Convert]::ToBase64String([IO.File]::ReadAllBytes($movedMarker)) -cne
                [Convert]::ToBase64String($moveBytes)) {
            Die "Native tree rollback treated a moved-out snapshotted child as deleted"
        }
        [IO.File]::Delete($movedMarker)
        Remove-PrivateDirectory -Path $movePrivate
        Write-Host "Native snapshotted-child move-out refusal passed" -ForegroundColor Green

        Invoke-NativeFreshDirectoryBoundarySelfTest -Root $rootFull

        $fileParent = Join-Path $rootFull ("not-a-directory-" + [guid]::NewGuid().ToString("N"))
        [IO.File]::WriteAllText($fileParent, "parent-type-guard", [Text.Encoding]::ASCII)
        $parentTypeRejected = $false
        try {
            [void](New-PrivateDirectory -Path (Join-Path $fileParent "child"))
        } catch {
            if (([string]$_.Exception.Message) -notmatch
                'private directory parent must be a real directory') {
                throw
            }
            $parentTypeRejected = $true
        } finally {
            [IO.File]::Delete($fileParent)
        }
        if (-not $parentTypeRejected) {
            Die "Native private-directory self-test accepted a file as its parent"
        }
        # This expected pre-registration refusal is the subject of the test,
        # not residue from a real installer transaction.
        $script:RollbackSafetyLedger.Clear()
    } finally {
        if ($stream) { $stream.Dispose() }
        if ($moveStream) { $moveStream.Dispose() }
        [DefenseClaw.Install.FreshV1.FreshPathClaim]::ClearTestMoveOutAfterSnapshot()
        if (Test-Path -LiteralPath $movedMarker -PathType Leaf) {
            [IO.File]::Delete($movedMarker)
        }
        if ($script:PrivateDirectoryClaims.ContainsKey([IO.Path]::GetFullPath($private))) {
            try { Remove-PrivateDirectory -Path $private } catch {}
        }
        if ($script:PrivateDirectoryClaims.ContainsKey([IO.Path]::GetFullPath($movePrivate))) {
            try { Remove-PrivateDirectory -Path $movePrivate } catch {}
        }
    }
    Write-Host "Native private directory lifecycle passed" -ForegroundColor Green
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
        # The CreateNew stream is exclusive and has DELETE access. Verify the
        # bytes and ACL while that creation-bound handle still pins the exact
        # object; any failure can then retire only that object by handle.
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
        Assert-PrivateFileAcl -Path $Destination
        if ($FreshInstallDestination) {
            # Retain exact rollback custody before the exclusive creation
            # stream closes. A pathname replacement during the handoff is
            # detected by file ID and preserved.
            Add-FreshInstallStreamClaim -Stream $output -Path $Destination
            $freshClaimRegistered = $true
        }
    } catch {
        if ($output -and -not $freshClaimRegistered) {
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
        Die "Could not materialize an authenticated private install artifact: $Destination"
    } finally {
        if ($output) { $output.Dispose() }
        if ($sourceStream) { $sourceStream.Dispose() }
        if ($outerHash) { $outerHash.Dispose() }
        if ($innerHash) { $innerHash.Dispose() }
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

# -- Logging ------------------------------------------------------------------

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

# -- Utilities ----------------------------------------------------------------

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
        try { [void]$claim.DeleteFileExact() } catch {}
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

function Invoke-FreshDirectoryFaultBoundary {
    param(
        [Parameter(Mandatory = $true)][string]$Boundary,
        [Parameter(Mandatory = $true)][string]$Path
    )
    if (-not $script:FreshDirectoryFaultMode -or
        $script:FreshDirectoryFaultMode -cne $Boundary -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath($Path),
            [IO.Path]::GetFullPath($script:FreshDirectoryFaultTarget),
            [StringComparison]::OrdinalIgnoreCase
        )) {
        return
    }
    $full = [IO.Path]::GetFullPath($Path)
    if ($Boundary -in @("identity-mismatch", "lost-binding")) {
        $displaced = "$full.injected-original"
        if (-not [DefenseClaw.Install.FreshV1.FreshPathClaim]::MoveDirectoryNoReplace(
            $full,
            $displaced
        )) {
            Die "Injected fresh-directory displacement collided: $displaced"
        }
        $script:FreshDirectoryFaultDisplaced = $displaced
        if ($Boundary -ceq "identity-mismatch") {
            [void][IO.Directory]::CreateDirectory($full)
        }
        return
    }
    Die "Injected fresh-directory fault at ${Boundary}: $full"
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
    $publishedClaim = $null
    $moved = $false
    $registered = $false
    $publicationSafety = ""
    try {
        [void](New-PrivateDirectory -Path $stage)
        $stageIdentity = [string]$script:PrivateDirectoryClaims[$stage].Identity
        $publicationSafety = Start-RollbackSafetyBoundary `
            -Boundary "fresh-directory-publication" `
            -Path $full `
            -Identity $stageIdentity

        $moved = [DefenseClaw.Install.FreshV1.FreshPathClaim]::MoveDirectoryNoReplace(
            $stage,
            $full
        )
        if (-not $moved) {
            Die "A fresh-install directory appeared concurrently and was preserved: $full"
        }
        Invoke-FreshDirectoryFaultBoundary -Boundary "pre-rekey" -Path $full
        Move-PrivateDirectoryClaimRegistration -Source $stage -Destination $full
        if ($InjectFailureAfterFreshDirectoryMove -and
            [string]::Equals(
                $full,
                [IO.Path]::GetFullPath($InstallDir),
                [StringComparison]::OrdinalIgnoreCase
            )) {
            Die "Injected fresh-install directory failure after publishing: $full"
        }
        Invoke-FreshDirectoryFaultBoundary -Boundary "open-failure" -Path $full
        Invoke-FreshDirectoryFaultBoundary -Boundary "lost-binding" -Path $full
        Invoke-FreshDirectoryFaultBoundary -Boundary "identity-mismatch" -Path $full
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
        Invoke-FreshDirectoryFaultBoundary -Boundary "list-add" -Path $full
        [void]$script:FreshInstallClaims.Add([pscustomobject]@{
            Kind = $Kind
            Path = $full
            Identity = $publishedClaim.Identity
            Native = $publishedClaim
        })
        $registered = $true
        Invoke-FreshDirectoryFaultBoundary -Boundary "release" -Path $full
        Release-PrivateDirectoryClaim -Path $full
        Complete-RollbackSafetyBoundary -Token $publicationSafety
    } catch {
        $publicationFailure = $_
        if (-not $stageIdentity) {
            # New-PrivateDirectory owns creation/registration cleanup and its
            # durable safety entry. Preserve its exact diagnostic rather than
            # inventing a retained publication identity that never existed.
            throw $publicationFailure
        }
        $cleanupFailure = ""
        $candidatePath = if ($moved) { $full } else { $stage }
        if (-not $registered -and $publishedClaim) {
            # A published claim prevents any second DELETE-capable cleanup
            # handle from opening. Drop it, but retain the creation claim and
            # require an identity match before deleting through the namespace.
            try {
                $publishedClaim.Dispose()
                $publishedClaim = $null
            } catch {
                $cleanupFailure = [string]$_.Exception.Message
            }
        }
        if (-not $registered) {
            $claimKey = ""
            foreach ($possibleKey in @($full, $stage)) {
                if (-not $script:PrivateDirectoryClaims.ContainsKey($possibleKey)) {
                    continue
                }
                $possibleIdentity = [string]$script:PrivateDirectoryClaims[$possibleKey].Identity
                if ($possibleIdentity -ceq $stageIdentity) {
                    $claimKey = $possibleKey
                    break
                }
            }
            if ($claimKey) {
                # Move/rekey itself is a failure boundary. Record the last
                # expected public binding even if registration failed midway,
                # so rollback never misreports the old staging name.
                $entry = $script:PrivateDirectoryClaims[$claimKey]
                $entry.Path = $candidatePath
                $entry.CleanupMode = "EmptyDirectory"
                try {
                    Remove-PrivateDirectoryClaimAt `
                        -ClaimKey $claimKey `
                        -CandidatePath $candidatePath `
                        -RequireEmpty
                } catch {
                    $claimCleanupFailure = [string]$_.Exception.Message
                    $cleanupFailure = if ($cleanupFailure) {
                        "$cleanupFailure; $claimCleanupFailure"
                    } else {
                        $claimCleanupFailure
                    }
                }
            } else {
                $missingClaimFailure = (
                    "fresh-install directory lost its creation-bound claim; " +
                    "canonical binding and current location are unverified"
                )
                $cleanupFailure = if ($cleanupFailure) {
                    "$cleanupFailure; $missingClaimFailure"
                } else {
                    $missingClaimFailure
                }
            }
        } elseif ($script:PrivateDirectoryClaims.ContainsKey($full)) {
            # FreshInstallClaims now owns exact rollback authority. Retire the
            # relocatable creation handle so it cannot become silent residue.
            try {
                Release-PrivateDirectoryClaim -Path $full
            } catch {
                $cleanupFailure = [string]$_.Exception.Message
            }
        }
        if ($cleanupFailure) {
            Die (
                "$([string]$publicationFailure.Exception.Message)`n" +
                "Fresh-install directory publication cleanup was incomplete; the retained " +
                "creation identity remains unretired. Canonical binding and current " +
                "location are unverified. Last expected path: '$candidatePath'. " +
                "Last cleanup error: $cleanupFailure"
            )
        }
        throw $publicationFailure
    }
}

function Add-PrivateDirectoryRollbackResidue {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$Residue
    )
    foreach ($token in @($script:RollbackSafetyLedger.Keys | Sort-Object)) {
        $safety = $script:RollbackSafetyLedger[$token]
        [void]$Residue.Add(
            "rollback safety boundary did not complete: $($safety.Boundary); retained " +
            "identity $($safety.Identity); last expected path '$($safety.Path)'"
        )
    }
    foreach ($key in @(
        $script:PrivateDirectoryClaims.Keys |
            Sort-Object -Property Length -Descending
    )) {
        if (-not $script:PrivateDirectoryClaims.ContainsKey($key)) { continue }
        $entry = $script:PrivateDirectoryClaims[$key]
        [void]$Residue.Add(
            "creation-bound private directory cleanup remains incomplete: retained " +
            "identity $($entry.Identity); last expected path '$($entry.Path)'; canonical " +
            "binding and current location are unverified, and the process-local identity " +
            "claim will close when the installer exits"
        )
    }
}

function Initialize-FreshInstallAttempt {
    if ($script:FreshInstallAttemptActive) {
        Die "Fresh-install transaction is already active"
    }
    $script:FreshInstallClaims = New-Object 'System.Collections.Generic.List[object]'
    $script:FreshInstallAttemptActive = $true
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
        Add-PrivateDirectoryRollbackResidue -Residue $residue
        return @($residue)
    }

    # Process PATH is private to this installer process. Restore it only when
    # it still equals this attempt's exact publication.
    try {
        if ($null -ne $script:FreshInstallPublishedProcessPath) {
            if ($env:PATH -ceq $script:FreshInstallPublishedProcessPath) {
                $env:PATH = $script:FreshInstallOriginalProcessPath
            } else {
                [void]$residue.Add("the process PATH changed concurrently and was preserved")
            }
        }
    } catch {
        [void]$residue.Add("the installer could not restore its process PATH: $($_.Exception.Message)")
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
    Add-PrivateDirectoryRollbackResidue -Residue $residue
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
    Write-Host "  Use the authenticated release-owned upgrade resolver from the target release in latest mode:" -ForegroundColor Yellow
    Write-Host '    & .\defenseclaw-upgrade.ps1 -Yes' -ForegroundColor Yellow
    Write-Host "  Do not pass -Version. Download and verify the resolver with its signed checksums:" -ForegroundColor Yellow
    Write-Host "    https://github.com/$Repo/blob/main/docs/CLI.md#upgrade" -ForegroundColor Yellow
    exit 1
}

# -- Platform detection -------------------------------------------------------

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

# -- Dependency: uv -----------------------------------------------------------

function Install-Uv {
    Write-Step "Checking uv"
    if (Test-HasCommand "uv") {
        Write-Ok "uv found"
        return
    }
    Write-Info "Installing uv..."
    $previousUvNoModifyPath = [Environment]::GetEnvironmentVariable(
        "UV_NO_MODIFY_PATH",
        [EnvironmentVariableTarget]::Process
    )
    try {
        # The upstream uv installer otherwise edits shell PATH state. Keep its
        # install process-local; Add-ToPath prints the explicit operator-owned
        # new-shell setup after DefenseClaw itself has installed successfully.
        [Environment]::SetEnvironmentVariable(
            "UV_NO_MODIFY_PATH",
            "1",
            [EnvironmentVariableTarget]::Process
        )
        Invoke-RestMethod -Uri "https://astral.sh/uv/install.ps1" | Invoke-Expression
    } catch {
        Die "Failed to install uv. Install manually: https://docs.astral.sh/uv/"
    } finally {
        [Environment]::SetEnvironmentVariable(
            "UV_NO_MODIFY_PATH",
            $previousUvNoModifyPath,
            [EnvironmentVariableTarget]::Process
        )
    }
    # uv's installer drops the binary in %USERPROFILE%\.local\bin; surface it on
    # PATH for the rest of this process so subsequent calls resolve.
    $uvDir = Join-Path $env:USERPROFILE ".local\bin"
    if (Test-Path $uvDir) { $env:PATH = "$uvDir;$env:PATH" }
    if (-not (Test-HasCommand "uv")) {
        Die (
            "uv installation completed but 'uv' was not found at the expected location " +
            "'$uvDir'. Persistent PATH was not modified. Install a current uv release " +
            "from https://docs.astral.sh/uv/getting-started/installation/ and retry."
        )
    }
    Write-Ok "uv installed"
}

# -- Dependency: Python -------------------------------------------------------

function Ensure-Python {
    Write-Step "Checking Python"
    # uv manages an interpreter for the private venv. Do not publish a global
    # executable or Windows registry registration for this internal runtime.
    $pythonInstallOutput = (& uv python install 3.12 --no-bin --no-registry --quiet 2>&1 |
        Select-Object -Last 20 | Out-String).Trim()
    $pythonInstallExitCode = $LASTEXITCODE
    if ($pythonInstallExitCode -ne 0) {
        $pythonInstallDetail = if ($pythonInstallOutput) {
            "`nuv output:`n$pythonInstallOutput"
        } else {
            ""
        }
        Die (
            "Failed to install the managed Python 3.12 runtime. A current uv release " +
            "with --no-bin and --no-registry support is required. Install or update uv " +
            "from https://docs.astral.sh/uv/getting-started/installation/ and retry." +
            $pythonInstallDetail
        )
    }
    Write-Ok "Python 3.12 (managed by uv)"
}

# -- Resolve release version --------------------------------------------------

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

# -- Artifact fetch + checksum verification ----------------------------------

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

# -- Install: gateway binary --------------------------------------------------

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

# -- Install: Python CLI (from wheel) -----------------------------------------

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

# -- Connector selection -----------------------------------------------------

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

# -- Optional: quickstart -----------------------------------------------------

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

# -- PATH configuration -------------------------------------------------------

function Add-ToPath {
    # Persistent User PATH is shared registry state without an atomic
    # compare-and-set API. Never modify/write it from this installer.
    # Process PATH is rollback-bound and exists only for the current quickstart.
    if (($env:PATH -split ';') -notcontains $InstallDir) {
        $publishedProcessPath = "$InstallDir;$env:PATH"
        $env:PATH = $publishedProcessPath
        $script:FreshInstallPublishedProcessPath = $publishedProcessPath
    }
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $userEntries = if ($userPath) {
        @($userPath -split ';' | Where-Object { $_ -ne "" })
    } else {
        @()
    }
    if ($userEntries -notcontains $InstallDir) {
        $shim = Join-Path $InstallDir "defenseclaw.cmd"
        Write-Step "New-shell PATH setup required"
        Write-Warn2 "Persistent User PATH was not modified."
        Write-Host "  To enable 'defenseclaw' in new shells:" -ForegroundColor Cyan
        Write-Host "    1. Open 'Edit environment variables for your account'."
        Write-Host "    2. Under User variables, edit Path and choose New."
        Write-Host "    3. Add this exact directory:"
        Write-Host "       $InstallDir" -ForegroundColor White
        Write-Host "  Until then, run the CLI by its exact path:" -ForegroundColor Cyan
        Write-Host "       & `"$shim`" <command>" -ForegroundColor White
    }
}

# -- Success ------------------------------------------------------------------

function Write-Success {
    $shim = Join-Path $InstallDir "defenseclaw.cmd"
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Green
    Write-Host "         DefenseClaw installed successfully!" -ForegroundColor Green
    Write-Host "  ============================================================" -ForegroundColor Green
    Write-Host ""
    switch ($script:PickedConnector) {
        "codex"      { Write-Host "  Get started (Codex):`n`n    & `"$shim`" init --connector codex`n" -ForegroundColor Cyan }
        "claudecode" { Write-Host "  Get started (Claude Code):`n`n    & `"$shim`" init --connector claudecode`n" -ForegroundColor Cyan }
        { $_ -in $HookConnectors } {
            Write-Host "  Get started ($script:PickedConnector):`n`n    & `"$shim`" init --connector $script:PickedConnector`n" -ForegroundColor Cyan
        }
        default      { Write-Host "  Get started (pick a connector later):`n`n    & `"$shim`" init`n" -ForegroundColor Cyan }
    }
}

# -- Entry point --------------------------------------------------------------

function Main {
    if ($Help) { Show-Help; return }

    if ((
        $InjectFailureBeforeShim -or
        $InjectConcurrentShimBeforePublish -or
        $InjectPolicyCleanupFailure -or
        $InjectPolicyCustodyMoveBeforeCleanup -or
        $InjectFailureAfterFreshDirectoryMove -or
        $NativePrivateDirectorySelfTestRoot
    ) -and -not $TestMode) {
        Die "Fresh-install fault injection requires -TestMode"
    }

    if ($NativePrivateDirectorySelfTestRoot) {
        Invoke-NativePrivateDirectorySelfTest -Root $NativePrivateDirectorySelfTestRoot
        return
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
