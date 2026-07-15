// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace DefenseClaw
{
    // Reads child-writable handoff files through an OPEN_REPARSE_POINT handle.
    // Metadata validation and bytes consumed therefore refer to one object,
    // not to two path resolutions separated by a race window.
    public static class DisposableFileGuard
    {
        private const uint GENERIC_READ = 0x80000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        private const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
        private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
        private const uint FILE_TYPE_DISK = 0x0001;

        [StructLayout(LayoutKind.Sequential)]
        private struct FILETIME
        {
            public uint LowDateTime;
            public uint HighDateTime;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BY_HANDLE_FILE_INFORMATION
        {
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

        [DllImport(
            "kernel32.dll",
            EntryPoint = "CreateFileW",
            CharSet = CharSet.Unicode,
            ExactSpelling = true,
            SetLastError = true)]
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
        private static extern uint GetFileType(SafeFileHandle file);

        private static SafeFileHandle OpenNoFollow(string path)
        {
            if (String.IsNullOrWhiteSpace(path) || !Path.IsPathRooted(path))
            {
                throw new ArgumentException("guarded file path must be absolute", "path");
            }
            if (path.IndexOf('\0') >= 0)
            {
                throw new ArgumentException("guarded file path contains NUL", "path");
            }
            SafeFileHandle handle = CreateFile(
                path,
                GENERIC_READ,
                FILE_SHARE_READ,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                IntPtr.Zero);
            if (handle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new Win32Exception(error, "CreateFileW no-follow open failed for " + path);
            }
            return handle;
        }

        private static long ValidateRegularSingleLink(
            SafeFileHandle handle,
            long maximumBytes,
            string path)
        {
            if (maximumBytes < 0) throw new ArgumentOutOfRangeException("maximumBytes");
            if (GetFileType(handle) != FILE_TYPE_DISK)
            {
                throw new InvalidOperationException("guarded handoff is not a disk file: " + path);
            }
            BY_HANDLE_FILE_INFORMATION information;
            if (!GetFileInformationByHandle(handle, out information))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "GetFileInformationByHandle failed for " + path);
            }
            if ((information.FileAttributes &
                (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0)
            {
                throw new InvalidOperationException(
                    "guarded handoff is a directory or reparse point: " + path);
            }
            if (information.NumberOfLinks != 1)
            {
                throw new InvalidOperationException(
                    "guarded handoff must have exactly one NTFS link: " + path);
            }
            ulong unsignedSize = ((ulong)information.FileSizeHigh << 32) |
                information.FileSizeLow;
            if (unsignedSize > (ulong)maximumBytes || unsignedSize > Int64.MaxValue)
            {
                throw new InvalidOperationException(
                    "guarded handoff exceeds its byte bound: " + path);
            }
            return (long)unsignedSize;
        }

        private static byte[] ReadExact(SafeFileHandle handle, long size, string path)
        {
            if (size > Int32.MaxValue)
            {
                throw new InvalidOperationException("guarded handoff is too large to read: " + path);
            }
            byte[] bytes = new byte[(int)size];
            using (FileStream input = new FileStream(handle, FileAccess.Read, 65536, false))
            {
                int offset = 0;
                while (offset < bytes.Length)
                {
                    int read = input.Read(bytes, offset, bytes.Length - offset);
                    if (read == 0)
                    {
                        throw new InvalidOperationException(
                            "guarded handoff became truncated while reading: " + path);
                    }
                    offset += read;
                }
                if (input.ReadByte() != -1)
                {
                    throw new InvalidOperationException(
                        "guarded handoff grew while reading: " + path);
                }
            }
            return bytes;
        }

        public static byte[] ReadBoundedBytes(string path, long maximumBytes)
        {
            using (SafeFileHandle handle = OpenNoFollow(path))
            {
                long size = ValidateRegularSingleLink(handle, maximumBytes, path);
                return ReadExact(handle, size, path);
            }
        }

        public static string ReadBoundedUtf8(string path, long maximumBytes)
        {
            return new UTF8Encoding(false, true).GetString(
                ReadBoundedBytes(path, maximumBytes));
        }

        public static string ComputeSha256Hex(string path, long maximumBytes)
        {
            using (SafeFileHandle handle = OpenNoFollow(path))
            {
                long size = ValidateRegularSingleLink(handle, maximumBytes, path);
                using (FileStream input = new FileStream(handle, FileAccess.Read, 65536, false))
                using (SHA256 sha256 = SHA256.Create())
                {
                    byte[] digest = sha256.ComputeHash(input);
                    if (input.Position != size || input.ReadByte() != -1)
                    {
                        throw new InvalidOperationException(
                            "guarded Setup changed while hashing: " + path);
                    }
                    StringBuilder hex = new StringBuilder(digest.Length * 2);
                    foreach (byte value in digest) hex.Append(value.ToString("X2"));
                    return hex.ToString();
                }
            }
        }

        public static long CopyBoundedRegularFile(
            string sourcePath,
            string destinationPath,
            long maximumBytes)
        {
            using (SafeFileHandle handle = OpenNoFollow(sourcePath))
            {
                long size = ValidateRegularSingleLink(handle, maximumBytes, sourcePath);
                using (FileStream input = new FileStream(handle, FileAccess.Read, 65536, false))
                using (FileStream output = new FileStream(
                    destinationPath,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.None,
                    65536,
                    FileOptions.WriteThrough))
                {
                    byte[] buffer = new byte[65536];
                    long remaining = size;
                    while (remaining != 0)
                    {
                        int requested = (int)Math.Min(buffer.Length, remaining);
                        int read = input.Read(buffer, 0, requested);
                        if (read == 0)
                        {
                            throw new InvalidOperationException(
                                "guarded diagnostic became truncated while copying: " + sourcePath);
                        }
                        output.Write(buffer, 0, read);
                        remaining -= read;
                    }
                    if (input.ReadByte() != -1)
                    {
                        throw new InvalidOperationException(
                            "guarded diagnostic grew while copying: " + sourcePath);
                    }
                    output.Flush(true);
                }
                return size;
            }
        }
    }
}
