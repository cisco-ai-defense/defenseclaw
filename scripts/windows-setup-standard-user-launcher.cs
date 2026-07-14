// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace DefenseClaw
{
    // Native release jobs need administrator authority for machine policy, but
    // user-scope Setup deliberately rejects elevation. This helper derives a
    // filtered LUA primary token, verifies the suspended child token, and only
    // then lets the exact Setup image execute.
    public static class SetupStandardUserLauncher
    {
        private const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        private const uint TOKEN_DUPLICATE = 0x0002;
        private const uint TOKEN_QUERY = 0x0008;
        private const uint DISABLE_MAX_PRIVILEGE = 0x0001;
        private const uint LUA_TOKEN = 0x0004;
        private const uint CREATE_SUSPENDED = 0x00000004;
        private const uint CREATE_NO_WINDOW = 0x08000000;
        private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const int TokenElevation = 20;

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_ELEVATION
        {
            public int TokenIsElevated;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr thread);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateProcess(IntPtr process, uint exitCode);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenProcessToken(
            IntPtr process,
            uint desiredAccess,
            out IntPtr token);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateRestrictedToken(
            IntPtr existingToken,
            uint flags,
            uint disableSidCount,
            IntPtr sidsToDisable,
            uint deletePrivilegeCount,
            IntPtr privilegesToDelete,
            uint restrictedSidCount,
            IntPtr sidsToRestrict,
            out IntPtr newToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetTokenInformation(
            IntPtr token,
            int informationClass,
            out TOKEN_ELEVATION information,
            int informationLength,
            out int returnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsTokenRestricted(IntPtr token);

        [DllImport(
            "advapi32.dll",
            EntryPoint = "CreateProcessAsUserW",
            CharSet = CharSet.Unicode,
            ExactSpelling = true,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateProcessAsUser(
            IntPtr token,
            string applicationName,
            StringBuilder commandLine,
            IntPtr processAttributes,
            IntPtr threadAttributes,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
            uint creationFlags,
            IntPtr environment,
            string currentDirectory,
            ref STARTUPINFO startupInfo,
            out PROCESS_INFORMATION processInformation);

        private static IntPtr OpenToken(IntPtr process, uint access)
        {
            IntPtr token;
            if (!OpenProcessToken(process, access, out token))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken failed");
            }
            return token;
        }

        private static bool IsElevated(IntPtr token)
        {
            TOKEN_ELEVATION elevation;
            int returned;
            if (!GetTokenInformation(
                token,
                TokenElevation,
                out elevation,
                Marshal.SizeOf(typeof(TOKEN_ELEVATION)),
                out returned))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "GetTokenInformation(TokenElevation) failed");
            }
            return elevation.TokenIsElevated != 0;
        }

        public static bool IsCurrentProcessElevated()
        {
            IntPtr token = IntPtr.Zero;
            try
            {
                token = OpenToken(GetCurrentProcess(), TOKEN_QUERY);
                return IsElevated(token);
            }
            finally
            {
                if (token != IntPtr.Zero) CloseHandle(token);
            }
        }

        // Implements the CommandLineToArgvW-compatible quoting rules used by
        // ProcessStartInfo.ArgumentList, including trailing backslashes before
        // the closing quote. It is public so the PowerShell smoke test can
        // exercise exact Unicode/quote/backslash round trips.
        public static string QuoteWindowsArgument(string argument)
        {
            if (argument == null) throw new ArgumentNullException("argument");
            if (argument.IndexOf('\0') >= 0)
            {
                throw new ArgumentException("Windows process arguments cannot contain NUL", "argument");
            }
            if (argument.Length == 0) return "\"\"";
            bool needsQuotes = false;
            foreach (char character in argument)
            {
                if (char.IsWhiteSpace(character) || character == '"')
                {
                    needsQuotes = true;
                    break;
                }
            }
            if (!needsQuotes) return argument;

            StringBuilder quoted = new StringBuilder();
            quoted.Append('"');
            int backslashes = 0;
            foreach (char character in argument)
            {
                if (character == '\\')
                {
                    backslashes++;
                    continue;
                }
                if (character == '"')
                {
                    quoted.Append('\\', backslashes * 2 + 1);
                    quoted.Append('"');
                    backslashes = 0;
                    continue;
                }
                quoted.Append('\\', backslashes);
                backslashes = 0;
                quoted.Append(character);
            }
            quoted.Append('\\', backslashes * 2);
            quoted.Append('"');
            return quoted.ToString();
        }

        private static StringBuilder BuildCommandLine(string applicationPath, string[] arguments)
        {
            StringBuilder commandLine = new StringBuilder(QuoteWindowsArgument(applicationPath));
            foreach (string argument in arguments ?? new string[0])
            {
                commandLine.Append(' ');
                commandLine.Append(QuoteWindowsArgument(argument));
            }
            return commandLine;
        }

        private static IntPtr BuildEnvironment(string[] environmentEntries)
        {
            string[] entries = (string[])(environmentEntries ?? new string[0]).Clone();
            Array.Sort(entries, StringComparer.OrdinalIgnoreCase);
            foreach (string entry in entries)
            {
                int separator = entry == null ? -1 : entry.IndexOf('=', entry.StartsWith("=") ? 1 : 0);
                if (entry == null || entry.IndexOf('\0') >= 0 || separator <= 0)
                {
                    throw new ArgumentException("invalid Windows environment entry");
                }
            }
            string block = String.Join("\0", entries) + "\0\0";
            return Marshal.StringToHGlobalUni(block);
        }

        public static Process StartRestricted(
            string applicationPath,
            string[] arguments,
            string workingDirectory,
            string[] environmentEntries)
        {
            if (String.IsNullOrWhiteSpace(applicationPath) || !Path.IsPathRooted(applicationPath))
            {
                throw new ArgumentException("restricted Setup application path must be absolute");
            }
            if (applicationPath.IndexOf('\0') >= 0)
            {
                throw new ArgumentException("restricted Setup application path contains NUL");
            }
            if (String.IsNullOrWhiteSpace(workingDirectory) || !Path.IsPathRooted(workingDirectory))
            {
                throw new ArgumentException("restricted Setup working directory must be absolute");
            }
            if (workingDirectory.IndexOf('\0') >= 0)
            {
                throw new ArgumentException("restricted Setup working directory contains NUL");
            }

            IntPtr sourceToken = IntPtr.Zero;
            IntPtr restrictedToken = IntPtr.Zero;
            IntPtr childToken = IntPtr.Zero;
            IntPtr environment = IntPtr.Zero;
            PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();
            Process process = null;
            bool resumed = false;
            try
            {
                sourceToken = OpenToken(
                    GetCurrentProcess(),
                    TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY);
                if (!IsElevated(sourceToken))
                {
                    throw new InvalidOperationException(
                        "restricted Setup launch was requested from an already non-elevated process");
                }
                if (!CreateRestrictedToken(
                    sourceToken,
                    DISABLE_MAX_PRIVILEGE | LUA_TOKEN,
                    0,
                    IntPtr.Zero,
                    0,
                    IntPtr.Zero,
                    0,
                    IntPtr.Zero,
                    out restrictedToken))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateRestrictedToken failed");
                }
                if (!IsTokenRestricted(restrictedToken) || IsElevated(restrictedToken))
                {
                    throw new InvalidOperationException(
                        "CreateRestrictedToken did not produce a non-elevated restricted LUA token");
                }

                environment = BuildEnvironment(environmentEntries);
                STARTUPINFO startupInfo = new STARTUPINFO();
                startupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));
                startupInfo.lpDesktop = @"winsta0\default";
                if (!CreateProcessAsUser(
                    restrictedToken,
                    applicationPath,
                    BuildCommandLine(applicationPath, arguments),
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                    environment,
                    workingDirectory,
                    ref startupInfo,
                    out processInfo))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessAsUserW failed");
                }

                childToken = OpenToken(processInfo.hProcess, TOKEN_QUERY);
                if (!IsTokenRestricted(childToken) || IsElevated(childToken))
                {
                    throw new InvalidOperationException(
                        "suspended Setup child did not inherit the verified non-elevated restricted LUA token");
                }
                process = Process.GetProcessById(checked((int)processInfo.dwProcessId));
                if (ResumeThread(processInfo.hThread) == UInt32.MaxValue)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "ResumeThread failed");
                }
                resumed = true;
                return process;
            }
            finally
            {
                if (!resumed && processInfo.hProcess != IntPtr.Zero)
                {
                    TerminateProcess(processInfo.hProcess, 1603);
                }
                if (processInfo.hThread != IntPtr.Zero) CloseHandle(processInfo.hThread);
                if (processInfo.hProcess != IntPtr.Zero) CloseHandle(processInfo.hProcess);
                if (childToken != IntPtr.Zero) CloseHandle(childToken);
                if (environment != IntPtr.Zero) Marshal.FreeHGlobal(environment);
                if (restrictedToken != IntPtr.Zero) CloseHandle(restrictedToken);
                if (sourceToken != IntPtr.Zero) CloseHandle(sourceToken);
                if (!resumed && process != null) process.Dispose();
            }
        }
    }
}
