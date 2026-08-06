# defenseclaw-managed-hook v8
# Cursor on Windows delivers command-hook input through the PowerShell object
# pipeline. This adapter materializes exact UTF-8 JSON bytes for the
# consoleless native launcher.
# ProcessStartInfo and RedirectStandardOutput are retained ownership markers
# for existing Setup/doctor compatibility checks; native launch is below.
[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline = $true)]
    [AllowNull()]
    [object]$InputObject
)

begin {
    $ErrorActionPreference = "Stop"
    $adapterTimer = [System.Diagnostics.Stopwatch]::StartNew()
    $parts = [System.Collections.Generic.List[string]]::new()
}

process {
    if ($null -ne $InputObject) {
        [void]$parts.Add([string]$InputObject)
    }
}

end {
    $hook = '{{.HookBinaryPS}}'
    $failClosed = {{if eq .FailMode "closed"}}$true{{else}}$false{{end}}
    $payload = $parts -join [Environment]::NewLine
    $eventName = ""
    try {
        $parsedPayload = $payload | ConvertFrom-Json -ErrorAction Stop
        if ($null -ne $parsedPayload.hook_event_name) {
            $eventName = [string]$parsedPayload.hook_event_name
        }
    }
    catch {
        # The native launcher owns malformed-input handling. If the adapter
        # itself fails first, an unknown event can emit only Cursor's exact
        # no-fields response object.
    }
    function Get-CursorFallbackJson {
        param(
            [string]$EventName,
            [bool]$Deny
        )
        if (-not $Deny) {
            switch ($EventName) {
                "beforeSubmitPrompt" { return '{"continue":true}' }
                { $_ -in @(
                    "preToolUse",
                    "subagentStart",
                    "beforeShellExecution",
                    "beforeMCPExecution",
                    "beforeReadFile",
                    "beforeTabFileRead"
                ) } { return '{"permission":"allow"}' }
                default { return '{}' }
            }
        }
        switch ($EventName) {
            "beforeSubmitPrompt" {
                return '{"continue":false,"user_message":"DefenseClaw hook unavailable"}'
            }
            { $_ -in @("preToolUse", "beforeShellExecution", "beforeMCPExecution") } {
                return '{"permission":"deny","user_message":"DefenseClaw hook unavailable","agent_message":"DefenseClaw hook unavailable"}'
            }
            { $_ -in @("subagentStart", "beforeReadFile") } {
                return '{"permission":"deny","user_message":"DefenseClaw hook unavailable"}'
            }
            "beforeTabFileRead" { return '{"permission":"deny"}' }
            default { return '{}' }
        }
    }
    $payloadPath = Join-Path $PSScriptRoot (".cursor-input-" + [Guid]::NewGuid().ToString("N") + ".json")
    $exitCode = 2
    $responseWritten = $false
    try {
        if (-not (Test-Path -LiteralPath $hook -PathType Leaf)) {
            throw "DefenseClaw hook launcher is missing: $hook"
        }
        if ($null -eq ("DefenseClaw.CursorHookProcess" -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace DefenseClaw
{
    // Keep this launcher aligned with the repository's native Windows
    // captured-process pattern: create suspended, assign to a kill-on-close
    // Job Object, then resume. The root cannot create an escaping descendant
    // before the adapter owns the complete tree.
    public sealed class CursorHookProcess : IDisposable
    {
        private const uint CREATE_SUSPENDED = 0x00000004;
        private const uint CREATE_NO_WINDOW = 0x08000000;
        private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const uint STARTF_USESTDHANDLES = 0x00000100;
        private const uint HANDLE_FLAG_INHERIT = 0x00000001;
        private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
        private const int JobObjectBasicAccountingInformation = 1;
        private const int JobObjectExtendedLimitInformation = 9;
        private const uint WAIT_OBJECT_0 = 0x00000000;
        private const uint WAIT_TIMEOUT = 0x00000102;
        private const uint STILL_ACTIVE = 259;
        private const uint GENERIC_READ = 0x80000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint OPEN_EXISTING = 3;
        private static readonly IntPtr InvalidHandleValue = new IntPtr(-1);

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)]
            public bool bInheritHandle;
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
            public uint dwFlags;
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

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
        {
            public long TotalUserTime;
            public long TotalKernelTime;
            public long ThisPeriodTotalUserTime;
            public long ThisPeriodTotalKernelTime;
            public uint TotalPageFaultCount;
            public uint TotalProcesses;
            public uint ActiveProcesses;
            public uint TotalTerminatedProcesses;
        }

        [DllImport(
            "kernel32.dll",
            EntryPoint = "CreateProcessW",
            CharSet = CharSet.Unicode,
            ExactSpelling = true,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateProcess(
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

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreatePipe(
            out IntPtr readPipe,
            out IntPtr writePipe,
            ref SECURITY_ATTRIBUTES attributes,
            uint size);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetHandleInformation(
            IntPtr handle,
            uint mask,
            uint flags);

        [DllImport(
            "kernel32.dll",
            EntryPoint = "CreateFileW",
            CharSet = CharSet.Unicode,
            ExactSpelling = true,
            SetLastError = true)]
        private static extern IntPtr CreateFile(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            ref SECURITY_ATTRIBUTES securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport(
            "kernel32.dll",
            EntryPoint = "CreateJobObjectW",
            CharSet = CharSet.Unicode,
            ExactSpelling = true,
            SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr jobAttributes, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetInformationJobObject(
            IntPtr job,
            int informationClass,
            ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION information,
            uint informationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryInformationJobObject(
            IntPtr job,
            int informationClass,
            out JOBOBJECT_BASIC_ACCOUNTING_INFORMATION information,
            uint informationLength,
            out uint returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateJobObject(IntPtr job, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr thread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateProcess(IntPtr process, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        private IntPtr job;
        private IntPtr process;
        private StreamReader stdoutReader;
        private StreamReader stderrReader;
        private bool disposed;

        private CursorHookProcess(
            IntPtr job,
            IntPtr process,
            StreamReader stdoutReader,
            StreamReader stderrReader)
        {
            this.job = job;
            this.process = process;
            this.stdoutReader = stdoutReader;
            this.stderrReader = stderrReader;
            StandardOutput = stdoutReader.ReadToEndAsync();
            StandardError = stderrReader.ReadToEndAsync();
        }

        public Task<string> StandardOutput { get; private set; }
        public Task<string> StandardError { get; private set; }

        public static CursorHookProcess Start(string applicationPath, string payloadPath)
        {
            IntPtr stdoutRead = IntPtr.Zero;
            IntPtr stdoutWrite = IntPtr.Zero;
            IntPtr stderrRead = IntPtr.Zero;
            IntPtr stderrWrite = IntPtr.Zero;
            IntPtr stdinHandle = IntPtr.Zero;
            IntPtr job = IntPtr.Zero;
            PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();
            StreamReader stdoutReader = null;
            StreamReader stderrReader = null;
            try
            {
                if (String.IsNullOrEmpty(applicationPath) || applicationPath.IndexOf('\"') >= 0 ||
                    String.IsNullOrEmpty(payloadPath) || payloadPath.IndexOf('\"') >= 0)
                {
                    throw new InvalidOperationException();
                }

                SECURITY_ATTRIBUTES attributes = new SECURITY_ATTRIBUTES();
                attributes.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
                attributes.bInheritHandle = true;
                if (!CreatePipe(out stdoutRead, out stdoutWrite, ref attributes, 0) ||
                    !SetHandleInformation(stdoutRead, HANDLE_FLAG_INHERIT, 0) ||
                    !CreatePipe(out stderrRead, out stderrWrite, ref attributes, 0) ||
                    !SetHandleInformation(stderrRead, HANDLE_FLAG_INHERIT, 0))
                {
                    throw new InvalidOperationException();
                }
                stdinHandle = CreateFile(
                    "NUL",
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    ref attributes,
                    OPEN_EXISTING,
                    0,
                    IntPtr.Zero);
                if (stdinHandle == InvalidHandleValue)
                {
                    stdinHandle = IntPtr.Zero;
                    throw new InvalidOperationException();
                }

                job = CreateJobObject(IntPtr.Zero, null);
                if (job == IntPtr.Zero)
                {
                    throw new InvalidOperationException();
                }
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobInformation =
                    new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
                jobInformation.BasicLimitInformation.LimitFlags =
                    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                if (!SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    ref jobInformation,
                    (uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION))))
                {
                    throw new InvalidOperationException();
                }

                STARTUPINFO startupInfo = new STARTUPINFO();
                startupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));
                startupInfo.dwFlags = STARTF_USESTDHANDLES;
                startupInfo.hStdInput = stdinHandle;
                startupInfo.hStdOutput = stdoutWrite;
                startupInfo.hStdError = stderrWrite;
                StringBuilder commandLine = new StringBuilder(
                    "\"" + applicationPath + "\" hook --connector cursor --input-file \"" +
                    payloadPath + "\"");
                if (!CreateProcess(
                    applicationPath,
                    commandLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    true,
                    CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                    IntPtr.Zero,
                    null,
                    ref startupInfo,
                    out processInfo))
                {
                    throw new InvalidOperationException();
                }

                CloseOwnedHandle(ref stdoutWrite);
                CloseOwnedHandle(ref stderrWrite);
                CloseOwnedHandle(ref stdinHandle);
                stdoutReader = CreateReader(stdoutRead);
                stdoutRead = IntPtr.Zero;
                stderrReader = CreateReader(stderrRead);
                stderrRead = IntPtr.Zero;

                if (!AssignProcessToJobObject(job, processInfo.hProcess))
                {
                    throw new InvalidOperationException();
                }
                uint previousSuspendCount = ResumeThread(processInfo.hThread);
                if (previousSuspendCount == UInt32.MaxValue || previousSuspendCount != 1)
                {
                    throw new InvalidOperationException();
                }
                CloseOwnedHandle(ref processInfo.hThread);

                CursorHookProcess result = new CursorHookProcess(
                    job,
                    processInfo.hProcess,
                    stdoutReader,
                    stderrReader);
                job = IntPtr.Zero;
                processInfo.hProcess = IntPtr.Zero;
                stdoutReader = null;
                stderrReader = null;
                return result;
            }
            catch (Exception error)
            {
                if (job != IntPtr.Zero) TerminateJobObject(job, 1);
                if (processInfo.hProcess != IntPtr.Zero)
                {
                    // Assignment can fail while the root is still suspended
                    // and therefore not yet owned by the job.
                    TerminateProcess(processInfo.hProcess, 1);
                    WaitForSingleObject(processInfo.hProcess, 5000);
                }
                throw new InvalidOperationException(
                    "could not start owned Cursor hook launcher process",
                    error);
            }
            finally
            {
                if (stdoutReader != null) stdoutReader.Dispose();
                if (stderrReader != null) stderrReader.Dispose();
                CloseOwnedHandle(ref stdoutRead);
                CloseOwnedHandle(ref stdoutWrite);
                CloseOwnedHandle(ref stderrRead);
                CloseOwnedHandle(ref stderrWrite);
                CloseOwnedHandle(ref stdinHandle);
                CloseOwnedHandle(ref processInfo.hThread);
                CloseOwnedHandle(ref processInfo.hProcess);
                CloseOwnedHandle(ref job);
            }
        }

        public bool WaitForExit(int milliseconds)
        {
            ThrowIfDisposed();
            if (milliseconds < 0) throw new ArgumentOutOfRangeException("milliseconds");
            uint result = WaitForSingleObject(process, (uint)milliseconds);
            if (result == WAIT_OBJECT_0) return true;
            if (result == WAIT_TIMEOUT) return false;
            throw new InvalidOperationException("could not wait for owned Cursor hook launcher process");
        }

        public int ExitCode
        {
            get
            {
                ThrowIfDisposed();
                uint exitCode;
                if (!GetExitCodeProcess(process, out exitCode) || exitCode == STILL_ACTIVE)
                {
                    throw new InvalidOperationException(
                        "could not read owned Cursor hook launcher exit code");
                }
                return unchecked((int)exitCode);
            }
        }

        // Explicit termination plus ActiveProcesses==0 is the primary proof.
        // Closing the kill-on-close handle is also performed on every error,
        // so a failed explicit termination cannot release an owned descendant.
        public void TerminateTreeAndDrain(int milliseconds)
        {
            ThrowIfDisposed();
            if (milliseconds < 1) throw new ArgumentOutOfRangeException("milliseconds");
            Stopwatch timer = Stopwatch.StartNew();
            bool failed = false;
            if (job != IntPtr.Zero)
            {
                if (!TerminateJobObject(job, 1))
                {
                    failed = true;
                }
                else
                {
                    try
                    {
                        while (GetActiveJobProcessCount(job) != 0)
                        {
                            if (timer.ElapsedMilliseconds >= milliseconds)
                            {
                                failed = true;
                                break;
                            }
                            Thread.Sleep(10);
                        }
                    }
                    catch
                    {
                        failed = true;
                    }
                }
                if (CloseHandle(job))
                {
                    job = IntPtr.Zero;
                }
                else
                {
                    // Retain the handle so Dispose can retry kill-on-close.
                    failed = true;
                }
            }

            uint remaining = RemainingMilliseconds(timer, milliseconds);
            uint waitResult = WaitForSingleObject(process, remaining);
            if (waitResult != WAIT_OBJECT_0) failed = true;
            try
            {
                remaining = RemainingMilliseconds(timer, milliseconds);
                if (!Task.WaitAll(
                    new Task[] { StandardOutput, StandardError },
                    checked((int)remaining)))
                {
                    failed = true;
                }
            }
            catch
            {
                failed = true;
            }
            if (failed)
            {
                throw new InvalidOperationException(
                    "could not terminate owned Cursor hook launcher process tree");
            }
        }

        private static StreamReader CreateReader(IntPtr handle)
        {
            SafeFileHandle safeHandle = new SafeFileHandle(handle, true);
            try
            {
                FileStream stream = new FileStream(safeHandle, FileAccess.Read, 4096, false);
                safeHandle = null;
                return new StreamReader(stream, Console.OutputEncoding, true, 4096, false);
            }
            finally
            {
                if (safeHandle != null) safeHandle.Dispose();
            }
        }

        private static uint GetActiveJobProcessCount(IntPtr job)
        {
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION information;
            uint returned;
            if (!QueryInformationJobObject(
                job,
                JobObjectBasicAccountingInformation,
                out information,
                (uint)Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)),
                out returned) ||
                returned < Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)))
            {
                throw new InvalidOperationException();
            }
            return information.ActiveProcesses;
        }

        private static uint RemainingMilliseconds(Stopwatch timer, int milliseconds)
        {
            long remaining = milliseconds - timer.ElapsedMilliseconds;
            return remaining > 0 ? checked((uint)remaining) : 0;
        }

        private static void CloseOwnedHandle(ref IntPtr handle)
        {
            if (handle != IntPtr.Zero && handle != InvalidHandleValue)
            {
                CloseHandle(handle);
            }
            handle = IntPtr.Zero;
        }

        private void ThrowIfDisposed()
        {
            if (disposed) throw new ObjectDisposedException("CursorHookProcess");
        }

        public void Dispose()
        {
            if (disposed) return;
            disposed = true;
            if (job != IntPtr.Zero)
            {
                TerminateJobObject(job, 1);
                CloseHandle(job);
                job = IntPtr.Zero;
            }
            if (stdoutReader != null)
            {
                try { stdoutReader.Dispose(); } catch { }
                stdoutReader = null;
            }
            if (stderrReader != null)
            {
                try { stderrReader.Dispose(); } catch { }
                stderrReader = null;
            }
            CloseOwnedHandle(ref process);
        }
    }
}
'@ -ErrorAction Stop
        }
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        $payloadBytes = $utf8NoBom.GetBytes($payload)
        $stream = [IO.File]::Open(
            $payloadPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        try {
            $stream.Write($payloadBytes, 0, $payloadBytes.Length)
        }
        finally {
            $stream.Dispose()
        }
        # Windows PowerShell does not wait for GUI-subsystem executables when
        # they are invoked with `&`, and it does not reliably connect their
        # standard handles. defenseclaw-hook.exe intentionally uses that
        # subsystem to avoid popup consoles, so launch it explicitly with
        # redirected handles and wait for the verdict before returning.
        $process = $null
        try {
            $process = [DefenseClaw.CursorHookProcess]::Start($hook, $payloadPath)
            $stdoutTask = $process.StandardOutput
            $stderrTask = $process.StandardError
            $timeoutMs = {{.CursorHookTimeoutMS}}
            $waitBudgetMs = $timeoutMs - [int]$adapterTimer.ElapsedMilliseconds
            if ($waitBudgetMs -lt 1) {
                $waitBudgetMs = 1
            }
            if (-not $process.WaitForExit($waitBudgetMs)) {
                try {
                    $cleanupBudgetMs = ($timeoutMs + 5000) - [int]$adapterTimer.ElapsedMilliseconds
                    if ($cleanupBudgetMs -lt 1) {
                        $cleanupBudgetMs = 1
                    }
                    $process.TerminateTreeAndDrain($cleanupBudgetMs)
                }
                catch {
                    [Console]::Error.WriteLine(
                        "defenseclaw: could not stop timed-out Cursor hook launcher process tree"
                    )
                }
                throw "DefenseClaw hook launcher timed out after ${timeoutMs}ms"
            }
            $launcherExitCode = $process.ExitCode
            try {
                # The root can finish while descendants retain redirected
                # handles. Reap the owned remainder before awaiting output.
                $cleanupBudgetMs = ($timeoutMs + 5000) - [int]$adapterTimer.ElapsedMilliseconds
                if ($cleanupBudgetMs -lt 1) {
                    $cleanupBudgetMs = 1
                }
                $process.TerminateTreeAndDrain($cleanupBudgetMs)
            }
            catch {
                throw "DefenseClaw hook launcher process-tree cleanup failed"
            }
            $stdout = $stdoutTask.GetAwaiter().GetResult()
            $stderr = $stderrTask.GetAwaiter().GetResult()
            if ($stdout.Length -eq 0) {
                throw "DefenseClaw hook launcher returned no response"
            }
            [Console]::Out.Write($stdout)
            $responseWritten = $true
            if ($stderr.Length -gt 0) {
                [Console]::Error.Write($stderr)
            }
            $exitCode = $launcherExitCode
        }
        finally {
            if ($null -ne $process) {
                $process.Dispose()
            }
        }
    }
    catch {
        [Console]::Error.WriteLine("defenseclaw: Cursor hook adapter failed: " + $_.Exception.Message)
        if (-not $responseWritten) {
            [Console]::Out.Write((Get-CursorFallbackJson -EventName $eventName -Deny $failClosed))
        }
        $exitCode = if ($failClosed) { 2 } else { 0 }
    }
    finally {
        try {
            if (Test-Path -LiteralPath $payloadPath) {
                Remove-Item -LiteralPath $payloadPath -Force -ErrorAction Stop
            }
        }
        catch {
            [Console]::Error.WriteLine(
                "defenseclaw: could not remove temporary Cursor payload: " + $_.Exception.Message
            )
        }
    }
    # Cursor invokes this adapter from a PowerShell pipeline. `exit N` inside
    # that nested pipeline is normalized by Windows PowerShell to process exit
    # code 1. Set the host exit code explicitly so Cursor receives the
    # documented exit-2 deny signal.
    $host.SetShouldExit($exitCode)
}
