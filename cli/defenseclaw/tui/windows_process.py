"""Windows process-tree ownership for TUI commands.

Each command is attached to its own Job Object.  The retained process and job
handles identify the process instances themselves, so cancellation never
targets a PID that may have been reused.
"""

from __future__ import annotations

import asyncio
import ctypes
from ctypes import wintypes

_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION = 1
_PROCESS_TERMINATE = 0x0001
_PROCESS_SET_QUOTA = 0x0100
_PROCESS_SUSPEND_RESUME = 0x0800
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_SYNCHRONIZE = 0x00100000


class _JobObjectBasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class _JobObjectExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JobObjectBasicLimitInformation),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _JobObjectBasicAccountingInformation(ctypes.Structure):
    _fields_ = [
        ("TotalUserTime", ctypes.c_longlong),
        ("TotalKernelTime", ctypes.c_longlong),
        ("ThisPeriodTotalUserTime", ctypes.c_longlong),
        ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
        ("TotalPageFaultCount", wintypes.DWORD),
        ("TotalProcesses", wintypes.DWORD),
        ("ActiveProcesses", wintypes.DWORD),
        ("TotalTerminatedProcesses", wintypes.DWORD),
    ]


class WindowsJob:
    """Own one Windows subprocess tree until it has been fully reaped."""

    def __init__(self, pid: int) -> None:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel32.TerminateJobObject.restype = wintypes.BOOL
        kernel32.QueryInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        kernel32.QueryInformationJobObject.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
        ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
        ntdll.NtResumeProcess.restype = wintypes.LONG
        self._kernel32 = kernel32
        self._ntdll = ntdll
        self._job = kernel32.CreateJobObjectW(None, None)
        self._process = None
        self._closed = False
        if not self._job:
            self._raise_last_error("CreateJobObjectW")
        try:
            limits = _JobObjectExtendedLimitInformation()
            limits.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not kernel32.SetInformationJobObject(
                self._job,
                _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(limits),
                ctypes.sizeof(limits),
            ):
                self._raise_last_error("SetInformationJobObject")
            access = (
                _PROCESS_TERMINATE
                | _PROCESS_SET_QUOTA
                | _PROCESS_SUSPEND_RESUME
                | _PROCESS_QUERY_LIMITED_INFORMATION
                | _SYNCHRONIZE
            )
            self._process = kernel32.OpenProcess(access, False, pid)
            if not self._process:
                self._raise_last_error("OpenProcess")
            if not kernel32.AssignProcessToJobObject(self._job, self._process):
                self._raise_last_error("AssignProcessToJobObject")
            status = ntdll.NtResumeProcess(self._process)
            if status != 0:
                raise OSError(f"NtResumeProcess failed with NTSTATUS 0x{status & 0xFFFFFFFF:08x}")
        except BaseException:
            self.close()
            raise

    async def cancel(self, process: asyncio.subprocess.Process, grace: float, force: float) -> None:
        """Wait briefly for EOF shutdown, then terminate and reap the job."""

        try:
            await asyncio.wait_for(asyncio.shield(process.wait()), timeout=grace)
        except TimeoutError:
            pass

        try:
            if await self._wait_empty(0.0):
                return
        except OSError:
            await self._close_and_wait(process, force)
            return
        if not self._kernel32.TerminateJobObject(self._job, 130):
            await self._close_and_wait(process, force)
            return
        try:
            await asyncio.wait_for(asyncio.shield(process.wait()), timeout=force)
        except TimeoutError:
            # Closing a kill-on-close job is the final bounded fallback.
            self.close()
            await self._kill_and_wait(process, force)
            return
        try:
            empty = await self._wait_empty(force)
        except OSError:
            empty = False
        if not empty:
            self.close()

    async def _close_and_wait(self, process: asyncio.subprocess.Process, timeout: float) -> None:
        """Apply the kill-on-close fallback and bound the root-process wait."""

        self.close()
        try:
            await asyncio.wait_for(asyncio.shield(process.wait()), timeout=timeout)
        except TimeoutError:
            await self._kill_and_wait(process, timeout)

    @staticmethod
    async def _kill_and_wait(process: asyncio.subprocess.Process, timeout: float) -> None:
        """Best-effort kill and bounded reap after the Job Object is closed."""

        try:
            process.kill()
        except ProcessLookupError:
            return
        try:
            await asyncio.wait_for(asyncio.shield(process.wait()), timeout=timeout)
        except TimeoutError:
            return

    async def _wait_empty(self, timeout: float) -> bool:
        deadline = asyncio.get_running_loop().time() + timeout
        while self.active_processes:
            if asyncio.get_running_loop().time() >= deadline:
                return False
            await asyncio.sleep(0.01)
        return True

    @property
    def active_processes(self) -> int:
        accounting = _JobObjectBasicAccountingInformation()
        if not self._kernel32.QueryInformationJobObject(
            self._job,
            _JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
            ctypes.byref(accounting),
            ctypes.sizeof(accounting),
            None,
        ):
            self._raise_last_error("QueryInformationJobObject")
        return int(accounting.ActiveProcesses)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._process:
            self._kernel32.CloseHandle(self._process)
            self._process = None
        if self._job:
            self._kernel32.CloseHandle(self._job)
            self._job = None

    @staticmethod
    def _raise_last_error(operation: str) -> None:
        error = ctypes.get_last_error()
        raise OSError(error, f"{operation} failed", None, error)
