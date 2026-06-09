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

"""Cross-platform PID liveness checks for the gateway daemon lifecycle.

The gateway is a detached background daemon whose PID is recorded in
``<data_dir>/gateway.pid``. The CLI reads that file to decide whether
``defenseclaw setup --restart`` should ``restart`` the running daemon or
``start`` a fresh one.

POSIX can probe liveness with ``os.kill(pid, 0)``: signal 0 sends nothing,
it only checks that the PID exists and is signalable. On Windows that idiom
is wrong — CPython maps signal 0 to ``CTRL_C_EVENT`` and routes it through
``GenerateConsoleCtrlEvent``, which fails for a daemon in a separate process
group and raises ``OSError``. The naive check therefore reports a live
gateway as dead, so ``setup --restart`` silently downgrades to a no-op
``start`` against the already-bound port. The daemon never reboots into the
guardrail-enabled config, its connector ``Setup`` never runs, the hook
``.token`` is never written, and every native Windows hook then fails open
with "missing gateway token".

On Windows we instead open a real process handle
(``OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)``) and confirm the process
has not already exited, mirroring the Go daemon's ``processExists`` in
``internal/daemon/proc_windows.go`` so both sides agree on what "running"
means.
"""

from __future__ import annotations

import json
import os
import sys

__all__ = ["pid_alive", "read_pid_file", "pid_file_alive"]


def pid_alive(pid: int) -> bool:
    """Return True when a process with ``pid`` is currently running.

    A non-positive PID is never alive (0 and negatives are signal/group
    sentinels on POSIX, never real daemon PIDs here).
    """
    if pid <= 0:
        return False
    if sys.platform == "win32":  # pragma: no cover - exercised on Windows runners
        return _pid_alive_windows(pid)
    return _pid_alive_posix(pid)


def _pid_alive_posix(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # The process exists but is owned by another user — still alive.
        return True
    except OSError:
        return False
    return True


def _pid_alive_windows(pid: int) -> bool:  # pragma: no cover - Windows only
    import ctypes
    from ctypes import wintypes

    process_query_limited_information = 0x1000
    still_active = 259

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    open_process = kernel32.OpenProcess
    open_process.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    open_process.restype = wintypes.HANDLE

    get_exit_code = kernel32.GetExitCodeProcess
    get_exit_code.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
    get_exit_code.restype = wintypes.BOOL

    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL

    handle = open_process(process_query_limited_information, False, pid)
    if not handle:
        return False
    try:
        code = wintypes.DWORD()
        if not get_exit_code(handle, ctypes.byref(code)):
            # Handle opened but exit code unavailable: treat as alive, matching
            # the Go daemon which considers a successful OpenProcess "running".
            return True
        return code.value == still_active
    finally:
        close_handle(handle)


def read_pid_file(pid_file: str) -> int | None:
    """Parse a daemon PID file.

    The file is either a bare integer or a JSON object with a ``pid`` key
    (the richer form the gateway writes). Returns None for a missing,
    unreadable, or malformed file.
    """
    try:
        with open(pid_file, encoding="utf-8") as fh:
            raw = fh.read().strip()
    except OSError:
        return None
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return int(json.loads(raw)["pid"])
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


def pid_file_alive(pid_file: str) -> bool:
    """Return True when the PID recorded in ``pid_file`` is alive."""
    pid = read_pid_file(pid_file)
    if pid is None:
        return False
    return pid_alive(pid)
