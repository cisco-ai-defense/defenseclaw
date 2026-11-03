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

"""DefenseClaw — Enterprise governance layer for OpenClaw."""

__version__ = "1.0.0"


def _disable_platform_wmi() -> None:
    """Keep the CPython ``platform`` module from running WMI queries on Windows.

    On CPython 3.12 and 3.13 the first ``platform.system()``, ``uname()``,
    ``machine()`` or ``win32_ver()`` call runs ``_wmi.exec_query``. Its C code
    gives a worker thread a pointer to a struct on the calling stack frame,
    waits 100 ms for the WMI connection, then returns. For a standard Windows
    user the connection takes longer (dc-win2: 30 of 30 queries timed out).
    The worker thread keeps running and later calls ``CloseHandle`` on the
    pipe-handle value it reads from that dead stack slot, which later calls
    have overwritten (PC/_wmimodule.cpp, ``_query_thread``). So it closes
    whatever handle the stale value names. When that is the CSR port, Windows
    unmaps the CSR heap of the process and the next ``CreateProcess`` crashes
    python.exe in ntdll (0xC0000005 in RtlAllocateHeap, or 0xC0000017)
    (rel-1-0-6:GAP-0231).

    ``platform`` catches ``OSError`` from every WMI query and falls back to
    ``sys.getwindowsversion()``, ``ver``, the registry and ``PROCESSOR_*``.
    That is what it already does after the timeout, so a query that fails at
    once gives the same answers, without the stray thread.
    This runs on package import, before any ``platform`` call in the process.
    """

    import sys

    if sys.platform != "win32":
        return
    import platform

    if not callable(getattr(platform, "_wmi_query", None)):
        return

    def _wmi_query(*_args: object, **_kwargs: object) -> tuple[str, ...]:
        raise OSError("WMI queries are disabled in DefenseClaw (rel-1-0-6:GAP-0231)")

    platform._wmi_query = _wmi_query  # type: ignore[attr-defined]


_disable_platform_wmi()
