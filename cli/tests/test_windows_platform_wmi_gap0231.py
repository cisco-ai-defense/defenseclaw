# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""rel-1-0-6:GAP-0231: the CLI never starts a CPython WMI query thread.

CPython 3.12/3.13 ``_wmi.exec_query`` returns after a 100 ms connect timeout
while its worker thread still holds a pointer into the returned stack frame;
the thread later closes the handle value it finds there. For a standard
Windows user that closed the CSR port and crashed the next CreateProcess.
"""

from __future__ import annotations

import platform
import subprocess
import sys
import textwrap

import defenseclaw
import pytest


@pytest.mark.skipif(sys.platform == "win32", reason="the guard is a no-op off Windows")
def test_guard_leaves_platform_alone_off_windows() -> None:
    before = getattr(platform, "_wmi_query", None)
    defenseclaw._disable_platform_wmi()
    assert getattr(platform, "_wmi_query", None) is before


@pytest.mark.skipif(sys.platform != "win32", reason="CPython WMI queries exist only on Windows")
def test_package_import_replaces_the_wmi_query_on_windows() -> None:
    with pytest.raises(OSError, match="GAP-0231"):
        platform._wmi_query("OS", "Version")  # type: ignore[attr-defined]


@pytest.mark.skipif(sys.platform != "win32", reason="CPython WMI queries exist only on Windows")
def test_platform_answers_without_any_wmi_query_on_windows() -> None:
    pytest.importorskip("_wmi")
    code = textwrap.dedent(
        """
        import _wmi
        calls = []
        _wmi.exec_query = lambda query: calls.append(query) or ""
        import defenseclaw  # installs the guard before any platform call
        import platform
        system = platform.system()
        machine = platform.machine()
        release, version, _csd, _ptype = platform.win32_ver()
        processor = platform.processor()
        assert calls == [], calls
        assert system == "Windows", system
        assert machine, machine
        assert version.count(".") == 2, version
        assert release, release
        print(system, machine, release, version, bool(processor))
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.startswith("Windows ")
