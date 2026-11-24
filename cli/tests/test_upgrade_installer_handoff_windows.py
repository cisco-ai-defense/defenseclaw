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

"""`defenseclaw upgrade` on Windows hands over to the installer it starts (GAP-2117).

On per-user Windows, `defenseclaw upgrade --version 1.0.9` opened the
installer window, and after 60 seconds the installer refused: "DefenseClaw is
in use by defenseclaw.exe, defenseclaw.exe, python.exe". Those were the
upgrade command's own processes: the shim waited for the install log, and a
downgrade's controller checks the venv before it opens one. These tests run
the real shim from a real venv and the installer's real venv check, with real
processes, so they need native Windows.
"""

from __future__ import annotations

import os
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path

import pytest

from tests.helpers import run_powershell

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "cli"
INSTALL_PS1 = ROOT / "scripts" / "install.ps1"
WAITING = "INFO Waiting for the DefenseClaw command that started this installer to exit"

pytestmark = [
    pytest.mark.skipif(os.name != "nt", reason="native Windows processes required"),
    pytest.mark.allow_subprocess,
]

# Runs from the test venv: the real shim starts the installer as
# `defenseclaw upgrade` does (its own console, a hidden recovery watcher).
DRIVER = """
import sys
from defenseclaw import upgrade_shim
try:
    rc = upgrade_shim._run_installer(sys.argv[1], [], sys.argv[2], rerun="defenseclaw upgrade --version 1.0.9")
except upgrade_shim.ShimError as exc:
    print(f"SHIM-ERROR {exc}", flush=True)
    rc = 1
print(f"RC {rc}", flush=True)
sys.exit(rc)
"""


def _ps1_function(name: str, *, required: bool = True) -> str:
    text = INSTALL_PS1.read_text(encoding="utf-8")
    match = re.search(rf"^function {re.escape(name)}[ (]", text, re.M)
    if match is None:
        assert not required, name
        return ""
    start = match.start()
    return text[start : text.index("\n}\n", start) + 3]


def _kernel32():
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetProcessTimes.argtypes = (wintypes.HANDLE,) + (ctypes.POINTER(wintypes.FILETIME),) * 4
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    kernel32.CreateEventW.argtypes = (ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR)
    kernel32.CreateEventW.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    return kernel32


def _created(kernel32, pid: int) -> int:
    """The creation FILETIME of process *pid*."""
    import ctypes
    from ctypes import wintypes

    handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    assert handle, ctypes.get_last_error()
    try:
        times = [wintypes.FILETIME() for _ in range(4)]
        assert kernel32.GetProcessTimes(handle, *(ctypes.byref(item) for item in times))
        return (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
    finally:
        kernel32.CloseHandle(handle)


def _clean_env(home: Path) -> dict[str, str]:
    # An SSH session has no desktop, and the shim refuses there (GAP-1993):
    # the test runs the desktop path, which is the one that self-blocked.
    env = {
        key: value
        for key, value in os.environ.items()
        if key.upper() not in {"SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY", "DC_INSTALLER_HANDOFF", "DEFENSECLAW_CONFIG"}
    }
    env["DEFENSECLAW_HOME"] = str(home)
    env["PYTHONPATH"] = str(CLI)
    # The shim prints arrows; a captured pipe is not the console it writes in a terminal.
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def _installer(path: Path, venv: Path, bin_dir: Path, result: Path) -> None:
    """An installer that runs the real venv check (Wait-VenvFree) and records its outcome."""
    functions = "\n".join(
        [
            _ps1_function("Move-Path"),
            _ps1_function("Get-ProcessesUnder"),
            _ps1_function("Get-GatewayDescendants"),
            # Absent before the GAP-2117 fix, whose red run shows the self-block.
            _ps1_function("Wait-UpgradeCaller", required=False),
            _ps1_function("Wait-VenvFree"),
        ]
    )
    path.write_text(
        f"""$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$BinDir = '{bin_dir}'
$Venv = '{venv}'
$Result = '{result}'
function Write-Info([string]$Message) {{ Add-Content -LiteralPath $Result -Value "INFO $Message" }}
function Die([string]$Message) {{ throw $Message }}
# The check polls 60 times a second apart; a fifth of a second keeps the test short.
function Start-Sleep {{ param([int]$Seconds, [int]$Milliseconds) [Threading.Thread]::Sleep(200) }}
{functions}
try {{ Wait-VenvFree; Add-Content -LiteralPath $Result -Value 'FREE'; exit 0 }}
catch {{ Add-Content -LiteralPath $Result -Value "REFUSED $($_.Exception.Message)"; exit 1 }}
""",
        encoding="utf-8-sig",
    )


def _outcome(result: Path, timeout: float) -> list[str]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if result.is_file():
            lines = result.read_text(encoding="utf-8-sig", errors="replace").splitlines()
            if any(line == "FREE" or line.startswith("REFUSED ") for line in lines):
                return lines
        time.sleep(0.5)
    found = result.read_text(encoding="utf-8-sig", errors="replace") if result.is_file() else ""
    raise AssertionError(f"the installer recorded no outcome in {timeout} s: {found}")


@pytest.mark.parametrize("other_holder", [False, True], ids=["cli-only", "another-program-holds-the-venv"])
def test_upgrade_cli_hands_off_so_the_installer_does_not_wait_on_it(tmp_path: Path, other_holder: bool) -> None:
    venv = tmp_path / "data" / ".venv"
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(venv)], check=True, timeout=300)
    python = venv / "Scripts" / "python.exe"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    home = tmp_path / "home"
    (home / "logs").mkdir(parents=True)
    workdir = tmp_path / "defenseclaw-upgrade-test"
    workdir.mkdir()
    result = tmp_path / "result.txt"
    installer = workdir / "install.ps1"
    _installer(installer, venv, bin_dir, result)
    env = _clean_env(home)
    holder: subprocess.Popen[bytes] | None = None
    holder_pids: list[int] = []
    try:
        if other_holder:
            # A program the user runs from the venv (the TUI): not the CLI
            # that started the installer, so it still holds the install.
            pidfile = tmp_path / "holder.pid"
            hold = "import os, sys, time; open(sys.argv[1], 'w').write(str(os.getpid())); time.sleep(300)"
            holder = subprocess.Popen(
                [str(python), "-c", hold, str(pidfile)],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            holder_pids.append(holder.pid)
            deadline = time.monotonic() + 60
            while not (pidfile.is_file() and pidfile.read_text()) and time.monotonic() < deadline:
                time.sleep(0.2)
            holder_pids.append(int(pidfile.read_text()))
        started = time.monotonic()
        driver = subprocess.run(
            [str(python), "-c", DRIVER, str(installer), str(workdir)],
            env=env,
            capture_output=True,
            text=True,
            timeout=600,
        )
        elapsed = time.monotonic() - started
        output = driver.stdout + driver.stderr
        lines = _outcome(result, 240)
    finally:
        for pid in reversed(holder_pids):
            # Exact pids: the venv's python.exe and the interpreter it started.
            subprocess.run(["taskkill.exe", "/PID", str(pid), "/F"], capture_output=True, check=False)
        if holder is not None:
            holder.wait(timeout=60)
    outcome = lines[-1]
    # The CLI exits once the installer took the handoff, which then waited for it.
    assert driver.returncode == 0, (output, lines)
    assert "RC 0" in output and "continues in a new window" in output, output
    assert elapsed < 120, (elapsed, output)
    assert WAITING in lines, lines
    if other_holder:
        assert holder is not None
        assert outcome.startswith("REFUSED DefenseClaw is in use by "), lines
        assert f"(pid {holder.pid})" in outcome, (holder.pid, lines)
        # The CLI's own processes had exited: only the other program is named.
        assert outcome.count("(pid ") == 1, lines
    else:
        assert outcome == "FREE", lines


@pytest.mark.parametrize("creation_matches", [True, False], ids=["the-caller", "pid-with-another-creation-time"])
def test_installer_waits_only_for_the_caller_it_was_handed(tmp_path: Path, creation_matches: bool) -> None:
    kernel32 = _kernel32()
    # The caller ends by itself 14 s after it started: long enough for
    # PowerShell to start, short enough to wait for.
    caller = subprocess.Popen(
        ["ping.exe", "-n", "15" if creation_matches else "60", "127.0.0.1"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    event = None
    try:
        created = _created(kernel32, caller.pid)
        name = "Local\\DefenseClaw-installer-handoff-" + secrets.token_hex(16)
        event = kernel32.CreateEventW(None, True, False, name)
        assert event
        script = tmp_path / "caller.ps1"
        script.write_text(
            "$ErrorActionPreference = 'Stop'\nSet-StrictMode -Version Latest\n"
            'function Write-Info([string]$Message) { "INFO $Message" }\n'
            + _ps1_function("Wait-UpgradeCaller")
            + '\nWait-UpgradeCaller\n"RETURNED left=[$env:DC_INSTALLER_HANDOFF]"\n',
            encoding="utf-8-sig",
        )
        env = dict(os.environ)
        env["DC_INSTALLER_HANDOFF"] = f"{caller.pid}:{created if creation_matches else created + 1}:{name}"
        run = run_powershell(
            ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script)],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        output = run.stdout + run.stderr
        assert run.returncode == 0, output
        # The value is used once: a child installer does not see it.
        assert "RETURNED left=[]" in output, output
        signalled = kernel32.WaitForSingleObject(event, 0) == 0
        if creation_matches:
            assert signalled, output
            assert WAITING in output, output
            # It returned when the caller exited, not before.
            assert caller.poll() is not None, output
        else:
            # Another process now has that pid: no handoff, no wait.
            assert not signalled, output
            assert "INFO" not in output, output
            assert caller.poll() is None, output
    finally:
        if caller.poll() is None:
            caller.kill()
        caller.wait(timeout=60)
        if event:
            kernel32.CloseHandle(event)
