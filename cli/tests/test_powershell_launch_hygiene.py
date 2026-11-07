# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Tests start PowerShell through tests.helpers.run_powershell, which skips a host without it.

A test that handed the discovered interpreter (None where PowerShell is not
installed) straight to subprocess failed with a TypeError instead of skipping.
Rather than prove every path to a launch, the launch has one door: the helper
skips when the interpreter is missing, and this check keeps every other launch
out of the test files. Tests that only read POWERSHELL (skip markers, discovery
checks, text in a script) are not touched.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

from tests import helpers

TESTS = Path(__file__).resolve().parent
# Native-Windows only: it asserts PowerShell is present (a Windows runner without
# it must fail, not skip) and finds its own interpreter, pwsh first.
OWN_INTERPRETER = {"test_windows_enterprise_service_contract.py"}
# An argv list that starts with the interpreter, or a subprocess call that takes it first.
DIRECT_LAUNCH = re.compile(r"(?:\[|subprocess\.\w+\()\s*(?:str\(\s*)?POWERSHELL\b")


def direct_launches(source: str) -> list[int]:
    return [source.count("\n", 0, match.start()) + 1 for match in DIRECT_LAUNCH.finditer(source)]


def test_no_test_file_starts_the_discovered_powershell_itself() -> None:
    offenders = {}
    for path in sorted(TESTS.rglob("*.py")):
        if path.name in {"helpers.py", Path(__file__).name} | OWN_INTERPRETER:
            continue
        lines = direct_launches(path.read_text(encoding="utf-8"))
        if lines:
            offenders[str(path.relative_to(TESTS))] = lines
    assert not offenders, offenders


@pytest.mark.parametrize(
    "source",
    [
        "subprocess.run([POWERSHELL, \x22-NoProfile\x22])",
        "subprocess.run(\n    [str(POWERSHELL), \x22-NoProfile\x22],\n)",
        "subprocess.Popen([POWERSHELL, \x22-File\x22, \x22x.ps1\x22])",
        "subprocess.check_output(POWERSHELL)",
        "argv = [POWERSHELL, \x22-Command\x22, script]",
        "@pytest.mark.parametrize(\x22shell\x22, [POWERSHELL])",
    ],
)
def test_a_direct_launch_of_the_discovered_powershell_is_reported(source: str) -> None:
    assert len(direct_launches(source)) == 1


@pytest.mark.parametrize(
    "source",
    [
        "assert POWERSHELL is None or isinstance(POWERSHELL, str)",
        "@pytest.mark.skipif(POWERSHELL is None, reason=\x22x\x22)",
        "script = f\x22& {POWERSHELL} -NoProfile -Help\x22",
        "run_powershell([\x22-NoProfile\x22, \x22-Command\x22, script])",
        "subprocess.run([\x22true\x22])",
    ],
)
def test_reading_the_discovered_powershell_is_not_a_launch(source: str) -> None:
    assert direct_launches(source) == []


def test_the_launcher_skips_where_powershell_is_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(helpers, "POWERSHELL", None)
    with pytest.raises(pytest.skip.Exception):
        helpers.run_powershell(["-NoProfile", "-Command", "exit 0"])


def test_the_launcher_runs_the_interpreter_where_it_is_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(helpers, "POWERSHELL", sys.executable)
    completed = helpers.run_powershell(["-c", "print(\x22ran\x22)"], capture_output=True, text=True, check=False)
    assert completed.returncode == 0 and completed.stdout.strip() == "ran"
