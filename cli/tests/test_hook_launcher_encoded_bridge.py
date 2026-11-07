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

"""Doctor and status name a launcher the Windows hook bridges cannot start.

Per-user Windows Kiro and Antigravity register an encoded PowerShell bridge
that starts defenseclaw-hook.exe, so the launcher path is only inside the
base64 script. Reading the registration without decoding it found no
launcher: a missing launcher, or a folder in its place, showed Kiro as
healthy and running while every hook call was blocked (rel-1-0-6 GAP-0810).
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from defenseclaw import hook_integrity
from defenseclaw.commands.cmd_doctor import _check_hook_health, _DoctorResult
from defenseclaw.hook_integrity import LAUNCHER_REINSTALL_STEP, hook_registration_problems, repair_command

_SYSTEM = "C:\\Windows\\System32"


def _pe_image(*, dll: bool = False, extra: bytes = b"") -> bytes:
    """A minimal PE32+ executable: one section whose bytes lie inside the file."""

    lfanew, optional, raw_at, raw_size = 0x80, 240, 0x200, 0x200
    dos = bytearray(64)
    dos[:2] = b"MZ"
    dos[0x3C:0x40] = lfanew.to_bytes(4, "little")
    characteristics = 0x2022 if dll else 0x0022
    header = (
        b"PE\0\0"
        + (0x8664).to_bytes(2, "little")
        + (1).to_bytes(2, "little")
        + bytes(12)
        + optional.to_bytes(2, "little")
        + characteristics.to_bytes(2, "little")
    )
    optional_header = (0x20B).to_bytes(2, "little") + bytes(optional - 2)
    section = bytearray(40)
    section[:6] = b".text\0"
    section[16:20] = raw_size.to_bytes(4, "little")
    section[20:24] = raw_at.to_bytes(4, "little")
    head = bytes(dos).ljust(lfanew, b"\0") + header + optional_header + bytes(section)
    return head.ljust(raw_at, b"\0") + bytes(raw_size) + extra


def _quote_literal(value: str) -> str:
    """*value* as managed.PowerShellLiteral renders it: every single-quote character doubled."""

    return "'" + "".join(char * 2 if char in "'‘’‚‛" else char for char in value) + "'"


def _bridge(launcher: str, connector: str) -> str:
    """The encoded bridge the per-user Windows renders register, around *launcher*."""

    quoted = _quote_literal(launcher)
    script = "; ".join(
        [
            "$ErrorActionPreference='Stop'",
            "$env:NoDefaultCurrentDirectoryInExePath='1'",
            "$hookStart=[System.Diagnostics.ProcessStartInfo]::new(" + quoted + ",'hook --connector " + connector + "')",
            "$hookStart.UseShellExecute=$false",
            "try { $hookProcess=[System.Diagnostics.Process]::Start($hookStart) } catch { exit 2 }",
            "$hookProcess.WaitForExit()",
            "exit $hookProcess.ExitCode",
        ]
    )
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    powershell = _SYSTEM + "\\WindowsPowerShell\\v1.0\\powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand "
    return powershell + encoded


def _register(tmp_path: Path, connector: str, launcher: str, *, plain: bool = False):
    command = '"' + launcher + '" hook --connector ' + connector if plain else _bridge(launcher, connector)
    if connector == "kiro":
        command = _SYSTEM + "\\cmd.exe /d /c " + command + "\nexit $LASTEXITCODE"
        config = tmp_path / "home" / ".kiro" / "hooks" / "defenseclaw.json"
        entry = {
            "name": "defenseclaw-pre-tool",
            "trigger": "PreToolUse",
            "matcher": ".*",
            "action": {"type": "command", "command": command},
            "timeout": 30,
            "enabled": True,
        }
        document = {"hooks": [entry]}
    else:
        config = tmp_path / "home" / ".gemini" / "config" / "hooks.json"
        document = {
            "defenseclaw-antigravity-pretooluse": {
                "enabled": True,
                "PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": command, "timeout": 30}]}],
            }
        }
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(json.dumps(document), encoding="utf-8")
    data_dir = tmp_path / "data"
    data_dir.mkdir(exist_ok=True)
    lock = {"version": 2, "connectors": {connector: {"locations": {"hook_config_paths": [str(config)]}}}}
    (data_dir / "hook_contract_lock.json").write_text(json.dumps(lock), encoding="utf-8")
    return SimpleNamespace(data_dir=str(data_dir)), config


@pytest.fixture
def make_launcher(tmp_path, monkeypatch):
    """Make a launcher under a user folder, on a drive letter that exists on this host.

    Switches the per-user Windows checks on.
    """

    monkeypatch.setattr(hook_integrity, "_is_windows", lambda: True)
    if sys.platform == "win32":
        base = tmp_path
    else:
        # "C:/..." is a relative folder here, so the drive-letter form the
        # renders carry resolves to a real file.
        monkeypatch.chdir(tmp_path)
        base = tmp_path / "C:"

    def make(user: str = "u"):
        launcher = base / "Users" / user / ".local" / "bin" / "defenseclaw-hook.exe"
        launcher.parent.mkdir(parents=True)
        launcher.write_bytes(_pe_image())
        return launcher, "C:/" + launcher.relative_to(base).as_posix()

    return make


@pytest.fixture
def windows_launcher(make_launcher):
    return make_launcher()


def _damage(launcher: Path, shape: str) -> None:
    if shape == "missing":
        launcher.unlink()
    elif shape == "folder":
        launcher.unlink()
        launcher.mkdir()
    elif shape == "empty":
        launcher.write_bytes(b"")
    elif shape == "not-pe":
        launcher.write_bytes(b"#!/bin/sh\n")


_DAMAGE = {
    "missing": "is missing",
    "folder": "is not a regular file",
    "empty": "is not a Windows executable",
    "not-pe": "is not a Windows executable",
}


@pytest.mark.parametrize("connector", ["kiro", "antigravity"])
@pytest.mark.parametrize("shape", sorted(_DAMAGE))
def test_status_names_a_damaged_launcher_behind_the_encoded_bridge(tmp_path, windows_launcher, connector, shape):
    launcher, text = windows_launcher
    cfg, _config = _register(tmp_path, connector, text)
    assert hook_integrity.hook_launcher_problems(cfg, connector) == []

    _damage(launcher, shape)
    problems = hook_registration_problems(cfg, connector)

    assert problems == [f"the DefenseClaw hook launcher {text} {_DAMAGE[shape]}, so every hook call fails"]
    assert repair_command(connector, problems[0]) == LAUNCHER_REINSTALL_STEP


@pytest.mark.parametrize("connector", ["kiro", "antigravity"])
def test_a_working_launcher_behind_the_encoded_bridge_stays_healthy(tmp_path, windows_launcher, connector):
    _launcher, text = windows_launcher
    cfg, _config = _register(tmp_path, connector, text)

    assert hook_integrity.hook_launcher_problems(cfg, connector) == []


def test_a_launcher_that_cannot_be_read_is_not_called_damaged(tmp_path, windows_launcher, monkeypatch):
    # Defender or a deny ACE holding the file is not proof of damage.
    _launcher, text = windows_launcher
    cfg, _config = _register(tmp_path, "kiro", text)

    def deny(*_args, **_kwargs):
        raise PermissionError("held")

    monkeypatch.setattr("builtins.open", deny)
    assert hook_integrity._launcher_defect(text) == ""


def test_managed_install_keeps_its_own_status(tmp_path, windows_launcher):
    launcher, text = windows_launcher
    cfg, _config = _register(tmp_path, "kiro", text)
    _damage(launcher, "missing")
    cfg.deployment_mode = "managed_enterprise"

    assert hook_integrity.hook_launcher_problems(cfg, "kiro") == []


def test_doctor_fails_the_kiro_row_when_the_launcher_is_missing_or_a_folder(tmp_path, windows_launcher, monkeypatch):
    launcher, text = windows_launcher
    cfg, config = _register(tmp_path, "kiro", text)
    monkeypatch.setattr("defenseclaw.commands.cmd_doctor._edited_hook_problem", lambda *_: "")
    monkeypatch.setattr("defenseclaw.commands.cmd_doctor._unguarded_tool_call_problem", lambda *_: "")

    healthy = _DoctorResult(passive=True, quiet=True)
    _check_hook_health(cfg, "kiro", healthy)
    assert [(row["label"], row["status"]) for row in healthy.checks] == [("Kiro hooks", "pass")]

    for shape in ("missing", "folder"):
        _damage(launcher, shape)
        result = _DoctorResult(passive=True, quiet=True)
        _check_hook_health(cfg, "kiro", result)
        (row,) = result.checks
        assert (row["label"], row["status"]) == ("Kiro hooks", "fail")
        assert text in row["detail"] and _DAMAGE[shape] in row["detail"]
        assert row["remediation"] == LAUNCHER_REINSTALL_STEP
        if shape == "folder":
            launcher.rmdir()
        launcher.write_bytes(_pe_image())


def _record_launcher_digest(cfg, body: bytes) -> None:
    installer = Path(cfg.data_dir, "installer")
    installer.mkdir(exist_ok=True)
    digest = hashlib.sha256(body).hexdigest()
    (installer / "binaries.sha256").write_text(f"{digest}  defenseclaw-hook.exe\n", encoding="utf-8")


@pytest.mark.parametrize("connector", ["kiro", "antigravity"])
@pytest.mark.parametrize("user", ["O'Neil", "A&B", "O’Neil", "Ana‘s ‚B‛"])
def test_a_launcher_path_with_a_quote_or_ampersand_is_read_whole(tmp_path, make_launcher, connector, user):
    # The renderers double every single-quote character inside the literal; the
    # path checked is the one the literal holds, not the escaped spelling.
    launcher, text = make_launcher(user)
    cfg, _config = _register(tmp_path, connector, text)
    assert hook_integrity.hook_launcher_problems(cfg, connector) == []

    launcher.unlink()
    assert hook_integrity.hook_launcher_problems(cfg, connector) == [
        f"the DefenseClaw hook launcher {text} is missing, so every hook call fails"
    ]


@pytest.mark.parametrize("user", ["O'Neil", "A&B"])
def test_a_double_quoted_plain_command_with_a_quote_or_ampersand_is_read_whole(tmp_path, make_launcher, user):
    launcher, text = make_launcher(user)
    cfg, _config = _register(tmp_path, "antigravity", text, plain=True)
    assert hook_integrity.hook_launcher_problems(cfg, "antigravity") == []

    launcher.unlink()
    assert hook_integrity.hook_launcher_problems(cfg, "antigravity") == [
        f"the DefenseClaw hook launcher {text} is missing, so every hook call fails"
    ]


@pytest.mark.parametrize("connector", ["kiro", "antigravity"])
def test_an_image_that_only_starts_with_mz_is_not_a_working_launcher(tmp_path, windows_launcher, connector):
    launcher, text = windows_launcher
    cfg, _config = _register(tmp_path, connector, text)
    whole = _pe_image()
    for body in (b"MZ", b"MZ" + bytes(200), b"MZ\x90\x00" + b"junk" * 100, whole[:0x300], _pe_image(dll=True)):
        launcher.write_bytes(body)
        assert hook_integrity.hook_launcher_problems(cfg, connector) == [
            f"the DefenseClaw hook launcher {text} is not a Windows executable, so every hook call fails"
        ]
    launcher.write_bytes(whole)
    assert hook_integrity.hook_launcher_problems(cfg, connector) == []


@pytest.mark.parametrize("connector", ["kiro", "antigravity"])
def test_another_program_under_the_launcher_name_is_named_when_the_installer_recorded_its_digest(
    tmp_path, windows_launcher, connector
):
    launcher, text = windows_launcher
    cfg, _config = _register(tmp_path, connector, text)
    _record_launcher_digest(cfg, launcher.read_bytes())
    assert hook_integrity.hook_launcher_problems(cfg, connector) == []

    launcher.write_bytes(_pe_image(extra=b"another program"))
    problems = hook_registration_problems(cfg, connector)

    assert problems == [
        f"the DefenseClaw hook launcher {text} does not match the copy the installer recorded, so every hook call fails"
    ]
    assert repair_command(connector, problems[0]) == LAUNCHER_REINSTALL_STEP
