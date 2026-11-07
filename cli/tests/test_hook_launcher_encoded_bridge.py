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


_COFF, _OPTIONAL, _SECTION = 0x84, 0x98, 0x98 + 240


def _pe_image(*, dll: bool = False, extra: bytes = b"", patches: tuple = ()) -> bytes:
    """A small PE32+ executable laid out the way the Windows loader reads one.

    Console subsystem, one executable .text section whose first bytes are
    ``xor eax,eax; ret``, an entry point on them, and the alignments,
    SizeOfImage and SizeOfHeaders a linker writes. *patches* are
    (offset, value, width) writes that break one field.
    """

    lfanew, raw_at = 0x80, 0x200
    image = bytearray(raw_at + 0x200)

    def put(at: int, value: int, width: int) -> None:
        image[at : at + width] = value.to_bytes(width, "little")

    image[:2] = b"MZ"
    put(0x3C, lfanew, 4)
    image[lfanew : lfanew + 4] = b"PE\0\0"
    put(_COFF, 0x8664, 2)  # machine: x64
    put(_COFF + 2, 1, 2)  # one section
    put(_COFF + 16, 240, 2)  # SizeOfOptionalHeader
    put(_COFF + 18, 0x2023 if dll else 0x0023, 2)  # executable, large address aware, relocations stripped
    put(_OPTIONAL, 0x20B, 2)
    put(_OPTIONAL + 4, 0x200, 4)  # SizeOfCode
    put(_OPTIONAL + 16, 0x1000, 4)  # AddressOfEntryPoint
    put(_OPTIONAL + 20, 0x1000, 4)  # BaseOfCode
    put(_OPTIONAL + 24, 0x140000000, 8)  # ImageBase
    put(_OPTIONAL + 32, 0x1000, 4)  # SectionAlignment
    put(_OPTIONAL + 36, 0x200, 4)  # FileAlignment
    put(_OPTIONAL + 40, 6, 2)  # MajorOperatingSystemVersion
    put(_OPTIONAL + 48, 6, 2)  # MajorSubsystemVersion
    put(_OPTIONAL + 56, 0x2000, 4)  # SizeOfImage
    put(_OPTIONAL + 60, 0x200, 4)  # SizeOfHeaders
    put(_OPTIONAL + 68, 3, 2)  # Subsystem: console
    put(_OPTIONAL + 70, 0x100, 2)  # NX compatible
    put(_OPTIONAL + 72, 0x100000, 8)
    put(_OPTIONAL + 80, 0x1000, 8)
    put(_OPTIONAL + 88, 0x100000, 8)
    put(_OPTIONAL + 96, 0x1000, 8)
    put(_OPTIONAL + 108, 16, 4)  # NumberOfRvaAndSizes
    image[_SECTION : _SECTION + 6] = b".text\0"
    put(_SECTION + 8, 0x10, 4)  # VirtualSize
    put(_SECTION + 12, 0x1000, 4)  # VirtualAddress
    put(_SECTION + 16, 0x200, 4)  # SizeOfRawData
    put(_SECTION + 20, raw_at, 4)  # PointerToRawData
    put(_SECTION + 36, 0x60000020, 4)  # code, executable, readable
    image[raw_at : raw_at + 3] = b"\x31\xc0\xc3"
    for at, value, width in patches:
        put(at, value, width)
    return bytes(image) + extra


def _hand_made_stub() -> bytes:
    """A 160-byte file with PE signatures but no optional header the loader could use."""

    stub = bytearray(160)
    stub[:2] = b"MZ"
    stub[0x3C:0x40] = (0x40).to_bytes(4, "little")
    stub[0x40:0x44] = b"PE\0\0"
    stub[0x46:0x48] = (1).to_bytes(2, "little")  # one section
    stub[0x54:0x56] = (2).to_bytes(2, "little")  # SizeOfOptionalHeader
    stub[0x56:0x58] = (0x22).to_bytes(2, "little")
    stub[0x58:0x5A] = (0x20B).to_bytes(2, "little")
    return bytes(stub)


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
    for body in (
        b"MZ",
        b"MZ" + bytes(200),
        b"MZ\x90\x00" + b"junk" * 100,
        whole[:0x300],
        _pe_image(dll=True),
    ):
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


_BREAKS = {
    "machine-unknown": [(_COFF, 0, 2)],
    "machine-not-a-windows-machine": [(_COFF, 0x1234, 2)],
    "machine-32-bit-with-a-pe32-plus-header": [(_COFF, 0x14C, 2)],
    "optional-magic-pe32-on-x64": [(_OPTIONAL, 0x10B, 2)],
    "optional-magic-unknown": [(_OPTIONAL, 0x107, 2)],
    "too-many-data-directories": [(_OPTIONAL + 108, 17, 4)],
    "data-directories-past-the-optional-header": [(_OPTIONAL + 108, 0xFFFFFFFF, 4)],
    "section-alignment-zero": [(_OPTIONAL + 32, 0, 4)],
    "section-alignment-not-a-power-of-two": [(_OPTIONAL + 32, 0x1800, 4)],
    "section-alignment-below-file-alignment": [(_OPTIONAL + 32, 0x100, 4)],
    "file-alignment-zero": [(_OPTIONAL + 36, 0, 4)],
    "file-alignment-too-small": [(_OPTIONAL + 36, 4, 4)],
    "image-size-zero": [(_OPTIONAL + 56, 0, 4)],
    "image-size-unaligned": [(_OPTIONAL + 56, 0x1800, 4)],
    "image-size-too-small-for-the-section": [(_OPTIONAL + 56, 0x1000, 4)],
    "headers-size-zero": [(_OPTIONAL + 60, 0, 4)],
    "headers-size-inside-the-section-table": [(_OPTIONAL + 60, 0x100, 4)],
    "headers-size-past-the-file": [(_OPTIONAL + 60, 0x1000, 4)],
    "subsystem-unknown": [(_OPTIONAL + 68, 0, 2)],
    "subsystem-native": [(_OPTIONAL + 68, 1, 2)],
    "entry-point-zero": [(_OPTIONAL + 16, 0, 4)],
    "entry-point-outside-the-sections": [(_OPTIONAL + 16, 0x5000, 4)],
    "entry-point-past-the-bytes-the-file-holds": [(_SECTION + 8, 0x1000, 4), (_OPTIONAL + 16, 0x1800, 4)],
    "entry-section-not-executable": [(_SECTION + 36, 0x40000040, 4)],
    "section-empty": [(_SECTION + 8, 0, 4), (_SECTION + 16, 0, 4)],
    "section-address-unaligned": [(_SECTION + 12, 0x1234, 4)],
    "section-address-inside-the-headers": [(_SECTION + 12, 0, 4)],
    "section-past-the-image": [(_SECTION + 12, 0x2000, 4)],
    "section-data-inside-the-headers": [(_SECTION + 20, 0x100, 4)],
    "section-data-past-the-file": [(_SECTION + 16, 0x400, 4)],
    "no-sections": [(_COFF + 2, 0, 2)],
    "too-many-sections": [(_COFF + 2, 97, 2)],
    "not-an-executable-image": [(_COFF + 18, 0x0020, 2)],
    "pe-header-past-the-file": [(0x3C, 0x10000, 4)],
    "pe-signature-wrong": [(0x80, ord("X"), 1)],
}


def test_the_fixture_is_a_working_executable_image(tmp_path):
    image = tmp_path / "defenseclaw-hook.exe"
    image.write_bytes(_pe_image())
    assert hook_integrity._launcher_defect(str(image)) == ""


@pytest.mark.parametrize("name", sorted(_BREAKS))
def test_one_broken_loader_field_makes_the_launcher_not_a_windows_executable(tmp_path, name):
    image = tmp_path / "defenseclaw-hook.exe"
    image.write_bytes(_pe_image(patches=tuple(_BREAKS[name])))
    assert hook_integrity._launcher_defect(str(image)) == "is not a Windows executable"


def test_a_hand_made_stub_with_pe_signatures_is_not_a_working_launcher(tmp_path, windows_launcher):
    launcher, text = windows_launcher
    cfg, _config = _register(tmp_path, "kiro", text)
    launcher.write_bytes(_hand_made_stub())

    assert hook_registration_problems(cfg, "kiro") == [
        f"the DefenseClaw hook launcher {text} is not a Windows executable, so every hook call fails"
    ]


def _distlib_launchers() -> list[Path]:
    try:
        from pip._vendor import distlib
    except ImportError:
        return []
    return sorted(Path(distlib.__file__).parent.glob("[tw]*.exe"))


def test_real_windows_launchers_are_accepted(tmp_path):
    # pip ships real console and GUI launchers for x86, x64 and ARM64.
    launchers = _distlib_launchers()
    if not launchers:
        pytest.skip("pip's vendored launcher executables are not installed")
    for source in launchers:
        image = tmp_path / source.name
        image.write_bytes(source.read_bytes())
        assert hook_integrity._launcher_defect(str(image)) == "", source.name


@pytest.mark.parametrize("connector", ["kiro", "antigravity"])
def test_a_replacement_too_large_to_hash_is_not_the_recorded_copy(tmp_path, windows_launcher, connector, monkeypatch):
    launcher, text = windows_launcher
    cfg, _config = _register(tmp_path, connector, text)
    _record_launcher_digest(cfg, launcher.read_bytes())
    monkeypatch.setattr(hook_integrity, "_RECORDED_BINARY_SIZE_LIMIT", 4096)
    assert hook_integrity.hook_launcher_problems(cfg, connector) == []

    launcher.write_bytes(_pe_image(extra=bytes(8192)))
    problems = hook_registration_problems(cfg, connector)

    assert problems == [
        f"the DefenseClaw hook launcher {text} does not match the copy the installer recorded, so every hook call fails"
    ]
    assert repair_command(connector, problems[0]) == LAUNCHER_REINSTALL_STEP


def test_a_large_launcher_with_no_recorded_digest_is_judged_by_its_image(tmp_path, windows_launcher, monkeypatch):
    launcher, text = windows_launcher
    cfg, _config = _register(tmp_path, "kiro", text)
    monkeypatch.setattr(hook_integrity, "_RECORDED_BINARY_SIZE_LIMIT", 4096)
    launcher.write_bytes(_pe_image(extra=bytes(8192)))

    assert hook_integrity.hook_launcher_problems(cfg, "kiro") == []


def test_a_hook_guard_too_large_to_hash_is_not_the_recorded_copy(tmp_path, monkeypatch):
    guard = tmp_path / "defenseclaw-hook-guard.exe"
    guard.write_bytes(b"guard")
    installer = tmp_path / "data" / "installer"
    installer.mkdir(parents=True)
    digest = hashlib.sha256(b"guard").hexdigest()
    (installer / "binaries.sha256").write_text(f"{digest}  {hook_integrity.HOOK_GUARD_NAME}\n", encoding="utf-8")
    data_dir = str(installer.parent)
    assert hook_integrity.hook_guard_problem(data_dir, "codex", str(guard)) is None

    monkeypatch.setattr(hook_integrity, "_RECORDED_BINARY_SIZE_LIMIT", 4)
    problem = hook_integrity.hook_guard_problem(data_dir, "codex", str(guard))
    assert problem is not None and "does not match the copy the installer recorded" in problem
