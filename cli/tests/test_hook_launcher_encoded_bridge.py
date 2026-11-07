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

One rule decides the launcher: a regular file (not a folder, not a link)
whose sha256 is the one the installer recorded. With no record, doctor warns
that the launcher is not verified; it never passes.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from defenseclaw import hook_integrity
from defenseclaw.commands.cmd_doctor import _check_hook_health, _DoctorResult
from defenseclaw.hook_integrity import LAUNCHER_REINSTALL_STEP, hook_registration_problems, repair_command

_SYSTEM = "C:\\Windows\\System32"
_BODY = b"MZ the installed launcher"


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
        launcher.write_bytes(_BODY)
        return launcher, "C:/" + launcher.relative_to(base).as_posix()

    return make


@pytest.fixture
def windows_launcher(make_launcher):
    return make_launcher()


def _record_launcher_digest(cfg, body: bytes = _BODY) -> None:
    installer = Path(cfg.data_dir, "installer")
    installer.mkdir(exist_ok=True)
    digest = hashlib.sha256(body).hexdigest()
    (installer / "binaries.sha256").write_text(f"{digest}  defenseclaw-hook.exe\n", encoding="utf-8")


def _damage(launcher: Path, shape: str) -> None:
    launcher.unlink()
    if shape == "folder":
        launcher.mkdir()
    elif shape == "link":
        target = launcher.parent / "elsewhere.exe"
        target.write_bytes(_BODY)
        try:
            launcher.symlink_to(target)
        except OSError:
            pytest.skip("this host cannot create symbolic links")
    elif shape == "other-program":
        launcher.write_bytes(b"another program")
    elif shape == "truncated":
        launcher.write_bytes(_BODY[:4])


def _restore(launcher: Path) -> None:
    if launcher.is_symlink() or launcher.is_file():
        launcher.unlink()
    elif launcher.is_dir():
        launcher.rmdir()
    launcher.write_bytes(_BODY)


_MISSING = "is missing"
_FOLDER = "is not a regular file"
_LINK = "is a link, not the installed file"
_MISMATCH = "does not match the copy the installer recorded"
_DAMAGE = {
    "missing": _MISSING,
    "folder": _FOLDER,
    "link": _LINK,
    "other-program": _MISMATCH,
    "truncated": _MISMATCH,
}
_CONNECTORS = ["kiro", "antigravity"]


@pytest.mark.parametrize("connector", _CONNECTORS)
@pytest.mark.parametrize("shape", sorted(_DAMAGE))
def test_status_names_a_damaged_launcher_behind_the_encoded_bridge(tmp_path, windows_launcher, connector, shape):
    launcher, text = windows_launcher
    cfg, _config = _register(tmp_path, connector, text)
    _record_launcher_digest(cfg)
    assert hook_registration_problems(cfg, connector) == []

    _damage(launcher, shape)
    problems = hook_registration_problems(cfg, connector)

    assert problems == [f"the DefenseClaw hook launcher {text} {_DAMAGE[shape]}, so every hook call fails"]
    assert repair_command(connector, problems[0]) == LAUNCHER_REINSTALL_STEP


@pytest.mark.parametrize("connector", _CONNECTORS)
@pytest.mark.parametrize("shape", ["missing", "folder", "link"])
def test_a_missing_folder_or_link_launcher_is_named_with_no_recorded_digest(tmp_path, windows_launcher, connector, shape):
    launcher, text = windows_launcher
    cfg, _config = _register(tmp_path, connector, text)

    _damage(launcher, shape)

    assert hook_registration_problems(cfg, connector) == [
        f"the DefenseClaw hook launcher {text} {_DAMAGE[shape]}, so every hook call fails"
    ]


@pytest.mark.parametrize("connector", _CONNECTORS)
def test_the_launcher_with_the_recorded_digest_is_healthy_and_verified(tmp_path, windows_launcher, connector):
    _launcher, text = windows_launcher
    cfg, _config = _register(tmp_path, connector, text)
    _record_launcher_digest(cfg)

    assert hook_integrity.hook_launcher_problems(cfg, connector) == []
    assert hook_integrity.hook_launcher_unverified(cfg, connector) == ""


@pytest.mark.parametrize("connector", _CONNECTORS)
def test_a_launcher_with_no_recorded_digest_is_unverified_not_damaged(tmp_path, windows_launcher, connector):
    # An install from before the installer recorded the launcher's digest.
    _launcher, text = windows_launcher
    cfg, _config = _register(tmp_path, connector, text)

    assert hook_registration_problems(cfg, connector) == []
    assert hook_integrity.hook_launcher_unverified(cfg, connector) == (
        f"the DefenseClaw hook launcher {text} is not verified: the installer recorded no copy of it to compare with"
    )
    _record_launcher_digest(cfg)
    assert hook_integrity.hook_launcher_unverified(cfg, connector) == ""


def test_a_digest_recorded_for_another_binary_is_no_record_for_the_launcher(tmp_path, windows_launcher):
    _launcher, text = windows_launcher
    cfg, _config = _register(tmp_path, "kiro", text)
    installer = Path(cfg.data_dir, "installer")
    installer.mkdir()
    digest = hashlib.sha256(_BODY).hexdigest()
    (installer / "binaries.sha256").write_text(f"{digest}  defenseclaw-gateway.exe\n", encoding="utf-8")

    assert hook_integrity.hook_launcher_unverified(cfg, "kiro") != ""


_UNREADABLE = "is not verified: it cannot be read here to compare it with the installer record"


def _deny_access(monkeypatch, text: str, how: str) -> None:
    """Make the launcher at *text* unreadable (Defender or a deny ACE holding it); nothing else changes."""

    real_open, real_lstat = open, os.lstat

    def guarded_open(path, *args, **kwargs):
        if how == "read" and str(path) == text:
            raise PermissionError("held")
        return real_open(path, *args, **kwargs)

    def guarded_lstat(path, *args, **kwargs):
        if how == "stat" and str(path) == text:
            raise PermissionError("held")
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", guarded_open)
    monkeypatch.setattr(os, "lstat", guarded_lstat)


@pytest.mark.parametrize("how", ["read", "stat"])
@pytest.mark.parametrize("connector", _CONNECTORS)
def test_a_launcher_that_cannot_be_read_is_unverified_not_damaged_and_not_healthy(
    tmp_path, windows_launcher, monkeypatch, connector, how
):
    # Held by Defender or a deny ACE: not proof of damage, and no digest was computed,
    # so it is not a match either. Doctor warns; status does not call it unprotected.
    launcher, text = windows_launcher
    cfg, _config = _register(tmp_path, connector, text)
    _record_launcher_digest(cfg)
    _damage(launcher, "other-program")
    _deny_access(monkeypatch, text, how)

    assert hook_integrity._launcher_defect(text, cfg.data_dir) == ""
    assert hook_registration_problems(cfg, connector) == []
    assert hook_integrity.hook_launcher_unverified(cfg, connector) == f"the DefenseClaw hook launcher {text} {_UNREADABLE}"


def test_doctor_warns_the_kiro_row_for_a_launcher_that_cannot_be_read(tmp_path, windows_launcher, monkeypatch):
    launcher, text = windows_launcher
    cfg, _config = _register(tmp_path, "kiro", text)
    _record_launcher_digest(cfg)
    _damage(launcher, "other-program")
    _deny_access(monkeypatch, text, "read")

    row = _kiro_doctor_row(cfg, monkeypatch)

    assert (row["label"], row["status"]) == ("Kiro hooks", "warn")
    assert text in row["detail"] and "cannot be read here" in row["detail"]


@pytest.mark.parametrize("tag", [0xA000000C, 0xA0000003])
@pytest.mark.parametrize("kind", [stat.S_IFREG, stat.S_IFDIR])
def test_a_windows_symlink_or_junction_reparse_point_is_a_link(monkeypatch, kind, tag):
    info = SimpleNamespace(st_mode=kind | 0o644, st_file_attributes=0x400, st_reparse_tag=tag)
    monkeypatch.setattr(os, "lstat", lambda _path: info)

    assert hook_integrity._launcher_defect("C:/x/defenseclaw-hook.exe", "") == _LINK


def _reparse_tagged(monkeypatch, text: str, tag: int) -> None:
    """Report the launcher at *text* as a regular file that carries the Windows reparse *tag*."""

    real_lstat = os.lstat

    def tagged(path, *args, **kwargs):
        info = real_lstat(path, *args, **kwargs)
        if str(path) != text:
            return info
        return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400, st_reparse_tag=tag)

    monkeypatch.setattr(os, "lstat", tagged)


# WOF (compact /EXE) and a cloud placeholder: a regular, runnable file, not a link.
@pytest.mark.parametrize("tag", [0x80000017, 0x9000001A])
def test_a_regular_launcher_with_a_non_link_reparse_tag_is_judged_by_its_digest(
    tmp_path, windows_launcher, monkeypatch, tag
):
    launcher, text = windows_launcher
    cfg, _config = _register(tmp_path, "kiro", text)
    _record_launcher_digest(cfg)
    _reparse_tagged(monkeypatch, text, tag)

    assert hook_registration_problems(cfg, "kiro") == []
    assert hook_integrity.hook_launcher_unverified(cfg, "kiro") == ""
    assert _kiro_doctor_row(cfg, monkeypatch)["status"] == "pass"

    _damage(launcher, "other-program")
    assert hook_registration_problems(cfg, "kiro") == [
        f"the DefenseClaw hook launcher {text} {_MISMATCH}, so every hook call fails"
    ]


def test_managed_install_keeps_its_own_status(tmp_path, windows_launcher):
    launcher, text = windows_launcher
    cfg, _config = _register(tmp_path, "kiro", text)
    _damage(launcher, "missing")
    cfg.deployment_mode = "managed_enterprise"

    assert hook_integrity.hook_launcher_problems(cfg, "kiro") == []
    assert hook_integrity.hook_launcher_unverified(cfg, "kiro") == ""


def _kiro_doctor_row(cfg, monkeypatch):
    monkeypatch.setattr("defenseclaw.commands.cmd_doctor._edited_hook_problem", lambda *_: "")
    monkeypatch.setattr("defenseclaw.commands.cmd_doctor._unguarded_tool_call_problem", lambda *_: "")
    result = _DoctorResult(passive=True, quiet=True)
    _check_hook_health(cfg, "kiro", result)
    (row,) = result.checks
    return row


def test_doctor_passes_the_kiro_row_for_the_recorded_launcher(tmp_path, windows_launcher, monkeypatch):
    _launcher, text = windows_launcher
    cfg, _config = _register(tmp_path, "kiro", text)
    _record_launcher_digest(cfg)

    row = _kiro_doctor_row(cfg, monkeypatch)

    assert (row["label"], row["status"]) == ("Kiro hooks", "pass")


def test_doctor_warns_the_kiro_row_when_no_launcher_digest_is_recorded(tmp_path, windows_launcher, monkeypatch):
    _launcher, text = windows_launcher
    cfg, _config = _register(tmp_path, "kiro", text)

    row = _kiro_doctor_row(cfg, monkeypatch)

    assert (row["label"], row["status"]) == ("Kiro hooks", "warn")
    assert text in row["detail"] and "is not verified" in row["detail"]
    assert row["remediation"] == LAUNCHER_REINSTALL_STEP


@pytest.mark.parametrize("recorded", [True, False])
@pytest.mark.parametrize("shape", ["missing", "folder", "link", "other-program"])
def test_doctor_fails_the_kiro_row_for_a_launcher_that_is_not_the_installed_file(
    tmp_path, windows_launcher, monkeypatch, shape, recorded
):
    launcher, text = windows_launcher
    cfg, _config = _register(tmp_path, "kiro", text)
    if recorded:
        _record_launcher_digest(cfg)
    elif shape == "other-program":
        pytest.skip("a different program is told apart only by the recorded digest")

    _damage(launcher, shape)
    row = _kiro_doctor_row(cfg, monkeypatch)

    assert (row["label"], row["status"]) == ("Kiro hooks", "fail")
    assert text in row["detail"] and _DAMAGE[shape] in row["detail"]
    assert row["remediation"] == LAUNCHER_REINSTALL_STEP


@pytest.mark.parametrize("connector", _CONNECTORS)
@pytest.mark.parametrize("user", ["O'Neil", "A&B", "O’Neil", "Ana‘s ‚B‛"])
def test_a_launcher_path_with_a_quote_or_ampersand_is_read_whole(tmp_path, make_launcher, connector, user):
    # The renderers double every single-quote character inside the literal; the
    # path checked is the one the literal holds, not the escaped spelling.
    launcher, text = make_launcher(user)
    cfg, _config = _register(tmp_path, connector, text)
    _record_launcher_digest(cfg)
    assert hook_integrity.hook_launcher_problems(cfg, connector) == []

    launcher.unlink()
    assert hook_integrity.hook_launcher_problems(cfg, connector) == [
        f"the DefenseClaw hook launcher {text} is missing, so every hook call fails"
    ]


@pytest.mark.parametrize("user", ["O'Neil", "A&B"])
def test_a_double_quoted_plain_command_with_a_quote_or_ampersand_is_read_whole(tmp_path, make_launcher, user):
    launcher, text = make_launcher(user)
    cfg, _config = _register(tmp_path, "antigravity", text, plain=True)
    _record_launcher_digest(cfg)
    assert hook_integrity.hook_launcher_problems(cfg, "antigravity") == []

    launcher.unlink()
    assert hook_integrity.hook_launcher_problems(cfg, "antigravity") == [
        f"the DefenseClaw hook launcher {text} is missing, so every hook call fails"
    ]


@pytest.mark.parametrize("connector", _CONNECTORS)
def test_a_replacement_too_large_to_hash_is_not_the_recorded_copy(tmp_path, windows_launcher, connector, monkeypatch):
    launcher, text = windows_launcher
    cfg, _config = _register(tmp_path, connector, text)
    _record_launcher_digest(cfg)
    monkeypatch.setattr(hook_integrity, "_RECORDED_BINARY_SIZE_LIMIT", 4096)
    assert hook_integrity.hook_launcher_problems(cfg, connector) == []

    launcher.write_bytes(bytes(8192))
    problems = hook_registration_problems(cfg, connector)

    assert problems == [f"the DefenseClaw hook launcher {text} {_MISMATCH}, so every hook call fails"]
    assert repair_command(connector, problems[0]) == LAUNCHER_REINSTALL_STEP


def test_a_large_launcher_with_no_recorded_digest_is_unverified_not_read(tmp_path, windows_launcher, monkeypatch):
    launcher, text = windows_launcher
    cfg, _config = _register(tmp_path, "kiro", text)
    monkeypatch.setattr(hook_integrity, "_RECORDED_BINARY_SIZE_LIMIT", 4096)
    launcher.write_bytes(bytes(8192))

    assert hook_integrity.hook_launcher_problems(cfg, "kiro") == []
    assert hook_integrity.hook_launcher_unverified(cfg, "kiro") != ""


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
