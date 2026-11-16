# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Doctor names vendor policy folders this account cannot read.

A gateway run as root used to create ``/etc/codex`` (mode 0700) for its
``/etc/codex/skills`` watch; Codex then paused every launch with
"Organization settings could not be loaded". Doctor must name the folder and
the administrator repair, and stay quiet when the folders are readable or
absent.
"""

from __future__ import annotations

import os
import stat
import sys

import pytest
from defenseclaw.commands import cmd_doctor
from defenseclaw.commands.cmd_doctor import _DoctorResult


def _rows(result: _DoctorResult) -> list[dict]:
    return [c for c in result.checks if c["label"] == "Vendor policy folders"]


@pytest.fixture
def vendor_dirs(tmp_path, monkeypatch):
    codex = tmp_path / "etc" / "codex"
    cursor = tmp_path / "etc" / "cursor"
    monkeypatch.setitem(cmd_doctor._VENDOR_POLICY_DIRS, "darwin", (str(codex), str(cursor)))
    return codex, cursor


def test_absent_folders_pass(vendor_dirs) -> None:
    r = _DoctorResult()
    cmd_doctor._check_vendor_policy_dirs(None, r, platform_name="darwin")
    rows = _rows(r)
    assert len(rows) == 1 and rows[0]["status"] == "pass"


def test_readable_folder_passes(vendor_dirs) -> None:
    codex, _ = vendor_dirs
    codex.mkdir(parents=True, mode=0o755)
    r = _DoctorResult()
    cmd_doctor._check_vendor_policy_dirs(None, r, platform_name="darwin")
    assert _rows(r)[0]["status"] == "pass"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits: chmod 0 does not stop traversal on Windows")
@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root can traverse any folder")
def test_unreadable_folder_fails_with_repair(vendor_dirs) -> None:
    codex, cursor = vendor_dirs
    codex.mkdir(parents=True)
    (codex / "skills").mkdir()
    cursor.mkdir(parents=True, mode=0o755)
    os.chmod(codex, 0)  # the folder exists but cannot be traversed, like root 0700 from another account
    try:
        r = _DoctorResult()
        cmd_doctor._check_vendor_policy_dirs(None, r, platform_name="darwin")
    finally:
        os.chmod(codex, stat.S_IRWXU)
    rows = _rows(r)
    assert len(rows) == 1 and rows[0]["status"] == "fail"
    assert str(codex) in rows[0]["detail"] and str(cursor) not in rows[0]["detail"]
    assert "Organization settings could not be loaded" in rows[0]["detail"]
    assert "sudo rm -rf" in rows[0]["remediation"]


def test_symlinked_folder_is_ignored(vendor_dirs, tmp_path) -> None:
    codex, _ = vendor_dirs
    target = tmp_path / "elsewhere"
    target.mkdir(mode=0o700)
    codex.parent.mkdir(parents=True)
    codex.symlink_to(target)
    r = _DoctorResult()
    cmd_doctor._check_vendor_policy_dirs(None, r, platform_name="darwin")
    assert _rows(r)[0]["status"] == "pass"


def test_other_platforms_emit_nothing() -> None:
    r = _DoctorResult()
    cmd_doctor._check_vendor_policy_dirs(None, r, platform_name="win32")
    assert _rows(r) == []
