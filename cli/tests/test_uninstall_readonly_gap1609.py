# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""rel-1-0-10 GAP-1609: a ReadOnly file under the data folder stopped the Windows uninstall.

`defenseclaw uninstall --all --binaries --yes` exited 0 and scheduled the
deferred cleanup, which then failed with "cannot be removed by your account
(Windows denied access)" on a git object (git writes them ReadOnly) under
backups\\rolled-back-*\\substrate\\hostcopies, and the whole data folder
stayed: .env with the API keys, device.key, the config. Windows refuses to
delete a ReadOnly file; the account that owns it may clear the attribute.
Uninstall now deletes a refused ReadOnly entry through one handle that does
not follow a link or junction and leaves the attribute as it is (a hard link
shares it with a file outside); before Windows 1809 it clears the attribute on
the entry itself, never on a file with another name.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands import cmd_uninstall  # noqa: E402
from defenseclaw.commands import windows_uninstall_helper as helper  # noqa: E402

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="real Windows ReadOnly attribute and junctions")
_READONLY = 0x1


def _denied(path: str, winerror: int = 5) -> PermissionError:
    error = PermissionError(13, "Access is denied", path)
    error.winerror = winerror
    return error


def _tree(root: Path) -> tuple[Path, Path, Path, Path]:
    """A data folder holding the shape that failed: ReadOnly git objects of a rolled-back hostcopy."""
    data_dir = root / ".defenseclaw"
    (data_dir / "policies").mkdir(parents=True)
    (data_dir / "config.yaml").write_text("", encoding="utf-8")
    (data_dir / ".env").write_text("", encoding="utf-8")
    (data_dir / "device.key").write_text("", encoding="utf-8")
    objects = data_dir / "backups" / "rolled-back-1.0.10-x" / "substrate" / "hostcopies" / "sub-1.git" / "objects"
    (objects / "09").mkdir(parents=True)
    obj = objects / "09" / "4f1e"
    obj.write_bytes(b"x")
    pack = objects / "pack"
    pack.mkdir()
    (pack / "pack-1.idx").write_bytes(b"x")
    outside = root / "outside"
    outside.mkdir()
    keep = outside / "keep.txt"
    keep.write_text("keep", encoding="utf-8")
    return data_dir, obj, pack, keep


class _FakeReadOnly:
    """Windows' ReadOnly refusal, off Windows: os.unlink and os.rmdir refuse a path in readonly.

    handle_delete: Windows 1809+ deletes a ReadOnly entry through its handle
    without changing the attribute; False is an older Windows, where only
    clearing the attribute works.
    """

    def __init__(self, *paths: Path, handle_delete: bool = True) -> None:
        self.readonly = {os.path.normcase(str(path)) for path in paths}
        self.handle_delete = handle_delete
        self.cleared: list[str] = []
        self.handle_deleted: list[str] = []
        self._unlink = os.unlink
        self._rmdir = os.rmdir

    def attributes(self, path: str) -> int:
        return _READONLY if os.path.normcase(str(path)) in self.readonly else 0

    def clear(self, path: str) -> bool:
        self.cleared.append(os.path.normcase(str(path)))
        self.readonly.discard(os.path.normcase(str(path)))
        return True

    def delete_by_handle(self, path: str) -> str:
        key = os.path.normcase(str(path))
        if key not in self.readonly:
            return helper._READONLY_NOT_SET
        if not self.handle_delete:
            return helper._READONLY_UNSUPPORTED
        self.handle_deleted.append(key)
        if os.path.isdir(path) and not os.path.islink(path):
            self._rmdir(path)
        else:
            self._unlink(path)
        self.readonly.discard(key)
        return helper._READONLY_DELETED

    @property
    def touched(self) -> list[str]:
        return self.cleared + self.handle_deleted

    def unlink(self, path, *args, **kwargs):
        if os.path.normcase(str(path)) in self.readonly:
            raise _denied(str(path))
        return self._unlink(path, *args, **kwargs)

    def rmdir(self, path, *args, **kwargs):
        if os.path.normcase(str(path)) in self.readonly:
            raise _denied(str(path))
        return self._rmdir(path, *args, **kwargs)

    def patches(self):
        return (
            patch.object(helper, "_file_attributes", side_effect=self.attributes),
            patch.object(helper, "_clear_readonly_attribute", side_effect=self.clear),
            patch.object(helper, "_delete_readonly_entry", side_effect=self.delete_by_handle),
            patch.object(helper.os, "unlink", side_effect=self.unlink),
            patch.object(helper.os, "rmdir", side_effect=self.rmdir),
        )


def _apply(patches):
    started = []
    try:
        for item in patches:
            item.start()
            started.append(item)
    except BaseException:
        _stop(started)
        raise
    return patches


def _stop(patches) -> None:
    for item in reversed(patches):
        item.stop()


@pytest.mark.parametrize("handle_delete", [True, False], ids=["handle-delete", "older-windows-clear"])
def test_a_refused_readonly_entry_is_removed(tmp_path, handle_delete):
    target = tmp_path / "f"
    target.write_text("", encoding="utf-8")
    fake = _FakeReadOnly(target, handle_delete=handle_delete)
    patches = _apply(fake.patches())
    try:
        helper.remove_clearing_readonly(str(target), os.unlink)
    finally:
        _stop(patches)
    assert not target.exists()
    # Where Windows can, the name goes through its handle and no attribute changes.
    assert fake.handle_deleted == ([os.path.normcase(str(target))] if handle_delete else [])
    assert fake.cleared == ([] if handle_delete else [os.path.normcase(str(target))])


def test_a_refusal_that_is_not_readonly_is_raised_and_changes_nothing(tmp_path):
    target = tmp_path / "f"
    target.write_text("", encoding="utf-8")
    cleared: list[str] = []

    def clear(path: str) -> bool:
        cleared.append(path)
        return True

    def held(path, *args, **kwargs):
        raise _denied(str(path), winerror=32)  # sharing violation: another program holds it

    def acl_denied(path, *args, **kwargs):
        raise _denied(str(path))

    with (
        patch.object(helper, "_clear_readonly_attribute", side_effect=clear),
        patch.object(helper, "_delete_readonly_entry", side_effect=clear),
    ):
        with patch.object(helper, "_file_attributes", return_value=_READONLY), pytest.raises(PermissionError):
            helper.remove_clearing_readonly(str(target), held)
        # Access denied on an entry that is not ReadOnly (an ACL refusal) is raised as it was.
        with patch.object(helper, "_file_attributes", return_value=0), pytest.raises(PermissionError):
            helper.remove_clearing_readonly(str(target), acl_denied)
    assert cleared == []
    assert target.exists()


def test_off_windows_no_attribute_is_ever_set(tmp_path):
    target = tmp_path / "f"
    target.write_text("", encoding="utf-8")
    if sys.platform == "win32":
        pytest.skip("off-Windows behavior")
    with patch.object(helper, "_clear_readonly_attribute", side_effect=AssertionError("set off Windows")):
        assert helper.clear_readonly(str(target)) is False


@pytest.mark.skipif(
    sys.platform == "win32", reason="a symlink needs a privilege on Windows; the native test uses a junction"
)
def test_the_deferred_cleanup_removes_readonly_entries_and_never_follows_a_link(tmp_path):
    data_dir, obj, pack, keep = _tree(tmp_path)
    link = data_dir / "backups" / "linked"
    os.symlink(keep.parent, link, target_is_directory=True)
    fake = _FakeReadOnly(obj, pack, obj.parent, keep, keep.parent, link)
    patches = _apply(fake.patches())
    try:
        helper._remove_tree(str(data_dir), marker_names=helper._OWNERSHIP_MARKERS)
    finally:
        _stop(patches)
    assert not data_dir.exists()
    assert keep.read_text(encoding="utf-8") == "keep"
    outside = os.path.normcase(str(keep.parent))
    assert not any(path == outside or path.startswith(outside + os.sep) for path in fake.touched), fake.touched
    assert os.path.normcase(str(link)) in fake.touched  # the link itself, not its target


# --- native Windows: the real ReadOnly attribute and a real junction ---------------------------


def _junction(link: Path, target: Path) -> None:
    result = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr


def _readonly(path: Path) -> bool:
    return bool(os.lstat(path).st_file_attributes & stat.FILE_ATTRIBUTE_READONLY)


def _native_tree(tmp_path: Path) -> tuple[Path, Path, Path]:
    data_dir, obj, pack, keep = _tree(tmp_path)
    # A junction from the data folder to a folder outside it whose file is ReadOnly too.
    _junction(data_dir / "backups" / "linked", keep.parent)
    os.chmod(keep, stat.S_IREAD)
    os.chmod(obj, stat.S_IREAD)
    (pack / "pack-1.idx").chmod(stat.S_IREAD)
    os.chmod(pack, stat.S_IREAD)  # a ReadOnly folder
    assert _readonly(obj) and _readonly(pack) and _readonly(keep)
    with pytest.raises(PermissionError) as refused:
        os.unlink(obj)
    assert getattr(refused.value, "winerror", None) == 5  # what the cleanup hit
    return data_dir, obj, keep


def _assert_outside_untouched(keep: Path) -> None:
    assert keep.read_text(encoding="utf-8") == "keep"
    assert _readonly(keep), "the junction's target lost its ReadOnly attribute: the junction was followed"
    assert not _readonly(keep.parent)


@windows_only
def test_native_deferred_cleanup_removes_a_readonly_tree_and_not_a_junction_target(tmp_path):
    data_dir, _obj, keep = _native_tree(tmp_path)
    try:
        helper._remove_tree(str(data_dir), marker_names=helper._OWNERSHIP_MARKERS)
        assert not data_dir.exists()
        _assert_outside_untouched(keep)
    finally:
        os.chmod(keep, stat.S_IWRITE)


@windows_only
def test_native_in_process_data_removal_removes_a_readonly_tree_and_not_a_junction_target(tmp_path):
    data_dir, _obj, keep = _native_tree(tmp_path)
    try:
        cmd_uninstall._remove_data_dir(str(data_dir), platform_name="win32")
        assert not data_dir.exists()
        _assert_outside_untouched(keep)
    finally:
        os.chmod(keep, stat.S_IWRITE)


@windows_only
def test_native_clear_readonly_on_a_junction_changes_the_junction_not_its_target(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    os.chmod(target, stat.S_IREAD)
    link = tmp_path / "link"
    _junction(link, target)
    try:
        # The junction itself is not ReadOnly; its target is, and must stay so.
        assert helper.clear_readonly(str(link)) is False
        assert helper._clear_readonly_attribute(str(link)) is False
        assert _readonly(target)
    finally:
        os.chmod(target, stat.S_IWRITE)


@windows_only
@pytest.mark.parametrize("handle_delete", [True, False], ids=["handle-delete", "older-windows-clear"])
def test_native_a_readonly_file_this_account_cannot_clear_is_reported_before_exit(tmp_path, handle_delete):
    data_dir = tmp_path / ".defenseclaw"
    data_dir.mkdir()
    (data_dir / "config.yaml").write_text("", encoding="utf-8")
    plain = data_dir / "plain-readonly"
    plain.write_text("", encoding="utf-8")
    locked = data_dir / "locked-readonly"
    locked.write_text("", encoding="utf-8")
    os.chmod(plain, stat.S_IREAD)
    os.chmod(locked, stat.S_IREAD)
    # Neither clearing ReadOnly nor deleting through the handle works for an
    # account that cannot write the attributes; the console says so before the CLI exits.
    subprocess.run(["icacls", str(locked), "/deny", "*S-1-1-0:(WA)"], check=True, capture_output=True)
    patches = (
        ()
        if handle_delete
        else (
            patch.object(helper, "_delete_readonly_entry", return_value=helper._READONLY_UNSUPPORTED),
            patch.object(helper, "_readonly_delete_by_handle_expected", return_value=False),
        )
    )
    _apply(patches)
    try:
        try:
            assert helper.denied_entries(str(data_dir)) == [str(locked)]
            with pytest.raises(PermissionError):
                helper.remove_clearing_readonly(str(locked), os.unlink)
            assert locked.exists() and _readonly(locked)
        finally:
            subprocess.run(["icacls", str(locked), "/remove:d", "*S-1-1-0"], check=False, capture_output=True)
        assert helper.denied_entries(str(data_dir)) == []
        helper._remove_tree(str(data_dir), marker_names=helper._OWNERSHIP_MARKERS)
        assert not data_dir.exists()
    finally:
        _stop(patches)
