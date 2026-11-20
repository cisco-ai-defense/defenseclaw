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

import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

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


# --- review RV-1609 P3-1..P3-3: hard links, the rmtree handler, the uncovered removal paths ----------


def test_where_windows_deletes_by_handle_the_deferred_cleanup_changes_no_attribute(tmp_path):
    data_dir, obj, pack, _keep = _tree(tmp_path)
    fake = _FakeReadOnly(obj, pack, obj.parent)
    patches = _apply(fake.patches())
    try:
        helper._remove_tree(str(data_dir), marker_names=helper._OWNERSHIP_MARKERS)
    finally:
        _stop(patches)
    assert not data_dir.exists()
    # A hard link shares its attributes with a name outside: none is cleared.
    assert fake.cleared == []
    assert sorted(fake.handle_deleted) == sorted(os.path.normcase(str(path)) for path in (obj, pack, obj.parent))


@pytest.mark.skipif(
    sys.platform == "win32", reason="a symlink needs a privilege on Windows; the native test uses a junction"
)
@pytest.mark.parametrize("handle_delete", [True, False], ids=["handle-delete", "older-windows-clear"])
def test_remove_tree_no_follow_removes_readonly_entries_and_never_follows_a_link(tmp_path, handle_delete):
    data_dir, obj, pack, keep = _tree(tmp_path)
    leftover = data_dir / "backups"
    link = leftover / "linked"
    os.symlink(keep.parent, link, target_is_directory=True)
    # The link itself is ReadOnly too (attrib +R /L), and so is what it points to.
    fake = _FakeReadOnly(obj, pack, obj.parent, keep, keep.parent, link, handle_delete=handle_delete)
    patches = _apply(fake.patches())
    try:
        cmd_uninstall._remove_tree_no_follow(str(leftover))
    finally:
        _stop(patches)
    assert not leftover.exists()
    assert keep.read_text(encoding="utf-8") == "keep"
    outside = os.path.normcase(str(keep.parent))
    assert not any(path == outside or path.startswith(outside + os.sep) for path in fake.touched), fake.touched
    assert os.path.normcase(str(link)) in fake.touched  # the link itself, not its target
    assert (fake.cleared == []) is handle_delete


# The rmtree handler of the in-process data removal, called as Python 3.11
# (onerror, an exc_info tuple) and as 3.12+ (onexc, the exception) call it.
_HANDLER_FORMS = [pytest.param((3, 11), id="py3.11-onerror"), pytest.param((3, 12), id="py3.12-onexc")]


def _run_rmtree_handler(python: tuple[int, int], target: Path, error: OSError, calls: list[str]) -> None:
    """_rmtree_gone_ok with an rmtree whose os.unlink of target was refused with error; calls: the unlinks after it."""

    def unlink(path, *args, **kwargs):
        calls.append(str(path))

    def rmtree(path, **kwargs):
        if python >= (3, 12):
            assert set(kwargs) == {"onexc"}
            kwargs["onexc"](os.unlink, str(target), error)
        else:
            assert set(kwargs) == {"onerror"}
            kwargs["onerror"](os.unlink, str(target), (type(error), error, None))

    with (
        patch.object(cmd_uninstall.sys, "version_info", (*python, 0, "final", 0)),
        patch.object(cmd_uninstall.shutil, "rmtree", side_effect=rmtree),
        patch.object(cmd_uninstall.os, "unlink", side_effect=unlink),
    ):
        cmd_uninstall._rmtree_gone_ok(str(target.parent))


@pytest.mark.skipif(sys.platform == "win32", reason="off-Windows behavior")
@pytest.mark.parametrize("python", _HANDLER_FORMS)
def test_off_windows_the_rmtree_handler_raises_a_refusal_without_a_second_delete(tmp_path, python):
    # As before GAP-1609: no second, path-based delete that could follow a
    # folder swapped for a link after rmtree opened it.
    target = tmp_path / "d" / "f"
    error = PermissionError(13, "Permission denied", str(target))
    calls: list[str] = []
    with (
        patch.object(helper, "_file_attributes", return_value=_READONLY),
        patch.object(helper, "remove_refused_readonly", side_effect=AssertionError("retried off Windows"), create=True),
        patch.object(helper, "remove_clearing_readonly", side_effect=AssertionError("retried off Windows")),
        pytest.raises(PermissionError) as raised,
    ):
        _run_rmtree_handler(python, target, error, calls)
    assert raised.value is error
    assert calls == []


@pytest.mark.parametrize("python", _HANDLER_FORMS)
@pytest.mark.parametrize(
    ("attributes", "by_handle", "clears", "gone", "unlinks"),
    [
        pytest.param(0, "unused", False, False, 0, id="not-readonly-is-raised"),
        pytest.param(_READONLY, "deleted", False, True, 0, id="readonly-deleted-by-handle"),
        pytest.param(_READONLY, "refused", False, False, 0, id="handle-delete-refused-is-raised"),
        pytest.param(_READONLY, "unsupported", True, True, 1, id="older-windows-cleared-and-retried"),
        pytest.param(_READONLY, "unsupported", False, False, 0, id="older-windows-hard-link-is-raised"),
    ],
)
def test_on_windows_the_rmtree_handler_retries_only_a_readonly_entry_it_could_remove(
    tmp_path, python, attributes, by_handle, clears, gone, unlinks
):
    target = tmp_path / "d" / "f"
    error = _denied(str(target))
    outcomes = {
        "deleted": helper._READONLY_DELETED,
        "refused": helper._READONLY_REFUSED,
        "unsupported": helper._READONLY_UNSUPPORTED,
    }
    by_handle_calls: list[str] = []
    calls: list[str] = []

    def delete_by_handle(path: str) -> str:
        by_handle_calls.append(path)
        return outcomes[by_handle]

    with (
        patch.object(cmd_uninstall.sys, "platform", "win32"),
        patch.object(helper, "_file_attributes", return_value=attributes),
        patch.object(helper, "_delete_readonly_entry", side_effect=delete_by_handle),
        patch.object(helper, "_clear_readonly_attribute", return_value=clears),
    ):
        if gone:
            _run_rmtree_handler(python, target, error, calls)
        else:
            with pytest.raises(PermissionError) as raised:
                _run_rmtree_handler(python, target, error, calls)
            assert raised.value is error  # the refusal itself, not a repeat of it
    # The failed delete is never simply repeated: only after the attribute was cleared.
    assert calls == [str(target)] * unlinks
    assert by_handle_calls == ([] if attributes == 0 else [str(target)])


def _deferred_plan(tmp: Path) -> tuple[Path, Path, Path]:
    """A deferred-cleanup plan (as the CLI writes it) with one launcher; the manifest, the launcher, the result."""
    install_root = tmp / "bin"
    data_dir = tmp / "data"
    managed_venv = data_dir / ".venv"
    (managed_venv / "Scripts").mkdir(parents=True)
    install_root.mkdir()
    shim = install_root / "defenseclaw.cmd"
    shim.write_text(
        f'@echo off\r\n"{managed_venv / "Scripts" / "defenseclaw.exe"}" %*\r\n', encoding="utf-8", newline=""
    )
    (data_dir / ".env").write_text("KEY=x", encoding="utf-8")
    (data_dir / "config.yaml").write_text("{}", encoding="utf-8")
    temp = tmp / "temp"
    temp.mkdir()
    status_path = temp / "defenseclaw-uninstall-result-new.json"
    helper_dir = tmp / "helper"
    helper_dir.mkdir()
    (helper_dir / "helper.py").write_text("", encoding="utf-8")
    manifest = helper_dir / "plan.json"
    manifest.write_text(
        json.dumps(
            {
                "parent_pid": 1,
                "parent_executable": sys.executable,
                "install_root": str(install_root),
                "data_dir": str(data_dir),
                "managed_venv": str(managed_venv),
                "protected_paths": [],
                "binary_targets": [str(shim)],
                "remove_data_dir": True,
                "remove_empty_install_root": True,
                "interpreter_dirs": [],
                "ready_path": str(helper_dir / "ready.json"),
                "status_path": str(status_path),
            }
        ),
        encoding="utf-8",
    )
    return manifest, shim, status_path


def _run_deferred_helper(manifest: Path, status_path: Path, extra_patches=()) -> dict:
    kernel32 = MagicMock()
    kernel32.WaitForSingleObject.return_value = 0
    patches = (
        patch.object(helper.sys, "platform", "win32"),
        patch.object(helper.sys, "argv", ["helper.py", str(manifest)]),
        patch.object(helper, "__file__", str(manifest.parent / "helper.py")),
        patch.object(helper, "_open_parent", return_value=0),
        patch.object(helper, "_open_launchers", return_value=[]),
        patch.object(helper, "_kernel32", return_value=kernel32),
        patch.object(helper.time, "sleep"),
        *extra_patches,
    )
    _apply(patches)
    try:
        helper.main()
    finally:
        _stop(patches)
    return json.loads(status_path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("handle_delete", [True, False], ids=["handle-delete", "older-windows-clear"])
def test_the_deferred_cleanup_removes_a_readonly_launcher(tmp_path, handle_delete):
    manifest, shim, status_path = _deferred_plan(tmp_path)
    fake = _FakeReadOnly(shim, handle_delete=handle_delete)
    result = _run_deferred_helper(manifest, status_path, fake.patches())
    assert result == {"status": "succeeded"}
    assert not shim.exists()
    assert os.path.normcase(str(shim)) in fake.touched


@windows_only
def test_native_the_deferred_cleanup_removes_a_readonly_launcher(tmp_path):
    manifest, shim, status_path = _deferred_plan(tmp_path)
    os.chmod(shim, stat.S_IREAD)
    assert _readonly(shim)
    result = _run_deferred_helper(manifest, status_path)
    assert result == {"status": "succeeded"}
    assert not shim.exists()


def _native_removers():
    return [
        pytest.param(
            lambda data_dir: helper._remove_tree(str(data_dir), marker_names=helper._OWNERSHIP_MARKERS), id="deferred"
        ),
        pytest.param(lambda data_dir: cmd_uninstall._remove_data_dir(str(data_dir), platform_name="win32"), id="cli"),
        pytest.param(lambda data_dir: cmd_uninstall._remove_tree_no_follow(str(data_dir)), id="no-follow"),
    ]


def _attributes(path: Path) -> int:
    return os.lstat(path).st_file_attributes


def _hard_linked_tree(tmp_path: Path) -> tuple[Path, Path, Path]:
    """A data folder with a hard link to a ReadOnly file outside it (mklink /H, then attrib +R on the outside copy)."""
    data_dir = tmp_path / ".defenseclaw"
    (data_dir / "policies").mkdir(parents=True)
    (data_dir / "config.yaml").write_text("", encoding="utf-8")
    outside = tmp_path / "dotfiles" / "x.rego"
    outside.parent.mkdir()
    outside.write_text("outside", encoding="utf-8")
    link = data_dir / "policies" / "x.rego"
    os.link(outside, link)
    os.chmod(outside, stat.S_IREAD)
    assert _readonly(outside) and _readonly(link)  # one file record, one attribute
    return data_dir, link, outside


@windows_only
@pytest.mark.parametrize("remove", _native_removers())
def test_native_a_hard_link_to_an_outside_readonly_file_goes_and_the_outside_file_keeps_readonly(tmp_path, remove):
    if sys.getwindowsversion().build < 17763:
        pytest.skip("Windows before 1809: the older-Windows test covers it")
    data_dir, link, outside = _hard_linked_tree(tmp_path)
    try:
        assert os.stat(link).st_nlink == 2
        assert helper.denied_entries(str(data_dir)) == []
        remove(data_dir)
        assert not data_dir.exists()
        assert outside.read_text(encoding="utf-8") == "outside"
        assert _readonly(outside), "the outside file lost ReadOnly through its hard link"
        assert os.stat(outside).st_nlink == 1
    finally:
        os.chmod(outside, stat.S_IWRITE)


@windows_only
def test_native_on_older_windows_a_hard_linked_readonly_file_stays_and_is_reported(tmp_path):
    data_dir, link, outside = _hard_linked_tree(tmp_path)
    try:
        with (
            patch.object(helper, "_delete_readonly_entry", return_value=helper._READONLY_UNSUPPORTED),
            patch.object(helper, "_readonly_delete_by_handle_expected", return_value=False),
        ):
            # Clearing ReadOnly would clear it on the outside name too: the file stays, and the console says so.
            assert helper._link_count(str(link)) == 2
            assert helper.denied_entries(str(data_dir)) == [str(link)]
            with pytest.raises(PermissionError):
                helper._remove_tree(str(data_dir), marker_names=helper._OWNERSHIP_MARKERS)
        assert link.exists()
        assert outside.read_text(encoding="utf-8") == "outside"
        assert _readonly(outside) and _readonly(link)
    finally:
        os.chmod(outside, stat.S_IWRITE)


@windows_only
def test_native_on_older_windows_a_readonly_tree_is_cleared_and_removed(tmp_path):
    data_dir, _obj, keep = _native_tree(tmp_path)
    try:
        with patch.object(helper, "_delete_readonly_entry", return_value=helper._READONLY_UNSUPPORTED):
            helper._remove_tree(str(data_dir), marker_names=helper._OWNERSHIP_MARKERS)
        assert not data_dir.exists()
        _assert_outside_untouched(keep)
    finally:
        os.chmod(keep, stat.S_IWRITE)


@windows_only
@pytest.mark.parametrize("handle_delete", [True, False], ids=["handle-delete", "older-windows-clear"])
@pytest.mark.parametrize("remove", _native_removers())
def test_native_a_junction_that_is_itself_readonly_goes_and_its_target_is_unchanged(tmp_path, remove, handle_delete):
    data_dir, obj, pack, keep = _tree(tmp_path)
    junction = data_dir / "backups" / "linked"
    _junction(junction, keep.parent)
    os.chmod(keep, stat.S_IREAD)
    os.chmod(keep.parent, stat.S_IREAD)
    result = subprocess.run(["attrib", "+R", str(junction), "/L"], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    os.chmod(obj, stat.S_IREAD)
    assert _readonly(junction), "attrib +R /L set ReadOnly on the junction itself"
    before = (_attributes(keep.parent), _attributes(keep))
    patches = () if handle_delete else (patch.object(helper, "_delete_readonly_entry", return_value="unsupported"),)
    _apply(patches)
    try:
        remove(data_dir)
        assert not data_dir.exists()
        assert keep.read_text(encoding="utf-8") == "keep"
        assert (_attributes(keep.parent), _attributes(keep)) == before
    finally:
        _stop(patches)
        os.chmod(keep, stat.S_IWRITE)
        os.chmod(keep.parent, stat.S_IWRITE)


@windows_only
def test_native_remove_tree_no_follow_removes_a_readonly_tree_and_not_a_junction_target(tmp_path):
    data_dir, _obj, keep = _native_tree(tmp_path)
    try:
        cmd_uninstall._remove_tree_no_follow(str(data_dir))
        assert not data_dir.exists()
        _assert_outside_untouched(keep)
    finally:
        os.chmod(keep, stat.S_IWRITE)
