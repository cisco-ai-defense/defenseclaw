# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""cowork-1-0-8 GAP-0058: a held data folder stops the Windows deferred cleanup.

After a gateway-down Cowork call, `defenseclaw uninstall --all --binaries
--yes` printed every phase as succeeded and "deferred cleanup: scheduled";
the cleanup, which runs after the CLI exits with no console, then failed on
hooks\\.outage-warnings ("in use by another program") and left the data
folder, while the console looked uninstalled.
"""

from __future__ import annotations

import contextlib
import errno
import io
import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands import cmd_uninstall  # noqa: E402
from defenseclaw.commands import windows_uninstall_helper as helper  # noqa: E402


def _os_error(code: int, winerror: int | None, filename: str) -> OSError:
    error = OSError(code, os.strerror(code), filename)
    if winerror is not None:
        error.winerror = winerror
    return error


@pytest.mark.parametrize(
    ("winerror", "code", "reason", "remedy"),
    [
        (32, errno.EACCES, "is in use by another program", "Close that program"),
        (33, errno.EACCES, "is in use by another program", "Close that program"),
        (145, errno.ENOTEMPTY, "is not empty: a program is still writing in it", "Close that program"),
        (
            5,
            errno.EACCES,
            "cannot be removed by your account (Windows denied access)",
            "Remove it from an elevated prompt",
        ),
        (None, errno.EACCES, "is in use by another program", "Close that program"),
    ],
)
def test_the_result_names_the_windows_error_not_always_in_use(winerror, code, reason, remedy):
    # Every error that named a path read "is in use by another program",
    # an access denial too.
    got_reason, got_remedy = helper._held_reason(_os_error(code, winerror, r"C:\d\hooks\.outage-warnings"))  # noqa: SLF001
    assert got_reason == reason
    assert got_remedy.startswith(remedy)


def test_access_denied_detail_does_not_send_the_user_to_close_a_program(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    held = str(data_dir / "hooks" / ".outage-warnings")
    cause = _os_error(errno.EACCES, 5, held)
    error = OSError("remove failed after waiting")
    error.__cause__ = cause
    plan = {"install_root": str(tmp_path / "bin"), "remove_empty_install_root": True}
    detail = helper._data_left_detail(plan, str(data_dir), error)  # noqa: SLF001
    assert f"{held} cannot be removed by your account (Windows denied access)" in detail
    assert "in use by another program" not in detail


def test_the_data_folder_removal_waits_a_minute_and_says_so():
    # 10 s was the whole wait for a held data folder.
    slept: list[float] = []

    def held():
        raise _os_error(errno.EACCES, 32, r"C:\d\hooks\.outage-warnings")

    with patch.object(helper.time, "sleep", side_effect=slept.append), pytest.raises(OSError) as raised:
        helper._retry(held, r"remove C:\d", helper._DATA_RETRY_DELAYS)  # noqa: SLF001
    assert 59 <= sum(slept) <= 61
    assert "waiting 60 s for file release" in str(raised.value)
    assert raised.value.__cause__.winerror == 32
    # A single file still waits 10 s.
    slept.clear()
    with patch.object(helper.time, "sleep", side_effect=slept.append), pytest.raises(OSError):
        helper._retry(held, r"remove C:\d\x")  # noqa: SLF001
    assert 9 <= sum(slept) <= 11


def test_held_folders_reports_held_folders_and_skips_the_running_runtime(tmp_path):
    data_dir = tmp_path / ".defenseclaw"
    markers = data_dir / "hooks" / ".outage-warnings"
    markers.mkdir(parents=True)
    (markers / "ab12").write_text("", encoding="utf-8")
    (data_dir / "policies").mkdir()
    venv_lib = data_dir / ".venv" / "Lib"
    venv_lib.mkdir(parents=True)
    opened: list[str] = []

    def opener(path: str) -> bool:
        opened.append(path)
        return path in (str(markers), str(venv_lib))

    found = helper.held_folders(str(data_dir), {str(data_dir / ".venv")}, opener=opener)
    assert found == [str(markers)]
    # Only folders are opened, never files, and nothing under the skipped runtime.
    assert str(markers / "ab12") not in opened
    assert not any(path.startswith(str(data_dir / ".venv")) for path in opened)


def test_held_folders_does_not_follow_a_link(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        os.symlink(outside, data_dir / "link", target_is_directory=True)
    except OSError:
        pytest.skip("no symlinks here")
    opened: list[str] = []
    helper.held_folders(str(data_dir), opener=lambda path: opened.append(path) or False)
    assert opened == [str(data_dir)]


def test_held_folders_is_empty_off_windows(tmp_path):
    with patch.object(helper.sys, "platform", "linux"):
        assert helper.held_folders(str(tmp_path)) == []


def _plan(data_dir: str) -> cmd_uninstall.UninstallPlan:
    return cmd_uninstall.UninstallPlan(
        platform_name="win32",
        data_dir=data_dir,
        managed_venv=os.path.join(data_dir, ".venv"),
        remove_data_dir=True,
    )


def test_a_brief_hold_is_rechecked_and_not_reported():
    plan = _plan(r"C:\Users\u\.defenseclaw")
    answers = [[r"C:\Users\u\.defenseclaw\hooks\.outage-warnings"], []]
    with (
        patch.object(cmd_uninstall.windows_uninstall_helper, "held_folders", side_effect=answers) as held,
        patch.object(cmd_uninstall.time, "sleep"),
    ):
        assert cmd_uninstall._deferred_cleanup_held_folders(plan) == []  # noqa: SLF001
    skip = held.call_args_list[0].args[1]
    assert plan.managed_venv in skip
    assert os.path.join(plan.data_dir, ".uv") in skip


def test_a_lasting_hold_is_reported():
    plan = _plan(r"C:\Users\u\.defenseclaw")
    folder = r"C:\Users\u\.defenseclaw\hooks\.outage-warnings"
    with (
        patch.object(cmd_uninstall.windows_uninstall_helper, "held_folders", return_value=[folder]) as held,
        patch.object(cmd_uninstall.time, "sleep"),
    ):
        assert cmd_uninstall._deferred_cleanup_held_folders(plan) == [folder]  # noqa: SLF001
    assert held.call_count == cmd_uninstall._HELD_FOLDER_CHECKS  # noqa: SLF001


def test_the_console_says_the_cleanup_is_not_finished_and_names_the_held_folder(monkeypatch):
    plan = _plan(r"C:\Users\u\.defenseclaw")
    folder = r"C:\Users\u\.defenseclaw\hooks\.outage-warnings"
    result = r"C:\Users\u\AppData\Local\Temp\defenseclaw-uninstall-result-ab.json"
    monkeypatch.setattr(cmd_uninstall, "_agent_config_wiring_files", lambda: [])
    buffer = io.StringIO()
    with (
        patch.object(cmd_uninstall, "_validate_plan"),
        patch.object(cmd_uninstall, "_requires_deferred_cleanup", return_value=True),
        patch.object(cmd_uninstall, "_deferred_cleanup_held_folders", return_value=[folder]),
        patch.object(cmd_uninstall, "_schedule_deferred_cleanup", return_value=result),
        patch.object(cmd_uninstall, "_remove_empty_plugin_cache"),
        patch.object(cmd_uninstall, "remove_own_api_port_claims"),
        contextlib.redirect_stdout(buffer),
    ):
        cmd_uninstall._execute_plan(plan)  # noqa: SLF001
    output = " ".join(buffer.getvalue().split())
    assert "deferred cleanup: scheduled (not finished yet:" in output
    assert f"{plan.data_dir} is removed within about a minute after this command exits" in output
    assert result in output
    assert f"{folder} is open in another program" in output
    assert f"or the cleanup cannot remove {plan.data_dir}" in output


@pytest.mark.skipif(sys.platform != "win32", reason="Windows folder handles")
def test_a_folder_that_is_a_process_current_folder_is_reported_and_left_unchanged(tmp_path):
    # The GAP-0058 shape: a process whose current folder is
    # hooks\.outage-warnings keeps it from being removed.
    import subprocess
    import time

    data_dir = tmp_path / ".defenseclaw"
    markers = data_dir / "hooks" / ".outage-warnings"
    markers.mkdir(parents=True)
    (data_dir / "policies").mkdir()
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], cwd=markers)
    try:
        deadline = 50
        found: list[str] = []
        while deadline and not found:
            found = helper.held_folders(str(data_dir))
            deadline -= 1
            time.sleep(0.1)
        assert found == [str(markers)]
        assert markers.is_dir()
        with pytest.raises(OSError) as raised:
            os.rmdir(markers)
        assert helper._held_reason(raised.value)[0] == "is in use by another program"  # noqa: SLF001
    finally:
        child.kill()
        child.wait(timeout=30)
    assert helper.held_folders(str(data_dir)) == []
