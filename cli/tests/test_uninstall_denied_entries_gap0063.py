# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""cowork-1-0-8 GAP-0063: an entry this account cannot remove stops the Windows deferred cleanup.

An elevated hook (Claude Desktop runs elevated as the built-in Administrator)
left hooks\\.outage-warnings owned by Administrators, with only SYSTEM and
OWNER RIGHTS in its DACL. `defenseclaw uninstall --all --binaries --yes` from
a token without elevation scheduled the cleanup, which failed on it after the
CLI had exited; the console did not say it would fail.
"""

from __future__ import annotations

import contextlib
import io
import os
import subprocess
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands import cmd_uninstall  # noqa: E402
from defenseclaw.commands import windows_uninstall_helper as helper  # noqa: E402


def _tree(tmp_path):
    data_dir = tmp_path / ".defenseclaw"
    markers = data_dir / "hooks" / ".outage-warnings"
    markers.mkdir(parents=True)
    (markers / "ab12").write_text("", encoding="utf-8")
    (data_dir / "hooks" / "claude-code-hook.sh").write_text("", encoding="utf-8")
    (data_dir / "config.yaml").write_text("", encoding="utf-8")
    venv = data_dir / ".venv" / "Lib"
    venv.mkdir(parents=True)
    (venv / "site.py").write_text("", encoding="utf-8")
    return data_dir, markers


def test_denied_entries_names_what_this_account_cannot_remove(tmp_path):
    data_dir, markers = _tree(tmp_path)
    probed: list[str] = []

    def prober(path: str) -> bool:
        probed.append(path)
        return path == str(markers / "ab12")

    found = helper.denied_entries(str(data_dir), {str(data_dir / ".venv")}, prober=prober)
    assert found == [str(markers / "ab12")]
    assert str(data_dir / "config.yaml") in probed
    # Nothing in or of the skipped runtime is opened; listable folders are walked, not probed.
    assert not any(path.startswith(str(data_dir / ".venv")) for path in probed)
    assert str(markers) not in probed


def test_a_folder_this_account_cannot_list_is_reported_whole(tmp_path):
    data_dir, markers = _tree(tmp_path)
    real_scandir = os.scandir

    def scandir(path):
        if os.path.normcase(str(path)) == os.path.normcase(str(markers)):
            error = PermissionError(13, "Access is denied", str(path))
            error.winerror = 5
            raise error
        return real_scandir(path)

    with patch.object(helper.os, "scandir", side_effect=scandir):
        found = helper.denied_entries(str(data_dir), {str(data_dir / ".venv")}, prober=lambda path: False)
    assert found == [str(markers)]


def test_denied_entries_is_empty_off_windows(tmp_path):
    with patch.object(helper.sys, "platform", "linux"):
        assert helper.denied_entries(str(tmp_path)) == []


def _plan(data_dir: str) -> cmd_uninstall.UninstallPlan:
    return cmd_uninstall.UninstallPlan(
        platform_name="win32",
        data_dir=data_dir,
        managed_venv=os.path.join(data_dir, ".venv"),
        remove_data_dir=True,
    )


def _run(plan, monkeypatch, **patches) -> str:
    result = r"C:\Users\u\AppData\Local\Temp\defenseclaw-uninstall-result-ab.json"
    monkeypatch.setattr(cmd_uninstall, "_agent_config_wiring_files", lambda: [])
    buffer = io.StringIO()
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.object(cmd_uninstall, "_validate_plan"))
        stack.enter_context(patch.object(cmd_uninstall, "_requires_deferred_cleanup", return_value=True))
        stack.enter_context(patch.object(cmd_uninstall, "_deferred_cleanup_held_folders", return_value=[]))
        schedule = stack.enter_context(
            patch.object(cmd_uninstall, "_schedule_deferred_cleanup", return_value=result)
        )
        stack.enter_context(patch.object(cmd_uninstall, "_remove_empty_plugin_cache"))
        stack.enter_context(patch.object(cmd_uninstall, "remove_own_api_port_claims"))
        for name, value in patches.items():
            stack.enter_context(patch.object(cmd_uninstall.windows_uninstall_helper, name, **value))
        stack.enter_context(contextlib.redirect_stdout(buffer))
        cmd_uninstall._execute_plan(plan)  # noqa: SLF001
        schedule.assert_called_once()
    return " ".join(buffer.getvalue().split())


def test_the_console_says_the_cleanup_will_not_finish_and_names_the_entry(monkeypatch):
    plan = _plan(r"C:\Users\u\.defenseclaw")
    entry = r"C:\Users\u\.defenseclaw\hooks\.outage-warnings"
    output = _run(plan, monkeypatch, denied_entries={"return_value": [entry]})
    assert f"deferred cleanup: scheduled (will not finish: this account cannot remove {entry}, so {plan.data_dir} stays" in output
    assert "not finished yet" not in output
    assert f"this account cannot remove {entry}: Windows denies it access" in output
    assert "An elevated defenseclaw uninstall removes it" in output
    assert "probably created by an earlier elevated run" in output
    assert "Run as administrator" in output


def test_many_denied_entries_are_counted_not_listed(monkeypatch):
    plan = _plan(r"C:\Users\u\.defenseclaw")
    entries = [rf"C:\Users\u\.defenseclaw\logs\f{index}" for index in range(5)]
    output = _run(plan, monkeypatch, denied_entries={"return_value": entries})
    assert f"{entries[2]} and 2 more" in output
    assert entries[3] not in output


def test_a_failing_denied_check_still_schedules_the_cleanup(monkeypatch):
    plan = _plan(r"C:\Users\u\.defenseclaw")
    output = _run(plan, monkeypatch, denied_entries={"side_effect": RuntimeError("boom")})
    assert "deferred cleanup: scheduled (not finished yet:" in output
    assert "cannot remove" not in output


@pytest.mark.skipif(sys.platform != "win32", reason="Windows file security")
def test_a_file_windows_refuses_to_delete_is_reported_and_left_unchanged(tmp_path):
    # The GAP-0063 shape without an elevated owner: deny DELETE on the file and
    # FILE_DELETE_CHILD on its folder, as Administrators ownership with only
    # SYSTEM and OWNER RIGHTS does to a token without elevation.
    data_dir = tmp_path / ".defenseclaw"
    markers = data_dir / "hooks" / ".outage-warnings"
    markers.mkdir(parents=True)
    marker = markers / "ab12"
    marker.write_text("", encoding="utf-8")
    (data_dir / "config.yaml").write_text("", encoding="utf-8")
    assert helper.denied_entries(str(data_dir)) == []
    subprocess.run(["icacls", str(marker), "/deny", "*S-1-1-0:(DE)"], check=True, capture_output=True)
    subprocess.run(["icacls", str(markers), "/deny", "*S-1-1-0:(DC)"], check=True, capture_output=True)
    try:
        assert helper.denied_entries(str(data_dir)) == [str(marker)]
        assert marker.is_file()
        with pytest.raises(OSError) as raised:
            os.unlink(marker)
        assert getattr(raised.value, "winerror", None) == 5
    finally:
        subprocess.run(["icacls", str(markers), "/remove:d", "*S-1-1-0"], check=False, capture_output=True)
        subprocess.run(["icacls", str(marker), "/remove:d", "*S-1-1-0"], check=False, capture_output=True)
    assert helper.denied_entries(str(data_dir)) == []
