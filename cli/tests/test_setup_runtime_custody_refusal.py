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

"""A file setup reads for its rollback point that another account can write is named, not hidden.

Windows setup used to turn that refusal into "applied runtime evidence did not
stabilize" with a hash reference. The refusal stays; setup now names the file,
the account and the one repair (rel-1-0-6 GAP-0804).
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from defenseclaw import file_permissions
from defenseclaw.commands import cmd_setup
from defenseclaw.inventory import claw_inventory

_OTHER_SID = "S-1-5-21-1111111111-2222222222-3333333333-1002"
_CURRENT_SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"
_OTHER_ACCOUNT = "EC2AMAZ-TEST\\other"


class _WindowsOs:
    """``os`` as cmd_setup sees it on Windows; everything else is the real module."""

    name = "nt"

    def __getattr__(self, attribute):
        return getattr(os, attribute)


def _plugin_file(tmp_path: Path) -> Path:
    plugin = Path(os.path.realpath(tmp_path)) / "plugins" / "defenseclaw.js"
    plugin.parent.mkdir()
    plugin.write_text("// bridge\n", encoding="utf-8")
    return plugin


def _refused_by_writer(sid: str = _OTHER_SID):
    return patch.object(cmd_setup, "windows_acl_write_error", return_value=file_permissions.windows_untrusted_writer_problem(sid))


def _capture(plugin: Path):
    return cmd_setup._capture_setup_runtime_location(os.fspath(plugin), "hook runtime")


def test_the_writer_text_the_acl_checks_return_names_its_sid(monkeypatch):
    # Both Windows custody validators return the text the setup refusal reads the SID from.
    entries = [
        (0x1F01FF, 1, 0x13, "S-1-5-18"),
        (0x1F01FF, 1, 0x13, _CURRENT_SID),
        (0x1301BF, 1, 0, _OTHER_SID),
    ]
    monkeypatch.setattr(file_permissions, "_windows_acl_snapshot", lambda _path: (_CURRENT_SID, False, entries))
    monkeypatch.setattr(file_permissions, "_windows_current_user_sid", lambda: _CURRENT_SID)
    real_os = file_permissions.os
    file_permissions.os = SimpleNamespace(name="nt", fspath=os.fspath)
    try:
        private = file_permissions.windows_acl_write_error("plugin.js")
        custody = file_permissions.windows_acl_write_error("plugin.js", trust_administrators=True)
    finally:
        file_permissions.os = real_os
    assert file_permissions.windows_untrusted_writer_sid(private) == _OTHER_SID
    assert file_permissions.windows_untrusted_writer_sid(custody) == _OTHER_SID


@pytest.mark.parametrize(
    "problem",
    [
        None,
        "",
        f"owner SID {_OTHER_SID} is not the current user",
        "ACL grants write access to Everyone (null DACL)",
        "ACL grants write access to untrusted SID <unknown>",
        "ACL grants write access to untrusted SID S-1-5-21-1; calc",
        "ACL grants write access to untrusted SID ",
    ],
)
def test_only_a_named_writer_gives_a_repair_by_account(problem):
    assert file_permissions.windows_untrusted_writer_sid(problem) is None


def test_a_plugin_file_another_account_can_write_is_named_with_its_account_and_one_repair(tmp_path):
    plugin = _plugin_file(tmp_path)
    with (
        patch.object(cmd_setup, "os", _WindowsOs()),
        _refused_by_writer(),
        patch.object(claw_inventory, "_windows_account_name_for_sid", return_value=_OTHER_ACCOUNT),
        pytest.raises(cmd_setup._SetupRuntimeCustodyRefusedError) as raised,
    ):
        _capture(plugin)

    reason, next_step = cmd_setup._setup_rollback_point_failure(raised.value)
    assert reason == f"hook runtime file {plugin} can be changed by {_OTHER_ACCOUNT}"
    assert next_step == (
        "Nothing was changed. Remove that account\x27s access to it, then run the command again:\n"
        f"      icacls \"{plugin}\" /remove:g \"{_OTHER_ACCOUNT}\""
    )
    # Recorded messages still name no path; the refusal is not retried into a hash reference.
    assert str(plugin) not in str(raised.value)
    assert "did not stabilize" not in str(raised.value)
    assert plugin.read_text(encoding="utf-8") == "// bridge\n"  # never changed for the user


def test_an_account_that_does_not_resolve_is_named_by_its_sid_which_icacls_takes(tmp_path):
    plugin = _plugin_file(tmp_path)
    with (
        patch.object(cmd_setup, "os", _WindowsOs()),
        _refused_by_writer(),
        patch.object(claw_inventory, "_windows_account_name_for_sid", side_effect=OSError("no mapping")),
        pytest.raises(cmd_setup._SetupRuntimeCustodyRefusedError) as raised,
    ):
        _capture(plugin)

    reason, next_step = cmd_setup._setup_rollback_point_failure(raised.value)
    assert reason == f"hook runtime file {plugin} can be changed by {_OTHER_SID}"
    assert next_step.endswith(f"icacls \"{plugin}\" /remove:g *{_OTHER_SID}")


def test_a_refusal_that_is_not_a_writer_gets_no_invented_icacls_command(tmp_path):
    plugin = _plugin_file(tmp_path)
    with (
        patch.object(cmd_setup, "os", _WindowsOs()),
        patch.object(cmd_setup, "windows_acl_write_error", return_value=f"owner SID {_OTHER_SID} is not the current user"),
        pytest.raises(cmd_setup._SetupRuntimeCustodyRefusedError) as raised,
    ):
        _capture(plugin)

    reason, next_step = cmd_setup._setup_rollback_point_failure(raised.value)
    assert reason == f"hook runtime file {plugin} is not protected the way DefenseClaw writes its files"
    assert "icacls" not in next_step
    assert next_step.startswith("Nothing was changed. Move it out of the folder")


def test_the_applied_runtime_capture_keeps_the_refusal_instead_of_the_stabilize_reference(tmp_path, monkeypatch):
    plugin = _plugin_file(tmp_path)
    monkeypatch.setattr(cmd_setup, "_SETUP_RUNTIME_SNAPSHOT_RETRY_SECONDS", 0)

    def once(_cfg, _required=()):
        return _capture(plugin)

    monkeypatch.setattr(cmd_setup, "_capture_setup_applied_runtime_once", once)
    with (
        patch.object(cmd_setup, "os", _WindowsOs()),
        _refused_by_writer(),
        patch.object(claw_inventory, "_windows_account_name_for_sid", return_value=_OTHER_ACCOUNT),
        pytest.raises(OSError) as raised,
    ):
        cmd_setup._capture_setup_applied_runtime(SimpleNamespace())

    assert isinstance(raised.value, cmd_setup._SetupRuntimeCustodyRefusedError)
    reason, next_step = cmd_setup._setup_rollback_point_failure(raised.value)
    assert _OTHER_ACCOUNT in reason and str(plugin) in reason
    assert f"/remove:g \"{_OTHER_ACCOUNT}\"" in next_step


def test_a_refusal_after_one_complete_snapshot_is_still_named_with_its_repair(tmp_path, monkeypatch):
    plugin = _plugin_file(tmp_path)
    monkeypatch.setattr(cmd_setup, "_SETUP_RUNTIME_SNAPSHOT_RETRY_SECONDS", 0)
    calls = {"n": 0}

    def once(_cfg, _required=()):
        calls["n"] += 1
        if calls["n"] == 1:
            return object()  # one complete sample, then another account gains write access
        return _capture(plugin)

    monkeypatch.setattr(cmd_setup, "_capture_setup_applied_runtime_once", once)
    with (
        patch.object(cmd_setup, "os", _WindowsOs()),
        _refused_by_writer(),
        patch.object(claw_inventory, "_windows_account_name_for_sid", return_value=_OTHER_ACCOUNT),
        pytest.raises(cmd_setup._SetupRuntimeCustodyRefusedError) as raised,
    ):
        cmd_setup._capture_setup_applied_runtime(SimpleNamespace())

    assert calls["n"] == cmd_setup._SETUP_RUNTIME_SNAPSHOT_ATTEMPTS
    reason, next_step = cmd_setup._setup_rollback_point_failure(raised.value)
    assert _OTHER_ACCOUNT in reason and str(plugin) in reason
    assert f"/remove:g \"{_OTHER_ACCOUNT}\"" in next_step


def test_a_transient_read_error_after_one_complete_snapshot_keeps_the_generic_retry_text(monkeypatch):
    monkeypatch.setattr(cmd_setup, "_SETUP_RUNTIME_SNAPSHOT_RETRY_SECONDS", 0)
    calls = {"n": 0}

    def once(_cfg, _required=()):
        calls["n"] += 1
        if calls["n"] == 1:
            return object()
        raise OSError("sharing violation")

    monkeypatch.setattr(cmd_setup, "_capture_setup_applied_runtime_once", once)
    with pytest.raises(OSError, match="applied runtime evidence did not stabilize") as raised:
        cmd_setup._capture_setup_applied_runtime(SimpleNamespace())
    assert not isinstance(raised.value, cmd_setup._SetupRuntimeCustodyRefusedError)


def test_an_unreadable_runtime_file_keeps_the_generic_retry_text(tmp_path, monkeypatch):
    # The benign twin: only a custody refusal changes the message; a read failure is still a retried reference.
    missing_parent = Path(os.path.realpath(tmp_path)) / "no-such-folder" / "defenseclaw.js"
    monkeypatch.setattr(cmd_setup, "_SETUP_RUNTIME_SNAPSHOT_RETRY_SECONDS", 0)

    def once(_cfg, _required=()):
        raise OSError("sharing violation")

    monkeypatch.setattr(cmd_setup, "_capture_setup_applied_runtime_once", once)
    with pytest.raises(OSError, match="applied runtime evidence did not stabilize") as raised:
        cmd_setup._capture_setup_applied_runtime(SimpleNamespace())
    assert not isinstance(raised.value, cmd_setup._SetupRuntimeCustodyRefusedError)
    assert cmd_setup._setup_rollback_point_failure(raised.value) == (str(raised.value), cmd_setup._SETUP_ROLLBACK_POINT_NEXT_STEP)
    # A file that does not exist is not a refusal either: it is simply absent evidence.
    assert _capture(missing_parent)[2] == "missing"


def test_a_protected_plugin_file_is_still_accepted(tmp_path):
    plugin = _plugin_file(tmp_path)
    with patch.object(cmd_setup, "os", _WindowsOs()), patch.object(cmd_setup, "windows_acl_write_error", return_value=None):
        _normalized, _identity, fingerprint = _capture(plugin)
    assert fingerprint.startswith("present:")
