# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""cowork-1-0-8 GAP-0045: a per-user first run after a managed uninstall.

The managed install left hook_contract_lock.json, hooks\\,
foreign-hook-env.json and logs\\hook-failures.jsonl in the account's data
folder with the managed access list, and ``defenseclaw init`` stopped with
"hook_contract_lock.json rollback source is not protected". The first run
now moves those entries, and only those, to a dated folder beside the data
folder and never reads them.
"""

from __future__ import annotations

import getpass
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from defenseclaw import managed_leftovers

STAMP = datetime(2026, 11, 4, 7, 50, 29, tzinfo=timezone.utc)
FIELD = (
    "hook_contract_lock.json",
    "hook_contract_lock.json.lock",
    "foreign-hook-env.json",
    os.path.join("hooks", "claude-code-hook.sh"),
    os.path.join("logs", "hook-failures.jsonl"),
)


def _field_leftover(data_dir: Path) -> None:
    for rel in FIELD:
        path = data_dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{"version":2,"connectors":{}}', encoding="utf-8")
    # What the per-user installer wrote before init runs.
    (data_dir / ".venv").mkdir()
    (data_dir / "installer").mkdir()
    (data_dir / "logs" / "install-20261104T074333.log").write_text("installed", encoding="utf-8")
    (data_dir / "agent_discovery.json").write_text("{}", encoding="utf-8")


@pytest.fixture
def windows_like():
    """The Windows code path with an access-list check the test decides."""
    with (
        patch.object(managed_leftovers, "_is_windows", return_value=True),
        patch.object(managed_leftovers, "_managed_deployment", return_value=None),
    ):
        yield


def _managed(path: str) -> bool:
    return os.path.basename(path) != "hook_contract_lock.json.lock"


def test_moves_only_the_managed_entries_to_a_dated_folder(tmp_path, windows_like):
    data_dir = tmp_path / ".defenseclaw"
    _field_leftover(data_dir)

    result = managed_leftovers.set_aside_managed_leftovers(str(data_dir), custody=_managed, now=STAMP)

    assert result is not None
    backup = tmp_path / ".defenseclaw-managed-leftovers-20261104T075029Z"
    assert result.backup_dir == str(backup)
    assert result.entries == (
        "hook_contract_lock.json",
        "hooks",
        "foreign-hook-env.json",
        os.path.join("logs", "hook-failures.jsonl"),
    )
    for name in result.entries:
        assert (backup / name).exists() and not (data_dir / name).exists()
    # Not managed custody (the per-user rule accepts it): it stays.
    assert (data_dir / "hook_contract_lock.json.lock").exists()
    # The per-user install's own files stay where they are.
    for name in (".venv", "installer", "agent_discovery.json", os.path.join("logs", "install-20261104T074333.log")):
        assert (data_dir / name).exists()
    detail = result.detail(str(data_dir))
    assert str(backup) in detail and "managed (enterprise) DefenseClaw that was removed" in detail

    # A second first run finds nothing more to move; a same-second rerun
    # gets its own folder.
    assert managed_leftovers.set_aside_managed_leftovers(str(data_dir), custody=_managed, now=STAMP) is None
    (data_dir / "hooks").mkdir()
    again = managed_leftovers.set_aside_managed_leftovers(str(data_dir), custody=_managed, now=STAMP)
    assert again is not None and again.backup_dir == str(backup) + "-1"


@pytest.mark.parametrize("marker", managed_leftovers.PER_USER_STATE)
def test_a_per_user_configuration_keeps_the_folder_as_it_is(tmp_path, windows_like, marker):
    data_dir = tmp_path / ".defenseclaw"
    _field_leftover(data_dir)
    (data_dir / marker).write_text("x", encoding="utf-8")
    assert managed_leftovers.set_aside_managed_leftovers(str(data_dir), custody=lambda _p: True) is None
    assert (data_dir / "hook_contract_lock.json").exists()


def test_nothing_moves_while_a_managed_deployment_is_installed(tmp_path):
    data_dir = tmp_path / ".defenseclaw"
    _field_leftover(data_dir)
    with (
        patch.object(managed_leftovers, "_is_windows", return_value=True),
        patch.object(managed_leftovers, "_managed_deployment", return_value="standalone"),
    ):
        assert managed_leftovers.set_aside_managed_leftovers(str(data_dir), custody=lambda _p: True) is None
    assert (data_dir / "hooks").is_dir()


def test_only_windows_moves_anything(tmp_path):
    data_dir = tmp_path / ".defenseclaw"
    _field_leftover(data_dir)
    with patch.object(managed_leftovers, "_is_windows", return_value=False):
        assert managed_leftovers.set_aside_managed_leftovers(str(data_dir), custody=lambda _p: True) is None
    assert (data_dir / "hook_contract_lock.json").exists()


def test_a_link_is_never_moved(tmp_path, windows_like):
    data_dir = tmp_path / ".defenseclaw"
    data_dir.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        (data_dir / "hooks").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("this account cannot create symbolic links")
    assert managed_leftovers.set_aside_managed_leftovers(str(data_dir), custody=lambda _p: True) is None
    assert (data_dir / "hooks").is_symlink() and outside.is_dir()


def test_an_entry_that_cannot_move_names_the_remediation(tmp_path, windows_like):
    data_dir = tmp_path / ".defenseclaw"
    _field_leftover(data_dir)
    with (
        patch("defenseclaw.managed_leftovers.os.rename", side_effect=PermissionError(13, "Access is denied")),
        pytest.raises(OSError) as raised,
    ):
        managed_leftovers.set_aside_managed_leftovers(str(data_dir), custody=lambda _p: True, now=STAMP)
    message = str(raised.value)
    assert str(data_dir / "hook_contract_lock.json") in message
    assert "Access is denied" in message
    assert "defenseclaw-managed-leftovers-20261104T075029Z" in message
    assert message.endswith("then run: defenseclaw init")


def _first_run(data_dir: Path):
    from defenseclaw.bootstrap import FirstRunOptions, run_first_run

    from tests.helpers import record_test_setup_agent_selections

    with (
        patch.dict(os.environ, {"DEFENSECLAW_HOME": str(data_dir)}),
        patch(
            "defenseclaw.agent_selection.record_setup_agent_selections",
            side_effect=record_test_setup_agent_selections,
        ),
    ):
        return run_first_run(
            FirstRunOptions(connector="none", profile="observe", skip_install=True, start_gateway=False, verify=False)
        )


def _unprotected_lock(data_dir: Path) -> None:
    # The per-user rule refuses this lock as a rollback source on every OS
    # (here: writable by others), as it refused the managed one.
    data_dir.mkdir(parents=True)
    lock = data_dir / "hook_contract_lock.json"
    lock.write_text('{"version":2,"updated_at":"2026-11-04T07:25:38Z","connectors":{}}', encoding="utf-8")
    lock.chmod(0o666)
    (data_dir / "hooks").mkdir()


@pytest.mark.skipif(os.name == "nt", reason="the unprotected stand-in lock uses POSIX modes")
def test_first_run_refuses_the_leftover_as_its_rollback_source(tmp_path):
    data_dir = Path(os.path.realpath(tmp_path)) / ".defenseclaw"
    _unprotected_lock(data_dir)
    report = _first_run(data_dir)
    assert report.status == "needs_attention"
    step = next(s for s in report.setup if s.name == "First-run transaction")
    lock = data_dir / "hook_contract_lock.json"
    # GAP-0074: the first run names the file and the command that fixes it.
    assert step.detail == (
        "could not establish the protected first-run rollback point: "
        "hook_contract_lock.json rollback source is not private: "
        f"other accounts can read or change {lock}; make it owner-only (chmod 600 {lock}) "
        "and run defenseclaw init again"
    )
    assert lock.stat().st_mode & 0o777 == 0o666


@pytest.mark.skipif(os.name == "nt", reason="the unprotected stand-in lock uses POSIX modes")
def test_first_run_moves_the_managed_leftover_aside_before_its_rollback_point(tmp_path, windows_like):
    data_dir = Path(os.path.realpath(tmp_path)) / ".defenseclaw"
    _unprotected_lock(data_dir)
    with patch.object(managed_leftovers, "managed_custody", return_value=True):
        report = _first_run(data_dir)
    assert report.status != "needs_attention", report.setup
    step = next(s for s in report.setup if s.name == "Managed leftovers")
    assert step.status == "pass" and "hook_contract_lock.json, hooks" in step.detail
    backups = sorted(Path(data_dir.parent).glob(managed_leftovers.BACKUP_PREFIX + "*"))
    assert len(backups) == 1
    moved = backups[0] / "hook_contract_lock.json"
    assert moved.read_text(encoding="utf-8").startswith('{"version":2')
    assert (data_dir / "config.yaml").exists()
    # The new lock (if any) is the first run's own, not the leftover.
    lock = data_dir / "hook_contract_lock.json"
    assert not lock.exists() or "2026-11-04T07:25:38Z" not in lock.read_text(encoding="utf-8")


ACCOUNT = "S-1-5-21-4053867087-1811248452-1158138866-1001"
_FA, _M, _M_DC, _RC = 0x1F01FF, 0x1301BF, 0x1301FF, 0x20000


def _ace(sid: str, mask: int, flags: int = 0) -> tuple[int, int, int, str]:
    return (mask, 1, flags, sid)


@pytest.mark.parametrize(
    ("entries", "locked"),
    [
        # hook_contract_lock.json as a 1.0.8 managed uninstall left it (vm-dc-cowork-win11).
        ([_ace("S-1-3-4", _RC), _ace(ACCOUNT, _M), _ace("S-1-5-18", _FA), _ace("S-1-5-32-544", _FA)], True),
        # hooks\: the same lock on a folder, with inherit-only copies for its children.
        (
            [
                _ace("S-1-3-4", _RC),
                _ace(ACCOUNT, _M_DC),
                _ace(ACCOUNT, 0xE0010040, 0x0B),
                _ace("S-1-5-18", _FA),
                _ace("S-1-5-18", 0x10000000, 0x0B),
                _ace("S-1-5-32-544", _FA),
                _ace("S-1-5-32-544", 0x10000000, 0x0B),
            ],
            True,
        ),
        # foreign-hook-env.json: written by the runtime in the locked folder, no OWNER RIGHTS entry.
        ([_ace(ACCOUNT, _M_DC), _ace("S-1-5-18", _FA), _ace("S-1-5-32-544", _FA)], True),
        # logs\\hook-failures.jsonl: a file the hook created later, inheriting the folder's lock.
        ([_ace(ACCOUNT, _M_DC, 0x10), _ace("S-1-5-18", _FA, 0x10), _ace("S-1-5-32-544", _FA, 0x10)], True),
        # The profile's own access list (GAP-0069): the account has full control.
        ([_ace("S-1-5-18", _FA, 0x10), _ace("S-1-5-32-544", _FA, 0x10), _ace(ACCOUNT, _FA, 0x10)], False),
        # The per-user private writer: SYSTEM and OWNER RIGHTS full control.
        ([_ace("S-1-5-18", _FA), _ace("S-1-3-4", _FA)], False),
    ],
    ids=["lock-file", "hooks-folder", "foreign-hook-env", "inherited-child", "profile-inherited", "per-user-private"],
)
def test_field_lock_is_the_managed_runtime_access_list(entries, locked):
    assert managed_leftovers.field_locked(entries, ACCOUNT) is locked


@pytest.mark.skipif(os.name != "nt", reason="Windows access lists")
def test_managed_custody_reads_the_windows_access_list(tmp_path):
    user = os.environ.get("USERDOMAIN", "") + "\\" + getpass.getuser()
    administrators, system, owner_rights = "*S-1-5-32-544", "*S-1-5-18", "*S-1-3-4"
    plain = tmp_path / "plain.json"
    managed = tmp_path / "managed.json"
    other = tmp_path / "other.json"
    # One icacls call per file: once OWNER RIGHTS is read-only, a standard
    # account can no longer change the access list.
    grants = {
        # The profile's access list, set as explicit entries.
        plain: [f"{user}:(F)", f"{system}:(F)", f"{administrators}:(F)"],
        # The field lock: the account Modify and a read-only OWNER RIGHTS entry.
        managed: [f"{user}:(M)", f"{system}:(F)", f"{administrators}:(F)", f"{owner_rights}:(RC)"],
        # The same, but every user can write it: not DefenseClaw's custody.
        other: [f"{user}:(M)", f"{system}:(F)", f"{administrators}:(F)", f"{owner_rights}:(RC)", "*S-1-5-32-545:(M)"],
    }
    for path, grant in grants.items():
        path.write_text("{}", encoding="utf-8")
        subprocess.run(["icacls", str(path), "/setowner", user], check=True, capture_output=True)
        subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", *grant], check=True, capture_output=True)
    from defenseclaw.file_permissions import windows_acl_write_error

    # The per-user rule refuses the plain entry too, so only the lock tells them apart.
    assert windows_acl_write_error(str(plain)) is not None
    assert managed_leftovers.managed_custody(str(plain)) is False
    assert managed_leftovers.managed_custody(str(managed)) is True
    assert managed_leftovers.managed_custody(str(other)) is False


class _WindowsOs:
    """``os`` as cmd_setup sees it on Windows; everything else is the real module."""

    name = "nt"

    def __getattr__(self, attribute):
        return getattr(os, attribute)


_MOVE_OR_DELETE = "Move it out of the folder, or delete it if you did not create it, then"


def _plain_lock(tmp_path: Path) -> Path:
    lock = Path(os.path.realpath(tmp_path)) / "hook_contract_lock.json"
    lock.write_text("{}", encoding="utf-8")
    return lock


def test_an_unprotected_windows_rollback_source_names_the_file_and_the_way_out(tmp_path):
    # cowork-1-0-8 GAP-0074: a plain hook_contract_lock.json the user made is
    # still refused; the first run now says which file and what to do.
    from defenseclaw.commands import cmd_setup

    lock = _plain_lock(tmp_path)
    with (
        patch.object(cmd_setup, "os", _WindowsOs()),
        patch.object(
            cmd_setup, "windows_acl_write_error", return_value="owner SID S-1-5-32-544 is not the current user"
        ),
        pytest.raises(cmd_setup.RollbackSourceRefusedError) as raised,
    ):
        cmd_setup._capture_protected_setup_file(str(lock), 1 << 20, "hook_contract_lock.json")
    assert raised.value.for_user("defenseclaw init") == (
        f"hook_contract_lock.json rollback source is not protected: {lock} is not protected the way "
        f"DefenseClaw writes its files. {_MOVE_OR_DELETE} run defenseclaw init again"
    )
    # Setup commands wrap and record the plain message, which names no path.
    assert str(raised.value) == (
        "hook_contract_lock.json rollback source is not protected: the file is not protected the way "
        f"DefenseClaw writes its files. {_MOVE_OR_DELETE} run the command again"
    )
    assert lock.read_text(encoding="utf-8") == "{}"  # never moved or deleted for the user


@pytest.mark.skipif(os.name == "nt", reason="POSIX owners")
def test_a_foreign_owned_rollback_source_is_worded_the_same(tmp_path):
    from defenseclaw.commands import cmd_setup

    lock = _plain_lock(tmp_path)
    lock.chmod(0o600)
    with (
        patch.object(cmd_setup, "trusted_runtime_owner", return_value=False),
        pytest.raises(cmd_setup.RollbackSourceRefusedError) as raised,
    ):
        cmd_setup._capture_protected_setup_file(str(lock), 1 << 20, "hook_contract_lock.json")
    assert raised.value.for_user("defenseclaw init") == (
        f"hook_contract_lock.json rollback source is not owned by a trusted principal: {lock} is not "
        f"protected the way DefenseClaw writes its files. {_MOVE_OR_DELETE} run defenseclaw init again"
    )
    assert str(lock) not in str(raised.value)
    assert lock.exists()
