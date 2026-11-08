# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Uninstall removes the connector records `config set data_dir` left in the folders it moved away from."""

from __future__ import annotations

import json
import os
from unittest.mock import patch

import pytest
from defenseclaw.commands import cmd_uninstall

pytestmark = pytest.mark.skipif(os.name == "nt", reason="private file modes are a POSIX property")

TOKEN = "ab" * 32
MARKER = "# defenseclaw-managed-hook v3\n"


def _write(path, text="x\n", mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)
    return path


def _backup_record(connector, logical):
    """A backup record as Setup writes it (managed_backup.go)."""
    return json.dumps(
        {
            "version": 1,
            "connector": connector,
            "logical_name": logical,
            "path": f"/agent/{logical}",
            "existed": True,
            "pristine_sha256": "00" * 32,
            "captured_at": "2026-11-08T00:00:00Z",
        }
    ) + "\n"


def _connector_records(folder, connector="hermes", script="hermes-hook.sh"):
    """What a setup and the move after it leave in a folder, for one connector."""
    return {
        "token": _write(folder / "hooks" / f".hook-{connector}.token", TOKEN + "\n"),
        "script": _write(folder / "hooks" / script, "#!/bin/sh\n" + MARKER, 0o700),
        "config_record": _write(folder / "hooks" / ".config-record", f"{folder}/config.yaml\n"),
        "home_record": _write(folder / "hooks" / ".install-home-record", f"{folder}\n"),
        "lock": _write(folder / "hook_contract_lock.json", "{}\n"),
        "backup": _write(
            folder / "connector_backups" / connector / "config.yaml.json", _backup_record(connector, "config.yaml")
        ),
        "allowlist_backup": _write(
            folder / "connector_backups" / connector / "shell-hooks-allowlist.json.json",
            _backup_record(connector, "shell-hooks-allowlist.json"),
        ),
        "last_good": _write(folder / "connector_backups" / connector / "config.yaml.last-good", "agent: x\n"),
        "setup": _write(folder / f"{connector}-home-setup.json", "{}\n"),
    }


def _plan(tmp_path, *, connectors=("hermes",)):
    home, first, second = (tmp_path / ".defenseclaw", tmp_path / "state", tmp_path / "state2")
    for folder in (home, first, second):
        folder.mkdir(exist_ok=True)
        _write(folder / "agent_discovery.json")
    plan = cmd_uninstall.UninstallPlan(
        data_dir=str(home), store_dir=str(second), previous_stores=(str(first),), connectors=tuple(connectors)
    )
    return plan, home, first, second


def test_the_credential_seals_and_backups_in_every_earlier_folder_are_removed(tmp_path):
    plan, home, first, second = _plan(tmp_path)
    earlier = {folder: _connector_records(folder) for folder in (home, first)}
    final = _connector_records(second)
    config = _write(home / "config.yaml", "data_dir: x\n")

    cmd_uninstall._remove_earlier_folder_connector_records(plan)

    for folder, records in earlier.items():
        for name, path in records.items():
            assert not path.exists(), f"{folder.name}: {name} stays"
        assert not (folder / "hooks").exists()
        assert not (folder / "connector_backups").exists()
        assert (folder / "agent_discovery.json").is_file()
    assert config.is_file()
    # The folder config.yaml names is the connector teardown's.
    assert all(path.exists() for path in final.values())


def test_a_second_connector_keeps_the_folder_level_records(tmp_path):
    plan, home, first, _second = _plan(tmp_path)
    records = _connector_records(first)
    other = _connector_records(first, "cursor", "cursor-hook.sh")

    cmd_uninstall._remove_earlier_folder_connector_records(plan)

    assert not records["token"].exists() and not records["backup"].exists() and not records["setup"].exists()
    assert other["token"].is_file() and other["backup"].is_file() and other["script"].is_file()
    assert other["lock"].is_file() and other["config_record"].is_file()


def test_only_the_connectors_this_uninstall_tore_down_lose_records(tmp_path):
    plan, _home, first, _second = _plan(tmp_path, connectors=("codex",))
    records = _connector_records(first)
    codex = _connector_records(first, "codex", "codex-hook.sh")

    cmd_uninstall._remove_earlier_folder_connector_records(plan)

    assert all(path.exists() for path in records.values())
    assert not codex["token"].exists() and not codex["backup"].exists() and not codex["script"].exists()


def test_a_file_that_is_not_defenseclaws_stays(tmp_path):
    plan, _home, first, _second = _plan(tmp_path)
    records = _connector_records(first)
    records["script"].write_text("#!/bin/sh\nexec /usr/local/bin/user-hook\n")
    note = _write(first / "hooks" / "my-notes.txt")
    outside = _write(tmp_path / "outside-token", TOKEN + "\n")
    records["token"].unlink()
    records["token"].symlink_to(outside)
    (first / "connector_backups" / "hermes" / "mine.txt").write_text("the user's file\n")

    cmd_uninstall._remove_earlier_folder_connector_records(plan)

    assert records["script"].is_file(), "a script that is not DefenseClaw's"
    assert note.is_file()
    assert records["token"].is_symlink() and outside.is_file(), "a linked credential is not followed"
    assert (first / "connector_backups" / "hermes" / "mine.txt").is_file()
    assert not records["backup"].exists()
    # Something of the user's remains in the folder: its records stay with it.
    assert records["lock"].is_file()


def test_a_linked_hooks_folder_is_not_entered(tmp_path):
    plan, _home, first, _second = _plan(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    token = _write(elsewhere / ".hook-hermes.token", TOKEN + "\n")
    (first / "hooks").symlink_to(elsewhere, target_is_directory=True)

    cmd_uninstall._remove_earlier_folder_connector_records(plan)

    assert token.is_file()


def test_an_install_that_never_moved_removes_nothing_extra(tmp_path):
    home = tmp_path / ".defenseclaw"
    home.mkdir()
    plan = cmd_uninstall.UninstallPlan(data_dir=str(home), connectors=("hermes",))
    records = _connector_records(home)
    assert len(plan.record_dirs) == 1

    cmd_uninstall._remove_earlier_folder_connector_records(plan)

    assert all(path.exists() for path in records.values())


def test_the_plan_names_the_install_home_records_it_removes(tmp_path, capsys):
    plan, home, _first, second = _plan(tmp_path)

    cmd_uninstall._render_plan(plan, dry_run=True)
    text = capsys.readouterr().out

    assert "earlier data_dir" in text and f"install home records: {home}" in text
    # With the wipe, the install home goes whole, so the line is not added.
    cmd_uninstall._render_plan(cmd_uninstall.replace(plan, remove_data_dir=True), dry_run=True)
    assert "install home records" not in capsys.readouterr().out


def test_a_user_json_file_beside_a_backup_record_stays(tmp_path):
    plan, _home, first, _second = _plan(tmp_path)
    records = _connector_records(first)
    backups = first / "connector_backups" / "hermes"
    personal = _write(backups / "personal.json", '{"mine": true}\n')
    other_connector = _write(backups / "elsewhere.json", _backup_record("cursor", "elsewhere"))
    renamed = _write(backups / "copy.json", _backup_record("hermes", "config.yaml"))
    keep = _write(backups / "notes.last-good", "the user's copy\n")

    stayed = cmd_uninstall._remove_earlier_folder_connector_records(plan)

    assert stayed == []
    assert not records["backup"].exists() and not records["last_good"].exists()
    for path in (personal, other_connector, renamed, keep):
        assert path.is_file(), path.name
    # The user's files keep the folder-level records with them.
    assert records["lock"].is_file()


def test_a_linked_earlier_folder_is_not_entered(tmp_path):
    plan, _home, first, _second = _plan(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    records = _connector_records(elsewhere)
    for child in list(first.iterdir()):
        child.unlink()
    first.rmdir()
    first.symlink_to(elsewhere, target_is_directory=True)

    stayed = cmd_uninstall._remove_earlier_folder_connector_records(plan)

    assert all(path.exists() for path in records.values())
    assert len(stayed) == 1 and str(first) in stayed[0]


def test_a_record_that_cannot_be_removed_is_reported(tmp_path):
    plan, _home, first, _second = _plan(tmp_path)
    records = _connector_records(first)
    records["token"].parent.chmod(0o500)
    try:
        stayed = cmd_uninstall._remove_earlier_folder_connector_records(plan)
    finally:
        records["token"].parent.chmod(0o700)

    if os.geteuid() != 0:
        assert records["token"].is_file()
        assert any(str(records["token"]) in line for line in stayed), stayed
    # The shared records stay while a credential is left.
    assert records["lock"].is_file()


def test_a_linked_credential_is_reported_not_followed(tmp_path):
    plan, _home, first, _second = _plan(tmp_path)
    records = _connector_records(first)
    outside = _write(tmp_path / "outside-token", TOKEN + "\n")
    records["token"].unlink()
    records["token"].symlink_to(outside)

    stayed = cmd_uninstall._remove_earlier_folder_connector_records(plan)

    assert outside.is_file() and records["token"].is_symlink()
    assert any(str(records["token"]) in line for line in stayed), stayed


def test_another_connectors_backup_keeps_the_shared_records_when_no_hooks_folder_is_left(tmp_path):
    plan, _home, first, _second = _plan(tmp_path)
    records = _connector_records(first)
    for path in (records["script"], records["config_record"], records["home_record"]):
        path.unlink()
    (first / "hooks" / ".hook-hermes.token").unlink()
    (first / "hooks").rmdir()
    other = _write(first / "connector_backups" / "cursor" / "config.yaml.json", _backup_record("cursor", "config.yaml"))

    stayed = cmd_uninstall._remove_earlier_folder_connector_records(plan)

    assert stayed == []
    assert other.is_file() and records["lock"].is_file()
    assert not records["backup"].exists()


def test_the_uninstall_fails_and_names_what_stayed(tmp_path):
    plan, home, first, second = _plan(tmp_path)
    records = _connector_records(first)
    outside = _write(tmp_path / "outside-token", TOKEN + "\n")
    records["token"].unlink()
    records["token"].symlink_to(outside)

    with (
        patch.object(cmd_uninstall, "_validate_plan"),
        patch.object(cmd_uninstall, "_connector_teardown"),
        patch.object(cmd_uninstall, "_turn_guardrail_off"),
        patch.object(cmd_uninstall, "_print_removed_connector_leftovers"),
        patch.object(cmd_uninstall, "_render_execution_result"),
    ):
        result = cmd_uninstall._execute_plan(plan)

    assert not result.succeeded
    left = cmd_uninstall._phases_left(result)
    assert [phase.name for phase in left] == [cmd_uninstall._EARLIER_FOLDER_RECORDS_PHASE]
    assert str(records["token"]) in left[0].detail


def _run_plan_phases(plan):
    with (
        patch.object(cmd_uninstall, "_validate_plan"),
        patch.object(cmd_uninstall, "_connector_teardown"),
        patch.object(cmd_uninstall, "_turn_guardrail_off"),
        patch.object(cmd_uninstall, "_print_removed_connector_leftovers"),
        patch.object(cmd_uninstall, "_render_execution_result"),
    ):
        return cmd_uninstall._execute_plan(plan)


def _plan_below(tmp_path, earlier):
    home, current = tmp_path / ".defenseclaw", tmp_path / "current"
    for folder in (home, current):
        folder.mkdir(exist_ok=True)
    return cmd_uninstall.UninstallPlan(
        data_dir=str(home), store_dir=str(current), previous_stores=(str(earlier),), connectors=("hermes",)
    )


def test_an_earlier_folder_below_a_real_parent_is_cleaned(tmp_path):
    earlier = tmp_path / "parent" / "state"
    records = _connector_records(earlier)

    stayed = cmd_uninstall._remove_earlier_folder_connector_records(_plan_below(tmp_path, earlier))

    assert stayed == []
    assert not records["token"].exists() and not records["lock"].exists()


def test_an_earlier_folder_below_a_parent_that_became_a_link_is_not_entered(tmp_path):
    old_parent, unrelated_parent = tmp_path / "old-parent", tmp_path / "unrelated-parent"
    (old_parent / "state").mkdir(parents=True)
    records = _connector_records(unrelated_parent / "state")
    link = tmp_path / "parent-link"
    link.symlink_to(unrelated_parent, target_is_directory=True)

    stayed = cmd_uninstall._remove_earlier_folder_connector_records(_plan_below(tmp_path, link / "state"))

    assert all(path.exists() for path in records.values()), "a linked ancestor redirected cleanup"
    assert len(stayed) == 1 and str(link) in stayed[0]


def test_a_linked_hooks_folder_fails_the_uninstall_and_keeps_the_shared_records(tmp_path):
    plan, _home, first, _second = _plan(tmp_path)
    records = _connector_records(first)
    outside = tmp_path / "outside-hooks"
    (first / "hooks").rename(outside)
    (first / "hooks").symlink_to(outside, target_is_directory=True)

    result = _run_plan_phases(plan)

    assert (outside / records["token"].name).exists()
    assert records["lock"].is_file()
    assert not result.succeeded
    left = cmd_uninstall._phases_left(result)
    assert [phase.name for phase in left] == [cmd_uninstall._EARLIER_FOLDER_RECORDS_PHASE]
    assert str(first / "hooks") in left[0].detail


def test_a_linked_backup_record_is_reported_not_followed(tmp_path):
    plan, _home, first, _second = _plan(tmp_path)
    records = _connector_records(first)
    outside = _write(tmp_path / "outside-backup.json", records["backup"].read_text())
    records["backup"].unlink()
    records["backup"].symlink_to(outside)

    stayed = cmd_uninstall._remove_earlier_folder_connector_records(plan)

    assert records["backup"].is_symlink() and outside.is_file()
    assert any(str(records["backup"]) in line for line in stayed), stayed
    assert records["lock"].is_file()


def test_a_linked_backup_folder_of_a_connector_is_reported(tmp_path):
    plan, _home, first, _second = _plan(tmp_path)
    records = _connector_records(first)
    outside = tmp_path / "outside-backups"
    (first / "connector_backups" / "hermes").rename(outside)
    (first / "connector_backups" / "hermes").symlink_to(outside, target_is_directory=True)

    stayed = cmd_uninstall._remove_earlier_folder_connector_records(plan)

    assert (outside / records["backup"].name).is_file()
    assert any(str(first / "connector_backups" / "hermes") in line for line in stayed), stayed


def _recorded_folder_with_dotdot(tmp_path):
    """A recorded earlier folder written old-parent/link/../state, read through the real move-history list."""
    from defenseclaw import config

    home, current = tmp_path / ".defenseclaw", tmp_path / "current"
    for folder in (home, current):
        folder.mkdir(exist_ok=True)
    base = tmp_path / "old-parent"
    (base / "state").mkdir(parents=True)
    (base / "link").mkdir()
    earlier = base / "link" / ".." / "state"
    history = home / config.STORE_HISTORY_FILE
    history.write_text(json.dumps({"folders": [str(earlier)]}))
    history.chmod(0o600)
    return home, current, base, earlier


def _previous_stores(home):
    from defenseclaw import config

    with (
        patch.object(config, "default_data_path", return_value=home),
        patch.object(config, "_install_home_binding", return_value=(str(home), None, False)),
    ):
        return config.previous_store_dirs()


def test_a_link_before_dotdot_in_a_recorded_folder_does_not_redirect_cleanup(tmp_path):
    home, current, base, earlier = _recorded_folder_with_dotdot(tmp_path)
    unrelated = tmp_path / "unrelated-parent"
    (unrelated / "child").mkdir(parents=True)
    records = _connector_records(unrelated / "state")
    base.joinpath("link").rmdir()
    base.joinpath("link").symlink_to(unrelated / "child", target_is_directory=True)
    plan = cmd_uninstall.UninstallPlan(
        data_dir=str(home), store_dir=str(current), previous_stores=_previous_stores(home), connectors=("hermes",)
    )

    stayed = cmd_uninstall._remove_earlier_folder_connector_records(plan)

    assert all(path.exists() for path in records.values()), f"records deleted through {earlier}"
    assert len(stayed) == 1 and str(base / "link") in stayed[0], stayed


def test_a_recorded_folder_with_dotdot_through_real_folders_is_cleaned(tmp_path):
    home, current, base, _earlier = _recorded_folder_with_dotdot(tmp_path)
    records = _connector_records(base / "state")
    plan = cmd_uninstall.UninstallPlan(
        data_dir=str(home), store_dir=str(current), previous_stores=_previous_stores(home), connectors=("hermes",)
    )

    stayed = cmd_uninstall._remove_earlier_folder_connector_records(plan)

    assert stayed == []
    assert not records["token"].exists() and not records["lock"].exists()


def test_a_probe_folder_reached_through_a_link_before_dotdot_is_not_a_real_chain(tmp_path):
    root = tmp_path / "home"
    (root / "a").mkdir(parents=True)
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "deep").mkdir(parents=True)
    (root / "link").symlink_to(elsewhere / "deep", target_is_directory=True)

    assert not cmd_uninstall._real_dir_chain(str(root), str(root / "link" / ".." / "a"))
    assert not cmd_uninstall._real_dir_chain(str(root), str(root / "a" / ".." / ".." / "elsewhere"))
    assert cmd_uninstall._real_dir_chain(str(root), str(root / "a" / ".." / "a"))
    assert cmd_uninstall._real_dir_chain(str(root), str(root / "a"))


def test_a_link_to_an_account_file_beside_the_backup_records_does_not_fail_the_uninstall(tmp_path):
    plan, _home, first, _second = _plan(tmp_path)
    records = _connector_records(first)
    mine = _write(tmp_path / "personal.json", "personal notes\n")
    (first / "connector_backups" / "hermes" / "personal.json").symlink_to(mine)

    stayed = cmd_uninstall._remove_earlier_folder_connector_records(plan)
    result = _run_plan_phases(plan)

    assert stayed == [], stayed
    assert result.succeeded, cmd_uninstall._phases_left(result)
    assert (first / "connector_backups" / "hermes" / "personal.json").is_symlink() and mine.is_file()
    assert not records["backup"].exists() and not records["token"].exists()
    assert records["lock"].is_file(), "the folder still holds the account file, so the shared records stay"


def test_a_path_that_folds_to_the_root_through_a_link_is_not_a_real_chain(tmp_path):
    root = tmp_path / "home"
    (root / "a").mkdir(parents=True)
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "deep").mkdir(parents=True)
    (root / "link").symlink_to(elsewhere / "deep", target_is_directory=True)

    assert not cmd_uninstall._real_dir_chain(str(root), str(root / "link" / ".."))
    assert not cmd_uninstall._real_dir_chain(str(root), str(root / "a" / "link" / ".." / ".."))
    assert cmd_uninstall._real_dir_chain(str(root), str(root / "a" / ".."))
    assert cmd_uninstall._real_dir_chain(str(root), str(root))


def _probe_record_for(home, recorded_path):
    """The record agent discovery writes for a probe-created entry, read at its recorded spelling."""
    from defenseclaw.inventory import agent_discovery as ad

    data_dir = home / ".defenseclaw"
    data_dir.mkdir(exist_ok=True)
    record = data_dir / ad.PROBE_STATE_RECORD
    record.write_text(json.dumps({"paths": {recorded_path: ad.probe_state_fingerprint(recorded_path)}, "dirs": []}))
    return data_dir


def test_a_probe_entry_recorded_through_a_link_before_dotdot_is_not_removed_after_the_link_moves(tmp_path, monkeypatch):
    home = (tmp_path / "home").resolve()
    (home / "stage").mkdir(parents=True)
    victim = _write(home / "victim.txt", "probe made this\n")
    (home / "link").symlink_to(home / "stage", target_is_directory=True)
    recorded = str(home / "link" / ".." / "victim.txt")
    data_dir = _probe_record_for(home, recorded)
    outside = tmp_path / "outside"
    (outside / "deep").mkdir(parents=True)
    unrelated = _write(outside / "victim.txt", "probe made this\n")
    os.utime(unrelated, ns=(victim.stat().st_atime_ns, victim.stat().st_mtime_ns))
    (home / "link").unlink()
    (home / "link").symlink_to(outside / "deep", target_is_directory=True)
    monkeypatch.setenv("HOME", str(home))

    cmd_uninstall._remove_probe_created_state(str(data_dir))

    assert unrelated.is_file(), "a file outside the home folder was removed"


def test_a_probe_entry_recorded_through_a_real_folder_before_dotdot_is_removed(tmp_path, monkeypatch):
    home = (tmp_path / "home").resolve()
    (home / "stage").mkdir(parents=True)
    victim = _write(home / "victim.txt", "probe made this\n")
    recorded = str(home / "stage" / ".." / "victim.txt")
    data_dir = _probe_record_for(home, recorded)
    monkeypatch.setenv("HOME", str(home))

    cmd_uninstall._remove_probe_created_state(str(data_dir))

    assert not victim.exists()
