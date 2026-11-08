# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Uninstall removes the connector records `config set data_dir` left in the folders it moved away from."""

from __future__ import annotations

import os

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


def _connector_records(folder, connector="hermes", script="hermes-hook.sh"):
    """What a setup and the move after it leave in a folder, for one connector."""
    return {
        "token": _write(folder / "hooks" / f".hook-{connector}.token", TOKEN + "\n"),
        "script": _write(folder / "hooks" / script, "#!/bin/sh\n" + MARKER, 0o700),
        "config_record": _write(folder / "hooks" / ".config-record", f"{folder}/config.yaml\n"),
        "home_record": _write(folder / "hooks" / ".install-home-record", f"{folder}\n"),
        "lock": _write(folder / "hook_contract_lock.json", "{}\n"),
        "backup": _write(folder / "connector_backups" / connector / "config.yaml.json", "{}\n"),
        "allowlist_backup": _write(folder / "connector_backups" / connector / "shell-hooks-allowlist.json.json", "{}\n"),
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
