# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Uninstall removes the Claude Code and Codex backup records `config set data_dir` copied into every earlier folder."""

import json
import os

import pytest
from click.testing import CliRunner
from defenseclaw import config as config_module
from defenseclaw.commands import cmd_config, cmd_uninstall
from defenseclaw.context import AppContext

from tests.test_config_data_dir_move import _install_home

pytestmark = pytest.mark.skipif(os.name == "nt", reason="needs symlink rights and POSIX modes")

CLAUDE = '{"had_hooks_key": true, "original_hooks": null}\n'
CODEX = '{"had_hooks_key": false, "added_codex_hooks_flag": true}\n'


def _move(value):
    result = CliRunner().invoke(cmd_config.config_cmd, ["set", "data_dir", str(value)], obj=AppContext())
    assert result.exit_code == 0, result.output


def _plan(home, store, connectors):
    return cmd_uninstall.UninstallPlan(
        data_dir=str(home),
        store_dir=str(store),
        previous_stores=config_module.previous_store_dirs(),
        connectors=tuple(connectors),
    )


def _setup_backups(home):
    (home / "claudecode_backup.json").write_text(CLAUDE)
    (home / "codex_config_backup.json").write_text(CODEX)
    for name in ("claudecode_backup.json", "codex_config_backup.json"):
        (home / name).chmod(0o600)
    (home / "agent_discovery.json").write_text('{"agents": {}}\n')


def test_the_backup_copies_every_move_left_are_removed_for_the_connectors_torn_down(tmp_path, monkeypatch):
    home, _path = _install_home(tmp_path, monkeypatch)
    monkeypatch.setattr(config_module, "_is_admin_process", lambda: False)
    _setup_backups(home)
    first, second, third = (tmp_path / name for name in ("state", "state2", "state2/inner"))
    for folder in (first, second, third):
        _move(folder)
    for folder in (home, first, second):
        assert (folder / "claudecode_backup.json").is_file(), f"the move copied it to {folder}"

    stayed = cmd_uninstall._remove_earlier_folder_connector_records(_plan(home, third, ["claudecode", "codex"]))

    assert stayed == []
    for folder in (home, first, second):
        assert not (folder / "claudecode_backup.json").exists(), folder
        assert not (folder / "codex_config_backup.json").exists(), folder
        assert (folder / "agent_discovery.json").is_file(), "other files stay"
    # The folder config.yaml names is the connector teardown's.
    assert (third / "claudecode_backup.json").is_file() and (third / "codex_config_backup.json").is_file()


def test_a_connector_that_is_not_torn_down_keeps_its_backup_and_the_folder_records(tmp_path, monkeypatch):
    home, _path = _install_home(tmp_path, monkeypatch)
    monkeypatch.setattr(config_module, "_is_admin_process", lambda: False)
    _setup_backups(home)
    (home / "hook_contract_lock.json").write_text("{}\n")
    (home / "hook_contract_lock.json").chmod(0o600)
    first = tmp_path / "state"
    _move(first)

    stayed = cmd_uninstall._remove_earlier_folder_connector_records(_plan(home, first, ["codex"]))

    assert stayed == []
    assert not (home / "codex_config_backup.json").exists()
    assert (home / "claudecode_backup.json").is_file()
    assert (home / "hook_contract_lock.json").is_file(), "the folder record stays while a connector's backup does"


def test_a_file_of_another_shape_at_the_name_is_the_accounts_own(tmp_path, monkeypatch):
    home, _path = _install_home(tmp_path, monkeypatch)
    monkeypatch.setattr(config_module, "_is_admin_process", lambda: False)
    (home / "claudecode_backup.json").write_text('{"notes": "mine"}\n')
    (home / "codex_config_backup.json").write_text("not json\n")
    first = tmp_path / "state"
    first.mkdir()

    stayed = cmd_uninstall._remove_earlier_folder_connector_records(_plan(home, first, ["claudecode", "codex"]))

    assert stayed == []
    assert (home / "claudecode_backup.json").read_text() == '{"notes": "mine"}\n'
    assert (home / "codex_config_backup.json").is_file()


def test_a_link_at_the_name_of_a_backup_is_reported_and_not_followed(tmp_path, monkeypatch):
    home, _path = _install_home(tmp_path, monkeypatch)
    monkeypatch.setattr(config_module, "_is_admin_process", lambda: False)
    target = tmp_path / "elsewhere.json"
    target.write_text(CLAUDE)
    (home / "claudecode_backup.json").symlink_to(target)
    first = tmp_path / "state"
    first.mkdir()

    stayed = cmd_uninstall._remove_earlier_folder_connector_records(_plan(home, first, ["claudecode"]))

    assert len(stayed) == 1 and "claudecode_backup.json" in stayed[0]
    assert target.read_text() == CLAUDE


def _record(**fields):
    return json.dumps(fields, indent=2) + "\n"


def test_a_backup_the_user_edited_to_hold_their_own_data_is_kept_after_a_move(tmp_path, monkeypatch):
    home, _path = _install_home(tmp_path, monkeypatch)
    monkeypatch.setattr(config_module, "_is_admin_process", lambda: False)
    _setup_backups(home)
    first = tmp_path / "state"
    _move(first)
    mine = _record(had_hooks_key=False, notes="my own data")
    (home / "claudecode_backup.json").write_text(mine)
    (home / "claudecode_backup.json").chmod(0o600)

    stayed = cmd_uninstall._remove_earlier_folder_connector_records(_plan(home, first, ["claudecode", "codex"]))

    assert stayed == []
    assert (home / "claudecode_backup.json").read_text() == mine
    assert not (home / "codex_config_backup.json").exists(), "the record Setup wrote is still removed"


def test_the_earlier_codex_backup_a_move_copied_is_removed_with_the_current_one(tmp_path, monkeypatch):
    home, _path = _install_home(tmp_path, monkeypatch)
    monkeypatch.setattr(config_module, "_is_admin_process", lambda: False)
    legacy = _record(had_base_url=True, old_base_url="https://api.example.invalid/v1")
    (home / "codex_backup.json").write_text(legacy)
    (home / "codex_backup.json").chmod(0o600)
    first, second = tmp_path / "state", tmp_path / "state2"
    _move(first)
    _move(second)
    assert (first / "codex_backup.json").read_text() == legacy, "the move copied it"

    stayed = cmd_uninstall._remove_earlier_folder_connector_records(_plan(home, second, ["codex"]))

    assert stayed == []
    assert not (home / "codex_backup.json").exists()
    assert not (first / "codex_backup.json").exists()


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("codex_backup.json", _record(had_base_url=True, old_base_url="x", notes="mine")),
        ("codex_backup.json", _record(had_base_url="yes", old_base_url="x")),
        ("codex_config_backup.json", _record(had_hooks_key=False, added_codex_hooks_flag=False, notes="mine")),
        ("claudecode_backup.json", _record(original_hooks=None)),
    ],
)
def test_a_file_that_is_not_the_record_setup_writes_stays(tmp_path, monkeypatch, name, text):
    home, _path = _install_home(tmp_path, monkeypatch)
    monkeypatch.setattr(config_module, "_is_admin_process", lambda: False)
    (home / name).write_text(text)
    (home / name).chmod(0o600)
    first = tmp_path / "state"
    first.mkdir()

    stayed = cmd_uninstall._remove_earlier_folder_connector_records(_plan(home, first, ["claudecode", "codex"]))

    assert stayed == []
    assert (home / name).read_text() == text


@pytest.mark.parametrize(
    "edited",
    [
        {"had_hooks_key": True, "original_hooks": {"user_notes": ["keep this"]}},
        {"had_hooks_key": False, "original_hooks": None},
        {"had_hooks_key": True, "original_hooks": None, "had_env_key": True},
    ],
)
def test_a_backup_the_account_edited_after_the_move_is_kept_even_inside_a_field_setup_writes(tmp_path, monkeypatch, edited):
    home, _path = _install_home(tmp_path, monkeypatch)
    monkeypatch.setattr(config_module, "_is_admin_process", lambda: False)
    _setup_backups(home)
    moved = tmp_path / "state"
    _move(moved)
    (home / "claudecode_backup.json").write_text(json.dumps(edited))

    stayed = cmd_uninstall._remove_earlier_folder_connector_records(_plan(home, moved, ["claudecode"]))

    assert stayed == []
    assert json.loads((home / "claudecode_backup.json").read_text()) == edited


def test_only_the_folder_whose_copy_was_edited_keeps_it_after_two_moves(tmp_path, monkeypatch):
    home, _path = _install_home(tmp_path, monkeypatch)
    monkeypatch.setattr(config_module, "_is_admin_process", lambda: False)
    _setup_backups(home)
    first, second = tmp_path / "state", tmp_path / "state2"
    _move(first)
    _move(second)
    (first / "claudecode_backup.json").write_text(json.dumps({"had_hooks_key": True, "original_hooks": {"mine": []}}))

    stayed = cmd_uninstall._remove_earlier_folder_connector_records(_plan(home, second, ["claudecode"]))

    assert stayed == []
    assert not (home / "claudecode_backup.json").exists()
    assert json.loads((first / "claudecode_backup.json").read_text())["original_hooks"] == {"mine": []}


def test_many_other_backup_named_files_do_not_make_the_folder_history_unreadable(tmp_path, monkeypatch):
    home, _path = _install_home(tmp_path, monkeypatch)
    monkeypatch.setattr(config_module, "_is_admin_process", lambda: False)
    _setup_backups(home)
    for index in range(400):
        (home / (f"{index:04d}-" + "x" * 125 + "_backup.json")).write_text("{}\n")
    first, second = tmp_path / "first", tmp_path / "second"
    _move(first)
    _move(second)

    history = home / config_module.STORE_HISTORY_FILE
    assert history.stat().st_size < config_module._STORE_HISTORY_MAX_BYTES // 4
    assert str(first) in config_module.previous_store_dirs()
    stayed = cmd_uninstall._remove_earlier_folder_connector_records(_plan(home, second, ["claudecode", "codex"]))
    assert stayed == []
    assert not (home / "claudecode_backup.json").exists()
    assert (home / ("0000-" + "x" * 125 + "_backup.json")).exists(), "a file of the account at another name stays"
