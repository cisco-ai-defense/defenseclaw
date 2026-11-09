# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Uninstall removes the Hermes lifecycle lock, plugin answer store and flat hook record left in earlier data folders."""

import json
import os
import signal

import pytest
from click.testing import CliRunner
from defenseclaw import config as config_module
from defenseclaw.commands import cmd_config, cmd_uninstall
from defenseclaw.context import AppContext

from tests.test_config_data_dir_move import _install_home

pytestmark = pytest.mark.skipif(os.name == "nt", reason="needs POSIX modes")

RECORDS = {
    ".hermes-lifecycle.lock": "",
    "hermes-plugin-entrypoints.json": "{\"answers\": {}}\n",
    "hooks/.hookcfg.hermes": "DEFENSECLAW_CONNECTOR=hermes\nDEFENSECLAW_FAIL_MODE=open\nFAIL_MODE_SOURCE=config\n",
}


def _write(folder, records):
    (folder / "hooks").mkdir(exist_ok=True)
    for name, body in records.items():
        (folder / name).write_text(body)
        (folder / name).chmod(0o600)


def _move_and_sweep(tmp_path, monkeypatch, records, connectors=("hermes",)):
    home, _path = _install_home(tmp_path, monkeypatch)
    monkeypatch.setattr(config_module, "_is_admin_process", lambda: False)
    _write(home, records)
    moved = tmp_path / "moved"
    result = CliRunner().invoke(cmd_config.config_cmd, ["set", "data_dir", str(moved)], obj=AppContext())
    assert result.exit_code == 0, result.output
    plan = cmd_uninstall.UninstallPlan(
        data_dir=str(home), store_dir=str(moved),
        previous_stores=config_module.previous_store_dirs(), connectors=tuple(connectors),
    )
    return home, cmd_uninstall._remove_earlier_folder_connector_records(plan)


def test_the_hermes_records_a_move_left_in_the_earlier_folder_are_removed(tmp_path, monkeypatch):
    home, stayed = _move_and_sweep(tmp_path, monkeypatch, RECORDS)

    assert stayed == []
    for name in RECORDS:
        assert not (home / name).exists(), name


@pytest.mark.parametrize(
    ("name", "body"),
    [
        (".hermes-lifecycle.lock", "my notes\n"),
        ("hermes-plugin-entrypoints.json", "{\"answers\": {}, \"mine\": 1}\n"),
        ("hermes-plugin-entrypoints.json", "[]\n"),
        ("hooks/.hookcfg.hermes", "DEFENSECLAW_CONNECTOR=hermes\nDEFENSECLAW_FAIL_MODE=open\nexport MINE=1\n"),
        ("hooks/.hookcfg.hermes", "DEFENSECLAW_CONNECTOR=cursor\nDEFENSECLAW_FAIL_MODE=open\n"),
    ],
)
def test_a_file_of_another_shape_at_a_hermes_record_name_stays_and_is_reported(tmp_path, monkeypatch, name, body):
    home, stayed = _move_and_sweep(tmp_path, monkeypatch, {**RECORDS, name: body})

    assert [line.split(" (")[0] for line in stayed] == [str(home / name)]
    assert (home / name).read_text() == body
    for other in set(RECORDS) - {name}:
        assert not (home / other).exists(), other


def test_the_hermes_records_stay_while_hermes_is_not_torn_down(tmp_path, monkeypatch):
    home, stayed = _move_and_sweep(tmp_path, monkeypatch, RECORDS, connectors=("claudecode",))

    assert stayed == []
    for name in RECORDS:
        assert (home / name).exists(), name


def test_a_link_at_a_hermes_record_name_is_reported_and_not_followed(tmp_path, monkeypatch):
    target = tmp_path / "mine.txt"
    target.write_text("mine\n")
    home, _path = _install_home(tmp_path, monkeypatch)
    monkeypatch.setattr(config_module, "_is_admin_process", lambda: False)
    (home / ".hermes-lifecycle.lock").symlink_to(target)
    moved = tmp_path / "moved"
    result = CliRunner().invoke(cmd_config.config_cmd, ["set", "data_dir", str(moved)], obj=AppContext())
    assert result.exit_code == 0, result.output
    plan = cmd_uninstall.UninstallPlan(
        data_dir=str(home), store_dir=str(moved),
        previous_stores=config_module.previous_store_dirs(), connectors=("hermes",),
    )

    stayed = cmd_uninstall._remove_earlier_folder_connector_records(plan)

    assert any(".hermes-lifecycle.lock" in line for line in stayed)
    assert target.read_text() == "mine\n"


def test_an_answer_store_the_account_edited_after_the_move_is_kept_and_reported(tmp_path, monkeypatch):
    home, plan = _move_and_plan(tmp_path, monkeypatch)
    edited = {"answers": {"personal": {"note": "keep this"}}}
    (home / "hermes-plugin-entrypoints.json").write_text(json.dumps(edited))

    stayed = cmd_uninstall._remove_earlier_folder_connector_records(plan)

    assert json.loads((home / "hermes-plugin-entrypoints.json").read_text()) == edited
    assert [line.split(" (")[0] for line in stayed] == [str(home / "hermes-plugin-entrypoints.json")]
    for name in (".hermes-lifecycle.lock", "hooks/.hookcfg.hermes"):
        assert not (home / name).exists(), name


def test_a_record_edited_after_the_move_stays_even_when_it_keeps_the_shape_setup_writes(tmp_path, monkeypatch):
    home, plan = _move_and_plan(tmp_path, monkeypatch)
    edited = "DEFENSECLAW_CONNECTOR=hermes\nDEFENSECLAW_FAIL_MODE=closed\n"
    (home / "hooks" / ".hookcfg.hermes").write_text(edited)

    stayed = cmd_uninstall._remove_earlier_folder_connector_records(plan)

    assert (home / "hooks" / ".hookcfg.hermes").read_text() == edited
    assert len(stayed) == 1


@pytest.mark.parametrize("kind", ["link to a pipe", "pipe"])
def test_a_link_or_pipe_at_a_hermes_record_name_is_reported_and_never_opened(tmp_path, monkeypatch, kind):
    home, plan = _move_and_plan(tmp_path, monkeypatch)
    record = home / "hermes-plugin-entrypoints.json"
    record.unlink()
    pipe = tmp_path / "pipe" if kind == "link to a pipe" else record
    os.mkfifo(pipe)
    if pipe != record:
        record.symlink_to(pipe)

    def blocked(_signum, _frame):
        raise AssertionError("cleanup waited on the pipe")

    previous = signal.signal(signal.SIGALRM, blocked)
    signal.alarm(5)
    try:
        stayed = cmd_uninstall._remove_earlier_folder_connector_records(plan)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)

    assert any(str(record) in line for line in stayed)
    assert os.path.lexists(record)


def _move_and_plan(tmp_path, monkeypatch):
    home, _path = _install_home(tmp_path, monkeypatch)
    monkeypatch.setattr(config_module, "_is_admin_process", lambda: False)
    _write(home, RECORDS)
    moved = tmp_path / "moved"
    result = CliRunner().invoke(cmd_config.config_cmd, ["set", "data_dir", str(moved)], obj=AppContext())
    assert result.exit_code == 0, result.output
    plan = cmd_uninstall.UninstallPlan(
        data_dir=str(home), store_dir=str(moved),
        previous_stores=config_module.previous_store_dirs(), connectors=("hermes",),
    )
    return home, plan
