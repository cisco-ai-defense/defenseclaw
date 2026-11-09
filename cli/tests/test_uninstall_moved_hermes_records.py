# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Uninstall removes the Hermes lifecycle lock, plugin answer store and flat hook record left in earlier data folders."""

import json
import os
import signal
from unittest.mock import patch

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


GATEWAY_ANSWERS = {
    "b" * 64: {"entrypoints": ["plugins/a/__init__.py", "plugins/é/x.py"], "seen": 1789012345678901234},
    "a" * 64: {"entrypoints": [], "seen": 7},
}


def _moved_plan(tmp_path, monkeypatch, records):
    # Move with the given records in the folder; the sweep is left to the test.
    home, _path = _install_home(tmp_path, monkeypatch)
    monkeypatch.setattr(config_module, "_is_admin_process", lambda: False)
    _write(home, records)
    moved = tmp_path / "moved"
    result = CliRunner().invoke(cmd_config.config_cmd, ["set", "data_dir", str(moved)], obj=AppContext())
    assert result.exit_code == 0, result.output
    return home, cmd_uninstall.UninstallPlan(
        data_dir=str(home), store_dir=str(moved),
        previous_stores=config_module.previous_store_dirs(), connectors=("hermes",),
    )


def _execute_earlier_folder_phase(plan):
    """_execute_plan with the teardown phases that are not under test stubbed out."""
    with (
        patch.object(cmd_uninstall, "_validate_plan"),
        patch.object(cmd_uninstall, "_connector_teardown"),
        patch.object(cmd_uninstall, "_turn_guardrail_off"),
        patch.object(cmd_uninstall, "_print_removed_connector_leftovers"),
        patch.object(cmd_uninstall, "_render_execution_result"),
    ):
        return cmd_uninstall._execute_plan(plan)


def test_a_cache_the_gateway_rewrote_after_the_move_is_kept_named_and_does_not_fail_the_uninstall(
    tmp_path, monkeypatch, capsys,
):
    # The gateway still running in the folder rewrites its scanner cache after the move. DefenseClaw cannot prove
    # who wrote it (the account can write the same bytes), so the file is kept; it holds scanner answers and no
    # credential, so keeping it is named in the output and the uninstall still succeeds.
    home, plan = _move_and_plan(tmp_path, monkeypatch)
    cache = home / "hermes-plugin-entrypoints.json"
    later = json.dumps({"answers": GATEWAY_ANSWERS}, separators=(",", ":"))
    cache.write_text(later)

    result = _execute_earlier_folder_phase(plan)

    assert cache.read_text() == later
    assert result.succeeded
    assert cmd_uninstall._phases_left(result) == []
    shown = capsys.readouterr()
    assert str(cache) in shown.out + shown.err
    assert "no longer the copy the move recorded" in shown.out + shown.err
    for name in (".hermes-lifecycle.lock", "hooks/.hookcfg.hermes"):
        assert not (home / name).exists(), name


def test_a_cache_the_gateway_wrote_where_the_move_found_none_is_kept_named_and_does_not_fail_the_uninstall(
    tmp_path, monkeypatch, capsys,
):
    records = {name: body for name, body in RECORDS.items() if name != "hermes-plugin-entrypoints.json"}
    home, plan = _moved_plan(tmp_path, monkeypatch, records)
    cache = home / "hermes-plugin-entrypoints.json"
    cache.write_text(json.dumps({"answers": GATEWAY_ANSWERS}, separators=(",", ":")))

    result = _execute_earlier_folder_phase(plan)

    assert cache.exists()
    assert result.succeeded
    shown = capsys.readouterr()
    assert str(cache) in shown.out + shown.err


def test_a_changed_hook_record_still_fails_the_uninstall_beside_a_kept_cache(tmp_path, monkeypatch):
    # Only the gateway's scanner answers are a named leftover; any other record DefenseClaw wrote that is not
    # removed keeps the phase failed.
    home, plan = _move_and_plan(tmp_path, monkeypatch)
    (home / "hermes-plugin-entrypoints.json").write_text(json.dumps({"answers": GATEWAY_ANSWERS}))
    (home / "hooks" / ".hookcfg.hermes").write_text("DEFENSECLAW_CONNECTOR=hermes\nDEFENSECLAW_FAIL_MODE=closed\n")

    result = _execute_earlier_folder_phase(plan)

    assert not result.succeeded
    left = cmd_uninstall._phases_left(result)
    assert [phase.name for phase in left] == [cmd_uninstall._EARLIER_FOLDER_RECORDS_PHASE]
    assert ".hookcfg.hermes" in left[0].detail
    assert "hermes-plugin-entrypoints.json" not in left[0].detail


def test_a_cache_with_answers_is_removed_while_it_is_the_copy_the_move_recorded(tmp_path, monkeypatch):
    body = json.dumps({"answers": GATEWAY_ANSWERS}, separators=(",", ":"))
    home, stayed = _move_and_sweep(tmp_path, monkeypatch, {**RECORDS, "hermes-plugin-entrypoints.json": body})

    assert stayed == []
    assert not (home / "hermes-plugin-entrypoints.json").exists()


@pytest.mark.parametrize(
    "body",
    [
        {"answers": {"b" * 64: {"note": "mine"}}},
        {"answers": {"b" * 64: {"entrypoints": [7], "seen": 1}}},
        {"answers": {"b" * 64: {"entrypoints": [], "seen": True}}},
        {"answers": {"b" * 64: {"entrypoints": [], "seen": 1.5}}},
        {"answers": {"b" * 64: {"entrypoints": [], "seen": 2**63}}},
        {"answers": {"b" * 64: {"entrypoints": [], "seen": 1, "note": "mine"}}},
        {"answers": {"b" * 64: {"entrypoints": None, "seen": 1}}},
        {"answers": {"b" * 64: "mine"}},
    ],
)
def test_an_answer_cache_the_writer_cannot_emit_that_is_there_at_the_move_is_kept_and_reported(
    tmp_path, monkeypatch, body,
):
    text = json.dumps(body)
    home, stayed = _move_and_sweep(tmp_path, monkeypatch, {**RECORDS, "hermes-plugin-entrypoints.json": text})

    assert (home / "hermes-plugin-entrypoints.json").read_text() == text
    assert [line.split(" (")[0] for line in stayed] == [str(home / "hermes-plugin-entrypoints.json")]


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
