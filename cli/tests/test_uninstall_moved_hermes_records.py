# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Uninstall removes the Hermes lifecycle lock, plugin answer store and flat hook record left in earlier data folders."""

import hashlib
import json
import os
import signal
from pathlib import Path
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


def _record_like_the_gateway(home, name):
    """Record the bytes now at *name* in the list, as RecordEarlierDataDirWrite does in the step that writes them."""
    path = Path(config_module._store_history_path())
    document = json.loads(path.read_text())
    digest = hashlib.sha256((home / name).read_bytes()).hexdigest()
    document.setdefault("backups", {}).setdefault(str(home), {})[name] = digest
    path.write_text(json.dumps(document, indent=2) + "\n")
    path.chmod(0o600)


def test_a_cache_the_gateway_rewrote_and_recorded_after_the_move_is_removed_and_the_uninstall_succeeds(
    tmp_path, monkeypatch,
):
    # The gateway still running in the folder rewrites its scanner cache after the move and records the write in
    # the same step: uninstall sees its own rewrite as its own.
    home, plan = _move_and_plan(tmp_path, monkeypatch)
    cache = home / "hermes-plugin-entrypoints.json"
    cache.write_text(json.dumps({"answers": GATEWAY_ANSWERS}, separators=(",", ":")))
    _record_like_the_gateway(home, "hermes-plugin-entrypoints.json")

    result = _execute_earlier_folder_phase(plan)

    assert result.succeeded
    assert cmd_uninstall._phases_left(result) == []
    for name in RECORDS:
        assert not (home / name).exists(), name


def test_a_cache_the_account_edited_after_the_gateway_recorded_its_write_is_kept_named_and_does_not_fail(
    tmp_path, monkeypatch, capsys,
):
    home, plan = _move_and_plan(tmp_path, monkeypatch)
    cache = home / "hermes-plugin-entrypoints.json"
    cache.write_text(json.dumps({"answers": GATEWAY_ANSWERS}, separators=(",", ":")))
    _record_like_the_gateway(home, "hermes-plugin-entrypoints.json")
    edited = json.dumps({"answers": {**GATEWAY_ANSWERS, "c" * 64: {"entrypoints": ["mine.py"], "seen": 3}}})
    cache.write_text(edited)

    result = _execute_earlier_folder_phase(plan)

    assert cache.read_text() == edited
    assert result.succeeded
    shown = capsys.readouterr()
    assert str(cache) in shown.out + shown.err
    assert "no longer the copy DefenseClaw recorded" in shown.out + shown.err


def test_a_cache_rewritten_by_a_gateway_that_recorded_nothing_is_kept_named_and_does_not_fail_the_uninstall(
    tmp_path, monkeypatch, capsys,
):
    # A gateway of an older release rewrites the cache and records nothing: DefenseClaw cannot tell that write
    # from an edit by the account, so the file is kept and named; it holds no credential, so the uninstall succeeds.
    home, plan = _move_and_plan(tmp_path, monkeypatch)
    cache = home / "hermes-plugin-entrypoints.json"
    later = json.dumps({"answers": GATEWAY_ANSWERS}, separators=(",", ":"))
    cache.write_text(later)

    result = _execute_earlier_folder_phase(plan)

    assert cache.read_text() == later
    assert result.succeeded
    shown = capsys.readouterr()
    assert str(cache) in shown.out + shown.err
    for name in (".hermes-lifecycle.lock", "hooks/.hookcfg.hermes"):
        assert not (home / name).exists(), name


def test_a_cache_the_gateway_wrote_and_recorded_where_the_move_found_none_is_removed(tmp_path, monkeypatch):
    records = {name: body for name, body in RECORDS.items() if name != "hermes-plugin-entrypoints.json"}
    home, plan = _moved_plan(tmp_path, monkeypatch, records)
    cache = home / "hermes-plugin-entrypoints.json"
    cache.write_text(json.dumps({"answers": GATEWAY_ANSWERS}, separators=(",", ":")))
    _record_like_the_gateway(home, "hermes-plugin-entrypoints.json")

    result = _execute_earlier_folder_phase(plan)

    assert result.succeeded
    assert not cache.exists()


def test_a_cache_the_account_made_where_the_move_found_none_is_kept_and_named(tmp_path, monkeypatch, capsys):
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


_ANSWER = "{\"entrypoints\":[],\"seen\":1}"


@pytest.mark.parametrize(
    ("body", "key"),
    [
        ("{\"answers\":{\"personal\":{\"note\":\"mine\"}},\"answers\":{}}", "answers"),
        ("{\"answers\":{\"" + "a" * 64 + "\":" + _ANSWER + ",\"" + "a" * 64 + "\":" + _ANSWER + "}}", "a" * 64),
        ("{\"answers\":{\"" + "a" * 64 + "\":{\"entrypoints\":[],\"seen\":1,\"seen\":2}}}", "seen"),
        ("{\"answers\":{\"" + "a" * 64 + "\":{\"entrypoints\":[],\"entrypoints\":[\"x\"],\"seen\":1}}}", "entrypoints"),
    ],
)
def test_an_answer_cache_with_a_key_given_twice_is_kept_and_named_with_the_reason(tmp_path, monkeypatch, body, key):
    home, stayed = _move_and_sweep(tmp_path, monkeypatch, {**RECORDS, "hermes-plugin-entrypoints.json": body})

    cache = home / "hermes-plugin-entrypoints.json"
    assert cache.read_text() == body
    assert len(stayed) == 1
    assert stayed[0].startswith(str(cache))
    assert "given twice" in stayed[0]
    assert key in stayed[0]


def test_an_answer_cache_that_is_not_json_is_kept_and_named_with_the_reason(tmp_path, monkeypatch):
    home, stayed = _move_and_sweep(tmp_path, monkeypatch, {**RECORDS, "hermes-plugin-entrypoints.json": "{\"answers\""})

    assert (home / "hermes-plugin-entrypoints.json").read_text() == "{\"answers\""
    assert len(stayed) == 1
    assert stayed[0].startswith(str(home / "hermes-plugin-entrypoints.json"))
    assert "not JSON" in stayed[0]


def test_a_gateway_record_does_not_make_a_cache_with_a_key_given_twice_removable(tmp_path, monkeypatch):
    # Even when the digest in the list matches the file, a file the gateway cannot have written stays.
    body = "{\"answers\":{\"personal\":{\"note\":\"mine\"}},\"answers\":{}}"
    home, plan = _move_and_plan(tmp_path, monkeypatch)
    cache = home / "hermes-plugin-entrypoints.json"
    cache.write_text(body)
    _record_like_the_gateway(home, "hermes-plugin-entrypoints.json")

    stayed = cmd_uninstall._remove_earlier_folder_connector_records(plan)

    assert cache.read_text() == body
    assert len(stayed) == 1


def test_a_setup_backup_record_with_a_key_given_twice_is_not_removed(tmp_path, monkeypatch):
    home, _path = _install_home(tmp_path, monkeypatch)
    monkeypatch.setattr(config_module, "_is_admin_process", lambda: False)
    body = "{\"had_hooks_key\":true,\"had_hooks_key\":false}"
    (home / "claudecode_backup.json").write_text(body)
    (home / "claudecode_backup.json").chmod(0o600)
    moved = tmp_path / "moved"
    result = CliRunner().invoke(cmd_config.config_cmd, ["set", "data_dir", str(moved)], obj=AppContext())
    assert result.exit_code == 0, result.output
    plan = cmd_uninstall.UninstallPlan(
        data_dir=str(home), store_dir=str(moved),
        previous_stores=config_module.previous_store_dirs(), connectors=("claudecode",),
    )

    cmd_uninstall._remove_earlier_folder_connector_records(plan)

    assert (home / "claudecode_backup.json").read_text() == body
