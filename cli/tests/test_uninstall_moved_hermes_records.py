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
    "hermes-plugin-entrypoints.json": "{\"answers\":{}}",
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


def test_an_answer_store_the_account_edited_after_the_move_is_moved_aside_and_named(tmp_path, monkeypatch, capsys):
    home, plan = _move_and_plan(tmp_path, monkeypatch)
    edited = json.dumps({"answers": {"personal": {"note": "keep this"}}})
    (home / "hermes-plugin-entrypoints.json").write_text(edited)

    stayed = cmd_uninstall._remove_earlier_folder_connector_records(plan)

    assert stayed == []
    assert not (home / "hermes-plugin-entrypoints.json").exists()
    assert (home / "hermes-plugin-entrypoints.json.moved-aside").read_text() == edited
    shown = capsys.readouterr()
    assert str(home / "hermes-plugin-entrypoints.json") in shown.out + shown.err
    for name in (".hermes-lifecycle.lock", "hooks/.hookcfg.hermes"):
        assert not (home / name).exists(), name


GATEWAY_ANSWERS = {
    "b" * 64: {"entrypoints": ["plugins/a/__init__.py", "plugins/é/x.py"], "seen": 1789012345678901234},
    "a" * 64: {"entrypoints": [], "seen": 7},
}


def _gateway_text(answers):
    """The bytes the gateway writes for *answers* (json.Marshal: keys sorted, no space, non-ASCII raw)."""
    return json.dumps({"answers": answers}, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


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
    cache.write_text(_gateway_text(GATEWAY_ANSWERS))
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
    cache.write_text(_gateway_text(GATEWAY_ANSWERS))
    _record_like_the_gateway(home, "hermes-plugin-entrypoints.json")
    edited = _gateway_text({**GATEWAY_ANSWERS, "c" * 64: {"entrypoints": ["mine.py"], "seen": 3}})
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
    later = _gateway_text(GATEWAY_ANSWERS)
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
    cache.write_text(_gateway_text(GATEWAY_ANSWERS))
    _record_like_the_gateway(home, "hermes-plugin-entrypoints.json")

    result = _execute_earlier_folder_phase(plan)

    assert result.succeeded
    assert not cache.exists()


def test_a_cache_the_account_made_where_the_move_found_none_is_kept_and_named(tmp_path, monkeypatch, capsys):
    records = {name: body for name, body in RECORDS.items() if name != "hermes-plugin-entrypoints.json"}
    home, plan = _moved_plan(tmp_path, monkeypatch, records)
    cache = home / "hermes-plugin-entrypoints.json"
    cache.write_text(_gateway_text(GATEWAY_ANSWERS))

    result = _execute_earlier_folder_phase(plan)

    assert cache.exists()
    assert result.succeeded
    shown = capsys.readouterr()
    assert str(cache) in shown.out + shown.err


def test_a_changed_hook_record_still_fails_the_uninstall_beside_a_kept_cache(tmp_path, monkeypatch):
    # Only the gateway's scanner answers are a named leftover; any other record DefenseClaw wrote that is not
    # removed keeps the phase failed.
    home, plan = _move_and_plan(tmp_path, monkeypatch)
    (home / "hermes-plugin-entrypoints.json").write_text(_gateway_text(GATEWAY_ANSWERS))
    (home / "hooks" / ".hookcfg.hermes").write_text("DEFENSECLAW_CONNECTOR=hermes\nDEFENSECLAW_FAIL_MODE=closed\n")

    result = _execute_earlier_folder_phase(plan)

    assert not result.succeeded
    left = cmd_uninstall._phases_left(result)
    assert [phase.name for phase in left] == [cmd_uninstall._EARLIER_FOLDER_RECORDS_PHASE]
    assert ".hookcfg.hermes" in left[0].detail
    assert "hermes-plugin-entrypoints.json" not in left[0].detail


def test_a_cache_with_answers_is_removed_while_it_is_the_copy_the_move_recorded(tmp_path, monkeypatch):
    body = _gateway_text(GATEWAY_ANSWERS)
    home, stayed = _move_and_sweep(tmp_path, monkeypatch, {**RECORDS, "hermes-plugin-entrypoints.json": body})

    assert stayed == []
    assert not (home / "hermes-plugin-entrypoints.json").exists()


_ONE = "{\"entrypoints\":[],\"seen\":1}"
_KEY = "\"" + "a" * 64 + "\""
# Cache files the gateway cannot have written, each with a word of the reason it is named with.
NOT_THE_GATEWAYS_BYTES = [
    ("{\"answers\":{\"" + "b" * 64 + "\":{\"note\":\"mine\"}}}", "exactly the keys"),
    ("{\"answers\":{\"" + "b" * 64 + "\":{\"entrypoints\":[7],\"seen\":1}}}", "not strings"),
    ("{\"answers\":{\"" + "b" * 64 + "\":{\"entrypoints\":[],\"seen\":true}}}", "64-bit"),
    ("{\"answers\":{\"" + "b" * 64 + "\":{\"entrypoints\":[],\"seen\":1.5}}}", "64-bit"),
    ("{\"answers\":{\"" + "b" * 64 + "\":{\"entrypoints\":[],\"seen\":" + str(2**63) + "}}}", "64-bit"),
    ("{\"answers\":{\"" + "b" * 64 + "\":{\"entrypoints\":[],\"seen\":1,\"note\":\"mine\"}}}", "exactly the keys"),
    ("{\"answers\":{\"" + "b" * 64 + "\":{\"entrypoints\":null,\"seen\":1}}}", "not strings"),
    ("{\"answers\":{\"" + "b" * 64 + "\":\"mine\"}}", "exactly the keys"),
    # a key given twice, at each level
    ("{\"answers\":{\"personal\":{\"note\":\"mine\"}},\"answers\":{}}", "given twice"),
    ("{\"answers\":{" + _KEY + ":" + _ONE + "," + _KEY + ":" + _ONE + "}}", "given twice"),
    ("{\"answers\":{" + _KEY + ":{\"entrypoints\":[],\"seen\":1,\"seen\":2}}}", "given twice"),
    ("{\"answers\":{" + _KEY + ":{\"entrypoints\":[],\"entrypoints\":[\"x\"],\"seen\":1}}}", "given twice"),
    # not JSON
    ("{\"answers\"", "not JSON"),
    # a string the writer cannot emit: an unpaired surrogate, in an entrypoint or in a key
    ("{\"entrypoints\":[\"\\ud800\"],\"seen\":1}".join(("{\"answers\":{" + _KEY + ":", "}}")), "surrogate"),
    ("{\"answers\":{\"" + "\\udc00" + "\":" + _ONE + "}}", "surrogate"),
    # a key the writer cannot originate: not a manifest digest
    ("{\"answers\":{\"personal\":" + _ONE + "}}", "manifest digest"),
    ("{\"answers\":{\"" + "A" * 64 + "\":" + _ONE + "}}", "manifest digest"),
    # the writer's values with another spelling, spacing or order
    ("{\"answers\": {" + _KEY + ":" + _ONE + "}}", "bytes are not what the gateway writes"),
    ("{\"answers\":{" + _KEY + ":" + _ONE + "}}\n", "bytes are not what the gateway writes"),
    ("{\"answers\":{" + _KEY + ":{\"seen\":1,\"entrypoints\":[]}}}", "bytes are not what the gateway writes"),
    ("{\"answers\":{\"" + "b" * 64 + "\":" + _ONE + "," + _KEY + ":" + _ONE + "}}", "bytes are not what the gateway writes"),
    ("{\"answers\":{" + _KEY + ":{\"entrypoints\":[\"\\u0061\"],\"seen\":1}}}", "bytes are not what the gateway writes"),
    ("{\"answers\":{" + _KEY + ":{\"entrypoints\":[\"a<b\"],\"seen\":1}}}", "bytes are not what the gateway writes"),
    ("{\"answers\":{" + _KEY + ":{\"entrypoints\":[\"\\ud83d\\ude00\"],\"seen\":1}}}", "bytes are not what the gateway writes"),
    ("[]", "only key is answers"),
    ("{\"answers\":{},\"mine\":1}", "only key is answers"),
    ("{\"answers\":{" + ",".join(f"\"{n:064x}\":{_ONE}" for n in range(257)) + "}}", "more answers"),
]


def _cache_moved_aside(home, body, capsys):
    cache = home / "hermes-plugin-entrypoints.json"
    aside = home / "hermes-plugin-entrypoints.json.moved-aside"
    assert not cache.exists()
    assert aside.read_bytes() == body.encode("utf-8", "surrogatepass")
    shown = capsys.readouterr()
    return shown.out + shown.err, str(cache), str(aside)


@pytest.mark.parametrize(("body", "reason"), NOT_THE_GATEWAYS_BYTES)
def test_an_answer_cache_the_writer_cannot_emit_is_moved_aside_and_named_with_the_reason(
    tmp_path, monkeypatch, capsys, body, reason,
):
    # Present at the move, so the move recorded its digest by name: that digest must not make it removable.
    home, stayed = _move_and_sweep(tmp_path, monkeypatch, {**RECORDS, "hermes-plugin-entrypoints.json": body})

    assert stayed == []
    shown, cache, aside = _cache_moved_aside(home, body, capsys)
    assert cache in shown
    assert aside in shown
    assert reason in shown
    for name in set(RECORDS) - {"hermes-plugin-entrypoints.json"}:
        assert not (home / name).exists(), name


@pytest.mark.parametrize(("body", "reason"), NOT_THE_GATEWAYS_BYTES)
def test_a_gateway_record_does_not_make_a_cache_the_writer_cannot_emit_removable(
    tmp_path, monkeypatch, capsys, body, reason,
):
    # Even when the digest in the list matches the file, a file the gateway cannot have written is moved aside.
    home, plan = _move_and_plan(tmp_path, monkeypatch)
    (home / "hermes-plugin-entrypoints.json").write_bytes(body.encode("utf-8", "surrogatepass"))
    _record_like_the_gateway(home, "hermes-plugin-entrypoints.json")

    stayed = cmd_uninstall._remove_earlier_folder_connector_records(plan)

    assert stayed == []
    shown, cache, _aside = _cache_moved_aside(home, body, capsys)
    assert cache in shown
    assert reason in shown


@pytest.mark.parametrize("body", [NOT_THE_GATEWAYS_BYTES[index][0] for index in (8, 13, 15)])
def test_an_uninstall_with_a_cache_the_writer_cannot_emit_succeeds_and_leaves_the_cache_aside(
    tmp_path, monkeypatch, capsys, body,
):
    home, plan = _move_and_plan(tmp_path, monkeypatch)
    (home / "hermes-plugin-entrypoints.json").write_bytes(body.encode("utf-8", "surrogatepass"))

    result = _execute_earlier_folder_phase(plan)

    assert result.succeeded
    assert cmd_uninstall._phases_left(result) == []
    shown, cache, aside = _cache_moved_aside(home, body, capsys)
    assert cache in shown
    assert aside in shown


def test_a_second_cache_the_writer_cannot_emit_is_moved_to_the_next_free_name_and_the_first_is_kept(
    tmp_path, monkeypatch, capsys,
):
    home, plan = _move_and_plan(tmp_path, monkeypatch)
    (home / "hermes-plugin-entrypoints.json.moved-aside").write_text("an earlier notice\n")
    (home / "hermes-plugin-entrypoints.json").write_text("[]")

    assert cmd_uninstall._remove_earlier_folder_connector_records(plan) == []

    assert (home / "hermes-plugin-entrypoints.json.moved-aside").read_text() == "an earlier notice\n"
    assert (home / "hermes-plugin-entrypoints.json.moved-aside-2").read_text() == "[]"
    assert not (home / "hermes-plugin-entrypoints.json").exists()


def test_a_cache_with_the_special_characters_the_gateway_escapes_is_removed_while_recorded(tmp_path, monkeypatch):
    # json.Marshal writes < > & U+2028 and control characters as \u escapes and non-ASCII raw; this is such a file.
    # The same two answers, byte for byte, as TestTheAnswerStoreWritesTheBytesTheUninstallCheckExpects (internal/watcher).
    body = (
        '{"answers":{"' + "a" * 64 + '":{"entrypoints":[],"seen":7},"' + "b" * 64 + '":{"entrypoints":["a'
        + "\\u003cb\\u003e\\u0026\\u2028\\u0001\\b\\f\\n\\r\\t" + '\\"' + "\\\\" + "\x7f\u00e9\U0001f600"
        + '"],"seen":9223372036854775807}}}'
    )
    home, plan = _move_and_plan(tmp_path, monkeypatch)
    (home / "hermes-plugin-entrypoints.json").write_bytes(body.encode())
    _record_like_the_gateway(home, "hermes-plugin-entrypoints.json")

    assert cmd_uninstall._remove_earlier_folder_connector_records(plan) == []

    assert not (home / "hermes-plugin-entrypoints.json").exists()
    assert not (home / "hermes-plugin-entrypoints.json.moved-aside").exists()


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
