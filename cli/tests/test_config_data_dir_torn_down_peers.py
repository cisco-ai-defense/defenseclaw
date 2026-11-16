# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""`config set data_dir` does not carry the lock entry of a connector the old folder tore down (GAP-0941)."""

import json
import os

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_config, cmd_setup
from defenseclaw.context import AppContext

from tests.test_cmd_setup_connector_readiness import _entry
from tests.test_config_data_dir_move import _install_home

pytestmark = pytest.mark.skipif(os.name == "nt", reason="needs POSIX modes")


def _write(path, document):
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _old_folder(home, tmp_path, *, state):
    lock = {"version": 2, "connectors": {name: _entry(name, tmp_path) for name in ("claudecode", "codex", "hermes")}}
    lock["shared_hook_script_digests"] = {"hook.sh": "sha256:abc"}
    _write(home / "hook_contract_lock.json", lock)
    if state is not None:
        _write(home / "active_connector.json", state)
    return lock


def _move(tmp_path, monkeypatch, home):
    monkeypatch.setattr(cmd_config.config_module, "_is_admin_process", lambda: False)
    moved = tmp_path / "dcdata"
    result = CliRunner().invoke(cmd_config.config_cmd, ["set", "data_dir", str(moved)], obj=AppContext())
    assert result.exit_code == 0, result.output
    return moved


def _ready(lock):
    state = {"version": 3, "names": ["hermes"], "inactive_names": []}
    return cmd_setup._connector_runtime_snapshot_ready(
        state, 2, lock, 2, expected={"hermes"}, previous_state_marker=1, previous_lock_marker=1
    )


def test_the_entries_of_connectors_the_old_folder_tore_down_are_not_carried(tmp_path, monkeypatch):
    home, _ = _install_home(tmp_path, monkeypatch)
    state = {"version": 3, "names": ["hermes"], "inactive_names": ["claudecode", "codex"]}
    _old_folder(home, tmp_path, state=state)

    moved = _move(tmp_path, monkeypatch, home)

    carried = json.loads((moved / "hook_contract_lock.json").read_text())
    assert sorted(carried["connectors"]) == ["hermes"]
    assert carried["shared_hook_script_digests"] == {"hook.sh": "sha256:abc"}
    assert _ready(carried), "setup of the one connector is not refused for a peer it has no mark for"
    assert sorted(json.loads((home / "hook_contract_lock.json").read_text())["connectors"]) == [
        "claudecode", "codex", "hermes",
    ], "the old folder is left as it is"


def test_the_digests_go_with_the_last_entry(tmp_path, monkeypatch):
    home, _ = _install_home(tmp_path, monkeypatch)
    lock = {"version": 2, "connectors": {"claudecode": _entry("claudecode", tmp_path)}}
    lock["shared_hook_script_digests"] = {"hook.sh": "sha256:abc"}
    _write(home / "hook_contract_lock.json", lock)
    _write(home / "active_connector.json", {"version": 3, "inactive_names": ["claudecode"]})

    moved = _move(tmp_path, monkeypatch, home)

    carried = json.loads((moved / "hook_contract_lock.json").read_text())
    assert carried["connectors"] == {} and "shared_hook_script_digests" not in carried


def test_a_peer_with_no_mark_is_carried_and_the_roster_check_still_refuses_it(tmp_path, monkeypatch):
    home, _ = _install_home(tmp_path, monkeypatch)
    state = {"version": 3, "names": ["hermes"], "inactive_names": ["claudecode"]}
    _old_folder(home, tmp_path, state=state)

    moved = _move(tmp_path, monkeypatch, home)

    carried = json.loads((moved / "hook_contract_lock.json").read_text())
    assert sorted(carried["connectors"]) == ["codex", "hermes"]
    assert not _ready(carried), "a peer nobody tore down is still not ready"


@pytest.mark.parametrize(
    "state",
    [
        None,
        {"version": 3, "names": ["hermes", "codex"], "inactive_names": ["codex"]},
        {"version": 2, "names": ["hermes"], "inactive_names": ["claudecode", "codex"]},
        {"version": 3, "names": "hermes", "inactive_names": ["claudecode", "codex"]},
    ],
)
def test_a_lock_is_carried_byte_for_byte_when_the_old_roster_tore_down_nothing(tmp_path, monkeypatch, state):
    home, _ = _install_home(tmp_path, monkeypatch)
    _old_folder(home, tmp_path, state=state)
    original = (home / "hook_contract_lock.json").read_bytes()

    moved = _move(tmp_path, monkeypatch, home)

    assert (moved / "hook_contract_lock.json").read_bytes() == original
