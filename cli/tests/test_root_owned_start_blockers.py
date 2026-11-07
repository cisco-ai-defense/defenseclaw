# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-0788: root-owned state that stops the gateway start of this account.

A gateway that ran under sudo and stopped leaves root-owned state behind. The
blocker scan reads it with ``lstat``, so the tests stand in for the owner of
the files they list (an ordinary user cannot create root-owned ones).
"""

from __future__ import annotations

import os
import stat

import pytest
from defenseclaw import file_permissions as fp

pytestmark = pytest.mark.skipif(
    os.name == "nt" or not hasattr(os, "geteuid") or os.geteuid() == 0,
    reason="a root caller never sees root-owned leftovers",
)


def _write(directory, name, mode):
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}")
    path.chmod(mode)
    return path


def _owned_by_root(monkeypatch, *paths):
    real = os.lstat
    owned = {os.fspath(p) for p in paths}

    def lstat(path, *args, **kwargs):
        info = real(path, *args, **kwargs)
        if os.fspath(path) in owned:
            fields = list(info)
            fields[stat.ST_UID] = 0
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(fp.os, "lstat", lstat)


def test_root_files_of_any_mode_block_and_loose_ones_are_flagged(tmp_path, monkeypatch):
    lock = _write(tmp_path, "hook_contract_lock.json", 0o600)
    active = _write(tmp_path, "active_connector.json", 0o644)
    _write(tmp_path, "application_protection_state.json", 0o600)  # owned by this account
    _owned_by_root(monkeypatch, lock, active)

    blockers, loose = fp.root_owned_start_blockers(tmp_path, ai_discovery_enabled=True)

    assert blockers == ["hook_contract_lock.json", "active_connector.json"]
    assert loose == [str(active)]


def test_the_sudo_leftovers_row_still_names_private_files_only(tmp_path, monkeypatch):
    lock = _write(tmp_path, "hook_contract_lock.json", 0o600)
    active = _write(tmp_path, "active_connector.json", 0o644)
    _owned_by_root(monkeypatch, lock, active)

    assert fp.sudo_runtime_leftover_relpaths(tmp_path) == ["hook_contract_lock.json"]


def test_a_root_owned_store_this_account_cannot_use_is_named_as_a_whole(tmp_path, monkeypatch):
    _owned_by_root(monkeypatch, tmp_path)
    monkeypatch.setattr(fp.os, "access", lambda *_a, **_k: False)
    assert fp.root_owned_start_blockers(tmp_path, ai_discovery_enabled=True) == ([fp.STORE_DIR_ENTRY], [])

    # The benign twin: the same owner with write access to the store is no blocker.
    monkeypatch.setattr(fp.os, "access", lambda *_a, **_k: True)
    assert fp.root_owned_start_blockers(tmp_path, ai_discovery_enabled=True) == ([], [])


def test_discovery_state_blocks_only_while_discovery_is_enabled(tmp_path, monkeypatch):
    state = _write(tmp_path, "ai_discovery_state.json", 0o600)
    _owned_by_root(monkeypatch, state)

    assert fp.root_owned_start_blockers(tmp_path, ai_discovery_enabled=False) == ([], [])
    assert fp.root_owned_start_blockers(tmp_path, ai_discovery_enabled=True) == (["ai_discovery_state.json"], [])


def test_a_root_owned_pid_record_in_the_install_home_blocks_a_moved_store(tmp_path, monkeypatch):
    store = tmp_path / "store"
    home = tmp_path / "home"
    store.mkdir()
    pid = _write(home, "gateway.pid", 0o600)
    _write(home, "device.key", 0o600)  # root-owned in a home the store left: not read
    _owned_by_root(monkeypatch, pid, home / "device.key")

    blockers, loose = fp.root_owned_start_blockers(store, ai_discovery_enabled=True, pid_dir=home)

    assert blockers == [str(pid)]
    assert loose == []


def test_an_account_owned_store_has_no_blockers(tmp_path):
    for name in fp.SUDO_RUNTIME_LEFTOVER_NAMES:
        _write(tmp_path, name, 0o600)
    _write(tmp_path, "hooks/.hook-abc.token", 0o600)

    assert fp.root_owned_start_blockers(tmp_path, ai_discovery_enabled=True, pid_dir=tmp_path) == ([], [])
    assert fp.root_owned_start_blockers(tmp_path / "missing", ai_discovery_enabled=True) == ([], [])
