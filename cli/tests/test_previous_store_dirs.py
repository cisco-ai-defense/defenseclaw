# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The install home lists the folders `config set data_dir` left behind, for uninstall to search."""

from __future__ import annotations

import json
import os

import pytest
from defenseclaw import config as config_module


@pytest.fixture
def home(tmp_path, monkeypatch):
    folder = tmp_path / ".defenseclaw"
    folder.mkdir(mode=0o700)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(folder))
    # An elevated process writes no list, and the Windows CI runner is elevated: run as the user.
    monkeypatch.setattr(config_module, "_is_admin_process", lambda: False)
    return folder


def _folders(tmp_path, count):
    made = []
    for index in range(count):
        folder = tmp_path / f"state-{index}"
        folder.mkdir()
        made.append(str(folder))
    return made


def test_a_move_lists_the_folder_it_leaves_and_never_the_install_home(tmp_path, home):
    one, two = _folders(tmp_path, 2)
    assert config_module.remember_previous_store(str(home)) == []
    assert config_module.remember_previous_store(one) == []
    assert config_module.remember_previous_store(two) == []
    assert config_module.remember_previous_store(one) == []
    assert config_module.previous_store_dirs() == (two, one)


def test_an_elevated_process_writes_no_list(tmp_path, home, monkeypatch):
    (one,) = _folders(tmp_path, 1)
    monkeypatch.setattr(config_module, "_is_admin_process", lambda: True)
    assert config_module.remember_previous_store(one) == []
    assert not (home / config_module.STORE_HISTORY_FILE).exists()
    monkeypatch.setattr(config_module, "_is_admin_process", lambda: False)
    assert config_module.previous_store_dirs() == ()


def test_the_list_keeps_the_newest_folders_and_drops_folders_that_are_gone(tmp_path, home):
    folders = _folders(tmp_path, 20)
    for folder in folders:
        config_module.remember_previous_store(folder)
    assert config_module.previous_store_dirs() == tuple(folders[-16:])
    os.rmdir(folders[-1])
    assert config_module.previous_store_dirs() == tuple(folders[-16:-1])


def test_no_list_means_no_earlier_folders(home):
    assert config_module.previous_store_dirs() == ()


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_a_list_other_accounts_can_read_names_nothing(tmp_path, home):
    (one,) = _folders(tmp_path, 1)
    config_module.remember_previous_store(one)
    path = home / config_module.STORE_HISTORY_FILE
    assert config_module.previous_store_dirs() == (one,)
    path.chmod(0o644)
    assert config_module.previous_store_dirs() == ()


@pytest.mark.skipif(os.name == "nt", reason="needs symlink rights")
def test_a_linked_list_names_nothing(tmp_path, home):
    (one,) = _folders(tmp_path, 1)
    real = tmp_path / "elsewhere.json"
    real.write_text(json.dumps({"folders": [one]}))
    real.chmod(0o600)
    (home / config_module.STORE_HISTORY_FILE).symlink_to(real)
    assert config_module.previous_store_dirs() == ()


@pytest.mark.parametrize(
    "body",
    [
        "not json",
        "[]",
        json.dumps({"folders": "x"}),
        json.dumps({"folders": [1, None, "relative/path", "/no/such/folder"]}),
    ],
)
def test_a_malformed_list_names_nothing(home, body):
    path = home / config_module.STORE_HISTORY_FILE
    path.write_text(body)
    path.chmod(0o600)
    assert config_module.previous_store_dirs() == ()


def test_a_managed_runtime_searches_no_earlier_folder(tmp_path, home, monkeypatch):
    (one,) = _folders(tmp_path, 1)
    config_module.remember_previous_store(one)
    assert config_module.previous_store_dirs() == (one,)
    monkeypatch.setenv(config_module.DEPLOYMENT_MODE_ENV, "managed_enterprise")
    assert config_module.previous_store_dirs() == ()
