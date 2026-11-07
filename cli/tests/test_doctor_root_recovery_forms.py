# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""GAP-0711, GAP-0713: the root-gateway recovery names the store the gateway uses.

The gateway starts with the install home as its working directory, so it takes
a relative ``DEFENSECLAW_CONFIG`` and a relative ``data_dir`` from there. Doctor
runs wherever the operator is. Every form must name the same folders from an
unrelated working directory, or the printed ``chown -R`` returns the wrong
folder.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from types import SimpleNamespace

import pytest
from defenseclaw import config as config_module
from defenseclaw import gateway as gateway_module
from defenseclaw.commands import cmd_doctor

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX per-user gateway account")


def _chowned(remedy: str) -> list[str]:
    tail = remedy.split('sudo chown -R "$(id -un)" ', 1)[1]
    return shlex.split(tail.split(" && defenseclaw-gateway start", 1)[0])


def _surfaces(cfg) -> dict[str, str]:
    """The three surfaces that print the recovery chain."""
    return {
        "gateway account": cmd_doctor._root_gateway_remedy_for("linux", cfg),
        "gateway account (macOS)": cmd_doctor._root_gateway_remedy_for("darwin", cfg),
        "sudo leftovers and hook contract": cmd_doctor._root_leftovers_remedy(cfg),
    }


@pytest.fixture
def account(monkeypatch, tmp_path):
    home = tmp_path / "install home"
    home.mkdir()
    elsewhere = tmp_path / "unrelated working directory"
    elsewhere.mkdir()
    monkeypatch.setenv("DEFENSECLAW_HOME", os.fspath(home))
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    monkeypatch.setattr(gateway_module, "resolve_gateway_binary", lambda: "")
    monkeypatch.chdir(elsewhere)
    return home, elsewhere


def test_relative_data_dir_is_taken_from_the_install_home(monkeypatch, account) -> None:
    home, elsewhere = account
    (home / "config.yaml").write_text("data_dir: moved store\n")
    cfg = config_module.load()

    for name, remedy in _surfaces(cfg).items():
        assert _chowned(remedy) == [os.fspath(home), os.fspath(home / "moved store")], name
        assert os.fspath(elsewhere) not in remedy, name


def test_relative_config_path_is_read_from_the_install_home(monkeypatch, account) -> None:
    home, elsewhere = account
    (home / "other.yaml").write_text("data_dir: /srv/moved-store\n")
    monkeypatch.setenv("DEFENSECLAW_CONFIG", "other.yaml")
    # From the unrelated folder the loader finds no such file and falls back to
    # defaults, so the moved store is not in what doctor loaded.
    cfg = SimpleNamespace(data_dir=os.fspath(home), deployment_mode="")

    for name, remedy in _surfaces(cfg).items():
        assert _chowned(remedy) == [os.fspath(home), "/srv/moved-store"], name


def test_relative_config_path_with_relative_data_dir(monkeypatch, account) -> None:
    home, _elsewhere = account
    (home / "other.yaml").write_text("data_dir: ../moved-next-to-home\n")
    monkeypatch.setenv("DEFENSECLAW_CONFIG", "other.yaml")
    cfg = SimpleNamespace(data_dir=os.fspath(home), deployment_mode="")

    for name, remedy in _surfaces(cfg).items():
        assert _chowned(remedy) == [os.fspath(home), os.fspath(home.parent / "moved-next-to-home")], name


def test_the_check_rows_name_the_same_folders(monkeypatch, account) -> None:
    home, _elsewhere = account
    (home / "config.yaml").write_text("data_dir: moved store\n")
    cfg = config_module.load()
    monkeypatch.setattr(cmd_doctor, "sudo_runtime_leftover_relpaths", lambda _d: ["active_connector.json"])
    result = cmd_doctor._DoctorResult(quiet=True)

    cmd_doctor._check_sudo_runtime_leftovers(cfg, result)

    assert _chowned(result.checks[-1]["remediation"]) == [os.fspath(home), os.fspath(home / "moved store")]


def test_unreadable_config_keeps_the_command_pasteable(monkeypatch, account) -> None:
    home, _elsewhere = account
    (home / "config.yaml").write_text("data_dir: [unterminated\n")
    cfg = SimpleNamespace(data_dir=os.fspath(home), deployment_mode="")

    for name, remedy in _surfaces(cfg).items():
        assert "could not be read here" in remedy, name
        chain = remedy.rsplit(": ", 1)[1]
        assert chain.startswith("sudo env DEFENSECLAW_HOME="), name
        assert chain.endswith("&& defenseclaw-gateway start"), name
        bash = shutil.which("bash")
        if bash:
            subprocess.run([bash, "-n", "-c", chain], check=True, capture_output=True)


def test_ordinary_absolute_store_and_plain_home_are_complete(monkeypatch, account) -> None:
    home, _elsewhere = account
    store = home.parent / "absolute store"
    (home / "config.yaml").write_text(f'data_dir: "{store}"\n')
    cfg = SimpleNamespace(data_dir=os.fspath(store), deployment_mode="")
    for name, remedy in _surfaces(cfg).items():
        assert _chowned(remedy) == [os.fspath(home), os.fspath(store)], name
        assert "could not be read" not in remedy, name

    (home / "config.yaml").write_text("gateway:\n  api_port: 18970\n")
    cfg = SimpleNamespace(data_dir=os.fspath(home), deployment_mode="")
    for name, remedy in _surfaces(cfg).items():
        assert _chowned(remedy) == [os.fspath(home)], name
