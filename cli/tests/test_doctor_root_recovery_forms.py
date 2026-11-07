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


@pytest.mark.parametrize("home_config", ["missing", "malformed", "unreadable"])
def test_the_store_doctor_loaded_never_stands_in_for_the_install_home_config(
    monkeypatch, account, home_config
) -> None:
    """GAP-0711, GAP-0713: a config of the same relative name in doctors folder is not the gateways.

    Doctor ran in a folder that holds a valid ``other.yaml`` naming an unrelated
    store; the gateway starts in the install home, where ``other.yaml`` is
    missing or cannot be read. The printed ``chown -R`` must not name the
    unrelated store, and an unreadable config must say its store is unknown.
    """
    home, elsewhere = account
    (elsewhere / "other.yaml").write_text("data_dir: /srv/unrelated-store\n")
    monkeypatch.setenv("DEFENSECLAW_CONFIG", "other.yaml")
    if home_config == "malformed":
        (home / "other.yaml").write_text("data_dir: [unterminated\n")
    elif home_config == "unreadable":
        (home / "other.yaml").write_bytes(b"\xff\xfe data_dir: \x00")
    cfg = SimpleNamespace(data_dir="/srv/unrelated-store", deployment_mode="")

    for name, remedy in _surfaces(cfg).items():
        assert _chowned(remedy) == [os.fspath(home)], name
        assert "/srv/unrelated-store" not in remedy, name
        assert ("could not be read here" in remedy) == (home_config != "missing"), name
    assert cmd_doctor._root_gateway_install_home(cfg) == os.fspath(home)


def _doctor_cfg_from_unrelated_cwd(monkeypatch, tmp_path):
    """A relative DEFENSECLAW_CONFIG names a different file here than in the install home."""
    install_home = tmp_path / "account" / ".defenseclaw"
    working_dir = tmp_path / "elsewhere"
    actual_store = tmp_path / "actual-store"
    unrelated_store = tmp_path / "unrelated-store"
    for path in (install_home, working_dir, actual_store, unrelated_store):
        path.mkdir(parents=True)
    (install_home / "other.yaml").write_text(f"data_dir: {actual_store}\n")
    (working_dir / "other.yaml").write_text(f"data_dir: {unrelated_store}\n")
    monkeypatch.setenv("DEFENSECLAW_HOME", str(install_home))
    monkeypatch.setenv("DEFENSECLAW_CONFIG", "other.yaml")
    monkeypatch.chdir(working_dir)
    return install_home, actual_store, unrelated_store, config_module.load()


def test_sudo_leftovers_scans_the_store_the_gateway_reads(monkeypatch, tmp_path):
    """GAP-0711/0713: diagnosis and remedy name the same (install-home) store."""
    _home, actual_store, unrelated_store, cfg = _doctor_cfg_from_unrelated_cwd(monkeypatch, tmp_path)
    assert os.path.realpath(cfg.data_dir) == os.path.realpath(unrelated_store)
    scanned = []

    def leftovers(data_dir):
        scanned.append(os.path.realpath(data_dir))
        return ["active_connector.json"] if os.path.realpath(data_dir) == os.path.realpath(actual_store) else []

    monkeypatch.setattr(cmd_doctor, "sudo_runtime_leftover_relpaths", leftovers)
    result = cmd_doctor._DoctorResult(quiet=True)
    cmd_doctor._check_sudo_runtime_leftovers(cfg, result)
    assert result.checks[-1]["status"] == "fail", result.checks[-1]
    assert scanned == [os.path.realpath(actual_store)]


def test_sudo_leftovers_in_the_unrelated_store_is_not_the_gateways(monkeypatch, tmp_path):
    """Benign twin: root files only in the folder doctor was run in are not the gateway's."""
    _home, actual_store, unrelated_store, cfg = _doctor_cfg_from_unrelated_cwd(monkeypatch, tmp_path)
    monkeypatch.setattr(
        cmd_doctor,
        "sudo_runtime_leftover_relpaths",
        lambda data_dir: ["active_connector.json"] if os.path.realpath(data_dir) == os.path.realpath(unrelated_store) else [],
    )
    result = cmd_doctor._DoctorResult(quiet=True)
    cmd_doctor._check_sudo_runtime_leftovers(cfg, result)
    assert result.checks[-1]["status"] == "pass", result.checks[-1]


def test_sudo_leftovers_keep_the_loaded_store_when_both_readers_agree(monkeypatch, tmp_path):
    """Benign twin: no relative DEFENSECLAW_CONFIG, so the loaded config is the gateway's."""
    store = tmp_path / "store"
    store.mkdir()
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "account"))
    seen = []
    monkeypatch.setattr(cmd_doctor, "sudo_runtime_leftover_relpaths", lambda data_dir: seen.append(data_dir) or [])
    cmd_doctor._check_sudo_runtime_leftovers(SimpleNamespace(data_dir=str(store)), cmd_doctor._DoctorResult(quiet=True))
    assert seen == [str(store)]


def test_hook_contract_lock_is_read_from_the_store_the_gateway_reads(monkeypatch, tmp_path):
    _home, actual_store, unrelated_store, cfg = _doctor_cfg_from_unrelated_cwd(monkeypatch, tmp_path)
    (actual_store / "hook_contract_lock.json").write_text("{}")
    (unrelated_store / "hook_contract_lock.json").unlink(missing_ok=True)
    opened = []
    real_open = open

    def tracking_open(path, *args, **kwargs):
        if os.path.basename(str(path)) == "hook_contract_lock.json":
            opened.append(os.path.realpath(path))
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", tracking_open)
    cmd_doctor._check_hook_contract_lock(cfg, "codex", cmd_doctor._DoctorResult(quiet=True))
    assert opened and opened[0] == os.path.realpath(actual_store / "hook_contract_lock.json"), opened
