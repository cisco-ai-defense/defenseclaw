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
    returned, restore = tail.split(" && chmod -R u+rwX ", 1)
    # The owner bits are restored on the folders that were returned, no others.
    assert shlex.split(restore.split(" && defenseclaw-gateway start", 1)[0]) == shlex.split(returned)
    return shlex.split(returned)


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


@pytest.mark.parametrize("absolute_config", [False, True])
def test_hook_contract_lock_relative_data_dir_is_read_from_the_install_home(monkeypatch, tmp_path, absolute_config):
    """A relative data_dir is the gateway's, taken from the install home, with any config form."""
    home = tmp_path / "install"
    elsewhere = tmp_path / "elsewhere"
    actual_store = home / "moved"
    for path in (home, elsewhere, actual_store):
        path.mkdir(parents=True)
    cfg_path = home / "config.yaml"
    cfg_path.write_text("config_version: 8\ndata_dir: moved\n")
    (actual_store / "hook_contract_lock.json").write_text("{}")
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    if absolute_config:
        monkeypatch.setenv("DEFENSECLAW_CONFIG", str(cfg_path))
    else:
        monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    monkeypatch.chdir(elsewhere)
    cfg = config_module.load()
    assert cfg.data_dir == "moved"
    opened = []
    real_open = open

    def tracking_open(path, *args, **kwargs):
        if os.path.basename(str(path)) == "hook_contract_lock.json":
            opened.append(os.path.abspath(path))
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", tracking_open)
    cmd_doctor._check_hook_contract_lock(cfg, "codex", cmd_doctor._DoctorResult(quiet=True))
    assert opened and opened[0] == str(actual_store / "hook_contract_lock.json"), opened


def test_tilde_store_recovery_returns_the_install_home_and_the_store(monkeypatch, tmp_path):
    """The gateway keeps a ~/ data_dir as a folder under the install home; its PID record is in the home."""
    home = tmp_path / "install"
    elsewhere = tmp_path / "elsewhere"
    home.mkdir()
    elsewhere.mkdir()
    raw = "config_version: 8\ndata_dir: ~/.dc-tilde\n"
    (home / "other.yaml").write_text(raw)
    (elsewhere / "other.yaml").write_text(raw)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    monkeypatch.setenv("DEFENSECLAW_CONFIG", "other.yaml")
    monkeypatch.chdir(elsewhere)
    cfg = config_module.load()
    store = str(home / "~" / ".dc-tilde")
    assert cmd_doctor._install_home_store(cfg) == store
    assert cmd_doctor._root_gateway_install_home(cfg) == str(home)
    assert _chowned(cmd_doctor._root_gateway_return_and_start_command(cfg)) == [str(home), store]


def test_managed_install_home_keeps_the_store_as_its_own_pid_home(monkeypatch, tmp_path):
    """Benign twin: a managed runtime keeps its own PID home, as before."""
    home = tmp_path / "install"
    home.mkdir()
    (home / "config.yaml").write_text("config_version: 8\ndeployment_mode: managed_enterprise\ndata_dir: moved\n")
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    assert config_module.install_home_for_bound_store(home / "moved") == str(home / "moved")


def _unreadable_install_config(monkeypatch, tmp_path, readable: bool):
    """A relative config only root can read, and a different file of that name where doctor runs."""
    home = tmp_path / "install"
    elsewhere = tmp_path / "elsewhere"
    actual = tmp_path / "root-store"
    unrelated = tmp_path / "unrelated"
    for path in (home, elsewhere, actual, unrelated):
        path.mkdir()
    install_config = home / "other.yaml"
    install_config.write_text(f"config_version: 8\ndata_dir: {actual}\n")
    if not readable:
        install_config.chmod(0)
    (elsewhere / "other.yaml").write_text(f"config_version: 8\ndata_dir: {unrelated}\n")
    (unrelated / "hook_contract_lock.json").write_text("{}")
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    monkeypatch.setenv("DEFENSECLAW_CONFIG", "other.yaml")
    monkeypatch.chdir(elsewhere)
    cfg = config_module.load()
    assert os.path.realpath(cfg.data_dir) == os.path.realpath(unrelated)
    return actual, unrelated, cfg


@pytest.mark.skipif(os.name == "nt" or os.geteuid() == 0, reason="needs a config this account cannot read")
def test_unreadable_install_config_leaves_the_store_unknown_not_doctors_unrelated_one(monkeypatch, tmp_path):
    """Round 9: the unrelated store doctor loaded never stands in for an unreadable gateway config."""
    actual, unrelated, cfg = _unreadable_install_config(monkeypatch, tmp_path, readable=False)
    assert cmd_doctor._gateway_store_dir(cfg) == ""
    scanned = []
    monkeypatch.setattr(
        cmd_doctor, "sudo_runtime_leftover_relpaths", lambda data_dir: scanned.append(data_dir) or ["x.json"]
    )
    opened = []
    real_open = open

    def tracking_open(path, *args, **kwargs):
        if os.path.basename(str(path)) == "hook_contract_lock.json":
            opened.append(str(path))
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", tracking_open)
    for check in (
        cmd_doctor._check_sudo_runtime_leftovers,
        lambda c, r: cmd_doctor._check_hook_contract_lock(c, "codex", r),
    ):
        result = cmd_doctor._DoctorResult(quiet=True)
        check(cfg, result)
        row = result.checks[-1]
        assert row["status"] == "warn", row
        assert "could not be read" in row["detail"], row
    assert scanned == [] and opened == [], (scanned, opened)


def test_readable_install_config_still_selects_its_store(monkeypatch, tmp_path):
    """Benign twin: the same layout with a readable install-home config checks that config store."""
    actual, unrelated, cfg = _unreadable_install_config(monkeypatch, tmp_path, readable=True)
    assert os.path.realpath(cmd_doctor._gateway_store_dir(cfg)) == os.path.realpath(actual)
    scanned = []
    monkeypatch.setattr(cmd_doctor, "sudo_runtime_leftover_relpaths", lambda data_dir: scanned.append(data_dir) or [])
    result = cmd_doctor._DoctorResult(quiet=True)
    cmd_doctor._check_sudo_runtime_leftovers(cfg, result)
    assert result.checks[-1]["status"] == "pass" and [os.path.realpath(p) for p in scanned] == [os.path.realpath(actual)]
