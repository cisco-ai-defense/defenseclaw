# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Concurrent first-run inits and a half-created device identity (GAP-0927).

Two inits on one fresh home used to race through the same seeds and device
identity and leave a provenance file with no key, which every later init then
refused and the printed Doctor fix could not clear.  Init now holds one lock on
every data folder it initializes, and a device identity is published all or
nothing.  A keyless provenance file is continuity evidence: init never replaces
it on its own, whatever else the home holds.  It stops, names the path and the
explicit repair (``defenseclaw init --repair-identity``), and that command, run
by the operator under the same locks, is what sets the files aside and creates
the identity again.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import threading
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from defenseclaw import bootstrap, doctor_recovery
from defenseclaw.bootstrap import FirstRunOptions, run_first_run
from defenseclaw.commands.cmd_init import _ensure_device_key, init_cmd
from defenseclaw.context import AppContext
from defenseclaw.doctor_recovery import (
    REPAIR_IDENTITY_COMMAND,
    DeviceKeyHealthStatus,
    inspect_device_key,
)
from defenseclaw.file_lock import locked_file_update
from defenseclaw.file_permissions import make_private_directory, protect_private_file

from tests.helpers import record_test_setup_agent_selections

SECRET = "device.provenance.secret"


@pytest.fixture(autouse=True)
def _selection_recorder():
    with patch(
        "defenseclaw.agent_selection.record_setup_agent_selections",
        side_effect=record_test_setup_agent_selections,
    ):
        yield


@pytest.fixture(autouse=True)
def _no_gateway_running():
    """The repair command asks Doctor's gateway-inactivity question; no test home has a gateway."""

    from defenseclaw.commands import cmd_doctor
    from defenseclaw.doctor_gateway import ListenerEvidence

    with (
        patch.object(cmd_doctor, "_managed_gateway_process_trust", return_value=cmd_doctor._GatewayTrust("missing", "none")),
        patch.object(cmd_doctor, "_verified_listener_gateway_evidence", return_value=ListenerEvidence("missing")),
    ):
        yield


def _options() -> FirstRunOptions:
    return FirstRunOptions(connector="none", profile="observe", skip_install=True, start_gateway=False, verify=False)


def _home(tmp_path: Path, name: str = "home") -> Path:
    home = Path(os.path.realpath(tmp_path)) / name
    make_private_directory(str(home))
    return home


def _orphans(home: Path) -> list[str]:
    return sorted(path.name for path in home.iterdir() if ".orphaned-" in path.name)


def _leftover_secret_and_sentinel(home: Path) -> None:
    secret = os.urandom(32)
    digest = hmac.new(secret, b"a key that is gone", hashlib.sha256).hexdigest().encode("ascii")
    for path, data in (
        (home / SECRET, secret),
        (home / "device.key.provenance", b"defenseclaw-device-provenance-v1:" + digest + b"\n"),
    ):
        path.write_bytes(data)
        protect_private_file(str(path))


def _valid(home: Path) -> bool:
    return inspect_device_key(str(home / "device.key"), data_dir=str(home)).status is DeviceKeyHealthStatus.VALID


def test_second_init_reports_it_when_the_home_lock_stays_held(tmp_path, monkeypatch):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    monkeypatch.setattr(bootstrap, "_FIRST_RUN_LOCK_WAIT_SECONDS", 0.2)

    with locked_file_update(str(home / "init")):
        report = run_first_run(_options())

    assert report.status == "needs_attention"
    assert [(step.name, step.status) for step in report.setup] == [("Init lock", "fail")]
    assert "another defenseclaw init is running" in report.setup[0].detail
    assert report.next_commands == ["defenseclaw init"]
    assert not (home / "config.yaml").exists()
    assert not (home / "device.key").exists()


def test_second_init_waits_for_the_lock_then_completes(tmp_path, monkeypatch):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    acquired, release = threading.Event(), threading.Event()

    def hold() -> None:
        with locked_file_update(str(home / "init")):
            acquired.set()
            release.wait(10)

    holder = threading.Thread(target=hold)
    holder.start()
    assert acquired.wait(10)
    threading.Timer(0.3, release.set).start()
    try:
        report = run_first_run(_options())
    finally:
        release.set()
        holder.join(10)

    assert report.status != "needs_attention"
    assert (home / "config.yaml").is_file()
    assert _valid(home)


def test_two_inits_started_together_on_a_fresh_home_both_succeed(tmp_path, monkeypatch):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    gate = threading.Barrier(2)
    reports: list[object] = []
    errors: list[BaseException] = []

    def run() -> None:
        try:
            gate.wait(10)
            reports.append(run_first_run(_options()))
        except BaseException as exc:  # noqa: BLE001 - the assertion below names it
            errors.append(exc)

    threads = [threading.Thread(target=run) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(120)

    assert errors == []
    assert [report.status for report in reports] != []
    assert all(report.status != "needs_attention" for report in reports), [r.to_dict() for r in reports]
    assert _valid(home)
    assert _orphans(home) == []


def _plain_init(*args: str):
    return CliRunner().invoke(init_cmd, ["--skip-install", *args], obj=AppContext())


def _repair(answer: str = "y\n"):
    return CliRunner().invoke(init_cmd, ["--repair-identity"], input=answer, obj=AppContext())


def _write_private(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    protect_private_file(str(path))


def _snapshot(home: Path) -> dict[str, bytes]:
    return {path.name: path.read_bytes() for path in home.iterdir() if path.is_file()}


def _identity_files(home: Path) -> dict[str, bytes]:
    return {name: data for name, data in _snapshot(home).items() if name.startswith("device.")}


def _interrupted_first_creation(home: Path, monkeypatch) -> None:
    """A first init killed after the secret was published: the secret stays, the key never exists."""

    real_publish = doctor_recovery._publish_no_replace

    def die_before_sentinel(source: str, target: str) -> None:
        if target.endswith(".provenance"):
            raise OSError("process ended before the sentinel was published")
        real_publish(source, target)

    with monkeypatch.context() as crash:
        crash.setattr(doctor_recovery, "_publish_no_replace", die_before_sentinel)
        crash.setattr(doctor_recovery, "_roll_back_device_identity", lambda placed: [])
        first = run_first_run(_options())
    assert first.status == "needs_attention"
    assert (home / SECRET).exists()
    assert not (home / "device.key").exists()
    assert not (home / "config.yaml").exists()


def _configured_home_without_key(tmp_path: Path, monkeypatch) -> Path:
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    assert run_first_run(_options()).status != "needs_attention"
    (home / "device.key").unlink()
    return home


def _refused_by(plain: bool, home: Path) -> None:
    """One init on either path stops, names the repair command and the path, and changes nothing."""

    identity_before = _identity_files(home)
    if plain:
        result = _plain_init()
        assert result.exit_code != 0
        output = result.output
    else:
        report = run_first_run(_options())
        assert report.status == "needs_attention"
        assert REPAIR_IDENTITY_COMMAND in report.next_commands
        output = " ".join(step.detail for step in report.setup)
    assert "continuity-evidence-present" in output
    assert REPAIR_IDENTITY_COMMAND in output
    assert str(home / "device.key") in output
    assert "no other defenseclaw init is running" in output
    assert "No device identity file was changed" in output
    assert not (home / "device.key").exists()
    assert _orphans(home) == []
    assert _identity_files(home) == identity_before


# --- a keyless identity is never replaced by init, whatever sits beside it -----------------------


@pytest.mark.parametrize("plain", [False, True])
def test_a_crashed_first_init_leaves_a_state_the_next_init_stops_on_and_names_the_repair(
    tmp_path, monkeypatch, plain
):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    _interrupted_first_creation(home, monkeypatch)
    secret = (home / SECRET).read_bytes()

    _refused_by(plain, home)

    assert (home / SECRET).read_bytes() == secret


@pytest.mark.parametrize("plain", [False, True])
@pytest.mark.parametrize("shape", ["secret-only", "cut-short-secret", "partial-sentinel", "complete-sentinel"])
def test_a_keyless_identity_on_a_home_with_no_config_is_never_replaced_by_init(
    tmp_path, monkeypatch, plain, shape
):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    _leftover_secret_and_sentinel(home)
    sentinel = home / "device.key.provenance"
    if shape == "secret-only":
        sentinel.unlink()
    elif shape == "cut-short-secret":
        sentinel.unlink()
        _write_private(home / SECRET, os.urandom(12))
    elif shape == "partial-sentinel":
        _write_private(sentinel, sentinel.read_bytes()[:60])

    _refused_by(plain, home)


def test_a_keyless_identity_on_a_configured_home_is_never_replaced_by_init(tmp_path, monkeypatch):
    home = _configured_home_without_key(tmp_path, monkeypatch)

    _refused_by(False, home)

    assert (home / "config.yaml").is_file()


def _finished_setup_whose_config_is_elsewhere(tmp_path: Path, monkeypatch) -> tuple[Path, Path]:
    """A finished setup: its config.yaml sits at an override path outside the data home."""

    home = _home(tmp_path)
    first = Path(os.path.realpath(tmp_path)) / "first" / "config.yaml"
    first.parent.mkdir()
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    monkeypatch.setenv("DEFENSECLAW_CONFIG", str(first))
    assert run_first_run(_options()).status != "needs_attention"
    assert first.is_file() and not (home / "config.yaml").exists()
    return home, first


@pytest.mark.parametrize("plain", [False, True])
@pytest.mark.parametrize("move", ["config-moved", "record-edited", "record-written"])
@pytest.mark.parametrize("shape", ["secret-only", "partial-sentinel"])
def test_a_moved_config_or_a_record_written_in_the_folder_never_authorizes_a_replacement(
    tmp_path, monkeypatch, plain, move, shape
):
    # The review's fixtures: a finished setup loses its key, then its config is moved away from the
    # path it ran with, or a file named init.configs is written (or edited) to list absent paths.
    home, first = _finished_setup_whose_config_is_elsewhere(tmp_path, monkeypatch)
    (home / "device.key").unlink()
    sentinel = home / "device.key.provenance"
    if shape == "secret-only":
        sentinel.unlink()
    else:
        _write_private(sentinel, sentinel.read_bytes()[:60])
    root = Path(os.path.realpath(tmp_path))
    if move == "config-moved":
        moved = root / "moved" / "config.yaml"
        moved.parent.mkdir()
        first.rename(moved)
    else:
        _write_private(home / "init.configs", (str(root / "gone" / "config.yaml") + "\n").encode())
    monkeypatch.setenv("DEFENSECLAW_CONFIG", str(root / "second" / "config.yaml"))
    secret = (home / SECRET).read_bytes()

    _refused_by(plain, home)

    assert (home / SECRET).read_bytes() == secret


# --- the explicit repair --------------------------------------------------------------------------


def test_the_repair_command_recreates_the_identity_after_a_crashed_first_init(tmp_path, monkeypatch):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    _interrupted_first_creation(home, monkeypatch)
    _refused_by(False, home)
    old_secret = (home / SECRET).read_bytes()

    result = _repair()

    assert result.exit_code == 0, result.output
    assert _valid(home)
    assert str(home / "device.key") in result.output
    assert "defenseclaw init" in result.output  # no config.yaml yet: the next step is named
    assert (home / SECRET).read_bytes() != old_secret
    assert [(home / name).read_bytes() for name in _orphans(home)] == [old_secret]
    again = run_first_run(_options())  # and the stopped init now completes
    assert again.status != "needs_attention", again.to_dict()
    assert (home / "config.yaml").is_file()
    assert _valid(home)


@pytest.mark.parametrize("plain", [False, True])
def test_the_repair_command_clears_the_state_both_init_paths_stopped_on(tmp_path, monkeypatch, plain):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    _leftover_secret_and_sentinel(home)
    _refused_by(plain, home)

    assert _repair().exit_code == 0

    assert _valid(home)
    assert len(_orphans(home)) == 2
    if plain:
        (home / "config.yaml").unlink(missing_ok=True)  # the stopped plain run kept the config it saved
        assert _plain_init().exit_code == 0
    else:
        assert run_first_run(_options()).status != "needs_attention"
    assert _valid(home)


def test_the_repair_command_works_on_a_configured_home(tmp_path, monkeypatch):
    home = _configured_home_without_key(tmp_path, monkeypatch)
    config = (home / "config.yaml").read_bytes()

    result = _repair()

    assert result.exit_code == 0, result.output
    assert "no config.yaml yet" not in result.output
    assert _valid(home)
    assert (home / "config.yaml").read_bytes() == config
    assert len(_orphans(home)) == 2


def test_the_repair_command_asks_first_and_declining_changes_nothing(tmp_path, monkeypatch):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    _leftover_secret_and_sentinel(home)
    before = _snapshot(home)

    result = _repair("n\n")

    assert result.exit_code != 0
    assert "nothing was changed" in result.output
    assert {name: data for name, data in _snapshot(home).items() if name != "init.lock"} == before
    assert _orphans(home) == []
    assert not (home / "device.key").exists()


def test_the_repair_command_never_touches_a_device_key_that_exists(tmp_path, monkeypatch):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    assert run_first_run(_options()).status != "needs_attention"
    before = _snapshot(home)

    result = _repair()

    assert result.exit_code != 0
    assert "a device key already exists" in result.output
    assert _snapshot(home) == before
    assert _orphans(home) == []


def test_the_repair_command_with_nothing_left_over_just_creates_the_identity(tmp_path, monkeypatch):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))

    result = _repair()

    assert result.exit_code == 0, result.output
    assert _valid(home)
    assert _orphans(home) == []


def test_the_repair_command_takes_the_init_lock(tmp_path, monkeypatch):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    monkeypatch.setattr(bootstrap, "_FIRST_RUN_LOCK_WAIT_SECONDS", 0.2)
    _leftover_secret_and_sentinel(home)
    before = _snapshot(home)

    with locked_file_update(str(home / "init")):
        result = _repair()

    assert result.exit_code != 0
    assert "another defenseclaw init is running" in result.output
    assert {name: data for name, data in _snapshot(home).items() if name != "init.lock"} == {
        name: data for name, data in before.items() if name != "init.lock"
    }
    assert _orphans(home) == []


def test_the_repair_command_locks_the_data_folder_the_config_names(tmp_path, monkeypatch):
    home, data = _home_naming_another_data_dir(tmp_path, monkeypatch)
    monkeypatch.setattr(bootstrap, "_FIRST_RUN_LOCK_WAIT_SECONDS", 0.2)
    _leftover_secret_and_sentinel(data)

    with locked_file_update(str(data / "init")):
        result = _repair()

    assert result.exit_code != 0
    assert "another defenseclaw init is running" in result.output
    assert _orphans(data) == []

    assert _repair().exit_code == 0
    assert _valid(data)


def test_doctor_names_the_same_repair_command(tmp_path):
    from defenseclaw.commands import cmd_doctor

    data = _home(tmp_path)
    cfg = type("Cfg", (), {})()
    cfg.data_dir = str(data)
    cfg.gateway = type("Gw", (), {"device_key_file": str(data / "device.key")})()
    _leftover_secret_and_sentinel(data)
    health = cmd_doctor._DoctorResult()

    cmd_doctor._check_device_identity(cfg, health)

    assert REPAIR_IDENTITY_COMMAND in health.checks[-1]["remediation"]


def test_attended_set_aside_moves_only_provenance_files_and_only_when_the_key_is_gone(tmp_path):
    home = _home(tmp_path)
    _leftover_secret_and_sentinel(home)
    _write_private(home / "keep.me", b"unrelated")

    moved = doctor_recovery.set_aside_identity_leftovers(str(home / "device.key"), str(home))

    assert len(moved) == 2
    assert sorted(path.name for path in home.iterdir() if not path.name.startswith("device.")) == ["keep.me"]

    _ensure_device_key(str(home / "device.key"), data_dir=str(home))
    before = _snapshot(home)
    assert doctor_recovery.set_aside_identity_leftovers(str(home / "device.key"), str(home)) == []
    assert _snapshot(home) == before


def test_repeated_set_asides_never_replace_an_earlier_orphan(tmp_path):
    home = _home(tmp_path)
    kept: dict[str, bytes] = {}
    with patch.object(doctor_recovery.time, "gmtime", return_value=(2026, 11, 8, 12, 0, 0, 6, 312, 0)):
        for _ in range(3):
            _leftover_secret_and_sentinel(home)
            moved = doctor_recovery.set_aside_identity_leftovers(str(home / "device.key"), str(home))
            assert len(moved) == 2
            for path in moved:
                assert path not in kept
                kept[path] = Path(path).read_bytes()

    assert len(kept) == 6
    assert all(Path(path).read_bytes() == data for path, data in kept.items())
    assert len(_orphans(home)) == 6


def test_a_name_that_appears_during_a_set_aside_is_never_replaced(tmp_path):
    home = _home(tmp_path)
    moving = home / "moving"
    _write_private(moving, b"the file to keep")
    names = iter([b"\x01" * 6, b"\x02" * 6])
    arrival = home / f"moving.orphaned-stamp-{'01' * 6}"
    primitive = "rename" if os.name == "nt" else "link"
    real = getattr(os, primitive)
    calls: list[str] = []

    def arrives_first(source, destination, *args, **kwargs):
        if not calls:
            _write_private(arrival, b"an earlier orphan")  # appears after the name was chosen
        calls.append(os.fspath(destination))
        return real(source, destination, *args, **kwargs)

    with patch.object(doctor_recovery.os, "urandom", side_effect=lambda _n: next(names)):
        with patch.object(os, primitive, arrives_first):
            aside = doctor_recovery._move_aside(str(moving), "stamp")

    assert aside.endswith("02" * 6)
    assert len(calls) == 2
    assert arrival.read_bytes() == b"an earlier orphan"
    assert Path(aside).read_bytes() == b"the file to keep"
    assert not moving.exists()


def test_an_unusable_lock_file_stops_init_before_it_changes_the_home(tmp_path, monkeypatch):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    (home / "init.lock").mkdir()

    report = run_first_run(_options())

    assert report.status == "needs_attention"
    assert [(step.name, step.status) for step in report.setup] == [("Init lock", "fail")]
    assert "cannot take the init lock" in report.setup[0].detail
    assert sorted(path.name for path in home.iterdir()) == ["init.lock"]


def _home_naming_another_data_dir(tmp_path: Path, monkeypatch) -> tuple[Path, Path]:
    """A configured install home whose config.yaml names a data folder elsewhere."""

    home, data = _home(tmp_path, "install-home"), _home(tmp_path, "data-folder")
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    assert run_first_run(_options()).status != "needs_attention"
    config = home / "config.yaml"
    text = config.read_text()
    assert "\ndata_dir:" not in "\n" + text
    config.write_text(f"data_dir: {data}\n{text}")
    for path in home.iterdir():
        if path.name.startswith("device.") or ".orphaned-" in path.name:
            path.unlink()
    return home, data


@pytest.mark.parametrize("plain", [False, True])
def test_the_data_folder_the_config_names_is_locked_too(tmp_path, monkeypatch, plain):
    from click.testing import CliRunner
    from defenseclaw.commands.cmd_init import init_cmd
    from defenseclaw.context import AppContext

    home, data = _home_naming_another_data_dir(tmp_path, monkeypatch)
    monkeypatch.setattr(bootstrap, "_FIRST_RUN_LOCK_WAIT_SECONDS", 0.2)

    with locked_file_update(str(data / "init")):
        if plain:
            result = CliRunner().invoke(init_cmd, ["--skip-install"], obj=AppContext())
            assert result.exit_code != 0
            assert "another defenseclaw init is running" in result.output
        else:
            report = run_first_run(_options())
            assert report.status == "needs_attention"
            assert [(step.name, step.status) for step in report.setup] == [("Init lock", "fail")]
            assert str(data) in report.setup[0].detail

    assert not (data / "device.key").exists()
    assert not (data / SECRET).exists()


def test_the_data_folder_the_config_names_gets_the_identity_when_no_init_holds_it(tmp_path, monkeypatch):
    home, data = _home_naming_another_data_dir(tmp_path, monkeypatch)

    report = run_first_run(_options())

    assert report.status != "needs_attention", report.to_dict()
    assert _valid(data)
    assert (home / "init.lock").exists() and (data / "init.lock").exists()


def test_a_data_folder_that_is_the_home_is_locked_once(tmp_path, monkeypatch):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    monkeypatch.setattr(bootstrap, "_FIRST_RUN_LOCK_WAIT_SECONDS", 0.2)

    with bootstrap.hold_init_lock() as locks:
        locks.take(str(home))
        locks.take(str(home / ".." / home.name))


def test_the_plain_init_path_takes_the_same_lock(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from defenseclaw.commands.cmd_init import init_cmd
    from defenseclaw.context import AppContext

    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    monkeypatch.setattr(bootstrap, "_FIRST_RUN_LOCK_WAIT_SECONDS", 0.2)

    with locked_file_update(str(home / "init")):
        result = CliRunner().invoke(init_cmd, ["--skip-install"], obj=AppContext())

    assert result.exit_code != 0
    assert "another defenseclaw init is running" in result.output
    assert not (home / "config.yaml").exists()
    assert not (home / "device.key").exists()


def test_a_failed_creation_takes_back_every_file_it_published(tmp_path):
    home = _home(tmp_path)
    real_publish = doctor_recovery._publish_no_replace

    def fail_on_key(source: str, target: str) -> None:
        if target.endswith("device.key"):
            raise OSError("disk full")
        real_publish(source, target)

    with patch.object(doctor_recovery, "_publish_no_replace", fail_on_key):
        with pytest.raises(Exception, match="device-key-create-failed"):
            _ensure_device_key(str(home / "device.key"), data_dir=str(home))

    assert sorted(path.name for path in home.iterdir()) == []

    _ensure_device_key(str(home / "device.key"), data_dir=str(home))
    assert _valid(home)


# --- a key file that holds no key (cut short while it was published) -------------------------------
# The Windows publication writes the secret and the sentinel completely, then the key; a stop in the
# middle of the key leaves a key pathname with an empty or partial payload.  Init treats an existing
# pathname as present, so only the explicit repair can clear it, and only after asking.


def _cut_short_key(home: Path, size: int, *, configured: bool) -> bytes:
    """A complete identity whose key file was cut after *size* bytes; returns what the key file holds."""

    assert run_first_run(_options()).status != "needs_attention"
    key = home / "device.key"
    cut = key.read_bytes()[:size]
    key.write_bytes(cut)  # keeps the private mode the publication gave the file
    if not configured:
        (home / "config.yaml").unlink()
    assert not _valid(home)
    return cut


@pytest.mark.parametrize("configured", [False, True])
@pytest.mark.parametrize("size", [0, 20, 80])
def test_the_repair_command_replaces_a_key_file_cut_short_and_keeps_every_old_file(
    tmp_path, monkeypatch, size, configured
):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    cut = _cut_short_key(home, size, configured=configured)
    old = _identity_files(home)

    result = _repair()

    assert result.exit_code == 0, result.output
    assert str(home / "device.key") in result.output
    assert _valid(home)
    kept = {name.split(".orphaned-")[0]: (home / name).read_bytes() for name in _orphans(home)}
    assert kept == {"device.key": cut, "device.key.provenance": old["device.key.provenance"], SECRET: old[SECRET]}
    assert (home / SECRET).read_bytes() != old[SECRET]


def test_the_repair_command_asks_before_it_touches_a_key_file_cut_short(tmp_path, monkeypatch):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    _cut_short_key(home, 20, configured=True)
    before = _snapshot(home)

    result = _repair("n\n")

    assert result.exit_code != 0
    assert "nothing was changed" in result.output
    assert "holds no usable key" in result.output
    assert _snapshot(home) == before
    assert _orphans(home) == []


def test_init_leaves_a_key_file_cut_short_alone_and_doctor_names_the_repair(tmp_path, monkeypatch):
    from defenseclaw.commands import cmd_doctor

    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    _cut_short_key(home, 20, configured=True)
    before = _snapshot(home)
    cfg = type("Cfg", (), {})()
    cfg.data_dir = str(home)
    cfg.gateway = type("Gw", (), {"device_key_file": str(home / "device.key")})()
    health = cmd_doctor._DoctorResult()

    cmd_doctor._check_device_identity(cfg, health)

    assert health.checks[-1]["status"] == "fail"
    assert REPAIR_IDENTITY_COMMAND in health.checks[-1]["remediation"]
    assert _snapshot(home) == before


@pytest.mark.skipif(os.name == "nt", reason="creating a link needs a privilege on Windows")
def test_the_repair_command_never_replaces_a_linked_key_path(tmp_path, monkeypatch):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    outside = tmp_path / "elsewhere.key"
    outside.write_bytes(b"not a key")
    protect_private_file(str(outside))
    (home / "device.key").symlink_to(outside)
    before = (outside.read_bytes(), os.readlink(home / "device.key"))

    result = _repair()

    assert result.exit_code != 0
    assert "a device key already exists" in result.output
    assert (outside.read_bytes(), os.readlink(home / "device.key")) == before
    assert _orphans(home) == []


# --- the repair needs proof that the gateway is not running, as Doctor does ------------------------


def _gateway_running():
    from defenseclaw.commands import cmd_doctor

    return patch.object(
        cmd_doctor,
        "_managed_gateway_process_trust",
        return_value=cmd_doctor._GatewayTrust("trusted", "verified", 4321, home_bound=True),
    )


@pytest.mark.parametrize("state", ["key-gone-files-remain", "key-cut-short", "nothing-left-over"])
def test_the_repair_command_on_a_configured_home_changes_nothing_while_the_gateway_runs(
    tmp_path, monkeypatch, state
):
    home = _configured_home_without_key(tmp_path, monkeypatch)
    if state == "key-cut-short":
        (home / "device.key").write_bytes(b"")
        protect_private_file(str(home / "device.key"))
    elif state == "nothing-left-over":
        for name in (SECRET, "device.key.provenance"):
            (home / name).unlink()
    before = _snapshot(home)

    with _gateway_running():
        refused = _repair()

    assert refused.exit_code != 0
    assert "verified managed gateway process is running" in refused.output
    assert "nothing was changed" in refused.output
    assert _snapshot(home) == before
    assert _orphans(home) == []

    assert _repair().exit_code == 0  # once the gateway is stopped, the same command repairs it
    assert _valid(home)


def test_the_repair_command_before_any_config_does_not_need_a_gateway_check(tmp_path, monkeypatch):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    _leftover_secret_and_sentinel(home)

    with _gateway_running():
        result = _repair()

    assert result.exit_code == 0, result.output
    assert _valid(home)


@pytest.mark.parametrize("override", ["absent-path", "other-config"])
@pytest.mark.parametrize("size", [0, 20])
def test_a_config_override_never_hides_the_gateway_of_a_home_that_is_configured(
    tmp_path, monkeypatch, override, size
):
    # DEFENSECLAW_CONFIG names a file that is absent, or another config, while the home own
    # config.yaml exists: the gateway of that home may still run, so the repair needs the proof.
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    _cut_short_key(home, size, configured=True)
    root = Path(os.path.realpath(tmp_path))
    if override == "other-config":
        other = root / "other" / "config.yaml"
        other.parent.mkdir()
        other.write_text((home / "config.yaml").read_text())
        monkeypatch.setenv("DEFENSECLAW_CONFIG", str(other))
    else:
        monkeypatch.setenv("DEFENSECLAW_CONFIG", str(root / "absent" / "config.yaml"))
    before = _snapshot(home)

    with _gateway_running():
        refused = _repair()

    assert refused.exit_code != 0
    assert "verified managed gateway process is running" in refused.output
    assert _snapshot(home) == before
    assert _orphans(home) == []

    assert _repair().exit_code == 0  # with the gateway stopped, the same command repairs it
    assert _valid(home)


def test_the_repair_command_with_an_absent_override_and_no_home_config_needs_no_gateway_check(
    tmp_path, monkeypatch
):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    _cut_short_key(home, 20, configured=False)
    monkeypatch.setenv("DEFENSECLAW_CONFIG", str(Path(os.path.realpath(tmp_path)) / "absent" / "config.yaml"))

    with _gateway_running():
        result = _repair()

    assert result.exit_code == 0, result.output
    assert _valid(home)
