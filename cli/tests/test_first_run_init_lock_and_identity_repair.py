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
nothing.  Only a home found without a config.yaml sets the leftovers of an
unfinished creation aside (nothing stored in a home can authorize that) and
creates the identity again; a keyless provenance file on a configured home
stays continuity evidence, whatever else sits beside it.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import threading
from pathlib import Path
from unittest.mock import patch

import pytest
from defenseclaw import bootstrap, doctor_recovery
from defenseclaw.bootstrap import FirstRunOptions, run_first_run
from defenseclaw.commands.cmd_init import _ensure_device_key
from defenseclaw.doctor_recovery import (
    DeviceKeyHealthStatus,
    _new_device_key_pem,
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


def test_a_creation_that_stops_before_the_sentinel_is_repaired_by_the_next_init(tmp_path, monkeypatch):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
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

    second = run_first_run(_options())

    assert second.status != "needs_attention", second.to_dict()
    assert _valid(home)
    assert any(name.startswith(SECRET + ".orphaned-") for name in _orphans(home))


def _write_private(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    protect_private_file(str(path))


def _configured_home_without_key(tmp_path: Path, monkeypatch) -> Path:
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    assert run_first_run(_options()).status != "needs_attention"
    (home / "device.key").unlink()
    return home


def _refused_with_nothing_moved(report, home: Path, secret_before: bytes) -> None:
    assert report.status == "needs_attention"
    assert any("continuity-evidence-present" in step.detail for step in report.setup)
    assert (home / SECRET).read_bytes() == secret_before
    assert not (home / "device.key").exists()
    assert _orphans(home) == []


def test_keyless_provenance_on_a_configured_home_is_still_refused(tmp_path, monkeypatch):
    home = _configured_home_without_key(tmp_path, monkeypatch)
    secret_before = (home / SECRET).read_bytes()

    _refused_with_nothing_moved(run_first_run(_options()), home, secret_before)


def test_a_file_made_from_the_secret_in_a_configured_home_does_not_reset_the_identity(tmp_path, monkeypatch):
    # Whoever can write the home can compute any proof from the secret it holds.
    home = _configured_home_without_key(tmp_path, monkeypatch)
    secret_before = (home / SECRET).read_bytes()
    prefix = b"defenseclaw-device-identity-creating-v1:"
    mac = hmac.new(secret_before, prefix, hashlib.sha256).hexdigest().encode("ascii")
    _write_private(home / "device.identity.creating", prefix + mac + b"\n")

    _refused_with_nothing_moved(run_first_run(_options()), home, secret_before)
    assert (home / "device.identity.creating").is_file()


def test_a_configured_home_stays_refused_for_a_cut_short_secret_too(tmp_path, monkeypatch):
    home = _configured_home_without_key(tmp_path, monkeypatch)
    _write_private(home / SECRET, os.urandom(12))
    secret_before = (home / SECRET).read_bytes()

    _refused_with_nothing_moved(run_first_run(_options()), home, secret_before)


def test_a_complete_sentinel_with_no_key_and_no_config_is_kept_for_the_attended_repair(tmp_path, monkeypatch):
    # The same state as a key deleted from a finished setup whose config.yaml is gone.
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    _leftover_secret_and_sentinel(home)
    secret_before = (home / SECRET).read_bytes()

    _refused_with_nothing_moved(run_first_run(_options()), home, secret_before)


def test_a_finished_setup_that_lost_its_config_and_key_keeps_its_identity(tmp_path, monkeypatch):
    home = _configured_home_without_key(tmp_path, monkeypatch)
    (home / "config.yaml").unlink()
    secret_before = (home / SECRET).read_bytes()

    _refused_with_nothing_moved(run_first_run(_options()), home, secret_before)


@pytest.mark.parametrize("plain", [False, True])
@pytest.mark.parametrize("cut_short", [False, True])
def test_a_moved_config_path_does_not_make_a_configured_data_folder_fresh(tmp_path, monkeypatch, plain, cut_short):
    home = _configured_home_without_key(tmp_path, monkeypatch)
    if cut_short:  # only a cut-short secret is left, which a fresh home would repair
        (home / "device.key.provenance").unlink()
        _write_private(home / SECRET, os.urandom(12))
    secret_before = (home / SECRET).read_bytes()
    elsewhere = Path(os.path.realpath(tmp_path)) / "elsewhere" / "config.yaml"
    monkeypatch.setenv("DEFENSECLAW_CONFIG", str(elsewhere))

    if plain:
        from click.testing import CliRunner
        from defenseclaw.commands.cmd_init import init_cmd
        from defenseclaw.context import AppContext

        result = CliRunner().invoke(init_cmd, ["--skip-install"], obj=AppContext())
        assert result.exit_code != 0
        assert "continuity-evidence-present" in result.output
    else:
        _refused_with_nothing_moved(run_first_run(_options()), home, secret_before)
    assert (home / SECRET).read_bytes() == secret_before
    assert not (home / "device.key").exists()
    assert _orphans(home) == []
    assert (home / "config.yaml").is_file()


def _init(plain: bool):
    """One init run on either path: (exit code or report status, a view of the refusal)."""

    if not plain:
        report = run_first_run(_options())
        return report.status, any("continuity-evidence-present" in step.detail for step in report.setup)
    from click.testing import CliRunner
    from defenseclaw.commands.cmd_init import init_cmd
    from defenseclaw.context import AppContext

    result = CliRunner().invoke(init_cmd, ["--skip-install"], obj=AppContext())
    return result.exit_code, "continuity-evidence-present" in result.output


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


def _lose_the_key(home: Path, shape: str) -> None:
    (home / "device.key").unlink()
    sentinel = home / "device.key.provenance"
    if shape == "secret-only":
        sentinel.unlink()
    elif shape == "partial-sentinel":
        sentinel.write_bytes(sentinel.read_bytes()[:60])
        protect_private_file(str(sentinel))
    else:  # the folder carries no record of earlier inits (made by a build that wrote none)
        sentinel.unlink()
        (home / "init.configs").unlink()


@pytest.mark.parametrize("plain", [False, True])
@pytest.mark.parametrize("shape", ["secret-only", "partial-sentinel", "no-record"])
def test_a_config_kept_at_an_earlier_override_path_keeps_the_identity_of_its_data_folder(
    tmp_path, monkeypatch, plain, shape
):
    home, first = _finished_setup_whose_config_is_elsewhere(tmp_path, monkeypatch)
    _lose_the_key(home, shape)
    before = {path.name: path.read_bytes() for path in home.iterdir() if path.is_file()}
    monkeypatch.setenv("DEFENSECLAW_CONFIG", str(Path(os.path.realpath(tmp_path)) / "second" / "config.yaml"))

    outcome, refused = _init(plain)

    assert refused, outcome
    assert outcome in ("needs_attention", 1)
    assert not (home / "device.key").exists()
    assert _orphans(home) == []
    assert {name: data for name, data in before.items() if name != "init.configs"}.items() <= {
        path.name: path.read_bytes() for path in home.iterdir() if path.is_file()
    }.items()
    assert first.is_file()


def test_an_interrupted_first_creation_is_still_repaired_when_the_config_path_is_an_override(tmp_path, monkeypatch):
    # The benign twin: the folder was only ever initialised by runs that never finished
    # (a guided run rolls its config back; a plain run keeps it, which is a finished setup).
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    monkeypatch.setenv("DEFENSECLAW_CONFIG", str(Path(os.path.realpath(tmp_path)) / "first" / "config.yaml"))
    real_publish = doctor_recovery._publish_no_replace

    def die_before_sentinel(source: str, target: str) -> None:
        if target.endswith(".provenance"):
            raise OSError("process ended before the sentinel was published")
        real_publish(source, target)

    with monkeypatch.context() as crash:
        crash.setattr(doctor_recovery, "_publish_no_replace", die_before_sentinel)
        crash.setattr(doctor_recovery, "_roll_back_device_identity", lambda placed: [])
        assert run_first_run(_options()).status == "needs_attention"
    assert (home / SECRET).exists() and not (home / "device.key").exists()
    assert (home / "audit.db").exists()  # the folder holds more than identity files, so the record decides
    monkeypatch.setenv("DEFENSECLAW_CONFIG", str(Path(os.path.realpath(tmp_path)) / "second" / "config.yaml"))

    status, refused = _init(False)

    assert not refused
    assert status != "needs_attention"
    assert _valid(home)
    assert any(name.startswith(SECRET + ".orphaned-") for name in _orphans(home))


def test_the_record_of_earlier_inits_is_kept_to_a_bounded_list_of_paths(tmp_path, monkeypatch):
    home = _home(tmp_path)
    for index in range(40):
        monkeypatch.setenv("DEFENSECLAW_CONFIG", str(home / f"c{index}" / "config.yaml"))
        bootstrap.begin_data_folder_init(str(home))
    lines = (home / "init.configs").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 32
    assert lines[-1].endswith(os.path.join("c39", "config.yaml"))


def test_a_key_the_normal_validator_accepts_is_kept_whatever_its_last_byte_is(tmp_path, monkeypatch):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    key = _new_device_key_pem().rstrip(b"\n")
    secret = os.urandom(32)
    sentinel = b"defenseclaw-device-provenance-v1:" + hmac.new(secret, key, hashlib.sha256).hexdigest().encode() + b"\n"
    for name, data in (("device.key", key), (SECRET, secret), ("device.key.provenance", sentinel)):
        _write_private(home / name, data)
    assert _valid(home)

    report = run_first_run(_options())

    assert _valid(home)
    assert (home / "device.key").read_bytes() == key
    assert (home / SECRET).read_bytes() == secret
    assert _orphans(home) == []
    assert report.status != "needs_attention", report.to_dict()


def _cut_short_creation(home: Path, *, secret_length: int, sentinel_length: int, key_length: int | None) -> None:
    """The files an interrupted Windows CREATE_NEW publication can leave: each cut anywhere."""

    secret = os.urandom(32)
    key = _new_device_key_pem()
    digest = hmac.new(secret, key, hashlib.sha256).hexdigest().encode("ascii")
    sentinel = b"defenseclaw-device-provenance-v1:" + digest + b"\n"
    _write_private(home / SECRET, secret[:secret_length])
    _write_private(home / "device.key.provenance", sentinel[:sentinel_length])
    if key_length is not None:
        _write_private(home / "device.key", key[:key_length])


@pytest.mark.parametrize(
    ("secret_length", "sentinel_length", "key_length"),
    [
        (0, 0, None),
        (1, 0, None),
        (31, 0, None),
        (32, 5, None),
        (32, 33, None),
        (32, 34, None),
        (32, 97, None),
        (32, 98, 0),
        (32, 98, 20),
        (32, 98, 36),
        (32, 98, 60),
        (32, 98, 80),
    ],
)
def test_a_fresh_home_with_a_cut_short_creation_is_repaired_by_init(
    tmp_path, monkeypatch, secret_length, sentinel_length, key_length
):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    _cut_short_creation(home, secret_length=secret_length, sentinel_length=sentinel_length, key_length=key_length)
    before = {path.name: path.read_bytes() for path in home.iterdir()}

    report = run_first_run(_options())

    assert report.status != "needs_attention", report.to_dict()
    assert _valid(home)
    moved = {name.split(".orphaned-")[0]: (home / name).read_bytes() for name in _orphans(home)}
    assert moved == before


def test_nothing_is_set_aside_unless_the_home_is_fresh(tmp_path):
    home = _home(tmp_path)
    _leftover_secret_and_sentinel(home)
    before = {path.name: path.read_bytes() for path in home.iterdir()}

    moved = doctor_recovery.set_aside_abandoned_identity(str(home / "device.key"), str(home), fresh_home=False)

    assert moved == []
    assert {path.name: path.read_bytes() for path in home.iterdir()} == before


def test_a_fresh_home_keeps_a_complete_key_and_files_that_are_not_a_creation(tmp_path):
    home = _home(tmp_path)
    key = _new_device_key_pem()
    _write_private(home / "device.key", key)
    _write_private(home / SECRET, os.urandom(32))
    _write_private(home / "device.key.provenance", b"defenseclaw-device-provenance-v1:" + b"0" * 64 + b"\n")

    _ensure_device_key(str(home / "device.key"), data_dir=str(home), fresh_home=True)

    assert (home / "device.key").read_bytes() == key
    assert _orphans(home) == []


@pytest.mark.parametrize(
    "bad",
    [
        {SECRET: os.urandom(33)},
        {SECRET: os.urandom(16), "device.key.provenance": b"not a sentinel"},
        {SECRET: os.urandom(32), "device.key.provenance": b"defenseclaw-device-provenance-v1:" + b"g" * 64},
        {"device.key.provenance": b"defenseclaw-device-provenance-v1:" + b"0" * 64 + b"\nextra"},
        {SECRET: os.urandom(32), "device.key": b"-----BEGIN ED25519 PRIVATE KEY-----\n" + b"A" * 43 + b"!"},
    ],
)
def test_unrecognised_files_on_a_fresh_home_are_not_set_aside(tmp_path, bad):
    home = _home(tmp_path)
    for name, data in bad.items():
        _write_private(home / name, data)

    if "device.key" in bad:
        _ensure_device_key(str(home / "device.key"), data_dir=str(home), fresh_home=True)  # a key is left alone
    else:
        with pytest.raises(Exception, match="continuity-evidence-present"):
            _ensure_device_key(str(home / "device.key"), data_dir=str(home), fresh_home=True)

    assert {path.name: path.read_bytes() for path in home.iterdir()} == bad


def test_repeated_set_asides_never_replace_an_earlier_orphan(tmp_path):
    home = _home(tmp_path)
    kept: dict[str, bytes] = {}
    with patch.object(doctor_recovery.time, "gmtime", return_value=(2026, 11, 8, 12, 0, 0, 6, 312, 0)):
        for _ in range(3):
            _cut_short_creation(home, secret_length=32, sentinel_length=60, key_length=None)
            moved = doctor_recovery.set_aside_abandoned_identity(
                str(home / "device.key"), str(home), fresh_home=True
            )
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


def test_the_plain_init_path_repairs_a_fresh_home_left_half_created(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from defenseclaw.commands.cmd_init import init_cmd
    from defenseclaw.context import AppContext

    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    _cut_short_creation(home, secret_length=32, sentinel_length=60, key_length=None)

    result = CliRunner().invoke(init_cmd, ["--skip-install"], obj=AppContext())

    assert result.exit_code == 0, result.output
    assert _valid(home)
    assert len(_orphans(home)) == 2


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
