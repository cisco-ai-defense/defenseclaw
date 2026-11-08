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
the home, and a device identity is published all or nothing: a leftover that is
provably an unfinished creation is set aside and created again, while a
keyless provenance file that is not stays continuity evidence.
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

PENDING = "device.identity.creating"
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
    assert not (home / PENDING).exists()
    assert _orphans(home) == []


def test_a_creation_that_stops_before_the_key_is_repaired_by_the_next_init(tmp_path, monkeypatch):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    real_publish = doctor_recovery._publish_no_replace

    def die_before_key(source: str, target: str) -> None:
        if target.endswith("device.key"):
            raise OSError("process ended before the key was published")
        real_publish(source, target)

    with monkeypatch.context() as crash:
        crash.setattr(doctor_recovery, "_publish_no_replace", die_before_key)
        crash.setattr(doctor_recovery, "_roll_back_device_identity", lambda placed: [])
        first = run_first_run(_options())
    assert first.status == "needs_attention"
    assert (home / PENDING).exists() and (home / SECRET).exists()
    assert not (home / "device.key").exists()

    second = run_first_run(_options())

    assert second.status != "needs_attention", second.to_dict()
    assert _valid(home)
    assert not (home / PENDING).exists()
    assert any(name.startswith(SECRET + ".orphaned-") for name in _orphans(home))


def _write_private(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    protect_private_file(str(path))


def _crashed_creation(home: Path) -> None:
    """The files a creation leaves when it stops before the key is published."""

    secret = os.urandom(32)
    digest = hmac.new(secret, b"a key that never was", hashlib.sha256).hexdigest().encode("ascii")
    _write_private(home / PENDING, doctor_recovery._pending_marker_bytes(secret))
    _write_private(home / SECRET, secret)
    _write_private(home / "device.key.provenance", b"defenseclaw-device-provenance-v1:" + digest + b"\n")


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


def test_an_authentic_marker_repairs_a_home_that_already_has_a_config(tmp_path, monkeypatch):
    home = _configured_home_without_key(tmp_path, monkeypatch)
    for name in ("device.key.provenance", SECRET):
        (home / name).unlink()
    _crashed_creation(home)

    report = run_first_run(_options())

    assert report.status != "needs_attention", report.to_dict()
    assert _valid(home)
    assert not (home / PENDING).exists()
    assert len(_orphans(home)) == 3


def test_a_marker_dropped_into_a_configured_home_does_not_reset_the_identity(tmp_path, monkeypatch):
    home = _configured_home_without_key(tmp_path, monkeypatch)
    secret_before = (home / SECRET).read_bytes()
    _write_private(home / PENDING, b"anything at all\n")

    _refused_with_nothing_moved(run_first_run(_options()), home, secret_before)
    assert (home / PENDING).read_bytes() == b"anything at all\n"


def test_a_marker_made_for_other_files_does_not_reset_the_identity(tmp_path, monkeypatch):
    home = _configured_home_without_key(tmp_path, monkeypatch)
    secret_before = (home / SECRET).read_bytes()
    _write_private(home / PENDING, doctor_recovery._pending_marker_bytes(os.urandom(32)))

    _refused_with_nothing_moved(run_first_run(_options()), home, secret_before)


@pytest.mark.skipif(os.name == "nt", reason="needs an unprivileged symlink")
def test_a_marker_beside_a_linked_secret_does_not_reset_the_identity(tmp_path, monkeypatch):
    home = _configured_home_without_key(tmp_path, monkeypatch)
    real = tmp_path / "elsewhere.secret"
    _write_private(real, (home / SECRET).read_bytes())
    (home / SECRET).unlink()
    os.symlink(real, home / SECRET)
    _write_private(home / PENDING, doctor_recovery._pending_marker_bytes(real.read_bytes()))

    report = run_first_run(_options())

    assert report.status == "needs_attention"
    assert (home / SECRET).is_symlink()
    assert not (home / "device.key").exists()
    assert _orphans(home) == []


def test_a_stale_marker_alone_is_set_aside_and_the_identity_is_created(tmp_path, monkeypatch):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    _write_private(home / PENDING, b"left by a stopped run\n")

    report = run_first_run(_options())

    assert report.status != "needs_attention", report.to_dict()
    assert _valid(home)
    assert [name.split(".orphaned-")[0] for name in _orphans(home)] == [PENDING]


def test_repeated_set_asides_never_replace_an_earlier_orphan(tmp_path):
    home = _home(tmp_path)
    kept: dict[str, bytes] = {}
    with patch.object(doctor_recovery.time, "gmtime", return_value=(2026, 11, 8, 12, 0, 0, 6, 312, 0)):
        for _ in range(3):
            _crashed_creation(home)
            moved = doctor_recovery.set_aside_abandoned_identity(
                str(home / "device.key"), str(home), fresh_home=False
            )
            assert len(moved) == 3
            for path in moved:
                assert path not in kept
                kept[path] = Path(path).read_bytes()

    assert len(kept) == 9
    assert all(Path(path).read_bytes() == data for path, data in kept.items())
    assert len(_orphans(home)) == 9


def test_an_unusable_lock_file_stops_init_before_it_changes_the_home(tmp_path, monkeypatch):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    (home / "init.lock").mkdir()

    report = run_first_run(_options())

    assert report.status == "needs_attention"
    assert [(step.name, step.status) for step in report.setup] == [("Init lock", "fail")]
    assert "cannot take the init lock" in report.setup[0].detail
    assert sorted(path.name for path in home.iterdir()) == ["init.lock"]


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


def test_a_home_an_earlier_build_left_half_created_is_repaired_by_init(tmp_path, monkeypatch):
    # The shape GAP-0927 left behind: provenance files, no key, no config.yaml.
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    _leftover_secret_and_sentinel(home)

    report = run_first_run(_options())

    assert report.status != "needs_attention", report.to_dict()
    assert _valid(home)
    assert len(_orphans(home)) == 2


def test_keyless_provenance_on_a_configured_home_is_still_refused(tmp_path, monkeypatch):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    assert run_first_run(_options()).status != "needs_attention"
    (home / "device.key").unlink()
    secret_before = (home / SECRET).read_bytes()

    report = run_first_run(_options())

    assert report.status == "needs_attention"
    assert any("continuity-evidence-present" in step.detail for step in report.setup)
    assert (home / SECRET).read_bytes() == secret_before
    assert not (home / "device.key").exists()
    assert _orphans(home) == []


def test_unrecognised_provenance_files_on_a_fresh_home_are_not_set_aside(tmp_path):
    home = _home(tmp_path)
    (home / SECRET).write_bytes(b"not what a creation writes")
    protect_private_file(str(home / SECRET))

    with pytest.raises(Exception, match="continuity-evidence-present"):
        _ensure_device_key(str(home / "device.key"), data_dir=str(home), fresh_home=True)

    assert (home / SECRET).read_bytes() == b"not what a creation writes"
    assert _orphans(home) == []


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
    assert not (home / PENDING).exists()


def test_a_marker_that_outlives_a_finished_creation_is_dropped(tmp_path):
    home = _home(tmp_path)
    key = home / "device.key"
    key.write_bytes(_new_device_key_pem())
    protect_private_file(str(key))
    (home / PENDING).write_bytes(b"device identity creation in progress\n")

    _ensure_device_key(str(key), data_dir=str(home))

    assert not (home / PENDING).exists()
    assert key.exists()
