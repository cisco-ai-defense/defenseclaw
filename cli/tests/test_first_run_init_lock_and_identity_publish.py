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
refused.  Init now holds one lock on every data folder it initializes, and a
device identity is published all or nothing.  A keyless provenance file that a
crash still leaves is continuity evidence: DefenseClaw never replaces it.  Init
and Doctor stop, name the file and print the manual steps (stop the gateway,
confirm no other init runs, remove the file, run init again).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import threading
from pathlib import Path
from unittest.mock import patch

import click
import pytest
from click.testing import CliRunner
from defenseclaw import bootstrap, doctor_recovery
from defenseclaw.bootstrap import FirstRunOptions, run_first_run
from defenseclaw.commands.cmd_init import _ensure_device_key, init_cmd
from defenseclaw.context import AppContext
from defenseclaw.doctor_recovery import DeviceKeyHealthStatus, inspect_device_key
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


def _plain_init(*args: str):
    return CliRunner().invoke(init_cmd, ["--skip-install", *args], obj=AppContext())


def _snapshot(home: Path) -> dict[str, bytes]:
    return {path.name: path.read_bytes() for path in home.iterdir() if path.is_file()}


def _identity_files(home: Path) -> dict[str, bytes]:
    return {name: data for name, data in _snapshot(home).items() if name.startswith("device.")}


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




# --- no keyless artifact survives a stop during publication --------------------------------------

_PUBLISH_SUFFIX = {"secret": SECRET, "sentinel": ".provenance", "key": "device.key"}


def _stop_publishing(stop_at: str, error: BaseException):
    real_publish = doctor_recovery._publish_no_replace

    def publish(source: str, target: str) -> None:
        if target.endswith(_PUBLISH_SUFFIX[stop_at]):
            raise error
        real_publish(source, target)

    return patch.object(doctor_recovery, "_publish_no_replace", publish)


@pytest.mark.parametrize("stop_at", ["secret", "sentinel", "key"])
@pytest.mark.parametrize("error", [OSError("disk full"), KeyboardInterrupt()], ids=["error", "interrupt"])
def test_a_stop_during_publication_never_leaves_a_keyless_artifact(tmp_path, stop_at, error):
    home = _home(tmp_path)

    with _stop_publishing(stop_at, error):
        with pytest.raises((click.ClickException, KeyboardInterrupt)):
            _ensure_device_key(str(home / "device.key"), data_dir=str(home))

    assert list(home.iterdir()) == []
    _ensure_device_key(str(home / "device.key"), data_dir=str(home))
    assert _valid(home)


def test_a_key_that_fails_its_checks_after_publication_is_taken_back_with_its_provenance(tmp_path):
    home = _home(tmp_path)

    with patch.object(doctor_recovery, "_device_key_postconditions", return_value=False):
        with pytest.raises(click.ClickException, match="device-key-postcondition-failed"):
            _ensure_device_key(str(home / "device.key"), data_dir=str(home))

    assert list(home.iterdir()) == []


@pytest.mark.parametrize("stop_at", ["sentinel", "key"])
def test_an_init_stopped_between_the_artifacts_and_the_key_leaves_a_home_the_next_init_completes(
    tmp_path, monkeypatch, stop_at
):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))

    with _stop_publishing(stop_at, OSError("process ended")):
        first = run_first_run(_options())

    assert first.status == "needs_attention"
    assert not [name for name in os.listdir(home) if name.startswith("device.") or name == SECRET]
    assert run_first_run(_options()).status != "needs_attention"
    assert _valid(home)
    assert _orphans(home) == []


# --- a keyless artifact that is still there is never replaced; the way out is manual ----------------

_MANUAL_STEPS = (
    "defenseclaw-gateway stop",
    "no other defenseclaw init is running",
    "remove ",
    "run defenseclaw init again",
)


def _plant(home: Path, shape: str) -> list[Path]:
    """Leave a keyless artifact the way a killed init does; returns the files that remain."""

    _leftover_secret_and_sentinel(home)
    if shape == "secret-only":
        (home / "device.key.provenance").unlink()
    elif shape == "sentinel-only":
        (home / SECRET).unlink()
    return [path for path in (home / SECRET, home / "device.key.provenance") if path.exists()]


def _assert_manual_steps(output: str, home: Path, files: list[Path]) -> None:
    for path in files:
        assert str(path) in output
    for step in _MANUAL_STEPS:
        assert step in output
    assert str(home / "device.key") in output
    assert "defenseclaw init --repair-identity" not in output


@pytest.mark.parametrize("plain", [False, True])
@pytest.mark.parametrize("shape", ["secret-only", "sentinel-only", "both"])
def test_a_planted_keyless_artifact_stops_init_with_the_manual_steps_and_replaces_nothing(
    tmp_path, monkeypatch, plain, shape
):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    files = _plant(home, shape)
    before = _identity_files(home)

    if plain:
        result = _plain_init()
        assert result.exit_code != 0
        output = result.output
    else:
        report = run_first_run(_options())
        assert report.status == "needs_attention"
        assert "defenseclaw init" in report.next_commands
        output = " ".join(step.detail for step in report.setup)
    _assert_manual_steps(output, home, files)

    assert _identity_files(home) == before
    assert not (home / "device.key").exists()
    assert _orphans(home) == []

    # The documented way out works: remove the named file(s), run init again.
    for path in files:
        path.unlink()
    if plain:
        # The plain path stops on a step this test home cannot finish (no gateway); it no longer
        # stops on the leftover.
        assert "continuity-evidence-present" not in _plain_init().output
    else:
        assert run_first_run(_options()).status != "needs_attention"
        assert _valid(home)


def test_a_planted_keyless_artifact_on_a_configured_home_is_not_replaced_either(tmp_path, monkeypatch):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    assert run_first_run(_options()).status != "needs_attention"
    (home / "device.key").unlink()
    before = _identity_files(home)

    report = run_first_run(_options())

    assert report.status == "needs_attention"
    _assert_manual_steps(
        " ".join(step.detail for step in report.setup), home, [home / SECRET, home / "device.key.provenance"]
    )
    assert _identity_files(home) == before
    assert _orphans(home) == []


@pytest.mark.parametrize("shape", ["secret-only", "sentinel-only", "both"])
def test_doctor_names_the_files_and_the_manual_steps_and_replaces_nothing(tmp_path, shape):
    from defenseclaw.commands import cmd_doctor

    home = _home(tmp_path)
    cfg = type("Cfg", (), {})()
    cfg.data_dir = str(home)
    cfg.gateway = type("Gw", (), {"device_key_file": str(home / "device.key")})()
    files = _plant(home, shape)
    before = _identity_files(home)
    result = cmd_doctor._DoctorResult()

    cmd_doctor._check_device_identity(cfg, result)

    assert result.failed == 1
    check = result.checks[-1]
    assert check["status"] == "fail"
    _assert_manual_steps(check["remediation"], home, files)
    assert _identity_files(home) == before
    assert _orphans(home) == []


def test_init_has_no_identity_repair_option():
    result = CliRunner().invoke(init_cmd, ["--repair-identity"], obj=AppContext())

    assert result.exit_code == 2
    assert "No such option" in result.output
