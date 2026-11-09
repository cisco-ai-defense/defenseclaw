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

import base64
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
    real_publish = doctor_recovery._publish_identity_file

    def fail_on_key(plan, source: str, target: str) -> None:
        if target.endswith("device.key"):
            raise OSError("disk full")
        real_publish(plan, source, target)

    with patch.object(doctor_recovery, "_publish_identity_file", fail_on_key):
        with pytest.raises(Exception, match="device-key-create-failed"):
            _ensure_device_key(str(home / "device.key"), data_dir=str(home))

    assert sorted(path.name for path in home.iterdir()) == []

    _ensure_device_key(str(home / "device.key"), data_dir=str(home))
    assert _valid(home)




# --- no keyless artifact survives a stop during publication --------------------------------------

_PUBLISH_SUFFIX = {"secret": SECRET, "sentinel": ".provenance", "key": "device.key"}


def _stop_publishing(stop_at: str, error: BaseException):
    real_publish = doctor_recovery._publish_identity_file

    def publish(plan, source: str, target: str) -> None:
        if target.endswith(_PUBLISH_SUFFIX[stop_at]):
            raise error
        real_publish(plan, source, target)

    return patch.object(doctor_recovery, "_publish_identity_file", publish)


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


@pytest.mark.skipif(os.name == "nt", reason="the directory sync after a publication is a POSIX step")
def test_a_directory_sync_that_fails_after_a_publication_takes_that_file_back(tmp_path):
    home = _home(tmp_path)

    with patch.object(doctor_recovery, "_fsync_directory", side_effect=OSError("sync failed")):
        with pytest.raises(click.ClickException, match="device-key-create-failed"):
            _ensure_device_key(str(home / "device.key"), data_dir=str(home))

    assert list(home.iterdir()) == []


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


# --- an empty or cut-short key is not a finished identity ------------------------------------------

_SHORT_KEYS = {"empty": b"", "cut-short": b"-----BEGIN ED25519 PRIVATE KEY-----\nMC4CAQAwBQYDK2Vw"}


def _home_with_short_key(tmp_path, monkeypatch, shape: str) -> Path:
    """Leave what a creation stopped during the key write leaves: the provenance files and a short key."""

    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    _leftover_secret_and_sentinel(home)
    (home / "device.key").write_bytes(_SHORT_KEYS[shape])
    protect_private_file(str(home / "device.key"))
    return home


def test_a_finished_identity_is_accepted_by_a_second_init(tmp_path, monkeypatch):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    assert run_first_run(_options()).status != "needs_attention"
    before = _identity_files(home)

    assert run_first_run(_options()).status != "needs_attention"
    assert _identity_files(home) == before
    assert _valid(home)


@pytest.mark.parametrize("plain", [False, True])
@pytest.mark.parametrize("shape", sorted(_SHORT_KEYS))
def test_an_empty_or_cut_short_key_stops_init_with_the_manual_steps_and_changes_no_identity_file(
    tmp_path, monkeypatch, plain, shape
):
    home = _home_with_short_key(tmp_path, monkeypatch, shape)
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

    for path in (home / "device.key", home / SECRET, home / "device.key.provenance"):
        assert str(path) in output
    for step in _MANUAL_STEPS[:2] + ("run defenseclaw init again",):
        assert step in output
    assert "holds no usable key" in output
    assert _identity_files(home) == before
    assert _orphans(home) == []

    # The documented way out works: remove the named files, run init again.
    for name in ("device.key", SECRET, "device.key.provenance"):
        (home / name).unlink()
    assert run_first_run(_options()).status != "needs_attention"
    assert _valid(home)


@pytest.mark.parametrize("shape", sorted(_SHORT_KEYS))
def test_doctor_names_the_unusable_key_file_and_replaces_nothing(tmp_path, monkeypatch, shape):
    from defenseclaw.commands import cmd_doctor

    home = _home_with_short_key(tmp_path, monkeypatch, shape)
    cfg = type("Cfg", (), {})()
    cfg.data_dir = str(home)
    cfg.gateway = type("Gw", (), {"device_key_file": str(home / "device.key")})()
    before = _identity_files(home)
    result = cmd_doctor._DoctorResult()

    cmd_doctor._check_device_identity(cfg, result)

    check = result.checks[-1]
    assert check["status"] == "fail"
    assert check["reason_code"] == "device-key-payload-invalid"
    for path in (home / "device.key", home / SECRET, home / "device.key.provenance"):
        assert str(path) in check["remediation"]
    assert "defenseclaw-gateway stop" in check["remediation"]
    assert "device-key.initialize" not in check["remediation"]
    assert _identity_files(home) == before
    assert _orphans(home) == []


def test_plain_init_does_not_claim_that_nothing_was_changed_when_it_stops_on_a_keyless_artifact(
    tmp_path, monkeypatch
):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    _plant(home, "both")

    result = _plain_init()

    assert result.exit_code != 0
    assert "nothing was changed" not in result.output
    assert "leaves them as they are" in result.output
    # Plain init saves its config before the identity step; the message must not deny that.
    assert (home / "config.yaml").exists()


# --- one test of whether an existing key is usable: init, Doctor and readiness agree --------------------


def _doctor_check(home: Path):
    from defenseclaw.commands import cmd_doctor

    cfg = type("Cfg", (), {})()
    cfg.data_dir = str(home)
    cfg.gateway = type("Gw", (), {"device_key_file": str(home / "device.key")})()
    result = cmd_doctor._DoctorResult()
    cmd_doctor._check_device_identity(cfg, result)
    return result.checks[-1]


def _plant_key(home: Path, shape: str) -> str:
    """Plant an existing device.key in one unusable state; returns the reason code every check must give."""

    key = home / "device.key"
    if shape == "empty-mode-0644":
        key.write_bytes(b"")
        os.chmod(key, 0o644)
        return "device-key-custody-invalid"
    if shape == "empty-through-a-link":
        target = home.parent / "elsewhere.key"
        target.write_bytes(b"")
        protect_private_file(str(target))
        os.symlink(target, key)
        return "target-is-not-regular-file"
    if shape == "oversized":
        key.write_bytes(b"x" * (doctor_recovery._DEVICE_KEY_READ_LIMIT + 1))
        protect_private_file(str(key))
        return "device-key-read-failed"
    if shape == "not-a-key":
        key.write_bytes(b"not a key\n")
        protect_private_file(str(key))
        return doctor_recovery.DEVICE_KEY_PAYLOAD_INVALID
    raise AssertionError(shape)


_POSIX_ONLY = {"empty-mode-0644", "empty-through-a-link"}


@pytest.mark.parametrize("plain", [False, True])
@pytest.mark.parametrize("shape", ["empty-mode-0644", "empty-through-a-link", "oversized", "not-a-key"])
def test_every_unusable_existing_key_stops_init_and_doctor_with_the_file_and_the_reason(
    tmp_path, monkeypatch, plain, shape
):
    if shape in _POSIX_ONLY and os.name == "nt":
        pytest.skip("mode bits and links are checked by the Windows ACL tests")
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    reason = _plant_key(home, shape)
    before = _identity_files(home)

    if plain:
        result = _plain_init()
        assert result.exit_code != 0
        output = result.output
    else:
        report = run_first_run(_options())
        assert report.status == "needs_attention"
        output = " ".join(step.detail for step in report.setup)

    assert str(home / "device.key") in output
    assert f"({reason})" in output
    assert "defenseclaw-gateway stop" in output
    assert _identity_files(home) == before

    check = _doctor_check(home)
    assert check["status"] == "fail"
    assert check["reason_code"] == reason
    assert str(home / "device.key") in check["remediation"]
    assert "device-key.initialize" not in check["remediation"]
    assert _identity_files(home) == before


@pytest.mark.parametrize("block_type", ["ED25519 PRIVATE KEY", "PRIVATE KEY"])
@pytest.mark.parametrize("plain", [False, True])
def test_a_key_the_gateway_can_load_is_kept_by_init_whatever_its_pem_block_type(
    tmp_path, monkeypatch, plain, block_type
):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    seed = base64.b64encode(bytes(range(1, 33))).decode()
    key = home / "device.key"
    key.write_text(f"-----BEGIN {block_type}-----\n{seed}\n-----END {block_type}-----\n")
    protect_private_file(str(key))
    before = key.read_bytes()

    if plain:
        assert _plain_init().exit_code == 0
    else:
        assert run_first_run(_options()).status != "needs_attention"

    assert key.read_bytes() == before
    check = _doctor_check(home)
    assert check["status"] == "pass"


def test_guided_init_on_a_keyless_home_names_the_manual_steps_and_recommends_no_refused_repair(
    tmp_path, monkeypatch
):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    files = _plant(home, "sentinel-only")
    before = _identity_files(home)

    report = run_first_run(
        FirstRunOptions(connector="none", profile="observe", skip_install=True, start_gateway=False, verify=True)
    )

    assert report.status == "needs_attention"
    device_key = next(step for step in report.readiness if step.name == "Device key")
    assert device_key.status == "fail"
    _assert_manual_steps(device_key.detail, home, files)
    assert device_key.next_command == "defenseclaw init"
    everything = [step.next_command for step in report.setup + report.readiness] + report.next_commands
    assert not any("device-key.initialize" in command for command in everything)
    assert _identity_files(home) == before


@pytest.mark.parametrize("shape", ["not-a-key", "oversized"])
def test_readiness_on_an_unusable_key_gives_the_manual_steps_and_the_init_rerun(tmp_path, monkeypatch, shape):
    home = _home(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    reason = _plant_key(home, shape)
    cfg = type("Cfg", (), {})()
    cfg.data_dir = str(home)
    cfg.gateway = type("Gw", (), {"device_key_file": str(home / "device.key")})()

    step = bootstrap._device_key_readiness(cfg, _options())

    assert step.status == "fail"
    assert f"({reason})" in step.detail
    assert str(home / "device.key") in step.detail
    assert step.next_command == "defenseclaw init"


def test_readiness_still_asks_for_the_repair_that_works_when_the_key_is_simply_absent(tmp_path):
    home = _home(tmp_path)
    cfg = type("Cfg", (), {})()
    cfg.data_dir = str(home)
    cfg.gateway = type("Gw", (), {"device_key_file": str(home / "device.key")})()

    step = bootstrap._device_key_readiness(cfg, _options())

    assert step.status == "fail"
    assert step.next_command == "defenseclaw doctor --fix --fix-id doctor.identity.device-key.initialize"
