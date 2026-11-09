# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""One test of whether an existing device key is usable (GAP-0927).

A key is usable if and only if the gateway parser accepts it (internal/gateway/device.go parseIdentity)
and its file custody holds. The Python port reaches the same verdict as the Go parser on every fixture in
internal/gateway/testdata/device_key_usability.json; the Go test
TestParseIdentityMatchesTheSharedKeyFileFixtures asserts the same verdicts over the same file.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import click
import pytest
from defenseclaw.bootstrap import FirstRunOptions, _device_key_readiness
from defenseclaw.commands.cmd_init import _ensure_device_key
from defenseclaw.config import default_config, prepare_fresh_v8_config
from defenseclaw.doctor_recovery import (
    DeviceKeyHealthStatus,
    device_key_bytes_usable,
    inspect_device_key,
    inspect_device_key_usability,
)
from defenseclaw.file_permissions import make_private_directory, protect_private_file

FIXTURES = Path(__file__).resolve().parents[2] / "internal" / "gateway" / "testdata" / "device_key_usability.json"
CASES = json.loads(FIXTURES.read_text(encoding="utf-8"))["cases"]


def test_the_fixtures_hold_both_verdicts():
    assert {case["usable"] for case in CASES} == {True, False}


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_the_python_verdict_is_the_gateway_parser_verdict(case):
    data = base64.b64decode(case["file_base64"])

    assert device_key_bytes_usable(data) is case["usable"]


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_a_private_key_file_is_usable_exactly_when_the_gateway_parser_accepts_it(tmp_path, case):
    home = Path(os.path.realpath(tmp_path)) / "home"
    make_private_directory(str(home))
    key = home / "device.key"
    key.write_bytes(base64.b64decode(case["file_base64"]))
    protect_private_file(str(key))

    health = inspect_device_key_usability(str(key), data_dir=str(home))

    assert (health.status is DeviceKeyHealthStatus.VALID) is case["usable"]
    if not case["usable"]:
        assert health.reason_code == "device-key-payload-invalid"


# A configured absolute device-key path outside the data folder: the gateway loads an existing file there as it
# is, so init, Doctor and readiness judge it on the same two things as any other key (the gateway parser and
# file custody), never on the layout rule that only governs where a missing key may be created.

_VALID_PEM = b"-----BEGIN PRIVATE KEY-----\n" + base64.b64encode(bytes(range(1, 33))) + b"\n-----END PRIVATE KEY-----\n"


def _outside_key(tmp_path, *, data=_VALID_PEM, mode="private", linked=False):
    root = Path(os.path.realpath(tmp_path))
    home = root / "home"
    make_private_directory(str(home))
    external = root / "operator-device.key"
    if linked:
        actual = root / "actual.key"
        actual.write_bytes(data)
        protect_private_file(str(actual))
        external.symlink_to(actual)
    else:
        external.write_bytes(data)
        if mode == "private":
            protect_private_file(str(external))
        else:
            os.chmod(external, 0o644)
    return home, external


def _verdicts(home, external, monkeypatch):
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    cfg = prepare_fresh_v8_config(default_config())
    cfg.gateway.device_key_file = str(external)
    options = FirstRunOptions(connector="none", profile="observe", skip_install=True, start_gateway=False)
    try:
        _ensure_device_key(str(external), data_dir=str(home))
        init = "accepted"
    except click.ClickException as exc:
        init = str(exc.message)
    return (
        inspect_device_key_usability(str(external), data_dir=str(home)),
        inspect_device_key(str(external), data_dir=str(home)),
        init,
        _device_key_readiness(cfg, options),
    )


@pytest.mark.skipif(os.name == "nt", reason="symlinks and POSIX modes")
@pytest.mark.parametrize(
    ("shape", "reason"),
    [
        ({"data": b"not a key\n"}, "device-key-payload-invalid"),
        ({"data": b""}, "device-key-payload-invalid"),
        ({"mode": "open"}, "device-key-custody-invalid"),
        ({"linked": True}, "target-is-not-regular-file"),
    ],
    ids=["not-a-key", "empty", "open-mode", "link"],
)
def test_an_unusable_key_outside_the_data_folder_stops_init_doctor_and_readiness(tmp_path, monkeypatch, shape, reason):
    home, external = _outside_key(tmp_path, **shape)

    usable, doctor, init, readiness = _verdicts(home, external, monkeypatch)

    assert usable.status is DeviceKeyHealthStatus.INVALID and usable.reason_code == reason
    assert doctor.status is DeviceKeyHealthStatus.INVALID and doctor.reason_code == reason
    assert f"({reason})" in init and str(external) in init
    assert readiness.status == "fail" and str(external) in readiness.detail


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_a_usable_key_outside_the_data_folder_is_not_blocked(tmp_path, monkeypatch):
    home, external = _outside_key(tmp_path)

    usable, doctor, init, readiness = _verdicts(home, external, monkeypatch)

    assert usable.status is DeviceKeyHealthStatus.VALID
    assert doctor.status is not DeviceKeyHealthStatus.INVALID
    assert init == "accepted"
    assert readiness.status == "pass"


def test_a_missing_key_outside_the_data_folder_is_still_not_created_there(tmp_path):
    root = Path(os.path.realpath(tmp_path))
    home = root / "home"
    make_private_directory(str(home))

    health = inspect_device_key_usability(str(root / "absent.key"), data_dir=str(home))

    assert health.status is DeviceKeyHealthStatus.INVALID
    assert health.reason_code == "target-outside-data-dir"
