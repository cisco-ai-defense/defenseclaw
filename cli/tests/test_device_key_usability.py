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

import pytest
from defenseclaw.doctor_recovery import (
    DeviceKeyHealthStatus,
    device_key_bytes_usable,
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
