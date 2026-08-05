# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import pytest
from defenseclaw.doctor_engine import (
    RepairRecord,
    RepairRunSummary,
    legacy_outcome_state,
    stable_doctor_id,
)


@pytest.mark.parametrize(
    ("tag", "detail", "expected"),
    (
        ("pass", "repair completed", "applied"),
        (" PASS ", "repair completed", "applied"),
        ("fail", "repair failed", "failed"),
        ("skip", "declined by user", "declined"),
        ("skip", "run `defenseclaw init`", "manual"),
        ("warn", "repair blocked by policy", "blocked"),
        ("skip", "already converged", "noop"),
        ("error", "adapter returned an unknown status", "failed"),
        ("plan", "planner result escaped into apply", "failed"),
    ),
)
def test_legacy_outcome_state_is_bounded_and_fail_closed(
    tag: str,
    detail: str,
    expected: str,
) -> None:
    assert legacy_outcome_state(tag, detail) == expected


def test_repair_summary_counts_each_typed_state_separately() -> None:
    summary = RepairRunSummary()
    for state in (
        "applicable",
        "noop",
        "blocked",
        "manual",
        "requires_confirmation",
        "declined",
        "applied",
        "failed",
    ):
        summary.record(state)

    assert summary.to_dict() == {
        "planned": 1,
        "applied": 1,
        "failed": 1,
        "blocked": 1,
        "manual": 1,
        "noop": 1,
        "declined": 1,
        "requires_confirmation": 1,
    }


def test_repair_record_serializes_portable_json_collections() -> None:
    record = RepairRecord(
        repair_id="doctor.gateway.service.reconcile",
        label="gateway service",
        state="applicable",
        risk="disruptive",
        detail="restart the verified managed gateway",
        dependencies=("doctor.gateway.pid.remove-stale",),
        effects=("restart the gateway",),
        blockers=("operator confirmation",),
        may_restart=True,
        platform="win32",
        metadata={"attempt": 1, "selected": True},
    )

    payload = record.to_dict()

    assert payload["dependencies"] == ["doctor.gateway.pid.remove-stale"]
    assert payload["effects"] == ["restart the gateway"]
    assert payload["blockers"] == ["operator confirmation"]
    assert payload["platform"] == "win32"
    assert payload["metadata"] == {"attempt": 1, "selected": True}


def test_stable_doctor_id_is_deterministic_and_collision_resistant() -> None:
    identifier = stable_doctor_id("check", "Services", "Gateway token")

    assert identifier == stable_doctor_id("check", "Services", "Gateway token")
    assert identifier.startswith("doctor.check.services.gateway.token.")
    assert identifier != stable_doctor_id("check", "Services", "Gateway-token")
