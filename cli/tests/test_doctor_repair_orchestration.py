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

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from defenseclaw.commands import cmd_doctor
from defenseclaw.doctor_engine import RepairDecision, RepairRecord, RepairSpec


def _cfg() -> SimpleNamespace:
    return SimpleNamespace(data_dir="", gateway=SimpleNamespace(token_env=""))


def _spec(
    repair_id: str,
    *,
    planner: Mock,
    applier: Mock,
    dependencies: tuple[str, ...] = (),
    explicit_selection_required: bool = False,
    platforms: tuple[str, ...] = ("linux", "darwin", "win32"),
) -> RepairSpec:
    return RepairSpec(
        repair_id=repair_id,
        label=repair_id,
        risk="policy" if explicit_selection_required else "safe",
        plan=planner,
        apply=applier,
        dependencies=dependencies,
        explicit_selection_required=explicit_selection_required,
        platforms=platforms,
    )


def test_failed_prerequisite_blocks_dependent_without_planning_or_applying(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent_plan = Mock(return_value=RepairDecision("applicable", "repair parent"))
    parent_apply = Mock(return_value=("fail", "parent did not converge"))
    child_plan = Mock(return_value=RepairDecision("applicable", "repair child"))
    child_apply = Mock(return_value=("pass", "must not run"))
    specs = (
        _spec("doctor.test.parent", planner=parent_plan, applier=parent_apply),
        _spec(
            "doctor.test.child",
            planner=child_plan,
            applier=child_apply,
            dependencies=("doctor.test.parent",),
        ),
    )
    monkeypatch.setattr(cmd_doctor, "_doctor_repair_specs", lambda: specs)
    result = cmd_doctor._DoctorResult(mode="repair")

    cmd_doctor._run_fixers(
        _cfg(),
        result,
        assume_yes=True,
        json_out=True,
    )

    parent_apply.assert_called_once()
    child_plan.assert_not_called()
    child_apply.assert_not_called()
    assert [record["state"] for record in result.repairs] == ["failed", "blocked"]
    assert result.repairs[1]["blockers"] == ["doctor.test.parent ended in failed"]


def test_selected_dependency_graph_runs_in_topological_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    call_order: list[str] = []
    parent = _spec(
        "doctor.test.parent",
        planner=Mock(return_value=RepairDecision("applicable", "repair parent")),
        applier=Mock(
            side_effect=lambda _cfg, **_kwargs: call_order.append("parent")
            or ("pass", "done")
        ),
    )
    child = _spec(
        "doctor.test.child",
        planner=Mock(return_value=RepairDecision("applicable", "repair child")),
        applier=Mock(
            side_effect=lambda _cfg, **_kwargs: call_order.append("child")
            or ("pass", "done")
        ),
        dependencies=(parent.repair_id,),
    )
    monkeypatch.setattr(cmd_doctor, "_doctor_repair_specs", lambda: (child, parent))
    result = cmd_doctor._DoctorResult(mode="repair")

    cmd_doctor._run_fixers(
        _cfg(),
        result,
        assume_yes=True,
        json_out=True,
        fix_ids=(child.repair_id,),
    )

    assert call_order == ["parent", "child"]
    assert [(row["repair_id"], row["state"]) for row in result.repairs] == [
        ("doctor.test.parent", "applied"),
        ("doctor.test.child", "applied"),
    ]


def test_missing_dependency_fails_graph_and_blocks_repair(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child = _spec(
        "doctor.test.child",
        planner=Mock(return_value=RepairDecision("applicable", "repair child")),
        applier=Mock(return_value=("pass", "must not run")),
        dependencies=("doctor.test.missing",),
    )
    monkeypatch.setattr(cmd_doctor, "_doctor_repair_specs", lambda: (child,))
    result = cmd_doctor._DoctorResult(mode="repair")

    cmd_doctor._run_fixers(
        _cfg(),
        result,
        assume_yes=True,
        json_out=True,
        fix_ids=(child.repair_id,),
    )

    assert [row["state"] for row in result.repairs] == ["failed", "blocked"]
    assert result.repairs[0]["repair_id"] == "doctor.repair.graph"
    assert "missing repair dependencies" in result.repairs[0]["blockers"][0]
    child.plan.assert_not_called()
    child.apply.assert_not_called()


def test_cyclic_dependency_graph_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    left = _spec(
        "doctor.test.left",
        planner=Mock(return_value=RepairDecision("applicable", "left")),
        applier=Mock(return_value=("pass", "must not run")),
        dependencies=("doctor.test.right",),
    )
    right = _spec(
        "doctor.test.right",
        planner=Mock(return_value=RepairDecision("applicable", "right")),
        applier=Mock(return_value=("pass", "must not run")),
        dependencies=("doctor.test.left",),
    )
    monkeypatch.setattr(cmd_doctor, "_doctor_repair_specs", lambda: (left, right))
    result = cmd_doctor._DoctorResult(mode="repair")

    cmd_doctor._run_fixers(
        _cfg(),
        result,
        assume_yes=True,
        json_out=True,
        fix_ids=(left.repair_id,),
    )

    assert [row["state"] for row in result.repairs] == ["failed", "blocked", "blocked"]
    assert "cyclic repair dependencies" in result.repairs[0]["blockers"][0]
    left.plan.assert_not_called()
    right.plan.assert_not_called()


def test_duplicate_repair_ids_fail_closed_without_running_either(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _spec(
        "doctor.test.duplicate",
        planner=Mock(return_value=RepairDecision("applicable", "first")),
        applier=Mock(return_value=("pass", "must not run")),
    )
    second = _spec(
        "doctor.test.duplicate",
        planner=Mock(return_value=RepairDecision("applicable", "second")),
        applier=Mock(return_value=("pass", "must not run")),
    )
    monkeypatch.setattr(cmd_doctor, "_doctor_repair_specs", lambda: (first, second))
    result = cmd_doctor._DoctorResult(mode="repair")

    cmd_doctor._run_fixers(
        _cfg(),
        result,
        assume_yes=True,
        json_out=True,
        fix_ids=(first.repair_id,),
    )

    assert [row["state"] for row in result.repairs] == ["failed", "blocked"]
    assert "duplicate repair IDs" in result.repairs[0]["blockers"][0]
    first.plan.assert_not_called()
    first.apply.assert_not_called()
    second.plan.assert_not_called()
    second.apply.assert_not_called()


def test_applied_repair_must_pass_explicit_postcondition_verifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = Mock(
        return_value=RepairDecision(
            "failed",
            "postcondition is still broken",
            blockers=("expected state was not observed",),
        )
    )
    spec = RepairSpec(
        repair_id="doctor.test.verified",
        label="verified repair",
        risk="safe",
        plan=Mock(return_value=RepairDecision("applicable", "repair")),
        apply=Mock(return_value=("pass", "claimed success")),
        verify=verifier,
    )
    monkeypatch.setattr(cmd_doctor, "_doctor_repair_specs", lambda: (spec,))
    result = cmd_doctor._DoctorResult(mode="repair")

    cmd_doctor._run_fixers(
        _cfg(),
        result,
        assume_yes=True,
        json_out=True,
    )

    verifier.assert_called_once()
    assert result.repairs[0]["state"] == "failed"
    assert "postcondition verification did not converge" in result.repairs[0]["detail"]
    assert result.to_dict()["exit_code"] == 1


def test_unsupported_platform_never_plans_or_applies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    planner = Mock(return_value=RepairDecision("applicable", "repair"))
    applier = Mock(return_value=("pass", "must not run"))
    spec = _spec(
        "doctor.test.linux-only",
        planner=planner,
        applier=applier,
        platforms=("linux",),
    )
    monkeypatch.setattr(cmd_doctor, "_doctor_repair_specs", lambda: (spec,))
    monkeypatch.setattr(cmd_doctor.sys, "platform", "freebsd14")
    result = cmd_doctor._DoctorResult(mode="repair")

    cmd_doctor._run_fixers(
        _cfg(),
        result,
        assume_yes=True,
        json_out=True,
    )

    planner.assert_not_called()
    applier.assert_not_called()
    assert result.repairs[0]["state"] == "manual"
    assert result.repairs[0]["platform"] == "freebsd14"


def test_planner_exception_becomes_typed_failure_and_later_repairs_continue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "planner-secret-must-not-render"
    broken = _spec(
        "doctor.test.broken-plan",
        planner=Mock(side_effect=RuntimeError(secret)),
        applier=Mock(),
    )
    healthy = _spec(
        "doctor.test.healthy",
        planner=Mock(return_value=RepairDecision("noop", "already healthy")),
        applier=Mock(),
    )
    monkeypatch.setattr(cmd_doctor, "_doctor_repair_specs", lambda: (broken, healthy))
    result = cmd_doctor._DoctorResult(mode="repair")

    cmd_doctor._run_fixers(
        _cfg(),
        result,
        assume_yes=True,
        json_out=True,
    )

    assert [record["state"] for record in result.repairs] == ["failed", "noop"]
    assert result.repairs[0]["detail"] == "RuntimeError: planner raised unexpectedly"
    assert secret not in repr(result.to_dict())
    broken.apply.assert_not_called()
    healthy.plan.assert_called_once()


def test_explicit_policy_selection_is_satisfied_in_dry_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    planner = Mock(return_value=RepairDecision("applicable", "change policy"))
    spec = _spec(
        "doctor.test.policy",
        planner=planner,
        applier=Mock(),
        explicit_selection_required=True,
    )
    monkeypatch.setattr(cmd_doctor, "_doctor_repair_specs", lambda: (spec,))
    result = cmd_doctor._DoctorResult(mode="plan", passive=True)

    cmd_doctor._run_fixers(
        _cfg(),
        result,
        assume_yes=False,
        json_out=True,
        dry_run=True,
        fix_ids=(spec.repair_id,),
    )

    assert result.repairs[0]["state"] == "applicable"
    assert "--fix-id" not in result.repairs[0]["detail"]


def test_overall_outcome_includes_repair_failure_without_changing_health_counts() -> None:
    result = cmd_doctor._DoctorResult(mode="repair")
    result.record("pass", "configuration")
    result.record_repair(
        RepairRecord(
            repair_id="doctor.test.failed",
            label="failed repair",
            state="failed",
            risk="safe",
            detail="repair did not converge",
        )
    )

    payload = result.to_dict()

    assert payload["failed"] == 0
    assert payload["summary"]["failed"] == 0
    assert payload["repair_summary"]["failed"] == 1
    assert payload["outcome"] == "failed"
    assert payload["exit_code"] == 1


def test_passive_doctor_never_emits_an_action_fact() -> None:
    logger = Mock()
    app = SimpleNamespace(logger=logger)
    result = cmd_doctor._DoctorResult(mode="check", passive=True)
    result.record("pass", "configuration")

    cmd_doctor._record_doctor_action(app, _cfg(), result, "check")

    logger.log_action.assert_not_called()


def test_unavailable_action_sink_cannot_replace_doctor_result() -> None:
    from defenseclaw.logger import CanonicalObservabilityUnavailableError

    logger = Mock()
    logger.log_action.side_effect = CanonicalObservabilityUnavailableError(
        "gateway unavailable",
    )
    app = SimpleNamespace(logger=logger)
    result = cmd_doctor._DoctorResult(mode="check")
    result.record("fail", "gateway authentication")

    cmd_doctor._record_doctor_action(app, _cfg(), result, "check")

    logger.log_action.assert_called_once()
    assert result.to_dict()["outcome"] == "failed"
    assert result.to_dict()["exit_code"] == 1


def test_transport_failure_from_embedded_action_sink_cannot_replace_result() -> None:
    from requests import ConnectionError

    logger = Mock()
    logger.log_action.side_effect = ConnectionError("connection reset after send")
    app = SimpleNamespace(logger=logger)
    result = cmd_doctor._DoctorResult(mode="repair")
    result.record("pass", "configuration")

    cmd_doctor._record_doctor_action(app, _cfg(), result, "repair")

    logger.log_action.assert_called_once()
    assert result.to_dict()["outcome"] == "healthy"
    assert result.to_dict()["exit_code"] == 0


@pytest.mark.parametrize(
    ("repair_id", "detail", "expected"),
    (
        (
            "doctor.credentials.dotenv.protect",
            "dotenv permissions exposed its contents; leaving the file unchanged "
            "until the gateway-token fixer can replace it",
            "applied",
        ),
        (
            "doctor.gateway.service.reconcile",
            "gateway service restarted and ownership verified; telemetry reconnecting",
            "applied",
        ),
        (
            "doctor.connector.backup.capture",
            "could not capture backup (permissions?)",
            "failed",
        ),
    ),
)
def test_legacy_warning_classification_is_fail_closed_except_bounded_handoffs(
    repair_id: str,
    detail: str,
    expected: str,
) -> None:
    spec = RepairSpec(
        repair_id=repair_id,
        label=repair_id,
        risk="safe",
        plan=Mock(),
        apply=Mock(),
    )

    decision = cmd_doctor._legacy_apply_decision(spec, "warn", detail)

    assert decision.state == expected
