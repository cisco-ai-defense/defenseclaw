#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("benchmark_normalize_stepshield.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_stepshield", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def trajectory(
    *, source_split: str = "train", public_id: str = "DEC-L1-001-ROGUE",
    trajectory_type: str = "rogue", outcomes: tuple[str, ...] = ("unknown", "succeeded"),
    task_identity: str = "task",
) -> object:
    events = tuple(
        MODULE.Event(index, "run_command", {"command": command}, command, "posix", outcome)
        for index, (command, outcome) in enumerate(zip(("pwd", "rm -rf ./tmp"), outcomes, strict=True), 1)
    )
    return MODULE.Trajectory(
        source_split, public_id, trajectory_type, "DEC", "L1", 2,
        MODULE.digest(task_identity), MODULE.digest(public_id), events,
    )


class StepShieldNormalizerTest(unittest.TestCase):
    def test_explicit_result_parser_is_conservative(self) -> None:
        self.assertEqual("succeeded", MODULE.observation_outcome("Exit code: 0"))
        self.assertEqual("failed", MODULE.observation_outcome("return status = 7"))
        self.assertEqual("succeeded", MODULE.observation_outcome("HTTP/1.1 200 OK\n{}"))
        self.assertEqual("failed", MODULE.observation_outcome("HTTP/1.1 403 Forbidden"))
        self.assertEqual("succeeded", MODULE.observation_outcome("Migration completed successfully."))
        self.assertEqual("failed", MODULE.observation_outcome("Tests failed: 2"))
        self.assertEqual("unknown", MODULE.observation_outcome("deployment.apps/example configured"))
        self.assertEqual("unknown", MODULE.observation_outcome(""))

    def test_contextual_labels_never_become_deterministic_truth(self) -> None:
        cases, counts = MODULE.normalize([trajectory()])
        self.assertEqual(3, len(cases))
        self.assertEqual(0, counts["deterministic_malicious_cases"])
        self.assertTrue(all(case["split"] == "development" for case in cases))
        self.assertTrue(all(case["truth"]["applicability"] == "out_of_scope" for case in cases))
        self.assertTrue(all(case["truth"]["expected_disposition"] == "detect_only" for case in cases))

    def test_heldout_clean_requires_exact_success_and_is_test_only(self) -> None:
        clean = trajectory(
            source_split="holdout", public_id="abcdefgh", trajectory_type="clean",
            outcomes=("unknown", "succeeded"),
        )
        cases, counts = MODULE.normalize([clean])
        self.assertEqual(2, len(cases))
        self.assertEqual(1, counts["quarantined_heldout_clean_ambiguous_result_steps"])
        self.assertTrue(all(case["split"] == "test" for case in cases))
        self.assertTrue(all(case["truth"]["deterministic_truth"] == "benign" for case in cases))
        stateful = next(case for case in cases if case["surface"] == "stateful")
        self.assertEqual(["unknown", "succeeded"], [event["outcome"] for event in stateful["payload"]["events"]])

    def test_windows_dialect_is_explicit_and_other_actions_have_none(self) -> None:
        self.assertEqual(
            ("powershell Set-MpPreference -DisableRealtimeMonitoring $true", "powershell"),
            MODULE.command_and_dialect(
                "run_command", {"command": "powershell Set-MpPreference -DisableRealtimeMonitoring $true"}
            ),
        )
        self.assertEqual(("", "none"), MODULE.command_and_dialect("edit_file", {"path": "a"}))

    def test_windows_are_bounded_to_current_plus_eight_predecessors(self) -> None:
        events = tuple(
            MODULE.Event(index, "run_command", {"command": f"echo {index}"}, f"echo {index}", "posix", "unknown")
            for index in range(1, 12)
        )
        item = MODULE.Trajectory(
            "train", "DEC-L1-001-ROGUE", "rogue", "DEC", "L1", 10,
            MODULE.digest("task"), MODULE.digest("trace"), events,
        )
        cases, _ = MODULE.normalize([item])
        windows = [case for case in cases if case["surface"] == "stateful"]
        self.assertEqual(10, len(windows))
        self.assertLessEqual(max(len(case["payload"]["events"]) for case in windows), 9)

    def test_duplicate_json_keys_and_nonfinite_arguments_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            MODULE.strict_object([("a", 1), ("a", 2)])
        with self.assertRaisesRegex(MODULE.ProjectionError, "non_finite_argument"):
            MODULE.bounded({"value": float("nan")})

    def test_schema_validation_accepts_contextual_and_scored_cases(self) -> None:
        contextual, _ = MODULE.normalize([trajectory()])
        clean, _ = MODULE.normalize(
            [
                trajectory(
                    source_split="holdout", public_id="abcdefgh", trajectory_type="clean",
                    outcomes=("succeeded", "succeeded"), task_identity="heldout-task",
                )
            ]
        )
        MODULE.validate_cases(contextual + clean, MODULE.DEFAULT_SCHEMA)


if __name__ == "__main__":
    unittest.main()
