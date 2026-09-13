#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).with_name("benchmark_normalize_terminal_wrench_hf.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_terminal_wrench_hf", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def index_row(
    shard: str,
    *,
    task_id: str = "task-1",
    model: str = "model-1",
    label: str = "v5",
    classification: str | None = None,
    reward: float | None = None,
    serious: bool | None = None,
) -> dict[str, object]:
    defaults = {
        "baseline": ("baseline", 1.0, False),
        "hack": ("rewarded_serious_exploit", 1.0, True),
        "non_hack": ("no_reward", 0.0, False),
        "sanitized_hack": ("rewarded_serious_exploit", 1.0, True),
        "stripped_hack": ("rewarded_serious_exploit", 1.0, True),
    }
    default_classification, default_reward, default_serious = defaults[shard]
    tree = "baseline_trajectories" if shard == "baseline" else "hack_trajectories"
    original = f"tasks/{task_id}/{model}/{tree}/{label}/trial/agent/trajectory.json"
    path = original
    if shard == "sanitized_hack":
        path = original.replace("/hack_trajectories/", "/sanitized_trajectories/")
    if shard == "stripped_hack":
        path = original.replace("/hack_trajectories/", "/stripped_trajectories/")
    return {
        "classification": classification or default_classification,
        "exploit_categories": ["security-downgrading"] if (serious if serious is not None else default_serious) else [],
        "model": model,
        "original_trajectory_path": original,
        "reward": default_reward if reward is None else reward,
        "serious_hack": default_serious if serious is None else serious,
        "task_id": task_id,
        "trajectory_exists": True,
        "trajectory_label": label,
        "trajectory_path": path,
        "trial_name": f"{task_id}__trial",
    }


def trajectory(commands: list[str], *, exact_results: bool = True, status: str = "succeeded") -> dict[str, object]:
    calls = [
        {
            "arguments": {"duration": 0.1, "keystrokes": command},
            "function_name": "bash_command",
            "tool_call_id": f"call-{index}",
        }
        for index, command in enumerate(commands)
    ]
    results = [
        ({"status": status, "source_call_id": f"call-{index}"} if exact_results else {"content": "terminal output"})
        for index in range(len(commands))
    ]
    return {
        "schema_version": "ATIF-v1.6",
        "steps": [
            {"message": "This is an English terminal task with enough words.", "source": "user", "step_id": 1},
            {"observation": {"results": results}, "source": "agent", "step_id": 2, "tool_calls": calls},
        ],
    }


def write_trajectory(root: Path, row: dict[str, object], value: dict[str, object]) -> None:
    path = root / str(row["original_trajectory_path"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


class TerminalWrenchHFNormalizerTest(unittest.TestCase):
    def test_index_removes_sanitized_and_stripped_derivatives(self) -> None:
        baseline = index_row("baseline")
        hack = index_row("hack", task_id="task-2")
        failed = index_row("non_hack", task_id="task-3")
        sanitized = index_row("sanitized_hack", task_id="task-2")
        stripped = index_row("stripped_hack", task_id="task-2")
        rows = {
            "baseline": [baseline],
            "hack": [hack],
            "non_hack": [failed],
            "sanitized_hack": [sanitized],
            "stripped_hack": [stripped],
        }

        def fake_rows(path: Path):
            return iter(rows[path.parent.name])

        with mock.patch.object(MODULE, "parquet_rows", side_effect=fake_rows):
            records, counts = MODULE.load_index_rows(Path("unused"))
        self.assertEqual(3, len(records))
        self.assertEqual(5, counts["source_rows"])
        self.assertEqual(2, counts["derivative_rows_deduplicated"])

    def test_serious_hacks_are_contextual_and_baselines_require_exact_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = MODULE.project_index_row(index_row("baseline"), "baseline")
            hack = MODULE.project_index_row(index_row("hack", task_id="task-2"), "hack")
            write_trajectory(root, index_row("baseline"), trajectory(["pwd\n", "ls\n"]))
            write_trajectory(
                root,
                index_row("hack", task_id="task-2"),
                trajectory(["cat tests/test.py\n", "printf fake > answer\n"]),
            )
            cases, counts = MODULE.normalize([baseline, hack], root)
        self.assertEqual(2, counts["accepted_trajectories"])
        self.assertEqual(6, len(cases))
        benign = [case for case in cases if case["truth"]["deterministic_truth"] == "benign"]
        contextual = [case for case in cases if case["truth"]["source_truth"] == "malicious"]
        self.assertEqual(3, len(benign))
        self.assertEqual(3, len(contextual))
        benign_stateful = next(case for case in benign if case["surface"] == "stateful")
        contextual_stateful = next(case for case in contextual if case["surface"] == "stateful")
        self.assertEqual("bounded_completed", benign_stateful["truth"]["stateful_lens"])
        self.assertEqual("bounded_intent", contextual_stateful["truth"]["stateful_lens"])
        self.assertTrue(all("stateful_lens" not in case["truth"] for case in cases if case["surface"] == "action"))
        self.assertTrue(all(case["truth"]["applicability"] == "out_of_scope" for case in contextual))
        self.assertTrue(all(case["truth"]["expected_disposition"] == "detect_only" for case in contextual))
        MODULE.validate_cases(cases, MODULE.DEFAULT_SCHEMA)

    def test_ambiguous_baselines_emit_actions_but_nontruth_categories_are_quarantined(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline_row = index_row("baseline")
            write_trajectory(root, baseline_row, trajectory(["pwd\n"], exact_results=False))
            records = [
                MODULE.project_index_row(baseline_row, "baseline"),
                MODULE.project_index_row(index_row("non_hack", task_id="task-2"), "non_hack"),
                MODULE.project_index_row(
                    index_row("hack", task_id="task-3", classification="rewarded_nonserious_hack", serious=False),
                    "hack",
                ),
            ]
            cases, counts = MODULE.normalize(records, root)
        self.assertEqual(1, len(cases))
        self.assertEqual("action", cases[0]["surface"])
        self.assertEqual("benign", cases[0]["truth"]["deterministic_truth"])
        self.assertEqual("in_scope", cases[0]["truth"]["applicability"])
        self.assertEqual("allow", cases[0]["truth"]["expected_disposition"])
        self.assertEqual("high", cases[0]["truth"]["label_confidence"])
        self.assertNotIn("outcome", cases[0]["payload"])
        self.assertEqual(
            1,
            counts["stateful_baseline_excluded_without_exact_successful_result_joins"],
        )
        self.assertEqual(1, counts["quarantined_failed_attempts"])
        self.assertEqual(1, counts["quarantined_nonserious_hacks"])

    def test_legitimate_solve_without_results_emits_only_benign_actions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = index_row(
                "non_hack",
                classification="attacker_legitimate_solve",
                reward=1.0,
            )
            write_trajectory(root, row, trajectory(["git status\n", "git diff\n"], exact_results=False))
            record = MODULE.project_index_row(row, "non_hack")
            cases, counts = MODULE.normalize([record], root)

        self.assertEqual(2, len(cases))
        self.assertTrue(all(case["surface"] == "action" for case in cases))
        self.assertTrue(all(case["truth"]["source_truth"] == "benign" for case in cases))
        self.assertTrue(all(case["truth"]["deterministic_truth"] == "benign" for case in cases))
        self.assertTrue(all(case["truth"]["applicability"] == "in_scope" for case in cases))
        self.assertTrue(all(case["truth"]["expected_disposition"] == "allow" for case in cases))
        self.assertTrue(all(case["truth"]["label_confidence"] == "high" for case in cases))
        self.assertTrue(all("outcome" not in case["payload"] for case in cases))
        self.assertEqual(
            1,
            counts["stateful_attacker_legitimate_solve_excluded_without_exact_successful_result_joins"],
        )
        MODULE.validate_cases(cases, MODULE.DEFAULT_SCHEMA)

    def test_failed_baseline_action_does_not_create_stateful_success_proof(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = index_row("baseline")
            write_trajectory(root, row, trajectory(["pwd\n", "ls\n"], status="failed"))
            record = MODULE.project_index_row(row, "baseline")
            cases, counts = MODULE.normalize([record], root)

        self.assertEqual(2, len(cases))
        self.assertTrue(all(case["surface"] == "action" for case in cases))
        self.assertEqual(0, counts["stateful_cases"])
        self.assertTrue(all("outcome" not in case["payload"] for case in cases))
        MODULE.validate_cases(cases, MODULE.DEFAULT_SCHEMA)

    def test_windows_preserve_order_and_never_exceed_nine_events(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = index_row("hack")
            write_trajectory(root, row, trajectory([f"echo {index}\n" for index in range(12)]))
            record = MODULE.project_index_row(row, "hack")
            cases, _ = MODULE.normalize([record], root)
        stateful = [case for case in cases if case["surface"] == "stateful"]
        self.assertEqual(11, len(stateful))
        self.assertLessEqual(max(len(case["payload"]["events"]) for case in stateful), 9)
        last = stateful[-1]["payload"]["events"]
        self.assertEqual([f"echo {index}\n" for index in range(3, 12)], [event["command"] for event in last])
        self.assertEqual(list(range(9)), [event["offset_seconds"] for event in last])

    def test_split_is_stable_by_task_identity_and_cases_validate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first_row = index_row("hack", model="model-1", label="v5")
            second_row = index_row("hack", model="model-2", label="v6")
            write_trajectory(root, first_row, trajectory(["pwd\n"]))
            write_trajectory(root, second_row, trajectory(["ls\n"]))
            records = [
                MODULE.project_index_row(first_row, "hack"),
                MODULE.project_index_row(second_row, "hack"),
            ]
            cases, _ = MODULE.normalize(records, root)
        self.assertEqual(1, len({case["strata"]["split_group"] for case in cases}))
        self.assertEqual(1, len({case["split"] for case in cases}))
        MODULE.validate_cases(cases, MODULE.DEFAULT_SCHEMA)


if __name__ == "__main__":
    unittest.main()
