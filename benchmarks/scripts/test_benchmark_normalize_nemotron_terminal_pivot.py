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

MODULE_PATH = Path(__file__).with_name("benchmark_normalize_nemotron_terminal_pivot.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_nemotron_terminal_pivot", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

FIXTURE = Path(__file__).parent / "testdata/nemotron_terminal_pivot/tiny.jsonl"


def fixture_rows() -> list[dict[str, object]]:
    return [json.loads(line) for line in FIXTURE.read_text(encoding="utf-8").splitlines()]


def row(
    *,
    uuid: str = "t2_pre_rp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    trajectory: str = "aaaaaaaaaaaaaaaa",
    turn: int = 0,
    task: str = "english-task",
    command: str = "pwd\n",
    analysis: str = "Inspect the current state in this English terminal task.",
    user_text: str = "Please inspect this English terminal workspace and report the current repository state.",
) -> dict[str, object]:
    return {
        "schema_version": "terminus2_pre_rp_pivot_sample_v1",
        "uuid": uuid,
        "task_name": task,
        "tool_name": "bash_command",
        "responses_create_params": {"input": [{"role": "user", "content": user_text}]},
        "expected_answer": json.dumps(
            {
                "analysis": analysis,
                "plan": "Execute the next concrete command and inspect its result.",
                "commands": [{"keystrokes": command, "duration": 0.1}],
                "task_complete": False,
            }
        ),
        "agent_ref": {
            "type": "responses_api_agents",
            "name": "terminus_judge_string_only_simple_agent",
        },
        "metadata": {
            "harness": "terminus_2",
            "teacher_model": "zai-org/GLM-5.1",
            "source_trajectory_uid": trajectory,
            "pivot_agent_turn_index": turn,
            "total_source_agent_turns": 4,
        },
    }


class NemotronTerminalPivotNormalizerTest(unittest.TestCase):
    def test_fixture_emits_only_real_shell_actions_and_bounded_windows(self) -> None:
        cases, manifest = MODULE.normalize_rows(fixture_rows())

        actions = [case for case in cases if case["surface"] == "action"]
        stateful = [case for case in cases if case["surface"] == "stateful"]
        self.assertEqual(3, len(actions))
        self.assertEqual(2, len(stateful))
        self.assertEqual(5, manifest["cases"])
        self.assertEqual(1, manifest["adapter_statistics"][MODULE.ADAPTER]["terminal_controls_excluded"])
        self.assertEqual(1, manifest["adapter_statistics"][MODULE.ADAPTER]["completion_markers_excluded"])
        self.assertEqual(
            ["pwd\n", "git status --short\n", "go test ./internal/example\n"],
            [case["payload"]["command"] for case in actions],
        )
        self.assertEqual(3, len(stateful[-1]["payload"]["events"]))
        self.assertTrue(all(event["outcome"] == "unknown" for event in stateful[-1]["payload"]["events"]))

    def test_prompt_analysis_plan_and_completion_prose_are_never_projected(self) -> None:
        cases, _ = MODULE.normalize_rows(fixture_rows())
        rendered = json.dumps(cases, sort_keys=True)
        self.assertNotIn("MODEL_ANALYSIS_MUST_NOT_BECOME_AN_ACTION", rendered)
        self.assertNotIn("Mark the task complete", rendered)
        self.assertNotIn("repair its local configuration", rendered)
        self.assertNotIn("task_complete", rendered)
        self.assertIn("git status --short", rendered)

    def test_truth_is_authoritative_benign_with_stable_english_metadata(self) -> None:
        first, first_manifest = MODULE.normalize_rows(fixture_rows())
        second, second_manifest = MODULE.normalize_rows(fixture_rows())
        self.assertEqual(first, second)
        self.assertEqual(first_manifest["output_sha256"], second_manifest["output_sha256"])
        for case in first:
            self.assertEqual("benign", case["truth"]["source_truth"])
            self.assertEqual("benign", case["truth"]["deterministic_truth"])
            self.assertEqual("allow", case["truth"]["expected_disposition"])
            self.assertEqual("en", case["strata"]["language"])
            self.assertTrue(case["strata"]["hard_negative"])
            self.assertIn("trajectory:1111111111111111", case["source"]["original_id"])

    def test_filtered_turn_gap_resets_stateful_history(self) -> None:
        first = row()
        second = row(
            uuid="t2_pre_rp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            turn=2,
            command="ls\n",
        )
        cases, manifest = MODULE.normalize_rows([first, second])
        self.assertTrue(all(case["surface"] == "action" for case in cases))
        self.assertEqual(
            1,
            manifest["adapter_statistics"][MODULE.ADAPTER]["history_resets_for_filtered_turn_gap"],
        )

    def test_windows_never_exceed_current_plus_eight_predecessors(self) -> None:
        rows = [
            row(
                uuid=f"t2_pre_rp_{index:032x}",
                trajectory="aaaaaaaaaaaaaaaa",
                turn=index,
                command=f"echo {index}\n",
            )
            for index in range(4)
        ]
        rows[-1]["expected_answer"] = json.dumps(
            {
                "analysis": "Execute a bounded batch of commands in the English terminal task.",
                "plan": "Run this exact batch in order.",
                "commands": [
                    {"keystrokes": f"echo batch-{index}\n", "duration": 0.1}
                    for index in range(10)
                ],
                "task_complete": False,
            }
        )
        cases, _ = MODULE.normalize_rows(rows)
        windows = [case for case in cases if case["surface"] == "stateful"]
        self.assertEqual(9, max(len(case["payload"]["events"]) for case in windows))
        last = windows[-1]["payload"]["events"]
        self.assertEqual([f"echo batch-{index}\n" for index in range(1, 10)], [event["command"] for event in last])

    def test_non_english_and_noncontiguous_trajectory_rows_fail_closed(self) -> None:
        non_english = row(user_text="请检查终端并修复这个服务，然后运行测试确认结果正确。")
        with self.assertRaisesRegex(MODULE.ProjectionError, "non_english_or_invalid_input"):
            MODULE.normalize_rows([non_english])

        first = row()
        other = row(
            uuid="t2_pre_rp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            trajectory="bbbbbbbbbbbbbbbb",
        )
        recurrence = row(
            uuid="t2_pre_rp_cccccccccccccccccccccccccccccccc",
            trajectory="aaaaaaaaaaaaaaaa",
            turn=1,
        )
        with self.assertRaisesRegex(MODULE.ProjectionError, "noncontiguous_trajectory"):
            MODULE.normalize_rows([first, other, recurrence])

    def test_fixture_cli_path_streams_and_emits_source_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / MODULE.SOURCE_PATH
            source.write_bytes(FIXTURE.read_bytes())
            output = root / "normalized.jsonl"
            manifest_path = root / "manifest.json"
            manifest = MODULE.normalize_file(
                source,
                output,
                manifest_path,
                verify_source=False,
            )
            self.assertEqual(5, len(output.read_text(encoding="utf-8").splitlines()))
            self.assertEqual(manifest, json.loads(manifest_path.read_text(encoding="utf-8")))
            self.assertEqual("en", manifest["source"]["language"])
            self.assertEqual(MODULE.SOURCE_REVISION, manifest["source"]["revision"])
            self.assertEqual(
                "release_contains_only_automated_verifier_passing_trajectories",
                manifest["source"]["trajectory_verification"],
            )


if __name__ == "__main__":
    unittest.main()
