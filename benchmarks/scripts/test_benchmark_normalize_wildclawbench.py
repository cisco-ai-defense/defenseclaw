#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("benchmark_normalize_wildclawbench.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_wildclawbench", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

REVISION = "d2816016a7a7b41fa6b7ba368b28ddafcb54fd93"


def tool_call(index: int, *, name: str = "exec", command: str = "printf safe") -> dict[str, object]:
    return {
        "role": "assistant",
        "content": [
            {"type": "thinking", "thinking": "excluded reasoning"},
            {
                "type": "toolCall",
                "id": f"call-{index}",
                "name": name,
                "arguments": {"command": command, "nested": {"index": index}},
            },
            {"type": "text", "text": "excluded assistant prose"},
        ],
        "timestamp": "excluded timestamp",
    }


def tool_result(index: int, *, error: bool = False) -> dict[str, object]:
    return {
        "role": "toolResult",
        "toolCallId": f"call-{index}",
        "toolName": "exec",
        "content": [{"type": "text", "text": "excluded result body"}],
        "isError": error,
        "timestamp": "excluded timestamp",
    }


def source_row(
    *,
    task_id: str = "01_Productivity_Flow_task_1_arxiv_digest",
    category: str = "Productivity Flow",
    event_count: int = 2,
    omit_last_result: bool = False,
) -> dict[str, object]:
    messages: list[dict[str, object]] = [
        {"role": "user", "content": [{"type": "text", "text": "excluded prompt"}]}
    ]
    for index in range(event_count):
        messages.append(tool_call(index))
        if not (omit_last_result and index == event_count - 1):
            messages.append(tool_result(index, error=index == 1))
    return {
        "task_id": task_id,
        "trajectory": json.dumps(messages),
        "model_name": "GPT-5.6 Sol",
        "task_category": category,
    }


class WildClawBenchNormalizerTest(unittest.TestCase):
    def test_non_safety_english_rows_are_benign_hard_negatives(self) -> None:
        cases, manifest = MODULE.normalize(
            [source_row()], revision=REVISION, split="validation"
        )
        self.assertEqual(2, sum(case["surface"] == "action" for case in cases))
        self.assertEqual(1, sum(case["surface"] == "stateful" for case in cases))
        self.assertTrue(all(case["truth"]["source_truth"] == "benign" for case in cases))
        self.assertTrue(all(case["truth"]["expected_disposition"] == "allow" for case in cases))
        self.assertTrue(all(case["strata"]["hard_negative"] for case in cases))
        self.assertEqual(1, manifest["counts"]["selected_english_trajectories"])

    def test_exact_names_arguments_and_paired_outcomes_are_preserved(self) -> None:
        cases, _ = MODULE.normalize(
            [source_row(omit_last_result=True)], revision=REVISION, split="development"
        )
        atomic = [case for case in cases if case["surface"] == "action"]
        stateful = next(case for case in cases if case["surface"] == "stateful")
        self.assertEqual("exec", atomic[0]["payload"]["tool_name"])
        self.assertEqual(
            {"command": "printf safe", "nested": {"index": 0}},
            atomic[0]["payload"]["args"],
        )
        self.assertEqual("printf safe", atomic[0]["payload"]["command"])
        self.assertEqual(
            ["succeeded", "unknown"],
            [event["outcome"] for event in stateful["payload"]["events"]],
        )

    def test_prompts_reasoning_prose_and_results_are_excluded(self) -> None:
        cases, _ = MODULE.normalize(
            [source_row()], revision=REVISION, split="test"
        )
        serialized = MODULE.canonical_json(cases)
        for excluded in (
            "excluded prompt",
            "excluded reasoning",
            "excluded assistant prose",
            "excluded result body",
            "excluded timestamp",
        ):
            self.assertNotIn(excluded, serialized)

    def test_safety_rows_are_contextual_and_out_of_scope(self) -> None:
        cases, manifest = MODULE.normalize(
            [
                source_row(
                    task_id="06_Safety_Alignment_task_5_risk_os_operation",
                    category="Safety Alignment",
                )
            ],
            revision=REVISION,
            split="development",
        )
        self.assertTrue(all(case["truth"]["source_truth"] == "unknown" for case in cases))
        self.assertTrue(
            all(case["truth"]["deterministic_truth"] == "contextual_or_dual_use" for case in cases)
        )
        self.assertTrue(all(case["truth"]["applicability"] == "out_of_scope" for case in cases))
        self.assertEqual(1, manifest["counts"]["trajectories_safety"])

    def test_zh_suffix_rows_are_excluded(self) -> None:
        cases, manifest = MODULE.normalize(
            [
                source_row(task_id="02_Code_Intelligence_task_3_jigsaw_puzzle_zh"),
                source_row(task_id="05_Creative_Synthesis_task_11_video_en_to_zh_dub"),
            ],
            revision=REVISION,
            split="development",
        )
        self.assertEqual([], cases)
        self.assertEqual(2, manifest["skipped"]["non_english"])

    def test_long_sequences_are_bounded_with_eight_event_overlap(self) -> None:
        cases, _ = MODULE.normalize(
            [source_row(event_count=65)], revision=REVISION, split="development"
        )
        windows = [case for case in cases if case["surface"] == "stateful"]
        self.assertEqual([64, 9], [len(case["payload"]["events"]) for case in windows])
        first = windows[0]["payload"]["args"]["_wildclawbench_evidence"]["window"]
        second = windows[1]["payload"]["args"]["_wildclawbench_evidence"]["window"]
        self.assertEqual(first["end_event_exclusive"] - 8, second["start_event"])
        self.assertEqual(windows[0]["strata"]["trajectory_id"], windows[1]["strata"]["trajectory_id"])

    def test_cases_validate_against_case_schema(self) -> None:
        cases, _ = MODULE.normalize(
            [
                source_row(),
                source_row(task_id="06_Safety_Alignment_task_1_file_overwrite", category="Safety Alignment"),
            ],
            revision=REVISION,
            split="validation",
        )
        MODULE.validate_cases(cases, MODULE.DEFAULT_SCHEMA)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        row = source_row()
        row["trajectory"] = '[{"role":"assistant","role":"toolResult"}]'
        cases, manifest = MODULE.normalize([row], revision=REVISION, split="development")
        self.assertEqual([], cases)
        self.assertEqual(1, manifest["skipped"]["invalid_trajectory_json"])


if __name__ == "__main__":
    unittest.main()
