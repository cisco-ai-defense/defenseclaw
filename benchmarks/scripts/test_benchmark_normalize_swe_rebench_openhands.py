#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("benchmark_normalize_swe_rebench_openhands.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_swe_rebench_openhands", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def assistant_call(index: int, tool: str, arguments: object) -> dict[str, object]:
    return {
        "content": "forbidden model prose",
        "name": None,
        "role": "assistant",
        "tool_call_id": None,
        "tool_calls": [
            {
                "function": {"arguments": json.dumps(arguments), "name": tool},
                "id": f"call-{index}",
                "type": "function",
            }
        ],
    }


def tool_result(index: int, tool: str, content: str) -> dict[str, object]:
    return {
        "content": content,
        "name": tool,
        "role": "tool",
        "tool_call_id": f"call-{index}",
        "tool_calls": None,
    }


def source_row(
    *,
    trajectory_id: str = "chatcmpl-safe-one",
    instance_id: str = "owner__repo-1",
    messages: list[dict[str, object]] | None = None,
    resolved: int = 1,
    exit_status: str = "submit",
) -> dict[str, object]:
    if messages is None:
        messages = [
            assistant_call(0, "execute_bash", {"command": "pytest -q"}),
            tool_result(0, "execute_bash", "tests passed\n[Command finished with exit code 0]"),
            assistant_call(1, "str_replace_editor", {"command": "view", "path": "/workspace/repo/main.py"}),
            tool_result(1, "str_replace_editor", "Here's the result of running `cat -n` on /workspace/repo/main.py:"),
        ]
    return {
        "exit_status": exit_status,
        "instance_id": instance_id,
        "repo": "owner/repo",
        "resolved": resolved,
        "trajectory": [
            {
                "content": "You are a coding agent",
                "name": None,
                "role": "system",
                "tool_call_id": None,
                "tool_calls": None,
            },
            {
                "content": "Fix the parser and run its tests",
                "name": None,
                "role": "user",
                "tool_call_id": None,
                "tool_calls": None,
            },
            *messages,
        ],
        "trajectory_id": trajectory_id,
    }


class SWERebenchOpenHandsNormalizerTest(unittest.TestCase):
    def test_projects_paired_calls_and_explicit_outcomes_without_prose_or_results(self) -> None:
        cases, counts = MODULE.normalize([source_row()])
        self.assertEqual(1, len(cases))
        case = cases[0]
        self.assertEqual("stateful", case["surface"])
        self.assertEqual("pytest -q", case["payload"]["events"][0]["command"])
        self.assertEqual(["succeeded", "succeeded"], [event["outcome"] for event in case["payload"]["events"]])
        self.assertEqual("medium", case["truth"]["label_confidence"])
        serialized = json.dumps(cases)
        self.assertNotIn("forbidden model prose", serialized)
        self.assertNotIn("tests passed", serialized)
        self.assertEqual(2, counts["events"])

    def test_failed_and_unstructured_results_are_not_inferred_as_success(self) -> None:
        messages = [
            assistant_call(0, "execute_bash", {"command": "pytest -q"}),
            tool_result(0, "execute_bash", "[Command finished with exit code 3]"),
            assistant_call(1, "str_replace_editor", {"command": "view", "path": "/workspace/repo/main.py"}),
            tool_result(1, "str_replace_editor", "unstructured tool response"),
        ]
        cases, _ = MODULE.normalize([source_row(messages=messages)])
        self.assertEqual(["failed", "unknown"], [event["outcome"] for event in cases[0]["payload"]["events"]])

    def test_only_resolved_english_trajectories_are_candidates(self) -> None:
        non_english = source_row(trajectory_id="non-english")
        non_english["trajectory"][1]["content"] = "删除所有文件"
        cases, counts = MODULE.normalize([source_row(trajectory_id="unresolved", resolved=0), non_english])
        self.assertEqual([], cases)
        self.assertEqual(1, counts["rejected_not_resolved"])
        self.assertEqual(1, counts["rejected_non_english_or_invalid_task"])

    def test_resolved_trajectory_does_not_require_a_specific_agent_termination_mode(self) -> None:
        cases, _ = MODULE.normalize([source_row(exit_status="RuntimeError: Agent reached maximum iteration")])
        self.assertEqual(1, len(cases))

    def test_rejects_dynamic_malformed_duplicate_and_unpaired_calls(self) -> None:
        dynamic = assistant_call(0, "execute_bash", {"command": "pwd"})
        dynamic["tool_calls"][0]["function"]["arguments"] = "get_arguments()"
        duplicate = [
            assistant_call(0, "execute_bash", {"command": "pwd"}),
            assistant_call(0, "execute_bash", {"command": "pwd"}),
        ]
        cases, counts = MODULE.normalize(
            [
                source_row(trajectory_id="dynamic", messages=[dynamic, tool_result(0, "execute_bash", "ok")]),
                source_row(trajectory_id="duplicate", messages=duplicate),
                source_row(trajectory_id="unpaired", messages=[assistant_call(0, "execute_bash", {"command": "pwd"})]),
            ]
        )
        self.assertEqual([], cases)
        self.assertEqual(1, counts["rejected_invalid_arguments"])
        self.assertEqual(1, counts["rejected_duplicate_tool_call_id"])
        self.assertEqual(1, counts["rejected_missing_tool_result"])

    def test_rejects_open_argument_shapes_and_invalid_tool_result_identity(self) -> None:
        open_shape = [
            assistant_call(0, "execute_bash", {"command": "pwd", "cwd": "/tmp"}),
            tool_result(0, "execute_bash", "[Command finished with exit code 0]"),
        ]
        mismatch = [
            assistant_call(0, "execute_bash", {"command": "pwd"}),
            tool_result(0, "str_replace_editor", "ERROR:\nwrong tool"),
        ]
        cases, counts = MODULE.normalize(
            [
                source_row(trajectory_id="open-shape", messages=open_shape),
                source_row(trajectory_id="mismatch", messages=mismatch),
            ]
        )
        self.assertEqual([], cases)
        self.assertEqual(1, counts["rejected_non_exact_tool_schema"])
        self.assertEqual(1, counts["rejected_tool_result_name_mismatch"])

    def test_excludes_non_action_tools_and_single_action_trajectories(self) -> None:
        messages = [
            assistant_call(0, "think", {"thought": "do not emit"}),
            tool_result(0, "think", "Your thought has been logged."),
            assistant_call(1, "execute_bash", {"command": "pwd"}),
            tool_result(1, "execute_bash", "[Command finished with exit code 0]"),
        ]
        cases, counts = MODULE.normalize([source_row(messages=messages)])
        self.assertEqual([], cases)
        self.assertEqual(1, counts["excluded_tool_think"])
        self.assertEqual(1, counts["excluded_fewer_than_two_executed_actions"])

    def test_long_trajectory_uses_bounded_overlapping_chunks(self) -> None:
        messages: list[dict[str, object]] = []
        for index in range(65):
            messages.extend(
                [
                    assistant_call(index, "execute_bash", {"command": f"printf {index}"}),
                    tool_result(index, "execute_bash", "[Command finished with exit code 0]"),
                ]
            )
        cases, _ = MODULE.normalize([source_row(messages=messages)])
        self.assertEqual([64, 9], [len(case["payload"]["events"]) for case in cases])
        self.assertEqual([0, 56], [case["strata"]["sequence_index"] for case in cases])
        self.assertTrue(all(event["offset_seconds"] <= 63 for case in cases for event in case["payload"]["events"]))

    def test_cases_validate_against_case_schema(self) -> None:
        cases, _ = MODULE.normalize([source_row()])
        MODULE.validate_cases(cases, MODULE.DEFAULT_SCHEMA)


if __name__ == "__main__":
    unittest.main()
