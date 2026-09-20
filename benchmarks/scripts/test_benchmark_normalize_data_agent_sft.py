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

MODULE_PATH = Path(__file__).with_name("benchmark_normalize_data_agent_sft.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_data_agent_sft", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def encoded(message: dict[str, object]) -> str:
    return json.dumps(message, separators=(",", ":"))


def assistant_call(index: int, command: str, *, call_id: str | None = None) -> dict[str, object]:
    return {
        "content": "forbidden assistant reasoning",
        "role": "assistant",
        "tool_calls": [
            {
                "function": {"arguments": {"command": command}, "name": "bash"},
                "id": call_id or f"call-{index}",
                "type": "function",
            }
        ],
    }


def tool_result(index: int, content: str, *, call_id: str | None = None, name: str = "bash") -> dict[str, object]:
    return {
        "content": content,
        "name": name,
        "role": "tool",
        "tool_call_id": call_id or f"call-{index}",
    }


def source_row(
    *,
    task_id: str = "0032_386_32386426_qa_2",
    messages: list[dict[str, object]] | None = None,
    source_agent: str = "bash",
) -> dict[str, object]:
    messages = messages or [
        {"role": "system", "content": "forbidden system prompt"},
        {"role": "user", "content": "Analyze the table and calculate the requested value."},
        assistant_call(0, "python3 -c 'print(42)'"),
        tool_result(0, "UNIQUE_RESULT_BODY"),
        assistant_call(1, "printf 42 > /workdir/answer.txt"),
        tool_result(1, "(empty output, rc=0)"),
        {"role": "assistant", "content": "forbidden final answer"},
    ]
    return {
        "difficulty": 2,
        "difficulty_tier": "medium",
        "messages": [encoded(message) for message in messages],
        "n_turns": 2,
        "source_agent": source_agent,
        "task_id": task_id,
        "tools": [
            {
                "function": {
                    "description": "forbidden tool description",
                    "name": "bash",
                    "parameters": {
                        "properties": {"command": {"description": "forbidden parameter prose", "type": "string"}},
                        "required": ["command"],
                        "type": "object",
                    },
                },
                "type": "function",
            }
        ],
    }


class DataAgentSFTNormalizerTest(unittest.TestCase):
    @staticmethod
    def by_surface(cases: list[dict[str, object]], surface: str) -> list[dict[str, object]]:
        return [case for case in cases if case["surface"] == surface]

    def test_projects_exact_arguments_identity_order_and_only_explicit_outcomes(self) -> None:
        cases, counts = MODULE.normalize([source_row(source_agent="seta")])
        self.assertEqual(3, len(cases))
        actions = self.by_surface(cases, "action")
        stateful = self.by_surface(cases, "stateful")
        self.assertEqual(2, len(actions))
        self.assertEqual(1, len(stateful))
        self.assertEqual(
            ["python3 -c 'print(42)'", "printf 42 > /workdir/answer.txt"],
            [case["payload"]["args"]["command"] for case in actions],
        )
        self.assertTrue(all("outcome" not in case["payload"] for case in actions))
        self.assertTrue(all("offset_seconds" not in case["payload"] for case in actions))
        events = stateful[0]["payload"]["events"]
        self.assertEqual(
            ["python3 -c 'print(42)'", "printf 42 > /workdir/answer.txt"],
            [event["args"]["command"] for event in events],
        )
        self.assertEqual(["unknown", "succeeded"], [event["outcome"] for event in events])
        self.assertEqual([0, 1], [event["offset_seconds"] for event in events])
        self.assertTrue(all(case["strata"]["campaign"] == "source_agent:seta" for case in cases))
        self.assertEqual(2, counts["events"])
        self.assertEqual(2, counts["action_cases"])
        self.assertEqual(1, counts["stateful_cases"])

    def test_truth_categories_distinguish_actions_from_sequences(self) -> None:
        cases, _ = MODULE.normalize([source_row()])
        actions = self.by_surface(cases, "action")
        stateful = self.by_surface(cases, "stateful")
        self.assertTrue(all("structured_tool_call" in case["truth"]["categories"] for case in actions))
        self.assertTrue(all("bounded_action_sequence" not in case["truth"]["categories"] for case in actions))
        self.assertTrue(all("bounded_action_sequence" in case["truth"]["categories"] for case in stateful))
        self.assertTrue(all("structured_tool_call" not in case["truth"]["categories"] for case in stateful))

    def test_excludes_prompts_prose_answers_tool_descriptions_and_result_bodies(self) -> None:
        cases, _ = MODULE.normalize([source_row()])
        serialized = json.dumps(cases)
        for forbidden in (
            "forbidden system prompt",
            "Analyze the table",
            "forbidden assistant reasoning",
            "forbidden final answer",
            "forbidden tool description",
            "forbidden parameter prose",
        ):
            self.assertNotIn(forbidden, serialized)
        self.assertNotIn("UNIQUE_RESULT_BODY", serialized)

    def test_parallel_calls_are_joined_by_exact_ids_then_restored_to_call_order(self) -> None:
        first = assistant_call(0, "first", call_id="id-first")["tool_calls"][0]
        second = assistant_call(1, "second", call_id="id-second")["tool_calls"][0]
        messages = [
            {"role": "user", "content": "Compute two independent statistics."},
            {"role": "assistant", "content": "parallel", "tool_calls": [first, second]},
            tool_result(1, "(empty output, rc=2)", call_id="id-second"),
            tool_result(0, "(empty output, rc=0)", call_id="id-first"),
        ]
        cases, _ = MODULE.normalize([source_row(messages=messages)])
        events = self.by_surface(cases, "stateful")[0]["payload"]["events"]
        self.assertEqual(["first", "second"], [event["command"] for event in events])
        self.assertEqual(["succeeded", "failed"], [event["outcome"] for event in events])

    def test_result_text_never_implies_outcome_without_exact_rc_marker(self) -> None:
        messages = [
            {"role": "user", "content": "Analyze a dataset with two shell commands."},
            assistant_call(0, "false"),
            tool_result(0, "ERROR: a command failed"),
            assistant_call(1, "true"),
            tool_result(1, "success"),
        ]
        cases, _ = MODULE.normalize([source_row(messages=messages)])
        stateful = self.by_surface(cases, "stateful")
        self.assertEqual(["unknown", "unknown"], [event["outcome"] for event in stateful[0]["payload"]["events"]])

    def test_rejects_non_english_dynamic_malformed_and_open_argument_shapes(self) -> None:
        dynamic = assistant_call(0, "one")
        dynamic["tool_calls"][0]["function"]["arguments"] = "build_arguments()"
        open_shape = assistant_call(0, "one")
        open_shape["tool_calls"][0]["function"]["arguments"] = {"command": "one", "cwd": "/tmp"}
        rows = [
            source_row(
                task_id="non-english",
                messages=[
                    {"role": "user", "content": "删除所有文件"},
                    assistant_call(0, "one"),
                    tool_result(0, "ok"),
                    assistant_call(1, "two"),
                    tool_result(1, "ok"),
                ],
            ),
            source_row(
                task_id="dynamic",
                messages=[
                    {"role": "user", "content": "Analyze data."},
                    dynamic,
                    tool_result(0, "ok"),
                    assistant_call(1, "two"),
                    tool_result(1, "ok"),
                ],
            ),
            source_row(
                task_id="open-shape",
                messages=[
                    {"role": "user", "content": "Analyze data."},
                    open_shape,
                    tool_result(0, "ok"),
                    assistant_call(1, "two"),
                    tool_result(1, "ok"),
                ],
            ),
        ]
        cases, counts = MODULE.normalize(rows)
        self.assertEqual([], cases)
        self.assertEqual(1, counts["quarantined_non_english_or_invalid_task"])
        self.assertEqual(1, counts["quarantined_dynamic_arguments"])
        self.assertEqual(1, counts["quarantined_non_exact_tool_schema"])

    def test_rejects_duplicate_orphan_missing_mismatched_and_interrupted_results(self) -> None:
        duplicate_first = assistant_call(0, "one")["tool_calls"][0]
        duplicate_second = assistant_call(0, "two")["tool_calls"][0]
        duplicate = [
            {"role": "user", "content": "Analyze data."},
            {"role": "assistant", "content": "parallel", "tool_calls": [duplicate_first, duplicate_second]},
        ]
        orphan = [
            {"role": "user", "content": "Analyze data."},
            tool_result(0, "ok"),
            assistant_call(1, "two"),
            tool_result(1, "ok"),
        ]
        missing = [
            {"role": "user", "content": "Analyze data."},
            assistant_call(0, "one"),
            tool_result(0, "ok"),
            assistant_call(1, "two"),
        ]
        mismatch = [
            {"role": "user", "content": "Analyze data."},
            assistant_call(0, "one"),
            tool_result(0, "ok", name="other"),
            assistant_call(1, "two"),
            tool_result(1, "ok"),
        ]
        interrupted = [
            {"role": "user", "content": "Analyze data."},
            assistant_call(0, "one"),
            {"role": "assistant", "content": "interruption"},
            tool_result(0, "late"),
            assistant_call(1, "two"),
            tool_result(1, "ok"),
        ]
        rows = [
            source_row(task_id="duplicate", messages=duplicate),
            source_row(task_id="orphan", messages=orphan),
            source_row(task_id="missing", messages=missing),
            source_row(task_id="mismatch", messages=mismatch),
            source_row(task_id="interrupted", messages=interrupted),
        ]
        cases, counts = MODULE.normalize(rows)
        self.assertEqual([], cases)
        self.assertEqual(1, counts["quarantined_interrupted_call_result_block"])
        self.assertEqual(1, counts["quarantined_orphan_tool_result"])
        self.assertEqual(1, counts["quarantined_missing_tool_result"])
        self.assertEqual(1, counts["quarantined_tool_result_name_mismatch"])
        self.assertEqual(1, counts["quarantined_duplicate_tool_call_id"])

    def test_duplicate_json_keys_are_quarantined(self) -> None:
        row = source_row()
        row["messages"][2] = (
            '{"role":"assistant","content":"x","tool_calls":['
            '{"id":"call-0","type":"function","function":'
            '{"name":"bash","arguments":{"command":"one","command":"two"}}}]}'
        )
        cases, counts = MODULE.normalize([row])
        self.assertEqual([], cases)
        self.assertEqual(1, counts["quarantined_invalid_message"])

    def test_windows_contain_current_plus_at_most_eight_predecessors(self) -> None:
        messages: list[dict[str, object]] = [{"role": "user", "content": "Analyze a table carefully."}]
        for index in range(12):
            messages.extend([assistant_call(index, f"step-{index}"), tool_result(index, "unknown")])
        cases, _ = MODULE.normalize([source_row(messages=messages)])
        actions = self.by_surface(cases, "action")
        stateful = self.by_surface(cases, "stateful")
        self.assertEqual(12, len(actions))
        self.assertEqual(11, len(stateful))
        self.assertEqual(
            [2, 3, 4, 5, 6, 7, 8, 9, 9, 9, 9],
            [len(case["payload"]["events"]) for case in stateful],
        )
        self.assertEqual(
            [0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3],
            [case["strata"]["sequence_index"] for case in stateful],
        )
        self.assertTrue(all(len(case["payload"]["events"]) <= 9 for case in stateful))

    def test_repeated_legitimate_atomic_calls_are_not_content_deduplicated(self) -> None:
        messages = [
            {"role": "user", "content": "Inspect the same file twice to verify its contents."},
            assistant_call(0, "head data.csv"),
            tool_result(0, "first"),
            assistant_call(1, "head data.csv"),
            tool_result(1, "second"),
        ]
        cases, counts = MODULE.normalize([source_row(messages=messages)])
        actions = self.by_surface(cases, "action")
        self.assertEqual(2, len(actions))
        self.assertEqual(["head data.csv", "head data.csv"], [case["payload"]["command"] for case in actions])
        self.assertEqual(2, counts["action_cases"])

    def test_splits_are_task_grouped_and_exact_payloads_are_deduplicated(self) -> None:
        duplicate = source_row(task_id="another-task")
        cases, counts = MODULE.normalize([duplicate, source_row()])
        actions = self.by_surface(cases, "action")
        stateful = self.by_surface(cases, "stateful")
        self.assertEqual(4, len(actions))
        self.assertEqual(1, len(stateful))
        self.assertEqual("0032_386_32386426_qa_2", stateful[0]["source"]["original_id"])
        self.assertEqual(1, counts["exact_payload_duplicates_removed"])
        self.assertEqual(1, counts["exact_stateful_windows_removed"])
        self.assertEqual(MODULE.split_for(MODULE.split_group("0032_386_32386426_qa_2")), stateful[0]["split"])

    def test_conflicting_duplicate_task_ids_are_all_quarantined(self) -> None:
        changed = source_row()
        changed_messages = [json.loads(value) for value in changed["messages"]]
        changed_messages[2] = assistant_call(0, "different-command")
        changed["messages"] = [encoded(message) for message in changed_messages]
        cases, counts = MODULE.normalize([source_row(), changed])
        self.assertEqual([], cases)
        self.assertEqual(1, counts["quarantined_conflicting_task_id"])

    def test_cases_validate_against_case_schema(self) -> None:
        cases, _ = MODULE.normalize([source_row()])
        MODULE.validate_cases(cases, MODULE.DEFAULT_SCHEMA)

    def test_main_rejects_wrong_source_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.parquet"
            source.write_bytes(b"not the pinned source")
            old_argv = sys.argv
            try:
                sys.argv = [str(MODULE_PATH), "--input", str(source), "--output", str(Path(directory) / "out.jsonl")]
                with self.assertRaisesRegex(ValueError, "source identity mismatch"):
                    MODULE.main()
            finally:
                sys.argv = old_argv


if __name__ == "__main__":
    unittest.main()
