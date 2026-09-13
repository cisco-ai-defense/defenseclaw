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

MODULE_PATH = Path(__file__).with_name("benchmark_normalize_actbench.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_actbench", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

REVISION = "a" * 40


def tool_call(call_id: str, name: str, arguments: dict[str, object]) -> dict[str, object]:
    return {"type": "toolCall", "id": call_id, "name": name, "arguments": arguments}


def tool_result(call_id: str, *, error: bool, text: str = "excluded result") -> dict[str, object]:
    return {
        "message": {
            "role": "toolResult",
            "toolCallId": call_id,
            "toolName": "ignored",
            "isError": error,
            "content": [{"type": "text", "text": text}],
            "timestamp": 1_000,
        }
    }


def source_row(
    role: str,
    *,
    passed: bool = True,
    task_id: str = "task-B1",
    trajectory_id: str = "trajectory-one",
    calls: list[dict[str, object]] | None = None,
    results: list[dict[str, object]] | None = None,
    extra_trajectory: dict[str, object] | None = None,
) -> dict[str, object]:
    if calls is None:
        calls = [
            tool_call("call-1", "read", {"path": "/workspace/note.txt"}),
            tool_call("call-2", "exec", {"command": "printf done", "workdir": "/workspace"}),
        ]
    if results is None:
        results = [tool_result("call-2", error=False), tool_result("call-1", error=False)]
    trajectory = {
        "role": MODULE.TRAJECTORY_ROLE[role],
        "trajectory_id": trajectory_id,
        "transcript": {
            "entries": [
                {"message": {"role": "user", "content": [{"type": "text", "text": "excluded prompt"}]}},
                {
                    "message": {
                        "role": "assistant",
                        "content": calls,
                        "timestamp": 1_000,
                    }
                },
                *results,
            ]
        },
        **(extra_trajectory or {}),
    }
    score = {"available": True, "evaluation_error": False}
    score["task_pass" if role == "clean" else "attack_pass"] = passed
    return {
        "role": role,
        "task_id": task_id,
        "trajectory_id": trajectory_id,
        "trajectory_json": json.dumps(trajectory),
        "score_json": json.dumps(score),
    }


class NormalizeActBenchTest(unittest.TestCase):
    def test_clean_success_emits_atomic_hard_negatives_and_benign_sequence(self) -> None:
        calls = [
            tool_call("call-1", "read", {"path": "/workspace/a"}),
            tool_call("call-2", "exec", {"command": "false"}),
            tool_call("call-3", "write", {"path": "/workspace/b", "content": "ok"}),
        ]
        results = [
            tool_result("call-3", error=False),
            tool_result("call-1", error=False),
            tool_result("call-2", error=True),
        ]
        cases, manifest = MODULE.normalize([source_row("clean", calls=calls, results=results)], REVISION)

        actions = [case for case in cases if case["surface"] == "action"]
        sequences = [case for case in cases if case["surface"] == "stateful"]
        self.assertEqual(2, len(actions))
        self.assertEqual(1, len(sequences))
        self.assertEqual([0, 2], [case["strata"]["sequence_index"] for case in actions])
        self.assertTrue(all(case["truth"]["deterministic_truth"] == "benign" for case in cases))
        self.assertTrue(all(case["strata"]["hard_negative"] for case in cases))
        self.assertTrue(all(case["strata"]["language"] == "en" for case in cases))
        self.assertEqual(
            ["succeeded", "failed", "succeeded"],
            [event["outcome"] for event in sequences[0]["payload"]["events"]],
        )
        stats = manifest["adapter_statistics"]["actbench"]
        self.assertEqual(2, stats["clean_action_cases"])
        self.assertEqual(1, stats["outcome_failed"])
        self.assertEqual(2, stats["outcome_succeeded"])

    def test_attack_pass_is_contextual_only_at_stateful_boundary(self) -> None:
        cases, manifest = MODULE.normalize([source_row("attack")], REVISION)

        self.assertEqual(1, len(cases))
        self.assertEqual("en", cases[0]["strata"]["language"])
        case = cases[0]
        self.assertEqual("stateful", case["surface"])
        self.assertEqual("malicious", case["truth"]["source_truth"])
        self.assertEqual("contextual_or_dual_use", case["truth"]["deterministic_truth"])
        self.assertEqual("out_of_scope", case["truth"]["applicability"])
        self.assertEqual("detect_only", case["truth"]["expected_disposition"])
        self.assertIn("contextual_trajectory_source_positive", case["truth"]["categories"])
        stats = manifest["adapter_statistics"]["actbench"]
        self.assertEqual(1, stats["attack_stateful_cases"])
        self.assertEqual(1, stats["attack_contextual_cases"])
        self.assertFalse(any(row["surface"] == "action" for row in cases))

    def test_failed_source_tasks_do_not_become_benign_or_malicious_labels(self) -> None:
        cases, manifest = MODULE.normalize(
            [
                source_row("clean", passed=False, trajectory_id="clean-failed"),
                source_row("attack", passed=False, trajectory_id="attack-failed"),
            ],
            REVISION,
        )

        self.assertEqual([], cases)
        stats = manifest["adapter_statistics"]["actbench"]
        self.assertEqual(1, stats["skipped_clean_task_not_passed"])
        self.assertEqual(1, stats["skipped_attack_not_passed"])

    def test_call_result_pairing_uses_ids_and_preserves_call_order(self) -> None:
        calls = [
            tool_call("first", "read", {"path": "/one"}),
            tool_call("second", "read", {"path": "/two"}),
        ]
        results = [tool_result("second", error=True), tool_result("first", error=False)]
        trajectory = MODULE.parse_json_object(
            source_row("attack", calls=calls, results=results)["trajectory_json"],
            "invalid",
        )
        events = MODULE.project_events(trajectory, max_argument_bytes=MODULE.MAX_ARGUMENT_BYTES)

        self.assertEqual(["first", "second"], [event.tool_call_id for event in events])
        self.assertEqual(["succeeded", "failed"], [event.outcome for event in events])
        self.assertEqual([0, 1], [event.sequence_index for event in events])
        self.assertEqual([0, 1], [event.call_index for event in events])

    def test_out_of_order_timestamps_are_clamped_to_transcript_order(self) -> None:
        row = source_row(
            "attack",
            calls=[
                tool_call("first", "read", {"path": "/one"}),
                tool_call("second", "read", {"path": "/two"}),
                tool_call("third", "read", {"path": "/three"}),
            ],
            results=[
                tool_result("first", error=False),
                tool_result("second", error=False),
                tool_result("third", error=False),
            ],
        )
        trajectory = MODULE.parse_json_object(row["trajectory_json"], "invalid")
        messages = trajectory["transcript"]["entries"]
        messages[1]["message"]["content"] = [messages[1]["message"]["content"][0]]
        messages[1]["message"]["timestamp"] = 1_000
        messages.insert(
            2,
            {
                "message": {
                    "role": "assistant",
                    "content": [tool_call("second", "read", {"path": "/two"})],
                    "timestamp": 9_000,
                }
            },
        )
        messages.insert(
            3,
            {
                "message": {
                    "role": "assistant",
                    "content": [tool_call("third", "read", {"path": "/three"})],
                    "timestamp": 8_000,
                }
            },
        )

        events = MODULE.project_events(trajectory, max_argument_bytes=MODULE.MAX_ARGUMENT_BYTES)

        self.assertEqual([0, 8, 8], [event.offset_seconds for event in events])

    def test_unpaired_clean_call_is_not_atomic_but_remains_in_the_sequence(self) -> None:
        calls = [
            tool_call("paired", "read", {"path": "/one"}),
            tool_call("unpaired", "write", {"path": "/two", "content": "x"}),
        ]
        cases, manifest = MODULE.normalize(
            [source_row("clean", calls=calls, results=[tool_result("paired", error=False)])],
            REVISION,
        )

        self.assertEqual(2, len(cases))
        actions = [case for case in cases if case["surface"] == "action"]
        sequences = [case for case in cases if case["surface"] == "stateful"]
        self.assertEqual("read", actions[0]["payload"]["tool_name"])
        self.assertEqual(
            ["succeeded", "unknown"],
            [event["outcome"] for event in sequences[0]["payload"]["events"]],
        )
        self.assertEqual(1, manifest["adapter_statistics"]["actbench"]["outcome_unknown"])

    def test_downloaded_grader_and_result_content_are_never_evaluated_or_projected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "must-not-exist"
            executable_text = f"__import__('pathlib').Path({str(marker)!r}).touch()"
            row = source_row(
                "attack",
                results=[
                    tool_result("call-1", error=False, text=executable_text),
                    tool_result("call-2", error=False, text="excluded evidence"),
                ],
                extra_trajectory={
                    "scoring_inputs": {"attack_check_code": executable_text},
                    "task": {"automated_checks": executable_text},
                    "execution": {"api_audit": {"secret": "excluded audit"}},
                },
            )
            cases, _ = MODULE.normalize([row], REVISION)
            serialized = json.dumps(cases)

            self.assertFalse(marker.exists())
            self.assertNotIn(executable_text, serialized)
            self.assertNotIn("excluded evidence", serialized)
            self.assertNotIn("excluded audit", serialized)
            self.assertNotIn("excluded prompt", serialized)

    def test_malformed_and_oversized_calls_are_excluded_conservatively(self) -> None:
        duplicate = source_row(
            "attack",
            trajectory_id="duplicate-call",
            calls=[
                tool_call("same", "read", {"path": "/one"}),
                tool_call("same", "write", {"path": "/two"}),
            ],
            results=[tool_result("same", error=False)],
        )
        oversized = source_row(
            "clean",
            trajectory_id="oversized",
            calls=[tool_call("large", "read", {"path": "x" * 128})],
            results=[tool_result("large", error=False)],
        )
        cases, manifest = MODULE.normalize([duplicate, oversized], REVISION, max_argument_bytes=64)

        self.assertEqual([], cases)
        stats = manifest["adapter_statistics"]["actbench"]
        self.assertEqual(1, stats["skipped_duplicate_tool_call"])
        self.assertEqual(1, stats["skipped_oversized_tool_arguments"])

    def test_task_pair_grouping_schema_validation_and_order_stability(self) -> None:
        rows = [
            source_row("clean", task_id="same-task", trajectory_id="clean-one"),
            source_row("attack", task_id="same-task", trajectory_id="attack-one"),
        ]
        first_cases, first_manifest = MODULE.normalize(rows, REVISION)
        second_cases, second_manifest = MODULE.normalize(reversed(rows), REVISION)

        self.assertEqual(first_cases, second_cases)
        self.assertEqual(first_manifest, second_manifest)
        self.assertEqual(1, len({case["strata"]["split_group"] for case in first_cases}))
        MODULE.validate_cases(first_cases, MODULE.DEFAULT_SCHEMA)

    def test_written_manifest_is_value_free_and_bound_to_output(self) -> None:
        cases, manifest = MODULE.normalize([source_row("clean")], REVISION)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "cases.jsonl"
            manifest_path = Path(temporary) / "manifest.json"
            MODULE.write_outputs(cases, manifest, output=output, manifest_path=manifest_path)
            written = json.loads(manifest_path.read_text(encoding="utf-8"))

            self.assertEqual(
                MODULE.hashlib.sha256(output.read_bytes()).hexdigest(),
                written["output_sha256"],
            )
            manifest_text = manifest_path.read_text(encoding="utf-8")
            self.assertNotIn("/workspace", manifest_text)
            self.assertNotIn("printf done", manifest_text)


if __name__ == "__main__":
    unittest.main()
