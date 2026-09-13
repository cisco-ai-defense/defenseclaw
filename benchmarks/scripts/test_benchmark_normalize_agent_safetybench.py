#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("benchmark_normalize_agent_safetybench.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_agent_safetybench", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def call(call_id: str, tool: str, arguments: dict[str, object]) -> dict[str, object]:
    return {
        "function": {"arguments": json.dumps(arguments), "name": tool},
        "id": call_id,
        "type": "function",
    }


def result(call_id: str, tool: str, content: str = "forbidden result body") -> dict[str, object]:
    return {"content": content, "name": tool, "role": "tool", "tool_call_id": call_id}


def source_row(
    *,
    task_id: int = 17,
    calls: list[dict[str, object]] | None = None,
    results: list[dict[str, object]] | None = None,
    instruction: str = "Review this ordinary operation and use the available tools safely.",
    fulfillable: int = 1,
) -> dict[str, object]:
    calls = calls or [call("call-1", "inspect_resource", {"resource": "public-report"})]
    results = results or [result("call-1", "inspect_resource")]
    return {
        "dialog": [
            {"content": "forbidden user prompt", "role": "user"},
            {"role": "assistant", "tool_calls": calls},
            *results,
        ],
        "environments": [
            {
                "name": "TestEnvironment",
                "parameters": {"forbidden": "environment detail"},
                "tools": ["inspect_resource"],
            }
        ],
        "failure_modes": "2,9",
        "fulfillable": fulfillable,
        "id": task_id,
        "instruction": instruction,
        "risks": ["Lead to property loss"],
    }


class AgentSafetyBenchNormalizerTest(unittest.TestCase):
    @staticmethod
    def by_surface(cases: list[dict[str, object]], surface: str) -> list[dict[str, object]]:
        return [case for case in cases if case["surface"] == surface]

    def test_risky_and_unfulfillable_labels_never_become_deterministic_truth(self) -> None:
        cases, counts = MODULE.normalize([source_row(fulfillable=0)])
        self.assertEqual(1, len(cases))
        self.assertEqual(0, counts["deterministic_positive_cases"])
        truth = cases[0]["truth"]
        self.assertEqual("unknown", truth["source_truth"])
        self.assertEqual("contextual_or_dual_use", truth["deterministic_truth"])
        self.assertEqual("out_of_scope", truth["applicability"])
        self.assertEqual("detect_only", truth["expected_disposition"])

    def test_preserves_exact_arguments_and_native_identity_but_not_result_body(self) -> None:
        cases, _ = MODULE.normalize([source_row()])
        self.assertEqual({"resource": "public-report"}, cases[0]["payload"]["args"])
        self.assertIn("call:call-1", cases[0]["source"]["original_id"])
        serialized = json.dumps(cases)
        self.assertNotIn("forbidden result body", serialized)
        self.assertNotIn("forbidden user prompt", serialized)
        self.assertNotIn("environment detail", serialized)

    def test_parallel_results_join_by_native_id_and_restore_call_order(self) -> None:
        calls = [
            call("call-first", "inspect_resource", {"resource": "first"}),
            call("call-second", "inspect_resource", {"resource": "second"}),
        ]
        results = [result("call-second", "inspect_resource"), result("call-first", "inspect_resource")]
        cases, _ = MODULE.normalize([source_row(calls=calls, results=results)])
        actions = self.by_surface(cases, "action")
        stateful = self.by_surface(cases, "stateful")
        self.assertEqual(["first", "second"], [case["payload"]["args"]["resource"] for case in actions])
        self.assertEqual(1, len(stateful))
        self.assertEqual(
            ["first", "second"],
            [event["args"]["resource"] for event in stateful[0]["payload"]["events"]],
        )
        self.assertEqual(["unknown", "unknown"], [event["outcome"] for event in stateful[0]["payload"]["events"]])

    def test_stateful_window_is_current_plus_at_most_eight_predecessors(self) -> None:
        calls = [call(f"call-{index}", "inspect_resource", {"resource": f"item-{index}"}) for index in range(12)]
        results = [result(f"call-{index}", "inspect_resource") for index in range(12)]
        cases, _ = MODULE.normalize([source_row(calls=calls, results=results)])
        stateful = sorted(self.by_surface(cases, "stateful"), key=lambda case: case["strata"]["call_index"])
        self.assertEqual(11, len(stateful))
        self.assertEqual([2, 3, 4, 5, 6, 7, 8, 9, 9, 9, 9], [len(case["payload"]["events"]) for case in stateful])
        self.assertEqual("item-3", stateful[-1]["payload"]["events"][0]["args"]["resource"])
        self.assertEqual("item-11", stateful[-1]["payload"]["events"][-1]["args"]["resource"])

    def test_credential_and_pii_arguments_are_quarantined_without_redaction(self) -> None:
        rows = [
            source_row(
                task_id=1,
                calls=[call("one", "inspect_resource", {"password": "provided by secret store"})],
                results=[result("one", "inspect_resource")],
            ),
            source_row(
                task_id=2,
                calls=[call("two", "inspect_resource", {"recipient": "person@example.invalid"})],
                results=[result("two", "inspect_resource")],
            ),
            source_row(
                task_id=3,
                calls=[call("three", "inspect_resource", {"path": "/home/alice/report.txt"})],
                results=[result("three", "inspect_resource")],
            ),
        ]
        cases, counts = MODULE.normalize(rows)
        self.assertEqual([], cases)
        self.assertEqual(3, counts["quarantined_credential_or_pii_argument"])

    def test_non_english_no_dialog_and_refusal_only_rows_are_quarantined(self) -> None:
        no_dialog = source_row(task_id=2)
        del no_dialog["dialog"]
        refusal = source_row(task_id=3)
        refusal["dialog"] = [{"content": "forbidden refusal", "role": "user"}]
        cases, counts = MODULE.normalize(
            [source_row(task_id=1, instruction="请执行这个危险操作。"), no_dialog, refusal]
        )
        self.assertEqual([], cases)
        self.assertEqual(1, counts["quarantined_non_english"])
        self.assertEqual(1, counts["quarantined_no_dialog"])
        self.assertEqual(1, counts["quarantined_refusal_or_no_executed_call"])

    def test_malformed_arguments_ids_and_result_links_are_quarantined(self) -> None:
        malformed_call = call("malformed", "inspect_resource", {"resource": "x"})
        malformed_call["function"]["arguments"] = "{"
        duplicate = [
            call("same", "inspect_resource", {"resource": "x"}),
            call("same", "inspect_resource", {"resource": "y"}),
        ]
        rows = [
            source_row(task_id=1, calls=[malformed_call], results=[result("malformed", "inspect_resource")]),
            source_row(task_id=2, calls=duplicate, results=[]),
            source_row(task_id=3, results=[result("wrong", "inspect_resource")]),
            source_row(task_id=4, results=[result("call-1", "other_tool")]),
        ]
        cases, counts = MODULE.normalize(rows)
        self.assertEqual([], cases)
        self.assertEqual(1, counts["quarantined_invalid_arguments_json"])
        self.assertEqual(1, counts["quarantined_duplicate_tool_call_id"])
        self.assertEqual(1, counts["quarantined_orphan_tool_result"])
        self.assertEqual(1, counts["quarantined_tool_result_mismatch"])

    def test_deterministic_task_grouped_splits_keep_all_surfaces_together(self) -> None:
        calls = [
            call("call-a", "inspect_resource", {"resource": "a"}),
            call("call-b", "inspect_resource", {"resource": "b"}),
        ]
        results = [result("call-a", "inspect_resource"), result("call-b", "inspect_resource")]
        first, _ = MODULE.normalize([source_row(calls=calls, results=results)])
        second, _ = MODULE.normalize([source_row(calls=calls, results=results)])
        self.assertEqual(first, second)
        self.assertEqual(1, len({case["split"] for case in first}))
        self.assertEqual(1, len({case["strata"]["split_group"] for case in first}))

    def test_schema_validation_rejects_sensitive_payload_and_in_scope_relabeling(self) -> None:
        cases, _ = MODULE.normalize([source_row()])
        schema = MODULE.DEFAULT_SCHEMA
        MODULE.validate_cases(cases, schema)
        sensitive = json.loads(json.dumps(cases))
        sensitive[0]["payload"]["args"] = {"api_key": "provided by secret store"}
        with self.assertRaisesRegex(ValueError, "credential or PII"):
            MODULE.validate_cases(sensitive, schema)
        relabeled = json.loads(json.dumps(cases))
        relabeled[0]["truth"]["applicability"] = "in_scope"
        with self.assertRaisesRegex(ValueError, "must not become deterministic"):
            MODULE.validate_cases(relabeled, schema)

    def test_full_source_identity_is_pinned(self) -> None:
        self.assertEqual("3c60d5aa0af6a5c817b4ea4856e72f252e283bb7", MODULE.SOURCE_REVISION)
        self.assertEqual("MIT", MODULE.SOURCE_LICENSE)
        self.assertEqual(2_876_562, MODULE.SOURCE_BYTES)
        self.assertEqual("59dd0333001ef767766d803e97086ec02af0fbf7ff1f7070b3797863b0dacbe2", MODULE.SOURCE_SHA256)


if __name__ == "__main__":
    unittest.main()
