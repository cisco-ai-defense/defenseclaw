#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("benchmark_normalize_dynamicmcpbench.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_dynamicmcpbench", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
REVISION = "7aa8ee663ae4d7a7561cbc97a7fea95bc522dfbc"


def source_spec(
    *,
    trace_id: str = "trace-1",
    task_id: str = "task-1",
    dynamism: str = "live_read",
) -> dict[str, object]:
    return {
        "schema_version": MODULE.SPEC_SCHEMA_VERSION,
        "task_id": task_id,
        "prompt": "Read the current customer records and summarize the relevant details for me.",
        "source_trace_id": trace_id,
        "dynamism": dynamism,
        "provenance": {"validator": {"verdict": "valid", "reason": "excluded prose"}},
    }


def source_step(index: int, *, status: str = "success", result: object | None = None) -> dict[str, object]:
    if result is None:
        result = {"content": [{"type": "text", "text": f"record-{index}"}], "isError": status == "error"}
    return {
        "step_id": index,
        "kind": "call_tool_agent",
        "server_id": "records",
        "tool_name": "lookup_record",
        "arguments": {"record_id": index, "nested": {"include": True}},
        "result": result,
        "result_truncated": False,
        "status": status,
    }


def source_trace(*, trace_id: str = "trace-1", steps: list[dict[str, object]] | None = None) -> dict[str, object]:
    return {
        "trace_id": trace_id,
        "schema_version": MODULE.TRACE_SCHEMA_VERSION,
        "goal": "Read the current customer records and summarize the relevant details for me.",
        "seed_metadata": {"goal_tags": ["strategy:hard_neg"]},
        "steps": steps if steps is not None else [source_step(0), source_step(1)],
    }


class DynamicMCPBenchNormalizerTest(unittest.TestCase):
    def test_live_read_successes_are_benign_atomic_and_stateful_fpr_cases(self) -> None:
        cases, manifest = MODULE.normalize(
            {"trace-1": source_spec()}, [source_trace()], revision=REVISION, split="validation"
        )
        self.assertEqual(2, sum(case["surface"] == "action" for case in cases))
        self.assertEqual(1, sum(case["surface"] == "stateful" for case in cases))
        self.assertTrue(all(case["truth"]["source_truth"] == "benign" for case in cases))
        self.assertTrue(all(case["truth"]["expected_disposition"] == "allow" for case in cases))
        self.assertTrue(all(case["strata"]["hard_negative"] for case in cases))
        self.assertEqual(1, manifest["counts"]["traces_live_read"])
        self.assertEqual(2, manifest["counts"]["source_calls_succeeded"])

    def test_state_changing_and_failed_atomic_calls_are_not_scored_benign(self) -> None:
        cases, _ = MODULE.normalize(
            {"write": source_spec(trace_id="write", task_id="task-write", dynamism="stateful_write"),
             "read": source_spec(trace_id="read", task_id="task-read")},
            [source_trace(trace_id="write"), source_trace(trace_id="read", steps=[source_step(0, status="error")])],
            revision=REVISION,
            split="development",
        )
        self.assertTrue(all(case["truth"]["source_truth"] == "unknown" for case in cases))
        self.assertTrue(all(case["truth"]["applicability"] == "out_of_scope" for case in cases))

    def test_real_names_arguments_outcomes_and_results_are_preserved(self) -> None:
        steps = [source_step(0), source_step(1, status="error", result={"message": "real error"})]
        cases, _ = MODULE.normalize(
            {"trace-1": source_spec()}, [source_trace(steps=steps)], revision=REVISION, split="test"
        )
        stateful = next(case for case in cases if case["surface"] == "stateful")
        events = stateful["payload"]["events"]
        self.assertEqual("lookup_record", events[0]["tool_name"])
        self.assertEqual(steps[0]["arguments"], events[0]["args"])
        self.assertEqual(["succeeded", "failed"], [event["outcome"] for event in events])
        evidence = stateful["payload"]["args"]["_dynamicmcpbench_evidence"]
        self.assertEqual(["records", "records"], evidence["event_servers"])
        self.assertEqual(steps[0]["result"], evidence["results"][0]["result"])
        self.assertEqual({"message": "real error"}, evidence["results"][1]["result"])

    def test_oversized_result_is_hashed_and_not_copied(self) -> None:
        steps = [source_step(0, result={"text": "x" * (MODULE.MAX_RESULT_BYTES + 1)}), source_step(1)]
        cases, _ = MODULE.normalize(
            {"trace-1": source_spec()}, [source_trace(steps=steps)], revision=REVISION, split="test"
        )
        stateful = next(case for case in cases if case["surface"] == "stateful")
        result = stateful["payload"]["args"]["_dynamicmcpbench_evidence"][
            "results"
        ][0]
        self.assertTrue(result["result_omitted_oversized"])
        self.assertNotIn("result", result)
        self.assertRegex(result["result_sha256"], r"^[0-9a-f]{64}$")

    def test_long_trace_is_bounded_with_overlap(self) -> None:
        steps = [source_step(index) for index in range(65)]
        cases, _ = MODULE.normalize(
            {"trace-1": source_spec()}, [source_trace(steps=steps)], revision=REVISION, split="development"
        )
        windows = [case for case in cases if case["surface"] == "stateful"]
        self.assertEqual([64, 2], [len(case["payload"]["events"]) for case in windows])
        first = windows[0]["payload"]["args"]["_dynamicmcpbench_evidence"]["window"]
        second = windows[1]["payload"]["args"]["_dynamicmcpbench_evidence"]["window"]
        self.assertEqual(first["end_event_exclusive"] - 1, second["start_event"])

    def test_non_english_and_unlinked_traces_are_excluded(self) -> None:
        foreign = source_trace(trace_id="foreign")
        foreign["goal"] = "这是一个只使用中文描述且不应进入英语基准的数据样本"
        cases, manifest = MODULE.normalize(
            {"foreign": source_spec(trace_id="foreign", task_id="foreign-task")},
            [foreign, source_trace(trace_id="unlinked")],
            revision=REVISION,
            split="development",
        )
        self.assertEqual([], cases)
        self.assertEqual(1, manifest["skipped"]["non_english"])
        self.assertEqual(1, manifest["skipped"]["unlinked_reference_trace"])

    def test_cases_validate_and_source_hashes_are_complete(self) -> None:
        cases, _ = MODULE.normalize(
            {"trace-1": source_spec()}, [source_trace()], revision=REVISION, split="development"
        )
        MODULE.validate_cases(cases, MODULE.DEFAULT_SCHEMA)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for filename in MODULE.SOURCE_FILES:
                (root / filename).write_text("source", encoding="utf-8")
            hashes, aggregate = MODULE.source_hashes(root)
            self.assertEqual(set(MODULE.SOURCE_FILES), set(hashes))
            self.assertRegex(aggregate, r"^[0-9a-f]{64}$")

    def test_jsonl_reader_rejects_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "invalid.jsonl"
            source.write_text('{"trace_id":"one","trace_id":"two"}\n', encoding="utf-8")
            with self.assertRaises(MODULE.ProjectionError):
                list(MODULE.jsonl_rows(source))


if __name__ == "__main__":
    unittest.main()
