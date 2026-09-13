#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("benchmark_normalize_agenttrace.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_agenttrace", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def span(index: int, tool: str = "bash", action: str = "printf safe", exit_code: int = 0) -> dict[str, object]:
    key = "command" if tool == "bash" else "code" if tool == "python_interpreter" else "answer"
    return {
        "span_id": f"span-{index}",
        "type": "TOOL",
        "tool_name": tool,
        "tool_input": f"kwargs={{{key!r}: {action!r}}}",
        "tool_output": "forbidden result body",
        "exit_code": exit_code,
        "telemetry": {"secret_host": "forbidden telemetry"},
    }


def source_row(
    *,
    trace_id: str = "trace-one",
    dataset: str = "nl2bash",
    task_id: int = 7,
    prompt: str = "List files in the test fixture",
    spans: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    spans = [span(0), span(1, "python_interpreter", "print('ok')", 3)] if spans is None else spans
    run_id = f"run-{trace_id}"
    metadata: dict[str, object] = {
        "schema_version": "0.3.0",
        "collector_version": "0.3.0",
        "dataset_name": dataset,
        "dataset_split": "test" if dataset == "mbpp" else "train",
        "source": dataset,
        "task_id": task_id,
        "run_id": run_id,
    }
    if dataset == "nl2bash":
        metadata["fixture_version"] = "f" * 64
    return {
        "trace_id": trace_id,
        "dataset_name": dataset,
        "task_id": task_id,
        "run_id": run_id,
        "tool_span_count": len(spans),
        "spans_json": json.dumps(spans),
        "metadata_json": json.dumps(metadata),
        "prompt": prompt,
        "model": "forbidden model ID",
        "reasoning": "forbidden reasoning",
        "labels": ["forbidden label"],
    }


class AgentTraceNormalizerTest(unittest.TestCase):
    def test_projects_exact_inputs_and_explicit_outcomes_without_forbidden_fields(self) -> None:
        cases, counts = MODULE.normalize([source_row()])
        self.assertEqual(1, len(cases))
        case = cases[0]
        self.assertEqual("stateful", case["surface"])
        self.assertEqual("printf safe", case["payload"]["events"][0]["command"])
        self.assertEqual({"code": "print('ok')"}, case["payload"]["events"][1]["args"])
        self.assertEqual(["succeeded", "failed"], [event["outcome"] for event in case["payload"]["events"]])
        serialized = json.dumps(cases)
        for forbidden in ("forbidden result body", "forbidden telemetry", "forbidden model ID", "forbidden reasoning"):
            self.assertNotIn(forbidden, serialized)
        self.assertEqual(2, counts["events"])

    def test_single_execution_becomes_atomic_case(self) -> None:
        cases, _ = MODULE.normalize([source_row(spans=[span(0)])])
        self.assertEqual("action", cases[0]["surface"])
        self.assertEqual("printf safe", cases[0]["payload"]["command"])

    def test_task_group_keeps_duplicate_runs_in_the_same_split(self) -> None:
        rows = [source_row(trace_id="trace-a", task_id=9), source_row(trace_id="trace-b", task_id=9)]
        cases, _ = MODULE.normalize(rows)
        self.assertEqual(1, len({case["strata"]["split_group"] for case in cases}))
        self.assertEqual(1, len({case["split"] for case in cases}))

    def test_filters_non_english_and_rejects_missing_execution_evidence(self) -> None:
        missing_exit = span(0)
        del missing_exit["exit_code"]
        cases, counts = MODULE.normalize(
            [
                source_row(trace_id="non-english", prompt="删除所有文件"),
                source_row(trace_id="missing-exit", spans=[missing_exit]),
            ]
        )
        self.assertEqual([], cases)
        self.assertEqual(1, counts["rejected_non_english_or_invalid_task"])
        self.assertEqual(1, counts["rejected_missing_explicit_exit_code"])

    def test_rejects_dynamic_or_non_exact_arguments_and_bad_provenance(self) -> None:
        dynamic = span(0)
        dynamic["tool_input"] = "kwargs=get_args()"
        extra = span(1)
        extra["tool_input"] = "kwargs={'command': 'true', 'cwd': '/tmp'}"
        bad_provenance = source_row(trace_id="bad-provenance")
        metadata = json.loads(str(bad_provenance["metadata_json"]))
        metadata["task_id"] = 999
        bad_provenance["metadata_json"] = json.dumps(metadata)
        cases, counts = MODULE.normalize(
            [
                source_row(trace_id="dynamic", spans=[dynamic]),
                source_row(trace_id="extra", spans=[extra]),
                bad_provenance,
            ]
        )
        self.assertEqual([], cases)
        self.assertEqual(1, counts["rejected_invalid_tool_input"])
        self.assertEqual(1, counts["rejected_non_exact_tool_schema"])
        self.assertEqual(1, counts["rejected_provenance_mismatch"])

    def test_long_trajectory_uses_bounded_overlapping_chunks(self) -> None:
        cases, _ = MODULE.normalize([source_row(spans=[span(index) for index in range(65)])])
        self.assertEqual([64, 9], [len(case["payload"]["events"]) for case in cases])
        self.assertEqual([0, 56], [case["strata"]["sequence_index"] for case in cases])
        self.assertEqual(1, len({case["strata"]["split_group"] for case in cases}))

    def test_cases_validate_against_case_schema(self) -> None:
        cases, _ = MODULE.normalize(
            [source_row(), source_row(trace_id="mbpp-trace", dataset="mbpp", task_id=8, spans=[span(0)])]
        )
        MODULE.validate_cases(cases, MODULE.DEFAULT_SCHEMA)


if __name__ == "__main__":
    unittest.main()
