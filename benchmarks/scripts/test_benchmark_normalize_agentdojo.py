#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("benchmark_normalize_agentdojo.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_agentdojo", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

PARTITION_PATH = Path(__file__).with_name("benchmark_partition.py")
PARTITION_SPEC = importlib.util.spec_from_file_location("benchmark_partition", PARTITION_PATH)
assert PARTITION_SPEC and PARTITION_SPEC.loader
PARTITION = importlib.util.module_from_spec(PARTITION_SPEC)
sys.modules[PARTITION_SPEC.name] = PARTITION
PARTITION_SPEC.loader.exec_module(PARTITION)


def tool_call(index: int, *, failed: bool = False) -> tuple[dict[str, object], dict[str, object]]:
    call = {
        "id": f"call-{index}",
        "function": "search_files" if index == 0 else "send_email",
        "args": {"query": f"record-{index}", "nested": {"limit": index + 1}},
    }
    emitted = {
        "role": "assistant",
        "content": "PRIVATE_REASONING_MARKER",
        "tool_calls": [copy.deepcopy(call)],
    }
    result = {
        "role": "tool",
        "content": {
            "records": [{"id": index}],
            "marker": "PRIVATE_RESULT_MARKER",
        },
        "tool_call_id": call["id"],
        "tool_call": copy.deepcopy(call),
        "error": "synthetic tool failure" if failed else None,
    }
    return emitted, result


def source_record(
    *,
    security: bool = True,
    utility: bool = True,
    attacked: bool = True,
    executed: int = 3,
    emitted_only: bool = False,
) -> dict[str, object]:
    messages: list[dict[str, object]] = [
        {"role": "system", "content": "PRIVATE_SYSTEM_MARKER"},
        {"role": "user", "content": "PRIVATE_PROMPT_MARKER"},
    ]
    for index in range(executed):
        emitted, result = tool_call(index, failed=index == 1)
        messages.extend((emitted, result))
    if emitted_only:
        messages.append(
            {
                "role": "assistant",
                "content": "PRIVATE_UNEXECUTED_REASONING",
                "tool_calls": [
                    {
                        "id": "never-executed",
                        "function": "delete_everything",
                        "args": {"scope": "all"},
                    }
                ],
            }
        )
    return {
        "suite_name": "workspace",
        "pipeline_name": "fixture-agent",
        "user_task_id": "user_task_1",
        "injection_task_id": "injection_task_1" if attacked else None,
        "attack_type": "important_instructions" if attacked else None,
        "injections": {"excluded": "PRIVATE_INJECTION_MARKER"},
        "messages": messages,
        "error": None,
        "utility": utility,
        "security": security,
    }


class AgentDojoNormalizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.runs = self.root / "runs"
        self.runs.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_run(self, name: str, value: dict[str, object]) -> Path:
        path = self.runs / "fixture-agent" / "workspace" / name / "direct" / "injection_task_1.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def build(self):
        return MODULE.build_corpus(self.root, MODULE.PINNED_REVISION, MODULE.PRE_PARTITION_SPLIT)

    def test_projects_only_executed_tool_messages_with_real_arguments(self) -> None:
        self.write_run("user_task_1", source_record(emitted_only=True))
        cases, manifest = self.build()
        actions = [row for row in cases if row["surface"] == "action"]
        self.assertEqual(3, len(actions))
        self.assertEqual(
            ["search_files", "send_email", "send_email"],
            [row["payload"]["tool_name"] for row in actions],
        )
        self.assertEqual("record-0", actions[0]["payload"]["args"]["query"])
        self.assertNotIn("delete_everything", json.dumps(cases))
        statistics = manifest["adapter_statistics"][MODULE.DATASET_ID]
        self.assertEqual(1, statistics["unobserved_emitted_calls"])
        self.assertEqual(3, statistics["result_join_exact_id"])

    def test_preserves_linked_results_errors_and_run_outcomes_without_prompts(
        self,
    ) -> None:
        record = source_record()
        first_result = next(message for message in record["messages"] if message["role"] == "tool")
        first_result["tool_call"]["id"] = ""
        first_result["tool_call_id"] = ""
        self.write_run("user_task_1", record)
        cases, _ = self.build()
        stateful = [row for row in cases if row["surface"] == "stateful"]
        self.assertEqual(2, len(stateful))
        final = stateful[-1]
        self.assertEqual(
            ["succeeded", "failed", "succeeded"],
            [event["outcome"] for event in final["payload"]["events"]],
        )
        evidence = final["payload"]["args"]["_agentdojo_execution"]
        self.assertTrue(evidence["security"])
        self.assertTrue(evidence["utility"])
        self.assertEqual(
            "synthetic tool failure",
            evidence["linked_results"][1]["error"],
        )
        self.assertEqual(
            "PRIVATE_RESULT_MARKER",
            evidence["linked_results"][0]["result"]["marker"],
        )
        self.assertEqual("", evidence["linked_results"][0]["call_ref"])
        self.assertEqual(
            ["message-local", "exact-id", "exact-id"],
            [item["result_join_authority"] for item in evidence["linked_results"]],
        )
        serialized = json.dumps(cases)
        self.assertNotIn("PRIVATE_SYSTEM_MARKER", serialized)
        self.assertNotIn("PRIVATE_PROMPT_MARKER", serialized)
        self.assertNotIn("PRIVATE_REASONING_MARKER", serialized)
        self.assertNotIn("PRIVATE_INJECTION_MARKER", serialized)

    def test_security_preserved_attacks_are_benign_hard_negatives(self) -> None:
        self.write_run("user_task_1", source_record(security=True, attacked=True))
        cases, _ = self.build()
        self.assertTrue(all(row["truth"]["source_truth"] == "benign" for row in cases))
        self.assertTrue(all(row["strata"]["hard_negative"] for row in cases))
        self.assertTrue(all(row["truth"]["expected_disposition"] == "allow" for row in cases))

    def test_only_complete_bounded_violated_run_is_contextual_positive(
        self,
    ) -> None:
        self.write_run("user_task_1", source_record(security=False, executed=3))
        cases, _ = self.build()
        actions = [row for row in cases if row["surface"] == "action"]
        windows = [row for row in cases if row["surface"] == "stateful"]
        self.assertTrue(all(row["truth"]["source_truth"] == "unknown" for row in actions))
        self.assertEqual("unknown", windows[0]["truth"]["source_truth"])
        self.assertEqual("malicious", windows[-1]["truth"]["source_truth"])
        self.assertEqual(
            "contextual_or_dual_use",
            windows[-1]["truth"]["deterministic_truth"],
        )
        self.assertEqual("detect_only", windows[-1]["truth"]["expected_disposition"])

    def test_long_violated_run_has_bounded_unscored_windows(self) -> None:
        self.write_run("user_task_1", source_record(security=False, executed=10))
        cases, _ = self.build()
        windows = [row for row in cases if row["surface"] == "stateful"]
        self.assertEqual(9, len(windows))
        self.assertTrue(all(2 <= len(row["payload"]["events"]) <= MODULE.MAX_EVENTS for row in windows))
        self.assertTrue(all(row["truth"]["source_truth"] == "unknown" for row in windows))

    def test_no_injection_runs_are_benign_but_not_attack_hard_negatives(
        self,
    ) -> None:
        self.write_run("user_task_1", source_record(attacked=False))
        cases, _ = self.build()
        self.assertTrue(all(row["truth"]["source_truth"] == "benign" for row in cases))
        self.assertTrue(all(not row["strata"]["hard_negative"] for row in cases))

    def test_rejects_id_mismatch_unknown_suite_and_unpinned_revision(
        self,
    ) -> None:
        mismatch = source_record()
        tool_message = next(message for message in mismatch["messages"] if message["role"] == "tool")
        tool_message["tool_call_id"] = "different"
        self.write_run("mismatch", mismatch)
        unknown_suite = source_record()
        unknown_suite["suite_name"] = "translated-suite"
        self.write_run("unknown-suite", unknown_suite)
        cases, manifest = self.build()
        self.assertEqual([], cases)
        statistics = manifest["adapter_statistics"][MODULE.DATASET_ID]
        self.assertEqual(1, statistics["skipped_mismatched_tool_call_id"])
        self.assertEqual(1, statistics["skipped_non_english_or_unknown_suite"])
        with self.assertRaisesRegex(ValueError, "must be pinned"):
            MODULE.build_corpus(self.root, "0" * 40, "development")

    def test_case_v1_validation_and_deterministic_output(self) -> None:
        self.write_run("safe", source_record(security=True))
        self.write_run("violated", source_record(security=False))
        first, first_manifest = self.build()
        second, second_manifest = self.build()
        self.assertEqual(first, second)
        self.assertEqual(first_manifest, second_manifest)
        MODULE.validate_cases(first, MODULE.DEFAULT_SCHEMA)
        self.assertEqual(
            {
                "schema_version",
                "datasets",
                "cases",
                "counts",
                "exact_payload_duplicates_removed",
                "label_conflicts_excluded",
                "adapter_statistics",
                "source",
            },
            set(first_manifest),
        )
        source = first_manifest["source"]
        self.assertEqual(
            {
                "dataset",
                "revision",
                "license",
                "redistribution",
                "path",
                "bytes",
                "files",
                "rows",
                "sha256",
                "language",
                "trajectory_verification",
                "source_url",
            },
            set(source),
        )
        self.assertEqual(MODULE.SOURCE_URL, source["source_url"])
        self.assertEqual(MODULE.PINNED_REVISION, source["revision"])
        self.assertEqual("MIT", source["license"])
        self.assertEqual("download-only", source["redistribution"])
        self.assertEqual(MODULE.DATASET_ID, source["dataset"])
        self.assertEqual({MODULE.DATASET_ID: len(first)}, first_manifest["counts"])
        self.assertEqual(len(first), first_manifest["cases"])
        self.assertIsInstance(first_manifest["adapter_statistics"][MODULE.DATASET_ID], dict)
        self.assertTrue(all(row["split"] == MODULE.PRE_PARTITION_SPLIT for row in first))

    def test_rejects_adapter_owned_final_split_assignment(self) -> None:
        self.write_run("safe", source_record(security=True))
        with self.assertRaisesRegex(ValueError, "must remain pre-partitioned"):
            MODULE.build_corpus(self.root, MODULE.PINNED_REVISION, "development")

    def test_output_is_accepted_by_canonical_group_partitioner(self) -> None:
        for index in range(9):
            self.write_run(f"run-{index}", source_record(security=index % 2 == 0))
        cases, manifest = self.build()
        corpus = self.root / "agentdojo-staging.jsonl"
        normalization = self.root / "agentdojo-staging.manifest.json"
        MODULE.write_jsonl(corpus, cases)
        manifest["output_sha256"] = MODULE.file_sha256(corpus)
        MODULE.write_json(normalization, manifest)

        output = self.root / "partitions"
        result = PARTITION.partition(corpus, normalization, output, 741983, 60, 20)
        self.assertEqual(len(cases), result["cases"])
        self.assertEqual(9, result["groups"])
        self.assertTrue(all(result["partitions"][split]["cases"] for split in PARTITION.SPLITS))
        PARTITION.verify_partition(corpus, normalization, output, 741983, 60, 20)
        for split in PARTITION.SPLITS:
            split_manifest = json.loads((output / f"{split}.manifest.json").read_text())
            self.assertEqual(
                {
                    "schema_version",
                    "datasets",
                    "cases",
                    "counts",
                    "exact_payload_duplicates_removed",
                    "label_conflicts_excluded",
                    "adapter_statistics",
                    "output_sha256",
                    "partition",
                },
                set(split_manifest),
            )
            self.assertEqual(
                {MODULE.DATASET_ID},
                set(split_manifest["adapter_statistics"]),
            )
            self.assertTrue(
                all(
                    type(value) is int
                    for value in split_manifest["adapter_statistics"][MODULE.DATASET_ID].values()
                )
            )


if __name__ == "__main__":
    unittest.main()
