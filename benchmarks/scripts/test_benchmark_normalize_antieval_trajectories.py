#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

adapter = importlib.import_module("benchmark_normalize_antieval_trajectories")

REVISIONS = {family: family[0] * 40 for family in adapter.DATASET_SPECS}
NORMALIZATION_MANIFEST_KEYS = {
    "schema_version",
    "datasets",
    "cases",
    "counts",
    "exact_payload_duplicates_removed",
    "label_conflicts_excluded",
    "adapter_statistics",
    "output_sha256",
}


def direct_call(name: str, task_number: int) -> dict[str, object]:
    return {
        "id": f"call-{task_number}",
        "type": "function",
        "function": name,
        "arguments": {"task_number": task_number, "options": {"dry_run": True}},
    }


def nested_call(name: str, task_number: int) -> dict[str, object]:
    return {
        "id": f"nested-{task_number}",
        "type": "function",
        "function": {
            "name": name,
            "arguments": json.dumps({"task_number": task_number, "mode": "check"}),
        },
    }


def source_row(family: str, task_number: int, model: str, *, nested: bool = False) -> dict[str, object]:
    if family == "agentharm":
        identity = {"id_original": f"task-{task_number}"}
    elif family == "cybench":
        identity = {
            "eval_file_path": f"evals/task-{task_number}.yaml",
            "eval_name": f"task-{task_number}",
            "variant_name": "default",
        }
    else:
        identity = {"repo": "example/project", "base_commit": f"commit-{task_number}"}
    call = nested_call("inspect_resource", task_number) if nested else direct_call("inspect_resource", task_number)
    return {
        "schema_version": "1",
        "id": f"row-{task_number}",
        "metadata": {**identity, "model": model},
        "input": [
            {"role": "system", "content": "excluded system text"},
            {"role": "user", "content": "excluded user text"},
            {"role": "assistant", "content": "excluded reasoning", "tool_calls": [call]},
            {
                "role": "tool",
                "tool_call_id": f"call-{task_number}",
                "content": "excluded observation",
                "function": "inspect_resource",
            },
        ],
    }


class AntiEvalTrajectoryAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.sources: dict[str, Path] = {}
        for family, spec in adapter.DATASET_SPECS.items():
            directory = self.root / spec.directory_name
            directory.mkdir()
            self.sources[family] = directory
            rows = []
            for task_number in range(5):
                rows.append(source_row(family, task_number, "model-a", nested=task_number == 0))
                rows.append(source_row(family, task_number, "model-b"))
            self.write_rows(directory / f"{family}_rollouts.jsonl", rows)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def write_rows(path: Path, rows: list[dict[str, object]]) -> None:
        path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    def build(self, *, max_argument_bytes: int = adapter.DEFAULT_MAX_ARGUMENT_BYTES):
        return adapter.build_corpus(
            self.sources,
            revisions=REVISIONS,
            max_argument_bytes=max_argument_bytes,
        )

    def test_projects_only_structured_tool_calls_with_stable_ordinals(self) -> None:
        rows, _ = self.build()
        self.assertEqual(len(rows), 30)
        self.assertTrue(all("/s000000-c000" in row["id"] for row in rows))
        self.assertTrue(all("sequence-000000/call-000" in row["source"]["original_id"] for row in rows))
        for row in rows:
            self.assertEqual(set(row["payload"]), {"direction", "tool_name", "args", "dialect"})
            self.assertEqual(row["payload"]["direction"], "tool_call")
            self.assertNotIn("content", row["payload"])
            self.assertNotIn("events", row["payload"])
            self.assertRegex(row["strata"]["trajectory_id"], r"^[0-9a-f]{24}$")
            self.assertEqual(row["strata"]["sequence_index"], 0)
            self.assertEqual(row["strata"]["call_index"], 0)

    def test_sequence_index_spans_messages_and_call_index_resets(self) -> None:
        messages = [
            {
                "role": "assistant",
                "content": "excluded",
                "tool_calls": [direct_call("first", 1), direct_call("second", 2)],
            },
            {"role": "tool", "content": "excluded observation", "tool_call_id": "call-1"},
            {
                "role": "assistant",
                "content": "excluded",
                "tool_calls": [direct_call("third", 3)],
            },
        ]
        calls = adapter.project_calls(messages, max_argument_bytes=adapter.DEFAULT_MAX_ARGUMENT_BYTES)
        self.assertEqual([call.sequence_index for call in calls], [0, 1, 2])
        self.assertEqual([call.call_index for call in calls], [0, 1, 0])

    def test_applies_conservative_source_truth(self) -> None:
        rows, _ = self.build()
        by_family = {row["strata"]["domain"]: row for row in rows}
        agentharm = by_family["agentharm"]["truth"]
        self.assertEqual(agentharm["source_truth"], "malicious")
        self.assertEqual(agentharm["deterministic_truth"], "contextual_or_dual_use")
        self.assertEqual(agentharm["applicability"], "out_of_scope")
        cybench = by_family["cybench"]["truth"]
        self.assertEqual(cybench["source_truth"], "unknown")
        self.assertEqual(cybench["applicability"], "out_of_scope")
        swebench = by_family["swebench"]["truth"]
        self.assertEqual(swebench["source_truth"], "benign")
        self.assertEqual(swebench["deterministic_truth"], "benign")
        self.assertEqual(swebench["applicability"], "in_scope")

    def test_repeated_model_rollouts_share_groups_but_split_assignment_is_deferred(self) -> None:
        rows, manifest = self.build()
        self.assertTrue(all(row["split"] == adapter.STAGING_SPLIT for row in rows))
        self.assertEqual(set(manifest), NORMALIZATION_MANIFEST_KEYS)
        self.assertNotIn("partition", manifest)
        self.assertNotIn("split_counts", manifest)
        grouped_rollouts: dict[tuple[str, int], set[str]] = {}
        for row in rows:
            family = row["strata"]["domain"]
            task_number = row["payload"]["args"]["task_number"]
            grouped_rollouts.setdefault((family, task_number), set()).add(row["strata"]["split_group"])
        self.assertTrue(all(len(groups) == 1 for groups in grouped_rollouts.values()))

    def test_output_is_independent_of_source_row_order(self) -> None:
        first = self.build()
        for family, directory in self.sources.items():
            original = directory / f"{family}_rollouts.jsonl"
            rows = adapter.load_jsonl(original)
            self.write_rows(original, list(reversed(rows)))
        second = self.build()
        self.assertEqual(first, second)

    def test_schema_group_isolation_and_argument_bound_validation(self) -> None:
        rows, _ = self.build()
        adapter.validate_cases(rows, adapter.DEFAULT_SCHEMA, max_argument_bytes=adapter.DEFAULT_MAX_ARGUMENT_BYTES)
        oversized = source_row("agentharm", 0, "model-a")
        assistant = oversized["input"][2]
        assistant["tool_calls"][0]["arguments"] = {"value": "x" * 128}
        with self.assertRaisesRegex(ValueError, "byte bound"):
            adapter.project_calls(oversized["input"], max_argument_bytes=64)

    def test_manifests_are_value_free_and_bind_written_outputs(self) -> None:
        rows, manifest = self.build()
        output = self.root / "cases.jsonl"
        manifest_path = self.root / "cases.manifest.json"
        adapter.write_outputs(
            rows,
            manifest,
            output=output,
            manifest_path=manifest_path,
        )
        self.assertEqual(adapter.sha256_bytes(output.read_bytes()), manifest["output_sha256"])
        manifest_text = manifest_path.read_text(encoding="utf-8")
        excluded_texts = ("excluded system text", "excluded user text", "excluded reasoning", "excluded observation")
        for excluded_text in excluded_texts:
            self.assertNotIn(excluded_text, manifest_text)
        forbidden_keys = {"input", "content", "tool_calls", "arguments", "args", "observation", "output", "result"}

        def assert_value_free(value: object) -> None:
            if isinstance(value, dict):
                self.assertTrue(forbidden_keys.isdisjoint(value))
                for child in value.values():
                    assert_value_free(child)
            elif isinstance(value, list):
                for child in value:
                    assert_value_free(child)

        metadata = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(set(metadata), NORMALIZATION_MANIFEST_KEYS)
        self.assertTrue(
            all(
                isinstance(value, int) and not isinstance(value, bool)
                for statistics in metadata["adapter_statistics"].values()
                for value in statistics.values()
            )
        )
        assert_value_free(metadata)


if __name__ == "__main__":
    unittest.main()
