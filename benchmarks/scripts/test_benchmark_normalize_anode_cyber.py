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

adapter = importlib.import_module("benchmark_normalize_anode_cyber")

LOCK = json.loads(adapter.DEFAULT_DATASET_LOCK.read_text(encoding="utf-8"))
LOCK_ENTRY = next(entry for entry in LOCK["datasets"] if entry["id"] == adapter.DATASET)
REVISION = LOCK_ENTRY["revision"]
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


def source_row(number: int, *, trajectory_success: bool | None = None) -> dict[str, object]:
    successful = number % 2 == 0 if trajectory_success is None else trajectory_success
    return {
        "id": f"trajectory-{number}",
        "task_category": "Network Audit",
        "is_successful": successful,
        "system_prompt": f"excluded system prompt {number}",
        "thought_trace": f"excluded thought trace {number}",
        "observation": f"excluded top-level observation {number}",
        "critique_trace": f"excluded critique {number}",
        "tool_call": {"tool_name": "excluded_top_level", "parameters": {"excluded": number}},
        "trajectory": [
            {
                "step": 10,
                "thought": f"excluded step thought {number}",
                "observation": f"excluded step observation {number}",
                "success": True,
                "tool_call": {
                    "tool_name": "inspect_host",
                    "parameters": {"host_id": number, "options": {"dry_run": True}},
                    "timestamp": "2026-01-01T00:00:00Z",
                },
            },
            {
                "step": 20,
                "thought": f"excluded second thought {number}",
                "observation": f"excluded second observation {number}",
                "success": False,
                "tool_call": {
                    "tool_name": "check_service",
                    "parameters": {"host_id": number, "port": 443},
                    "timestamp": "2026-01-01T00:00:01Z",
                },
            },
        ],
    }


class AnodeCyberAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "agent_trajectories.jsonl"
        self.write_rows([source_row(number) for number in range(5)])

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_rows(self, rows: list[dict[str, object]]) -> None:
        self.source.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    def build(self, *, max_argument_bytes: int = adapter.DEFAULT_MAX_ARGUMENT_BYTES):
        return adapter.build_corpus(
            self.source,
            revision=REVISION,
            max_argument_bytes=max_argument_bytes,
        )

    def test_projects_only_trajectory_tool_names_and_parameters(self) -> None:
        rows, _ = self.build()
        self.assertEqual(len(rows), 10)
        for row in rows:
            self.assertEqual(set(row["payload"]), {"direction", "tool_name", "args", "dialect"})
            self.assertEqual(row["payload"]["direction"], "tool_call")
            self.assertIn(row["payload"]["tool_name"], {"inspect_host", "check_service"})
            self.assertRegex(row["strata"]["trajectory_id"], r"^[0-9a-f]{24}$")
            self.assertEqual(row["strata"]["trajectory_id"], row["strata"]["split_group"])
            self.assertEqual(row["strata"]["call_index"], 0)
            serialized = json.dumps(row["payload"])
            for excluded in ("excluded system", "excluded thought", "excluded observation", "excluded critique"):
                self.assertNotIn(excluded, serialized)
            self.assertNotIn("excluded_top_level", serialized)

    def test_preserves_trajectory_step_identity_order_and_success_metadata(self) -> None:
        rows, manifest = self.build()
        trajectory_zero = sorted(
            (row for row in rows if "trajectory:trajectory-0/" in row["source"]["original_id"]),
            key=lambda row: row["id"],
        )
        self.assertEqual(
            [row["source"]["original_id"] for row in trajectory_zero],
            [
                "trajectory:trajectory-0/step:10/position:000000",
                "trajectory:trajectory-0/step:20/position:000001",
            ],
        )
        self.assertEqual([row["strata"]["sequence_index"] for row in trajectory_zero], [0, 1])
        self.assertIn("source_trajectory_success:true", trajectory_zero[0]["truth"]["categories"])
        self.assertIn("source_step_success:true", trajectory_zero[0]["truth"]["categories"])
        self.assertIn("source_step_success:false", trajectory_zero[1]["truth"]["categories"])
        stats = manifest["adapter_statistics"]["anode_cyber"]
        self.assertEqual(stats["source_trajectory_success_false"], 2)
        self.assertEqual(stats["source_trajectory_success_true"], 3)
        self.assertEqual(stats["source_step_success_false"], 5)
        self.assertEqual(stats["source_step_success_true"], 5)

    def test_success_never_becomes_deterministic_malicious_truth(self) -> None:
        rows, _ = self.build()
        for row in rows:
            truth = row["truth"]
            self.assertEqual(truth["source_truth"], "unknown")
            self.assertEqual(truth["deterministic_truth"], "contextual_or_dual_use")
            self.assertEqual(truth["label_confidence"], "low")
            self.assertEqual(truth["applicability"], "out_of_scope")
            self.assertEqual(truth["expected_disposition"], "allow")
            self.assertIn("GPT-OSS", truth["exclusion_reason"])

    def test_defers_all_split_assignment_to_canonical_partitioner(self) -> None:
        rows, manifest = self.build()
        self.assertTrue(all(row["split"] == adapter.STAGING_SPLIT for row in rows))
        self.assertEqual(set(manifest), NORMALIZATION_MANIFEST_KEYS)
        self.assertNotIn("partition", manifest)
        self.assertNotIn("split_counts", manifest)

    def test_output_is_independent_of_source_row_order(self) -> None:
        first = self.build()
        self.write_rows(list(reversed([source_row(number) for number in range(5)])))
        second = self.build()
        self.assertEqual(first, second)

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
        metadata = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(set(metadata), NORMALIZATION_MANIFEST_KEYS)
        self.assertTrue(
            all(
                isinstance(value, int) and not isinstance(value, bool)
                for statistics in metadata["adapter_statistics"].values()
                for value in statistics.values()
            )
        )
        forbidden_keys = {
            "args",
            "parameters",
            "payload",
            "observation",
            "result",
            "thought",
            "tool_call",
            "tool_name",
            "trajectory",
        }

        def assert_value_free(value: object) -> None:
            if isinstance(value, dict):
                self.assertTrue(forbidden_keys.isdisjoint(value))
                for child in value.values():
                    assert_value_free(child)
            elif isinstance(value, list):
                for child in value:
                    assert_value_free(child)

        assert_value_free(metadata)

    def test_provenance_exactly_matches_canonical_dataset_lock(self) -> None:
        rows, _ = self.build()
        for row in rows:
            self.assertEqual(row["source"]["dataset"], LOCK_ENTRY["id"])
            self.assertEqual(row["source"]["revision"], LOCK_ENTRY["revision"])
            self.assertEqual(row["source"]["license"], LOCK_ENTRY["license"])
            self.assertEqual(row["source"]["redistribution"], LOCK_ENTRY["redistribution"])
        self.assertEqual(LOCK_ENTRY["license"], "Apache-2.0")

    def test_rejects_provenance_that_differs_from_dataset_lock(self) -> None:
        with self.assertRaisesRegex(ValueError, "differs from dataset lock"):
            adapter.build_corpus(self.source, revision="a" * 40)

    def test_schema_validation_and_argument_bound(self) -> None:
        rows, _ = self.build()
        adapter.validate_cases(rows, adapter.DEFAULT_SCHEMA, max_argument_bytes=adapter.DEFAULT_MAX_ARGUMENT_BYTES)
        oversized = source_row(0)
        oversized["trajectory"][0]["tool_call"]["parameters"] = {"value": "x" * 256}
        with self.assertRaisesRegex(ValueError, "byte bound"):
            adapter.project_trajectory(oversized, max_argument_bytes=64)

    def test_rejects_duplicate_trajectory_and_step_identities(self) -> None:
        duplicate_trajectory = [source_row(0), source_row(0), source_row(1), source_row(2)]
        self.write_rows(duplicate_trajectory)
        with self.assertRaisesRegex(ValueError, "duplicate trajectory"):
            self.build()
        duplicate_step = source_row(0)
        duplicate_step["trajectory"][1]["step"] = 10
        self.write_rows([duplicate_step, source_row(1), source_row(2)])
        with self.assertRaisesRegex(ValueError, "duplicate step"):
            self.build()


if __name__ == "__main__":
    unittest.main()
