#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy
import importlib
import json
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

adapter = importlib.import_module("benchmark_normalize_atbench")
REVISIONS = {family: family[0] * 40 for family in adapter.DATASET_SPECS}


def codex_row(identity: int, safe: bool) -> dict[str, object]:
    return {
        "id": identity,
        "is_safe": safe,
        "risk_source": "environmental",
        "failure_mode": "unsafe execution",
        "harm_type": "data loss",
        "codex_rollout": [
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call",
                    "name": "shell",
                    "call_id": f"call-{identity}",
                    "arguments": json.dumps({"command": f"inspect-{identity}", "dry_run": True}),
                },
            },
            {
                "type": "response_item",
                        "payload": {
                            "type": "function_call_output",
                            "call_id": f"call-{identity}",
                            "status": "completed",
                            "output": "PRIVATE_OBSERVATION_MARKER",
                        },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call",
                    "name": "write_file",
                    "call_id": f"write-{identity}",
                    "status": "completed",
                    "arguments": json.dumps({"path": f"fixture-{identity}", "content": "synthetic"}),
                },
            },
        ],
    }


def claw_row(identity: int, safe: bool) -> dict[str, object]:
    return {
        "trajectory": {
            "id": f"claw-{identity}",
            "events": [
                {
                    "type": "message",
                    "message": {
                        "role": "assistant",
                        "content": [
                            {
                                "type": "toolCall",
                                "id": f"read-{identity}",
                                "name": "read_file",
                                "arguments": {"path": f"fixture-{identity}"},
                            }
                        ],
                    },
                },
                {
                    "type": "message",
                    "message": {
                        "role": "toolResult",
                        "toolCallId": f"read-{identity}",
                        "status": "succeeded",
                        "content": [{"type": "text", "text": "PRIVATE_OBSERVATION_MARKER"}],
                    },
                },
                {
                    "type": "message",
                    "message": {
                        "role": "assistant",
                        "content": [
                            {
                                "type": "toolCall",
                                "toolCall": {
                                    "id": f"send-{identity}",
                                    "name": "send_message",
                                    "arguments": {"destination": f"fixture-{identity}"},
                                },
                            }
                        ],
                    },
                },
                {
                    "type": "message",
                    "message": {
                        "role": "toolResult",
                        "toolCallId": f"send-{identity}",
                        "isError": False,
                        "content": [{"type": "text", "text": "PRIVATE_OBSERVATION_MARKER"}],
                    },
                },
            ],
        },
        "labels": {
            "is_safe": safe,
            "risk_source": "user",
            "failure_mode": "policy violation",
            "harm_type": "privacy",
        },
        "reason": "PRIVATE_REASON_MARKER",
    }


def atbench_row(identity: int, safe: bool) -> dict[str, object]:
    return {
        "id": identity,
        "label": 0 if safe else 1,
        "risk_source": "tool",
        "failure_mode": "overreach",
        "real_world_harm": "integrity",
        "contents": [
            [
                {"role": "user", "content": "PRIVATE_MESSAGE_MARKER"},
                {
                    "role": "assistant",
                    "action": json.dumps(
                        {
                            "name": "database_query",
                            "arguments": {"query_id": identity, "read_only": True},
                            "status": "succeeded",
                        }
                    ),
                    "thought": "PRIVATE_REASONING_MARKER",
                },
                {"role": "toolResult", "content": "PRIVATE_OBSERVATION_MARKER"},
                {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "status": "completed",
                            "function": {
                                "name": "audit_event",
                                "arguments": json.dumps({"event_id": identity}),
                            }
                        }
                    ],
                },
            ]
        ],
    }


class ATBenchNormalizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.sources: dict[str, Path] = {}
        for family, spec in adapter.DATASET_SPECS.items():
            directory = self.root / spec.directory_name
            directory.mkdir()
            self.sources[family] = directory

        codex_rows = [codex_row(2759, False), codex_row(2951, False)]
        codex_rows.extend(codex_row(3000 + index, index % 2 == 0) for index in range(10))
        self.write_array(self.sources["codex"] / "test.json", codex_rows)

        claw_rows = [claw_row(index, index % 2 == 0) for index in range(12)]
        self.write_array(self.sources["claw"] / "test.json", claw_rows)

        atbench_dir = self.sources["atbench"] / "ATBench"
        atbench_dir.mkdir()
        exposed = [atbench_row(1, False), atbench_row(19, False)]
        retained = [atbench_row(100 + index, index % 2 == 0) for index in range(10)]
        self.write_array(atbench_dir / "test.json", [*exposed, *retained])

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def write_array(path: Path, rows: list[dict[str, object]]) -> None:
        path.write_text(json.dumps(rows), encoding="utf-8")

    def build(self, *, max_argument_bytes: int = adapter.DEFAULT_MAX_ARGUMENT_BYTES):
        return adapter.build_corpus(
            self.sources,
            revisions=REVISIONS,
            max_argument_bytes=max_argument_bytes,
        )

    def test_extracts_calls_and_excludes_results_and_observations(self) -> None:
        rows, manifest, _ = self.build()
        self.assertEqual(Counter(row["surface"] for row in rows), {"action": 60, "stateful": 30})
        self.assertEqual(len(rows), 90)
        for row in rows:
            payload = row["payload"]
            self.assertRegex(row["strata"]["trajectory_id"], r"^[0-9a-f]{24}$")
            self.assertIsInstance(row["strata"]["sequence_index"], int)
            self.assertIsInstance(row["strata"]["call_index"], int)
            self.assertNotIn("observation", payload)
            self.assertNotIn("output", payload)
            self.assertNotIn("result", payload)
            if row["surface"] == "action":
                self.assertIn("args", payload)
                self.assertNotIn("events", payload)
            else:
                self.assertEqual(len(payload["events"]), 2)
                self.assertEqual([event["offset_seconds"] for event in payload["events"]], [0, 1])
                self.assertEqual({event["outcome"] for event in payload["events"]}, {"succeeded"})

    def test_quarantines_all_previously_exposed_records(self) -> None:
        _, manifest, freeze = self.build()
        statistics = manifest["adapter_statistics"]
        self.assertEqual(statistics["codex"]["quarantined_records"], 2)
        self.assertEqual(statistics["claw"]["quarantined_records"], 2)
        self.assertEqual(statistics["atbench"]["quarantined_records"], 2)
        self.assertEqual(freeze["group_count"], 30)

    def test_sequence_and_call_indexes_are_zero_based(self) -> None:
        messages = [
            {
                "role": "assistant",
                "tool_calls": [
                    {"name": "first", "arguments": {}},
                    {"name": "second", "arguments": {}},
                ],
            },
            {"role": "toolResult", "content": "PRIVATE_OBSERVATION_MARKER"},
            {"role": "assistant", "tool_calls": [{"name": "third", "arguments": {}}]},
        ]
        calls = adapter.content_calls(messages, max_argument_bytes=adapter.DEFAULT_MAX_ARGUMENT_BYTES)
        self.assertEqual([call.sequence_index for call in calls], [0, 1, 2])
        self.assertEqual([call.call_index for call in calls], [0, 1, 0])

    def test_unsafe_atomic_calls_are_unknown_and_proof_pending(self) -> None:
        rows, _, _ = self.build()
        unsafe_atomic = [
            row
            for row in rows
            if row["surface"] == "action" and "source_trajectory_unsafe" in row["truth"]["categories"]
        ]
        self.assertTrue(unsafe_atomic)
        for row in unsafe_atomic:
            truth = row["truth"]
            self.assertEqual(truth["source_truth"], "unknown")
            self.assertEqual(truth["deterministic_truth"], "contextual_or_dual_use")
            self.assertEqual(truth["applicability"], "out_of_scope")
            self.assertIn("proof_pending", truth["categories"])
        unsafe_sequences = [
            row
            for row in rows
            if row["surface"] == "stateful" and "source_trajectory_unsafe" in row["truth"]["categories"]
        ]
        self.assertTrue(unsafe_sequences)
        self.assertTrue(all(row["truth"]["source_truth"] == "malicious" for row in unsafe_sequences))

    def test_normalization_is_pre_partitioned_and_has_no_split_claims(self) -> None:
        first = self.build()
        second = self.build()
        self.assertEqual(first, second)
        rows, _, group_manifest = first
        self.assertEqual({row["split"] for row in rows}, {adapter.PRE_PARTITION_SPLIT})
        self.assertEqual(group_manifest["partition_authority"], "benchmarks/scripts/benchmark_partition.py")
        self.assertEqual(group_manifest["group_count"], 30)
        forbidden = {"assignment_sha256", "case_counts", "group_counts", "ratios", "split"}
        self.assertTrue(forbidden.isdisjoint(group_manifest))
        self.assertTrue(all(forbidden.isdisjoint(group) for group in group_manifest["groups"]))

    def test_outcomes_require_explicit_execution_evidence_not_safety_label(self) -> None:
        explicit = adapter.content_calls(
            [
                {
                    "role": "assistant",
                    "tool_calls": [
                        {"id": "known", "name": "first", "arguments": {}},
                        {"id": "unknown", "name": "second", "arguments": {}},
                    ],
                },
                {"role": "toolResult", "toolCallId": "known", "status": "completed"},
            ],
            max_argument_bytes=adapter.DEFAULT_MAX_ARGUMENT_BYTES,
        )
        self.assertEqual([call.outcome for call in explicit], ["succeeded", "unknown"])

        safe = adapter.Trajectory(
            spec=adapter.DATASET_SPECS["atbench"],
            config="synthetic",
            identity_digest="a" * 64,
            group_digest="b" * 64,
            source_safe=True,
            taxonomy=(),
            calls=(adapter.ProjectedCall("tool", {}, 0, 0), adapter.ProjectedCall("tool", {}, 1, 0)),
        )
        unsafe = adapter.Trajectory(**{**safe.__dict__, "source_safe": False})
        for trajectory in (safe, unsafe):
            stateful = [
                row
                for row in adapter.make_cases(trajectory, revision="c" * 40)
                if row["surface"] == "stateful"
            ]
            self.assertEqual(
                [event["outcome"] for event in stateful[0]["payload"]["events"]],
                ["unknown", "unknown"],
            )

    def test_stateful_windows_retain_order_and_eight_event_boundary(self) -> None:
        calls = tuple(
            adapter.ProjectedCall("tool", {"ordinal": index}, index, 0) for index in range(70)
        )
        windows = list(adapter.stateful_windows(calls))
        self.assertEqual([start for start, _ in windows], [0, 57])
        self.assertEqual([len(window) for _, window in windows], [64, 13])
        self.assertEqual(windows[0][1][-7:], windows[1][1][:7])

    def test_schema_and_argument_bounds_are_enforced(self) -> None:
        rows, _, _ = self.build()
        adapter.validate_cases(rows, adapter.DEFAULT_SCHEMA, max_argument_bytes=adapter.DEFAULT_MAX_ARGUMENT_BYTES)
        with self.assertRaisesRegex(ValueError, "byte bound"):
            adapter.parse_call(
                {"name": "tool", "arguments": {"value": "x" * 128}},
                sequence_index=0,
                call_index=0,
                max_argument_bytes=64,
            )

    def test_manifests_are_value_free_and_bind_outputs(self) -> None:
        rows, manifest, group_manifest = self.build()
        output = self.root / "cases.jsonl"
        manifest_path = self.root / "cases.manifest.json"
        group_manifest_path = self.root / "cases.groups.json"
        adapter.write_outputs(
            rows,
            manifest,
            group_manifest,
            output=output,
            manifest_path=manifest_path,
            group_manifest_path=group_manifest_path,
        )
        self.assertEqual(adapter.sha256_bytes(output.read_bytes()), manifest["output_sha256"])
        self.assertEqual(
            json.loads(group_manifest_path.read_text(encoding="utf-8"))["corpus_sha256"],
            manifest["output_sha256"],
        )
        combined = manifest_path.read_text(encoding="utf-8") + group_manifest_path.read_text(encoding="utf-8")
        for marker in (
            "PRIVATE_MESSAGE_MARKER",
            "PRIVATE_REASONING_MARKER",
            "PRIVATE_OBSERVATION_MARKER",
            "PRIVATE_REASON_MARKER",
        ):
            if marker in combined:
                self.fail("value-free manifest contains excluded source material")
        forbidden_keys = {
            "payload",
            "arguments",
            "args",
            "events",
            "content",
            "contents",
            "observation",
            "output",
            "result",
            "reason",
            "trajectory_id",
            "original_id",
        }

        def assert_value_free(value: object) -> None:
            if isinstance(value, dict):
                self.assertTrue(forbidden_keys.isdisjoint(value))
                for child in value.values():
                    assert_value_free(child)
            elif isinstance(value, list):
                for child in value:
                    assert_value_free(child)

        assert_value_free(json.loads(manifest_path.read_text(encoding="utf-8")))
        assert_value_free(json.loads(group_manifest_path.read_text(encoding="utf-8")))

    def test_manifest_schemas_reject_unknown_fields(self) -> None:
        _, manifest, group_manifest = self.build()
        invalid_manifest = copy.deepcopy(manifest)
        invalid_manifest["payload"] = {}
        with self.assertRaisesRegex(ValueError, "normalization manifest"):
            adapter.validate_manifests(invalid_manifest, group_manifest)
        invalid_group_manifest = copy.deepcopy(group_manifest)
        invalid_group_manifest["groups"][0]["trajectory_id"] = "a" * 24
        with self.assertRaisesRegex(ValueError, "trajectory group manifest entry"):
            adapter.validate_manifests(manifest, invalid_group_manifest)


if __name__ == "__main__":
    unittest.main()
