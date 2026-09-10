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

adapter = importlib.import_module("benchmark_normalize_terminalbench")

REVISION = "a" * 40


def step(index: int, *, observation: str = "excluded observation") -> dict[str, object]:
    if index % 2 == 0:
        tool = {"fn": "execute_bash", "cmd": f"printf task-{index}"}
    else:
        tool = {"fn": "read_file", "cmd": f"src/file-{index}.py"}
    return {
        "src": "agent",
        "msg": f"excluded reasoning {index}",
        "tools": [tool],
        "obs": observation,
    }


def source_row(
    task_number: int,
    rollout_number: int,
    *,
    reward: int = 1,
    call_count: int = 2,
    empty_trial_id: bool = False,
) -> dict[str, object]:
    return {
        "task_name": f"task-{task_number:02d}",
        "agent": f"agent-{rollout_number % 2}",
        "model": f"model-{rollout_number}",
        "reward": reward,
        "trial_name": f"task-{task_number:02d}-trial-{rollout_number:02d}",
        "trial_id": "" if empty_trial_id else f"00000000-0000-{task_number:04d}-{rollout_number:012d}",
        "steps": json.dumps([step(index) for index in range(call_count)]),
    }


class TerminalBenchNormalizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.rows: list[dict[str, object]] = []
        for task_number in range(10):
            for rollout_number in range(3):
                self.rows.append(
                    source_row(
                        task_number,
                        rollout_number,
                        empty_trial_id=rollout_number == 2,
                    )
                )
            self.rows.append(source_row(task_number, 99, reward=0))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def build(self, rows=None, **overrides):
        options = {
            "revision": REVISION,
            "max_trajectories": 20,
            "max_trajectories_per_task": 2,
            "max_tool_calls_per_trajectory": 16,
            "max_events_per_case": 8,
            "max_argument_bytes": 1024,
        }
        options.update(overrides)
        return adapter.build_corpus(self.rows if rows is None else rows, **options)

    def test_selects_only_successful_trajectories_as_benign_hard_negatives(self) -> None:
        rows, manifest, _ = self.build()
        stats = manifest["adapter_statistics"]["terminalbench"]
        self.assertEqual(stats["selected_trajectories"], 20)
        self.assertEqual(stats["selected_tool_calls"], 40)
        self.assertEqual(stats["non_successful_rows"], 10)
        self.assertEqual(len(rows), 20)
        for row in rows:
            self.assertEqual(row["surface"], "stateful")
            self.assertEqual(row["truth"]["source_truth"], "benign")
            self.assertEqual(row["truth"]["deterministic_truth"], "benign")
            self.assertEqual(row["truth"]["expected_disposition"], "allow")
            self.assertTrue(row["strata"]["hard_negative"])
            self.assertEqual(row["source"]["license"], "Apache-2.0")
            self.assertRegex(row["strata"]["trajectory_id"], r"^[0-9a-f]{64}$")
            self.assertIsInstance(row["strata"]["sequence_index"], int)
            self.assertGreaterEqual(row["strata"]["sequence_index"], 0)
            self.assertIsInstance(row["strata"]["call_index"], int)
            self.assertGreaterEqual(row["strata"]["call_index"], 0)
            self.assertEqual(
                {event["outcome"] for event in row["payload"]["events"]},
                {"succeeded"},
            )

    def test_projects_real_invocation_arguments_but_excludes_messages_and_observations(self) -> None:
        rows, manifest, freeze = self.build()
        event = rows[0]["payload"]["events"][0]
        self.assertEqual(set(event) & {"msg", "obs", "observation", "result", "output"}, set())
        self.assertEqual(set(event["args"]), {"cmd"})
        shell_events = [
            item
            for row in rows
            for item in row["payload"]["events"]
            if item["tool_name"] == "execute_bash"
        ]
        self.assertTrue(shell_events)
        self.assertTrue(all(item["command"] == item["args"]["cmd"] for item in shell_events))
        self.assertTrue(all(item["dialect"] == "posix" for item in shell_events))
        serialized = json.dumps([manifest, freeze], sort_keys=True)
        self.assertNotIn("excluded reasoning", serialized)
        self.assertNotIn("excluded observation", serialized)

    def test_task_groups_are_deterministic_without_claiming_partitions(self) -> None:
        first_rows, first_manifest, first_groups = self.build()
        second_rows, second_manifest, second_groups = self.build(list(reversed(self.rows)))
        self.assertEqual(first_rows, second_rows)
        self.assertEqual(first_manifest, second_manifest)
        self.assertEqual(first_groups, second_groups)
        self.assertEqual({row["split"] for row in first_rows}, {adapter.PRE_PARTITION_SPLIT})
        self.assertEqual(first_groups["partition_authority"], "benchmarks/scripts/benchmark_partition.py")
        forbidden = {
            "assignment_sha256", "case_counts", "group_counts", "ratios", "split",
            "tool_call_counts", "trajectory_counts",
        }
        self.assertTrue(forbidden.isdisjoint(first_groups))
        self.assertTrue(all(forbidden.isdisjoint(group) for group in first_groups["groups"]))

    def test_hash_sampling_is_bounded_and_retains_task_coverage(self) -> None:
        rows, manifest, group_manifest = self.build(
            max_trajectories=7, max_trajectories_per_task=3
        )
        self.assertEqual(manifest["adapter_statistics"]["terminalbench"]["selected_trajectories"], 7)
        self.assertEqual(manifest["adapter_statistics"]["terminalbench"]["selected_task_groups"], 7)
        self.assertEqual(group_manifest["trajectory_count"], 7)
        self.assertEqual(len({row["strata"]["split_group"] for row in rows}), 7)
        with self.assertRaisesRegex(ValueError, "at least three task groups"):
            self.build(max_trajectories=2, max_trajectories_per_task=3)

    def test_chunks_long_trajectories_without_reordering_calls(self) -> None:
        source = [source_row(task, 0, call_count=5) for task in range(3)]
        rows, manifest, _ = self.build(
            source,
            max_trajectories=3,
            max_trajectories_per_task=1,
            max_events_per_case=2,
        )
        self.assertEqual(manifest["adapter_statistics"]["terminalbench"]["selected_tool_calls"], 15)
        trajectory_prefix = rows[0]["id"].rsplit("/", 1)[0]
        trajectory_rows = [row for row in rows if row["id"].startswith(trajectory_prefix + "/")]
        self.assertEqual([row["id"].rsplit("/", 1)[1] for row in trajectory_rows], [
            "calls-0000-0001",
            "calls-0002-0003",
            "calls-0004-0004",
        ])
        arguments: list[str] = []
        for row in trajectory_rows:
            if row["surface"] == "stateful":
                arguments.extend(event["args"]["cmd"] for event in row["payload"]["events"])
            else:
                arguments.append(row["payload"]["args"]["cmd"])
        self.assertEqual(arguments, [
            "printf task-0",
            "src/file-1.py",
            "printf task-2",
            "src/file-3.py",
            "printf task-4",
        ])
        self.assertTrue(trajectory_rows[-1]["source"]["original_id"].endswith("calls-0004-0004"))
        self.assertEqual(
            [row["strata"]["sequence_index"] for row in trajectory_rows],
            [0, 2, 4],
        )
        self.assertEqual([row["strata"]["call_index"] for row in trajectory_rows], [0, 0, 0])

    def test_call_index_tracks_position_within_a_source_step(self) -> None:
        source = [source_row(task, 0, call_count=2) for task in range(3)]
        for row in source:
            row["steps"] = json.dumps([
                {
                    "src": "agent",
                    "msg": "excluded reasoning",
                    "tools": [
                        {"fn": "execute_bash", "cmd": "pwd"},
                        {"fn": "read_file", "cmd": "README.md"},
                    ],
                    "obs": "excluded observation",
                }
            ])
        rows, _, _ = self.build(
            source,
            max_trajectories=3,
            max_trajectories_per_task=1,
            max_events_per_case=2,
        )
        for row in rows:
            self.assertEqual(row["strata"]["sequence_index"], 0)
            self.assertEqual(row["strata"]["call_index"], 0)
            self.assertEqual(
                [event["offset_seconds"] for event in row["payload"]["events"]],
                [0, 1],
            )

    def test_call_bound_is_recorded_and_schema_validation_passes(self) -> None:
        source = [source_row(task, 0, call_count=5) for task in range(3)]
        rows, manifest, _ = self.build(
            source,
            max_trajectories=3,
            max_trajectories_per_task=1,
            max_tool_calls_per_trajectory=3,
        )
        stats = manifest["adapter_statistics"]["terminalbench"]
        self.assertEqual(stats["selected_tool_calls"], 9)
        self.assertEqual(stats["truncated_trajectories"], 3)
        self.assertEqual(stats["truncated_tool_calls"], 6)
        adapter.validate_cases(rows, adapter.DEFAULT_SCHEMA, max_argument_bytes=1024)

    def test_manifests_are_value_free_and_bind_atomic_outputs(self) -> None:
        rows, manifest, group_manifest = self.build()
        output = self.root / "terminalbench.jsonl"
        manifest_path = self.root / "terminalbench.manifest.json"
        group_manifest_path = self.root / "terminalbench.groups.json"
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

        forbidden = {
            "cmd",
            "command",
            "args",
            "events",
            "steps",
            "msg",
            "obs",
            "observation",
            "result",
            "output",
            "task_name",
            "trial_id",
            "trial_name",
        }

        def assert_value_free(value: object) -> None:
            if isinstance(value, dict):
                self.assertTrue(forbidden.isdisjoint(value))
                for child in value.values():
                    assert_value_free(child)
            elif isinstance(value, list):
                for child in value:
                    assert_value_free(child)

        assert_value_free(json.loads(manifest_path.read_text(encoding="utf-8")))
        assert_value_free(json.loads(group_manifest_path.read_text(encoding="utf-8")))

    def test_group_manifest_rejects_split_assignment_metadata(self) -> None:
        _, manifest, group_manifest = self.build()
        group_manifest["ratios"] = {"development": 60, "validation": 20, "test": 20}
        with self.assertRaisesRegex(ValueError, "must not claim partition assignments"):
            adapter.validate_group_manifest(manifest, group_manifest)

    def test_rejects_oversized_or_result_shaped_tool_data(self) -> None:
        oversized = source_row(0, 0)
        oversized["steps"] = json.dumps([
            {"src": "agent", "msg": "x", "tools": [{"fn": "Bash", "cmd": "x" * 128}], "obs": "y"}
        ])
        with self.assertRaisesRegex(ValueError, "byte bound"):
            adapter.trajectory_from_row(oversized, max_tool_calls=16, max_argument_bytes=64)

        result_shaped = source_row(0, 0)
        result_shaped["steps"] = json.dumps([
            {
                "src": "agent",
                "msg": "x",
                "tools": [{"fn": "Bash", "cmd": "pwd", "result": "must not enter input"}],
                "obs": "y",
            }
        ])
        with self.assertRaisesRegex(ValueError, "exactly fn and cmd"):
            adapter.trajectory_from_row(result_shaped, max_tool_calls=16, max_argument_bytes=1024)


if __name__ == "__main__":
    unittest.main()
