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
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

adapter = importlib.import_module("benchmark_normalize_linuxarena")
REVISION = "a" * 40


def action(
    function: str,
    arguments: dict[str, object],
    *,
    output_error: str | None = None,
) -> dict[str, object]:
    return {
        "function": function,
        "arguments": arguments,
        "output": "PRIVATE_TOOL_OUTPUT_MARKER",
        "output_error": output_error,
        "agent_reasoning": "PRIVATE_REASONING_MARKER",
        "extended_thinking": "PRIVATE_THINKING_MARKER",
        "inter_action_messages": "PRIVATE_MESSAGE_MARKER",
        "monitor_response": {"reasoning": "PRIVATE_MONITOR_MARKER"},
        "substeps": [{"message": "PRIVATE_SUBSTEP_MARKER"}],
    }


def source_row(
    identity: int,
    *,
    environment_id: str = "shared_dotfiles",
    main_task_id: str = "task-family-1",
    side_task: bool = False,
    side_task_success: bool | None = False,
    main_task_success: bool | None = True,
    actions: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "trajectory_id": f"trajectory-{identity}",
        "run_id": f"run-{identity}",
        "run_display_name": "PRIVATE_RUN_NAME",
        "trajectory_url": f"https://example.invalid/{identity}",
        "actions": actions
        if actions is not None
        else [
            action("bash", {"cmd": "printf hello", "timeout": 10}),
            action("text_editor", {"command": "view", "path": "README.md"}),
        ],
        "main_task_success": main_task_success,
        "side_task_success": side_task_success,
        "scorer_explanation": "PRIVATE_SCORER_MARKER",
        "traj_monitor_response": {"reasoning": "PRIVATE_TRAJECTORY_MONITOR_MARKER"},
        "environment": {"id": environment_id},
        "main_task": {"id": main_task_id},
        "side_task": {"id": "side-task-1"} if side_task else None,
        "agent_model": {"name": "PRIVATE_MODEL_MARKER"},
        "system_prompt": "PRIVATE_SYSTEM_MARKER",
        "initial_user_message": "PRIVATE_USER_MARKER",
        "attack_analysis": "PRIVATE_ATTACK_ANALYSIS_MARKER",
    }


class LinuxArenaNormalizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def build(self, rows=None, **overrides):
        values = (
            [
                source_row(1),
                source_row(2, side_task=True, side_task_success=True),
                source_row(3, side_task=True, side_task_success=False),
            ]
            if rows is None
            else rows
        )
        options = {"revision": REVISION, "max_argument_bytes": 1024 * 1024}
        options.update(overrides)
        return adapter.build_corpus(values, **options)

    def test_preserves_function_and_structured_arguments_but_excludes_private_fields(self) -> None:
        rows, manifest, group_manifest = self.build()
        atomic = next(row for row in rows if row["surface"] == "action" and row["payload"]["tool_name"] == "bash")
        self.assertEqual(atomic["payload"]["args"], {"cmd": "printf hello", "timeout": 10})
        self.assertEqual(atomic["payload"]["command"], "printf hello")
        text_editor = next(
            row for row in rows if row["surface"] == "action" and row["payload"]["tool_name"] == "text_editor"
        )
        self.assertNotIn("command", text_editor["payload"])
        serialized = json.dumps([rows, manifest, group_manifest], sort_keys=True)
        for marker in (
            "PRIVATE_TOOL_OUTPUT_MARKER",
            "PRIVATE_REASONING_MARKER",
            "PRIVATE_THINKING_MARKER",
            "PRIVATE_MESSAGE_MARKER",
            "PRIVATE_MONITOR_MARKER",
            "PRIVATE_SUBSTEP_MARKER",
            "PRIVATE_SCORER_MARKER",
            "PRIVATE_SYSTEM_MARKER",
            "PRIVATE_USER_MARKER",
            "PRIVATE_ATTACK_ANALYSIS_MARKER",
            "PRIVATE_RUN_NAME",
            "PRIVATE_MODEL_MARKER",
        ):
            self.assertNotIn(marker, serialized)

    def test_output_error_is_the_only_per_call_outcome_signal(self) -> None:
        rows, _, _ = self.build(
            [
                source_row(
                    1,
                    main_task_success=False,
                    actions=[
                        action("bash", {"cmd": "true"}, output_error=None),
                        action("bash", {"cmd": "false"}, output_error="exit status 1"),
                    ],
                )
            ]
        )
        stateful = next(row for row in rows if row["surface"] == "stateful")
        self.assertEqual([event["outcome"] for event in stateful["payload"]["events"]], ["succeeded", "failed"])
        self.assertIn("main_task_failed", stateful["truth"]["categories"])

    def test_truth_is_conservative_for_side_task_trajectories(self) -> None:
        rows, _, _ = self.build()
        by_trajectory: dict[str, list[dict[str, object]]] = {}
        for row in rows:
            by_trajectory.setdefault(row["strata"]["trajectory_id"], []).append(row)
        groups = list(by_trajectory.values())
        honest = next(values for values in groups if values[0]["strata"]["hard_negative"])
        successful_attack = next(
            values for values in groups if "side_task_succeeded" in values[0]["truth"]["categories"]
        )
        failed_attack = next(values for values in groups if "side_task_failed" in values[0]["truth"]["categories"])
        self.assertTrue(all(row["truth"]["source_truth"] == "benign" for row in honest))
        self.assertTrue(all(row["truth"]["applicability"] == "in_scope" for row in honest))
        successful_atomic = next(row for row in successful_attack if row["surface"] == "action")
        successful_stateful = next(row for row in successful_attack if row["surface"] == "stateful")
        self.assertEqual(successful_atomic["truth"]["source_truth"], "unknown")
        self.assertEqual(successful_stateful["truth"]["source_truth"], "malicious")
        self.assertEqual(successful_stateful["truth"]["deterministic_truth"], "contextual_or_dual_use")
        self.assertEqual(successful_stateful["truth"]["applicability"], "out_of_scope")
        self.assertTrue(all(row["truth"]["source_truth"] == "unknown" for row in failed_attack))

    def test_groups_environment_and_main_task_family_across_honest_and_attack(self) -> None:
        rows, _, groups = self.build()
        self.assertEqual(groups["group_count"], 1)
        self.assertEqual(len({row["strata"]["split_group"] for row in rows}), 1)
        self.assertEqual({row["split"] for row in rows}, {adapter.PRE_PARTITION_SPLIT})
        self.assertEqual(groups["partition_authority"], "benchmarks/scripts/benchmark_partition.py")
        forbidden = {"development", "validation", "test", "assignment_sha256", "ratios"}
        self.assertTrue(forbidden.isdisjoint(groups))

    def test_deduplicates_monitor_only_reruns_by_projected_content(self) -> None:
        first = source_row(1, side_task=True, side_task_success=True)
        rerun = copy.deepcopy(first)
        rerun["trajectory_id"] = "trajectory-monitor-rerun"
        rerun["run_id"] = "monitor-run"
        rerun["run_display_name"] = "DIFFERENT_PRIVATE_MONITOR_RUN"
        rerun["traj_monitor_response"] = {"reasoning": "DIFFERENT_PRIVATE_MONITOR"}
        rows, manifest, groups = self.build([first, rerun])
        self.assertEqual(manifest["adapter_statistics"]["linuxarena"]["selected_trajectories"], 1)
        self.assertEqual(manifest["exact_payload_duplicates_removed"], 1)
        self.assertEqual(groups["trajectory_count"], 1)
        self.assertNotIn("DIFFERENT_PRIVATE", json.dumps([rows, manifest, groups]))
        self.assertEqual((rows, manifest, groups), self.build([rerun, first]))

    def test_nullable_task_outcomes_remain_unknown_not_malicious(self) -> None:
        rows, _, _ = self.build(
            [
                source_row(
                    1,
                    side_task=True,
                    side_task_success=None,
                    main_task_success=None,
                )
            ]
        )
        stateful = next(row for row in rows if row["surface"] == "stateful")
        self.assertEqual(stateful["truth"]["source_truth"], "unknown")
        self.assertEqual(stateful["truth"]["applicability"], "out_of_scope")
        self.assertIn("side_task_outcome_unknown", stateful["truth"]["categories"])
        self.assertIn("main_task_outcome_unknown", stateful["truth"]["categories"])

    def test_long_trajectories_overlap_by_chain_bound(self) -> None:
        actions = [action("bash", {"cmd": f"call-{index}"}) for index in range(70)]
        rows, _, _ = self.build([source_row(1, actions=actions)])
        windows = sorted(
            (row for row in rows if row["surface"] == "stateful"),
            key=lambda row: row["strata"]["sequence_index"],
        )
        self.assertEqual([len(row["payload"]["events"]) for row in windows], [64, 13])
        self.assertEqual([row["strata"]["sequence_index"] for row in windows], [0, 57])

    def test_schema_manifest_license_and_revision_validation(self) -> None:
        rows, manifest, groups = self.build()
        adapter.validate_cases(rows, adapter.DEFAULT_SCHEMA, max_argument_bytes=1024 * 1024)
        self.assertEqual(manifest["source"]["license"], "CC-BY-4.0")
        self.assertEqual(manifest["source"]["revision"], REVISION)
        self.assertRegex(manifest["source"]["sha256"], r"^[0-9a-f]{64}$")
        adapter.validate_manifests(manifest, groups)
        with self.assertRaisesRegex(ValueError, "revision"):
            self.build(revision="main")
        mismatched_source = copy.deepcopy(manifest["source"])
        mismatched_source["revision"] = "b" * 40
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.build(source_manifest=mismatched_source)
        tampered_groups = copy.deepcopy(groups)
        tampered_groups["groups"][0]["tool_calls"] += 1
        with self.assertRaisesRegex(ValueError, "tool-call count"):
            adapter.validate_manifests(manifest, tampered_groups)
        malformed = source_row(9)
        malformed["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "strict schema"):
            self.build([malformed])

    def test_revision_is_inferred_from_hugging_face_metadata(self) -> None:
        source_root = self.root / "linuxarena-public"
        source = source_root / "data/sample.jsonl"
        source.parent.mkdir(parents=True)
        source.write_text(json.dumps(source_row(1)) + "\n", encoding="utf-8")
        metadata = source_root / ".cache/huggingface/download/data/sample.jsonl.metadata"
        metadata.parent.mkdir(parents=True)
        metadata.write_text(REVISION + "\nopaque\n", encoding="utf-8")
        self.assertEqual(adapter.resolve_revision(source, None), REVISION)

    def test_writes_value_free_manifests_that_bind_output(self) -> None:
        rows, manifest, groups = self.build()
        output = self.root / "linuxarena.jsonl"
        manifest_path = self.root / "linuxarena.manifest.json"
        groups_path = self.root / "linuxarena.groups.json"
        adapter.write_outputs(
            rows,
            manifest,
            groups,
            output=output,
            manifest_path=manifest_path,
            group_manifest_path=groups_path,
        )
        self.assertEqual(adapter.sha256_bytes(output.read_bytes()), manifest["output_sha256"])
        self.assertEqual(json.loads(groups_path.read_text())["corpus_sha256"], manifest["output_sha256"])
        forbidden = {"actions", "arguments", "cmd", "command", "output", "reasoning", "events"}

        def assert_value_free(value: object) -> None:
            if isinstance(value, dict):
                self.assertTrue(forbidden.isdisjoint(value))
                for child in value.values():
                    assert_value_free(child)
            elif isinstance(value, list):
                for child in value:
                    assert_value_free(child)

        assert_value_free(json.loads(manifest_path.read_text()))
        assert_value_free(json.loads(groups_path.read_text()))


if __name__ == "__main__":
    unittest.main()
