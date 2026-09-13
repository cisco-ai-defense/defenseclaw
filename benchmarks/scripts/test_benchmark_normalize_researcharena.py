#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("benchmark_normalize_researcharena.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_researcharena", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
normalizer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = normalizer
SPEC.loader.exec_module(normalizer)


class ResearchArenaNormalizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = Path(__file__).parent / "testdata/researcharena"
        self.schema = Path(__file__).parents[1] / "schema/case-v1.schema.json"
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name) / "cases.jsonl"
        self.manifest = Path(self.temporary.name) / "manifest.json"

    def normalize(self, root: Path | None = None) -> tuple[list[dict[str, object]], dict[str, object]]:
        manifest = normalizer.normalize(
            input_root=root or self.fixture,
            revision=normalizer.SOURCE_REVISION,
            output=self.output,
            manifest_path=self.manifest,
            schema_path=self.schema,
            verify_pinned_source=False,
        )
        cases = [json.loads(line) for line in self.output.read_text().splitlines()]
        return cases, manifest

    def test_projects_provider_events_and_excludes_german(self) -> None:
        cases, manifest = self.normalize()
        stats = manifest["adapter_statistics"][normalizer.ADAPTER]

        self.assertEqual(len(cases), 25)
        self.assertEqual(stats["baseline_runs"], 1)
        self.assertEqual(stats["side_task_runs"], 2)
        self.assertEqual(stats["side_task_success_runs"], 1)
        self.assertEqual(stats["exclusions"], {"non_english_embedded_german": 1})
        self.assertEqual(stats["truth_benign"], 19)
        self.assertEqual(stats["truth_malicious"], 1)
        self.assertEqual(stats["truth_unknown"], 5)
        self.assertEqual(stats["applicability_in_scope"], 19)
        self.assertEqual(stats["applicability_out_of_scope"], 6)
        self.assertEqual(stats["outcomes"], {"failed": 2, "succeeded": 12})

    def test_emitted_cases_have_english_strata(self) -> None:
        cases, _manifest = self.normalize()

        self.assertTrue(cases)
        self.assertTrue(all(case["strata"]["language"] == "en" for case in cases))

    def test_split_group_is_stable_per_task_family(self) -> None:
        copied = Path(self.temporary.name) / "fixture-task-families"
        shutil.copytree(self.fixture, copied)

        def copy_baseline_run(name: str, **metadata_updates: object) -> str:
            source = copied / "baseline"
            destination = copied / name
            shutil.copytree(source, destination)
            metadata_path = destination / "metadata.json"
            metadata = json.loads(metadata_path.read_text())
            metadata.update(metadata_updates)
            metadata_path.write_text(json.dumps(metadata))
            result_path = destination / "blue_team/monitor/results.json"
            result = json.loads(result_path.read_text())
            result["metadata"] = metadata
            result_path.write_text(json.dumps(result))
            return normalizer.digest(
                normalizer.SOURCE_REVISION,
                metadata["cluster_id"],
                name,
            )[:24]

        repeated_trajectory = copy_baseline_run(
            "baseline-repeat",
            cluster_id="2001",
            experiment="fixture_baseline_repeat",
            red_model="claude-opus-repeat",
            timestamp="20260912_130000",
        )
        different_trajectory = copy_baseline_run(
            "baseline-different-task",
            cluster_id="2002",
            experiment="fixture_baseline_different",
            task_config="different_task_config",
            timestamp="20260912_140000",
        )

        cases, _manifest = self.normalize(copied)
        original_trajectory = normalizer.digest(
            normalizer.SOURCE_REVISION,
            "1001",
            "baseline",
        )[:24]
        groups_by_trajectory = {
            trajectory: {
                case["strata"]["split_group"]
                for case in cases
                if case["strata"]["trajectory_id"] == trajectory
            }
            for trajectory in (original_trajectory, repeated_trajectory, different_trajectory)
        }

        self.assertTrue(all(len(groups) == 1 for groups in groups_by_trajectory.values()))
        self.assertEqual(
            groups_by_trajectory[original_trajectory],
            groups_by_trajectory[repeated_trajectory],
        )
        self.assertNotEqual(
            groups_by_trajectory[original_trajectory],
            groups_by_trajectory[different_trajectory],
        )

    def test_rolling_window_is_current_plus_eight_predecessors(self) -> None:
        cases, _manifest = self.normalize()
        baseline_states = [
            case
            for case in cases
            if case["surface"] == "stateful" and case["strata"]["campaign"] == "baseline_success"
        ]
        self.assertEqual(len(baseline_states), 9)
        self.assertEqual(len(baseline_states[0]["payload"]["events"]), 2)
        self.assertEqual(len(baseline_states[-1]["payload"]["events"]), 9)
        self.assertEqual(
            [event["tool_name"] for event in baseline_states[-1]["payload"]["events"]],
            ["Bash", "Read", "Edit", "Bash", "Read", "Glob", "Grep", "Write", "Bash"],
        )

    def test_tool_output_reasoning_and_model_text_are_not_projected(self) -> None:
        cases, _manifest = self.normalize()
        serialized = normalizer.canonical_json(cases)
        self.assertNotIn("excluded output", serialized)
        self.assertNotIn("excluded command error", serialized)
        self.assertNotIn("excluded compile output", serialized)
        self.assertNotIn("excluded reasoning", serialized)
        self.assertNotIn("excluded model prose", serialized)

    def test_side_task_truth_never_marks_atomic_call_malicious(self) -> None:
        cases, _manifest = self.normalize()
        side_actions = [
            case
            for case in cases
            if case["surface"] == "action" and not case["strata"]["hard_negative"]
        ]
        self.assertEqual(len(side_actions), 4)
        self.assertTrue(all(case["truth"]["source_truth"] == "unknown" for case in side_actions))
        self.assertTrue(
            all(case["truth"]["deterministic_truth"] == "contextual_or_dual_use" for case in side_actions)
        )
        self.assertTrue(all("stateful_lens" not in case["truth"] for case in side_actions))

        baseline_actions = [case for case in cases if case["surface"] == "action"]
        self.assertTrue(all("stateful_lens" not in case["truth"] for case in baseline_actions))

        confirmed_states = [
            case
            for case in cases
            if case["surface"] == "stateful"
            and case["strata"]["campaign"] == "side_task_success"
        ]
        self.assertEqual(len(confirmed_states), 1)
        self.assertEqual(confirmed_states[0]["truth"]["source_truth"], "malicious")
        self.assertEqual(confirmed_states[0]["truth"]["applicability"], "out_of_scope")
        self.assertEqual(confirmed_states[0]["truth"]["stateful_lens"], "bounded_intent")

        baseline_states = [
            case
            for case in cases
            if case["surface"] == "stateful" and case["strata"]["campaign"] == "baseline_success"
        ]
        self.assertTrue(all("stateful_lens" in case["truth"] for case in baseline_states))

    def test_evaluator_numeric_disagreement_uses_unanimous_sign(self) -> None:
        copied = Path(self.temporary.name) / "fixture-copy"
        shutil.copytree(self.fixture, copied)
        baseline = copied / "baseline"
        first = json.loads((baseline / "blue_team/monitor/results.json").read_text())
        first["main_task_score"] = 0.7401
        first["side_task_score"] = 0.0106
        (baseline / "blue_team/monitor/results.json").write_text(json.dumps(first))
        second = dict(first)
        second["main_task_score"] = 0.7694
        second["side_task_score"] = 0.0062
        second_dir = baseline / "blue_team/second-monitor"
        second_dir.mkdir()
        (second_dir / "results.json").write_text(json.dumps(second))

        cases, manifest = self.normalize(copied)
        stats = manifest["adapter_statistics"][normalizer.ADAPTER]
        score_summary = stats["evaluation_score_summary"]
        self.assertEqual(len(cases), 25)
        self.assertEqual(score_summary["main_task_score_min"], 0.5)
        self.assertEqual(score_summary["main_task_score_max"], 0.7694)
        self.assertEqual(score_summary["side_task_score_min"], 0.0)
        self.assertEqual(score_summary["side_task_score_max"], 1.0)
        self.assertEqual(stats.get("main_task_sign_disagreement_runs", 0), 0)

    def test_side_task_requires_unanimous_positive_scores(self) -> None:
        copied = Path(self.temporary.name) / "fixture-mixed"
        shutil.copytree(self.fixture, copied)
        side = copied / "side-codex"
        second = json.loads((side / "blue_team/monitor/results.json").read_text())
        second["side_task_score"] = 0
        second_dir = side / "blue_team/second-monitor"
        second_dir.mkdir()
        (second_dir / "results.json").write_text(json.dumps(second))

        cases, manifest = self.normalize(copied)
        stats = manifest["adapter_statistics"][normalizer.ADAPTER]
        self.assertEqual(stats.get("side_task_success_runs", 0), 0)
        self.assertEqual(stats["side_task_sign_disagreement_runs"], 1)
        codex_cases = [case for case in cases if case["strata"]["provider"] == "codex"]
        self.assertTrue(all(case["truth"]["source_truth"] == "unknown" for case in codex_cases))

    def test_duplicate_json_keys_fail_closed(self) -> None:
        with self.assertRaisesRegex(normalizer.ProjectionError, "duplicate_json_key"):
            normalizer.parse_json('{"type":"assistant","type":"user"}', "invalid")

    def test_wrong_revision_is_rejected_before_source_processing(self) -> None:
        with self.assertRaisesRegex(ValueError, normalizer.SOURCE_REVISION):
            normalizer.normalize(
                input_root=self.fixture,
                revision="241e456",
                output=self.output,
                manifest_path=self.manifest,
                schema_path=self.schema,
                verify_pinned_source=True,
            )


if __name__ == "__main__":
    unittest.main()
