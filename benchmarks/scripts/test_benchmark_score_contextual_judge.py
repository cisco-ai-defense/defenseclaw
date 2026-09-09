#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib
import json
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
scorer = importlib.import_module("benchmark_score_contextual_judge")


def case(case_id: str, label: str, confidence: str = "high") -> dict[str, object]:
    benign = label == "benign"
    return {
        "schema_version": "1",
        "id": case_id,
        "source": {"dataset": "fixture"},
        "surface": "action",
        "payload": {"tool_name": "must-not-leak", "args": {"secret": "must-not-leak"}},
        "truth": {
            "source_truth": "unknown" if benign else "malicious",
            "deterministic_truth": "benign" if benign else "contextual_or_dual_use",
            "expected_disposition": "allow" if benign else "detect_only",
            "label_confidence": confidence,
        },
    }


def deterministic(case_id: str, detected: bool = False, blocked: bool = False) -> dict[str, object]:
    return {
        "case_id": case_id,
        "detected": detected,
        "action": "block" if blocked else ("alert" if detected else "allow"),
    }


def llm(case_id: str, detected: bool = False, blocked: bool = False) -> dict[str, object]:
    return {
        "case_id": case_id,
        "model": "ollama/test",
        "surface": "action",
        "detected": detected,
        "action": "block" if blocked else ("alert" if detected else "allow"),
        "invocation_count": 1,
        "json_mode_count": 1,
        "prompt_tokens": 100,
        "completion_tokens": 10,
        "total_tokens": 110,
        "provider_latency_ms": 20,
        "end_to_end_latency_ms": 21,
        "decision_count": 2,
        "detected_decision_count": 1 if detected else 0,
        "blocked_decision_count": 1 if blocked else 0,
    }


class ContextualJudgeScorerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.cases = [
            case("benign", "benign"),
            case("attack-a", "attack"),
            case("attack-b", "attack"),
            case("diagnostic", "attack", "low"),
        ]

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self, name: str, rows: list[dict[str, object]]) -> Path:
        path = self.root / name
        path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        return path

    def test_scores_incremental_coverage_blocking_and_cost(self) -> None:
        case_path = self.write("cases.jsonl", self.cases)
        det_path = self.write(
            "det.jsonl",
            [deterministic("benign"), deterministic("attack-a", True, True), deterministic("attack-b"), deterministic("diagnostic")],
        )
        llm_path = self.write(
            "llm.jsonl",
            [llm("benign"), llm("attack-a"), llm("attack-b", True, False), llm("diagnostic", True, True)],
        )
        args = Namespace(
            cases=case_path,
            deterministic_predictions=det_path,
            llm_predictions=[llm_path],
            output=self.root / "report.json",
            input_usd_per_million_tokens=None,
            output_usd_per_million_tokens=None,
        )
        report = scorer.score(args)
        model = report["models"][0]
        self.assertEqual(report["label_partition"], {"attack": 2, "benign": 1, "diagnostic": 1})
        self.assertEqual(report["surface_counts"], {"action": 4})
        self.assertEqual(model["deterministic"]["detection"]["recall"], 0.5)
        self.assertEqual(model["llm_judge_first"]["detection"]["recall"], 0.5)
        self.assertEqual(model["deterministic_then_llm"]["detection"]["f1"], 1.0)
        self.assertEqual(model["deterministic_then_llm"]["incremental_attack_detections"], 1)
        self.assertEqual(model["deterministic_then_llm"]["cost"]["cases"], 2)
        self.assertEqual(model["all_cases_runtime_cost"]["cases"], 4)
        activity = model["all_cases_runtime_cost"]["decision_activity"]
        self.assertEqual(activity["decisions"], 8)
        self.assertEqual(activity["detected_decisions"], 2)
        self.assertEqual(activity["blocked_decisions"], 1)
        self.assertEqual(activity["mean_provider_latency_ms_per_invocation"], 20.0)
        self.assertEqual(activity["mean_end_to_end_latency_ms_per_decision"], 10.5)
        self.assertEqual(
            model["all_cases_runtime_cost"]["latency_by_surface"]["action"]["latency_semantics"],
            "single pre-tool judge decision",
        )
        self.assertEqual(model["diagnostic_contextual"]["llm_detected"], 1)
        self.assertNotIn("must-not-leak", json.dumps(report))

    def test_duplicate_or_missing_predictions_fail(self) -> None:
        ids = {"a"}
        with self.assertRaisesRegex(ValueError, "duplicate prediction"):
            scorer.index_predictions([llm("a"), llm("a")], ids, model_required=True)
        with self.assertRaisesRegex(ValueError, "missing"):
            scorer.index_predictions([], ids, model_required=False)

    def test_wilson_and_percentiles_are_bounded(self) -> None:
        self.assertEqual(scorer.percentile([1, 2, 100], 0.95), 100)
        interval = scorer.wilson(0, 10)
        self.assertEqual(interval["lower"], 0.0)
        self.assertGreater(interval["upper"], 0.0)

    def test_decision_activity_is_optional_and_validated(self) -> None:
        self.assertFalse(scorer.decision_activity([{"invocation_count": 1}])["available"])
        with self.assertRaisesRegex(ValueError, "exceed total decisions"):
            scorer.decision_activity(
                [{"decision_count": 1, "detected_decision_count": 2, "blocked_decision_count": 0}]
            )

    def test_per_model_pricing_handles_model_tags_and_overrides_global_rates(self) -> None:
        pricing = scorer.parse_model_pricing(
            ["ollama/gemma4:12b-mlx:0.13:0.40", "bedrock/google.gemma-3-12b-it:0.09:0.29"]
        )
        self.assertEqual(pricing["ollama/gemma4:12b-mlx"], (0.13, 0.40))
        args = Namespace(
            model_pricing=["bedrock/google.gemma-3-12b-it:0.09:0.29"],
            input_usd_per_million_tokens=9.0,
            output_usd_per_million_tokens=9.0,
        )
        self.assertEqual(scorer.token_rates(args, "bedrock/google.gemma-3-12b-it"), (0.09, 0.29))
        self.assertEqual(scorer.token_rates(args, "unlisted"), (9.0, 9.0))
        with self.assertRaisesRegex(ValueError, "duplicate model pricing"):
            scorer.parse_model_pricing(["model:1:2", "model:3:4"])

    def test_monitoring_atomic_truth_is_diagnostic_without_trajectory(self) -> None:
        value = case("monitoring", "attack")
        value["source"] = {"dataset": "neur26anonsub/ctrldataset2026"}
        self.assertEqual(
            scorer.case_label(value),
            ("diagnostic", "environment-verified-action-requires-trajectory-context"),
        )
        value["surface"] = "stateful"
        self.assertEqual(scorer.case_label(value)[0], "attack")

    def test_medium_confidence_source_label_is_diagnostic_without_proof(self) -> None:
        value = case("bashbench", "attack", confidence="medium")
        value["source"] = {"dataset": "AISafety-Student/labeled-bashBench"}
        self.assertEqual(
            scorer.case_label(value),
            ("diagnostic", "medium-confidence-source-label-coverage-only"),
        )
        value["truth"]["deterministic_truth"] = "malicious"
        self.assertEqual(scorer.case_label(value)[0], "attack")

if __name__ == "__main__":
    unittest.main()
