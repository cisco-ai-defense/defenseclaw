#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
analysis = importlib.import_module("benchmark_error_analysis")


def contextual_case(case_id: str, payload: dict[str, object]) -> dict[str, object]:
    return {
        "id": case_id,
        "split": "development",
        "surface": "action",
        "source": {"dataset": "fixture"},
        "payload": payload,
        "truth": {
            "applicability": "in_scope",
            "source_truth": "malicious",
            "deterministic_truth": "contextual_or_dual_use",
            "expected_disposition": "detect_only",
        },
    }


def prediction(case_id: str, detected: bool = False) -> dict[str, object]:
    return {
        "case_id": case_id,
        "profile": "default",
        "detected": detected,
        "action": "allow",
        "parse_status": "parsed",
        "authoritative": True,
    }


class ErrorAnalysisTests(unittest.TestCase):
    def test_contextual_candidates_are_opt_in(self) -> None:
        case = contextual_case("a", {"tool_name": "kubectl", "args": {"namespace": "prod"}})
        cases = {"a": case}
        predictions = [prediction("a")]
        self.assertEqual(analysis.build_queue(cases, predictions, "default", 0), [])
        queue = analysis.build_queue(cases, predictions, "default", 0, True)
        self.assertEqual(queue[0]["reasons"], ["authoritative_candidate", "contextual_detection_candidate"])
        self.assertEqual(queue[0]["payload"]["args"]["namespace"], "prod")

    def test_detected_contextual_row_is_not_a_gap_candidate(self) -> None:
        case = contextual_case("a", {"command": "kubectl get pods"})
        self.assertEqual(
            analysis.build_queue({"a": case}, [prediction("a", detected=True)], "default", 0, True),
            [],
        )

    def test_stateful_projection_keeps_only_bounded_history(self) -> None:
        payload = {"events": [{"tool_name": "bash", "args": {"command": str(index)}} for index in range(12)]}
        projected = analysis.review_payload(payload)
        self.assertIsNotNone(projected)
        self.assertEqual(len(projected["events"]), 9)
        self.assertEqual(projected["events"][0]["args"]["command"], "3")

    def test_review_payload_bounds_large_strings(self) -> None:
        projected = analysis.review_payload({"tool_name": "file_write", "args": {"content": "x" * 100_000}})
        self.assertIsNotNone(projected)
        self.assertLess(len(projected["args"]["content"]), 9_000)
        self.assertTrue(projected["args"]["content"].endswith("<truncated>"))

    def test_main_binds_cluster_metadata_to_exact_queue_bytes(self) -> None:
        """The producer records the digest consumed by the near-miss builder."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus_path = root / "corpus.jsonl"
            predictions_path = root / "predictions.jsonl"
            output_dir = root / "analysis"
            corpus_path.write_text(
                json.dumps(contextual_case("a", {"command": "safe"})) + "\n",
                encoding="utf-8",
            )
            predictions_path.write_text(
                json.dumps(prediction("a")) + "\n",
                encoding="utf-8",
            )
            argv = [
                "benchmark_error_analysis.py",
                "--corpus",
                str(corpus_path),
                "--predictions",
                str(predictions_path),
                "--output-dir",
                str(output_dir),
                "--include-contextual-candidates",
            ]
            with mock.patch.object(sys, "argv", argv):
                self.assertEqual(analysis.main(), 0)

            queue_path = output_dir / "adjudication-queue.jsonl"
            clusters = json.loads((output_dir / "clusters.json").read_text(encoding="utf-8"))
            self.assertEqual(clusters["queue_sha256"], analysis.sha256_file(queue_path))
            self.assertEqual(clusters["queue_count"], 1)


if __name__ == "__main__":
    unittest.main()
