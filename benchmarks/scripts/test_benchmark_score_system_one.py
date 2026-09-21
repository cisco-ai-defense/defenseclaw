from __future__ import annotations

import unittest

from benchmarks.scripts import benchmark_score_system_one as scorer


class ScoreTests(unittest.TestCase):
    def test_metrics_and_calibration(self) -> None:
        metrics = scorer.binary_metrics([True, True, False, False], [True, False, True, False])
        self.assertEqual(
            metrics["confusion"], {"true_positive": 1, "true_negative": 1, "false_positive": 1, "false_negative": 1}
        )
        calibrated = scorer.calibration([True, False], [0.9, 0.1])
        self.assertAlmostEqual(calibrated["brier"], 0.01)

    def test_event_aggregation_uses_most_restrictive_action(self) -> None:
        rows = [
            {
                "case_id": "a",
                "run_id": "run",
                "event_index": 0,
                "model_revision": "m",
                "context_variant": "C1",
                "instruction_variant": "I0",
                "question_variant": "Q0",
                "action": "allow",
                "confidence": 0.9,
                "probabilities": {"disposition.allow": 0.9},
                "duration_ms": 1,
                "input_tokens": 5,
            },
            {
                "case_id": "a",
                "run_id": "run",
                "event_index": 1,
                "model_revision": "m",
                "context_variant": "C1",
                "instruction_variant": "I0",
                "question_variant": "Q0",
                "action": "block",
                "confidence": 0.8,
                "probabilities": {"disposition.allow": 0.05},
                "duration_ms": 2,
                "input_tokens": 5,
            },
        ]
        aggregated = scorer.aggregate_system(rows)["m/C1/I0/Q0"]["a"]
        self.assertEqual(aggregated["action"], "block")
        self.assertEqual(aggregated["requests"], 2)
        with self.assertRaisesRegex(ValueError, "duplicate System One prediction"):
            scorer.aggregate_system([rows[0], rows[0]])

    def test_per_event_counts_survive_trajectory_aggregation(self) -> None:
        def row(event_index: int, action: str) -> dict[str, object]:
            return {
                "case_id": "a",
                "run_id": "run",
                "event_index": event_index,
                "model_revision": "m",
                "context_variant": "C1",
                "instruction_variant": "I0",
                "question_variant": "Q0",
                "action": action,
                "confidence": 0.9,
                "probabilities": {"disposition.allow": 0.9},
                "duration_ms": 1,
                "input_tokens": 5,
            }

        aggregated = scorer.aggregate_system([row(0, "allow"), row(1, "allow"), row(2, "block")])["m/C1/I0/Q0"]["a"]
        self.assertEqual(aggregated["action"], "block")
        self.assertEqual(aggregated["event_count"], 3)
        self.assertEqual(aggregated["flagged_events"], 1)

    def test_repeatability_reports_flips_across_identical_requests(self) -> None:
        def row(context: str, action: str, digest: str) -> dict[str, object]:
            return {"context_variant": context, "action": action, "request_sha256": digest}

        stable = scorer.repeatability([row("C0", "allow", "aa"), row("C1", "allow", "aa")])
        self.assertEqual(stable["repeated_requests"], 1)
        self.assertEqual(stable["flipped_requests"], 0)
        self.assertEqual(stable["flip_rate"], 0)

        flipped = scorer.repeatability(
            [row("C0", "allow", "aa"), row("C1", "block", "aa"), row("C0", "allow", "bb")]
        )
        self.assertEqual(flipped["distinct_requests"], 2)
        self.assertEqual(flipped["repeated_requests"], 1)
        self.assertEqual(flipped["flipped_requests"], 1)
        self.assertEqual(flipped["flip_rate"], 1)

    def test_pareto_culling_records_reasons(self) -> None:
        def candidate(name: str, f1: float, fpr: float, latency: float, cost: float) -> dict[str, object]:
            return {
                "candidate": name,
                "system_one": {
                    "errors": 0,
                    "binary": {"f1": f1, "false_positive_rate": fpr},
                    "latency_ms": {"p95": latency},
                    "estimated_usd": cost,
                },
            }

        ledger = scorer.culling_ledger([candidate("bad", 0.5, 0.2, 10, 1), candidate("good", 0.8, 0.1, 5, 0.5)], 1)
        self.assertEqual(ledger["advanced"], ["good"])
        bad = next(item for item in ledger["decisions"] if item["candidate"] == "bad")
        self.assertTrue(any(reason.startswith("pareto_dominated_by") for reason in bad["reasons"]))


if __name__ == "__main__":
    unittest.main()
