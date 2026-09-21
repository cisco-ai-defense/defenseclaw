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
