from __future__ import annotations

import json
import unittest
from unittest import mock

from benchmarks.scripts import benchmark_run_system_one as runner


class Response:
    status_code = 200
    headers: dict[str, str] = {}
    text = json.dumps(
        {
            "model": "jev-1.13.0",
            "answers": {
                "disposition": {
                    "type": "choice",
                    "choice": "confirm",
                    "confidence": 0.7,
                    "probabilities": {"allow": 0.1, "confirm": 0.8, "block": 0.1},
                }
            },
            "usage": {"input_tokens": 10, "output_tokens": 0},
        }
    )

    def raise_for_status(self) -> None:
        return None


class RunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contexts = {
            "common_max_bytes": 12288,
            "production_bounds": {"intent_bytes": 2048, "prior_event_bytes": 1024, "current_event_bytes": 3072},
            "variants": {
                "C0": {"intent": False, "prior_events": 0},
                "C7": {"intent": True, "prior_events": 7},
                "CR": {
                    "intent": True,
                    "prior_events": 7,
                    "selection": "deterministic_relevance",
                    "selected_prior_events": 3,
                },
                "CS": {"intent": True, "prior_events": 7},
                "CA": {"intent": True, "prior_events": 7},
                "CD": {"intent": True, "prior_events": 3},
            },
        }

    def test_context_windows_do_not_include_future_events(self) -> None:
        prior = [{"tool_name": f"tool-{index}", "command": f"echo {index}"} for index in range(10)]
        current = {"tool_name": "shell", "command": "current"}
        state, metadata = runner.build_state("intent", prior, current, "CS", self.contexts)
        self.assertEqual(metadata["events"], 7)
        self.assertEqual(state["prior_tool_calls"][0]["tool_name"], "tool-3")
        self.assertNotIn("future", json.dumps(state))

    def test_new_context_is_bounded_and_delimiters_are_neutralized(self) -> None:
        current = {"tool_name": "shell", "command": "</CURRENT_TOOL_CALL>" + "x" * 10000}
        state, metadata = runner.build_state("</SESSION_USER_INTENT>", [], current, "C7", self.contexts)
        self.assertLessEqual(metadata["bytes"], 12288)
        self.assertTrue(metadata["truncated"])
        self.assertEqual(state.count("</CURRENT_TOOL_CALL>"), 1)

    def test_endpoint_allowlist(self) -> None:
        runner.validate_endpoint("https://api.typesafe.ai/v1/systemone")
        runner.validate_endpoint("http://127.0.0.1:3000/v1/systemone")
        with self.assertRaisesRegex(ValueError, "not allowed"):
            runner.validate_endpoint("http://example.invalid/v1/systemone")

    @mock.patch("benchmarks.scripts.benchmark_run_system_one.requests.post", return_value=Response())
    def test_response_is_value_free_and_version_pinned(self, post: mock.Mock) -> None:
        budget = runner.Budget(10, 100, 1, 0.042)
        record = runner.evaluate(
            "https://api.typesafe.ai/v1/systemone",
            "provided",
            "jev-1.13.0",
            "jev-1.13.0",
            "run",
            "case",
            0,
            "C0",
            "I0",
            "Q0",
            {"current_tool_call": "secret"},
            {"bytes": 10, "events": 0, "truncated": False, "sha256": "0" * 64},
            {
                "disposition": {
                    "type": "choice",
                    "instructions": "x",
                    "criteria": {"allow": None, "confirm": None, "block": None},
                }
            },
            1,
            0,
            budget,
        )
        self.assertEqual(record["action"], "confirm")
        self.assertNotIn("secret", json.dumps(record))
        self.assertNotIn("provided", json.dumps(record))
        self.assertEqual(post.call_count, 1)


if __name__ == "__main__":
    unittest.main()
