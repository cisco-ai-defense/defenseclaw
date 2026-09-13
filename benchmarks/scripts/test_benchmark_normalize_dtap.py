#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

import json
import tempfile
import unittest
from pathlib import Path

import benchmark_normalize_dtap as normalizer


def agent_call(tool_name, arguments):
    return {
        "role": "agent",
        "metadata": {"tool_name": tool_name, "tool_params": arguments},
        "content": "agent prose is not action evidence",
    }


def tool_result(tool_name, state):
    return {"role": "tool", "metadata": {"tool_name": tool_name}, "state": state}


def trace(*trajectory, instruction="List the records"):
    return {
        "task_info": {"domain": "research", "task_id": "task-1", "original_instruction": instruction},
        "trajectory": list(trajectory),
    }


class DTapNormalizerTest(unittest.TestCase):
    def test_parallel_calls_require_matching_non_error_results_and_keep_identity(self):
        source = trace(
            agent_call("search", {"query": "records"}),
            agent_call("search", {"query": "users"}),
            tool_result("search", {"success": True, "items": [1]}),
            tool_result("search", {"text": '{"success": true, "items": [2]}'}),
            agent_call("empty", {}),
            agent_call("failed", {"cmd": "not-authorized"}),
            tool_result("failed", {"success": False, "error": "denied"}),
            agent_call("unmatched", {"query": "never returns"}),
        )
        events = normalizer.normalized_events(source)
        self.assertEqual([event["tool_name"] for event in events], ["search", "search"])
        self.assertEqual([event["offset_seconds"] for event in events], [0, 1])
        self.assertEqual([event["outcome"] for event in events], ["succeeded", "succeeded"])
        self.assertEqual([event["args"]["query"] for event in events], ["records", "users"])

    def test_unknown_but_non_error_result_is_kept_and_literal_state_is_safe(self):
        source = trace(
            agent_call("lookup", {"key": "abc"}),
            tool_result("lookup", "{'text': '{\"value\": 7}'}"),
        )
        events = normalizer.normalized_events(source)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["outcome"], "unknown")

    def test_plain_error_result_is_not_evidence(self):
        source = trace(
            agent_call("lookup", {"key": "abc"}),
            tool_result("lookup", "Error: permission denied"),
        )
        self.assertEqual(normalizer.normalized_events(source), [])

    def test_normalize_is_english_only_and_labels_are_source_limited(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            benign = root / "research" / "benign"
            malicious = root / "research" / "malicious" / "direct" / "dangerous-actions"
            benign.mkdir(parents=True)
            malicious.mkdir(parents=True)
            good = trace(agent_call("read", {"path": "/tmp/report"}), tool_result("read", {"success": True}))
            bad_language = trace(
                agent_call("read", {"path": "/tmp/report"}),
                tool_result("read", {"success": True}),
                instruction="列出报告",
            )
            (benign / "one.json").write_text(json.dumps(good), encoding="utf-8")
            (benign / "judge_result.json").write_text(json.dumps({"task_success": True}), encoding="utf-8")
            (malicious / "two.json").write_text(json.dumps(bad_language), encoding="utf-8")
            (malicious / "judge_result.json").write_text(json.dumps({"attack_success": True}), encoding="utf-8")
            rows, counts = normalizer.normalize(root, normalizer.PINNED_REVISION)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["truth"]["expected_disposition"], "allow")
        self.assertEqual(counts["non_english"], 1)
        self.assertEqual(rows[0]["source"]["revision"], normalizer.PINNED_REVISION)

    def test_bounded_chunks_and_revision_guard(self):
        events = [
            {"args": {"n": index}, "dialect": "none", "offset_seconds": index, "outcome": "unknown", "tool_name": "x"}
            for index in range(normalizer.MAX_EVENTS + 1)
        ]
        projected = normalizer.bounded_payloads(events)
        self.assertEqual([surface for surface, _ in projected], ["stateful", "action"])
        self.assertEqual(len(projected[0][1]["events"]), normalizer.MAX_EVENTS)
        sparse = [
            {"_ordinal": 0, "args": {"n": 0}, "dialect": "none", "offset_seconds": 0, "outcome": "unknown", "tool_name": "x"},
            {"_ordinal": 1, "args": {"n": 1}, "dialect": "none", "offset_seconds": 1, "outcome": "unknown", "tool_name": "x"},
            {"_ordinal": normalizer.MAX_EVENTS, "args": {"n": 1}, "dialect": "none", "offset_seconds": normalizer.MAX_EVENTS, "outcome": "unknown", "tool_name": "x"},
        ]
        sparse_projected = normalizer.bounded_payloads_from_source(sparse, normalizer.MAX_EVENTS + 1)
        self.assertEqual(len(sparse_projected), 2)
        self.assertNotIn("_ordinal", sparse_projected[0][1]["events"][0])
        with self.assertRaises(ValueError):
            normalizer.normalize(Path("/does/not/exist"), "not-the-pinned-revision")


if __name__ == "__main__":
    unittest.main()

