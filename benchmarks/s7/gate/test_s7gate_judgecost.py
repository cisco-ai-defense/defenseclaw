#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: E501
"""judge_stats prices every judge request the hook sent, beside the answered-only figure (rel-1-0-10 GAP-0649)."""
from __future__ import annotations

import math
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import s7gate as G  # noqa: E402, N812


def pred_of(calls):
    return {"c1": {"n": 2, "jc": calls, "hook_ms": [5, 6]}}


class JudgeCost(unittest.TestCase):
    def test_a_cut_call_is_priced_from_its_request_size(self):
        answered = {"latency_ms": 100, "in_tok": 1000, "out_tok": 100, "parsed": True, "req_chars": 3500, "max_tok": 200}
        cut = {"latency_ms": 900, "cancelled": True, "err": "context canceled", "req_chars": 7000, "max_tok": 200}
        js = G.judge_stats(pred_of([answered, cut]), ["c1"], "gemma-4-31b")
        pi, po = G.JUDGE_PRICE["gemma-4-31b"]
        usd_answered = (1000 * pi + 100 * po) / 1e6
        self.assertAlmostEqual(js["usd"], usd_answered)
        want_all = usd_answered + (7000 / G.CHARS_PER_TOKEN * pi + 200 * po) / 1e6
        self.assertAlmostEqual(js["usd_all_sent_est"], want_all)
        self.assertGreater(js["usd_per_1k_all_sent_est"], js["usd_per_1k_tool_calls"])
        self.assertEqual((js["unanswered"], js["unanswered_sized"]), (1, 1))

    def test_a_failed_call_without_a_size_adds_nothing_and_is_counted(self):
        old_failed = {"latency_ms": 10, "err": "http 500"}
        js = G.judge_stats(pred_of([old_failed]), ["c1"], "gemma-4-31b")
        self.assertEqual((js["unanswered"], js["unanswered_sized"]), (1, 0))
        self.assertTrue(math.isclose(js["usd_all_sent_est"], js["usd"]))


if __name__ == "__main__":
    unittest.main()
