#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
module = importlib.import_module("benchmark_build_near_miss_fpr_lane")


def queue_row(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "id": "fixture/case",
        "dataset": "fixture",
        "split": "validation",
        "surface": "action",
        "reasons": ["deterministic_benign_finding"],
        "truth_source": "deterministic",
        "deterministic_truth": "benign",
        "payload": {"tool_name": "shell", "args": {"command": "true"}},
        "baseline": {
            "detected": True,
            "action": "alert",
            "authoritative": True,
            "enforcement_eligible": False,
            "parse_status": "parsed",
            "issue_codes": [],
            "route": "semantic",
            "rule_ids": ["fixture.rule"],
        },
    }
    row.update(overrides)
    return row


class NearMissFPRLaneTests(unittest.TestCase):
    def test_selector_requires_frozen_validation_benign_finding(self) -> None:
        self.assertTrue(module.selected_case(queue_row()))
        for overrides in (
            {"split": "development"},
            {"truth_source": "model"},
            {"deterministic_truth": "contextual_or_dual_use"},
            {"baseline": {"detected": False}},
            {"reasons": ["other_reason"]},
        ):
            self.assertFalse(module.selected_case(queue_row(**overrides)))

    def test_payload_summary_does_not_retain_argument_values(self) -> None:
        summary = module.payload_summary(
            {
                "events": [
                    {"tool_name": "shell", "args": {"command": "private-value"}},
                    {"tool": "file_read", "args": {"path": "private-path"}},
                ]
            }
        )
        self.assertEqual(summary["event_count"], 2)
        self.assertEqual(summary["event_tools"], ["file_read", "shell"])
        self.assertNotIn("private-value", summary)
        self.assertNotIn("private-path", summary)

    def test_manifest_contract_is_non_gating(self) -> None:
        self.assertEqual(module.SCHEMA_VERSION, "defenseclaw/near-miss-fpr-lane/v1")
        self.assertEqual(module.SELECTOR_REASON, "deterministic_benign_finding")


if __name__ == "__main__":
    unittest.main()
