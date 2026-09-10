#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
projector = importlib.import_module("benchmark_project_stateful_actions")


def stateful_row() -> dict[str, object]:
    return {
        "schema_version": "1",
        "id": "fixture/trajectory",
        "source": {
            "dataset": "fixture",
            "revision": "1",
            "original_id": "trajectory-1",
            "license": "Apache-2.0",
            "redistribution": "vendored",
        },
        "split": "validation",
        "surface": "stateful",
        "payload": {
            "events": [
                {
                    "tool_name": "execute_command",
                    "args": {"command": "echo ok"},
                    "dialect": "none",
                    "outcome": "unknown",
                    "offset_seconds": 0,
                },
                {
                    "tool_name": "sql_query",
                    "args": {"connection": "fixture", "query": "SELECT 1"},
                    "dialect": "none",
                    "outcome": "succeeded",
                    "offset_seconds": 1,
                },
            ]
        },
        "truth": {
            "source_truth": "malicious",
            "deterministic_truth": "contextual_or_dual_use",
            "label_confidence": "low",
            "label_source": "fixture",
            "applicability": "in_scope",
            "expected_disposition": "detect_only",
            "categories": ["synthetic_authorized_red_team"],
        },
        "strata": {
            "campaign": "fixture",
            "domain": "structured_tool_call",
            "hard_negative": False,
            "split_group": "a" * 24,
        },
    }


class StatefulActionProjectionTests(unittest.TestCase):
    def test_projects_events_without_outcome(self) -> None:
        rows, manifest = projector.project([json.dumps(stateful_row())])
        self.assertEqual(manifest["source_cases"], 1)
        self.assertEqual(manifest["row_count"], 2)
        self.assertEqual(rows[0]["surface"], "action")
        self.assertEqual(rows[0]["payload"]["args"], {"command": "echo ok"})
        self.assertNotIn("outcome", rows[0]["payload"])
        self.assertEqual(rows[1]["strata"]["sequence_index"], 1)
        self.assertEqual(rows[0]["split"], "validation")
        self.assertIn("projected_atomic_event", rows[0]["truth"]["categories"])

    def test_rejects_non_stateful_input(self) -> None:
        row = stateful_row()
        row["surface"] = "action"
        with self.assertRaisesRegex(ValueError, "expected stateful"):
            projector.project([json.dumps(row)])

    def test_rows_validate_against_case_schema(self) -> None:
        rows, _ = projector.project([json.dumps(stateful_row())])
        projector.validate_cases(rows, Path("benchmarks/schema/case-v1.schema.json"))


if __name__ == "__main__":
    unittest.main()
