#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
adapter = importlib.import_module("benchmark_normalize_trace_commons")


class TraceCommonsAdapterTests(unittest.TestCase):
    def test_projects_only_action_arguments(self) -> None:
        rows = [
            {
                "session_id": "session-one",
                "messages": [
                    json.dumps(
                        {
                            "role": "assistant",
                            "content": "excluded prose",
                            "tool_calls": [
                                {
                                    "id": "one",
                                    "function": {
                                        "name": "Bash",
                                        "arguments": {"command": "printf ok", "description": "safe"},
                                    },
                                },
                                {"id": "two", "function": {"name": "TodoWrite", "arguments": {"todos": []}}},
                            ],
                        }
                    ),
                    json.dumps({"role": "tool", "content": "excluded result"}),
                ],
            }
        ]
        cases, manifest = adapter.normalize(rows, "a" * 40)
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["payload"]["args"]["command"], "printf ok")
        self.assertEqual(cases[0]["payload"]["command"], "printf ok")
        self.assertEqual(cases[0]["payload"]["dialect"], "posix")
        self.assertEqual(cases[0]["truth"]["deterministic_truth"], "benign")
        statistics = manifest["adapter_statistics"][adapter.ADAPTER]
        self.assertEqual(statistics["source_tool_calls"], 2)
        self.assertEqual(statistics["skipped_non_action_tool"], 1)
        self.assertEqual(manifest["datasets"], [adapter.DATASET_ID])
        self.assertEqual(manifest["counts"], {adapter.DATASET_ID: 1})
        self.assertEqual(
            set(manifest),
            {
                "adapter_statistics",
                "cases",
                "counts",
                "datasets",
                "exact_payload_duplicates_removed",
                "label_conflicts_excluded",
                "schema_version",
            },
        )
        self.assertNotIn("excluded", json.dumps(cases))

    def test_powershell_commands_retain_their_declared_dialect(self) -> None:
        message = json.dumps(
            {
                "role": "assistant",
                "tool_calls": [
                    {
                        "function": {
                            "name": "PowerShell",
                            "arguments": {"command": "Remove-Item -Recurse -Force build"},
                        }
                    }
                ],
            }
        )
        cases, _ = adapter.normalize([{"session_id": "one", "messages": [message]}], "a" * 40)

        self.assertEqual(cases[0]["payload"]["dialect"], "powershell")
        self.assertEqual(cases[0]["payload"]["command"], "Remove-Item -Recurse -Force build")

    def test_session_is_split_group_and_call_ordinal_is_stable(self) -> None:
        message = json.dumps(
            {
                "role": "assistant",
                "tool_calls": [{"function": {"name": "Read", "arguments": {"file_path": "/repo/a"}}}],
            }
        )
        cases, _ = adapter.normalize(
            [{"session_id": "one", "messages": [message]}, {"session_id": "two", "messages": [message]}],
            "b" * 40,
        )
        self.assertEqual(len(cases), 2)
        self.assertEqual(len({case["strata"]["split_group"] for case in cases}), 2)

    def test_rows_validate_against_case_schema(self) -> None:
        cases, _ = adapter.normalize(
            [
                {
                    "session_id": "one",
                    "messages": [
                        json.dumps(
                            {
                                "role": "assistant",
                                "tool_calls": [
                                    {
                                        "function": {
                                            "name": "Write",
                                            "arguments": {"file_path": "/tmp/a", "content": "x"},
                                        }
                                    }
                                ],
                            }
                        )
                    ],
                }
            ],
            "c" * 40,
        )
        adapter.validate_cases(cases, Path("benchmarks/schema/case-v1.schema.json"))


if __name__ == "__main__":
    unittest.main()
