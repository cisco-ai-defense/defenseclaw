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
        cases, manifest = adapter.normalize(rows, adapter.SOURCE_REVISION)
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["payload"]["args"]["command"], "printf ok")
        self.assertEqual(cases[0]["payload"]["command"], "printf ok")
        self.assertEqual(cases[0]["payload"]["dialect"], "posix")
        self.assertEqual(cases[0]["split"], "smoke")
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
        cases, _ = adapter.normalize([{"session_id": "one", "messages": [message]}], adapter.SOURCE_REVISION)

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
            adapter.SOURCE_REVISION,
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
            adapter.SOURCE_REVISION,
        )
        adapter.validate_cases(cases, Path("benchmarks/schema/case-v1.schema.json"))

    def test_redacts_secret_fields_and_identity_fragments_but_preserves_safe_literals(self) -> None:
        message = json.dumps(
            {
                "role": "assistant",
                "tool_calls": [
                    {
                        "function": {
                            "name": "Bash",
                            "arguments": {
                                "command": "tool --token provided-by-store /home/contributor/repo",
                                "description": "inspect src safely",
                                "password": "provided-by-store",
                            },
                        }
                    }
                ],
            }
        )
        cases, manifest = adapter.normalize(
            [{"session_id": "one", "messages": [message]}], adapter.SOURCE_REVISION
        )
        arguments = cases[0]["payload"]["args"]
        self.assertEqual(arguments["description"], "inspect src safely")
        self.assertEqual(arguments["password"], "<redacted:secret>")
        self.assertEqual(
            arguments["command"], "tool --token <redacted:secret> /home/<redacted-user>/repo"
        )
        statistics = manifest["adapter_statistics"][adapter.ADAPTER]
        self.assertEqual(statistics["privacy_redacted_sensitive_values"], 1)
        self.assertEqual(statistics["privacy_redacted_string_values"], 1)

    def test_quoted_and_bearer_command_secrets_are_redacted(self) -> None:
        statistics = adapter.Counter()
        projected = adapter.redact_string(
            "tool --token='provided-by-store' -H 'Authorization: Bearer provided-by-store' "
            "-H 'Cookie: session=provided-by-store; preference=safe'",
            sensitive_key=False,
            statistics=statistics,
        )
        self.assertNotIn("provided-by-store", projected)
        self.assertNotIn("preference=safe", projected)
        self.assertGreaterEqual(projected.count("<redacted:secret>"), 3)

    def test_common_structured_secret_keys_are_fully_redacted(self) -> None:
        projected = adapter.secret_safe(
            {
                "api_key": "provided-by-store",
                "accessKey": "provided-by-store",
                "client-secret": "provided-by-store",
                "nested": [{"session_key": "provided-by-store"}],
            },
            adapter.Counter(),
        )
        self.assertNotIn("provided-by-store", json.dumps(projected))

    def test_rejects_unpinned_revision(self) -> None:
        with self.assertRaisesRegex(ValueError, "revision differs"):
            adapter.normalize([], "0" * 40)

    def test_nested_headers_and_url_userinfo_are_redacted(self) -> None:
        arguments = {
            "headers": [{"Authorization": "Bearer provided-by-store"}],
            "url": "https://contributor:provided-by-store@example.invalid/api",
            "options": {"dry_run": True, "retries": 2},
        }
        projected = adapter.secret_safe(arguments, adapter.Counter())
        self.assertEqual(projected["headers"][0]["Authorization"], "<redacted:secret>")
        self.assertEqual(
            projected["url"],
            "https://<redacted-user>:<redacted:secret>@example.invalid/api",
        )
        self.assertEqual(projected["options"], {"dry_run": True, "retries": 2})

    def test_nonfinite_and_oversized_arguments_are_quarantined(self) -> None:
        messages = [
            json.dumps(
                {
                    "role": "assistant",
                    "tool_calls": [
                        {"function": {"name": "Bash", "arguments": '{"command": NaN}'}},
                        {
                            "function": {
                                "name": "Bash",
                                "arguments": {"command": "x" * (adapter.MAX_ARGUMENT_BYTES + 1)},
                            }
                        },
                    ],
                }
            )
        ]
        cases, manifest = adapter.normalize(
            [{"session_id": "one", "messages": messages}], adapter.SOURCE_REVISION
        )
        self.assertEqual(cases, [])
        statistics = manifest["adapter_statistics"][adapter.ADAPTER]
        self.assertEqual(statistics["skipped_invalid_arguments"], 1)
        self.assertEqual(statistics["skipped_oversized_arguments"], 1)

    def test_duplicate_argument_keys_are_quarantined(self) -> None:
        message = json.dumps(
            {
                "role": "assistant",
                "tool_calls": [
                    {
                        "function": {
                            "name": "Bash",
                            "arguments": '{"command":"first","command":"second"}',
                        }
                    }
                ],
            }
        )
        cases, manifest = adapter.normalize(
            [{"session_id": "one", "messages": [message]}], adapter.SOURCE_REVISION
        )
        self.assertEqual(cases, [])
        self.assertEqual(
            manifest["adapter_statistics"][adapter.ADAPTER]["skipped_invalid_arguments"],
            1,
        )


if __name__ == "__main__":
    unittest.main()
