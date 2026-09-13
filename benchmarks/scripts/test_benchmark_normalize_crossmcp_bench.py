#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("benchmark_normalize_crossmcp_bench.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_crossmcp_bench", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

REVISION = "a" * 40


def source_row(
    *,
    source_id: str = "ATK-01",
    is_attack: bool = True,
    tools: list[str] | None = None,
    authorization: dict[str, list[str]] | None = None,
) -> dict[str, object]:
    if tools is None:
        tools = ["read_file", "http_post"]
    if authorization is None:
        authorization = {
            "approved_recipients": [],
            "approved_data_domains": [],
            "approved_sink_classes": [],
        }
    return {
        "id": source_id,
        "is_attack": is_attack,
        "attack_type": "exfiltration" if is_attack else None,
        "sensitivity_label": "sensitive" if is_attack else "public",
        "auth_context": json.dumps(authorization),
        "expected_policy": "P1_EXFILTRATION" if is_attack else None,
        "expected_tools": json.dumps(tools),
        "description": "excluded description",
        "user_instruction": "excluded user prompt",
    }


class CrossMCPBenchNormalizerTest(unittest.TestCase):
    def test_attack_is_only_a_complete_stateful_source_positive(self) -> None:
        cases, manifest = MODULE.normalize(
            [source_row()], revision=REVISION, split="development"
        )

        self.assertEqual(1, len(cases))
        case = cases[0]
        self.assertEqual("stateful", case["surface"])
        self.assertEqual("malicious", case["truth"]["source_truth"])
        self.assertEqual(
            "contextual_or_dual_use", case["truth"]["deterministic_truth"]
        )
        self.assertIn("trajectory_only_positive", case["truth"]["categories"])
        self.assertEqual(
            ["read_file", "http_post"],
            [event["tool_name"] for event in case["payload"]["events"]],
        )
        self.assertFalse(any(row["surface"] == "action" for row in cases))
        self.assertEqual(1, manifest["counts"]["attack_scenarios"])

    def test_source_authorization_and_policy_are_scenario_context(self) -> None:
        authorization = {
            "approved_recipients": ["https://approved.example.invalid/import"],
            "approved_data_domains": ["FileContent", "PII"],
            "approved_sink_classes": ["SendExternal"],
        }
        cases, _ = MODULE.normalize(
            [source_row(authorization=authorization)],
            revision=REVISION,
            split="validation",
        )

        context = cases[0]["payload"]["args"]["_crossmcp_context"]
        self.assertEqual(authorization, context["authorization"])
        self.assertEqual("P1_EXFILTRATION", context["expected_policy"])
        self.assertEqual("sensitive", context["sensitivity_label"])
        for event in cases[0]["payload"]["events"]:
            self.assertEqual({}, event["args"])

    def test_benign_single_call_is_atomic_and_multi_call_is_stateful(self) -> None:
        rows = [
            source_row(source_id="BEN-01", is_attack=False, tools=["read_file"]),
            source_row(
                source_id="BEN-02",
                is_attack=False,
                tools=["read_file", "write_file"],
            ),
        ]
        cases, manifest = MODULE.normalize(rows, revision=REVISION, split="test")

        by_source = {case["source"]["original_id"]: case for case in cases}
        self.assertEqual("action", by_source["BEN-01"]["surface"])
        self.assertEqual("stateful", by_source["BEN-02"]["surface"])
        self.assertTrue(all(case["strata"]["hard_negative"] for case in cases))
        self.assertTrue(
            all(case["truth"]["deterministic_truth"] == "benign" for case in cases)
        )
        self.assertEqual(1, manifest["counts"]["benign_action_cases"])
        self.assertEqual(1, manifest["counts"]["benign_stateful_cases"])

    def test_missing_execution_evidence_is_not_invented(self) -> None:
        cases, _ = MODULE.normalize(
            [source_row()], revision=REVISION, split="development"
        )

        for event in cases[0]["payload"]["events"]:
            self.assertNotIn("outcome", event)
            self.assertNotIn("offset_seconds", event)
            self.assertNotIn("call_id", event)
        serialized = MODULE.canonical_json(cases[0])
        self.assertNotIn("excluded description", serialized)
        self.assertNotIn("excluded user prompt", serialized)

    def test_attack_singleton_and_benign_attack_metadata_are_quarantined(self) -> None:
        benign = source_row(source_id="BEN-bad", is_attack=False)
        benign["expected_policy"] = "P1_EXFILTRATION"
        cases, manifest = MODULE.normalize(
            [source_row(tools=["shell"]), benign],
            revision=REVISION,
            split="development",
        )

        self.assertEqual([], cases)
        self.assertEqual(1, manifest["skipped"]["attack_requires_stateful_sequence"])
        self.assertEqual(1, manifest["skipped"]["benign_has_attack_metadata"])

    def test_embedded_json_rejects_duplicate_keys_and_invalid_tool_names(self) -> None:
        duplicate_auth = source_row(source_id="ATK-duplicate")
        duplicate_auth["auth_context"] = (
            '{"approved_recipients":[],"approved_recipients":[],'
            '"approved_data_domains":[],"approved_sink_classes":[]}'
        )
        bad_tool = source_row(source_id="ATK-tool")
        bad_tool["expected_tools"] = json.dumps(["read_file", "bad tool"])

        cases, manifest = MODULE.normalize(
            [duplicate_auth, bad_tool], revision=REVISION, split="development"
        )

        self.assertEqual([], cases)
        self.assertEqual(1, manifest["skipped"]["invalid_auth_context"])
        self.assertEqual(1, manifest["skipped"]["invalid_tool_name"])

    def test_duplicate_source_ids_do_not_duplicate_cases(self) -> None:
        row = source_row()
        cases, manifest = MODULE.normalize(
            [row, dict(row)], revision=REVISION, split="development"
        )

        self.assertEqual(1, len(cases))
        self.assertEqual(1, manifest["skipped"]["duplicate_source_id"])

    def test_cases_validate_against_case_v1(self) -> None:
        cases, _ = MODULE.normalize(
            [
                source_row(),
                source_row(source_id="BEN-01", is_attack=False, tools=["read_file"]),
                source_row(
                    source_id="BEN-02",
                    is_attack=False,
                    tools=["read_file", "write_file"],
                ),
            ],
            revision=REVISION,
            split="development",
        )

        MODULE.validate_cases(cases, MODULE.DEFAULT_SCHEMA)

    def test_jsonl_reader_never_evaluates_untrusted_text(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "must-not-exist"
            row = source_row()
            row["description"] = f"__import__('pathlib').Path({str(marker)!r}).touch()"
            source = Path(temporary) / "source.jsonl"
            source.write_text(json.dumps(row) + "\n", encoding="utf-8")

            parsed = list(MODULE.jsonl_rows(source))

            self.assertEqual(1, len(parsed))
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
