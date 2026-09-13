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

MODULE_PATH = Path(__file__).with_name("benchmark_normalize_toucan_sft.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_toucan_sft", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def tool_def(name: str) -> dict[str, object]:
    return {
        "function": {"description": "forbidden tool prose", "name": name, "parameters": {"type": "object"}},
        "type": "function",
    }


def call(name: str, arguments: str) -> dict[str, str]:
    return {"role": "tool_call", "content": repr({"name": name, "arguments": arguments})}


def result(content: str) -> dict[str, str]:
    return {"role": "tool_response", "content": content}


def row(
    *,
    identity: str = "7900c4d1-9c88-5e4b-b91a-d113dcd4d031",
    question: str = "Find the weather and then convert the temperature.",
    messages: list[dict[str, str]] | None = None,
) -> dict[str, object]:
    messages = messages or [
        {"role": "user", "content": "forbidden user prose"},
        {"role": "assistant", "content": "forbidden reasoning"},
        call("weather-get", '{"city":"Boston"}'),
        result('{"status":"success","temperature":72}'),
        call("units-convert", '{"from":"F","to":"C","value":72}'),
        result("Error: conversion service unavailable"),
        {"role": "assistant", "content": "forbidden answer"},
    ]
    return {
        "messages": json.dumps(messages),
        "question": question,
        "subset_name": "single-turn-original",
        "target_tools": "weather-get, units-convert",
        "tools": json.dumps([tool_def("weather-get"), tool_def("units-convert")]),
        "uuid": identity,
    }


class ToucanSFTNormalizerTest(unittest.TestCase):
    def test_projects_exact_pairs_as_unlabeled_out_of_scope_sequence(self) -> None:
        cases, statistics = MODULE.normalize_rows([row()])
        self.assertEqual(1, len(cases))
        case = cases[0]
        self.assertEqual(["weather-get", "units-convert"], [event["tool_name"] for event in case["payload"]["events"]])
        self.assertEqual(["succeeded", "failed"], [event["outcome"] for event in case["payload"]["events"]])
        self.assertEqual("unknown", case["truth"]["source_truth"])
        self.assertEqual("contextual_or_dual_use", case["truth"]["deterministic_truth"])
        self.assertEqual("out_of_scope", case["truth"]["applicability"])
        self.assertEqual(2, statistics["events"])

    def test_excludes_all_prose_tool_definitions_and_result_bodies(self) -> None:
        cases, _ = MODULE.normalize_rows([row()])
        serialized = json.dumps(cases)
        for forbidden in (
            "forbidden user prose",
            "forbidden reasoning",
            "forbidden answer",
            "forbidden tool prose",
            "conversion service unavailable",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_unstructured_result_remains_unknown(self) -> None:
        messages = [
            call("weather-get", '{"city":"Boston"}'),
            result("A normal response that does not assert execution status"),
            call("units-convert", '{"value":72}'),
            result("42"),
        ]
        cases, _ = MODULE.normalize_rows([row(messages=messages)])
        self.assertEqual(["unknown", "unknown"], [event["outcome"] for event in cases[0]["payload"]["events"]])

    def test_rejects_dynamic_malformed_and_duplicate_nested_arguments(self) -> None:
        rows = [
            row(
                identity="7900c4d1-9c88-5e4b-b91a-d113dcd4d032",
                messages=[
                    {"role": "tool_call", "content": "build_call()"},
                    result("ok"),
                    call("units-convert", '{"value":1}'),
                    result("ok"),
                ],
            ),
            row(
                identity="7900c4d1-9c88-5e4b-b91a-d113dcd4d033",
                messages=[
                    call("weather-get", '{"city":"Boston","city":"Cambridge"}'),
                    result("ok"),
                    call("units-convert", '{"value":1}'),
                    result("ok"),
                ],
            ),
        ]
        cases, statistics = MODULE.normalize_rows(rows)
        self.assertEqual([], cases)
        self.assertEqual(1, statistics["quarantined_invalid_call_envelope"])
        self.assertEqual(1, statistics["quarantined_invalid_nested_arguments"])

    def test_rejects_duplicate_outer_keys_unpaired_and_interrupted_blocks(self) -> None:
        duplicate_outer = "{'name':'weather-get','name':'units-convert','arguments':'{}'}"
        rows = [
            row(
                identity="7900c4d1-9c88-5e4b-b91a-d113dcd4d034",
                messages=[
                    {"role": "tool_call", "content": duplicate_outer},
                    result("ok"),
                    call("units-convert", "{}"),
                    result("ok"),
                ],
            ),
            row(
                identity="7900c4d1-9c88-5e4b-b91a-d113dcd4d035",
                messages=[result("orphan"), call("weather-get", "{}"), result("ok")],
            ),
            row(
                identity="7900c4d1-9c88-5e4b-b91a-d113dcd4d036",
                messages=[
                    call("weather-get", "{}"),
                    {"role": "assistant", "content": "interruption"},
                    result("late"),
                    call("units-convert", "{}"),
                    result("ok"),
                ],
            ),
        ]
        cases, statistics = MODULE.normalize_rows(rows)
        self.assertEqual([], cases)
        self.assertEqual(1, statistics["quarantined_invalid_call_envelope"])
        self.assertEqual(1, statistics["quarantined_orphan_tool_result"])
        self.assertEqual(1, statistics["quarantined_interrupted_call_result_block"])

    def test_rejects_parallel_calls_without_stable_call_ids(self) -> None:
        cases, statistics = MODULE.normalize_rows(
            [
                row(
                    messages=[
                        call("weather-get", '{"city":"Boston"}'),
                        call("units-convert", '{"value":72}'),
                        result('{"success":true}'),
                        result('{"success":true}'),
                    ]
                )
            ]
        )
        self.assertEqual([], cases)
        self.assertEqual(1, statistics["quarantined_ambiguous_parallel_pairing"])

    def test_rejects_missing_result_unknown_tool_and_non_english_question(self) -> None:
        cases, statistics = MODULE.normalize_rows(
            [
                row(
                    identity="7900c4d1-9c88-5e4b-b91a-d113dcd4d037",
                    messages=[call("weather-get", "{}"), result("ok"), call("units-convert", "{}")],
                ),
                row(
                    identity="7900c4d1-9c88-5e4b-b91a-d113dcd4d038",
                    messages=[call("not-advertised", "{}"), result("ok"), call("units-convert", "{}"), result("ok")],
                ),
                row(identity="7900c4d1-9c88-5e4b-b91a-d113dcd4d039", question="删除所有文件"),
            ]
        )
        self.assertEqual([], cases)
        self.assertEqual(1, statistics["quarantined_missing_tool_result"])
        self.assertEqual(1, statistics["quarantined_unknown_or_invalid_tool"])
        self.assertEqual(1, statistics["quarantined_non_english_or_invalid_question"])

    def test_single_call_is_excluded_because_action_schema_cannot_retain_outcome(self) -> None:
        cases, statistics = MODULE.normalize_rows(
            [row(messages=[call("weather-get", "{}"), result('{"success":true}')])]
        )
        self.assertEqual([], cases)
        self.assertEqual(1, statistics["quarantined_fewer_than_two_paired_calls"])

    def test_long_sequences_are_bounded_with_overlap_and_local_offsets(self) -> None:
        messages: list[dict[str, str]] = []
        for index in range(65):
            messages.extend([call("weather-get", json.dumps({"index": index})), result("unknown")])
        cases, _ = MODULE.normalize_rows([row(messages=messages)])
        self.assertEqual([64, 9], [len(case["payload"]["events"]) for case in cases])
        self.assertEqual([0, 56], [case["strata"]["sequence_index"] for case in cases])
        self.assertTrue(all(event["offset_seconds"] <= 63 for case in cases for event in case["payload"]["events"]))

    def test_exact_payload_duplicates_are_removed_deterministically(self) -> None:
        cases, statistics = MODULE.normalize_rows(
            [row(), row(identity="7900c4d1-9c88-5e4b-b91a-d113dcd4d040")]
        )
        self.assertEqual(1, len(cases))
        self.assertEqual(1, statistics["exact_payload_duplicates_removed"])
        self.assertEqual("7900c4d1-9c88-5e4b-b91a-d113dcd4d031", cases[0]["source"]["original_id"])

    def test_select_split_rebinds_counts_and_output_digest(self) -> None:
        cases, _ = MODULE.normalize_rows(
            [
                row(),
                row(identity="7900c4d1-9c88-5e4b-b91a-d113dcd4d041"),
                row(identity="7900c4d1-9c88-5e4b-b91a-d113dcd4d042"),
            ]
        )
        target = cases[0]["split"]
        selected, manifest = MODULE.select_split(
            cases,
            {"cases": len(cases), "counts": {MODULE.DATASET_ID: len(cases)}, "output_sha256": "old"},
            target,
        )
        self.assertTrue(selected)
        self.assertTrue(all(case["split"] == target for case in selected))
        self.assertEqual(len(selected), manifest["cases"])
        self.assertEqual({MODULE.DATASET_ID: len(selected)}, manifest["counts"])
        body = "".join(MODULE.canonical_json(case) + "\n" for case in selected).encode()
        self.assertEqual(MODULE.hashlib.sha256(body).hexdigest(), manifest["output_sha256"])
        self.assertEqual(target, manifest["split"])

    def test_cases_validate_against_case_schema(self) -> None:
        cases, _ = MODULE.normalize_rows([row()])
        MODULE.validate_cases(cases, MODULE.DEFAULT_SCHEMA)

    def test_source_metadata_requires_exact_revision_config_and_shard_names(self) -> None:
        metadata = {
            "config": "SFT",
            "files": {
                name: {"bytes": index + 1, "sha256": f"{index + 1:064x}"}
                for index, name in enumerate(MODULE.SOURCE_FILES)
            },
            "revision": MODULE.SOURCE_REVISION,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source-metadata.json"
            path.write_text(json.dumps(metadata), encoding="utf-8")
            identities = MODULE.parse_source_metadata(path)
            self.assertEqual(set(MODULE.SOURCE_FILES), set(identities))
            metadata["revision"] = "0" * 40
            path.write_text(json.dumps(metadata), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "pinned SFT revision"):
                MODULE.parse_source_metadata(path)


if __name__ == "__main__":
    unittest.main()
