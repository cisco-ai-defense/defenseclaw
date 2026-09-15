#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import importlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
adapter = importlib.import_module("benchmark_normalize_orchard_swe")


def orchard_row(
    *,
    instance_id: str = "owner__repo-1",
    sample_idx: int = 0,
    verify_status: str = "resolved",
    commands: tuple[tuple[str, int], ...] = (("git status --short", 0), ("pytest -q", 1)),
) -> dict[str, object]:
    messages: list[dict[str, object]] = [
        {"role": "user", "content": "free-form task text that must not survive", "tool_calls": []}
    ]
    for index, (command, return_code) in enumerate(commands):
        call_id = f"call-{index}"
        messages.extend(
            [
                {
                    "role": "assistant",
                    "content": "private reasoning that must not survive",
                    "tool_calls": [
                        {
                            "id": call_id,
                            "type": "function",
                            "function": {
                                "name": "bash",
                                "arguments": json.dumps(
                                    {
                                        "command": command,
                                        "password": "fixture-sensitive-value",
                                        "nested": {"safe": "kept"},
                                    }
                                ),
                            },
                        }
                    ],
                },
                {
                    "role": "tool",
                    "content": f"<returncode>{return_code}</returncode>\n<output>discard me</output>",
                    "tool_call_id": call_id,
                    "tool_calls": [],
                },
            ]
        )
    return {
        "tools": json.dumps(
            [
                {
                    "type": "function",
                    "function": {
                        "name": "bash",
                        "description": "Execute a bash command",
                        "parameters": {"type": "object"},
                    },
                }
            ]
        ),
        "messages": messages,
        "metadata": json.dumps(
            {
                "instance_id": instance_id,
                "sample_idx": sample_idx,
                "source": "rebench-M2.5",
                "model": "teacher",
                "repo": "owner/repo",
                "verify_status": verify_status,
            }
        ),
    }


class OrchardSweAdapterTests(unittest.TestCase):
    def test_resolved_projection_preserves_calls_and_explicit_outcomes(self) -> None:
        cases, manifest = adapter.normalize([orchard_row()])
        self.assertEqual(manifest["counts"]["selected_trajectories"], 1)
        self.assertEqual(manifest["counts"]["action_cases"], 2)
        self.assertEqual(manifest["counts"]["stateful_cases"], 1)
        actions = [case for case in cases if case["surface"] == "action"]
        stateful = [case for case in cases if case["surface"] == "stateful"][0]
        self.assertEqual(actions[0]["payload"]["tool_name"], "bash")
        self.assertEqual(actions[0]["payload"]["args"]["command"], "git status --short")
        self.assertEqual(actions[0]["payload"]["args"]["nested"], {"safe": "kept"})
        self.assertEqual(actions[0]["payload"]["args"]["password"], "<redacted>")
        self.assertEqual([event["outcome"] for event in stateful["payload"]["events"]], ["succeeded", "failed"])
        serialized = json.dumps(cases)
        self.assertNotIn("free-form task", serialized)
        self.assertNotIn("private reasoning", serialized)
        self.assertNotIn("discard me", serialized)
        self.assertNotIn("fixture-sensitive-value", serialized)
        self.assertTrue(all(case["truth"]["source_truth"] == "benign" for case in cases))
        self.assertTrue(all(case["truth"]["expected_disposition"] == "allow" for case in cases))

    def test_unresolved_and_non_english_trajectories_are_excluded(self) -> None:
        unresolved = orchard_row(verify_status="unresolved")
        non_english = orchard_row(instance_id="other")
        metadata = json.loads(str(non_english["metadata"]))
        metadata["language"] = "fr"
        non_english["metadata"] = json.dumps(metadata)
        cases, manifest = adapter.normalize([unresolved, non_english])
        self.assertEqual(cases, [])
        self.assertEqual(manifest["skipped"], {"non_english": 1, "unresolved": 1})
        self.assertEqual(manifest["cases"], 0)

    def test_windows_are_bounded_to_eight_and_ordered(self) -> None:
        commands = tuple((f"printf {index}", 0) for index in range(10))
        cases, _ = adapter.normalize([orchard_row(commands=commands)])
        windows = [case["payload"]["events"] for case in cases if case["surface"] == "stateful"]
        self.assertEqual([len(window) for window in windows], [8, 2])
        self.assertEqual([event["command"] for event in windows[0]], [f"printf {i}" for i in range(8)])
        self.assertEqual([event["offset_seconds"] for event in windows[1]], [8, 9])

    def test_missing_per_call_return_code_is_preserved_as_unknown(self) -> None:
        row = orchard_row(commands=(("git diff", 0), ("git status", 0)))
        row["messages"][2]["content"] = "plain OpenHands observation without status metadata"
        cases, manifest = adapter.normalize([row])
        window = [case for case in cases if case["surface"] == "stateful"][0]
        self.assertEqual(window["payload"]["events"][0]["outcome"], "unknown")
        self.assertEqual(manifest["counts"]["outcome_unknown"], 1)

    def test_sampling_partition_and_cap_are_reproducible(self) -> None:
        rows = [orchard_row(instance_id=f"repo-{index}") for index in range(12)]
        first, first_manifest = adapter.normalize(rows, sample_modulus=3, sample_remainder=1, max_trajectories=2)
        second, second_manifest = adapter.normalize(rows, sample_modulus=3, sample_remainder=1, max_trajectories=2)
        self.assertEqual(first, second)
        self.assertEqual(first_manifest, second_manifest)
        self.assertLessEqual(first_manifest["counts"].get("selected_trajectories", 0), 2)
        self.assertEqual(adapter.sample_bucket("stable-key", 97), adapter.sample_bucket("stable-key", 97))

    def test_malformed_or_unbounded_arguments_are_rejected(self) -> None:
        malformed = orchard_row()
        malformed["messages"][1]["tool_calls"][0]["function"]["arguments"] = '{"command":"x","command":"y"}'
        oversized = orchard_row(instance_id="oversized")
        oversized["messages"][1]["tool_calls"][0]["function"]["arguments"] = json.dumps(
            {"command": "x" * (adapter.MAX_STRING_BYTES + 1)}
        )
        cases, manifest = adapter.normalize([malformed, oversized])
        self.assertEqual(cases, [])
        self.assertEqual(manifest["skipped"]["invalid_arguments_json"], 1)
        self.assertEqual(manifest["skipped"]["arguments_string_too_large"], 1)

    def test_json_shards_stream_and_reject_malformed_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jsonl = root / "rows.jsonl"
            jsonl.write_text(json.dumps(orchard_row()) + "\n", encoding="utf-8")
            array = root / "rows.json"
            array.write_text(json.dumps([orchard_row(instance_id="array")]), encoding="utf-8")
            self.assertEqual(len(list(adapter.source_rows(jsonl))), 1)
            self.assertEqual(len(list(adapter.source_rows(array))), 1)
            malformed = root / "malformed.jsonl"
            malformed.write_text('{"metadata": 1,,}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "malformed JSON record"):
                list(adapter.source_rows(malformed))

    def test_parquet_is_streamed_in_batches_when_pyarrow_is_available(self) -> None:
        try:
            import pyarrow as pa
            import pyarrow.parquet as pq
        except ImportError:
            self.skipTest("pyarrow not installed")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.parquet"
            row = orchard_row()
            table = pa.Table.from_pylist([row])
            pq.write_table(table, path)
            loaded = list(adapter.parquet_rows(path))
            self.assertEqual(len(loaded), 1)
            self.assertEqual(json.loads(loaded[0]["metadata"])["verify_status"], "resolved")

    def test_projection_validates_against_case_v1_and_revision_is_pinned(self) -> None:
        cases, _ = adapter.normalize([orchard_row()])
        adapter.validate_cases(cases)
        with self.assertRaisesRegex(ValueError, "pinned source revision"):
            adapter.normalize([orchard_row()], revision="main")

    def test_cli_streams_output_and_records_input_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "rows.jsonl"
            source.write_text(
                json.dumps(orchard_row()) + "\n" + json.dumps(orchard_row(verify_status="unresolved")) + "\n",
                encoding="utf-8",
            )
            output = root / "cases.jsonl"
            manifest_path = root / "manifest.json"
            args = argparse.Namespace(
                input=[source],
                output=output,
                manifest=manifest_path,
                schema=adapter.DEFAULT_SCHEMA,
                revision=adapter.SOURCE_REVISION,
                sample_modulus=1,
                sample_remainder=0,
                max_trajectories=1,
            )
            manifest = adapter.run(args)
            self.assertEqual(manifest["counts"]["selected_trajectories"], 1)
            self.assertEqual(manifest["skipped"]["unresolved"], 1)
            self.assertEqual(len(manifest["input_files"][0]["sha256"]), 64)
            self.assertTrue(output.read_text(encoding="utf-8").endswith("\n"))
            self.assertEqual(json.loads(manifest_path.read_text())["output"]["sha256"], manifest["output"]["sha256"])


if __name__ == "__main__":
    unittest.main()
