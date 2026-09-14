#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from benchmarks.scripts.benchmark_merge_corpora import normalization_inputs
from benchmarks.scripts.benchmark_normalize import write_outputs


def structured_action(case_id: str, tool_name: str, value: int) -> dict[str, object]:
    return {
        "id": case_id,
        "surface": "action",
        "payload": {
            "direction": "tool_call",
            "dialect": "none",
            "tool_name": tool_name,
            "args": {"value": value},
        },
        "source": {"dataset": "example/structured-actions"},
        "truth": {"source_truth": "benign", "expected_disposition": "allow"},
    }


class MergeCorporaTest(unittest.TestCase):
    def test_structured_actions_without_command_use_the_full_payload_identity(self) -> None:
        rows = [
            structured_action("case-1", "read_file", 1),
            structured_action("case-2", "write_file", 2),
            structured_action("case-3", "read_file", 1),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "cases.jsonl"
            manifest = root / "manifest.json"
            counts: dict[str, int] = {}

            write_outputs(
                output,
                manifest,
                ["example/structured-actions"],
                rows,
                counts,
            )

            merged = [json.loads(line) for line in output.read_text().splitlines()]
            metadata = json.loads(manifest.read_text())

        self.assertEqual(2, len(merged))
        self.assertEqual(
            {"read_file", "write_file"},
            {row["payload"]["tool_name"] for row in merged},
        )
        self.assertEqual(1, metadata["exact_payload_duplicates_removed"])

    def test_input_metadata_is_path_independent_and_content_deduplicated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "z-last.jsonl"
            duplicate = root / "a-first-copy.jsonl"
            second = root / "middle.jsonl"
            first.write_bytes(b'{"id":"same"}\n')
            duplicate.write_bytes(first.read_bytes())
            second.write_bytes(b'{"id":"other"}\n')

            left = normalization_inputs([first, second, duplicate])
            right = normalization_inputs([second, duplicate, first])

        self.assertEqual(left, right)
        self.assertEqual(2, len(left))
        self.assertEqual(
            sorted(left, key=lambda item: (item["sha256"], item["bytes"])),
            left,
        )


if __name__ == "__main__":
    unittest.main()
