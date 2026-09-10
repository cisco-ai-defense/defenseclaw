#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
module = importlib.import_module("benchmark_add_terminalbench_context")


class TerminalBenchContextTests(unittest.TestCase):
    def test_contextualize_copies_context_without_mutating_input(self) -> None:
        row = {
            "id": "terminalbench/case",
            "source": {"dataset": module.DATASET},
            "strata": {"split_group": "family"},
            "payload": {"events": [{"tool_name": "shell", "args": {"cmd": "pwd"}}]},
        }
        output = module.contextualize([row], {"family": "authorized task"})
        self.assertEqual(output[0]["payload"]["content"], "authorized task")
        self.assertNotIn("content", row["payload"])

    def test_rejects_non_terminalbench_rows(self) -> None:
        with self.assertRaisesRegex(ValueError, "not a TerminalBench case"):
            module.contextualize(
                [{"id": "other", "source": {"dataset": "other"}, "strata": {}, "payload": {}}],
                {},
            )


if __name__ == "__main__":
    unittest.main()
