#!/usr/bin/env python3

import importlib.util
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("benchmark_normalize_open_swe_traces.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_open_swe_traces", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


class NormalizeOpenSWETracesTests(unittest.TestCase):
    def test_extracts_only_exact_bash_arguments(self) -> None:
        rows = [{"trajectory_id": "t1", "language": "python", "resolved": 1, "messages": [
            {"role": "assistant", "tool_calls": [
                {"function": {"name": "bash", "arguments": '{"command":"pytest -q"}'}},
                {"function": {"name": "other", "arguments": "{}"}},
            ]},
            {"role": "tool", "content": "ignored output"},
        ]}]
        cases, manifest = MODULE.normalize(rows, "revision")
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["payload"]["args"], {"command": "pytest -q"})
        self.assertEqual(cases[0]["truth"]["deterministic_truth"], "benign")
        self.assertEqual(manifest["source_tool_calls"], 2)
        self.assertEqual(manifest["skipped"], {"non_bash_call": 1})

    def test_rejects_open_and_oversized_argument_shapes(self) -> None:
        rows = [{"trajectory_id": "t2", "messages": [{"tool_calls": [
            {"function": {"name": "bash", "arguments": {"command": "pwd", "cwd": "/tmp"}}},
            {"function": {"name": "bash", "arguments": {"command": "x" * 70000}}},
        ]}]}]
        cases, manifest = MODULE.normalize(rows, "revision")
        self.assertEqual(cases, [])
        self.assertEqual(manifest["skipped"], {"invalid_arguments": 1, "oversized_arguments": 1})


if __name__ == "__main__":
    unittest.main()
