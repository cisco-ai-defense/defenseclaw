#!/usr/bin/env python3

import importlib.util
import json
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("benchmark_normalize_open_swe_traces.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_open_swe_traces", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


class NormalizeOpenSWETracesTests(unittest.TestCase):
    @staticmethod
    def row(**overrides: object) -> dict[str, object]:
        row: dict[str, object] = {
            "trajectory_id": "t1",
            "language": "python",
            "resolved": 1,
            "messages": [
                {
                    "role": "assistant",
                    "content": "excluded assistant response",
                    "reasoning_content": "excluded private reasoning",
                    "tool_calls": [
                        {"id": "call-other", "function": {"name": "other", "arguments": "{}"}},
                        {
                            "id": "call-bash",
                            "function": {"name": "bash", "arguments": '{"command":"pytest -q"}'},
                        },
                    ],
                },
                {"role": "tool", "content": "excluded tool result", "tool_call_id": "call-bash"},
            ],
        }
        row.update(overrides)
        return row

    def test_extracts_only_exact_bash_arguments(self) -> None:
        cases, manifest = MODULE.normalize([self.row()], "revision")
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["payload"]["args"], {"command": "pytest -q"})
        self.assertEqual(cases[0]["truth"]["deterministic_truth"], "benign")
        self.assertEqual(cases[0]["source"]["original_id"], "trajectory:t1#call-1")
        self.assertEqual(cases[0]["strata"]["language"], "python")
        self.assertEqual(cases[0]["strata"]["call_index"], 1)
        serialized = json.dumps(cases)
        self.assertNotIn("excluded assistant response", serialized)
        self.assertNotIn("excluded private reasoning", serialized)
        self.assertNotIn("excluded tool result", serialized)
        self.assertEqual(manifest["source_tool_calls"], 2)
        self.assertEqual(manifest["skipped"], {"non_bash_call": 1})
        self.assertEqual(manifest["required_resolved_status"], 1)
        self.assertEqual(manifest["supported_languages"], sorted(MODULE.SUPPORTED_LANGUAGES))

    def test_excludes_unresolved_unknown_trajectory(self) -> None:
        cases, manifest = MODULE.normalize([self.row(resolved=-1)], "revision")
        self.assertEqual(cases, [])
        self.assertEqual(manifest["skipped"], {"unresolved_trajectory": 1})
        self.assertEqual(manifest["source_tool_calls"], 2)

    def test_excludes_failed_trajectory(self) -> None:
        cases, manifest = MODULE.normalize([self.row(resolved=0)], "revision")
        self.assertEqual(cases, [])
        self.assertEqual(manifest["skipped"], {"failed_trajectory": 1})

    def test_excludes_unsupported_language(self) -> None:
        cases, manifest = MODULE.normalize([self.row(language="ruby")], "revision")
        self.assertEqual(cases, [])
        self.assertEqual(manifest["skipped"], {"unsupported_language": 1})

    def test_excludes_missing_language(self) -> None:
        row = self.row()
        del row["language"]
        cases, manifest = MODULE.normalize([row], "revision")
        self.assertEqual(cases, [])
        self.assertEqual(manifest["skipped"], {"missing_language": 1})

    def test_excludes_missing_status(self) -> None:
        row = self.row()
        del row["resolved"]
        cases, manifest = MODULE.normalize([row], "revision")
        self.assertEqual(cases, [])
        self.assertEqual(manifest["skipped"], {"missing_resolved_status": 1})

    def test_excludes_ambiguous_status_values(self) -> None:
        cases, manifest = MODULE.normalize(
            [self.row(trajectory_id="bool", resolved=True), self.row(trajectory_id="string", resolved="1")],
            "revision",
        )
        self.assertEqual(cases, [])
        self.assertEqual(manifest["skipped"], {"ambiguous_resolved_status": 2})

    def test_excludes_unsupported_status_integer(self) -> None:
        cases, manifest = MODULE.normalize([self.row(resolved=2)], "revision")
        self.assertEqual(cases, [])
        self.assertEqual(manifest["skipped"], {"unsupported_resolved_status": 1})

    def test_accepts_every_documented_language_exactly(self) -> None:
        rows = [
            self.row(trajectory_id=f"t-{language}", language=language)
            for language in MODULE.SUPPORTED_LANGUAGES
        ]
        cases, manifest = MODULE.normalize(rows, "revision")
        self.assertEqual(len(cases), len(MODULE.SUPPORTED_LANGUAGES))
        self.assertEqual({case["strata"]["language"] for case in cases}, MODULE.SUPPORTED_LANGUAGES)
        self.assertEqual(manifest["skipped"], {"non_bash_call": len(MODULE.SUPPORTED_LANGUAGES)})

    def test_rejects_open_and_oversized_argument_shapes(self) -> None:
        rows = [{
            "trajectory_id": "t2",
            "language": "go",
            "resolved": 1,
            "messages": [{"tool_calls": [
                {"function": {"name": "bash", "arguments": {"command": "pwd", "cwd": "/tmp"}}},
                {"function": {"name": "bash", "arguments": {"command": "x" * 70000}}},
            ]}],
        }]
        cases, manifest = MODULE.normalize(rows, "revision")
        self.assertEqual(cases, [])
        self.assertEqual(manifest["skipped"], {"invalid_arguments": 1, "oversized_arguments": 1})


if __name__ == "__main__":
    unittest.main()
