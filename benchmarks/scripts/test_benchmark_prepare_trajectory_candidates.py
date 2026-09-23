# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from benchmarks.scripts import benchmark_prepare_trajectory_candidates as prepare


def case(
    case_id: str,
    *,
    split_group: str = "1" * 24,
    trajectory_id: str = "2" * 24,
    split: str = "development",
    language: str = "en",
    sequence: int = 0,
    call: int = 0,
    surface: str = "action",
    contextual: bool = True,
    payload: dict[str, Any] | None = None,
    dataset: str = "public/example",
    redistribution: str = "download-only",
) -> dict[str, Any]:
    categories = ["bounded_chain"] if contextual else ["benign_candidate"]
    return {
        "schema_version": "1",
        "id": case_id,
        "source": {
            "dataset": dataset,
            "revision": "public revision",
            "original_id": "/Users/local-person/private/source.jsonl",
            "license": "Apache-2.0",
            "redistribution": redistribution,
        },
        "split": split,
        "surface": surface,
        "payload": payload
        or {
            "direction": "tool_call",
            "tool_name": "read_file",
            "args": {"path": "/workspace/example.txt"},
        },
        "truth": {
            "source_truth": "unknown",
            "deterministic_truth": "contextual_or_dual_use" if contextual else "benign",
            "applicability": "out_of_scope" if contextual else "in_scope",
            "expected_disposition": "detect_only" if contextual else "allow",
            "categories": categories,
        },
        "strata": {
            "language": language,
            "split_group": split_group,
            "trajectory_id": trajectory_id,
            "sequence_index": sequence,
            "call_index": call,
        },
    }


class PrepareTrajectoryCandidatesTest(unittest.TestCase):
    def test_filters_split_language_and_non_public_sources(self) -> None:
        rows = [
            case("kept"),
            case("validation", split="validation"),
            case("spanish", language="es"),
            case("private", dataset="private/codex-sessions"),
            case("manual", redistribution="manual"),
        ]

        candidates, stats = prepare.prepare_candidates(rows)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["split"], "development")
        self.assertEqual(stats["excluded_non_development"], 1)
        self.assertEqual(stats["excluded_non_english"], 1)
        self.assertEqual(stats["excluded_non_public_source"], 2)

    def test_grouping_uses_split_group_and_trajectory_identity(self) -> None:
        rows = [
            case("group-a-predecessor", contextual=False, sequence=0, call=0),
            case("group-a-current", sequence=1, call=1),
            case("group-b-current", split_group="3" * 24, sequence=2, call=2),
        ]

        candidates, _ = prepare.prepare_candidates(rows)

        self.assertEqual(len(candidates), 2)
        self.assertEqual(len(candidates[0]["events"]), 2)
        self.assertEqual(len(candidates[1]["events"]), 1)
        self.assertNotEqual(candidates[0]["trajectory_group"], candidates[1]["trajectory_group"])

    def test_current_event_has_at_most_eight_predecessors(self) -> None:
        rows = [
            case(
                f"case-{index}",
                contextual=index == 11,
                sequence=index,
                call=index,
                payload={
                    "direction": "tool_call",
                    "tool_name": "shell",
                    "args": {"command_number": index},
                },
            )
            for index in range(12)
        ]

        candidates, _ = prepare.prepare_candidates(rows)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(len(candidates[0]["events"]), 9)
        self.assertEqual(candidates[0]["events"][0]["arguments"]["command_number"], 3)
        self.assertEqual(candidates[0]["target_event_index"], 8)

    def test_character_and_element_limits_remove_oldest_predecessors_or_skip(self) -> None:
        rows = [
            case(
                "predecessor",
                contextual=False,
                sequence=0,
                call=0,
                payload={"tool_name": "read_file", "args": {"content": "x" * 300}},
            ),
            case(
                "current",
                sequence=1,
                call=1,
                payload={"tool_name": "send", "args": {"destination": "https://example.test"}},
            ),
        ]

        candidates, stats = prepare.prepare_candidates(rows, max_total_chars=250)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(len(candidates[0]["events"]), 1)
        self.assertEqual(stats["predecessors_removed_for_limits"], 1)

        candidates, stats = prepare.prepare_candidates(rows, max_total_elements=2)
        self.assertEqual(candidates, [])
        self.assertEqual(stats["excluded_current_event_over_limit"], 1)

    def test_stateful_projection_strips_provenance_and_unrelated_case_text(self) -> None:
        stateful = case(
            "stateful",
            surface="stateful",
            sequence=0,
            call=1,
            payload={
                "direction": "tool_call",
                "events": [
                    {
                        "tool_name": "read_file",
                        "args": {
                            "path": "/Users/local-person/project/item.txt",
                            "metadata": {"source_path": "/private/source"},
                            "sha256": "a" * 64,
                        },
                        "outcome": "succeeded",
                    },
                    {
                        "tool_name": "send",
                        "args": {"destination": "https://outside.example"},
                        "outcome": "succeeded",
                    },
                ],
                "args": {"prompt": "unrelated source prose"},
            },
        )

        candidates, _ = prepare.prepare_candidates([stateful])
        serialized = prepare.canonical_json(candidates)

        self.assertEqual(len(candidates), 1)
        self.assertNotIn("source", candidates[0])
        self.assertNotIn("truth", candidates[0])
        self.assertNotIn("local-person", serialized)
        self.assertNotIn("unrelated source prose", serialized)
        self.assertNotIn("a" * 64, serialized)
        self.assertEqual(candidates[0]["events"][0]["arguments"]["path"], "<local-home>/project/item.txt")
        self.assertEqual(candidates[0]["events"][0]["result"], {"outcome": "succeeded"})

    def test_stateful_windows_take_precedence_over_action_reconstruction(self) -> None:
        rows = [
            case("action-predecessor", contextual=False, sequence=0, call=0),
            case("action-current", sequence=1, call=1),
            case(
                "stateful-current",
                surface="stateful",
                sequence=1,
                call=1,
                payload={
                    "events": [
                        {"tool_name": "read_file", "args": {"path": "/workspace/item"}},
                        {"tool_name": "send", "args": {"destination": "https://example.test"}},
                    ]
                },
            ),
        ]

        candidates, stats = prepare.prepare_candidates(rows)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(len(candidates[0]["events"]), 2)
        self.assertEqual(stats["excluded_action_group_with_stateful"], 1)

    def test_secret_values_are_redacted_consistently_across_result_and_argument(self) -> None:
        sensitive_value = "provided by the secret store"
        stateful = case(
            "secret-lineage",
            surface="stateful",
            sequence=0,
            call=1,
            payload={
                "events": [
                    {
                        "tool_name": "read_secret",
                        "args": {"name": "deployment credential"},
                        "result": {"token": sensitive_value},
                        "outcome": "succeeded",
                    },
                    {
                        "tool_name": "authenticate",
                        "args": {
                            "token": sensitive_value,
                            "credentials": {"password": "another raw value"},
                        },
                        "outcome": "succeeded",
                    },
                ]
            },
        )

        candidates, _ = prepare.prepare_candidates([stateful])
        serialized = prepare.canonical_json(candidates)

        self.assertNotIn(sensitive_value, serialized)
        self.assertNotIn("another raw value", serialized)
        first = candidates[0]["events"][0]["result"]["data"]["token"]
        second = candidates[0]["events"][1]["arguments"]["token"]
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("<redacted-secret-"))

    def test_output_is_deterministic_for_input_order(self) -> None:
        rows = [
            case("later", sequence=1, call=1),
            case("earlier", contextual=False, sequence=0, call=0),
            case("other", split_group="3" * 24, trajectory_id="4" * 24),
        ]

        first, first_stats = prepare.prepare_candidates(rows)
        second, second_stats = prepare.prepare_candidates(reversed(rows))

        self.assertEqual(prepare.canonical_json(first), prepare.canonical_json(second))
        self.assertEqual(first_stats, second_stats)

    def test_dry_run_prints_summary_without_writing_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "cases.jsonl"
            output_path = root / "candidates.jsonl"
            input_path.write_text(prepare.canonical_json(case("candidate")) + "\n", encoding="utf-8")
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                result = prepare.main(
                    ["--input", str(input_path), "--output", str(output_path), "--dry-run"]
                )

            summary = json.loads(stdout.getvalue())
            self.assertEqual(result, 0)
            self.assertFalse(output_path.exists())
            self.assertTrue(summary["dry_run"])
            self.assertEqual(summary["statistics"]["candidate_count"], 1)


if __name__ == "__main__":
    unittest.main()
