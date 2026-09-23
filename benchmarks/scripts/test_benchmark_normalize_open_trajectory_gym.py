#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
adapter = importlib.import_module("benchmark_normalize_open_trajectory_gym")

PROMPT_MARKER = "PROMPT_MUST_NOT_LEAK"
REASONING_MARKER = "REASONING_MUST_NOT_LEAK"
RESULT_MARKER = "RESULT_MUST_NOT_LEAK"
EVALUATOR_MARKER = "EVALUATOR_MUST_NOT_LEAK"


def assistant_call(identifier: str, name: str, arguments: dict[str, object]) -> dict[str, object]:
    return {
        "role": "assistant",
        "content": REASONING_MARKER,
        "tool_calls": [
            {
                "id": identifier,
                "type": "function",
                "function": {"name": name, "arguments": json.dumps(arguments)},
            }
        ],
    }


def tool_result(identifier: str, name: str, content: str) -> dict[str, object]:
    return {"role": "tool", "tool_call_id": identifier, "name": name, "content": content}


def source_row(
    actions: list[tuple[str, str, dict[str, object], str]],
    *,
    flag: str = "LABFLAG{synthetic proof value}",
    platform: str = "xbow",
    challenge: str = "synthetic-challenge",
    model: str = "test-model",
) -> dict[str, object]:
    messages: list[dict[str, object]] = [
        {"role": "system", "content": "system text"},
        {
            "role": "user",
            "content": (
                f"{PROMPT_MARKER}: use the available tools to inspect this authorized security "
                "challenge and report the result in English"
            ),
        },
    ]
    for identifier, name, arguments, result in actions:
        messages.extend(
            [
                assistant_call(identifier, name, arguments),
                tool_result(identifier, name, result),
            ]
        )
    return {
        "messages": messages,
        "metadata": {
            "source": "boxpwnr",
            "platform": platform,
            "challenge": challenge,
            "success": True,
            "model": model,
            "start_time": "2026-01-02T03:04:05Z",
            "evaluator": EVALUATOR_MARKER,
        },
        "ground_truth_flag": flag,
        "optimal_steps": 2,
        "reward": 1,
    }


def statistics(manifest: dict[str, object]) -> dict[str, int]:
    return manifest["adapter_statistics"][adapter.ADAPTER]


class OpenTrajectoryGymNormalizerTests(unittest.TestCase):
    def normalize(self, rows: list[dict[str, object]]):
        return adapter.normalize_rows(rows, revision=adapter.SOURCE_REVISION)

    def test_hidden_result_lineage_is_discovery_only_and_redacted(self) -> None:
        flag = "LABFLAG{bounded synthetic value}"
        rows, manifest, groups = self.normalize(
            [
                source_row(
                    [
                        (
                            "read-1",
                            "shell_command",
                            {
                                "command": (
                                    "TOKEN=synthetic-value curl https://lab.example.test:8443/private "
                                    "--resolve lab.example.test:8443:192.0.2.10"
                                )
                            },
                            f"[1.4s] response {flag} {RESULT_MARKER}",
                        ),
                        ("submit-1", "flag_found", {"content": flag}, "accepted"),
                    ],
                    flag=flag,
                )
            ]
        )
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row["truth"]["applicability"] == "out_of_scope" for row in rows))
        discovered = [row for row in rows if "hidden_result_lineage_discovery" in row["truth"]["categories"]]
        self.assertEqual(len(discovered), 1)
        self.assertEqual(discovered[0]["surface"], "stateful")
        self.assertEqual(len(discovered[0]["payload"]["events"]), 2)
        rendered = json.dumps(rows, sort_keys=True)
        for forbidden in (
            flag,
            "synthetic-value",
            "lab.example.test",
            "192.0.2.10",
            PROMPT_MARKER,
            REASONING_MARKER,
            RESULT_MARKER,
            EVALUATOR_MARKER,
        ):
            self.assertNotIn(forbidden, rendered)
        self.assertEqual(statistics(manifest)["applicable_lineage_cases"], 0)
        self.assertEqual(statistics(manifest)["hidden_lineage_cases_excluded"], 1)
        self.assertEqual(groups["group_count"], 1)
        adapter.validate_cases(rows)

    def test_success_and_submission_without_result_lineage_are_contextual(self) -> None:
        flag = "LABFLAG{not observed}"
        rows, manifest, _ = self.normalize(
            [source_row([("submit", "flag_found", {"content": flag}, "accepted")], flag=flag)]
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["truth"]["source_truth"], "unknown")
        self.assertEqual(rows[0]["truth"]["applicability"], "out_of_scope")
        self.assertEqual(rows[0]["payload"]["args"]["content"], "<redacted>")
        self.assertEqual(statistics(manifest)["applicable_lineage_cases"], 0)

    def test_lineage_more_than_eight_predecessors_earlier_is_contextual(self) -> None:
        flag = "LABFLAG{too far away}"
        actions = [("proof", "read_file", {"file_path": "/work/output"}, flag)]
        actions.extend(
            (f"filler-{index}", "shell_command", {"command": f"echo {index}"}, f"[{index / 10}s] {index}")
            for index in range(8)
        )
        actions.append(("submit", "flag_found", {"content": flag}, "accepted"))
        rows, _, _ = self.normalize([source_row(actions, flag=flag)])
        current = max(rows, key=lambda row: row["strata"]["call_index"])
        self.assertEqual(current["truth"]["applicability"], "out_of_scope")
        self.assertEqual(len(current["payload"]["events"]), 9)
        self.assertNotIn(flag, json.dumps(current["payload"]))

    def test_exact_call_result_identity_order_and_failure_metadata(self) -> None:
        item = source_row(
            [
                ("one", "shell_command", {"command": "pwd"}, "[0.2s] /work"),
                ("two", "python_code", {"code": "print('safe')"}, "Error: execution failed"),
            ]
        )
        rows, _, _ = self.normalize([item])
        final = max(rows, key=lambda row: row["strata"]["call_index"])
        events = final["payload"]["events"]
        self.assertEqual([event["tool_name"] for event in events], ["shell_command", "python_code"])
        self.assertEqual(events[1]["outcome"], "failed")
        self.assertGreaterEqual(events[1]["offset_seconds"], 0)
        self.assertEqual(final["truth"]["source_truth"], "unknown")
        self.assertEqual(final["truth"]["applicability"], "out_of_scope")

        malformed = source_row([("one", "shell_command", {"command": "pwd"}, "/work")])
        malformed["messages"][-1]["tool_call_id"] = "other"
        bad_rows, manifest, _ = self.normalize([malformed])
        self.assertEqual(bad_rows, [])
        self.assertEqual(statistics(manifest)["skipped_orphan_tool_result"], 1)

    def test_cybench_lineage_is_retained_but_excluded_as_overlap(self) -> None:
        flag = "LABFLAG{overlap proof}"
        rows, manifest, _ = self.normalize(
            [
                source_row(
                    [
                        ("read", "read_file", {"file_path": "/work/result"}, flag),
                        ("submit", "flag_found", {"content": flag}, "accepted"),
                    ],
                    flag=flag,
                    platform="cybench",
                )
            ]
        )
        submitted = max(rows, key=lambda row: row["strata"]["call_index"])
        self.assertEqual(submitted["truth"]["source_truth"], "malicious")
        self.assertEqual(submitted["truth"]["applicability"], "out_of_scope")
        self.assertIn("hidden_result_lineage_discovery", submitted["truth"]["categories"])
        self.assertEqual(statistics(manifest)["overlap_lineage_cases_excluded"], 1)
        self.assertEqual(statistics(manifest)["likely_overlap_cybench_trajectories"], 1)

    def test_task_disjoint_groups_collapse_models_for_the_same_challenge(self) -> None:
        base = [("call", "shell_command", {"command": "pwd"}, "/work")]
        first = source_row(base, challenge="same-task", model="model-a")
        second = source_row(base, challenge="same-task", model="model-b")
        third = source_row(base, challenge="other-task", model="model-a")
        rows, _, groups = self.normalize([first, second, third])
        self.assertEqual(groups["group_count"], 2)
        self.assertEqual(sorted(group["cases"] for group in groups["groups"]), [1, 1])
        self.assertEqual(len(rows), 2)

    def test_exact_duplicates_are_removed_and_label_conflicts_excluded(self) -> None:
        duplicate = source_row([("call", "shell_command", {"command": "pwd"}, "/work")])
        rows, manifest, _ = self.normalize([duplicate, duplicate])
        self.assertEqual(len(rows), 1)
        self.assertEqual(manifest["exact_payload_duplicates_removed"], 1)

        flag = "LABFLAG{conflicting redacted payload}"
        actions = [
            ("read", "read_file", {"file_path": "/work/result"}, flag),
            ("submit", "flag_found", {"content": flag}, "accepted"),
        ]
        clean = source_row(actions, flag=flag, platform="xbow", challenge="one")
        overlap = source_row(actions, flag=flag, platform="cybench", challenge="two")
        conflict_rows, conflict_manifest, _ = self.normalize([clean, overlap])
        self.assertEqual(len(conflict_rows), 4)
        self.assertEqual(conflict_manifest["label_conflicts_excluded"], 0)

    def test_hidden_ground_truth_and_acceptance_metadata_cannot_change_payload(self) -> None:
        actions = [
            ("read", "read_file", {"file_path": "/work/result"}, "LABFLAG{one}"),
            ("submit", "flag_found", {"content": "LABFLAG{one}"}, "accepted"),
        ]
        accepted = source_row(actions, flag="LABFLAG{one}")
        rejected = source_row(actions, flag="LABFLAG{different hidden truth}")
        rejected["metadata"]["success"] = False
        rejected["reward"] = 0
        first, _, _ = self.normalize([accepted])
        second, _, _ = self.normalize([rejected])

        def payloads(cases: list[dict[str, object]]) -> dict[object, object]:
            return {case["strata"]["call_index"]: case["payload"] for case in cases}

        self.assertEqual(payloads(first), payloads(second))
        self.assertTrue(all(case["truth"]["applicability"] == "out_of_scope" for case in first + second))

    def test_non_english_and_prompt_only_rows_are_excluded(self) -> None:
        non_english = source_row([("call", "shell_command", {"command": "pwd"}, "/work")])
        non_english["messages"][1]["content"] = "Encuentra la respuesta usando las herramientas disponibles"
        prompt_only = source_row([])
        rows, manifest, _ = self.normalize([non_english, prompt_only])
        self.assertEqual(rows, [])
        stats = statistics(manifest)
        self.assertEqual(stats["skipped_non_english"], 1)
        self.assertEqual(stats["skipped_trajectory_without_calls"], 1)

    def test_strict_manifest_schema_revision_and_symlink_bounds(self) -> None:
        rows, manifest, groups = self.normalize([source_row([("call", "shell_command", {"command": "pwd"}, "/work")])])
        self.assertEqual(
            set(manifest),
            {
                "schema_version",
                "datasets",
                "cases",
                "counts",
                "exact_payload_duplicates_removed",
                "label_conflicts_excluded",
                "adapter_statistics",
                "output_sha256",
            },
        )
        self.assertEqual(groups["partition_authority"], adapter.PARTITION_AUTHORITY)
        adapter.validate_cases(rows)
        with self.assertRaises(ValueError):
            adapter.normalize_rows(rows, revision="moving-revision")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.jsonl"
            source.write_text("{}\n", encoding="utf-8")
            alias = root / "alias.jsonl"
            alias.symlink_to(source)
            with self.assertRaisesRegex(ValueError, "regular JSONL"):
                list(adapter.jsonl_rows(alias))


if __name__ == "__main__":
    unittest.main()
