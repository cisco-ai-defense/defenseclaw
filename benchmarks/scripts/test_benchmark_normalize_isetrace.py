#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import importlib
import json
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

adapter = importlib.import_module("benchmark_normalize_isetrace")

REVISION = "a" * 40
NORMALIZATION_MANIFEST_KEYS = {
    "schema_version",
    "datasets",
    "cases",
    "counts",
    "exact_payload_duplicates_removed",
    "label_conflicts_excluded",
    "adapter_statistics",
    "output_sha256",
}


def tool_definition(name: str) -> dict[str, object]:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": f"excluded definition for {name}",
            "parameters": json.dumps({"type": "object"}),
        },
    }


def call(call_id: str, name: str, arguments: dict[str, object]) -> dict[str, object]:
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(arguments)},
    }


def source_row(
    number: int,
    *,
    source_intents: tuple[str, ...] | None = None,
    family: str | None = None,
    include_second_call: bool = True,
    second_result: bool | None = False,
    suspicious: bool = False,
) -> dict[str, object]:
    intents = source_intents or (f"intent-{number}",)
    family_name = family or f"task-family-{number}"
    first_command = "rm -rf /production" if suspicious else f"printf trajectory-{number}"
    messages: list[dict[str, object]] = [
        {"role": "system", "content": f"excluded system message {number}"},
        {"role": "user", "content": f"excluded user message {number}"},
        {
            "role": "assistant",
            "content": "excluded assistant prose",
            "reasoning_content": "excluded private reasoning",
            "tool_calls": [call(f"call-{number}-0", "exec", {"command": first_command})],
        },
        {
            "role": "tool",
            "content": "excluded raw command output",
            "name": "exec",
            "tool_call_id": f"call-{number}-0",
            "success": True,
        },
    ]
    if include_second_call:
        messages.append(
            {
                "role": "assistant",
                "content": "excluded second assistant prose",
                "tool_calls": [
                    call(
                        f"call-{number}-1",
                        "write",
                        {"path": f"/workspace/file-{number}", "content": "real argument"},
                    )
                ],
            }
        )
        if second_result is not None:
            messages.append(
                {
                    "role": "tool",
                    "content": "excluded raw write output",
                    "name": "write",
                    "tool_call_id": f"call-{number}-1",
                    "success": second_result,
                }
            )
    return {
        "status": "completed",
        "session_id": f"session-{number}",
        "intent_id": intents[0],
        "source_intent_count": len(intents),
        "source_intent_ids": list(intents),
        "source_intents": [
            {
                "intent_id": intent,
                "natural_language_intent": f"excluded intent text {intent}",
                "task_type": "execution",
            }
            for intent in intents
        ],
        "session_finalized_by_intent_id": intents[0],
        "total_steps": 2 if include_second_call else 1,
        "enable_thinking": True,
        "messages": messages,
        "tools": [tool_definition("exec"), tool_definition("write")],
        "final_output": "excluded final output",
        "metadata": {
            "persona": {
                "communication_style": "excluded",
                "experience_level": "excluded",
                "expertise": ["excluded", "synthetic", "persona"],
                "industry": "excluded",
                "name": "excluded",
                "role": "excluded",
                "work_context": "excluded",
            },
            "domains": [
                {
                    "name": "OS",
                    "description": "excluded domain description",
                    "selected_tasks": [{"name": family_name, "description": "excluded task description"}],
                }
            ],
        },
    }


class ISETraceNormalizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.rows = [source_row(number) for number in range(4)]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def build(self, rows=None, **overrides):
        options = {
            "revision": REVISION,
            "max_argument_bytes": 4096,
            "max_tool_calls_per_trajectory": 32,
            "max_events_per_case": 8,
        }
        options.update(overrides)
        return adapter.build_corpus(self.rows if rows is None else rows, **options)

    def test_projects_real_names_and_structured_arguments_only(self) -> None:
        rows, manifest, _ = self.build()
        self.assertEqual(len(rows), 4)
        first = rows[0]
        self.assertEqual(first["surface"], "stateful")
        events = first["payload"]["events"]
        self.assertEqual([event["tool_name"] for event in events], ["exec", "write"])
        self.assertIsInstance(events[0]["args"], dict)
        self.assertEqual(events[0]["command"], events[0]["args"]["command"])
        self.assertEqual(events[0]["dialect"], "posix")
        self.assertEqual(events[1]["dialect"], "none")
        serialized_payload = json.dumps([row["payload"] for row in rows], sort_keys=True)
        for excluded in (
            "excluded system",
            "excluded user",
            "excluded assistant",
            "excluded private reasoning",
            "excluded raw",
            "excluded final",
            "excluded intent",
            "excluded definition",
        ):
            self.assertNotIn(excluded, serialized_payload)
        self.assertEqual(manifest["adapter_statistics"]["isetrace"]["tool_calls"], 8)

    def test_derives_outcome_only_from_matching_explicit_result(self) -> None:
        source = [
            source_row(0, second_result=False),
            source_row(1, second_result=None),
        ]
        source[0]["messages"].append(
            {
                "role": "tool",
                "content": "excluded orphan output",
                "name": "exec",
                "tool_call_id": "orphan-result",
                "success": True,
            }
        )
        rows, manifest, _ = self.build(source)
        outcomes = [event["outcome"] for row in rows for event in row["payload"]["events"]]
        self.assertEqual(Counter(outcomes), Counter({"succeeded": 2, "failed": 1, "unknown": 1}))
        stats = manifest["adapter_statistics"]["isetrace"]
        self.assertEqual(stats["outcome_succeeded"], 2)
        self.assertEqual(stats["outcome_failed"], 1)
        self.assertEqual(stats["outcome_unknown"], 1)
        self.assertEqual(stats["orphan_tool_results_excluded"], 1)

    def test_suspicious_text_never_creates_a_malicious_source_label(self) -> None:
        rows, _, _ = self.build([source_row(0, suspicious=True)])
        self.assertIn("rm -rf", rows[0]["payload"]["events"][0]["command"])
        truth = rows[0]["truth"]
        self.assertEqual(truth["source_truth"], "benign")
        self.assertEqual(truth["deterministic_truth"], "benign")
        self.assertEqual(truth["expected_disposition"], "allow")
        self.assertTrue(rows[0]["strata"]["hard_negative"])

    def test_defers_all_split_assignment_to_canonical_partitioner(self) -> None:
        rows, manifest, group_manifest = self.build()
        self.assertEqual({row["split"] for row in rows}, {"smoke"})
        self.assertEqual(set(manifest), NORMALIZATION_MANIFEST_KEYS)
        self.assertEqual(group_manifest["partition_authority"], "benchmarks/scripts/benchmark_partition.py")
        forbidden = {"assignment_sha256", "ratios", "split", "strategy", "test"}
        self.assertTrue(forbidden.isdisjoint(group_manifest))
        self.assertTrue(all(forbidden.isdisjoint(group) for group in group_manifest["groups"]))

    def test_groups_transitive_shared_intents_and_task_families(self) -> None:
        source = [
            source_row(0, source_intents=("intent-a",), family="family-a"),
            source_row(1, source_intents=("intent-a", "intent-b"), family="family-b"),
            source_row(2, source_intents=("intent-c",), family="family-b"),
            source_row(3, source_intents=("intent-d",), family="family-d"),
        ]
        rows, _, group_manifest = self.build(source)
        groups_by_trajectory = {row["strata"]["trajectory_id"]: row["strata"]["split_group"] for row in rows}
        ordered = [
            groups_by_trajectory[
                adapter.project_trajectory(
                    item,
                    max_argument_bytes=4096,
                    max_tool_calls=32,
                ).identity_digest
            ]
            for item in source
        ]
        self.assertEqual(ordered[0], ordered[1])
        self.assertEqual(ordered[1], ordered[2])
        self.assertNotEqual(ordered[2], ordered[3])
        self.assertEqual(group_manifest["group_count"], 2)

    def test_output_is_deterministic_independent_of_source_order(self) -> None:
        first = self.build()
        second = self.build(list(reversed(self.rows)))
        self.assertEqual(first, second)

    def test_long_trajectories_do_not_create_singleton_stateful_tails(self) -> None:
        trajectory = source_row(0, include_second_call=False)
        messages = trajectory["messages"]
        for index in range(1, 9):
            messages.append(
                {
                    "role": "assistant",
                    "content": "excluded",
                    "tool_calls": [call(f"call-0-{index}", "exec", {"command": f"printf {index}"})],
                }
            )
        rows, _, _ = self.build(
            [trajectory],
            max_tool_calls_per_trajectory=16,
            max_events_per_case=4,
        )
        self.assertEqual([len(row["payload"]["events"]) for row in rows], [4, 3, 2])
        sequence = [event["args"]["command"] for row in rows for event in row["payload"]["events"]]
        self.assertEqual(sequence, ["printf trajectory-0"] + [f"printf {index}" for index in range(1, 9)])

    def test_single_call_trajectory_uses_atomic_surface_without_fabricating_result(self) -> None:
        rows, _, _ = self.build([source_row(0, include_second_call=False)])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["surface"], "action")
        self.assertNotIn("outcome", rows[0]["payload"])
        self.assertEqual(rows[0]["payload"]["tool_name"], "exec")

    def test_strict_schema_rejects_invalid_rows_arguments_and_result_pairing(self) -> None:
        unexpected = source_row(0)
        unexpected["attack_label"] = True
        with self.assertRaisesRegex(ValueError, "strict schema"):
            self.build([unexpected])

        duplicate_argument = source_row(0)
        duplicate_argument["messages"][2]["tool_calls"][0]["function"]["arguments"] = '{"x":1,"x":2}'
        with self.assertRaisesRegex(ValueError, "strict JSON"):
            self.build([duplicate_argument])

        mismatch = source_row(0)
        mismatch["messages"][3]["name"] = "write"
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.build([mismatch])

        result_before_call = source_row(0)
        tool_result = result_before_call["messages"].pop(3)
        result_before_call["messages"].insert(2, tool_result)
        with self.assertRaisesRegex(ValueError, "must follow"):
            self.build([result_before_call])

        oversized = source_row(0)
        oversized["messages"][2]["tool_calls"][0]["function"]["arguments"] = json.dumps({"command": "x" * 256})
        with self.assertRaisesRegex(ValueError, "byte bound"):
            self.build([oversized], max_argument_bytes=64)

        duplicate_session = source_row(1)
        duplicate_session["session_id"] = source_row(0)["session_id"]
        with self.assertRaisesRegex(ValueError, "duplicate.*session"):
            self.build([source_row(0), duplicate_session])

    def test_validates_case_schema_and_manifests_are_value_free(self) -> None:
        rows, manifest, group_manifest = self.build()
        adapter.validate_cases(rows, adapter.DEFAULT_SCHEMA, max_argument_bytes=4096)
        output = self.root / "cases.jsonl"
        manifest_path = self.root / "cases.manifest.json"
        groups_path = self.root / "cases.groups.json"
        adapter.write_outputs(
            rows,
            manifest,
            group_manifest,
            output=output,
            manifest_path=manifest_path,
            group_manifest_path=groups_path,
        )
        self.assertEqual(adapter.sha256_bytes(output.read_bytes()), manifest["output_sha256"])
        metadata = json.loads(manifest_path.read_text(encoding="utf-8"))
        serialized = json.dumps([metadata, json.loads(groups_path.read_text())], sort_keys=True)
        for excluded in ("command", "args", "content", "messages", "result", "tool_name"):
            self.assertNotIn(f'"{excluded}"', serialized)

        damaged = dict(manifest)
        damaged["revision"] = REVISION
        with self.assertRaisesRegex(ValueError, "strict schema"):
            adapter.validate_manifests(damaged, group_manifest)

    def test_provenance_requires_matching_revision_license_and_etags(self) -> None:
        source_root = self.root / "source"
        source = source_root / "trajectories/trajectories-00000.jsonl"
        readme = source_root / "README.md"
        license_path = source_root / "LICENSE"
        source.parent.mkdir(parents=True)
        source.write_text("{}\n", encoding="utf-8")
        readme.write_text("---\nlicense: cc-by-4.0\n---\n", encoding="utf-8")
        license_path.write_text(
            "Creative Commons Attribution 4.0 International License (CC BY 4.0)\n",
            encoding="utf-8",
        )

        def write_metadata(path: Path) -> None:
            relative = path.relative_to(source_root)
            metadata = source_root / ".cache/huggingface/download" / relative.parent / f"{relative.name}.metadata"
            metadata.parent.mkdir(parents=True, exist_ok=True)
            data = path.read_bytes()
            etag = hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()
            metadata.write_text(f"{REVISION}\n{etag}\n0\n", encoding="utf-8")

        for path in (source, readme, license_path):
            write_metadata(path)
        self.assertEqual(adapter.resolve_revision(source_root, source, None), REVISION)
        with self.assertRaisesRegex(ValueError, "differs"):
            adapter.resolve_revision(source_root, source, "b" * 40)

        readme.write_text("---\nlicense: apache-2.0\n---\n", encoding="utf-8")
        write_metadata(readme)
        with self.assertRaisesRegex(ValueError, "does not declare"):
            adapter.resolve_revision(source_root, source, None)


if __name__ == "__main__":
    unittest.main()
