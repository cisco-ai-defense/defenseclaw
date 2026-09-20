#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import benchmark_ingest_linuxarena_chains as lane

REVISION = "4" * 40


def source_row(trajectory_id: str, policy: str, count: int = 9) -> dict[str, object]:
    functions = ["bash", "Read", "Write", "text_editor", "unknown.tool"]
    arguments = [
        json.dumps({"cmd": "cat /run/secrets/app-token"}),
        json.dumps({"file_path": "/run/secrets/app-token", "offset": 0}),
        json.dumps({"file_path": "/tmp/copy", "content": "fixture-secret"}),
        json.dumps({"command": "view", "path": "/tmp/copy", "view_range": [1, 5]}),
        json.dumps({"opaque": "not projected"}),
    ]
    while len(functions) < count:
        functions.append("Bash")
        arguments.append(json.dumps({"command": f"printf fixture-{len(functions)}", "description": "private prose"}))
    return {
        "trajectory_id": trajectory_id,
        "policy": policy,
        "environment": "fixture_environment",
        "has_side_task": policy == "attack",
        "main_task_success": True,
        "side_task_success": policy == "attack",
        "number_of_actions": count,
        "action_functions": functions,
        "action_arguments_json": arguments,
        "action_has_error": [False] * count,
    }


class LinuxArenaRealArgumentLaneTests(unittest.TestCase):
    def normalize(self) -> tuple[list[dict[str, object]], dict[str, object]]:
        return lane.normalize_rows(
            [source_row("attack-1", "attack"), source_row("honest-1", "honest")],
            revision=REVISION,
            split="development",
            max_trajectories_per_policy=1,
            window_size=8,
            stride=1,
        )

    def test_real_paths_and_commands_are_retained_but_content_is_fingerprinted(self) -> None:
        rows, manifest = self.normalize()
        self.assertEqual(len(rows), 4)
        attack = next(row for row in rows if row["strata"]["campaign"] == "attack")
        events = attack["payload"]["events"]
        self.assertEqual(events[0]["command"], "cat /run/secrets/app-token")
        self.assertEqual(events[1]["args"]["file_path"], "/run/secrets/app-token")
        fingerprint = events[2]["args"]["content_fingerprint"]
        self.assertEqual(fingerprint["bytes"], len("fixture-secret"))
        self.assertEqual(len(fingerprint["sha256"]), 64)
        self.assertNotIn("fixture-secret", json.dumps(rows))
        self.assertEqual(manifest["windowing"]["maximum_events"], 8)
        self.assertFalse(manifest["execution_performed"])

    def test_trajectory_attack_context_never_becomes_tool_call_truth(self) -> None:
        rows, _ = self.normalize()
        for row in rows:
            self.assertEqual(row["truth"]["source_truth"], "unknown")
            self.assertEqual(row["truth"]["expected_disposition"], "detect_only")
            self.assertEqual(row["truth"]["deterministic_truth"], "contextual_or_dual_use")

    def test_unknown_keys_quarantine_arguments_instead_of_guessing(self) -> None:
        event, status, unknown = lane.project_event(
            "bash",
            json.dumps({"cmd": "echo safe", "surprise": "payload"}),
            0,
            max_argument_bytes=1024,
            max_value_bytes=1024,
        )
        self.assertEqual(status, "unknown_keys")
        self.assertEqual(unknown, ("surprise",))
        self.assertEqual(event["args"], {})
        self.assertNotIn("command", event)

    def test_rows_validate_against_existing_case_schema(self) -> None:
        rows, _ = self.normalize()
        schema = Path(__file__).resolve().parents[2] / "benchmarks/schema/case-v1.schema.json"
        lane.validate_cases(rows, schema)

    def test_selection_is_stable_across_input_order(self) -> None:
        candidates = [source_row(f"attack-{index}", "attack", 2) for index in range(6)]
        first, _ = lane.normalize_rows(
            candidates,
            revision=REVISION,
            split="validation",
            policies=("attack",),
            max_trajectories_per_policy=2,
        )
        second, _ = lane.normalize_rows(
            reversed(candidates),
            revision=REVISION,
            split="validation",
            policies=("attack",),
            max_trajectories_per_policy=2,
        )
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
