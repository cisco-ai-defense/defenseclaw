#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("benchmark_normalize_infraset.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_infraset", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def run_row(
    run_id: str = "single-node-os-comparison/configure-ssh/2026-09-01/cluster-a",
    *,
    image: str = "ubuntu24",
    task: str = "configure-ssh-ubuntu24",
    command_count: int = 3,
    reward: float = 1.0,
    functionality: float = 1.0,
    hygiene: float | None = 0.95,
    confidence: float | None = 0.95,
    coverage: float = 1.0,
    complete: float = 1.0,
) -> dict[str, object]:
    return {
        "run_id": run_id,
        "category": "single-node-os-comparison",
        "image": image,
        "task": task,
        "started_at_dir": "2026-09-01",
        "reward": reward,
        "functionality": functionality,
        "evaluation_coverage": coverage,
        "operational_hygiene": hygiene,
        "confidence": confidence,
        "evaluation_complete": complete,
        "command_count": command_count,
        "node_count": 1,
        "first_command_at": None,
        "last_command_at": None,
        "wall_seconds": 1.0,
    }


def command_row(
    run_id: str,
    sequence: int,
    command: str,
    *,
    command_id: str | None = None,
    node: str = "node1",
    return_code: int | None = 0,
    completed: bool = True,
) -> dict[str, object]:
    return {
        "run_id": run_id,
        "command_id": command_id or f"cmd-{sequence}",
        "sequence": sequence,
        "node": node,
        "command": command,
        "issued_at": None,
        "return_code": return_code,
        "duration_ms": 1,
        "stdout": "forbidden result body",
        "stderr": "forbidden stderr body",
        "executor_attempt": 1,
        "completed": completed,
    }


class InfraSetNormalizerTest(unittest.TestCase):
    def test_projects_exact_commands_nodes_sequences_and_results(self) -> None:
        run = run_row()
        run_id = str(run["run_id"])
        commands = [
            command_row(run_id, 1, "apt-get update", return_code=0),
            command_row(run_id, 2, "systemctl restart sshd", return_code=1),
            command_row(run_id, 3, "systemctl status sshd", return_code=None, completed=False),
        ]
        cases, counts = MODULE.normalize([run], commands)
        actions = [case for case in cases if case["surface"] == "action"]
        stateful = [case for case in cases if case["surface"] == "stateful"]
        self.assertEqual(3, len(actions))
        self.assertEqual(2, len(stateful))
        self.assertTrue(all(case["truth"]["stateful_lens"] == "bounded_intent" for case in stateful))
        self.assertTrue(all(case["truth"]["rule_ids"] == MODULE.CHAIN_RULE_IDS for case in stateful))
        self.assertEqual(5, counts["cases"])
        self.assertEqual(
            ["succeeded", "failed", "unknown"],
            [event["outcome"] for event in stateful[-1]["payload"]["events"]],
        )
        final_args = stateful[-1]["payload"]["events"][-1]["args"]
        self.assertEqual(
            {
                "command": "systemctl status sshd",
                "completed": False,
                "node": "node1",
                "return_code": None,
                "sequence": 3,
            },
            final_args,
        )
        serialized = MODULE.canonical_json(cases)
        self.assertNotIn("forbidden result body", serialized)
        self.assertNotIn("forbidden stderr body", serialized)

    def test_only_complete_high_hygiene_high_confidence_successes_are_scored(self) -> None:
        variants = [
            run_row("runs/good", command_count=1),
            run_row("runs/reward", command_count=1, reward=0.0),
            run_row("runs/functionality", command_count=1, functionality=0.9),
            run_row("runs/hygiene", command_count=1, hygiene=0.89),
            run_row("runs/confidence", command_count=1, confidence=0.89),
            run_row("runs/coverage", command_count=1, coverage=0.9),
            run_row("runs/complete", command_count=1, complete=0.0),
        ]
        commands = [command_row(str(row["run_id"]), 1, f"echo {index}") for index, row in enumerate(variants)]
        cases, counts = MODULE.normalize(variants, commands)
        self.assertEqual(1, len(cases))
        self.assertEqual(1, counts["quarantined_unrewarded_run"])
        self.assertEqual(1, counts["quarantined_incomplete_functionality"])
        self.assertEqual(1, counts["quarantined_low_hygiene"])
        self.assertEqual(1, counts["quarantined_low_confidence"])
        self.assertEqual(2, counts["quarantined_incomplete_evaluation"])
        self.assertEqual(6, counts["quarantined_commands_from_unscored_runs"])

    def test_task_identity_prevents_cross_image_split_leakage(self) -> None:
        first = run_row("runs/ubuntu", image="ubuntu24", task="configure-ssh-ubuntu24", command_count=1)
        second = run_row("runs/rhel", image="rhel9", task="configure-ssh-rhel9", command_count=1)
        commands = [
            command_row("runs/ubuntu", 1, "apt-get install openssh-server"),
            command_row("runs/rhel", 1, "dnf install openssh-server"),
        ]
        cases, _ = MODULE.normalize([first, second], commands)
        self.assertEqual(1, len({case["strata"]["split_group"] for case in cases}))
        self.assertEqual(1, len({case["split"] for case in cases}))

    def test_deduplicates_atomic_payloads_and_bounds_stateful_windows(self) -> None:
        run = run_row(command_count=11)
        run_id = str(run["run_id"])
        commands = [command_row(run_id, index, "true") for index in range(1, 12)]
        cases, counts = MODULE.normalize([run], commands)
        actions = [case for case in cases if case["surface"] == "action"]
        stateful = [case for case in cases if case["surface"] == "stateful"]
        # Repeated normalized actions within a stable task group are counted once.
        self.assertEqual(1, len(actions))
        self.assertEqual(10, len(stateful))
        self.assertLessEqual(max(len(case["payload"]["events"]) for case in stateful), 9)
        self.assertEqual(10, counts["exact_atomic_payload_duplicates_removed"])

    def test_exact_duplicate_command_identity_is_removed_but_conflicts_fail(self) -> None:
        run = run_row(command_count=1)
        run_id = str(run["run_id"])
        command = command_row(run_id, 1, "true")
        cases, counts = MODULE.normalize([run], [command, dict(command)])
        self.assertEqual(1, len(cases))
        self.assertEqual(1, counts["exact_source_command_duplicates_removed"])
        conflicting = dict(command)
        conflicting["command"] = "false"
        with self.assertRaisesRegex(ValueError, "conflicting command identity"):
            MODULE.normalize([run], [command, conflicting])

    def test_rejects_unknown_runs_and_completed_rows_without_return_code(self) -> None:
        run = run_row(command_count=1)
        with self.assertRaisesRegex(ValueError, "unknown run"):
            MODULE.normalize([run], [command_row("runs/unknown", 1, "true")])
        bad = command_row(str(run["run_id"]), 1, "true", return_code=None, completed=True)
        with self.assertRaisesRegex(MODULE.ProjectionError, "completed_without_return_code"):
            MODULE.normalize([run], [bad])

    def test_schema_validation_accepts_normalized_cases(self) -> None:
        run = run_row(command_count=2)
        run_id = str(run["run_id"])
        cases, _ = MODULE.normalize(
            [run], [command_row(run_id, 1, "uname -a"), command_row(run_id, 2, "systemctl status sshd")]
        )
        MODULE.validate_cases(cases, MODULE.DEFAULT_SCHEMA)


if __name__ == "__main__":
    unittest.main()
