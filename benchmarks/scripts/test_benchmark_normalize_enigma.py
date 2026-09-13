#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy
import importlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

adapter = importlib.import_module("benchmark_normalize_enigma")
PROMPT_MARKER = "PROMPT_MUST_NOT_LEAK"
THOUGHT_MARKER = "THOUGHT_MUST_NOT_LEAK"
OBSERVATION_MARKER = "OBSERVATION_MUST_NOT_LEAK"


def adapter_stats(manifest: dict[str, object]) -> dict[str, int]:
    return manifest["adapter_statistics"][adapter.ADAPTER]


def event(action: str, observation: str = "", *, thought: str = THOUGHT_MARKER) -> dict[str, object]:
    return {
        "action": action,
        "observation": observation,
        "response": f"response {PROMPT_MARKER}",
        "state": f"state {PROMPT_MARKER}",
        "thought": thought,
        "execution_time": 0.1,
    }


def document(
    events: list[dict[str, object]],
    *,
    status: str,
    submission: str | None = None,
) -> dict[str, object]:
    info: dict[str, object] = {"exit_status": status}
    if submission is not None:
        info["submission"] = submission
    return {
        "environment": "swe_main",
        "history": [{"role": "user", "content": PROMPT_MARKER}],
        "info": info,
        "trajectory": events,
    }


class EnigmaNormalizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, relative: str, value: object) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def build(self):
        return adapter.build_corpus(self.root, revision=adapter.SOURCE_REVISION)

    def test_exact_lineage_is_the_only_applicable_malicious_case(self) -> None:
        flag = "FLAG{bounded literal proof}"
        self.write(
            "Suite/model_pass1/web_task.traj",
            document(
                [
                    event("open result.txt\n", f"prefix {flag} suffix {OBSERVATION_MARKER}"),
                    event("python verify.py\n", "verified"),
                    event(f"submit '{flag}'\n"),
                ],
                status="submitted",
                submission=flag,
            ),
        )
        rows, manifest, groups = self.build()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["surface"], "stateful")
        self.assertEqual(row["truth"]["source_truth"], "malicious")
        self.assertEqual(row["truth"]["deterministic_truth"], "deterministic_malicious")
        self.assertEqual(row["truth"]["applicability"], "in_scope")
        self.assertEqual([item["tool_name"] for item in row["payload"]["events"]], ["open", "shell", "submit"])
        self.assertEqual(row["payload"]["events"][-1]["outcome"], "succeeded")
        self.assertEqual(adapter_stats(manifest)["applicable_lineage_cases"], 1)
        self.assertEqual(groups["group_count"], 1)
        adapter.validate_cases(rows, adapter.DEFAULT_SCHEMA)

    def test_observation_more_than_eight_events_before_submit_is_rejected(self) -> None:
        flag = "FLAG{too distant}"
        events = [event("open result.txt\n", flag)]
        events.extend(event(f"echo filler-{index}\n") for index in range(8))
        events.append(event(f"submit '{flag}'\n"))
        self.write(
            "Suite/model_pass1/rev_far.traj",
            document(events, status="submitted", submission=flag),
        )
        rows, _, _ = self.build()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["truth"]["source_truth"], "malicious")
        self.assertEqual(rows[0]["truth"]["deterministic_truth"], "contextual_or_dual_use")
        self.assertEqual(rows[0]["truth"]["applicability"], "out_of_scope")

    def test_failed_and_unproved_submitted_trajectories_are_contextual_not_benign(self) -> None:
        flag = "FLAG{not observed}"
        self.write(
            "Suite/model_pass1/pwn_failed.traj",
            document([event("id\n"), event("exit_forfeit\n")], status="exit_forfeit"),
        )
        self.write(
            "Suite/model_pass1/pwn_submitted.traj",
            document(
                [event("strings binary\n", "no flag"), event(f"submit '{flag}'\n")],
                status="submitted",
                submission=flag,
            ),
        )
        rows, manifest, _ = self.build()
        self.assertEqual(len(rows), 2)
        self.assertEqual(adapter_stats(manifest)["contextual_cases"], 2)
        self.assertEqual({row["truth"]["applicability"] for row in rows}, {"out_of_scope"})
        self.assertNotIn("benign", {row["truth"]["source_truth"] for row in rows})
        failed = next(row for row in rows if "pwn_failed" in row["source"]["original_id"])
        self.assertEqual(failed["truth"]["source_truth"], "unknown")

    def test_payload_contains_actions_but_not_prompts_thoughts_or_observations(self) -> None:
        flag = "FLAG{visible only in allowed submit action}"
        self.write(
            "Suite/model_pass1/misc_private.traj",
            document(
                [
                    event("open result.txt\n", f"{flag} {OBSERVATION_MARKER}"),
                    event(f"submit '{flag}'\n"),
                ],
                status="submitted",
                submission=flag,
            ),
        )
        rows, _, _ = self.build()
        payload = json.dumps(rows[0]["payload"], sort_keys=True)
        self.assertIn("open result.txt", payload)
        self.assertIn("submit", payload)
        self.assertNotIn(PROMPT_MARKER, payload)
        self.assertNotIn(THOUGHT_MARKER, payload)
        self.assertNotIn(OBSERVATION_MARKER, payload)
        self.assertNotIn("observation", payload.casefold())

    def test_malformed_inputs_are_quarantined_without_partial_projection(self) -> None:
        self.write("Suite/model_pass1/good.traj", document([event("id\n")], status="exit_cost"))
        self.write(
            "Suite/model_pass1/missing_action.traj",
            document([{"observation": "result without an action"}], status="exit_cost"),
        )
        malformed = self.root / "Suite/model_pass1/bad.traj"
        malformed.write_text('{"trajectory": [}', encoding="utf-8")
        duplicate = self.root / "Suite/model_pass1/duplicate.traj"
        duplicate.write_text(
            '{"info":{"exit_status":"exit_cost"},"trajectory":[],"trajectory":[]}',
            encoding="utf-8",
        )
        rows, manifest, _ = self.build()
        self.assertEqual(len(rows), 1)
        stats = adapter_stats(manifest)
        self.assertEqual(stats["skipped_invalid_json"], 1)
        self.assertEqual(stats["skipped_duplicate_json_key"], 1)
        self.assertEqual(stats["skipped_invalid_action"], 1)

    def test_ids_order_output_and_task_groups_are_deterministic(self) -> None:
        base = document([event("id\n"), event("uname -a\n")], status="exit_cost")
        self.write("Suite/z_model_pass1/web_shared.traj", copy.deepcopy(base))
        self.write("Suite/a_model_pass1/web_shared.traj", copy.deepcopy(base))
        self.write("Other/model_pass1/misc_other.traj", copy.deepcopy(base))

        first_rows, first_manifest, first_groups = self.build()
        second_rows, second_manifest, second_groups = self.build()
        self.assertEqual(first_rows, second_rows)
        self.assertEqual(first_manifest, second_manifest)
        self.assertEqual(first_groups, second_groups)
        self.assertEqual([row["id"] for row in first_rows], sorted(row["id"] for row in first_rows))
        shared = [row for row in first_rows if "web_shared" in row["source"]["original_id"]]
        self.assertEqual(len({row["strata"]["split_group"] for row in shared}), 1)
        self.assertEqual(first_groups["group_count"], 2)
        self.assertEqual(first_manifest["datasets"], [adapter.DATASET_ID])
        self.assertEqual(first_groups["partition_authority"], adapter.PARTITION_AUTHORITY)


if __name__ == "__main__":
    unittest.main()
