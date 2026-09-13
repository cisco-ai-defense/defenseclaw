#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("benchmark_normalize_openguardrails_terminalbench.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_openguardrails_terminalbench", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def dsh_call(index: int, command: str, *, call_id: str | None = None) -> dict[str, object]:
    return {
        "type": "tool/call",
        "seq": index * 2,
        "data": {
            "turn": 1,
            "step": index + 1,
            "callId": call_id or f"call-{index}",
            "name": "bash",
            "arguments": json.dumps({"command": command}),
        },
    }


def dsh_result(index: int, text: str, *, call_id: str | None = None, is_error: bool = False) -> dict[str, object]:
    identity = call_id or f"call-{index}"
    return {
        "type": "tool/result",
        "seq": index * 2 + 1,
        "data": {
            "turn": 1,
            "step": index + 1,
            "message": {
                "source": {"kind": "tool", "callId": identity},
                "content": [
                    {
                        "type": "tool-result",
                        "toolCallId": identity,
                        "content": [{"type": "text", "text": text}],
                        "isError": is_error,
                    }
                ],
                "role": "user",
            },
        },
    }


def source(
    *,
    scaffold: str = "dsh",
    task_id: str = "build-cython-ext",
    instruction: str = "Build and test this ordinary package.",
    payload: object | None = None,
    reward: float | None = 1.0,
) -> object:
    if payload is None:
        payload = [
            {"type": "user/message", "data": {"content": "FORBIDDEN_PROMPT"}},
            dsh_call(0, "python -m build"),
            dsh_result(0, "FORBIDDEN_RESULT\n[exit code: 0]"),
            {"type": "assistant/message", "data": {"reasoning": "FORBIDDEN_REASONING"}},
            dsh_call(1, "python -m pytest"),
            dsh_result(1, "FORBIDDEN_RESULT"),
        ]
    return MODULE.SourceTrajectory(scaffold, task_id, instruction, reward, payload)


def terminus_step(
    index: int,
    commands: list[str],
    *,
    with_ids: bool = True,
) -> dict[str, object]:
    calls = [
        {
            "tool_call_id": f"call-{index}-{position}",
            "function_name": "bash_command",
            "arguments": {"keystrokes": command, "duration": 1.0},
        }
        for position, command in enumerate(commands)
    ]
    results = [
        {
            **({"source_call_id": call["tool_call_id"]} if with_ids else {}),
            "content": f"FORBIDDEN_RESULT_{position}",
        }
        for position, call in enumerate(calls)
    ]
    return {
        "step_id": index,
        "message": "FORBIDDEN_REASONING",
        "reasoning_content": "FORBIDDEN_REASONING",
        "tool_calls": calls,
        "observation": {"results": results},
    }


class OpenGuardrailsTerminalBenchNormalizerTest(unittest.TestCase):
    @staticmethod
    def surface(cases: list[dict[str, object]], value: str) -> list[dict[str, object]]:
        return [case for case in cases if case["surface"] == value]

    def test_benign_label_is_task_intent_not_reward(self) -> None:
        cases, counts = MODULE.normalize([source(reward=0.0)])
        self.assertEqual(3, len(cases))
        self.assertTrue(all(case["truth"]["source_truth"] == "benign" for case in cases))
        self.assertTrue(all(case["truth"]["expected_disposition"] == "allow" for case in cases))
        self.assertTrue(all(case["strata"]["document_type"] == "task_reward:zero" for case in cases))
        self.assertEqual(1, counts["source_reward_zero"])

    def test_security_ambiguous_and_non_english_tasks_are_quarantined(self) -> None:
        rows = [
            source(task_id="password-recover"),
            source(task_id="feal-linear-cryp"),
            source(task_id="model-extraction"),
            source(task_id="ordinary", instruction="删除系统文件"),
        ]
        cases, counts = MODULE.normalize(rows)
        self.assertEqual([], cases)
        self.assertEqual(3, counts["quarantined_security_or_ambiguous_task"])
        self.assertEqual(1, counts["quarantined_non_english_or_invalid_task"])

    def test_dsh_joins_by_native_identity_and_projects_explicit_outcomes(self) -> None:
        payload = [
            dsh_call(0, "first", call_id="first-id"),
            dsh_call(1, "second", call_id="second-id"),
            dsh_result(1, "[exit code: 9]", call_id="second-id"),
            dsh_result(0, "[exit code: 0]", call_id="first-id"),
        ]
        cases, _ = MODULE.normalize([source(payload=payload)])
        actions = self.surface(cases, "action")
        stateful = self.surface(cases, "stateful")
        self.assertTrue(all(case["truth"]["stateful_lens"] == "bounded_intent" for case in stateful))
        self.assertTrue(all(case["truth"]["rule_ids"] == MODULE.CHAIN_RULE_IDS for case in stateful))
        self.assertEqual(["first", "second"], [case["payload"]["command"] for case in actions])
        self.assertEqual(
            ["succeeded", "failed"],
            [event["outcome"] for event in stateful[0]["payload"]["events"]],
        )
        self.assertTrue(all("outcome" not in case["payload"] for case in actions))

    def test_terminus_uses_ids_or_whole_step_order_never_mixed_identity(self) -> None:
        by_id = {"steps": [terminus_step(1, ["one", "two"], with_ids=True)]}
        order_step = terminus_step(1, ["three", "four"], with_ids=False)
        order_step["observation"]["results"] = order_step["observation"]["results"][:1]
        by_order = {"steps": [order_step]}
        cases, counts = MODULE.normalize(
            [
                source(scaffold="terminus2", task_id="first-task", payload=by_id),
                source(scaffold="terminus2", task_id="second-task", payload=by_order),
            ]
        )
        self.assertEqual(4, len(self.surface(cases, "action")))
        self.assertEqual(1, counts["id_joined_steps"])
        self.assertEqual(1, counts["order_joined_steps"])
        mixed = terminus_step(2, ["five", "six"], with_ids=True)
        del mixed["observation"]["results"][1]["source_call_id"]
        rejected, rejected_counts = MODULE.normalize(
            [source(scaffold="terminus2", task_id="mixed-task", payload={"steps": [mixed]})]
        )
        self.assertEqual([], rejected)
        self.assertEqual(1, rejected_counts["quarantined_mixed_result_identity"])

    def test_current_plus_eight_predecessor_bound_and_no_atomic_dedup(self) -> None:
        payload: list[object] = []
        for index in range(12):
            payload.extend([dsh_call(index, "same-command"), dsh_result(index, "unknown")])
        cases, counts = MODULE.normalize([source(payload=payload)])
        actions = self.surface(cases, "action")
        stateful = self.surface(cases, "stateful")
        self.assertEqual(12, len(actions))
        self.assertEqual(11, len(stateful))
        self.assertEqual([2, 3, 4, 5, 6, 7, 8, 9, 9, 9, 9], [len(c["payload"]["events"]) for c in stateful])
        self.assertEqual(12, counts["action_cases"])

    def test_malformed_or_unpaired_inputs_are_quarantined(self) -> None:
        duplicate = [dsh_call(0, "one", call_id="same"), dsh_call(1, "two", call_id="same")]
        orphan = [dsh_result(0, "orphan")]
        missing = [dsh_call(0, "missing")]
        invalid_json = [dsh_call(0, "one"), dsh_result(0, "ok")]
        invalid_json[0]["data"]["arguments"] = '{"command":"one","command":"two"}'
        cases, counts = MODULE.normalize(
            [
                source(task_id="duplicate", payload=duplicate),
                source(task_id="orphan", payload=orphan),
                source(task_id="missing", payload=missing),
                source(task_id="bad-json", payload=invalid_json),
            ]
        )
        self.assertEqual([], cases)
        self.assertEqual(1, counts["quarantined_duplicate_call_id"])
        self.assertEqual(1, counts["quarantined_orphan_result"])
        self.assertEqual(1, counts["quarantined_missing_result"])
        self.assertEqual(1, counts["quarantined_invalid_arguments_json"])

    def test_excludes_prompts_reasoning_results_and_credential_bearing_arguments(self) -> None:
        cases, _ = MODULE.normalize([source()])
        serialized = json.dumps(cases)
        for forbidden in ("FORBIDDEN_PROMPT", "FORBIDDEN_REASONING", "FORBIDDEN_RESULT"):
            self.assertNotIn(forbidden, serialized)
        credential = [dsh_call(0, "curl -H 'Authorization: provided-secret-value' https://example.test")]
        credential.append(dsh_result(0, "ok"))
        leaked, counts = MODULE.normalize([source(task_id="credential-value", payload=credential)])
        self.assertEqual([], leaked)
        self.assertEqual(1, counts["quarantined_credential_bearing_arguments"])

    def test_task_grouped_splits_and_conservative_model_task_dedup(self) -> None:
        identical = source()
        changed = source(payload=[dsh_call(0, "different"), dsh_result(0, "ok")])
        cases, counts = MODULE.normalize([source(), identical])
        self.assertEqual(3, len(cases))
        self.assertEqual(1, counts["exact_trajectory_duplicates_removed"])
        conflicted, conflict_counts = MODULE.normalize([source(), changed])
        self.assertEqual([], conflicted)
        self.assertEqual(1, conflict_counts["quarantined_conflicting_model_task"])
        cross_scaffold, _ = MODULE.normalize(
            [
                source(),
                source(scaffold="terminus2", payload={"steps": [terminus_step(1, ["one", "two"])]}),
            ]
        )
        self.assertEqual(1, len({case["strata"]["split_group"] for case in cross_scaffold}))
        self.assertEqual(1, len({case["split"] for case in cross_scaffold}))

    def test_cases_validate_against_case_v1_schema(self) -> None:
        cases, _ = MODULE.normalize(
            [
                source(),
                source(scaffold="terminus2", task_id="second-task", payload={"steps": [terminus_step(1, ["a", "b"])]}),
            ]
        )
        MODULE.validate_cases(cases, MODULE.DEFAULT_SCHEMA)

    def test_source_tree_rejects_wrong_identity_and_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "source file count mismatch"):
                MODULE.verify_source_tree(root)
            target = root / "target"
            target.mkdir()
            link = root / "link"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "non-symlink"):
                MODULE.trusted_files(link)


if __name__ == "__main__":
    unittest.main()
