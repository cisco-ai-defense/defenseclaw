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

MODULE_PATH = Path(__file__).with_name("benchmark_normalize_terminal_wrench.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_terminal_wrench", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def tool_call(identifier: str, command: str, *, function: str = "bash_command") -> dict[str, object]:
    return {
        "tool_call_id": identifier,
        "function_name": function,
        "arguments": {"keystrokes": command, "duration": 0.1},
    }


def trajectory(calls: list[dict[str, object]], results: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": "ATIF-v1.6",
        "session_id": "excluded session identifier",
        "agent": {"name": "excluded agent metadata"},
        "steps": [
            {"step_id": 1, "source": "user", "message": "PROMPT MUST NOT LEAK"},
            {
                "step_id": 2,
                "source": "agent",
                "message": "REASONING MUST NOT LEAK",
                "tool_calls": calls,
                "observation": {"results": results},
            },
        ],
        "final_metrics": {"excluded": True},
    }


class SourceTree:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.trajectories: list[dict[str, object]] = []
        self.tasks: dict[tuple[str, str], dict[str, object]] = {}

    def add(
        self,
        *,
        task: str,
        model: str,
        tree: str,
        label: str,
        classification: str,
        reward: float,
        trace: dict[str, object],
        serious: bool = False,
        legitimate: bool = False,
        category: str = "CATEGORY MUST NOT LEAK",
        key_steps: list[int] | None = None,
    ) -> None:
        trial_name = f"trial-{task}-{model}-{tree}-{label}"
        row: dict[str, object] = {
            "task_id": task,
            "model": model,
            "classification": classification,
            "reward": reward,
            "trial_name": trial_name,
        }
        if classification == "baseline":
            row["label"] = label
            task_row = self.tasks.setdefault(
                (task, model),
                {"task_id": task, "model": model, "baselines": []},
            )
            task_row["baselines"].append(row)
            tree = "baseline_trajectories"
        else:
            row.update(
                {
                    "tree_name": tree,
                    "trajectory_label": label,
                    "judged_serious_exploit": serious,
                    "judged_legitimate_solve": legitimate,
                    "observed_categories": [category] if category else [],
                    "targeted_categories": [],
                    "key_hack_steps": key_steps or [],
                    "brief_exploit_summary": "SUMMARY MUST NOT LEAK",
                    "explanation": "EXPLANATION MUST NOT LEAK",
                }
            )
            self.trajectories.append(row)
        trial = self.root / "tasks" / task / model / tree / label / "trial"
        (trial / "agent").mkdir(parents=True, exist_ok=True)
        (trial / "verifier").mkdir(parents=True, exist_ok=True)
        (trial / "agent/trajectory.json").write_text(json.dumps(trace), encoding="utf-8")
        (trial / "verifier/reward.txt").write_text(str(reward), encoding="utf-8")
        result = {
            "id": f"result-{trial_name}",
            "task_name": task,
            "trial_name": trial_name,
            "verifier_result": {"rewards": {"reward": reward}},
            "agent_result": {"raw_output": "RESULT CONTENT MUST NOT LEAK"},
        }
        (trial / "result.json").write_text(json.dumps(result), encoding="utf-8")

    def write_indexes(self) -> None:
        index = self.root / "index"
        index.mkdir(parents=True, exist_ok=True)
        (index / "trajectories.json").write_text(json.dumps(self.trajectories), encoding="utf-8")
        (index / "tasks.json").write_text(json.dumps(list(self.tasks.values())), encoding="utf-8")


class TerminalWrenchNormalizerTest(unittest.TestCase):
    @staticmethod
    def stats(manifest: dict[str, object]) -> dict[str, int]:
        return manifest["adapter_statistics"][MODULE.ADAPTER]

    def normalize(self, source: SourceTree) -> tuple[list[dict[str, object]], dict[str, object]]:
        source.write_indexes()
        return MODULE.normalize_input(
            source.root,
            revision=MODULE.SOURCE_REVISION,
            split="validation",
        )

    def test_labels_non_leakage_and_result_content_exclusion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = SourceTree(Path(temporary))
            source.add(
                task="task-a",
                model="model-a",
                tree="baseline_trajectories",
                label="1",
                classification="baseline",
                reward=1.0,
                trace=trajectory(
                    [tool_call("baseline-1", "git status --short")],
                    [
                        {
                            "tool_call_id": "baseline-1",
                            "content": "OBSERVATION MUST NOT LEAK",
                            "status": "completed",
                        }
                    ],
                ),
            )
            source.add(
                task="task-b",
                model="model-a",
                tree="hack_trajectories",
                label="v5",
                classification="rewarded_serious_exploit",
                reward=1.0,
                serious=True,
                key_steps=[2],
                trace=trajectory(
                    [
                        tool_call("attack-1", "printf first-step\n"),
                        tool_call("attack-2", "printf second-step\n"),
                    ],
                    [{"content": "COMBINED RESULT MUST NOT LEAK"}],
                ),
            )
            cases, manifest = self.normalize(source)

        baseline = next(case for case in cases if case["strata"]["campaign"] == "baseline")
        exploit = next(case for case in cases if case["strata"]["campaign"] == "rewarded_serious_exploit")
        self.assertEqual("benign", baseline["truth"]["source_truth"])
        self.assertEqual("allow", baseline["truth"]["expected_disposition"])
        self.assertTrue(baseline["strata"]["hard_negative"])
        self.assertEqual("malicious", exploit["truth"]["source_truth"])
        self.assertEqual("contextual_or_dual_use", exploit["truth"]["deterministic_truth"])
        self.assertEqual("out_of_scope", exploit["truth"]["applicability"])
        self.assertEqual("detect_only", exploit["truth"]["expected_disposition"])
        self.assertEqual("stateful", exploit["surface"])
        self.assertEqual(["unknown", "unknown"], [event["outcome"] for event in exploit["payload"]["events"]])
        serialized_payloads = json.dumps([case["payload"] for case in cases])
        for forbidden in (
            "PROMPT MUST NOT LEAK",
            "REASONING MUST NOT LEAK",
            "OBSERVATION MUST NOT LEAK",
            "COMBINED RESULT MUST NOT LEAK",
            "RESULT CONTENT MUST NOT LEAK",
            "CATEGORY MUST NOT LEAK",
            "SUMMARY MUST NOT LEAK",
            "EXPLANATION MUST NOT LEAK",
        ):
            self.assertNotIn(forbidden, serialized_payloads)
        self.assertNotIn("label_metadata", manifest)

    def test_successful_task_actions_outside_closed_grammar_are_contextual(self) -> None:
        cases_by_task: dict[str, dict[str, object]] = {}
        with tempfile.TemporaryDirectory() as temporary:
            source = SourceTree(Path(temporary))
            calls = {
                "python": tool_call("python-call", "python -c \"import shutil; shutil.rmtree('repo')\""),
                "shred": tool_call("shred-call", "shred -u .env"),
                "wrapper": tool_call("wrapper-call", "sh -c 'pwd'"),
                "cloud": tool_call("cloud-call", "aws sts get-caller-identity"),
                "credentials": {
                    "tool_call_id": "credential-call",
                    "function_name": "get_credentials",
                    "arguments": {"account": "prod"},
                },
            }
            for task, call in calls.items():
                identifier = str(call["tool_call_id"])
                source.add(
                    task=f"task-{task}",
                    model="model-a",
                    tree="baseline_trajectories",
                    label="1",
                    classification="baseline",
                    reward=1.0,
                    trace=trajectory([call], [{"tool_call_id": identifier, "status": "success"}]),
                )
            normalized, _ = self.normalize(source)
            cases_by_task = {
                case["source"]["original_id"]: case for case in normalized if case["strata"]["campaign"] == "baseline"
            }

        self.assertEqual(len(calls), len(cases_by_task))
        self.assertTrue(all(case["truth"]["source_truth"] == "unknown" for case in cases_by_task.values()))
        self.assertTrue(all(case["truth"]["applicability"] == "out_of_scope" for case in cases_by_task.values()))
        self.assertTrue(all(not case["strata"]["hard_negative"] for case in cases_by_task.values()))

    def test_unambiguous_pairing_uses_only_structured_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = SourceTree(Path(temporary))
            source.add(
                task="task-pair",
                model="model-a",
                tree="baseline_trajectories",
                label="1",
                classification="baseline",
                reward=1.0,
                trace=trajectory(
                    [
                        tool_call("call-one", "printf one\n"),
                        tool_call("call-two", "printf two\n"),
                    ],
                    [
                        {"tool_call_id": "call-two", "content": "excluded", "exit_code": 7},
                        {"tool_call_id": "call-one", "content": "excluded", "status": "success"},
                    ],
                ),
            )
            cases, manifest = self.normalize(source)

        events = cases[0]["payload"]["events"]
        self.assertEqual(["succeeded", "failed"], [event["outcome"] for event in events])
        self.assertEqual(2, self.stats(manifest)["results_unambiguously_paired"])
        self.assertNotIn("excluded", json.dumps(cases[0]["payload"]))

    def test_attacker_legitimate_solve_is_never_malicious_tp(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = SourceTree(Path(temporary))
            source.add(
                task="task-control",
                model="model-a",
                tree="non_hack_trajectories",
                label="v5",
                classification="attacker_legitimate_solve",
                reward=1.0,
                legitimate=True,
                trace=trajectory(
                    [tool_call("one", "printf one\n"), tool_call("two", "printf two\n")],
                    [{"content": "combined and ambiguous"}],
                ),
            )
            cases, _ = self.normalize(source)

        truth = cases[0]["truth"]
        self.assertEqual("benign", truth["source_truth"])
        self.assertEqual("out_of_scope", truth["applicability"])
        self.assertEqual("detect_only", truth["expected_disposition"])

    def test_nonserious_is_unscored_control_and_unrewarded_is_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = SourceTree(Path(temporary))
            source.add(
                task="task-nonserious",
                model="model-a",
                tree="hack_trajectories",
                label="v5",
                classification="rewarded_nonserious_hack",
                reward=1.0,
                trace=trajectory(
                    [tool_call("one", "printf one\n"), tool_call("two", "printf two\n")],
                    [{"content": "combined"}],
                ),
            )
            source.add(
                task="task-unrewarded",
                model="model-a",
                tree="hack_trajectories",
                label="v5",
                classification="no_reward",
                reward=0.0,
                trace=trajectory(
                    [tool_call("three", "printf three\n"), tool_call("four", "printf four\n")],
                    [{"content": "combined"}],
                ),
            )
            cases, manifest = self.normalize(source)

        self.assertEqual(1, len(cases))
        self.assertEqual("unknown", cases[0]["truth"]["source_truth"])
        self.assertEqual("out_of_scope", cases[0]["truth"]["applicability"])
        self.assertEqual(1, self.stats(manifest)["excluded_no_reward"])

    def test_exact_content_dedup_and_task_disjoint_groups(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = SourceTree(Path(temporary))
            duplicate = trajectory(
                [tool_call("same-call", "printf duplicate\n")],
                [{"content": "excluded"}],
            )
            source.add(
                task="task-one",
                model="model-a",
                tree="baseline_trajectories",
                label="1",
                classification="baseline",
                reward=1.0,
                trace=duplicate,
            )
            source.add(
                task="task-one",
                model="model-b",
                tree="baseline_trajectories",
                label="2",
                classification="baseline",
                reward=1.0,
                trace=duplicate,
            )
            source.add(
                task="task-two",
                model="model-a",
                tree="baseline_trajectories",
                label="1",
                classification="baseline",
                reward=1.0,
                trace=trajectory(
                    [tool_call("different-call", "printf different\n")],
                    [{"content": "excluded"}],
                ),
            )
            cases, manifest = self.normalize(source)

        self.assertEqual(2, len(cases))
        self.assertEqual(1, manifest["exact_payload_duplicates_removed"])
        self.assertEqual(2, len({case["strata"]["split_group"] for case in cases}))
        self.assertEqual(2, len({case["id"] for case in cases}))

    def test_label_conflicting_exact_content_is_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = SourceTree(Path(temporary))
            calls = [tool_call("one", "printf one\n"), tool_call("two", "printf two\n")]
            trace = trajectory(calls, [{"content": "combined"}])
            source.add(
                task="task-benign",
                model="model-a",
                tree="baseline_trajectories",
                label="1",
                classification="baseline",
                reward=1.0,
                trace=trace,
            )
            source.add(
                task="task-attack",
                model="model-a",
                tree="hack_trajectories",
                label="v5",
                classification="rewarded_serious_exploit",
                reward=1.0,
                serious=True,
                trace=trace,
            )
            source.add(
                task="task-kept",
                model="model-a",
                tree="baseline_trajectories",
                label="1",
                classification="baseline",
                reward=1.0,
                trace=trajectory([tool_call("kept", "printf kept\n")], [{"content": "x"}]),
            )
            cases, manifest = self.normalize(source)

        self.assertEqual(1, len(cases))
        self.assertEqual(2, manifest["label_conflicts_excluded"])

    def test_bounds_exclude_oversized_command_and_overlong_trajectory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = SourceTree(Path(temporary))
            source.add(
                task="task-kept",
                model="model-a",
                tree="baseline_trajectories",
                label="1",
                classification="baseline",
                reward=1.0,
                trace=trajectory([tool_call("kept", "printf kept\n")], [{"content": "x"}]),
            )
            source.add(
                task="task-large",
                model="model-a",
                tree="baseline_trajectories",
                label="1",
                classification="baseline",
                reward=1.0,
                trace=trajectory(
                    [tool_call("large", "x" * (MODULE.MAX_COMMAND_BYTES + 1))],
                    [{"status": "success"}],
                ),
            )
            calls = [tool_call(f"call-{index}", f"printf {index}\n") for index in range(MODULE.MAX_EVENTS + 1)]
            source.add(
                task="task-long",
                model="model-a",
                tree="baseline_trajectories",
                label="1",
                classification="baseline",
                reward=1.0,
                trace=trajectory(calls, [{"content": "combined"}]),
            )
            cases, manifest = self.normalize(source)

        self.assertEqual(1, len(cases))
        self.assertEqual(1, self.stats(manifest)["excluded_command_too_large"])
        self.assertEqual(1, self.stats(manifest)["excluded_trajectory_too_many_events"])

    def test_malformed_index_and_trajectory_are_handled_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "index").mkdir()
            (root / "index/trajectories.json").write_text("[]", encoding="utf-8")
            (root / "index/tasks.json").write_text('[{"task_id":"a","task_id":"b"}]', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid source JSON"):
                MODULE.normalize_input(root, revision=MODULE.SOURCE_REVISION)

        with tempfile.TemporaryDirectory() as temporary:
            source = SourceTree(Path(temporary))
            source.add(
                task="task-good",
                model="model-a",
                tree="baseline_trajectories",
                label="1",
                classification="baseline",
                reward=1.0,
                trace=trajectory([tool_call("good", "printf good\n")], [{"content": "x"}]),
            )
            source.add(
                task="task-bad",
                model="model-a",
                tree="baseline_trajectories",
                label="1",
                classification="baseline",
                reward=1.0,
                trace={"schema_version": "unexpected", "steps": []},
            )
            cases, manifest = self.normalize(source)
        self.assertEqual(1, len(cases))
        self.assertEqual(1, self.stats(manifest)["excluded_unsupported_trajectory_schema"])

    def test_wrong_revision_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "must be pinned"):
                MODULE.normalize_input(Path(temporary), revision="main")

    def test_non_english_trajectory_is_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = SourceTree(Path(temporary))
            trace = trajectory(
                [tool_call("call", "printf safe\n")],
                [{"tool_call_id": "call", "status": "success"}],
            )
            trace["steps"][0]["message"] = "请读取这个文件并完成终端任务"
            source.add(
                task="task-language",
                model="model-a",
                tree="baseline_trajectories",
                label="1",
                classification="baseline",
                reward=1.0,
                trace=trace,
            )
            source.write_indexes()
            with self.assertRaisesRegex(ValueError, "no Terminal Wrench trajectories"):
                MODULE.normalize_input(source.root, revision=MODULE.SOURCE_REVISION)

    def test_sensitive_arguments_are_redacted_and_result_ids_must_match(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = SourceTree(Path(temporary))
            source.add(
                task="task-secrets",
                model="model-a",
                tree="baseline_trajectories",
                label="1",
                classification="baseline",
                reward=1.0,
                trace=trajectory(
                    [
                        {
                            "tool_call_id": "secret-call",
                            "function_name": "bash_command",
                            "arguments": {
                                "keystrokes": "curl -u user:real-secret --token real-token /health",
                                "password": "real-password",
                                "reasoning": "must not be projected",
                            },
                        }
                    ],
                    [{"tool_call_id": "different-call", "status": "success"}],
                ),
            )
            cases, manifest = self.normalize(source)
        rendered = json.dumps(cases[0]["payload"])
        for secret in ("real-secret", "real-token", "real-password", "must not be projected"):
            self.assertNotIn(secret, rendered)
        self.assertEqual("unknown", cases[0]["payload"].get("outcome", "unknown"))
        self.assertEqual(0, self.stats(manifest)["results_unambiguously_paired"])
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


if __name__ == "__main__":
    unittest.main()
