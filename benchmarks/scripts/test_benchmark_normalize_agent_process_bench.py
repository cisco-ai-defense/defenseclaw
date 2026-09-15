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

MODULE_PATH = Path(__file__).with_name("benchmark_normalize_agent_process_bench.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_agent_process_bench", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def call(identifier: str, name: str, arguments: dict[str, object]) -> dict[str, object]:
    return {
        "role": "assistant",
        "content": "excluded assistant reasoning",
        "tool_calls": [
            {
                "id": identifier,
                "type": "function",
                "function": {"name": name, "arguments": json.dumps(arguments)},
            }
        ],
    }


def result(identifier: str, name: str, content: object) -> dict[str, object]:
    return {
        "role": "tool",
        "tool_call_id": identifier,
        "name": name,
        "content": content if isinstance(content, str) else json.dumps(content),
    }


def source_row(
    messages: list[dict[str, object]],
    *,
    final_label: int = 1,
    labels: dict[int, int] | None = None,
    query_index: int = 7,
    total_index: int = 35,
) -> dict[str, object]:
    return {
        "question": "Find the requested public information using the available read-only tools.",
        "task_description": "Complete the authorized service task safely and accurately.",
        "messages": [{"role": "user", "content": "Please complete this authorized lookup."}, *messages],
        "step_labels": {str(key): value for key, value in (labels or {}).items()},
        "final_label": final_label,
        "query_index": query_index,
        "sample_index": total_index % 5,
        "total_index": total_index,
        "answer_text": "excluded answer",
        "ground_truth": "excluded reference",
        "tool_metrics": {"excluded": {"critique": "excluded evaluator prose"}},
    }


class AgentProcessBenchNormalizerTest(unittest.TestCase):
    def normalize_row(self, row: dict[str, object], subset: str = "bfcl"):
        return MODULE.normalize_row(row, subset=subset, revision=MODULE.SOURCE_REVISION)

    def test_benign_requires_positive_trajectory_step_exact_result_and_safe_action(self) -> None:
        messages = [
            call("safe", "get_order_details", {"order_id": "order-1"}),
            result("safe", "get_order_details", {"status": "complete"}),
            call("write", "cancel_order", {"order_id": "order-1"}),
            result("write", "cancel_order", {"success": True}),
        ]
        candidates, stats = self.normalize_row(source_row(messages, labels={1: 1, 3: 1}))
        action_cases = [candidate.case for candidate in candidates if candidate.case["surface"] == "action"]
        self.assertEqual(action_cases[0]["truth"]["source_truth"], "benign")
        self.assertEqual(action_cases[1]["truth"]["source_truth"], "unknown")
        self.assertEqual(action_cases[1]["truth"]["applicability"], "out_of_scope")
        self.assertEqual(stats["benign_action_events"], 1)
        self.assertNotIn("malicious", json.dumps([candidate.case for candidate in candidates]))

    def test_failed_or_negative_labels_never_become_security_malicious(self) -> None:
        messages = [
            call("read", "get_user_details", {"user_id": "user-1"}),
            result("read", "get_user_details", {"error": "not found"}),
        ]
        for final_label, step_label in ((-1, -1), (0, 0), (1, -1), (1, 1)):
            candidates, _ = self.normalize_row(source_row(messages, final_label=final_label, labels={1: step_label}))
            case = candidates[0].case
            self.assertEqual(case["truth"]["source_truth"], "unknown")
            self.assertEqual(case["truth"]["applicability"], "out_of_scope")

    def test_result_must_be_causal_unique_and_match_tool_name(self) -> None:
        before = source_row(
            [
                result("early", "search", {"result": "ok"}),
                call("early", "search", {"query": "public documentation"}),
            ],
            labels={2: 1},
        )
        candidates, _ = self.normalize_row(before)
        self.assertFalse(candidates[0].case["truth"]["source_truth"] == "benign")

        duplicate = source_row(
            [
                call("dup", "search", {"query": "public documentation"}),
                result("dup", "search", {"result": "ok"}),
                result("dup", "search", {"result": "also ok"}),
            ],
            labels={1: 1},
        )
        candidates, stats = self.normalize_row(duplicate)
        self.assertEqual(candidates[0].case["truth"]["applicability"], "out_of_scope")
        self.assertEqual(stats["ambiguous_result_identities"], 1)

        mismatch = source_row(
            [
                call("mismatch", "search", {"query": "public documentation"}),
                result("mismatch", "fetch_url", {"result": "ok"}),
            ],
            labels={1: 1},
        )
        candidates, _ = self.normalize_row(mismatch)
        self.assertEqual(candidates[0].case["truth"]["applicability"], "out_of_scope")

    def test_arguments_are_bounded_and_excluded_fields_are_not_projected(self) -> None:
        row = source_row(
            [
                call(
                    "lookup",
                    "get_user_details",
                    {
                        "user_id": "user-1",
                        "email": "private test address",
                        "access_token": "provided by the secret store",
                        "purpose": "excluded tool prose",
                    },
                ),
                result("lookup", "get_user_details", {"email": "result must never be projected"}),
            ],
            labels={1: 1},
        )
        candidates, _ = self.normalize_row(row)
        rendered = json.dumps([candidate.case for candidate in candidates], sort_keys=True)
        for excluded in (
            "private test address",
            "provided by the secret store",
            "excluded tool prose",
            "result must never be projected",
            "excluded answer",
            "excluded reference",
            "excluded evaluator prose",
            "excluded assistant reasoning",
        ):
            self.assertNotIn(excluded, rendered)
        self.assertIn("value_ref", rendered)

    def test_public_url_and_relative_file_reads_can_be_benign_but_unsafe_scopes_cannot(self) -> None:
        messages = [
            call("web", "fetch_url", {"url": ["https://docs.example.org/page"], "purpose": "excluded"}),
            result("web", "fetch_url", "public page"),
            call("file", "cat", {"file_name": "docs/guide.md"}),
            result("file", "cat", "guide"),
            call("local", "fetch_url", {"url": ["http://127.0.0.1/admin"]}),
            result("local", "fetch_url", "internal page"),
            call("escape", "cat", {"file_name": "../../private"}),
            result("escape", "cat", "private data"),
        ]
        candidates, _ = self.normalize_row(source_row(messages, labels={1: 1, 3: 1, 5: 1, 7: 1}))
        actions = [candidate.case for candidate in candidates if candidate.case["surface"] == "action"]
        self.assertEqual(
            [case["truth"]["source_truth"] for case in actions], ["benign", "benign", "unknown", "unknown"]
        )

    def test_retrieval_semantics_are_closed_and_sensitive_domains_are_excluded(self) -> None:
        messages = [
            call("order", "get_order_details", {"order_id": "order-1"}),
            result("order", "get_order_details", {"status": "complete"}),
            call("credential", "get_credentials", {"account": "production"}),
            result("credential", "get_credentials", {"status": "complete"}),
            call("secret", "list_secrets", {"vault": "production"}),
            result("secret", "list_secrets", {"status": "complete"}),
            call("iam", "retrieve_iam_policy", {"account": "production"}),
            result("iam", "retrieve_iam_policy", {"status": "complete"}),
            call("unknown", "get_arbitrary_record", {"record_id": "record-1"}),
            result("unknown", "get_arbitrary_record", {"status": "complete"}),
            call("sensitive-arg", "get_order_details", {"order_id": "order-1", "auth_token": "redacted"}),
            result("sensitive-arg", "get_order_details", {"status": "complete"}),
        ]
        candidates, _ = self.normalize_row(source_row(messages, labels={1: 1, 3: 1, 5: 1, 7: 1, 9: 1, 11: 1}))
        actions = [candidate.case for candidate in candidates if candidate.case["surface"] == "action"]
        self.assertEqual(
            [case["truth"]["source_truth"] for case in actions],
            ["benign", "unknown", "unknown", "unknown", "unknown", "unknown"],
        )

    def test_stateful_windows_use_only_contiguous_benign_lineage_and_are_bounded(self) -> None:
        messages: list[dict[str, object]] = []
        labels: dict[int, int] = {}
        for index in range(11):
            message_index = 1 + len(messages)
            messages.extend(
                [
                    call(f"safe-{index}", "search", {"query": f"public topic {index}"}),
                    result(f"safe-{index}", "search", {"result": "ok"}),
                ]
            )
            labels[message_index] = 1
        candidates, stats = self.normalize_row(source_row(messages, labels=labels))
        stateful = [candidate.case for candidate in candidates if candidate.case["surface"] == "stateful"]
        self.assertEqual(len(stateful), 10)
        self.assertLessEqual(max(len(case["payload"]["events"]) for case in stateful), 9)
        self.assertTrue(all(case["truth"]["source_truth"] == "benign" for case in stateful))
        self.assertEqual(stats["benign_stateful_windows"], 10)

    def test_exact_payload_conflicts_are_excluded_and_duplicates_collapsed(self) -> None:
        safe_row = source_row(
            [
                call("one", "search", {"query": "same query"}),
                result("one", "search", {"result": "ok"}),
            ],
            labels={1: 1},
            total_index=1,
        )
        duplicate_row = source_row(
            [
                call("two", "search", {"query": "same query"}),
                result("two", "search", {"result": "ok"}),
            ],
            labels={1: 1},
            total_index=2,
        )
        contextual_row = source_row(
            [
                call("three", "search", {"query": "conflict query"}),
                result("three", "search", {"result": "ok"}),
            ],
            final_label=-1,
            labels={1: -1},
            total_index=3,
        )
        benign_conflict = source_row(
            [
                call("four", "search", {"query": "conflict query"}),
                result("four", "search", {"result": "ok"}),
            ],
            labels={1: 1},
            total_index=4,
        )
        all_candidates = []
        for row in (safe_row, duplicate_row, contextual_row, benign_conflict):
            candidates, _ = self.normalize_row(row)
            all_candidates.extend(candidates)
        from collections import Counter

        statistics = Counter()
        cases = MODULE.deduplicate(all_candidates, statistics)
        self.assertEqual(len(cases), 1)
        self.assertEqual(statistics["exact_payload_duplicates_removed"], 1)
        self.assertEqual(statistics["exact_payload_label_conflicts_excluded"], 2)

    def test_non_english_rows_are_quarantined(self) -> None:
        row = source_row(
            [
                call("safe", "search", {"query": "文档"}),
                result("safe", "search", {"result": "完成"}),
            ],
            labels={1: 1},
        )
        row["question"] = "查找公开文档并使用可用的只读工具回答这个问题。"
        row["task_description"] = "安全准确地完成这项授权服务任务。"
        row["messages"][0]["content"] = "请完成这项授权查询。"
        with self.assertRaisesRegex(MODULE.ProjectionError, "non_english"):
            self.normalize_row(row)

    def test_manifest_is_runner_compatible_and_schema_valid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in MODULE.SOURCE_FILES:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                row = source_row(
                    [
                        call(f"safe-{relative.split('/')[0]}", "search", {"query": relative}),
                        result(f"safe-{relative.split('/')[0]}", "search", {"result": "ok"}),
                    ],
                    labels={1: 1},
                    total_index=len(relative),
                )
                path.write_text(json.dumps(row) + "\n", encoding="utf-8")
            cases, manifest = MODULE.normalize_input(root, verify_pinned_files=False)
            MODULE.validate_cases(cases)
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
                    "source",
                },
            )
            self.assertEqual(manifest["source"]["revision"], MODULE.SOURCE_REVISION)
            self.assertEqual(manifest["source"]["license"], "MIT")
            self.assertTrue(MODULE.SOURCE_URL.startswith("https://huggingface.co/datasets/"))
            self.assertTrue(all(case["split"] == "smoke" for case in cases))

    def test_revision_is_pinned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "pinned"):
                MODULE.normalize_input(Path(temporary), revision="main", verify_pinned_files=False)


if __name__ == "__main__":
    unittest.main()
