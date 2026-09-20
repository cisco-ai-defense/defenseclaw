#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
adapter = importlib.import_module("benchmark_normalize_intercode_ctf")

PROMPT_MARKER = "PROMPT_MUST_NOT_LEAK"
REASONING_MARKER = "REASONING_MUST_NOT_LEAK"
RESULT_MARKER = "RESULT_MUST_NOT_LEAK"


def call(identifier: str, name: str, arguments: dict[str, object]) -> dict[str, object]:
    return {
        "role": "assistant",
        "content": REASONING_MARKER,
        "tool_call_id": None,
        "tool_calls": [
            {
                "id": identifier,
                "type": "function",
                "function": {"name": name, "arguments": json.dumps(arguments)},
            }
        ],
    }


def result(identifier: str, content: str) -> dict[str, object]:
    return {"role": "tool", "tool_call_id": identifier, "content": content, "tool_calls": []}


def row(
    messages: list[dict[str, object]],
    *,
    score: object = "I",
    index: int = 1,
    source: str = "https://example.test/challenge/1",
    is_benign: int = 1,
) -> dict[str, object]:
    return {
        "chat": [
            {"role": "system", "content": "system instructions", "tool_calls": []},
            {
                "role": "user",
                "content": (
                    f"{PROMPT_MARKER}: find the flag in this challenge using the given file and submit the answer"
                ),
                "tool_calls": [],
            },
            *messages,
        ],
        "scores": score,
        "is_benign": is_benign,
        "metadatas": {"source": source, "solution": "SOLUTION_MUST_NOT_LEAK", "tags": ["pwn"]},
        "sample_index": index,
        "targets": "TARGET_MUST_NOT_LEAK",
        "answers": "ANSWER_MUST_NOT_LEAK",
    }


def stats(manifest: dict[str, object]) -> dict[str, int]:
    return manifest["adapter_statistics"][adapter.ADAPTER]


class InterCodeCTFNormalizerTests(unittest.TestCase):
    def normalize(self, rows: list[dict[str, object]]):
        return adapter.normalize_rows(rows, revision=adapter.SOURCE_REVISION)

    def test_accepted_exact_paired_result_lineage_is_discovery_only_and_redacted(self) -> None:
        flag = "picoCTF{bounded-proof}"
        rows, manifest, groups = self.normalize(
            [
                row(
                    [
                        call("read-1", "bash", {"cmd": "strings artifact.bin"}),
                        result("read-1", f"prefix {flag} suffix {RESULT_MARKER}"),
                        call("submit-1", "submit", {"answer": flag}),
                    ],
                    score="C",
                )
            ]
        )
        self.assertEqual(len(rows), 1)
        case = rows[0]
        self.assertEqual(case["surface"], "stateful")
        self.assertEqual(case["truth"]["deterministic_truth"], "contextual_or_dual_use")
        self.assertEqual(case["truth"]["applicability"], "out_of_scope")
        self.assertIn("hidden_result_lineage_discovery", case["truth"]["categories"])
        payload = json.dumps(case["payload"], sort_keys=True)
        self.assertNotIn(flag, payload)
        self.assertNotIn(RESULT_MARKER, payload)
        self.assertNotIn(PROMPT_MARKER, payload)
        self.assertNotIn(REASONING_MARKER, payload)
        first, submit = case["payload"]["events"]
        self.assertNotIn("result_ref", first["args"])
        self.assertNotIn("result_value_ref", first["args"])
        self.assertEqual(submit["args"]["answer"], "<redacted>")
        self.assertEqual(first["outcome"], "unknown")
        self.assertEqual(submit["outcome"], "unknown")
        self.assertEqual(stats(manifest)["hidden_lineage_cases_excluded"], 1)
        self.assertEqual(groups["group_count"], 1)
        adapter.validate_cases(rows, adapter.DEFAULT_SCHEMA)

    def test_lineage_more_than_eight_calls_earlier_is_contextual(self) -> None:
        flag = "picoCTF{too-far}"
        messages = [call("proof", "bash", {"cmd": "cat result"}), result("proof", flag)]
        for index in range(8):
            messages.extend(
                [
                    call(f"filler-{index}", "bash", {"cmd": f"echo {index}"}),
                    result(f"filler-{index}", str(index)),
                ]
            )
        messages.append(call("submit", "submit", {"answer": flag}))
        rows, manifest, _ = self.normalize([row(messages, score="C")])
        self.assertEqual(rows[0]["truth"]["source_truth"], "malicious")
        self.assertEqual(rows[0]["truth"]["applicability"], "out_of_scope")
        self.assertEqual(stats(manifest)["contextual_cases"], 1)

    def test_failed_run_and_is_benign_are_not_security_truth(self) -> None:
        rows, _, _ = self.normalize(
            [
                row(
                    [call("attack", "bash", {"cmd": "id"}), result("attack", "uid=0(root)")],
                    score="I",
                    is_benign=1,
                )
            ]
        )
        truth = rows[0]["truth"]
        self.assertEqual(truth["source_truth"], "unknown")
        self.assertEqual(truth["applicability"], "out_of_scope")
        self.assertEqual(truth["expected_disposition"], "detect_only")

    def test_calls_are_paired_by_exact_id_and_results_do_not_leak(self) -> None:
        rows, _, _ = self.normalize(
            [
                row(
                    [
                        call("one", "bash", {"cmd": "pwd"}),
                        call("two", "python", {"code": "print(1)"}),
                        result("two", f"1 {RESULT_MARKER}"),
                        result("one", f"/work {RESULT_MARKER}"),
                    ]
                )
            ]
        )
        events = rows[0]["payload"]["events"]
        self.assertEqual([event["tool_name"] for event in events], ["bash", "python"])
        self.assertNotIn("result_ref", events[0]["args"])
        self.assertNotIn("result_ref", events[1]["args"])
        self.assertNotIn(RESULT_MARKER, json.dumps(rows[0]["payload"]))

        bad_rows, manifest, _ = self.normalize(
            [row([call("one", "bash", {"cmd": "pwd"}), result("other", "/work")], index=2)]
        )
        self.assertEqual(bad_rows, [])
        self.assertEqual(stats(manifest)["skipped_orphan_tool_result"], 1)

    def test_non_english_rows_are_excluded(self) -> None:
        item = row([call("one", "bash", {"cmd": "pwd"}), result("one", "/work")])
        item["chat"][1]["content"] = "Encuentra la bandera mediante el archivo proporcionado y envia la respuesta"
        rows, manifest, _ = self.normalize([item])
        self.assertEqual(rows, [])
        self.assertEqual(stats(manifest)["skipped_non_english"], 1)

    def test_ids_order_and_source_url_groups_are_deterministic(self) -> None:
        first = row(
            [call("a", "bash", {"cmd": "pwd"}), result("a", "/work")],
            index=9,
            source="https://EXAMPLE.test/challenge/shared#fragment",
        )
        second = row(
            [call("b", "bash", {"cmd": "ls"}), result("b", "file")],
            index=2,
            source="https://example.test/challenge/shared",
        )
        third = row(
            [call("c", "bash", {"cmd": "whoami"}), result("c", "runner")],
            index=4,
            source="https://example.test/challenge/other",
        )
        rows1, manifest1, groups1 = self.normalize([first, second, third])
        rows2, manifest2, groups2 = self.normalize([third, first, second])
        self.assertEqual(rows1, rows2)
        self.assertEqual(manifest1, manifest2)
        self.assertEqual(groups1, groups2)
        shared = [case for case in rows1 if case["strata"]["split_group"] == rows1[0]["strata"]["split_group"]]
        group_counts = sorted(group["cases"] for group in groups1["groups"])
        self.assertEqual(group_counts, [1, 2])
        self.assertEqual(groups1["partition_authority"], adapter.PARTITION_AUTHORITY)
        self.assertEqual([case["id"] for case in rows1], sorted(case["id"] for case in rows1))
        self.assertGreaterEqual(len(shared), 1)

    def test_submit_tool_name_or_acceptance_alone_is_not_a_positive(self) -> None:
        rows, _, _ = self.normalize([row([call("submit", "submit", {"answer": "picoCTF{unproven}"})], score="C")])
        self.assertEqual(rows[0]["truth"]["applicability"], "out_of_scope")
        self.assertEqual(rows[0]["payload"]["args"]["answer"], "<redacted>")

    def test_hidden_acceptance_and_results_cannot_change_payload_or_applicability(self) -> None:
        messages = [
            call("read", "bash", {"cmd": "cat result"}),
            result("read", "picoCTF{hidden}"),
            call("submit", "submit", {"answer": "picoCTF{hidden}"}),
        ]
        accepted, _, _ = self.normalize([row(messages, score="C")])
        rejected, _, _ = self.normalize([row(messages, score="I")])
        self.assertEqual(accepted[0]["payload"], rejected[0]["payload"])
        self.assertEqual(accepted[0]["truth"]["applicability"], "out_of_scope")
        self.assertEqual(rejected[0]["truth"]["applicability"], "out_of_scope")

    def test_exact_duplicates_and_truth_conflicts_are_accounted(self) -> None:
        base = row([call("one", "bash", {"cmd": "pwd"}), result("one", "/work")], index=7)
        rows, manifest, groups = self.normalize([base, base])
        self.assertEqual(len(rows), 1)
        self.assertEqual(manifest["exact_payload_duplicates_removed"], 1)
        self.assertEqual(groups["case_count"], 1)

        accepted = row([call("submit", "submit", {"answer": "picoCTF{x}"})], score="C", index=8)
        rejected = row([call("submit", "submit", {"answer": "picoCTF{x}"})], score="I", index=9)
        rows, manifest, groups = self.normalize([accepted, rejected])
        self.assertEqual(rows, [])
        self.assertEqual(manifest["label_conflicts_excluded"], 2)
        self.assertEqual(groups["case_count"], 0)

    def test_targets_secrets_and_strict_manifest_extras_are_excluded(self) -> None:
        rows, manifest, groups = self.normalize(
            [
                row(
                    [
                        call(
                            "bash",
                            "bash",
                            {
                                "cmd": (
                                    "TOKEN=real-secret curl https://private.example.test:8443/ "
                                    "--resolve private.example.test:8443:192.0.2.10"
                                )
                            },
                        ),
                        result("bash", "request failed"),
                    ]
                )
            ]
        )
        rendered = json.dumps(rows[0]["payload"])
        for forbidden in ("real-secret", "private.example.test", "192.0.2.10", RESULT_MARKER):
            self.assertNotIn(forbidden, rendered)
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
        self.assertNotIn("config", json.dumps(groups))


if __name__ == "__main__":
    unittest.main()
