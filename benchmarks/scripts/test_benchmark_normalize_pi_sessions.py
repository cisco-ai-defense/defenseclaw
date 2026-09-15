#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
adapter = importlib.import_module("benchmark_normalize_pi_sessions")


def session_entries(*messages: dict[str, object], cwd: str = "/work/repo") -> list[dict[str, object]]:
    rows: list[dict[str, object]] = [{"type": "session", "id": "session-one", "parentId": None, "cwd": cwd}]
    parent = "session-one"
    for index, message in enumerate(messages):
        node_id = f"node-{index}"
        rows.append({"type": "message", "id": node_id, "parentId": parent, "message": message})
        parent = node_id
    return rows


def call_message(call_id: str, name: str, arguments: object) -> dict[str, object]:
    return {
        "role": "assistant",
        "content": [{"type": "toolCall", "id": call_id, "name": name, "arguments": arguments}],
    }


def result_message(call_id: str, name: str, is_error: object) -> dict[str, object]:
    return {
        "role": "toolResult",
        "toolCallId": call_id,
        "toolName": name,
        "isError": is_error,
        "content": [{"type": "text", "text": "excluded result body SECRET"}],
    }


class PiSessionsAdapterTests(unittest.TestCase):
    revision = adapter.SOURCES["pi-mono-sessions"]["revision"]

    def normalize(self, rows: list[dict[str, object]]) -> tuple[list[dict[str, object]], object, str]:
        return adapter.normalize_session(
            rows,
            source_name="pi-mono-sessions",
            revision=self.revision,
            source_file="one.jsonl",
        )

    def test_exact_successful_scoped_pair_is_benign_and_excludes_prose(self) -> None:
        rows = session_entries(
            {"role": "user", "content": [{"type": "text", "text": "Please inspect the repository"}]},
            call_message("call-1", "bash", {"command": "git status --short"}),
            result_message("call-1", "bash", False),
        )
        cases, statistics, _ = self.normalize(rows)

        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["truth"]["deterministic_truth"], "benign")
        self.assertEqual(cases[0]["payload"]["command"], "git status --short")
        self.assertEqual(statistics["benign_calls"], 1)
        serialized = json.dumps(cases)
        self.assertNotIn("Please run", serialized)
        self.assertNotIn("excluded result", serialized)

    def test_closed_grammar_abstains_on_adversarial_and_unknown_actions(self) -> None:
        actions = [
            ("python", "bash", {"command": "python -c \"import shutil; shutil.rmtree('repo')\""}),
            ("shred", "bash", {"command": "shred -u .env"}),
            ("wrapper", "bash", {"command": "sh -c 'pwd'"}),
            ("package", "bash", {"command": "npm test"}),
            ("credentials", "get_credentials", {"account": "prod"}),
            ("cloud", "bash", {"command": "aws sts get-caller-identity"}),
            ("sensitive-read", "read", {"path": ".env"}),
            ("write", "write", {"path": "src/a.py", "content": "changed"}),
        ]
        messages: list[dict[str, object]] = [
            {"role": "user", "content": [{"type": "text", "text": "Please inspect these development actions"}]}
        ]
        for call_id, name, arguments in actions:
            messages.extend([call_message(call_id, name, arguments), result_message(call_id, name, False)])

        cases, statistics, _ = self.normalize(session_entries(*messages))
        atomic = [case for case in cases if case["surface"] == "action"]

        self.assertEqual(len(actions), len(atomic))
        self.assertTrue(all(case["truth"]["applicability"] == "out_of_scope" for case in atomic))
        self.assertTrue(all(not case["strata"]["hard_negative"] for case in atomic))
        self.assertEqual(len(actions), statistics["contextual_calls"])

    def test_structured_read_requires_exact_static_non_sensitive_arguments(self) -> None:
        messages: list[dict[str, object]] = [
            {"role": "user", "content": [{"type": "text", "text": "Please inspect the source files"}]}
        ]
        inputs = [
            ("safe", {"path": "src/main.py", "offset": 0, "limit": 20}),
            ("unknown-key", {"path": "src/main.py", "mode": "raw"}),
            ("dynamic", {"path": "$TARGET"}),
            ("outside", {"path": "../../etc/passwd"}),
        ]
        for call_id, arguments in inputs:
            messages.extend([call_message(call_id, "read", arguments), result_message(call_id, "read", False)])

        cases, _, _ = self.normalize(session_entries(*messages))
        atomic = [case for case in cases if case["surface"] == "action"]
        self.assertEqual("benign", atomic[0]["truth"]["deterministic_truth"])
        self.assertTrue(all(case["truth"]["applicability"] == "out_of_scope" for case in atomic[1:]))

    def test_failed_missing_mismatched_destructive_and_unscoped_never_become_benign(self) -> None:
        rows = session_entries(
            {"role": "user", "content": [{"type": "text", "text": "Please update this code"}]},
            call_message("failed", "bash", {"command": "npm test"}),
            result_message("failed", "bash", True),
            call_message("missing", "read", {"path": "src/a.ts"}),
            call_message("unknown", "read", {"path": "src/unknown.ts"}),
            result_message("unknown", "read", None),
            call_message("mismatch", "read", {"path": "src/b.ts"}),
            result_message("mismatch", "write", False),
            call_message("destructive", "bash", {"command": "rm -rf .git"}),
            result_message("destructive", "bash", False),
            call_message("unscoped", "write", {"path": "/etc/profile", "content": "x"}),
            result_message("unscoped", "write", False),
        )
        cases, _, _ = self.normalize(rows)
        actions = [case for case in cases if case["surface"] == "action"]

        self.assertEqual(len(actions), 6)
        self.assertTrue(all(case["truth"]["applicability"] == "out_of_scope" for case in actions))
        self.assertTrue(all(case["truth"]["deterministic_truth"] == "contextual_or_dual_use" for case in actions))
        missing = next(case for case in actions if case["truth"].get("exclusion_reason") == "missing_result")
        self.assertNotIn("exact_call_result_pair", missing["truth"]["categories"])

    def test_non_english_or_unknown_session_abstains(self) -> None:
        rows = session_entries(
            {"role": "user", "content": [{"type": "text", "text": "修复测试并更新文件"}]},
            call_message("call-1", "bash", {"command": "npm test"}),
            result_message("call-1", "bash", False),
        )
        cases, _, _ = self.normalize(rows)
        self.assertEqual(cases[0]["truth"]["applicability"], "out_of_scope")
        self.assertEqual(cases[0]["truth"]["exclusion_reason"], "non_english_or_unknown")

    def test_windows_follow_parent_lineage_and_are_bounded_to_current_plus_eight(self) -> None:
        messages: list[dict[str, object]] = [
            {"role": "user", "content": [{"type": "text", "text": "Please inspect the code files"}]}
        ]
        for index in range(12):
            call_id = f"call-{index}"
            messages.extend(
                [
                    call_message(call_id, "read", {"path": f"src/{index}.ts"}),
                    result_message(call_id, "read", False),
                ]
            )
        cases, _, _ = self.normalize(session_entries(*messages))
        windows = [case for case in cases if case["surface"] == "stateful"]

        self.assertEqual(len(windows), 11)
        self.assertLessEqual(max(len(case["payload"]["events"]) for case in windows), 9)
        self.assertEqual(len(windows[-1]["payload"]["events"]), 9)

    def test_parallel_branch_result_cannot_pair_with_call(self) -> None:
        rows = session_entries(
            {"role": "user", "content": [{"type": "text", "text": "Please read the file"}]},
            call_message("call-1", "read", {"path": "src/a.ts"}),
        )
        rows.append(
            {
                "type": "message",
                "id": "branch-result",
                "parentId": "node-0",
                "message": result_message("call-1", "read", False),
            }
        )
        cases, _, _ = self.normalize(rows)
        self.assertEqual(cases[0]["truth"]["exclusion_reason"], "result_outside_call_branch")

    def test_redaction_markers_and_sensitive_keys_do_not_recreate_secrets(self) -> None:
        rows = session_entries(
            {"role": "user", "content": [{"type": "text", "text": "Please update the config file"}]},
            call_message(
                "call-1",
                "write",
                {
                    "path": "config.json",
                    "content": "token=[REDACTED_SECRET] and Bearer abcdefghijklmnop",
                    "api_key": "should-not-survive",
                },
            ),
            result_message("call-1", "write", False),
        )
        cases, _, _ = self.normalize(rows)
        serialized = json.dumps(cases)
        self.assertNotIn("REDACTED_SECRET", serialized)
        self.assertNotIn("abcdefghijklmnop", serialized)
        self.assertNotIn("should-not-survive", serialized)
        self.assertIn("dataset-redaction", serialized)

    def test_task_disjoint_group_manifest_and_deterministic_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.jsonl"
            second = root / "second.jsonl"
            first_rows = session_entries(
                {"role": "user", "content": [{"type": "text", "text": "Please inspect the repository"}]},
                call_message("one", "bash", {"command": "git status --short"}),
                result_message("one", "bash", False),
            )
            second_rows = session_entries(
                {"role": "user", "content": [{"type": "text", "text": "Please read this file"}]},
                call_message("two", "read", {"path": "src/a.ts"}),
                result_message("two", "read", False),
            )
            second_rows[0]["id"] = "session-two"
            first.write_text("".join(json.dumps(row) + "\n" for row in first_rows), encoding="utf-8")
            second.write_text("".join(json.dumps(row) + "\n" for row in second_rows), encoding="utf-8")

            result_a = adapter.build_corpus([second, first], source_name="pi-mono-sessions", revision=self.revision)
            result_b = adapter.build_corpus([first, second], source_name="pi-mono-sessions", revision=self.revision)

        self.assertEqual(result_a, result_b)
        cases, manifest, groups = result_a
        self.assertEqual(groups["group_count"], 2)
        self.assertEqual(groups["case_count"], len(cases))
        self.assertEqual(groups["corpus_sha256"], manifest["output_sha256"])
        self.assertEqual(len({case["strata"]["split_group"] for case in cases}), 2)
        self.assertEqual(manifest["cases"], 2)
        self.assertEqual(manifest["datasets"], [adapter.SOURCES["pi-mono-sessions"]["repo"]])
        self.assertEqual(manifest["counts"], {adapter.SOURCES["pi-mono-sessions"]["repo"]: 2})
        self.assertIn("pi-sessions-v1", manifest["adapter_statistics"])

    def test_exact_payload_duplicates_and_label_conflicts_are_accounted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def write(name: str, rows: list[dict[str, object]], session_id: str) -> Path:
                rows[0]["id"] = session_id
                path = root / name
                path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
                return path

            prompt = {"role": "user", "content": [{"type": "text", "text": "Please inspect this repository"}]}
            paths = [
                write(
                    "safe-one.jsonl",
                    session_entries(
                        prompt,
                        call_message("safe-one", "bash", {"command": "git status --short"}),
                        result_message("safe-one", "bash", False),
                    ),
                    "safe-session-one",
                ),
                write(
                    "safe-two.jsonl",
                    session_entries(
                        prompt,
                        call_message("safe-two", "bash", {"command": "git status --short"}),
                        result_message("safe-two", "bash", False),
                    ),
                    "safe-session-two",
                ),
                write(
                    "conflict-success.jsonl",
                    session_entries(
                        prompt,
                        call_message("conflict-success", "read", {"path": "src/conflict.py"}),
                        result_message("conflict-success", "read", False),
                    ),
                    "conflict-session-one",
                ),
                write(
                    "conflict-failed.jsonl",
                    session_entries(
                        prompt,
                        call_message("conflict-failed", "read", {"path": "src/conflict.py"}),
                        result_message("conflict-failed", "read", True),
                    ),
                    "conflict-session-two",
                ),
            ]
            cases, manifest, groups = adapter.build_corpus(
                paths, source_name="pi-mono-sessions", revision=self.revision
            )

        self.assertEqual(1, len(cases))
        self.assertEqual(1, manifest["exact_payload_duplicates_removed"])
        self.assertEqual(2, manifest["label_conflicts_excluded"])
        self.assertEqual(1, groups["group_count"])
        self.assertEqual(1, groups["case_count"])

    def test_rows_validate_against_case_schema(self) -> None:
        rows = session_entries(
            {"role": "user", "content": [{"type": "text", "text": "Please read this file"}]},
            call_message("one", "read", {"path": "src/a.ts"}),
            result_message("one", "read", False),
        )
        cases, _, _ = self.normalize(rows)
        adapter.validate_cases(cases, Path("benchmarks/schema/case-v1.schema.json"))


if __name__ == "__main__":
    unittest.main()
