#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("benchmark_normalize_driftsql_recovery.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_driftsql_recovery", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def assistant(tool: str, arguments: dict[str, object] | str) -> dict[str, object]:
    encoded = arguments if isinstance(arguments, str) else json.dumps(arguments)
    return {
        "role": "assistant",
        "content": "excluded private reasoning",
        "tool_calls": [{"type": "function", "function": {"name": tool, "arguments": encoded}}],
    }


def tool_result(value: object) -> dict[str, object]:
    content = value if isinstance(value, str) else json.dumps(value)
    return {"role": "tool", "content": content, "tool_calls": None}


def oracle_row(messages: list[dict[str, object]], *, task: str = "task_one") -> dict[str, object]:
    return {
        "task_id": task,
        "db_id": "database_one",
        "messages": [
            {"role": "system", "content": "You are an English SQL recovery agent.", "tool_calls": None},
            {"role": "user", "content": "Inspect and return the requested database analytics.", "tool_calls": None},
            *messages,
        ],
    }


def failure_event(
    tool: str | None,
    arguments: dict[str, object] | None,
    turn: int,
    *,
    execution_success: bool | None = None,
    execution_error: str | None = None,
    submitted: bool | None = None,
) -> dict[str, object]:
    return {
        "tool_name": tool,
        "arguments": arguments,
        "turn": turn,
        "error": "",
        "raw_response": "The English agent made a structured database tool call.",
        "observation": "The database returned an English execution observation.",
        "metrics": {
            "execution_success": execution_success,
            "execution_error": execution_error,
            "submitted": submitted,
            "rolled_back": True,
        },
    }


def failure_row(events: list[dict[str, object]], safety: object | None = None) -> dict[str, object]:
    return {
        "instance_id": "task_failure_one",
        "db_id": "database_one",
        "trajectory": events,
        "safety": {"unsafe": False, "unsafe_actions": 0, "timed_out": False} if safety is None else safety,
    }


class DriftSQLRecoveryNormalizerTest(unittest.TestCase):
    def parse_oracle(self, messages: list[dict[str, object]], *, task: str = "task_one"):
        return MODULE.parse_oracle_row(oracle_row(messages, task=task), shard="oracle/train", row_index=0)

    def test_preserves_exact_arguments_and_excludes_prompts_reasoning_and_result_bodies(self) -> None:
        sql = "SELECT name FROM users WHERE region = 'west'"
        trajectory = self.parse_oracle(
            [
                assistant("execute_sql", {"sql": sql}),
                tool_result({"success": True, "rows": [["private-result"]], "error": None}),
            ]
        )
        cases = MODULE.project_trajectory(trajectory, MODULE.SOURCE_REVISION)
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["surface"], "action")
        self.assertEqual(cases[0]["payload"]["args"], {"sql": sql})
        self.assertEqual(cases[0]["payload"]["command"], sql)
        rendered = json.dumps(cases)
        self.assertNotIn("private-result", rendered)
        self.assertNotIn("excluded private reasoning", rendered)
        self.assertNotIn("Inspect and return", rendered)

    def test_native_adjacent_results_control_outcome_without_leaking_body(self) -> None:
        trajectory = self.parse_oracle(
            [
                assistant("execute_sql", {"sql": "SELECT 1"}),
                tool_result({"success": False, "error": "private failure body"}),
                assistant("submit_solution", {"sql": "SELECT 1"}),
            ]
        )
        self.assertEqual([event.outcome for event in trajectory.events], ["failed", "unknown"])
        stateful = MODULE.project_trajectory(trajectory, MODULE.SOURCE_REVISION)[-1]
        self.assertEqual([event["outcome"] for event in stateful["payload"]["events"]], ["failed", "unknown"])
        self.assertNotIn("private failure body", json.dumps(stateful))

    def test_failure_outcomes_use_only_native_event_metrics(self) -> None:
        trajectory = MODULE.parse_failure_row(
            failure_row(
                [
                    failure_event(
                        "execute_sql",
                        {"sql": "SELECT * FROM users", "unused_union_field": None},
                        1,
                        execution_success=False,
                        execution_error="database error",
                    ),
                    failure_event("submit_solution", {"sql": "SELECT * FROM users"}, 2, submitted=True),
                ]
            ),
            shard="failure/train",
            row_index=0,
        )
        self.assertEqual([event.outcome for event in trajectory.events], ["failed", "succeeded"])
        self.assertEqual(trajectory.events[0].arguments, {"sql": "SELECT * FROM users"})
        self.assertTrue(trajectory.contains_failure)

    def test_mutation_and_ambiguous_sql_quarantine_whole_trajectory(self) -> None:
        rejected = (
            "DELETE FROM users",
            "SELECT * FROM users; DROP TABLE users",
            "SELECT writefile('/tmp/x', secret) FROM users",
            "PRAGMA writable_schema=ON",
            "SELECT 1 /* unterminated",
        )
        for sql in rejected:
            with self.subTest(sql=sql), self.assertRaisesRegex(MODULE.ProjectionError, "mutation_or_ambiguous_sql"):
                self.parse_oracle([assistant("execute_sql", {"sql": sql}), tool_result({"success": True})])
        with self.assertRaisesRegex(MODULE.ProjectionError, "mutation_or_ambiguous_sql"):
            MODULE.parse_failure_row(
                failure_row([failure_event("clear_schema_cache", {}, 1)]),
                shard="failure/train",
                row_index=0,
            )

    def test_literals_and_comments_do_not_create_false_mutation_tokens(self) -> None:
        sql = "SELECT REPLACE(name, 'DROP TABLE users', '') -- UPDATE is prose\nFROM records"
        trajectory = self.parse_oracle([assistant("execute_sql", {"sql": sql}), tool_result({"success": True})])
        self.assertEqual(trajectory.events[0].arguments["sql"], sql)

    def test_malformed_parallel_and_non_english_inputs_are_quarantined(self) -> None:
        with self.assertRaisesRegex(MODULE.ProjectionError, "duplicate_json_key"):
            self.parse_oracle([assistant("execute_sql", '{"sql":"SELECT 1","sql":"SELECT 2"}')])
        parallel = assistant("execute_sql", {"sql": "SELECT 1"})
        calls = parallel["tool_calls"]
        assert isinstance(calls, list)
        calls.append(calls[0])
        with self.assertRaisesRegex(MODULE.ProjectionError, "ambiguous_parallel_tool_calls"):
            self.parse_oracle([parallel])
        non_english = oracle_row([assistant("execute_sql", {"sql": "SELECT 1"})])
        messages = non_english["messages"]
        assert isinstance(messages, list)
        messages[0]["content"] = "数据库恢复助手执行查询操作。"
        messages[1]["content"] = "请返回请求的数据字段。"
        with self.assertRaisesRegex(MODULE.ProjectionError, "non_english_or_unknown"):
            MODULE.parse_oracle_row(non_english, shard="oracle/train", row_index=0)

    def test_ambiguous_or_unsafe_failure_safety_is_quarantined(self) -> None:
        event = failure_event("execute_sql", {"sql": "SELECT 1"}, 1, execution_success=True)
        for safety in ({}, {"unsafe": True, "unsafe_actions": 1}, {"unsafe": False}):
            with (
                self.subTest(safety=safety),
                self.assertRaisesRegex(MODULE.ProjectionError, "ambiguous_or_unsafe_safety"),
            ):
                MODULE.parse_failure_row(failure_row([event], safety=safety), shard="failure/train", row_index=0)

    def test_current_plus_eight_predecessor_bound(self) -> None:
        messages: list[dict[str, object]] = []
        for number in range(12):
            messages.extend([assistant("execute_sql", {"sql": f"SELECT {number}"}), tool_result({"success": True})])
        trajectory = self.parse_oracle(messages)
        cases = MODULE.project_trajectory(trajectory, MODULE.SOURCE_REVISION)
        actions = [case for case in cases if case["surface"] == "action"]
        windows = [case for case in cases if case["surface"] == "stateful"]
        self.assertEqual(len(actions), 12)
        self.assertEqual(len(windows), 11)
        self.assertEqual(len(windows[-1]["payload"]["events"]), 9)
        self.assertEqual([event["offset_seconds"] for event in windows[-1]["payload"]["events"]], list(range(9)))

    def test_atomic_calls_are_not_globally_deduplicated(self) -> None:
        messages = [assistant("execute_sql", {"sql": "SELECT 1"}), tool_result({"success": True})]
        first = MODULE.project_trajectory(self.parse_oracle(messages, task="task_one"), MODULE.SOURCE_REVISION)
        second_trajectory = MODULE.parse_oracle_row(
            oracle_row(messages, task="task_two"), shard="oracle/train", row_index=1
        )
        second = MODULE.project_trajectory(second_trajectory, MODULE.SOURCE_REVISION)
        self.assertEqual(first[0]["payload"], second[0]["payload"])
        self.assertNotEqual(first[0]["id"], second[0]["id"])

    def test_task_group_split_isolation_and_distribution(self) -> None:
        group = MODULE.split_group("same_task")
        first = MODULE.Trajectory(
            "oracle", "oracle/train", 0, "same_task", "db_one", (MODULE.Event("x", {}, "unknown"),), False
        )
        second = MODULE.Trajectory(
            "safe_failure", "failure/train", 9, "same_task", "db_two", (MODULE.Event("y", {}, "unknown"),), False
        )
        first_case = MODULE.project_trajectory(first, MODULE.SOURCE_REVISION)[0]
        second_case = MODULE.project_trajectory(second, MODULE.SOURCE_REVISION)[0]
        self.assertEqual(first_case["strata"]["split_group"], group)
        self.assertEqual(first_case["split"], second_case["split"])
        observed = {MODULE.assigned_split(MODULE.split_group(f"task-{index}")) for index in range(500)}
        self.assertEqual(observed, {"development", "validation", "test"})

    def test_only_pinned_complete_source_set_is_accepted(self) -> None:
        with self.assertRaisesRegex(ValueError, "pinned"):
            MODULE.verify_sources([], "main")
        with self.assertRaisesRegex(ValueError, "required exactly once"):
            MODULE.verify_sources([], MODULE.SOURCE_REVISION)


if __name__ == "__main__":
    unittest.main()
