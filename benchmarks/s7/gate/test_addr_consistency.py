#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: E501  (the checked-in benchmark tooling has always been long-line)
"""Tests for addr_consistency (rel-1-0-10 GAP-1280): the task keeps the real address while the calls hold the placeholder. Synthetic cases, no corpus data."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import addr_consistency as AC  # noqa: E402, N812

TOOL = HERE / "addr_consistency.py"


def action(cid, content, args):
    return {
        "id": cid,
        "schema_version": "1",
        "surface": "action",
        "strata": {"platform": "linux"},
        "truth": {"source_truth": "benign", "expected_disposition": "allow"},
        "payload": {"tool_name": "send_email", "dialect": "none", "args": args, "content": content},
    }


def stateful(cid, intent, ev_args):
    return {
        "id": cid,
        "schema_version": "1",
        "surface": "stateful",
        "strata": {"platform": "linux"},
        "truth": {"source_truth": "malicious", "expected_disposition": "block"},
        "payload": {"user_intent": intent, "events": [{"tool_name": "send_email", "args": ev_args, "dialect": "none"}]},
    }


MISMATCH = action(
    "m1", "Send the summary to alice.smith@corp.test and cc bob@corp.test", {"to": ["user@example.com"], "subject": "x"}
)
STATEFUL = stateful("m2", "Mail the report to carol@corp.test", {"to": "user@example.com"})
NO_PLACEHOLDER = action("n1", "Send the summary to alice.smith@corp.test", {"to": "alice.smith@corp.test"})
CONSISTENT = action("c1", "Send the summary to user@example.com", {"to": "user@example.com"})
NO_ADDRESS = action("n2", "Summarise the file", {"path": "/tmp/a"})


class AddrConsistency(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def corpus(self, name, rows):
        p = self.root / name
        p.write_text("".join(AC.dumps(r, True) + "\n" for r in rows))
        return p

    def tool(self, *args):
        return subprocess.run(
            [sys.executable, "-I", str(TOOL), *map(str, args)], capture_output=True, text=True, check=False
        )

    def test_which_cases_need_the_fix(self):
        self.assertTrue(AC.needs_fix(MISMATCH))
        self.assertTrue(AC.needs_fix(STATEFUL))
        for r in (NO_PLACEHOLDER, CONSISTENT, NO_ADDRESS):
            self.assertFalse(AC.needs_fix(r), r["id"])

    def test_fixed_redacts_the_task_only(self):
        f = AC.fixed(MISMATCH)
        self.assertEqual(f["payload"]["content"], "Send the summary to user@example.com and cc user@example.com")
        self.assertEqual(f["payload"]["args"], MISMATCH["payload"]["args"])
        self.assertEqual(
            {k: v for k, v in f.items() if k != "payload"}, {k: v for k, v in MISMATCH.items() if k != "payload"}
        )
        self.assertEqual(AC.fixed(STATEFUL)["payload"]["user_intent"], "Mail the report to user@example.com")
        self.assertFalse(AC.needs_fix(f), "a fixed case needs nothing more")
        self.assertEqual(MISMATCH["payload"]["content"].count("@corp.test"), 2, "the input case is not modified")

    def test_check_lists_ids_only_and_exits_1(self):
        c = self.corpus("in.jsonl", [MISMATCH, NO_PLACEHOLDER, STATEFUL, CONSISTENT])
        r = self.tool("check", c)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertEqual(r.stdout.splitlines()[:2], ["m1", "m2"])
        self.assertIn("2 of 4 cases", r.stdout)
        self.assertNotIn("corp.test", r.stdout + r.stderr)
        self.assertEqual(
            self.tool("check", self.corpus("ok.jsonl", [NO_PLACEHOLDER, CONSISTENT, NO_ADDRESS])).returncode, 0
        )

    def test_check_takes_several_files_and_is_red_when_any_is(self):
        red = self.corpus("red.jsonl", [MISMATCH, CONSISTENT])
        green = self.corpus("green.jsonl", [NO_PLACEHOLDER, NO_ADDRESS])
        r = self.tool("check", green, red)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("0 of 2 cases", r.stdout)
        self.assertIn("1 of 2 cases", r.stdout)
        self.assertEqual(self.tool("check", green, self.corpus("green2.jsonl", [CONSISTENT])).returncode, 0)
        fixed = self.root / "red.fixed.jsonl"
        self.assertEqual(self.tool("fix", red, fixed).returncode, 0)
        self.assertEqual(self.tool("check", green, fixed).returncode, 0, "the new corpus version is green")

    def test_fix_writes_a_new_file_and_keeps_untouched_rows_byte_identical(self):
        c = self.corpus("in.jsonl", [MISMATCH, NO_PLACEHOLDER, STATEFUL, CONSISTENT])
        out = self.root / "out.jsonl"
        r = self.tool("fix", c, out)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("redacted in 2", r.stdout)
        old, new = c.read_text().splitlines(), out.read_text().splitlines()
        self.assertEqual(len(old), len(new))
        self.assertEqual([new[1], new[3]], [old[1], old[3]])
        self.assertNotEqual((new[0], new[2]), (old[0], old[2]))
        self.assertEqual(json.loads(new[0]), AC.fixed(MISMATCH))
        self.assertEqual(self.tool("check", out).returncode, 0, "after the fix there is nothing left to fix")
        self.assertNotIn("corp.test", new[0] + new[2])

    def test_fix_never_rewrites_a_file_in_place(self):
        c = self.corpus("in.jsonl", [MISMATCH])
        before = c.read_text()
        self.assertEqual(self.tool("fix", c, c).returncode, 4)
        (self.root / "exists.jsonl").write_text("x")
        self.assertEqual(self.tool("fix", c, self.root / "exists.jsonl").returncode, 4)
        self.assertEqual(c.read_text(), before)

    def test_fix_refuses_a_row_that_is_not_in_canonical_form(self):
        c = self.root / "in.jsonl"
        c.write_text(json.dumps(MISMATCH, indent=1).replace("\n", " ") + "\n")
        r = self.tool("fix", c, self.root / "out.jsonl")
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertFalse((self.root / "out.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
