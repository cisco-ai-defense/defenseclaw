#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: E501  (the checked-in benchmark tooling has always been long-line)
"""Tests for build_chainbench_addr1.py --from-built (rel-1-0-10 GAP-1585): task addresses redacted, every other byte of the built chainbench file unchanged. Synthetic sessions."""
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

BUILDER = HERE / "build_chainbench_addr1.py"


def session(sid, content, args):
    return {"id": sid, "schema_version": "case-v1", "surface": "stateful", "split": "eval", "source": {"dataset": "d", "original_id": sid, "revision": "chainbench-v1"},
            "strata": {"src_corpus": "v2-surfaces"}, "truth": {"source_truth": "benign"},
            "payload": {"events": [{"tool_name": "read_file", "args": {"path": "a"}, "outcome": "succeeded"}, {"tool_name": "send_email", "args": args, "outcome": "succeeded"}], "content": content}}


def line(row):
    return json.dumps(row, separators=(",", ":"))  # the builder's own spelling: compact, keys in insertion order (not sorted)


BAD = session("cb/x/bad", "Mail the report to carol@corp.test", {"to": "user@example.com"})
OK1 = session("cb/x/ok1", "Mail the report to user@example.com", {"to": "user@example.com"})
OK2 = session("cb/x/ok2", "Summarise the file", {"path": "a"})


class FromBuilt(unittest.TestCase):
    def test_redacts_the_task_and_keeps_every_other_row_byte_identical(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "in").mkdir()
            src = root / "in" / "chainbench.cases.jsonl"
            src.write_text("".join(line(r) + "\n" for r in (BAD, OK1, OK2)))
            self.assertEqual(subprocess.run([sys.executable, "-I", str(HERE / "addr_consistency.py"), "check", src], capture_output=True, text=True, check=False).returncode, 1, "red before")
            r = subprocess.run([sys.executable, "-I", str(BUILDER), "--out", root / "out", "--from-built", src], capture_output=True, text=True, check=False)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            out = root / "out" / "chainbench.cases.jsonl"
            old, new = src.read_text().splitlines(), out.read_text().splitlines()
            self.assertEqual(len(old), len(new))
            self.assertEqual(old[1:], new[1:], "rows that need nothing are byte-identical")
            row = json.loads(new[0])
            self.assertEqual(row["payload"]["content"], "Mail the report to user@example.com")
            self.assertEqual(AC.fixed(BAD), row, "only the task text changed")
            self.assertEqual(subprocess.run([sys.executable, "-I", str(HERE / "addr_consistency.py"), "check", out], capture_output=True, text=True, check=False).returncode, 0, "green after")
            self.assertEqual(json.loads((root / "out" / "corpora_chainbench_addr1.json").read_text())["chainbench"]["files"], [str(out)])
            again = subprocess.run([sys.executable, "-I", str(BUILDER), "--out", root / "out", "--from-built", src], capture_output=True, text=True, check=False)
            self.assertNotEqual(again.returncode, 0, "an existing output is never overwritten")


if __name__ == "__main__":
    unittest.main()
