# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0
"""fold-labels / check-labels refuse bad input with exit 4, never pass it or die with a traceback (rel-1-0-10 GAP-1583)."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
GATE = HERE / "s7gate.py"


class LabelfoldInputs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.base = self.root / "base.jsonl"
        self.base.write_text(json.dumps({"id": "c1", "source_truth": "benign"}) + "\n")
        self.overlay = self.root / "ov.jsonl"
        self.overlay.write_text(json.dumps({"id": "c1", "source_truth": "malicious", "why": "unit"}) + "\n")

    def gate(self, *args):
        return subprocess.run(
            [sys.executable, "-I", str(GATE), *map(str, args)], capture_output=True, text=True, check=False
        )

    def fold(self, overlay=None, out=None):
        out = out or self.root / "out"
        return self.gate(
            "fold-labels",
            "--base",
            self.base,
            "--overlay",
            overlay or self.overlay,
            "--out",
            out,
            "--version",
            "v-unit",
        )

    def check(self, overlay=None, labels=None):
        return self.gate("check-labels", "--labels", labels or self.base, "--overlay", overlay or self.overlay)

    def assert_refused(self, r, text):
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertIn(text, r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_good_input_folds_and_checks(self):
        self.assertEqual(self.fold().returncode, 0)
        self.assertEqual(self.check(labels=self.root / "out" / "labels-v3.jsonl").returncode, 0)

    def test_an_empty_overlay_is_refused_by_check_and_fold(self):
        empty = self.root / "empty.jsonl"
        empty.write_text("\n")
        self.assert_refused(self.check(overlay=empty), "no rows")
        self.assert_refused(self.fold(overlay=empty), "no rows")
        self.assertFalse((self.root / "out" / "labels-v3.jsonl").exists())

    def test_non_utf8_input_exits_4_with_the_line(self):
        bad = self.root / "bad.jsonl"
        bad.write_bytes(json.dumps({"id": "c1", "source_truth": "benign"}).encode() + b"\n" + b'{"id": "\xff"}\n')
        self.assert_refused(self.check(overlay=bad), "line 2: not UTF-8")
        self.assert_refused(self.fold(overlay=bad), "line 2: not UTF-8")

    def test_an_out_under_a_regular_file_exits_4(self):
        blocker = self.root / "file"
        blocker.write_text("x")
        self.assert_refused(self.fold(out=blocker / "sub"), "cannot create")

    def test_a_duplicated_key_in_one_row_is_refused(self):
        dup = self.root / "dup.jsonl"
        dup.write_text('{"id": "c1", "source_truth": "benign", "source_truth": "malicious"}\n')
        self.assert_refused(self.check(overlay=dup), "duplicated key")

    def test_a_line_separator_inside_a_string_stays_one_row(self):
        ov = self.root / "ls.jsonl"
        ov.write_text(
            json.dumps({"id": "c1", "source_truth": "malicious", "why": "a\u2028b"}, ensure_ascii=False) + "\n"
        )
        self.assertEqual(self.fold(overlay=ov).returncode, 0)


if __name__ == "__main__":
    unittest.main()
