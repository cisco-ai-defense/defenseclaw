# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0
"""One scorer (rel-1-0-10 GAP-1580, GAP-1581, GAP-1582): what the merged s7gate.py must do that one of the two old copies
did not."""

from __future__ import annotations

import json
import os
import stat
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from test_s7gate_failclosed import Env  # noqa: E402

# A harness stand-in that only records that it was started.
FAKE_BIN = """#!/bin/sh
for a in "$@"; do :; done
touch "$S7_UNIT_STARTED"
exit 0
"""


class AllChecksLabelsFirst(unittest.TestCase):
    """GAP-1580: `all` with no label file refuses before the harness runs, not after the whole run."""

    def test_missing_default_label_file_refuses_before_any_harness_run(self):
        e = Env(self)
        started = e.root / "harness-started"
        fake = e.root / "s7bench"
        fake.write_text(FAKE_BIN)
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
        e.env["S7_UNIT_STARTED"] = str(started)
        pol = e.root / "policy"
        pol.mkdir()
        out = e.root / "out"
        reg = e.run("register-corpus", e.corpus, "--version", "unit-v1")
        self.assertEqual(reg.returncode, 0, reg.stdout + reg.stderr)
        r = e.run("all", "--bin", fake, "--policy-dir", pol, "--corpora", e.cfg, "--out", out, "--min-free-gb", "1")
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("not found", r.stderr)
        self.assertFalse(started.exists(), "the harness ran although the score was bound to refuse")
        self.assertFalse((out / "decisions").exists(), "no decisions may be written before the label check")


class DispositionOnlyLabelRows(unittest.TestCase):
    """GAP-1582: a label row without source_truth (a disposition-only row, as labels-v3.4 has) keeps the corpus verdict."""

    def test_a_row_without_source_truth_is_scored_not_a_keyerror(self):
        e = Env(self)
        lab = e.labels / "dispo.jsonl"
        lab.write_text(
            json.dumps({"id": "b1", "source_truth": "benign"})
            + "\n"
            + json.dumps({"id": "a1", "expected_disposition": "alert"})
            + "\n"
        )
        out = e.root / "out"
        r = e.score(out, "--labels", lab)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("KeyError", r.stderr)
        sc = json.loads((out / "scores" / "unit-default.json").read_text())
        self.assertEqual(sc["labels"]["rows"], 2)
        # a1 stays an attack (its corpus verdict): the run blocks it, so the block recall is 1.0
        self.assertEqual(sc["block"]["recall"], 1.0)


class FixtureRootIsRecorded(unittest.TestCase):
    """GAP-1581: the deployed scorer never recorded its fixture root, so compare could not refuse a pair rewritten to
    different paths (the repo copy's GAP-0495 check)."""

    def test_compare_refuses_runs_recorded_under_different_fixture_roots(self):
        e = Env(self)
        sides = []
        for name, fx in (("base", "/fx/one"), ("cand", "/fx/two")):
            d = e.root / name
            (d / "scores").mkdir(parents=True)
            cell = {"fpr": 0.0, "f1": 1.0, "recall": 1.0}
            lab = {"sha256": "a" * 64}
            (d / "scores" / "unit-default.json").write_text(
                json.dumps({"block": cell, "alert": cell, "benign_alert_rules": [], "labels": lab})
            )
            (d / "RUN.json").write_text(json.dumps({"fixture_root": fx}))
            sides.append(d)
        r = e.run("compare", "--base", sides[0], "--cand", sides[1])
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertIn("FIXTURE ROOTS DIFFER", r.stdout)


class RuleListsAreStable(unittest.TestCase):
    """Equal-count rules are listed by name, whatever order the scorer met them in (two scorings of one run on
    dc-s7-bench4 listed them in different orders)."""

    def test_ties_are_ordered_by_key_and_the_cut_is_stable(self):
        import collections

        sys.path.insert(0, str(HERE))
        import s7gate as G  # noqa: N812

        a = collections.Counter({"R-B": 2, "R-A": 2, "R-C": 5, "R-D": 1})
        b = collections.Counter({"R-D": 1, "R-A": 2, "R-C": 5, "R-B": 2})
        self.assertEqual(G.top_counts(a, 3), [["R-C", 5], ["R-A", 2], ["R-B", 2]])
        self.assertEqual(G.top_counts(a, 3), G.top_counts(b, 3))
        self.assertEqual(G.top_counts(a), G.top_counts(b))


if __name__ == "__main__":
    os.environ.setdefault("S7_HOLDOUT_SPLIT", str(HERE / "testdata" / "holdout-split-test.json"))
    unittest.main()
