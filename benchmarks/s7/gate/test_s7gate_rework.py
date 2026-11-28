# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0
"""RV-CI111B rework: labels pinned for a whole `all` run, compare across the fixture-root switch, labelfold optional."""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from test_s7gate_failclosed import Env  # noqa: E402

# A harness stand-in that changes the default label file whenever it starts (what s7-gate push_labels does mid-run).
CHANGE_LABELS_BIN = """#!/bin/sh
printf '{"id":"new-%s","source_truth":"benign"}\\n' "$$" >> "$S7_UNIT_LABELS"
exit 0
"""


def score_dir(d: Path, run: dict) -> Path:
    (d / "scores").mkdir(parents=True)
    cell = {"fpr": 0.0, "f1": 1.0, "recall": 1.0}
    (d / "scores" / "unit-default.json").write_text(
        json.dumps({"block": cell, "alert": cell, "benign_alert_rules": [], "labels": {"sha256": "a" * 64}})
    )
    (d / "RUN.json").write_text(json.dumps(run))
    return d


class LabelsPinnedForTheRun(unittest.TestCase):
    def test_a_label_set_replaced_during_all_is_refused_not_scored_under_the_old_sha(self):
        e = Env(self)
        lab = e.label_file("current.jsonl")
        fake = e.root / "s7bench"
        fake.write_text(CHANGE_LABELS_BIN)
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
        e.env["S7_UNIT_LABELS"] = str(lab)
        (e.root / "policy").mkdir()
        self.assertEqual(e.run("register-corpus", e.corpus, "--version", "unit-v1").returncode, 0)
        out = e.root / "out"
        r = e.run(
            "all",
            "--bin",
            fake,
            "--policy-dir",
            e.root / "policy",
            "--corpora",
            e.cfg,
            "--out",
            out,
            "--min-free-gb",
            "1",
        )
        self.assertNotEqual(lab.read_text().count("\n"), 1, "the stand-in harness did not change the label file")
        self.assertIn("changed during the run", r.stderr, r.stdout + r.stderr)
        self.assertNotIn(r.returncode, (0, 4), r.stdout + r.stderr)
        self.assertFalse(list((out / "scores").glob("*.json")) if (out / "scores").exists() else [])


class FixtureRootAcrossTheSwitch(unittest.TestCase):
    def setUp(self):
        self.e = Env(self)
        self.fx = self.e.root / "fx"
        self.e.env.update(S7_FX_BASE=str(self.fx), S7_FIXTURE_ROOT=str(self.fx))

    def old_run(self, name: str, h: str) -> Path:
        d = score_dir(self.e.root / name, {})  # the deployed scorer records no fixture_root
        tree = self.fx / h
        tree.mkdir(parents=True)
        os.symlink(tree, d / "fx")
        return d

    def test_an_old_per_run_tree_against_the_box_root_gives_no_verdict(self):
        base = self.old_run("old", "0123456789ab")
        cand = score_dir(self.e.root / "new", {"fixture_root": str(self.fx)})
        r = self.e.run("compare", "--base", base, "--cand", cand)
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertIn("FIXTURE ROOTS DIFFER", r.stdout)

    def test_a_rootless_old_run_without_fx_against_the_box_root_gives_no_verdict(self):
        # s7-gate compare --allow-cross-host copies scores and RUN.json only: an old-scorer side has no root and no fx
        base = score_dir(self.e.root / "old-copied", {})
        cand = score_dir(self.e.root / "new", {"fixture_root": str(self.fx)})
        for b, c in ((base, cand), (cand, base)):
            r = self.e.run("compare", "--base", b, "--cand", c)
            self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
            self.assertIn("FIXTURE ROOTS DIFFER", r.stdout)

    def test_two_rootless_old_runs_compare_with_a_warning(self):
        a, b = score_dir(self.e.root / "old1", {}), score_dir(self.e.root / "old2", {})
        r = self.e.run("compare", "--base", a, "--cand", b)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("records no fixture root", r.stdout)

    def test_two_old_per_run_trees_still_compare(self):
        a, b = self.old_run("old1", "0123456789ab"), self.old_run("old2", "ba9876543210")
        r = self.e.run("compare", "--base", a, "--cand", b)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


class LabelfoldIsOptional(unittest.TestCase):
    def test_a_box_without_labelfold_runs_the_scorer_and_fold_labels_says_why(self):
        with tempfile.TemporaryDirectory() as td:
            for f in ("s7gate.py", "holdout.py", "surface.py", "s7session.py"):
                shutil.copy(HERE / f, td)
            e = Env(self)
            gate = Path(td) / "s7gate.py"
            r = e.run("register-corpus", e.corpus, "--version", "unit-v1", script=gate)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            r = e.run("fold-labels", "--base", "x", "--overlay", "y", "--out", td, "--version", "v", script=gate)
            self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
            self.assertIn("needs labelfold.py", r.stderr)


if __name__ == "__main__":
    unittest.main()
