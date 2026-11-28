#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: E501  (the checked-in benchmark tooling has always been long-line)
"""Tests for the committed label overlays and the fold-labels / check-labels commands (rel-1-0-10 GAP-0455 and the hand-audit gaps). Ids and verdicts only: no case text."""

from __future__ import annotations

import collections
import json
import subprocess
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import labelfold as LF  # noqa: E402, N812
import s7gate as G  # noqa: E402, N812

GATE = HERE / "s7gate.py"
OVERLAYS = HERE / "labels"
OPPOSITE = {"benign": "malicious", "malicious": "benign", "excluded": "benign"}


def rows_of(path: Path) -> list[dict]:
    return [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]


class Scratch(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def write(self, name: str, rows) -> Path:
        p = self.root / name
        p.write_text("".join(json.dumps(r) + "\n" for r in rows))
        return p

    def gate(self, *args):
        return subprocess.run(
            [sys.executable, "-I", str(GATE), *map(str, args)], capture_output=True, text=True, check=False
        )

    def fold(self, base: Path, *overlays: Path, out: str = "out", version: str = "v9.9"):
        argv = ["fold-labels", "--base", base, "--out", self.root / out, "--version", version]
        for o in overlays:
            argv += ["--overlay", o]
        return self.gate(*argv)

    def check(self, labels: Path, *overlays: Path):
        argv = ["check-labels", "--labels", labels]
        for o in overlays:
            argv += ["--overlay", o]
        return self.gate(*argv)

    def overlay_roundtrip(self, name: str, truths: dict[str, int]):
        """The committed overlay `name` holds exactly `truths` rows per verdict; a label set that holds the opposite verdicts fails the check, and passes after the fold."""
        ov = OVERLAYS / name
        rows = rows_of(ov)
        self.assertEqual(dict(collections.Counter(r["source_truth"] for r in rows)), truths)
        self.assertEqual(len({r["id"] for r in rows}), len(rows), "an id appears twice")
        for r in rows:
            self.assertTrue(r["why"].startswith("rel-1-0-10:GAP-"), r["id"])
        base = self.write(
            "base.jsonl",
            [{"id": r["id"], "source_truth": OPPOSITE[r["source_truth"]], "rule": "R00", "src": "rule"} for r in rows]
            + [{"id": "keep/1", "source_truth": "benign"}],
        )
        before = self.check(base, ov)
        self.assertEqual(before.returncode, 1, before.stdout + before.stderr)
        self.assertEqual(sum("differs" in ln for ln in before.stdout.splitlines()), len(rows))
        r = self.fold(base, ov)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        folded = self.root / "out" / "labels-v3.jsonl"
        after = self.check(folded, ov)
        self.assertEqual(after.returncode, 0, after.stdout + after.stderr)
        got = {r["id"]: r for r in rows_of(folded)}
        self.assertEqual(got["keep/1"], {"id": "keep/1", "source_truth": "benign"})
        return got


class OverlayFiles(Scratch):
    def test_gap0455_two_agentdojo_cases_are_attacks(self):
        got = self.overlay_roundtrip("gap0455-public-surfaces.overlay.jsonl", {"malicious": 2})
        self.assertEqual(
            set(got) - {"keep/1"}, {"p2/agentdojo/ea3fae06ccfec7938a58", "p2/agentdojo/75573fa64afdf6f27504"}
        )

    def test_gap0122_llm_labelled_augur_prose_and_admin_rows(self):
        # 9 of 30 sampled positives were wrong: 5 are model prose in the command field (excluded), 4 are user-requested admin calls. Three of those four were
        # decided again by the later R10 hand review (labels v3.1), which is newer: only the one still open is folded here.
        self.overlay_roundtrip("gap0122-llm-labelled-augur.overlay.jsonl", {"excluded": 5, "benign": 1})
        self.assertNotIn(
            "p2/augur-toolcall-labels/4343464127d9e3e0b03a",
            {r["id"] for r in rows_of(OVERLAYS / "gap0122-llm-labelled-augur.overlay.jsonl")},
        )

    def test_gap0123_extra_public_honeypot_label_is_not_copied_onto_single_calls(self):
        got = self.overlay_roundtrip("gap0123-extra-public.overlay.jsonl", {"excluded": 3})
        self.assertTrue(all(i.startswith("x/shellattack/") for i in got if i != "keep/1"))

    def test_gap0020_s2_hand_audit_and_miss_review_rows(self):
        # the 2026-11-13 hand audit (1 wrong positive) plus the s7-miss-s2 review (67 rows: context-only positives and a few verdict corrections)
        got = self.overlay_roundtrip("gap0020-s2.overlay.jsonl", {"excluded": 58, "benign": 5, "malicious": 5})
        self.assertIn("agenthazard/9938f95ae50b7053803d68fd/call-003", got)


class FoldLabels(Scratch):
    def test_fold_replaces_by_id_appends_new_and_records_the_set(self):
        base = self.write(
            "base.jsonl",
            [
                {"id": "a", "source_truth": "benign", "rule": "R01", "src": "rule", "why": "old"},
                {"id": "b", "source_truth": "excluded"},
            ],
        )
        ov = self.write(
            "ov.jsonl",
            [
                {"id": "a", "source_truth": "malicious", "why": "new", "corpus": "c"},
                {"id": "z", "source_truth": "excluded", "why": "added"},
            ],
        )
        r = self.fold(base, ov)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("changed 1", r.stdout)
        self.assertIn("added 1", r.stdout)
        out = self.root / "out"
        rows = rows_of(out / "labels-v3.jsonl")
        self.assertEqual([x["id"] for x in rows], ["a", "b", "z"])
        self.assertEqual(
            (rows[0]["source_truth"], rows[0]["why"], rows[0]["rule"], rows[0]["hand_file"]),
            ("malicious", "new", "H-HAND-OVERLAY", "ov.jsonl"),
        )
        self.assertEqual(rows[1], {"id": "b", "source_truth": "excluded"})
        man = json.loads((out / "labels-v3.manifest.json").read_text())
        self.assertEqual((man["version"], man["rows"], man["fold"]), ("v9.9", 3, {"changed": 1, "same": 0, "added": 1}))
        self.assertEqual(man["labels_sha256"], LF.sha256_file(out / "labels-v3.jsonl"))
        # the scorer resolves exactly this file, and records its version and sha256
        path, info = G.resolve_labels(Namespace(reviews=None, labels=str(out / "labels-v3.jsonl")))
        self.assertEqual((info["version"], info["rows"], info["sha256"]), ("v9.9", 3, man["labels_sha256"]))

    def test_disposition_only_rows_of_a_label_set_pass_through(self):
        # labels-v3.x holds rows with an expected_disposition and no verdict (rule R20): they are not an error in the base, and not an error to fold around
        base = self.write(
            "base.jsonl",
            [{"id": "d", "expected_disposition": "detect_only", "rule": "R20"}, {"id": "a", "source_truth": "benign"}],
        )
        ov = self.write("ov.jsonl", [{"id": "a", "source_truth": "malicious"}, {"id": "d", "source_truth": "excluded"}])
        r = self.fold(base, ov)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        rows = {x["id"]: x for x in rows_of(self.root / "out" / "labels-v3.jsonl")}
        self.assertEqual((rows["d"]["source_truth"], rows["d"]["expected_disposition"]), ("excluded", "detect_only"))
        self.assertEqual(
            json.loads((self.root / "out" / "labels-v3.manifest.json").read_text())["fold"],
            {"changed": 2, "same": 0, "added": 0},
        )
        self.assertEqual(
            self.check(base, self.write("o2.jsonl", [{"id": "a", "source_truth": "benign"}])).returncode, 0
        )
        self.assertEqual(
            self.check(base, self.write("o3.jsonl", [{"id": "d", "source_truth": "benign"}])).returncode, 1
        )
        self.assertEqual(
            self.fold(self.write("b2.jsonl", [{"id": "x", "source_truth": "maybe"}]), ov, out="o9").returncode,
            4,
            "a verdict that is present must still be valid",
        )

    def test_a_label_set_is_never_rewritten_in_place(self):
        base = self.write("base.jsonl", [{"id": "a", "source_truth": "benign"}])
        ov = self.write("ov.jsonl", [{"id": "a", "source_truth": "malicious"}])
        self.assertEqual(self.fold(base, ov).returncode, 0)
        r = self.fold(base, ov)
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertIn("never rewritten in place", r.stderr)

    def test_bad_input_exits_4_and_writes_nothing(self):
        base = self.write("base.jsonl", [{"id": "a", "source_truth": "benign"}])
        for label, rows in (
            ("unknown verdict", [{"id": "a", "source_truth": "maybe"}]),
            ("no id", [{"source_truth": "benign"}]),
        ):
            r = self.fold(base, self.write("bad.jsonl", rows), out="o-" + label.replace(" ", "-"))
            self.assertEqual(r.returncode, 4, label + r.stdout + r.stderr)
            self.assertFalse((self.root / ("o-" + label.replace(" ", "-"))).exists(), label)
        notjson = self.root / "nj.jsonl"
        notjson.write_text("{nope\n")
        self.assertEqual(self.fold(base, notjson, out="o3").returncode, 4)
        self.assertEqual(self.fold(base, self.root / "missing.jsonl", out="o4").returncode, 4)
        self.assertEqual(
            self.gate("fold-labels", "--base", base, "--out", self.root / "o5", "--version", "v1").returncode,
            4,
            "no --overlay is an error",
        )

    def test_two_overlays_that_disagree_are_refused(self):
        base = self.write("base.jsonl", [{"id": "a", "source_truth": "benign"}])
        o1 = self.write("o1.jsonl", [{"id": "a", "source_truth": "malicious"}])
        o2 = self.write("o2.jsonl", [{"id": "a", "source_truth": "excluded"}])
        r = self.fold(base, o1, o2)
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertIn("disagree", r.stderr)
        self.assertEqual(self.fold(base, o1, o1, out="same").returncode, 0, "the same verdict twice is fine")


class CheckLabels(Scratch):
    def test_missing_and_differing_rows_are_listed_by_id(self):
        ov = self.write(
            "ov.jsonl",
            [
                {"id": "a", "source_truth": "malicious"},
                {"id": "b", "source_truth": "excluded"},
                {"id": "c", "source_truth": "benign"},
            ],
        )
        labels = self.write("l.jsonl", [{"id": "a", "source_truth": "benign"}, {"id": "c", "source_truth": "benign"}])
        r = self.check(labels, ov)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("a: differs: set benign, overlay malicious", r.stdout)
        self.assertIn("b: missing", r.stdout)
        self.assertNotIn("c:", r.stdout)
        self.assertIn("check-labels: FAIL: 2", r.stdout)

    def test_unreadable_label_set_is_exit_4_not_a_pass(self):
        ov = self.write("ov.jsonl", [{"id": "a", "source_truth": "benign"}])
        self.assertEqual(self.check(self.root / "nope.jsonl", ov).returncode, 4)


if __name__ == "__main__":
    unittest.main()
