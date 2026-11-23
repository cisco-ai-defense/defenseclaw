#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: E501  (the checked-in benchmark tooling has always been long-line)
"""Fail-closed tests for s7gate (rel-1-0-10 GAP-0226 and GAP-0362). No corpus data, no attack text: the cases are two inert shell commands.

GAP-0226: compare gave PASS/FAIL when only one side recorded a label set; the scorer fell back silently when the label file was missing;
          the label copy hid its errors.
GAP-0362: a redaction pass rewrote corpus files in place while the labels stayed; a run read the mutated copy.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "wincorpus"))
import s7gate as G  # noqa: E402, N812

GATE = HERE / "s7gate.py"
BUILD = HERE.parent / "wincorpus" / "build.py"


def case(cid: str, truth: str) -> dict:
    return {
        "id": cid,
        "surface": "action",
        "source": {"dataset": "unit/inert"},
        "strata": {"platform": "linux", "provider": "claude-code"},
        "truth": {
            "source_truth": truth,
            "applicability": "in_scope",
            "expected_disposition": "block" if truth == "malicious" else "allow",
            "categories": [],
        },
        "payload": {"tool_name": "Bash", "command": "echo inert", "dialect": "claudecode"},
    }


class Env:
    """A scratch tree: a two-case corpus, its decisions, a label file, and an isolated registry and default-label path."""

    def __init__(self, test: unittest.TestCase):
        self.tmp = tempfile.TemporaryDirectory()
        test.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.croot = self.root / "corpora"
        self.croot.mkdir()
        self.corpus = self.croot / "unit.cases.jsonl"
        self.corpus.write_text(
            "".join(json.dumps(case(i, t)) + "\n" for i, t in (("b1", "benign"), ("a1", "malicious")))
        )
        self.cfg = self.root / "corpora.json"
        self.cfg.write_text(json.dumps({"unit": {"files": [str(self.corpus)]}}))
        self.labels = self.root / "labels"
        self.labels.mkdir()
        self.default_labels = self.labels / "current.jsonl"
        self.env = dict(
            os.environ,
            S7_CORPORA_ROOT=str(self.croot),
            S7_LABELS_DEFAULT=str(self.default_labels),
            S7_FX_BASE=str(self.root / "fx"),
            S7_FIXTURE_ROOT=str(self.root / "fx"),
        )  # never the real ~/s7c/fx
        self.env.pop("S7_LABELS", None)

    def decisions(self, out: Path) -> None:
        d = out / "decisions" / "unit"
        d.mkdir(parents=True)
        rows = [
            {"case": "b1", "idx": 0, "action": "allow"},
            {"case": "a1", "idx": 0, "action": "block", "raw_action": "block", "rule_ids": ["R-1"]},
        ]
        (d / "x-default.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
        # a complete harness shard, as s7gate run leaves it: its ids file and exit status 0 (GAP-0170 completeness)
        (d / "ids.x.txt").write_text("b1\na1\n")
        (d / "x-default.jsonl.rc").write_text("0\n")

    def label_file(self, name: str = "v.jsonl", rows=(("b1", "benign"),)) -> Path:
        p = self.labels / name
        p.write_text("".join(json.dumps({"id": i, "source_truth": t}) + "\n" for i, t in rows))
        return p

    def run(self, *args, script: Path = GATE):
        return subprocess.run(
            [sys.executable, "-I", str(script), *map(str, args)],
            capture_output=True,
            text=True,
            env=self.env,
            check=False,
        )

    def score(self, out: Path, *extra):
        self.decisions(out)
        return self.run("score", "--corpora", self.cfg, "--out", out, *extra)


def write_score(d: Path, labels: dict | None, fpr: float = 0.0) -> None:
    (d / "scores").mkdir(parents=True)
    cell = {"fpr": fpr, "f1": 1.0, "recall": 1.0}
    (d / "scores" / "unit-default.json").write_text(
        json.dumps({"block": cell, "alert": cell, "benign_alert_rules": [], "labels": labels})
    )


class CompareFailsClosed(unittest.TestCase):
    def sides(self, base_lab, cand_lab):
        e = Env(self)
        b, c = e.root / "base", e.root / "cand"
        write_score(b, base_lab)
        write_score(c, cand_lab)
        return e, b, c

    def compare(self, base_lab, cand_lab, *extra):
        e, b, c = self.sides(base_lab, cand_lab)
        return e.run("compare", "--base", b, "--cand", c, *extra)

    def test_same_label_set_gives_a_verdict(self):
        r = self.compare({"sha256": "a" * 64}, {"sha256": "a" * 64})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("GATE: PASS", r.stdout)

    def test_different_label_sets_give_no_verdict(self):
        r = self.compare({"sha256": "a" * 64}, {"sha256": "b" * 64})
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertIn("LABELS DIFFER", r.stdout)
        self.assertNotIn("GATE: PASS", r.stdout)
        self.assertNotIn("GATE: FAIL", r.stdout)

    def test_candidate_without_labels_gives_no_verdict(self):
        r = self.compare({"sha256": "a" * 64}, None)
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertIn("LABELS MISSING on the candidate side", r.stdout)
        self.assertNotIn("GATE: PASS", r.stdout)

    def test_base_without_labels_gives_no_verdict(self):
        r = self.compare(None, {"sha256": "a" * 64})
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertIn("LABELS MISSING on the base side", r.stdout)

    def test_a_pre_labels_score_file_without_the_key_gives_no_verdict(self):
        e, b, c = self.sides({"sha256": "a" * 64}, {"sha256": "a" * 64})
        f = c / "scores" / "unit-default.json"
        d = json.loads(f.read_text())
        del d["labels"]
        f.write_text(json.dumps(d))
        r = e.run("compare", "--base", b, "--cand", c)
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)

    def test_neither_side_labelled_gives_no_verdict(self):
        r = self.compare(None, None)
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertIn("LABELS MISSING on the base and candidate side", r.stdout)

    def test_allow_unlabelled_is_the_explicit_opt_out_and_warns(self):
        r = self.compare({"sha256": "a" * 64}, None, "--allow-unlabelled")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("WARNING no recorded label set on the candidate side", r.stdout)
        self.assertIn("GATE: PASS", r.stdout)

    def test_allow_unlabelled_does_not_hide_different_label_sets(self):
        r = self.compare({"sha256": "a" * 64}, {"sha256": "b" * 64}, "--allow-unlabelled")
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)

    def test_a_regression_is_still_a_fail_when_the_labels_agree(self):
        e = Env(self)
        b, c = e.root / "base", e.root / "cand"
        write_score(b, {"sha256": "a" * 64}, fpr=0.0)
        write_score(c, {"sha256": "a" * 64}, fpr=0.2)
        r = e.run("compare", "--base", b, "--cand", c)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("GATE: FAIL", r.stdout)


class ScoreLabels(unittest.TestCase):
    def test_missing_default_label_file_is_an_error_not_a_fallback(self):
        e = Env(self)
        out = e.root / "out"
        r = e.score(out)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("label file", r.stderr)
        self.assertIn("not found", r.stderr)
        self.assertFalse(
            (out / "scores").exists() and any((out / "scores").iterdir()),
            "no score may be written without its label set",
        )

    def test_missing_named_label_file_is_an_error(self):
        e = Env(self)
        r = e.score(e.root / "out", "--labels", e.root / "nope.jsonl")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not found", r.stderr)

    def test_missing_reviews_file_is_an_error(self):
        e = Env(self)
        r = e.score(e.root / "out", "--reviews", e.root / "nope.jsonl")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not found", r.stderr)

    def test_missing_label_file_named_by_environment_is_an_error(self):
        e = Env(self)
        e.env["S7_LABELS"] = str(e.root / "nope.jsonl")
        r = e.score(e.root / "out")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not found", r.stderr)

    def test_labels_none_scores_the_corpus_files_on_purpose_and_records_it(self):
        e = Env(self)
        out = e.root / "out"
        r = e.score(out, "--labels", "none")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        sc = json.loads((out / "scores" / "unit-default.json").read_text())
        self.assertIsNone(sc["labels"])
        self.assertIsNone(json.loads((out / "RUN.json").read_text())["labels"])
        self.assertIn("labels: none", (out / "SUMMARY.md").read_text())

    def test_default_label_file_is_applied_and_recorded_with_its_sha256(self):
        e = Env(self)
        lab = e.label_file("current.jsonl")
        (e.labels / "current.manifest.json").write_text(json.dumps({"version": "v-unit"}))
        out = e.root / "out"
        r = e.score(out)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        info = json.loads((out / "scores" / "unit-default.json").read_text())["labels"]
        self.assertEqual(info["sha256"], G.file_sha256(str(lab)))
        self.assertEqual((info["rows"], info["version"]), (1, "v-unit"))
        self.assertEqual(json.loads((out / "RUN.json").read_text())["labels"]["sha256"], info["sha256"])

    def test_scores_under_different_label_files_are_not_comparable(self):
        e = Env(self)
        l1 = e.label_file("one.jsonl", (("b1", "benign"),))
        l2 = e.label_file("two.jsonl", (("b1", "benign"), ("a1", "malicious")))
        o1, o2 = e.root / "o1", e.root / "o2"
        self.assertEqual(e.score(o1, "--labels", l1).returncode, 0)
        self.assertEqual(e.score(o2, "--labels", l2).returncode, 0)
        r = e.run("compare", "--base", o1, "--cand", o2)
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)

    def test_resolve_labels_none_and_precedence(self):
        e = Env(self)
        lab = e.label_file()
        ns = type("A", (), {})()
        ns.reviews, ns.labels = None, "none"
        self.assertEqual(G.resolve_labels(ns), (None, None))
        ns.reviews, ns.labels = str(lab), "none"
        self.assertEqual(G.resolve_labels(ns)[0], str(lab))  # --reviews wins


class PushLabelsFailsLoudly(unittest.TestCase):
    def src(self, e: Env, manifest: bool = True) -> Path:
        s = e.root / "src"
        s.mkdir()
        (s / "labels-v3.jsonl").write_text(json.dumps({"id": "b1", "source_truth": "benign"}) + "\n")
        if manifest:
            (s / "labels-v3.manifest.json").write_text(json.dumps({"version": "v3"}))
        return s

    def test_copy_is_verified_and_lands_as_current(self):
        e = Env(self)
        s, d = self.src(e), e.root / "dest"
        r = e.run("push-labels", "--src", s, "--dest", d)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual((d / "current.jsonl").read_bytes(), (s / "labels-v3.jsonl").read_bytes())
        self.assertEqual((d / "current.manifest.json").read_bytes(), (s / "labels-v3.manifest.json").read_bytes())

    def test_missing_source_exits_4(self):
        e = Env(self)
        s = e.root / "empty"
        s.mkdir()
        r = e.run("push-labels", "--src", s, "--dest", e.root / "dest")
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertIn("is missing", r.stderr)

    def test_missing_manifest_exits_4_and_copies_nothing(self):
        e = Env(self)
        s, d = self.src(e, manifest=False), e.root / "dest"
        r = e.run("push-labels", "--src", s, "--dest", d)
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertFalse((d / "current.jsonl").exists())

    def test_unwritable_destination_exits_4(self):
        e = Env(self)
        s = self.src(e)
        blocker = e.root / "file"
        blocker.write_text("x")
        r = e.run("push-labels", "--src", s, "--dest", blocker / "sub")
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertIn("push-labels", r.stderr)

    def test_a_copy_that_does_not_match_the_source_exits_4(self):
        e = Env(self)
        s, d = self.src(e), e.root / "dest"

        def bad_copy(src, dst, **kw):
            Path(dst).write_text("truncated")
            return dst

        with mock.patch.object(G.shutil, "copyfile", bad_copy), self.assertRaises(SystemExit) as cm:
            G.push_labels(str(s), str(d))
        self.assertIn("does not match", str(cm.exception.code))

    def test_a_failing_copy_exits_4_with_the_step(self):
        e = Env(self)
        s, d = self.src(e), e.root / "dest"
        with (
            mock.patch.object(G.shutil, "copyfile", side_effect=OSError("disk full")),
            self.assertRaises(SystemExit) as cm,
        ):
            G.push_labels(str(s), str(d))
        self.assertIn("disk full", str(cm.exception.code))


class CorpusFilesAreNeverRewritten(unittest.TestCase):
    def run_cmd(self, e: Env):
        return e.run(
            "run",
            "--bin",
            "/nonexistent/s7bench",
            "--policy-dir",
            e.root,
            "--corpora",
            e.cfg,
            "--out",
            e.root / "out",
            "--min-free-gb",
            "1",
        )

    def register(self, e: Env, version: str = "v1"):
        return e.run("register-corpus", e.corpus, "--version", version)

    def test_run_refuses_an_unregistered_corpus_file(self):
        e = Env(self)
        r = self.run_cmd(e)
        self.assertEqual(r.returncode, 5, r.stdout + r.stderr)
        self.assertIn("not a registered corpus version", r.stderr)
        self.assertFalse((e.root / "out").exists(), "a refused run must not create its output")

    def test_run_refuses_a_corpus_file_changed_in_place(self):
        e = Env(self)
        self.assertEqual(self.register(e).returncode, 0)
        e.corpus.write_text(
            e.corpus.read_text().replace("echo inert", "echo REDACTED_SECRET")
        )  # the pass-2 redaction, in place
        r = self.run_cmd(e)
        self.assertEqual(r.returncode, 5, r.stdout + r.stderr)
        self.assertIn("changed in place", r.stderr)

    def test_run_refuses_a_missing_corpus_file(self):
        e = Env(self)
        self.assertEqual(self.register(e).returncode, 0)
        e.corpus.unlink()
        r = self.run_cmd(e)
        self.assertEqual(r.returncode, 5, r.stdout + r.stderr)
        self.assertIn("is missing", r.stderr)

    def test_meta_files_are_covered_too(self):
        e = Env(self)
        meta = e.croot / "unit.meta.jsonl"
        meta.write_text(json.dumps({"id": "b1", "weight": 2}) + "\n")
        e.cfg.write_text(json.dumps({"unit": {"files": [str(e.corpus)], "meta": [str(meta)]}}))
        self.assertEqual(self.register(e).returncode, 0)
        r = self.run_cmd(e)
        self.assertEqual(r.returncode, 5, r.stdout + r.stderr)
        self.assertIn("unit.meta.jsonl", r.stderr)

    def test_a_registered_unchanged_corpus_passes_verification(self):
        e = Env(self)
        self.assertEqual(self.register(e).returncode, 0)
        r = e.run("verify-corpora", "--corpora", e.cfg)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("all corpus files match", r.stdout)
        with mock.patch.dict(os.environ, {"S7_CORPORA_ROOT": str(e.croot)}):
            self.assertEqual(G.verify_corpora(json.loads(e.cfg.read_text())), [])

    def test_verify_corpora_exits_1_on_a_mutation(self):
        e = Env(self)
        self.assertEqual(self.register(e).returncode, 0)
        e.corpus.write_text("{}\n")
        r = e.run("verify-corpora", "--corpora", e.cfg)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("changed in place", r.stdout)

    def test_a_registered_path_cannot_be_registered_again_with_other_bytes(self):
        e = Env(self)
        self.assertEqual(self.register(e).returncode, 0)
        e.corpus.write_text("{}\n")
        r = self.register(e, "v2")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("never rewritten", r.stderr)

    def test_a_redacted_variant_is_a_new_file_with_a_new_version(self):
        e = Env(self)
        self.assertEqual(self.register(e).returncode, 0)
        red = e.croot / "unit-r2.cases.jsonl"
        red.write_text(e.corpus.read_text().replace("echo inert", "echo redacted"))
        r = e.run("register-corpus", red, "--version", "v1-r2")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        e.cfg.write_text(json.dumps({"unit": {"files": [str(red)]}}))
        self.assertEqual(e.run("verify-corpora", "--corpora", e.cfg).returncode, 0)
        self.assertEqual(
            G.file_sha256(str(e.corpus)),
            json.loads((e.croot / "VERSIONS.json").read_text())["files"]["unit.cases.jsonl"]["sha256"],
        )

    def test_register_a_missing_file_exits_2(self):
        e = Env(self)
        r = e.run("register-corpus", e.croot / "nope.jsonl", "--version", "v1")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)

    def test_refuse_corpus_overwrite(self):
        e = Env(self)
        self.assertEqual(self.register(e).returncode, 0)
        with mock.patch.dict(os.environ, {"S7_CORPORA_ROOT": str(e.croot)}):
            with self.assertRaises(SystemExit):
                G.refuse_corpus_overwrite(str(e.croot / "x.jsonl"), [str(e.croot / "x.jsonl")])  # its own input
            with self.assertRaises(SystemExit):
                G.refuse_corpus_overwrite(str(e.corpus), [])  # a registered version
            G.refuse_corpus_overwrite(str(e.croot / "new.jsonl"), [str(e.corpus)])  # a new file is fine

    def test_the_corpus_builder_refuses_to_write_over_its_input(self):
        e = Env(self)
        before = e.corpus.read_bytes()
        r = e.run("audit-sample", e.corpus, "--out", e.corpus, script=BUILD)
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("never rewritten in place", r.stderr)
        self.assertEqual(e.corpus.read_bytes(), before)

    def test_the_corpus_builder_refuses_a_registered_output(self):
        e = Env(self)
        self.assertEqual(self.register(e).returncode, 0)
        src = e.root / "other.jsonl"
        src.write_text(e.corpus.read_text())
        r = e.run("audit-sample", src, "--out", e.corpus, script=BUILD)
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("registered corpus version", r.stderr)


if __name__ == "__main__":
    unittest.main()
