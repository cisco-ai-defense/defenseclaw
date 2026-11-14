#!/usr/bin/env python3
"""Regression tests for s7-labelfix (rel-1-0-10:GAP-0666): the run LABEL must not change the text of a call.

Run beside s7gate.py:  python3 -I test_labelfix.py            (unit tests)
Real harness, same corpus under two labels of different length, decisions must match:
  S7_LABELFIX_BIN=<s7bench> S7_LABELFIX_POLICIES=<policy dir> S7_LABELFIX_CORPORA=<corpora json> python3 -I test_labelfix.py
(S7_LABELFIX_CORPORA names a corpora.json with one corpus holding calls near the 4096-byte reading bound, e.g. corpora_labelfix.json.)"""
import json, os, shutil, subprocess, sys, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import s7gate  # noqa: E402

LABELS = ["a", "xx-head", "xx-base0", "gp6h-aaaaaaaa", "lfx-head-with-a-much-longer-label-0123456789abcdef"]


class FixtureRoot(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="lfx-test-")
        self.fxbase = os.path.join(self.tmp, "fx")
        s7gate.FX_BASE = self.fxbase
        self.gate = os.path.join(self.tmp, "gate")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def out(self, label):
        d = os.path.join(self.gate, label)
        os.makedirs(d, exist_ok=True)
        return d

    def test_root_length_does_not_depend_on_the_label(self):
        roots = {l: s7gate.make_fixture(self.out(l)) for l in LABELS}
        self.assertEqual(len({len(r) for r in roots.values()}), 1, roots)
        self.assertEqual(len(set(roots.values())), len(LABELS), "every run keeps its own root")
        for l, r in roots.items():
            self.assertTrue(os.path.islink(os.path.join(self.out(l), "fx")))   # OUT/fx still leads to the tree
            self.assertTrue(os.path.isfile(os.path.join(r, "home", "alice", ".ssh", "authorized_keys")))
            self.assertTrue(r.startswith(self.fxbase + os.sep))

    def test_a_rewritten_call_has_the_same_length_under_every_label(self):
        pad = "x" * 4000
        line = json.dumps({"id": "c", "command": f"cd /Users/alice/p && echo {pad} > /home/alice/f"}) + "\n"
        lens = set()
        for l in LABELS:
            o = self.out(l)
            src, dst = os.path.join(o, "in.jsonl"), os.path.join(o, "rw.jsonl")
            open(src, "w").write(line)
            s7gate.rewrite_corpus(src, dst, s7gate.make_fixture(o))
            lens.add(len(open(dst).read()))
        self.assertEqual(len(lens), 1, lens)

    def test_a_new_run_does_not_inherit_the_tree_of_an_overwritten_one(self):
        o = self.out("rerun")
        fx = s7gate.make_fixture(o)
        stray = os.path.join(fx, "rootfs", "tmp", "stray")
        os.makedirs(os.path.dirname(stray)); open(stray, "w").write("x")
        s7gate.make_fixture(o)                      # a --resume keeps it
        self.assertTrue(os.path.exists(stray))
        shutil.rmtree(o); os.makedirs(o)            # --overwrite: rm -rf gate/<label>
        self.assertEqual(s7gate.make_fixture(o), fx)
        self.assertFalse(os.path.exists(stray))

    def test_trees_of_deleted_runs_are_collected(self):
        gone, kept = self.out("gone"), self.out("kept")
        fg, fk = s7gate.make_fixture(gone), s7gate.make_fixture(kept)
        shutil.rmtree(gone)
        s7gate.gc_fixtures()
        self.assertFalse(os.path.exists(fg))
        self.assertTrue(os.path.exists(fk))

    def test_a_run_made_before_the_fix_keeps_its_own_directory(self):
        o = self.out("old")
        os.makedirs(os.path.join(o, "fx"))
        self.assertEqual(s7gate.fixture_root(o), os.path.join(o, "fx"))


@unittest.skipUnless(all(os.environ.get(k) for k in ("S7_LABELFIX_BIN", "S7_LABELFIX_POLICIES", "S7_LABELFIX_CORPORA")), "needs a harness binary, policies and a corpora json")
class SameDecisionsUnderTwoLabels(unittest.TestCase):
    def run_label(self, tmp, label):
        out = os.path.join(tmp, "gate", label)
        r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "s7gate.py"), "run", "--bin", os.environ["S7_LABELFIX_BIN"], "--policy-dir", os.environ["S7_LABELFIX_POLICIES"],
                            "--corpora", os.environ["S7_LABELFIX_CORPORA"], "--out", out, "--parallel", "1", "--gomaxprocs", "2", "--workers", "2"], capture_output=True, text=True)
        self.assertIn(r.returncode, (0, 4), r.stdout[-2000:] + r.stderr[-2000:])
        rows = {}
        for root, _, files in os.walk(os.path.join(out, "decisions")):
            for f in files:
                if f.endswith(".jsonl") and not f.startswith("ids."):
                    with open(os.path.join(root, f)) as fh: lines = fh.readlines()
                    for l in lines:
                        d = json.loads(l)
                        rows.setdefault((os.path.relpath(os.path.join(root, f), out), d.get("case")), []).append((d.get("idx"), d.get("action"), d.get("raw_action"), d.get("sev")))
        return rows

    def test_decisions_do_not_depend_on_the_label(self):
        tmp = tempfile.mkdtemp(prefix="lfx-e2e-")
        try:
            os.environ["S7_FX_BASE"] = os.path.join(tmp, "fx")
            a = self.run_label(tmp, "lf-a")
            b = self.run_label(tmp, "lf-a-label-that-is-quite-a-bit-longer-0123456789")
            self.assertTrue(a, "no decisions")
            self.assertEqual(a, b)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
