"""Tests of benchmarks/s7/det111/det111-noloss-v2.py (the R-NOLOSS check, rel-1-0-10:GAP-1969)."""

import importlib.util
import os
import pathlib
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("det111_noloss", HERE / "det111-noloss-v2.py")
noloss = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(noloss)


def run_dir(root, name, rows, roles):
    d = pathlib.Path(root) / name
    d.mkdir()
    (d / "rows.txt").write_text("".join("%s|%s|%s|%s\n" % (k, t, r, v) for (k, t, r), v in rows.items()))
    (d / "meta.tsv").write_text("".join("%s\t%s\n" % kv for kv in roles.items()))
    return str(d)


ROLES = {"atk": "variant", "twin": "twin", "ben": "benign"}
REF = {
    ("atk", "default", "hook-cc"): "block HIGH rule.a",
    ("twin", "default", "hook-cc"): "allow  ",
    ("ben", "strict", "hook-cc"): "alert LOW rule.b",
}


class NoLoss(unittest.TestCase):
    def check(self, head, roles=ROLES, ref=REF):
        with tempfile.TemporaryDirectory() as tmp:
            a = run_dir(tmp, "ref", ref, roles)
            b = run_dir(tmp, "head", head, roles)
            out = os.path.join(tmp, "cells.tsv")
            rc = noloss.main([a, b, "--out", out])
            counts, _ = noloss.compare(a, b)
            return rc, counts

    def test_same_rows_pass(self):
        rc, counts = self.check(dict(REF))
        self.assertEqual(rc, 0)
        self.assertEqual(counts["cells"], 3)

    def test_attack_lower_fails_and_its_benign_twin_lower_does_not(self):
        head = dict(REF)
        head[("atk", "default", "hook-cc")] = "alert HIGH rule.a"
        head[("ben", "strict", "hook-cc")] = "allow  "
        rc, counts = self.check(head)
        self.assertEqual(rc, 1)
        self.assertEqual(counts["attack_lower"], 1)
        self.assertEqual(counts["benign_raise"], 0)

    def test_severity_only_lower_is_a_loss(self):
        head = dict(REF)
        head[("atk", "default", "hook-cc")] = "block MEDIUM rule.a"
        rc, counts = self.check(head)
        self.assertEqual((rc, counts["attack_lower"]), (1, 1))

    def test_benign_raise_and_new_block(self):
        head = dict(REF)
        head[("twin", "default", "hook-cc")] = "block CRITICAL rule.c"
        rc, counts = self.check(head)
        self.assertEqual(rc, 1)
        self.assertEqual((counts["benign_raise"], counts["benign_newblock"]), (1, 1))

    def test_lost_cell_fails_closed(self):
        # v1 iterated HEAD only, so a cell HEAD lost was never counted.
        head = dict(REF)
        del head[("atk", "default", "hook-cc")]
        rc, counts = self.check(head)
        self.assertEqual((rc, counts["missing"]), (1, 1))

    def test_new_head_cell_is_not_counted(self):
        head = dict(REF)
        head[("atk", "permissive", "hook-cc")] = "allow  "
        rc, _ = self.check(head)
        self.assertEqual(rc, 0)

    def test_error_and_unknown_role_fail_closed(self):
        head = dict(REF)
        head[("atk", "default", "hook-cc")] = "error 504 scan-timeout"
        rc, counts = self.check(head)
        self.assertEqual((rc, counts["errors"]), (1, 1))
        rc, counts = self.check(dict(REF), roles={"atk": "variant", "twin": "twin"})
        self.assertEqual((rc, counts["unknown_role"]), (1, 1))

    def test_missing_run_is_not_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = run_dir(tmp, "ref", REF, ROLES)
            self.assertEqual(noloss.main([a, os.path.join(tmp, "nope")]), 2)
            empty = pathlib.Path(tmp) / "empty"
            empty.mkdir()
            (empty / "rows.txt").write_text("")
            self.assertEqual(noloss.main([a, str(empty)]), 2)


if __name__ == "__main__":
    unittest.main()
