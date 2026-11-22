# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Truth-rule tests for s7_datasets.convert (DET111 DATA).

Contract: an attack row of a corpus needs deterministic proof (in_scope + deterministic_malicious). A source-malicious row
without that proof goes to <slug>-srcmal (label_grade source-label), never to the attack corpus. Run: python3 -m unittest
benchmarks/s7/datasets/test_s7_datasets.py
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import s7_datasets  # noqa: E402
from registry import REGISTRY  # noqa: E402

SET = "test/set"


def row(rid, app="in_scope", det=None, srct=None):
    t = {"applicability": app}
    if det is not None:
        t["deterministic_truth"] = det
    if srct is not None:
        t["source_truth"] = srct
    return {"id": rid, "payload": {"args": {"command": "true"}}, "truth": t}


class ConvertTruthRules(unittest.TestCase):
    def convert(self, rows):
        REGISTRY[SET] = {"slug": "tset", "norm": ["x.py"], "fetch": "hf"}
        self.addCleanup(REGISTRY.pop, SET, None)
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        (root / "norm").mkdir()
        (root / "norm/tset.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
        cdir = root / "corpora"
        st = s7_datasets.convert(root, SET, "v1", 1, cdir)
        main = cdir / "tset-v1.cases.jsonl"
        sm = cdir / "tset-srcmal-v1.cases.jsonl"
        load = lambda p: {json.loads(x)["id"]: json.loads(x) for x in p.read_text().splitlines()} if p.is_file() else {}
        return st, load(main), load(sm)

    def test_deterministic_rows_stay_in_contract_corpus(self):
        st, main, sm = self.convert([
            row("a1", det="deterministic_malicious", srct="malicious"),
            row("b1", det="benign", srct="benign"),
        ])
        self.assertEqual(sorted(main), ["a1", "b1"])
        self.assertEqual(main["a1"]["truth"]["source_truth"], "malicious")
        self.assertEqual((st["attack"], st["benign"], st["srcmal"]), (1, 1, 0))
        self.assertEqual(sm, {})

    def test_source_malicious_without_proof_goes_to_srcmal_never_attack(self):
        st, main, sm = self.convert([
            row("c1", det="contextual_or_dual_use", srct="malicious"),
            row("u1", det="unresolved", srct="malicious"),
            row("o1", app="out_of_scope", det="deterministic_malicious", srct="malicious"),
            row("n1", det=None, srct="malicious"),  # no deterministic_truth at all: used to land in the attack corpus
            row("b1", det="benign", srct="benign"),
        ])
        self.assertEqual(sorted(main), ["b1"])
        self.assertEqual(sorted(sm), ["c1", "n1", "o1", "u1"])
        for r in sm.values():
            self.assertEqual(r["truth"]["label_grade"], "source-label")
            self.assertEqual(r["truth"]["source_truth"], "malicious")
        self.assertEqual((st["attack"], st["srcmal"]), (0, 4))

    def test_label_only_benign_is_kept_and_counted(self):
        st, main, _ = self.convert([row("l1", det=None, srct="benign")])
        self.assertEqual(sorted(main), ["l1"])
        self.assertEqual((st["label_only_benign"], st["attack"]), (1, 0))

    def test_contextual_rows_are_never_benign_and_sensitive_is_dropped(self):
        st, main, sm = self.convert([
            row("x1", det="contextual_or_dual_use", srct="benign"),
            row("s1", det=None, srct="sensitive"),
            row("b1", det="benign", srct="benign"),
        ])
        self.assertEqual(sorted(main), ["b1"])
        self.assertEqual((st["abstain"], st["sensitive"]), (1, 1))
        self.assertEqual(sm, {})

    def test_duplicate_ids_counted_once_and_output_sorted(self):
        st, main, _ = self.convert([row("z", det="benign", srct="benign"), row("a", det="benign", srct="benign"), row("z", det="benign", srct="benign")])
        self.assertEqual(list(main), ["a", "z"])
        self.assertEqual(st["dup"], 1)


if __name__ == "__main__":
    unittest.main()
