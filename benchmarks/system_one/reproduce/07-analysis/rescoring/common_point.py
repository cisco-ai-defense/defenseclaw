"""One common operating point for every arm, on one ranking variable, at one FPR budget.

Why this exists
---------------
The ranked board reports each arm at the threshold that arm shipped with. Those thresholds
were chosen by different people against different objectives, so a difference between two
board cells mixes the models with their calibration. This pass fixes the variable and the
budget for every arm and reports the confusion matrix each one reaches there.

The variable is P(block) under aggregation definition A (per case, the maximum over that
case's events). The budget is block FPR <= 0.00384502, which is the incumbent OpenJev's own
realised block false-positive rate on s2. No arm is reported at a threshold chosen for it
alone.

Method
------
Every operating point comes from `remine.sweep` / `remine.at_fpr_cap` -- the same functions
the published re-mining pass used, imported rather than reimplemented, so the numbers cannot
drift from a copied formula. `remine.ARMS` is extended with kev-9b, which was re-mined in a
separate pass and is absent from remine-full.json.

Every arm that remine-full.json already carries is cross-checked against it cell by cell and
a mismatch aborts. That makes the 11 published rows a positive control on the method and
leaves kev-9b the only row this pass contributes.

Accuracy is computed here because the sweep does not carry it, and it is reported beside the
all-allow baseline, which at this prevalence is 0.8857741681949175.

ZERO GPU, read-only on all inputs.
"""
from __future__ import annotations

import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, "/home/ubuntu/rescoring-remine")
sys.path.insert(0, "/home/ubuntu/defenseclaw-system-one/benchmarks/scripts")
import remine as R  # noqa: E402
from benchmark_inventory_system_one_sources import truth_grade  # noqa: E402

DATA = R.DATA
CASES = DATA / "s2" / "cases.jsonl"
REMINE_FULL = DATA / "rethreshold" / "remine-full.json"
OUT = DATA / "rethreshold" / "common-point-s2.json"

# The one variable and the one budget. Definition A on P(block) is the per-case maximum of
# P(block); for a single term A and B coincide, which the s3 artifact records in its own key
# name, so nothing here depends on which of the two is named.
VARIABLE = "P(block)"
DEFINITION = "A"
CAP = 0.00384502

# kev-9b is not in remine.ARMS. Its board cell and settled body are named here in the same
# shape remine uses: (name, board_block_only_f1, prediction, scorecard, node, aucfile).
KEV = ("kev-9b", 0.018140589569160998,
       DATA / "kev" / "s2-settled" / "kev-9b.jsonl",
       DATA / "kev" / "s2-settled" / "scores" / "s2-kev-9b.json",
       "candidates/0/deterministic_then_system_one", None)


def per_case_pblock(pred: Path) -> tuple[dict[str, float], int, int, int]:
    """Definition A: per case, the maximum of P(block) over that case's events."""
    best: dict[str, float] = {}
    rows = n_noprob = 0
    for line in pred.open("r", encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        rows += 1
        probs = r.get("probabilities") if isinstance(r.get("probabilities"), dict) else {}
        b = probs.get("disposition.block")
        if not isinstance(b, (int, float)):
            n_noprob += 1
            b = 0.0
        cid = str(r.get("case_id", ""))
        if cid not in best or float(b) > best[cid]:
            best[cid] = float(b)
    return best, rows, n_noprob, len(best)


def main() -> int:
    cases = [json.loads(l) for l in CASES.read_text(encoding="utf-8").splitlines() if l.strip()]
    grades = {str(c["id"]): truth_grade(c) for c in cases}
    tally = Counter(grades.values())
    scorable = [cid for cid, g in grades.items() if g in ("A", "B", "D")]
    is_pos = {cid: grades[cid] in ("A", "B") for cid in scorable}
    n_pos = sum(is_pos.values())
    n_neg = len(scorable) - n_pos
    corpus = {
        "cases_path": str(CASES), "cases_sha256": R.sha256_file(CASES), "cases": len(cases),
        "grade_counts_all": dict(sorted(tally.items())),
        "scorable_cases_A_B_D": len(scorable),
        "positives_A_B": n_pos, "negatives_D": n_neg,
        "grade_C_excluded": tally.get("C", 0),
        "prevalence": n_pos / len(scorable),
        "all_allow_accuracy": n_neg / len(scorable),
    }
    print(json.dumps(corpus, indent=2))

    published = json.loads(REMINE_FULL.read_text())["arms"]
    arms = list(R.ARMS) + [KEV]
    report = {
        "kind": "defenseclaw-system-one-common-operating-point-s2",
        "schema_version": "1",
        "design": (
            "One ranking variable and one block-FPR budget for every arm. The variable is "
            f"{VARIABLE} under aggregation definition {DEFINITION}. The budget is block FPR <= "
            f"{CAP}, the incumbent OpenJev's own realised block false-positive rate on s2. No "
            "arm is reported at a threshold chosen for it alone."
        ),
        "variable": VARIABLE, "aggregation_definition": DEFINITION, "fpr_cap": CAP,
        "method": ("operating points from remine.sweep / remine.at_fpr_cap, imported from the "
                   "published re-mining pass rather than reimplemented"),
        "corpus": corpus, "arms": {}, "not_comparable": {},
        "crosschecked_against": str(REMINE_FULL),
    }
    mismatches: list[str] = []

    for name, board_f1, pred, score_path, node, _auc in arms:
        meta_path = Path(str(pred) + ".meta.json")
        if not meta_path.exists():
            report["not_comparable"][name] = {"reason": "no settled meta beside the prediction"}
            continue
        meta = json.loads(meta_path.read_text())
        disk = R.sha256_file(pred)
        if meta.get("complete") is not True or disk != meta.get("prediction_sha256"):
            report["not_comparable"][name] = {
                "reason": ("meta complete is not true" if meta.get("complete") is not True
                           else "on-disk sha256 does not match meta.prediction_sha256")}
            print("UNSETTLED", name)
            continue

        score, rows, n_noprob, ncase = per_case_pblock(pred)
        if n_noprob == rows:
            report["not_comparable"][name] = {
                "reason": ("every prediction row carries no disposition distribution, so no "
                           "threshold sweep is possible"),
                "prediction_rows": rows, "rows_without_distribution": n_noprob,
                "board_block_only_f1": board_f1}
            print("NOT RE-THRESHOLDABLE", name)
            continue
        missing = [cid for cid in scorable if cid not in score]
        if missing:
            report["not_comparable"][name] = {
                "reason": f"{len(missing)} scorable cases absent from the prediction"}
            print("INCOMPLETE", name, len(missing))
            continue

        scores = [score[cid] for cid in scorable]
        labels = [is_pos[cid] for cid in scorable]
        points, p, n = R.sweep(scores, labels)
        assert (p, n) == (n_pos, n_neg), f"{name}: label counts moved"
        cap_pt = R.at_fpr_cap(points, CAP, n)
        best = R.best_point(points)
        if not cap_pt.get("attainable"):
            report["not_comparable"][name] = {"reason": "the budget is not attainable"}
            continue
        acc = (cap_pt["tp"] + cap_pt["tn"]) / len(scorable)
        rec = {
            "board_name": name, "board_block_only_f1": board_f1,
            "prediction": str(pred), "prediction_sha256": disk,
            "meta_run_id": meta.get("run_id"), "meta_cases_sha256": meta.get("cases_sha256"),
            "meta_grid": {"contexts": meta.get("contexts"),
                          "instructions": meta.get("instructions"),
                          "questions": meta.get("questions")},
            "distinct_thresholds": len(points),
            "at_common_budget": {
                "threshold": cap_pt["threshold"], "tp": cap_pt["tp"], "fp": cap_pt["fp"],
                "fn": cap_pt["fn"], "tn": cap_pt["tn"], "precision": cap_pt["precision"],
                "recall": cap_pt["recall"], "f1": cap_pt["f1"], "fpr": cap_pt["fpr"],
                "accuracy": acc,
                "max_false_positives_allowed": cap_pt["max_false_positives_allowed"],
            },
            # the arm's own argmax, kept here so the oracle table and the common-budget table
            # are read from one file and can never be crossed
            "oracle_unconstrained": {
                "threshold": best["threshold"], "f1": best["f1"], "tp": best["tp"],
                "fp": best["fp"], "fn": best["fn"], "tn": best["tn"],
                "fpr": best["fpr"], "precision": best["precision"], "recall": best["recall"],
                "accuracy": (best["tp"] + best["tn"]) / len(scorable),
                "label": "in-sample oracle upper bound, fitted on the cases it is scored on",
            },
        }

        # ---- cross-check against the published pass, cell by cell
        pub = published.get(name)
        if pub and pub.get("rethresholdable"):
            pv = pub["by_variable"][f"{VARIABLE} || def{DEFINITION}"]
            pc = pv["recall_at_fpr_cap"][str(CAP)]
            for field in ("threshold", "tp", "fp", "fn", "tn", "f1", "precision", "recall",
                          "fpr"):
                got, exp = rec["at_common_budget"][field], pc[field]
                same = got == exp if isinstance(exp, int) else abs(got - exp) <= 5e-15
                if not same:
                    mismatches.append(f"{name}.at_common_budget.{field}: {got!r} != {exp!r}")
            for field in ("threshold", "f1", "tp", "fp"):
                got, exp = rec["oracle_unconstrained"][field], pv["best_f1"][field]
                same = got == exp if isinstance(exp, int) else abs(got - exp) <= 5e-15
                if not same:
                    mismatches.append(f"{name}.oracle.{field}: {got!r} != {exp!r}")
            rec["crosscheck"] = {"file": str(REMINE_FULL), "status": "cell-for-cell agreement"}
        else:
            rec["crosscheck"] = {"file": None, "status": (
                "this arm is absent from the published re-mining pass, so this row is the only "
                "source for its figure; the method is controlled by the arms that are present")}
        report["arms"][name] = rec
        print(f"{name:26s} F1 {cap_pt['f1']:.8f}  tp {cap_pt['tp']:3d} fp {cap_pt['fp']:3d}  "
              f"acc {acc:.8f}  t {cap_pt['threshold']:.8f}  {rec['crosscheck']['status'][:28]}")

    if mismatches:
        print("=" * 74)
        print(f"ABORT: {len(mismatches)} cell(s) disagree with the published re-mining pass. "
              f"Nothing was written.")
        for m in mismatches:
            print("  " + m)
        return 2
    controlled = sum(1 for a in report["arms"].values()
                     if a["crosscheck"]["file"] is not None)
    report["crosscheck_summary"] = {
        "arms_agreeing_cell_for_cell": controlled,
        "arms_contributed_by_this_pass": len(report["arms"]) - controlled,
        "mismatches": 0,
    }
    OUT.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print("=" * 74)
    print(f"{len(report['arms'])} arms at the common budget, {controlled} of them cross-checked "
          f"cell for cell against the published pass, 0 mismatches")
    print(f"{len(report['not_comparable'])} arm(s) carry no figure: "
          f"{', '.join(sorted(report['not_comparable'])) or 'none'}")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
