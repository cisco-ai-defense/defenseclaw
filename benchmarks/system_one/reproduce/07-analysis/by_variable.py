"""Recall at fixed FPR for every ranking variable, with OpenJev's own FPR as a fifth point.

The reused recall-at-fpr script ranks only on `risk`, which is the worse variable for both
Gemma arms. This measures the low-FPR behaviour of the better variables too, so the row can
say whether a higher AUC actually buys recall where a guardrail runs, or only mid-curve.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO = "$WORK/defenseclaw-system-one"
sys.path.insert(0, REPO)
sys.path.insert(0, REPO + "/benchmarks/scripts")

_spec = importlib.util.spec_from_file_location(
    "raf", "$WORK/.system-one-data/outputs/secjudge/code/recall_at_fpr.py")
_raf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_raf)

G = Path("$WORK/.system-one-data/outputs/gemma4jev/s2")
OPENJEV_FPR = 0.00384502
POINTS = [0.001, OPENJEV_FPR, 0.005, 0.01, 0.05]
VARS = ("risk", "p_block", "p_block_minus_p_confirm")
ARMS = [("gemma-4-26B-A4B-it", "gemma-4-26b-a4b-it"), ("jevify-gemma4-26b-a4b", "jevify-gemma4-26b-a4b")]
# OpenJev reference, from the settled secjudge recall-at-fpr artifact
OPENJEV = {"roc_auc": 0.937432, "0.001": 0.098624, "0.005": 0.288991, "0.01": 0.431193, "0.05": 0.738532}

out = {"kind": "gemma4jev-recall-at-fpr-by-ranking-variable", "stage": "s2",
       "fpr_points": POINTS, "openjev_reference_fpr": OPENJEV_FPR,
       "openjev_reference": OPENJEV, "arms": {}}

for display, stem in ARMS:
    auc = json.loads((G / "scores" / f"auc-variants-{stem}.json").read_text())
    print("=" * 96)
    print(f"{display}   n={auc['scorable_cases']}  positives={auc['positives']} negatives={auc['negatives']}")
    print("  %-26s %8s | %s" % ("variable", "AUC", "  ".join(f"<={p:<9g}" for p in POINTS)))
    arm_out = {}
    for var in VARS:
        res = auc["variants"][var]
        row, cells = {"roc_auc": res["roc_auc"], "distinct_scores": res["distinct_scores"]}, []
        for p in POINTS:
            if p == OPENJEV_FPR:
                point = res["matched_fpr"]["openjev_det_then_system_one_block_fpr"]
            else:
                point = res[f"recall_at_fpr_{p}"]
            key = f"recall_at_fpr_{p}"
            row[key] = {"recall": point["recall"], "achieved_fpr": point["achieved_fpr"],
                        "tp": point["tp"], "fp": point["fp"]}
            cells.append("%.6f " % point["recall"])
        print("  %-26s %8.6f | %s" % (var, res["roc_auc"], " ".join(cells)))
        arm_out[var] = row
    best = auc["best_variable"]
    risk_005 = arm_out["risk"]["recall_at_fpr_0.005"]["recall"]
    best_005 = arm_out[best]["recall_at_fpr_0.005"]["recall"]
    risk_oj = arm_out["risk"][f"recall_at_fpr_{OPENJEV_FPR}"]["recall"]
    best_oj = arm_out[best][f"recall_at_fpr_{OPENJEV_FPR}"]["recall"]
    arm_out["verdict"] = {
        "best_variable": best,
        "best_roc_auc": auc["best_roc_auc"],
        "risk_roc_auc": auc["risk_roc_auc"],
        "auc_gain_from_best_variable": round(auc["best_roc_auc"] - auc["risk_roc_auc"], 6),
        "recall_gain_at_openjev_fpr": round(best_oj - risk_oj, 6),
        "recall_gain_at_fpr_0.005": round(best_005 - risk_005, 6),
        "openjev_recall_at_its_own_fpr": 0.288991,
        "better_variable_buys_recall_at_operating_fpr": bool(best_oj > risk_oj),
        "reaches_openjev_recall_at_openjev_fpr": bool(best_oj >= 0.288991),
    }
    v = arm_out["verdict"]
    print(f"  best variable {best}: AUC +{v['auc_gain_from_best_variable']:.6f} over risk, "
          f"recall at OpenJev's FPR {risk_oj:.6f} -> {best_oj:.6f} (+{v['recall_gain_at_openjev_fpr']:.6f})")
    print(f"  OpenJev at the same FPR: 0.288991  |  this arm's best: {best_oj:.6f}  "
          f"-> reaches OpenJev: {v['reaches_openjev_recall_at_openjev_fpr']}")
    out["arms"][display] = arm_out

path = G / "scores" / "recall-at-fpr-by-variable-gemma4-arms.json"
path.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
print("=" * 96)
print("wrote", path)
