"""PRIMARY held-out design: fit the threshold on s2, evaluate it on s3.

s2 and s3 share ZERO scorable case_ids (verified), so s3 is a genuinely disjoint corpus,
not a resample. ZERO GPU, read-only on all inputs.

Prevalence differs sharply between the two corpora (s2: 436/3817 = 11.42% positive;
s3: 221/24476 = 0.90%), and F1 is prevalence-sensitive. So the s2->s3 drop in raw F1 is NOT
the overfitting penalty. The penalty reported here is, as specified:
      penalty = s3_oracle_best_F1(variable)  -  s3_F1(threshold fitted on s2)
Both terms are measured on s3, so prevalence cancels. Recall and FPR at the transferred
threshold are also reported because those two are prevalence-free and are the cleaner
statement of whether the threshold landed where s2 said it would.
"""
from __future__ import annotations
import hashlib, json, math, sys
from collections import Counter, defaultdict
from pathlib import Path
sys.path.insert(0, "/home/ubuntu/rescoring-remine")
sys.path.insert(0, "/home/ubuntu/defenseclaw-system-one/benchmarks/scripts")
import remine as R
from benchmark_inventory_system_one_sources import truth_grade

DATA = R.DATA
OUT = Path("/home/ubuntu/rescoring-remine")
VARS = R.VARS
CAPS = R.FPR_CAPS

S3_CASES = DATA / "s3/cases.jsonl"
S3_ARMS = [   # (label, prediction, published scorecard, node)
    ("OpenJev", DATA/"s3/openjev-full.jsonl", DATA/"deterministic-real/realdet-s3-openjev.json", "system_one"),
    ("Jev 1.13.0", DATA/"s3/jev-C7.jsonl", DATA/"deterministic-real/realdet-s3-jev.json", "system_one"),
    ("DiffusionGemma 26B-A4B", DATA/"s3/diffgemma-q2.jsonl",
     DATA/"jev-parity/scores/s3__diffusiongemma__diffgemma-q2.json", "system_one"),
]
# s3 arms that exist on disk but are NOT settled -> named, not scored
S3_BLOCKED = ["open-jev-qwen-2b (s3)", "open-jev-qwen-9b (s3)", "bespoke-nimble-9b (s3)", "kev-9b (s2, studio)"]


def aggregate(pred: Path, wanted: set[str]):
    agg = {}
    acts = defaultdict(list)
    rows = noprob = 0
    with pred.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line); rows += 1
            cid = str(r.get("case_id", ""))
            p = r.get("probabilities") if isinstance(r.get("probabilities"), dict) else {}
            b, c, a = p.get("disposition.block"), p.get("disposition.confirm"), p.get("disposition.allow")
            if not (isinstance(b,(int,float)) and isinstance(c,(int,float)) and isinstance(a,(int,float))):
                noprob += 1
            b = float(b) if isinstance(b,(int,float)) else 0.0
            c = float(c) if isinstance(c,(int,float)) else 0.0
            a = float(a) if isinstance(a,(int,float)) else 1.0
            e = agg.get(cid)
            if e is None:
                e = agg[cid] = {"maxb":0.0,"maxc":0.0,"mina":1.0,"maxsumB":-math.inf,"maxdiffB":-math.inf}
            e["maxb"]=max(e["maxb"],b); e["maxc"]=max(e["maxc"],c); e["mina"]=min(e["mina"],a)
            e["maxsumB"]=max(e["maxsumB"],b+c); e["maxdiffB"]=max(e["maxdiffB"],b-c)
            if not r.get("error_code") and str(r.get("action","error")) != "error":
                acts[cid].append(str(r.get("action","error")))
    return agg, acts, rows, noprob


PROJ = {
    "A": {VARS[0]: lambda e: 1-e["mina"], VARS[1]: lambda e: e["maxb"],
          VARS[2]: lambda e: e["maxb"]+e["maxc"], VARS[3]: lambda e: e["maxb"]-e["maxc"]},
    "B": {VARS[0]: lambda e: 1-e["mina"], VARS[1]: lambda e: e["maxb"],
          VARS[2]: lambda e: e["maxsumB"], VARS[3]: lambda e: e["maxdiffB"]},
}


def apply_threshold(scores, labels, t):
    """Confusion for the fixed predicate (score >= t). t may be None (no gate)."""
    if t is None:
        n_pos = sum(labels); n_neg = len(labels)-n_pos
        return {"threshold": None, "tp":0, "fp":0, "fn":n_pos, "tn":n_neg, "f1":0.0,
                "precision":None, "recall":0.0, "fpr":0.0, "gate":"none (no fp==0 gate existed on s2)"}
    tp=fp=fn=tn=0
    for s,l in zip(scores,labels):
        if s >= t:
            if l: tp+=1
            else: fp+=1
        else:
            if l: fn+=1
            else: tn+=1
    return {"threshold": t, "tp":tp,"fp":fp,"fn":fn,"tn":tn,
            "f1": R.f1_of(tp,fp,fn), "precision": (tp/(tp+fp)) if (tp+fp) else None,
            "recall": tp/(tp+fn) if (tp+fn) else None, "fpr": fp/(fp+tn) if (fp+tn) else None}


def main():
    s2 = json.loads((OUT/"out/remine-full.json").read_text())
    # ---- s3 corpus
    grades = {}
    for l in S3_CASES.open(encoding="utf-8"):
        if l.strip():
            r = json.loads(l); grades[str(r["id"])] = truth_grade(r)
    scorable = [c for c,g in grades.items() if g in ("A","B","D")]
    labels_by = {c: grades[c] in ("A","B") for c in scorable}
    s2_scorable = set()
    for l in (DATA/"s2/cases.jsonl").open(encoding="utf-8"):
        if l.strip():
            r = json.loads(l)
            if truth_grade(r) in ("A","B","D"): s2_scorable.add(str(r["id"]))
    overlap = sorted(set(scorable) & s2_scorable)
    corpus = {
        "s3_cases_path": str(S3_CASES), "s3_cases_sha256": R.sha256_file(S3_CASES),
        "s3_cases": len(grades), "s3_grade_counts": dict(sorted(Counter(grades.values()).items())),
        "s3_scorable_A_B_D": len(scorable),
        "s3_positives_A_B": sum(labels_by.values()),
        "s3_negatives_D": len(scorable)-sum(labels_by.values()),
        "s3_positive_prevalence": sum(labels_by.values())/len(scorable),
        "s2_positive_prevalence": 436/3817,
        "case_id_overlap_with_s2_scorable": len(overlap),
        "held_out_is_disjoint": len(overlap) == 0,
        "note": "s3 carries no grade C and no grade E, so all 24,476 cases are scorable.",
    }
    print(json.dumps(corpus, indent=2))
    report = {"design": "PRIMARY: threshold fitted on s2 (3,817 rows), evaluated on s3 (24,476 rows), "
                        "disjoint case_ids", "s3_corpus": corpus,
              "fpr_caps": CAPS, "arms": {},
              "blocked_pending_settlement": S3_BLOCKED}

    for label, pred, score_path, node in S3_ARMS:
        rec = {"arm": label, "s3_prediction": str(pred)}
        mp = Path(str(pred)+".meta.json")
        m = json.loads(mp.read_text())
        disk = R.sha256_file(pred)
        rec.update({"meta_complete": m.get("complete"), "meta_prediction_sha256": m.get("prediction_sha256"),
                    "disk_sha256": disk, "sha256_match": disk == m.get("prediction_sha256"),
                    "meta_requests": m.get("requests"), "meta_cases": m.get("cases"),
                    "meta_cases_sha256": m.get("cases_sha256"), "meta_run_id": m.get("run_id"),
                    "settled": m.get("complete") is True and disk == m.get("prediction_sha256")})
        if not rec["settled"]:
            rec["verdict"] = "UNUSABLE"; report["arms"][label]=rec; continue

        agg, acts, rows, noprob = aggregate(pred, set(scorable))
        rec.update({"s3_prediction_rows": rows, "rows_without_distribution": noprob,
                    "cases_in_prediction": len(agg),
                    "s3_scorable_missing": len([c for c in scorable if c not in agg])})
        if rec["s3_scorable_missing"]:
            rec["verdict"]="UNUSABLE: s3 coverage incomplete"; report["arms"][label]=rec; continue

        labels = [labels_by[c] for c in scorable]
        # shipped point on s3, recomputed from rows
        ship = {}
        for c in scorable:
            a = acts.get(c) or []
            ship[c] = max(a, key=lambda v: R.ACTION_RANK.get(v,-1)) if a else "error"
        def cm(flags):
            tp=fp=fn=tn=0
            for l,f in zip(labels,flags):
                if l and f: tp+=1
                elif l: fn+=1
                elif f: fp+=1
                else: tn+=1
            return {"tp":tp,"fp":fp,"fn":fn,"tn":tn,"f1":R.f1_of(tp,fp,fn),
                    "recall":tp/(tp+fn) if (tp+fn) else None,"fpr":fp/(fp+tn) if (fp+tn) else None}
        rec["s3_shipped_recomputed"] = {
            "block_only": cm([ship[c] in ("block","deny") for c in scorable]),
            "any_intervention": cm([ship[c] in ("block","deny","confirm","alert") for c in scorable])}
        pub = json.loads(score_path.read_text())["candidates"][0][node]
        rec["s3_published_shipped"] = {"block_only_f1": pub["binary_block_only"]["f1"],
                                       "block_only_confusion": pub["binary_block_only"]["confusion"],
                                       "any_f1": pub["binary"]["f1"], "any_confusion": pub["binary"]["confusion"]}
        mine = rec["s3_shipped_recomputed"]["block_only"]
        rec["s3_shipped_agrees_with_published"] = (
            mine["tp"]==pub["binary_block_only"]["confusion"]["true_positive"] and
            mine["fp"]==pub["binary_block_only"]["confusion"]["false_positive"] and
            mine["fn"]==pub["binary_block_only"]["confusion"]["false_negative"] and
            mine["tn"]==pub["binary_block_only"]["confusion"]["true_negative"])

        by = {}
        for defn in ("A","B"):
            for v in VARS:
                s2e = s2["arms"][label]["by_variable"][f"{v} || def{defn}"]
                scores = [PROJ[defn][v](agg[c]) for c in scorable]
                pts, n_pos, n_neg = R.sweep(scores, labels)
                oracle = R.best_point(pts)
                entry = {
                    "aggregation_definition": defn,
                    "s3_positives": n_pos, "s3_negatives": n_neg, "s3_scored_cases": len(scores),
                    "s3_distinct_thresholds": len(pts),
                    "s2_distinct_thresholds": s2e["distinct_thresholds"],
                    "s3_roc_auc": R.mann_whitney_auc(scores, labels),
                    "s2_roc_auc": s2e["roc_auc_mann_whitney_tie_corrected"],
                    # --- best-F1 threshold transfer
                    "s2_fitted_bestF1_threshold": s2e["best_f1"]["threshold"],
                    "s2_bestF1_in_sample": s2e["best_f1"]["f1"],
                    "s2_bestF1_point_on_s2": s2e["best_f1"],
                    "s3_at_s2_bestF1_threshold": apply_threshold(scores, labels, s2e["best_f1"]["threshold"]),
                    "s3_oracle_bestF1": oracle,
                    # --- FPR-cap threshold transfer
                    "caps": {}, 
                    # --- zero-FP gate transfer
                    "zero_fp": {},
                }
                entry["overfitting_penalty_bestF1"] = oracle["f1"] - entry["s3_at_s2_bestF1_threshold"]["f1"]
                entry["s3_oracle_minus_s2_insample"] = oracle["f1"] - s2e["best_f1"]["f1"]
                for cap in CAPS:
                    s2cap = s2e["recall_at_fpr_cap"][str(cap)]
                    t = s2cap.get("threshold") if s2cap.get("attainable") else None
                    s3cap = R.at_fpr_cap(pts, cap, n_neg)
                    entry["caps"][str(cap)] = {
                        "s2_fitted_threshold": t, "s2_point": s2cap,
                        "s3_at_s2_threshold": apply_threshold(scores, labels, t),
                        "s3_oracle_at_same_cap": s3cap,
                        "s3_max_fp_allowed": s3cap.get("max_false_positives_allowed"),
                    }
                    a1 = entry["caps"][str(cap)]["s3_at_s2_threshold"]
                    entry["caps"][str(cap)]["cap_respected_on_s3"] = (a1["fpr"] is not None and a1["fpr"] <= cap)
                    entry["caps"][str(cap)]["recall_penalty_vs_s3_oracle"] = (
                        (s3cap.get("recall") - a1["recall"]) if s3cap.get("attainable") else None)
                s2z = s2e["zero_false_positive_point"]
                tz = s2z.get("threshold") if s2z.get("attainable") else None
                s3z = R.zero_fp_point(pts, n_pos, n_neg)
                transferred = apply_threshold(scores, labels, tz)
                entry["zero_fp"] = {
                    "s2_fitted_threshold": tz, "s2_point": {k: s2z.get(k) for k in
                        ("threshold","tp","fp","fn","tn","recall","f1")},
                    "s3_at_s2_threshold": transferred,
                    "s3_gate_still_zero_fp": transferred["fp"] == 0,
                    "s3_false_positives_leaked": transferred["fp"],
                    "s3_fpr_at_transferred_gate": transferred["fpr"],
                    "s3_fpr_wilson95": R.wilson(transferred["fp"], n_neg),
                    "s3_oracle_zero_fp": {k: s3z.get(k) for k in
                        ("attainable","threshold","tp","fn","recall","f1")},
                    "s3_rule_of_three_upper_if_zero": 3/n_neg,
                    "s3_recall_penalty_vs_s3_oracle": (s3z.get("recall") - transferred["recall"])
                        if s3z.get("attainable") else None,
                }
                by[f"{v} || def{defn}"] = entry
        rec["by_variable"] = by
        report["arms"][label] = rec

        # console
        print("### ARM:", label)
        for defn in ("A","B"):
            for v in VARS:
                e = by[f"{v} || def{defn}"]
                a1 = e["s3_at_s2_bestF1_threshold"]; o = e["s3_oracle_bestF1"]
                print(f"def{defn} {v[:34]:34s} s2t={e['s2_fitted_bestF1_threshold']!r:<24} "
                      f"s2F1={e['s2_bestF1_in_sample']:.8f} -> s3F1={a1['f1']:.8f} "
                      f"(s3 oracle {o['f1']:.8f}, penalty {e['overfitting_penalty_bestF1']:.8f}) "
                      f"s3 tp/fp/fn/tn={a1['tp']}/{a1['fp']}/{a1['fn']}/{a1['tn']}")
        sys.stdout.flush()

    (OUT/"heldout-s2-to-s3.json").write_text(json.dumps(report, indent=2, sort_keys=True)+"\n")
    print("wrote", OUT/"heldout-s2-to-s3.json")


main()
