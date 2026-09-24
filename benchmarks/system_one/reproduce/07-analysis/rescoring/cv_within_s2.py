"""SECONDARY held-out design: grouped, stratified k-fold cross-validation inside s2.

Weaker evidence than s2->s3 (same corpus, same generative process, only the rows differ),
and labelled as such. Its value is coverage: it is the only held-out estimate available for
the arms with no settled s3 counterpart.

Grouping: the group key is the case id truncated to its first two "/"-separated segments
(family/document). In the s2 corpus that key is unique per case -- 3,817 groups for 3,817
scored cases, verified -- so no group can span folds at any k. Fold assignment is a
deterministic round-robin over cases ordered by sha256(case_id), done separately for
positives and negatives, so folds are label-stratified and reproducible from the ids alone.

ZERO GPU, read-only on all inputs.
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
KS = [5, 10]

ARMS = [
    ("OpenJev", DATA/"s2/openjev-final.jsonl"),
    ("Jev 1.13.0", DATA/"s2/jev-C7.jsonl"),
    ("gemma-4-26B-A4B-it", DATA/"gemma4jev/s2/gemma-4-26b-a4b-it.jsonl"),
    ("open-jev-qwen-27b", DATA/"openjev-qwen/s2/h200-settled/open-jev-qwen-27b.jsonl"),
    ("DiffusionGemma 26B-A4B", DATA/"s2/diffgemma-q2.jsonl"),
    ("bespoke-nimble-9b", DATA/"nimble/s2/bespoke-nimble-9b.jsonl"),
    ("secjudge", DATA/"secjudge/predictions/secjudge-s2-C7-sev.jsonl"),
    ("open-jev-qwen-9b", DATA/"openjev-qwen/s2/open-jev-qwen-9b.jsonl"),
    ("open-jev-qwen-2b", DATA/"openjev-qwen/s2/open-jev-qwen-2b.jsonl"),
    ("decider-2b", DATA/"decider/s2/decider-2b.jsonl"),
    ("jevify-gemma4-26b-a4b", DATA/"gemma4jev/s2/jevify-gemma4-26b-a4b.jsonl"),
    ("Jev 1.13.0 @Q0", DATA/"s2/jev-q0-C7.jsonl"),
    ("Jev 1.13.0 @Q4", DATA/"s2/jev-q4-C7.jsonl"),
    ("kev-9b", Path("/home/ubuntu/rescoring-remine/kev-s2/kev-9b-shard0.jsonl")),
]
PROJ = {
    "A": {VARS[0]: lambda e: 1-e["mina"], VARS[1]: lambda e: e["maxb"],
          VARS[2]: lambda e: e["maxb"]+e["maxc"], VARS[3]: lambda e: e["maxb"]-e["maxc"]},
    "B": {VARS[0]: lambda e: 1-e["mina"], VARS[1]: lambda e: e["maxb"],
          VARS[2]: lambda e: e["maxsumB"], VARS[3]: lambda e: e["maxdiffB"]},
}

def group_key(cid: str) -> str:
    p = cid.split("/")
    return "/".join(p[:2]) if len(p) >= 2 else cid

def cm_at(scores, labels, t):
    if t is None:
        n_pos = sum(labels)
        return {"threshold": None, "tp":0,"fp":0,"fn":n_pos,"tn":len(labels)-n_pos,
                "f1":0.0,"recall":0.0,"fpr":0.0}
    tp=fp=fn=tn=0
    for s,l in zip(scores,labels):
        if s>=t:
            if l: tp+=1
            else: fp+=1
        else:
            if l: fn+=1
            else: tn+=1
    return {"threshold":t,"tp":tp,"fp":fp,"fn":fn,"tn":tn,"f1":R.f1_of(tp,fp,fn),
            "recall": tp/(tp+fn) if (tp+fn) else None, "fpr": fp/(fp+tn) if (fp+tn) else None}

def mean(v): return sum(v)/len(v) if v else None
def stdev(v):
    if len(v) < 2: return 0.0
    m = mean(v); return math.sqrt(sum((x-m)**2 for x in v)/(len(v)-1))

def main():
    cases = [json.loads(l) for l in (DATA/"s2/cases.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    grades = {str(c["id"]): truth_grade(c) for c in cases}
    scorable = [c for c,g in grades.items() if g in ("A","B","D")]
    lab = {c: grades[c] in ("A","B") for c in scorable}
    groups = {group_key(c) for c in scorable}
    s2ref = {**json.loads((OUT/"out/remine-full.json").read_text())["arms"],
             **json.loads((OUT/"out-extra/remine-full.json").read_text())["arms"],
             **json.loads((OUT/"out-kev/remine-full.json").read_text())["arms"]}

    # deterministic, label-stratified fold assignment
    def assign(k):
        pos = sorted([c for c in scorable if lab[c]], key=lambda c: hashlib.sha256(c.encode()).hexdigest())
        neg = sorted([c for c in scorable if not lab[c]], key=lambda c: hashlib.sha256(c.encode()).hexdigest())
        fold = {}
        for i,c in enumerate(pos): fold[c] = i % k
        for i,c in enumerate(neg): fold[c] = i % k
        return fold

    report = {"design":"SECONDARY: grouped stratified k-fold cross-validation within s2. "
                       "Weaker than s2->s3: same corpus, only the rows differ.",
              "grouping":{"key_rule":"case_id truncated to its first two '/'-separated segments",
                          "groups": len(groups), "scored_cases": len(scorable),
                          "key_is_unique_per_case": len(groups)==len(scorable),
                          "fold_assignment":"round-robin over sha256(case_id) order, done separately "
                                            "for positives and negatives (label-stratified, reproducible)"},
              "ks": KS, "fpr_caps": CAPS, "arms": {}}
    folds_by_k = {k: assign(k) for k in KS}
    for k in KS:
        f = folds_by_k[k]
        report["grouping"][f"fold_sizes_k{k}"] = {
            str(i): {"cases": sum(1 for c in scorable if f[c]==i),
                     "positives": sum(1 for c in scorable if f[c]==i and lab[c]),
                     "negatives": sum(1 for c in scorable if f[c]==i and not lab[c])} for i in range(k)}

    for name, pred in ARMS:
        agg = {}
        with pred.open("r", encoding="utf-8") as fh:
            for line in fh:
                line=line.strip()
                if not line: continue
                r=json.loads(line); cid=str(r.get("case_id",""))
                p=r.get("probabilities") if isinstance(r.get("probabilities"),dict) else {}
                b,c,a = p.get("disposition.block"),p.get("disposition.confirm"),p.get("disposition.allow")
                b=float(b) if isinstance(b,(int,float)) else 0.0
                c=float(c) if isinstance(c,(int,float)) else 0.0
                a=float(a) if isinstance(a,(int,float)) else 1.0
                e=agg.get(cid)
                if e is None:
                    e=agg[cid]={"maxb":0.0,"maxc":0.0,"mina":1.0,"maxsumB":-math.inf,"maxdiffB":-math.inf}
                e["maxb"]=max(e["maxb"],b); e["maxc"]=max(e["maxc"],c); e["mina"]=min(e["mina"],a)
                e["maxsumB"]=max(e["maxsumB"],b+c); e["maxdiffB"]=max(e["maxdiffB"],b-c)
        rec = {"prediction": str(pred), "by_variable": {}}
        for defn in ("A","B"):
            for v in VARS:
                sc = {c: PROJ[defn][v](agg[c]) for c in scorable}
                ref = s2ref[name]["by_variable"][f"{v} || def{defn}"]
                entry = {"aggregation_definition": defn,
                         "full_in_sample_bestF1": ref["best_f1"]["f1"],
                         "full_in_sample_threshold": ref["best_f1"]["threshold"],
                         "distinct_thresholds_full": ref["distinct_thresholds"],
                         "cv": {}}
                for k in KS:
                    fmap = folds_by_k[k]
                    per_fold = []
                    pooled = {"tp":0,"fp":0,"fn":0,"tn":0}
                    pooled_caps = {str(cp): {"tp":0,"fp":0,"fn":0,"tn":0} for cp in CAPS}
                    pooled_zero = {"tp":0,"fp":0,"fn":0,"tn":0}
                    for i in range(k):
                        tr = [c for c in scorable if fmap[c]!=i]
                        te = [c for c in scorable if fmap[c]==i]
                        trs=[sc[c] for c in tr]; trl=[lab[c] for c in tr]
                        tes=[sc[c] for c in te]; tel=[lab[c] for c in te]
                        pts, npos, nneg = R.sweep(trs, trl)
                        fit = R.best_point(pts)
                        held = cm_at(tes, tel, fit["threshold"])
                        tpts, tnpos, tnneg = R.sweep(tes, tel)
                        oracle = R.best_point(tpts)
                        fold = {"fold":i,"train_cases":len(tr),"test_cases":len(te),
                                "fitted_threshold":fit["threshold"],"train_bestF1":fit["f1"],
                                "heldout":held,"heldout_oracle":oracle,
                                "penalty_F1": oracle["f1"]-held["f1"], "caps":{}, "zero_fp":{}}
                        for key in pooled: pooled[key]+=held[key]
                        for cp in CAPS:
                            fc = R.at_fpr_cap(pts, cp, nneg)
                            t = fc.get("threshold") if fc.get("attainable") else None
                            h = cm_at(tes, tel, t)
                            oc = R.at_fpr_cap(tpts, cp, tnneg)
                            fold["caps"][str(cp)] = {"fitted_threshold":t,"heldout":h,
                                "heldout_oracle_at_cap":oc,
                                "cap_respected_heldout": (h["fpr"] is not None and h["fpr"]<=cp)}
                            for key in pooled_caps[str(cp)]: pooled_caps[str(cp)][key]+=h[key]
                        fz = R.zero_fp_point(pts, npos, nneg)
                        tz = fz.get("threshold") if fz.get("attainable") else None
                        hz = cm_at(tes, tel, tz)
                        fold["zero_fp"] = {"fitted_threshold":tz,"train_tp":fz.get("tp"),
                            "heldout":hz,"heldout_still_zero_fp":hz["fp"]==0,"heldout_fp_leaked":hz["fp"]}
                        for key in pooled_zero: pooled_zero[key]+=hz[key]
                        per_fold.append(fold)
                    f1s=[f["heldout"]["f1"] for f in per_fold]
                    pen=[f["penalty_F1"] for f in per_fold]
                    def pooled_f1(p): return R.f1_of(p["tp"],p["fp"],p["fn"])
                    entry["cv"][str(k)] = {
                        "per_fold": per_fold,
                        "heldout_F1_mean": mean(f1s), "heldout_F1_stdev": stdev(f1s),
                        "heldout_F1_min": min(f1s), "heldout_F1_max": max(f1s),
                        "penalty_F1_mean": mean(pen), "penalty_F1_stdev": stdev(pen),
                        "pooled_out_of_fold": {**pooled, "f1": pooled_f1(pooled),
                            "recall": pooled["tp"]/(pooled["tp"]+pooled["fn"]) if (pooled["tp"]+pooled["fn"]) else None,
                            "fpr": pooled["fp"]/(pooled["fp"]+pooled["tn"]) if (pooled["fp"]+pooled["tn"]) else None},
                        "in_sample_optimism_pooled": ref["best_f1"]["f1"] - pooled_f1(pooled),
                        "pooled_caps": {cp: {**p, "f1": pooled_f1(p),
                            "recall": p["tp"]/(p["tp"]+p["fn"]) if (p["tp"]+p["fn"]) else None,
                            "fpr": p["fp"]/(p["fp"]+p["tn"]) if (p["fp"]+p["tn"]) else None,
                            "cap_respected_pooled": (p["fp"]/(p["fp"]+p["tn"]) <= float(cp)) if (p["fp"]+p["tn"]) else None}
                            for cp,p in pooled_caps.items()},
                        "pooled_zero_fp": {**pooled_zero,
                            "still_zero_fp_pooled": pooled_zero["fp"]==0,
                            "fp_leaked_pooled": pooled_zero["fp"],
                            "recall": pooled_zero["tp"]/(pooled_zero["tp"]+pooled_zero["fn"]) if (pooled_zero["tp"]+pooled_zero["fn"]) else None,
                            "fpr": pooled_zero["fp"]/(pooled_zero["fp"]+pooled_zero["tn"]) if (pooled_zero["fp"]+pooled_zero["tn"]) else None,
                            "fpr_wilson95": R.wilson(pooled_zero["fp"], pooled_zero["fp"]+pooled_zero["tn"]),
                            "folds_still_zero": sum(1 for f in per_fold if f["zero_fp"]["heldout_still_zero_fp"]),
                            "folds_total": k},
                    }
                rec["by_variable"][f"{v} || def{defn}"] = entry
        report["arms"][name] = rec
        e5 = rec["by_variable"]["P(block) || defA"]["cv"]["5"]
        print(f"{name:26s} P(block) defA  in-sample {rec['by_variable']['P(block) || defA']['full_in_sample_bestF1']:.8f}  "
              f"pooled-OOF {e5['pooled_out_of_fold']['f1']:.8f}  optimism {e5['in_sample_optimism_pooled']:.8f}  "
              f"fold penalty {e5['penalty_F1_mean']:.8f} +/- {e5['penalty_F1_stdev']:.8f}  "
              f"zeroFP leaked {e5['pooled_zero_fp']['fp_leaked_pooled']}")
        sys.stdout.flush()
    (OUT/"heldout-s2-cv.json").write_text(json.dumps(report, indent=2, sort_keys=True)+"\n")
    print("wrote", OUT/"heldout-s2-cv.json")

main()
