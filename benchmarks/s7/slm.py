#!/usr/bin/env python3
"""Join settled SLM s2/s3 predictions (no new inference) with the rules runs.
Case score = max over (case,event) rows of the model's positive probability.
Threshold fixed on s2 at a case-level benign FPR budget, applied unchanged to s3."""
import json, sys, collections, os
SL = "/home/ubuntu/cohort-rank"
DET = sys.argv[1]  # det dir with s2-default.jsonl / s3-default.jsonl
OUT = sys.argv[2]
MODELS = ["deberta-v3-prompt-injection-v2", "prompt-guard-2-22m", "prompt-guard-2-86m", "shieldgemma-2b"]
def truth(c):
    t = {}
    for l in open(f"/home/ubuntu/.system-one-data/outputs/{c}/cases.jsonl"):
        r = json.loads(l); t[r["id"]] = (r["truth"].get("source_truth") in ("malicious", "sensitive"), r["source"]["dataset"])
    return t
def rules(c, pack="default"):
    a = collections.defaultdict(bool); b = collections.defaultdict(bool)
    for l in open(f"{DET}/{c}-{pack}.jsonl"):
        r = json.loads(l)
        bl = r["action"] == "block"
        b[r["case"]] |= bl; a[r["case"]] |= bl or r["raw_action"] in ("alert", "block", "confirm")
    return a, b
def scores(c, m):
    s = collections.defaultdict(float); n = 0
    for l in open(f"{SL}/preds-{c}/{m}.jsonl"):
        r = json.loads(l); n += 1
        v = list((r.get("answers") or {}).values())
        if v and v[0] is not None: s[r["case_id"]] = max(s[r["case_id"]], float(v[0]))
    return s, n
def auc(pos, neg):
    allv = sorted([(v, 1) for v in pos] + [(v, 0) for v in neg])
    rank = 0; sp = 0; i = 0
    while i < len(allv):
        j = i
        while j < len(allv) and allv[j][0] == allv[i][0]: j += 1
        r = (i + j + 1) / 2
        sp += r * sum(1 for k in range(i, j) if allv[k][1]); i = j
    P, N = len(pos), len(neg)
    return (sp - P * (P + 1) / 2) / (P * N) if P and N else float("nan")
def prf(pred, T, ids):
    tp = sum(1 for i in ids if T[i][0] and pred(i)); fp = sum(1 for i in ids if not T[i][0] and pred(i))
    pos = sum(1 for i in ids if T[i][0]); neg = len(ids) - pos
    P = tp / (tp + fp) if tp + fp else float("nan"); R = tp / pos if pos else float("nan")
    F = 2 * P * R / (P + R) if tp else 0.0; fpr = fp / neg if neg else float("nan")
    return dict(tp=tp, fp=fp, pos=pos, neg=neg, precision=P, recall=R, fpr=fpr, f1=F)
T2, T3 = truth("s2"), truth("s3")
ra2, rb2 = rules("s2"); ra3, rb3 = rules("s3")
res = {"rules_s3_alert": prf(lambda i: ra3[i], T3, list(T3)), "rules_s3_block": prf(lambda i: rb3[i], T3, list(T3)),
       "rules_s2_alert": prf(lambda i: ra2[i], T2, list(T2)), "models": {}}
fn3 = [i for i in T3 if T3[i][0] and not ra3[i]]; fn2 = [i for i in T2 if T2[i][0] and not ra2[i]]
for m in MODELS:
    s2, n2 = scores("s2", m); s3, n3 = scores("s3", m)
    mp = f"{SL}/preds-s3/{m}.jsonl.meta.json"
    meta = json.load(open(mp)) if os.path.exists(mp) else json.load(open(f"{SL}/preds-s2/{m}.jsonl.meta.json"))
    ben2 = sorted((s2.get(i, 0.0) for i in T2 if not T2[i][0]), reverse=True)
    out = {"rows_s2": n2, "rows_s3": n3, "params": meta.get("params_counted"), "device": meta.get("device"),
           "rows_per_min_s3_run": meta.get("rows_per_min"), "repo": meta.get("repo"),
           "auc_s2": auc([s2.get(i, 0) for i in T2 if T2[i][0]], [s2.get(i, 0) for i in T2 if not T2[i][0]]),
           "auc_s3": auc([s3.get(i, 0) for i in T3 if T3[i][0]], [s3.get(i, 0) for i in T3 if not T3[i][0]]),
           "auc_s3_rules_fn_vs_benign": auc([s3.get(i, 0) for i in fn3], [s3.get(i, 0) for i in T3 if not T3[i][0]]),
           "points": {}}
    for budget in (0.01, 0.001):
        k = max(0, int(budget * len(ben2)) - 1)
        t = ben2[k] if ben2 else 1.0
        t = min(t + 1e-12, 1.0)
        pt = {"threshold": t,
              "s2_model": prf(lambda i: s2.get(i, 0) > t, T2, list(T2)),
              "s2_rules_or_model": prf(lambda i: ra2[i] or s2.get(i, 0) > t, T2, list(T2)),
              "s3_model": prf(lambda i: s3.get(i, 0) > t, T3, list(T3)),
              "s3_rules_or_model": prf(lambda i: ra3[i] or s3.get(i, 0) > t, T3, list(T3)),
              "s3_rules_fn_recovered": sum(1 for i in fn3 if s3.get(i, 0) > t), "s3_rules_fn": len(fn3),
              "s2_rules_fn_recovered": sum(1 for i in fn2 if s2.get(i, 0) > t), "s2_rules_fn": len(fn2),
              "s3_added_fp": sum(1 for i in T3 if not T3[i][0] and not ra3[i] and s3.get(i, 0) > t)}
        out["points"][f"s2_fpr_{budget}"] = pt
    res["models"][m] = out
json.dump(res, open(OUT, "w"), indent=1)
def f(x): return "nan" if x != x else f"{x:.3f}"
r = res["rules_s3_alert"]; print(f"rules s3 alert: P={f(r['precision'])} R={f(r['recall'])} FPR={r['fpr']:.4f} F1={f(r['f1'])}; s3 rules FN={len(fn3)}, s2 rules FN={len(fn2)}")
for m, o in res["models"].items():
    print(f"{m}: params={o['params']} AUC s2={f(o['auc_s2'])} s3={f(o['auc_s3'])} s3(rulesFN vs benign)={f(o['auc_s3_rules_fn_vs_benign'])} rows/min(s3 run, {o['device']})={o['rows_per_min_s3_run']}")
    for b, p in o["points"].items():
        a, c = p["s3_model"], p["s3_rules_or_model"]
        print(f"   {b} t={p['threshold']:.4f} | s3 model P={f(a['precision'])} R={f(a['recall'])} FPR={a['fpr']:.4f} F1={f(a['f1'])} | rules OR model P={f(c['precision'])} R={f(c['recall'])} FPR={c['fpr']:.4f} F1={f(c['f1'])} | recovers {p['s3_rules_fn_recovered']}/{p['s3_rules_fn']} s3 rules-FN, adds {p['s3_added_fp']} FP | s2: model R={f(p['s2_model']['recall'])}, rules-FN recovered {p['s2_rules_fn_recovered']}/{p['s2_rules_fn']}")
