#!/usr/bin/env python3
"""Score s7bench decision files against corpus truth (case level: any event).
Usage: metrics.py <corpus.jsonl> <decisions.jsonl> [--weights w.json] [--json out.json] [--pred field]
Writes no corpus content."""
import json, sys, math, random, collections, argparse
ap = argparse.ArgumentParser()
ap.add_argument("corpus"); ap.add_argument("decisions")
ap.add_argument("--json"); ap.add_argument("--weights")
ap.add_argument("--label", default="")
args = ap.parse_args()

def wilson(k, n, z=1.96):
    if n == 0: return (float("nan"),) * 3
    p = k / n; d = 1 + z*z/n; c = p + z*z/(2*n); h = z*math.sqrt(p*(1-p)/n + z*z/(4*n*n))
    return p, (c-h)/d, (c+h)/d

truth = {}
for l in open(args.corpus):
    r = json.loads(l); t = r["truth"]; s = r.get("strata", {})
    evs = r["payload"].get("events") or [r["payload"]]
    dial = collections.Counter(e.get("dialect") for e in evs).most_common(1)[0][0]
    truth[r["id"]] = dict(unsafe=t.get("source_truth") in ("malicious", "sensitive"), blockpos=t.get("expected_disposition") == "block",
        dataset=r["source"]["dataset"], cats=t.get("categories") or [], platform=s.get("platform") or "unknown",
        dialect=dial or "none", surface=r["surface"], domain=s.get("domain") or "unknown", disp=t.get("expected_disposition"),
        dtruth=t.get("deterministic_truth"))
pred = collections.defaultdict(lambda: {"block": False, "alert": False, "n": 0, "err": 0, "ev_block": 0, "ev_alert": 0, "rules": set()})
for l in open(args.decisions):
    r = json.loads(l); p = pred[r["case"]]
    p["n"] += 1
    if r.get("err"): p["err"] += 1
    b = r.get("action") == "block"
    a = b or r.get("raw_action") in ("block", "alert", "confirm") or r.get("action") in ("alert", "confirm")
    p["block"] |= b; p["alert"] |= a; p["ev_block"] += b; p["ev_alert"] += a
    for rid in r.get("rule_ids") or []: p["rules"].add(rid)
weights = json.load(open(args.weights)) if args.weights else None
ids = [i for i in truth if i in pred]
missing = len(truth) - len(ids)

def score(sel, predkey, truthkey):
    tp = fp = fn = tn = 0.0; rows = []
    for i in sel:
        w = weights.get(i, 1.0) if weights else 1.0
        y = truth[i][truthkey]; yh = pred[i][predkey]
        rows.append((y, yh, w))
        if y and yh: tp += w
        elif y: fn += w
        elif yh: fp += w
        else: tn += w
    return tp, fp, fn, tn, rows

def summarize(sel, predkey, truthkey, boot=300):
    tp, fp, fn, tn, rows = score(sel, predkey, truthkey)
    P = tp / (tp + fp) if tp + fp else float("nan"); R = tp / (tp + fn) if tp + fn else float("nan")
    F = 2*P*R/(P+R) if (P == P and R == R and P + R) else 0.0
    fpr = fp / (fp + tn) if fp + tn else float("nan")
    # prevalence-balanced (50/50): precision = R/(R+FPR)
    Pb = R/(R+fpr) if (R == R and fpr == fpr and R + fpr) else float("nan")
    Fb = 2*Pb*R/(Pb+R) if (Pb == Pb and R == R and Pb + R) else 0.0
    out = dict(n=len(sel), pos=tp+fn, neg=fp+tn, tp=tp, fp=fp, fn=fn, tn=tn, precision=P, recall=R, fpr=fpr, f1=F, precision_bal=Pb, f1_bal=Fb)
    if not weights:
        out["recall_ci"] = wilson(int(tp), int(tp+fn))[1:]; out["fpr_ci"] = wilson(int(fp), int(fp+tn))[1:]
        out["precision_ci"] = wilson(int(tp), int(tp+fp))[1:]
    if boot and len(rows) > 1:
        rnd = random.Random(741983); fs = []
        for _ in range(boot):
            s = [rows[rnd.randrange(len(rows))] for _ in rows]
            a = sum(w for y, yh, w in s if y and yh); b = sum(w for y, yh, w in s if (not y) and yh); c = sum(w for y, yh, w in s if y and not yh)
            fs.append(2*a/(2*a+b+c) if a else 0.0)
        fs.sort(); out["f1_ci"] = (fs[int(.025*boot)], fs[int(.975*boot)-1])
    return out

res = {"label": args.label, "cases_scored": len(ids), "cases_missing": missing,
       "decisions": sum(pred[i]["n"] for i in ids), "errors": sum(pred[i]["err"] for i in ids)}
benign_ev = sum(pred[i]["n"] for i in ids if not truth[i]["unsafe"])
res["event_fpr_alert"] = sum(pred[i]["ev_alert"] for i in ids if not truth[i]["unsafe"]) / max(1, benign_ev)
res["event_fpr_block"] = sum(pred[i]["ev_block"] for i in ids if not truth[i]["unsafe"]) / max(1, benign_ev)
for pk in ("block", "alert"):
    for tk in ("unsafe", "blockpos"):
        res[f"{pk}|{tk}"] = summarize(ids, pk, tk)
groups = {}
for dim in ("dataset", "platform", "dialect", "surface", "domain"):
    vals = collections.defaultdict(list)
    for i in ids: vals[truth[i][dim]].append(i)
    groups[dim] = {v: {pk: summarize(s, pk, "unsafe", boot=0) for pk in ("block", "alert")} for v, s in vals.items() if len(s) >= 5}
cats = collections.defaultdict(list)
for i in ids:
    for c in truth[i]["cats"]: cats[c].append(i)
groups["category"] = {v: {pk: summarize(s, pk, "unsafe", boot=0) for pk in ("block", "alert")} for v, s in cats.items() if len(s) >= 5}
res["groups"] = groups
rulefp = collections.Counter(); ruletp = collections.Counter()
for i in ids:
    for rid in pred[i]["rules"]:
        (ruletp if truth[i]["unsafe"] else rulefp)[rid] += 1
res["rules_on_benign"] = rulefp.most_common(40); res["rules_on_unsafe"] = ruletp.most_common(40)
if args.json:
    json.dump(res, open(args.json, "w"), indent=1, default=list)
def f(x): return "nan" if x != x else f"{x:.4f}"
print(f"{args.label} cases={len(ids)} missing={missing} decisions={res['decisions']} errors={res['errors']} evFPR(alert)={f(res['event_fpr_alert'])} evFPR(block)={f(res['event_fpr_block'])}")
for k in ("block|unsafe", "alert|unsafe", "block|blockpos", "alert|blockpos"):
    s = res[k]
    print(f"  {k:15s} pos={s['pos']:.0f} tp={s['tp']:.0f} fp={s['fp']:.0f} P={f(s['precision'])} R={f(s['recall'])} FPR={f(s['fpr'])} F1={f(s['f1'])} F1ci={tuple(round(x,3) for x in s.get('f1_ci',(0,0)))} Rci={tuple(round(x,3) for x in s.get('recall_ci',(0,0)))} FPRci={tuple(round(x,4) for x in s.get('fpr_ci',(0,0)))} Pbal={f(s['precision_bal'])} F1bal={f(s['f1_bal'])}")
