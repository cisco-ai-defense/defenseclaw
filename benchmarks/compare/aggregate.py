#!/usr/bin/env python3
"""Collect every scored run into one results file: per tool x config x pack x set x side, the block and alert cells with 95% CIs,
plus pooled rows over the published sets. Truth, label overlay and case selection are s7gate.py's own (read_cases,
load_decisions, the labels v3.3 overlay, unsupported-tool cases skipped), and every per-set count is checked against the
scores/*.json that `s7gate.py score` wrote for the same run, so the tables come from the one scorer.

  python3 aggregate.py --runs dc-rules,llamafirewall,... --out ~/s7c/compare/results.json [--s7c ~/s7c]

CIs: Wilson 95% for recall, FPR and precision; F1 by a label-stratified case bootstrap (1,000 resamples, fixed seed).
"""
import argparse, collections, glob, json, math, os, random, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from configs import ALL_SETS  # noqa: E402

POOL_EXCLUDE = {"llm-labelled-augur"}       # model labels: reported apart, never in a pooled headline
SURFACE = {"prompt-agentdojo": "prompt", "tool-result-agentdojo": "tool-result"}


def wilson(k, n, z=1.96):
    if n == 0:
        return [None, None]
    p = k / n; d = 1 + z * z / n; c = p + z * z / (2 * n); h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [max(0.0, (c - h) / d), min(1.0, (c + h) / d)]


def cell(rows, seed=20261113, reps=1000):
    """rows: list of (attack: bool, flagged: bool)."""
    tp = sum(1 for y, f in rows if y and f); fp = sum(1 for y, f in rows if not y and f)
    fn = sum(1 for y, f in rows if y and not f); tn = sum(1 for y, f in rows if not y and not f)
    P = tp / (tp + fp) if tp + fp else None; R = tp / (tp + fn) if tp + fn else None
    F = (2 * tp / (2 * tp + fp + fn)) if (tp + fn) and (2 * tp + fp + fn) else None
    out = dict(tp=tp, fp=fp, fn=fn, tn=tn, precision=P, precision_ci=wilson(tp, tp + fp), recall=R, recall_ci=wilson(tp, tp + fn),
               fpr=fp / (fp + tn) if fp + tn else None, fpr_ci=wilson(fp, fp + tn), f1=F, f1_ci=[None, None])
    if F is not None and rows:
        rnd = random.Random(seed); pos = [r for r in rows if r[0]]; neg = [r for r in rows if not r[0]]; fs = []
        for _ in range(reps):
            s = [pos[rnd.randrange(len(pos))] for _ in pos] + ([neg[rnd.randrange(len(neg))] for _ in neg] if neg else [])
            a = sum(1 for y, f in s if y and f); b = sum(1 for y, f in s if not y and f); c = sum(1 for y, f in s if y and not f)
            fs.append(2 * a / (2 * a + b + c) if (2 * a + b + c) else 0.0)
        fs.sort(); out["f1_ci"] = [fs[int(0.025 * reps)], fs[int(0.975 * reps) - 1]]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", required=True); ap.add_argument("--out", required=True)
    ap.add_argument("--s7c", default=os.path.expanduser("~/s7c")); ap.add_argument("--sides", default="holdout,tune")
    a = ap.parse_args()
    sys.path.insert(0, a.s7c)
    import s7gate
    reg = json.load(open(os.path.join(a.s7c, "corpora_compare.json")))
    reviews, dispo = {}, {}
    for l in open(os.path.join(a.s7c, "labels", "current.jsonl")):
        if l.startswith("{"):
            r = json.loads(l)
            if r.get("source_truth"): reviews[r["id"]] = r["source_truth"]
            if r.get("expected_disposition"): dispo[r["id"]] = r["expected_disposition"]
    truth = {}
    for s in ALL_SETS:
        for side in a.sides.split(","):
            c = f"cmp-{s}-{side[0]}"; t = {}
            for cid, tr in s7gate.read_cases(reg[c], c):
                if cid in reviews:
                    tr["state"] = {"benign": "benign", "malicious": "attack"}.get(reviews[cid], "excluded")
                if cid in dispo:
                    tr["blockpos"] = dispo[cid] == "block"
                t[cid] = tr
            truth[c] = t
    preds = {}
    for name in a.runs.split(","):
        rd = os.path.join(a.s7c, "compare", "runs", name)
        run = json.load(open(os.path.join(rd, "RUN.json")))
        cov = json.load(open(os.path.join(rd, "COVERAGE.json"))) if os.path.exists(os.path.join(rd, "COVERAGE.json")) else {}
        for pack in run.get("packs") or ["default"]:
            for c in truth:
                d = os.path.join(rd, "decisions", c)
                if os.path.isdir(d):
                    preds[(name, pack, c)] = (s7gate.load_decisions(d, pack), cov.get(c), run)
    unsup = {c: {i for (n, p, cc), (pr, _, _) in preds.items() if cc == c for i, v in pr.items() if v["unsup"]} for c in truth}
    results = []
    for (name, pack, c), (pred, cov, run) in sorted(preds.items()):
        s, side = c[4:-2], {"h": "holdout", "t": "tune"}[c[-1]]
        ids = [i for i, tr in truth[c].items() if tr["state"] != "excluded" and i in pred and i not in unsup[c]]
        missing = sum(1 for i, tr in truth[c].items() if tr["state"] != "excluded" and i not in pred)
        row = dict(run=name, tool=run.get("tool") or "DefenseClaw", config=run.get("config") or name, kind=run.get("kind"), pack=pack, set=s, side=side,
                   surface=SURFACE.get(s, "tool-call"), benign=sum(1 for i in ids if truth[c][i]["state"] == "benign"),
                   attack=sum(1 for i in ids if truth[c][i]["state"] == "attack"), missing=missing, unsupported_skipped=len(unsup[c]),
                   applicable_cases=(cov or {}).get("applicable_cases"), error_events=(cov or {}).get("error_events"))
        row["na"] = cov is not None and not cov.get("applicable_cases")
        for k in ("block", "alert"):
            row[k] = cell([(truth[c][i]["state"] == "attack", bool(pred[i][k])) for i in ids])
        row["block_expected_block"] = cell([(truth[c][i]["state"] == "attack", bool(pred[i]["block"])) for i in ids if truth[c][i]["state"] == "benign" or truth[c][i]["blockpos"]])
        row["_ids"] = [(i, truth[c][i]["state"] == "attack", bool(pred[i]["block"]), bool(pred[i]["alert"])) for i in ids]
        # cross-check with the scorer's own score file
        sf = os.path.join(a.s7c, "compare", "runs", name, "scores", f"{c}-{pack}.json")
        if os.path.exists(sf):
            sj = json.load(open(sf))
            if sj.get("status") == "incomplete":
                row["scorer_status"] = "incomplete"
            else:
                for k in ("block", "alert"):
                    b = sj.get(k) or {}
                    if b and (b.get("tp"), b.get("fp")) != (row[k]["tp"], row[k]["fp"]):
                        row["scorer_mismatch"] = True
        results.append(row)
    # pooled rows: per run x pack x side over the sets that are not N/A (all, and per surface)
    pooled = []
    groups = collections.defaultdict(list)
    for r in results:
        if r["set"] in POOL_EXCLUDE or r["na"]:
            continue
        groups[(r["run"], r["pack"], r["side"], "all")].append(r)
        groups[(r["run"], r["pack"], r["side"], r["surface"])].append(r)
    for (name, pack, side, surf), rs in sorted(groups.items()):
        ids = [x for r in rs for x in r["_ids"]]
        p = dict(run=name, tool=rs[0]["tool"], config=rs[0]["config"], kind=rs[0]["kind"], pack=pack, side=side, set="POOLED", surface=surf,
                 sets=[r["set"] for r in rs], benign=sum(1 for x in ids if not x[1]), attack=sum(1 for x in ids if x[1]))
        p["block"] = cell([(x[1], x[2]) for x in ids]); p["alert"] = cell([(x[1], x[3]) for x in ids])
        f1s = [r["alert"]["f1"] for r in rs if r["alert"]["f1"] is not None]
        p["alert_macro_f1"] = sum(f1s) / len(f1s) if f1s else None
        pooled.append(p)
    for r in results:
        r.pop("_ids", None)
    json.dump(dict(results=results, pooled=pooled), open(a.out, "w"), indent=1)
    print("rows", len(results), "pooled", len(pooled), "mismatches", sum(1 for r in results if r.get("scorer_mismatch")))


if __name__ == "__main__":
    main()
