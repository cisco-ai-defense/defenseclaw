#!/usr/bin/env python3
"""Turn raw competitor scanner outputs into decision files in the DefenseClaw harness format and score them with s7gate.py.

  python3 materialize.py --config llamafirewall [--tuned] [--sets all] [--sides holdout,tune] [--s7c ~/s7c] [--score]

Writes <s7c>/compare/runs/<config>[-tuned]/decisions/cmp-<set>-<h|t>/g0-default.jsonl (+ ids, .rc, .ok markers),
RUN.json (tool, config, thresholds, raw VERSION files) and COVERAGE.json (cases per set where at least one rule applied).
--tuned first fits every tunable threshold on the TUNE side only (pooled over configs.TUNE_SETS, the F1 of flagged =
alert-or-block cases, a grid over the scores seen) and writes THRESHOLDS.json; the holdout side is never read for that.
--score runs `s7gate.py score` on the run (labels v3.3 overlay, the frozen split), the one scorer every tool and DefenseClaw use.
"""
import argparse, collections, glob, json, os, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import caseview  # noqa: E402
from configs import ALL_SETS, CONFIGS, TUNE_SETS  # noqa: E402

LEVEL = {"allow": 0, "alert": 1, "block": 2}


def load_raw(raw_dir, raw, s, side):
    p = os.path.join(raw_dir, raw, f"{s}.{side}.jsonl")
    out = {}
    if not os.path.exists(p):
        return None
    for l in open(p):
        try:
            r = json.loads(l)
        except ValueError:
            continue
        out[(r["case"], r["idx"])] = r
    return out


def tkey(rule):
    return rule.get("tie") or rule["scanner"]


def event_decision(rules, raws, cid, idx, kind, thr):
    lvl, fired, applicable, err, ms = 0, [], False, False, 0.0
    for ru in rules:
        if kind not in ru["on"]:
            continue
        rr = raws.get(ru["raw"])
        row = rr.get((cid, idx)) if rr else None
        if row is None:
            continue
        sc = row["scanners"].get(ru["scanner"])
        if not sc or not sc.get("applicable", True):
            continue
        applicable = True
        if not sc.get("cached"):
            ms += sc.get("ms", 0.0)
        if sc.get("decision") == "error":
            err = True
            l = LEVEL.get(sc.get("native") or "allow", 0)
        elif ru.get("threshold") is None:
            l = LEVEL.get(sc.get("decision"), 0)
        else:
            t = thr.get(tkey(ru), ru["threshold"])
            l = LEVEL[ru.get("level", "block")] if (sc.get("score") is not None and sc["score"] >= t) else 0
        if l:
            fired.append(ru["scanner"])
        lvl = max(lvl, l)
    return lvl, fired, applicable, err, ms


def case_events(sets_dir, s, side):
    for l in open(os.path.join(sets_dir, f"{s}.{side}.cases.jsonl")):
        c = json.loads(l)
        yield c, caseview.events(c)


def truth_of(s7c, s, side):
    """case id -> attack? (in-scope cases only), with the scorer's own truth rules and the labels overlay."""
    sys.path.insert(0, s7c)
    import s7gate
    labels = {}
    for l in open(os.path.join(s7c, "labels", "current.jsonl")):
        if l.startswith("{"):
            r = json.loads(l)
            if r.get("source_truth"):
                labels[r["id"]] = r["source_truth"]
    cfg = {"files": [os.path.join(s7c, "compare", "sets", f"{s}.{side}.cases.jsonl")]}
    out = {}
    for cid, tr in s7gate.read_cases(cfg):
        st = tr["state"]
        if cid in labels:
            st = {"benign": "benign", "malicious": "attack"}.get(labels[cid], "excluded")
        if st != "excluded":
            out[cid] = st == "attack"
    return out


def fit(cfgname, raw_dir, sets_dir, s7c):
    cfg = CONFIGS[cfgname]
    keys = sorted({tkey(r) for r in cfg["rules"] if r.get("tune")})
    if not keys:
        return {}
    raws = {}
    data = []   # (attack?, [(kind, idx)] , cid, set)
    for s in TUNE_SETS:
        truth = truth_of(s7c, s, "tune")
        for r in {r["raw"] for r in cfg["rules"]}:
            raws.setdefault(s, {})[r] = load_raw(raw_dir, r, s, "tune")
        for c, evs in case_events(sets_dir, s, "tune"):
            if c["id"] in truth:
                data.append((truth[c["id"]], [(e["kind"], i) for i, e in enumerate(evs)], c["id"], s))
    # candidate thresholds: the distinct scores seen for each key, thinned to <= 400
    cands = {k: set() for k in keys}
    for _, evl, cid, s in data:
        for kind, i in evl:
            for ru in cfg["rules"]:
                if tkey(ru) in cands and kind in ru["on"]:
                    rr = raws[s].get(ru["raw"])
                    row = rr.get((cid, i)) if rr else None
                    sc = row and row["scanners"].get(ru["scanner"])
                    if sc and sc.get("score") is not None:
                        cands[tkey(ru)].add(round(sc["score"], 4))
    for k in keys:
        v = sorted(cands[k] | {CONFIGS[cfgname]["rules"][[tkey(r) for r in cfg["rules"]].index(k)]["threshold"]})
        if len(v) > 400:
            v = [v[int(i * (len(v) - 1) / 399)] for i in range(400)]
        cands[k] = v
    thr = {k: next(r["threshold"] for r in cfg["rules"] if tkey(r) == k) for k in keys}
    # per case: flagged by the fixed (untuned) rules, and the max score per tunable key; a case is flagged at thresholds th
    # iff fixed or any key's max >= th[key] (exactly what event_decision gives, without re-reading rows per candidate)
    fixed_rules = [r for r in cfg["rules"] if not r.get("tune")]
    pre = []
    for y, evl, cid, s in data:
        fx = any(event_decision(fixed_rules, raws[s], cid, i, kind, {})[0] > 0 for kind, i in evl)
        mx = {}
        for kind, i in evl:
            for ru in cfg["rules"]:
                if ru.get("tune") and kind in ru["on"]:
                    rr = raws[s].get(ru["raw"]); row = rr.get((cid, i)) if rr else None
                    sc = row and row["scanners"].get(ru["scanner"])
                    if sc and sc.get("applicable", True) and sc.get("score") is not None and sc.get("decision") != "error":
                        mx[tkey(ru)] = max(mx.get(tkey(ru), -1.0), sc["score"])
        pre.append((y, fx, mx))

    def f1(th):
        tp = fp = fn = 0
        for y, fx, mx in pre:
            flag = fx or any(v >= th[k] for k, v in mx.items())
            tp += y and flag; fp += (not y) and flag; fn += y and not flag
        return 2 * tp / (2 * tp + fp + fn) if tp else 0.0, tp, fp, fn
    best = f1(thr)
    for _ in range(3):   # coordinate ascent over the tied threshold groups (usually one)
        changed = False
        for k in keys:
            for t in cands[k]:
                th = dict(thr); th[k] = t
                r = f1(th)
                if r[0] > best[0] + 1e-12:
                    best, thr, changed = r, th, True
        if not changed:
            break
    return dict(thresholds=thr, tune_f1=best[0], tune_tp=best[1], tune_fp=best[2], tune_fn=best[3], tune_sets=TUNE_SETS, tune_cases=len(data),
                objective="max F1 of flagged (alert-or-block) cases, pooled over the tune side of TUNE_SETS")


def materialize(cfgname, label, thr, raw_dir, sets_dir, s7c, sets, sides):
    cfg = CONFIGS[cfgname]
    out = os.path.join(s7c, "compare", "runs", label)
    cov = {}
    for s in sets:
        for side in sides:
            raws = {r: load_raw(raw_dir, r, s, side) for r in {r["raw"] for r in cfg["rules"]}}
            missing = [r for r, v in raws.items() if v is None]
            corpus = f"cmp-{s}-{side[0]}"
            d = os.path.join(out, "decisions", corpus)
            os.makedirs(d, exist_ok=True)
            ids, rows, napp, nerr, nmiss = [], [], 0, 0, 0
            for c, evs in case_events(sets_dir, s, side):
                ids.append(c["id"]); app = False; complete = True
                for i, e in enumerate(evs):
                    if not all(v is not None and (c["id"], i) in v for v in raws.values()):
                        complete = False
                    lvl, fired, a, err, ms = event_decision(cfg["rules"], raws, c["id"], i, e["kind"], thr)
                    app |= a; nerr += err
                    act = ["allow", "alert", "block"][lvl]
                    rows.append(dict(case=c["id"], idx=i, action=act, raw_action=act, rule_ids=fired, lat_us=int(ms * 1000), err=bool(err), extra={"applicable": a}))
                if not complete:
                    nmiss += 1
                    rows = [r for r in rows if r["case"] != c["id"]]   # an undecided case stays missing: the scorer marks the set incomplete
                napp += app
            with open(os.path.join(d, "ids.g0.txt"), "w") as f:
                f.write("\n".join(ids) + "\n")
            with open(os.path.join(d, "g0-default.jsonl"), "w") as f:
                for r in rows:
                    f.write(json.dumps(r) + "\n")
            open(os.path.join(d, "g0-default.jsonl.rc"), "w").write("0\n")
            open(os.path.join(d, "g0-default.jsonl.ok"), "w").write("ok\n")
            cov[corpus] = dict(cases=len(ids), applicable_cases=napp, error_events=nerr, undecided_cases=nmiss, missing_raw=missing)
    vers = {}
    for r in {r["raw"] for r in cfg["rules"]}:
        p = os.path.join(raw_dir, r, "VERSION.json")
        vers[r] = json.load(open(p)) if os.path.exists(p) else None
    json.dump(dict(packs=["default"], tool=cfg["tool"], config=cfgname, desc=cfg["desc"], rules=cfg["rules"], thresholds=thr, raw_versions=vers, kind="competitor"),
              open(os.path.join(out, "RUN.json"), "w"), indent=1)
    json.dump(cov, open(os.path.join(out, "COVERAGE.json"), "w"), indent=1)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--tuned", action="store_true")
    ap.add_argument("--sets", default="all")
    ap.add_argument("--sides", default="holdout,tune")
    ap.add_argument("--s7c", default=os.path.expanduser("~/s7c"))
    ap.add_argument("--score", action="store_true")
    a = ap.parse_args()
    raw_dir = os.path.join(a.s7c, "compare", "raw"); sets_dir = os.path.join(a.s7c, "compare", "sets")
    sets = ALL_SETS if a.sets == "all" else a.sets.split(",")
    thr, label = {}, a.config
    if a.tuned:
        label += "-tuned"
        info = fit(a.config, raw_dir, sets_dir, a.s7c)
        thr = info.get("thresholds", {})
        os.makedirs(os.path.join(a.s7c, "compare", "runs", label), exist_ok=True)
        json.dump(info, open(os.path.join(a.s7c, "compare", "runs", label, "THRESHOLDS.json"), "w"), indent=1)
        print("fit", a.config, json.dumps(info))
    out = materialize(a.config, label, thr, raw_dir, sets_dir, a.s7c, sets, a.sides.split(","))
    print("wrote", out)
    if a.score:
        r = subprocess.run([sys.executable, "-I", os.path.join(a.s7c, "s7gate.py"), "score", "--corpora", os.path.join(a.s7c, "corpora_compare.json"),
                            "--out", out], cwd=a.s7c, capture_output=True, text=True)
        print(r.stdout[-3000:], r.stderr[-2000:])


if __name__ == "__main__":
    main()
