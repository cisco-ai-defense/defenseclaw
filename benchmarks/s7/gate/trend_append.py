#!/usr/bin/env python3
"""Append trend rows for one finished gate run.
usage: trend_append.py SCORES_DIR LABEL CODE KIND BOX_LOAD [--trend FILE] [--dry-run] [--stamp ISO]
One row per (corpus, pack, surface); surface "all" plus every tool surface that has cases. benign_block / benign_alert are COUNTS of benign cases blocked / alerted
(the convention of the seeded rows), with benign_n and the rates and Wilson CIs next to them. Every row says its layers ("rules" or "rules+judge"),
its judge model (null for rules only) and whether the corpus was a stratified sample; sampled rows add precision / recall / FPR / F1 at corpus
prevalence (w_*) and the judge rows add judge latency, cut-at-window share and USD per 1k tool calls. Writes the STATUS line text to stdout."""
import sys, os, json, glob, math, time
args = [a for a in sys.argv[1:] if not a.startswith("--")]
flags = sys.argv[1:]
def opt(name, default=None):
    return flags[flags.index(name) + 1] if name in flags else default
scores, label, code, kind, load = args[:5]
trend = opt("--trend", os.path.expanduser("~/dc-eh/evidence/rel-1-0-10/s7/trend/trend.jsonl")); dry = "--dry-run" in flags
stamp = opt("--stamp", time.strftime("%Y-%m-%dT%H:%MZ", time.gmtime()))
def wil(k, n, z=1.96):
    if n == 0: return None
    p = k / n; d = 1 + z * z / n; c = p + z * z / (2 * n); h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)); return [round((c - h) / d, 5), round((c + h) / d, 5)]
def rnd(x): return None if x is None or x != x else round(x, 4)
def wrow(b, a, r):
    x = {}
    for key, c in (("block", b), ("alert", a)):
        w = c.get("weighted")
        if w:
            for m in ("precision", "recall", "fpr", "f1"): x[f"w_{key}_{m}"] = rnd(w[m])
            for m, ci in (c.get("weighted_ci") or {}).items(): x[f"w_{key}_{m}_ci"] = [round(v, 4) for v in ci]
    j = r.get("judge")
    if j:
        x.update(judge_calls=j["judge_calls"], tool_calls=j["tool_calls"], judge_per_tool_call=rnd(j["per_tool_call"]), judge_p50_ms=j["p50_ms"], judge_p95_ms=j["p95_ms"],
                 hook_p50_ms=rnd(j["hook_p50_ms"]), hook_p95_ms=rnd(j["hook_p95_ms"]), judge_cut_share=rnd(j["cut_share"]), judge_parse_failed=j["parse_failed"],
                 judge_failed=j["failed"], usd_per_1k_tool_calls=rnd(j["usd_per_1k_tool_calls"]))
    return x
def row(corpus, pack, surface, cases, benign, attack, b, a, r=None):
    r = r or {}
    return {"t": stamp, "layers": r.get("layers", "rules"), "judge": r.get("judge_model"), "sampled": bool(r.get("sampled")), "run": label, "code": code, "kind": kind, "corpus": corpus, "pack": pack, "surface": surface, "cases": cases, "benign_n": benign, "attack_n": attack,
            "benign_block": int(b["fp"]), "benign_alert": int(a["fp"]), "benign_block_rate": rnd(b["fp"] / benign) if benign else None, "benign_alert_rate": rnd(a["fp"] / benign) if benign else None,
            "benign_block_ci": wil(int(b["fp"]), benign), "benign_alert_ci": wil(int(a["fp"]), benign),
            "block_recall": rnd(b["recall"]), "alert_recall": rnd(a["recall"]), "block_f1": rnd(b["f1"]), "alert_f1": rnd(a["f1"]),
            "block_recall_ci": wil(int(b["tp"]), int(b["tp"] + b["fn"])), "alert_recall_ci": wil(int(a["tp"]), int(a["tp"] + a["fn"])), "box_load": load, **(wrow(b, a, r) if r.get("_top") else {})}
rows = []
for f in sorted(glob.glob(scores + "/*.json")):
    r = json.load(open(f)); corpus, pack = r["corpus"], r["pack"]
    b, a = r["block"], r["alert"]
    rows.append(row(corpus, pack, "all", r["scored"], int(b["neg"]), int(b["pos"]), b, a, dict(r, _top=True)))
    for sname, g in sorted((r.get("surfaces") or {}).items()):
        rows.append(row(corpus, pack, sname, g["cases"], g["benign"], g["attack"], g["block"], g["alert"], {k: r.get(k) for k in ("layers", "judge_model", "sampled")}))
if dry:
    print(f"[dry-run] would append {len(rows)} rows to {trend}")
else:
    os.makedirs(os.path.dirname(trend), exist_ok=True)
    with open(trend, "a") as o:
        for x in rows: o.write(json.dumps(x, sort_keys=True) + "\n")
parts = []
for x in rows:
    if x["surface"] == "all" and x["pack"] == "default":
        parts.append(f"{x['corpus']}{' [' + x['layers'] + (':' + x['judge'] if x['judge'] else '') + (' sample' if x['sampled'] else '') + ']' if x['layers'] != 'rules' or x['sampled'] else ''} benign-block {x['benign_block']}/{x['benign_n']} alert {x['benign_alert']} recall block {x['block_recall']} alert {x['alert_recall']}")
print(f"s7-corpus: {stamp} TREND {label} ({kind}) {code}: {len(rows)} rows" + (" [dry-run]" if dry else "") + "; default pack: " + "; ".join(parts))
