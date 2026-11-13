#!/usr/bin/env python3
"""Render TREND.md from trend.jsonl.   usage: trend.py [--trend FILE] [--out FILE]   (-h: usage; unknown flags exit 2)
Per corpus and pack (surface "all"): the baseline row, then every run in order with the change against the baseline and against the previous run.
Better = fewer benign blocks/alerts, higher recall and F1. Worse is marked REGRESSION and never hidden."""
import sys, os, json, collections
USAGE = "usage: trend.py [--trend FILE] [--out FILE]\n  renders TREND.md (default next to this script's evidence trend dir) from trend.jsonl"
argv = sys.argv[1:]
if any(a in ("-h", "--help") for a in argv): print(USAGE); sys.exit(0)
trend = os.path.expanduser("~/dc-eh/evidence/rel-1-0-10/s7/trend/trend.jsonl"); out = os.path.expanduser("~/dc-eh/jobs/s7-corpus/TREND.md")
i = 0
while i < len(argv):
    if argv[i] == "--trend" and i + 1 < len(argv): trend = os.path.expanduser(argv[i + 1]); i += 2
    elif argv[i] == "--out" and i + 1 < len(argv): out = os.path.expanduser(argv[i + 1]); i += 2
    else: print(f"trend.py: unknown argument {argv[i]!r}\n{USAGE}", file=sys.stderr); sys.exit(2)
allrows = [json.loads(l) for l in open(trend) if l.strip()]
# Only s7-gate rows are rendered (they carry t, run and the benign counts); other lanes append rows of their own shape to the same file.
# Rows marked in trend-marks.jsonl (scorer=score2-legacy etc., rel-1-0-10:GAP-0121) are never rendered, whatever their shape.
import hashlib
_mf = os.path.join(os.path.dirname(trend), "trend-marks.jsonl")
_marked = {json.loads(m)["sha"] for m in open(_mf) if m.strip()} if os.path.exists(_mf) else set()
_lines = [l.rstrip("\n") for l in open(trend) if l.strip()]
allrows = [r for r, l in zip(allrows, _lines) if hashlib.sha256(l.encode()).hexdigest()[:16] not in _marked]
rows = [r for r in allrows if "t" in r and "run" in r and "benign_block" in r]
other = len(allrows) - len(rows)
for r in rows:
    r.setdefault("surface", "all")
    r["cfg"] = (r.get("layers") or "rules") + (":" + r["judge"] if r.get("judge") and r.get("judge") != "none" else "") + (" (judge sample)" if r.get("sampled") else "")
BASE_CODE = "rel/1.0.10 00e6d52cf3"
LOWER = ("benign_block", "benign_alert"); HIGHER = ("block_recall", "alert_recall", "block_f1", "alert_f1")
def key(r): return (r["corpus"], r["pack"], r["surface"], r["cfg"])
def arrow(metric, d):
    if d is None or d == 0: return "="
    good = d < 0 if metric in LOWER else d > 0
    return ("▲ better" if good else "▼ WORSE")
def fmt(metric, v):
    if v is None: return "n/a"
    return str(v) if metric in LOWER else f"{v:.3f}"
def delta(metric, v, ref):
    if v is None or ref is None: return None
    return v - ref
def cell(metric, v, base, prev):
    s = fmt(metric, v)
    if v is None: return s
    parts = []
    for tag, ref in (("base", base), ("prev", prev)):
        d = delta(metric, v, ref)
        if d is None: continue
        parts.append(f"{tag} {'+' if d > 0 else ''}{d:.3f}".replace(".000", "") if metric not in LOWER else f"{tag} {'+' if d > 0 else ''}{int(d)}")
    a = arrow(metric, delta(metric, v, base)); b = arrow(metric, delta(metric, v, prev))
    flag = " **REGRESSION**" if "WORSE" in (a, b) else ""
    return f"{s} ({', '.join(parts)}) {a if a == b else a + ' / ' + b}{flag}" if parts else s
groups = collections.defaultdict(list)
for r in rows: groups[key(r)].append(r)
L = ["# S7 benchmark trend", "", f"Generated from `{trend}` ({len(rows)} s7-gate rows; {other} rows of other shapes and {len(_marked)} rows marked legacy in trend-marks.jsonl not rendered). Each table is one configuration: `rules` (free layers) or `rules+judge:<model>`; judge rows run on the stratified judge sample, with precision / FPR / F1 at corpus prevalence in the w_* fields of the trend file. Baseline = rel/1.0.10 00e6d52cf3 (phase 1 for s2/s3, the first connector-aware run for the new corpora). Runs of kind `merge-head` are the points that count; `branch` runs are shown as branch-only.",
     "`benign_block` / `benign_alert` are counts of benign cases blocked / alerted on that corpus (lower is better); recall and F1 higher is better. `base` = change against the baseline row, `prev` = against the previous run of the same corpus and pack.", ""]
regs = []
for corpus in sorted({k[0] for k in groups}):
    L += [f"## {corpus}", ""]
    for pack, cfg in sorted({(k[1], k[3]) for k in groups if k[0] == corpus}, key=lambda t: (("default", "permissive", "strict").index(t[0]) if t[0] in ("default", "permissive", "strict") else 9, t[1] != "rules", t[1])):
        g = sorted(groups.get((corpus, pack, "all", cfg), []), key=lambda r: r["t"])
        if not g: continue
        base = next((r for r in g if r["code"].startswith(BASE_CODE) and "branch" not in r.get("kind", "")), g[0])
        L += [f"### {pack}" + ("" if cfg == "rules" else f" / {cfg}"), "", "| time (UTC) | run | code | kind | benign blocked | benign alerted | block recall | alert recall | block F1 | alert F1 | box load |", "|---|---|---|---|---|---|---|---|---|---|---:|"]
        prev = None
        for r in g:
            cells = []
            for m in ("benign_block", "benign_alert", "block_recall", "alert_recall", "block_f1", "alert_f1"):
                v = r.get(m)
                c = cell(m, v, base.get(m) if r is not base else None, prev.get(m) if prev else None) if r is not base else (fmt(m, v) + " (baseline)")
                if "REGRESSION" in c: regs.append((corpus, pack + ("" if cfg == "rules" else f" / {cfg}"), r["run"], m, c))
                cells.append(c)
            L.append(f"| {r['t']} | {r['run']} | {r['code']} | {r.get('kind', '')} | " + " | ".join(cells) + f" | {r.get('box_load', '')} |")
            prev = r
        L.append("")
latest = {}
for k, g in groups.items():
    if k[2] != "all": latest.setdefault((k[0], k[1]), None)
L += ["## Regressions (every metric of every run that is worse than the baseline or the previous run)", ""]
L += ([f"* {c} / {p} / run `{run}` / {m}: {txt}" for c, p, run, m, txt in regs] or ["* none"])
L += ["", "## By tool surface (latest run vs the first run that has the surface, default pack)", "", "| corpus | surface | cases | first run | latest run | benign blocked | benign alerted | block recall | alert recall |", "|---|---|---:|---|---|---|---|---|---|"]
for (corpus, pack, surface, cfg), g in sorted(groups.items()):
    if pack != "default" or surface == "all" or cfg != "rules": continue
    g = sorted(g, key=lambda r: r["t"]); a, z = g[0], g[-1]
    if len(g) < 2:
        L.append(f"| {corpus} | {surface} | {z['cases']} | {a['run']} | (only one run) | {z['benign_block']} | {z['benign_alert']} | {fmt('block_recall', z['block_recall'])} | {fmt('alert_recall', z['alert_recall'])} |")
    else:
        L.append(f"| {corpus} | {surface} | {z['cases']} | {a['run']} | {z['run']} | " + " | ".join(f"{fmt(m, z[m])} ({'+' if z[m] is not None and a[m] is not None and z[m] > a[m] else ''}{'' if z[m] is None or a[m] is None else round(z[m] - a[m], 3)}) {arrow(m, delta(m, z[m], a[m]))}" for m in ("benign_block", "benign_alert", "block_recall", "alert_recall")) + " |")
open(out, "w").write("\n".join(L) + "\n"); print(f"wrote {out} ({len(L)} lines, {len(regs)} regression cells)")
