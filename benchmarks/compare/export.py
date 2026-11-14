#!/usr/bin/env python3
"""Build docs-site/data/guardrail-compare.json and the markdown tables of COMPARE.md from the results of one comparison.

  python3 export.py --results ~/s7c/compare/results.json --sets ~/s7c/compare/sets/SETS.json --latency-dir ~/s7c/compare/latency \
      --llm-logs DIR --out-json docs-site/data/guardrail-compare.json --out-md tables.md [--meta meta.json]

Every number in the outputs is copied from results.json (scored by s7gate.py, CIs from aggregate.py), the latency files
(latency.py / gpu_run.py --latency) or the LLM call logs (llmshim / s7proxy): nothing is typed by hand. Cost per 1,000 calls =
API tokens at list price (measured tokens per call) + instance hours at the on-demand list price / measured throughput.
"""
import argparse, glob, json, os, sys, time

# on-demand list prices, us-east-1 (AWS Price List, 2026-11-13)
INSTANCE_USD_H = {"c7i.16xlarge": 2.856, "g6e.xlarge": 1.861}
HEADLINE_SIDE = "holdout"


def r4(x):
    return None if x is None else round(x, 4)


def mcc(c):
    tp, fp, fn, tn = c["tp"], c["fp"], c["fn"], c["tn"]
    d = ((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)) ** 0.5
    return (tp * tn - fp * fn) / d if d else 0.0


def cellj(c):
    return {k: (r4(v) if not isinstance(v, list) else [r4(x) for x in v]) for k, v in c.items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True); ap.add_argument("--sets", required=True); ap.add_argument("--latency-dir", required=True)
    ap.add_argument("--meta", default=""); ap.add_argument("--out-json", required=True); ap.add_argument("--out-md", required=True)
    a = ap.parse_args()
    R = json.load(open(a.results)); S = json.load(open(a.sets)); meta = json.load(open(a.meta)) if a.meta else {}
    lat = {}
    for f in glob.glob(os.path.join(a.latency_dir, "*.json")):
        j = json.load(open(f)); lat[j["name"]] = j
    out = dict(generated=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), split="holdout (frozen S7 split v1, strict: holdout under every corpus name)",
               split_sha256=S.get("split_sha256"), labels_sha256=S.get("labels_sha256"), scorer="s7gate.py score (one scorer for every tool)",
               datasets=[], tools=meta.get("tools", []), results=[], pooled=[], latency=[], cost=meta.get("cost", []), notes=meta.get("notes", []))
    private = {n for n, d in meta.get("datasets", {}).items() if d.get("public") is False}
    out["internal_only_sets"] = sorted(private)
    for name, v in S["sets"].items():
        if name in private:
            continue
        h = v["holdout"]
        out["datasets"].append(dict(name=name, holdout_benign=h.get("benign", 0), holdout_attack=h.get("attack", 0), holdout_excluded=h.get("excluded", 0),
                                    holdout_attack_expected_block=h.get("attack_expected_block", 0), events=h.get("events"), sampled=h.get("sampled"), sampled_from=h.get("sampled_from"),
                                    sources={k[8:]: c for k, c in h.items() if k.startswith("dataset:")}, licenses={k[8:]: c for k, c in h.items() if k.startswith("license:")},
                                    surfaces={k[8:]: c for k, c in h.items() if k.startswith("surface:")}, sha256=h.get("sha256"), **(meta.get("datasets", {}).get(name, {}))))
    for r in R["results"]:
        if r["side"] != HEADLINE_SIDE or r["set"] in private:
            continue
        out["results"].append(dict(run=r["run"], tool=r["tool"], config=r["config"], pack=r["pack"], set=r["set"], surface=r["surface"], na=r["na"],
                                   benign=r["benign"], attack=r["attack"], applicable_cases=r.get("applicable_cases"), block=cellj(r["block"]), alert=cellj(r["alert"])))
    for p in R["pooled"]:
        if p["side"] != HEADLINE_SIDE:
            continue
        out["pooled"].append(dict(run=p["run"], tool=p["tool"], config=p["config"], pack=p["pack"], surface=p["surface"], sets=p["sets"], benign=p["benign"], attack=p["attack"],
                                  block=cellj(p["block"]), alert=cellj(p["alert"]), alert_macro_f1=r4(p.get("alert_macro_f1"))))
    for n, j in sorted(lat.items()):
        s = j.get("single_stream_ms", {}).get("all") or {}
        out["latency"].append(dict(name=n, host=(j.get("host") or {}).get("cpu_model") or (j.get("version") or {}).get("gpu"), gpu=(j.get("version") or {}).get("gpu"),
                                   p50_ms=r4(s.get("p50")), p95_ms=r4(s.get("p95")), p99_ms=r4(s.get("p99")), per_kind={k: {q: r4(v.get(q)) for q in ("p50", "p95", "p99")} for k, v in j["single_stream_ms"].items() if k != "all"},
                                   throughput_events_per_s=r4((j.get("throughput") or {}).get("events_per_s")), load_before=j.get("load_before")))
    # headline: each tool's full documented config, threshold variant chosen on the TUNE side (pooled MCC, all surfaces);
    # DefenseClaw: every DefenseClaw run x pack. The holdout row of the chosen variant is what the tables show.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from configs import CONFIGS
    tune = {(p["run"], p["pack"]): p for p in R["pooled"] if p["side"] == "tune" and p["surface"] == "all"}
    hold = {(p["run"], p["pack"], p["surface"]): p for p in R["pooled"] if p["side"] == HEADLINE_SIDE}
    head = []
    for cfg, c in CONFIGS.items():
        if not c.get("headline"):
            continue
        cands = [r for r in (cfg, cfg + "-tuned") if (r, "default", "all") in hold]
        if not cands:
            continue
        scored = [(mcc(tune[(r, "default")]["alert"]), r) for r in cands if (r, "default") in tune]
        pick = max(scored)[1] if scored else cands[0]
        head.append(dict(tool=c["tool"], config=cfg, run=pick, variant="tuned" if pick.endswith("-tuned") else "default",
                         chosen_by="tune-side pooled MCC of flagged cases (the tuning rule)" if scored else "only variant", surfaces={k[2]: hold[k] for k in hold if k[0] == pick and k[1] == "default"}))
    for (r, pk, sf), p in hold.items():
        if p.get("kind") == "defenseclaw" and sf == "all":
            head.append(dict(tool="DefenseClaw", config=f"{r} ({pk})", run=r, pack=pk, variant="n/a", chosen_by="all DefenseClaw configs",
                             surfaces={k[2]: hold[k] for k in hold if k[0] == r and k[1] == pk}))
    out["headline"] = head
    json.dump(out, open(a.out_json, "w"), indent=1)
    # markdown: pooled headline, holdout, every run x pack, then per set
    md = ["## Datasets (holdout side)", "", "| Set | Source | Licence | Surface | Benign | Attack (expected block) | Events | What it tests |", "|---|---|---|---|---:|---:|---:|---|"]
    for d in out["datasets"]:
        smp = f" (sample of {d['sampled']} from {d['sampled_from']})" if d.get("sampled") else ""
        md.append(f"| {d['name']} | [{d.get('source', '?')}]({d.get('url', '')}) | {d.get('license', '?')} | {d.get('surface', '?')} | {d['holdout_benign']}{smp} | {d['holdout_attack']} ({d['holdout_attack_expected_block']}) | {d.get('events')} | {d.get('tests', '')}{(' ' + d['note']) if d.get('note') else ''} |")
    md += ["", "## Configurations", "", "| Config | Tool | What runs |", "|---|---|---|"]
    for cfg, c in CONFIGS.items():
        md.append(f"| {cfg} | {c['tool']} | {c['desc']} |")
    md += ["", "## Headline (holdout; threshold variant chosen on the tune side)", "", "| Tool | Run | Surface | Benign / attack | Block P / R / FPR / F1 | Alert P / R / FPR / F1 |", "|---|---|---|---:|---|---|"]
    fh = lambda c: " / ".join("-" if c.get(k) is None else f"{c[k]:.3f}" for k in ("precision", "recall", "fpr", "f1"))
    for h in head:
        for sf, p in sorted(h["surfaces"].items()):
            md.append(f"| {h['tool']} | {h['run']}{(' ' + h['pack']) if h.get('pack') else ''} | {sf} ({len(p['sets'])} sets) | {p['benign']} / {p['attack']} | {fh(p['block'])} | {fh(p['alert'])} |")
    md += ["", "## Pooled, every run", ""]
    md += ["| Tool | Config | Pack | Sets | Benign / attack | Block P / R / FPR / F1 | Alert P / R / FPR / F1 (F1 95% CI) |", "|---|---|---|---|---:|---|---|"]
    f = lambda c: " / ".join("-" if c.get(k) is None else f"{c[k]:.3f}" for k in ("precision", "recall", "fpr", "f1"))
    for p in sorted(out["pooled"], key=lambda x: (x["surface"], -(x["alert"]["f1"] or 0))):
        ci = p["alert"].get("f1_ci") or [None, None]
        md.append(f"| {p['tool']} | {p['config']} | {p['pack']} | {p['surface']} ({len(p['sets'])}) | {p['benign']} / {p['attack']} | {f(p['block'])} | {f(p['alert'])} ({'-' if ci[0] is None else f'{ci[0]:.3f}-{ci[1]:.3f}'}) |")
    md += ["", "| Set | Tool | Config | Pack | Benign / attack | Block R / FPR | Alert P / R / FPR / F1 |", "|---|---|---|---|---:|---|---|"]
    for r in sorted(out["results"], key=lambda x: (x["set"], x["tool"], x["config"], x["pack"])):
        if r["na"]:
            md.append(f"| {r['set']} | {r['tool']} | {r['config']} | {r['pack']} | {r['benign']} / {r['attack']} | N/A | N/A |"); continue
        b, al = r["block"], r["alert"]
        br = "-" if b["recall"] is None else f"{b['recall']:.3f}"
        bf = "-" if b["fpr"] is None else f"{b['fpr']:.4f}"
        md.append(f"| {r['set']} | {r['tool']} | {r['config']} | {r['pack']} | {r['benign']} / {r['attack']} | {br} / {bf} | {f(al)} |")
    open(a.out_md, "w").write("\n".join(md) + "\n")
    print("datasets", len(out["datasets"]), "results", len(out["results"]), "pooled", len(out["pooled"]), "latency", len(out["latency"]))


if __name__ == "__main__":
    main()
