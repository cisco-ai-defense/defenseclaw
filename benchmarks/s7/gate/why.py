#!/usr/bin/env python3
"""Break down a rules-lane decisions file vs truth: positives by tool mapping and block outcome. usage: why.py DEC CASES"""
import json, sys, collections
dec, cases = sys.argv[1], sys.argv[2]
truth = {}
for l in open(cases):
    r = json.loads(l); t = r["truth"]; truth[r["id"]] = (t.get("source_truth"), t.get("expected_disposition"), t.get("applicability", "in_scope"), r["strata"].get("provider"))
pred = collections.defaultdict(lambda: dict(b=False, n=0, tools=set(), conn=set()))
for l in open(dec):
    r = json.loads(l); p = pred[r["case"]]; p["n"] += 1; p["b"] |= r.get("action") == "block"
    p["tools"].add(f"{r.get('src_tool')}->{r.get('tool')}/{r.get('mapped')}"); p["conn"].add(r.get("connector") or "claudecode(legacy)")
print("decision rows connectors:", collections.Counter(c for p in pred.values() for c in p["conn"]))
c = collections.Counter()
for i, p in pred.items():
    st, ed, app, prov = truth[i]
    if st in ("malicious", "sensitive"):
        c[(ed, prov, ",".join(sorted(p["tools"]))[:60], "BLOCK" if p["b"] else "-")] += 1
for k, v in sorted(c.items(), key=lambda kv: -kv[1])[:14]: print(v, k)
att = [i for i in pred if truth[i][0] in ("malicious", "sensitive")]
eb = [i for i in att if truth[i][1] == "block"]
print(f"block TP {sum(pred[i]['b'] for i in att)} / attacks {len(att)} = {sum(pred[i]['b'] for i in att)/max(1,len(att)):.4f}; on expected-block {sum(pred[i]['b'] for i in eb)}/{len(eb)} = {sum(pred[i]['b'] for i in eb)/max(1,len(eb)):.4f}")
