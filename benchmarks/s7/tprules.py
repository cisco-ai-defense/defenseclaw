import json, sys, collections
corpus, dec = sys.argv[1], sys.argv[2]
T = {}
for l in open(corpus):
    r = json.loads(l); T[r["id"]] = r["truth"].get("source_truth") in ("malicious", "sensitive")
tp = collections.Counter(); tpb = collections.Counter(); fpc = collections.Counter(); seen = set()
for l in open(dec):
    r = json.loads(l)
    if not (r["action"] == "block" or r["raw_action"] in ("alert", "block", "confirm")): continue
    for f in r.get("findings") or []:
        rid = f.split(":", 1)[0] if not f.startswith("codeguard:") else "codeguard:" + f.split(":")[1]
        k = (r["case"], rid)
        if k in seen: continue
        seen.add(k)
        if T[r["case"]]:
            tp[rid] += 1
            if r["action"] == "block": tpb[rid] += 1
        else: fpc[rid] += 1
print("rule | TP cases (alert) | of which blocked | FP cases")
for rid in sorted(set(tp) | set(fpc), key=lambda x: -(tp[x] + fpc[x]))[:25]:
    print(f"{rid} | {tp[rid]} | {tpb[rid]} | {fpc[rid]}")
