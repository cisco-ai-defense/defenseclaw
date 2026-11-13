import json, sys, random, collections
sys.path.insert(0, "/home/ubuntu/dc-eh/jobs/s7-bench")
from errs_red import red
DET = "/home/ubuntu/dc-eh/evidence/rel-1-0-10/s7/bench/det"
KEY = ("curl", "wget", "nc ", ".env", "secret", "token", "passw", "send", "post", "upload", "rm -", "chmod", "ssh", "key", "cred", "email", "http", "write", "sudo")
rnd = random.Random(741983)
sel = []
for corpus, nfp, nfn in (("s3", 39, 30), ("s2", 5, 26)):
    T = {}; TX = {}
    for l in open(f"/home/ubuntu/.system-one-data/outputs/{corpus}/cases.jsonl"):
        r = json.loads(l)
        T[r["id"]] = (r["truth"].get("source_truth") in ("malicious", "sensitive"), r["source"]["dataset"].split("/")[-1][:14], ",".join((r["truth"].get("categories") or [])[:3])[:50])
        TX[r["id"]] = [(e.get("tool_name"), e.get("command") or json.dumps(e.get("args"))) for e in (r["payload"].get("events") or [r["payload"]])]
    by = collections.defaultdict(list)
    for l in open(f"{DET}/{corpus}-default.jsonl"):
        r = json.loads(l); by[r["case"]].append(r)
    fp, fn = [], []
    for cid, rs in by.items():
        al = any(r["action"] == "block" or r["raw_action"] in ("alert", "block", "confirm") for r in rs)
        if al and not T[cid][0]: fp.append(cid)
        if T[cid][0] and not al: fn.append(cid)
    for kind, pool, n in (("FP", sorted(fp), nfp), ("FN", sorted(fn), nfn)):
        for cid in rnd.sample(pool, min(n, len(pool))):
            rs = sorted(by[cid], key=lambda r: r["idx"])
            if kind == "FP":
                idx = [r["idx"] for r in rs if r["action"] == "block" or r["raw_action"] in ("alert", "block", "confirm")][:2]
            else:
                idx = [i for i, (t, x) in enumerate(TX[cid]) if any(k in (x or "").lower() for k in KEY)][:2] or [0, len(TX[cid]) - 1][:min(2, len(TX[cid]))]
            sel.append((corpus, kind, cid, T[cid][1], T[cid][2], len(TX[cid]), [(i, TX[cid][i][0], red(TX[cid][i][1], 170)) for i in idx]))
for n, (corpus, kind, cid, ds, cat, ne, evs) in enumerate(sel, 1):
    print(f"#{n} {corpus} {kind} {ds} [{cat}] n={ne}")
    for i, t, x in evs: print(f"    e{i} {t}: {x}")
json.dump([s[:3] for s in sel], open(f"{DET}/spotcheck-ids.json", "w"))
