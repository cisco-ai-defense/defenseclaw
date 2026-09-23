"""Read-only: does ANY benchmark stage on this host draw from a SecJudge training source?"""
import json, glob, collections, os
BASE = "$WORK/.system-one-data/outputs"
SECJUDGE_TRAIN = ["defenseclaw", "nl2bash", "infraset", "S-Labs", "prompt-injection-dataset",
                  "Magicoder", "Trendyol", "3nesdeniz", "deepset", "prompt-injections"]
out = {}
for p in sorted(glob.glob(BASE + "/*/cases.jsonl")):
    stage = os.path.basename(os.path.dirname(p))
    c = collections.Counter(); n = 0
    try:
        for line in open(p, encoding="utf-8"):
            line = line.strip()
            if not line: continue
            n += 1
            try: d = json.loads(line)
            except Exception: continue
            s = d.get("source") or {}
            if isinstance(s, dict): c[str(s.get("dataset"))] += 1
    except Exception as e:
        out[stage] = {"error": str(e)[:200]}; continue
    hits = {k: v for k, v in c.items() if any(t.lower() in k.lower() for t in SECJUDGE_TRAIN)}
    out[stage] = {"n_cases": n, "n_datasets": len(c), "dataset_counts": dict(sorted(c.items(), key=lambda kv: -kv[1])),
                  "secjudge_training_source_hits": hits}
json.dump(out, open("$WORK/.system-one-data/outputs/secjudge/contamination/work/all_stages_sources.json", "w"), indent=2)
for k, v in out.items():
    print("%-20s cases=%-7s hits=%s" % (k, v.get("n_cases"), v.get("secjudge_training_source_hits")))
