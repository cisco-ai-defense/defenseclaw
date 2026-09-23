"""Confidence/score resolution so far, per arm. Diagnostic only -- files are still open."""
import json
import statistics

G = "$WORK/.system-one-data/outputs/gemma4jev/s2"
for label, f in (("arm3 jevify T=1.0", "jevify-gemma4-26b-a4b.jsonl"),
                 ("arm2 base   T=5.155", "gemma-4-26b-a4b-it.jsonl")):
    conf, risks, errs, meta_t = [], [], 0, None
    for line in open(f"{G}/{f}"):
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue  # last line may be partially written
        if r.get("error"):
            errs += 1
            continue
        if r.get("confidence") is not None:
            conf.append(r["confidence"])
        p = r.get("probabilities") or {}
        if "disposition.allow" in p:
            risks.append(1.0 - p["disposition.allow"])
    print("=== %s   rows=%d errors=%d" % (label, len(conf), errs))
    if conf:
        print("    confidence: distinct=%d  median=%.6f  frac>0.999=%.4f"
              % (len(set(conf)), statistics.median(conf), sum(1 for c in conf if c > 0.999) / len(conf)))
    if risks:
        print("    risk(1-allow): distinct=%d  median=%.8f  max=%.6f  frac>0 =%.4f"
              % (len(set(risks)), statistics.median(risks), max(risks),
                 sum(1 for x in risks if x > 0) / len(risks)))
