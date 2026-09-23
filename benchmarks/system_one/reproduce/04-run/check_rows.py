"""Assert a System One prediction file really carries a graded, rankable readout."""
import json
import statistics
import sys

path = sys.argv[1]
rows = [json.loads(line) for line in open(path)]
errors = [r for r in rows if r.get("error")]
print("rows=%d errors=%d" % (len(rows), len(errors)))
if errors:
    print("first error:", json.dumps(errors[0])[:500])
have_probs = sum(1 for r in rows if r.get("probabilities"))
have_conf = sum(1 for r in rows if r.get("confidence") is not None)
print("with probabilities=%d with confidence=%d" % (have_probs, have_conf))
conf = [r["confidence"] for r in rows if r.get("confidence") is not None]
if conf:
    print("distinct confidence=%d min=%.6f median=%.6f max=%.6f"
          % (len(set(conf)), min(conf), statistics.median(conf), max(conf)))
    print("fraction above 0.999 = %.4f" % (sum(1 for c in conf if c > 0.999) / len(conf)))
dur = [r["duration_ms"] for r in rows if r.get("duration_ms")]
if dur:
    print("mean ms/request=%.1f median=%.1f (3 prefills per request)"
          % (statistics.mean(dur), statistics.median(dur)))
acts = {}
for r in rows:
    acts[r.get("action")] = acts.get(r.get("action"), 0) + 1
print("actions:", acts)
if errors:
    sys.exit(1)
