import json, sys, collections
for path in sys.argv[1:]:
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    toks = sum(int(r.get("input_tokens", 0)) for r in rows)
    lat = sorted(r["duration_ms"] for r in rows if isinstance(r.get("duration_ms"), (int, float)))
    errs = [r for r in rows if r.get("action") == "error"]
    trunc = [r for r in rows if r.get("truncated")]
    disp = collections.Counter(r.get("action") for r in rows)
    print(f"== {path}")
    print(f"   rows={len(rows)} input_tokens_total={toks} errors={len(errs)} truncated={len(trunc)}")
    if lat:
        n = len(lat)
        pick = lambda q: lat[min(n - 1, int(q * n))]
        print(f"   duration_ms mean={sum(lat)/n:.1f} p50={pick(.5):.1f} p90={pick(.9):.1f} p99={pick(.99):.1f} max={lat[-1]:.1f}")
    print(f"   dispositions={dict(disp)}")
