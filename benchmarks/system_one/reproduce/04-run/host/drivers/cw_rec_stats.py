#!/usr/bin/env python3
"""Latency / token stats from benchmark_run_system_one output records."""
import glob
import json
import os
import statistics as st
import sys


def pct(xs, p):
    if not xs:
        return float("nan")
    xs = sorted(xs)
    k = (len(xs) - 1) * p / 100.0
    lo = int(k // 1)
    hi = min(lo + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def main(paths):
    for path in paths:
        recs = []
        try:
            with open(path, errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        recs.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except OSError:
            continue
        if not recs:
            continue
        models = {}
        for r in recs:
            models.setdefault(str(r.get("model")), []).append(r)
        for model, rs in sorted(models.items()):
            d = [r["duration_ms"] for r in rs if isinstance(r.get("duration_ms"), (int, float))]
            it = [r["input_tokens"] for r in rs if isinstance(r.get("input_tokens"), (int, float))]
            cb = [r["context_bytes"] for r in rs if isinstance(r.get("context_bytes"), (int, float))]
            errs = sum(1 for r in rs if r.get("error_code"))
            traj = {}
            for r in rs:
                traj.setdefault(r.get("case_id", "").split("/")[0] if "/" in str(r.get("case_id", "")) else r.get("case_id"), 0)
            qv = sorted({r.get("question_variant") for r in rs})
            cv = sorted({r.get("context_variant") for r in rs})
            print("%-58s n=%-7d model=%-12s q=%s c=%s err=%d" % (os.path.basename(path), len(rs), model[:12], ",".join(map(str, qv)), ",".join(map(str, cv)), errs))
            if d:
                print("    duration_ms  p50=%8.0f p90=%8.0f p95=%8.0f p99=%8.0f max=%8.0f mean=%8.0f  sum=%.0fs"
                      % (pct(d, 50), pct(d, 90), pct(d, 95), pct(d, 99), max(d), st.mean(d), sum(d) / 1000.0))
            if it:
                print("    input_tokens p50=%8.0f p90=%8.0f max=%8.0f mean=%8.1f  sum=%.0f" % (pct(it, 50), pct(it, 90), max(it), st.mean(it), sum(it)))
            if cb:
                print("    ctx_bytes    p50=%8.0f p90=%8.0f max=%8.0f mean=%8.1f" % (pct(cb, 50), pct(cb, 90), max(cb), st.mean(cb)))


if __name__ == "__main__":
    pats = sys.argv[1:]
    files = []
    for p in pats:
        files.extend(sorted(glob.glob(p)))
    main(files)
