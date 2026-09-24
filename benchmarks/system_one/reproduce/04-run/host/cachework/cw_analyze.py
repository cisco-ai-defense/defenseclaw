#!/usr/bin/env python3
"""Combine the controlled-experiment artefacts into one report.

Inputs (all on the controller except metrics, which is fetched separately):
  --marks     outputs/cache/marks.jsonl        run/gap window timestamps
  --records   outputs/cache/<cfg>-r<n>.jsonl   benchmark records (latency + decisions)
  --calls     cw/runs/<cfg>-r<n>/calls.jsonl   per-upstream-call latency + prompt tokens
  --poll      cw/poll-8002.jsonl               1 Hz vLLM counter samples
"""
import argparse
import collections
import glob
import json
import os
import statistics as st


def pct(xs, p):
    if not xs:
        return float("nan")
    xs = sorted(xs)
    k = (len(xs) - 1) * p / 100.0
    lo = int(k // 1)
    hi = min(lo + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def read_jsonl(path):
    out = []
    try:
        with open(path, errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    except OSError:
        pass
    return out


def windows(marks):
    """-> {(cfg, round): (run_start, run_end)}, [(gap_start, gap_end), ...]"""
    runs = {}
    gaps = []
    open_gap = None
    for m in marks:
        key = (m["cfg"], m["round"])
        if m["event"] == "run_start":
            runs.setdefault(key, [None, None])[0] = m["t"]
        elif m["event"] == "run_end":
            runs.setdefault(key, [None, None])[1] = m["t"]
        elif m["event"] == "gap_start":
            open_gap = m["t"]
        elif m["event"] == "gap_end" and open_gap is not None:
            gaps.append((open_gap, m["t"]))
            open_gap = None
    return {k: tuple(v) for k, v in runs.items() if v[0] and v[1]}, gaps


def interp(samples, t, key):
    """counter value at time t, linearly interpolated between the bracketing samples"""
    prev = None
    for s in samples:
        if key not in s:
            continue
        if s["t"] >= t:
            if prev is None:
                return s.get(key)
            span = s["t"] - prev["t"]
            if span <= 0:
                return s.get(key)
            f = (t - prev["t"]) / span
            return prev[key] + f * (s[key] - prev[key])
        prev = s
    return prev.get(key) if prev else None


def delta(samples, t0, t1, key):
    a = interp(samples, t0, key)
    b = interp(samples, t1, key)
    if a is None or b is None:
        return None
    return b - a


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--marks", required=True)
    ap.add_argument("--records-dir", required=True)
    ap.add_argument("--calls-dir", required=True)
    ap.add_argument("--poll", required=True)
    a = ap.parse_args()

    marks = read_jsonl(a.marks)
    runs, gaps = windows(marks)
    poll = [s for s in read_jsonl(a.poll) if "vllm:prompt_tokens_total" in s]
    poll.sort(key=lambda s: s["t"])

    # ---- background prefix-cache rate from the idle gaps between configs -------------
    bg_rates = []
    bg_tokrate = []
    for g0, g1 in gaps:
        g0 += 4.0  # let my own in-flight work drain
        if g1 - g0 < 8:
            continue
        dp = delta(poll, g0, g1, "vllm:prompt_tokens_total")
        dc = delta(poll, g0, g1, "vllm:prompt_tokens_cached_total")
        if dp and dp > 1000 and dc is not None:
            bg_rates.append(dc / dp)
            bg_tokrate.append(dp / (g1 - g0))
    bg = st.median(bg_rates) if bg_rates else float("nan")
    print("BACKGROUND (idle gaps, n=%d windows): cached fraction median=%.2f%%  p25=%.2f%% p75=%.2f%%   submitted %.0f tok/s"
          % (len(bg_rates), 100 * bg, 100 * pct(bg_rates, 25), 100 * pct(bg_rates, 75),
             st.median(bg_tokrate) if bg_tokrate else float("nan")))
    print()

    # ---- per config -----------------------------------------------------------------
    by_cfg = collections.defaultdict(lambda: dict(dur=[], call_ms=[], call_tok=[], sub=0, mine=0,
                                                  tot_sub=0.0, tot_cached=0.0, wins=0, secs=0.0,
                                                  bgshare=[]))
    recs_by_cfg = collections.defaultdict(list)
    for (cfg, rnd), (t0, t1) in sorted(runs.items()):
        tag = "%s-r%d" % (cfg, rnd)
        recs = read_jsonl(os.path.join(a.records_dir, tag + ".jsonl"))
        calls = read_jsonl(os.path.join(a.calls_dir, tag, "calls.jsonl"))
        d = by_cfg[cfg]
        d["dur"].extend(r["duration_ms"] for r in recs if isinstance(r.get("duration_ms"), (int, float)))
        d["call_ms"].extend(c["ms"] for c in calls)
        d["call_tok"].extend(c["prompt_tokens"] for c in calls)
        d["mine"] += sum(c["prompt_tokens"] for c in calls)
        d["wins"] += 1
        d["secs"] += (t1 - t0)
        ds = delta(poll, t0, t1 + 3, "vllm:prompt_tokens_total")
        dc = delta(poll, t0, t1 + 3, "vllm:prompt_tokens_cached_total")
        if ds:
            d["tot_sub"] += ds
            d["tot_cached"] += dc if dc is not None else 0.0
        recs_by_cfg[cfg].append((tag, recs))

    hdr = ("%-9s %4s %7s %8s %8s %8s | %8s %8s | %10s %10s | %7s %7s %7s" %
           ("config", "n", "reqs", "p50_ms", "p90_ms", "mean_ms", "call_p50", "call_p90",
            "my_prompt", "my_tok/req", "win_hit", "bg_est", "my_hit"))
    print(hdr)
    print("-" * len(hdr))
    rows = {}
    for cfg, d in sorted(by_cfg.items(), key=lambda kv: kv[0]):
        n = len(d["dur"])
        win_hit = d["tot_cached"] / d["tot_sub"] if d["tot_sub"] else float("nan")
        bg_tok = d["tot_sub"] - d["mine"]
        my_cached = d["tot_cached"] - bg * bg_tok if bg == bg else float("nan")
        my_hit = my_cached / d["mine"] if d["mine"] else float("nan")
        rows[cfg] = dict(p50=pct(d["dur"], 50), mean=st.mean(d["dur"]) if d["dur"] else 0,
                         my_tok=d["mine"] / max(1, len(d["dur"])), my_hit=my_hit, win_hit=win_hit,
                         call_p50=pct(d["call_ms"], 50), n=n)
        print("%-9s %4d %7d %8.0f %8.0f %8.0f | %8.0f %8.0f | %10d %10.0f | %6.2f%% %6.2f%% %6.2f%%" %
              (cfg, d["wins"], n, pct(d["dur"], 50), pct(d["dur"], 90), st.mean(d["dur"]) if d["dur"] else 0,
               pct(d["call_ms"], 50), pct(d["call_ms"], 90), d["mine"], d["mine"] / max(1, n),
               100 * win_hit, 100 * bg, 100 * my_hit))
    print()
    if "base" in rows:
        b = rows["base"]
        print("relative to base (p50 shim latency / upstream tokens submitted per request):")
        for cfg, r in sorted(rows.items()):
            print("  %-9s p50 %+7.1f%%   mean %+7.1f%%   upstream tokens %+7.1f%%   my_hit %6.2f%%"
                  % (cfg, 100 * (r["p50"] / b["p50"] - 1), 100 * (r["mean"] / b["mean"] - 1),
                     100 * (r["my_tok"] / b["my_tok"] - 1), 100 * r["my_hit"]))
    print()

    # ---- decision agreement ---------------------------------------------------------
    print("DECISION AGREEMENT (key = case_id/event_index/context/instruction/question)")
    def index(recs):
        return {(r["case_id"], r["event_index"], r["context_variant"], r["instruction_variant"],
                 r["question_variant"]): r for r in recs}
    base_runs = dict(recs_by_cfg.get("base", []))
    if not base_runs:
        print("  no base run")
        return
    ref_tag = sorted(base_runs)[0]
    ref = index(base_runs[ref_tag])
    print("  reference: %s (n=%d)" % (ref_tag, len(ref)))
    for cfg in sorted(recs_by_cfg):
        for tag, recs in sorted(recs_by_cfg[cfg]):
            if tag == ref_tag:
                continue
            other = index(recs)
            keys = set(ref) & set(other)
            act = sum(1 for k in keys if ref[k]["action"] != other[k]["action"])
            det = sum(1 for k in keys if ref[k]["detected"] != other[k]["detected"])
            disp = sum(1 for k in keys
                       if ref[k]["answers"].get("disposition") != other[k]["answers"].get("disposition"))
            ans = sum(1 for k in keys if ref[k]["answers"] != other[k]["answers"])
            maxp = 0.0
            drisk = []
            dnoul = []
            for k in keys:
                pa, pb = ref[k]["probabilities"], other[k]["probabilities"]
                for kk in set(pa) | set(pb):
                    maxp = max(maxp, abs(pa.get(kk, 0.0) - pb.get(kk, 0.0)))
                for name, acc in (("risk", drisk), ("context_sufficient", dnoul)):
                    va, vb = ref[k]["answers"].get(name), other[k]["answers"].get(name)
                    if isinstance(va, (int, float)) and isinstance(vb, (int, float)):
                        acc.append(abs(va - vb))
            print("  %-14s n=%3d  action_diff=%2d  detected_diff=%2d  disposition_diff=%2d  any_float_diff=%2d  "
                  "max|dprob|=%.4f  max|drisk|=%.4f  max|dnoul|=%.4f"
                  % (tag, len(keys), act, det, disp, ans, maxp,
                     max(drisk) if drisk else 0.0, max(dnoul) if dnoul else 0.0))


if __name__ == "__main__":
    main()
