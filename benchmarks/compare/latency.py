#!/usr/bin/env python3
"""Per-call latency and throughput of one competitor adapter on a fixed event sample, cache off, on the box it runs on.

  python3 latency.py --adapter adapters.llmguard [--opt k=v] --sample ~/s7c/compare/latency-sample.jsonl --out ~/s7c/compare/latency \
      [--threads 8] [--par 16] [--par-threads 4] [--seconds 60]
  python3 latency.py --make-sample --sets-dir ~/s7c/compare/sets --sample ~/s7c/compare/latency-sample.jsonl

The sample (--make-sample): 200 prompt events (prompt-agentdojo), 200 tool-output events (tool-result-agentdojo) and 400 tool-call
events (100 each from agentdojo, mcphunt, dtap and extra-public), holdout side, chosen by sha256(seed|case|idx), the same events for
every tool. Single stream: one process, --threads intra-op threads, 10 warm-up events, then every sample event once in order
(each event's scanners run back to back, as one inline guardrail call): p50 / p95 / p99 / mean per event kind. Throughput: --par
processes x --par-threads threads looping over the sample for --seconds, events per second for the whole box. Writes
<out>/<NAME>.json with the host (CPU model, vCPUs, GPU), the load average before and after, and the package versions.
"""
import argparse, hashlib, importlib, json, multiprocessing as mp, os, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import caseview  # noqa: E402
import run as RUN  # noqa: E402

SEED = "s7-compare-latency-2026-11-13"
PLAN = [("prompt-agentdojo", "prompt", 200), ("tool-result-agentdojo", "result", 200), ("agentdojo", "call", 100), ("mcphunt", "call", 100),
        ("dtap", "call", 100), ("extra-public", "call", 100)]


def make_sample(sets_dir, path):
    out = []
    for s, kind, n in PLAN:
        evs = []
        for l in open(os.path.join(sets_dir, f"{s}.holdout.cases.jsonl")):
            c = json.loads(l)
            for i, e in enumerate(caseview.events(c)):
                if e["kind"] == kind:
                    evs.append((hashlib.sha256(f"{SEED}|{c['id']}|{i}".encode()).hexdigest(), s, c["id"], i, e))
        evs.sort(key=lambda x: x[0])
        out += [dict(set=s, case=cid, idx=i, ev=e) for _, s, cid, i, e in evs[:n]]
    with open(path, "w") as f:
        for r in out:
            f.write(json.dumps(r) + "\n")
    print("sample", len(out), path)


def direct(scanner, payload, fn):
    t = time.perf_counter(); r = dict(fn()); r.setdefault("ms", (time.perf_counter() - t) * 1000); r.setdefault("applicable", True); r["cached"] = False
    return r


def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))] if xs else None


def _par_worker(adapter, opts, threads, sample, seconds, q):
    RUN.init_worker(adapter, opts, None, threads)
    RUN._A.cached = direct
    n = 0; t0 = time.time()
    while time.time() - t0 < seconds:
        for r in sample:
            RUN._A.scan(RUN._S, r["ev"]); n += 1
            if time.time() - t0 >= seconds:
                break
    q.put(n)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--adapter"); ap.add_argument("--opt", action="append", default=[])
    ap.add_argument("--sample", required=True); ap.add_argument("--out", default=os.path.expanduser("~/s7c/compare/latency"))
    ap.add_argument("--threads", type=int, default=8); ap.add_argument("--par", type=int, default=16); ap.add_argument("--par-threads", type=int, default=4)
    ap.add_argument("--seconds", type=int, default=60); ap.add_argument("--make-sample", action="store_true"); ap.add_argument("--sets-dir", default=os.path.expanduser("~/s7c/compare/sets"))
    ap.add_argument("--kinds", default="prompt,result,call", help="event kinds this tool scans (others are skipped, not timed)")
    ap.add_argument("--every", type=int, default=1, help="time every Nth sample event only (slow tools: the CPU Llama Guard note)")
    a = ap.parse_args()
    if a.make_sample:
        return make_sample(a.sets_dir, a.sample)
    opts = dict(o.split("=", 1) for o in a.opt)
    sample = [json.loads(l) for l in open(a.sample)]
    kinds = set(a.kinds.split(","))
    sample = [r for r in sample if r["ev"]["kind"] in kinds][::a.every]
    load0 = os.getloadavg()
    RUN.init_worker(a.adapter, opts, None, a.threads)
    RUN._A.cached = direct
    for r in sample[:10]:
        RUN._A.scan(RUN._S, r["ev"])
    lat = {}
    for r in sample:
        t = time.perf_counter(); sc = RUN._A.scan(RUN._S, r["ev"]); ms = (time.perf_counter() - t) * 1000
        if any(v.get("applicable", True) for v in sc.values()):
            lat.setdefault(r["ev"]["kind"], []).append(ms)
    single = {k: dict(n=len(v), p50=pct(v, .5), p95=pct(v, .95), p99=pct(v, .99), mean=sum(v) / len(v)) for k, v in lat.items()}
    allv = [x for v in lat.values() for x in v]
    single["all"] = dict(n=len(allv), p50=pct(allv, .5), p95=pct(allv, .95), p99=pct(allv, .99), mean=sum(allv) / len(allv) if allv else None)
    thr = None
    if a.par > 0 and a.seconds > 0:
        ctx = mp.get_context("spawn"); q = ctx.Queue()
        ps = [ctx.Process(target=_par_worker, args=(a.adapter, opts, a.par_threads, sample, a.seconds, q)) for _ in range(a.par)]
        for p in ps: p.start()
        n = sum(q.get() for _ in ps)
        for p in ps: p.join()
        thr = dict(processes=a.par, threads_each=a.par_threads, seconds=a.seconds, events=n, events_per_s=n / a.seconds)
    mod = importlib.import_module(a.adapter)
    name = mod.NAME + (("-" + opts["variant"]) if opts.get("variant") else "")
    res = dict(name=name, adapter=a.adapter, options=opts, host=RUN.host_info(), threads=a.threads, load_before=load0, load_after=os.getloadavg(),
               single_stream_ms=single, throughput=thr, version=mod.version(opts), sample=a.sample, sample_events=len(sample))
    os.makedirs(a.out, exist_ok=True)
    json.dump(res, open(os.path.join(a.out, name + ".json"), "w"), indent=1)
    print(json.dumps(dict(name=name, single=single.get("all"), throughput=thr)))


if __name__ == "__main__":
    main()
