#!/usr/bin/env python3
"""DefenseClaw per-call latency on the same 800-event sample as the competitors, from a harness run over the sample's cases.

  # 1) run the harness on the sample's cases, one process, one worker, on the same cores as latency.py:
  taskset -c 32-63 python3 -I ~/s7c/s7gate.py all --bin BIN --policy-dir POL --corpora corpora_compare_lat.json --out ~/s7c/gate/LABEL \
      --gomaxprocs 8 --workers 1 --parallel 1 --connector auto --packs default
  # 2) summarise:
  python3 dc_latency.py --gate ~/s7c/gate/LABEL --sample ~/s7c/compare/latency-sample.jsonl --name defenseclaw-rules --out ~/s7c/compare/latency

lat_us is the harness's time for one hook call (request in, verdict out, through the connector's real hook handler). Run the harness
with -session-start-arrival-ms 1: live, SessionStart arrives before the first tool call, so the first call of a session does not
wait for it (the harness default waits up to 1 s, which is a benchmark artefact). Throughput: events per second of the harness
with --parallel 8 --workers 4 on the same cores (pass --throughput-gate for that run).
"""
import argparse, glob, json, os


def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))] if xs else None


def rows_of(gate, pack="default"):
    out = {}
    for f in glob.glob(os.path.join(gate, "decisions", "*", f"*-{pack}*.jsonl")):
        if os.path.basename(f).startswith("ids."):
            continue
        for l in open(f):
            r = json.loads(l)
            out[(r["case"], r.get("idx", 0))] = r
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gate", required=True); ap.add_argument("--sample", required=True); ap.add_argument("--name", required=True)
    ap.add_argument("--out", required=True); ap.add_argument("--throughput-gate", default=""); ap.add_argument("--note", default="")
    a = ap.parse_args()
    rows = rows_of(a.gate)
    lat = {}
    for l in open(a.sample):
        s = json.loads(l)
        r = rows.get((s["case"], s["idx"]))
        if r is None:
            continue
        if not r.get("lat_us"):
            continue   # the prompt surface (proxy inspector) records no lat_us: not measured here
        ms = r["lat_us"] / 1000.0
        lat.setdefault(s["ev"]["kind"], []).append(ms); lat.setdefault("all", []).append(ms)
    single = {k: dict(n=len(v), p50=pct(v, .5), p95=pct(v, .95), p99=pct(v, .99), mean=sum(v) / len(v)) for k, v in lat.items()}
    thr = None
    if a.throughput_gate:
        run = json.load(open(os.path.join(a.throughput_gate, "RUN.json")))
        tr = rows_of(a.throughput_gate)
        secs = run.get("elapsed_s") or run.get("seconds")
        thr = dict(events=len(tr), seconds=secs, events_per_s=(len(tr) / secs) if secs else None, note="harness wall time for the whole run")
    run = json.load(open(os.path.join(a.gate, "RUN.json")))
    res = dict(name=a.name, single_stream_ms=single, throughput=thr, sample=a.sample, version=dict(bin=run.get("bin"), code=run.get("code"), harness_args=run.get("harness_args")),
               host=dict(cpu_model="Intel Xeon (c7i.16xlarge), 32 vCPUs pinned"), note=a.note or "lat_us of the harness hook call; prompt-surface rows carry no lat_us")
    os.makedirs(a.out, exist_ok=True)
    json.dump(res, open(os.path.join(a.out, a.name + ".json"), "w"), indent=1)
    print(json.dumps(dict(name=a.name, single=single.get("all"), kinds={k: v["p50"] for k, v in single.items()})))


if __name__ == "__main__":
    main()
