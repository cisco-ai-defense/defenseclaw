#!/usr/bin/env python3
"""Latency and cost of an API-backed check from its call log (llmshim.py JSONL, or the System One relay log), in the latency.py
result format, so export.py shows it next to the locally timed tools.

  python3 llm_latency.py --log alignmentcheck-maverick.jsonl --name llamafirewall-alignmentcheck --out ~/s7c/compare/latency \
      --note "Bedrock Llama 4 Maverick, us-east-1, from a c7i.16xlarge in the same region"

The latency is the API round trip as the adapter saw it (one call per tool call). Cost per 1,000 calls is the logged list-price
spend divided by the number of answered calls.
"""
import argparse, json, os


def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))] if xs else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", required=True); ap.add_argument("--name", required=True); ap.add_argument("--out", required=True); ap.add_argument("--note", default="")
    ap.add_argument("--ms-field", default="ms"); ap.add_argument("--usd-field", default="usd")
    a = ap.parse_args()
    rows = [json.loads(l) for l in open(a.log) if l.strip()]
    ok = [r for r in rows if not r.get("err") and r.get("status", 200) == 200]
    ms = [r[a.ms_field] for r in ok if r.get(a.ms_field) is not None]
    usd = sum(r.get(a.usd_field) or 0 for r in ok)
    tin = sum(r.get("in") or r.get("input_tokens") or 0 for r in ok); tout = sum(r.get("out") or 0 for r in ok)
    res = dict(name=a.name, single_stream_ms={"call": dict(n=len(ms), p50=pct(ms, .5), p95=pct(ms, .95), p99=pct(ms, .99), mean=sum(ms) / len(ms) if ms else None),
                                              "all": dict(n=len(ms), p50=pct(ms, .5), p95=pct(ms, .95), p99=pct(ms, .99), mean=sum(ms) / len(ms) if ms else None)},
               throughput=None, api=dict(calls=len(ok), failed=len(rows) - len(ok), usd=usd, usd_per_1k_calls=usd / len(ok) * 1000 if ok else None,
                                         input_tokens_per_call=tin / len(ok) if ok else None, output_tokens_per_call=tout / len(ok) if ok else None),
               host=dict(cpu_model="API: " + a.note), note=a.note, source=os.path.basename(a.log))
    os.makedirs(a.out, exist_ok=True)
    json.dump(res, open(os.path.join(a.out, a.name + ".json"), "w"), indent=1)
    print(json.dumps(dict(name=a.name, p50=res["single_stream_ms"]["all"]["p50"], api=res["api"])))


if __name__ == "__main__":
    main()
