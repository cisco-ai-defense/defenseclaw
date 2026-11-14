#!/usr/bin/env python3
"""Test for dc_latency.py (s7-benchfix3): a prompt-surface row with a lat_us is counted, one with none is skipped and reported, never read as 0 ms.
  python3 -I test_dc_latency.py     exit 0 = pass. Synthetic rows only."""
import json, os, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
with tempfile.TemporaryDirectory() as d:
    gate = os.path.join(d, "gate"); os.makedirs(os.path.join(gate, "decisions", "c"))
    rows = [{"case": "p1", "idx": 0, "lat_us": 2_000_000}, {"case": "p2", "idx": 0, "lat_us": 0}, {"case": "t1", "idx": 1, "lat_us": 6_000}]
    with open(os.path.join(gate, "decisions", "c", "alice-default.jsonl"), "w") as f:
        for r in rows: f.write(json.dumps(r) + "\n")
    json.dump({"bin": "b", "code_commit": "c" * 40, "host": "box1", "build": {"bin_sha256": "x"}, "harness_args": ""}, open(os.path.join(gate, "RUN.json"), "w"))
    sample = os.path.join(d, "sample.jsonl")
    with open(sample, "w") as f:
        for c, i in (("p1", 0), ("p2", 0), ("t1", 1)): f.write(json.dumps({"case": c, "idx": i, "ev": {"kind": "prompt" if c[0] == "p" else "shell"}}) + "\n")
    out = os.path.join(d, "out")
    r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "dc_latency.py"), "--gate", gate, "--sample", sample, "--name", "t", "--out", out], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    res = json.load(open(os.path.join(out, "t.json")))
    assert res["single_stream_ms"]["prompt"]["n"] == 1 and res["single_stream_ms"]["prompt"]["p50"] == 2000.0, res
    assert res["single_stream_ms"]["all"]["n"] == 2 and res["rows_untimed"] == 1, res
    assert res["version"]["code"] == "c" * 40 and res["host"]["name"] == "box1" , res
    assert "carry no lat_us" not in res["note"] and "rows_untimed" in res["note"], res["note"]
print("ALL PASS")
