#!/usr/bin/env python3
"""Second pass: run the remaining hosted-Jev parity-gap arms derived from enumerate_gaps.py.

Waits for the first driver's screen session to exit so only one arm ever hits the shared
hosted API at a time (concurrency 8 total, as instructed).

No budget cap: the caller lifted it. Per-arm --max-usd is set deliberately loose so it
cannot bind on a normal run; it only catches a pathological runaway. Cumulative spend is
recorded after EVERY arm and a check-in threshold is reported (not enforced as a stop)
at $25.00.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path

DATA = Path("$WORK/.system-one-data/outputs")
LAUNCHER = "$WORK/jev-arm2.sh"
LEDGER = DATA / "jev-run-ledger-2.json"
CHECK_IN = 25.00

# name, cases, output, ctx, ins, qst, questions-config, max_usd (loose runaway guard),
# max_calls, run_id, projected_usd
ARMS = [
    # 1. label-corpus instruction arms - completes the I1/I2/I3 comparison
    ("toolcall-labels/jev-q4-C7-I1", DATA / "toolcall-labels/cases.jsonl",
     DATA / "toolcall-labels/jev-q4-C7-I1.jsonl",
     "C7", "I1", "Q4", "questions-v2.json", 6.0, 15000, "toolcall-labels-jev-q4-C7-I1", 0.36),
    ("toolcall-labels/jev-q4-C7-I2", DATA / "toolcall-labels/cases.jsonl",
     DATA / "toolcall-labels/jev-q4-C7-I2.jsonl",
     "C7", "I2", "Q4", "questions-v2.json", 6.0, 15000, "toolcall-labels-jev-q4-C7-I2", 0.42),
    ("toolcall-labels/jev-q4-C0-I1", DATA / "toolcall-labels/cases.jsonl",
     DATA / "toolcall-labels/jev-q4-C0-I1.jsonl",
     "C0", "I1", "Q4", "questions-v2.json", 6.0, 15000, "toolcall-labels-jev-q4-C0-I1", 0.36),
    ("toolcall-labels/jev-q4-C0-I2", DATA / "toolcall-labels/cases.jsonl",
     DATA / "toolcall-labels/jev-q4-C0-I2.jsonl",
     "C0", "I2", "Q4", "questions-v2.json", 6.0, 15000, "toolcall-labels-jev-q4-C0-I2", 0.42),
    # 2. Broad comparison Q1 - completes the question grid at s2 scale
    ("s2/jev-q1-C7", DATA / "s2/cases.jsonl", DATA / "s2/jev-q1-C7.jsonl",
     "C7", "I3", "Q1", "questions-v1.json", 12.0, 45000, "s2-jev-q1-C7", 3.40),
    # 3. Intent (large)
    ("intent-large/jev-C7", DATA / "intent-large/cases.jsonl", DATA / "intent-large/jev-C7.jsonl",
     "C7", "I3", "Q2", "questions-v1.json", 6.0, 16000, "intent-large-jev-C7", 0.32),
    # 4. TerminalBench Q2 / Q3 reference lane (s1-n1000 corpus)
    ("s1-n1000/tb-jev-q2", DATA / "s1-n1000/terminalbench-context-cases.jsonl",
     DATA / "s1-n1000/tb-jev-q2.jsonl",
     "C7", "I3", "Q2", "questions-v1.json", 3.0, 2500, "s1-tb-jev-q2", 0.09),
    ("s1-n1000/tb-jev-q3", DATA / "s1-n1000/terminalbench-context-cases.jsonl",
     DATA / "s1-n1000/tb-jev-q3.jsonl",
     "C7", "I3", "Q3", "questions-v1.json", 3.0, 2500, "s1-tb-jev-q3", 0.22),
]

PRIOR_LEDGERS = [DATA / "jev-run-ledger.json"]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def settled(pred: Path) -> dict:
    meta_path = Path(str(pred) + ".meta.json")
    if not meta_path.exists():
        raise RuntimeError(f"missing meta for {pred}")
    meta = json.loads(meta_path.read_text())
    if meta.get("complete") is not True:
        raise RuntimeError(f"{pred}: meta complete is not true")
    if sha256_file(pred) != meta.get("prediction_sha256"):
        raise RuntimeError(f"{pred}: sha256 mismatch against meta")
    return meta


def wait_for_first_driver() -> None:
    """Wait until pass 1 is finished.

    Matching on the screen name is unsafe here: this driver's own session is called
    `jev-drive2`, which contains `jev-drive` as a substring, so a substring test would wait
    on itself forever. Use pass 1's completion sentinel instead, and fall back to an exact
    session-name match.
    """
    log = DATA / "jev-drive.log"
    for _ in range(4320):  # up to 12h
        if log.exists() and "ALL DONE" in log.read_text():
            return
        out = subprocess.run(["screen", "-ls"], capture_output=True, text=True).stdout
        if not re.search(r"\d+\.jev-drive\s", out):
            return
        time.sleep(10)


def prior_cumulative() -> float:
    total = 0.0
    for path in PRIOR_LEDGERS:
        if path.exists():
            total += float(json.loads(path.read_text()).get("cumulative_usd", 0.0))
    return total


def main() -> int:
    print("waiting for the first driver to finish...", flush=True)
    wait_for_first_driver()
    time.sleep(5)
    cumulative = prior_cumulative()
    print(f"prior cumulative from pass 1: ${cumulative:.6f}", flush=True)
    ledger = {"pass": 2, "check_in_threshold_usd": CHECK_IN,
              "prior_cumulative_usd": round(cumulative, 6), "arms": []}

    for (name, cases, out, ctx, ins, qst, qcfg, cap, maxcalls, run_id, proj) in ARMS:
        if out.exists():
            try:
                meta = settled(out)
                cumulative += float(meta["estimated_usd"])
                print(f"SKIP {name}: already settled ${meta['estimated_usd']:.6f} "
                      f"cumulative ${cumulative:.6f}", flush=True)
                continue
            except RuntimeError:
                print(f"{name}: existing output not settled, re-running", flush=True)

        log = Path(str(out).removesuffix(".jsonl") + ".log")
        print(f"START {name} [{ctx}/{ins}/{qst}] projection ${proj:.2f} "
              f"cumulative ${cumulative:.4f}", flush=True)
        started = time.time()
        with log.open("w") as handle:
            proc = subprocess.run(
                [LAUNCHER, str(cases), str(out), ctx, ins, qst, qcfg, str(cap), str(maxcalls), run_id],
                stdout=handle, stderr=subprocess.STDOUT,
            )
        elapsed = round(time.time() - started, 1)
        if proc.returncode != 0:
            print(f"FAIL {name}: exit {proc.returncode}; see {log}", flush=True)
            ledger["failed"] = {"name": name, "returncode": proc.returncode, "log": str(log)}
            ledger["cumulative_usd"] = round(cumulative, 6)
            LEDGER.write_text(json.dumps(ledger, indent=2, sort_keys=True))
            return 1
        meta = settled(out)
        cumulative += float(meta["estimated_usd"])
        entry = {
            "name": name, "run_id": run_id, "grid": f"{ctx}/{ins}/{qst}",
            "questions_config": qcfg, "cases": meta["cases"], "requests": meta["requests"],
            "attempted_provider_calls": meta.get("attempted_provider_calls"),
            "actual_input_tokens": meta["actual_input_tokens"],
            "tokens_per_request": round(meta["actual_input_tokens"] / meta["requests"], 1),
            "estimated_usd": meta["estimated_usd"], "cumulative_usd": round(cumulative, 6),
            "projected_usd": proj, "elapsed_seconds": elapsed, "complete": True,
            "prediction_sha256": meta["prediction_sha256"],
        }
        ledger["arms"].append(entry)
        ledger["cumulative_usd"] = round(cumulative, 6)
        if cumulative > CHECK_IN:
            ledger["check_in_exceeded_after"] = name
        LEDGER.write_text(json.dumps(ledger, indent=2, sort_keys=True))
        print(f"DONE {name}: ${meta['estimated_usd']:.6f} ({meta['requests']} req, "
              f"{entry['tokens_per_request']} tok/req, {elapsed}s) cumulative ${cumulative:.6f}",
              flush=True)
        if cumulative > CHECK_IN:
            print(f"CHECK-IN: cumulative ${cumulative:.4f} exceeds ${CHECK_IN:.2f}; "
                  f"pausing for operator confirmation.", flush=True)
            return 0

    ledger["cumulative_usd"] = round(cumulative, 6)
    ledger["all_arms_complete"] = True
    LEDGER.write_text(json.dumps(ledger, indent=2, sort_keys=True))
    print(f"PASS 2 ALL DONE cumulative ${cumulative:.6f}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
