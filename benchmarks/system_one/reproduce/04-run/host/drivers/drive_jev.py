#!/usr/bin/env python3
"""Sequentially run the remaining hosted-Jev arms with a hard cumulative budget guard.

After every single arm this script:
  * verifies the meta reports complete: true
  * verifies the on-disk sha256 of the prediction file matches meta.prediction_sha256
  * adds meta.estimated_usd to the running total
  * refuses to start the next arm if (cumulative + next projection) would exceed HARD_STOP

Writes a ledger to $WORK/.system-one-data/outputs/jev-run-ledger.json after each arm.
Never prints the API key (it is only read inside the launcher shell script).
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

DATA = Path("$WORK/.system-one-data/outputs")
LAUNCHER = "$WORK/jev-arm2.sh"
LEDGER = DATA / "jev-run-ledger.json"
HARD_STOP = 19.00

# name, cases path, output path, ctx, ins, qst, questions-config, max_usd cap, max_calls,
# run_id, projected_usd (conservative: OpenJev tok/req at $0.04906/M)
ARMS = [
    ("toolcall-labels/jev-q4-C0", DATA / "toolcall-labels/cases.jsonl", DATA / "toolcall-labels/jev-q4-C0.jsonl",
     "C0", "I3", "Q4", "questions-v2.json", 1.30, 15000, "toolcall-labels-jev-q4-C0", 0.5206),
    ("toolcall-labels/jev-q4-C7", DATA / "toolcall-labels/cases.jsonl", DATA / "toolcall-labels/jev-q4-C7.jsonl",
     "C7", "I3", "Q4", "questions-v2.json", 1.30, 15000, "toolcall-labels-jev-q4-C7", 0.5181),
    ("intent-real/jev-q4-C0", DATA / "intent-real/cases.jsonl", DATA / "intent-real/jev-q4-C0.jsonl",
     "C0", "I3", "Q4", "questions-v2.json", 0.55, 6000, "intent-real-jev-q4-C0", 0.1677),
    ("intent-real/jev-q4-C7", DATA / "intent-real/cases.jsonl", DATA / "intent-real/jev-q4-C7.jsonl",
     "C7", "I3", "Q4", "questions-v2.json", 0.60, 6000, "intent-real-jev-q4-C7", 0.1859),
    ("terminalbench/jev-q4-C1", DATA / "s1-n1000/terminalbench-context-cases.jsonl",
     DATA / "terminalbench/jev-q4-C1.jsonl",
     "C1", "I3", "Q4", "questions-v2.json", 0.30, 2500, "terminalbench-jev-q4-C1", 0.0734),
    ("terminalbench/jev-q4-C7", DATA / "s1-n1000/terminalbench-context-cases.jsonl",
     DATA / "terminalbench/jev-q4-C7.jsonl",
     "C7", "I3", "Q4", "questions-v2.json", 0.70, 2500, "terminalbench-jev-q4-C7", 0.2152),
    ("intent-ablation/jev-C1", DATA / "intent-ablation/cases.jsonl", DATA / "intent-ablation/jev-C1.jsonl",
     "C1", "I3", "Q2", "questions-v1.json", 1.80, 26000, "intent-ablation-jev-C1", 0.7388),
    ("s3/jev-C7", DATA / "s3/cases.jsonl", DATA / "s3/jev-C7.jsonl",
     "C7", "I3", "Q2", "questions-v1.json", 9.00, 140000, "s3-jev-C7", 6.2545),
    # optional, in coordinator priority order
    ("intent-ablation/jev-q4-C1", DATA / "intent-ablation/cases.jsonl", DATA / "intent-ablation/jev-q4-C1.jsonl",
     "C1", "I3", "Q4", "questions-v2.json", 2.40, 26000, "intent-ablation-jev-q4-C1", 1.0183),
    ("s2/jev-q3-C7", DATA / "s2/cases.jsonl", DATA / "s2/jev-q3-C7.jsonl",
     "C7", "I3", "Q3", "questions-v1.json", 9.00, 45000, "s2-jev-q3-C7", 6.3182),
]

# already-spent arms whose metas are counted as the starting cumulative
PRIOR = [
    DATA / "s2/jev-smoke20.jsonl",
    DATA / "s2/jev-C7.jsonl",
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def settled(pred: Path) -> dict:
    """Return the meta only if the run is complete and the file on disk matches it."""
    meta_path = Path(str(pred) + ".meta.json")
    if not meta_path.exists():
        raise RuntimeError(f"missing meta for {pred}")
    meta = json.loads(meta_path.read_text())
    if meta.get("complete") is not True:
        raise RuntimeError(f"{pred}: meta complete is not true")
    actual = sha256_file(pred)
    if actual != meta.get("prediction_sha256"):
        raise RuntimeError(f"{pred}: sha256 mismatch on disk={actual} meta={meta.get('prediction_sha256')}")
    return meta


def main() -> int:
    ledger = {"hard_stop_usd": HARD_STOP, "arms": [], "cumulative_usd": 0.0}
    cumulative = 0.0
    for pred in PRIOR:
        meta = settled(pred)
        cumulative += float(meta["estimated_usd"])
        ledger["arms"].append({
            "name": str(pred.relative_to(DATA)).removesuffix(".jsonl"),
            "phase": "prior",
            "requests": meta["requests"],
            "actual_input_tokens": meta["actual_input_tokens"],
            "tokens_per_request": round(meta["actual_input_tokens"] / meta["requests"], 1),
            "estimated_usd": meta["estimated_usd"],
            "cumulative_usd": round(cumulative, 6),
            "contexts": meta["contexts"], "instructions": meta["instructions"], "questions": meta["questions"],
            "complete": True,
        })
    ledger["cumulative_usd"] = round(cumulative, 6)
    LEDGER.write_text(json.dumps(ledger, indent=2, sort_keys=True))
    print(f"starting cumulative ${cumulative:.6f}", flush=True)

    for (name, cases, out, ctx, ins, qst, qcfg, cap, maxcalls, run_id, proj) in ARMS:
        if out.exists() and Path(str(out) + ".meta.json").exists():
            try:
                meta = settled(out)
                cumulative += float(meta["estimated_usd"])
                print(f"SKIP {name}: already settled, ${meta['estimated_usd']:.6f}", flush=True)
                ledger["arms"].append({
                    "name": name, "phase": "pre-existing", "requests": meta["requests"],
                    "actual_input_tokens": meta["actual_input_tokens"],
                    "tokens_per_request": round(meta["actual_input_tokens"] / meta["requests"], 1),
                    "estimated_usd": meta["estimated_usd"], "cumulative_usd": round(cumulative, 6),
                    "contexts": meta["contexts"], "instructions": meta["instructions"],
                    "questions": meta["questions"], "complete": True,
                })
                ledger["cumulative_usd"] = round(cumulative, 6)
                LEDGER.write_text(json.dumps(ledger, indent=2, sort_keys=True))
                continue
            except RuntimeError:
                print(f"{name}: existing output not settled, re-running", flush=True)

        if cumulative + proj > HARD_STOP:
            print(f"STOP before {name}: cumulative ${cumulative:.4f} + projection ${proj:.4f} "
                  f"exceeds hard stop ${HARD_STOP:.2f}", flush=True)
            ledger["stopped_before"] = name
            ledger["stop_reason"] = (f"cumulative {cumulative:.6f} + projection {proj:.6f} > hard stop {HARD_STOP}")
            ledger["cumulative_usd"] = round(cumulative, 6)
            LEDGER.write_text(json.dumps(ledger, indent=2, sort_keys=True))
            return 0

        log = Path(str(out).removesuffix(".jsonl") + ".log")
        print(f"START {name} (cap ${cap}, projection ${proj:.4f}, cumulative ${cumulative:.4f})", flush=True)
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
            "name": name, "phase": "new", "run_id": run_id,
            "grid": f"{ctx}/{ins}/{qst}", "questions_config": qcfg,
            "cases": meta["cases"], "requests": meta["requests"],
            "attempted_provider_calls": meta.get("attempted_provider_calls"),
            "actual_input_tokens": meta["actual_input_tokens"],
            "tokens_per_request": round(meta["actual_input_tokens"] / meta["requests"], 1),
            "estimated_usd": meta["estimated_usd"], "cumulative_usd": round(cumulative, 6),
            "max_usd_cap": cap, "projected_usd": proj,
            "elapsed_seconds": elapsed, "complete": True,
            "prediction_sha256": meta["prediction_sha256"],
        }
        ledger["arms"].append(entry)
        ledger["cumulative_usd"] = round(cumulative, 6)
        LEDGER.write_text(json.dumps(ledger, indent=2, sort_keys=True))
        print(f"DONE {name}: ${meta['estimated_usd']:.6f} "
              f"({meta['requests']} req, {entry['tokens_per_request']} tok/req, {elapsed}s) "
              f"cumulative ${cumulative:.6f}", flush=True)

    ledger["cumulative_usd"] = round(cumulative, 6)
    ledger["all_arms_complete"] = True
    LEDGER.write_text(json.dumps(ledger, indent=2, sort_keys=True))
    print(f"ALL DONE cumulative ${cumulative:.6f}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
