#!/usr/bin/env python3
"""Third pass: the last remaining hosted-Jev parity-gap arms.

Ordering rationale (highest comparability per dollar, but cheap-and-certain first):
  1-3. three trivial smoke arms (~$0.01 total) that close the literal grid; they cannot
       starve anything else.
  4.   s3 C7/I3/Q3 - the single most valuable remaining cell. DiffusionGemma has a published
       Q3 arm at Production-weighted scale while OpenJev only has Q2, which is exactly the
       confound this work exists to remove. It is also the most expensive (~$4.9), so it runs
       last and is RESUMABLE: benchmark_run_system_one.py --resume can finish it after a
       credit refill, so an out-of-credit stop part-way is recoverable, not wasted.

No cost cap. Cumulative spend is recorded after every arm. If the provider returns an
out-of-credit style failure the runner marks rows with error_code and the meta will not be
complete: true, which this driver reports rather than papering over.
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
LEDGER = DATA / "jev-run-ledger-3.json"
PRIOR_LEDGERS = [DATA / "jev-run-ledger.json", DATA / "jev-run-ledger-2.json"]

ARMS = [
    ("s1-n1000/jev-smoke", DATA / "s1-n1000/openjev-smoke-cases.jsonl",
     DATA / "s1-n1000/jev-smoke.jsonl",
     "C0", "I0", "Q0", "questions-v1.json", 1.0, 400, "s1-smoke-jev", 0.004),
    ("toolcall-labels/jev-q4-smoke-C0", DATA / "toolcall-labels/cases-smoke20.jsonl",
     DATA / "toolcall-labels/jev-q4-smoke-C0.jsonl",
     "C0", "I3", "Q4", "questions-v2.json", 1.0, 200, "toolcall-labels-jev-q4-smoke-C0", 0.002),
    ("toolcall-labels/jev-q4-smoke-C7", DATA / "toolcall-labels/cases-smoke20.jsonl",
     DATA / "toolcall-labels/jev-q4-smoke-C7.jsonl",
     "C7", "I3", "Q4", "questions-v2.json", 1.0, 200, "toolcall-labels-jev-q4-smoke-C7", 0.002),
    ("s3/jev-q3-C7", DATA / "s3/cases.jsonl", DATA / "s3/jev-q3-C7.jsonl",
     "C7", "I3", "Q3", "questions-v1.json", 20.0, 140000, "s3-jev-q3-C7", 4.86),
]


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


def wait_for(sentinel_log: Path, session_re: str) -> None:
    for _ in range(4320):
        if sentinel_log.exists():
            text = sentinel_log.read_text()
            if "ALL DONE" in text or "CHECK-IN" in text or "FAIL " in text:
                return
        out = subprocess.run(["screen", "-ls"], capture_output=True, text=True).stdout
        if not re.search(session_re, out):
            return
        time.sleep(10)


def prior_cumulative() -> float:
    total = 0.0
    for path in PRIOR_LEDGERS:
        if path.exists():
            data = json.loads(path.read_text())
            # ledger 2 already folds in ledger 1's total
            total = max(total, float(data.get("cumulative_usd", 0.0)))
    return total


def error_census(pred: Path) -> dict:
    counts: dict[str, int] = {}
    with pred.open() as handle:
        for line in handle:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                counts["unparseable_line"] = counts.get("unparseable_line", 0) + 1
                continue
            code = row.get("error_code") or "none"
            counts[code] = counts.get(code, 0) + 1
    return counts


def main() -> int:
    print("waiting for pass 2...", flush=True)
    wait_for(DATA / "jev-drive2.log", r"\d+\.jevd2\s")
    time.sleep(5)
    cumulative = prior_cumulative()
    print(f"prior cumulative: ${cumulative:.6f}", flush=True)
    ledger = {"pass": 3, "prior_cumulative_usd": round(cumulative, 6), "arms": []}

    for (name, cases, out, ctx, ins, qst, qcfg, cap, maxcalls, run_id, proj) in ARMS:
        if out.exists():
            try:
                meta = settled(out)
                cumulative += float(meta["estimated_usd"])
                print(f"SKIP {name}: settled ${meta['estimated_usd']:.6f} "
                      f"cumulative ${cumulative:.6f}", flush=True)
                continue
            except RuntimeError:
                print(f"{name}: present but not settled, re-running", flush=True)

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
        entry = {"name": name, "run_id": run_id, "grid": f"{ctx}/{ins}/{qst}",
                 "projected_usd": proj, "elapsed_seconds": elapsed,
                 "launcher_returncode": proc.returncode}
        if proc.returncode != 0:
            entry["complete"] = False
            entry["log_tail"] = log.read_text().strip().splitlines()[-12:]
            if out.exists():
                entry["error_census"] = error_census(out)
                entry["rows_written"] = sum(1 for _ in out.open())
            entry["resume_hint"] = (
                "re-run the same command with --resume once credit is restored; "
                "benchmark_run_system_one.py will keep the rows already written")
            ledger["arms"].append(entry)
            ledger["cumulative_usd"] = round(cumulative, 6)
            ledger["stopped_at"] = name
            LEDGER.write_text(json.dumps(ledger, indent=2, sort_keys=True))
            print(f"STOPPED at {name}: launcher exit {proc.returncode}", flush=True)
            for line in entry.get("log_tail", []):
                print(f"   {line}", flush=True)
            return 1
        try:
            meta = settled(out)
        except RuntimeError as exc:
            entry["complete"] = False
            entry["settled_error"] = str(exc)
            entry["error_census"] = error_census(out) if out.exists() else None
            ledger["arms"].append(entry)
            ledger["cumulative_usd"] = round(cumulative, 6)
            ledger["stopped_at"] = name
            LEDGER.write_text(json.dumps(ledger, indent=2, sort_keys=True))
            print(f"STOPPED at {name}: {exc}", flush=True)
            return 1
        cumulative += float(meta["estimated_usd"])
        entry.update({
            "cases": meta["cases"], "requests": meta["requests"],
            "attempted_provider_calls": meta.get("attempted_provider_calls"),
            "actual_input_tokens": meta["actual_input_tokens"],
            "tokens_per_request": round(meta["actual_input_tokens"] / meta["requests"], 1),
            "estimated_usd": meta["estimated_usd"], "cumulative_usd": round(cumulative, 6),
            "complete": True, "prediction_sha256": meta["prediction_sha256"],
            "error_census": error_census(out),
        })
        ledger["arms"].append(entry)
        ledger["cumulative_usd"] = round(cumulative, 6)
        LEDGER.write_text(json.dumps(ledger, indent=2, sort_keys=True))
        print(f"DONE {name}: ${meta['estimated_usd']:.6f} ({meta['requests']} req, "
              f"{entry['tokens_per_request']} tok/req, {elapsed}s) cumulative ${cumulative:.6f}",
              flush=True)

    ledger["cumulative_usd"] = round(cumulative, 6)
    ledger["all_arms_complete"] = True
    LEDGER.write_text(json.dumps(ledger, indent=2, sort_keys=True))
    print(f"PASS 3 ALL DONE cumulative ${cumulative:.6f}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
