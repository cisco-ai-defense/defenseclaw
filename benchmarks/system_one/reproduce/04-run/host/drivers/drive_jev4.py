#!/usr/bin/env python3
"""Fourth pass: burn the residual credit on the one measurement that still gains from it.

After pass 3's s3 C7/I3/Q3 arm the enumerated parity gap set is empty: every
(stage, context, instruction, question) combination for which OpenJev or DiffusionGemma has a
completed arm now has a hosted-Jev arm. So no further arm buys cross-model comparability.

What does still gain: Jev is the only one of the three models that is NOT deterministic
(OpenJev flips 0/1519 across three repeat runs, Jev flips 21/1519 and 21/152 of the decisions
it flags). That flagged-only instability estimate rests on just 152 flagged decisions, so extra
repeat runs sharpen the single figure that is uniquely Jev's weakness. Each run is 1,519
requests / ~$0.065 / ~65 s, so an out-of-credit stop wastes almost nothing - which is the right
risk profile for spending down to zero.

Runs repeats until the provider stops answering, then records the exact failure.
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
LEDGER = DATA / "jev-run-ledger-4.json"
CASES = DATA / "s1-n1000/screen-cases.jsonl"  # sha a16ad66ebac4..., the repeat-stage corpus
PRIOR_LEDGERS = [DATA / "jev-run-ledger.json", DATA / "jev-run-ledger-2.json",
                 DATA / "jev-run-ledger-3.json"]
# extra repeat replicates, in order; each ~$0.065
REPLICATES = list(range(4, 17))


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


def error_census(pred: Path) -> dict:
    counts: dict[str, int] = {}
    if not pred.exists():
        return counts
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


def wait_for_pass3() -> None:
    log = DATA / "jev-drive3.log"
    for _ in range(8640):  # up to 24h
        if log.exists():
            text = log.read_text()
            if "ALL DONE" in text or "STOPPED" in text:
                return
        out = subprocess.run(["screen", "-ls"], capture_output=True, text=True).stdout
        if not re.search(r"\d+\.jevd3\s", out):
            return
        time.sleep(10)


def prior_cumulative() -> float:
    total = 0.0
    for path in PRIOR_LEDGERS:
        if path.exists():
            total = max(total, float(json.loads(path.read_text()).get("cumulative_usd", 0.0)))
    return total


def main() -> int:
    print("waiting for pass 3...", flush=True)
    wait_for_pass3()
    time.sleep(5)
    cumulative = prior_cumulative()
    print(f"prior cumulative: ${cumulative:.6f}", flush=True)
    ledger = {"pass": 4, "purpose": "sharpen Jev's repeat-run flip-rate estimate; spend to zero",
              "prior_cumulative_usd": round(cumulative, 6), "arms": []}

    if not CASES.exists():
        print(f"ABORT: {CASES} not found", flush=True)
        ledger["aborted"] = f"{CASES} not found"
        LEDGER.write_text(json.dumps(ledger, indent=2, sort_keys=True))
        return 1

    for index in REPLICATES:
        out = DATA / f"repeat/jev-r{index}.jsonl"
        name = f"repeat/jev-r{index}"
        if out.exists():
            try:
                meta = settled(out)
                cumulative += float(meta["estimated_usd"])
                print(f"SKIP {name}: settled ${meta['estimated_usd']:.6f}", flush=True)
                continue
            except RuntimeError:
                pass
        log = DATA / f"repeat/jev-r{index}.log"
        print(f"START {name} cumulative ${cumulative:.4f}", flush=True)
        started = time.time()
        with log.open("w") as handle:
            proc = subprocess.run(
                [LAUNCHER, str(CASES), str(out), "C7", "I3", "Q2", "questions-v1.json",
                 "1.0", "3000", f"repeat-jev-r{index}"],
                stdout=handle, stderr=subprocess.STDOUT,
            )
        elapsed = round(time.time() - started, 1)
        entry = {"name": name, "grid": "C7/I3/Q2", "elapsed_seconds": elapsed,
                 "launcher_returncode": proc.returncode}
        try:
            meta = settled(out)
        except (RuntimeError, FileNotFoundError) as exc:
            entry["complete"] = False
            entry["settled_error"] = str(exc)
            entry["error_census"] = error_census(out)
            entry["log_tail"] = (log.read_text().strip().splitlines()[-15:]
                                 if log.exists() else [])
            ledger["arms"].append(entry)
            ledger["cumulative_usd"] = round(cumulative, 6)
            ledger["credit_exhausted_at"] = name
            ledger["exhaustion_evidence"] = {
                "launcher_returncode": proc.returncode,
                "error_census": entry["error_census"],
                "log_tail": entry["log_tail"],
            }
            LEDGER.write_text(json.dumps(ledger, indent=2, sort_keys=True))
            print(f"STOPPED at {name}: {exc}", flush=True)
            print("error census: " + json.dumps(entry["error_census"]), flush=True)
            for line in entry["log_tail"]:
                print(f"   {line}", flush=True)
            return 0
        cumulative += float(meta["estimated_usd"])
        entry.update({
            "requests": meta["requests"], "actual_input_tokens": meta["actual_input_tokens"],
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
    ledger["all_replicates_complete"] = True
    LEDGER.write_text(json.dumps(ledger, indent=2, sort_keys=True))
    print(f"PASS 4 ALL DONE cumulative ${cumulative:.6f}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
