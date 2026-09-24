#!/usr/bin/env python3
"""Fifth pass: spend the $5 refill on complete question sweeps.

Ordering and rationale:
  1-2. s2 Q0 and s2 Q4 (~$1.1 and ~$1.5). Jev already has Q1/Q2/Q3 at Broad-comparison scale,
       so these two complete a 5-of-5 question sweep on one model and one corpus. Question
       format is the largest single effect in the programme and no model has all five at this
       scale, so this is new ground rather than catch-up.
  3-5. intent-real Q0/Q1/Q3 (~$0.12 each). Jev has Q2 and Q4 there; three cheap arms complete a
       second 5-of-5 sweep on a corpus that HAS unsafe truth cases, so unlike the benign-only
       stages its block-lens numbers are meaningful.
  6-8. intent-ablation Q0/Q1/Q3 (~$0.55 each) completes a third 5-of-5 sweep.

DELIBERATELY NOT RUN: s3 Q1. Measured evidence, not a guess: Jev's s3 Q2 arm ran at 886.8
tok/req and its s2 Q1/Q2 token ratio was 1304.5/1010.5 = 1.29, so s3 Q1 projects to ~1,144
tok/req = 100,001 x 1144 x $0.042/1e6 = ~$4.81. That alone consumes essentially the whole
refill with no margin, and OpenJev has no s3 Q1 either so it buys no parity. Starting it would
risk a truncated 100k arm that looks complete.
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
LEDGER = DATA / "jev-run-ledger-5.json"
PRIOR_LEDGERS = [DATA / f"jev-run-ledger-{n}.json" for n in (2, 3, 4)] + [DATA / "jev-run-ledger.json"]

ARMS = [
    ("s2/jev-q0-C7", DATA / "s2/cases.jsonl", DATA / "s2/jev-q0-C7.jsonl",
     "C7", "I3", "Q0", "questions-v1.json", 12.0, 45000, "s2-jev-q0-C7", 1.08),
    ("s2/jev-q4-C7", DATA / "s2/cases.jsonl", DATA / "s2/jev-q4-C7.jsonl",
     "C7", "I3", "Q4", "questions-v2.json", 12.0, 45000, "s2-jev-q4-C7", 1.46),
    ("intent-real/jev-q0-C7", DATA / "intent-real/cases.jsonl", DATA / "intent-real/jev-q0-C7.jsonl",
     "C7", "I3", "Q0", "questions-v1.json", 2.0, 6000, "intent-real-jev-q0-C7", 0.12),
    ("intent-real/jev-q1-C7", DATA / "intent-real/cases.jsonl", DATA / "intent-real/jev-q1-C7.jsonl",
     "C7", "I3", "Q1", "questions-v1.json", 2.0, 6000, "intent-real-jev-q1-C7", 0.12),
    ("intent-real/jev-q3-C7", DATA / "intent-real/cases.jsonl", DATA / "intent-real/jev-q3-C7.jsonl",
     "C7", "I3", "Q3", "questions-v1.json", 2.0, 6000, "intent-real-jev-q3-C7", 0.12),
    ("intent-ablation/jev-q0-C1", DATA / "intent-ablation/cases.jsonl",
     DATA / "intent-ablation/jev-q0-C1.jsonl",
     "C1", "I3", "Q0", "questions-v1.json", 3.0, 26000, "intent-ablation-jev-q0-C1", 0.50),
    ("intent-ablation/jev-q1-C1", DATA / "intent-ablation/cases.jsonl",
     DATA / "intent-ablation/jev-q1-C1.jsonl",
     "C1", "I3", "Q1", "questions-v1.json", 3.0, 26000, "intent-ablation-jev-q1-C1", 0.60),
    ("intent-ablation/jev-q3-C1", DATA / "intent-ablation/cases.jsonl",
     DATA / "intent-ablation/jev-q3-C1.jsonl",
     "C1", "I3", "Q3", "questions-v1.json", 3.0, 26000, "intent-ablation-jev-q3-C1", 0.60),
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


def prior_cumulative() -> float:
    total = 0.0
    for path in PRIOR_LEDGERS:
        if path.exists():
            total = max(total, float(json.loads(path.read_text()).get("cumulative_usd", 0.0)))
    return total


def main() -> int:
    cumulative = prior_cumulative()
    print(f"prior cumulative across ledgers: ${cumulative:.6f}", flush=True)
    ledger = {"pass": 5, "purpose": "spend the $5 refill on complete question sweeps",
              "deliberately_not_run": {
                  "arm": "s3 C7/I3/Q1",
                  "reason": ("projects to ~$4.81 from measured token rates (s3 Q2 at 886.8 tok/req "
                             "x the observed s2 Q1/Q2 ratio of 1.29), which consumes the whole "
                             "refill with no margin; OpenJev has no s3 Q1 either so it buys no "
                             "parity, and a truncated 100k arm that looks complete is worse than "
                             "no arm")},
              "prior_cumulative_usd": round(cumulative, 6), "arms": []}

    for (name, cases, out, ctx, ins, qst, qcfg, cap, maxcalls, run_id, proj) in ARMS:
        if out.exists():
            try:
                meta = settled(out)
                cumulative += float(meta["estimated_usd"])
                print(f"SKIP {name}: settled ${meta['estimated_usd']:.6f}", flush=True)
                continue
            except RuntimeError:
                pass
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
        try:
            meta = settled(out)
        except (RuntimeError, FileNotFoundError) as exc:
            entry["complete"] = False
            entry["settled_error"] = str(exc)
            entry["error_census"] = error_census(out)
            entry["log_tail"] = log.read_text().strip().splitlines()[-20:] if log.exists() else []
            ledger["arms"].append(entry)
            ledger["cumulative_usd"] = round(cumulative, 6)
            ledger["stopped_at"] = name
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
            "cases": meta["cases"], "requests": meta["requests"],
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
    print(f"PASS 5 ALL DONE cumulative ${cumulative:.6f}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
