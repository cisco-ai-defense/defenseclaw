"""Build S2/S3 stage corpora directly from the catalog.

benchmark_prepare_system_one.py needs exact per-(grade,surface,split) quotas, but the real
constraint here is simpler: after excluding S1's families only 5,486 families remain, so S2
takes everything available rather than hitting a quota. S3 is sized in *decisions* (the plan
says "cases/decisions"), which means the benign lane may draw many cases per family - that
lane measures noise and cost at volume, not family independence.

Modes:
  --mode s2   one case per family, all remaining development+validation families
  --mode s3   decision-scale: unsafe lanes family-deduplicated, benign lane row-sampled
              from untouched families until the decision target is met
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

try:
    from benchmark_inventory_system_one_sources import family_authority, read_jsonl, truth_grade
except ModuleNotFoundError:
    from benchmarks.scripts.benchmark_inventory_system_one_sources import (
        family_authority,
        read_jsonl,
        truth_grade,
    )

GRADE_RANK = {"A": 0, "B": 1, "C": 2, "D": 3}


def stable_key(seed: int, value: str) -> str:
    return hashlib.sha256(f"{seed}\0{value}".encode()).hexdigest()


def event_count(row: dict[str, Any]) -> int:
    payload = row.get("payload") if isinstance(row.get("payload"), dict) else {}
    events = payload.get("events") if isinstance(payload.get("events"), list) else [payload]
    return max(1, len(events))


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--catalog", type=Path, required=True)
    p.add_argument("--exclude-cases", action="append", type=Path, default=[])
    p.add_argument("--mode", choices=["s2", "s3"], required=True)
    p.add_argument("--splits", default="development,validation")
    p.add_argument("--decision-target", type=int, default=100000)
    p.add_argument("--seed", type=int, default=741983)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--manifest", type=Path, required=True)
    args = p.parse_args()

    excluded: set[str] = set()
    for path in args.exclude_cases:
        for row in read_jsonl(path):
            excluded.add(family_authority(row)[1])
    splits = {s.strip() for s in args.splits.split(",") if s.strip()}

    catalog = json.loads(args.catalog.read_text(encoding="utf-8"))
    # best row per family for the deduplicated lanes, plus a pool for the benign lane
    best: dict[str, tuple[str, dict[str, Any]]] = {}
    benign_pool: list[dict[str, Any]] = []
    for corpus in catalog["corpora"]:
        path = Path(corpus["path"])
        if not path.exists():
            continue
        for row in read_jsonl(path):
            grade = truth_grade(row)
            if grade == "E":
                continue
            split = str(row.get("split", "missing"))
            fam = family_authority(row)[1]
            if fam in excluded:
                continue
            if split in splits:
                prev = best.get(fam)
                if prev is None or GRADE_RANK[grade] < GRADE_RANK[prev[0]]:
                    best[fam] = (grade, row)
            if args.mode == "s3" and grade == "D":
                benign_pool.append(row)

    selected: list[dict[str, Any]] = [row for _, row in best.values()]
    selected.sort(key=lambda r: stable_key(args.seed, str(r["id"])))
    decisions = sum(event_count(r) for r in selected)

    added_benign = 0
    if args.mode == "s3" and decisions < args.decision_target:
        chosen_ids = {str(r["id"]) for r in selected}
        benign_pool.sort(key=lambda r: stable_key(args.seed, str(r["id"])))
        for row in benign_pool:
            if decisions >= args.decision_target:
                break
            rid = str(row["id"])
            if rid in chosen_ids:
                continue
            selected.append(row)
            chosen_ids.add(rid)
            decisions += event_count(row)
            added_benign += 1

    grade_counts: dict[str, int] = defaultdict(int)
    split_counts: dict[str, int] = defaultdict(int)
    for row in selected:
        grade_counts[truth_grade(row)] += 1
        split_counts[str(row.get("split", "missing"))] += 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        for row in selected:
            fh.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")

    manifest = {
        "schema_version": "1",
        "kind": "defenseclaw-system-one-stage-corpus",
        "mode": args.mode,
        "seed": args.seed,
        "splits": sorted(splits),
        "cases": len(selected),
        "decisions": decisions,
        "families": len({family_authority(r)[1] for r in selected}),
        "grades": dict(sorted(grade_counts.items())),
        "split_counts": dict(sorted(split_counts.items())),
        "excluded_families": len(excluded),
        "benign_rows_added_beyond_family_dedup": added_benign,
        "decision_target": args.decision_target if args.mode == "s3" else None,
        "note": (
            "S2/S3 downscaled from the original 8k+2k and 100k family targets: only 5,486 "
            "families remain after S1 exclusion. S3 is sized in decisions, with the benign "
            "lane permitted multiple cases per family."
        ),
    }
    args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: manifest[k] for k in ("mode", "cases", "decisions", "families", "grades")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
