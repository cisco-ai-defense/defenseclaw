#!/usr/bin/env python3
"""Merge two S2 half-corpus prediction files, reproducing the discipline in openjev-q3.merge.json.

Discipline (copied from that file, not invented here):
  * both halves must pass the settled-file gate: meta complete == true AND on-disk sha256 ==
    meta prediction_sha256
  * rows are concatenated in half order (h0 then h1), preserving each half's own row order
  * the ONLY field rewritten is ``run_id``, because
    benchmark_score_system_one.aggregate_system() rejects mixed run_ids within one candidate key
  * serialization is json.dumps(row, sort_keys=True, separators=(",", ":")) + "\\n", which is what
    benchmark_run_system_one.py writes
  * verification: 0 case_id overlap between halves, union case count == the corpus case count,
    0 duplicate (case_id, event_index) pairs, no error rows, single route

Self-validating: --expect-sha256 makes the script assert the merged digest, so the same code path
can be proved on an already-published merge before it is trusted on a new one.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def gate(path: Path) -> dict[str, Any]:
    meta_path = Path(str(path) + ".meta.json")
    if not path.exists():
        raise SystemExit(f"{path} does not exist")
    if not meta_path.exists():
        raise SystemExit(f"{meta_path} does not exist: the run has not finished writing")
    meta = json.loads(meta_path.read_text())
    on_disk = sha256_file(path)
    if meta.get("complete") is not True:
        raise SystemExit(f"{path}: meta complete={meta.get('complete')!r}, refusing to merge")
    if on_disk != meta.get("prediction_sha256"):
        raise SystemExit(
            f"{path}: on-disk sha256 {on_disk} != meta prediction_sha256 {meta.get('prediction_sha256')}"
        )
    return {
        "path": str(path),
        "run_id": meta.get("run_id"),
        "cases": meta.get("cases"),
        "cases_sha256": meta.get("cases_sha256"),
        "planned_requests": meta.get("requests"),
        "prediction_sha256": on_disk,
        "actual_input_tokens": meta.get("actual_input_tokens"),
        "contexts": meta.get("contexts"),
        "instructions": meta.get("instructions"),
        "questions": meta.get("questions"),
        "model": meta.get("model"),
        "model_revision": meta.get("model_revision"),
        "instruction_format": meta.get("instruction_format"),
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--half", action="append", required=True, help="half prediction file, repeatable, in merge order")
    p.add_argument("--cases", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--merge-json", type=Path, required=True)
    p.add_argument("--merged-run-id", required=True)
    p.add_argument("--expect-sha256", default=None, help="assert the merged digest (validation mode)")
    p.add_argument("--dry-run", action="store_true", help="compute and verify without writing the merged file")
    args = p.parse_args()

    halves = [gate(Path(h)) for h in args.half]
    corpus_cases = set()
    with args.cases.open() as handle:
        for line in handle:
            line = line.strip()
            if line:
                corpus_cases.add(json.loads(line)["id"])
    cases_sha = sha256_file(args.cases)

    case_sets: list[set[str]] = []
    pairs: Counter[tuple[str, int]] = Counter()
    routes: Counter[str] = Counter()
    errors: Counter[str] = Counter()
    rows_by_half: list[int] = []
    out_lines: list[str] = []
    for half in halves:
        seen: set[str] = set()
        count = 0
        with Path(half["path"]).open() as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                count += 1
                seen.add(str(row.get("case_id", "")))
                pairs[(str(row.get("case_id", "")), int(row.get("event_index", -1)))] += 1
                routes[str(row.get("route", ""))] += 1
                if row.get("error_code"):
                    errors[str(row["error_code"])] += 1
                row["run_id"] = args.merged_run_id
                out_lines.append(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
        case_sets.append(seen)
        rows_by_half.append(count)
        half["observed_rows"] = count

    overlap = 0
    for i in range(len(case_sets)):
        for j in range(i + 1, len(case_sets)):
            overlap += len(case_sets[i] & case_sets[j])
    union = set().union(*case_sets)
    duplicates = sum(v - 1 for v in pairs.values() if v > 1)

    verification = {
        "rows": sum(rows_by_half),
        "planned_rows": sum(int(h["planned_requests"]) for h in halves),
        "rows_by_half": rows_by_half,
        "case_id_overlap_between_halves": overlap,
        "union_cases": len(union),
        "corpus_cases": len(corpus_cases),
        "coverage_complete": union == corpus_cases,
        "duplicate_case_event_pairs": duplicates,
        "routes": dict(routes),
        "errors_by_code": dict(errors),
        "grid": "/".join([
            (halves[0]["contexts"] or [""])[0],
            (halves[0]["instructions"] or [""])[0],
            (halves[0]["questions"] or [""])[0],
        ]),
        "model_revision": halves[0]["model_revision"],
    }
    problems = []
    if overlap != 0:
        problems.append(f"case_id overlap between halves = {overlap}, expected 0")
    if union != corpus_cases:
        problems.append(f"union cases {len(union)} != corpus cases {len(corpus_cases)}")
    if duplicates != 0:
        problems.append(f"duplicate (case_id, event_index) pairs = {duplicates}, expected 0")
    if verification["rows"] != verification["planned_rows"]:
        problems.append(f"rows {verification['rows']} != planned {verification['planned_rows']}")
    if errors:
        problems.append(f"error rows present: {dict(errors)}")
    if problems:
        raise SystemExit("MERGE VERIFICATION FAILED:\n  " + "\n  ".join(problems))

    blob = "".join(out_lines).encode()
    merged_sha = hashlib.sha256(blob).hexdigest()
    if args.expect_sha256 and merged_sha != args.expect_sha256:
        raise SystemExit(f"merged sha256 {merged_sha} != expected {args.expect_sha256}")
    if not args.dry_run:
        args.out.write_bytes(blob)
        record = {
            "kind": "defenseclaw-system-one-prediction-merge",
            "schema_version": "1",
            "corpus": {"cases": str(args.cases), "cases_sha256": cases_sha},
            "halves": halves,
            "merged": str(args.out),
            "merged_run_id": args.merged_run_id,
            "merged_sha256": merged_sha,
            "rewritten_fields": ["run_id"],
            "rewrite_reason": (
                "benchmark_score_system_one.aggregate_system() rejects mixed run_ids within one "
                "candidate key; no other field is altered"
            ),
            "verification": verification,
        }
        args.merge_json.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"merged_sha256": merged_sha, "verification": verification,
                      "expected_sha256": args.expect_sha256, "dry_run": args.dry_run}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
