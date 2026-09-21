from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

try:
    from benchmark_inventory_system_one_sources import family_id, read_jsonl, sha256_file, truth_grade
except ModuleNotFoundError:
    from benchmarks.scripts.benchmark_inventory_system_one_sources import (
        family_id,
        read_jsonl,
        sha256_file,
        truth_grade,
    )


def stable_rank(seed: int, case_id: str) -> str:
    return hashlib.sha256(f"{seed}\0{case_id}".encode()).hexdigest()


def parse_quota(value: str) -> tuple[tuple[str, str, str], int]:
    parts = value.rsplit(":", 3)
    if len(parts) != 4:
        raise ValueError(f"invalid quota {value!r}; expected GRADE:SURFACE:SPLIT:COUNT")
    grade, surface, split, raw_count = parts
    count = int(raw_count)
    if (
        grade not in {"A", "B", "C", "D", "E", "any"}
        or surface not in {"action", "stateful", "text", "e2e", "any"}
        or split not in {"development", "validation", "test", "smoke", "any"}
        or count < 0
    ):
        raise ValueError(f"invalid quota {value!r}")
    return (grade, surface, split), count


def row_keys(row: dict[str, Any]) -> set[tuple[str, str, str]]:
    grade = truth_grade(row)
    surface = str(row.get("surface", "missing"))
    split = str(row.get("split", "missing"))
    return {
        (grade, surface, split),
        (grade, "any", split),
        (grade, surface, "any"),
        (grade, "any", "any"),
        ("any", surface, split),
        ("any", "any", split),
        ("any", "any", "any"),
    }


def select_rows(
    rows: list[dict[str, Any]],
    quotas: dict[tuple[str, str, str], int],
    seed: int,
    excluded_ids: set[str],
    excluded_families: set[str],
    forbidden_datasets: set[str],
    allow_test: bool,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    buckets: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        case_id = str(row.get("id", ""))
        family = family_id(row)
        source = row.get("source") if isinstance(row.get("source"), dict) else {}
        dataset = str(source.get("dataset", ""))
        if not case_id or case_id in excluded_ids or family in excluded_families or dataset in forbidden_datasets:
            continue
        if row.get("split") == "test" and not allow_test:
            continue
        for key in row_keys(row):
            buckets[key].append(row)
    selected: list[dict[str, Any]] = []
    selected_ids: set[str] = set()
    selected_families: set[str] = set()
    available: dict[str, int] = {}
    for key, count in quotas.items():
        candidates = sorted(buckets.get(key, []), key=lambda item: stable_rank(seed, str(item.get("id", ""))))
        available[":".join(key)] = len(candidates)
        chosen = 0
        for row in candidates:
            case_id = str(row["id"])
            family = family_id(row)
            if case_id in selected_ids or family in selected_families:
                continue
            selected.append(row)
            selected_ids.add(case_id)
            selected_families.add(family)
            chosen += 1
            if chosen == count:
                break
        if chosen != count:
            raise ValueError(f"quota {':'.join(key)} requested {count}, selected {chosen}, available {len(candidates)}")
    selected.sort(key=lambda item: str(item["id"]))
    return selected, available


def load_rows(paths: list[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in paths:
        for row in read_jsonl(path):
            case_id = str(row.get("id", ""))
            if not case_id or case_id in seen:
                raise ValueError(f"duplicate or missing case ID {case_id!r}")
            seen.add(case_id)
            rows.append(row)
    return rows


def load_exclusions(paths: list[Path]) -> tuple[set[str], set[str]]:
    ids: set[str] = set()
    families: set[str] = set()
    for path in paths:
        for row in read_jsonl(path):
            ids.add(str(row.get("id", "")))
            families.add(family_id(row))
    return ids, families


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", action="append", type=Path, required=True)
    parser.add_argument("--exclude", action="append", type=Path, default=[])
    parser.add_argument("--quota", action="append", required=True)
    parser.add_argument("--forbid-dataset", action="append", default=[])
    parser.add_argument("--allow-test", action="store_true")
    parser.add_argument("--seed", type=int, default=741983)
    parser.add_argument("--stage", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    quotas = dict(parse_quota(value) for value in args.quota)
    rows = load_rows(args.input)
    excluded_ids, excluded_families = load_exclusions(args.exclude)
    selected, available = select_rows(
        rows, quotas, args.seed, excluded_ids, excluded_families, set(args.forbid_dataset), args.allow_test
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for row in selected:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    manifest = {
        "schema_version": "1",
        "kind": "defenseclaw-system-one-selection",
        "stage": args.stage,
        "seed": args.seed,
        "row_count": len(selected),
        "family_count": len({family_id(row) for row in selected}),
        "quotas": {":".join(key): value for key, value in sorted(quotas.items())},
        "available": available,
        "selected_counts": dict(sorted(Counter(f"grade:{truth_grade(row)}" for row in selected).items())),
        "input_sha256": {str(path): sha256_file(path) for path in args.input},
        "exclude_sha256": {str(path): sha256_file(path) for path in args.exclude},
        "output_sha256": sha256_file(args.output),
        "forbidden_datasets": sorted(set(args.forbid_dataset)),
        "test_allowed": args.allow_test,
    }
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
