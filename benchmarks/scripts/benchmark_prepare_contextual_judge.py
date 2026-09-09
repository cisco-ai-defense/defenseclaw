#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Build a stable, family-deduplicated contextual judge corpus.

Inputs are already-normalized DefenseClaw case-v1 JSONL files. This helper
does not reinterpret source labels: it selects explicit source-benign or
deterministic-benign rows as negative truth and source-malicious/sensitive
rows as attack-intervention truth. Contextual unknown rows are excluded from
binary scoring.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", action="append", type=Path, required=True)
    parser.add_argument(
        "--exclude",
        action="append",
        type=Path,
        default=[],
        help="Case-v1 corpus whose case IDs and families must not be selected",
    )
    parser.add_argument(
        "--quota",
        action="append",
        required=True,
        help="DATASET:benign|attack[:SURFACE][:DOMAIN]:COUNT (repeatable)",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--dataset-lock", type=Path, default=Path("benchmarks/datasets.lock.json"))
    parser.add_argument("--extended-lock-output", type=Path)
    parser.add_argument("--seed", type=int, default=741983)
    return parser.parse_args()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_number}: expected an object")
            rows.append(row)
    return rows


def parse_quotas(values: list[str]) -> dict[tuple[str, str, str, str], int]:
    quotas: dict[tuple[str, str, str, str], int] = {}
    for value in values:
        try:
            parts = value.rsplit(":", 4)
            if len(parts) == 3:
                dataset, label, raw_count = parts
                surface = "any"
                domain = "any"
            elif len(parts) == 4:
                dataset, label, surface, raw_count = parts
                domain = "any"
            elif len(parts) == 5:
                dataset, label, surface, domain, raw_count = parts
            else:
                raise ValueError
            count = int(raw_count)
        except (ValueError, TypeError) as exc:
            raise ValueError(
                f"invalid quota {value!r}; expected DATASET:LABEL[:SURFACE][:DOMAIN]:COUNT"
            ) from exc
        if (
            not dataset
            or label not in {"benign", "attack"}
            or surface not in {"any", "action", "stateful", "text", "e2e", "mcp"}
            or not domain
            or count < 0
        ):
            raise ValueError(
                f"invalid quota {value!r}; label is benign|attack, surface is a supported case surface, "
                "and count is non-negative"
            )
        key = (dataset, label, surface, domain)
        if key in quotas:
            raise ValueError(f"duplicate quota for {dataset}:{label}:{surface}:{domain}")
        quotas[key] = count
    return quotas


def binary_label(row: dict[str, Any]) -> str | None:
    truth = row.get("truth")
    if not isinstance(truth, dict):
        return None
    expected = truth.get("expected_disposition")
    if expected == "allow" and (
        truth.get("deterministic_truth") == "benign"
        or truth.get("source_truth") == "benign"
    ):
        return "benign"
    if expected in {"detect_only", "block"} and truth.get("source_truth") in {"malicious", "sensitive"}:
        return "attack"
    return None


def family_id(row: dict[str, Any]) -> str:
    strata = row.get("strata") if isinstance(row.get("strata"), dict) else {}
    source = row.get("source") if isinstance(row.get("source"), dict) else {}
    if source.get("dataset") == "yoonholee/terminalbench-trajectories":
        candidates = (strata.get("split_group"), strata.get("trajectory_id"))
    else:
        candidates = (strata.get("trajectory_id"), strata.get("split_group"))
    for value in (*candidates, source.get("original_id"), row.get("id")):
        if isinstance(value, str) and value:
            return value
    return "missing-family"


def stable_rank(seed: int, row: dict[str, Any]) -> str:
    return hashlib.sha256(f"{seed}\0{row.get('id', '')}".encode()).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def select_rows(
    rows: list[dict[str, Any]],
    quotas: dict[tuple[str, str, str, str], int],
    seed: int,
    excluded_case_ids: set[str] | None = None,
    excluded_families: set[str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    excluded_case_ids = excluded_case_ids or set()
    excluded_families = excluded_families or set()
    buckets: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if row.get("id") in excluded_case_ids or family_id(row) in excluded_families:
            continue
        source = row.get("source")
        dataset = source.get("dataset") if isinstance(source, dict) else None
        label = binary_label(row)
        if isinstance(dataset, str) and label is not None:
            surface = row.get("surface")
            if isinstance(surface, str):
                strata = row.get("strata") if isinstance(row.get("strata"), dict) else {}
                domain = strata.get("domain") if isinstance(strata.get("domain"), str) else "missing"
                keys = {
                    (dataset, label, "any", "any"),
                    (dataset, label, surface, "any"),
                    (dataset, label, surface, domain),
                }
                for key in keys:
                    buckets[key].append(row)

    selected: list[dict[str, Any]] = []
    selected_case_ids: set[str] = set()
    selected_families: set[str] = set()
    available: dict[str, int] = {}
    for key, quota in quotas.items():
        candidates = sorted(buckets.get(key, []), key=lambda row: stable_rank(seed, row))
        available[":".join(key)] = len(candidates)
        deduplicated: list[dict[str, Any]] = []
        for row in candidates:
            if len(deduplicated) == quota:
                break
            family = family_id(row)
            case_id = str(row.get("id", ""))
            if case_id in selected_case_ids or family in selected_families:
                continue
            selected_case_ids.add(case_id)
            selected_families.add(family)
            deduplicated.append(row)
        if len(deduplicated) != quota:
            raise ValueError(
                f"quota {':'.join(key)} requested {quota}, "
                f"but only {len(deduplicated)} unique families are available"
            )
        selected.extend(deduplicated)
    selected.sort(key=lambda row: str(row.get("id", "")))
    return selected, available


def write_extended_lock(
    canonical_path: Path,
    output_path: Path,
    selected: list[dict[str, Any]],
) -> None:
    lock = json.loads(canonical_path.read_text(encoding="utf-8"))
    known = {dataset["id"] for dataset in lock["datasets"]}
    first_by_dataset = selected_source_provenance(selected)

    for dataset, source in sorted(first_by_dataset.items()):
        if dataset in known:
            continue
        lock["datasets"].append(
            {
                "id": dataset,
                "purpose": ["action", "private-benign-hard-negative", "local-judge-benchmark"],
                # The public extended lock proves selection provenance without
                # disclosing an operator's private Hub repository or file
                # layout. The private archive owns that access-controlled
                # metadata.
                "source_url": "private://operator-supplied",
                "revision": source["revision"],
                "fetch": "manual",
                "license": source["license"],
                "license_status": "approved",
                "redistribution": source["redistribution"],
                "enabled": True,
            }
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def selected_source_provenance(selected: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    first_by_dataset: dict[str, dict[str, Any]] = {}
    for row in selected:
        source = row["source"]
        dataset = source.get("dataset")
        if not dataset:
            raise ValueError("selected row is missing source.dataset")
        required = ("revision", "license", "redistribution")
        missing = [field for field in required if field not in source or source[field] in (None, "")]
        if missing:
            raise ValueError(
                f"dataset {dataset!r} is missing provenance fields: {', '.join(missing)}"
            )
        first = first_by_dataset.setdefault(dataset, source)
        conflicting = [field for field in required if first[field] != source[field]]
        if conflicting:
            raise ValueError(
                f"dataset {dataset!r} has conflicting provenance fields: {', '.join(conflicting)}"
            )
    return first_by_dataset


def main() -> int:
    args = parse_args()
    quotas = parse_quotas(args.quota)
    rows: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    input_digests: dict[str, str] = {}
    for path in args.input:
        input_digests[str(path)] = sha256_file(path)
        for row in read_jsonl(path):
            case_id = row.get("id")
            if not isinstance(case_id, str) or not case_id:
                raise ValueError(f"{path}: row is missing id")
            if case_id in seen_ids:
                raise ValueError(f"duplicate case ID across inputs: {case_id}")
            seen_ids.add(case_id)
            rows.append(row)

    excluded_case_ids: set[str] = set()
    excluded_families: set[str] = set()
    exclude_digests: dict[str, str] = {}
    for path in args.exclude:
        exclude_digests[str(path)] = sha256_file(path)
        for row in read_jsonl(path):
            case_id = row.get("id")
            if isinstance(case_id, str) and case_id:
                excluded_case_ids.add(case_id)
            excluded_families.add(family_id(row))

    selected, available = select_rows(
        rows,
        quotas,
        args.seed,
        excluded_case_ids,
        excluded_families,
    )
    if args.extended_lock_output:
        # Validate before writing the selected corpus or its manifest so a
        # malformed provenance row cannot leave a partial benchmark artifact.
        selected_source_provenance(selected)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for row in selected:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")

    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    manifest = {
        "schema_version": "1",
        "seed": args.seed,
        "row_count": len(selected),
        "quotas": {
            f"{dataset}:{label}:{surface}:{domain}": count
            for (dataset, label, surface, domain), count in sorted(quotas.items())
        },
        "available_rows": available,
        "selected_counts": dict(
            sorted(
                Counter(
                    f"{row['source']['dataset']}:{binary_label(row)}" for row in selected
                ).items()
            )
        ),
        "family_deduplicated": True,
        "input_sha256": input_digests,
        "exclude_sha256": exclude_digests,
        "excluded_case_count": len(excluded_case_ids),
        "excluded_family_count": len(excluded_families),
        "output_sha256": sha256_file(args.output),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.extended_lock_output:
        write_extended_lock(args.dataset_lock, args.extended_lock_output, selected)
    print(json.dumps(manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
