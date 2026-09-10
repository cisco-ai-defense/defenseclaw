#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Partition a normalized corpus by adapter-owned leakage groups.

The output directory contains separate development, validation, and sealed
test JSONL files. Source payloads remain only in these ignored corpus files;
the global split manifest contains stable case IDs and hashed group IDs only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path

SCHEMA_VERSION = "1"
STRATEGY = "adapter-group-balanced-v1"
SPLITS = ("development", "validation", "test")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", required=True, help="normalized source corpus")
    parser.add_argument("--normalization-manifest", help="source manifest; inferred beside corpus")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--seed", type=int, default=741983)
    parser.add_argument("--development-percent", type=int, default=60)
    parser.add_argument("--validation-percent", type=int, default=20)
    parser.add_argument("--verify", action="store_true", help="verify an existing partition directory")
    return parser.parse_args()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def strict_json_object(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def load_cases(path: Path) -> tuple[bytes, list[dict[str, object]]]:
    data = path.read_bytes()
    rows: list[dict[str, object]] = []
    seen: set[str] = set()
    for line_number, raw_line in enumerate(data.splitlines(), start=1):
        if not raw_line.strip() or raw_line.lstrip().startswith(b"//"):
            continue
        value = json.loads(raw_line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_number}: expected a JSON object")
        case_id = value.get("id")
        if not isinstance(case_id, str) or not case_id:
            raise ValueError(f"{path}:{line_number}: missing case ID")
        if case_id in seen:
            raise ValueError(f"{path}:{line_number}: duplicate case ID {case_id!r}")
        seen.add(case_id)
        strata = value.get("strata")
        split_group = strata.get("split_group") if isinstance(strata, dict) else None
        if not isinstance(split_group, str) or len(split_group) != 24:
            raise ValueError(f"{case_id}: adapter-owned strata.split_group is required")
        if any(character not in "0123456789abcdef" for character in split_group):
            raise ValueError(f"{case_id}: strata.split_group is not lowercase hex")
        rows.append(value)
    if not rows:
        raise ValueError("source corpus is empty")
    rows.sort(key=lambda row: str(row["id"]))
    return data, rows


def stable_order(seed: int, *values: str) -> str:
    return hashlib.sha256(("\0".join((STRATEGY, str(seed), *values))).encode()).hexdigest()


def validate_ratios(development_percent: int, validation_percent: int) -> dict[str, int]:
    test_percent = 100 - development_percent - validation_percent
    ratios = {
        "development": development_percent,
        "validation": validation_percent,
        "test": test_percent,
    }
    if any(value <= 0 for value in ratios.values()):
        raise ValueError("development, validation, and test percentages must all be positive")
    return ratios


def assignment_digest(assignments: Iterable[tuple[str, str, str]]) -> str:
    digest = hashlib.sha256()
    for case_id, group, split in sorted(assignments):
        digest.update(case_id.encode())
        digest.update(b"\0")
        digest.update(group.encode())
        digest.update(b"\0")
        digest.update(split.encode())
        digest.update(b"\n")
    return digest.hexdigest()


def partition_cases(
    rows: list[dict[str, object]],
    seed: int,
    ratios: dict[str, int],
) -> tuple[dict[str, list[dict[str, object]]], list[dict[str, object]], str]:
    rows_by_group: dict[str, list[dict[str, object]]] = defaultdict(list)
    group_datasets: dict[str, set[str]] = defaultdict(set)
    group_strata: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for row in rows:
        case_id = str(row["id"])
        source = row.get("source")
        strata = row.get("strata")
        truth = row.get("truth")
        if not isinstance(source, dict) or not isinstance(strata, dict) or not isinstance(truth, dict):
            raise ValueError(f"{case_id}: source, truth, and strata objects are required")
        dataset = source.get("dataset")
        group = strata.get("split_group")
        source_truth = truth.get("source_truth")
        disposition = truth.get("expected_disposition")
        if not all(isinstance(value, str) for value in (dataset, group, source_truth, disposition)):
            raise ValueError(f"{case_id}: dataset, truth labels, and split group are required")
        rows_by_group[str(group)].append(row)
        group_datasets[str(group)].add(str(dataset))
        group_strata[str(group)][f"truth:{source_truth}"] += 1
        group_strata[str(group)][f"disposition:{disposition}"] += 1

    groups_by_dataset: dict[str, list[str]] = defaultdict(list)
    for group, datasets in group_datasets.items():
        if len(datasets) != 1:
            raise ValueError(f"split group {group} spans datasets: {', '.join(sorted(datasets))}")
        groups_by_dataset[next(iter(datasets))].append(group)

    split_by_group: dict[str, str] = {}
    ratio_fraction = {split: ratios[split] / 100 for split in SPLITS}
    for dataset, dataset_groups in sorted(groups_by_dataset.items()):
        dimension_totals: dict[str, int] = defaultdict(int)
        for group in dataset_groups:
            dimension_totals["cases"] += len(rows_by_group[group])
            for dimension, count in group_strata[group].items():
                dimension_totals[dimension] += count
        targets = {
            dimension: {split: total * ratio_fraction[split] for split in SPLITS}
            for dimension, total in dimension_totals.items()
        }
        assigned = {
            dimension: {split: 0 for split in SPLITS}
            for dimension in dimension_totals
        }
        ordered_groups = sorted(
            dataset_groups,
            key=lambda group: (-len(rows_by_group[group]), stable_order(seed, dataset, group)),
        )
        for group in ordered_groups:
            additions = {"cases": len(rows_by_group[group]), **group_strata[group]}

            def allocation_score(split: str) -> tuple[float, str]:
                score = 0.0
                for dimension, target_by_split in targets.items():
                    scale = max(float(dimension_totals[dimension]), 1.0)
                    for candidate_split in SPLITS:
                        value = assigned[dimension][candidate_split]
                        if candidate_split == split:
                            value += additions.get(dimension, 0)
                        difference = (value - target_by_split[candidate_split]) / scale
                        score += difference * difference
                return score, stable_order(seed, dataset, group, split)

            selected_split = min(SPLITS, key=allocation_score)
            split_by_group[group] = selected_split
            for dimension, count in additions.items():
                assigned[dimension][selected_split] += count

    partitions: dict[str, list[dict[str, object]]] = {split: [] for split in SPLITS}
    group_cases: dict[str, list[str]] = defaultdict(list)
    assignment_rows: list[tuple[str, str, str]] = []
    for row in rows:
        case_id = str(row["id"])
        source = row.get("source")
        strata = row.get("strata")
        if not isinstance(source, dict) or not isinstance(strata, dict):
            raise ValueError(f"{case_id}: source and strata objects are required")
        dataset = source.get("dataset")
        group = strata.get("split_group")
        if not isinstance(dataset, str) or not isinstance(group, str):
            raise ValueError(f"{case_id}: dataset and split group are required")
        split = split_by_group[group]
        row["split"] = split
        partitions[split].append(row)
        group_cases[group].append(case_id)
        group_datasets[group].add(dataset)
        assignment_rows.append((case_id, group, split))
    empty = [split for split, values in partitions.items() if not values]
    if empty:
        raise ValueError(f"partitioning produced empty splits: {', '.join(empty)}")
    groups = [
        {
            "group": group,
            "split": split_by_group[group],
            "cases": len(group_cases[group]),
            "datasets": sorted(group_datasets[group]),
        }
        for group in sorted(split_by_group)
    ]
    return partitions, groups, assignment_digest(assignment_rows)


def source_manifest_path(corpus: Path, explicit: str | None) -> Path:
    return Path(explicit) if explicit else corpus.with_suffix(".manifest.json")


def validate_source_manifest(
    manifest: dict[str, object],
    manifest_data: bytes,
    corpus_sha256: str,
    row_count: int,
) -> None:
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("source normalization manifest has unsupported schema")
    if manifest.get("output_sha256") != corpus_sha256 or manifest.get("cases") != row_count:
        raise ValueError("source normalization manifest identity differs from corpus")
    if len(manifest_data) > 4 << 20:
        raise ValueError("source normalization manifest exceeds 4 MiB")


def serialized_rows_sha256(rows: Iterable[dict[str, object]]) -> str:
    digest = hashlib.sha256()
    for row in rows:
        digest.update((json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode())
    return digest.hexdigest()


def partition_normalization(
    split: str,
    rows: list[dict[str, object]],
    source_manifest: dict[str, object],
    source_corpus_sha256: str,
    source_normalization_sha256: str,
    ratios: dict[str, int],
    seed: int,
    global_assignment_sha256: str,
    output_sha256: str,
) -> dict[str, object]:
    counts: dict[str, int] = defaultdict(int)
    groups: set[str] = set()
    for row in rows:
        source = row["source"]
        strata = row["strata"]
        assert isinstance(source, dict) and isinstance(strata, dict)
        counts[str(source["dataset"])] += 1
        groups.add(str(strata["split_group"]))
    return {
        "schema_version": SCHEMA_VERSION,
        "datasets": sorted(counts),
        "cases": len(rows),
        "counts": dict(sorted(counts.items())),
        "exact_payload_duplicates_removed": source_manifest.get("exact_payload_duplicates_removed", 0),
        "label_conflicts_excluded": source_manifest.get("label_conflicts_excluded", 0),
        "adapter_statistics": source_manifest.get("adapter_statistics", {}),
        "output_sha256": output_sha256,
        "partition": {
            "strategy": STRATEGY,
            "seed": seed,
            "source_corpus_sha256": source_corpus_sha256,
            "source_normalization_sha256": source_normalization_sha256,
            "split": split,
            "ratios": ratios,
            "split_group_count": len(groups),
            "assignment_sha256": global_assignment_sha256,
        },
    }


def write_partition_file(
    directory: Path,
    split: str,
    rows: list[dict[str, object]],
    source_manifest: dict[str, object],
    source_corpus_sha256: str,
    source_normalization_sha256: str,
    ratios: dict[str, int],
    seed: int,
    global_assignment_sha256: str,
) -> dict[str, object]:
    corpus_path = directory / f"{split}.jsonl"
    digest = hashlib.sha256()
    with corpus_path.open("x", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            encoded = (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()
            handle.write(encoded.decode())
            digest.update(encoded)
    output_sha256 = digest.hexdigest()
    normalized = partition_normalization(
        split,
        rows,
        source_manifest,
        source_corpus_sha256,
        source_normalization_sha256,
        ratios,
        seed,
        global_assignment_sha256,
        output_sha256,
    )
    manifest_path = directory / f"{split}.manifest.json"
    manifest_path.write_text(json.dumps(normalized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "corpus": corpus_path.name,
        "normalization_manifest": manifest_path.name,
        "cases": len(rows),
        "groups": normalized["partition"]["split_group_count"],  # type: ignore[index]
        "sha256": output_sha256,
    }


def split_audit_records(
    partitions: dict[str, list[dict[str, object]]],
) -> tuple[dict[str, dict[str, int]], list[dict[str, str]]]:
    dataset_splits: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    case_assignments: list[dict[str, str]] = []
    for split in SPLITS:
        for row in partitions[split]:
            source = row["source"]
            strata = row["strata"]
            assert isinstance(source, dict) and isinstance(strata, dict)
            dataset_splits[str(source["dataset"])][split] += 1
            case_assignments.append(
                {"case_id": str(row["id"]), "group": str(strata["split_group"]), "split": split}
            )
    return (
        {dataset: dict(sorted(values.items())) for dataset, values in sorted(dataset_splits.items())},
        sorted(case_assignments, key=lambda item: item["case_id"]),
    )


def global_split_manifest(
    rows: list[dict[str, object]],
    partitions: dict[str, list[dict[str, object]]],
    groups: list[dict[str, object]],
    outputs: dict[str, dict[str, object]],
    seed: int,
    ratios: dict[str, int],
    source_corpus_sha256: str,
    source_normalization_sha256: str,
    global_assignment_sha256: str,
) -> dict[str, object]:
    dataset_splits, case_assignments = split_audit_records(partitions)
    return {
        "schema_version": SCHEMA_VERSION,
        "strategy": STRATEGY,
        "seed": seed,
        "ratios": ratios,
        "source_corpus_sha256": source_corpus_sha256,
        "source_normalization_sha256": source_normalization_sha256,
        "assignment_sha256": global_assignment_sha256,
        "cases": len(rows),
        "groups": len(groups),
        "partitions": outputs,
        "dataset_split_counts": dataset_splits,
        "group_assignments": groups,
        "case_assignments": case_assignments,
    }


def partition(
    corpus: Path,
    normalization_manifest: Path,
    output_dir: Path,
    seed: int,
    development_percent: int,
    validation_percent: int,
) -> dict[str, object]:
    if output_dir.exists():
        raise ValueError(f"output directory already exists: {output_dir}")
    ratios = validate_ratios(development_percent, validation_percent)
    corpus_data, rows = load_cases(corpus)
    corpus_sha256 = sha256_bytes(corpus_data)
    normalization_data = normalization_manifest.read_bytes()
    source_normalization = strict_json_object(normalization_manifest)
    validate_source_manifest(source_normalization, normalization_data, corpus_sha256, len(rows))
    partitions, groups, global_assignment_sha256 = partition_cases(rows, seed, ratios)

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".{output_dir.name}-", dir=output_dir.parent) as temporary:
        temporary_dir = Path(temporary)
        outputs = {
            split: write_partition_file(
                temporary_dir,
                split,
                partitions[split],
                source_normalization,
                corpus_sha256,
                sha256_bytes(normalization_data),
                ratios,
                seed,
                global_assignment_sha256,
            )
            for split in SPLITS
        }
        split_manifest = global_split_manifest(
            rows,
            partitions,
            groups,
            outputs,
            seed,
            ratios,
            corpus_sha256,
            sha256_bytes(normalization_data),
            global_assignment_sha256,
        )
        (temporary_dir / "splits.json").write_text(
            json.dumps(split_manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary_dir.replace(output_dir)
    return split_manifest


def verify_partition(
    corpus: Path,
    normalization_manifest: Path,
    output_dir: Path,
    seed: int,
    development_percent: int,
    validation_percent: int,
) -> dict[str, object]:
    if not output_dir.is_dir():
        raise ValueError(f"partition output directory is missing: {output_dir}")
    ratios = validate_ratios(development_percent, validation_percent)
    corpus_data, rows = load_cases(corpus)
    corpus_sha256 = sha256_bytes(corpus_data)
    normalization_data = normalization_manifest.read_bytes()
    source_normalization = strict_json_object(normalization_manifest)
    validate_source_manifest(source_normalization, normalization_data, corpus_sha256, len(rows))
    partitions, groups, global_assignment_sha256 = partition_cases(rows, seed, ratios)
    source_normalization_sha256 = sha256_bytes(normalization_data)
    outputs: dict[str, dict[str, object]] = {}
    for split in SPLITS:
        corpus_path = output_dir / f"{split}.jsonl"
        actual_sha256 = sha256_bytes(corpus_path.read_bytes())
        expected_sha256 = serialized_rows_sha256(partitions[split])
        if actual_sha256 != expected_sha256:
            raise ValueError(f"{split} corpus differs from deterministic partition")
        expected_normalization = partition_normalization(
            split,
            partitions[split],
            source_normalization,
            corpus_sha256,
            source_normalization_sha256,
            ratios,
            seed,
            global_assignment_sha256,
            expected_sha256,
        )
        actual_normalization = strict_json_object(output_dir / f"{split}.manifest.json")
        if actual_normalization != expected_normalization:
            raise ValueError(f"{split} normalization manifest differs from deterministic partition")
        partition_metadata = expected_normalization["partition"]
        assert isinstance(partition_metadata, dict)
        outputs[split] = {
            "corpus": corpus_path.name,
            "normalization_manifest": f"{split}.manifest.json",
            "cases": len(partitions[split]),
            "groups": partition_metadata["split_group_count"],
            "sha256": expected_sha256,
        }
    expected_manifest = global_split_manifest(
        rows,
        partitions,
        groups,
        outputs,
        seed,
        ratios,
        corpus_sha256,
        source_normalization_sha256,
        global_assignment_sha256,
    )
    actual_manifest = strict_json_object(output_dir / "splits.json")
    if actual_manifest != expected_manifest:
        raise ValueError("splits.json differs from deterministic partition")
    return expected_manifest


def main() -> int:
    args = parse_args()
    corpus = Path(args.corpus)
    manifest = source_manifest_path(corpus, args.normalization_manifest)
    operation = verify_partition if args.verify else partition
    result = operation(
        corpus,
        manifest,
        Path(args.output_dir),
        args.seed,
        args.development_percent,
        args.validation_percent,
    )
    counts = ", ".join(f"{split}={result['partitions'][split]['cases']}" for split in SPLITS)  # type: ignore[index]
    verb = "verified" if args.verify else "partitioned"
    print(f"{verb} {result['cases']} cases in {result['groups']} groups ({counts})")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"benchmark-partition: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
