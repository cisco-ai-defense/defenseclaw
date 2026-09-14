#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Generate strict, value-free manifests for checked-in benchmark fixtures."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA_VERSION = "1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--lock", type=Path, default=Path("benchmarks/datasets.lock.json"))
    parser.add_argument("--dataset", action="append", required=True)
    return parser.parse_args()


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_lock(path: Path) -> dict[str, dict[str, Any]]:
    raw = read_json(path)
    if not isinstance(raw, dict) or raw.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported dataset lock schema")
    datasets = raw.get("datasets")
    if not isinstance(datasets, list):
        raise ValueError("dataset lock requires datasets")
    entries: dict[str, dict[str, Any]] = {}
    for entry in datasets:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
            raise ValueError("dataset lock contains an invalid entry")
        dataset_id = entry["id"]
        if dataset_id in entries:
            raise ValueError(f"duplicate dataset ID {dataset_id!r}")
        entries[dataset_id] = entry
    return entries


def locked_fixture_path(repo_root: Path, entry: dict[str, Any]) -> tuple[Path, str]:
    dataset_id = entry["id"]
    if (
        entry.get("enabled") is not True
        or entry.get("fetch") != "vendored"
        or entry.get("redistribution") != "vendored"
        or entry.get("license_status") != "approved"
    ):
        raise ValueError(f"{dataset_id}: dataset lock does not authorize a vendored fixture")
    source_url = entry.get("source_url")
    if not isinstance(source_url, str):
        raise ValueError(f"{dataset_id}: dataset lock source_url is invalid")
    relative = PurePosixPath(source_url)
    if relative.is_absolute() or ".." in relative.parts or relative.suffix != ".jsonl":
        raise ValueError(f"{dataset_id}: vendored source_url must be a repository JSONL path")
    if relative.parent != PurePosixPath("benchmarks/fixtures"):
        raise ValueError(f"{dataset_id}: vendored fixture must be under benchmarks/fixtures")
    fixture = repo_root.joinpath(*relative.parts)
    if not fixture.is_file():
        raise ValueError(f"{dataset_id}: vendored fixture is absent")
    return fixture, relative.as_posix()


def load_and_verify_cases(fixture: Path, entry: dict[str, Any]) -> int:
    dataset_id = entry["id"]
    case_ids: set[str] = set()
    count = 0
    with fixture.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                raise ValueError(f"{dataset_id}: blank JSONL line {line_number}")
            try:
                case = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"{dataset_id}: invalid JSONL line {line_number}") from error
            if not isinstance(case, dict):
                raise ValueError(f"{dataset_id}: JSONL line {line_number} is not an object")
            source = case.get("source")
            if not isinstance(source, dict):
                raise ValueError(f"{dataset_id}: case {line_number} has no source authority")
            for field in ("dataset", "revision", "license", "redistribution"):
                lock_field = "id" if field == "dataset" else field
                if source.get(field) != entry.get(lock_field):
                    raise ValueError(
                        f"{dataset_id}: case {line_number} source {field} differs from dataset lock"
                    )
            case_id = case.get("id")
            if not isinstance(case_id, str) or not case_id or case_id in case_ids:
                raise ValueError(f"{dataset_id}: case {line_number} has an invalid or duplicate ID")
            case_ids.add(case_id)
            count += 1
    if count == 0:
        raise ValueError(f"{dataset_id}: vendored fixture is empty")
    return count


def build_manifest(repo_root: Path, entry: dict[str, Any]) -> tuple[Path, bytes]:
    fixture, source_path = locked_fixture_path(repo_root, entry)
    cases = load_and_verify_cases(fixture, entry)
    fixture_bytes = fixture.read_bytes()
    digest = hashlib.sha256(fixture_bytes).hexdigest()
    dataset_id = entry["id"]
    manifest = {
        "adapter_statistics": {dataset_id: {"rows_emitted": cases, "rows_read": cases}},
        "cases": cases,
        "counts": {dataset_id: cases},
        "datasets": [dataset_id],
        "exact_payload_duplicates_removed": 0,
        "label_conflicts_excluded": 0,
        "output_sha256": digest,
        "schema_version": SCHEMA_VERSION,
        "source": {
            "bytes": len(fixture_bytes),
            "dataset": dataset_id,
            "license": entry["license"],
            "path": source_path,
            "redistribution": entry["redistribution"],
            "revision": str(entry["revision"]),
            "rows": cases,
            "sha256": digest,
        },
    }
    output = fixture.with_suffix(".manifest.json")
    return output, (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main() -> None:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    lock_path = args.lock if args.lock.is_absolute() else repo_root / args.lock
    entries = load_lock(lock_path)
    if len(set(args.dataset)) != len(args.dataset):
        raise ValueError("duplicate --dataset selection")
    for dataset_id in sorted(args.dataset):
        if dataset_id not in entries:
            raise ValueError(f"dataset {dataset_id!r} is absent from dataset lock")
        output, data = build_manifest(repo_root, entries[dataset_id])
        write_atomic(output, data)


if __name__ == "__main__":
    main()
