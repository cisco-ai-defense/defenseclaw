# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path

import pytest

SCRIPT = Path(__file__).with_name("benchmark_manifest_vendored_fixture.py")
SPEC = importlib.util.spec_from_file_location("benchmark_manifest_vendored_fixture", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

REPO_ROOT = SCRIPT.parents[2]
DATASETS = (
    "defenseclaw-smoke",
    "defenseclaw-cloud-production-conformance-v1",
    "defenseclaw-database-destruction-conformance-v1",
    "defenseclaw-kubernetes-production-conformance-v1",
    "defenseclaw-infrastructure-destruction-conformance-v1",
    "defenseclaw-postgresql-copy-program-v1",
    "defenseclaw-sql-command-udf-atomic-v1",
)
MANIFEST_KEYS = {
    "adapter_statistics", "cases", "counts", "datasets",
    "exact_payload_duplicates_removed", "label_conflicts_excluded",
    "output_sha256", "schema_version", "source",
}
SOURCE_KEYS = {
    "bytes", "dataset", "license", "path", "redistribution",
    "revision", "rows", "sha256",
}


@pytest.mark.parametrize("dataset_id", DATASETS)
def test_committed_manifest_regenerates_byte_identically(dataset_id: str) -> None:
    entries = MODULE.load_lock(REPO_ROOT / "benchmarks/datasets.lock.json")
    output, first = MODULE.build_manifest(REPO_ROOT, entries[dataset_id])
    _, second = MODULE.build_manifest(REPO_ROOT, entries[dataset_id])
    assert first == second == output.read_bytes()

    manifest = json.loads(first)
    assert set(manifest) == MANIFEST_KEYS
    assert set(manifest["source"]) == SOURCE_KEYS
    assert manifest["datasets"] == [dataset_id]
    assert manifest["counts"] == {dataset_id: manifest["cases"]}
    assert manifest["source"]["dataset"] == dataset_id
    assert manifest["source"]["sha256"] == manifest["output_sha256"]
    assert b'"payload"' not in first
    assert b'"content"' not in first
    assert b'"command"' not in first


def test_dataset_lock_is_authoritative(tmp_path: Path) -> None:
    fixture_dir = tmp_path / "benchmarks/fixtures"
    fixture_dir.mkdir(parents=True)
    fixture = REPO_ROOT / "benchmarks/fixtures/smoke.jsonl"
    shutil.copyfile(fixture, fixture_dir / fixture.name)
    lock = json.loads((REPO_ROOT / "benchmarks/datasets.lock.json").read_text())
    smoke = next(item for item in lock["datasets"] if item["id"] == "defenseclaw-smoke")
    smoke["revision"] = "different"
    (tmp_path / "benchmarks/datasets.lock.json").write_text(json.dumps(lock))

    entries = MODULE.load_lock(tmp_path / "benchmarks/datasets.lock.json")
    with pytest.raises(ValueError, match="differs from dataset lock"):
        MODULE.build_manifest(tmp_path, entries["defenseclaw-smoke"])
