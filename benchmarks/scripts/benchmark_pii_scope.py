# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Project public PII labels onto DefenseClaw's deterministic identifier scope."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

if __package__:
    from .benchmark_error_analysis import load_jsonl, sha256_file
else:
    from benchmark_error_analysis import load_jsonl, sha256_file

SCOPE_VERSION = "pii-structured-identifiers-v1"
HIGH_ASSURANCE_SCOPE_VERSION = "pii-high-assurance-v1"

# These public-dataset entity labels correspond directly to a shipped local
# signature family. Names, locations, demographics, arbitrary account IDs,
# and similar semantic entities are deliberately excluded: recognizing them
# requires context or a model and is not a deterministic regex claim.
SUPPORTED_LABELS = {
    "credit_card_number",
    "credit_debit_card",
    "date_of_birth",
    "email",
    "fax_number",
    "medical_record_number",
    "phone_number",
    "ssn",
}

# The opt-in privacy-high-assurance pack intentionally narrows the blocking
# claim to structured identifiers with strong local evidence. Bulk CSV/JSON and
# IBAN rules are measured in authored conformance corpora because the public PII
# span sources do not provide equivalent labels for those families.
HIGH_ASSURANCE_SUPPORTED_LABELS = {
    "credit_card_number",
    "credit_debit_card",
    "date_of_birth",
    "medical_record_number",
    "ssn",
}

SCOPES = {
    SCOPE_VERSION: SUPPORTED_LABELS,
    HIGH_ASSURANCE_SCOPE_VERSION: HIGH_ASSURANCE_SUPPORTED_LABELS,
}


def project_row(
    row: dict[str, Any],
    supported_labels: set[str] = SUPPORTED_LABELS,
    scope_version: str = SCOPE_VERSION,
) -> tuple[dict[str, Any], Counter[str]]:
    projected = json.loads(json.dumps(row))
    truth = projected["truth"]
    stats: Counter[str] = Counter()
    if truth.get("source_truth") == "benign":
        stats["benign_cases"] += 1
        return projected, stats
    if truth.get("source_truth") != "sensitive":
        return projected, stats

    spans = truth.get("spans") or []
    retained = [span for span in spans if str(span.get("label", "")) in supported_labels]
    stats["source_sensitive_cases"] += 1
    stats["source_spans"] += len(spans)
    stats["retained_spans"] += len(retained)
    stats["excluded_spans"] += len(spans) - len(retained)
    truth["spans"] = retained
    if retained:
        stats["in_scope_sensitive_cases"] += 1
        truth["categories"] = sorted(set((truth.get("categories") or []) + [scope_version]))
    else:
        stats["out_of_scope_sensitive_cases"] += 1
        if truth.get("applicability") == "in_scope":
            truth["applicability"] = "out_of_scope"
            truth["exclusion_reason"] = "no_supported_deterministic_pii_entity"
    return projected, stats


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")


def normalization_manifest(
    source_path: Path,
    output_path: Path,
    rows: list[dict[str, Any]],
    totals: Counter[str],
    scope_version: str = SCOPE_VERSION,
) -> dict[str, Any]:
    source_manifest_path = source_path.with_suffix(".manifest.json")
    source_manifest: dict[str, Any] = {}
    if source_manifest_path.is_file():
        source_manifest = json.loads(source_manifest_path.read_text(encoding="utf-8"))
    dataset_counts = Counter(str(row["source"]["dataset"]) for row in rows)
    adapter_statistics = json.loads(json.dumps(source_manifest.get("adapter_statistics") or {}))
    adapter_statistics[scope_version] = dict(sorted(totals.items()))
    manifest: dict[str, Any] = {
        "schema_version": "1",
        "datasets": sorted(dataset_counts),
        "cases": len(rows),
        "counts": dict(sorted(dataset_counts.items())),
        "exact_payload_duplicates_removed": int(source_manifest.get("exact_payload_duplicates_removed", 0)),
        "label_conflicts_excluded": int(source_manifest.get("label_conflicts_excluded", 0)),
        "adapter_statistics": adapter_statistics,
        "output_sha256": sha256_file(output_path),
    }
    if isinstance(source_manifest.get("partition"), dict):
        manifest["partition"] = source_manifest["partition"]
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scope", choices=tuple(SCOPES), default=SCOPE_VERSION)
    parser.add_argument("--allow-test", action="store_true")
    args = parser.parse_args()

    source_rows = load_jsonl(args.corpus)
    if not args.allow_test and any(row.get("split") == "test" for row in source_rows):
        parser.error("refusing to project sealed test rows without --allow-test")
    projected: list[dict[str, Any]] = []
    totals: Counter[str] = Counter()
    for row in source_rows:
        projected_row, stats = project_row(row, SCOPES[args.scope], args.scope)
        projected.append(projected_row)
        totals.update(stats)
    write_jsonl(args.output, projected)
    manifest = normalization_manifest(args.corpus, args.output, projected, totals, args.scope)
    args.output.with_suffix(".manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    scope_record = {
        "schema_version": "1",
        "scope_version": args.scope,
        "supported_entity_labels": sorted(SCOPES[args.scope]),
        "source_corpus": str(args.corpus),
        "source_corpus_sha256": sha256_file(args.corpus),
        "output_sha256": sha256_file(args.output),
        "case_count": len(projected),
        "counts": dict(sorted(totals.items())),
    }
    args.output.with_suffix(".scope.json").write_text(
        json.dumps(scope_record, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        f"wrote {len(projected)} cases: in_scope_sensitive={totals['in_scope_sensitive_cases']}, "
        f"out_of_scope_sensitive={totals['out_of_scope_sensitive_cases']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
