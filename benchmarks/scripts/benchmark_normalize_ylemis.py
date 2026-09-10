#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Normalize the revision-pinned Ylemis India PII benchmark as a sealed holdout."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

SOURCE_ID = "ylemis-india-pii-benchmark"
SOURCE_REVISION = "cc2cc39c8462bfe939ad20ce19b895361c5464d7"
SOURCE_LICENSE = "CC0-1.0"
SOURCE_SHA256 = "7003719c62f451b68ec68280fbccaca12990718ad9ee7aacbcaba66c4c43f914"
ENTITY_TYPES = {
    "person", "address", "location", "organization", "account_id", "medical_id",
    "email", "indian_phone", "pan", "aadhaar", "gstin", "ifsc", "upi_id",
    "voter_id", "vehicle_registration", "indian_passport",
}
LABEL_MAP = {"email": "email", "indian_phone": "phone_number", "medical_id": "medical_record_number"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalized_span(text: str, entity: object, case_id: str = "case") -> tuple[dict[str, Any], str]:
    if not isinstance(entity, dict):
        raise ValueError(f"{case_id}: entity is not an object")
    entity_type = str(entity.get("type", ""))
    start, end = entity.get("start"), entity.get("end")
    if entity_type not in ENTITY_TYPES:
        raise ValueError(f"{case_id}: unsupported source entity type {entity_type!r}")
    if not isinstance(start, int) or not isinstance(end, int) or start < 0 or end <= start or end > len(text):
        raise ValueError(f"{case_id}: invalid entity span")
    return {"label": LABEL_MAP.get(entity_type, entity_type), "start": start, "end": end}, entity_type


def normalize(input_path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    source_digest = sha256_file(input_path)
    if source_digest != SOURCE_SHA256:
        raise ValueError("Ylemis source digest differs from the frozen release")
    rows: list[dict[str, Any]] = []
    ids: set[str] = set()
    types: Counter[str] = Counter()
    categories: Counter[str] = Counter()
    languages: Counter[str] = Counter()
    for line_number, line in enumerate(input_path.read_text(encoding="utf-8").splitlines(), 1):
        value = json.loads(line)
        case_id = str(value.get("id", ""))
        text = value.get("text")
        language = str(value.get("language", ""))
        category = str(value.get("category", ""))
        entities = value.get("entities")
        if not case_id or case_id in ids or not isinstance(text, str) or not text:
            raise ValueError(f"line {line_number}: missing/duplicate ID or text")
        if not language or not category or not isinstance(entities, list):
            raise ValueError(f"{case_id}: missing language, category, or entities")
        ids.add(case_id)
        spans: list[dict[str, Any]] = []
        raw_types: set[str] = set()
        for entity in entities:
            span, entity_type = normalized_span(text, entity, case_id)
            spans.append(span)
            raw_types.add(entity_type)
            types[entity_type] += 1
        sensitive = bool(spans)
        split_group = hashlib.sha256(f"{SOURCE_ID}\0{case_id}".encode()).hexdigest()[:24]
        rows.append({
            "schema_version": "1",
            "id": f"{SOURCE_ID}/{case_id}",
            "source": {"dataset": SOURCE_ID, "revision": SOURCE_REVISION, "original_id": case_id,
                       "license": SOURCE_LICENSE, "redistribution": "vendored"},
            "split": "test",
            "surface": "text",
            "payload": {"content": text, "direction": "completion"},
            "truth": {
                "source_truth": "sensitive" if sensitive else "benign",
                "applicability": "in_scope",
                "expected_disposition": "detect_only" if sensitive else "allow",
                "categories": ["pii", "pii-positive" if sensitive else "pii-negative", SOURCE_ID,
                               *[f"pii-type:{item}" for item in sorted(raw_types)]],
                **({"spans": spans} if spans else {}),
            },
            "strata": {"language": language, "domain": category,
                       "hard_negative": category == "hard_negative", "split_group": split_group},
        })
        categories[category] += 1
        languages[language] += 1
    rows.sort(key=lambda row: row["id"])
    if len(rows) != 10_000:
        raise ValueError(f"expected 10000 Ylemis rows, found {len(rows)}")
    manifest = {
        "schema_version": "1", "dataset": SOURCE_ID, "revision": SOURCE_REVISION,
        "license": SOURCE_LICENSE, "source_sha256": source_digest, "cases": len(rows),
        "sensitive_cases": sum(bool(row["truth"].get("spans")) for row in rows),
        "benign_cases": sum(not row["truth"].get("spans") for row in rows),
        "entity_counts": dict(sorted(types.items())), "category_counts": dict(sorted(categories.items())),
        "language_counts": dict(sorted(languages.items())),
        "holdout_contract": "candidate pii-v4-008 frozen before acquisition; do not tune on this corpus",
    }
    return rows, manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows, manifest = normalize(args.input)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    manifest["output_sha256"] = sha256_file(args.output)
    args.output.with_suffix(".manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: manifest[key] for key in ("cases", "sensitive_cases", "benign_cases", "output_sha256")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
