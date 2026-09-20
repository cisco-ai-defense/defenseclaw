# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Apply an explicit enforcement lens without changing source truth labels."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

if __package__:
    from .benchmark_error_analysis import load_jsonl, sha256_file
else:
    from benchmark_error_analysis import load_jsonl, sha256_file


def expected_disposition(row: dict[str, Any], lens: str) -> str:
    truth = row["truth"]
    if row.get("surface") != "text":
        return str(truth["expected_disposition"])
    if truth.get("source_truth") == "benign":
        return "allow"
    if truth.get("source_truth") != "sensitive":
        return str(truth["expected_disposition"])
    if lens == "monitor":
        return "detect_only"
    if lens == "egress":
        return "block" if row.get("payload", {}).get("direction") == "completion" else "detect_only"
    raise ValueError(f"unsupported enforcement lens {lens!r}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--lens", choices=("monitor", "egress"), required=True)
    parser.add_argument("--allow-test", action="store_true")
    args = parser.parse_args()

    rows = load_jsonl(args.corpus)
    if not args.allow_test and any(row.get("split") == "test" for row in rows):
        parser.error("refusing to transform sealed test rows without --allow-test")
    changed = 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            disposition = expected_disposition(row, args.lens)
            if disposition != row["truth"]["expected_disposition"]:
                changed += 1
            transformed = json.loads(json.dumps(row))
            transformed["truth"]["expected_disposition"] = disposition
            transformed["truth"]["enforcement_lens"] = args.lens
            handle.write(json.dumps(transformed, sort_keys=True, separators=(",", ":")) + "\n")
    manifest = {
        "schema_version": "1",
        "lens": args.lens,
        "source_corpus_sha256": sha256_file(args.corpus),
        "output_sha256": sha256_file(args.output),
        "case_count": len(rows),
        "changed_disposition_count": changed,
    }
    args.output.with_suffix(".manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote {len(rows)} {args.lens} lens rows ({changed} dispositions changed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
