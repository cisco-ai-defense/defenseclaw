#!/usr/bin/env python3
"""Verify prediction files are settled: meta complete: true AND on-disk sha256 == meta.prediction_sha256."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

DATA = Path("$WORK/.system-one-data/outputs")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main(rels: list[str]) -> int:
    bad = 0
    for rel in rels:
        path = DATA / rel
        meta_path = DATA / (rel + ".meta.json")
        if not path.exists():
            print(f"{rel:38s} MISSING FILE")
            bad += 1
            continue
        if not meta_path.exists():
            print(f"{rel:38s} NO META")
            bad += 1
            continue
        meta = json.loads(meta_path.read_text())
        complete = meta.get("complete")
        sha_ok = sha256_file(path) == meta.get("prediction_sha256")
        req = meta.get("requests")
        tok = meta.get("actual_input_tokens")
        tpr = round(tok / req, 1) if (req and tok) else None
        status = "OK" if (complete is True and sha_ok) else "NOT SETTLED"
        if status != "OK":
            bad += 1
        print(
            f"{rel:38s} {status:12s} complete={complete} sha_ok={sha_ok} "
            f"cases={meta.get('cases')} req={req} tok/req={tpr} "
            f"C={meta.get('contexts')} I={meta.get('instructions')} Q={meta.get('questions')} "
            f"usd={meta.get('estimated_usd')}"
        )
    print(f"\n{len(rels) - bad}/{len(rels)} settled")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
