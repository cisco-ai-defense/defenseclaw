#!/usr/bin/env python3
"""Settle s1-n1000/jev-context.jsonl without rewriting provenance that is already published.

The arm's meta predates the schema generation that added `complete` / `actual_input_tokens`
(it carries `input_tokens` instead), so a consumer keyed on `complete` cannot verify it. The
file itself is fine: the on-disk sha256 equals meta.prediction_sha256 and the row count equals
meta.requests.

Rewriting the meta in place is the wrong fix, because that meta is ALREADY PUBLISHED in the
private predictions repo with its sha256 recorded in that repo's MANIFEST.json - editing it
locally would silently put the published manifest digest out of agreement with the file. This
writes an additive sidecar instead, at a new path, carrying the explicit `complete: true` a
consumer needs plus the evidence for it.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

DATA = Path("$WORK/.system-one-data/outputs")
PRED = DATA / "s1-n1000/jev-context.jsonl"
META = Path(str(PRED) + ".meta.json")
SIDECAR = Path(str(PRED) + ".settlement.json")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    meta = json.loads(META.read_text())
    digest = sha256_file(PRED)
    rows = sum(1 for _ in PRED.open("rb"))
    errors: dict[str, int] = {}
    with PRED.open() as handle:
        for line in handle:
            row = json.loads(line)
            code = row.get("error_code") or "none"
            errors[code] = errors.get(code, 0) + 1

    digest_ok = digest == meta.get("prediction_sha256")
    rows_ok = rows == meta.get("requests")
    no_errors = set(errors) <= {"none"}
    complete = bool(digest_ok and rows_ok and no_errors)

    sidecar = {
        "kind": "defenseclaw-system-one-run-settlement",
        "schema_version": "1",
        "prediction": str(PRED),
        "meta": str(META),
        "complete": complete,
        "why_a_sidecar": (
            "the original meta predates the schema generation that added the `complete` key and is "
            "already published in the private predictions repo with its sha256 recorded in that "
            "repo's MANIFEST.json; editing it in place would put the published manifest digest out "
            "of agreement with the file, so this settlement record is additive"),
        "evidence": {
            "prediction_sha256_on_disk": digest,
            "prediction_sha256_in_meta": meta.get("prediction_sha256"),
            "digest_matches": digest_ok,
            "rows_on_disk": rows,
            "requests_in_meta": meta.get("requests"),
            "rows_match_requests": rows_ok,
            "error_census": dict(sorted(errors.items())),
            "no_error_rows": no_errors,
        },
        "meta_fields_present": sorted(meta.keys()),
        "meta_fields_missing_vs_current_schema": sorted(
            {"complete", "actual_input_tokens", "attempted_provider_calls", "reserved_input_tokens",
             "run_plan_sha256"} - set(meta.keys())),
        "input_tokens_field_used": "input_tokens" if "input_tokens" in meta else None,
        "input_tokens": meta.get("input_tokens") or meta.get("actual_input_tokens"),
        "model": meta.get("model"),
        "model_revision": meta.get("model_revision"),
        "run_id": meta.get("run_id"),
        "contexts": meta.get("contexts"),
        "instructions": meta.get("instructions"),
        "questions": meta.get("questions"),
        "estimated_usd": meta.get("estimated_usd"),
    }
    SIDECAR.write_text(json.dumps(sidecar, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: sidecar[k] for k in
                      ("complete", "evidence", "meta_fields_missing_vs_current_schema")},
                     indent=1, sort_keys=True))
    print(f"wrote {SIDECAR}")
    return 0 if complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
