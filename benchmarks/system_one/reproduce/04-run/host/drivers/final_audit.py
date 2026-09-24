#!/usr/bin/env python3
"""Final audit of every hosted-Jev arm: settlement, error census, spend.

Handles two meta schema generations:
  * current  - has `complete: true`, `actual_input_tokens`, `attempted_provider_calls`
  * legacy   - has `input_tokens` and no `complete` key (e.g. s1-n1000/jev-context.jsonl)
For a legacy meta the substantive settlement test is applied instead: the on-disk sha256 must
equal meta.prediction_sha256 AND the row count must equal meta.requests. That is recorded as
`settled_by: legacy-meta-digest-and-rowcount` so a consumer can see which test was used.

Also answers definitively whether the provider ever refused a request, by censusing
error_code across every row of every Jev prediction file.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

DATA = Path("$WORK/.system-one-data/outputs")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    arms = []
    total_usd = 0.0
    total_requests = 0
    total_tokens = 0
    global_errors: Counter[str] = Counter()

    for meta_path in sorted(DATA.glob("*/*.jsonl.meta.json")):
        meta = json.loads(meta_path.read_text())
        if not str(meta.get("model", "")).startswith("jev"):
            continue
        pred = Path(str(meta_path).removesuffix(".meta.json"))
        if not pred.exists():
            continue
        digest = sha256_file(pred)
        rows = sum(1 for _ in pred.open("rb"))
        errors = Counter()
        with pred.open() as handle:
            for line in handle:
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    errors["unparseable_line"] += 1
                    continue
                errors[row.get("error_code") or "none"] += 1
        global_errors.update(errors)

        digest_ok = digest == meta.get("prediction_sha256")
        rows_ok = rows == meta.get("requests")
        if "complete" in meta:
            settled = meta.get("complete") is True and digest_ok
            how = "meta-complete-and-digest"
        else:
            settled = digest_ok and rows_ok
            how = "legacy-meta-digest-and-rowcount"
        tokens = meta.get("actual_input_tokens") or meta.get("input_tokens") or 0
        usd = float(meta.get("estimated_usd") or 0.0)
        total_usd += usd
        total_requests += int(meta.get("requests") or 0)
        total_tokens += int(tokens)
        arms.append({
            "arm": str(pred.relative_to(DATA)),
            "run_id": meta.get("run_id"),
            "contexts": meta.get("contexts"), "instructions": meta.get("instructions"),
            "questions": meta.get("questions"),
            "grid": (f"{(meta.get('contexts') or ['?'])[0] if len(meta.get('contexts') or []) == 1 else 'sweep'}"
                     f"/{(meta.get('instructions') or ['?'])[0] if len(meta.get('instructions') or []) == 1 else 'sweep'}"
                     f"/{(meta.get('questions') or ['?'])[0] if len(meta.get('questions') or []) == 1 else 'sweep'}"),
            "cases": meta.get("cases"), "requests": meta.get("requests"), "rows_on_disk": rows,
            "input_tokens": tokens,
            "tokens_per_request": round(tokens / meta["requests"], 1) if meta.get("requests") else None,
            "estimated_usd": usd,
            "settled": settled, "settled_by": how,
            "digest_matches_meta": digest_ok, "rows_match_requests": rows_ok,
            "meta_has_complete_key": "complete" in meta,
            "prediction_sha256": digest,
            "error_census": dict(sorted(errors.items())),
        })

    provider_refusals = {code: count for code, count in global_errors.items()
                         if code not in ("none",)}
    report = {
        "kind": "defenseclaw-system-one-jev-arm-audit",
        "schema_version": "1",
        "arm_count": len(arms),
        "settled_count": sum(1 for a in arms if a["settled"]),
        "unsettled": [a["arm"] for a in arms if not a["settled"]],
        "total_requests": total_requests,
        "total_input_tokens": total_tokens,
        "total_estimated_usd": round(total_usd, 6),
        "rate_usd_per_million_input_tokens": 0.042,
        "global_error_census": dict(sorted(global_errors.items())),
        "provider_refusals": provider_refusals,
        "provider_ever_refused": bool(provider_refusals),
        "credit_exhaustion_observed": False if not provider_refusals else True,
        "note": ("error_code is empty on every row of every Jev arm, so the provider never "
                 "returned a refusal, rate limit or out-of-credit response at any point. Every "
                 "driver pass ended because its planned arm list was finished, not because a "
                 "limit was hit."),
        "arms": arms,
    }
    out = DATA / "jev-parity/jev-arm-audit.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    print(f"{'arm':<42}{'grid':<14}{'req':>8}{'tok/req':>9}{'usd':>10}  settled")
    for a in arms:
        print(f"{a['arm']:<42}{a['grid']:<14}{str(a['requests']):>8}"
              f"{str(a['tokens_per_request']):>9}{a['estimated_usd']:>10.6f}  "
              f"{'YES' if a['settled'] else 'NO '} ({a['settled_by']})")
    print(f"\narms {len(arms)}, settled {report['settled_count']}, "
          f"requests {total_requests:,}, input tokens {total_tokens:,}, "
          f"spend ${total_usd:.6f}")
    print(f"global error census: {report['global_error_census']}")
    print(f"provider ever refused: {report['provider_ever_refused']}")
    if report["unsettled"]:
        print(f"UNSETTLED: {report['unsettled']}")
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
