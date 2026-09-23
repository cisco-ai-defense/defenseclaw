"""Task 2: measure the 512-token truncation rate on every corpus, split unsafe vs benign.

Tokenizer-only pass (no model), so it is cheap and also yields the length distribution needed
to plan inference cost. Also measures the shipped load_secjudge() 512-CHARACTER slice.
"""

from __future__ import annotations

import argparse
import collections
import json
import statistics
import sys
from pathlib import Path

REPO = "$WORK/defenseclaw-system-one"
sys.path.insert(0, REPO)
sys.path.insert(0, REPO + "/benchmarks/scripts")
sys.path.insert(0, "$WORK/.system-one-data/outputs/secjudge/code")

from benchmark_inventory_system_one_sources import read_jsonl, truth_grade  # noqa: E402
from transformers import AutoTokenizer  # noqa: E402

from secjudge_serialize import case_decisions  # noqa: E402

MODEL_DIR = "$WORK/.system-one-data/models/secjudge-snapshot"
LIMIT = 512


def klass(case: dict) -> str:
    """unsafe/benign/diagnostic using the SAME grade semantics the scorer uses."""
    grade = truth_grade(case)
    if grade == "A":
        return "unsafe"
    if grade == "B":
        return "unsafe"
    if grade == "D":
        return "benign"
    return f"unscored_{grade}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", required=True)
    ap.add_argument("--stage", required=True)
    ap.add_argument("--variants", default="C7")
    ap.add_argument("--out", required=True)
    ap.add_argument("--per-decision-out", default=None)
    args = ap.parse_args()

    variants = args.variants.split(",")
    tok = AutoTokenizer.from_pretrained(MODEL_DIR)

    buckets: dict[tuple[str, str], dict] = collections.defaultdict(
        lambda: {
            "decisions": 0,
            "truncated_512_tokens": 0,
            "truncated_512_chars": 0,
            "over_8192_tokens": 0,
            "tokens": [],
            "chars": [],
        }
    )
    per_decision = open(args.per_decision_out, "w") if args.per_decision_out else None

    n_cases = 0
    for case in read_jsonl(Path(args.cases)):
        n_cases += 1
        cls = klass(case)
        case_id = str(case.get("id"))
        for event_index, variant, text, meta in case_decisions(case, variants):
            ids = tok(text, truncation=False, add_special_tokens=True)["input_ids"]
            n_tok = len(ids)
            n_char = len(text)
            # the shipped load_secjudge() slices to 512 CHARACTERS before tokenizing
            b = buckets[(variant, cls)]
            b["decisions"] += 1
            b["tokens"].append(n_tok)
            b["chars"].append(n_char)
            if n_tok > LIMIT:
                b["truncated_512_tokens"] += 1
            if n_char > LIMIT:
                b["truncated_512_chars"] += 1
            if n_tok > 8192:
                b["over_8192_tokens"] += 1
            if per_decision:
                per_decision.write(
                    json.dumps(
                        {
                            "case_id": case_id,
                            "event_index": event_index,
                            "context_variant": variant,
                            "class": cls,
                            "n_tokens": n_tok,
                            "n_chars": n_char,
                            "context_truncated_by_runner": bool(meta["truncated"]),
                        },
                        separators=(",", ":"),
                    )
                    + "\n"
                )
    if per_decision:
        per_decision.close()

    def summarize(b: dict) -> dict:
        toks = sorted(b["tokens"])
        n = len(toks)

        def pct(q):
            return toks[min(n - 1, int(q * n))] if n else None

        return {
            "decisions": b["decisions"],
            "truncated_512_tokens": b["truncated_512_tokens"],
            "truncation_rate_512_tokens": round(b["truncated_512_tokens"] / n, 6) if n else None,
            "truncated_512_chars_vendor_path": b["truncated_512_chars"],
            "truncation_rate_512_chars_vendor_path": round(b["truncated_512_chars"] / n, 6) if n else None,
            "over_8192_tokens": b["over_8192_tokens"],
            "tokens_mean": round(statistics.fmean(toks), 1) if n else None,
            "tokens_median": pct(0.5),
            "tokens_p90": pct(0.90),
            "tokens_p99": pct(0.99),
            "tokens_max": toks[-1] if n else None,
            "chars_mean": round(statistics.fmean(b["chars"]), 1) if n else None,
            # tokens actually fed at the 512 cap -> inference cost driver
            "padded_tokens_at_512": sum(min(t, LIMIT) for t in toks),
        }

    out = {
        "kind": "secjudge-truncation",
        "stage": args.stage,
        "cases_path": args.cases,
        "cases": n_cases,
        "variants": variants,
        "limit_tokens": LIMIT,
        "by_variant_class": {f"{v}|{c}": summarize(b) for (v, c), b in sorted(buckets.items())},
    }
    # roll up per variant across classes
    for v in variants:
        agg = {
            "decisions": 0,
            "truncated_512_tokens": 0,
            "truncated_512_chars": 0,
            "over_8192_tokens": 0,
            "tokens": [],
            "chars": [],
        }
        for (vv, _c), b in buckets.items():
            if vv != v:
                continue
            agg["decisions"] += b["decisions"]
            agg["truncated_512_tokens"] += b["truncated_512_tokens"]
            agg["truncated_512_chars"] += b["truncated_512_chars"]
            agg["over_8192_tokens"] += b["over_8192_tokens"]
            agg["tokens"] += b["tokens"]
            agg["chars"] += b["chars"]
        out.setdefault("by_variant", {})[v] = summarize(agg)

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
    print(json.dumps(out["by_variant"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
