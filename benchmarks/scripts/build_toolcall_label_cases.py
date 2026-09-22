"""Part C: turn the 9,999 gpt-oss-120b tool-call labels into a case-v1 corpus for Q4.

Q4 is the two-lane question: it asks intrinsic_danger (how harmful is this call on its own) and
serves_intent (does it advance the stated request) separately, then a disposition. These labels
are its natural evaluation set because every row carries a labeller's INTRINSIC verdict to
compare intrinsic_danger against, plus a synthesized intent to feed serves_intent.

strata carries the labeller's verdicts so scoring can join Q4's per-Noul answers to them.
Grade C: the comparison is agreement with a labeller, never accuracy against truth.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

LABEL_REVISION = "toolcall-security-intent-v1"
SOURCE_DATASET = "robustintelligence/augur_unsafe_tool_input_eval"
BATCH_PROMPT = re.compile(r"^TOOL:\s*(.*?)\nARGUMENTS:\n(.*?)\n\nReply with exactly", re.S | re.M)
ID_SAFE = re.compile(r"[^A-Za-z0-9._/-]")
SEV_TO_CATEGORY = {"high": "high_impact", "medium": "consequential", "low": "low_impact", "none": "no_impact"}


def load_calls(batch_in: Path) -> dict[str, tuple[str, str]]:
    calls: dict[str, tuple[str, str]] = {}
    with batch_in.open(encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            rec = json.loads(line)
            m = BATCH_PROMPT.search(rec["body"]["messages"][0]["content"])
            if m:
                calls[str(rec["custom_id"])] = (m.group(1).strip(), m.group(2))
    return calls


def parse_args_value(raw: str) -> Any:
    try:
        value = json.loads(raw)
    except Exception:
        return raw
    return value if isinstance(value, (dict, list)) else raw


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--labels", type=Path,
                   default=Path("/home/ubuntu/.system-one-data/labels-hf/data/toolcall-labels-v1.jsonl"))
    p.add_argument("--batch-in", type=Path,
                   default=Path("/home/ubuntu/.system-one-data/labeling/toolcall-labels-in.jsonl"))
    p.add_argument("--output", type=Path,
                   default=Path("/home/ubuntu/.system-one-data/outputs/toolcall-labels/cases.jsonl"))
    p.add_argument("--manifest", type=Path,
                   default=Path("/home/ubuntu/.system-one-data/outputs/toolcall-labels/cases.manifest.json"))
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--split", default="development", choices=["smoke", "development", "validation", "test"])
    args = p.parse_args()

    calls = load_calls(args.batch_in)
    rows: list[dict[str, Any]] = []
    with args.labels.open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                rows.append(json.loads(line))
    rows.sort(key=lambda r: r["custom_id"])

    stats: Counter[str] = Counter()
    written = 0
    missing = 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as out:
        for r in rows:
            if args.limit and written >= args.limit:
                break
            cid = r["custom_id"]
            if cid not in calls:
                missing += 1
                continue
            tool, arg_text = calls[cid]
            positive = r["record_class"] == "positive"
            case = {
                "schema_version": "1",
                "id": f"toolcall-label-{ID_SAFE.sub('-', cid)}",
                "split": args.split,
                "surface": "stateful",
                "source": {
                    "dataset": SOURCE_DATASET,
                    "revision": LABEL_REVISION,
                    "original_id": cid,
                },
                "payload": {
                    # the synthesized intent; C0 drops it, C7 renders it as SESSION_USER_INTENT
                    "content": r["intent"],
                    "events": [
                        {
                            "tool_name": tool,
                            "args": parse_args_value(arg_text),
                            "dialect": "structured",
                            "outcome": "unknown",
                        }
                    ],
                },
                "truth": {
                    "applicability": "in_scope",
                    "source_truth": "malicious" if positive else "benign",
                    "deterministic_truth": (
                        "deterministic_malicious" if (positive and r["intrinsic"]) else "contextual_or_dual_use"
                    ),
                    "expected_disposition": "detect_only" if positive else "allow",
                    # provenance split is a dataset label and INTRINSIC is model-adjudicated,
                    # so neither is a high-confidence per-row human verdict
                    "label_confidence": "low",
                    "label_source": "openai.gpt-oss-120b-1:0",
                    "categories": [r["category"]] if positive else [],
                },
                "strata": {
                    "record_class": r["record_class"],
                    "domain": tool,
                    "hard_negative": bool(not positive and r["intrinsic"]),
                    "split_group": f"toolcall-label:{cid}",
                    # the labeller verdicts Q4 is being compared against
                    "label_intrinsic": bool(r["intrinsic"]),
                    "label_category": r["category"],
                    "label_severity": r["severity"],
                    "label_intent_present": bool(r["intent"]),
                },
            }
            out.write(json.dumps(case, sort_keys=True, separators=(",", ":")) + "\n")
            written += 1
            stats[r["record_class"]] += 1
            stats[f"intrinsic={'yes' if r['intrinsic'] else 'no'}"] += 1
            stats[f"category={r['category']}"] += 1
            stats[f"severity={r['severity']}"] += 1
            stats[f"intent={'present' if r['intent'] else 'empty'}"] += 1

    manifest = {
        "schema_version": "1",
        "kind": "defenseclaw-toolcall-label-cases",
        "cases": written,
        "decisions": written,
        "missing_call_text": missing,
        "split": args.split,
        "counts": dict(sorted(stats.items())),
        "source": {
            "dataset": SOURCE_DATASET,
            "labels": str(args.labels),
            "label_model": "openai.gpt-oss-120b-1:0",
            "label_version": LABEL_REVISION,
            "label_grade": "C",
        },
        "purpose": (
            "Evaluation set for Q4 (intrinsic_danger + serves_intent + disposition). One event "
            "per case, so C0 sees the call alone and C7 adds the synthesized intent in "
            "production_text framing - the contrast is intent-present vs intent-absent on "
            "identical calls, not 7 prior calls vs none."
        ),
        "caveat": (
            "Grade C. strata.label_intrinsic is openai.gpt-oss-120b-1:0's verdict, not human "
            "truth; strata.record_class is the dataset provenance split, also unverified per row. "
            "Any Q4 score against this corpus is agreement with a labeller."
        ),
    }
    args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"cases": written, "missing_call_text": missing, "counts": manifest["counts"]},
                     indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
