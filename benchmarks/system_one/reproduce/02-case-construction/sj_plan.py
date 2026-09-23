"""Exact compute budget: padded-token totals per stage/variant + deduplication potential.

Identical input text under a deterministic fp32 forward pass gives an identical result, so a
sha256 cache over serialised text is exact, not an approximation.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPO = "$WORK/defenseclaw-system-one"
sys.path.insert(0, REPO)
sys.path.insert(0, REPO + "/benchmarks/scripts")
sys.path.insert(0, "$WORK/.system-one-data/outputs/secjudge/code")

from benchmark_inventory_system_one_sources import read_jsonl  # noqa: E402
from transformers import AutoTokenizer  # noqa: E402

from secjudge_serialize import case_decisions  # noqa: E402

MODEL_DIR = "$WORK/.system-one-data/models/secjudge-snapshot"
tok = AutoTokenizer.from_pretrained(MODEL_DIR)
DATA = Path("$WORK/.system-one-data/outputs")

STAGES = [
    ("s2", DATA / "s2/cases.jsonl"),
    ("s3", DATA / "s3/cases.jsonl"),
    ("intent-real", DATA / "intent-real/cases.jsonl"),
    ("toolcall-labels", DATA / "toolcall-labels/cases.jsonl"),
]

out = {}
for stage, path in STAGES:
    for variant in ["C0", "C7"]:
        seen: dict[str, int] = {}
        n = 0
        tokens_total = 0
        tokens_unique = 0
        for case in read_jsonl(path):
            for _ei, _v, text, _m in case_decisions(case, [variant]):
                n += 1
                h = hashlib.sha256(text.encode()).hexdigest()
                L = min(len(tok(text, truncation=False)["input_ids"]), 512)
                tokens_total += L
                if h not in seen:
                    seen[h] = L
                    tokens_unique += L
        out[f"{stage}|{variant}"] = {
            "decisions": n,
            "unique_texts": len(seen),
            "dedup_ratio": round(len(seen) / n, 4) if n else None,
            "padded_tokens_total": tokens_total,
            "padded_tokens_unique": tokens_unique,
            "token_saving_from_dedup": round(1 - tokens_unique / tokens_total, 4) if tokens_total else None,
        }
        print(json.dumps({f"{stage}|{variant}": out[f"{stage}|{variant}"]}), flush=True)

Path("$WORK/.system-one-data/outputs/secjudge/truncation/compute-plan.json").write_text(
    json.dumps(out, indent=2, sort_keys=True) + "\n"
)
# throughput reference measured on this host, fp32, 8 threads
REF_TOKENS_PER_S = 876.0
total_unique = sum(v["padded_tokens_unique"] for v in out.values())
print(
    json.dumps(
        {
            "total_padded_tokens_all_stages_both_variants": sum(v["padded_tokens_total"] for v in out.values()),
            "total_unique": total_unique,
            "est_hours_at_876_tok_per_s_one_process": round(total_unique / REF_TOKENS_PER_S / 3600, 2),
        },
        indent=2,
    )
)
