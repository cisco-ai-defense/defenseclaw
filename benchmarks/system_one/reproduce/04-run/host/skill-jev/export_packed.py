"""Re-export System One inputs using the structured packing, not raw skill text.

Raw text produced inverted, length-correlated answers. That was a framing result rather
than a verdict on the model, so this rebuilds the state the way the packing module
intends: files collected and role-classified, ordered by priority, bounded, and with
untrusted content neutralised. If the model still fails to separate here, the framing
excuse is gone.
"""

import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, "$WORK/skill-scanner")

from evals.lib.cross_tool import CleanCorpus, read_rows  # noqa: E402
from evals.system_one.packing import pack_skill  # noqa: E402

CLEAN = Path(os.path.expanduser("~/.skill-scanner-data/clean"))
B = Path(os.path.expanduser("~/.skill-scanner-data/xtool/jev"))
CORPUS = "msb-source-disjoint"

# 16,384-token prompt limit, guarded at a pessimistic 2 bytes per token. Oversize is
# rejected rather than truncated: a model that answers about content it never saw is a
# fail-open, not a low score.
BUDGET = 24_000
HARD_REJECT = 28_000

corpus = CleanCorpus.load(CLEAN, CORPUS)
by_id = {r.record_id: r for r in corpus.records}
rows = [r for r in read_rows(B / "ours-sd.jsonl") if r.capability_ok and not r.error]

out = B / "inputs-packed-sd.jsonl"
tiers: dict[str, int] = {}
written = 0
with out.open("w") as handle:
    for row in rows:
        record = by_id.get(row.record_id)
        if record is None:
            continue
        packed = pack_skill(record.directory, budget_bytes=BUDGET, hard_reject_bytes=HARD_REJECT)
        tier = getattr(packed.tier, "value", str(packed.tier))
        tiers[tier] = tiers.get(tier, 0) + 1
        if tier == "oversize":
            continue
        # A structured state: one entry per file with its role, in priority order.
        state = {
            "skill": {
                "files": [
                    {"path": f.relative_path, "role": getattr(f.role, "value", str(f.role)), "text": f.text}
                    for f in packed.files
                ],
                "file_count": len(packed.files),
                "truncated": bool(packed.truncated),
            },
            "deterministic": {"fired_categories": list((row.extra or {}).get("categories") or [])},
        }
        blob = json.dumps(state, sort_keys=True)
        handle.write(json.dumps({
            "record_id": row.record_id,
            "state": state,
            "fired_categories": list((row.extra or {}).get("categories") or []),
            "tier": tier,
            "state_sha256": hashlib.sha256(blob.encode()).hexdigest(),
        }, sort_keys=True) + "\n")
        written += 1

print("wrote %s (%d records)" % (out, written))
print("packing tiers:", tiers)
