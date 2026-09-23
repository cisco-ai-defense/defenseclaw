"""Ground the ETAs in measured shard metas rather than guesses."""

import json
from pathlib import Path

SJ = Path("$WORK/.system-one-data/outputs/secjudge")
plan = json.loads((SJ / "truncation" / "compute-plan.json").read_text())

groups: dict[str, dict] = {}
for m in sorted((SJ / "raw").glob("*.jsonl.meta.json")):
    d = json.loads(m.read_text())
    k = d["stage"]
    g = groups.setdefault(
        k,
        {
            "shards": 0,
            "decisions": 0,
            "forward": 0,
            "cache": 0,
            "tokens": 0,
            "max_wall": 0.0,
            "threads": d.get("threads"),
            "nshards": d.get("shards"),
            "ser": d.get("serialisation", "production_text"),
        },
    )
    g["shards"] += 1
    g["decisions"] += d["decisions"]
    g["forward"] += d.get("forward_passes") or d["decisions"]
    g["cache"] += d.get("cache_hits") or 0
    g["tokens"] += d.get("padded_tokens") or 0
    g["max_wall"] = max(g["max_wall"], d.get("wall_clock_s") or 0)

print("MEASURED (completed runs)")
print(
    f"{'run':<22}{'cfg':>8}{'ser':>16}{'decisions':>11}{'forward':>10}{'cache':>9}"
    f"{'padtok':>12}{'wall_min':>10}{'dec/s':>8}{'tok/s':>9}"
)
tok_rates = {}
for k, g in sorted(groups.items()):
    if g["shards"] != g["nshards"]:
        continue  # partial
    dps = g["decisions"] / g["max_wall"] if g["max_wall"] else 0
    tps = g["tokens"] / g["max_wall"] if g["max_wall"] else 0
    cfg = f"{g['nshards']}x{g['threads']}"
    tok_rates[k] = tps
    print(
        f"{k:<22}{cfg:>8}{g['ser']:>16}{g['decisions']:>11,}{g['forward']:>10,}{g['cache']:>9,}"
        f"{g['tokens']:>12,}{g['max_wall'] / 60:>10.1f}{dps:>8.2f}{tps:>9.0f}"
    )

# reference tok/s at 8x1 from the completed s2-C0 run; 12 shards is ~1.2x per the memory-bound
# scaling actually observed on this host (cores 10->14 of 16, not 8->12 of free cores)
ref = tok_rates.get("s2-C0")
print()
if ref:
    print(f"reference throughput (s2-C0, 8x1, contended): {ref:,.0f} padded tokens/s")
    r12 = ref * 1.2
    print(f"projected at 12x1 (1.2x, memory-bound not core-bound): {r12:,.0f} padded tokens/s")
    print()
    print("REMAINING STAGE ETAs (unique padded tokens / projected rate)")
    print(f"{'stage':<26}{'decisions':>11}{'unique':>10}{'unique_padtok':>15}{'eta_hours':>11}")
    remaining = [
        ("s2 C7 (parity cell)", "s2|C7"),
        ("toolcall-labels C0", "toolcall-labels|C0"),
        ("toolcall-labels C7", "toolcall-labels|C7"),
        ("s3 C0", "s3|C0"),
        ("s3 C7", "s3|C7"),
    ]
    total = 0.0
    for label, key in remaining:
        p = plan[key]
        eta = p["padded_tokens_unique"] / r12 / 3600
        total += eta
        print(
            f"{label:<26}{p['decisions']:>11,}{p['unique_texts']:>10,}"
            f"{p['padded_tokens_unique']:>15,}{eta:>11.2f}"
        )
    print(f"{'TOTAL':<26}{'':>11}{'':>10}{'':>15}{total:>11.2f}")
