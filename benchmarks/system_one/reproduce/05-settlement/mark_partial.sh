#!/bin/bash
# Mark the stopped open-jev-qwen-27b AWS shards as partial and superseded.
# Files are renamed, never deleted, and no meta is written for them: an absent meta is
# exactly what the settlement rule treats as unsettled, so the safest thing is to leave it
# absent rather than write one that says complete:false.
set -euo pipefail
S=$WORK/.system-one-data/outputs/openjev-qwen/s2/shards
SUF=partial-superseded-by-h200

total=0
declare -a counts
for i in 0 1 2 3; do
  src="$S/open-jev-qwen-27b-shard$i.jsonl"
  n=$(wc -l < "$src")
  counts[$i]=$n
  total=$((total + n))
  mv "$src" "$src.$SUF"
  [ -f "$S/open-jev-qwen-27b-shard$i.log" ] && \
    mv "$S/open-jev-qwen-27b-shard$i.log" "$S/open-jev-qwen-27b-shard$i.log.$SUF"
  echo "  shard$i: $n rows -> $(basename "$src.$SUF")"
done

cat > "$S/README-open-jev-qwen-27b.$SUF.txt" <<EOF
open-jev-qwen-27b -- AWS L40S run, STOPPED AND SUPERSEDED. NOT A RESULT.
========================================================================

These four .jsonl.$SUF files hold $total of the 30,310 required rows and are
NOT a settled run. They must not be merged, scored, published or spliced with any
other run's rows. There is deliberately NO .meta.json for any of them: under the
publication rule a settled figure needs meta complete:true plus an on-disk sha256
matching prediction_sha256, and an absent meta is unambiguously unsettled.

Per-shard rows at stop: shard0=${counts[0]} shard1=${counts[1]} shard2=${counts[2]} shard3=${counts[3]} (total $total)
Stopped at: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
Errors recorded before the stop: none (0 error rows across all four shards)

Why it was stopped
------------------
The arm was re-launched on 4x H200 and is roughly 8.3x faster: ~456 rows/min
against 48-58 rows/min here. The cause is structural, not clock speed. The
resident language-model backbone is 47.73 GiB, which does not fit the 44.39 GiB
usable on one L40S, so each replica had to be pipeline-sharded across two cards
and only one card computes at a time per replica -- two half-idle replicas on
four cards. A 140 GiB H200 holds the checkpoint whole, giving four real
single-card replicas.

These rows are discarded by decision, not lost to a fault. A run cannot be
spliced under settlement discipline, so restarting on the faster hardware was
still ~3.5 h cheaper than finishing here.

What remains valid
------------------
Two measurements in ../../validation/ are properties of the corpus and the
checkpoint rather than of this hardware, and still hold:

  audit-lengths-open-jev-qwen-27b.json
      All 30,310 rendered prompts under the 27B's own tokenizer: max 3,464
      tokens per candidate, ZERO above the pinned max_length of 4,096.
      (mean 522.2, p50 494, p95 1,168, p999 2,271)

  capacity-selftest-open-jev-qwen-27b.json
      L40S-specific: the 47.73 GiB vs 44.39 GiB placement measurement, the
      zero-offload assertion, and the eager-attention memory profile that
      forced candidate batch size 4. Retained as the record of why this
      hardware needed two cards per replica; the per-request latencies in it
      are L40S numbers and do not describe the H200 run.

Facts re-derived from the artifact here, which are hardware-independent and
should carry over: 320 F32 tensors, 160 resolved LoRA modules across all 64
layers (in_proj_qkv + out_proj in the 48 linear-attention layers, q/k/v/o_proj
in the 16 full-attention layers), 15,466,496 adapter + 5,121 head =
15,471,617 params, temperature 2.5343690298472983, 7 candidate sequences per
Q2 decision, and all three staged checksums verified matching.
EOF

echo "  wrote $S/README-open-jev-qwen-27b.$SUF.txt"
echo "=== nothing named like a settled artifact remains ==="
ls "$S" | grep "open-jev-qwen-27b" | sed 's/^/  /'
