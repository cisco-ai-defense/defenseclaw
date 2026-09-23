#!/bin/bash
# Wait for both Gemma 4 arms to settle, then score them on the real deterministic tier
# and compute recall at fixed FPR. Never scores an unsettled file.
set -u
G=$WORK/.system-one-data/outputs/gemma4jev
S2=$WORK/.system-one-data/outputs/s2
SRC=$WORK/defenseclaw-system-one
PY=$WORK/.system-one-venv/bin/python
mkdir -p "$G/s2/scores"
exec >>"$G/s2/finish.log" 2>&1

echo "===== $(date -u +%FT%TZ) finish_arms waiting for settlement"

ARM3=$G/s2/jevify-gemma4-26b-a4b.jsonl
ARM2=$G/s2/gemma-4-26b-a4b-it.jsonl

settled () { python3 -c "
import json,sys
try:
    m=json.load(open('$1.meta.json'))
except Exception:
    sys.exit(1)
sys.exit(0 if m.get('complete') is True and m.get('settled') is True else 1)
"; }

for i in $(seq 1 1440); do
  s3=no; s2s=no
  settled "$ARM3" && s3=yes
  settled "$ARM2" && s2s=yes
  echo "[$(date -u +%H:%M:%SZ)] arm3_settled=$s3 arm2_settled=$s2s rows3=$(wc -l < "$ARM3" 2>/dev/null) rows2=$(wc -l < "$ARM2" 2>/dev/null)"
  [ "$s3" = yes ] && [ "$s2s" = yes ] && break
  sleep 60
done

settled "$ARM3" || { echo "arm3 never settled"; exit 1; }
settled "$ARM2" || { echo "arm2 never settled"; exit 1; }
echo "both settled at $(date -u +%FT%TZ)"

cd "$SRC"
for pair in "arm3-jevify:$ARM3" "arm2-base-temp:$ARM2"; do
  LABEL=${pair%%:*}; PRED=${pair#*:}
  echo "--- scoring $LABEL"
  $PY benchmarks/scripts/benchmark_score_system_one.py \
    --cases "$S2/cases.jsonl" \
    --system-one-predictions "$PRED" \
    --deterministic-predictions "$S2/deterministic.jsonl" \
    --llm-predictions "$S2/gemma4-q2.jsonl" \
    --output "$G/s2/scores/score-$LABEL.json" \
    --culling-output "$G/s2/scores/culling-$LABEL.json" \
    --closure-output "$G/s2/scores/closure-$LABEL.json" \
    && echo "scored $LABEL" || echo "SCORING FAILED $LABEL"
done

echo "--- recall at fixed FPR (both arms plus the settled incumbents)"
$PY $WORK/.system-one-data/outputs/secjudge/code/recall_at_fpr.py \
  --cases "$S2/cases.jsonl" \
  --arm "arm3-jevify=$ARM3" \
  --arm "arm2-base-temp=$ARM2" \
  --stage s2 \
  --out "$G/s2/scores/recall-at-fpr-gemma4-arms.json" \
  && echo "recall-at-fpr done" || echo "RECALL AT FPR FAILED"

echo "===== FINISH DONE $(date -u +%FT%TZ)"
