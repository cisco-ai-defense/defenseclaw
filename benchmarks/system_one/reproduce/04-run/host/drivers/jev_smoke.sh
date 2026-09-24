#!/bin/bash
# 20-case smoke against hosted Jev to check reachability and remaining budget
# before committing to the full intent-real arms. Jev is the ONE backend not
# re-run on the separation reversal, and "three of four backends" is the last
# named limitation on that headline result.
set -u
I=$WORK/.system-one-data/outputs/intent-real
PY=$WORK/.system-one-venv/bin/python
set -a; . $WORK/.config/defenseclaw/system-one.env; set +a
cd $WORK/defenseclaw-system-one || exit 1
head -20 "$I/cases.jsonl" > /tmp/jev-smoke-cases.jsonl
"$PY" benchmarks/scripts/benchmark_run_system_one.py \
  --cases /tmp/jev-smoke-cases.jsonl \
  --context C7 --instruction I3 --question Q2 \
  --endpoint "https://api.typesafe.ai/v1/systemone" \
  --model jev --model-revision jev-1.13.0 \
  --instruction-format structured \
  --run-id "jev-smoke-intent-real" \
  --output /tmp/jev-smoke.jsonl \
  --concurrency 4 --timeout 60 --retries 1 2>&1 | tail -6
echo "--- rows / errors ---"
wc -l < /tmp/jev-smoke.jsonl 2>/dev/null || echo 0
grep -c error_code /tmp/jev-smoke.jsonl 2>/dev/null || echo 0
python3 -c "
import json
try:
    d=json.load(open('/tmp/jev-smoke.jsonl.meta.json'))
    print('complete:', d.get('complete'), 'requests:', d.get('requests'), 'usd:', d.get('estimated_usd'))
except Exception as e:
    print('no meta:', type(e).__name__)
"
