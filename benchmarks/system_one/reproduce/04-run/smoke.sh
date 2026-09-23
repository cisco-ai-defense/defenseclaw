#!/bin/bash
# 20-case smoke: validate the /v1/systemone contract end-to-end for all three adapters.
set -uo pipefail
cd $WORK/defenseclaw-system-one
PY=$WORK/.system-one-venv/bin/python
O=$WORK/.system-one-data/outputs
CASES=$O/s2/cases-jevsmoke20.jsonl
mkdir -p "$O/openjev-qwen/smoke" "$O/nimble/smoke"

run() { # name port outdir revision
  local name=$1 port=$2 out=$3 rev=$4
  echo "=== $name on :$port ==="
  $PY benchmarks/scripts/benchmark_run_system_one.py \
    --cases "$CASES" \
    --context C7 --instruction I3 --question Q2 \
    --endpoint "http://127.0.0.1:${port}/v1/systemone" \
    --model "$name" --model-revision "$rev" \
    --instruction-format structured \
    --api-key-env SYSONE_NO_KEY \
    --run-id "smoke-${name}" \
    --output "${out}/${name}.jsonl" \
    --concurrency 4 --timeout 300 --retries 1 \
    --max-input-tokens 4000000000 --max-calls 1000000 2>&1 | tail -3
}

run open-jev-qwen-2b  8802 "$O/openjev-qwen/smoke" "openjev-qwen-2b-adapter-2d23935b" &
P2=$!
run open-jev-qwen-9b  8801 "$O/openjev-qwen/smoke" "openjev-qwen-9b-adapter-f85650a8" &
P9=$!
run bespoke-nimble-9b 8803 "$O/nimble/smoke"      "nimble-9b-adapter-ba7e28ac" &
PN=$!
wait $P2 $P9 $PN

echo "=== error / action summary ==="
for f in "$O/openjev-qwen/smoke/open-jev-qwen-2b.jsonl" "$O/openjev-qwen/smoke/open-jev-qwen-9b.jsonl" "$O/nimble/smoke/bespoke-nimble-9b.jsonl"; do
  [ -f "$f" ] || { echo "MISSING $f"; continue; }
  $PY - "$f" <<'PY'
import json, sys, collections
rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
acts = collections.Counter(r["action"] for r in rows)
errs = collections.Counter(r.get("error_code","") for r in rows if r.get("error_code"))
lat = sorted(r["duration_ms"] for r in rows)
tok = [r["input_tokens"] for r in rows]
print(f"{sys.argv[1].split('/')[-1]:28s} n={len(rows):5d} actions={dict(acts)} errors={dict(errs)}")
if rows:
    print(f"    p50={lat[len(lat)//2]:.0f}ms p95={lat[int(len(lat)*0.95)]:.0f}ms mean_in_tok={sum(tok)/len(tok):.0f}")
    s = rows[0]
    print(f"    sample answers={s.get('answers')}")
    print(f"    sample probs={ {k:round(v,4) for k,v in list(s.get('probabilities',{}).items())} }")
PY
done
