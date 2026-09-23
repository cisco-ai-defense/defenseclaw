#!/bin/bash
# Measure warm single-replica and two-replica throughput on the H200.
# Kernels are already JIT-cached by this point, so these rates exclude Triton warmup.
set -uo pipefail
R="$HOME/sysone"
cd "$R/agree"
mkdir -p tp

run_one() {  # port, cases, out, runid
  "$R/venv-ojev/bin/python" "$R/benchmark_run_system_one.py" \
    --cases "$2" \
    --contexts-config cfg/contexts-v1.json \
    --questions-config cfg/questions-v1.json \
    --prediction-schema cfg/system-one-prediction-v1.schema.json \
    --context C7 --instruction I3 --question Q2 --instruction-format structured \
    --endpoint "http://127.0.0.1:$1/v1/systemone" \
    --model open-jev-qwen-2b \
    --model-revision 3076462e6356412082e79af909227b39b2863b90def79155ca0821aa506b7ded \
    --run-id "$4" --output "$3" --concurrency 4 --timeout 300 > "tp/$4.log" 2>&1
}

echo "=== A) warm single replica, 507 requests ==="
rm -f tp/warm1.jsonl*
S=$(date +%s); run_one 8791 s2-cases-agree.jsonl tp/warm1.jsonl tp-warm1; E=$(date +%s)
N=$(wc -l < tp/warm1.jsonl)
A_SEC=$((E-S)); A_RATE=$(python3 -c "print(f'{$N/$A_SEC*60:.1f}')")
echo "warm_1replica: rows=$N seconds=$A_SEC rows_per_min=$A_RATE"

echo "=== B) two replicas, stride-split halves ==="
python3 - <<'PY'
rows = open('s2-cases-agree.jsonl').readlines()
open('tp/half0.jsonl','w').writelines(rows[0::2])
open('tp/half1.jsonl','w').writelines(rows[1::2])
PY
rm -f tp/two0.jsonl* tp/two1.jsonl*
S=$(date +%s)
run_one 8791 tp/half0.jsonl tp/two0.jsonl tp-two0 &
P0=$!
run_one 8792 tp/half1.jsonl tp/two1.jsonl tp-two1 &
P1=$!
wait $P0; wait $P1
E=$(date +%s)
N2=$(( $(wc -l < tp/two0.jsonl) + $(wc -l < tp/two1.jsonl) ))
B_SEC=$((E-S)); B_RATE=$(python3 -c "print(f'{$N2/$B_SEC*60:.1f}')")
echo "warm_2replica: rows=$N2 seconds=$B_SEC rows_per_min=$B_RATE"

echo "=== projections for s3 = 100001 requests ==="
python3 -c "
for label, rate in [('1 replica', $A_RATE), ('2 replicas', $B_RATE)]:
    m = 100001/rate
    print(f'{label:12} {rate:8.1f} rows/min -> {m:8.1f} min = {m/60:6.2f} h')
"
