#!/bin/bash
# Fan out four arms, one per H200 card, each a single replica over its whole lane.
#   card 0  open-jev-qwen-2b     s3  100,001  venv-ojev   sdpa
#   card 1  open-jev-qwen-9b     s3  100,001  venv-ojev   sdpa
#   card 2  bespoke-nimble-9b    s3  100,001  venv-nimble sdpa
#   card 3  kev-9b               s2   30,310  venv-kev    eager (its own loader)
#
# Each arm asserts its imports before serving, because Lightning's studio-setup can
# complete after ssh works and silently remove packages from a live venv. Failing in the
# first second is the whole point.
set -uo pipefail
R="$HOME/sysone"; CK="$R/checkpoints"; export HF_HOME="$R/hf"
cd "$R/agree"

echo "=== free the cards: stop the finished 27B servers ==="
for p in 8821 8822 8823 8824; do
  PID=$(ss -ltnp 2>/dev/null | grep "127.0.0.1:$p " | grep -o 'pid=[0-9]*' | cut -d= -f2 | head -1)
  [ -n "${PID:-}" ] && { kill "$PID" 2>/dev/null; echo "stopped :$p (pid $PID)"; }
done
sleep 8
nvidia-smi --query-gpu=index,memory.used --format=csv,noheader

assert_imports() {  # venv, modules...
  local v=$1; shift
  "$R/$v/bin/python" -c "
import importlib, sys
for m in '$*'.split():
    importlib.import_module(m)
print('imports OK: $*')
" || { echo "ABORT: import assertion failed for $v ($*)"; return 1; }
}

wait_ready() {  # port
  for _ in $(seq 300); do
    curl -s -m 3 "http://127.0.0.1:$1/health" 2>/dev/null | grep -q ready && { echo "  :$1 ready"; return 0; }
    sleep 5
  done
  echo "  :$1 NEVER READY"; return 1
}

start_runner() {  # arm, cases, port, venv, revision, runid, outdir
  local arm=$1 cases=$2 port=$3 venv=$4 rev=$5 runid=$6 od=$7
  mkdir -p "$od"
  date +%s > "$od/t_start"
  setsid nohup "$R/$venv/bin/python" "$R/benchmark_run_system_one.py" \
    --cases "$cases" \
    --contexts-config cfg/contexts-v1.json \
    --questions-config cfg/questions-v1.json \
    --prediction-schema cfg/system-one-prediction-v1.schema.json \
    --context C7 --instruction I3 --question Q2 --instruction-format structured \
    --endpoint "http://127.0.0.1:$port/v1/systemone" \
    --model "$arm" --model-revision "$rev" \
    --run-id "$runid" --output "$od/$arm-shard0.jsonl" \
    --concurrency 4 --timeout 600 \
    > "$R/logs/run-$arm.log" 2>&1 &
  echo "  runner $arm -> :$port  out=$od"
}

echo "=== card 0: open-jev-qwen-2b on s3 ==="
assert_imports venv-ojev jev jev.server jev.serving transformers peft fla || exit 1
CUDA_VISIBLE_DEVICES=0 PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True \
  setsid nohup "$R/venv-ojev/bin/python" "$R/openjev_serve.py" \
  --checkpoint "$CK/open-jev-2b/package/checkpoint" \
  --name open-jev-qwen-2b --repo-id ZefanCai/Open-Jev-2B \
  --batch-size 32 --no-prefix-cache --device cuda:0 --host 127.0.0.1 --port 8831 \
  > "$R/logs/serve-2b-s3.log" 2>&1 &

echo "=== card 1: open-jev-qwen-9b on s3 ==="
CUDA_VISIBLE_DEVICES=1 PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True \
  setsid nohup "$R/venv-ojev/bin/python" "$R/openjev_serve.py" \
  --checkpoint "$CK/open-jev-9b/package/checkpoint" \
  --name open-jev-qwen-9b --repo-id ZefanCai/Open-Jev-9B \
  --batch-size 32 --no-prefix-cache --device cuda:0 --host 127.0.0.1 --port 8832 \
  > "$R/logs/serve-9b-s3.log" 2>&1 &

echo "=== card 2: bespoke-nimble-9b on s3 ==="
assert_imports venv-nimble transformers peft || exit 1
CUDA_VISIBLE_DEVICES=2 PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True \
  setsid nohup "$R/venv-nimble/bin/python" "$R/nimble_shim.py" \
  --checkpoint "$CK/nimble-9b" --name bespoke-nimble-9b --max-length 8192 \
  --device cuda:0 --host 127.0.0.1 --port 8833 \
  > "$R/logs/serve-nimble-s3.log" 2>&1 &

echo "=== card 3: kev-9b on s2 ==="
assert_imports venv-kev kev kev.api kev.serve kev.model transformers peft || exit 1
CUDA_VISIBLE_DEVICES=3 PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True \
  setsid nohup "$R/venv-kev/bin/python" "$R/serve_kev.py" \
  --kev-src "$R/kev-src" --adapter-path "$CK/kev-9b" \
  --name kev-9b --repo-id jaredpalmer/kev-9b \
  --repo-revision 2629c06a5aeb0feb3b9783bafed17ed8f39ecf5c \
  --attn eager --rows-per-forward 1 \
  --max-memory-gib 120 --weights-budget-gib 40 \
  --host 127.0.0.1 --port 8834 \
  --provenance-out "$R/runs/kev-s2/startup-shard0.json" \
  > "$R/logs/serve-kev-s2.log" 2>&1 &

mkdir -p "$R/runs/kev-s2"
echo "=== waiting for all four servers ==="
for p in 8831 8832 8833 8834; do wait_ready "$p"; done
nvidia-smi --query-gpu=index,memory.used,utilization.gpu --format=csv,noheader

echo "=== launching runners ==="
start_runner open-jev-qwen-2b  s3-cases.jsonl 8831 venv-ojev \
  3076462e6356412082e79af909227b39b2863b90def79155ca0821aa506b7ded \
  s3-open-jev-qwen-2b-h200 "$R/runs/2b-s3"
start_runner open-jev-qwen-9b  s3-cases.jsonl 8832 venv-ojev \
  9302c52feba99d079918755f2469f4f088266e9786327bab550248f3d83716d3 \
  s3-open-jev-qwen-9b-h200 "$R/runs/9b-s3"
start_runner bespoke-nimble-9b s3-cases.jsonl 8833 venv-nimble \
  93ec5d6ff1a9cd31d6cc0e0c58d312465d36de7c \
  s3-bespoke-nimble-9b-h200 "$R/runs/nimble-s3"
start_runner kev-9b            s2-cases.jsonl 8834 venv-kev \
  f31c1f8b0f1dbf1a97697b8695f9798e365267454d8e8ea3939a0e9fb36a48dd \
  s2-kev-9b-h200 "$R/runs/kev-s2"

sleep 60
echo "=== early progress ==="
for d in 2b-s3/open-jev-qwen-2b 9b-s3/open-jev-qwen-9b nimble-s3/bespoke-nimble-9b kev-s2/kev-9b; do
  f="$R/runs/${d}-shard0.jsonl"
  echo "  $(basename $d) rows=$(wc -l < "$f" 2>/dev/null || echo 0)"
done
nvidia-smi --query-gpu=index,utilization.gpu --format=csv,noheader | tr '\n' ' '; echo
