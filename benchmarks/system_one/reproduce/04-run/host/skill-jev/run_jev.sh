#!/bin/bash
# Serve OpenJev on the assigned card, ask the three question sets over the exported
# inputs, then stop only what this job started. Self-contained so the queue slot is
# clean on exit.
set -uo pipefail
R=/teamspace/studios/this_studio/openjev
T=/teamspace/studios/this_studio
export PATH="$R/venv/bin:$PATH"
CARD=${CUDA_VISIBLE_DEVICES:-0}
echo "card $CARD"

"$R/venv/bin/python" - <<'PY'
import sys
try:
    import torch, vllm, transformers, openai
except Exception as e:
    print("IMPORT ASSERT FAILED:", type(e).__name__, e); sys.exit(3)
print("imports ok | vllm", vllm.__version__, "| transformers", transformers.__version__)
PY
[ $? -ne 0 ] && exit 3

PORT=8${CARD}10
SHIMPORT=8${CARD}11
"$R/venv/bin/vllm" serve "$R/model" --host 127.0.0.1 --served-model-name qwen \
  --port "$PORT" --enable-prefix-caching --max-model-len 16384 \
  --gpu-memory-utilization 0.80 --limit-mm-per-prompt '{"image":1}' \
  --trust-remote-code --max-num-seqs 256 --max-logprobs 64 \
  --quantization fp8 > "$R/log/vllm-$CARD.log" 2>&1 &
VPID=$!

for i in $(seq 1 90); do
  sleep 10
  [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:$PORT/v1/models || true)" = "200" ] && break
  kill -0 $VPID 2>/dev/null || { echo "vllm died"; tail -5 "$R/log/vllm-$CARD.log"; exit 4; }
done
echo "vllm ready"

cd "$R/model"
SHIM_TOKEN= VLLM="http://127.0.0.1:$PORT/v1" TOKENIZER="$R/model" \
  READOUT_T=0.85 READOUT_NOUL_T=1.829074 READOUT_NOUL_BIAS=0 \
  READOUT_TARGETED=1 READOUT_INSTR_STYLE=pyrepr SHIM_STAGGER=1 \
  "$R/venv/bin/python" helper/shim.py --host 127.0.0.1 --port "$SHIMPORT" \
  > "$R/log/shim-$CARD.log" 2>&1 &
SPID=$!
sleep 30
echo "shim: $(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:$SHIMPORT/v1/version)"

SHIM="http://127.0.0.1:$SHIMPORT/v1/systemone" JEV_LIMIT="${JEV_LIMIT:-0}" \
  "$R/venv/bin/python" "$T/cisco_jev_questions.py" \
  "$T/cisco_inputs-sd.jsonl" "$T/cisco_jev_predictions-sd.jsonl"
rc=$?
echo "questions rc=$rc"

kill $SPID 2>/dev/null; kill $VPID 2>/dev/null
sleep 5
echo "torn down"
exit $rc
