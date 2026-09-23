#!/bin/bash
# Settle, score and publish the open-jev-qwen-27b s2 arm.
#
# Steps 1-5 are the shared, already-published pipeline (sysone-score_s2.sh: shard
# settledness -> coverage-verified merge -> merged digest check -> settled meta ->
# scorer -> recall at fixed FPR). Steps 6-8 add the three validation artifacts the
# Space build resolves under openjev-qwen/validation/, and step 9 appends the one
# comparison row. Nothing here rewrites an existing arm's output.
set -uo pipefail

NAME=open-jev-qwen-27b
PY=$WORK/.system-one-venv/bin/python
O=$WORK/.system-one-data/outputs
OUTDIR=$O/openjev-qwen/s2
VALID=$O/openjev-qwen/validation
CASES=$O/s2/cases.jsonl
MERGED=$OUTDIR/$NAME.jsonl
INCUMBENT=$O/s2/openjev-final.jsonl
mkdir -p "$VALID"

T0=$(cat $WORK/j27/run-start-epoch.txt)
T1=$(date -u +%s)
WALL=$((T1-T0))
# Four L40S were resident for the whole run (two replicas, two cards each).
GPU_SECONDS=$((WALL*4))
echo "=== wall=${WALL}s gpu_seconds=${GPU_SECONDS} ==="

echo "=== 1-5. shared settle + score pipeline ==="
GPU_SECONDS=$GPU_SECONDS bash $WORK/sysone-score_s2.sh "$NAME" "$OUTDIR" || exit 1

echo "=== 6. auc variants (all three ranking variables) ==="
( cd $WORK/defenseclaw-system-one && PYTHONPATH=$WORK/defenseclaw-system-one/benchmarks/scripts \
  $PY $WORK/sysone-auc_variants.py \
    --cases "$CASES" --predictions "$MERGED" --label "$NAME" \
    --out "$VALID/auc-variants-$NAME.json" ) || exit 1

echo "=== 7. mapping check (per-grade breakdown) ==="
( cd $WORK/defenseclaw-system-one && PYTHONPATH=$WORK/defenseclaw-system-one/benchmarks/scripts \
  $PY $WORK/sysone-mapping_check.py \
    --cases "$CASES" --predictions "$MERGED" \
    --out "$VALID/mapping-check-$NAME.json" ) || exit 1

echo "=== 8. recall at fixed FPR by ranking variable ==="
# Two output names on purpose. The live Space build resolves
# `recall-by-variable-<pred>.json` (src/build.py added_rel kind="recallvar"), while the brief
# asked for `recall-at-fpr-by-variable-<pred>.json`. Identical content under both names, so
# neither consumer misses it.
( cd $WORK/defenseclaw-system-one && PYTHONPATH=$WORK/defenseclaw-system-one/benchmarks/scripts \
  $PY $WORK/j27/by_variable_27b.py \
    --cases "$CASES" --predictions "$MERGED" --label "$NAME" \
    --incumbent-predictions "$INCUMBENT" \
    --auc-variants "$VALID/auc-variants-$NAME.json" \
    --out "$VALID/recall-by-variable-$NAME.json" \
    --out "$VALID/recall-at-fpr-by-variable-$NAME.json" ) || exit 1

echo "=== 8b. eager-vs-sdpa agreement on this checkpoint ==="
# The 2B and 9B arms ran the sdpa path hardcoded in jev/model.py; this arm ran eager. The
# serving record points a reader at this file, so it has to exist. Measured after the run so
# the cards are free, on the same 24 representative request bodies the eager dump used.
GPU=<GPU_HOST>
KEY=<SSH_KEY>

# The two replicas this run started still hold all four cards, so they have to come down
# before an sdpa replica can load. Only the two PIDs recorded at launch are signalled, and
# only after re-reading /proc to confirm each one is still the serve27.py process this run
# started on its own port. No pkill, no pattern match against anything this run did not create.
ssh -o StrictHostKeyChecking=no -i $KEY ubuntu@$GPU '
for pid in $(cat $WORK/sysone/j27/server-pids-only.txt); do
  cmd=$(tr "\0" " " < /proc/$pid/cmdline 2>/dev/null)
  case "$cmd" in
    *"j27/serve27.py"*"--name open-jev-qwen-27b"*)
      echo "stopping own replica pid=$pid"; kill -TERM "$pid" ;;
    "") echo "pid $pid already gone, nothing to do" ;;
    *)  echo "REFUSING to signal pid $pid: not our serve27.py ($cmd)" ;;
  esac
done
for _ in $(seq 60); do
  still=0
  for pid in $(cat $WORK/sysone/j27/server-pids-only.txt); do
    [ -d /proc/$pid ] && still=1
  done
  [ $still -eq 0 ] && break
  sleep 2
done
nvidia-smi --query-gpu=index,memory.used --format=csv,noheader
'

ssh -o StrictHostKeyChecking=no -i $KEY ubuntu@$GPU "cd $WORK/sysone && \
  CUDA_VISIBLE_DEVICES=0,1 HF_HOME=/opt/dlami/nvme/hf PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True \
  ./venv-ojev/bin/python j27/serve27.py \
    --checkpoint /opt/dlami/nvme/model-staging/open-jev-27b-v1.1/package/checkpoint \
    --name $NAME --repo-id ZefanCai/Open-Jev-27B-v1.1 \
    --repo-revision 28cf73067d5b337860bbef3c85b8b82ba8730956 \
    --attn sdpa --device-map balanced --max-memory-per-card 30GiB --batch-size 4 \
    --no-prefix-cache --selftest j27/selftest-rep.jsonl \
    --selftest-out j27/selftest-rep-sdpa-b4.json > logs/selftest-rep-sdpa.log 2>&1 && \
  ./venv-ojev/bin/python j27/compare_attn.py \
    --a j27/selftest-rep-eager-b4.json --b j27/selftest-rep-sdpa-b4.json \
    --out j27/attn-agreement-27b.json" \
  && scp -q -i $KEY ubuntu@$GPU:$WORK/sysone/j27/attn-agreement-27b.json \
       "$VALID/attn-agreement-$NAME.json" \
  && $PY -c "
import json; d=json.load(open('$VALID/attn-agreement-$NAME.json'))
print(json.dumps({k: d[k] for k in ('max_abs_delta','p50_abs_delta','mean_abs_delta',
      'argmax_disposition_flips','requests_compared','scalar_fields_compared',
      'within_tolerance')}, indent=2, sort_keys=True))" \
  || echo "WARNING: eager/sdpa agreement measurement did not complete; see logs/selftest-rep-sdpa.log"

echo "=== 9. append the comparison row ==="
$PY $WORK/j27/append_row_27b.py --name "$NAME" --scoredir "$OUTDIR/scores" \
  --predictions "$MERGED" --by-variable "$VALID/recall-at-fpr-by-variable-$NAME.json" || exit 1

echo "=== 10. settled verification ==="
$PY - "$MERGED" <<'PY' || exit 1
import hashlib, json, pathlib, sys
merged = pathlib.Path(sys.argv[1])
meta = json.loads(pathlib.Path(str(merged) + ".meta.json").read_text())
digest = hashlib.sha256()
with merged.open("rb") as stream:
    for block in iter(lambda: stream.read(8 << 20), b""):
        digest.update(block)
disk = digest.hexdigest()
ok = meta.get("complete") is True and disk == meta.get("prediction_sha256")
print(json.dumps({"complete": meta.get("complete"), "requests": meta.get("requests"),
                  "cases": meta.get("cases"), "errors_by_code": meta.get("errors_by_code"),
                  "on_disk_sha256": disk, "meta_prediction_sha256": meta.get("prediction_sha256"),
                  "sha_match": disk == meta.get("prediction_sha256"),
                  "temperature": meta.get("temperature"),
                  "forward_passes_per_decision": meta.get("forward_passes_per_decision"),
                  "max_length": meta.get("max_length"), "SETTLED": ok}, indent=2, sort_keys=True))
sys.exit(0 if ok else 1)
PY

echo "=== FINISH DONE ==="
