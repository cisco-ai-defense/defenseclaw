#!/usr/bin/env bash
# Re-run each stage's OWN scoring script with the hosted-Jev arm added, writing to NEW paths
# only (no existing artifact is overwritten).
set -uo pipefail

REPO=$WORK/defenseclaw-system-one
D=$WORK/.system-one-data/outputs
PY=$WORK/.system-one-venv/bin/python
export PYTHONPATH="$REPO/benchmarks/scripts"
S="$REPO/benchmarks/scripts"
OUT="$D/jev-parity/native"
mkdir -p "$OUT"

run() {
  local label="$1"; shift
  echo "=============== $label"
  "$@" > "$OUT/$label.stdout.txt" 2>&1
  local rc=$?
  echo "exit=$rc"
  tail -4 "$OUT/$label.stdout.txt"
  echo
}

# --- TerminalBench benign-lane per-event FPR: adds the two Jev Q4 arms alongside the
#     existing OpenJev / DiffusionGemma arms. Must run with cwd = outputs (relative paths).
cd "$D"
run tb-q4-lane-fpr-with-jev \
  "$PY" "$S/score_tb_q4_lane_fpr.py" \
  --cases "$D/s1-n1000/terminalbench-context-cases.jsonl" \
  --candidate "openjev/C7/I3/Q4=$D/terminalbench/openjev-q4-C7.jsonl" \
  --candidate "diffusiongemma/C7/I3/Q4=$D/terminalbench/diffgemma-q4-C7.jsonl" \
  --candidate "jev/C7/I3/Q4=$D/terminalbench/jev-q4-C7.jsonl" \
  --candidate "openjev/C1/I3/Q4=$D/terminalbench/openjev-q4-C1.jsonl" \
  --candidate "diffusiongemma/C1/I3/Q4=$D/terminalbench/diffgemma-q4-C1.jsonl" \
  --candidate "jev/C1/I3/Q4=$D/terminalbench/jev-q4-C1.jsonl" \
  --out-json "$D/terminalbench/q4-lane-fpr-with-jev.json" \
  --out-txt "$D/terminalbench/q4-lane-fpr-with-jev.txt"

# --- Intent (real corpus) Q4 analysis: all three backends, Q4 + paired Q2.
run intent-real-q4-with-jev \
  "$PY" "$S/score_q4_intent_real.py" \
  --cases "$D/intent-real/cases.jsonl" \
  --q4 "openjev-q4-C0=$D/intent-real/openjev-q4-C0.jsonl" \
  --q4 "openjev-q4-C7=$D/intent-real/openjev-q4-C7.jsonl" \
  --q4 "diffgemma-q4-C0=$D/intent-real/diffgemma-q4-C0.jsonl" \
  --q4 "diffgemma-q4-C7=$D/intent-real/diffgemma-q4-C7.jsonl" \
  --q4 "jev-q4-C0=$D/intent-real/jev-q4-C0.jsonl" \
  --q4 "jev-q4-C7=$D/intent-real/jev-q4-C7.jsonl" \
  --q2 "openjev-C0=$D/intent-real/openjev-C0.jsonl" \
  --q2 "openjev-C7=$D/intent-real/openjev-C7.jsonl" \
  --q2 "diffgemma-C0=$D/intent-real/diffgemma-C0.jsonl" \
  --q2 "diffgemma-C7=$D/intent-real/diffgemma-C7.jsonl" \
  --q2 "jev-C0=$D/intent-real/jev-C0.jsonl" \
  --q2 "jev-C7=$D/intent-real/jev-C7.jsonl" \
  --validate-cases "$D/toolcall-labels/cases.jsonl" \
  --validate-predictions "$D/toolcall-labels/openjev-q4-C0.jsonl" \
  --json "$D/intent-real/q4-analysis-with-jev.json" \
  --txt "$D/intent-real/q4-analysis-with-jev.txt"

# --- Intent ablation, stage-native single-arm analysis, Jev arm.
run intent-ablation-jev \
  "$PY" "$S/score_intent_ablation.py" \
  --predictions "$D/intent-ablation/jev-C1.jsonl" \
  --candidate "jev C1/I3/Q2" \
  --output "$D/intent-ablation/ablation-analysis-jev.json" \
  --digest "$D/intent-ablation/ablation-analysis-jev.txt"

# --- Label corpus: the stage's C0-vs-C7 paired analysis, run for Jev.
run toolcall-labels-c0-vs-c7-jev \
  "$PY" "$S/score_q4_c0_vs_c7.py" \
  --cases "$D/toolcall-labels/cases.jsonl" \
  --c0 "$D/toolcall-labels/jev-q4-C0.jsonl" \
  --c7 "$D/toolcall-labels/jev-q4-C7.jsonl" \
  --out-json "$D/toolcall-labels/q4-c0-vs-c7-jev.json" \
  --out-txt "$D/toolcall-labels/q4-c0-vs-c7-jev.txt"

# --- Label corpus: the stage's two-lane analysis, run for Jev at C0 and C7.
run toolcall-labels-twolane-jev-C0 \
  "$PY" "$S/score_q4_twolane.py" \
  --cases "$D/toolcall-labels/cases.jsonl" \
  --predictions "$D/toolcall-labels/jev-q4-C0.jsonl" \
  --out-json "$D/toolcall-labels/q4-analysis-jev-C0.json" \
  --out-txt "$D/toolcall-labels/q4-analysis-jev-C0.txt"

run toolcall-labels-twolane-jev-C7 \
  "$PY" "$S/score_q4_twolane.py" \
  --cases "$D/toolcall-labels/cases.jsonl" \
  --predictions "$D/toolcall-labels/jev-q4-C7.jsonl" \
  --out-json "$D/toolcall-labels/q4-analysis-jev-C7.json" \
  --out-txt "$D/toolcall-labels/q4-analysis-jev-C7.txt"

echo "ALL NATIVE SCORES ATTEMPTED"
