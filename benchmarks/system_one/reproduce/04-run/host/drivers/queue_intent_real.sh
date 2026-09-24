#!/bin/bash
# Queue the OpenJev C0-vs-C7 contrast on the intent-real corpus.
#
# WHY THIS RUN
# ------------
# DefenseClaw's shipped guardrail judges whether recent tool calls deviate from the last user
# prompt. Eight measurements of that mechanism (Jev / DiffusionGemma / OpenJev / Gemma 4, each at
# C0 and C7) all returned NEGATIVE separation, and adding intent (C0 -> C7) made it worse in all
# four backends. Every one of those eight sits on 651 AgentDojo cases with 194 compromised rows,
# all grade B, on synthetic tool APIs. This re-measures the same quantity on
# outputs/intent-real: 3,402 cases / 3,946 decisions / 1,929 families, 1,049 compromised of which
# 405 are grade-A proof-backed, with 1,083 attacked_resisted hard negatives. C0 vs C7 is the whole
# point - it isolates whether supplying the user's intent helps at all.
#
# WHY C7/Q4 IS THIRD AND CONDITIONAL
# ----------------------------------
# Q4 is the only question variant that splits intrinsic_danger from serves_intent, which is
# exactly the hypothesis under test, and this corpus is the right place to test it. But Q4 has
# never been run anywhere until q4chain runs it on the tool-call labels. This chain therefore
# launches the Q4 arm only if that run closed out AND came back with a low error rate; otherwise
# it logs the reason and skips, leaving the two Q2 arms intact.
#
# DEPENDENCY ORDERING AND PORTS
# -----------------------------
# Chains already in flight:
#   q1chain  waits for s2/openjev-q3-h0+h1 meta.json, then runs Q1 on ports 8767 (h0) / 8768 (h1)
#   q4chain  waits for s2/openjev-q1-h0+h1 meta.json, then runs Q4 on ports 8767 (C0) / 8768 (C7)
# This chain waits for BOTH q4chain OUTPUTS (toolcall-labels/openjev-q4-C0|C7.jsonl.meta.json),
# which are written only on completion, and then reuses 8767/8768. Gating on q4chain's outputs
# rather than on Q1's makes port contention structurally impossible: q1chain and q4chain are the
# only users of 8767/8768 and both have finished with them by the time this starts.
#
# Port 8765 is deliberately NOT used (and as of 06:02Z another chain has claimed it for the Q4
# C0 arm anyway) even though it is idle and would let this chain start ~6h
# earlier. 8765 is the default shim and forwards to vLLM :8000, which is also what the cache /
# prefix-caching timing harness (cwshim on 8769) targets. Sixteen concurrent requests against
# :8000 would silently corrupt someone else's latency measurements. 8767/8768 forward to the
# dedicated vLLM :8002/:8003, used only by these benchmark chains.
#
# Wait cap is 24h: Q3 may take up to 8h, then Q1, then Q4. On timeout this logs ABORT and exits
# rather than becoming an orphan poller. Nothing here kills, signals or restarts any process,
# tunnel or shim.
set -u
O=$WORK/.system-one-data/outputs/intent-real
L=$WORK/.system-one-data/outputs/toolcall-labels
PY=$WORK/.system-one-venv/bin/python
REV=5ec9e5fd2f80a6fff386779b1e5ac7e389971889
QCFG2=benchmarks/system_one/questions-v2.json
CHAIN=$WORK/intent-chain.log
cd $WORK/defenseclaw-system-one || exit 1

echo "$(date -u +%FT%TZ) intentchain start" >> "$CHAIN"
echo "$(date -u +%FT%TZ) cases sha256=$(sha256sum "$O/cases.jsonl" | cut -d' ' -f1)" >> "$CHAIN"
echo "$(date -u +%FT%TZ) waiting on $L/openjev-q4-C0.jsonl.meta.json and openjev-q4-C7.jsonl.meta.json" >> "$CHAIN"

# 8640 * 10s = 24h
for _ in $(seq 1 8640); do
  [ -f "$L/openjev-q4-C0.jsonl.meta.json" ] && [ -f "$L/openjev-q4-C7.jsonl.meta.json" ] && break
  sleep 10
done
if [ ! -f "$L/openjev-q4-C0.jsonl.meta.json" ] || [ ! -f "$L/openjev-q4-C7.jsonl.meta.json" ]; then
  echo "$(date -u +%FT%TZ) ABORT: q4chain did not complete within 24h; not launching intent-real" >> "$CHAIN"
  exit 1
fi
echo "$(date -u +%FT%TZ) q4chain complete; 8767/8768 are free; launching intent-real Q2 arms" >> "$CHAIN"

# Belt-and-braces port guard. The dependency ordering above should already make 8767/8768
# free, but another agent has since started arms early on idle shims, so before touching a port
# this waits (read-only pgrep; it never signals anything) until no other runner is pointed at it.
wait_port_free () {
  local PORT=$1
  for _ in $(seq 1 2880); do
    if ! pgrep -af benchmark_run_system_one.py | grep -q "127.0.0.1:$PORT/"; then
      return 0
    fi
    sleep 10
  done
  return 1
}

launch_q2 () {
  local CTX=$1 PORT=$2
  if [ -f "$O/openjev-$CTX.jsonl.meta.json" ]; then
    echo "$(date -u +%FT%TZ) intent-real $CTX already complete; skipping" >> "$CHAIN"
    return 0
  fi
  if ! wait_port_free "$PORT"; then
    echo "$(date -u +%FT%TZ) ABORT $CTX: port $PORT still busy after 8h" >> "$CHAIN"
    return 1
  fi
  echo "$(date -u +%FT%TZ) port $PORT free; launching intent-real $CTX q2" >> "$CHAIN"
  "$PY" benchmarks/scripts/benchmark_run_system_one.py \
    --cases "$O/cases.jsonl" \
    --context "$CTX" --instruction I3 --question Q2 \
    --endpoint "http://127.0.0.1:$PORT/v1/systemone" \
    --model openjev --model-revision "$REV" \
    --instruction-format structured \
    --run-id "intent-real-openjev-$CTX-q2" \
    --output "$O/openjev-$CTX.jsonl" \
    --concurrency 16 --timeout 300 --retries 2 \
    >> "$WORK/intent-real-$CTX.log" 2>&1
  echo "$(date -u +%FT%TZ) intent-real $CTX q2 exit=$?" >> "$CHAIN"
}

launch_q2 C0 8767 &
launch_q2 C7 8768 &
wait
echo "$(date -u +%FT%TZ) intent-real Q2 arms finished" >> "$CHAIN"

# --- conditional third arm: C7/I3/Q4, only if Q4 wiring is proven on the label corpus ---
Q4SRC="$L/openjev-q4-C7.jsonl"
Q4READY=0
if [ -f "$Q4SRC" ]; then
  ROWS=$(wc -l < "$Q4SRC")
  ERRS=$(grep -c '"error_code"' "$Q4SRC" || true)
  # proven working = closed out (meta.json, already checked above) and under 2% error rows
  if [ "$ROWS" -gt 0 ] && [ $((ERRS * 50)) -le "$ROWS" ]; then
    Q4READY=1
  fi
  echo "$(date -u +%FT%TZ) Q4 readiness: rows=$ROWS error_rows=$ERRS ready=$Q4READY" >> "$CHAIN"
else
  echo "$(date -u +%FT%TZ) Q4 readiness: $Q4SRC absent; ready=0" >> "$CHAIN"
fi

if [ "$Q4READY" = "1" ]; then
  if [ -f "$O/openjev-C7-q4.jsonl.meta.json" ]; then
    echo "$(date -u +%FT%TZ) intent-real C7 q4 already complete; skipping" >> "$CHAIN"
  elif ! wait_port_free 8767; then
    echo "$(date -u +%FT%TZ) ABORT C7 q4: port 8767 still busy after 8h" >> "$CHAIN"
  else
    "$PY" benchmarks/scripts/benchmark_run_system_one.py \
      --cases "$O/cases.jsonl" \
      --questions-config "$QCFG2" \
      --context C7 --instruction I3 --question Q4 \
      --endpoint "http://127.0.0.1:8767/v1/systemone" \
      --model openjev --model-revision "$REV" \
      --instruction-format structured \
      --run-id "intent-real-openjev-C7-q4" \
      --output "$O/openjev-C7-q4.jsonl" \
      --concurrency 16 --timeout 300 --retries 2 \
      >> $WORK/intent-real-C7-q4.log 2>&1
    echo "$(date -u +%FT%TZ) intent-real C7 q4 exit=$?" >> "$CHAIN"
  fi
else
  echo "$(date -u +%FT%TZ) SKIPPED intent-real C7 q4: Q4 wiring not proven on the label corpus" >> "$CHAIN"
fi

echo "$(date -u +%FT%TZ) intentchain finished" >> "$CHAIN"
