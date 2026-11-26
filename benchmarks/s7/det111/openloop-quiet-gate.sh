#!/bin/bash
# openloop-quiet-gate.sh <gateway test binary> [max tries, default 6] [sleep seconds between tries, default 60]
#
# Fail-closed gate step for the open-loop latency tests (rel-1-0-10:GAP-2129,
# DET111 ruling 2026-11-24). Under measured CPU contention each test ends as
# the named skip "GAP-1456 INCONCLUSIVE, box short of CPU (...)" whose
# message prints the probe values and their limits (openLoopProbeMinShare,
# openLoopProbeMaxPressure, openLoopProbeMaxWait in gap0490_open_loop_test.go).
# A skip is never a pass: this step reruns the tests until every one of them
# has RUN and PASSED at least once, and fails the gate when one has not
# after the last try. A FAIL in any try fails the gate at once (a slow
# stream on a quiet box fails in the test itself).
# Last line: OPENLOOP_GATE PASS|FAIL tries=N runs=R skipped=S passed=P failed=F <Test>=<pass>/<skip>/<fail> ...
# Exit 0 PASS, 1 FAIL, 2 bad usage.
set -uo pipefail
bin=${1:-}; tries=${2:-6}; pause=${3:-60}
[ -x "$bin" ] || { echo "usage: openloop-quiet-gate.sh <gateway test binary> [tries] [pause]" >&2; exit 2; }
tests=(TestGAP0490OpenLoopSandboxStream TestGAP0490OpenLoopTwoSandboxes TestGAP0490OpenLoopFourSandboxes)
# The account-budget streams are opt-in (they skip by name unless
# DC_GAP0490_OPEN_LOOP_BUDGET=1); with it set they must pass here too.
if [ "${DC_GAP0490_OPEN_LOOP_BUDGET:-}" = 1 ]; then
  tests+=(TestGAP0490OpenLoopFourSandboxesAtTheAccountBudget TestHookPerUserOpenLoopOneSession100 TestHookPerUserOpenLoopTenSessions100)
fi
re="^($(IFS='|'; echo "${tests[*]}"))$"
declare -A pass skip fail
for t in "${tests[@]}"; do pass[$t]=0; skip[$t]=0; fail[$t]=0; done
log=$(mktemp "${TMPDIR:-/tmp}/openloop-gate.XXXXXX")
trap 'rm -f "$log"' EXIT
n=0
while [ $n -lt "$tries" ]; do
  n=$((n+1))
  "$bin" -test.run "$re" -test.count=1 -test.v > "$log" 2>&1
  for t in "${tests[@]}"; do
    grep -q -- "^--- PASS: $t " "$log" && pass[$t]=$((pass[$t]+1))
    grep -q -- "^--- SKIP: $t " "$log" && skip[$t]=$((skip[$t]+1))
    grep -q -- "^--- FAIL: $t " "$log" && fail[$t]=$((fail[$t]+1))
  done
  echo "OPENLOOP_TRY $n load=$(cut -d' ' -f1 /proc/loadavg 2>/dev/null) pass=$(grep -c -- '^--- PASS: Test' "$log") skip=$(grep -c -- '^--- SKIP: Test' "$log") fail=$(grep -c -- '^--- FAIL: Test' "$log")"
  grep -h -- 'GAP-1456 \(INCONCLUSIVE\|FAIL\)' "$log" | cut -c1-300 | head -5
  failed=0; missing=0
  for t in "${tests[@]}"; do
    [ "${fail[$t]}" -gt 0 ] && failed=1
    [ "${pass[$t]}" -eq 0 ] && missing=1
  done
  [ $failed = 1 ] && break
  [ $missing = 0 ] && break
  [ $n -lt "$tries" ] && sleep "$pause"
done
runs=0; s=0; p=0; f=0; per=""
for t in "${tests[@]}"; do
  runs=$((runs+pass[$t]+fail[$t])); s=$((s+skip[$t])); p=$((p+pass[$t])); f=$((f+fail[$t]))
  per="$per $t=${pass[$t]}/${skip[$t]}/${fail[$t]}"
done
verdict=PASS
[ $failed = 1 ] && verdict=FAIL
[ $missing = 1 ] && verdict=FAIL
echo "OPENLOOP_GATE $verdict tries=$n runs=$runs skipped=$s passed=$p failed=$f$per"
[ $verdict = PASS ]
