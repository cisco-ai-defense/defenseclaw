#!/bin/bash
# Measure the GAP-0844 latency guard (TestCapFloorLatencyStaysNearRel) the way
# the rel ratios in capFloorLatencyRel were recorded (rel-1-0-10:GAP-0896).
#
#   usage, from the repo root:  bash internal/gateway/testdata/capfloor_latency/measure.sh <tag>
#
# To record rel ratios: check out the rel commit (16f68a06f6 or 644d23fa3b, never a
# candidate head), copy internal/gateway/cap_floor_latency_test.go from the branch
# that carries the pinned five-block test over the rel one, then run this on an
# otherwise idle box. It builds the test binary once, then runs the guard 20 times
# (-test.count 20) at each of GOMAXPROCS 2, 4 and 16, and prints one GAP0844LATENCY
# line per shape and run. aggregate.py turns the log into rel-medians.tsv.
set -o pipefail
tag=${1:?usage: measure.sh <tag>}
S=${MEASURE_SCRATCH:-/var/tmp/capfloor_latency}/$tag
export GOCACHE=${MEASURE_SCRATCH:-/var/tmp/capfloor_latency}/gocache GOTMPDIR=$S TMPDIR=$S
mkdir -p "$S"
go version; git log --oneline -1 | cut -c1-80; uptime
nice -n 5 go test -c -o "$S/lat.test" ./internal/gateway/ || { echo BUILD_FAIL; exit 1; }
cd internal/gateway || exit 1
for P in 2 4 16; do
  echo "GOMAXPROCS=$P $(cut -d' ' -f1-3 /proc/loadavg)"
  GOMAXPROCS=$P "$S/lat.test" -test.run '^TestCapFloorLatencyStaysNearRel$' -test.count 20 -test.v 2>&1 |
    grep -E 'GAP0844LATENCY|^--- |cap_floor_latency_test.go.*times|^(ok|FAIL|PASS)'
  echo "RC_P$P=$?"
done
uptime; rm -f "$S/lat.test"
