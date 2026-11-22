# capfloor_latency: where the rel ratios of TestCapFloorLatencyStaysNearRel come from

`capFloorLatencyRel` (internal/gateway/cap_floor_latency_test.go) holds the
GAP-0844 latency guard's rel ratios. They are the median of 120 runs of the
guard built from rel/1.0.10 `16f68a06f6` (testctl TST-3302, rel-1-0-10:GAP-0896).

- `measure.sh <tag>`: run from the repo root; builds the test binary and runs the
  guard `-test.count 20` at GOMAXPROCS 2, 4 and 16.
- `aggregate.py`: turns the logs into the two tables below.
- `rel-runs.tsv`: every run's ratio (shape, gomaxprocs, box, run, ratio, rel sha).
- `rel-medians.tsv`: shape, gomaxprocs, box, n, median, rel sha; the `all` rows
  (n=120) are the table values.

Recorded with the pinned five-block test file of s7/gap0895 copied over the rel
checkout (rel's own test file has no such measurement), so the code measured is
rel's and the harness is the candidate's. dcb-bg jobs: `g896-lat-rlo` on
dc-s7-gates and `g896-lat-rl2` on dc-s7-gates2; logs in
`~/dc-eh/evidence/rel-1-0-10/s7/g0895/lat-rlo.log` and `lat-rl2.log` on defenseclaw-dev.
To record again, check out `16f68a06f6` or `644d23fa3b`, never a candidate head.

Reproduce the table: `python3 aggregate.py 16f68a06f6 <outdir> dc-s7-gates=<log> dc-s7-gates2=<log>`.
