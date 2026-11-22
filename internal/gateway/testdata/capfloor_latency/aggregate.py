#!/usr/bin/env python3
"""Aggregate measure.sh logs into rel-medians.tsv and rel-runs.tsv (GAP-0896).

usage: aggregate.py REL_SHA OUT_DIR BOX=LOG [BOX=LOG ...]

A log is the stdout of measure.sh: a "GOMAXPROCS=<n> <load>" line starts each
section, then one GAP0844LATENCY line per shape and run. rel-runs.tsv has every
run's ratio (the median of the 5 blocks of that run); rel-medians.tsv has the
median per shape, GOMAXPROCS and box, then per shape over all boxes and
GOMAXPROCS values (gomaxprocs "all", box "all"), the value in capFloorLatencyRel.
The median is the usual one (the mean of the two middle values when n is even),
printed to 3 decimals; capFloorLatencyRel holds it rounded to the precision of the
table (110.225 -> 110.2, 81.025 -> 81.0).
"""
import collections
import os
import re
import statistics
import sys

rel, out = sys.argv[1], sys.argv[2]
runs = collections.defaultdict(list)  # (shape, gomaxprocs, box) -> ratios in log order
for spec in sys.argv[3:]:
    box, path = spec.split("=", 1)
    procs = "?"
    for line in open(path):
        m = re.match(r"GOMAXPROCS=(\d+)", line)
        if m:
            procs = m.group(1)
            continue
        m = re.search(r"GAP0844LATENCY (\S+) ratio ([\d.]+) ", line)
        if m:
            runs[(m.group(1), procs, box)].append(float(m.group(2)))


def median(v):
    return statistics.median(v)


with open(os.path.join(out, "rel-runs.tsv"), "w") as f:
    f.write("shape\tgomaxprocs\tbox\trun\tratio\trel_sha\n")
    for (shape, procs, box), v in sorted(runs.items()):
        for i, r in enumerate(v, 1):
            f.write(f"{shape}\t{procs}\t{box}\t{i}\t{r:.2f}\t{rel}\n")
with open(os.path.join(out, "rel-medians.tsv"), "w") as f:
    f.write("shape\tgomaxprocs\tbox\tn\tmedian\trel_sha\n")
    pooled = collections.defaultdict(list)
    for (shape, procs, box), v in sorted(runs.items()):
        f.write(f"{shape}\t{procs}\t{box}\t{len(v)}\t{median(v):.3f}\t{rel}\n")
        pooled[shape] += v
    for shape, v in sorted(pooled.items()):
        f.write(f"{shape}\tall\tall\t{len(v)}\t{median(v):.3f}\t{rel}\n")
