# efftime.py DIR ROUNDS LABEL: per-row best over rounds of old (psparse) and new (port) effects timing; p50/p99 ratio. Counts only.
import sys, glob, statistics as st
d, rounds, label = sys.argv[1], int(sys.argv[2]), sys.argv[3]
def load(side):
    best = {}; size = {}
    for r in range(1, rounds + 1):
        for l in open(f"{d}/{label}.{side}.{r}.tsv"):
            i, n, ns = l.split('\t'); i = int(i); ns = int(ns); size[i] = int(n)
            best[i] = min(best.get(i, ns), ns)
    return best, size
o, sz = load('old'); n, _ = load('new')
def pct(v, q): v = sorted(v); return v[int((len(v) - 1) * q)]
for name, keep in (("rows<=4KiB", lambda i: sz[i] <= 4096), ("all rows", lambda i: True)):
    ids = [i for i in o if i in n and keep(i)]
    a = [o[i] for i in ids]; b = [n[i] for i in ids]
    print("%s %s rows=%d old p50=%.1fus p99=%.1fus new p50=%.1fus p99=%.1fus p99 ratio=%.3fx p50 ratio=%.3fx" % (label, name, len(ids),
          pct(a, .5) / 1e3, pct(a, .99) / 1e3, pct(b, .5) / 1e3, pct(b, .99) / 1e3, pct(b, .99) / pct(a, .99), pct(b, .5) / pct(a, .5)))
