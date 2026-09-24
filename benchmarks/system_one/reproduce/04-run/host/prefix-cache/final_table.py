import csv
rows = []
with open("$WORK/prefix-unit-test/metrics-8004.tsv") as f:
    for r in csv.reader(f, delimiter="\t"):
        rows.append(r)
by = {r[1]: r for r in rows}
def d(a, b, i):
    return float(by[b][i]) - float(by[a][i])
PT, CT, LC, PF = 2, 3, 4, 5
seq = [
    ("cases20   unit112", "baseline-zero", "armA-P1-cases20-cold"),
    ("cases20   unit784", "armA-unit112-probe-repeat-AFTER", "armB-default784-P1-cases20-cold"),
    ("screen200 unit112 pass1", "armA-P1-cases20-cold", "armA-unit112-P2-screen200-cold"),
    ("screen200 unit784 pass1", "armB-default784-P1-cases20-cold", "armB-default784-P2-screen200-cold"),
    ("screen200 unit112 pass2", "armA-unit112-P2-screen200-cold", "armA-unit112-P3-screen200-warm"),
    ("screen200 unit784 pass2", "armB-default784-P2-screen200-cold", "armB-default784-P3-screen200-warm"),
    ("cases20   unit112 warm", "armA-unit112-P3-screen200-warm", "armA-unit112-P4-cases20-warm"),
    ("cases20   unit784 warm", "armB-default784-P3-screen200-warm", "armB-default784-P4-cases20-warm"),
]
print("{:<26} {:>10} {:>9} {:>8} {:>11} {:>10}".format(
    "pass", "prompt_tok", "cached", "hit%", "computed", "prefill_s"))
for label, a, b in seq:
    pt, ct, lc, pf = d(a, b, PT), d(a, b, CT), d(a, b, LC), d(a, b, PF)
    print("{:<26} {:>10.0f} {:>9.0f} {:>7.2f}% {:>11.0f} {:>10.1f}".format(label, pt, ct, 100 * ct / pt, lc, pf))
