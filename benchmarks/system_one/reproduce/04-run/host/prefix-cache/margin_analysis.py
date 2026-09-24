import json, sys
D = "$WORK/prefix-unit-test/"
def load(p):
    out = {}
    for line in open(p):
        line = line.strip()
        if line:
            r = json.loads(line)
            out[r["request_sha256"]] = r
    return out
def margin(r):
    p = sorted((v for k, v in (r.get("probabilities") or {}).items()
                if k.startswith("disposition.")), reverse=True)
    return (p[0] - p[1]) if len(p) >= 2 else None
for pass_ in ("P2-screen200-cold", "P3-screen200-warm"):
    A = load(D + "armA-unit112-" + pass_ + ".jsonl")
    B = load(D + "armB-default784-" + pass_ + ".jsonl")
    common = set(A) & set(B)
    margins = [(k, margin(B[k])) for k in common]
    margins = [(k, m) for k, m in margins if m is not None]
    flips = {k for k in common if A[k].get("action") != B[k].get("action")}
    tiny = [k for k, m in margins if m < 1e-9]
    near = [k for k, m in margins if m < 0.01]
    print("=== " + pass_ + " ===")
    print("  records with a disposition distribution: {}".format(len(margins)))
    print("  EXACT ties at 4dp (margin < 1e-9): {}".format(len(tiny)))
    print("  near-ties (margin < 0.01):         {}".format(len(near)))
    print("  disposition flips:                 {}".format(len(flips)))
    print("  flips that are exact ties:         {}/{}".format(len(flips & set(tiny)), len(flips)))
    print("  flips that are near-ties (<0.01):  {}/{}".format(len(flips & set(near)), len(flips)))
    if tiny:
        print("  flip rate among exact ties:  {}/{} = {:.1%}".format(
            len(flips & set(tiny)), len(tiny), len(flips & set(tiny)) / len(tiny)))
    rest = set(margins and [k for k, m in margins]) - set(near)
    print("  flip rate among NON-near-ties: {}/{} = {:.3%}".format(
        len(flips & rest), len(rest), (len(flips & rest) / len(rest)) if rest else 0))
    print()
# same-config floor for comparison
for lbl, f1, f2 in (("armA-unit112 P2 vs P3", "armA-unit112-P2-screen200-cold", "armA-unit112-P3-screen200-warm"),
                    ("armB-default784 P2 vs P3", "armB-default784-P2-screen200-cold", "armB-default784-P3-screen200-warm")):
    A = load(D + f1 + ".jsonl"); B = load(D + f2 + ".jsonl")
    common = set(A) & set(B)
    flips = {k for k in common if A[k].get("action") != B[k].get("action")}
    near = {k for k in common if (margin(B[k]) or 1) < 0.01}
    print("SAME-CONFIG {}: flips={} of which near-ties={}".format(lbl, len(flips), len(flips & near)))
