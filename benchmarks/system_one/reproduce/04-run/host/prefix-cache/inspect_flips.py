import json
D = "$WORK/prefix-unit-test/"
targets = {
    ("mcphunt/45fd144a23652f4a29c8b135/window-000", 20),
    ("mcphunt/fc523d6a838f3e31fde59ea4/window-000", 17),
    ("mcphunt/45fd144a23652f4a29c8b135/window-000", 21),
    ("mcphunt/08c0e220c188572a6f6e46ef/window-000", 6),
    ("mcphunt/a8f168aa32846e474858637d/window-000", 5),
    ("mcphunt/2f933436c5dbfc430c4c0c9c/exact-chain-001", 0),
}
def load(p):
    out = {}
    for line in open(p):
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        k = (r.get("case_id"), r.get("event_index"))
        if k in targets:
            out[k] = r
    return out
for pass_ in ("P2-screen200-cold", "P3-screen200-warm"):
    A = load(D + "armA-unit112-" + pass_ + ".jsonl")
    B = load(D + "armB-default784-" + pass_ + ".jsonl")
    print("=== " + pass_ + " ===")
    for k in sorted(targets, key=str):
        a, b = A.get(k), B.get(k)
        if not a or not b:
            continue
        pa = {x: y for x, y in (a.get("probabilities") or {}).items() if x.startswith("disposition.")}
        pb = {x: y for x, y in (b.get("probabilities") or {}).items() if x.startswith("disposition.")}
        flag = "FLIP" if a.get("action") != b.get("action") else "same"
        print("  {} ev{}  [{}]".format(k[0], k[1], flag))
        print("    unit112: {:>8} conf={} {}".format(str(a.get("action")), a.get("confidence"), pa))
        print("    unit784: {:>8} conf={} {}".format(str(b.get("action")), b.get("confidence"), pb))
        top = sorted(pb.values(), reverse=True)
        if len(top) >= 2:
            print("    784 top-2 margin = {:.4f}".format(top[0] - top[1]))
    print()
