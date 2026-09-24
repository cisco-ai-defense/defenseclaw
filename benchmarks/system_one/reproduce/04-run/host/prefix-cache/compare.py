import json, sys
def load(p):
    d = {}
    with open(p) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            d[r.get("request_sha256") or (r.get("case_id"), r.get("event_index"))] = r
    return d
A, B = load(sys.argv[1]), load(sys.argv[2])
common = sorted(set(A) & set(B), key=str)
print(f"A={sys.argv[1]} rows={len(A)}")
print(f"B={sys.argv[2]} rows={len(B)}")
print(f"common={len(common)} A_only={len(set(A)-set(B))} B_only={len(set(B)-set(A))}")
dispdiff, nconf, maxconf, nprob, maxprob = [], 0, 0.0, 0, 0.0
worst = None
for k in common:
    a, b = A[k], B[k]
    if a.get("action") != b.get("action"):
        dispdiff.append((a.get("case_id"), a.get("event_index"), a.get("action"), b.get("action")))
    ca, cb = a.get("confidence"), b.get("confidence")
    if isinstance(ca, (int, float)) and isinstance(cb, (int, float)) and abs(ca - cb) > 1e-12:
        nconf += 1
        maxconf = max(maxconf, abs(ca - cb))
    pa, pb = a.get("probabilities") or {}, b.get("probabilities") or {}
    diffed = False
    for key in set(pa) | set(pb):
        va, vb = pa.get(key), pb.get(key)
        if isinstance(va, (int, float)) and isinstance(vb, (int, float)):
            d = abs(va - vb)
            if d > 1e-12:
                diffed = True
                if d > maxprob:
                    maxprob, worst = d, (a.get("case_id"), key, va, vb)
    if diffed:
        nprob += 1
print(f"DISPOSITION_DIFFS={len(dispdiff)}")
for c, e, x, y in dispdiff[:25]:
    print(f"   case={c} event={e}: A={x} B={y}")
print(f"CONFIDENCE_DIFFS={nconf}/{len(common)} max_abs_delta={maxconf:.6f}")
print(f"PROBABILITY_RECORDS_DIFFERING={nprob}/{len(common)} max_abs_delta={maxprob:.6f}")
if worst:
    print(f"   worst prob delta: case={worst[0]} key={worst[1]} A={worst[2]} B={worst[3]}")
