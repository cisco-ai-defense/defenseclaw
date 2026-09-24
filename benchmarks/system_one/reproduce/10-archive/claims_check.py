import json
R = "$WORK/cohort-rank/out/"
ra = json.load(open(R + "ranking-analysis.json"))
cr = json.load(open(R + "cohort-rank.json"))


def show(label, val):
    print("%-52s %s" % (label, val))


print("=== length cue ===")
show("length_cue_no_model_s2", json.dumps(cr["length_cue_no_model_s2"])[:220])
show("length_cue_no_model_s3", json.dumps(cr["length_cue_no_model_s3"])[:220])

print("")
print("=== s2->s3 transfer (gates) ===")
t = ra["s2_to_s3_transfer"]
if isinstance(t, dict):
    for k, v in t.items():
        show("  " + k, json.dumps(v)[:220])

print("")
print("=== chance band / floors ===")
show("s3_chance_band", json.dumps(ra["s3_chance_band"])[:220])
show("s3_trivial_floor.f1", ra["s3_trivial_floor"]["f1"])

print("")
print("=== truncation for deberta (s2 + s3) ===")
for key in ("arms_s2", "arms_s3"):
    for a in cr.get(key, []):
        nm = a.get("arm") or a.get("model")
        if nm and "deberta" in nm:
            tr = {k: v for k, v in a.items() if "trunc" in k.lower() or "max_len" in k.lower() or "cap" in k.lower()}
            show("  %s %s" % (key, nm), json.dumps(tr)[:300])

print("")
print("=== caps / truncation for ranks 2 and 3 on s3 ===")
for a in cr.get("arms_s3", []):
    nm = a.get("arm") or a.get("model")
    tr = {k: v for k, v in a.items() if "trunc" in k.lower() or "max_len" in k.lower()}
    show("  %s" % nm, json.dumps(tr)[:220])

print("")
print("=== any FPR-cap / zero-FP structures present ===")
for k in list(ra.keys()) + list(cr.keys()):
    if any(s in k.lower() for s in ("fpr", "zero", "gate", "cap")):
        src = ra if k in ra else cr
        show("key " + k, json.dumps(src[k])[:400])
