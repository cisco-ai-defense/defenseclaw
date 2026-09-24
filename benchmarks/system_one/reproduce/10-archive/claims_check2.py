import json
R = "$WORK/cohort-rank/out/"
ra = json.load(open(R + "ranking-analysis.json"))
cr = json.load(open(R + "cohort-rank.json"))

print("=== length cue, all variables ===")
for stage in ("length_cue_no_model_s2", "length_cue_no_model_s3"):
    print(stage)
    for var, d in cr[stage].items():
        print("   %-34s auc=%s" % (var, d.get("auc")))

print("")
print("=== arms_s3 type/keys ===")
a3 = cr["arms_s3"]
print(type(a3).__name__, (list(a3)[:8] if isinstance(a3, dict) else len(a3)))
sample = a3[list(a3)[0]] if isinstance(a3, dict) else a3[0]
print("per-arm keys:", list(sample)[:40] if isinstance(sample, dict) else type(sample))

print("")
print("=== truncation per s3 arm ===")
it = a3.items() if isinstance(a3, dict) else [(x.get("arm"), x) for x in a3]
for nm, a in it:
    if not isinstance(a, dict):
        continue
    tr = {k: v for k, v in a.items()
          if any(s in k.lower() for s in ("trunc", "max_len", "cap"))}
    if tr:
        print("   %-34s %s" % (nm, json.dumps(tr)[:240]))

print("")
print("=== keys mentioning fpr/zero/gate/cap ===")
for name, src in (("ranking-analysis", ra), ("cohort-rank", cr)):
    for k in src:
        if any(s in k.lower() for s in ("fpr", "zero", "gate", "cap")):
            print("   [%s] %s = %s" % (name, k, json.dumps(src[k])[:500]))
