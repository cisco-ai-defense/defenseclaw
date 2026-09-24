import json
d = json.load(open("$WORK/cohort-rank/out/ranking-analysis.json"))
FLOOR = 0.20503174229955326
arms = d["candidate_ranking_by_length_controlled_auc_primary_block_variable"]
print("s2 block-only trivial floor = %r" % FLOOR)
print("%d candidates" % len(arms))
fails = []
for a in sorted(arms, key=lambda x: x["shipped_f1"]):
    below = a["shipped_f1"] <= FLOOR
    if below:
        fails.append(a["arm"])
    print("  %-4s %-34s shipped_f1=%.12f  field_beats=%s"
          % ("FAIL" if below else "pass", a["arm"], a["shipped_f1"],
             a.get("shipped_beats_trivial_floor")))
print("")
print("computed at-or-below floor : %d" % len(fails))
print("field says beats==False    : %d"
      % sum(1 for a in arms if a.get("shipped_beats_trivial_floor") is False))
print("strictly-below (<) count   : %d"
      % sum(1 for a in arms if a["shipped_f1"] < FLOOR))
# is the floor itself recorded anywhere?
for k in d:
    if "floor" in k.lower():
        print("key %s = %s" % (k, json.dumps(d[k])[:300]))
