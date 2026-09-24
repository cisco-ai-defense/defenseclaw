import json, math, sys
from collections import defaultdict
from pathlib import Path
sys.path.insert(0, "/home/ubuntu/rescoring-remine")
import remine as H
DATA = Path("/home/ubuntu/.system-one-data/outputs"); COHORT = Path("/home/ubuntu/cohort-scoring/preds")
cases = [json.loads(l) for l in (DATA/"s2/cases.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
grades = {str(c["id"]): H.truth_grade(c) for c in cases}
scorable = [c for c, g in grades.items() if g in ("A","B","D")]
lab = {c: grades[c] in ("A","B") for c in scorable}; labels=[lab[c] for c in scorable]
npos=sum(labels); nneg=len(labels)-npos
out={}

# trivial baselines -- the honest floor for argmax F1 at this prevalence
out["trivial_baselines"] = {
  "block_every_case":  {"tp":npos,"fp":nneg,"fn":0,"tn":0,"f1":H.f1_of(npos,nneg,0),
                        "precision":npos/(npos+nneg),"recall":1.0,"fpr":1.0},
  "allow_every_case":  {"tp":0,"fp":0,"fn":npos,"tn":nneg,"f1":H.f1_of(0,0,npos)},
  "prevalence_positives_over_scorable": npos/len(labels),
  "note":"any argmax F1 at or below block_every_case carries no information about discrimination",
}
# AUC null band (Hanley-McNeil at A=0.5)
A=0.5; Q1=A/(2-A); Q2=2*A*A/(1+A)
se=math.sqrt((A*(1-A)+(npos-1)*(Q1-A*A)+(nneg-1)*(Q2-A*A))/(npos*nneg))
out["auc_null_band"]={"npos":npos,"nneg":nneg,"hanley_mcneil_se_at_auc_0.5":se,
  "chance_95pct_interval":[0.5-1.959963984540054*se, 0.5+1.959963984540054*se]}

# per-event natural prompt length (from a control: shrunk == 0 so input_tokens is natural)
tok=defaultdict(list)
for line in open(COHORT/"control-modernbert-base.jsonl"):
    r=json.loads(line); tok[str(r["case_id"])].append(r["input_tokens"])
tmax={c:max(v) for c,v in tok.items()}
t=[tmax[c] for c in scorable]
qs=sorted(t); cuts=[qs[int(len(qs)*f)] for f in (0.2,0.4,0.6,0.8)]
def bucket(x):
    b=0
    for c in cuts:
        if x>=c: b+=1
    return b
def length_controlled(sc):
    s=[sc[c] for c in scorable]; res={}
    for b in range(5):
        idx=[i for i in range(len(s)) if bucket(t[i])==b]
        a=H.mann_whitney_auc([s[i] for i in idx],[labels[i] for i in idx])
        res[b]={"cases":len(idx),"positives":sum(labels[i] for i in idx),"auc":a}
    aucs=[v["auc"] for v in res.values() if v["auc"] is not None]
    return {"overall_auc":H.mann_whitney_auc(s,labels),
            "mean_within_length_quintile_auc":sum(aucs)/len(aucs),
            "per_quintile":res}

# anchor variables, length-controlled
agg={}
for line in open(COHORT/"open-jev-qwen-2b-merged.jsonl"):
    r=json.loads(line); cid=str(r["case_id"]); p=r["probabilities"]
    b=float(p["disposition.block"]); c=float(p["disposition.confirm"]); a=float(p["disposition.allow"])
    e=agg.setdefault(cid,{"maxb":0.0,"maxc":0.0,"mina":1.0,"maxdiffB":-math.inf})
    e["maxb"]=max(e["maxb"],b); e["maxc"]=max(e["maxc"],c); e["mina"]=min(e["mina"],a)
    e["maxdiffB"]=max(e["maxdiffB"],b-c)
db={}
for line in open(COHORT/"deberta-v3-prompt-injection-v2.jsonl"):
    r=json.loads(line); cid=str(r["case_id"])
    db[cid]=max(db.get(cid,-math.inf), float(r["probabilities"]["injection.true"]))
out["length_controlled_auc"]={
 "deberta P(injection.true) [single scalar, A==B]": length_controlled(db),
 "anchor P(block) defA==defB": length_controlled({c:agg[c]["maxb"] for c in scorable}),
 "anchor P(block)-P(confirm) defA [FLAGGED VARIABLE]": length_controlled({c:agg[c]["maxb"]-agg[c]["maxc"] for c in scorable}),
 "anchor P(block)-P(confirm) defB [FLAGGED VARIABLE]": length_controlled({c:agg[c]["maxdiffB"] for c in scorable}),
 "anchor risk = 1-P(allow) defA==defB": length_controlled({c:1-agg[c]["mina"] for c in scorable}),
 "pure length counter (natural prompt tokens)": length_controlled(tmax),
}
# headline comparisons, exact
DEB_SHIP=0.21057810578105782; ANCHOR=0.17194570135746606
OJ_SHIP=0.7023121387283237; OJ_PUB=0.70231214; DEB_ORACLE=0.48
out["headline_comparisons"]={
 "deberta_shipped_minus_anchor_shipped": DEB_SHIP-ANCHOR,
 "deberta_shipped_beats_anchor": DEB_SHIP>ANCHOR,
 "deberta_shipped_minus_block_everything": DEB_SHIP-H.f1_of(npos,nneg,0),
 "anchor_shipped_minus_block_everything": ANCHOR-H.f1_of(npos,nneg,0),
 "openjev_shipped_recomputed": OJ_SHIP, "openjev_published_rounded": OJ_PUB,
 "openjev_shipped_minus_deberta_shipped": OJ_SHIP-DEB_SHIP,
 "deberta_shipped_as_fraction_of_openjev": DEB_SHIP/OJ_SHIP,
 "openjev_shipped_minus_deberta_ORACLE_ceiling": OJ_SHIP-DEB_ORACLE,
 "deberta_ORACLE_ceiling_as_fraction_of_openjev_shipped": DEB_ORACLE/OJ_SHIP,
 "deberta_ORACLE_reaches_openjev_shipped": DEB_ORACLE>OJ_SHIP,
}
print(json.dumps(out,indent=2,sort_keys=True))
Path("/home/ubuntu/cohort-scoring/final-comparisons.json").write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")
