#!/usr/bin/env python3
"""Render the cohort results tables from analyse.py output. Exact, unrounded."""
import json, sys, importlib.util, os
W="/teamspace/studios/this_studio/laptopguard"
sys.path.insert(0,W); import arms as A

res=json.load(open(sys.argv[1]))
BOARD={"Gemma 4 judge":0.71248247,"OpenJev":0.70231214,"Jev":0.54152824,
 "gemma-4-26B-A4B-it":0.47495961,"open-jev-qwen-27b (shipped)":0.33206107,
 "open-jev-qwen-27b (re-thresholded)":0.73876404,"DiffusionGemma":0.26792453,
 "bespoke-nimble-9b":0.21568627,"SecJudge":0.20724154,"open-jev-qwen-9b":0.17551020,
 "open-jev-qwen-2b":0.17194570,"decider-2b":0.10843373,"jevify":0.04921700}

def g(d,*ks):
    for k in ks:
        if d is None: return None
        d=d.get(k)
    return d

cands=[k for k in res if k in A.ARMS and not A.ARMS[k].get("control")]
ctrls=[k for k in res if k in A.ARMS and A.ARMS[k].get("control")]

print("="*132)
print("TABLE 1 -- CANDIDATES: block-only F1 at shipped argmax vs best threshold on P(block)")
print("="*132)
print("%-32s %-26s %-13s %11s %11s %11s  %s" % (
    "arm","licence / origin","params","shipped F1","best F1","matchFPR F1","best-F1 tp/fp/fn/tn"))
rows=[]
for k in cands:
    r=res[k]; a=A.ARMS[k]
    sh=g(r,"shipped_block_only","f1")
    bv=g(r,"by_variable","P(block)")
    bf=g(bv,"best_f1","f1"); mf=g(bv,"at_openjev_fpr","f1")
    rows.append((bf if bf is not None else -1,k,a,sh,bf,mf,bv))
rows.sort(reverse=True)
for _,k,a,sh,bf,mf,bv in rows:
    b=g(bv,"best_f1")
    print("%-32s %-26s %13s %11.8f %11.8f %11s  %s" % (
        k, (a["licence"][:16]+" / "+a["origin"].split("(")[0].strip())[:26],
        "{:,}".format(a["params"]),
        sh if sh is not None else float("nan"),
        bf if bf is not None else float("nan"),
        ("%.8f"%mf) if mf is not None else "n/a",
        "%d/%d/%d/%d"%(b["tp"],b["fp"],b["fn"],b["tn"]) if b else "-"))

print()
print("="*132)
print("TABLE 2 -- CONTROLS (bare masked-LM backbones, no safety training). Predicted: near chance.")
print("="*132)
for k in ctrls:
    r=res[k]; bv=g(r,"by_variable","P(block)")
    print("%-32s bestF1=%.8f  AUC=%.8f  tp/fp/fn/tn=%s" % (
        k, g(bv,"best_f1","f1"), g(bv,"auc_mann_whitney"),
        "%d/%d/%d/%d"%tuple(g(bv,"best_f1")[x] for x in ("tp","fp","fn","tn"))))
print("  (AUC 0.5 == chance. An AUC is a ranking statistic and is NOT comparable to an F1.)")

print()
print("="*132)
print("TABLE 3 -- PER RANKING VARIABLE, all arms (block-only lens; best-F1 point)")
print("="*132)
for k in [r[1] for r in rows]+ctrls:
    r=res[k]
    print("\n%s   [%s]" % (k, r["readout"]))
    for v,d in sorted(r["by_variable"].items()):
        b=d["best_f1"]; z=d["zero_false_positive"]; m=d["at_openjev_fpr"]
        print("   %-24s AUC=%9.6f  bestF1=%.8f thr=%-11.6g tp=%-4d fp=%-4d fn=%-4d tn=%-4d" % (
            v, d["auc_mann_whitney"] if d["auc_mann_whitney"] is not None else float("nan"),
            b["f1"], b["threshold"], b["tp"], b["fp"], b["fn"], b["tn"]))
        if m: print("   %-24s  matchedFPR(%.8f): F1=%.8f tp=%d fp=%d recall=%.6f" % (
            "", m["target_fpr"], m["f1"], m["tp"], m["fp"], m["recall"]))
        if z: print("   %-24s  zero-FP: tp=%d recall_retained=%.8f  FPR=0 Wilson95=[%.8f, %.8f] n=%d" % (
            "", z["tp"], z["recall_retained"], z["fpr_wilson95"][0], z["fpr_wilson95"][1],
            r["negatives_D"]))
        else: print("   %-24s  zero-FP: none achievable" % "")

print()
print("="*132)
print("TABLE 4 -- any-intervention lens at shipped argmax (action != allow)")
print("="*132)
for k in [r[1] for r in rows]+ctrls:
    s=res[k].get("shipped_any_intervention"); b=res[k].get("shipped_block_only")
    print("%-32s any-int F1=%.8f tp/fp/fn/tn=%d/%d/%d/%d   | block-only F1=%.8f" % (
        k, s["f1"], s["tp"], s["fp"], s["fn"], s["tn"], b["f1"]))

print()
print("="*132); print("PUBLISHED BOARD (block-only F1 at shipped operating points)"); print("="*132)
for k,v in sorted(BOARD.items(), key=lambda x:-x[1]): print("  %-38s %.8f" % (k,v))
print()
print("coverage check (must be 3817 scorable / 436 pos / 3381 neg):")
for k in [r[1] for r in rows]+ctrls:
    r=res[k]
    flag="" if r["scorable_covered"]==3817 else "   <-- INCOMPLETE"
    print("  %-32s rows=%-6d covered=%-5d pos=%-4d neg=%-5d err_rows=%d%s" % (
        k, r["rows"], r["scorable_covered"], r["positives_A_B"], r["negatives_D"],
        r["error_rows"], flag))
