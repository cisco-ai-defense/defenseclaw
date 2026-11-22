import json, sys, collections as C
for f in sys.argv[1:]:
    cnt = {k: C.Counter() for k in ["dataset","surface","split","det_truth","exp_disp","src_truth","label_src","label_conf","applic","dialect","platform","tool","nevents","cat","grade_hn","domain","keys_payload","ev_keys","outcome"]}
    pos = C.Counter()
    n=0
    for line in open(f):
        r=json.loads(line); n+=1
        t=r["truth"]; s=r.get("strata",{}); p=r["payload"]
        cnt["dataset"][r["source"]["dataset"]]+=1
        cnt["surface"][r["surface"]]+=1
        cnt["split"][r["split"]]+=1
        cnt["det_truth"][t.get("deterministic_truth")]+=1
        cnt["exp_disp"][t.get("expected_disposition")]+=1
        cnt["src_truth"][t.get("source_truth")]+=1
        cnt["label_src"][t.get("label_source")]+=1
        cnt["label_conf"][t.get("label_confidence")]+=1
        cnt["applic"][t.get("applicability")]+=1
        cnt["platform"][s.get("platform")]+=1
        cnt["domain"][s.get("domain")]+=1
        cnt["grade_hn"][s.get("hard_negative")]+=1
        for c in t.get("categories") or []: cnt["cat"][c]+=1
        cnt["keys_payload"][",".join(sorted(p.keys()))]+=1
        evs = p.get("events") or [p]
        cnt["nevents"][min(len(evs),20)]+=1
        for e in evs:
            cnt["dialect"][e.get("dialect")]+=1
            cnt["tool"][e.get("tool_name")]+=1
            cnt["ev_keys"][",".join(sorted(e.keys()))]+=1
            cnt["outcome"][e.get("outcome")]+=1
        if t.get("expected_disposition") in ("block",):
            pos[(r["source"]["dataset"], t.get("deterministic_truth"))]+=1
    print("=====",f,n)
    for k,v in cnt.items(): print(k, v.most_common(25))
    print("block-pos by dataset/dettruth", pos.most_common(30))
