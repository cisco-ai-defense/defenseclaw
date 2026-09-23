import json, collections, hashlib
P="$WORK/.system-one-data/outputs/secjudge/contamination/cache/nvidia__Nemotron-RL-Agentic-Terminal-Pivot-v1/atcb_terminal_pivot_release_final_v2.jsonl"
n=0; uuids=set(); tasks=collections.Counter(); schemas=collections.Counter(); tools=collections.Counter()
harness=collections.Counter(); agents=collections.Counter()
out=open("$WORK/.system-one-data/outputs/secjudge/contamination/work/pivot_extract.jsonl","w")
for l in open(P, encoding="utf-8", errors="replace"):
    l=l.strip()
    if not l: continue
    n+=1
    d=json.loads(l)
    u=d.get("uuid"); uuids.add(u)
    tasks[d.get("task_name")]+=1
    schemas[d.get("schema_version")]+=1
    tools[d.get("tool_name")]+=1
    md=d.get("metadata") or {}
    harness[md.get("harness")]+=1
    ar=d.get("agent_ref") or {}
    agents[ar.get("name")]+=1
    inp=(d.get("responses_create_params") or {}).get("input") or []
    first=""
    for m in inp:
        if isinstance(m,dict) and m.get("content"):
            first=str(m["content"]); break
    out.write(json.dumps({"uuid":u,"task_name":d.get("task_name"),"tool_name":d.get("tool_name"),
        "first_content":first[:20000], "expected_answer":str(d.get("expected_answer"))[:8000],
        "src_traj":md.get("source_trajectory_uid"), "turn":md.get("pivot_agent_turn_index")})+"\n")
out.close()
print("rows",n,"distinct uuids",len(uuids))
print("schema_versions",dict(schemas))
print("tool_names",dict(tools.most_common(10)))
print("harness",dict(harness))
print("agent_ref names",dict(agents.most_common(5)))
print("distinct task_names",len(tasks),"top",tasks.most_common(5))
json.dump({"rows":n,"distinct_uuids":len(uuids),"schema_versions":dict(schemas),"tool_names":dict(tools),
           "harness":dict(harness),"agent_names":dict(agents),"n_distinct_task_names":len(tasks)},
          open("$WORK/.system-one-data/outputs/secjudge/contamination/work/pivot_stats.json","w"), indent=2)
json.dump(sorted(uuids), open("$WORK/.system-one-data/outputs/secjudge/contamination/work/pivot_uuids.json","w"))
print("DONE")
