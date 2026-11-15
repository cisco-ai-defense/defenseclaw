#!/usr/bin/env python3
"""Exact-label corpora for two unmeasured guardrail surfaces, from the pinned AgentDojo runs (089ed468):
  tool-result-agentdojo.cases.jsonl  one case = one tool output; malicious = it contains the run's injected text (AgentDojo records it in
                                     `injections`), benign = a tool output from a run with no attack. Label = text presence, not compromise.
  prompt-agentdojo.cases.jsonl       one case = one user-turn text; malicious = an injection text pasted as the user turn,
                                     benign = the suites' real user requests.
Case text is the source text (public, MIT, download-only: never committed). usage: ad_surfaces.py RUNS_DIR OUT_DIR"""
import json, os, sys, glob, hashlib, random, collections
runs, out = sys.argv[1], sys.argv[2]; os.makedirs(out, exist_ok=True)
REV = "089ed468cf3ed0322acc66b0211f26d9d90dbf60"
def text(c):
    if isinstance(c, str): return c
    if isinstance(c, list): return "\n".join(b.get("content", "") if isinstance(b, dict) else str(b) for b in c if b)
    return ""
pos, ben, inj_texts, prompts = {}, {}, {}, {}
for f in glob.glob(os.path.join(runs, "**", "*.json"), recursive=True):
    try: d = json.load(open(f))
    except Exception: continue
    if not isinstance(d, dict) or "messages" not in d: continue
    suite = d.get("suite_name") or "?"; attacked = d.get("attack_type") not in (None, "none") or d.get("injection_task_id") not in (None, "none")
    injs = [v for v in (d.get("injections") or {}).values() if isinstance(v, str) and len(v.strip()) >= 30]
    for v in injs: inj_texts.setdefault(hashlib.sha256(v.encode()).hexdigest()[:20], (suite, d.get("attack_type"), v))
    calls = {}
    for m in d["messages"]:
        if m.get("role") == "user":
            u = text(m.get("content")).strip()
            if u and not attacked: prompts.setdefault(hashlib.sha256(u.encode()).hexdigest()[:20], (suite, u))
        for c in m.get("tool_calls") or []:
            if isinstance(c, dict): calls[c.get("id")] = c
        if m.get("role") != "tool": continue
        t = text(m.get("content"))
        if not t or len(t) < 20: continue
        call = m.get("tool_call") or calls.get(m.get("tool_call_id")) or {}
        k = hashlib.sha256(t.encode()).hexdigest()[:20]
        item = (suite, str(call.get("function") or "tool"), call.get("args") if isinstance(call.get("args"), dict) else {}, t)
        if attacked and any(v.strip()[:200] in t for v in injs): pos.setdefault(k, item)
        elif not attacked: ben.setdefault(k, item)
rnd = random.Random(20261113)
def cap(dct, n):
    ks = sorted(dct); return ks if len(ks) <= n else sorted(rnd.sample(ks, n))
def case(cid, surface, suite, st, ev, content=None):
    t = {"applicability": "in_scope", "source_truth": st, "deterministic_truth": "contextual_or_dual_use", "expected_disposition": "detect_only" if st == "malicious" else "allow",
         "label_confidence": "high", "label_source": "agentdojo:injection-text-presence", "categories": ["indirect_prompt_injection"] if st == "malicious" else []}
    p = dict(ev); 
    if content is not None: p["content"] = content
    return {"schema_version": "1", "id": cid, "split": "development", "surface": "action", "source": {"dataset": "agentdojo", "revision": REV, "original_id": cid[-60:], "license": "MIT", "redistribution": "download-only"},
            "payload": p, "truth": t, "strata": {"platform": "linux", "domain": suite, "split_group": cid[-24:], "trajectory_id": cid[-32:].rjust(32, "0"), "sequence_index": 0, "call_index": 0, "guardrail_surface": surface}}
n = collections.Counter()
with open(os.path.join(out, "tool-result-agentdojo.cases.jsonl"), "w") as o:
    for lab, dct in (("malicious", pos), ("benign", ben)):
        for k in cap(dct, 1500):
            suite, fn, args, t = dct[k]
            o.write(json.dumps(case(f"tr/agentdojo/{k}", "tool-result", suite, lab, {"tool_name": fn, "args": args, "dialect": "none", "outcome": "succeeded", "result": t})) + "\n"); n["tool-result:" + lab] += 1
with open(os.path.join(out, "prompt-agentdojo.cases.jsonl"), "w") as o:
    for k in cap(inj_texts, 1500):
        suite, at, v = inj_texts[k]
        o.write(json.dumps(case(f"pr/agentdojo/{k}", "prompt", suite, "malicious", {"tool_name": "__prompt__", "dialect": "none"}, content=v)) + "\n"); n["prompt:malicious"] += 1
    for k in cap(prompts, 1500):
        suite, u = prompts[k]
        o.write(json.dumps(case(f"pr/agentdojo/{k}", "prompt", suite, "benign", {"tool_name": "__prompt__", "dialect": "none"}, content=u)) + "\n"); n["prompt:benign"] += 1
print(dict(n), "pools", len(pos), len(ben), len(inj_texts), len(prompts))
