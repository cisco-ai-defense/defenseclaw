#!/usr/bin/env python3
"""Build the published comparison sets from the S7 case-v1 corpora (public sources only).

  python3 -I sets.py --s7c ~/s7c --out ~/s7c/compare/sets

Every set is a filter over existing corpus files by source.dataset; case ids, payloads and labels are unchanged, so every
tool (DefenseClaw included) is scored on the same cases by the same scorer (s7gate.py score) under the same label overlay.
Owner traces, our own authored suites and ledger repros are never selected.

Split: the frozen S7 holdout split v1 (holdout.py, sha in holdout-split-v1.json). A case is HOLDOUT here only when it is holdout
under every corpus name it has been scored under before (the source corpus and its -n1 version, whose pre-registered
shellrecall overrides differ), so no case that any S7 lane could read as tune is reported. Everything else is TUNE, the
only side a threshold may be fitted on. Large benign-only sets are sampled with a fixed seed, the same ids for every tool.
Writes <out>/<set>.{holdout,tune}.cases.jsonl, <s7c>/corpora_compare.json (the scorer registry) and <out>/SETS.json (counts).
"""
import argparse, collections, hashlib, json, os, random, sys

# set name -> list of (source corpus registry name, file relative to s7c/corpora, dataset names kept, extra registry names the case has been scored under)
SETS = {
    "agentdojo":        [("public-surfaces-v2-n1", "n1/public-surfaces-v2.cases.jsonl", {"agentdojo"}, ["public-surfaces-v2", "public-surfaces", "public-surfaces-n1"])],
    "mcptox":           [("public-surfaces-v2-n1", "n1/public-surfaces-v2.cases.jsonl", {"mcptox"}, ["public-surfaces-v2", "public-surfaces", "public-surfaces-n1"])],
    "injecagent":       [("public-surfaces-v2-n1", "n1/public-surfaces-v2.cases.jsonl", {"injecagent"}, ["public-surfaces-v2", "public-surfaces", "public-surfaces-n1"])],
    "mcphunt":          [("s2-v2", "s2-v2.cases.jsonl", {"lihaonan0716/mcphunt-agent-traces"}, ["s2"]),
                         ("public-surfaces-v2-n1", "n1/public-surfaces-v2.cases.jsonl", {"lihaonan0716/mcphunt-agent-traces"}, ["public-surfaces-v2", "public-surfaces", "public-surfaces-n1"])],
    "dtap":             [("s2-v2", "s2-v2.cases.jsonl", {"AI-Secure/DTap-Bench-Agent-Trajectories"}, ["s2"]),
                         ("s3", "s3.cases.jsonl", {"AI-Secure/DTap-Bench-Agent-Trajectories"}, []),
                         ("public-surfaces-v2-n1", "n1/public-surfaces-v2.cases.jsonl", {"AI-Secure/DTap-Bench-Agent-Trajectories"}, ["public-surfaces-v2", "public-surfaces", "public-surfaces-n1"])],
    "agentic-redteam":  [("s2-v2", "s2-v2.cases.jsonl", {"agentic-redteam-benchmark"}, ["s2"])],
    "nemotron-terminal": [("s3", "s3.cases.jsonl", {"nvidia/Nemotron-RL-Agentic-Terminal-Pivot-v1"}, [])],
    "extra-public":     [("extra-public-n1", "n1/extra-public.cases.jsonl", None, ["extra-public"])],
    "llm-labelled-augur": [("llm-labelled-augur-n1", "n1/llm-labelled.cases.jsonl", None, ["llm-labelled-augur"])],
    "prompt-agentdojo": [("prompt-agentdojo", "prompt-agentdojo.cases.jsonl", None, [])],
    "tool-result-agentdojo": [("tool-result-agentdojo", "tool-result-agentdojo.cases.jsonl", None, [])],
    "windows-shell-public": [("windows-shell", "windows-shell.cases.jsonl", {"redcanaryco/atomic-red-team", "trace-commons/agent-traces"}, [])],
}
SAMPLE = {"nemotron-terminal": 1000}          # cases per side, fixed seed, benign-only set (FPR only)
SEED = "s7-compare-2026-11-13"
HARNESS = {"prompt-agentdojo": ["-surface", "prompt"], "tool-result-agentdojo": ["-surface", "tool-result"]}
TR_SETS = {"dtap", "mcphunt", "agentic-redteam"}   # trajectories with real tool results: also run the tool-result surface
NEVER = ("Vineethsain/agent-transcripts", "defenseclaw-")      # owner traces and our own authored / ledger rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--s7c", default=os.path.expanduser("~/s7c")); ap.add_argument("--out", required=True)
    a = ap.parse_args()
    sys.path.insert(0, a.s7c)
    import holdout as HOLD
    from surface import case_surface
    h = HOLD.load()
    labels = {}
    for l in open(f"{a.s7c}/labels/current.jsonl"):
        if l.startswith("{"):
            r = json.loads(l); labels[r["id"]] = r
    os.makedirs(a.out, exist_ok=True)
    reg, summary = {}, {"split_sha256": HOLD.sha256(), "labels_sha256": hashlib.sha256(open(f"{a.s7c}/labels/current.jsonl", "rb").read()).hexdigest(), "seed": SEED, "sets": {}}
    for name, srcs in SETS.items():
        rows = {"holdout": [], "tune": []}; seen = set()
        stat = collections.defaultdict(collections.Counter)
        for corpus, rel, keep, also in srcs:
            for line in open(f"{a.s7c}/corpora/{rel}"):
                r = json.loads(line)
                ds = r["source"]["dataset"]
                if keep is not None and ds not in keep: continue
                if ds.startswith(NEVER): continue
                if r["id"] in seen: continue
                seen.add(r["id"])
                sides = {HOLD.split_of(n, r, h) for n in [corpus] + also}
                side = "holdout" if sides == {"holdout"} else "tune"
                rows[side].append(line)
                t = dict(r["truth"]); lb = labels.get(r["id"])
                if lb and lb.get("source_truth"): t["source_truth"] = lb["source_truth"]; t["applicability"] = "in_scope" if lb["source_truth"] in ("benign", "malicious") else "out_of_scope"
                if lb and lb.get("expected_disposition"): t["expected_disposition"] = lb["expected_disposition"]
                st = "benign" if t.get("source_truth") == "benign" and t.get("applicability", "in_scope") == "in_scope" else "attack" if t.get("source_truth") in ("malicious", "sensitive") and t.get("applicability", "in_scope") == "in_scope" else "excluded"
                stat[side][st] += 1
                if st == "attack" and t.get("expected_disposition") == "block": stat[side]["attack_expected_block"] += 1
                stat[side]["surface:" + case_surface(r)] += 1
                stat[side]["dataset:" + ds] += 1; stat[side]["license:" + str(r["source"].get("license"))] += 1
                stat[side]["events"] += len(r["payload"].get("events") or [r["payload"]])
                stat[side]["has_user_task"] += bool(r["payload"].get("user_intent") or r["payload"].get("content"))
                stat[side]["has_tool_result"] += bool(r["payload"].get("result") or r["payload"].get("event_result") or any(e.get("tool_result") for e in r["payload"].get("events") or []))
        for side in ("holdout", "tune"):
            lines = rows[side]
            if name in SAMPLE and len(lines) > SAMPLE[name]:
                lines = sorted(lines, key=lambda l: hashlib.sha256((SEED + "|" + json.loads(l)["id"]).encode()).hexdigest())[:SAMPLE[name]]
                stat[side]["sampled_from"] = len(rows[side]); stat[side]["sampled"] = len(lines)
            p = f"{a.out}/{name}.{side}.cases.jsonl"
            with open(p, "w") as f: f.writelines(lines)
            key = f"cmp-{name}-{side[0]}"
            reg[key] = {"files": [p]}
            if name in HARNESS: reg[key]["harness_args"] = HARNESS[name]
            if name in TR_SETS: reg[key + "-tr"] = {"files": [p], "harness_args": ["-surface", "tool-result"]}
            stat[side]["sha256"] = hashlib.sha256(open(p, "rb").read()).hexdigest()
        summary["sets"][name] = {s: dict(stat[s]) for s in ("holdout", "tune")}
        print(name, {s: (stat[s]["benign"], stat[s]["attack"], stat[s]["excluded"]) for s in ("holdout", "tune")})
    json.dump(reg, open(f"{a.s7c}/corpora_compare.json", "w"), indent=1)
    json.dump({k: v for k, v in reg.items() if "-h" in k[-5:]}, open(f"{a.s7c}/corpora_compare_h.json", "w"), indent=1)   # holdout only (LLM-backed runs)
    json.dump(summary, open(f"{a.out}/SETS.json", "w"), indent=1, sort_keys=True)


if __name__ == "__main__":
    main()
