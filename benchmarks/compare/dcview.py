#!/usr/bin/env python3
"""DefenseClaw decisions on the comparison sets, from one s7-gate run made with --corpora corpora_compare.json.

  python3 dcview.py --gate-label cmp-dc-herm2 --name dc-rules [--s7c ~/s7c] [--score]

For the trajectory sets with real tool results (dtap, mcphunt, agentic-redteam) the run has two corpora per side: the hook
surface (cmp-<set>-<s>: PreToolUse on every call) and the tool-result surface (cmp-<set>-<s>-tr: PostToolUse on the real
result). A deployed DefenseClaw runs both, so the view merges them per event (the stronger action wins), exactly as the
competitor adapters record both the call check and the tool-output check of the same event. Other sets are copied as they are.
Writes <s7c>/compare/runs/<name>/decisions/... and RUN.json (the gate run's RUN.json plus the merge note); --score runs s7gate.py.
"""
import argparse, glob, json, os, re, shutil, subprocess, sys

LEVEL = {"block": 2, "alert": 1, "confirm": 1}


def lvl(r):
    return max(LEVEL.get(r.get("action"), 0), LEVEL.get(r.get("raw_action"), 0))


def read_rows(d, pack):
    rows = []
    for f in sorted(glob.glob(f"{d}/*-{pack}*.jsonl")):
        if os.path.basename(f).startswith("ids."):
            continue
        for l in open(f):
            if l.strip():
                rows.append(json.loads(l))
    return rows


def ids_of(d):
    out = []
    for f in sorted(glob.glob(f"{d}/ids.*.txt")):
        out += [l.strip() for l in open(f) if l.strip()]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gate-label", required=True); ap.add_argument("--name", required=True)
    ap.add_argument("--s7c", default=os.path.expanduser("~/s7c")); ap.add_argument("--score", action="store_true")
    a = ap.parse_args()
    src = os.path.join(a.s7c, "gate", a.gate_label)
    run = json.load(open(os.path.join(src, "RUN.json")))
    packs = run.get("packs") or ["default", "permissive", "strict"]
    out = os.path.join(a.s7c, "compare", "runs", a.name)
    if os.path.exists(out):
        shutil.rmtree(out)
    os.makedirs(os.path.join(out, "decisions"))
    merged = []
    for d in sorted(glob.glob(os.path.join(src, "decisions", "cmp-*"))):
        corpus = os.path.basename(d)
        if corpus.endswith("-tr"):
            continue
        od = os.path.join(out, "decisions", corpus)
        tr = d + "-tr"
        if not os.path.isdir(tr):
            shutil.copytree(d, od)
            continue
        os.makedirs(od)
        ids = ids_of(d)
        open(os.path.join(od, "ids.g0.txt"), "w").write("\n".join(ids) + "\n")
        for pack in packs:
            base = read_rows(d, pack); post = {}
            for r in read_rows(tr, pack):
                k = (r["case"], r.get("idx", 0))
                if k not in post or lvl(r) > lvl(post[k]):
                    post[k] = r
            n_up = 0
            with open(os.path.join(od, f"g0-{pack}.jsonl"), "w") as f:
                for r in base:
                    p = post.get((r["case"], r.get("idx", 0)))
                    if p and lvl(p) > lvl(r):
                        r = dict(r); n_up += 1
                        r["action"] = p.get("action"); r["raw_action"] = p.get("raw_action")
                        r["rule_ids"] = sorted(set(r.get("rule_ids") or []) | set(p.get("rule_ids") or []))
                        r.setdefault("extra", {})
                        r["extra"] = dict(r["extra"] or {}, merged_from="tool-result")
                    f.write(json.dumps(r) + "\n")
            # completeness markers: both shards must have completed for the merged shard to count as complete
            ok_b = all(os.path.exists(x) for x in glob.glob(f"{d}/*-{pack}*.jsonl.ok")) and glob.glob(f"{d}/*-{pack}*.jsonl.ok")
            ok_t = all(os.path.exists(x) for x in glob.glob(f"{tr}/*-{pack}*.jsonl.ok")) and glob.glob(f"{tr}/*-{pack}*.jsonl.ok")
            rcs = [open(x).read().split()[0] for x in glob.glob(f"{d}/*-{pack}*.jsonl.rc") + glob.glob(f"{tr}/*-{pack}*.jsonl.rc")]
            rc = "0" if rcs and all(x == "0" for x in rcs) else (next((x for x in rcs if x != "0"), "1"))
            open(os.path.join(od, f"g0-{pack}.jsonl.rc"), "w").write(rc + "\n")
            if ok_b and ok_t:
                open(os.path.join(od, f"g0-{pack}.jsonl.ok"), "w").write("ok\n")
            merged.append(dict(corpus=corpus, pack=pack, events_raised_by_tool_result=n_up))
    run = dict(run, kind="defenseclaw", view=dict(from_gate=a.gate_label, merged_tool_result=merged))
    json.dump(run, open(os.path.join(out, "RUN.json"), "w"), indent=1)
    print("wrote", out, json.dumps(merged)[:600])
    if a.score:
        r = subprocess.run([sys.executable, "-I", os.path.join(a.s7c, "s7gate.py"), "score", "--corpora", os.path.join(a.s7c, "corpora_compare.json"), "--out", out],
                           cwd=a.s7c, capture_output=True, text=True)
        print(r.stdout[-3000:], r.stderr[-1500:])


if __name__ == "__main__":
    main()
