#!/usr/bin/env python3
"""Tests for s7gate.py run completeness and the prompt scoring column (lane s7-hookscorerev, 2026-11-14).

  python3 -I test_s7gate_completeness.py [path/to/s7gate.py]     (default: s7gate.py beside this file); exit 0 = all pass

1. sr7 case (TASKS: response-owner decided 0 of 645, not caught): a run with a corpus whose harness_args the harness refuses (-surface response
   in a harness build without that surface) is INCOMPLETE in RUN.json, and its reason names the refusal; a later --resume --only <other corpus>
   that finishes cleanly must NOT turn RUN.json complete (the old code wrote complete: true from that subset).
2. Prompt surface (GAP-0554): the default column scores the UserPromptSubmit hook answer of old records (extra.hook_*) and new records alike;
   --effects-column inspect scores the text inspection; an old record with an empty hook answer counts as an error.
Everything runs in a temporary HOME (its own ~/s7c/corpora registry); nothing outside it is touched. Synthetic cases only.
"""

import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
GATE = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "s7gate.py")
FAKE = r"""#!/usr/bin/env python3
# fake s7bench: refuses -surface response like a harness build that lacks it; otherwise one decision row per event of every listed case
import json, sys
a = sys.argv[1:]
if "-h" in a: print("usage: fake"); sys.exit(0)
if "-surface" in a and a[a.index("-surface") + 1] not in ("hook", "prompt", "tool-result"):
    print("-surface must be hook, prompt or tool-result", file=sys.stderr); sys.exit(2)
ids = {l.strip() for l in open(a[a.index("-ids") + 1]) if l.strip()}
with open(a[a.index("-out") + 1], "w") as o:
    for line in open(a[a.index("-corpus") + 1]):
        c = json.loads(line)
        if c["id"] in ids:
            for i, _ in enumerate(c["payload"].get("events") or [c["payload"]]):
                o.write(json.dumps({"case": c["id"], "idx": i, "action": "allow", "raw_action": "allow", "status": 200}) + "\n")
"""


def case(cid, truth):
    return {
        "id": cid,
        "surface": "action",
        "source": {"dataset": "synthetic/s7rev"},
        "strata": {"platform": "linux", "provider": "claudecode"},
        "truth": {"source_truth": truth, "applicability": "in_scope"},
        "payload": {"events": [{"tool_name": "Bash", "tool_input": {"command": "ls"}}]},
    }


def gate(home, *args):
    env = dict(os.environ, HOME=home)
    return subprocess.run(
        [sys.executable, "-I", GATE] + list(args), env=env, capture_output=True, text=True, timeout=300
    )


fails = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else ": " + detail))
    if not cond:
        fails.append(name)


with tempfile.TemporaryDirectory() as home:
    croot = os.path.join(home, "s7c", "corpora")
    os.makedirs(croot)
    files = {}
    for name in ("good", "resp"):
        p = os.path.join(croot, name + ".cases.jsonl")
        with open(p, "w") as f:
            for i in range(4):
                f.write(json.dumps(case("%s-%d" % (name, i), "benign" if i % 2 else "malicious")) + "\n")
        files[name] = p
        r = gate(home, "register-corpus", p, "--version", "t1")
        check("register " + name, r.returncode == 0, r.stderr[-300:])
    cj = os.path.join(home, "corpora.json")
    json.dump(
        {
            "good": {"files": [files["good"]]},
            "resp": {"files": [files["resp"]], "harness_args": ["-surface", "response"]},
        },
        open(cj, "w"),
    )
    fake = os.path.join(home, "fake-s7bench")
    open(fake, "w").write(FAKE)
    os.chmod(fake, 0o755)
    out = os.path.join(home, "gate", "t1")
    scr = os.path.join(home, "scr")
    os.makedirs(scr)
    common = [
        "--bin",
        fake,
        "--policy-dir",
        home,
        "--corpora",
        cj,
        "--out",
        out,
        "--packs",
        "default",
        "--parallel",
        "2",
        "--scratch-dir",
        scr,
        "--min-free-gb",
        "1",
    ]
    r1 = gate(home, "run", *common)
    run1 = json.load(open(os.path.join(out, "RUN.json")))
    check("first run exits 4", r1.returncode == 4, "rc %d %s" % (r1.returncode, r1.stdout[-400:] + r1.stderr[-400:]))
    check("first run RUN.json incomplete", run1["complete"] is False, json.dumps(run1)[:300])
    rs = [x for x in run1["incomplete_shards"] if x["shard"].startswith("resp/")]
    check("incomplete shard names its corpus", bool(rs), json.dumps(run1["incomplete_shards"])[:300])
    check(
        "reason names the refused argument",
        any("harness refused its arguments" in " ".join(x["reasons"]) for x in rs),
        json.dumps(rs)[:400],
    )
    check(
        "good corpus complete",
        not [x for x in run1["incomplete_shards"] if x["shard"].startswith("good/")],
        json.dumps(run1["incomplete_shards"])[:300],
    )
    # resume only the good corpus: its shards are already done; the run dir still has the refused corpus
    r2 = gate(home, "run", *common, "--only", "good")
    run2 = json.load(open(os.path.join(out, "RUN.json")))
    check("resume --only subset keeps RUN.json incomplete", run2["complete"] is False, json.dumps(run2)[:300])
    check("resume --only subset exits 4", r2.returncode == 4, "rc %d" % r2.returncode)
    check(
        "resume reports the shards outside its set", "outside this --resume/--only set" in r2.stdout, r2.stdout[-400:]
    )
    a1 = gate(home, "audit", "--gate-dir", os.path.join(home, "gate"), "--corpora", cj)
    check("audit agrees (exit 4)", a1.returncode == 4, "rc %d %s" % (a1.returncode, a1.stdout[-200:]))

# 2. prompt column

spec = importlib.util.spec_from_loader("s7gate_t", importlib.machinery.SourceFileLoader("s7gate_t", GATE))
g = importlib.util.module_from_spec(spec)
sys.argv = [GATE]
spec.loader.exec_module(g)
with tempfile.TemporaryDirectory() as d:
    rows = [
        # old harness: action = InspectText alert, hook answer allow in extra.hook_*
        {
            "case": "old-1",
            "mapped": "prompt",
            "status": 200,
            "action": "alert",
            "raw_action": "alert",
            "findings": ["ENT-X:y"],
            "extra": {"hook_action": "allow", "hook_raw_action": "allow", "hook_findings": ""},
        },
        # old harness: hook answered alert, text inspection allow
        {
            "case": "old-2",
            "mapped": "prompt",
            "status": 200,
            "action": "allow",
            "raw_action": "allow",
            "extra": {"hook_action": "alert", "hook_raw_action": "alert", "hook_findings": "PI-1:z"},
        },
        # old harness: the hook gave no answer (empty action, http 400)
        {
            "case": "old-3",
            "mapped": "prompt",
            "status": 400,
            "action": "alert",
            "raw_action": "alert",
            "extra": {"hook_action": "", "hook_raw_action": ""},
        },
        # fixed harness: hook answer allow, inspect alert
        {
            "case": "new-1",
            "mapped": "prompt",
            "status": 200,
            "action": "allow",
            "raw_action": "allow",
            "extra": {"scored_via": "hook", "inspect_action": "alert", "inspect_findings": "ENT-X:y"},
        },
        # a tool call row is never touched
        {
            "case": "tool-1",
            "mapped": "shell",
            "status": 200,
            "action": "alert",
            "raw_action": "alert",
            "extra": {"hook_action": "allow"},
        },
    ]
    with open(os.path.join(d, "alice-default.jsonl"), "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    p = g.load_decisions(d, "default")
    check("default: old record scores the hook answer (allow)", p["old-1"]["alert"] is False, str(p["old-1"]))
    check(
        "default: old record hook alert counts",
        p["old-2"]["alert"] is True and "PI-1" in p["old-2"]["rules"],
        str(p["old-2"]),
    )
    check(
        "default: old record empty hook answer is an error, not an alert",
        p["old-3"]["alert"] is False and p["old-3"]["err"] == 1,
        str(p["old-3"]),
    )
    check(
        "default: new record scores the hook answer",
        p["new-1"]["alert"] is False and p["new-1"]["via"] == "hook",
        str(p["new-1"]),
    )
    check("default: tool rows unchanged", p["tool-1"]["alert"] is True and "via" not in p["tool-1"], str(p["tool-1"]))
    q = g.load_decisions(d, "default", "inspect")
    check("inspect: old record scores the text inspection", q["old-1"]["alert"] is True, str(q["old-1"]))
    check(
        "inspect: new record scores extra.inspect_action",
        q["new-1"]["alert"] is True and "ENT-X" in q["new-1"]["rules"],
        str(q["new-1"]),
    )
    h = g.load_decisions(d, "default", "hook")
    check(
        "hook column == default on prompts",
        all(h[k]["alert"] == p[k]["alert"] for k in p),
        str({k: (h[k]["alert"], p[k]["alert"]) for k in p}),
    )
print("ALL PASS" if not fails else "FAILED: " + ", ".join(fails))
sys.exit(1 if fails else 0)
