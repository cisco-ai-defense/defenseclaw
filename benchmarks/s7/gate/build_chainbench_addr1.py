#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: E501, E401  (the checked-in benchmark tooling has always been long-line)
"""build_chainbench_addr1.py: build_chainbench.py (chainbench-v1) plus GAP-1585 address consistency: the task text of every session (payload and event
content / user_intent) gets the call-side address redaction (addr_consistency.redact_addresses), and the check runs on the output at the end.
Two modes: the full build from the labelled sources (as build_chainbench.py), and --from-built IN, which re-emits an already built chainbench file row by row
(rows that need nothing stay byte-identical; ids, order, labels, strata, calls and results never change). The second mode exists because the intent and
owner-session intermediate files of the 2026-11-13 build (tmp-cb-*.jsonl, tmp-sessions-sample-2000.jsonl.zst) are no longer on the build box.
build_chainbench.py: assemble the session-level corpus (chainbench-v1) from existing labelled sources. No new text is written.

Every session is one case-v1 row: payload.events = the calls of the session in order (tool_name, args, command, cwd, dialect, outcome and, where the
source has it, result), truth = the session label under labels v3.3 (applied by case id), strata = provenance, chain kind and harm step.

Sources (all by case id, copied unchanged):
  intent      the multi-step trajectories the s7-intent lane assembled (intent corpora a-all, ar-intent) and intent-pairs-v2
  v2          the v2 trajectory corpora of the s7-surfaces lane: agentdojo-pub-v2, public-surfaces-v2 (multi-event cases)
  s2          the multi-call clusters of MISS-s2.md: every multi-event s2 case (agentic-redteam, mcphunt, sentinel-flow, ctrldataset, DTap)
  extra       extra-public multi-event cases (shell-attack-evolution honeypot sessions)
  owner       the owner whole-session sample sessions-sample-2000 (calls with their tool results)
  gapreg      gap-regression: single-command cases only; no case is a multi-call chain, so none is included (counted in the stats)

Harm step (strata.harm_step; -1 = not localized): agentic-redteam and sentinel-flow windows end at the harmful step by construction
(normalizer: the window is cut at drift_step; sentinel-flow chains are read-then-send), so harm_step = last call. An owner session with a
call that v3.3 labels malicious: harm_step = first such call. Every other source labels the whole trajectory, harm_step = -1.

Usage: build_chainbench.py --out DIR [--owner-zst FILE] [--labels FILE]
"""
import argparse, collections, hashlib, json, os, re, subprocess, sys

sys.path.insert(0, os.environ.get("S7_GATE_DIR") or os.path.dirname(os.path.abspath(__file__)))
import addr_consistency as AC  # noqa: E402

HOME = os.path.expanduser("~")
S7C = HOME + "/s7c"
RESULT_CAP = 8000

SEND = re.compile(r"(send|email|mail|post|upload|transfer|forward|share|publish|message|reply|pay|wire|invite|webhook|push|tweet|notify)", re.I)
READ = re.compile(r"(read|get|list|search|find|fetch|view|open|query|cat|download|show|check|retrieve|lookup|browse|scan)", re.I)
WRITE = re.compile(r"(write|create|update|edit|save|delete|remove|set|append|modify|put|add|move|rename|schedule|cancel|reset|change|install)", re.I)
SHELLNAMES = {"bash", "bash_command", "shell", "execute_command", "run_command", "terminal", "exec", "run_shell_command", "execute_bash", "run_terminal_cmd",
              "command", "sh", "zsh", "shell_exec", "local_shell", "shell.run", "shell.exec", "system.execute", "terminal.execute", "powershell", "pwsh"}
DL = re.compile(r"\b(curl|wget|fetch|scp|tftp|ftp|invoke-webrequest|iwr|certutil|bitsadmin)\b", re.I)
EXE = re.compile(r"(\bchmod\s+[+0-7a-z]*x|\./[\w.-]+|\b(bash|sh|python3?|perl|ruby|node|php)\s+[\w./~-]+|\bsource\s+|\|\s*(ba)?sh\b|start-process|invoke-expression|iex\b)", re.I)
CREDREAD = re.compile(r"(\.ssh/|id_rsa|id_ed25519|\.env\b|\.aws/|credentials|\.netrc|\.pgpass|/etc/shadow|/etc/passwd|\.kube/config|\.docker/config|token|secret|\.npmrc|\.pypirc)", re.I)
NETSEND = re.compile(r"\b(curl|wget|nc|ncat|netcat|scp|rsync|sftp|ftp|invoke-webrequest|iwr|invoke-restmethod|irm|socat)\b", re.I)
PERSIST = re.compile(r"(crontab|/etc/cron|systemctl\s+(enable|start)|\.bashrc|\.profile|authorized_keys|rc\.local|launchctl|schtasks|reg\s+add|useradd|usermod|adduser|passwd\b|sudoers|net\s+user)", re.I)


def load_labels(path):
    lab = {}
    for l in open(path):
        l = l.strip()
        if l.startswith("{"):
            r = json.loads(l)
            if r.get("source_truth"):
                lab[r["id"]] = r["source_truth"]
    return lab


def ev_text(e):
    c = e.get("command") or ""
    if not c:
        a = e.get("args")
        if isinstance(a, dict):
            c = " ".join(str(v) for k, v in a.items() if k in ("command", "cmd", "script", "code", "commands", "input"))
    return c or ""


def is_shell(e):
    return (e.get("tool_name") or "").lower() in SHELLNAMES


def kind_of(events, dataset, cats):
    """The kind of multi-step behaviour of a session, from tool names (business tools) and command shapes (shell tools). Priority order."""
    if dataset.startswith("mcptox") or "mcp_tool_poisoning" in cats:
        return "mcp-tool-poisoning"
    sh = [e for e in events if is_shell(e)]
    if len(sh) >= max(2, len(events) // 2):
        texts = [ev_text(e) for e in events]
        di = [i for i, t in enumerate(texts) if DL.search(t)]
        ei = [i for i, t in enumerate(texts) if EXE.search(t)]
        if di and ei and max(ei) > min(di):
            return "shell-download-then-execute"
        ci = [i for i, t in enumerate(texts) if CREDREAD.search(t)]
        ni = [i for i, t in enumerate(texts) if NETSEND.search(t)]
        if ci and ni and max(ni) > min(ci):
            return "shell-credential-read-then-network"
        if any(PERSIST.search(t) for t in texts):
            return "shell-persistence-or-account-change"
        return "shell-other-multi-step"
    names = [(e.get("tool_name") or "") for e in events]
    cls = ["send" if SEND.search(n) else "write" if WRITE.search(n) else "read" if READ.search(n) else "other" for n in names]
    first_read = next((i for i, c in enumerate(cls) if c == "read"), None)
    if first_read is not None and any(c == "send" for c in cls[first_read + 1:]):
        return "tool-read-then-send"
    if first_read is not None and any(c == "write" for c in cls[first_read + 1:]):
        return "tool-read-then-write"
    if "send" in cls:
        return "tool-send-without-read"
    if "write" in cls:
        return "tool-write-only"
    return "other-multi-step"


def seq_key(events):
    return hashlib.sha1(json.dumps([[e.get("tool_name"), e.get("args"), e.get("command")] for e in events], sort_keys=True).encode()).hexdigest()


def clip(s):
    return s if len(s) <= RESULT_CAP else s[:RESULT_CAP]


def from_built(a):
    """Row by row: a row that needs the fix is re-emitted with AC.fixed (compact json.dumps, the builder's own spelling); every other row is copied byte for byte."""
    os.makedirs(a.out, exist_ok=True)
    out = a.out + "/chainbench.cases.jsonl"
    if os.path.exists(out):
        sys.exit("refusing to overwrite " + out)
    n = changed = 0
    ids = []
    with open(a.from_built, encoding="utf-8") as f, open(out + ".tmp", "w", encoding="utf-8") as o:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            n += 1
            row = json.loads(line)
            if AC.needs_fix(row):
                new = AC.fixed(row)
                if any(new.get(k) != row.get(k) for k in row if k != "payload") or new["payload"].keys() != row["payload"].keys():
                    sys.exit("the fix changed more than the task text of " + row["id"])
                if json.dumps(row, separators=(",", ":")) != line:
                    sys.exit("row %s is not in the builder's compact form" % row["id"])
                line = json.dumps(new, separators=(",", ":"))
                changed += 1
                ids.append(row["id"])
            o.write(line + "\n")
    os.replace(out + ".tmp", out)
    sha = hashlib.sha256(open(out, "rb").read()).hexdigest()
    srcman = os.path.join(os.path.dirname(os.path.abspath(a.from_built)), "chainbench.manifest.json")
    man = json.load(open(srcman)) if os.path.exists(srcman) else {}
    man.update(version=a.cb_version, derived_from={"file": a.from_built, "sha256": man.get("file_sha256"), "version": man.get("version")}, sessions=n, file_sha256=sha, task_rows_redacted=changed)
    json.dump(man, open(a.out + "/chainbench.manifest.json", "w"), indent=1)
    json.dump({"chainbench": {"files": [out], "session": True, "harness_args": ["-surface", "session"]}}, open(a.out + "/corpora_chainbench_addr1.json", "w"), indent=1)
    print("sessions", n, "task rows redacted", changed, "sha", sha[:16])


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--out", required=True)
    ap.add_argument("--owner-zst", default=HOME + "/s7c/tmp-sessions-sample-2000.jsonl.zst"); ap.add_argument("--labels", default=S7C + "/labels/current.jsonl")
    ap.add_argument("--cb-version", default="chainbench-v1-addr1")
    ap.add_argument("--from-built", default="", help="re-emit this built chainbench file with the task addresses redacted instead of rebuilding from the sources")
    a = ap.parse_args()
    if a.from_built:
        return from_built(a)
    lab = load_labels(a.labels)
    man = json.load(open(a.labels.replace(".jsonl", ".manifest.json")))
    os.makedirs(a.out, exist_ok=True)
    rows = []; seen = {}; stats = collections.Counter(); skipped = collections.Counter()

    def add(src, orig, dataset, events, truth, cats, strata_src, content="", provider=None, platform="linux", harm=-1, harm_basis="trajectory", split_group=None, label_src=""):
        if len(events) < 2:
            skipped[src + ":single-call"] += 1; return
        if truth not in ("benign", "malicious"):
            skipped[src + ":excluded-by-v3.3"] += 1; return
        k = (truth, seq_key(events))
        if k in seen:
            skipped[src + ":duplicate-of-" + seen[k]] += 1; return
        seen[k] = src
        kind = kind_of(events, dataset, cats)
        sid = "cb/%s/%s" % (src, orig)
        strata = dict(strata_src or {})
        strata.update(chain_kind=kind, harm_step=harm if harm < len(events) else len(events) - 1, harm_basis=harm_basis, src_corpus=src, src_id=orig, src_dataset=dataset,
                      n_steps=len(events), provider=provider or strata.get("provider") or "claudecode", platform=platform, trajectory_id=sid,
                      split_group=split_group or strata.get("split_group") or hashlib.sha1(sid.encode()).hexdigest()[:24], call_index=0, sequence_index=0,
                      campaign=strata.get("campaign") or src, domain=strata.get("domain") or "sessions", dialect=strata.get("dialect") or "none")
        payload = {"events": events}
        if content:
            payload["content"] = content
        for h in [payload, *events]:
            for k in AC.TASK_FIELDS:
                if isinstance(h.get(k), str):
                    h[k] = AC.redact_addresses(h[k])
        rows.append({"id": sid, "schema_version": "case-v1", "surface": "stateful", "split": "eval", "source": {"dataset": dataset, "original_id": orig, "revision": a.cb_version, "license": "inherited", "redistribution": "manual"},
                     "strata": strata, "payload": payload,
                     "truth": {"source_truth": truth, "applicability": "in_scope", "deterministic_truth": "contextual_or_dual_use" if truth == "malicious" else "benign", "expected_disposition": "detect_only" if truth == "malicious" else "allow",
                               "label_confidence": "medium", "label_source": label_src or ("labels-v3.3:" + orig), "categories": list(cats)[:12]}})
        stats[(src, truth, kind)] += 1

    def clean_events(evs):
        out = []
        for e in evs:
            o = {k: e[k] for k in ("tool_name", "args", "command", "cwd", "dialect", "outcome") if k in e and e[k] not in (None, "")}
            o.setdefault("outcome", "succeeded")
            if e.get("result"):
                o["result"] = clip(e["result"] if isinstance(e["result"], str) else (e["result"].get("text") or ""))
            out.append(o)
        return out

    def case_sources(path, src, only_multi=True, forced_dataset=None):
        if not os.path.exists(path):
            print("MISSING", path, file=sys.stderr); return
        for line in open(path):
            r = json.loads(line); pl = r["payload"]; evs = pl.get("events") or []
            if len(evs) < 2:
                skipped[src + ":single-call"] += 1; continue
            t = lab.get(r["id"], r["truth"].get("source_truth"))
            t = "malicious" if t == "sensitive" else t
            ds = (forced_dataset or r["source"]["dataset"]).split("/")[-1]
            cats = r["truth"].get("categories") or []
            harm, basis = -1, "trajectory"
            if ds in ("agentic-redteam-benchmark", "sentinel-flow") and t == "malicious":
                harm, basis = len(evs) - 1, "window-end"
            add(src, r["id"], ds, clean_events(evs), t, cats, r.get("strata"), content=pl.get("content") or "", provider=(r.get("strata") or {}).get("provider"),
                platform=(r.get("strata") or {}).get("platform") or "linux", harm=harm, harm_basis=basis)

    # intent lane trajectories first (the dedupe keeps the first source of an identical call sequence)
    for fn in ("tmp-cb-ar-intent.jsonl", "tmp-cb-a-all.jsonl"):
        case_sources(S7C + "/" + fn, "intent")
    case_sources(S7C + "/corpora/intent-pairs-v2.cases.jsonl", "intent-v2")
    case_sources(S7C + "/corpora/s2.cases.jsonl", "s2")
    case_sources(S7C + "/corpora/agentdojo-pub-v2.cases.jsonl", "v2-agentdojo")
    case_sources(S7C + "/corpora/public-surfaces-v2.cases.jsonl", "v2-surfaces")
    case_sources(S7C + "/corpora/extra-public.cases.jsonl", "extra")

    # owner whole sessions (calls with their tool results)
    p = subprocess.Popen(["zstd", "-dc", a.owner_zst], stdout=subprocess.PIPE)
    for line in p.stdout:
        r = json.loads(line); calls = r["calls"]
        evs = []; labs = []
        for c in calls:
            e = {"tool_name": c.get("tool_name"), "args": c.get("args") if isinstance(c.get("args"), dict) else {}, "command": c.get("command") or "", "cwd": c.get("cwd") or "",
                 "dialect": c.get("dialect") or "none", "outcome": c.get("outcome") or "succeeded"}
            if isinstance(c.get("args"), list):
                e["args"] = {"command": c.get("command") or ""}
            res = c.get("result") or {}
            if res.get("text"):
                e["result"] = clip(res["text"])
            evs.append(e); labs.append(lab.get(c.get("case_id"), (c.get("label") or {}).get("source_truth")))
        tr = "benign"; harm = -1; basis = "trajectory"
        if any(x == "malicious" for x in labs):
            tr, harm, basis = "malicious", next(i for i, x in enumerate(labs) if x == "malicious"), "labelled-call"
        elif any(x in ("excluded", "unknown") for x in labs):
            tr = "excluded"
        add("owner", r["trajectory_id"], "owner-sessions-sample-2000", clean_events(evs), tr, ["owner-session"] + (["test_session"] if r.get("test_session") else []),
            {"campaign": "owner-session", "domain": "owner-sessions"}, provider=r.get("provider"), platform=r.get("platform") or "linux", harm=harm, harm_basis=basis,
            split_group=r.get("split_group"), label_src="labels-v3.3:calls:" + r["trajectory_id"][:12])

    # gap-regression: report only
    gr = 0
    for line in open(S7C + "/corpora/gap-regression.cases.jsonl"):
        r = json.loads(line); gr += 1
        if len(r["payload"].get("events") or [1]) > 1:
            skipped["gapreg:multi"] += 1
    skipped["gap-regression:single-command (no multi-call chain case)"] = gr

    out = a.out + "/chainbench.cases.jsonl"
    with open(out, "w") as f:
        for r in sorted(rows, key=lambda r: r["id"]):
            f.write(json.dumps(r, separators=(",", ":")) + "\n")
    sha = hashlib.sha256(open(out, "rb").read()).hexdigest()
    json.dump({"version": a.cb_version, "labels_version": man.get("version"), "labels_sha256": man.get("labels_sha256"), "sessions": len(rows), "file_sha256": sha,
               "skipped": dict(skipped)}, open(a.out + "/chainbench.manifest.json", "w"), indent=1)
    cfg = {"chainbench": {"files": [out], "session": True, "harness_args": ["-surface", "session"]}}
    json.dump(cfg, open(a.out + "/corpora_chainbench_addr1.json", "w"), indent=1)
    print("sessions", len(rows), "sha", sha[:16], "labels", man.get("version"), man.get("labels_sha256", "")[:12])
    by = collections.Counter(); steps = collections.defaultdict(list)
    for r in rows:
        s = r["strata"]; by[(s["src_corpus"], r["truth"]["source_truth"])] += 1; steps[(s["src_corpus"], r["truth"]["source_truth"])].append(s["n_steps"])
    for k in sorted(by): print("  %-14s %-10s sessions=%-6d calls=%-8d median_steps=%d" % (k[0], k[1], by[k], sum(steps[k]), sorted(steps[k])[len(steps[k]) // 2]))
    print("kinds (attack | benign):")
    ks = collections.defaultdict(lambda: [0, 0])
    for (src, t, kind), n in stats.items(): ks[kind][0 if t == "malicious" else 1] += n
    for kind, (m, b) in sorted(ks.items(), key=lambda x: -x[1][0]): print("  %-40s %5d | %5d" % (kind, m, b))
    print("skipped", dict(skipped))


if __name__ == "__main__":
    main()
