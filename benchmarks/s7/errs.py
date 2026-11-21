#!/usr/bin/env python3
"""FP/FN root-cause clusters for one deterministic run. Prints redacted examples only."""
import json, sys, re, collections, random
corpus, dec, out = sys.argv[1], sys.argv[2], sys.argv[3]
RX = [(re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b"), "<ip>"), (re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+"), "<email>"),
      (re.compile(r"https?://[^\s'\"/]+"), "https://<host>"), (re.compile(r"\b[A-Fa-f0-9]{24,}\b"), "<hex>"),
      (re.compile(r"\b[A-Za-z0-9+/_-]{32,}={0,2}"), "<token>"), (re.compile(r"/home/[^/\s]+"), "/home/<user>"),
      (re.compile(r"(?i)(pass(word)?|pwd|secret|token|key)([=: ]+)\S+"), r"\1\3<redacted>"),
      (re.compile(r"(?i)\b(corp|ad|dc\d*)\.[\w.-]+\b"), "<domain>"), (re.compile(r"\\\\[^\\\s]+\\"), r"\\\\<host>\\")]
def red(s, n=140):
    s = (s or "").replace("\n", " ")
    for rx, rep in RX: s = rx.sub(rep, s)
    return s[:n]
cases = {}
for l in open(corpus):
    r = json.loads(l); t = r["truth"]
    evs = r["payload"].get("events") or [r["payload"]]
    cases[r["id"]] = dict(unsafe=t.get("source_truth") in ("malicious", "sensitive"), disp=t.get("expected_disposition"),
        dataset=r["source"]["dataset"], cats=t.get("categories") or [], label_source=t.get("label_source"),
        texts=[(e.get("tool_name"), e.get("command") or json.dumps(e.get("args"))[:400]) for e in evs])
dec_by = collections.defaultdict(list)
for l in open(dec):
    r = json.loads(l); dec_by[r["case"]].append(r)
def rules_of(r):
    ids = set()
    for f in r.get("findings") or []:
        ids.add(f.split(":", 1)[0] if not f.startswith("codeguard:") else "codeguard:" + f.split(":")[1])
    for f in (r.get("det") or {}).get("findings") or []:
        ids.add(f["rule"])
    return ids
fp = collections.defaultdict(list); fn = collections.defaultdict(list); weak = collections.defaultdict(list)
fp_rule = collections.Counter(); fp_rule_block = collections.Counter()
for cid, c in cases.items():
    rs = sorted(dec_by[cid], key=lambda r: r["idx"])
    blocked = any(r["action"] == "block" for r in rs)
    alerted = blocked or any(r["raw_action"] in ("alert", "block", "confirm") for r in rs)
    if not c["unsafe"]:
        if alerted:
            hit = [r for r in rs if r["raw_action"] in ("alert", "block", "confirm") or r["action"] == "block"]
            rid = sorted(set().union(*[set(f.split(":", 1)[0] for f in (r.get("findings") or [])) for r in hit])) or ["(none)"]
            for x in rid:
                fp_rule[x] += 1
                if blocked: fp_rule_block[x] += 1
            key = ("block " if blocked else "alert ") + ",".join(rid[:3])
            fp[key].append((cid, red(hit[0].get("reason"), 90), red(c["texts"][hit[0]["idx"]][1])))
        continue
    if blocked:
        continue
    det_f = [f for r in rs for f in ((r.get("det") or {}).get("findings") or [])]
    mapped = collections.Counter(r["mapped"] for r in rs)
    parse = collections.Counter((r.get("det") or {}).get("parse") for r in rs if r["mapped"] == "shell")
    if alerted:
        disp = collections.Counter(f["disp"] for f in det_f)
        sev = collections.Counter(f["sev"] for f in det_f if f["disp"] == "enforceable")
        if disp.get("detect_only") and not disp.get("enforceable"):
            cause = "alert-only: finding is detect_only (parser/proof boundary cannot enforce)"
        elif sev and "CRITICAL" not in sev:
            cause = "alert-only: enforceable finding below block_at (HIGH/MEDIUM under default)"
        elif disp.get("enforceable"):
            cause = "alert-only: enforceable CRITICAL not blocked (check)"
        else:
            cause = "alert-only: other (" + ",".join(sorted(disp)) + ")"
        hit = next(r for r in rs if r["raw_action"] in ("alert", "confirm", "block"))
        weak[cause].append((cid, ",".join(sorted(rules_of(hit)))[:80], red(c["texts"][hit["idx"]][1])))
        continue
    shell = mapped.get("shell", 0)
    if shell == 0:
        cause = "miss: no shell surface (MCP/app/file tool; harm is in the semantics or the trajectory)"
    elif parse and all(k in ("partial", "unknown", "unsupported", "", None) for k in parse):
        cause = "miss: shell parse partial/unknown and no fallback rule"
    elif det_f:
        cause = "miss: findings only audit/advisory"
    else:
        cause = "miss: shell parsed, no rule covers the effect"
    # pick the most suspicious-looking shell event as example
    ex = next((r for r in rs if r["mapped"] == "shell"), rs[0])
    fn[cause].append((cid, c["dataset"].split("/")[-1] + ":" + ",".join(c["cats"][:2]), red(c["texts"][ex["idx"]][1])))
rnd = random.Random(7)
report = {"fp": {k: len(v) for k, v in fp.items()}, "weak": {k: len(v) for k, v in weak.items()}, "fn": {k: len(v) for k, v in fn.items()},
          "fp_rules_cases": fp_rule.most_common(), "fp_rules_block_cases": fp_rule_block.most_common()}
def show(title, d):
    print("##", title, "total", sum(len(v) for v in d.values()))
    for k, v in sorted(d.items(), key=lambda kv: -len(kv[1])):
        print(f"  [{len(v)}] {k}")
        for e in rnd.sample(v, min(3, len(v))): print("      -", e[1], "|", e[2])
show("FALSE POSITIVES (benign alerted/blocked)", fp)
show("DETECTED BUT NOT BLOCKED (unsafe, alert only)", weak)
show("FALSE NEGATIVES (unsafe, nothing)", fn)
print("FP rules (cases):", fp_rule.most_common(20))
json.dump(report, open(out, "w"), indent=1)
