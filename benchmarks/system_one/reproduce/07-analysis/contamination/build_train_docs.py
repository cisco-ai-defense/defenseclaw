"""Emit normalised doc records for every obtainable SecJudge training source +
the DefenseClaw Security Suite + the Task-E eval sources."""
from __future__ import annotations
import ast, csv, json, os, sys, hashlib
sys.path.insert(0, "$WORK/.system-one-data/outputs/secjudge/contamination/work")
import contam_lib as L
import pyarrow.parquet as pq

ROOT  = "$WORK/.system-one-data/outputs/secjudge/contamination"
CACHE = ROOT + "/cache"
DOCS  = ROOT + "/work/docs"
REPO  = "$WORK/defenseclaw-system-one"
SUITE = REPO + "/internal/gateway/testdata/security_suite"
FIXT  = REPO + "/benchmarks/fixtures"
os.makedirs(DOCS, exist_ok=True)
csv.field_size_limit(10**9)

def sha_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for c in iter(lambda: fh.read(1 << 20), b""): h.update(c)
    return h.hexdigest()

class W:
    def __init__(self, group):
        self.group = group
        self.path = DOCS + "/train__" + group.replace("/", "__") + ".jsonl"
        self.fh = open(self.path, "w", encoding="utf-8")
        self.n = 0; self.n_empty = 0; self.maxlen = 0; self.totlen = 0
        self.views = {}
    def add(self, row_ref, view, raw_text):
        t = L.normalize(raw_text)
        if not t:
            self.n_empty += 1; return
        self.fh.write(json.dumps({"id": self.group + "|" + str(row_ref) + "|" + view,
                                  "sha": L.sha256_text(t), "n": len(t), "t": t},
                                 ensure_ascii=False) + "\n")
        self.n += 1; self.totlen += len(t); self.maxlen = max(self.maxlen, len(t))
        self.views[view] = self.views.get(view, 0) + 1
    def close(self):
        self.fh.close()
        return {"group": self.group, "docs_path": self.path, "n_docs": self.n,
                "n_empty_skipped": self.n_empty, "max_norm_chars": self.maxlen,
                "mean_norm_chars": round(self.totlen / self.n, 1) if self.n else 0,
                "views": self.views}

summary = {}
files_read = {}
def note(p): files_read[p] = {"sha256": sha_file(p), "bytes": os.path.getsize(p)}

# ---- 2. S-Labs/prompt-injection-dataset (csv: text,label) -------------------
w = W("S-Labs__prompt-injection-dataset"); rowcounts = {}
for split in ["train", "validation", "test"]:
    p = CACHE + "/S-Labs__prompt-injection-dataset/data/" + split + ".csv"; note(p)
    with open(p, newline="", encoding="utf-8") as fh:
        rr = list(csv.DictReader(fh))
    rowcounts[split] = len(rr)
    for i, r in enumerate(rr): w.add(split + ":" + str(i), "text", r.get("text"))
summary["S-Labs/prompt-injection-dataset"] = dict(w.close(), source_rows=rowcounts,
    text_fields=["text"], splits=list(rowcounts))

# ---- 3. AnishJoshi/nl2bash-custom ------------------------------------------
w = W("AnishJoshi__nl2bash-custom"); rowcounts = {}
for split in ["train", "dev", "test"]:
    p = CACHE + "/AnishJoshi__nl2bash-custom/data/" + split + ".json"; note(p)
    rr = json.load(open(p, encoding="utf-8")); rowcounts[split] = len(rr)
    for i, r in enumerate(rr):
        ref = split + ":" + str(i) + ":srno=" + str(r.get("srno"))
        w.add(ref, "nl_command", r.get("nl_command"))
        w.add(ref, "bash_code", r.get("bash_code"))
        w.add(ref, "nl_plus_bash", str(r.get("nl_command")) + "\n" + str(r.get("bash_code")))
summary["AnishJoshi/nl2bash-custom"] = dict(w.close(), source_rows=rowcounts,
    text_fields=["nl_command", "bash_code"], splits=list(rowcounts))

# ---- 6. Magicoder-OSS-Instruct-75K -----------------------------------------
w = W("ise-uiuc__Magicoder-OSS-Instruct-75K"); n = 0
p = CACHE + "/ise-uiuc__Magicoder-OSS-Instruct-75K/data-oss_instruct-decontaminated.jsonl"; note(p)
for line in open(p, encoding="utf-8", errors="replace"):
    line = line.strip()
    if not line: continue
    r = json.loads(line); ref = "train:" + str(n) + ":index=" + str(r.get("index")); n += 1
    w.add(ref, "problem", r.get("problem")); w.add(ref, "solution", r.get("solution")); w.add(ref, "seed", r.get("seed"))
summary["ise-uiuc/Magicoder-OSS-Instruct-75K"] = dict(w.close(), source_rows={"train": n},
    text_fields=["problem", "solution", "seed"], splits=["train"])

# ---- 8. Trendyol cybersecurity instruction tuning --------------------------
w = W("Trendyol__Trendyol-Cybersecurity-Instruction-Tuning-Dataset"); n = 0
p = CACHE + "/Trendyol__Trendyol-Cybersecurity-Instruction-Tuning-Dataset/CyberSec-Dataset_escaped.jsonl"; note(p)
for line in open(p, encoding="utf-8", errors="replace"):
    line = line.strip()
    if not line: continue
    r = json.loads(line); ref = "train:" + str(n); n += 1
    w.add(ref, "system", r.get("system")); w.add(ref, "user", r.get("user")); w.add(ref, "assistant", r.get("assistant"))
summary["Trendyol/Trendyol-Cybersecurity-Instruction-Tuning-Dataset"] = dict(w.close(),
    source_rows={"train": n}, text_fields=["system", "user", "assistant"], splits=["train"])

# ---- 9. 3nesdeniz boundary pairs -------------------------------------------
w = W("3nesdeniz__agentic-prompt-injection-boundary-pairs"); rowcounts = {}
for split in ["train", "validation", "test"]:
    p = CACHE + "/3nesdeniz__agentic-prompt-injection-boundary-pairs/data/" + split + ".jsonl"; note(p)
    k = 0
    for line in open(p, encoding="utf-8"):
        line = line.strip()
        if not line: continue
        r = json.loads(line); k += 1
        w.add(split + ":" + str(r.get("id")), "text", r.get("text"))
    rowcounts[split] = k
summary["3nesdeniz/agentic-prompt-injection-boundary-pairs"] = dict(w.close(), source_rows=rowcounts,
    text_fields=["text"], splits=list(rowcounts))

# ---- 10. deepset/prompt-injections (parquet) -------------------------------
w = W("deepset__prompt-injections"); rowcounts = {}
for split, fn in [("train", "train-00000-of-00001-9564e8b05b4757ab.parquet"),
                  ("test",  "test-00000-of-00001-701d16158af87368.parquet")]:
    p = CACHE + "/deepset__prompt-injections/data/" + fn; note(p)
    tb = pq.read_table(p).to_pylist(); rowcounts[split] = len(tb)
    for i, r in enumerate(tb): w.add(split + ":" + str(i), "text", r.get("text"))
summary["deepset/prompt-injections"] = dict(w.close(), source_rows=rowcounts,
    text_fields=["text"], splits=list(rowcounts))

# ---- 11. infraset/infraset -------------------------------------------------
w = W("infraset__infraset"); rowcounts = {}
p = CACHE + "/infraset__infraset/data/commands.parquet"; note(p)
tb = pq.read_table(p, columns=["run_id", "command_id", "command"]).to_pylist(); rowcounts["commands"] = len(tb)
for r in tb: w.add("commands:" + str(r.get("command_id")), "command", r.get("command"))
p = CACHE + "/infraset__infraset/data/tasks.parquet"; note(p)
tb = pq.read_table(p, columns=["task_path", "slug", "instruction"]).to_pylist(); rowcounts["tasks"] = len(tb)
for r in tb: w.add("tasks:" + str(r.get("task_path")), "instruction", r.get("instruction"))
p = CACHE + "/infraset__infraset/data/runs.parquet"; note(p)
tb = pq.read_table(p, columns=["run_id", "task"]).to_pylist(); rowcounts["runs"] = len(tb)
for r in tb: w.add("runs:" + str(r.get("run_id")), "task", r.get("task"))
summary["infraset/infraset"] = dict(w.close(), source_rows=rowcounts,
    text_fields=["commands.command", "tasks.instruction", "runs.task"],
    splits=["commands", "tasks", "runs"])

# ---- DefenseClaw Security Suite -------------------------------------------
SUITE_FILES = {
    "regex":               SUITE + "/regex/corpus.jsonl",
    "toolcall":            SUITE + "/toolcall/corpus.jsonl",
    "toolcall_stateful":   SUITE + "/toolcall/stateful.jsonl",
    "judge":               SUITE + "/judge/corpus.jsonl",
    "e2e":                 SUITE + "/e2e/corpus.jsonl",
    "eval_injection":      SUITE + "/eval_corpus/injection/corpus.jsonl",
    "eval_pii":            SUITE + "/eval_corpus/pii/corpus.jsonl",
    "eval_exfil":          SUITE + "/eval_corpus/exfil/corpus.jsonl",
    "eval_tool_injection": SUITE + "/eval_corpus/tool_injection/corpus.jsonl",
}
STRFIELDS = ["content", "command", "prompt", "text", "arguments", "body", "input"]
w = W("dc-security-suite"); rowcounts = {}; eval_generated = {}
for sub, p in SUITE_FILES.items():
    note(p); k = 0; gen = 0
    for line in open(p, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("//"): continue
        r = json.loads(line); k += 1
        rid = str(r.get("id"))
        if rid.startswith("eval-"): gen += 1
        ref = sub + ":" + rid
        for f in STRFIELDS:
            if isinstance(r.get(f), str) and r[f].strip(): w.add(ref, f, r[f])
        w.add(ref, "row_json", L.canon_json(r))
    rowcounts[sub] = k; eval_generated[sub] = gen
summary["DefenseClaw Security Suite"] = dict(w.close(), source_rows=rowcounts,
    rows_machine_generated_from_eval_corpus=eval_generated,
    text_fields=STRFIELDS + ["row_json"], splits=list(SUITE_FILES), repo_path=SUITE)

# ---- benchmarks/fixtures DefenseClaw lock entries -------------------------
FIX = ["smoke", "cloud-production-conformance-v1", "database-destruction-conformance-v1",
       "kubernetes-production-conformance-v1", "infrastructure-destruction-conformance-v1",
       "postgresql-copy-program-v1", "sql-command-udf-atomic-v1"]
sys.path.insert(0, "$WORK/.system-one-data/outputs/secjudge/code")
from secjudge_serialize import case_decisions
w = W("dc-benchmark-fixtures"); rowcounts = {}
for name in FIX:
    p = FIXT + "/" + name + ".jsonl"; note(p); k = 0
    for line in open(p, encoding="utf-8"):
        line = line.strip()
        if not line: continue
        case = json.loads(line); k += 1
        cid = str(case.get("id"))
        for ei, variant, text, meta in case_decisions(case, ["C7"]):
            w.add(name + ":" + cid + ":e" + str(ei), "c7", text)
        pl = case.get("payload") if isinstance(case.get("payload"), dict) else {}
        evs = pl.get("events") if isinstance(pl.get("events"), list) else [pl]
        parts = []
        for ev in evs:
            if not isinstance(ev, dict): continue
            if ev.get("args") is not None: parts.append(L.canon_json(ev.get("args")))
            if ev.get("command") is not None: parts.append(str(ev.get("command")))
        w.add(name + ":" + cid, "raw", "\n".join(parts))
        if isinstance(pl.get("content"), str): w.add(name + ":" + cid, "content", pl["content"])
    rowcounts[name] = k
summary["DefenseClaw benchmark fixtures (lock entries)"] = dict(w.close(), source_rows=rowcounts,
    text_fields=["c7", "raw", "payload.content"], splits=FIX, repo_path=FIXT)

# ---- Task E: rogue-security ----------------------------------------------
REV = "bf7ff748d80ca24db30b57c9255a2fb8884ed7eb"
p = CACHE + "/rogue-security__coding-agent-security-benchmark@" + REV[:12] + "/data/test-00000-of-00001.parquet"
note(p)
w = W("rogue-security__coding-agent-security-benchmark")
tb = pq.read_table(p).to_pylist()
rogue_ident = {}
for i, r in enumerate(tb):
    raw = r.get("data_to_evaluate")
    ident = hashlib.sha256((REV + "\x00" + str(i) + "\x00" + str(raw)).encode("utf-8")).hexdigest()
    rogue_ident[ident[:24]] = {"row_index": i, "message_type": r.get("message_type"),
                               "label": r.get("label"), "category": r.get("category_and_criticality")}
    ref = "row:" + ident[:24]
    w.add(ref, "data_to_evaluate", raw)
    try:
        val = ast.literal_eval(raw) if isinstance(raw, str) else None
    except Exception:
        val = None
    if isinstance(val, dict):
        tc = val.get("tool_calls")
        if isinstance(tc, list):
            for j, call in enumerate(tc):
                if isinstance(call, dict):
                    args = call.get("arguments", call.get("args"))
                    if isinstance(args, str):
                        try: args = json.loads(args)
                        except Exception: pass
                    w.add(ref + "#call:" + str(j), "call_args_json", L.canon_json(args))
        if isinstance(val.get("content"), str): w.add(ref, "content", val["content"])
summary["rogue-security/coding-agent-security-benchmark"] = dict(w.close(),
    source_rows={"test": len(tb)},
    text_fields=["data_to_evaluate", "parsed tool_calls arguments", "content"],
    splits=["test"], pinned_revision=REV)
json.dump(rogue_ident, open(ROOT + "/work/rogue_row_identities.json", "w"), indent=1)

# ---- Task E: nvidia Nemotron IPI -----------------------------------------
p = CACHE + "/nvidia__Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1/train.jsonl"; note(p)
w = W("nvidia__Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1"); n = 0
for line in open(p, encoding="utf-8"):
    line = line.strip()
    if not line: continue
    r = json.loads(line); n += 1
    ref = "id=" + str(r.get("id"))
    if isinstance(r.get("injection"), str): w.add(ref, "injection", r["injection"])
    w.add(ref, "params_json", L.canon_json(r.get("responses_create_params")))
    inp = (r.get("responses_create_params") or {}).get("input") or []
    for j, m in enumerate(inp):
        if isinstance(m, dict) and isinstance(m.get("content"), str):
            w.add(ref + "#msg" + str(j), "msg_content", m["content"])
summary["nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1"] = dict(w.close(),
    source_rows={"train": n},
    text_fields=["injection", "responses_create_params", "input[].content"], splits=["train"])

json.dump({"groups": summary, "input_files": files_read},
          open(ROOT + "/work/train_docs_summary.json", "w"), indent=2)
for k, v in summary.items():
    print("%-70s docs=%8d rows=%s" % (k, v["n_docs"], v["source_rows"]))
print("WROTE train_docs_summary.json")
