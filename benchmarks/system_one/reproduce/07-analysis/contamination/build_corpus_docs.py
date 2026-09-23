"""Emit normalised doc records for every case in our four evaluation corpora.

Two mandated text views per case:
  c7        -- the C7 serialised production text, one doc per event index
               (exactly what SecJudge is fed), via secjudge_serialize.case_decisions
  raw       -- one doc per case: concatenation of every event's args/command JSON
Plus one extra, strictly-more-sensitive view:
  raw_event -- one doc per event: that event's args/command JSON alone
"""
from __future__ import annotations
import json, os, sys, hashlib, collections
sys.path.insert(0, "$WORK/.system-one-data/outputs/secjudge/contamination/work")
sys.path.insert(0, "$WORK/.system-one-data/outputs/secjudge/code")
sys.path.insert(0, "$WORK/defenseclaw-system-one/benchmarks/scripts")
import contam_lib as L
from secjudge_serialize import case_decisions
from benchmark_inventory_system_one_sources import truth_grade

ROOT = "$WORK/.system-one-data/outputs/secjudge/contamination"
DOCS = ROOT + "/work/docs"
BASE = "$WORK/.system-one-data/outputs"
STAGES = ["s2", "s3", "intent-real", "toolcall-labels"]
os.makedirs(DOCS, exist_ok=True)

def sha_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for c in iter(lambda: fh.read(1 << 20), b""): h.update(c)
    return h.hexdigest()

def raw_parts(ev):
    parts = []
    if isinstance(ev, dict):
        if ev.get("args") is not None: parts.append(L.canon_json(ev.get("args")))
        if ev.get("command") is not None: parts.append(str(ev.get("command")))
    return parts

summary = {}
for stage in STAGES:
    src = BASE + "/" + stage + "/cases.jsonl"
    outp = DOCS + "/corpus__" + stage + ".jsonl"
    out = open(outp, "w", encoding="utf-8")
    n_cases = 0; n_docs = collections.Counter(); ds_counts = collections.Counter()
    maxlen = 0; totlen = 0; empty = collections.Counter()
    tg_counts = collections.Counter(); case_index = {}
    dup_original_ids = collections.Counter()
    for line in open(src, encoding="utf-8"):
        line = line.strip()
        if not line: continue
        case = json.loads(line); n_cases += 1
        cid = str(case.get("id"))
        s = case.get("source") or {}
        ds = str(s.get("dataset")); ds_counts[ds] += 1
        dup_original_ids[(ds, str(s.get("original_id")))] += 1
        try: tg = truth_grade(case)
        except Exception: tg = "unknown"
        tg_counts[tg] += 1
        case_index[cid] = {"ds": ds, "tg": tg, "oid": str(s.get("original_id"))}

        def emit(doc_id, view, raw_text):
            global maxlen, totlen
            t = L.normalize(raw_text)
            if not t:
                empty[view] += 1; return
            out.write(json.dumps({"id": doc_id, "sha": L.sha256_text(t), "n": len(t),
                                  "ds": ds, "cid": cid, "view": view, "t": t},
                                 ensure_ascii=False) + "\n")
            n_docs[view] += 1; totlen += len(t)
            if len(t) > maxlen: maxlen = len(t)

        for ei, variant, text, meta in case_decisions(case, ["C7"]):
            emit(stage + "|" + cid + "|e" + str(ei) + "|c7", "c7", text)
        pl = case.get("payload") if isinstance(case.get("payload"), dict) else {}
        evs = pl.get("events") if isinstance(pl.get("events"), list) else [pl]
        allparts = []
        for ei, ev in enumerate(evs):
            ps = raw_parts(ev)
            allparts.extend(ps)
            if ps: emit(stage + "|" + cid + "|e" + str(ei) + "|raw_event", "raw_event", "\n".join(ps))
        emit(stage + "|" + cid + "|raw", "raw", "\n".join(allparts))
    out.close()
    total = sum(n_docs.values())
    ndup = sum(v - 1 for v in dup_original_ids.values() if v > 1)
    summary[stage] = {
        "cases_path": src, "cases_sha256": sha_file(src), "cases_bytes": os.path.getsize(src),
        "n_cases": n_cases, "docs_path": outp, "n_docs_total": total,
        "n_docs_by_view": dict(n_docs), "n_empty_skipped_by_view": dict(empty),
        "max_norm_chars": maxlen, "mean_norm_chars": round(totlen / total, 1) if total else 0,
        "dataset_counts": dict(sorted(ds_counts.items(), key=lambda kv: -kv[1])),
        "truth_grade_counts": dict(tg_counts),
        "n_distinct_case_ids": len(case_index),
        "n_duplicate_source_original_ids": ndup,
    }
    json.dump(case_index, open(ROOT + "/work/case_index__" + stage + ".json", "w"))
    print(stage, "cases", n_cases, "docs", total, dict(n_docs), "maxchars", maxlen, flush=True)

json.dump(summary, open(ROOT + "/work/corpus_docs_summary.json", "w"), indent=2)
print("WROTE corpus_docs_summary.json")
