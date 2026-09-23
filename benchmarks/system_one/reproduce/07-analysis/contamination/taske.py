"""Task E: eval-set reuse.
(a) exact row-level provenance of our rogue-coding-agent-security cases
(b) exact row-level provenance of our Nemotron Terminal-Pivot cases
(c) is Terminal-Pivot the same dataset as Indirect-Prompt-Injection, a sibling, or unrelated?
"""
from __future__ import annotations
import json, os, re, sys, time, collections
sys.path.insert(0, "$WORK/.system-one-data/outputs/secjudge/contamination/work")
import contam_lib as L
import numpy as np

ROOT = "$WORK/.system-one-data/outputs/secjudge/contamination"
CACHE = ROOT + "/cache"; DOCS = ROOT + "/work/docs"; MH = ROOT + "/work/mh"; SK = ROOT + "/work/sk"
t0 = time.time()
out = {}

# ---------------- (a) rogue-security provenance ----------------
rogue_ident = json.load(open(ROOT + "/work/rogue_row_identities.json"))
ours = json.load(open(ROOT + "/work/our_original_ids.json"))
res_a = {}
for key, oids in ours.items():
    if "rogue" not in key: continue
    stage = key.split("::")[0]
    rows = set(); calls = collections.Counter(); matched = 0; unmatched = []
    for oid in oids:
        m = re.match(r"^row:([0-9a-f]{24})#call[-:](\d+)$", oid)
        if not m:
            unmatched.append(oid); continue
        rid, ci = m.group(1), int(m.group(2))
        if rid in rogue_ident:
            matched += 1; rows.add(rid); calls[ci] += 1
        else:
            unmatched.append(oid)
    cats = collections.Counter(rogue_ident[r]["category"] for r in rows)
    mts = collections.Counter(rogue_ident[r]["message_type"] for r in rows)
    res_a[stage] = {
        "our_cases": len(oids), "original_ids_parsed": len(oids) - len(unmatched),
        "original_ids_matched_to_a_row_of_the_332_row_benchmark": matched,
        "original_ids_not_matched": unmatched[:20],
        "distinct_source_rows_of_332_used": len(rows),
        "fraction_of_332_row_benchmark_used": round(len(rows) / len(rogue_ident), 6),
        "call_index_histogram": dict(calls),
        "source_category_and_criticality_histogram": dict(cats.most_common()),
        "source_message_type_histogram": dict(mts),
    }
all_rows = set()
for key, oids in ours.items():
    if "rogue" not in key: continue
    for oid in oids:
        m = re.match(r"^row:([0-9a-f]{24})#call[-:](\d+)$", oid)
        if m and m.group(1) in rogue_ident: all_rows.add(m.group(1))
res_a["_union_across_stages"] = {
    "n_source_rows_of_332_benchmark_used": len(all_rows),
    "n_rows_in_benchmark": len(rogue_ident),
    "fraction": round(len(all_rows) / len(rogue_ident), 6),
    "row_identity_formula": 'sha256(revision + "\\x00" + row_index + "\\x00" + data_to_evaluate)[:24]',
    "revision": "bf7ff748d80ca24db30b57c9255a2fb8884ed7eb",
}
out["a_rogue_security_provenance"] = res_a
print("rogue provenance", json.dumps(res_a["_union_across_stages"]), flush=True)

# ---------------- (b) Nemotron Terminal-Pivot provenance ----------------
pivot_uuids = set(json.load(open(ROOT + "/work/pivot_uuids.json")))
pstats = json.load(open(ROOT + "/work/pivot_stats.json"))
ours_pivot = ours.get("s3::nvidia/Nemotron-RL-Agentic-Terminal-Pivot-v1", [])
samp = collections.Counter(); matched = 0; bad = []
turns = collections.Counter(); cmds = collections.Counter()
for oid in ours_pivot:
    m = re.match(r"^trajectory:([0-9a-f]+)/turn:(\d+)/sample:(\S+?)/command:(\d+)$", oid)
    if not m:
        bad.append(oid); continue
    samp[m.group(3)] += 1; turns[int(m.group(2))] += 1; cmds[int(m.group(4))] += 1
    if m.group(3) in pivot_uuids: matched += 1
out["b_nemotron_terminal_pivot_provenance"] = {
    "our_s3_distinct_original_ids": len(ours_pivot),
    "original_ids_unparseable": len(bad), "examples_unparseable": bad[:5],
    "original_ids_whose_sample_uuid_exists_in_the_published_dataset": matched,
    "distinct_sample_uuids_referenced": len(samp),
    "published_dataset_rows": pstats["rows"], "published_distinct_uuids": pstats["distinct_uuids"],
    "fraction_of_published_rows_referenced": round(len(samp) / pstats["distinct_uuids"], 6),
    "turn_index_histogram": dict(sorted(turns.items())[:10]),
    "command_index_histogram": dict(sorted(cmds.items())[:10]),
}
print("pivot provenance", json.dumps(out["b_nemotron_terminal_pivot_provenance"])[:400], flush=True)

# ---------------- (c) Terminal-Pivot vs Indirect-Prompt-Injection ----------------
NPERM = 128; SEED = 20260922
rng = np.random.default_rng(SEED)
A = (rng.integers(1, 2**63, size=NPERM, dtype=np.uint64) * np.uint64(2) + np.uint64(1)).astype(np.uint64)
Bp = rng.integers(0, 2**63, size=NPERM, dtype=np.uint64).astype(np.uint64)

def sig_of(h):
    if h.size == 0: return np.full(NPERM, L.UINT64_MAX, dtype=np.uint64)
    with np.errstate(over="ignore"):
        return ((h[None, :] * A[:, None]) + Bp[:, None]).min(axis=1)

# IPI side (already normalised in the train doc file)
ipi_ids = []; ipi_sh = []; ipi_sha = set(); ipi_shas = []
for d in L.read_docs(DOCS + "/train__nvidia__Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1.jsonl"):
    ipi_ids.append(d["id"]); ipi_sh.append(L.shingle_hashes(d["t"])); ipi_sha.add(d["sha"]); ipi_shas.append(d["sha"])
ipi_sig = np.stack([sig_of(h) for h in ipi_sh]) if ipi_sh else np.zeros((0, NPERM), np.uint64)
print("IPI docs", len(ipi_ids), round(time.time() - t0, 1), flush=True)

R = 2; NB = NPERM // R
def band_keys(sig):
    n = sig.shape[0]; o = np.empty((n, NB), dtype=np.uint64)
    off = np.uint64(14695981039346656037); prm = np.uint64(1099511628211); mix = np.uint64(0x9E3779B97F4A7C15)
    with np.errstate(over="ignore"):
        for j in range(NB):
            h = np.full(n, off, dtype=np.uint64)
            for t in range(R): h = (h ^ sig[:, j * R + t]) * prm
            o[:, j] = h ^ (np.uint64(j) * mix)
    return o
tk = band_keys(ipi_sig).reshape(-1)
town = np.repeat(np.arange(len(ipi_ids), dtype=np.int64), NB)
o = np.argsort(tk, kind="stable"); tk = tk[o]; town = town[o]
uk, ust, uct = np.unique(tk, return_index=True, return_counts=True)

# Pivot side: stream the reduced extract
best = []; nexact = 0; npivot = 0; maxj = 0.0
exact_examples = []
for line in open(ROOT + "/work/pivot_extract.jsonl", encoding="utf-8"):
    line = line.strip()
    if not line: continue
    r = json.loads(line)
    for view in ["first_content", "expected_answer"]:
        t = L.normalize(r.get(view))
        if not t: continue
        npivot += 1
        sh = L.sha256_text(t)
        if sh in ipi_sha:
            nexact += 1
            if len(exact_examples) < 5:
                exact_examples.append({"pivot_uuid": r["uuid"], "view": view, "text_200": t[:200]})
        h = L.shingle_hashes(t); s = sig_of(h)
        bk = band_keys(s[None, :]).reshape(-1)
        pos = np.minimum(np.searchsorted(uk, bk), max(uk.size - 1, 0))
        if uk.size == 0: continue
        ok = uk[pos] == bk
        pos = pos[ok]
        if pos.size == 0: continue
        cands = set()
        for p in pos:
            cands.update(int(x) for x in town[ust[p]:ust[p] + uct[p]])
        for ti in cands:
            j = L.exact_jaccard(h, ipi_sh[ti])
            if j > maxj: maxj = j
            if j >= 0.5:
                best.append({"jaccard": round(j, 6), "pivot_uuid": r["uuid"], "pivot_view": view,
                             "ipi_doc": ipi_ids[ti], "pivot_text_200": t[:200]})
    if npivot % 20000 == 0:
        print("pivot docs scanned", npivot, "exact", nexact, "maxj", round(maxj, 4), round(time.time() - t0, 1), flush=True)
best.sort(key=lambda x: -x["jaccard"])
out["c_pivot_vs_ipi_text_overlap"] = {
    "pivot_docs_compared": npivot, "ipi_docs": len(ipi_ids),
    "exact_normalised_text_collisions": nexact, "exact_examples": exact_examples,
    "max_jaccard_observed": round(maxj, 6),
    "n_pairs_with_jaccard_ge_0.5": len(best), "top_pairs": best[:20],
    "method": "128-perm MinHash, LSH r=2/b=64 (detection 1-(1-J^2)^64 = 1.000 at J>=0.5), exact-Jaccard verified",
}
print("pivot-vs-ipi exact", nexact, "maxj", maxj, "ge0.5", len(best), flush=True)

json.dump(out, open(ROOT + "/work/taske_raw.json", "w"), indent=2)
print("WROTE work/taske_raw.json", round(time.time() - t0, 1), flush=True)
