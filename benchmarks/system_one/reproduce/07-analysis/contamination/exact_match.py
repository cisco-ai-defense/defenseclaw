"""Task B: exact-match contamination check (sha256 of identically normalised text)."""
from __future__ import annotations
import glob, json, os, sys, collections
sys.path.insert(0, "$WORK/.system-one-data/outputs/secjudge/contamination/work")
import contam_lib as L

ROOT = "$WORK/.system-one-data/outputs/secjudge/contamination"
DOCS = ROOT + "/work/docs"
STAGES = ["s2", "s3", "intent-real", "toolcall-labels"]

# ---- load every training-side normalised text hash -------------------------
train_by_sha = {}          # sha -> (group, [doc_ids up to 5])
train_text = {}            # sha -> text (truncated) for examples
group_docs = collections.Counter()
group_distinct = collections.defaultdict(set)
for p in sorted(glob.glob(DOCS + "/train__*.jsonl")):
    for d in L.read_docs(p):
        g = d["id"].split("|", 1)[0]
        group_docs[g] += 1
        group_distinct[g].add(d["sha"])
        e = train_by_sha.get(d["sha"])
        if e is None:
            train_by_sha[d["sha"]] = [g, [d["id"]]]
            train_text[d["sha"]] = d["t"][:400]
        elif len(e[1]) < 5:
            e[1].append(d["id"])
    print("loaded", os.path.basename(p), len(train_by_sha), flush=True)

# group label for a sha may be ambiguous across groups; track all groups per sha
sha_groups = collections.defaultdict(set)
for sha, (g, ids) in train_by_sha.items():
    for i in ids: sha_groups[sha].add(i.split("|", 1)[0])

print("TRAIN distinct normalised texts:", len(train_by_sha), flush=True)

pair_counts = collections.Counter()      # (group, stage, view) -> n corpus docs
case_hits = collections.defaultdict(set) # (group, stage) -> {case_id}
examples = []
corpus_totals = collections.Counter()
corpus_distinct = collections.defaultdict(set)
for stage in STAGES:
    for d in L.read_docs(DOCS + "/corpus__" + stage + ".jsonl"):
        corpus_totals[(stage, d["view"])] += 1
        corpus_distinct[(stage, d["view"])].add(d["sha"])
        hit = train_by_sha.get(d["sha"])
        if hit is None: continue
        for g in sha_groups[d["sha"]]:
            pair_counts[(g, stage, d["view"])] += 1
            case_hits[(g, stage)].add(d["cid"])
            if len(examples) < 400:
                examples.append({
                    "train_group": g, "stage": stage, "view": d["view"],
                    "corpus_doc_id": d["id"], "corpus_case_id": d["cid"],
                    "corpus_source_dataset": d["ds"],
                    "train_doc_ids": train_by_sha[d["sha"]][1],
                    "sha256_normalised": d["sha"],
                    "text_200": d["t"][:200],
                })
    print("scanned", stage, flush=True)

out = {
    "task": "B -- exact match on sha256 of identically normalised text",
    "normalisation": "NFKC -> remove framing tags -> lowercase -> collapse whitespace runs to single space -> strip",
    "train_side": {
        "n_docs_total": sum(group_docs.values()),
        "n_distinct_normalised_texts": len(train_by_sha),
        "per_group": {g: {"n_docs": group_docs[g], "n_distinct_norm_texts": len(group_distinct[g])}
                      for g in sorted(group_docs)},
    },
    "corpus_side": {
        "per_stage_view": {stage + "/" + view: {"n_docs": n,
                            "n_distinct_norm_texts": len(corpus_distinct[(stage, view)])}
                           for (stage, view), n in sorted(corpus_totals.items())},
    },
    "exact_collisions": {
        "total_corpus_docs_with_a_collision": sum(pair_counts.values()),
        "by_train_group_x_stage_x_view": {"%s || %s || %s" % k: v for k, v in sorted(pair_counts.items())},
        "distinct_corpus_cases_by_train_group_x_stage": {"%s || %s" % k: len(v) for k, v in sorted(case_hits.items())},
    },
    "examples_truncated_200": examples,
}
json.dump(out, open(ROOT + "/exact-matches.json", "w"), indent=2)
print("collisions:", sum(pair_counts.values()))
for k, v in sorted(pair_counts.items()): print("   ", k, v)
print("WROTE exact-matches.json")
