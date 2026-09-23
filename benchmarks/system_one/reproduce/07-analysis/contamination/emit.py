"""Emit the six deliverable artifacts under contamination/."""
from __future__ import annotations
import glob, hashlib, json, os, sys, collections
sys.path.insert(0, "$WORK/.system-one-data/outputs/secjudge/contamination/work")

ROOT = "$WORK/.system-one-data/outputs/secjudge/contamination"
W = ROOT + "/work"
REPO = "$WORK/defenseclaw-system-one"
SUITE = REPO + "/internal/gateway/testdata/security_suite"
FIXT = REPO + "/benchmarks/fixtures"
BASE = "$WORK/.system-one-data/outputs"
SNAP = "$WORK/.system-one-data/models/secjudge-snapshot"
STAGES = ["s2", "s3", "intent-real", "toolcall-labels"]

def J(p):
    try: return json.load(open(p))
    except Exception: return None

def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for c in iter(lambda: fh.read(1 << 20), b""): h.update(c)
    return {"sha256": h.hexdigest(), "bytes": os.path.getsize(p)}

probe = J(W + "/probe.json")
dl = J(W + "/downloads.json") or {}
dlp = J(W + "/downloads_pivot.json") or {}
dlr = J(W + "/downloads_rogue_pinned.json") or {}
tds = J(W + "/train_docs_summary.json")
cds = J(W + "/corpus_docs_summary.json")
srcc = J(W + "/source_counts.json")
allst = J(W + "/all_stages_sources.json")
agg = J(W + "/aggregate.json")
cmdo = J(W + "/command_overlap.json")
taske = J(W + "/taske_raw.json")
pstats = J(W + "/pivot_stats.json")
lsh_metas = {os.path.basename(p): J(p) for p in sorted(glob.glob(W + "/lsh_meta__*.json"))}
lock = J(REPO + "/benchmarks/datasets.lock.json")
exact = J(ROOT + "/exact-matches.json")

# ---------------- file provenance ----------------
prov = {"corpora": {}, "repo_files": {}, "downloaded_dataset_files": {}, "model_snapshot": {}}
for s in STAGES:
    prov["corpora"][BASE + "/" + s + "/cases.jsonl"] = sha(BASE + "/" + s + "/cases.jsonl")
for p in [REPO + "/benchmarks/datasets.lock.json"] + \
         sorted(glob.glob(SUITE + "/*/corpus.jsonl")) + sorted(glob.glob(SUITE + "/*/*/corpus.jsonl")) + \
         [SUITE + "/toolcall/stateful.jsonl"] + sorted(glob.glob(FIXT + "/*.jsonl")):
    if os.path.exists(p): prov["repo_files"][p] = sha(p)
for grp in (tds or {}).get("input_files", {}):
    prov["downloaded_dataset_files"][grp] = tds["input_files"][grp]
for d in (dl, dlp, dlr):
    for repo, files in d.items():
        if isinstance(files, dict) and "ok" in files:
            if files.get("ok"): prov["downloaded_dataset_files"][files["path"]] = {"sha256": files["sha256"], "bytes": files["bytes"]}
        elif isinstance(files, dict):
            for f, rec in files.items():
                if isinstance(rec, dict) and rec.get("ok"): prov["downloaded_dataset_files"][rec["path"]] = {"sha256": rec["sha256"], "bytes": rec["bytes"]}
                elif isinstance(rec, dict) and rec.get("sha256"): prov["downloaded_dataset_files"][rec.get("path", f)] = {"sha256": rec["sha256"], "bytes": rec.get("bytes")}
for f in ["README.md", "config.json", "secjudge_config.json"]:
    prov["model_snapshot"][SNAP + "/" + f] = sha(SNAP + "/" + f)
json.dump(prov, open(ROOT + "/file-provenance.json", "w"), indent=2)

# ---------------- Task A: training-sources.json ----------------
CARD = [
    (1, "DefenseClaw Security Suite", 4100, None, "Apache-2.0", "Primary signal (5x weight)"),
    (2, "S-Labs/prompt-injection-dataset", 5900, "S-Labs/prompt-injection-dataset", "MIT", "Hard negatives"),
    (3, "AnishJoshi/nl2bash-custom", 1400, "AnishJoshi/nl2bash-custom", "-", "Benign shell commands"),
    (4, "DC JSON-augmented", 190, None, "Apache-2.0", "Attacks in tool-call JSON format"),
    (5, "DC context-augmented", 490, None, "Apache-2.0", "Attacks embedded in benign paragraphs"),
    (6, "ise-uiuc/Magicoder-OSS-Instruct-75K", 870, "ise-uiuc/Magicoder-OSS-Instruct-75K", "MIT", "Long code content"),
    (7, "Attack Example Bank (EN)", 770, None, "Internal", "Jailbreak diversity"),
    (8, "Trendyol/Trendyol-Cybersecurity-Instruction-Tuning-Dataset", 680, "Trendyol/Trendyol-Cybersecurity-Instruction-Tuning-Dataset", "Apache-2.0", "Security discussions"),
    (9, "3nesdeniz/agentic-prompt-injection-boundary-pairs", 840, "3nesdeniz/agentic-prompt-injection-boundary-pairs", "CC-BY-4.0", "Paired attack/benign"),
    (10, "deepset/prompt-injections", 330, "deepset/prompt-injections", "Apache-2.0", "Foundational injection detection"),
    (11, "infraset/infraset", 225, "infraset/infraset", "Apache-2.0", "Sysadmin tasks"),
]
GROUPMAP = {
    "S-Labs/prompt-injection-dataset": "S-Labs/prompt-injection-dataset",
    "AnishJoshi/nl2bash-custom": "AnishJoshi/nl2bash-custom",
    "ise-uiuc/Magicoder-OSS-Instruct-75K": "ise-uiuc/Magicoder-OSS-Instruct-75K",
    "Trendyol/Trendyol-Cybersecurity-Instruction-Tuning-Dataset": "Trendyol/Trendyol-Cybersecurity-Instruction-Tuning-Dataset",
    "3nesdeniz/agentic-prompt-injection-boundary-pairs": "3nesdeniz/agentic-prompt-injection-boundary-pairs",
    "deepset/prompt-injections": "deepset/prompt-injections",
    "infraset/infraset": "infraset/infraset",
}
items = []
for num, name, claimed, repo_id, lic, role in CARD:
    rec = {"card_item": num, "card_name": name, "card_claimed_samples": claimed,
           "card_license": lic, "card_role": role, "hf_repo_id": repo_id}
    if repo_id is None:
        if name == "DefenseClaw Security Suite":
            rec.update({"obtainable": "PARTIAL -- not published as a dataset repo",
                        "status": "no HuggingFace dataset repo exists; the SecJudge model repo contains no data files",
                        "what_we_used_instead": SUITE,
                        "why_partial": "we located the in-repo DefenseClaw Security Suite corpora and compared against them, "
                                       "but we cannot know which 4,100 of those rows (or which earlier revision) SecJudge sampled",
                        "rows_available_in_repo": (tds["groups"]["DefenseClaw Security Suite"]["source_rows"] if tds else None)})
        else:
            rec.update({"obtainable": "NO", "status": "unpublished / internal to the SecJudge author",
                        "why_not": "not a HuggingFace dataset repo and not present in the SecJudge model repo (which ships only "
                                   "weights, config, tokenizer, calibrator and README); rows are not enumerable from any artifact we can reach"})
        items.append(rec); continue
    p = (probe or {}).get(repo_id, {})
    g = GROUPMAP[repo_id]
    ts = (tds or {}).get("groups", {}).get(g, {})
    rec.update({
        "reachable": p.get("status") == "reachable", "gated": p.get("gated"), "private": p.get("private"),
        "resolved_revision_sha": p.get("sha"), "hub_license": p.get("card_license"),
        "declared_configs": p.get("card_configs"), "declared_dataset_info": p.get("card_dataset_info"),
        "obtainable": "YES", "status": "downloaded and parsed",
        "files_downloaded": {k: v for k, v in (dl.get(repo_id) or {}).items()},
        "splits": ts.get("splits"), "source_rows_per_split": ts.get("source_rows"),
        "total_source_rows": sum(ts.get("source_rows", {}).values()) if ts.get("source_rows") else None,
        "text_fields_used": ts.get("text_fields"), "text_views_built": ts.get("views"),
        "normalised_docs_built": ts.get("n_docs"), "max_normalised_chars": ts.get("max_norm_chars"),
        "normalised_docs_path": ts.get("docs_path"),
    })
    if rec["total_source_rows"] and claimed:
        rec["note_superset"] = ("repo holds %d rows; the card says SecJudge used %d of them. The specific subset is not "
                                "recorded anywhere we can reach, so we compare against ALL rows (a conservative superset)."
                                % (rec["total_source_rows"], claimed))
    items.append(rec)

taskA = {
    "task": "A -- obtain SecJudge's named public training datasets",
    "model_card_source": SNAP + "/README.md",
    "model_card_sha256": prov["model_snapshot"][SNAP + "/README.md"]["sha256"],
    "card_totals": {"sources": 11, "samples_stated_by_card": 15266,
                    "samples_summed_from_card_table": 15795,
                    "discrepancy": 529,
                    "note": "the card states 15,266 samples but its own per-source table sums to 15,795 "
                            "(4100+5900+1400+190+490+870+770+680+840+330+225). We report both; percentages "
                            "below use the tabulated 15,795 unless stated otherwise."},
    "secjudge_repo_contains_no_data_files": True,
    "summary": {
        "publicly_named_hf_datasets": 7,
        "obtained": 7, "gated": 0, "missing": 0,
        "not_obtainable_unpublished_sources": 4,
        "not_obtainable_names": ["DefenseClaw Security Suite (located in-repo instead)",
                                  "DC JSON-augmented", "DC context-augmented", "Attack Example Bank (EN)"],
        "samples_covered_by_obtained_sources": 5900 + 1400 + 870 + 680 + 840 + 330 + 225,
        "samples_not_covered": 4100 + 190 + 490 + 770,
        "fraction_of_tabulated_15795_samples_whose_source_pool_we_could_obtain": round(10245/15795, 4),
        "fraction_of_stated_15266_samples_whose_source_pool_we_could_obtain": round(10245/15266, 4),
    },
    "sources": items,
    "additional_sources_downloaded_for_task_E": {
        "rogue-security/coding-agent-security-benchmark": {
            "role": "SecJudge EVALUATION set; also an enabled entry in our datasets.lock.json",
            "reachable": True, "gated": (probe or {}).get("rogue-security/coding-agent-security-benchmark", {}).get("gated"),
            "rows": 332, "text_fields": ["data_to_evaluate", "message_type", "label", "category_and_criticality"],
            "pinned_revision_we_used": "bf7ff748d80ca24db30b57c9255a2fb8884ed7eb", "files": dlr},
        "nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1": {
            "role": "SecJudge EVALUATION set", "reachable": True, "rows": 1272,
            "text_fields": ["injection", "responses_create_params", "input[].content"]},
        "nvidia/Nemotron-RL-Agentic-Terminal-Pivot-v1": {
            "role": "source of 23,410 of our s3 cases (NOT a SecJudge source)",
            "reachable": True, "rows": (pstats or {}).get("rows"), "files": dlp},
    },
    "cache_dir": ROOT + "/cache",
}
json.dump(taskA, open(ROOT + "/training-sources.json", "w"), indent=2)
print("WROTE training-sources.json")

# ---------------- Task B: augment exact-matches.json ----------------
if exact is not None:
    exact["bare_command_string_exact_collisions"] = {
        "why": "our corpora wrap commands as {\"command\": \"...\"}; this section compares the bare command string "
               "against the bare command/content strings of the training sources",
        "method": (cmdo or {}).get("method"),
        "corpus_command_strings_extracted": (cmdo or {}).get("corpus_command_strings_extracted"),
        "by_train_group_stage_field": (cmdo or {}).get("exact_string_collisions_by_group_stage_field"),
        "distinct_corpus_cases_by_train_group_stage": (cmdo or {}).get("exact_distinct_corpus_cases_by_group_stage"),
        "examples_truncated_200": (cmdo or {}).get("exact_examples", [])[:60],
    }
    exact["corpus_file_sha256"] = {k: v["sha256"] for k, v in prov["corpora"].items()}
    json.dump(exact, open(ROOT + "/exact-matches.json", "w"), indent=2)
    print("WROTE exact-matches.json (augmented)")

# ---------------- Task C: near-duplicates.json / .txt ----------------
nd = {
    "task": "C -- near-duplicate detection between SecJudge training-source rows and our corpus cases",
    "what_the_numbers_mean": {
        "unit": "a count is a number of DISTINCT CASES in our corpus (not documents) whose best-matching "
                "training-source row reaches the given exact Jaccard similarity",
        "similarity": "Jaccard over sets of character 5-grams of the identically normalised text; EXACT, "
                      "recomputed from the full 5-gram sets (MinHash is used only to pick candidates)",
        "thresholds": [0.9, 0.7, 0.5],
        "ge_0.3_floor": "pairs below Jaccard 0.30 were discarded, so counts are complete only at and above 0.5",
    },
    "lsh_passes": lsh_metas,
    "recall_note": ("the r=2/b=64 pass has detection probability 1.000 at J>=0.5 and 0.9976 at J>=0.3, so the "
                    ">=0.5/0.7/0.9 counts are effectively complete; 917 over-capacity LSH buckets "
                    "(21,882,459 postings) were skipped in that pass and are the only known recall gap"),
    "corpus_totals": {s: {"n_cases": cds[s]["n_cases"], "n_docs": cds[s]["n_docs_total"],
                          "n_docs_by_view": cds[s]["n_docs_by_view"]} for s in STAGES} if cds else None,
    "results_by_source_x_stage": (agg or {}).get("by_source_x_stage"),
    "results_by_source_x_stage_x_view": (agg or {}).get("by_source_x_stage_x_view"),
    "results_by_source_x_stage_x_corpus_source_dataset": (agg or {}).get("by_source_x_stage_x_corpus_source_dataset"),
    "top_20_pairs_per_source_x_stage": (agg or {}).get("top_pairs_per_source_x_stage"),
    "defenseclaw_suite_by_subcorpus_x_stage": (agg or {}).get("defenseclaw_by_subcorpus_x_stage"),
    "top_20_pairs_defenseclaw_subcorpus_x_stage": (agg or {}).get("top_pairs_defenseclaw_subcorpus_x_stage"),
    "bare_command_string_pass": {
        "method": (cmdo or {}).get("method"), "posting_cap": (cmdo or {}).get("posting_cap"),
        "indexable_coverage": (cmdo or {}).get("indexable_coverage"),
        "near_dup_cases_by_group_x_stage": (cmdo or {}).get("near_dup_cases_by_group_x_stage"),
        "top_pairs": (cmdo or {}).get("top_pairs"),
    },
    "sources_with_zero_pairs_at_any_threshold": None,
}
seen_groups = set(k.split(" || ")[0] for k in ((agg or {}).get("by_source_x_stage") or {}))
ALLG = ["S-Labs__prompt-injection-dataset", "AnishJoshi__nl2bash-custom",
        "ise-uiuc__Magicoder-OSS-Instruct-75K", "Trendyol__Trendyol-Cybersecurity-Instruction-Tuning-Dataset",
        "3nesdeniz__agentic-prompt-injection-boundary-pairs", "deepset__prompt-injections",
        "infraset__infraset", "dc-security-suite", "dc-benchmark-fixtures",
        "rogue-security__coding-agent-security-benchmark",
        "nvidia__Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1"]
nd["sources_with_zero_pairs_at_any_threshold"] = sorted(set(ALLG) - seen_groups)
json.dump(nd, open(ROOT + "/near-duplicates.json", "w"), indent=2)
print("WROTE near-duplicates.json")

L = []
L.append("SecJudge training-data contamination -- near-duplicate report (Task C)")
L.append("=" * 100)
L.append("")
L.append("Similarity = EXACT Jaccard over sets of character 5-grams of identically normalised text.")
L.append("Counts are DISTINCT CASES in our corpus whose best training-source match reaches the threshold.")
L.append("Candidate generation: 128-permutation MinHash, LSH banding r=2/b=64 (detection 1.000 at J>=0.5)")
L.append("and r=3/b=42 (0.9963 at J>=0.5). Every candidate was verified with an exact Jaccard.")
L.append("Pairs below J=0.30 were discarded.")
L.append("")
if cds:
    L.append("Corpus sizes: " + ", ".join("%s=%d cases/%d docs" % (s, cds[s]["n_cases"], cds[s]["n_docs_total"]) for s in STAGES))
L.append("")
L.append("-" * 100)
L.append("%-55s %-16s %7s %7s %7s %9s" % ("TRAINING SOURCE", "OUR STAGE", ">=0.9", ">=0.7", ">=0.5", "MAX J"))
L.append("-" * 100)
bss = (agg or {}).get("by_source_x_stage") or {}
for k in sorted(bss):
    g, st = k.split(" || ")
    v = bss[k]
    L.append("%-55s %-16s %7d %7d %7d %9.4f" % (g[:55], st, v["ge_0.9"], v["ge_0.7"], v["ge_0.5"], v["max_jaccard"]))
L.append("-" * 100)
if nd["sources_with_zero_pairs_at_any_threshold"]:
    L.append("")
    L.append("Training sources with NO pair reaching even J=0.30 against ANY of our cases:")
    for g in nd["sources_with_zero_pairs_at_any_threshold"]: L.append("   " + g)
L.append("")
L.append("=" * 100)
L.append("DefenseClaw Security Suite broken out by sub-corpus (highest-risk overlap path)")
L.append("=" * 100)
L.append("%-45s %-16s %7s %7s %7s %9s" % ("SUB-CORPUS", "OUR STAGE", ">=0.9", ">=0.7", ">=0.5", "MAX J"))
sub = (agg or {}).get("defenseclaw_by_subcorpus_x_stage") or {}
for k in sorted(sub):
    parts = k.split(" || "); v = sub[k]
    L.append("%-45s %-16s %7d %7d %7d %9.4f" % ((parts[0] + "/" + parts[1])[:45], parts[2],
             v["ge_0.9"], v["ge_0.7"], v["ge_0.5"], v["max_jaccard"]))
if cmdo:
    L.append("")
    L.append("=" * 100)
    L.append("BARE COMMAND-STRING pass (wrapper {\"command\": ...} removed; exact inverted index, no MinHash)")
    L.append("=" * 100)
    L.append("%-55s %-16s %7s %7s %7s %7s" % ("TRAINING SOURCE", "OUR STAGE", "EXACT", ">=0.9", ">=0.7", ">=0.5"))
    for k, v in sorted((cmdo.get("near_dup_cases_by_group_x_stage") or {}).items()):
        g, st = k.split(" || ")
        L.append("%-55s %-16s %7d %7d %7d %7d" % (g[:55], st, v["ge_1.0_exact"], v["ge_0.9"], v["ge_0.7"], v["ge_0.5"]))
L.append("")
L.append("=" * 100)
L.append("TOP PAIRS PER (TRAINING SOURCE x OUR STAGE)   [texts truncated to 200 chars]")
L.append("=" * 100)
for k, lst in sorted(((agg or {}).get("top_pairs_per_source_x_stage") or {}).items()):
    L.append("")
    L.append("### " + k)
    for e in lst:
        L.append("  J=%.4f" % e["jaccard"])
        L.append("    OURS  [%s]" % e["corpus_doc_id"])
        L.append("          %s" % e["corpus_text_200"])
        L.append("    TRAIN [%s]" % e["train_doc_id"])
        L.append("          %s" % e["train_text_200"])
open(ROOT + "/near-duplicates.txt", "w", encoding="utf-8").write("\n".join(L) + "\n")
print("WROTE near-duplicates.txt")
