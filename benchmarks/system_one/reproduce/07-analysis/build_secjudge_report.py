#!/usr/bin/env python3
"""Assemble outputs/secjudge/secjudge-report.json and .md from settled artifacts only.

Re-runnable: any stage that is not settled is reported as NOT RUN / NOT SETTLED rather than
omitted, so a partial run is honest rather than complete-looking.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import sys
sys.path.insert(0, "$WORK/.system-one-data/outputs/secjudge/code")
from narrative import BOTTOM_LINE, CLAIMS, CONTAMINATION_VERDICT  # noqa: E402

SJ = Path("$WORK/.system-one-data/outputs/secjudge")
DATA = Path("$WORK/.system-one-data/outputs")

STAGES = [
    ("s2", "C0", "Broad comparison, current-event context", "s2-C0"),
    ("s2", "C7", "Broad comparison, PARITY context", "s2-C7"),
    ("s2-cmd", "C0", "Broad comparison, bare-command serialisation", "s2-cmd-C0"),
    ("s3", "C0", "Production-weighted, current-event context", "s3-C0"),
    ("s3", "C7", "Production-weighted, PARITY context", "s3-C7"),
    ("s3-cmd", "C0", "Production-weighted, bare-command serialisation", "s3-cmd-C0"),
    ("intent-real", "C0", "Intent reversal test, no-intent context", "intent-real-C0"),
    ("intent-real", "C7", "Intent reversal test, full context", "intent-real-C7"),
    ("toolcall-labels", "C0", "Label corpus, current-event context", "toolcall-labels-C0"),
    ("toolcall-labels", "C7", "Label corpus, full context", "toolcall-labels-C7"),
]


def sha256_file(path: Path) -> str | None:
    if not path.exists():
        return None
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load(path: Path):
    return json.loads(path.read_text()) if path.exists() else None


def lens(block: dict | None) -> dict:
    if not block:
        return {}
    b = block.get("binary", {})
    bo = block.get("binary_block_only", {})
    t = block.get("three_way", {})
    return {
        "any_intervention": {
            "f1": b.get("f1"),
            "precision": b.get("precision"),
            "recall": b.get("recall"),
            "fpr": b.get("false_positive_rate"),
            "confusion": b.get("confusion"),
        },
        "block_only": {
            "f1": bo.get("f1"),
            "precision": bo.get("precision"),
            "recall": bo.get("recall"),
            "fpr": bo.get("false_positive_rate"),
            "confusion": bo.get("confusion"),
        },
        "three_way_accuracy": t.get("accuracy"),
        "three_way_macro_f1": t.get("macro_f1"),
        "confirm_rate": block.get("review_rate"),
        "llm_invocation_rate": block.get("llm_invocation_rate"),
        "system_one_invocation_rate": block.get("system_one_invocation_rate"),
    }


report: dict = {
    "kind": "secjudge-benchmark-report",
    "schema_version": "1",
    "model": {
        "repo": "nghodki/SecJudge",
        "revision": "28e810afc9113d5b3ec60401940657108f51f1bb",
        "gated": "manual",
        "license": "Apache-2.0",
        "base_model": "answerdotai/ModernBERT-large",
        "params": 395836421,
        "snapshot": "$WORK/.system-one-data/models/secjudge-snapshot",
    },
    "verification": load(SJ / "load-verification.json"),
    "calibrator": load(SJ / "calibrator-resolution.json"),
    "contamination": {},
    "truncation": {},
    "serialisation": {
        "primary": "production_text rendering of the requested context variant",
        "definition": (
            "build_state() from benchmark_run_system_one.py produces the canonical bounded context "
            "for the variant (identical byte bounds, identical security-term-aware middle-out "
            "truncation, identical tag neutralisation) and the C7 production_text tag format "
            "flattens it to one string. For C7 build_state already returns that string and it is "
            "used byte for byte; for C0 the same tag format is rendered from the structured dict, "
            "which reduces to the single CURRENT_TOOL_CALL block."
        ),
        "confound_declaration": (
            "DIFFERENT PROMPTING CONTRACT. SecJudge is a 5-class sequence classifier: it receives "
            "no policy text, no question and no instruction variant. The other five backends "
            "answered the Q0-Q4 question grid with an instruction variant. The prediction schema "
            "has no slot for 'not a question', so SecJudge rows are labelled I0/Q0; that is a "
            "schema requirement, NOT a claim that SecJudge answered the Q0 prompt. Every SecJudge "
            "number in this report is therefore a model+contract measurement, not a pure model "
            "comparison."
        ),
        "alternative_diagnostic": "cmd (bare command text, no framing tags)",
        "ablation": load(SJ / "serialisation-ablation.json"),
        "ablation_alt": load(SJ / "serialisation-ablation-alt.json"),
    },
    "class_mapping": {
        "primary_arm": "sev",
        "sev": "severity argmax: NONE/LOW -> allow, MEDIUM -> confirm, HIGH/CRITICAL -> block",
        "isattack": "the model's own shipped binary rule (calibrated_score > 0.5) -> block",
        "threshold_family": {
            "t05-50": "confirm at calibrated >= 0.05, block at >= 0.50",
            "t10-90": "confirm at calibrated >= 0.10, block at >= 0.90",
            "t20-75": "confirm at calibrated >= 0.20, block at >= 0.75",
        },
        "risk_convention": (
            "probabilities['disposition.allow'] = 1 - calibrated_score, so the shared scorer's "
            "risk = 1 - disposition.allow IS SecJudge's own calibrated P(attack). The scorer then "
            "generates the two-sided cascade family @0.05/@0.10/@0.20/@0.30 from that risk for "
            "every arm, exactly as it does for the other models."
        ),
    },
    "stages": {},
    "recall_at_fixed_fpr": {},
    "throughput_and_cost": {},
    "not_run": [],
}

# ---- truncation ----
for stage in ["s2", "s3", "intent-real", "toolcall-labels"]:
    t = load(SJ / "truncation" / f"{stage}.json")
    if t:
        report["truncation"][stage] = {
            "cases": t["cases"],
            "by_variant": t["by_variant"],
            "by_variant_class": t["by_variant_class"],
            "artifact": str(SJ / "truncation" / f"{stage}.json"),
        }
report["truncation"]["compute_plan"] = load(SJ / "truncation" / "compute-plan.json")

# ---- contamination ----
# Referenced by path + digest rather than inlined: the near-dup and suite-overlap artifacts are
# hundreds of KB each and belong in their own files.
report["contamination"]["artifacts"] = {}
for name in [
    "training-sources",
    "exact-matches",
    "near-duplicates",
    "defenseclaw-suite-overlap",
    "eval-reuse",
    "file-provenance",
    "methodology",
]:
    for ext in ("json", "md"):
        p_ = SJ / "contamination" / f"{name}.{ext}"
        if p_.exists():
            report["contamination"]["artifacts"][f"{name}.{ext}"] = {
                "path": str(p_),
                "bytes": p_.stat().st_size,
                "sha256": sha256_file(p_),
            }
em = load(SJ / "contamination" / "exact-matches.json") or {}
report["contamination"]["exact_match_summary"] = {
    "normalisation": em.get("normalisation"),
    "train_side_distinct_normalised_texts": (em.get("train_side") or {}).get("n_distinct_normalised_texts"),
    "train_side_docs_total": (em.get("train_side") or {}).get("n_docs_total"),
    "total_corpus_docs_with_a_collision": (em.get("exact_collisions") or {}).get(
        "total_corpus_docs_with_a_collision"
    ),
    "by_train_group_x_stage_x_view": (em.get("exact_collisions") or {}).get("by_train_group_x_stage_x_view"),
    "distinct_corpus_cases_by_train_group_x_stage": (em.get("exact_collisions") or {}).get(
        "distinct_corpus_cases_by_train_group_x_stage"
    ),
}
report["contamination"]["verdict"] = {
    "overall": "undeterminable",
    "s2": "clean",
    "s3": "clean",
    "intent-real": "clean",
    "toolcall-labels": "contaminated",
    "public_training_sources_obtained": "7 of 11",
    "training_samples_unobtainable": 5550,
    "training_samples_unobtainable_share": 0.351,
    "missing_evidence": [
        "the actual 4,100-row DefenseClaw Security Suite training slice and its revision",
        "DC JSON-augmented (190 rows)",
        "DC context-augmented (490 rows)",
        "Attack Example Bank (EN) (770 rows, internal)",
        "the internal DefenseClaw command dumps behind augur defenseclaw_convs_parquet / defenseclaw_dump_100k",
    ],
    "eval_set_reuse": {
        "rogue-coding-agent-security": {
            "our_cases": 96,
            "s2": 87,
            "s3": 9,
            "distinct_benchmark_rows_covered": 91,
            "share_of_secjudge_eval_benchmark": 0.274,
            "exact_text_matches": 63,
            "note": "same 332-case benchmark SecJudge reports its cross-domain number on; not out-of-sample for it",
        },
        "nemotron": "sibling dataset, not the same: 0 exact collisions, max Jaccard 0.0792, disjoint id spaces",
    },
}
report["contamination"]["repo_has_no_dataset_files"] = True
report["contamination"]["repo_file_list"] = load(SJ / "repo-meta" / "fetch-manifest.json")

# ---- stages ----
for stage, ctx, label, key in STAGES:
    card = load(SJ / "scores" / f"{key}.json")
    closure = load(SJ / "scores" / f"{key}.closure.json")
    entry: dict = {"label": label, "context_variant": ctx, "scorecard": str(SJ / "scores" / f"{key}.json")}
    if not card:
        entry["status"] = "NOT RUN"
        report["not_run"].append(f"{stage} {ctx}")
        report["stages"][key] = entry
        continue
    entry["status"] = "complete" if (closure or {}).get("complete") else "scored (no closure)"
    entry["cases_sha256"] = card.get("cases_sha256")
    entry["case_count"] = card.get("case_count")
    entry["truth_grades"] = card.get("truth_grades")
    entry["prediction_sha256"] = card.get("prediction_sha256")
    entry["repeatability"] = card.get("repeatability")
    arms = {}
    for cand in card.get("candidates", []):
        name = cand["candidate"]
        a = {
            "scorable_cases": cand["scorable_cases"],
            "truth_grades_scorable": cand["truth_grades"],
            "system_one": lens(cand.get("system_one")),
            "per_event": cand.get("per_event"),
            "requests": cand["system_one"].get("requests"),
            "input_tokens": cand["system_one"].get("input_tokens"),
            "errors": cand["system_one"].get("errors"),
            "latency_ms": cand["system_one"].get("latency_ms"),
            "calibration": cand["system_one"].get("calibration"),
        }
        for cas in [
            "deterministic_then_system_one",
            "deterministic_then_llm",
            "deterministic_then_system_one_then_llm",
            "deterministic_then_system_one_then_llm_two_sided_0.05",
            "deterministic_then_system_one_then_llm_two_sided_0.10",
            "deterministic_then_system_one_then_llm_two_sided_0.20",
            "deterministic_then_system_one_then_llm_two_sided_0.30",
        ]:
            if cas in cand:
                a.setdefault("cascade", {})[cas] = lens(cand[cas])
        arms[name] = a
    entry["arms"] = arms
    # run provenance from the prediction metas
    prov = []
    for meta_path in sorted((SJ / "predictions").glob(f"secjudge-{stage}-{ctx}-*.jsonl.meta.json")):
        m = load(meta_path)
        if m:
            prov.append(
                {
                    "arm": m.get("arm"),
                    "path": str(meta_path).removesuffix(".meta.json"),
                    "prediction_sha256": m.get("prediction_sha256"),
                    "on_disk_sha256": sha256_file(Path(str(meta_path).removesuffix(".meta.json"))),
                    "complete": m.get("complete"),
                    "decisions": m.get("decisions"),
                    "truncation_rate_512_tokens": m.get("truncation_rate_512_tokens"),
                    "action_counts": m.get("action_counts"),
                    "actual_input_tokens": m.get("actual_input_tokens"),
                }
            )
    for p in prov:
        p["settled"] = bool(p["complete"]) and p["prediction_sha256"] == p["on_disk_sha256"]
    entry["run_provenance"] = prov
    report["stages"][key] = entry

# ---- recall at fixed FPR ----
for f in sorted((SJ / "scores").glob("recall-at-fpr-*.json")):
    report["recall_at_fixed_fpr"][f.stem] = load(f)

# ---- throughput and cost ----
shards = []
for meta_path in sorted((SJ / "raw").glob("*.jsonl.meta.json")):
    m = load(meta_path)
    if m:
        shards.append(
            {
                "path": str(meta_path).removesuffix(".meta.json"),
                "stage": m.get("stage"),
                "variants": m.get("variants"),
                "serialisation": m.get("serialisation", "production_text"),
                "shard": m.get("shard"),
                "shards": m.get("shards"),
                "threads": m.get("threads"),
                "decisions": m.get("decisions"),
                "forward_passes": m.get("forward_passes"),
                "cache_hits": m.get("cache_hits"),
                "padded_tokens": m.get("padded_tokens"),
                "wall_clock_s": m.get("wall_clock_s"),
                "decisions_per_s": m.get("decisions_per_s"),
            }
        )
by_stage: dict = {}
for s in shards:
    k = f"{s['stage']}"
    g = by_stage.setdefault(
        k,
        {
            "shards": 0,
            "decisions": 0,
            "forward_passes": 0,
            "cache_hits": 0,
            "padded_tokens": 0,
            "max_wall_clock_s": 0.0,
            "sum_decisions_per_s": 0.0,
            "threads_per_shard": s.get("threads"),
            "serialisation": s.get("serialisation"),
        },
    )
    g["shards"] += 1
    for f_ in ("decisions", "forward_passes", "cache_hits", "padded_tokens"):
        g[f_] += s.get(f_) or 0
    g["max_wall_clock_s"] = max(g["max_wall_clock_s"], s.get("wall_clock_s") or 0)
    g["sum_decisions_per_s"] += s.get("decisions_per_s") or 0
for k, g in by_stage.items():
    g["aggregate_decisions_per_s"] = round(g["sum_decisions_per_s"], 2)
    g["wall_clock_minutes"] = round(g["max_wall_clock_s"] / 60, 2)
    g["provider_usd"] = 0.0
report["throughput_and_cost"] = {
    "provider_cost_usd": 0.0,
    "cost_note": (
        "SecJudge ran entirely on the shared dev host CPU (Intel Xeon 6975P-C, 8 physical cores). "
        "There is no provider/API cost for any SecJudge stage. The host was shared with other "
        "running work throughout, so the achieved rates below are contended, not peak."
    ),
    "dtype": "float32",
    "dtype_rationale": (
        "bfloat16 via AMX was measured at only 1.97x and broke agreement: is_attack agreement fell "
        "to 0.9375 and the calibrated score moved by up to 0.404, because the shipped isotonic "
        "calibrator has just 19 distinct output levels so tiny numeric shifts jump a whole plateau. "
        "fp32 was therefore used for every reported number."
    ),
    "by_stage": by_stage,
    "shards": shards,
    "int8_equivalence": load(SJ / "int8-equivalence.json"),
    "parallelism_measurements": {
        "note": (
            "Measured on this host, contended. More single-thread processes beat fewer "
            "multi-thread processes for this workload, which is the opposite of the usual advice: "
            "torch CPU GEMM at these sequence lengths scales poorly across threads within a "
            "process. Sharding costs memory though - each shard holds its own fp32 model copy at "
            "~4.0 GB RSS - so memory, not cores, is the binding constraint."
        ),
        "1proc_8threads_padded_tokens_per_s": 876,
        "3proc_2threads_padded_tokens_per_s": 728,
        "8proc_1thread_padded_tokens_per_s": 1147,
        "12proc_1thread_projected_padded_tokens_per_s": 1376,
        "consolidation_tradeoff": (
            "One resident model with 8-12 threads would cut memory roughly 8x but measured ~876 "
            "tok/s against 1,147 for 8x1, so it would cost ~24% throughput. Sharding was kept and "
            "capped at 12 to stay clear of the memory ceiling while other work shares the host."
        ),
    },
    "rejected_speedups": {
        "bfloat16_amx": {
            "speedup": 1.97,
            "is_attack_agreement": 0.9375,
            "max_calibrated_delta": 0.403509,
            "verdict": "rejected",
        },
        "int8_dynamic": {
            "speedup": 1.833,
            "is_attack_agreement": 0.985,
            "three_way_disposition_agreement": 0.995,
            "median_calibrated_delta": 0.151375,
            "max_calibrated_delta": 0.665667,
            "disposition_changes": 2,
            "verdict": "rejected",
            "reason": (
                "A median calibrated-score shift of 0.151 and 2 disposition changes in 400 samples "
                "is not equivalence, and a quantized number compared against full-precision "
                "baselines is not a fair comparison. 1.83x did not justify it."
            ),
        },
    },
}

report["contamination_verdict_md"] = CONTAMINATION_VERDICT
report["claims_md"] = CLAIMS
report["bottom_line_md"] = BOTTOM_LINE

out_json = SJ / "secjudge-report.json"
out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
print(f"wrote {out_json}")
print(json.dumps({"stages_present": sorted(report["stages"]), "not_run": report["not_run"]}, indent=2))
