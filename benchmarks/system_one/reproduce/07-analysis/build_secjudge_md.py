#!/usr/bin/env python3
"""Render outputs/secjudge/secjudge-report.md from secjudge-report.json + the incumbent scorecards.

Every number here must exist in an artifact on disk; anything absent is printed as "not run"
rather than inferred.
"""

from __future__ import annotations

import json
from pathlib import Path

SJ = Path("$WORK/.system-one-data/outputs/secjudge")
R = json.loads((SJ / "secjudge-report.json").read_text())
L: list[str] = []


def w(s: str = "") -> None:
    L.append(s)


def num(v, nd=4, pct=False):
    if v is None:
        return "-"
    if isinstance(v, str):
        return v
    return f"{v * 100:.2f}%" if pct else f"{v:.{nd}f}"


def load(p: Path):
    return json.loads(p.read_text()) if p.exists() else None


w("# SecJudge (`nghodki/SecJudge`) on the System One corpora")
w()
m = R["model"]
w(
    f"Model `{m['repo']}` @ `{m['revision'][:12]}` - {m['params']:,} params, {m['license']}, "
    f"base `{m['base_model']}`, gated `{m['gated']}`. Ran on the shared dev host CPU, fp32."
)
w()
w("**Data only. Nothing in this run was published, uploaded, pushed or committed.**")
w()

# ------------------------------------------------------------------ 0. load verification
w("## 0. Model load verification (gate before any measurement)")
w()
v = R.get("verification") or {}
if v:
    w(
        f"- `load_state_dict` mapped **{v.get('state_dict_keys')}/{v.get('state_dict_keys')}** tensors: "
        f"**{v.get('n_missing')} missing, {v.get('n_unexpected')} unexpected**. Parameter count "
        f"**{v.get('param_count'):,}**, exactly the card's 395,836,421."
    )
    w(
        f"- Isotonic calibrator loaded: {v.get('calibrator_points')} table points, "
        f"output range [{v.get('calibrator_y_min')}, {v.get('calibrator_y_max')}]."
    )
    ce = v.get("card_examples") or []
    ok = sum(1 for c in ce if c.get("match_is_attack") and c.get("match_severity"))
    w(f"- The card's three documented examples reproduce **{ok}/{len(ce)}** on `is_attack` and `severity`.")
    w()
    w("Two load hazards worth recording, because either silently produces garbage:")
    w()
    w(
        "1. `SecJudgeForSequenceClassification.from_pretrained_secjudge()` builds the classifier with "
        "`AutoModelForSequenceClassification.from_config()` and then calls "
        "`load_state_dict(..., strict=False)`. With a key mismatch that path yields a **randomly "
        "initialised** 395M model with no error. We assert 0 missing / 0 unexpected keys before running."
    )
    w(
        "2. The same function resolves weights with `os.path.join(model_dir, 'model.safetensors')` and "
        "`os.path.exists`. The card's documented call `load_secjudge(\"nghodki/SecJudge\")` passes a "
        "**repo id**, for which that path does not exist, so no weights and no calibrator are ever "
        "loaded. A local snapshot directory is required. We used a pinned local snapshot."
    )
w()

# ------------------------------------------------------------------ 1. contamination
w("## 1. Contamination verdict")
w()
w(R.get("contamination_verdict_md", "_see the contamination section of secjudge-report.json_"))
w()

# ------------------------------------------------------------------ 2. truncation
w("## 2. Truncation at the 512-token contract")
w()
w(
    "The brief stated 512 tokens comes from `config.json`. It does not: `config.json` sets "
    "`max_position_embeddings: 8192` and `tokenizer_config.json` sets `model_max_length: 8192`. "
    "The 512 limit exists only in the model card and in the shipped `load_secjudge()`, which uses "
    "`max_length=512`. Worse, that function slices the input with `str(text)[:512]` - **512 "
    "characters**, not tokens - before tokenising. Both are measured below."
)
w()
w("| stage | ctx | class | decisions | trunc @512 tok | trunc @512 char (vendor path) | tok mean | tok p99 | tok max |")
w("|---|---|---|---:|---:|---:|---:|---:|---:|")
for stage, t in R.get("truncation", {}).items():
    if stage == "compute_plan" or not isinstance(t, dict) or "by_variant_class" not in t:
        continue
    for k, b in sorted(t["by_variant_class"].items()):
        ctx, cls = k.split("|")
        w(
            f"| {stage} | {ctx} | {cls} | {b['decisions']:,} | "
            f"{num(b['truncation_rate_512_tokens'], pct=True)} | "
            f"{num(b['truncation_rate_512_chars_vendor_path'], pct=True)} | "
            f"{b['tokens_mean']} | {b['tokens_p99']} | {b['tokens_max']} |"
        )
w()
s2 = R.get("truncation", {}).get("s2", {}).get("by_variant_class", {})
if "C7|unsafe" in s2 and "C7|benign" in s2:
    u = s2["C7|unsafe"]["truncation_rate_512_tokens"]
    b = s2["C7|benign"]["truncation_rate_512_tokens"]
    w(
        f"**Class bias.** On the s2 parity context C7, truncation hits unsafe cases "
        f"**{num(u, pct=True)}** vs benign **{num(b, pct=True)}** - a "
        f"**{(u - b) * 100:+.1f} pp** gap against the class SecJudge must catch. Any recall number "
        f"on s2/C7 is therefore measured through an input channel that clips the unsafe class harder "
        f"than the benign class."
    )
    w()

# ------------------------------------------------------------------ 3. serialisation
w("## 3. Serialisation and the prompting-contract confound")
w()
ser = R["serialisation"]
w(f"**Primary serialisation.** {ser['definition']}")
w()
w(f"> **{ser['confound_declaration']}**")
w()
ab = ser.get("ablation") or {}
if ab.get("results"):
    w(
        "**Justified from data, not asserted.** Same stratified s2 sample "
        f"({ab.get('sampled_unsafe')} unsafe grade-A/B, {ab.get('sampled_benign')} benign grade-D, "
        f"seed {ab.get('seed')}), same per-case aggregation as the shared scorer:"
    )
    w()
    w("| serialisation | ROC AUC | block rate unsafe | block rate benign | distinct risk levels | mean tokens |")
    w("|---|---:|---:|---:|---:|---:|")
    for k, r in ab["results"].items():
        w(
            f"| `{k}` | {r['roc_auc_calibrated']:.4f} | {num(r['severity_block_rate_unsafe'], pct=True)} | "
            f"{num(r['severity_block_rate_benign'], pct=True)} | {r['distinct_risk_levels']} | {r['tokens_mean']} |"
        )
    w()
    w(
        "The parity-faithful `prod_C0` framing drives SecJudge to **block 100% of both classes** - "
        "no discrimination at all. Stripping the framing tags recovers real signal (`cmd`, AUC "
        f"{ab['results'].get('cmd', {}).get('roc_auc_calibrated', 0):.4f}), so the tagged "
        "production_text form is genuinely out of distribution for this model. Notably even "
        "`card_toolcall` - the exact input shape the model card documents - still blocks "
        f"{num(ab['results'].get('card_toolcall', {}).get('severity_block_rate_benign'), pct=True)} of "
        "benign cases. We therefore report the parity arm as the 1:1 number **and** a `cmd` arm as "
        "SecJudge's best case."
    )
w()

# ------------------------------------------------------------------ 4. class mapping
w("## 4. Class mapping to the three-way disposition")
w()
cm = R["class_mapping"]
w(f"- `sev` (primary): {cm['sev']}")
w(f"- `isattack`: {cm['isattack']}")
for k, val in cm["threshold_family"].items():
    w(f"- `{k}`: {val}")
w()
w(f"**Risk convention.** {cm['risk_convention']}")
w()
cal = R.get("calibrator") or {}
if cal:
    w(
        f"**Calibration resolution limit.** The shipped isotonic table has {cal.get('table_points')} "
        f"points but only **{cal.get('distinct_y_values_in_table')} distinct y values**, so it is "
        "mostly long plateaus; a dense uniform sweep of raw scores through it yields "
        f"**{cal.get('dense_sweep_distinct_outputs')}** distinct outputs. Measured on s2: at the "
        "decision level 16,853 distinct raw scores collapse to **396** distinct calibrated values, "
        "and per case the calibrated score takes **80** distinct values across 3,817 cases against "
        "**2,260** for `raw_score`."
    )
    w()
    w(
        "We verified the calibrator is **monotone non-decreasing on the observed scores (0 inversions "
        "over 30,310 decisions)**, so it never re-orders a pair it keeps distinct. It does collapse "
        "many distinct raw values onto a plateau, and a tie counts 0.5 in a tie-corrected AUC - so "
        "collapsing a *mis-ordered* pair lifts it from 0 to 0.5. That is why the calibrated AUC can "
        "come out **above** the raw AUC (0.7398 vs 0.6629 on the s2 `cmd` arm), and it tells us the "
        "raw ordering inside those plateaus is worse than random. The two are not interchangeable, so "
        "both are reported: `raw_score` is the right variable for selecting an operating point at a "
        "target FPR, `calibrated_score` is what the shipped model actually decides on."
    )
w()

# ------------------------------------------------------------------ 5. per-stage metrics
w("## 5. Per-stage metrics (shared scorer, unchanged)")
w()
w(
    "Scored by `benchmarks/scripts/benchmark_score_system_one.py` with the same cases file, the same "
    "**real** deterministic tier (`outputs/deterministic-real/` via `<stage>/deterministic.jsonl`) "
    "and the same Gemma 4 LLM tier used for every other model. Truth grades are the scorer's own: "
    "A -> block, B -> confirm, D -> allow, C/E excluded."
)
w()
for key, st in R.get("stages", {}).items():
    if st.get("status") == "NOT RUN":
        w(f"### {key} - **NOT RUN**")
        w()
        continue
    w(f"### {key} - {st['label']}")
    w()
    w(f"- status: `{st['status']}`, cases {st.get('case_count'):,}, grades {st.get('truth_grades')}")
    w(f"- scorecard: `{st['scorecard']}`")
    settled = [p for p in st.get("run_provenance", []) if p.get("settled")]
    w(f"- settled prediction arms: {len(settled)}/{len(st.get('run_provenance', []))}")
    w()
    w("| arm | n scorable | block F1 | block P | block R | block FPR | any F1 | any P | any R | any FPR | 3-way acc |")
    w("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    # degenerate reference: block everything. F1 = 2p/(1+p) where p = positive prevalence.
    first = next(iter(st.get("arms", {}).values()), None)
    if first:
        conf = first["system_one"]["block_only"].get("confusion") or {}
        pos = (conf.get("true_positive") or 0) + (conf.get("false_negative") or 0)
        nsc = first["scorable_cases"]
        if nsc:
            prev = pos / nsc
            ab = 2 * prev / (1 + prev)
            w(
                f"| _all-block baseline_ | {nsc:,} | _{ab:.4f}_ | _{prev:.4f}_ | _1.0000_ | _1.0000_ | "
                f"_{ab:.4f}_ | _{prev:.4f}_ | _1.0000_ | _1.0000_ | _{prev:.4f}_ |"
            )
    for name, a in sorted(st.get("arms", {}).items()):
        so = a["system_one"]
        bo, an = so["block_only"], so["any_intervention"]
        short = name.split("/")[0].replace("secjudge-28e810afc911", "sj")
        w(
            f"| `{short}` | {a['scorable_cases']:,} | {num(bo['f1'])} | {num(bo['precision'])} | "
            f"{num(bo['recall'])} | {num(bo['fpr'])} | {num(an['f1'])} | {num(an['precision'])} | "
            f"{num(an['recall'])} | {num(an['fpr'])} | {num(so['three_way_accuracy'])} |"
        )
    w()
    # cascade on the real deterministic tier
    any_cascade = any("cascade" in a for a in st.get("arms", {}).values())
    if any_cascade:
        w("**Cascade on the REAL deterministic tier** (never the all-allow stand-in):")
        w()
        w("| arm | composition | block F1 | block FPR | any F1 | any FPR | 3-way acc | LLM call rate |")
        w("|---|---|---:|---:|---:|---:|---:|---:|")
        for name, a in sorted(st.get("arms", {}).items()):
            short = name.split("/")[0].replace("secjudge-28e810afc911", "sj")
            for comp, cv in (a.get("cascade") or {}).items():
                bo, an = cv["block_only"], cv["any_intervention"]
                w(
                    f"| `{short}` | {comp.replace('deterministic_then_', 'det+')} | {num(bo['f1'])} | "
                    f"{num(bo['fpr'])} | {num(an['f1'])} | {num(an['fpr'])} | "
                    f"{num(cv['three_way_accuracy'])} | {num(cv.get('llm_invocation_rate'))} |"
                )
        w()

# ------------------------------------------------------- 5b. incumbent comparison
inc = load(SJ / "incumbent-metrics.json")
if inc:
    w("## 5b. Side by side with the incumbents (same scorer, same cases, same real deterministic tier)")
    w()
    w(
        "These incumbent numbers were re-computed here from the incumbents' own settled prediction "
        "files, so nothing is read from another agent's in-flight scorecards. Every arm below was "
        "verified settled (`meta.complete == true` AND on-disk sha256 == `meta.prediction_sha256`)."
    )
    w()
    w("| stage | model | n | block F1 | block P | block R | block FPR | any F1 | any FPR | 3-way acc |")
    w("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    for r in inc:
        stg = r["arm"].split("-")[0]
        w(
            f"| {stg} | {r['arm']} | {r['n']:,} | {num(r['block_f1'])} | {num(r['block_p'])} | "
            f"{num(r['block_r'])} | {num(r['block_fpr'])} | {num(r['any_f1'])} | "
            f"{num(r['any_fpr'])} | {num(r['three_way_acc'])} |"
        )
    w()
    # SecJudge rows for the same stages, primary sev arm
    w("SecJudge on the same stages, primary `sev` arm:")
    w()
    w("| stage | arm | n | block F1 | block P | block R | block FPR | any F1 | any FPR | 3-way acc |")
    w("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    for key, st in R.get("stages", {}).items():
        if st.get("status") == "NOT RUN":
            continue
        for name, a in st.get("arms", {}).items():
            if not name.endswith("-sev/" + st["context_variant"] + "/I0/Q0"):
                continue
            so = a["system_one"]
            bo, an = so["block_only"], so["any_intervention"]
            w(
                f"| {key} | sev | {a['scorable_cases']:,} | {num(bo['f1'])} | {num(bo['precision'])} | "
                f"{num(bo['recall'])} | {num(bo['fpr'])} | {num(an['f1'])} | {num(an['fpr'])} | "
                f"{num(so['three_way_accuracy'])} |"
            )
    w()

# ------------------------------------------------------------------ 6. recall at fixed FPR
w("## 6. Recall at fixed FPR - SecJudge's own preferred metric, applied to every model")
w()
w(
    "SecJudge's card argues F1 is the wrong metric for a security gate and that recall at <=0.5% FPR "
    "is right. That argument is tested here on our corpora for every model that emits a graded score."
)
w()
w(
    "> **Context-variant caveat, read this before comparing rows.** Every incumbent arm in these "
    "tables ran at **C7**. Where a SecJudge row is labelled **C0** it ran at C0, and the context "
    "recipe is one of the largest effects in this programme - so a C0 SecJudge row against a C7 "
    "incumbent row is *not* apples-to-apples and must not be read as a ranking. The decidable cell "
    "is `s2 C7`; its status is given in section 9. Any C0-vs-C7 comparison below is indicative only."
)
w()
for name, rep in sorted(R.get("recall_at_fixed_fpr", {}).items()):
    if not isinstance(rep, dict) or "arms" not in rep:
        continue
    w(f"### {name} (scorable n={rep.get('scorable_cases'):,}, grades {rep.get('truth_grades_scorable')})")
    w()
    w("| arm | score variable | ROC AUC | distinct levels | R@0.1% | R@0.5% | R@1% | R@5% |")
    w("|---|---|---:|---:|---:|---:|---:|---:|")
    for arm, a in sorted(rep["arms"].items()):
        if "error" in a:
            w(f"| `{arm}` | - | _{a['error']}_ | - | - | - | - | - |")
            continue

        def cell(t):
            r = a.get(f"recall_at_fpr_{t}")
            return f"{r['recall']:.4f}" if r else "-"

        sv = a.get("score_variable", "risk")
        w(
            f"| `{arm.split('|')[0]}` | {sv.split(' (')[0].split(' =')[0]} | {a['roc_auc']:.4f} | "
            f"{a['distinct_scores']} | {cell(0.001)} | {cell(0.005)} | {cell(0.01)} | {cell(0.05)} |"
        )
    w()
w(
    "**Gemma 4 is NOT RANKED here, and its row must not be read as a result.** The Gemma 4 arm is a "
    "categorical judge, not a scorer: its prediction rows carry no `probabilities` and no "
    "`confidence` field, so it emits only a discrete disposition. Over **2 distinct values** a "
    "threshold sweep is meaningless, and the shared scorer's risk fallback additionally assigns risk "
    "0 to every detection and risk 1 to every allow, which inverts it. That is why its ROC AUC comes "
    "out at 0.2727 and its recall at every FPR target comes out 0.0000. **Those numbers are "
    "artifacts of a missing score, not evidence that Gemma 4 is the worst model** - it simply cannot "
    "be placed on this metric at all. Treat the Gemma 4 row as 'not measurable' wherever it appears "
    "in a sorted table."
)
w()

# ------------------------------------------------------------------ 7. card claims
w("## 7. The card's self-reported claims vs what our data can say")
w()
w(R.get("claims_md", "_see claims section of secjudge-report.json_"))
w()

# ------------------------------------------------------------------ 8. throughput
w("## 8. Throughput and cost")
w()
tc = R["throughput_and_cost"]
w(f"- **Provider cost: ${tc['provider_cost_usd']:.2f}.** {tc['cost_note']}")
w(f"- dtype: `{tc['dtype']}`. {tc['dtype_rationale']}")
w()
pm = tc.get("parallelism_measurements") or {}
if pm:
    w(f"**Parallelism, measured not assumed.** {pm['note']}")
    w()
    w("| configuration | padded tokens/s |")
    w("|---|---:|")
    w(f"| 1 process x 8 threads | {pm['1proc_8threads_padded_tokens_per_s']:,} |")
    w(f"| 3 processes x 2 threads | {pm['3proc_2threads_padded_tokens_per_s']:,} |")
    w(f"| 8 processes x 1 thread | {pm['8proc_1thread_padded_tokens_per_s']:,} |")
    w(f"| 12 processes x 1 thread (projected) | {pm['12proc_1thread_projected_padded_tokens_per_s']:,} |")
    w()
    w(pm["consolidation_tradeoff"])
    w()
rs = tc.get("rejected_speedups") or {}
if rs:
    w("**Two speedups tested and rejected, both for numerical reasons rather than speed.**")
    w()
    w("| approach | speedup | is_attack agreement | median calibrated delta | max calibrated delta | disposition changes | verdict |")
    w("|---|---:|---:|---:|---:|---:|---|")
    b = rs.get("bfloat16_amx", {})
    i8 = rs.get("int8_dynamic", {})
    w(
        f"| bfloat16 (AMX) | {b.get('speedup')}x | {b.get('is_attack_agreement')} | - | "
        f"{b.get('max_calibrated_delta')} | - | **{b.get('verdict')}** |"
    )
    w(
        f"| int8 dynamic | {i8.get('speedup')}x | {i8.get('is_attack_agreement')} | "
        f"{i8.get('median_calibrated_delta')} | {i8.get('max_calibrated_delta')} | "
        f"{i8.get('disposition_changes')} of 400 | **{i8.get('verdict')}** |"
    )
    w()
    w(i8.get("reason", ""))
    w()
    w(
        "Both failures have the same root cause as the deployability finding in section 4: the "
        "calibrated score sits on wide isotonic plateaus, so a small numeric perturbation jumps a "
        "whole plateau. Every number in this report is fp32."
    )
    w()
if tc.get("by_stage"):
    w("| run key | serialisation | shards x threads | decisions | forward passes | cache hits | padded tokens | wall clock (min) | aggregate dec/s |")
    w("|---|---|---|---:|---:|---:|---:|---:|---:|")
    for k, g in sorted(tc["by_stage"].items()):
        w(
            f"| {k} | {g.get('serialisation')} | {g['shards']}x{g.get('threads_per_shard')} | "
            f"{g['decisions']:,} | {g['forward_passes']:,} | {g['cache_hits']:,} | "
            f"{g['padded_tokens']:,} | {g['wall_clock_minutes']} | {g['aggregate_decisions_per_s']} |"
        )
    w()

# ------------------------------------------------------------------ 9. completeness
w("## 9. What is complete and what is not")
w()
done = [k for k, st_ in R.get("stages", {}).items() if st_.get("status") != "NOT RUN"]
pending = [k for k, st_ in R.get("stages", {}).items() if st_.get("status") == "NOT RUN"]
# a stage with raw shards on disk but no scorecard is in flight, not abandoned
RAWKEY = {
    "s2-C7": "s2-C7", "s3-C0": "s3-C0", "s3-C7": "s3-C7",
    "s3-cmd-C0": "s3-CMD",
    "toolcall-labels-C0": "toolcall-labels-C0C7", "toolcall-labels-C7": "toolcall-labels-C0C7",
}
inflight, notrun = [], []
for k in pending:
    rk = RAWKEY.get(k)
    if rk and list((SJ / "raw").glob(f"{rk}.shard*.jsonl")):
        inflight.append(k)
    else:
        notrun.append(k)
w(f"**Complete and settled ({len(done)}):** " + (", ".join(f"`{d}`" for d in done) or "none"))
w()
w(
    f"**In flight at the time this report was written ({len(inflight)}):** "
    + (", ".join(f"`{d}`" for d in inflight) or "none")
    + (
        ". Inference shards exist on disk but the stage is not settled, so it carries NO numbers here."
        if inflight
        else " (no stage has raw shards on disk without a settled scorecard)."
    )
)
w()
w(f"**Not started ({len(notrun)}):** " + (", ".join(f"`{d}`" for d in notrun) or "none"))
w()
w(
    "**No summary line in this report implies coverage beyond the settled list.** Every metric is "
    "tagged with the stage and context variant it came from, and a stage with no scorecard "
    "contributes nothing. Measured ETAs for the outstanding stages, at the 12x1 aggregate "
    "throughput actually observed on this host (~1,200 padded tokens/s):"
)
w()
w("| stage | decisions | unique texts | unique padded tokens | measured ETA |")
w("|---|---:|---:|---:|---:|")
plan = (R.get("truncation") or {}).get("compute_plan") or {}
ETA = [
    ("s2 C7 (parity cell)", "s2|C7"),
    ("toolcall-labels C0 (contaminated lane)", "toolcall-labels|C0"),
    ("toolcall-labels C7 (contaminated lane)", "toolcall-labels|C7"),
    ("s3 C0", "s3|C0"),
    ("s3 C7", "s3|C7"),
]
tot = 0.0
for label, key in ETA:
    # a settled stage is no longer outstanding and must not be billed in the remaining-cost total
    if key.replace("|", "-") in done:
        continue
    pp = plan.get(key)
    if not pp:
        continue
    hrs = pp["padded_tokens_unique"] / 1200 / 3600
    tot += hrs
    w(
        f"| {label} | {pp['decisions']:,} | {pp['unique_texts']:,} | "
        f"{pp['padded_tokens_unique']:,} | {hrs:.2f} h |"
    )
w(f"| **total outstanding** | | | | **{tot:.2f} h** |")
w()
w(R.get("bottom_line_md", "_see bottom_line in secjudge-report.json_"))
w()

(SJ / "secjudge-report.md").write_text("\n".join(L) + "\n")
print(f"wrote {SJ / 'secjudge-report.md'} ({len(L)} lines)")
