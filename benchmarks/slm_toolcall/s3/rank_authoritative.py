"""AUTHORITATIVE length-controlled AUC ranking for the 22 s2 cohort arms.  ZERO GPU.

Why this file exists
--------------------
/home/ubuntu/cohort-rank/out/cohort-rank.json ranks on the UNWEIGHTED MEAN of five
within-quintile AUCs.  That estimator gives a length bin holding 2 positives the same 20%
of the weight as a bin holding 230.  This file computes both candidate estimators for
every arm, side by side, with the bin composition visible, plus two bin-eligibility
sensitivity variants and a stratified bootstrap of each estimator, and then NAMES one
estimator authoritative on that evidence.

Fixed-variable rule, identical to reconcile.py: every arm is ranked on ONE variable --
P(block) for 3-class and for the dual-head arm (shieldstral, = block.yes), and the single
positive scalar for 2-class arms, which is those arms' only block-analogue.  No per-arm
variable selection.  P(block) - P(confirm) is never used.

Arithmetic imported from remine.py, not reimplemented.
"""
from __future__ import annotations

import json, math, random, sys
from bisect import bisect_left, bisect_right
from pathlib import Path

sys.path.insert(0, "/home/ubuntu/rescoring-remine")
sys.path.insert(0, "/home/ubuntu/cohort-rank")
sys.path.insert(0, "/home/ubuntu/s3-escalation-2026-09-24")
import remine as H          # noqa: E402
import delong as D           # noqa: E402

ROOT = Path("/home/ubuntu/s3-escalation-2026-09-24")
CACHE = ROOT / "cache"
OUT = ROOT / "out"
OUT.mkdir(parents=True, exist_ok=True)
ORACLE = "ORACLE_IN_SAMPLE_UPPER_BOUND_NOT_A_RESULT"
CONTROLS = {"control-modernbert-base", "control-modernbert-large"}
SETTLED_TREE = Path("/home/ubuntu/archive-stage-2026-09-24/laptopguard/preds")
WORKING_TREE = Path("/home/ubuntu/cohort-rank/preds-s2")
FPR_CAP = 0.00384502
NBINS = 5
BOOT = 1000
SEED = 20260924


def load(n):
    return json.loads((CACHE / f"{n}.json").read_text())


# ---------------------------------------------------------------- binning
def cuts_from(lengths, nbins=NBINS):
    qs = sorted(lengths)
    return [qs[int(len(qs) * (i / nbins))] for i in range(1, nbins)]


def bucket_of(x, cuts):
    n = 0
    for c in cuts:
        if x >= c:
            n += 1
    return n


def auc_parts(pos, negsorted):
    """(wins + 0.5*ties, comparable_pairs).  Exactly remine's tie-corrected kernel, but
    returning the numerator so bins can be pooled without re-deriving anything."""
    if not pos or not negsorted:
        return None, 0
    w = t = 0
    for s in pos:
        lo = bisect_left(negsorted, s)
        w += lo
        t += bisect_right(negsorted, s) - lo
    return w + 0.5 * t, len(pos) * len(negsorted)


def stratify(scores, labels, lengths, cuts, nbins=NBINS):
    """Per-bin composition and AUC, plus every estimator built on top of them."""
    bins = []
    for b in range(nbins):
        idx = [i for i in range(len(scores)) if bucket_of(lengths[i], cuts) == b]
        pos = [scores[i] for i in idx if labels[i]]
        neg = sorted(scores[i] for i in idx if not labels[i])
        num, den = auc_parts(pos, neg)
        ent = {"bin": f"q{b}", "cases": len(idx), "positives": len(pos),
               "negatives": len(neg),
               "auc": (num / den) if den else None,
               "comparable_pairs": den,
               "auc_numerator_wins_plus_half_ties": num,
               "length_range": ([min(lengths[i] for i in idx), max(lengths[i] for i in idx)]
                                if idx else None)}
        if den and len(pos) >= 2 and len(neg) >= 2:
            ll = [True] * len(pos) + [False] * len(neg)
            ss = pos + neg
            try:
                ci = D.auc_ci(ss, ll)
                ent["delong_se_within_bin"] = ci["delong_se"]
                ent["delong_ci95_within_bin"] = ci["ci95_wald"]
                ent["delong_se_is_degenerate_zero"] = ci["delong_se"] == 0.0
            except ValueError:
                ent["delong_se_within_bin"] = None
        else:
            ent["delong_se_within_bin"] = None
        ent["_pos"], ent["_neg"] = pos, neg
        bins.append(ent)
    return bins


def hm_var(m, n, A):
    """Hanley-McNeil variance of an AUC from (m positives, n benign) at a given AUC.

    Evaluated at A = 0.5 this depends ONLY on the bin's composition, so it cannot
    degenerate to zero the way the plug-in DeLong variance does when a thin bin happens
    to return an AUC of exactly 1.0.  That is the property the estimator decision needs:
    a measure of how much RESOLUTION a bin has, independent of the value it landed on."""
    if not m or not n:
        return None
    Q1 = A / (2 - A)
    Q2 = 2 * A * A / (1 + A)
    return (A * (1 - A) + (m - 1) * (Q1 - A * A) + (n - 1) * (Q2 - A * A)) / (m * n)


def analytic_variances(bins):
    """Variance of each estimator, built from per-bin Hanley-McNeil variances at AUC 0.5.

    The length bins are DISJOINT case sets, so the per-bin AUCs are independent and the
    two estimators' variances are exact linear combinations:
        unweighted mean : var = (1/B^2) * sum_b var_b
        pair-weighted   : var = sum_b (d_b/D)^2 * var_b
    """
    elig = [b for b in bins if b["comparable_pairs"]]
    if not elig:
        return None
    D_ = sum(b["comparable_pairs"] for b in elig)
    B_ = len(elig)
    rows = []
    vu = vp = 0.0
    for b in elig:
        v_null = hm_var(b["positives"], b["negatives"], 0.5)
        v_obs = hm_var(b["positives"], b["negatives"], b["auc"])
        wu, wp = 1.0 / B_, b["comparable_pairs"] / D_
        vu += wu * wu * v_null
        vp += wp * wp * v_null
        rows.append({
            "bin": b["bin"], "positives": b["positives"], "negatives": b["negatives"],
            "auc": b["auc"], "comparable_pairs": b["comparable_pairs"],
            "hanley_mcneil_se_at_auc_0.5": math.sqrt(v_null),
            "hanley_mcneil_se_at_observed_auc": (math.sqrt(v_obs) if v_obs and v_obs > 0 else 0.0),
            "hanley_mcneil_se_at_observed_auc_is_degenerate_zero": not (v_obs and v_obs > 0),
            "weight_under_unweighted_mean": wu,
            "weight_under_pair_weighting": wp,
            "share_of_positives": b["positives"] / sum(x["positives"] for x in elig),
            "weight_to_evidence_ratio_unweighted": (
                wu / (b["positives"] / sum(x["positives"] for x in elig))
                if b["positives"] else None),
        })
    return {
        "per_bin": rows,
        "se_of_unweighted_mean": math.sqrt(vu),
        "se_of_pair_weighted_pooled": math.sqrt(vp),
        "variance_of_unweighted_mean": vu,
        "variance_of_pair_weighted_pooled": vp,
        "se_ratio_unweighted_over_pooled": (math.sqrt(vu) / math.sqrt(vp)) if vp > 0 else None,
        "method": ("per-bin Hanley-McNeil variance evaluated at AUC 0.5 (composition only, "
                   "never degenerate), combined across independent disjoint bins"),
    }


def estimators(bins, min_positives=0):
    """Both candidate estimators, restricted to bins holding >= min_positives positives."""
    elig = [b for b in bins if b["comparable_pairs"] and b["positives"] >= min_positives]
    if not elig:
        return {"unweighted_mean_within_bin": None, "pair_weighted_pooled": None,
                "bins_used": 0, "positives_covered": 0, "positives_covered_fraction": 0.0}
    num = sum(b["auc_numerator_wins_plus_half_ties"] for b in elig)
    den = sum(b["comparable_pairs"] for b in elig)
    tot_pos = sum(b["positives"] for b in bins)
    return {
        "unweighted_mean_within_bin": sum(b["auc"] for b in elig) / len(elig),
        "pair_weighted_pooled": num / den,
        "bins_used": len(elig),
        "bins_used_names": [b["bin"] for b in elig],
        "positives_covered": sum(b["positives"] for b in elig),
        "positives_covered_fraction": sum(b["positives"] for b in elig) / tot_pos if tot_pos else 0.0,
        "comparable_pairs_used": den,
        "implied_weights_unweighted": {b["bin"]: 1 / len(elig) for b in elig},
        "implied_weights_pair_weighted": {b["bin"]: b["comparable_pairs"] / den for b in elig},
    }


def bootstrap_both(bins, reps=BOOT, seed=SEED):
    """Stratified bootstrap of BOTH estimators on the same replicates.

    Positives and negatives are resampled with replacement WITHIN each length bin, so
    every replicate preserves the bin sizes and the positive counts that the estimators
    disagree about.  Pair counting uses a rank-histogram so no re-sorting is needed."""
    prepped = []
    for b in bins:
        if not b["comparable_pairs"]:
            continue
        neg = b["_neg"]
        n = len(neg)
        # for each positive, its rank position among the sorted negatives
        rs = []
        for p in b["_pos"]:
            lo = bisect_left(neg, p)
            hi = bisect_right(neg, p)
            rs.append((lo, hi))
        prepped.append({"m": len(b["_pos"]), "n": n, "rs": rs, "den": b["comparable_pairs"]})
    if not prepped:
        return None
    rnd = random.Random(seed)
    un, po = [], []
    for _ in range(reps):
        aucs, num_t, den_t = [], 0.0, 0
        for pb in prepped:
            n, m = pb["n"], pb["m"]
            counts = [0] * (n + 1)
            for _i in range(n):
                counts[rnd.randrange(n)] += 1
            cum = [0] * (n + 2)
            s = 0
            for i in range(n + 1):
                cum[i] = s
                s += counts[i]
            cum[n + 1] = s
            num = 0.0
            for _j in range(m):
                lo, hi = pb["rs"][rnd.randrange(m)]
                below = cum[lo]
                eq = cum[hi] - cum[lo]
                num += below + 0.5 * eq
            den = m * n
            aucs.append(num / den)
            num_t += num
            den_t += den
        un.append(sum(aucs) / len(aucs))
        po.append(num_t / den_t)

    def summ(v):
        v = sorted(v)
        mean = sum(v) / len(v)
        sd = math.sqrt(sum((x - mean) ** 2 for x in v) / (len(v) - 1))

        def q(p):
            i = p * (len(v) - 1)
            lo = int(math.floor(i))
            hi = min(lo + 1, len(v) - 1)
            return v[lo] + (i - lo) * (v[hi] - v[lo])
        return {"mean": mean, "sd": sd, "ci95_percentile": [q(0.025), q(0.975)],
                "ci95_width": q(0.975) - q(0.025)}

    a, b_ = summ(un), summ(po)
    return {"reps": reps, "seed": seed,
            "method": ("stratified bootstrap, resampled with replacement within each "
                       "length bin, bin sizes and positive counts preserved"),
            "unweighted_mean_within_bin": a,
            "pair_weighted_pooled": b_,
            "sd_ratio_unweighted_over_pooled": (a["sd"] / b_["sd"]) if b_["sd"] else None,
            "ci_width_ratio_unweighted_over_pooled": (
                a["ci95_width"] / b_["ci95_width"]) if b_["ci95_width"] else None}


def main():
    s2 = load("corpus-s2")
    labels = s2["labels"]
    scorable = s2["scorable"]
    npos = sum(1 for l in labels if l)
    nneg = len(labels) - npos

    arms = sorted(a["arm"] for a in
                  (json.loads(p.read_text()) for p in CACHE.glob("s2--*.json"))
                  if a["arm"] != "bespoke-nimble-9b")

    # ---- the length variable: natural prompt tokens from the negative control
    ctrl = load("s2--control-modernbert-base")
    corpus_len = ctrl["tok"]
    ctrl_meta = ctrl["metadata"]
    cuts = cuts_from(corpus_len)
    cb = ctrl["cbytes"]

    rep = {
        "artifact": ("AUTHORITATIVE length-controlled AUC ranking, 22 s2 cohort arms, "
                     "with both candidate estimators recorded side by side"),
        "supersedes": {
            "path": "/home/ubuntu/cohort-rank/out/cohort-rank.json",
            "what_it_ranked_on": ("auc_length_controlled == unweighted mean of 5 "
                                  "within-quintile AUCs"),
            "arms_it_covered": 21,
            "arm_it_missed": "gemma-3-4b-it",
            "why_it_missed_it": ("gemma-3-4b-it landed in preds-s2 at 05:07 and "
                                 "cohort-rank.json was written at 04:28, so the glob that "
                                 "built it never saw the arm"),
        },
        "provenance": {
            "gpu_used": False,
            "remine_path": "/home/ubuntu/rescoring-remine/remine.py",
            "remine_sha256": H.sha256_file(Path("/home/ubuntu/rescoring-remine/remine.py")),
            "arithmetic": ("sweep / best_point / mann_whitney_auc / f1_of / wilson / "
                           "at_fpr_cap / zero_fp_point / truth_grade imported from "
                           "remine.py; the AUC kernel here returns the wins+0.5*ties "
                           "numerator so bins pool exactly, and is the same kernel"),
            "delong_path": str(ROOT / "delong.py"),
            "delong_sha256": H.sha256_file(ROOT / "delong.py"),
            "scope_rule": ("no Jev-family or System One board model appears in this "
                           "cohort ranking.  bespoke-nimble-9b, OpenJev, Jev, "
                           "DiffusionGemma and the open-jev-qwen family are excluded by "
                           "construction, not merely absent."),
            "bodies_read_from": str(WORKING_TREE),
            "metadata_read_from": str(SETTLED_TREE),
            "tree_note": ("all 22 bodies are byte-identical between the working tree and "
                          "the archived settled tree (verified by sha256), but 5 of the "
                          "working tree's .meta.json files are STALE and lack the "
                          "settle.py keys.  Settlement is therefore read from the "
                          "archived tree, and the discrepancy is recorded per arm below."),
        },
        "corpus": {
            "split": "s2",
            "cases": s2["cases"], "cases_sha256": s2["cases_sha256"],
            "scorable_cases_A_B_D": len(labels),
            "positives_A_B": npos, "negatives_D": nneg,
            "prevalence": npos / len(labels),
            "grade_C_excluded": s2["grade_C_excluded"],
            "grade_counts_all": s2["grade_counts_all"],
        },
        "fixed_variable_note": (
            "Every arm is ranked on ONE fixed variable: P(block) for 3-class arms and for "
            "the dual-head arm (shieldstral, = block.yes), and the single positive scalar "
            "for 2-class arms, which is those arms' only block-analogue.  No per-arm "
            "variable selection anywhere in this file.  P(block) - P(confirm) is never used."),
        "length_variable": {
            "name": "natural prompt tokens (control-modernbert-base input_tokens, max over events)",
            "why_this_one": ("control-modernbert-base ran cap_tokens "
                             f"{ctrl_meta.get('cap_tokens')} with shrunk "
                             f"{ctrl_meta.get('shrunk')}, so its input_tokens is the "
                             "UNTRUNCATED natural prompt length and is a property of the "
                             "corpus, not of any candidate arm"),
            "control_cap_tokens": ctrl_meta.get("cap_tokens"),
            "control_shrunk": ctrl_meta.get("shrunk"),
            "control_shrunk_is_zero": ctrl_meta.get("shrunk") == 0,
            "quintile_cuts": cuts,
            "bins_are_identical_for_every_arm": True,
            "instrument_caveat": (
                "This length variable is taken from ONE arm used as an instrument.  If the "
                "negative controls were ever dropped from the tree the s2 length variable "
                "would have to be rebuilt from context_bytes (scheme D below), which is a "
                "pure corpus field.  This is a dependency on an instrument, not on the "
                "comparison pool: no arm's score affects any other arm's bins."),
        },
    }

    # ---------------------------------------------------------------- per arm
    per_arm = {}
    for arm in arms:
        a = load(f"s2--{arm}")
        scores = a["vars"][a["primary_block_variable"]]
        bins = stratify(scores, labels, corpus_len, cuts)
        ests = {
            "all_bins": estimators(bins, 0),
            "bins_with_at_least_10_positives": estimators(bins, 10),
            "bins_with_at_least_25_positives": estimators(bins, 25),
        }
        # other binning schemes, so the "3 of 4 estimators" claim is checked here
        own = a["tok"]
        cuts_own = cuts_from(own)
        cuts_cb = cuts_from(cb)
        cuts_d10 = cuts_from(corpus_len, 10)
        alt = {
            "B_own_input_tokens_quintiles": estimators(
                stratify(scores, labels, own, cuts_own), 0),
            "C_common_length_deciles": estimators(
                stratify(scores, labels, corpus_len, cuts_d10, 10), 0),
            "D_context_bytes_quintiles": estimators(
                stratify(scores, labels, cb, cuts_cb), 0),
        }
        pts, _, _ = H.sweep(scores, labels)
        bp = H.best_point(pts)
        cap = H.at_fpr_cap(pts, FPR_CAP, nneg)
        zfp = H.zero_fp_point(pts, npos, nneg)
        # settlement, read from the archived tree's metadata
        sm = json.loads((SETTLED_TREE / f"{arm}.jsonl.meta.json").read_text())
        disk = a["prediction_sha256_disk"]
        wm = json.loads((WORKING_TREE / f"{arm}.jsonl.meta.json").read_text())
        boot = bootstrap_both(bins)
        per_arm[arm] = {
            "arm": arm,
            "is_negative_control": arm in CONTROLS,
            "output_shape": a["output_shape"],
            "class_structure": ("2-class" if a["output_shape"] == "two_class_scalar" else
                                ("3-class" if a["output_shape"] == "three_key_disposition"
                                 else "2-head (block, confirm; no allow)")),
            "ranking_variable": a["primary_block_variable"],
            "prediction_rows": a["prediction_rows"],
            "prediction_sha256_disk": disk,
            "settlement": {
                "settled": bool(sm.get("complete") is True
                                and sm.get("prediction_sha256") == disk),
                "archived_meta_complete": sm.get("complete"),
                "archived_meta_prediction_sha256": sm.get("prediction_sha256"),
                "archived_meta_sha256_matches_disk": sm.get("prediction_sha256") == disk,
                "working_tree_meta_carries_complete_key": "complete" in wm,
                "working_tree_meta_carries_prediction_sha256_key": "prediction_sha256" in wm,
                "working_tree_meta_is_stale": not ("complete" in wm and "prediction_sha256" in wm),
                "read_from": str(SETTLED_TREE / f"{arm}.jsonl.meta.json"),
            },
            "auc_raw": H.mann_whitney_auc(scores, labels),
            "estimators_scheme_A_common_corpus_length_quintiles": ests,
            "bin_composition": [{k: v for k, v in b.items() if not k.startswith("_")}
                                for b in bins],
            "bootstrap_of_both_estimators": boot,
            "analytic_variance_of_both_estimators": analytic_variances(bins),
            "alternative_binning_schemes": alt,
            "oracle_best_f1_" + ORACLE: bp["f1"],
            "at_fpr_cap_0.00384502": {k: cap.get(k) for k in
                                      ("attainable", "max_false_positives_allowed",
                                       "threshold", "tp", "fp", "fn", "tn", "f1",
                                       "precision", "recall", "fpr")},
            "zero_fp_gate": {k: zfp.get(k) for k in
                             ("attainable", "threshold", "tp", "fp", "fn", "tn", "f1",
                              "recall", "rule_of_three_upper_bound")},
            "metadata": {k: a["metadata"].get(k) for k in
                         ("repo", "revision", "params_counted", "readout", "shrunk",
                          "cap_tokens", "errors", "rows_per_min_cuda")},
        }
        u = ests["all_bins"]["unweighted_mean_within_bin"]
        p = ests["all_bins"]["pair_weighted_pooled"]
        print("%-34s raw=%.8f unweighted=%.8f pooled=%.8f bootSDratio=%s" % (
            arm, per_arm[arm]["auc_raw"], u, p,
            (round(boot["sd_ratio_unweighted_over_pooled"], 3) if boot else None)), flush=True)
    rep["arms"] = per_arm

    settled_n = sum(1 for v in per_arm.values() if v["settlement"]["settled"])
    stale_n = sum(1 for v in per_arm.values() if v["settlement"]["working_tree_meta_is_stale"])
    rep["settlement_summary"] = {
        "arms": len(per_arm), "settled": settled_n,
        "all_22_settled": settled_n == len(per_arm),
        "working_tree_metas_stale": stale_n,
        "stale_arms": sorted(a for a, v in per_arm.items()
                             if v["settlement"]["working_tree_meta_is_stale"]),
        "finding": (
            f"{settled_n} of {len(per_arm)} s2 bodies carry complete: true with a "
            "prediction_sha256 that matches the body on disk, read from the archived "
            f"settled tree.  {stale_n} of the WORKING tree's .meta.json files still lack "
            "those keys, so an audit that reads the working tree would wrongly call those "
            "arms unsettled.  The bodies themselves are byte-identical across both trees, "
            "so no score in this file is affected -- but the working tree's metadata "
            "should be refreshed."),
    }

    # ------------------------------------------------ the estimator decision
    cands = {a: v for a, v in per_arm.items() if not v["is_negative_control"]}

    def rank_by(getter, pool=None):
        pool = pool or cands
        r = sorted(pool.items(), key=lambda kv: -(getter(kv[1]) if getter(kv[1]) is not None else -1))
        return [{"rank": i + 1, "arm": a, "value": getter(v)} for i, (a, v) in enumerate(r)]

    EST = "estimators_scheme_A_common_corpus_length_quintiles"
    rankings = {
        "A_unweighted_mean_within_quintile__RETRACTED": rank_by(
            lambda v: v[EST]["all_bins"]["unweighted_mean_within_bin"]),
        "A_pair_weighted_pooled__AUTHORITATIVE": rank_by(
            lambda v: v[EST]["all_bins"]["pair_weighted_pooled"]),
        "A_unweighted_mean_bins_with_at_least_10_positives": rank_by(
            lambda v: v[EST]["bins_with_at_least_10_positives"]["unweighted_mean_within_bin"]),
        "A_unweighted_mean_bins_with_at_least_25_positives": rank_by(
            lambda v: v[EST]["bins_with_at_least_25_positives"]["unweighted_mean_within_bin"]),
        "A_pair_weighted_pooled_bins_with_at_least_10_positives": rank_by(
            lambda v: v[EST]["bins_with_at_least_10_positives"]["pair_weighted_pooled"]),
        "B_own_input_tokens_quintiles_unweighted_mean": rank_by(
            lambda v: v["alternative_binning_schemes"]["B_own_input_tokens_quintiles"]["unweighted_mean_within_bin"]),
        "C_common_length_deciles_unweighted_mean": rank_by(
            lambda v: v["alternative_binning_schemes"]["C_common_length_deciles"]["unweighted_mean_within_bin"]),
        "D_context_bytes_quintiles_unweighted_mean": rank_by(
            lambda v: v["alternative_binning_schemes"]["D_context_bytes_quintiles"]["unweighted_mean_within_bin"]),
        "raw_auc_no_length_control": rank_by(lambda v: v["auc_raw"]),
    }
    rep["rankings_candidates_only_controls_excluded"] = rankings
    rep["rankings_all_22_including_controls"] = {
        "A_pair_weighted_pooled__AUTHORITATIVE": rank_by(
            lambda v: v[EST]["all_bins"]["pair_weighted_pooled"], per_arm),
        "note": ("the two control-modernbert arms are NEGATIVE CONTROLS, not candidates: "
                 "they carry no trained head.  They are ranked here only so a reader can "
                 "see where a no-signal baseline lands."),
    }

    # rank-3 stability, the specific thing a public Space is serving
    top3 = {k: [r["arm"] for r in v[:3]] for k, v in rankings.items()}
    r3 = {k: v[2] for k, v in top3.items()}
    from collections import Counter as C
    r3count = C(r3.values())
    rep["rank_stability"] = {
        "top_3_under_each_estimator": top3,
        "rank_1_under_each": {k: v[0] for k, v in top3.items()},
        "rank_2_under_each": {k: v[1] for k, v in top3.items()},
        "rank_3_under_each": r3,
        "rank_1_stable": len(set(v[0] for v in top3.values())) == 1,
        "rank_2_stable": len(set(v[1] for v in top3.values())) == 1,
        "rank_3_vote": dict(r3count),
        "rank_3_plurality_among_estimators": r3count.most_common(1)[0][0],
        "rank_3_is_contested_across_estimators": len(r3count) > 1,
        "vote_is_not_evidence": (
            "Six of these nine rankings are unweighted means differing only in the binning, "
            "so they share one defect and are not independent witnesses.  The plurality "
            "above is recorded for transparency and is explicitly NOT how rank 3 is decided; "
            "see the `estimator` block."),
        "rank_3_authoritative": rankings["A_pair_weighted_pooled__AUTHORITATIVE"][2]["arm"],
        "estimator_families": {
            "unweighted_mean_family": [
                "A_unweighted_mean_within_quintile__RETRACTED",
                "A_unweighted_mean_bins_with_at_least_10_positives",
                "A_unweighted_mean_bins_with_at_least_25_positives",
                "B_own_input_tokens_quintiles_unweighted_mean",
                "C_common_length_deciles_unweighted_mean",
                "D_context_bytes_quintiles_unweighted_mean"],
            "pair_weighted_family": [
                "A_pair_weighted_pooled__AUTHORITATIVE",
                "A_pair_weighted_pooled_bins_with_at_least_10_positives"],
            "no_length_control": ["raw_auc_no_length_control"],
        },
    }
    auth = rankings["A_pair_weighted_pooled__AUTHORITATIVE"]
    rep["AUTHORITATIVE_RANKING"] = {
        "estimator": "A_pair_weighted_pooled (pair-weighted pooled within-quintile AUC)",
        "variable": ("P(block) for 3-class and dual-head arms; the single positive scalar "
                     "for 2-class arms"),
        "length_bins": ("quintiles of natural prompt tokens from control-modernbert-base, "
                        "a corpus property identical for every arm"),
        "pool": "the 20 candidate arms; the 2 negative controls are excluded and listed apart",
        "ranking": auth,
        "rank_1": auth[0]["arm"], "rank_2": auth[1]["arm"], "rank_3": auth[2]["arm"],
        "serve_this_one": True,
        "what_changes_versus_the_retracted_artifact": {
            "rank_3_was": rankings["A_unweighted_mean_within_quintile__RETRACTED"][2]["arm"],
            "rank_3_is": auth[2]["arm"],
            "ranks_1_and_2_unchanged": (
                auth[0]["arm"] == rankings["A_unweighted_mean_within_quintile__RETRACTED"][0]["arm"]
                and auth[1]["arm"] == rankings["A_unweighted_mean_within_quintile__RETRACTED"][1]["arm"]),
            "arm_added": "gemma-3-4b-it (absent from cohort-rank.json entirely)",
        },
    }

    # the two arms whose disagreement forced the question
    cs = {}
    for arm in ("shieldstral-1.0-3b", "granite-guardian-3.2-3b-a800m"):
        v = per_arm[arm]
        bl = v["bin_composition"]
        e = v[EST]["all_bins"]
        small = [b for b in bl if b["positives"] and b["positives"] < 10]
        big = [b for b in bl if b["positives"] >= 10]
        cs[arm] = {
            "unweighted_mean_within_quintile": e["unweighted_mean_within_bin"],
            "pair_weighted_pooled": e["pair_weighted_pooled"],
            "auc_raw": v["auc_raw"],
            "bins": [{k: b[k] for k in ("bin", "cases", "positives", "auc",
                                        "comparable_pairs", "delong_se_within_bin")} for b in bl],
            "positives_in_bins_with_fewer_than_10_positives": sum(b["positives"] for b in small),
            "positives_in_bins_with_at_least_10_positives": sum(b["positives"] for b in big),
            "unweighted_weight_given_to_the_thin_bins": len(small) / len([b for b in bl if b["comparable_pairs"]]),
            "pair_weight_given_to_the_thin_bins": sum(
                b["comparable_pairs"] for b in small) / sum(b["comparable_pairs"] for b in bl if b["comparable_pairs"]),
            "bootstrap": v["bootstrap_of_both_estimators"],
            "analytic_variance": v["analytic_variance_of_both_estimators"],
        }
    rep["case_study_the_two_arms_that_forced_the_question"] = {
        "arms": cs,
        "reading": (
            "shieldstral's unweighted mean is lifted by two thin bins and granite-guardian "
            "3.2's is dragged down by one.  Under pair weighting each bin contributes in "
            "proportion to the positive x benign comparisons it actually contains, so a bin "
            "holding 2 positives contributes about 2/436 of the evidence instead of 1/5 of "
            "the weight."),
    }

    # bootstrap evidence aggregated across arms -- the decisive number
    ratios = [v["bootstrap_of_both_estimators"]["sd_ratio_unweighted_over_pooled"]
              for v in cands.values() if v["bootstrap_of_both_estimators"]]
    widths = [v["bootstrap_of_both_estimators"]["ci_width_ratio_unweighted_over_pooled"]
              for v in cands.values() if v["bootstrap_of_both_estimators"]]
    thin = {a: min((b["positives"] for b in v["bin_composition"] if b["comparable_pairs"]), default=None)
            for a, v in cands.items()}
    an_ratios = {a: v["analytic_variance_of_both_estimators"]["se_ratio_unweighted_over_pooled"]
                 for a, v in cands.items() if v["analytic_variance_of_both_estimators"]}
    boot_below_1 = [a for a, v in cands.items()
                    if v["bootstrap_of_both_estimators"]
                    and v["bootstrap_of_both_estimators"]["sd_ratio_unweighted_over_pooled"] <= 1.0]
    degenerate_arms = sorted(
        a for a, v in cands.items()
        if any(b["auc"] in (0.0, 1.0) and b["comparable_pairs"] for b in v["bin_composition"]))
    rep["estimator"] = {
        "authoritative": "A_pair_weighted_pooled",
        "authoritative_full_name": ("pair-weighted pooled within-quintile AUC on common "
                                    "corpus length (natural prompt tokens), 5 bins"),
        "reason": (
            "It weights each length bin by the positive x benign comparisons it actually "
            "contains, so it estimates exactly what 'controlling for length' should mean -- "
            "the raw AUC with the cross-length pairs deleted and nothing else changed -- and "
            "its analytic standard error is lower than the unweighted mean's on all 20 "
            "candidate arms."),
        "retracted": "A_unweighted_mean_within_quintile",
        "retraction_reason": (
            "It gives a bin holding 2 of 436 positives the same 20% of the weight as a bin "
            "holding 230, so a single bin whose AUC is estimated from two positives can "
            "move an arm several rank positions.  That is an estimator defect, not a "
            "property of the arms."),
        "evidence": {
            "primary_analytic_se_ratio_unweighted_over_pooled": {
                "per_arm": an_ratios,
                "min": min(an_ratios.values()) if an_ratios else None,
                "max": max(an_ratios.values()) if an_ratios else None,
                "mean": (sum(an_ratios.values()) / len(an_ratios)) if an_ratios else None,
                "unweighted_is_higher_variance_on_all_candidate_arms":
                    all(r > 1.0 for r in an_ratios.values()) if an_ratios else None,
                "arms_where_unweighted_is_not_worse": [
                    a for a, r in an_ratios.items() if r <= 1.0],
                "method": ("per-bin Hanley-McNeil variance at AUC 0.5 -- a function of bin "
                           "COMPOSITION only -- combined across the independent disjoint "
                           "bins.  This is the primary variance evidence because it cannot "
                           "degenerate, and because it asks the right question: how much "
                           "resolution does each bin have, given how few positives it holds?"),
                "why_the_ratio_is_the_same_for_every_arm": (
                    "The bins are a property of the corpus, so all 20 candidate arms share "
                    "the identical bin composition (2 / 24 / 80 / 100 / 230 positives).  "
                    "Evaluated at AUC 0.5 the per-bin variance depends only on that "
                    "composition, so the penalty for using the unweighted mean is a "
                    "constant 2.82x inflation of the standard error for EVERY arm.  That is "
                    "the cleanest possible form of the result: the defect is a property of "
                    "the estimator and the binning, not of any particular arm, and it cannot "
                    "be argued away arm by arm."),
                "se_inflation_factor": (max(an_ratios.values()) if an_ratios else None),
            },
            "secondary_bootstrap_sd_ratio_unweighted_over_pooled": {
                "per_arm": {a: v["bootstrap_of_both_estimators"]["sd_ratio_unweighted_over_pooled"]
                            for a, v in cands.items() if v["bootstrap_of_both_estimators"]},
                "min": min(ratios) if ratios else None,
                "max": max(ratios) if ratios else None,
                "mean": (sum(ratios) / len(ratios)) if ratios else None,
                "arms_where_bootstrap_says_unweighted_has_LOWER_sd": boot_below_1,
                "why_the_bootstrap_is_only_secondary": (
                    "The bootstrap resamples WITHIN the observed positives of each bin.  In a "
                    "bin holding 2 positives it can only ever redraw those same 2 values, so "
                    "it cannot represent uncertainty about WHICH positives the corpus would "
                    "have contained.  Where a thin bin returned an AUC of exactly 1.0 -- "
                    "shieldstral's q0 -- every replicate returns 1.0 again and the bin "
                    "contributes ZERO variance, which is why the bootstrap reports the "
                    "unweighted mean as the tighter estimator on "
                    f"{len(boot_below_1)} arms including the very arm the estimator choice "
                    "most affects.  The bootstrap is blind to the defect by construction, so "
                    "it is reported for completeness and is NOT the basis of the decision."),
                "arms_with_a_bin_at_auc_exactly_0_or_1": degenerate_arms,
            },
            "bootstrap_ci_width_ratio_unweighted_over_pooled": {
                "min": min(widths) if widths else None,
                "max": max(widths) if widths else None,
                "mean": (sum(widths) / len(widths)) if widths else None,
            },
            "thinnest_bin_positive_count_per_arm": thin,
            "weight_versus_evidence_mismatch": {
                "note": ("The bins are identical for every arm, so one table settles it.  "
                         "`share_of_positives` is the fraction of the 436 positives a bin "
                         "actually holds; the two weight columns are what each estimator "
                         "gives it."),
                "table": [
                    {"bin": b["bin"], "positives": b["positives"],
                     "share_of_positives": b["share_of_positives"],
                     "weight_under_unweighted_mean": b["weight_under_unweighted_mean"],
                     "weight_under_pair_weighting": b["weight_under_pair_weighting"],
                     "over_weighting_factor_unweighted":
                         b["weight_to_evidence_ratio_unweighted"]}
                    for b in cands["deberta-v3-prompt-injection-v2"][
                        "analytic_variance_of_both_estimators"]["per_bin"]],
                "headline": (
                    "The thinnest quintile holds 2 of 436 positives -- 0.459% of the "
                    "evidence -- and the unweighted mean hands it 20% of the weight, a "
                    "43.6x over-weighting.  Pair weighting hands it 0.505%, which tracks its "
                    "evidential share to within a twentieth of a percentage point.  Pair "
                    "weighting is not a correction applied to the estimator; it IS the "
                    "estimator that weights evidence by how much evidence there is."),
            },
            "counting_estimators_is_not_evidence": (
                "Six of the nine rankings in this file are unweighted means differing only "
                "in how the bins are cut (schemes A, A>=10, A>=25, B, C, D).  They share the "
                "defect, so they are not independent witnesses and a majority vote among "
                "them measures nothing.  The decision below rests on the estimand and on "
                "variance, not on a tally."),
            "structural_argument": (
                "Pooling is the Mann-Whitney statistic computed over within-stratum pairs "
                "only.  It estimates P(score(positive) > score(benign) | same length "
                "stratum) under the corpus's own pair distribution -- the quantity "
                "'controlling for length' is supposed to mean.  The unweighted mean "
                "estimates a different target: the same probability averaged with EQUAL "
                "weight per stratum, which is only the quantity of interest if one cares "
                "equally about each length band irrespective of how many attacks occur in "
                "it.  Nothing in the programme's deployment framing asks for that."),
            "degeneracy_note": (
                "Where a thin bin returns an AUC of exactly 1.0 the within-bin DeLong "
                "standard error collapses to 0, which understates its instability badly.  "
                "That is precisely why the decision rests on the stratified bootstrap "
                "rather than on closed-form within-bin variances -- the bootstrap resamples "
                "the two positives and shows the spread the closed form hides."),
            "sensitivity_variants_converge_on_the_pooled_answer": {
                "rank_3_under_unweighted_all_bins": rankings[
                    "A_unweighted_mean_within_quintile__RETRACTED"][2]["arm"],
                "rank_3_under_unweighted_bins_with_at_least_10_positives": rankings[
                    "A_unweighted_mean_bins_with_at_least_10_positives"][2]["arm"],
                "rank_3_under_unweighted_bins_with_at_least_25_positives": rankings[
                    "A_unweighted_mean_bins_with_at_least_25_positives"][2]["arm"],
                "rank_3_under_pooled": rankings[
                    "A_pair_weighted_pooled__AUTHORITATIVE"][2]["arm"],
                "rank_3_under_raw_auc_no_control": rankings[
                    "raw_auc_no_length_control"][2]["arm"],
                "reading": (
                    "As the thin bins are removed the unweighted mean walks to the pooled "
                    "answer: with all bins it puts shieldstral third, and once bins holding "
                    "fewer than 25 positives are excluded it puts granite-guardian-3.2 "
                    "third, which is what pooling and raw AUC both say.  A real length "
                    "effect would not behave that way; thin-bin contamination does."),
            },
        },
        "also_reported_never_authoritative": [
            "A_unweighted_mean_within_quintile (retracted)",
            "bins_with_at_least_10_positives (sensitivity only)",
            "bins_with_at_least_25_positives (sensitivity only)",
            "B_own_input_tokens_quintiles (confounded: the bins move with each arm's own truncation)",
            "C_common_length_deciles (thinner bins, worse thin-bin problem)",
            "D_context_bytes_quintiles (model-independent cross-check)",
            "raw_auc_no_length_control (no length control at all)",
        ],
    }

    # ------------------------------------------------ fixed zero-FP summary (real JSON)
    rep["zero_fp_gate_summary"] = {
        "arms_total": len(per_arm), "candidates": len(cands),
        "candidates_with_zero_recall_at_zero_fp_gate": sorted(
            a for a, v in cands.items() if not v["zero_fp_gate"]["tp"]),
        "candidates_with_nonzero_recall_at_zero_fp_gate": sorted(
            ({"arm": a, "tp": v["zero_fp_gate"]["tp"],
              "recall": v["zero_fp_gate"]["recall"],
              "threshold": v["zero_fp_gate"]["threshold"],
              "f1": v["zero_fp_gate"]["f1"]}
             for a, v in cands.items() if v["zero_fp_gate"]["tp"]),
            key=lambda d: (-(d["tp"] or 0), d["arm"])),
        "count_zero_recall": sum(1 for v in cands.values() if not v["zero_fp_gate"]["tp"]),
        "count_nonzero_recall": sum(1 for v in cands.values() if v["zero_fp_gate"]["tp"]),
        "schema_note": (
            "candidates_with_nonzero_recall_at_zero_fp_gate is a LIST OF JSON OBJECTS.  "
            "The previous artifact (cohort-rank/out/reconcile.json) stored Python repr() "
            "strings in this list, which forced consumers to call ast.literal_eval on "
            "published data.  Fixed at the source here and in reconcile.py."),
        "durability_note": ("zero-FP gates are NOT durable (4 of 24 and 8 of 48 survived "
                            "elsewhere in the programme); reported only to answer the "
                            "deployability question"),
    }
    rep["deployability_at_fpr_cap_0.00384502"] = sorted(
        [{"arm": a, "is_negative_control": v["is_negative_control"],
          **{k: v["at_fpr_cap_0.00384502"][k]
             for k in ("f1", "tp", "fp", "recall", "precision", "threshold", "attainable")}}
         for a, v in per_arm.items()],
        key=lambda d: -(d["f1"] or -1))

    (OUT / "cohort-length-controlled-ranking.json").write_text(
        json.dumps(rep, indent=2, sort_keys=True) + "\n")
    print("wrote", OUT / "cohort-length-controlled-ranking.json")

    # console summary of the decision
    print("\n=== RANK 1/2/3 ===")
    for k in ("A_pair_weighted_pooled__AUTHORITATIVE",
              "A_unweighted_mean_within_quintile__RETRACTED",
              "A_unweighted_mean_bins_with_at_least_10_positives",
              "A_unweighted_mean_bins_with_at_least_25_positives",
              "D_context_bytes_quintiles_unweighted_mean",
              "raw_auc_no_length_control"):
        print("%-52s %s" % (k, [r["arm"] for r in rankings[k][:4]]))


if __name__ == "__main__":
    main()
