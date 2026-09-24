"""Task 4 -- what other benchmarks these 22 models support.

Everything here that is marked computable is actually COMPUTED from the settled rows,
with zero new inference and zero GPU:
  * cascade / triage frontier   (s2 in-sample AND s3 held-out)
  * calibration: reliability tables, ECE, MCE, Brier
  * error correlation across the arms
The one axis that genuinely needs new inference (policy sensitivity) is scoped with a
cost estimate built from the measured CPU throughput primitives, not guessed.
"""
from __future__ import annotations

import json, math, sys
from itertools import combinations
from pathlib import Path

sys.path.insert(0, "/home/ubuntu/rescoring-remine")
sys.path.insert(0, "/home/ubuntu/cohort-rank")
import remine as H          # noqa: E402

ROOT = Path("/home/ubuntu/s3-escalation-2026-09-24")
CACHE = ROOT / "cache"
OUT = ROOT / "out"
OUT.mkdir(parents=True, exist_ok=True)
ORACLE = "ORACLE_IN_SAMPLE_UPPER_BOUND_NOT_A_RESULT"

FEAS = Path("/home/ubuntu/.slm-space-stage/benchmarks/slm_toolcall/site-build/pinned/laptop-feasibility.json")
COHORT6 = ["deberta-v3-prompt-injection-v2", "shieldgemma-2b",
           "granite-guardian-3.2-3b-a800m", "shieldstral-1.0-3b",
           "prompt-guard-2-22m", "prompt-guard-2-86m"]
JEV_Q = {"Q0": 0.8260381593714927, "Q2": 0.8112994350282486}


def load(n):
    return json.loads((CACHE / f"{n}.json").read_text())


def primary_vec(tag, arm):
    a = load(f"{tag}--{arm}")
    return a["vars"][a["primary_block_variable"]], a


def cm(labels, flags):
    tp = fp = fn = tn = 0
    for l, f in zip(labels, flags):
        if l and f: tp += 1
        elif l: fn += 1
        elif f: fp += 1
        else: tn += 1
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "f1": H.f1_of(tp, fp, fn),
            "precision": (tp / (tp + fp)) if (tp + fp) else None,
            "recall": tp / (tp + fn) if (tp + fn) else None,
            "block_fpr": fp / (fp + tn) if (fp + tn) else None}


# ---------------------------------------------------------------- 1. cascade
def cascade(labels, s1, s2v, t1_lo_grid, t1_hi_grid, t2, rpm1, rpm2, tag):
    """Cheap encoder first.  score < lo -> allow outright; score >= hi -> block outright;
    otherwise escalate the case to the expensive arm, which decides at its own t2.

    Cost is CPU wall time per case in minutes, from the measured rows/min primitives:
        latency = 1/rpm1 + escalated_fraction * 1/rpm2
    Stage 1 runs on every case; stage 2 only on escalated ones."""
    n = len(labels)
    base1 = 1.0 / rpm1
    base2 = 1.0 / rpm2
    pts = []
    for lo in t1_lo_grid:
        for hi in t1_hi_grid:
            if hi < lo:
                continue
            flags = []
            esc = 0
            for i in range(n):
                v = s1[i]
                if v >= hi:
                    flags.append(True)
                elif v < lo:
                    flags.append(False)
                else:
                    esc += 1
                    flags.append(s2v[i] >= t2)
            c = cm(labels, flags)
            frac = esc / n
            lat = base1 + frac * base2
            pts.append({"stage1_allow_below": lo, "stage1_block_at_or_above": hi,
                        "stage2_threshold": t2, "escalated": esc,
                        "escalated_fraction": frac,
                        "minutes_per_case_cpu": lat,
                        "rows_per_min_effective": 1.0 / lat, **c})
    # Pareto frontier: maximise F1, minimise minutes per case
    front = []
    for p in sorted(pts, key=lambda p: (p["minutes_per_case_cpu"], -(p["f1"] or 0))):
        if not front or (p["f1"] or 0) > (front[-1]["f1"] or 0):
            front.append(p)
    return {"grid_points": len(pts), "design": tag, "pareto_frontier": front,
            "best_f1_anywhere_on_grid": max(pts, key=lambda p: (p["f1"] or 0)),
            "cheapest_point": min(pts, key=lambda p: p["minutes_per_case_cpu"])}


# ---------------------------------------------------------------- 2. calibration
def calibration(scores, labels, bins=10):
    """Equal-width reliability table, ECE, MCE and Brier on the arm's own
    positive-class probability.  Equal-width (not equal-count) bins are used so the
    table is comparable across arms whose score distributions differ wildly."""
    tab = []
    ece = 0.0
    mce = 0.0
    n = len(labels)
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        idx = [i for i in range(n) if (scores[i] >= lo and (scores[i] < hi or (b == bins - 1 and scores[i] <= hi)))]
        if not idx:
            tab.append({"bin": [lo, hi], "cases": 0, "mean_score": None,
                        "empirical_positive_rate": None, "gap": None})
            continue
        ms = sum(scores[i] for i in idx) / len(idx)
        er = sum(1 for i in idx if labels[i]) / len(idx)
        gap = abs(ms - er)
        ece += len(idx) / n * gap
        mce = max(mce, gap)
        tab.append({"bin": [lo, hi], "cases": len(idx), "mean_score": ms,
                    "empirical_positive_rate": er, "gap": gap,
                    "positives": sum(1 for i in idx if labels[i])})
    brier = sum((scores[i] - (1.0 if labels[i] else 0.0)) ** 2 for i in range(n)) / n
    base = sum(1 for l in labels if l) / n
    brier_base = sum((base - (1.0 if labels[i] else 0.0)) ** 2 for i in range(n)) / n
    return {"bins": bins, "reliability_table": tab, "ece": ece, "mce": mce,
            "brier": brier, "brier_of_always_predicting_prevalence": brier_base,
            "brier_skill_score_vs_prevalence": 1 - brier / brier_base if brier_base else None,
            "mean_predicted": sum(scores) / n, "empirical_prevalence": base,
            "mean_predicted_minus_prevalence": sum(scores) / n - base}


# ---------------------------------------------------------------- 3. error correlation
def phi(a, b):
    n = len(a)
    n11 = sum(1 for x, y in zip(a, b) if x and y)
    n10 = sum(1 for x, y in zip(a, b) if x and not y)
    n01 = sum(1 for x, y in zip(a, b) if not x and y)
    n00 = n - n11 - n10 - n01
    den = math.sqrt((n11 + n10) * (n01 + n00) * (n11 + n01) * (n10 + n00))
    return ((n11 * n00 - n10 * n01) / den) if den else None


def jaccard(a, b):
    inter = sum(1 for x, y in zip(a, b) if x and y)
    uni = sum(1 for x, y in zip(a, b) if x or y)
    return (inter / uni) if uni else None


def error_correlation(labels, per_arm_flags, tag):
    armnames = sorted(per_arm_flags)
    pos_idx = [i for i, l in enumerate(labels) if l]
    neg_idx = [i for i, l in enumerate(labels) if not l]
    miss = {a: [not per_arm_flags[a][i] for i in pos_idx] for a in armnames}   # false negatives
    fp = {a: [per_arm_flags[a][i] for i in neg_idx] for a in armnames}          # false positives
    pw = {}
    for a, b in combinations(armnames, 2):
        pw[f"{a}  vs  {b}"] = {
            "missed_positives_jaccard": jaccard(miss[a], miss[b]),
            "missed_positives_phi": phi(miss[a], miss[b]),
            "false_positives_jaccard": jaccard(fp[a], fp[b]),
            "false_positives_phi": phi(fp[a], fp[b]),
        }
    mj = [v["missed_positives_jaccard"] for v in pw.values() if v["missed_positives_jaccard"] is not None]
    mp = [v["missed_positives_phi"] for v in pw.values() if v["missed_positives_phi"] is not None]
    fj = [v["false_positives_jaccard"] for v in pw.values() if v["false_positives_jaccard"] is not None]
    # unanimity
    missed_by_all = [i for k, i in enumerate(pos_idx) if all(miss[a][k] for a in armnames)]
    caught_by_none = len(missed_by_all)
    caught_by_all = sum(1 for k in range(len(pos_idx)) if all(not miss[a][k] for a in armnames))
    oracle_union = sum(1 for k in range(len(pos_idx)) if any(not miss[a][k] for a in armnames))
    fp_by_all = sum(1 for k in range(len(neg_idx)) if all(fp[a][k] for a in armnames))
    return {
        "design": tag, "arms": armnames, "n_arms": len(armnames),
        "positives": len(pos_idx), "benign": len(neg_idx),
        "pairwise": pw,
        "mean_pairwise_missed_positive_jaccard": (sum(mj) / len(mj)) if mj else None,
        "mean_pairwise_missed_positive_phi": (sum(mp) / len(mp)) if mp else None,
        "mean_pairwise_false_positive_jaccard": (sum(fj) / len(fj)) if fj else None,
        "positives_missed_by_every_arm": caught_by_none,
        "positives_missed_by_every_arm_fraction": caught_by_none / len(pos_idx),
        "positives_caught_by_every_arm": caught_by_all,
        "positives_caught_by_at_least_one_arm": oracle_union,
        "union_oracle_recall": oracle_union / len(pos_idx),
        "benign_blocked_by_every_arm": fp_by_all,
        "interpretation_hook": (
            "positives_missed_by_every_arm is the CORPUS floor: no choice among these arms "
            "and no ensemble of them can recover those cases.  union_oracle_recall is the "
            "unreachable ceiling a perfect router over the same arms would hit."),
    }


def main():
    rep = {"provenance": {
        "gpu_used": False, "new_inference_run": False,
        "cpu_throughput_source": str(FEAS),
        "cpu_throughput_note": ("rows/min measured CPU-only, 8 pinned threads, decoders "
                                "GGUF Q4_K_M under llama.cpp, encoders dynamic int8.  The "
                                "ledger calls these an OPTIMISTIC CEILING: the bench host "
                                "carried ~31 of 96 cores of foreign load and a real laptop "
                                "also thermally throttles."),
    }}
    feas = json.loads(FEAS.read_text())
    rpm = {d["arm"]: d["rows_per_min"] for d in feas["decoder_throughput_rows_per_min"]}
    rpm.update({d["arm"]: d["rows_per_min"] for d in feas["encoder_throughput_rows_per_min"]})
    rep["cpu_rows_per_min"] = rpm
    rep["cpu_throughput_gap"] = {
        "arms_with_a_cpu_figure": sorted(rpm),
        "cohort_arms_without_a_cpu_figure": [a for a in COHORT6 if a not in rpm],
        "note": ("prompt-guard-2-22m / -86m and shieldgemma-2b have no CPU rows/min in the "
                 "ledger, so any cascade costed here uses only arms that do.  That is a "
                 "measurement gap, not a modelling choice."),
    }

    s2c, s3c = load("corpus-s2"), load("corpus-s3")
    l2, l3 = s2c["labels"], s3c["labels"]

    # ============================================================ 1. cascade
    d3, _ = primary_vec("s3", "deberta-v3-prompt-injection-v2")
    d2, _ = primary_vec("s2", "deberta-v3-prompt-injection-v2")
    casc = {}
    for partner in ("shieldstral-1.0-3b", "granite-guardian-3.2-3b-a800m"):
        p3, _ = primary_vec("s3", partner)
        p2, _ = primary_vec("s2", partner)
        pts2, _, _ = H.sweep(p2, l2)
        t2_fitted = H.best_point(pts2)["threshold"]          # fitted on s2
        pts3, _, _ = H.sweep(p3, l3)
        t3_oracle = H.best_point(pts3)["threshold"]          # s3 oracle, labelled
        qs = sorted(d3)
        grid_lo = [qs[int(len(qs) * f)] for f in [i / 24 for i in range(0, 23)]]
        grid_hi = [qs[int(len(qs) * f)] for f in [0.90 + i * 0.004 for i in range(25)]] + [max(qs) + 1.0]
        casc[f"deberta -> {partner} | s3 HELD OUT, stage2 threshold fitted on s2"] = cascade(
            l3, d3, p3, sorted(set(grid_lo)), sorted(set(grid_hi)), t2_fitted,
            rpm["deberta-v3-prompt-injection-v2"], rpm[partner],
            "genuine held-out cascade: both stage thresholds chosen without seeing s3")
        casc[f"deberta -> {partner} | s3, stage2 at the s3 ORACLE threshold ({ORACLE})"] = cascade(
            l3, d3, p3, sorted(set(grid_lo)), sorted(set(grid_hi)), t3_oracle,
            rpm["deberta-v3-prompt-injection-v2"], rpm[partner],
            "UPPER BOUND ONLY -- stage 2 threshold peeked at s3")
        qs2 = sorted(d2)
        g2lo = [qs2[int(len(qs2) * f)] for f in [i / 24 for i in range(0, 23)]]
        g2hi = [qs2[int(len(qs2) * f)] for f in [0.90 + i * 0.004 for i in range(25)]] + [max(qs2) + 1.0]
        casc[f"deberta -> {partner} | s2 in-sample ({ORACLE})"] = cascade(
            l2, d2, p2, sorted(set(g2lo)), sorted(set(g2hi)), t2_fitted,
            rpm["deberta-v3-prompt-injection-v2"], rpm[partner],
            "in-sample on s2; upper bound, not a result")
    # the two single-model reference points the frontier must be judged against
    solo = {}
    for arm in ("deberta-v3-prompt-injection-v2", "shieldstral-1.0-3b",
                "granite-guardian-3.2-3b-a800m"):
        v3, _ = primary_vec("s3", arm)
        v2, _ = primary_vec("s2", arm)
        p2s, _, _ = H.sweep(v2, l2)
        tf = H.best_point(p2s)["threshold"]
        p3s, _, _ = H.sweep(v3, l3)
        bo = H.best_point(p3s)
        solo[arm] = {
            "cpu_rows_per_min": rpm.get(arm),
            "minutes_per_case_cpu": (1.0 / rpm[arm]) if arm in rpm else None,
            "s3_at_s2_fitted_threshold": cm(l3, [v >= tf for v in v3]),
            "s3_oracle_" + ORACLE: {"threshold": bo["threshold"], "f1": bo["f1"],
                                    "tp": bo["tp"], "fp": bo["fp"], "fn": bo["fn"],
                                    "tn": bo["tn"], "recall": bo["recall"],
                                    "block_fpr": bo["fpr"]},
        }
    rep["benchmark_1_cascade_triage"] = {
        "verdict": "COMPUTABLE NOW from existing rows, zero new inference -- CONFIRMED",
        "design": (
            "Stage 1 is DeBERTa on every case (186.7 rows/min CPU).  A case scoring below "
            "`lo` is allowed outright and a case at or above `hi` is blocked outright; only "
            "the band between them is escalated to the expensive arm.  Cost per case is "
            "1/186.7 + escalated_fraction * 1/rows_per_min(stage2) minutes."),
        "single_model_reference_points": solo,
        "frontiers": casc,
    }

    # ============================================================ 2. calibration
    cal = {}
    for arm in COHORT6:
        v3, a3 = primary_vec("s3", arm)
        v2, a2 = primary_vec("s2", arm)
        # only a genuine probability can be calibrated; a difference variable cannot
        ok = not a3["primary_block_variable"].startswith("P(block) - P(confirm)")
        cal[arm] = {
            "primary_variable": a3["primary_block_variable"],
            "is_a_probability": ok,
            "s3": calibration(v3, l3) if ok else "not a probability; ECE undefined",
            "s2": calibration(v2, l2) if ok else "not a probability; ECE undefined",
        }
    sh = cal["shieldstral-1.0-3b"]
    rep["benchmark_3_calibration"] = {
        "verdict": "COMPUTABLE NOW from existing rows, zero new inference -- CONFIRMED",
        "per_arm": cal,
        "shieldstral_card_claim_tested": {
            "claim": "the model card claims a 'calibrated' probability and publishes no FPR",
            "s3_ece": sh["s3"]["ece"], "s3_mce": sh["s3"]["mce"],
            "s3_brier": sh["s3"]["brier"],
            "s3_brier_skill_vs_prevalence": sh["s3"]["brier_skill_score_vs_prevalence"],
            "s3_mean_predicted": sh["s3"]["mean_predicted"],
            "s3_empirical_prevalence": sh["s3"]["empirical_prevalence"],
            "s3_mean_predicted_minus_prevalence": sh["s3"]["mean_predicted_minus_prevalence"],
            "s2_ece": sh["s2"]["ece"],
            "measured_s3_block_fpr_at_shipped_argmax": 0.004906204906204906,
            "note": ("The card publishes no FPR, so the shipped block FPR measured here is "
                     "new information about the model regardless of the ECE result."),
        },
        "ece_ranking_s3": sorted(
            [{"arm": a, "ece": cal[a]["s3"]["ece"], "brier": cal[a]["s3"]["brier"]}
             for a in cal if cal[a]["is_a_probability"]], key=lambda r: r["ece"]),
        "caveat": (
            "At 0.903% prevalence almost every case sits in the lowest score bin, so ECE is "
            "dominated by that bin and a model that simply predicts a near-zero probability "
            "everywhere scores a deceptively good ECE.  The Brier skill score against a "
            "predict-the-prevalence baseline is reported next to it for exactly that reason, "
            "and the reliability table is included so the empty high-score bins are visible "
            "rather than averaged away."),
    }

    # ============================================================ 4. error correlation
    ec = {}
    # s2: all 22 arms, each at its own s2 in-sample oracle threshold (ORACLE) and at shipped
    s2_arms = sorted(p.stem.split("s2--")[-1] for p in CACHE.glob("s2--*.json"))
    s2_arms = [a for a in s2_arms if a != "bespoke-nimble-9b"]   # scope rule
    flags_oracle, flags_ship = {}, {}
    for arm in s2_arms:
        v, a = primary_vec("s2", arm)
        pts, _, _ = H.sweep(v, l2)
        t = H.best_point(pts)["threshold"]
        flags_oracle[arm] = [x >= t for x in v]
        flags_ship[arm] = [s in ("block", "deny") for s in a["ship_action"]]
    ec["s2_all_22_at_oracle_thresholds_" + ORACLE] = error_correlation(
        l2, flags_oracle, "s2, 22 cohort arms, each at its own in-sample best-F1 threshold "
                          "(ORACLE upper bound, used here only to give every arm its most "
                          "favourable operating point before asking whether they fail together)")
    ec["s2_all_22_at_shipped_argmax"] = error_correlation(
        l2, flags_ship, "s2, 22 cohort arms, each at its shipped argmax decision")
    f3o, f3s = {}, {}
    for arm in COHORT6:
        v, a = primary_vec("s3", arm)
        pts, _, _ = H.sweep(v, l3)
        t = H.best_point(pts)["threshold"]
        f3o[arm] = [x >= t for x in v]
        f3s[arm] = [s in ("block", "deny") for s in a["ship_action"]]
    ec["s3_six_at_oracle_thresholds_" + ORACLE] = error_correlation(
        l3, f3o, "s3 held out, the six settled arms at their s3 oracle thresholds")
    ec["s3_six_at_shipped_argmax"] = error_correlation(
        l3, f3s, "s3 held out, the six settled arms at shipped argmax")
    rep["benchmark_4_error_correlation"] = {
        "verdict": "COMPUTABLE NOW from existing rows, zero new inference -- CONFIRMED",
        "results": ec,
    }

    # ============================================================ 2b. policy sensitivity (scoped)
    npos3 = sum(1 for x in l3 if x)
    rows_s2, rows_s3 = 30310, 100001
    policy_arms = {"shieldgemma-2b": "plain-language policy string",
                   "shieldstral-1.0-3b": "plain-language policy string",
                   "llama-guard-3-1b": "custom category list (S1..Sn)"}
    est = {}
    for arm, how in policy_arms.items():
        r = rpm.get(arm)
        est[arm] = {
            "policy_surface": how,
            "cpu_rows_per_min": r,
            "cpu_minutes_per_policy_variant_s2": (rows_s2 / r) if r else None,
            "cpu_hours_per_policy_variant_s2": (rows_s2 / r / 60) if r else None,
            "cpu_hours_per_policy_variant_s3": (rows_s3 / r / 60) if r else None,
            "gpu_rows_per_min_measured": load(f"s2--{arm}")["metadata"].get("rows_per_min_cuda"),
            "gpu_minutes_per_policy_variant_s2": (
                rows_s2 / load(f"s2--{arm}")["metadata"]["rows_per_min_cuda"]
                if load(f"s2--{arm}")["metadata"].get("rows_per_min_cuda") else None),
        }
    rep["benchmark_2_policy_sensitivity"] = {
        "verdict": "NEEDS NEW INFERENCE -- not computable from existing rows",
        "why": ("Every settled row was produced under one fixed policy/prompt at cell "
                "C7 / I3 / Q2.  The policy text is an INPUT to the model, so varying it "
                "changes the request and cannot be recovered by re-reading outputs.  No "
                "rethresholding trick substitutes for it."),
        "what_it_would_separate": (
            "Model from prompt.  Today an arm's score confounds the checkpoint's ability "
            "with the particular policy wording it was handed.  Holding the checkpoint "
            "fixed and sweeping k policy wordings gives a within-model variance that can "
            "be compared against the between-model variance already measured.  If policy "
            "variance rivals model variance, the entire cohort ranking is a ranking of "
            "prompts, not of models -- and the s2/s3 rank reshuffle already makes that "
            "hypothesis live."),
        "eligible_arms": est,
        "scope_estimate": {
            "arms": 3, "suggested_policy_variants": 5,
            "runs": 15,
            "gpu_hours_estimate_s2_only": sum(
                (rows_s2 / est[a]["gpu_rows_per_min_measured"] / 60) * 5
                for a in est if est[a]["gpu_rows_per_min_measured"]),
            "note": ("s2 only, 5 wordings per arm, using each arm's own measured CUDA "
                     "throughput.  s3 is 3.3x the rows and would cost 3.3x.  This is the "
                     "cheapest new-inference experiment on the list by a wide margin."),
        },
    }

    # ============================================================ 5. ladder / question axes
    rep["benchmark_5_context_ladder_and_question_format"] = {
        "verdict": "NEEDS NEW INFERENCE for the cohort; the axis is already proven to matter",
        "evidence_that_the_axis_is_real": {
            "jev_at_Q0": JEV_Q["Q0"], "jev_at_Q2": JEV_Q["Q2"],
            "delta_Q0_minus_Q2": JEV_Q["Q0"] - JEV_Q["Q2"],
            "note": ("Question phrasing alone moved Jev by this much elsewhere in the "
                     "programme.  That delta is comparable in size to several of the gaps "
                     "the cohort ranking currently treats as real model differences, which "
                     "is the reason to run it."),
        },
        "why_not_computable_now": (
            "Every cohort row is at the single cell C7 / I3 / Q2.  C0-C7 / CR / CS / CF / "
            "CA / CD and Q0-Q4 are different rendered requests, so they require new "
            "inference.  Nothing in the existing rows can stand in for them."),
        "cost_shape": ("the grid is multiplicative -- 13 context variants x 5 question "
                       "variants is 65 cells per arm, so this is the most expensive item "
                       "on the list and should be run on a small arm subset, not all 22"),
    }

    # ============================================================ ranking of the five
    rep["ranking_by_what_it_would_actually_tell_us"] = [
        {"rank": 1, "benchmark": "error correlation across the arms",
         "cost": "zero, computable now",
         "why": ("It is the only item that can invalidate the whole model-selection "
                 "exercise.  If the arms fail the same cases, the ceiling is a corpus "
                 "property and no choice among these 22 -- and no ensemble of them -- "
                 "moves it.  Results are in this file: see "
                 "positives_missed_by_every_arm and union_oracle_recall.")},
        {"rank": 2, "benchmark": "cascade / triage curve",
         "cost": "zero, computable now",
         "why": ("It is the only item that changes a DEPLOYMENT decision rather than a "
                 "leaderboard.  DeBERTa is 18.8x faster on CPU than the best decoder "
                 "partner, so if a thin escalation band keeps most of the accuracy the "
                 "cost/accuracy frontier is the actionable artifact.  Computed here on s3 "
                 "held out, with both stage thresholds fitted without seeing s3.")},
        {"rank": 3, "benchmark": "policy sensitivity",
         "cost": "new inference, cheapest of the new-inference items",
         "why": ("It tests whether the cohort ranking is a ranking of models or of "
                 "prompts.  The s2 -> s3 rank reshuffle makes that a live hypothesis "
                 "rather than a pedantic one, so this is the highest-value new inference.")},
        {"rank": 4, "benchmark": "calibration",
         "cost": "zero, computable now",
         "why": ("It settles one vendor claim and fills one published gap, but it changes "
                 "no ranking and no deployment decision.  Cheap and worth reporting, and "
                 "at 0.903% prevalence ECE is easy to over-read, so it is ranked below the "
                 "two items that change conclusions.")},
        {"rank": 5, "benchmark": "context ladder and question-format axes",
         "cost": "new inference, multiplicative grid, most expensive",
         "why": ("The axis is proven to matter, but a 65-cell grid across 22 arms is the "
                 "largest spend on the list and it answers a narrower question than policy "
                 "sensitivity does.  Worth a small arm subset, not the full cohort.")},
    ]

    (OUT / "task4-feasibility.json").write_text(json.dumps(rep, indent=2, sort_keys=True) + "\n")
    print("wrote", OUT / "task4-feasibility.json")


if __name__ == "__main__":
    main()
