"""Ranking table, headline-claim verification, and s2->s3 transfer. ZERO GPU."""
from __future__ import annotations
import json, math, sys
from pathlib import Path
sys.path.insert(0, "/home/ubuntu/rescoring-remine")
import remine as H

BASE = Path("/home/ubuntu/cohort-rank")
OUT = BASE / "out"
ORACLE = "ORACLE_IN_SAMPLE_UPPER_BOUND_NOT_A_RESULT"
CONTROLS = {"control-modernbert-base", "control-modernbert-large"}
r = json.load(open(OUT / "cohort-rank.json"))
s2 = r["arms_s2"]
s3 = r["arms_s3"]
out = {}

FLOOR2 = r["corpus_s2"]["trivial_floor_block_everything"]["f1"]
FLOOR3 = r["corpus_s3"]["trivial_floor_block_everything"]["f1"]
BAND2 = r["corpus_s2"]["auc_chance_band_hanley_mcneil"]["band_95pct"]
BAND3 = r["corpus_s3"]["auc_chance_band_hanley_mcneil"]["band_95pct"]

# ------------------------------------------------ ranking on length-controlled AUC
def row(a, rec):
    h = rec["headline"]
    pv = rec["primary_block_variable"]
    bv = rec["by_variable"][pv]
    bf = bv["best_f1_" + ORACLE]
    sh = rec["shipped_argmax_from_rows"]["block_only"]
    return {
        "arm": a,
        "is_control": a in CONTROLS,
        "class_structure": rec["class_structure"],
        "settled": rec["metadata"].get("settled"),
        "auc_length_controlled_primary": bv["auc_length_controlled"],
        "auc_raw_primary": bv["auc_raw_mann_whitney_tie_corrected"],
        "primary_variable": pv,
        "auc_lc_best_eligible": h["best_auc_length_controlled_over_eligible_variables"],
        "auc_lc_best_eligible_variable": h["best_auc_length_controlled_variable"],
        "shipped_f1": sh["f1"], "shipped_tp": sh["tp"], "shipped_fp": sh["fp"],
        "shipped_fn": sh["fn"], "shipped_tn": sh["tn"],
        "shipped_precision": sh["precision"], "shipped_recall": sh["recall"],
        "shipped_block_fpr": sh["block_fpr"],
        "oracle_f1": bf["f1"], "oracle_threshold": bf["threshold"],
        "oracle_tp": bf["tp"], "oracle_fp": bf["fp"], "oracle_fn": bf["fn"], "oracle_tn": bf["tn"],
        "oracle_precision": bf["precision"], "oracle_recall": bf["recall"],
        "oracle_block_fpr": bf["block_fpr"],
        "shipped_beats_trivial_floor": sh["f1"] > FLOOR2,
        "oracle_beats_trivial_floor": bf["f1"] > FLOOR2,
        "auc_lc_above_chance_band": bv["auc_length_controlled"] > BAND2[1],
        "auc_raw_above_chance_band": bv["auc_raw_mann_whitney_tie_corrected"] > BAND2[1],
    }

rows = [row(a, rec) for a, rec in s2.items()]
cands = [x for x in rows if not x["is_control"]]
ctrls = [x for x in rows if x["is_control"]]
cands.sort(key=lambda x: -x["auc_length_controlled_primary"])
out["candidate_ranking_by_length_controlled_auc_primary_block_variable"] = cands
out["negative_controls_not_candidates"] = ctrls
out["candidate_count"] = len(cands)

by_best = sorted(cands, key=lambda x: -x["auc_lc_best_eligible"])
out["candidate_ranking_by_best_eligible_variable_length_controlled_auc"] = [
    {k: x[k] for k in ("arm", "auc_lc_best_eligible", "auc_lc_best_eligible_variable",
                       "auc_length_controlled_primary", "class_structure")} for x in by_best]

out["top3_primary"] = [x["arm"] for x in cands[:3]]
out["top3_best_eligible"] = [x["arm"] for x in by_best[:3]]
S3_CHOSEN = ["deberta-v3-prompt-injection-v2", "prompt-guard-2-86m", "prompt-guard-2-22m"]
out["s3_arms_actually_run"] = S3_CHOSEN
rank_primary = {x["arm"]: i + 1 for i, x in enumerate(cands)}
rank_best = {x["arm"]: i + 1 for i, x in enumerate(by_best)}
out["s3_choice_audit"] = {
    "chosen": {a: {"rank_on_primary_lc_auc": rank_primary[a],
                   "rank_on_best_eligible_lc_auc": rank_best[a],
                   "lc_auc_primary": next(x["auc_length_controlled_primary"] for x in cands if x["arm"] == a)}
               for a in S3_CHOSEN},
    "chosen_are_top3_on_primary": set(S3_CHOSEN) == set(out["top3_primary"]),
    "chosen_are_top3_on_best_eligible": set(S3_CHOSEN) == set(out["top3_best_eligible"]),
    "arms_that_outrank_a_chosen_arm_but_got_no_s3_run": [
        {"arm": x["arm"], "rank": rank_primary[x["arm"]],
         "lc_auc": x["auc_length_controlled_primary"]}
        for x in cands if x["arm"] not in S3_CHOSEN
        and x["auc_length_controlled_primary"] > min(
            next(y["auc_length_controlled_primary"] for y in cands if y["arm"] == a) for a in S3_CHOSEN)],
}

# ------------------------------------------------ headline claim
CB = s2["control-modernbert-base"]
cb_oracle = CB["by_variable"][CB["primary_block_variable"]]["best_f1_" + ORACLE]["f1"]
cb_ship = CB["shipped_argmax_from_rows"]["block_only"]["f1"]
cb_fp = CB["shipped_argmax_from_rows"]["block_only"]["fp"]
deb_fp = s2["deberta-v3-prompt-injection-v2"]["shipped_argmax_from_rows"]["block_only"]["fp"]
lower_oracle = sorted([(x["arm"], x["oracle_f1"]) for x in cands if x["oracle_f1"] < cb_oracle],
                      key=lambda t: -t[1])
lower_ship = sorted([(x["arm"], x["shipped_f1"]) for x in cands if x["shipped_f1"] < cb_ship],
                    key=lambda t: -t[1])
out["headline_claim_check"] = {
    "claim": ("control-modernbert-base (untrained backbone) beats SIX candidates on best-F1 on "
              "P(block) (claimed 0.30849478390462), beats several on shipped F1 (claimed "
              "0.24963181), and blocks a third fewer benign cases than DeBERTa"),
    "control_oracle_best_f1_recomputed": cb_oracle,
    "control_oracle_best_f1_claimed": 0.30849478390462,
    "control_oracle_matches_claim_exactly": cb_oracle == 0.30849478390462,
    "control_shipped_f1_recomputed": cb_ship,
    "control_shipped_f1_claimed_rounded": 0.24963181,
    "candidates_compared": len(cands),
    "VERDICT_oracle_count": len(lower_oracle),
    "claimed_oracle_count": 6,
    "oracle_claim_correct": len(lower_oracle) == 6,
    "candidates_control_beats_on_oracle_best_f1": [
        {"arm": a, "oracle_f1": f, "margin_control_minus_arm": cb_oracle - f} for a, f in lower_oracle],
    "VERDICT_shipped_count": len(lower_ship),
    "candidates_control_beats_on_shipped_f1": [
        {"arm": a, "shipped_f1": f, "margin": cb_ship - f} for a, f in lower_ship],
    "benign_blocked_control": cb_fp, "benign_blocked_deberta": deb_fp,
    "control_fp_as_fraction_of_deberta": cb_fp / deb_fp,
    "reduction_fraction": 1 - cb_fp / deb_fp,
    "a_third_fewer_is_accurate": None,
    "control_length_controlled_auc": CB["headline"]["primary_auc_length_controlled"],
    "control_sits_in_chance_band_once_length_controlled":
        BAND2[0] <= CB["headline"]["primary_auc_length_controlled"] <= BAND2[1],
    "chance_band_s2": BAND2,
    "interpretation": ("An untrained backbone cannot discriminate; its length-controlled AUC is "
                       "inside the s2 chance band. Any F1 it posts is a statement about the F1 "
                       "metric at 11.42% prevalence, not about the backbone."),
}
out["headline_claim_check"]["a_third_fewer_is_accurate"] = (
    0.30 <= (1 - cb_fp / deb_fp) <= 0.37)

# ------------------------------------------------ s2 -> s3 transfer
cases3 = [json.loads(l) for l in (Path("/home/ubuntu/.system-one-data/outputs/s3/cases.jsonl")
                                  ).read_text(encoding="utf-8").splitlines() if l.strip()]
g3 = {str(c["id"]): H.truth_grade(c) for c in cases3}
sc3 = [cid for cid, g in g3.items() if g in ("A", "B", "D")]
lab3 = [g3[c] in ("A", "B") for c in sc3]

def s3_scores(arm):
    agg = {}
    for line in open(BASE / f"preds-s3/{arm}.jsonl"):
        d = json.loads(line)
        p = d["probabilities"]
        k = next(x for x in p if x.endswith((".true", ".yes")))
        cid = str(d["case_id"])
        agg[cid] = max(agg.get(cid, -math.inf), float(p[k]))
    return agg

def cmat(scores, thr):
    tp = fp = fn = tn = 0
    for cid, lab in zip(sc3, lab3):
        pf = scores[cid] >= thr
        if lab and pf: tp += 1
        elif lab: fn += 1
        elif pf: fp += 1
        else: tn += 1
    return {"threshold": thr, "tp": tp, "fp": fp, "fn": fn, "tn": tn, "f1": H.f1_of(tp, fp, fn),
            "precision": (tp / (tp + fp)) if (tp + fp) else None,
            "recall": tp / (tp + fn) if (tp + fn) else None,
            "block_fpr": fp / (fp + tn) if (fp + tn) else None}

trans = {}
for arm in S3_CHOSEN:
    pv2 = s2[arm]["primary_block_variable"]
    thr2 = s2[arm]["by_variable"][pv2]["best_f1_" + ORACLE]["threshold"]
    f1_s2 = s2[arm]["by_variable"][pv2]["best_f1_" + ORACLE]["f1"]
    sc = s3_scores(arm)
    fitted = cmat(sc, thr2)
    pv3 = s3[arm]["primary_block_variable"]
    orc3 = s3[arm]["by_variable"][pv3]["best_f1_" + ORACLE]
    ship3 = s3[arm]["shipped_argmax_from_rows"]["block_only"]
    trans[arm] = {
        "variable": pv2,
        "s2_oracle_threshold_fitted": thr2,
        "s2_oracle_f1_" + ORACLE: f1_s2,
        "s3_at_s2_fitted_threshold_HONEST_TRANSFER": fitted,
        "s3_oracle_same_variable_" + ORACLE: orc3,
        "s3_shipped_argmax": {k: ship3[k] for k in
                              ("tp", "fp", "fn", "tn", "f1", "precision", "recall", "block_fpr")},
        "overfitting_penalty_s3_oracle_minus_s3_transferred":
            (orc3["f1"] or 0) - (fitted["f1"] or 0),
        "generalisation_gap_s2_oracle_minus_s3_transferred": f1_s2 - (fitted["f1"] or 0),
        "s3_trivial_floor": FLOOR3,
        "s3_transferred_beats_s3_trivial_floor": (fitted["f1"] or 0) > FLOOR3,
        "s3_oracle_beats_s3_trivial_floor": (orc3["f1"] or 0) > FLOOR3,
        "s3_auc_raw": s3[arm]["by_variable"][pv3]["auc_raw_mann_whitney_tie_corrected"],
        "s3_auc_length_controlled": s3[arm]["by_variable"][pv3]["auc_length_controlled"],
        "s3_auc_above_chance_band":
            s3[arm]["by_variable"][pv3]["auc_raw_mann_whitney_tie_corrected"] > BAND3[1],
        "s2_auc_length_controlled": s2[arm]["by_variable"][pv2]["auc_length_controlled"],
    }
out["s2_to_s3_transfer"] = trans
out["s3_chance_band"] = BAND3
out["s3_trivial_floor"] = r["corpus_s3"]["trivial_floor_block_everything"]

# ------------------------------------------------ settle status
out["settle_status"] = {
    "settled_arms": sorted(a for a, x in s2.items() if x["metadata"].get("settled")),
    "unsettled_arms_missing_complete_or_sha": sorted(
        a for a, x in s2.items() if not x["metadata"].get("settled")),
    "detail": {a: {"carries_complete_key": x["metadata"].get("carries_complete_key"),
                   "carries_prediction_sha256_key": x["metadata"].get("carries_prediction_sha256_key"),
                   "sha256_meta_matches_disk": x["metadata"].get("sha256_meta_matches_disk"),
                   "rows": x["prediction_rows"], "shrunk": x["metadata"].get("shrunk"),
                   "fraction_rows_shrunk": x["metadata"].get("fraction_rows_shrunk"),
                   "cap_tokens": x["metadata"].get("cap_tokens")}
               for a, x in sorted(s2.items())},
    "s3_detail": {a: {"carries_complete_key": x["metadata"].get("carries_complete_key"),
                      "carries_prediction_sha256_key": x["metadata"].get("carries_prediction_sha256_key"),
                      "rows": x["prediction_rows"]} for a, x in sorted(s3.items())},
}
out["inapplicable_variables_by_arm"] = {
    a: {"class_structure": x["class_structure"], "inapplicable": sorted(x["inapplicable_variables"])}
    for a, x in sorted(s2.items())}

(OUT / "ranking-analysis.json").write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
print(json.dumps({k: out[k] for k in ("top3_primary", "top3_best_eligible", "s3_choice_audit",
                                      "headline_claim_check", "candidate_count")},
                 indent=2, sort_keys=True))
print("wrote", OUT / "ranking-analysis.json")
