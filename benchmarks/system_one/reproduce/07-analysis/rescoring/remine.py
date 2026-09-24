"""Systematic re-mining of settled System One s2 predictions.

ZERO GPU. Read-only on every existing prediction / meta / scorecard file.
Writes only into --out (a fresh directory).

Definitions, stated because they are not interchangeable:
  Definition A (the programme's published one, = auc_variants.py / by_variable_27b.py):
      aggregate per case FIRST, then combine:
          risk   = 1 - min_events(P(allow))
          block  = max_events(P(block))
          sum    = max_events(P(block)) + max_events(P(confirm))
          diff   = max_events(P(block)) - max_events(P(confirm))
  Definition B:
      combine per EVENT first, then take the max over events:
          risk   = max_events(1 - P(allow))            [identical to A by construction]
          block  = max_events(P(block))                [identical to A by construction]
          sum    = max_events(P(block) + P(confirm))
          diff   = max_events(P(block) - P(confirm))
"""
from __future__ import annotations

import argparse, hashlib, json, math, sys
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from pathlib import Path

REPO = "/home/ubuntu/defenseclaw-system-one"
sys.path.insert(0, REPO + "/benchmarks/scripts")
from benchmark_inventory_system_one_sources import truth_grade  # noqa: E402

DATA = Path("/home/ubuntu/.system-one-data/outputs")
CASES = DATA / "s2/cases.jsonl"
ACTION_RANK = {"allow": 0, "confirm": 1, "alert": 1, "block": 2, "deny": 2, "error": -1, "not_applicable": -1}
Z = 1.959963984540054
FPR_CAPS = [0.00384502, 0.005]

VARS = ["risk = 1 - P(allow)  [leaderboard variable]", "P(block)", "P(block) + P(confirm)", "P(block) - P(confirm)"]

ARMS = [
    # board name, board F1, prediction path, published scorecard, shipped node, auc-variants file
    ("Gemma 4 judge (det->LLM)", 0.71248247, DATA/"s2/gemma4-c7.jsonl",
     DATA/"deterministic-real/realdet-s2-openjev.json", "deterministic_then_llm", None),
    ("OpenJev", 0.70231214, DATA/"s2/openjev-final.jsonl",
     DATA/"deterministic-real/realdet-s2-openjev.json", "system_one", None),
    ("Jev 1.13.0", 0.54152824, DATA/"s2/jev-C7.jsonl",
     DATA/"deterministic-real/realdet-s2-jev.json", "system_one", None),
    ("gemma-4-26B-A4B-it", 0.47495961, DATA/"gemma4jev/s2/gemma-4-26b-a4b-it.jsonl",
     DATA/"gemma4jev/s2/scores/s2-gemma-4-26b-a4b-it.json", "system_one",
     DATA/"openjev-qwen/validation/auc-variants-gemma-4-26b-a4b-it.json"),
    ("open-jev-qwen-27b", 0.33206107, DATA/"openjev-qwen/s2/h200-settled/open-jev-qwen-27b.jsonl",
     DATA/"openjev-qwen/s2/h200-settled/scores/s2-open-jev-qwen-27b.json", "system_one",
     DATA/"openjev-qwen/s2/h200-settled/auc-variants-open-jev-qwen-27b.json"),
    ("DiffusionGemma 26B-A4B", 0.26792453, DATA/"s2/diffgemma-q2.jsonl",
     DATA/"jev-parity/scores/s2__diffusiongemma__diffgemma-q2.json", "system_one", None),
    ("bespoke-nimble-9b", 0.21568627, DATA/"nimble/s2/bespoke-nimble-9b.jsonl",
     DATA/"nimble/s2/scores/s2-bespoke-nimble-9b.json", "system_one",
     DATA/"openjev-qwen/validation/auc-variants-bespoke-nimble-9b.json"),
    ("secjudge", 0.20724154, DATA/"secjudge/predictions/secjudge-s2-C7-sev.jsonl",
     DATA/"secjudge/s2/scores/s2-secjudge.json", "system_one",
     DATA/"openjev-qwen/validation/auc-variants-secjudge.json"),
    ("open-jev-qwen-9b", 0.17551020, DATA/"openjev-qwen/s2/open-jev-qwen-9b.jsonl",
     DATA/"openjev-qwen/s2/scores/s2-open-jev-qwen-9b.json", "system_one",
     DATA/"openjev-qwen/validation/auc-variants-open-jev-qwen-9b.json"),
    ("open-jev-qwen-2b", 0.17194570, DATA/"openjev-qwen/s2/open-jev-qwen-2b.jsonl",
     DATA/"openjev-qwen/s2/scores/s2-open-jev-qwen-2b.json", "system_one",
     DATA/"openjev-qwen/validation/auc-variants-open-jev-qwen-2b.json"),
    ("decider-2b", 0.10843373, DATA/"decider/s2/decider-2b.jsonl",
     DATA/"decider/s2/scores/s2-decider-2b.json", "system_one",
     DATA/"openjev-qwen/validation/auc-variants-decider-2b.json"),
    ("jevify-gemma4-26b-a4b", 0.04921700, DATA/"gemma4jev/s2/jevify-gemma4-26b-a4b.jsonl",
     DATA/"gemma4jev/s2/scores/s2-jevify-gemma4-26b-a4b.json", "system_one",
     DATA/"openjev-qwen/validation/auc-variants-jevify-gemma4-26b-a4b.json"),
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def wilson(successes: int, total: int, z: float = Z):
    if not total:
        return {"lower": None, "upper": None}
    p = successes / total
    den = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / den
    radius = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / den
    return {"lower": max(0.0, centre - radius), "upper": min(1.0, centre + radius)}


def mann_whitney_auc(scores, labels):
    """Tie-corrected Mann-Whitney AUC. Byte-identical arithmetic to auc_variants.auc."""
    pos = [s for s, l in zip(scores, labels) if l]
    neg = sorted(s for s, l in zip(scores, labels) if not l)
    if not pos or not neg:
        return None
    wins = ties = 0
    for s in pos:
        lo = bisect_left(neg, s)
        wins += lo
        ties += bisect_right(neg, s) - lo
    return (wins + 0.5 * ties) / (len(pos) * len(neg))


def f1_of(tp, fp, fn):
    d = 2 * tp + fp + fn
    return (2 * tp / d) if d else None


def sweep(scores, labels):
    """Every distinct single threshold t on `scores`, predicate (score >= t).

    Returns the list of operating points in descending threshold order. Exact, unrounded.
    """
    n_pos = sum(1 for l in labels if l)
    n_neg = len(labels) - n_pos
    pairs = sorted(zip(scores, labels), key=lambda x: -x[0])
    points = []
    tp = fp = 0
    i = 0
    N = len(pairs)
    while i < N:
        t = pairs[i][0]
        j = i
        while j < N and pairs[j][0] == t:
            if pairs[j][1]:
                tp += 1
            else:
                fp += 1
            j += 1
        fn = n_pos - tp
        tn = n_neg - fp
        points.append({"threshold": t, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
                       "f1": f1_of(tp, fp, fn),
                       "precision": (tp / (tp + fp)) if (tp + fp) else None,
                       "recall": (tp / n_pos) if n_pos else None,
                       "fpr": (fp / n_neg) if n_neg else None})
        i = j
    return points, n_pos, n_neg


def best_point(points):
    """Max F1. Deterministic tie-break: higher F1, then fewer false positives, then
    the HIGHER threshold (the tighter gate). No rounding anywhere in the comparison."""
    return max(points, key=lambda p: (p["f1"] if p["f1"] is not None else -1.0, -p["fp"], p["threshold"]))


def at_fpr_cap(points, cap, n_neg):
    """Most permissive threshold whose realised FPR is still <= cap (max recall under the cap)."""
    max_fp = math.floor(cap * n_neg + 1e-9)
    eligible = [p for p in points if p["fp"] <= max_fp]
    if not eligible:
        return {"cap": cap, "max_false_positives_allowed": max_fp, "attainable": False}
    chosen = max(eligible, key=lambda p: (p["tp"], -p["fp"], p["threshold"]))
    return {"cap": cap, "max_false_positives_allowed": max_fp, "attainable": True, **chosen}


def zero_fp_point(points, n_pos, n_neg):
    """Lowest threshold at which fp == 0 -> the zero-false-positive gate that retains the
    most recall. (The HIGHEST such threshold is degenerate: recall 0 at every arm.)"""
    eligible = [p for p in points if p["fp"] == 0]
    out = {"n_benign_D": n_neg,
           "fpr_wilson95_at_0_of_n": wilson(0, n_neg),
           "rule_of_three_upper_bound": 3 / n_neg}
    if not eligible:
        out.update({"attainable": False, "note": "no threshold yields fp == 0 with tp > 0",
                    "threshold": None, "tp": 0, "fp": 0, "fn": n_pos, "tn": n_neg, "recall": 0.0, "f1": 0.0})
        return out
    chosen = max(eligible, key=lambda p: (p["tp"], p["threshold"]))
    out.update({"attainable": True, **chosen,
                "highest_threshold_with_fp_0": max(p["threshold"] for p in eligible),
                "note": "reported point is the LOWEST threshold with fp == 0 (max recall). "
                        "The literal highest threshold with fp == 0 is the top of the score "
                        "range and retains recall 0."})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    cases = [json.loads(l) for l in CASES.read_text(encoding="utf-8").splitlines() if l.strip()]
    grades = {str(c["id"]): truth_grade(c) for c in cases}
    grade_counts = Counter(grades.values())
    scorable = [cid for cid, g in grades.items() if g in ("A", "B", "D")]
    labels_by_case = {cid: grades[cid] in ("A", "B") for cid in scorable}
    corpus = {
        "cases_path": str(CASES), "cases_sha256": sha256_file(CASES), "cases": len(cases),
        "grade_counts_all": dict(sorted(grade_counts.items())),
        "scorable_cases_A_B_D": len(scorable),
        "grade_counts_scorable": dict(sorted(Counter(grades[c] for c in scorable).items())),
        "positives_A_B": sum(labels_by_case.values()),
        "negatives_D": len(scorable) - sum(labels_by_case.values()),
        "grade_C_excluded": grade_counts.get("C", 0),
    }
    print(json.dumps(corpus, indent=2))
    (out / "corpus.json").write_text(json.dumps(corpus, indent=2, sort_keys=True) + "\n")

    report = {"corpus": corpus, "fpr_caps": FPR_CAPS, "arms": {}, "unusable": []}

    for name, board_f1, pred, score_path, node, aucfile in ARMS:
        rec = {"board_name": name, "board_block_only_f1": board_f1, "prediction": str(pred),
               "published_scorecard": (str(score_path) if score_path is not None else None), "shipped_node": node}
        # ---- settled discipline
        meta_path = Path(str(pred) + ".meta.json")
        if not meta_path.exists():
            rec["settled"] = False; rec["settled_reason"] = "no .meta.json"
            report["unusable"].append(rec); print("UNUSABLE", name, rec["settled_reason"]); continue
        meta = json.loads(meta_path.read_text())
        disk = sha256_file(pred)
        complete = meta.get("complete") is True
        sha_ok = disk == meta.get("prediction_sha256")
        rec["meta_complete"] = meta.get("complete")
        rec["prediction_sha256_meta"] = meta.get("prediction_sha256")
        rec["prediction_sha256_disk"] = disk
        rec["sha256_match"] = sha_ok
        rec["settled"] = bool(complete and sha_ok)
        rec["meta_cases"] = meta.get("cases")
        rec["meta_cases_sha256"] = meta.get("cases_sha256")
        rec["meta_run_id"] = meta.get("run_id")
        rec["meta_model_revision"] = meta.get("model_revision")
        rec["meta_grid"] = {"contexts": meta.get("contexts"), "instructions": meta.get("instructions"),
                            "questions": meta.get("questions")}
        rec["meta_errors_by_code"] = meta.get("errors_by_code")
        if not rec["settled"]:
            rec["settled_reason"] = ("meta complete is not true" if not complete
                                     else "on-disk sha256 != meta.prediction_sha256")
            report["unusable"].append(rec); print("UNUSABLE", name, rec["settled_reason"]); continue

        # ---- aggregate
        agg = {}
        rows = n_noprob = 0
        actions_by_case = defaultdict(list)
        with pred.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                r = json.loads(line)
                rows += 1
                cid = str(r.get("case_id", ""))
                probs = r.get("probabilities") if isinstance(r.get("probabilities"), dict) else {}
                b = probs.get("disposition.block"); c = probs.get("disposition.confirm"); a = probs.get("disposition.allow")
                has = isinstance(b, (int, float)) and isinstance(c, (int, float)) and isinstance(a, (int, float))
                if not has:
                    n_noprob += 1
                b = float(b) if isinstance(b, (int, float)) else 0.0
                c = float(c) if isinstance(c, (int, float)) else 0.0
                a = float(a) if isinstance(a, (int, float)) else 1.0
                e = agg.get(cid)
                if e is None:
                    e = agg[cid] = {"maxb": 0.0, "maxc": 0.0, "mina": 1.0, "maxsumB": -math.inf, "maxdiffB": -math.inf,
                                    "events": 0}
                e["maxb"] = max(e["maxb"], b); e["maxc"] = max(e["maxc"], c); e["mina"] = min(e["mina"], a)
                e["maxsumB"] = max(e["maxsumB"], b + c); e["maxdiffB"] = max(e["maxdiffB"], b - c)
                e["events"] += 1
                if not r.get("error_code") and str(r.get("action", "error")) != "error":
                    actions_by_case[cid].append(str(r.get("action", "error")))
        rec["prediction_rows"] = rows
        rec["rows_without_full_disposition_distribution"] = n_noprob
        rec["cases_in_prediction"] = len(agg)
        missing = [cid for cid in scorable if cid not in agg]
        rec["scorable_cases_missing_from_prediction"] = len(missing)
        if n_noprob == rows:
            rec["rethresholdable"] = False
            rec["rethreshold_blocked_reason"] = (
                "every prediction row carries an empty `probabilities` object -- no "
                "disposition distribution exists in this artifact, so no threshold sweep is possible")
            report["arms"][name] = rec
            print("NOT RE-MINEABLE", name, "-", rec["rethreshold_blocked_reason"])
            continue
        if missing:
            rec["rethresholdable"] = False
            rec["rethreshold_blocked_reason"] = f"{len(missing)} scorable cases absent from prediction"
            report["arms"][name] = rec
            print("NOT RE-MINEABLE", name, rec["rethreshold_blocked_reason"]); continue
        rec["rethresholdable"] = True

        # ---- shipped operating point, recomputed from rows
        labels = [labels_by_case[cid] for cid in scorable]
        ship_action = {}
        for cid in scorable:
            acts = actions_by_case.get(cid) or []
            ship_action[cid] = max(acts, key=lambda v: ACTION_RANK.get(v, -1)) if acts else "error"
        def cm(pred_flags):
            tp = fp = fn = tn = 0
            for lab, pf in zip(labels, pred_flags):
                if lab and pf: tp += 1
                elif lab: fn += 1
                elif pf: fp += 1
                else: tn += 1
            return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "f1": f1_of(tp, fp, fn),
                    "precision": (tp/(tp+fp)) if (tp+fp) else None,
                    "recall": tp/(tp+fn) if (tp+fn) else None,
                    "fpr": fp/(fp+tn) if (fp+tn) else None}
        block_flags = [ship_action[cid] in ("block", "deny") for cid in scorable]
        any_flags = [ship_action[cid] in ("block", "deny", "confirm", "alert") for cid in scorable]
        rec["shipped_recomputed_from_rows"] = {"block_only": cm(block_flags), "any_intervention": cm(any_flags)}
        rec["shipped_action_histogram"] = dict(sorted(Counter(ship_action[c] for c in scorable).items()))
        # cross-check against the published scorecard
        pub = json.loads(score_path.read_text())["candidates"][0] if score_path is not None else {}
        if node is not None and node in pub:
            pb = pub[node]["binary_block_only"]; pa = pub[node]["binary"]
            rec["published_shipped"] = {
                "block_only": {"f1": pb["f1"], "confusion": pb["confusion"]},
                "any_intervention": {"f1": pa["f1"], "confusion": pa["confusion"]},
                "scorable_cases": pub.get("scorable_cases")}
            mine = rec["shipped_recomputed_from_rows"]
            rec["shipped_agrees_with_published"] = {
                "block_only_confusion": (mine["block_only"]["tp"] == pb["confusion"]["true_positive"]
                                         and mine["block_only"]["fp"] == pb["confusion"]["false_positive"]
                                         and mine["block_only"]["fn"] == pb["confusion"]["false_negative"]
                                         and mine["block_only"]["tn"] == pb["confusion"]["true_negative"]),
                "any_confusion": (mine["any_intervention"]["tp"] == pa["confusion"]["true_positive"]
                                  and mine["any_intervention"]["fp"] == pa["confusion"]["false_positive"]
                                  and mine["any_intervention"]["fn"] == pa["confusion"]["false_negative"]
                                  and mine["any_intervention"]["tn"] == pa["confusion"]["true_negative"]),
                "block_only_f1_abs_delta": abs((mine["block_only"]["f1"] or 0) - pb["f1"]),
                "board_block_only_f1_abs_delta": (abs((mine["block_only"]["f1"] or 0) - board_f1) if board_f1 is not None else None)}

        # ---- the four ranking variables, under both aggregation definitions
        projections = {
            "A": {VARS[0]: lambda e: 1 - e["mina"], VARS[1]: lambda e: e["maxb"],
                  VARS[2]: lambda e: e["maxb"] + e["maxc"], VARS[3]: lambda e: e["maxb"] - e["maxc"]},
            "B": {VARS[0]: lambda e: 1 - e["mina"], VARS[1]: lambda e: e["maxb"],
                  VARS[2]: lambda e: e["maxsumB"], VARS[3]: lambda e: e["maxdiffB"]},
        }
        by_var = {}
        for defn in ("A", "B"):
            for vname, proj in projections[defn].items():
                scores = [proj(agg[cid]) for cid in scorable]
                pts, n_pos, n_neg = sweep(scores, labels)
                bp = best_point(pts)
                entry = {
                    "aggregation_definition": defn,
                    "positives_A_B": n_pos, "negatives_D": n_neg, "scored_cases": len(scores),
                    "distinct_thresholds": len(pts),
                    "roc_auc_mann_whitney_tie_corrected": mann_whitney_auc(scores, labels),
                    "best_f1": {"threshold": bp["threshold"], "tp": bp["tp"], "fp": bp["fp"],
                                "fn": bp["fn"], "tn": bp["tn"], "f1": bp["f1"],
                                "precision": bp["precision"], "recall": bp["recall"], "fpr": bp["fpr"]},
                    "recall_at_fpr_cap": {str(c): at_fpr_cap(pts, c, n_neg) for c in FPR_CAPS},
                    "zero_false_positive_point": zero_fp_point(pts, n_pos, n_neg),
                }
                by_var[f"{vname} || def{defn}"] = entry
        rec["by_variable"] = by_var

        # ---- best over all variables, Definition A (the published definition)
        defA = {v: by_var[f"{v} || defA"] for v in VARS}
        defB = {v: by_var[f"{v} || defB"] for v in VARS}
        bestA_var = max(VARS, key=lambda v: defA[v]["best_f1"]["f1"])
        bestB_var = max(VARS, key=lambda v: defB[v]["best_f1"]["f1"])
        shipped_block = rec["shipped_recomputed_from_rows"]["block_only"]["f1"]
        shipped_any = rec["shipped_recomputed_from_rows"]["any_intervention"]["f1"]
        rec["verdict"] = {
            "shipped_block_only_f1": shipped_block,
            "shipped_any_intervention_f1": shipped_any,
            "best_f1_defA": defA[bestA_var]["best_f1"]["f1"], "best_variable_defA": bestA_var,
            "best_point_defA": defA[bestA_var]["best_f1"],
            "best_f1_defB": defB[bestB_var]["best_f1"]["f1"], "best_variable_defB": bestB_var,
            "best_point_defB": defB[bestB_var]["best_f1"],
            "delta_vs_shipped_block_only_defA": defA[bestA_var]["best_f1"]["f1"] - shipped_block,
            "delta_vs_shipped_any_intervention_defA": defA[bestA_var]["best_f1"]["f1"] - shipped_any,
            "ratio_vs_shipped_block_only_defA": (defA[bestA_var]["best_f1"]["f1"] / shipped_block) if shipped_block else None,
            "crosses_openjev_shipped_0_70231214": defA[bestA_var]["best_f1"]["f1"] > 0.70231214,
            "note": "A single threshold on a single ranking variable produces ONE predicted-positive "
                    "set, so the block-only and any-intervention lenses share the same sweep and the "
                    "same best F1 (the labels A|B are identical in both lenses; only the shipped "
                    "baseline differs). Both deltas are therefore reported against one best F1.",
        }

        # ---- agreement with any existing auc-variants artifact
        if aucfile and Path(aucfile).exists():
            published = json.loads(Path(aucfile).read_text())
            pa = published.get("auc") or {}
            checks = {}
            for v in VARS:
                if v not in pa:
                    checks[v] = {"published": None, "status": "absent from published file"}
                    continue
                mineA = defA[v]["roc_auc_mann_whitney_tie_corrected"]
                mineB = defB[v]["roc_auc_mann_whitney_tie_corrected"]
                checks[v] = {"published": pa[v], "mine_defA": mineA, "mine_defB": mineB,
                             "abs_delta_defA": abs(pa[v] - mineA), "abs_delta_defB": abs(pa[v] - mineB),
                             "agrees_defA_within_5e-12": abs(pa[v] - mineA) <= 5e-12,
                             "matches_which_definition": ("A" if abs(pa[v] - mineA) <= 5e-12
                                                          else ("B" if abs(pa[v] - mineB) <= 5e-12 else "neither"))}
            rec["auc_variants_crosscheck"] = {"file": str(aucfile),
                                              "published_positives_A_B": published.get("positives_A_B"),
                                              "published_negatives_D": published.get("negatives_D"),
                                              "published_predictions": published.get("predictions"),
                                              "checks": checks}
        else:
            rec["auc_variants_crosscheck"] = {"file": str(aucfile) if aucfile else None,
                                              "status": "no auc-variants artifact found for this arm"}
        report["arms"][name] = rec
        v = rec["verdict"]
        print(f"{name:26s} shipped {shipped_block!r:22s} best {v['best_f1_defA']!r:22s} "
              f"({v['best_variable_defA']}) delta {v['delta_vs_shipped_block_only_defA']!r}")
        sys.stdout.flush()

    (out / "remine-full.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("wrote", out / "remine-full.json")


if __name__ == "__main__":
    main()
