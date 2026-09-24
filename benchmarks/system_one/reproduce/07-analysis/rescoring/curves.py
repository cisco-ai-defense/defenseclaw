"""ROC and PR curves, uncertainty, calibration, failure overlap and per-source recall, on s2.

Why this exists
---------------
AUC was reported in a dozen tables and no ROC or PR curve existed anywhere. Recall, block FPR
and F1 were reported as points with no interval, while the programme had already computed
Wilson bounds and family bootstraps elsewhere. This pass emits every curve and every interval
from the same aggregation the published board is read on, so a curve and the scalar beside it
cannot disagree.

Method
------
Every operating point comes from `remine.sweep` / `remine.at_fpr_cap` / `remine.best_point` and
every AUC from `remine.mann_whitney_auc` -- the functions the published re-mining pass used,
imported rather than reimplemented. The per-case score is `common_point.per_case_pblock`, which
is P(block) under aggregation definition A: the maximum of P(block) over a case's events. Rows
are per event and scoring is per case, so nothing here reads a row as a case.

The control: every AUC computed here is compared against the AUC the published pass wrote for
the same arm on the same variable and the same definition, to 5e-15. A mismatch aborts and
writes nothing, so a published curve cannot carry an AUC the board disagrees with.

What it writes
--------------
  curves/curves-s2.json
    corpus            the case counts, prevalence and digest, recomputed
    arms[name]
      roc             thinned (fpr, recall) with the threshold and counts at each point
      pr              thinned (recall, precision) with the same
      auc             the definition-A AUC on P(block), and the published figure it matched
      at_budget       the common-budget point with Wilson 95% on recall and on block FPR,
                      and a family bootstrap 95% on F1
      oracle          the in-sample argmax, labelled an upper bound
      calibration     10 equal-width buckets of P(block): n, mean predicted, observed rate
      per_source      recall at the budget per s2 source dataset, with the positive count
    overlap
      jaccard         pairwise Jaccard over the caught-positive sets at the budget
      unions          every two-arm union, with its tp/fp/fn/tn, precision, recall, F1, block FPR
    not_comparable    arms that carry no curve, with the reason
    sources           every s2 source dataset with its row and positive counts

ZERO GPU. Read-only on every input. Writes only OUT.
"""
from __future__ import annotations

import json
import math
import random
import sys
from collections import Counter, defaultdict
from itertools import combinations
from pathlib import Path

sys.path.insert(0, "$WORK/rescoring-remine")
sys.path.insert(0, "$WORK/defenseclaw-system-one/benchmarks/scripts")
import remine as R  # noqa: E402
from benchmark_inventory_system_one_sources import truth_grade  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common_point import KEV, per_case_pblock  # noqa: E402

DATA = R.DATA
CASES = DATA / "s2" / "cases.jsonl"
REMINE_FULL = DATA / "rethreshold" / "remine-full.json"
KEV_REMINE = DATA / "rethreshold" / "kev-remine-s2.json"
COMMON_POINT = DATA / "rethreshold" / "common-point-s2.json"
OUT = DATA / "curves" / "curves-s2.json"

VARIABLE = "P(block)"
DEFINITION = "A"
CAP = 0.00384502

# The two seeds and the replicate count this programme uses everywhere, so a bootstrap here is
# the same bootstrap the glossary already documents.
SEED = 741983
REPLICATES = 2000

# Full resolution over the left margin of the ROC, because the budget lives there: at 3,381
# benign cases the cap is 13 false positives, so a curve thinned on a uniform FPR grid would
# collapse the whole region the decision is made in into its first bin.
LEFT_MARGIN_FP = 60
RIGHT_BINS = 40
PR_BINS = 60
CAL_BUCKETS = 10


def thin_roc(points: list[dict]) -> list[dict]:
    """Every distinct false-positive count up to LEFT_MARGIN_FP, then binned beyond it."""
    keep: dict[int, dict] = {}
    for i, p in enumerate(points):
        if p["fp"] <= LEFT_MARGIN_FP:
            # the most permissive threshold at this fp count is the highest recall there
            cur = keep.get(p["fp"])
            if cur is None or p["tp"] >= cur["tp"]:
                keep[p["fp"]] = p
    out = [keep[k] for k in sorted(keep)]
    beyond = [p for p in points if p["fp"] > LEFT_MARGIN_FP]
    if beyond:
        lo = min(p["fp"] for p in beyond)
        hi = max(p["fp"] for p in beyond)
        span = max(1, hi - lo)
        bins: dict[int, dict] = {}
        for p in beyond:
            b = int((p["fp"] - lo) / span * (RIGHT_BINS - 1))
            cur = bins.get(b)
            if cur is None or p["tp"] >= cur["tp"]:
                bins[b] = p
        out += [bins[k] for k in sorted(bins)]
    return sorted(out, key=lambda p: (p["fp"], p["tp"]))


def thin_pr(points: list[dict]) -> list[dict]:
    """One point per recall bin, plus full resolution while fp is inside the left margin."""
    keep: list[dict] = [p for p in points if p["fp"] <= LEFT_MARGIN_FP]
    bins: dict[int, dict] = {}
    for p in points:
        if p["fp"] <= LEFT_MARGIN_FP:
            continue
        b = min(PR_BINS - 1, int((p["recall"] or 0.0) * PR_BINS))
        cur = bins.get(b)
        if cur is None or (p["precision"] or 0.0) >= (cur["precision"] or 0.0):
            bins[b] = p
    keep += [bins[k] for k in sorted(bins)]
    seen = set()
    out = []
    for p in sorted(keep, key=lambda q: (q["tp"], -q["fp"])):
        k = (p["tp"], p["fp"])
        if k in seen:
            continue
        seen.add(k)
        out.append(p)
    return out


def pt(p: dict) -> dict:
    return {"threshold": p["threshold"], "tp": p["tp"], "fp": p["fp"], "fn": p["fn"],
            "tn": p["tn"], "recall": p["recall"], "fpr": p["fpr"],
            "precision": p["precision"], "f1": p["f1"]}


def f1_from(tp: int, fp: int, fn: int):
    d = 2 * tp + fp + fn
    return (2 * tp / d) if d else None


def family_triples(scorable, family, is_pos, score, thr) -> list[tuple[int, int, int]]:
    """One (tp, fp, fn) contribution per family at a fixed threshold."""
    acc: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    for cid in scorable:
        flag = score[cid] >= thr
        pos = is_pos[cid]
        t = acc[family[cid]]
        if flag and pos:
            t[0] += 1
        elif flag:
            t[1] += 1
        elif pos:
            t[2] += 1
    return [tuple(v) for v in acc.values()]


def bootstrap_f1(triples: list[tuple[int, int, int]], reps: int = REPLICATES, seed: int = SEED):
    """Family bootstrap 95% on F1 at a fixed threshold.

    `triples` is one (tp, fp, fn) contribution per family, families being
    `strata.split_group`; the resampling unit is the family, with replacement, which is the unit
    the glossary already names. The threshold is held fixed, so this is the interval on F1 at the
    reported operating point and not an interval on a re-fitted one.
    """
    if not triples:
        return {"lower": None, "upper": None, "replicates": 0}
    rng = random.Random(seed)
    n = len(triples)
    idx = range(n)
    vals = []
    for _ in range(reps):
        tp = fp = fn = 0
        for i in rng.choices(idx, k=n):
            a, b, c = triples[i]
            tp += a
            fp += b
            fn += c
        v = f1_from(tp, fp, fn)
        if v is not None:
            vals.append(v)
    if not vals:
        return {"lower": None, "upper": None, "replicates": 0}
    vals.sort()
    lo = vals[int(0.025 * (len(vals) - 1))]
    hi = vals[int(math.ceil(0.975 * (len(vals) - 1)))]
    return {"lower": lo, "upper": hi, "replicates": len(vals),
            "unit": "family (strata.split_group)", "seed": seed,
            "method": "percentile bootstrap over families, threshold held fixed"}


def main() -> int:
    raw = [json.loads(l) for l in CASES.read_text(encoding="utf-8").splitlines() if l.strip()]
    grades = {str(c["id"]): truth_grade(c) for c in raw}
    tally = Counter(grades.values())
    scorable = [cid for cid, g in grades.items() if g in ("A", "B", "D")]
    is_pos = {cid: grades[cid] in ("A", "B") for cid in scorable}
    n_pos = sum(is_pos.values())
    n_neg = len(scorable) - n_pos

    family: dict[str, str] = {}
    source: dict[str, str] = {}
    for c in raw:
        cid = str(c["id"])
        st = c.get("strata") if isinstance(c.get("strata"), dict) else {}
        sr = c.get("source") if isinstance(c.get("source"), dict) else {}
        family[cid] = str(st.get("split_group") or cid)
        source[cid] = str(sr.get("dataset") or "missing")

    src_rows = Counter(source[cid] for cid in scorable)
    src_pos = Counter(source[cid] for cid in scorable if is_pos[cid])
    corpus = {
        "cases_path": str(CASES), "cases_sha256": R.sha256_file(CASES), "cases": len(raw),
        "grade_counts_all": dict(sorted(tally.items())),
        "scorable_cases_A_B_D": len(scorable),
        "positives_A_B": n_pos, "negatives_D": n_neg,
        "grade_C_excluded": tally.get("C", 0),
        "prevalence": n_pos / len(scorable),
        "all_allow_accuracy": n_neg / len(scorable),
        "families": len(set(family[cid] for cid in scorable)),
    }
    print(json.dumps(corpus, indent=2))

    published = json.loads(REMINE_FULL.read_text())["arms"]
    kev_pub = json.loads(KEV_REMINE.read_text()) if KEV_REMINE.exists() else {}
    cp_doc = json.loads(COMMON_POINT.read_text())

    report = {
        "kind": "defenseclaw-system-one-curves-s2",
        "schema_version": "1",
        "design": (
            f"ROC and PR curves for every arm on one ranking variable, {VARIABLE} under "
            f"aggregation definition {DEFINITION}, with the common block-FPR budget {CAP} marked. "
            f"Rows are per event and scoring is per case; the per-case score is the maximum of "
            f"P(block) over that case's events, from the published pass's own loader."
        ),
        "variable": VARIABLE, "aggregation_definition": DEFINITION, "fpr_cap": CAP,
        "method": ("curve points from remine.sweep, the budget point from remine.at_fpr_cap, the "
                   "oracle point from remine.best_point and every AUC from "
                   "remine.mann_whitney_auc, all imported from the published re-mining pass"),
        "auc_reconciliation": {
            "rule": (f"every AUC computed here must equal the AUC the published pass recorded for "
                     f"the same arm on {VARIABLE} under definition {DEFINITION}, to 5e-15"),
            "tolerance": 5e-15, "checked": 0, "mismatches": 0, "sources": {},
        },
        "uncertainty": {
            "recall": "Wilson 95% on tp of the positive count",
            "block_fpr": "Wilson 95% on fp of the benign count",
            "precision": "Wilson 95% on tp of the flagged count",
            "f1": (f"percentile bootstrap 95% over {REPLICATES} resamples of families "
                   f"(strata.split_group) with replacement, seed {SEED}, threshold held fixed"),
        },
        "corpus": corpus,
        "sources": {
            "field": "source.dataset, per case, from outputs/s2/cases.jsonl",
            "note": ("this is the attribution of the scored corpus. The 13-source catalogue in "
                     "source-catalog-v2.json attributes the upstream normalisation pool, which is "
                     "a larger set; the arms are scored on this one."),
            "datasets": {k: {"scorable_cases": src_rows[k], "positives": src_pos.get(k, 0)}
                         for k in sorted(src_rows)},
            "checked_absent": {},
        },
        "arms": {}, "not_comparable": {}, "overlap": {},
    }
    for absent in ("mcptox", "robustintelligence/augur_unsafe_tool_input_eval",
                   "augur_unsafe_tool_input_eval"):
        report["sources"]["checked_absent"][absent] = src_rows.get(absent, 0)

    mismatches: list[str] = []
    caught: dict[str, set[str]] = {}
    flagged: dict[str, set[str]] = {}
    scored: dict[str, dict[str, float]] = {}
    sweeps: dict[str, list[dict]] = {}
    arms = list(R.ARMS) + [KEV]

    for name, board_f1, pred, _score_path, _node, _auc in arms:
        meta_path = Path(str(pred) + ".meta.json")
        if not meta_path.exists():
            report["not_comparable"][name] = {"reason": "no settled meta beside the prediction"}
            continue
        meta = json.loads(meta_path.read_text())
        disk = R.sha256_file(pred)
        if meta.get("complete") is not True or disk != meta.get("prediction_sha256"):
            report["not_comparable"][name] = {"reason": "the prediction body is not settled"}
            continue

        score, rows, n_noprob, _ncase = per_case_pblock(pred)
        if n_noprob == rows:
            # the distinction matters on the page: the key is absent from the row object, not
            # present and empty, so there is nothing to threshold rather than a zero to threshold
            first = json.loads(next(l for l in pred.open(encoding="utf-8") if l.strip()))
            report["not_comparable"][name] = {
                "reason": ("no prediction row carries a disposition distribution, so no threshold "
                           "sweep and no curve are possible"),
                "probabilities_key": ("absent from the row object"
                                      if "probabilities" not in first
                                      else "present and empty"),
                "prediction_rows": rows, "rows_without_distribution": n_noprob,
                "prediction": str(pred), "board_block_only_f1": board_f1}
            print("NO CURVE", name, report["not_comparable"][name]["probabilities_key"])
            continue
        missing = [cid for cid in scorable if cid not in score]
        if missing:
            report["not_comparable"][name] = {
                "reason": f"{len(missing)} scorable cases absent from the prediction"}
            continue

        scores = [score[cid] for cid in scorable]
        labels = [is_pos[cid] for cid in scorable]
        points, p, n = R.sweep(scores, labels)
        assert (p, n) == (n_pos, n_neg), f"{name}: label counts moved"
        auc = R.mann_whitney_auc(scores, labels)
        cap_pt = R.at_fpr_cap(points, CAP, n)
        best = R.best_point(points)
        if not cap_pt.get("attainable"):
            report["not_comparable"][name] = {"reason": "the budget is not attainable"}
            continue

        # ---- the control: this AUC against the published one
        key = f"{VARIABLE} || def{DEFINITION}"
        pub_auc = None
        pub_src = None
        pub = published.get(name)
        if pub and pub.get("rethresholdable"):
            pub_auc = pub["by_variable"][key]["roc_auc_mann_whitney_tie_corrected"]
            pub_src = f"{REMINE_FULL.name} :: arms[{name}].by_variable[{key}]"
        else:
            # kev-9b is absent from remine-full.json. Its published definition-A AUC is in the
            # separate pass's own file, whose `auc` field is documented as definition A and was
            # verified at delta 0 against every other auc-variants file in the programme.
            for row in kev_pub.get("rows", []):
                if row.get("display_name") == name or row.get("model") == name:
                    pub_auc = (row.get("auc") or {}).get(VARIABLE)
                    if pub_auc is not None:
                        pub_src = (f"{KEV_REMINE.name} :: rows[0].auc[{VARIABLE!r}] "
                                   f"(definition A)")
                    break
        if pub_auc is not None:
            report["auc_reconciliation"]["checked"] += 1
            report["auc_reconciliation"]["sources"][name] = pub_src
            if abs(auc - pub_auc) > 5e-15:
                mismatches.append(f"{name}: AUC {auc!r} != published {pub_auc!r}")

        # ---- the common-budget cell also has to agree with the board's own file
        cpa = cp_doc["arms"].get(name, {}).get("at_common_budget")
        if cpa:
            for field in ("threshold", "tp", "fp", "fn", "tn", "f1", "precision", "recall",
                          "fpr"):
                got, exp = cap_pt[field], cpa[field]
                same = got == exp if isinstance(exp, int) else abs(got - exp) <= 5e-15
                if not same:
                    mismatches.append(f"{name}.at_budget.{field}: {got!r} != {exp!r}")

        thr = cap_pt["threshold"]
        caught[name] = {cid for cid in scorable if is_pos[cid] and score[cid] >= thr}
        flagged[name] = {cid for cid in scorable if score[cid] >= thr}
        scored[name] = score
        sweeps[name] = points

        triples = family_triples(scorable, family, is_pos, score, thr)

        # ---- calibration: equal-width buckets of the per-case score
        buckets = []
        for b in range(CAL_BUCKETS):
            lo, hi = b / CAL_BUCKETS, (b + 1) / CAL_BUCKETS
            ids = [cid for cid in scorable
                   if (score[cid] >= lo and (score[cid] < hi or (b == CAL_BUCKETS - 1
                                                                 and score[cid] <= hi)))]
            k = sum(1 for cid in ids if is_pos[cid])
            buckets.append({
                "lower": lo, "upper": hi, "n": len(ids), "positives": k,
                "mean_predicted": (sum(score[cid] for cid in ids) / len(ids)) if ids else None,
                "observed_rate": (k / len(ids)) if ids else None,
                "observed_wilson95": R.wilson(k, len(ids)) if ids else {"lower": None,
                                                                        "upper": None},
            })

        per_source = {}
        for ds in sorted(src_pos):
            ids = [cid for cid in scorable if source[cid] == ds and is_pos[cid]]
            hit = sum(1 for cid in ids if score[cid] >= thr)
            per_source[ds] = {"positives": len(ids), "caught": hit,
                              "recall": (hit / len(ids)) if ids else None,
                              "recall_wilson95": R.wilson(hit, len(ids)) if ids else
                              {"lower": None, "upper": None}}

        report["arms"][name] = {
            "board_name": name, "board_block_only_f1": board_f1,
            "prediction": str(pred), "prediction_sha256": disk,
            "meta_run_id": meta.get("run_id"),
            "prediction_rows": rows, "distinct_thresholds": len(points),
            "auc": {
                "value": auc, "variable": VARIABLE, "definition": DEFINITION,
                "estimator": "tie-corrected Mann-Whitney",
                "published": pub_auc, "published_source": pub_src,
                "agrees": pub_auc is None or abs(auc - pub_auc) <= 5e-15,
            },
            "at_budget": {
                **pt(cap_pt),
                "accuracy": (cap_pt["tp"] + cap_pt["tn"]) / len(scorable),
                "max_false_positives_allowed": cap_pt["max_false_positives_allowed"],
                "recall_wilson95": R.wilson(cap_pt["tp"], n_pos),
                "fpr_wilson95": R.wilson(cap_pt["fp"], n_neg),
                "precision_wilson95": R.wilson(cap_pt["tp"], cap_pt["tp"] + cap_pt["fp"]),
                "f1_bootstrap95": bootstrap_f1(triples),
            },
            "oracle": {
                **pt(best),
                "label": "in-sample oracle upper bound, fitted on the cases it is scored on",
            },
            "roc": [pt(q) for q in thin_roc(points)],
            "pr": [pt(q) for q in thin_pr(points)],
            "calibration": {"buckets": buckets,
                            "definition": "equal-width buckets of the per-case maximum P(block)"},
            "per_source": per_source,
        }
        bs = report["arms"][name]["at_budget"]["f1_bootstrap95"]
        span = ("[none]" if bs["lower"] is None
                else f'[{bs["lower"]:.8f}, {bs["upper"]:.8f}]')
        print(f"{name:26s} AUC {auc:.16f} "
              f"{'reconciled' if pub_auc is not None else 'no published AUC'} "
              f"roc {len(report['arms'][name]['roc']):3d} "
              f"pr {len(report['arms'][name]['pr']):3d} "
              f"F1 {cap_pt['f1']:.8f} {span}")

    # ---------------------------------------------------------------- failure overlap
    names = sorted(caught, key=lambda k: -report["arms"][k]["at_budget"]["f1"])
    budget_fp = math.floor(CAP * n_neg + 1e-9)

    # Candidate thresholds for a union: the most permissive threshold at each false-positive
    # count from 0 to the budget. Anything looser already spends more than the union is allowed,
    # so a pair only has to be searched over these.
    cand: dict[str, list[tuple[float, frozenset, frozenset]]] = {}
    for name in names:
        by_fp: dict[int, dict] = {}
        for p in sweeps[name]:
            if p["fp"] > budget_fp:
                continue
            cur = by_fp.get(p["fp"])
            if cur is None or p["tp"] >= cur["tp"]:
                by_fp[p["fp"]] = p
        sc = scored[name]
        cand[name] = []
        for fp_count in sorted(by_fp):
            t = by_fp[fp_count]["threshold"]
            cand[name].append((
                t,
                frozenset(cid for cid in scorable if is_pos[cid] and sc[cid] >= t),
                frozenset(cid for cid in scorable if not is_pos[cid] and sc[cid] >= t)))
    jac = {}
    for a, b in combinations(names, 2):
        u = len(caught[a] | caught[b])
        jac[f"{a} || {b}"] = {
            "intersection": len(caught[a] & caught[b]), "union": u,
            "jaccard": (len(caught[a] & caught[b]) / u) if u else None,
            "only_a": len(caught[a] - caught[b]), "only_b": len(caught[b] - caught[a]),
        }
    unions = []
    for a, b in combinations(names, 2):
        pos_set = flagged[a] | flagged[b]
        tp = sum(1 for cid in pos_set if is_pos[cid])
        fp = len(pos_set) - tp
        fn = n_pos - tp
        tn = n_neg - fp
        unions.append({
            "arms": [a, b], "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": (tp / (tp + fp)) if (tp + fp) else None,
            "recall": tp / n_pos, "f1": f1_from(tp, fp, fn), "fpr": fp / n_neg,
            "accuracy": (tp + tn) / len(scorable),
            "within_budget": fp <= math.floor(CAP * n_neg + 1e-9),
            "recall_wilson95": R.wilson(tp, n_pos), "fpr_wilson95": R.wilson(fp, n_neg),
        })
    unions.sort(key=lambda u: (-(u["f1"] or 0.0), u["fp"]))
    best_single = max(report["arms"].values(), key=lambda a: a["at_budget"]["f1"])
    best_union = unions[0]

    # The union under the SAME budget every single arm is held to. Each arm's own budget
    # threshold already spends all 13 allowed false blocks, so any union of two of those spends
    # more than the budget by construction; the question a reader is asking is whether a PAIR of
    # thresholds exists whose union stays inside 13 and catches more than the best single arm.
    # Both thresholds are searched together over the candidate set above.
    constrained = []
    for a, b in combinations(names, 2):
        best_pair = None
        for ta, pa, na in cand[a]:
            for tb, pb, nb in cand[b]:
                fp = len(na | nb)
                if fp > budget_fp:
                    continue
                tp = len(pa | pb)
                key_ = (tp, -fp)
                if best_pair is None or key_ > best_pair[0]:
                    best_pair = (key_, ta, tb, tp, fp, pa, pb)
        if best_pair is None:
            continue
        _k, ta, tb, tp, fp, pa, pb = best_pair
        fn = n_pos - tp
        tn = n_neg - fp
        constrained.append({
            "arms": [a, b], "thresholds": [ta, tb],
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": (tp / (tp + fp)) if (tp + fp) else None,
            "recall": tp / n_pos, "f1": f1_from(tp, fp, fn), "fpr": fp / n_neg,
            "accuracy": (tp + tn) / len(scorable),
            "recall_wilson95": R.wilson(tp, n_pos), "fpr_wilson95": R.wilson(fp, n_neg),
            # at the two thresholds this pair was chosen at, not at either arm's own budget point
            "caught_by_both": len(pa & pb),
            "caught_by_first_only": len(pa - pb),
            "caught_by_second_only": len(pb - pa),
        })
    constrained.sort(key=lambda u: (-(u["f1"] or 0.0), u["fp"]))
    best_constrained = constrained[0] if constrained else None
    if best_constrained is not None:
        acc: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
        a, b = best_constrained["arms"]
        ta, tb = best_constrained["thresholds"]
        for cid in scorable:
            t = acc[family[cid]]
            hit = scored[a][cid] >= ta or scored[b][cid] >= tb
            if hit and is_pos[cid]:
                t[0] += 1
            elif hit:
                t[1] += 1
            elif is_pos[cid]:
                t[2] += 1
        best_constrained = dict(best_constrained)
        best_constrained["f1_bootstrap95"] = bootstrap_f1([tuple(v) for v in acc.values()])
    report["overlap"] = {
        "definition": ("Jaccard over the caught-positive sets at the common budget: a case counts "
                       "for an arm when that arm's per-case P(block) reaches its own "
                       "common-budget threshold and the case is a grade A or B positive"),
        "arms": names,
        "jaccard": jac,
        "unions": unions,
        "unions_definition": ("each arm held at its own common-budget threshold, so the union "
                              "spends both arms' false-block allowances"),
        "constrained_unions": constrained,
        "constrained_unions_definition": (
            "both thresholds chosen together under the one shared budget the single arms are held "
            "to, maximising true blocks subject to the union's own false blocks staying inside the "
            "allowance"),
        "budget_false_positive_allowance": budget_fp,
        "best_single_arm": {"arm": best_single["board_name"],
                            "f1": best_single["at_budget"]["f1"],
                            "recall": best_single["at_budget"]["recall"],
                            "precision": best_single["at_budget"]["precision"],
                            "fpr": best_single["at_budget"]["fpr"],
                            "tp": best_single["at_budget"]["tp"],
                            "fp": best_single["at_budget"]["fp"]},
        "best_two_arm_union": best_union,
        "best_two_arm_union_within_budget": best_constrained,
        "unions_within_budget": sum(1 for u in unions if u["within_budget"]),
        "unions_total": len(unions),
        "constrained_unions_total": len(constrained),
        "constrained_unions_beating_best_single": sum(
            1 for u in constrained if (u["f1"] or 0.0) > best_single["at_budget"]["f1"]),
        "union_clears_the_budget_gate_no_single_arm_clears": bool(
            best_constrained is not None
            and (best_constrained["f1"] or 0.0) > best_single["at_budget"]["f1"]),
    }

    if mismatches:
        print("=" * 74)
        print(f"ABORT: {len(mismatches)} figure(s) disagree with the published pass. Nothing was "
              f"written.")
        for m in mismatches:
            print("  " + m)
        return 2
    report["auc_reconciliation"]["mismatches"] = 0

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print("=" * 74)
    print(f"{len(report['arms'])} arms carry a curve; "
          f"{report['auc_reconciliation']['checked']} of their AUCs were compared against the "
          f"published pass and {report['auc_reconciliation']['mismatches']} disagree")
    print(f"{len(report['not_comparable'])} arm(s) carry no curve: "
          f"{', '.join(sorted(report['not_comparable'])) or 'none'}")
    ov = report["overlap"]
    print(f"best single arm {ov['best_single_arm']['arm']} F1 "
          f"{ov['best_single_arm']['f1']:.8f} at {ov['best_single_arm']['fp']} false blocks")
    print(f"both at their own budget thresholds: best union "
          f"{' + '.join(ov['best_two_arm_union']['arms'])} F1 "
          f"{ov['best_two_arm_union']['f1']:.8f} at {ov['best_two_arm_union']['fp']} false blocks; "
          f"{ov['unions_within_budget']} of {ov['unions_total']} such unions stay inside the "
          f"{ov['budget_false_positive_allowance']}-false-block budget")
    bc = ov["best_two_arm_union_within_budget"]
    if bc:
        print(f"both thresholds chosen together under the one budget: best union "
              f"{' + '.join(bc['arms'])} F1 {bc['f1']:.8f} at {bc['fp']} false blocks, "
              f"recall {bc['recall']:.8f}, precision {bc['precision']:.8f}; "
              f"{ov['constrained_unions_beating_best_single']} of "
              f"{ov['constrained_unions_total']} beat the best single arm")
    print(f"a union clears a gate no single arm clears: "
          f"{ov['union_clears_the_budget_gate_no_single_arm_clears']}")
    print(f"wrote {OUT} ({OUT.stat().st_size:,} bytes)")
    return 0


def _families(scorable, family):
    fam = defaultdict(list)
    for cid in scorable:
        fam[family[cid]].append(cid)
    return list(fam.values())


if __name__ == "__main__":
    raise SystemExit(main())
