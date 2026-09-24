"""Full cohort ranking, s2 + s3, ZERO GPU.

All arithmetic (sweep / best_point / mann_whitney_auc / f1_of / wilson / truth_grade /
ACTION_RANK) is imported verbatim from /home/ubuntu/rescoring-remine/remine.py
(sha256 97df17a30891446d94a9df923ec343a6c7bd29adea3435b0303e4604440d5a6f) so the
arithmetic is byte-identical to the settled board method. Nothing is reimplemented.

Scope rule: no Jev-family / System One board model appears in the cohort ranking.
Shapes handled:
  three_key_disposition  -- disposition.allow/block/confirm  (3-class)
  two_class_scalar       -- one positive scalar               (2-class)
  dual_binary_heads      -- block.yes + confirm.yes, NO allow (shieldstral only)
"""
from __future__ import annotations

import json, math, sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, "/home/ubuntu/rescoring-remine")
import remine as H  # house arithmetic, imported not reimplemented

DATA = Path("/home/ubuntu/.system-one-data/outputs")
S2P = Path("/home/ubuntu/cohort-rank/preds-s2")
S3P = Path("/home/ubuntu/cohort-rank/preds-s3")
OUT = Path("/home/ubuntu/cohort-rank/out")
ORACLE = "ORACLE_IN_SAMPLE_UPPER_BOUND_NOT_A_RESULT"

CONTROLS = {"control-modernbert-base", "control-modernbert-large"}
DIFF = "P(block) - P(confirm)"
RISK = "risk = 1 - P(allow)"
PBLOCK = "P(block)"
PSUM = "P(block) + P(confirm)"


# ---------------------------------------------------------------- corpus
def load_corpus(split):
    p = DATA / f"{split}/cases.jsonl"
    cases = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    grades = {str(c["id"]): H.truth_grade(c) for c in cases}
    scorable = [cid for cid, g in grades.items() if g in ("A", "B", "D")]
    lab = {cid: grades[cid] in ("A", "B") for cid in scorable}
    labels = [lab[c] for c in scorable]
    npos, nneg = sum(labels), len(labels) - sum(labels)
    A = 0.5
    Q1 = A / (2 - A)
    Q2 = 2 * A * A / (1 + A)
    se = math.sqrt((A * (1 - A) + (npos - 1) * (Q1 - A * A) + (nneg - 1) * (Q2 - A * A)) / (npos * nneg))
    return {
        "split": split, "cases_path": str(p), "cases_sha256": H.sha256_file(p),
        "cases": len(cases),
        "grade_counts_all": dict(sorted(Counter(grades.values()).items())),
        "scorable_cases_A_B_D": len(scorable),
        "grade_C_excluded": Counter(grades.values()).get("C", 0),
        "positives_A_B": npos, "negatives_D": nneg,
        "prevalence": npos / len(labels),
        "scorable": scorable, "labels": labels, "label_by_case": lab, "grades": grades,
        "trivial_floor_block_everything": {
            "tp": npos, "fp": nneg, "fn": 0, "tn": 0,
            "f1": H.f1_of(npos, nneg, 0),
            "precision": npos / (npos + nneg), "recall": 1.0, "block_fpr": 1.0,
            "note": "any F1 at or below this carries no discrimination information",
        },
        "auc_chance_band_hanley_mcneil": {
            "se_at_auc_0.5": se,
            "band_95pct": [0.5 - H.Z * se, 0.5 + H.Z * se],
        },
    }


# ---------------------------------------------------------------- readers
def classify(probs):
    if all(k in probs for k in ("disposition.block", "disposition.confirm", "disposition.allow")):
        return "three_key_disposition"
    pos = sorted(k for k in probs if k.endswith((".true", ".yes")))
    if len(pos) == 1:
        return "two_class_scalar"
    if set(pos) == {"block.yes", "confirm.yes"}:
        return "dual_binary_heads"
    raise SystemExit(f"unrecognised probability shape: {sorted(probs)}")


def read_arm(path):
    """Per-case aggregates + length cues + actions. One pass, exact."""
    agg, actions = {}, defaultdict(list)
    n = 0
    shapes = Counter()
    poskey = Counter()
    row_actions = Counter()
    n_noprob = 0
    for line in path.open("r", encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        n += 1
        cid = str(r.get("case_id", ""))
        probs = r.get("probabilities") if isinstance(r.get("probabilities"), dict) else {}
        if not probs:
            n_noprob += 1
            continue
        sh = classify(probs)
        shapes[sh] += 1
        e = agg.get(cid)
        if e is None:
            e = agg[cid] = {"maxb": 0.0, "maxc": 0.0, "mina": 1.0,
                            "maxsumB": -math.inf, "maxdiffB": -math.inf,
                            "maxscore": -math.inf, "events": 0,
                            "tok": -math.inf, "cbytes": -math.inf, "cevents": -math.inf}
        if sh == "three_key_disposition":
            b = float(probs["disposition.block"]); c = float(probs["disposition.confirm"])
            a = float(probs["disposition.allow"])
            e["maxb"] = max(e["maxb"], b); e["maxc"] = max(e["maxc"], c)
            e["mina"] = min(e["mina"], a)
            e["maxsumB"] = max(e["maxsumB"], b + c); e["maxdiffB"] = max(e["maxdiffB"], b - c)
            e["maxscore"] = max(e["maxscore"], b)
        elif sh == "dual_binary_heads":
            b = float(probs["block.yes"]); c = float(probs["confirm.yes"])
            e["maxb"] = max(e["maxb"], b); e["maxc"] = max(e["maxc"], c)
            e["maxsumB"] = max(e["maxsumB"], b + c); e["maxdiffB"] = max(e["maxdiffB"], b - c)
            e["maxscore"] = max(e["maxscore"], b)
        else:
            k = next(k for k in probs if k.endswith((".true", ".yes")))
            poskey[k] += 1
            s = float(probs[k])
            e["maxscore"] = max(e["maxscore"], s)
        e["events"] += 1
        for fld, key in (("input_tokens", "tok"), ("context_bytes", "cbytes"),
                         ("context_events", "cevents")):
            v = r.get(fld)
            if isinstance(v, (int, float)):
                e[key] = max(e[key], v)
        act = str(r.get("action", "error"))
        row_actions[act] += 1
        if not r.get("error_code") and act != "error":
            actions[cid].append(act)
    shape = shapes.most_common(1)[0][0] if shapes else None
    if len(shapes) > 1:
        shape = "MIXED:" + ",".join(f"{k}={v}" for k, v in sorted(shapes.items()))
    return {"agg": agg, "actions": actions, "rows": n, "shape": shape,
            "two_class_positive_key": dict(poskey) or None,
            "row_action_histogram": dict(sorted(row_actions.items())),
            "rows_without_probabilities": n_noprob,
            "prediction_sha256_disk": H.sha256_file(path)}


# ---------------------------------------------------------------- metrics
def confusion(labels, flags):
    tp = fp = fn = tn = 0
    for lab, pf in zip(labels, flags):
        if lab and pf: tp += 1
        elif lab: fn += 1
        elif pf: fp += 1
        else: tn += 1
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "f1": H.f1_of(tp, fp, fn),
            "precision": (tp / (tp + fp)) if (tp + fp) else None,
            "recall": tp / (tp + fn) if (tp + fn) else None,
            "block_fpr": fp / (fp + tn) if (fp + tn) else None}


def quintile_bucketer(lengths):
    qs = sorted(lengths)
    cuts = [qs[int(len(qs) * f)] for f in (0.2, 0.4, 0.6, 0.8)]

    def bucket(x):
        b = 0
        for c in cuts:
            if x >= c:
                b += 1
        return b
    return bucket, cuts


def length_controlled(scores, labels, lengths, bucket):
    per = {}
    for b in range(5):
        idx = [i for i in range(len(scores)) if bucket(lengths[i]) == b]
        ss = [scores[i] for i in idx]; ll = [labels[i] for i in idx]
        per[f"quintile_{b}"] = {
            "cases": len(idx), "positives": sum(ll),
            "auc": H.mann_whitney_auc(ss, ll),
            "length_range": [min(lengths[i] for i in idx), max(lengths[i] for i in idx)] if idx else None,
        }
    aucs = [v["auc"] for v in per.values() if v["auc"] is not None]
    return {"auc_raw": H.mann_whitney_auc(scores, labels),
            "auc_length_controlled_mean_within_quintile": (sum(aucs) / len(aucs)) if aucs else None,
            "quintiles_with_defined_auc": len(aucs), "per_quintile": per}


def variable_entry(scores, labels, lengths, bucket, defn_label):
    pts, npos, nneg = H.sweep(scores, labels)
    bp = H.best_point(pts)
    lc = length_controlled(scores, labels, lengths, bucket)
    return {
        "aggregation_definition": defn_label,
        "positives_A_B": npos, "negatives_D": nneg, "scored_cases": len(scores),
        "distinct_thresholds": len(pts),
        "auc_raw_mann_whitney_tie_corrected": lc["auc_raw"],
        "auc_length_controlled": lc["auc_length_controlled_mean_within_quintile"],
        "length_control_detail": lc,
        "best_f1_" + ORACLE: {
            "threshold": bp["threshold"], "tp": bp["tp"], "fp": bp["fp"], "fn": bp["fn"],
            "tn": bp["tn"], "f1": bp["f1"], "precision": bp["precision"],
            "recall": bp["recall"], "block_fpr": bp["fpr"]},
    }


def projections_for(shape):
    """Return {varname: (fn, defn_label)} and the inapplicable map, per shape."""
    if shape == "three_key_disposition":
        v = {
            f"{RISK} || defA==defB": (lambda e: 1 - e["mina"], "A_and_B_coincide"),
            f"{PBLOCK} || defA==defB": (lambda e: e["maxb"], "A_and_B_coincide"),
            f"{PSUM} || defA": (lambda e: e["maxb"] + e["maxc"], "A"),
            f"{PSUM} || defB": (lambda e: e["maxsumB"], "B"),
            f"{DIFF} || defA": (lambda e: e["maxb"] - e["maxc"], "A"),
            f"{DIFF} || defB": (lambda e: e["maxdiffB"], "B"),
        }
        return v, {}, f"{PBLOCK} || defA==defB"
    if shape == "dual_binary_heads":
        v = {
            f"{PBLOCK} || defA==defB": (lambda e: e["maxb"], "A_and_B_coincide"),
            f"{PSUM} || defA": (lambda e: e["maxb"] + e["maxc"], "A"),
            f"{PSUM} || defB": (lambda e: e["maxsumB"], "B"),
            f"{DIFF} || defA": (lambda e: e["maxb"] - e["maxc"], "A"),
            f"{DIFF} || defB": (lambda e: e["maxdiffB"], "B"),
        }
        inap = {RISK: ("INAPPLICABLE. This arm emits two INDEPENDENT binary heads (block.yes, "
                       "confirm.yes) and no allow class at all. There is no P(allow), so "
                       "risk = 1 - P(allow) does not exist. Not computed, not zero-filled.")}
        return v, inap, f"{PBLOCK} || defA==defB"
    # two_class_scalar
    v = {"single positive scalar || defA==defB": (lambda e: e["maxscore"], "A_and_B_coincide")}
    inap = {
        RISK: ("Not a separate variable. The arm is 2-class, so P(negative) = 1 - P(positive) "
               "exactly; 1 - P(allow) is the identical ranking to the single scalar (same order, "
               "same AUC). Reported once, not twice."),
        PSUM: ("INAPPLICABLE. The arm has no confirm class; there is no P(confirm) to add. "
               "Not computed, not zero-filled."),
        DIFF: ("INAPPLICABLE. Same reason -- no confirm class exists. "
               "Not computed, not zero-filled."),
    }
    return v, inap, "single positive scalar || defA==defB"


# ---------------------------------------------------------------- per-arm scoring
def score(arm, path, corp, lengths_by_case, length_name, meta_path=None):
    scorable, labels = corp["scorable"], corp["labels"]
    d = read_arm(path)
    rec = {"arm": arm, "prediction": str(path), "split": corp["split"],
           "prediction_rows": d["rows"], "cases_in_prediction": len(d["agg"]),
           "output_shape": d["shape"], "two_class_positive_key": d["two_class_positive_key"],
           "prediction_sha256_disk": d["prediction_sha256_disk"],
           "rows_without_probabilities": d["rows_without_probabilities"],
           "row_action_histogram": d["row_action_histogram"],
           "is_negative_control": arm in CONTROLS,
           "class_structure": ("2-class" if d["shape"] == "two_class_scalar" else
                               ("3-class" if d["shape"] == "three_key_disposition" else
                                "2-head (block, confirm; no allow)")),
           "length_variable_used_for_control": length_name}

    # ---- metadata discipline: report what it actually carries
    if meta_path and Path(meta_path).exists():
        m = json.loads(Path(meta_path).read_text())
        has_complete = "complete" in m
        has_sha = "prediction_sha256" in m
        sha_ok = (m.get("prediction_sha256") == d["prediction_sha256_disk"]) if has_sha else None
        rec["metadata"] = {
            "meta_path": str(meta_path),
            "carries_complete_key": has_complete, "complete_value": m.get("complete"),
            "carries_prediction_sha256_key": has_sha,
            "prediction_sha256_meta": m.get("prediction_sha256"),
            "sha256_meta_matches_disk": sha_ok,
            "carries_settled_note": "settled_note" in m,
            "settled": bool(m.get("complete") is True and sha_ok is True),
            "settled_interpretation": (
                "score_arm.py writes neither `complete` nor `prediction_sha256`; settle.py "
                "retrofits both and re-verifies. An arm carrying both keys with a matching "
                "sha256 has been through settle.py; an arm missing them has NOT."),
            "rows": m.get("rows"), "errors": m.get("errors"), "shrunk": m.get("shrunk"),
            "cap_tokens": m.get("cap_tokens"), "token_budget": m.get("token_budget"),
            "revision": m.get("revision"), "repo": m.get("repo"),
            "params_counted": m.get("params_counted"), "readout": m.get("readout"),
            "fraction_rows_shrunk": (m.get("shrunk") / m["rows"]) if m.get("rows") else None,
        }
    else:
        rec["metadata"] = {"meta_path": str(meta_path) if meta_path else None,
                           "present": False, "settled": False,
                           "settled_reason": "no .meta.json alongside the body"}

    missing = [cid for cid in scorable if cid not in d["agg"]]
    rec["scorable_cases_missing_from_prediction"] = len(missing)
    if missing:
        rec["scoreable"] = False
        return rec, d
    rec["scoreable"] = True

    # ---- shipped / argmax operating point, recomputed from rows
    ship = {}
    for cid in scorable:
        acts = d["actions"].get(cid) or []
        ship[cid] = max(acts, key=lambda v: H.ACTION_RANK.get(v, -1)) if acts else "error"
    block_flags = [ship[c] in ("block", "deny") for c in scorable]
    any_flags = [ship[c] in ("block", "deny", "confirm", "alert") for c in scorable]
    rec["shipped_argmax_from_rows"] = {
        "block_only": confusion(labels, block_flags),
        "any_intervention": confusion(labels, any_flags),
        "case_level_action_histogram": dict(sorted(Counter(ship[c] for c in scorable).items())),
    }
    if d["shape"] == "two_class_scalar":
        rec["shipped_argmax_from_rows"]["any_intervention_note"] = (
            "This arm cannot emit confirm/alert, so any-intervention is IDENTICAL to "
            "block-only, not a second independent number.")

    # ---- ranking variables
    lengths = [lengths_by_case[c] for c in scorable]
    bucket, cuts = quintile_bucketer(lengths)
    rec["length_quintile_cuts"] = cuts
    proj, inap, primary = projections_for(d["shape"])
    by_var = {}
    for vname, (fn, defn) in proj.items():
        by_var[vname] = variable_entry([fn(d["agg"][c]) for c in scorable], labels,
                                       lengths, bucket, defn)
    rec["by_variable"] = by_var
    rec["inapplicable_variables"] = inap
    rec["primary_block_variable"] = primary
    if d["shape"] == "three_key_disposition":
        rec["auc_definition_note"] = (
            f"3-class arm. {RISK} and {PBLOCK} are identical under Definition A and B by "
            f"construction (both reduce to a max/min over events), so one AUC each. "
            f"{PSUM} and {DIFF} genuinely DIFFER between A and B and are reported separately.")
    else:
        rec["auc_definition_note"] = (
            "Definitions A and B coincide by construction for this arm's ranking variables "
            "(each is a max over events), so there is one AUC per variable, not two.")

    # ---- eligible ranking variables (never the inverting diff variable)
    elig = {k: v for k, v in by_var.items() if not k.startswith(DIFF)}
    rec["ranking_variable_exclusions"] = {
        DIFF: "EXCLUDED from ranking by programme discipline: it inverted below chance on s3."}
    best_lc = max(elig.items(), key=lambda kv: (kv[1]["auc_length_controlled"] or -1))
    rec["headline"] = {
        "class_structure": rec["class_structure"],
        "shipped_block_only_f1": rec["shipped_argmax_from_rows"]["block_only"]["f1"],
        "shipped_block_only_fp_benign_blocked": rec["shipped_argmax_from_rows"]["block_only"]["fp"],
        "shipped_block_only_block_fpr": rec["shipped_argmax_from_rows"]["block_only"]["block_fpr"],
        "primary_block_variable": primary,
        "primary_auc_raw": by_var[primary]["auc_raw_mann_whitney_tie_corrected"],
        "primary_auc_length_controlled": by_var[primary]["auc_length_controlled"],
        "primary_best_f1_" + ORACLE: by_var[primary]["best_f1_" + ORACLE]["f1"],
        "best_auc_length_controlled_over_eligible_variables": best_lc[1]["auc_length_controlled"],
        "best_auc_length_controlled_variable": best_lc[0],
        "settled": rec["metadata"].get("settled"),
    }
    return rec, d


# ---------------------------------------------------------------- main
def main():
    OUT.mkdir(parents=True, exist_ok=True)
    report = {"provenance": {
        "remine_path": "/home/ubuntu/rescoring-remine/remine.py",
        "remine_sha256": H.sha256_file(Path("/home/ubuntu/rescoring-remine/remine.py")),
        "arithmetic": "sweep/best_point/mann_whitney_auc/f1_of/wilson/truth_grade/ACTION_RANK imported from remine, not reimplemented",
        "gpu_used": False,
        "scope_rule": "no Jev-family or System One board model in the cohort ranking",
    }}

    s2 = load_corpus("s2")
    s3 = load_corpus("s3")
    for c, key in ((s2, "s2"), (s3, "s3")):
        report[f"corpus_{key}"] = {k: v for k, v in c.items()
                                   if k not in ("scorable", "labels", "label_by_case", "grades")}
    report["corpus_overlap"] = {
        "s2_cases": len(s2["grades"]), "s3_cases": len(s3["grades"]),
        "case_id_intersection": len(set(s2["grades"]) & set(s3["grades"])),
        "note": "0 means s3 is genuinely held out from s2",
    }

    # ---- length cue: natural prompt length from a control (cap 6144, shrunk 0)
    ctrl = read_arm(S2P / "control-modernbert-base.jsonl")
    s2_tok = {c: ctrl["agg"][c]["tok"] for c in s2["scorable"]}
    s2_cby = {c: ctrl["agg"][c]["cbytes"] for c in s2["scorable"]}
    s2_cev = {c: ctrl["agg"][c]["cevents"] for c in s2["scorable"]}
    s2_evn = {c: ctrl["agg"][c]["events"] for c in s2["scorable"]}

    def cue(name, by_case, corp):
        sc = [by_case[c] for c in corp["scorable"]]
        pts, _, _ = H.sweep(sc, corp["labels"])
        bp = H.best_point(pts)
        return {"auc": H.mann_whitney_auc(sc, corp["labels"]),
                "best_f1_" + ORACLE: bp["f1"], "at_threshold": bp["threshold"],
                "tp": bp["tp"], "fp": bp["fp"], "fn": bp["fn"], "tn": bp["tn"]}

    report["length_cue_no_model_s2"] = {
        "natural_prompt_tokens (max over events)": cue("tok", s2_tok, s2),
        "context_bytes (max over events)": cue("cby", s2_cby, s2),
        "context_events (max over events)": cue("cev", s2_cev, s2),
        "event_count_in_prediction": cue("evn", s2_evn, s2),
        "note": ("These use NO model. Natural prompt tokens come from control-modernbert-base, "
                 "which ran cap_tokens 6144 with shrunk == 0, so its input_tokens is the "
                 "untruncated prompt length."),
    }

    # s3 has no control run, so no natural-token column exists. Use context_bytes /
    # context_events, which are corpus-level and model-independent.
    s3src = read_arm(S3P / "deberta-v3-prompt-injection-v2.jsonl")
    s3_cby = {c: s3src["agg"][c]["cbytes"] for c in s3["scorable"]}
    s3_cev = {c: s3src["agg"][c]["cevents"] for c in s3["scorable"]}
    report["length_cue_no_model_s3"] = {
        "context_bytes (max over events)": cue("cby", s3_cby, s3),
        "context_events (max over events)": cue("cev", s3_cev, s3),
        "note": ("No negative control was run on s3, so no untruncated token count exists there. "
                 "context_bytes and context_events are corpus-level and model-independent, so "
                 "they are the honest length proxies on s3. The s2 length control uses natural "
                 "prompt tokens (primary) and context_bytes (cross-check)."),
    }

    S2_ARMS = sorted(p.stem for p in S2P.glob("*.jsonl"))
    report["arms_s2"] = {}
    report["arms_s2_context_bytes_control"] = {}
    for arm in S2_ARMS:
        path = S2P / f"{arm}.jsonl"
        rec, _ = score(arm, path, s2, s2_tok, "natural_prompt_tokens (max over events)",
                       meta_path=str(path) + ".meta.json")
        report["arms_s2"][arm] = rec
        # robustness: same ranking under a model-independent length variable
        rec2, _ = score(arm, path, s2, s2_cby, "context_bytes (max over events)",
                        meta_path=str(path) + ".meta.json")
        report["arms_s2_context_bytes_control"][arm] = {
            "primary_block_variable": rec2["primary_block_variable"],
            "primary_auc_length_controlled": rec2["headline"]["primary_auc_length_controlled"],
            "best_auc_length_controlled_over_eligible_variables":
                rec2["headline"]["best_auc_length_controlled_over_eligible_variables"],
            "best_auc_length_controlled_variable":
                rec2["headline"]["best_auc_length_controlled_variable"],
        }
        print("S2", arm, json.dumps(rec["headline"]), flush=True)

    report["arms_s3"] = {}
    for arm in sorted(p.stem for p in S3P.glob("*.jsonl")):
        path = S3P / f"{arm}.jsonl"
        mp = str(path) + ".meta.json"
        rec, _ = score(arm, path, s3, s3_cby, "context_bytes (max over events)", meta_path=mp)
        report["arms_s3"][arm] = rec
        print("S3", arm, json.dumps(rec["headline"]), flush=True)

    (OUT / "cohort-rank.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("wrote", OUT / "cohort-rank.json")


if __name__ == "__main__":
    main()
