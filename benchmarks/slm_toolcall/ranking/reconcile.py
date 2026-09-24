"""Reconcile two independent length-controlled AUC rankings. ZERO GPU.

Ranks EVERY arm on a FIXED variable: P(block) for 3-class and dual-head arms, the single
positive scalar for 2-class arms (which is that arm's only block-analogue). No per-arm
variable selection anywhere in this file.

Tests four binning schemes to locate the disagreement, and reports per-bin composition.
"""
from __future__ import annotations
import json, math, sys
from bisect import bisect_left, bisect_right
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, "/home/ubuntu/rescoring-remine")
import remine as H

BASE = Path("/home/ubuntu/cohort-rank")
S2P = BASE / "preds-s2"
OUT = BASE / "out"
DATA = Path("/home/ubuntu/.system-one-data/outputs")
ORACLE = "ORACLE_IN_SAMPLE_UPPER_BOUND_NOT_A_RESULT"
CONTROLS = {"control-modernbert-base", "control-modernbert-large"}
FPR_CAP = 0.00384502

cases = [json.loads(l) for l in (DATA / "s2/cases.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
grades = {str(c["id"]): H.truth_grade(c) for c in cases}
scorable = [cid for cid, g in grades.items() if g in ("A", "B", "D")]
labmap = {cid: grades[cid] in ("A", "B") for cid in scorable}
labels = [labmap[c] for c in scorable]
NPOS, NNEG = sum(labels), len(labels) - sum(labels)


def read(path):
    """max-over-events of the fixed block variable + own input_tokens + corpus length."""
    blk, tok, cby, nev = {}, {}, {}, defaultdict(int)
    shape = None
    for line in path.open(encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        cid = str(r["case_id"])
        p = r.get("probabilities") or {}
        if all(k in p for k in ("disposition.block", "disposition.confirm", "disposition.allow")):
            shape, v = "3class", float(p["disposition.block"])
        elif "block.yes" in p and "confirm.yes" in p:
            shape, v = "dualhead", float(p["block.yes"])
        else:
            k = next(k for k in p if k.endswith((".true", ".yes")))
            shape, v = "2class", float(p[k])
        blk[cid] = max(blk.get(cid, -math.inf), v)
        if isinstance(r.get("input_tokens"), (int, float)):
            tok[cid] = max(tok.get(cid, -math.inf), r["input_tokens"])
        if isinstance(r.get("context_bytes"), (int, float)):
            cby[cid] = max(cby.get(cid, -math.inf), r["context_bytes"])
        nev[cid] += 1
    return blk, tok, cby, dict(nev), shape


def bins_from(lengths, nbins):
    qs = sorted(lengths)
    cuts = [qs[int(len(qs) * (i / nbins))] for i in range(1, nbins)]

    def b(x):
        n = 0
        for c in cuts:
            if x >= c:
                n += 1
        return n
    return b, cuts


def auc_parts(scores, labs):
    """Return (wins+0.5*ties, npos*nneg) so bins can be pooled exactly."""
    pos = [s for s, l in zip(scores, labs) if l]
    neg = sorted(s for s, l in zip(scores, labs) if not l)
    if not pos or not neg:
        return None, 0
    w = t = 0
    for s in pos:
        lo = bisect_left(neg, s)
        w += lo
        t += bisect_right(neg, s) - lo
    return w + 0.5 * t, len(pos) * len(neg)


def stratified(scores, labs, lengths, bucket, nbins):
    per, num, den, simple = {}, 0.0, 0, []
    for b in range(nbins):
        idx = [i for i in range(len(scores)) if bucket(lengths[i]) == b]
        ss = [scores[i] for i in idx]
        ll = [labs[i] for i in idx]
        n, d = auc_parts(ss, ll)
        a = (n / d) if d else None
        per[f"q{b}"] = {"cases": len(idx), "positives": sum(ll), "negatives": len(ll) - sum(ll),
                        "auc": a, "comparable_pairs": d,
                        "length_range": [min(lengths[i] for i in idx), max(lengths[i] for i in idx)] if idx else None}
        if d:
            num += n
            den += d
            simple.append(a)
    return {
        "unweighted_mean_within_bin": (sum(simple) / len(simple)) if simple else None,
        "pair_weighted_pooled": (num / den) if den else None,
        "bins_with_defined_auc": len(simple),
        "per_bin": per,
    }


# ---- corpus length from the control (cap 6144, shrunk 0 -> untruncated)
cblk, ctok, ccby, cnev, _ = read(S2P / "control-modernbert-base.jsonl")
CORPUS_LEN = [ctok[c] for c in scorable]

arms = sorted(p.stem for p in S2P.glob("*.jsonl"))
res = {}
for a in arms:
    blk, tok, cby, nev, shape = read(S2P / f"{a}.jsonl")
    s = [blk[c] for c in scorable]
    own = [tok[c] for c in scorable]
    pts, _, _ = H.sweep(s, labels)
    bp = H.best_point(pts)
    cap = H.at_fpr_cap(pts, FPR_CAP, NNEG)
    zfp = H.zero_fp_point(pts, NPOS, NNEG)
    e = {"shape": shape, "variable": "P(block) [3class/dualhead] or single positive scalar [2class]",
         "auc_raw": H.mann_whitney_auc(s, labels),
         "is_control": a in CONTROLS,
         "oracle_best_f1_" + ORACLE: bp["f1"],
         "at_fpr_cap_0.00384502": {k: cap.get(k) for k in
                                   ("attainable", "max_false_positives_allowed", "threshold",
                                    "tp", "fp", "fn", "tn", "f1", "precision", "recall", "fpr")},
         "zero_fp_gate": {k: zfp.get(k) for k in
                          ("attainable", "threshold", "tp", "fp", "fn", "tn", "f1", "recall")},
         }
    # scheme A: common corpus length, 5 bins  (my published method)
    b5, cuts5 = bins_from(CORPUS_LEN, 5)
    A = stratified(s, labels, CORPUS_LEN, b5, 5)
    e["A_common_corpus_length_quintiles"] = A
    e["A_cuts"] = cuts5
    # scheme B: the arm's OWN input_tokens (post-shrink for capped arms), 5 bins
    bo, cutso = bins_from(own, 5)
    B = stratified(s, labels, own, bo, 5)
    e["B_own_input_tokens_quintiles"] = {k: v for k, v in B.items() if k != "per_bin"}
    e["B_per_bin"] = B["per_bin"]
    e["B_cuts"] = cutso
    e["own_token_distinct_values"] = len(set(own))
    # scheme C: common length, 10 bins
    b10, _ = bins_from(CORPUS_LEN, 10)
    e["C_common_length_deciles"] = {k: v for k, v in stratified(s, labels, CORPUS_LEN, b10, 10).items()
                                    if k != "per_bin"}
    # scheme D: common length = context_bytes (model independent), 5 bins
    ccb = [ccby[c] for c in scorable]
    bcb, _ = bins_from(ccb, 5)
    e["D_context_bytes_quintiles"] = {k: v for k, v in stratified(s, labels, ccb, bcb, 5).items()
                                      if k != "per_bin"}
    res[a] = e
    print(f"{a:<34} raw={e['auc_raw']:.8f} A={A['unweighted_mean_within_bin']:.8f} "
          f"Apool={A['pair_weighted_pooled']:.8f} B={B['unweighted_mean_within_bin']:.8f}", flush=True)

out = {"fixed_variable_note": (
    "Every arm ranked on ONE fixed variable: P(block) for 3-class and for the dual-head arm "
    "(shieldstral, = block.yes), and the single positive scalar for 2-class arms, which is "
    "those arms' only block-analogue. No per-arm variable selection. P(block)-P(confirm) is "
    "never used."),
    "corpus": {"scorable": len(scorable), "positives_A_B": NPOS, "negatives_D": NNEG},
    "corpus_length_source": ("control-modernbert-base input_tokens, max over events; that arm ran "
                             "cap_tokens 6144 with shrunk == 0 so the value is the untruncated "
                             "natural prompt length. It is a CORPUS property, so scheme A gives "
                             "every arm IDENTICAL bins."),
    "arms": res}

cands = {a: v for a, v in res.items() if not v["is_control"]}
for scheme, path in (("A_common_corpus_length_quintiles", "unweighted_mean_within_bin"),
                     ("A_common_corpus_length_quintiles", "pair_weighted_pooled"),
                     ("B_own_input_tokens_quintiles", "unweighted_mean_within_bin"),
                     ("C_common_length_deciles", "unweighted_mean_within_bin"),
                     ("D_context_bytes_quintiles", "unweighted_mean_within_bin")):
    key = f"{scheme}::{path}"
    r = sorted(cands.items(), key=lambda kv: -(kv[1][scheme][path] or -1))
    out.setdefault("rankings", {})[key] = [{"arm": a, "value": v[scheme][path]} for a, v in r[:8]]

# deployability
out["deployability_at_fpr_cap"] = sorted(
    [{"arm": a, **{k: v["at_fpr_cap_0.00384502"][k] for k in ("f1", "tp", "fp", "recall", "threshold")},
      "is_control": v["is_control"]} for a, v in res.items()],
    key=lambda d: -(d["f1"] or -1))
out["zero_fp_gate_summary"] = {
    "arms_total": len(res), "candidates": len(cands),
    "candidates_with_zero_recall_at_zero_fp_gate": sorted(
        a for a, v in cands.items() if not v["zero_fp_gate"]["tp"]),
    # FIXED 2026-09-24: this list previously held Python repr() strings, which forced
    # consumers to call ast.literal_eval on published data. It now holds real JSON objects.
    "candidates_with_nonzero_recall_at_zero_fp_gate": sorted(
        ({"arm": a, "tp": v["zero_fp_gate"]["tp"], "recall": v["zero_fp_gate"]["recall"],
          "threshold": v["zero_fp_gate"]["threshold"], "f1": v["zero_fp_gate"]["f1"]}
         for a, v in cands.items() if v["zero_fp_gate"]["tp"]),
        key=lambda d: (-(d["tp"] or 0), d["arm"])),
    "schema_note": (
        "candidates_with_nonzero_recall_at_zero_fp_gate is a LIST OF JSON OBJECTS. It "
        "previously stored Python repr() strings, which forced consumers to call "
        "ast.literal_eval on published data. Fixed 2026-09-24; no consumer should ever "
        "need ast.literal_eval on anything in this file."),
    "note": "zero-FP gates are NOT durable; reported only to answer the deployability question",
}
(OUT / "reconcile.json").write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
print("wrote", OUT / "reconcile.json")
