"""Leakage / surface-cue diagnostic for the negative controls. ZERO GPU, read-only."""
import json, math, sys
from collections import Counter, defaultdict
from pathlib import Path
sys.path.insert(0, "/home/ubuntu/rescoring-remine")
import remine as H

DATA = Path("/home/ubuntu/.system-one-data/outputs")
COHORT = Path("/home/ubuntu/cohort-scoring/preds")
cases = [json.loads(l) for l in (DATA / "s2/cases.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
grades = {str(c["id"]): H.truth_grade(c) for c in cases}
scorable = [cid for cid, g in grades.items() if g in ("A", "B", "D")]
lab = {c: grades[c] in ("A", "B") for c in scorable}
labels = [lab[c] for c in scorable]

def agg_max(path, key):
    out = {}
    per = defaultdict(list)
    for line in open(path):
        r = json.loads(line)
        cid = str(r["case_id"])
        v = r[key] if key in r else float(r["probabilities"][
            [k for k in r["probabilities"] if k.endswith((".true", ".yes"))][0]])
        out[cid] = max(out.get(cid, -math.inf), v)
        per[cid].append(v)
    return out, per

report = {}

# ---- 1. pure structural cues: how much of the label is predictable from LENGTH alone?
ctrl = COHORT / "control-modernbert-base.jsonl"
tok_max, tok_per = agg_max(ctrl, "input_tokens")
byt_max, _ = agg_max(ctrl, "context_bytes")
evt_max, _ = agg_max(ctrl, "context_events")
tok_sum = {c: sum(v) for c, v in tok_per.items()}
cues = {
    "natural_prompt_tokens (max over events)": [tok_max[c] for c in scorable],
    "natural_prompt_tokens (sum over events)": [tok_sum[c] for c in scorable],
    "context_bytes (max over events)": [byt_max[c] for c in scorable],
    "context_events": [evt_max[c] for c in scorable],
    "event_count_in_prediction": [len(tok_per[c]) for c in scorable],
}
report["structural_cue_auc"] = {}
for n, s in cues.items():
    pts, npos, nneg = H.sweep(s, labels)
    bp = H.best_point(pts)
    report["structural_cue_auc"][n] = {
        "auc": H.mann_whitney_auc(s, labels),
        "best_f1_ORACLE": bp["f1"], "at_threshold": bp["threshold"],
        "tp": bp["tp"], "fp": bp["fp"], "fn": bp["fn"], "tn": bp["tn"],
    }

# ---- 2. the controls' own scores vs length
report["controls"] = {}
for arm in ("control-modernbert-base", "control-modernbert-large", "deberta-v3-prompt-injection-v2"):
    sc_max, _ = agg_max(COHORT / f"{arm}.jsonl", "__score__")
    s = [sc_max[c] for c in scorable]
    t = [tok_max[c] for c in scorable]
    # Spearman between the arm's score and natural prompt length
    def rank(v):
        order = sorted(range(len(v)), key=lambda i: v[i])
        r = [0.0] * len(v); i = 0
        while i < len(order):
            j = i
            while j < len(order) and v[order[j]] == v[order[i]]: j += 1
            avg = (i + j - 1) / 2 + 1
            for k in range(i, j): r[order[k]] = avg
            i = j
        return r
    rs, rt = rank(s), rank(t)
    n = len(rs); ms = sum(rs) / n; mt = sum(rt) / n
    num = sum((a - ms) * (b - mt) for a, b in zip(rs, rt))
    den = math.sqrt(sum((a - ms) ** 2 for a in rs) * sum((b - mt) ** 2 for b in rt))
    ent = {"auc_overall": H.mann_whitney_auc(s, labels),
           "spearman_score_vs_natural_prompt_length": num / den if den else None}
    # AUC inside length strata (quintiles of natural prompt length) -> removes the length cue
    qs = sorted(t); cuts = [qs[int(len(qs) * f)] for f in (0.2, 0.4, 0.6, 0.8)]
    def bucket(x):
        b = 0
        for c in cuts:
            if x >= c: b += 1
        return b
    strata = {}
    for b in range(5):
        idx = [i for i in range(len(s)) if bucket(t[i]) == b]
        ss = [s[i] for i in idx]; ll = [labels[i] for i in idx]
        strata[f"length_quintile_{b}"] = {
            "cases": len(idx), "positives": sum(ll),
            "auc": H.mann_whitney_auc(ss, ll),
            "token_range": [min(t[i] for i in idx), max(t[i] for i in idx)] if idx else None}
    ent["auc_within_length_quintile"] = strata
    aucs = [v["auc"] for v in strata.values() if v["auc"] is not None]
    ent["mean_within_stratum_auc"] = sum(aucs) / len(aucs) if aucs else None
    report["controls"][arm] = ent

# ---- 3. do the two controls agree with each other? real leakage would be found by both
b_max, _ = agg_max(COHORT / "control-modernbert-base.jsonl", "__score__")
l_max, _ = agg_max(COHORT / "control-modernbert-large.jsonl", "__score__")
sb = [b_max[c] for c in scorable]; sl = [l_max[c] for c in scorable]
mb = sum(sb) / len(sb); ml = sum(sl) / len(sl)
num = sum((a - mb) * (b - ml) for a, b in zip(sb, sl))
den = math.sqrt(sum((a - mb) ** 2 for a in sb) * sum((b - ml) ** 2 for b in sl))
report["controls_agree_with_each_other"] = {
    "pearson_base_vs_large": num / den if den else None,
    "base_auc": H.mann_whitney_auc(sb, labels), "large_auc": H.mann_whitney_auc(sl, labels),
    "note": ("a genuine corpus-level label leak would be visible to BOTH untrained backbones "
             "in the same direction; divergence points at idiosyncratic readout behaviour"),
}
# ---- 4. score dispersion: is the control actually discriminating, or nearly constant?
for arm, s in (("control-modernbert-base", sb), ("control-modernbert-large", sl)):
    srt = sorted(s)
    report["controls"][arm]["score_distribution"] = {
        "min": srt[0], "p05": srt[int(.05 * len(srt))], "median": srt[len(srt) // 2],
        "p95": srt[int(.95 * len(srt))], "max": srt[-1],
        "distinct_values": len(set(s)),
        "interquartile_width": srt[int(.75 * len(srt))] - srt[int(.25 * len(srt))]}
print(json.dumps(report, indent=2, sort_keys=True))
Path("/home/ubuntu/cohort-scoring/leakage-diagnostic.json").write_text(
    json.dumps(report, indent=2, sort_keys=True) + "\n")
