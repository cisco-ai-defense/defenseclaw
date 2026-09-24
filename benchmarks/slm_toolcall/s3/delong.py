"""DeLong variance / covariance for correlated ROC AUCs, in pure Python.

This host has no numpy, so the structure ("placement") functions are computed with
bisect against sorted arrays.  That kernel is exactly the tie-corrected psi used by
remine.mann_whitney_auc, so the AUC recovered here equals the house AUC bit for bit --
score_s3.py asserts that rather than assuming it.

Reference: DeLong, DeLong & Clarke-Pearson (1988), with the fast placement-value form
of Sun & Xu (2014).

    psi(x, y) = 1 if x > y, 0.5 if x == y, 0 otherwise
    V10[i]    = (1/n) sum_j psi(x_i, y_j)        i over the m positives
    V01[j]    = (1/m) sum_i psi(x_i, y_j)        j over the n negatives
    AUC       = mean(V10) = mean(V01)
    S10       = cov(V10, V10)   (sample covariance, ddof=1, over positives)
    S01       = cov(V01, V01)   (over negatives)
    var(AUC)  = S10/m + S01/n

For two AUCs on the SAME cases the two sets of placement values are paired, so the
covariance of the difference is exact:

    var(A - B) = (S10_AA - 2 S10_AB + S10_BB)/m + (S01_AA - 2 S01_AB + S01_BB)/n
"""
from __future__ import annotations

import math
import random
from bisect import bisect_left, bisect_right

Z = 1.959963984540054  # same constant as remine.Z


def normal_cdf(z: float) -> float:
    return 0.5 * (1.0 + math.erf(z / math.sqrt(2.0)))


def two_sided_p(z: float) -> float:
    return 2.0 * (1.0 - normal_cdf(abs(z)))


def placements(scores, labels):
    """(V10, V01, auc, m, n).  V10 is in positive order, V01 in negative order, both
    following the order of `scores`, so placement vectors from two arms on the same
    corpus are element-wise paired."""
    xs = [s for s, l in zip(scores, labels) if l]
    ys = [s for s, l in zip(scores, labels) if not l]
    m, n = len(xs), len(ys)
    if m == 0 or n == 0:
        raise ValueError("need both classes")
    xsort, ysort = sorted(xs), sorted(ys)
    V10 = []
    for x in xs:
        lo = bisect_left(ysort, x)
        hi = bisect_right(ysort, x)
        V10.append((lo + 0.5 * (hi - lo)) / n)
    V01 = []
    for y in ys:
        lo = bisect_left(xsort, y)
        hi = bisect_right(xsort, y)
        V01.append(((m - hi) + 0.5 * (hi - lo)) / m)
    return V10, V01, sum(V10) / m, m, n


def _cov(a, b) -> float:
    k = len(a)
    if k < 2:
        return 0.0
    ma = sum(a) / k
    mb = sum(b) / k
    return sum((x - ma) * (y - mb) for x, y in zip(a, b)) / (k - 1)


def auc_ci(scores, labels, z: float = Z):
    """DeLong AUC, variance, and both a Wald and a logit-transformed 95% CI.

    The logit interval is reported because a Wald interval on an AUC near 1 can exceed
    1; the logit one cannot, and is the honest interval for the high-AUC arms."""
    V10, V01, auc, m, n = placements(scores, labels)
    auc_from_neg = sum(V01) / n
    S10 = _cov(V10, V10)
    S01 = _cov(V01, V01)
    var = S10 / m + S01 / n
    se = math.sqrt(var) if var > 0 else 0.0
    out = {
        "auc": auc,
        "auc_recovered_from_negative_placements": auc_from_neg,
        "auc_identity_abs_delta": abs(auc - auc_from_neg),
        "positives_m": m, "negatives_n": n,
        "delong_S10": S10, "delong_S01": S01,
        "delong_var": var, "delong_se": se,
        "ci95_wald": [auc - z * se, auc + z * se],
        "z_vs_chance_0.5": ((auc - 0.5) / se) if se > 0 else None,
    }
    out["p_two_sided_vs_chance_0.5"] = (two_sided_p(out["z_vs_chance_0.5"])
                                       if out["z_vs_chance_0.5"] is not None else None)
    if 0.0 < auc < 1.0 and se > 0:
        lo_l = math.log(auc / (1 - auc)) - z * se / (auc * (1 - auc))
        hi_l = math.log(auc / (1 - auc)) + z * se / (auc * (1 - auc))
        out["ci95_logit"] = [1 / (1 + math.exp(-lo_l)), 1 / (1 + math.exp(-hi_l))]
    else:
        out["ci95_logit"] = None
    return out


def auc_diff(scores_a, scores_b, labels, z: float = Z):
    """Paired DeLong test for AUC_a - AUC_b on the same cases."""
    A10, A01, aA, m, n = placements(scores_a, labels)
    B10, B01, aB, m2, n2 = placements(scores_b, labels)
    assert (m, n) == (m2, n2)
    s10 = _cov(A10, A10) - 2 * _cov(A10, B10) + _cov(B10, B10)
    s01 = _cov(A01, A01) - 2 * _cov(A01, B01) + _cov(B01, B01)
    var = s10 / m + s01 / n
    diff = aA - aB
    se = math.sqrt(var) if var > 0 else 0.0
    zz = (diff / se) if se > 0 else None
    out = {
        "auc_a": aA, "auc_b": aB, "auc_difference": diff,
        "positives_m": m, "negatives_n": n,
        "var_of_difference": var, "se_of_difference": se,
        "z": zz, "p_two_sided": (two_sided_p(zz) if zz is not None else None),
        "ci95_of_difference": [diff - z * se, diff + z * se],
        "significant_at_0.05": (abs(zz) > z) if zz is not None else None,
        "correlation_of_placements_positives": (
            _cov(A10, B10) / math.sqrt(_cov(A10, A10) * _cov(B10, B10))
            if _cov(A10, A10) > 0 and _cov(B10, B10) > 0 else None),
        "correlation_of_placements_negatives": (
            _cov(A01, B01) / math.sqrt(_cov(A01, A01) * _cov(B01, B01))
            if _cov(A01, A01) > 0 and _cov(B01, B01) > 0 else None),
    }
    # ---- how much corpus this difference needs, and what the corpus can resolve
    out["sample_size_to_significance"] = _needed(diff, s10, s01, m, n, z)
    if se > 0:
        # the smallest AUC gap this corpus could have called significant, holding the
        # placement covariance structure fixed
        out["minimum_detectable_auc_difference_at_this_corpus"] = z * se
        out["observed_difference_as_multiple_of_the_minimum_detectable"] = abs(diff) / (z * se)
        out["already_significant_so_no_extra_corpus_is_required"] = abs(zz) > z
        k = out["sample_size_to_significance"].get("proportional_growth", {}).get(
            "k_multiplier_on_whole_corpus")
        if k is not None and k < 1:
            out["sample_size_to_significance"]["interpretation"] = (
                "k < 1 means this gap was ALREADY significant and would still have been "
                "significant on a corpus %.4fx this size -- about %d positives instead of "
                "%d.  The figure is HEADROOM, not a shortfall." % (k, math.ceil(m * k), m))
        elif k is not None:
            out["sample_size_to_significance"]["interpretation"] = (
                "k > 1 means this gap is NOT resolvable at %d positives and would need "
                "about %d." % (m, math.ceil(m * k)))
    return out


def _needed(diff, s10, s01, m, n, z):
    """Two scalings of the corpus that would make |diff| reach significance."""
    res = {
        "s10_of_difference": s10, "s01_of_difference": s01,
        "note": ("var(diff) = s10/m + s01/n.  Scaling the whole corpus by k scales both "
                 "m and n by k, so var scales as 1/k and |z| as sqrt(k).  Holding the "
                 "benign count fixed and adding only positives has a variance FLOOR of "
                 "s01/n, which caps the attainable |z| no matter how many positives are "
                 "added."),
    }
    var = s10 / m + s01 / n
    if var <= 0 or diff == 0:
        res["attainable"] = False
        res["reason"] = "zero variance or zero difference"
        return res
    zobs = abs(diff) / math.sqrt(var)
    res["z_observed"] = zobs
    # (a) proportional growth of the whole corpus, prevalence preserved
    k = (z / zobs) ** 2
    res["proportional_growth"] = {
        "k_multiplier_on_whole_corpus": k,
        "positives_needed": 221 * k if m == 221 else m * k,
        "positives_needed_ceiling": math.ceil(m * k),
        "benign_needed_ceiling": math.ceil(n * k),
        "total_cases_needed_ceiling": math.ceil((m + n) * k),
    }
    # (b) add positives only, benign held at n
    floor_var = s01 / n
    max_z_positives_only = abs(diff) / math.sqrt(floor_var) if floor_var > 0 else None
    res["positives_only_growth"] = {
        "variance_floor_from_benign_s01_over_n": floor_var,
        "max_attainable_abs_z_with_infinite_positives": max_z_positives_only,
        "attainable_by_adding_positives_alone": (max_z_positives_only is not None
                                                 and max_z_positives_only > z),
    }
    target = diff * diff / (z * z) - floor_var
    if target > 0:
        res["positives_only_growth"]["positives_needed"] = s10 / target
        res["positives_only_growth"]["positives_needed_ceiling"] = math.ceil(s10 / target)
    else:
        res["positives_only_growth"]["positives_needed"] = None
        res["positives_only_growth"]["why_not"] = (
            "the benign term s01/n alone already exceeds the variance that significance "
            "requires, so no number of extra positives suffices at this benign count")
    return res


def bootstrap_auc_ci(scores, labels, reps=1000, seed=20260924, z=Z):
    """Stratified (class-preserving) bootstrap CI, as an independent cross-check on the
    DeLong interval.  Positives and negatives are resampled with replacement within
    class, so the positive count is held at its observed value in every replicate."""
    xs = [s for s, l in zip(scores, labels) if l]
    ys = [s for s, l in zip(scores, labels) if not l]
    m, n = len(xs), len(ys)
    rnd = random.Random(seed)
    aucs = []
    for _ in range(reps):
        bx = [xs[rnd.randrange(m)] for _ in range(m)]
        by = sorted(ys[rnd.randrange(n)] for _ in range(n))
        wins = ties = 0
        for v in bx:
            lo = bisect_left(by, v)
            hi = bisect_right(by, v)
            wins += lo
            ties += hi - lo
        aucs.append((wins + 0.5 * ties) / (m * n))
    aucs.sort()

    def q(p):
        i = p * (len(aucs) - 1)
        lo = int(math.floor(i))
        hi = min(lo + 1, len(aucs) - 1)
        return aucs[lo] + (i - lo) * (aucs[hi] - aucs[lo])

    mean = sum(aucs) / len(aucs)
    sd = math.sqrt(sum((a - mean) ** 2 for a in aucs) / (len(aucs) - 1))
    return {"reps": reps, "seed": seed, "method": "stratified percentile bootstrap",
            "mean": mean, "sd": sd,
            "ci95_percentile": [q(0.025), q(0.975)],
            "median": q(0.5)}


def bootstrap_diff_ci(scores_a, scores_b, labels, reps=1000, seed=20260924):
    """Paired stratified bootstrap on the AUC difference: the SAME resampled case
    indices are scored under both arms, which preserves the correlation that makes the
    paired comparison so much tighter than two independent intervals."""
    ia = [i for i, l in enumerate(labels) if l]
    ib = [i for i, l in enumerate(labels) if not l]
    m, n = len(ia), len(ib)
    rnd = random.Random(seed)
    diffs = []
    for _ in range(reps):
        px = [ia[rnd.randrange(m)] for _ in range(m)]
        py = [ib[rnd.randrange(n)] for _ in range(n)]
        vals = []
        for sc in (scores_a, scores_b):
            bx = [sc[i] for i in px]
            by = sorted(sc[i] for i in py)
            wins = ties = 0
            for v in bx:
                lo = bisect_left(by, v)
                hi = bisect_right(by, v)
                wins += lo
                ties += hi - lo
            vals.append((wins + 0.5 * ties) / (m * n))
        diffs.append(vals[0] - vals[1])
    diffs.sort()

    def q(p):
        i = p * (len(diffs) - 1)
        lo = int(math.floor(i))
        hi = min(lo + 1, len(diffs) - 1)
        return diffs[lo] + (i - lo) * (diffs[hi] - diffs[lo])

    lo, hi = q(0.025), q(0.975)
    return {"reps": reps, "seed": seed, "method": "paired stratified percentile bootstrap",
            "ci95_percentile": [lo, hi], "median": q(0.5),
            "excludes_zero": (lo > 0 or hi < 0),
            "fraction_of_replicates_with_sign_flip":
                sum(1 for d in diffs if (d < 0) != (diffs[len(diffs) // 2] < 0)) / len(diffs)}
