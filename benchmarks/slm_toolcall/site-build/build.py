#!/usr/bin/env python3
"""Build the DefenseClaw SLM tool-call security Space.

Reads the cohort scoring artifacts on disk plus two pinned primitive files, verifies every
headline figure against its artifact, renders hand-written inline SVG charts and substitutes
them into the page templates. No numpy / matplotlib / pandas: arithmetic and string building.

Conventions are taken from the System One site generator
(benchmarks/system_one/reproduce/08-site-build/build.py) and are the reason the same guard,
verifier and word counter run over this payload unchanged:

  * every drawn SVG element carries its own literal fill / stroke, every text run its own
    font-size, so a chart renders correctly with the stylesheet removed
  * the stylesheet is inlined into every page, because a Space serves subresources from a
    separate request
  * every figure on a page is a key in a dict that was checked against an artifact first
  * no <img>, no <script src>, no external subresource

Abort conditions:
  * any asserted figure disagrees with its artifact              (exit 2)
  * any template token is left unsubstituted                     (exit 3)
  * any axis label would overflow its gutter                     (exit 4)
  * the stylesheet and the chart palette disagree                (exit 5)
  * a chart is built and never placed on a page                  (exit 6)
  * an escaping defect in the generated output                   (exit 7)
  * two drawn labels overlap                                     (exit 8)
  * the Space card's front matter would be rejected on upload     (exit 9)
  * an out-of-scope model or arm is named in the output           (exit 10)
"""

from __future__ import annotations

import hashlib
import html
import json
import math
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.environ.get("SLM_SPACE_OUT", os.path.join(HERE, "site"))
COHORT = os.environ.get("SLM_COHORT", "/home/ubuntu/cohort-scoring")
PAGES = os.path.join(HERE, "pages")
ASSETS = os.path.join(HERE, "assets")
PINNED = os.path.join(HERE, "pinned")

BRANCH = "feat/system-one-benchmarks"
GH = f"https://github.com/cisco-ai-defense/defenseclaw/blob/{BRANCH}"

_TOUCHED: set[str] = set()
_CACHE: dict[str, object] = {}


def load(rel: str, root: str | None = None):
    """Load a JSON artifact and record that it was read."""
    base = root if root is not None else COHORT
    path = os.path.join(base, rel)
    key = path
    if key not in _CACHE:
        with open(path, "r", encoding="utf-8") as fh:
            _CACHE[key] = json.load(fh)
        _TOUCHED.add(path)
    return _CACHE[key]


HARNESS = os.path.abspath(os.path.join(HERE, "..", "harness"))


def load_registry() -> dict:
    """The arm registry, imported from the harness that ran the cohort. Pure data."""
    import importlib.util
    path = os.path.join(HARNESS, "arms.py")
    spec = importlib.util.spec_from_file_location("slm_arms", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    _TOUCHED.add(path)
    return mod.ARMS


def load_manifests() -> dict:
    """Every weight download record, keyed by repo. Carries the on-disk snapshot size and,
    where the download recorded it, the architecture class and position limit."""
    out: dict[str, dict] = {}
    for n in ("weights_manifest.json", "weights_manifest2.json", "weights_manifest3.json",
              "weights_manifest4.json"):
        path = os.path.join(HARNESS, n)
        with open(path, "r", encoding="utf-8") as fh:
            rows = json.load(fh)
        _TOUCHED.add(path)
        for e in rows:
            e = dict(e)
            e["manifest"] = n
            out[e["repo"]] = e
    return out


SCORES = load("cohort-scores.json")
LEAK = load("leakage-diagnostic.json")
FINAL = load("final-comparisons.json")
RANK = load("cohort-rank.json")            # shipped-argmax confusion, 21 arms
AUTH = load("cohort-length-controlled-ranking.json")   # the authoritative ranking, 22 arms
S3 = load("s3-stats.json")                 # the held-out corpus, read for corpus design only
S3C = load("s3-scores-in-scope.json")      # scope-filtered; read for the s3 length cue only
ROSTER = load("roster.json", PINNED)
LAPTOP = load("laptop-feasibility.json", PINNED)
# The full-cohort ranking artifact carries a richer corpus record than the stage-0 scorecards.
# Only the s2 half of it is read: the held-out s3 results are being scored separately and are
# held out of this revision entirely, so touching an s3 key here would put a partial transfer
# story on the page.
S3_KEYS = ("arms_s3", "corpus_s3", "length_cue_no_model_s3", "corpus_overlap")
CORPUS = RANK["corpus_s2"]

# Every arm the scorecards hold, before the scope filter. Jev-family arms and System One board
# arms are out of scope on this Space and are dropped here, not hidden later in the templates.
ALL_ARMS = SCORES["arms"]
ARMS: dict = {}
TRUNC = SCORES["deberta_truncation_analysis"]
PARITY = SCORES["parity_gate"]
TRIVIAL = FINAL["trivial_baselines"]
BAND = FINAL["auc_null_band"]
ALL_LCA = FINAL["length_controlled_auc"]
ALL_HEAD = FINAL["headline_comparisons"]
LCA: dict = {}
HEAD: dict = {}

GIB = 1024 ** 3

SCOPE = ROSTER["scope"]
# Drop the out-of-scope arms and the comparison keys that quote them. Each exclusion is named in
# the overlay, so the set is declared in one place and checked below.
# The vendored artifacts are scope-filtered at vendoring time, so an excluded arm is normally
# already absent. The filter is recorded rather than assumed: the arm must be absent, and if it is
# present the runtime filter below removes it.
for _k in SCOPE["excluded_scorecard_arms"]:
    if _k in ALL_ARMS:
        print(f"note: {_k} present in the artifact and removed at build time as well as at "
              f"vendoring time")
ARMS.update({k: v for k, v in ALL_ARMS.items() if k not in SCOPE["excluded_scorecard_arms"]})
LCA.update({k: v for k, v in ALL_LCA.items() if k not in SCOPE["excluded_lca_keys"]})
HEAD.update({k: v for k, v in ALL_HEAD.items() if k not in SCOPE["excluded_comparison_keys"]})

DEB = ARMS["deberta-v3-prompt-injection-v2"]
CB = ARMS["control-modernbert-base"]
CL = ARMS["control-modernbert-large"]

REGISTRY = load_registry()
MANIFEST = load_manifests()
SCORER = load("scorer-provenance.json", PINNED)
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_roster() -> list[dict]:
    """One row per registry arm, every field derived from the registry or a manifest."""
    rows = []
    for key, a in REGISTRY.items():
        lic = a["licence"]
        # the registry writes the gating marker into the licence string; split it back out
        gated = bool(a.get("gated"))
        licence = lic.split(" (")[0]
        licence_name = None
        if lic.startswith("other (") and "GATED" not in lic:
            licence_name = lic[len("other ("):-1]
        group = None
        if gated:
            group = "promptguard2" if "separate acceptance group" in lic else licence
        cls = ROSTER["class_override"].get(key) or ROSTER["class_from_readout"][a["readout"]]
        man = MANIFEST.get(a["repo"], {})
        rows.append({
            "key": key, "repo": a["repo"], "display": key, "revision": a["revision"],
            "params": a["params"], "params_exact": True,
            "licence": licence, "licence_name": licence_name,
            "origin": a["origin"], "readout": a["readout"], "note": a.get("note"),
            "cls": cls, "gated": group, "is_control": bool(a.get("control")),
            "status": ("ranked" if key in COH else "not scored"),
            "backbone": ROSTER["backbone"].get(key),
            "snapshot_bytes": man.get("bytes"),
            "architectures": man.get("architectures"),
            "max_pos": man.get("max_pos"),
            "manifest": man.get("manifest"),
        })
    return rows


# ------------------------------------------------------- length-control estimators
# The published length-controlled AUC is the unweighted mean of the per-quintile AUCs. That gives
# a bin holding 2 positives the same weight as one holding 230, so an arm whose sparse bins
# disagree with its dense bins can hold a position the data does not support. Every arm is
# therefore reported under four estimators, all computed here from the per-bin counts the ranking
# artifact carries, and the stability of each rank is stated.

EST_ORDER = ("A_pair_weighted_pooled", "A_unweighted_mean_within_quintile",
             "A_unweighted_mean_bins_ge_10_positives",
             "A_unweighted_mean_bins_ge_25_positives")
EST_LABEL = {"A_pair_weighted_pooled": "Pair-weighted pooled",
             "A_unweighted_mean_within_quintile": "Unweighted mean, all bins (retracted)",
             "A_unweighted_mean_bins_ge_10_positives": "Unweighted, bins with 10+ positives",
             "A_unweighted_mean_bins_ge_25_positives": "Unweighted, bins with 25+ positives"}


def published_estimator() -> tuple[str, str]:
    """Which estimator this Space publishes, and where that choice is recorded. The artifact's own
    field wins; the overlay is the fallback for an artifact that carries none."""
    named = (AUTH.get("estimator") or {}).get("authoritative")
    if named:
        return named, "the ranking artifact's own `estimator.authoritative` field"
    declared = ROSTER.get("ranking", {}).get("published_estimator")
    if not declared:
        BAD.append("neither the ranking artifact nor the overlay names which length-control "
                   "estimator is published, so the ranking would rest on an unnamed choice")
        return "unknown", "nowhere"
    return declared, "pinned/roster.json, because the artifact carries no `estimator` field"


def estimator_values(key: str) -> dict:
    """All four estimators for one arm, read from the authoritative artifact, with the two
    unweighted variants recomputed here from the bin composition as a cross-check."""
    a = AUTH["arms"][key]
    sch = a["estimators_scheme_A_common_corpus_length_quintiles"]
    comp = {f"q{i}": {"positives": b["positives"], "cases": b["cases"], "auc": b["auc"]}
            for i, b in enumerate(a["bin_composition"])}
    b = [(v["positives"], v["auc"]) for v in comp.values() if v["auc"] is not None]

    def unweighted(threshold: int):
        vals = [auc for pos, auc in b if pos >= threshold]
        return sum(vals) / len(vals) if vals else None

    out = {
        "A_pair_weighted_pooled": sch["all_bins"]["pair_weighted_pooled"],
        "A_unweighted_mean_within_quintile": sch["all_bins"]["unweighted_mean_within_bin"],
        "A_unweighted_mean_bins_ge_10_positives":
            sch["bins_with_at_least_10_positives"]["unweighted_mean_within_bin"],
        "A_unweighted_mean_bins_ge_25_positives":
            sch["bins_with_at_least_25_positives"]["unweighted_mean_within_bin"],
        "bins": comp,
        "recomputed_unweighted_all": unweighted(0),
        "recomputed_unweighted_ge10": unweighted(10),
        "recomputed_unweighted_ge25": unweighted(25),
        "se_ratio": a["analytic_variance_of_both_estimators"]["se_ratio_unweighted_over_pooled"],
        "weights_pooled": sch["all_bins"]["implied_weights_pair_weighted"],
        "weights_unweighted": sch["all_bins"]["implied_weights_unweighted"],
        "pairs": sch["all_bins"]["comparable_pairs_used"],
    }
    return out


def estimator_ranks() -> dict:
    """Candidate ordering under each of the four estimators this Space reports, controls
    excluded. Recomputed here so the table and the artifact can be cross-checked."""
    out = {}
    for est in EST_ORDER:
        xs = [(k, v["est"][est]) for k, v in COH.items()
              if not v["is_control"] and v["est"][est] is not None]
        out[est] = [k for k, _ in sorted(xs, key=lambda kv: -kv[1])]
    return out


def rank_stability() -> dict:
    """The authoritative artifact's own stability record, plus the ordering under the four
    estimators reported here. The artifact evaluates nine schemes; six of them are unweighted
    means differing only in binning, so it records that a tally among them is not evidence."""
    rs = AUTH["rank_stability"]
    schemes = rs["rank_1_under_each"]
    fam = rs["estimator_families"]
    unstable = {}
    for pos in (1, 2, 3):
        under = rs[f"rank_{pos}_under_each"]
        winners = set(under.values())
        unstable[pos] = sorted(
            {s for s, w in under.items() if w != AUTH["AUTHORITATIVE_RANKING"][f"rank_{pos}"]})
    return {"ranks": estimator_ranks(), "artifact": rs, "schemes": len(schemes),
            "families": {k: len(v) for k, v in fam.items()},
            "disagreeing_schemes": unstable,
            "rank1": AUTH["AUTHORITATIVE_RANKING"]["rank_1"],
            "rank2": AUTH["AUTHORITATIVE_RANKING"]["rank_2"],
            "rank3": AUTH["AUTHORITATIVE_RANKING"]["rank_3"]}



# ---------------------------------------------------------------- the cohort layer
# One normalised record per ranked arm, composed from the ranking artifact. Every arm is ranked
# on ONE fixed variable chosen by class structure, never per-arm, and never on the excluded
# difference variable. The deployment rows come from the reconciliation artifact, which covers
# one arm more than the ranking artifact does; that gap is carried explicitly rather than
# smoothed over.

def build_cohort() -> dict:
    """One record per arm in the authoritative ranking, which covers all 22. Shipped-argmax
    confusion comes from the earlier scorecard file, which covers 21: the arm whose body landed
    after that run has no shipped row and is carried with `shipped` set to None."""
    shipped_src = RANK["arms_s2"]
    out: dict[str, dict] = {}
    for key, a in AUTH["arms"].items():
        m, st = a["metadata"], a["settlement"]
        sh = shipped_src.get(key)
        rec = {
            "key": key,
            "is_control": bool(a["is_negative_control"]),
            "class_structure": a["class_structure"],
            "primary_var": a["ranking_variable"],
            "auc_raw": a["auc_raw"],
            "auc_lc": a["estimators_scheme_A_common_corpus_length_quintiles"]["all_bins"][
                "pair_weighted_pooled"],
            "oracle_f1": a["oracle_best_f1_ORACLE_IN_SAMPLE_UPPER_BOUND_NOT_A_RESULT"],
            "cap_tokens": m["cap_tokens"],
            "params": m["params_counted"],
            "repo": m["repo"],
            "revision": m["revision"],
            "shrunk": m["shrunk"],
            "frac_shrunk": m["shrunk"] / a["prediction_rows"],
            "rows": a["prediction_rows"],
            "errors": m["errors"],
            "settled": bool(st["settled"]),
            "digest_matches_disk": bool(st["archived_meta_sha256_matches_disk"]),
            "working_tree_stale": bool(st.get("working_tree_meta_is_stale")),
            "digest": a["prediction_sha256_disk"],
            "cap_row": a["at_fpr_cap_0.00384502"],
            "zero_fp": a["zero_fp_gate"],
            "est": estimator_values(key),
        }
        if sh:
            b = sh["shipped_argmax_from_rows"]["block_only"]
            hist = sh["shipped_argmax_from_rows"]["case_level_action_histogram"]
            pv = sh["headline"]["primary_block_variable"]
            rec["shipped"] = dict(b)
            rec["oracle"] = dict(sh["by_variable"][pv][
                "best_f1_ORACLE_IN_SAMPLE_UPPER_BOUND_NOT_A_RESULT"])
            rec["distinct_thresholds"] = sh["by_variable"][pv]["distinct_thresholds"]
            rec["flagged_cases"] = hist.get("block", 0)
            rec["flag_rate"] = hist.get("block", 0) / CORPUS["scorable_cases_A_B_D"]
            rec["inapplicable"] = sh["inapplicable_variables"]
        else:
            rec.update(shipped=None, oracle=None, distinct_thresholds=None,
                       flagged_cases=None, flag_rate=None, inapplicable={})
        out[key] = rec
    return out


COH = build_cohort()
CANDS = {k: v for k, v in COH.items() if not v["is_control"]}
CTRLS = {k: v for k, v in COH.items() if v["is_control"]}
BASE = COH["control-modernbert-base"]
FLOOR = CORPUS["trivial_floor_block_everything"]

# The ranking artifact ran before the last arm's body landed, so one arm has deployment rows and
# no ranking row. It is named wherever the two counts differ.
# arms in the ranking with no shipped-argmax row, because their body landed after that run
SHIPPED_MISSING = sorted(k for k, v in COH.items() if v["shipped"] is None)
# arms with a shipped-argmax row, which is every shipped-metric consumer's population
SHIP = {k: v for k, v in COH.items() if v["shipped"] is not None}
FPR_CAP = 0.00384502
PUB_EST, PUB_EST_SOURCE = published_estimator()
STABILITY = rank_stability()

ROWS = build_roster()

# --------------------------------------------------------------------- size bands
# Counted parameters, from each arm's own run metadata. The cuts are 3e9 and 6e9 exactly, so an
# arm at 2,614,341,888 is in the first band and one at 3,075,098,624 is in the second. The third
# band is declared even though the cohort puts nothing in it: a band that is simply absent from
# the page reads as an omission rather than as a measured zero.
SIZE_BANDS = (("under 3B", 0, 3_000_000_000),
              ("3B to 6B", 3_000_000_000, 6_000_000_000),
              ("6B and up", 6_000_000_000, None))


def band_of(params: int) -> str:
    for label, lo, hi in SIZE_BANDS:
        if params >= lo and (hi is None or params < hi):
            return label
    raise AssertionError(params)


def in_band(label: str) -> list[dict]:
    """The arms in one band, ordered by F1 at the common operating point, then by parameters."""
    return sorted((a for a in COH.values() if band_of(a["params"]) == label),
                  key=lambda a: (-a["cap_row"]["f1"], a["params"]))


def accuracy(m: dict, scorable: int) -> float:
    return (m["tp"] + m["tn"]) / scorable


# --------------------------------------------------- the held-out corpus, as scored
# The settled held-out artifact covers six arms. The stage-0 ranking artifact carries a partial
# `arms_s3` block covering three. Only the NAMES of that block are read here, for the
# reconciliation; every held-out number on the page comes from the settled artifact, and a gate
# in main() scans the built figures for any score-shaped value under the stage-0 block.
S3_STAGE0_NAMES = sorted(RANK.get("arms_s3", {}))
S3ARMS = S3C["task1_cohort_s3"]
S3CORP = S3C["corpora"]["s3"]
S2CORP = S3C["corpora"]["s2"]
S3FLOOR = S3C["corpora"]["s3_trivial_floor_block_everything"]
S3BANDC = S3C["corpora"]["s3_chance_band_hanley_mcneil"]
GRADE = S3["grade_composition_confound"]
S3DESIGN = S3["design"]
S3RES = S3["resolution_of_the_current_corpus"]
S3BIND = S3["binding_constraint"]


def wilson(k: int, n: int, z: float = 1.959963984540054) -> tuple[float, float]:
    p = k / n
    z2 = z * z
    c = (p + z2 / (2 * n)) / (1 + z2 / n)
    h = (z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))) / (1 + z2 / n)
    return c - h, c + h



def tightest_pair() -> dict:
    """The narrowest of the 15 pairwise comparisons, and the positive count that would have
    settled it. Both growth models are reported, because they disagree by one positive."""
    nar = S3RES["narrowest_minimum_detectable_difference"]
    rec = S3["pairwise_delong_all_pairs"][nar["pair"]]["sample_size_to_significance"]
    return {"pair": nar["pair"], "mdd": nar["value"],
            "proportional": rec["proportional_growth"]["positives_needed_ceiling"],
            "positives_only": rec["positives_only_growth"]["positives_needed_ceiling"]}




def s3_primary(key: str) -> dict:
    """One held-out arm's record on its primary block variable."""
    a = S3ARMS[key]
    return a["by_variable"][a["primary_block_variable"]]


# The second corpus is never named in a table without the grade-composition figure that keeps it
# from being read as a generalisation result. The label carries the figure so it travels with
# every row it appears in.
S3LABEL = (f'held out, {S3CORP["grade_counts_all"]["A"] * 100 / S3CORP["positives_A_B"]:.2f}% '
           f'grade A positives')


# ------------------------------------------------- where the labels and the licences come from
# The overlay names two first-party files: the module that assigns every truth grade, and the
# source lock that carries each source dataset's licence and redistribution marker. Both are read
# and hashed here, so the datasets page cites files that exist at a digest this build checked.
CORPORA = ROSTER["corpora"]


def label_provenance() -> dict:
    rel = CORPORA["label_scheme"]["source"]
    path = os.path.join(REPO_ROOT, rel)
    if not os.path.exists(path):
        BAD.append(f"the module that assigns every truth grade is not at {rel}, so the label "
                   f"scheme on the datasets page cites nothing in this repository")
        return {"path": rel, "sha256": None, "bytes": 0, "defines": False}
    _TOUCHED.add(path)
    with open(path, "r", encoding="utf-8") as fh:
        src = fh.read()
    fn = CORPORA["label_scheme"]["function"]
    if f"def {fn}(" not in src:
        BAD.append(f"{rel} does not define {fn}(), so the label scheme cites the wrong function")
    for grade in ("A", "B", "C", "D", "E"):
        if f'return "{grade}"' not in src:
            BAD.append(f"{rel} never returns grade {grade}, so the grade table names a grade the "
                       f"function cannot assign")
    return {"path": rel, "sha256": sha256_file(path), "bytes": os.path.getsize(path),
            "defines": True}


def restricted_source_census() -> dict:
    """The archive record's census of the two restricted sources over both corpora.

    The record's keys name one of those sources, and that name is being removed from the corpora
    entirely, so only the counts are read out of it. Both are expected to be 0, which is what lets
    this Space publish a figure over either corpus at all.
    """
    rel = CORPORA["redistribution"]["census_record"]
    path = os.path.join(REPO_ROOT, rel)
    if not os.path.exists(path):
        BAD.append(f"the restricted-source census is not at {rel}, so the statement that neither "
                   f"contributes a row rests on nothing in this repository")
        return {"path": rel, "sha256": None, "rows": None, "sources": 0, "method": None}
    _TOUCHED.add(path)
    with open(path, "r", encoding="utf-8") as fh:
        rec = json.load(fh)
    gate = rec.get("licence_gate") or {}
    counts = {k: v for k, v in gate.items() if k.endswith("_rows") and isinstance(v, int)}
    if not counts:
        BAD.append(f"{rel} carries no per-source row counts, so the census has no numbers in it")
    return {"path": rel, "sha256": sha256_file(path), "bytes": os.path.getsize(path),
            "rows": sum(counts.values()), "sources": len(counts),
            "method": gate.get("method", ""),
            "payload_field_absent": gate.get("payload_field_present_in_any_uploaded_file")}


def source_lock() -> dict:
    rel = CORPORA["redistribution"]["source_lock"]
    path = os.path.join(REPO_ROOT, rel)
    if not os.path.exists(path):
        BAD.append(f"the source lock is not at {rel}, so the redistribution markers on the "
                   f"datasets page rest on nothing in this repository")
        return {"path": rel, "sha256": None, "entries": 0, "redistribution": {},
                "licence_status": {}, "enabled": 0, "licences": {}}
    _TOUCHED.add(path)
    with open(path, "r", encoding="utf-8") as fh:
        lock = json.load(fh)
    rows = lock["datasets"]
    def tally(field):
        out: dict[str, int] = {}
        for e in rows:
            out[str(e.get(field))] = out.get(str(e.get(field)), 0) + 1
        return dict(sorted(out.items(), key=lambda kv: (-kv[1], kv[0])))
    return {"path": rel, "sha256": sha256_file(path), "bytes": os.path.getsize(path),
            "frozen_at": lock.get("frozen_at"), "schema": lock.get("schema_version"),
            "entries": len(rows), "redistribution": tally("redistribution"),
            "licence_status": tally("license_status"), "licences": tally("license"),
            "enabled": sum(1 for e in rows if e.get("enabled"))}






# ------------------------------------------------------------------- assertions
# Each entry is a figure that is recomputed from primitives and checked against the value the
# artifact records. A disagreement aborts the build before anything is written.

ASSERTS: list[tuple[str, float, float]] = []
BAD: list[str] = []
# the two first-party files the overlay names, read and hashed now that BAD exists to record a
# missing one
LABELS = label_provenance()
LOCK = source_lock()
CENSUS = restricted_source_census()
# Keys read out of the stage-0 ranking artifact. `arms_s3` is read for one purpose: the two
# held-out artifacts cover different arm counts, 3 against 6, and the page has to say which one
# governs. The check below requires the two to agree on every arm they share, so the answer rests
# on a comparison rather than on a preference. `corpus_s3` and `length_cue_no_model_s3` are still
# not read: the settled pair carries both and is the only source for a held-out number.
_READ_KEYS: set[str] = {"arms_s2", "corpus_s2", "length_cue_no_model_s2", "provenance",
                        "arms_s3"}
_S3_KEYS_STILL_CLOSED = ("corpus_s3", "length_cue_no_model_s3", "corpus_overlap")


def expect(label: str, computed: float, recorded: float, tol: float = 5e-12) -> float:
    """Recompute a figure and check it against what the artifact records. Returns the
    artifact's value, so the page always prints the artifact rather than the recomputation."""
    ASSERTS.append((label, computed, recorded))
    if recorded is None or computed is None or abs(computed - recorded) > tol:
        BAD.append(f"{label}: recomputed {computed!r} against artifact {recorded!r}")
    return recorded


def f1_of(tp: int, fp: int, fn: int) -> float:
    return 0.0 if tp == 0 else 2 * tp / (2 * tp + fp + fn)


def check_figures() -> None:
    """Every derived number the site prints, recomputed from the primitives beside it."""
    # --- the trivial floor, from the corpus label counts alone
    be = TRIVIAL["block_every_case"]
    expect("trivial floor F1", f1_of(be["tp"], be["fp"], be["fn"]), be["f1"])
    expect("trivial floor precision", be["tp"] / (be["tp"] + be["fp"]), be["precision"])
    expect("trivial floor recall", be["tp"] / (be["tp"] + be["fn"]), be["recall"])
    expect("trivial floor FPR", be["fp"] / (be["fp"] + be["tn"]), be["fpr"])
    expect("positives", be["tp"], CORPUS["positives_A_B"], 0)
    expect("negatives", be["fp"], CORPUS["negatives_D"], 0)
    expect("scorable cases",
           CORPUS["positives_A_B"] + CORPUS["negatives_D"], CORPUS["scorable_cases_A_B_D"], 0)
    expect("cases total",
           CORPUS["scorable_cases_A_B_D"] + CORPUS["grade_C_excluded"], CORPUS["cases"], 0)
    expect("prevalence", CORPUS["positives_A_B"] / CORPUS["scorable_cases_A_B_D"],
           TRIVIAL["prevalence_positives_over_scorable"])

    # --- the null band, from Hanley and McNeil at AUC 0.5
    n1, n2 = BAND["npos"], BAND["nneg"]
    a = 0.5
    q1, q2 = a / (2 - a), 2 * a * a / (1 + a)
    se = math.sqrt((a * (1 - a) + (n1 - 1) * (q1 - a * a) + (n2 - 1) * (q2 - a * a)) / (n1 * n2))
    expect("Hanley-McNeil SE at AUC 0.5", se, BAND["hanley_mcneil_se_at_auc_0.5"], 5e-15)
    lo, hi = BAND["chance_95pct_interval"]
    # the band is the exact 97.5th percentile of the standard normal, not the 1.96 shorthand;
    # solved back out of the artifact's own endpoints and asserted to 1e-13
    z = 1.959963984540054
    expect("null band z", (hi - 0.5) / BAND["hanley_mcneil_se_at_auc_0.5"], z, 1e-13)
    expect("null band lower", 0.5 - z * BAND["hanley_mcneil_se_at_auc_0.5"], lo, 5e-15)
    expect("null band upper", 0.5 + z * BAND["hanley_mcneil_se_at_auc_0.5"], hi, 5e-15)
    expect("null band positives", n1, CORPUS["positives_A_B"], 0)
    expect("null band negatives", n2, CORPUS["negatives_D"], 0)

    # --- each scored arm's shipped confusion matrix reproduces its own F1
    for key, arm in ARMS.items():
        blk = arm["shipped_argmax_recomputed_from_rows"]["block_only"]
        expect(f"{key} shipped block-only F1",
               f1_of(blk["tp"], blk["fp"], blk["fn"]), blk["f1"], 5e-15)
        expect(f"{key} shipped block-only recall",
               blk["tp"] / (blk["tp"] + blk["fn"]), blk["recall"], 5e-15)
        expect(f"{key} shipped block-only precision",
               blk["tp"] / (blk["tp"] + blk["fp"]), blk["precision"], 5e-15)
        expect(f"{key} shipped block-only FPR",
               blk["fp"] / (blk["fp"] + blk["tn"]), blk["fpr"], 5e-15)
        expect(f"{key} shipped labels agree with the corpus",
               blk["tp"] + blk["fn"], CORPUS["positives_A_B"], 0)
        expect(f"{key} shipped negatives agree with the corpus",
               blk["fp"] + blk["tn"], CORPUS["negatives_D"], 0)
        expect(f"{key} headline block-only F1 equals its confusion matrix",
               blk["f1"], arm["headline"]["shipped_block_only_f1"], 0)

    # --- the two-class arms' identity: any-intervention equals block-only by construction
    for key in ("deberta-v3-prompt-injection-v2", "control-modernbert-base",
                "control-modernbert-large"):
        h = ARMS[key]["headline"]
        expect(f"{key} any-intervention equals block-only",
               h["shipped_block_only_f1"], h["shipped_any_intervention_f1"], 0)

    # --- length-controlled AUC is the unweighted mean over the five quintiles
    for name, rec in LCA.items():
        q = rec["per_quintile"]
        mean = sum(v["auc"] for v in q.values()) / len(q)
        expect(f"length-controlled AUC, {name}", mean, rec["mean_within_length_quintile_auc"],
               5e-12)
        expect(f"quintile case total, {name}",
               sum(v["cases"] for v in q.values()), CORPUS["scorable_cases_A_B_D"], 0)
        expect(f"quintile positive total, {name}",
               sum(v["positives"] for v in q.values()), CORPUS["positives_A_B"], 0)
    for key, rec in LEAK["controls"].items():
        q = rec["auc_within_length_quintile"]
        mean = sum(v["auc"] for v in q.values()) / len(q)
        expect(f"length-controlled AUC, leakage {key}", mean, rec["mean_within_stratum_auc"],
               5e-12)

    # --- the one headline comparison that survives the scope rule
    d_ship = DEB["headline"]["shipped_block_only_f1"]
    expect("DeBERTa shipped minus the floor", d_ship - be["f1"],
           HEAD["deberta_shipped_minus_block_everything"], 5e-12)
    expect("the comparison keys that quote an out-of-scope arm are all dropped",
           len(set(HEAD) & set(SCOPE["excluded_comparison_keys"])), 0, 0)
    expect("the out-of-scope AUC rows are all dropped",
           len(set(LCA) & set(SCOPE["excluded_lca_keys"])), 0, 0)
    expect("no out-of-scope arm survives into the scored set",
           len(set(ARMS) & set(SCOPE["excluded_scorecard_arms"])), 0, 0)

    # --- the scorer-equivalence gate, as a property of the check rather than of any arm's score
    deltas = [v["abs_delta_f1"] for v in PARITY.values()]
    expect("references the gate re-derives", len(PARITY), 3, 0)
    expect("largest absolute F1 delta across the references", max(deltas),
           1.2977099395072855e-09, 5e-18)
    expect("references whose confusion matrix matched exactly",
           sum(1 for v in PARITY.values() if v.get("confusion_matches_published")), 2, 0)
    expect("references with an AUC check, and its delta",
           sum(1 for v in PARITY.values() if v.get("auc_abs_delta") is not None), 1, 0)
    expect("AUC delta on the reference that carries one",
           next(v["auc_abs_delta"] for v in PARITY.values()
                if v.get("auc_abs_delta") is not None), 0.0, 0)

    # --- DeBERTa's 512-token window
    sc = TRUNC["scored_corpus"]
    expect("rows over 512 in the full pass",
           TRUNC["runner_reported_rows_shrunk"] / TRUNC["runner_total_rows"],
           TRUNC["runner_fraction_rows_shrunk"], 5e-15)
    expect("cases with a truncated event",
           sc["cases_with_at_least_one_event_over_512"] / sc["scored_cases"],
           sc["cases_with_at_least_one_event_over_512_fraction"], 5e-15)
    expect("rows over 512 within the scored set",
           sc["rows_over_512_in_scored_cases"] / sc["rows_belonging_to_scored_cases"],
           sc["rows_over_512_fraction"], 5e-15)
    expect("scored cases", sc["scored_cases"], CORPUS["scorable_cases_A_B_D"], 0)
    expect("DeBERTa cap", min(6144, 512 - 2), TRUNC["deberta_cap_tokens"], 0)
    ec = TRUNC["error_correlation"]
    for stratum in ("truncated_cases", "untruncated_cases"):
        for point in ("at_shipped_argmax", "at_oracle_best_f1_threshold"):
            c = ec[point][stratum]
            expect(f"DeBERTa {point} {stratum} F1", f1_of(c["tp"], c["fp"], c["fn"]), c["f1"],
                   5e-15)
            expect(f"DeBERTa {point} {stratum} cases",
                   c["tp"] + c["fp"] + c["fn"] + c["tn"], c["cases"], 0)
        pos = ec["at_shipped_argmax"][stratum]["positives_A_B"]
        tot = ec["at_shipped_argmax"][stratum]["cases"]
        expect(f"DeBERTa {stratum} positive rate", pos / tot,
               ec["prevalence_confound"]["positive_rate_" + stratum], 5e-15)
    expect("truncated plus untruncated cases",
           ec["at_shipped_argmax"]["truncated_cases"]["cases"]
           + ec["at_shipped_argmax"]["untruncated_cases"]["cases"],
           CORPUS["scorable_cases_A_B_D"], 0)

    # --- the two multimodal splits, checked against the registry's parameter counts
    by_key = {a["key"]: a for a in ROWS}
    for m in LAPTOP["multimodal_splits"]:
        dead = m["vision_params"] + m["projector_params"]
        total = dead + m["text_tower_params"]
        expect(f'{m["arm"]} parameter split sums to the registry count', total,
               by_key[m["arm"]]["params"], 0)
        MM[m["arm"]] = {"dead": dead, "total": total, "share": dead / total}
    expect("Shieldstral text-only Q4_K_M in GiB",
           round(LAPTOP["multimodal_splits"][0]["text_only_q4_k_m_bytes"] / GIB, 4), 1.9991, 0)
    expect("gemma-3-4b-it weight bytes in GiB",
           round(LAPTOP["multimodal_splits"][1]["full_checkpoint_bytes"] / GIB, 4), 8.0096, 0)
    expect("arms whose weight bytes pass 8 GiB",
           sum(1 for m in LAPTOP["multimodal_splits"]
               if m.get("full_checkpoint_bytes", 0) > 8 * GIB), 1, 0)

    # --- the roster, derived from the registry
    expect("roster size", len(ROWS), 22, 0)
    expect("gated arms", sum(1 for a in ROWS if a["gated"]), 8, 0)
    expect("gating groups", len({a["gated"] for a in ROWS if a["gated"]}), 3, 0)
    expect("trained encoders", sum(1 for a in ROWS if a["cls"] == "encoder"), 3, 0)
    expect("trained encoders on the DebertaV2 backbone",
           sum(1 for a in ROWS if a["cls"] == "encoder" and a["backbone"] == "DebertaV2"), 3, 0)
    expect("MLM controls", sum(1 for a in ROWS if a["cls"] == "control"), 2, 0)
    expect("every control is flagged as one in the registry",
           sum(1 for a in ROWS if a["is_control"]),
           sum(1 for a in ROWS if a["cls"] == "control"), 0)
    expect("safety classifiers", sum(1 for a in ROWS if a["cls"] == "safety"), 5, 0)
    expect("general decoders", sum(1 for a in ROWS if a["cls"] == "general"), 12, 0)
    expect("candidate arms, controls excluded",
           sum(1 for a in ROWS if a["cls"] != "control"), 20, 0)
    expect("the four classes partition the roster",
           sum(1 for a in ROWS if a["cls"] in ("general", "safety", "encoder", "control")),
           len(ROWS), 0)
    expect("registry arms with a ranking record", sum(1 for a in ROWS
                                                     if a["status"] == "ranked"), 22, 0)
    expect("registry arms with no score at all",
           sum(1 for a in ROWS if a["status"] == "not scored"), 0, 0)
    expect("every arm has a weight-manifest snapshot size",
           sum(1 for a in ROWS if a["snapshot_bytes"]), len(ROWS), 0)
    expect("arms whose download recorded an architecture class",
           sum(1 for a in ROWS if a["architectures"]), 2, 0)
    for a in ROWS:
        if a["architectures"] and a["backbone"] == "DebertaV2":
            if a["architectures"] != ["DebertaV2ForSequenceClassification"]:
                BAD.append(f'{a["key"]}: manifest architectures {a["architectures"]!r} do not '
                           f'support the DebertaV2 backbone claim')
        if a["max_pos"] is not None:
            expect(f'{a["key"]} position limit', a["max_pos"], 512, 0)

    # --- the cohort: every arm's confusion matrix reproduces its own rates, from rows
    for key, a in SHIP.items():
        sh = a["shipped"]
        expect(f"{key} shipped F1", f1_of(sh["tp"], sh["fp"], sh["fn"]), sh["f1"], 5e-15)
        expect(f"{key} shipped recall", sh["tp"] / (sh["tp"] + sh["fn"]), sh["recall"], 5e-15)
        if sh["tp"] + sh["fp"]:
            expect(f"{key} shipped precision", sh["tp"] / (sh["tp"] + sh["fp"]),
                   sh["precision"], 5e-15)
        expect(f"{key} shipped block FPR", sh["fp"] / (sh["fp"] + sh["tn"]),
               sh["block_fpr"], 5e-15)
        expect(f"{key} positives", sh["tp"] + sh["fn"], CORPUS["positives_A_B"], 0)
        expect(f"{key} negatives", sh["fp"] + sh["tn"], CORPUS["negatives_D"], 0)
        o = a["oracle"]
        expect(f"{key} oracle F1", f1_of(o["tp"], o["fp"], o["fn"]), o["f1"], 5e-15)
        expect(f"{key} oracle cases", o["tp"] + o["fp"] + o["fn"] + o["tn"],
               CORPUS["scorable_cases_A_B_D"], 0)
        if a["primary_var"].endswith("P(confirm)"):
            BAD.append(f"{key}: ranked on the excluded difference variable")
    for key, a in COH.items():
        expect(f"{key} rows", a["rows"], 30310, 0)
        expect(f"{key} errors", a["errors"], 0, 0)
        expect(f"{key} shrunk fraction", a["shrunk"] / a["rows"], a["frac_shrunk"], 5e-15)
    # the published estimator must agree with the arm records, and the stability must be measured
    for key, a in COH.items():
        expect(f"{key} published length-controlled AUC matches the named estimator",
               a["est"][PUB_EST], a["auc_lc"], 5e-12)
        expect(f"{key} bins", len(a["est"]["bins"]), 5, 0)
        expect(f"{key} bin positives sum to the corpus",
               sum(v["positives"] for v in a["est"]["bins"].values()),
               CORPUS["positives_A_B"], 0)
        expect(f"{key} bin cases sum to the corpus",
               sum(v["cases"] for v in a["est"]["bins"].values()),
               CORPUS["scorable_cases_A_B_D"], 0)
    if PUB_EST not in EST_ORDER:
        BAD.append(f"the published estimator {PUB_EST!r} is not one this build computes")
    expect("estimators reported per arm", len(EST_ORDER), 4, 0)
    expect("schemes the artifact evaluates", STABILITY["schemes"], 9, 0)
    expect("unweighted-mean schemes among them",
           STABILITY["families"]["unweighted_mean_family"], 6, 0)
    expect("pair-weighted schemes among them",
           STABILITY["families"]["pair_weighted_family"], 2, 0)
    # ranks 1 and 2 are each contradicted by exactly one scheme, and it is the same scheme, the
    # one the artifact marks confounded because its bins move with each arm's own truncation
    for pos in (1, 2):
        expect(f"schemes disagreeing with rank {pos}",
               len(STABILITY["disagreeing_schemes"][pos]), 1, 0)
    if (STABILITY["disagreeing_schemes"][1] != STABILITY["disagreeing_schemes"][2]
            or not STABILITY["disagreeing_schemes"][1][0].startswith("B_")):
        BAD.append(f"ranks 1 and 2 are not contradicted by the same scheme B: "
                   f"{STABILITY['disagreeing_schemes']}")
    expect("schemes disagreeing with rank 3",
           len(STABILITY["disagreeing_schemes"][3]), 5, 0)
    if AUTH["rank_stability"]["rank_3_plurality_among_estimators"] == STABILITY["rank3"]:
        BAD.append("the artifact's plurality and its authoritative rank 3 now agree, so the "
                   "statement that a tally is not how this is decided needs rewriting")
    expect("ranked arms", len(COH), 22, 0)
    expect("ranked candidates", len(CANDS), 20, 0)
    expect("negative controls", len(CTRLS), 2, 0)
    expect("arms with a shipped-argmax row", len(SHIP), 21, 0)
    expect("arms without one", len(SHIPPED_MISSING), 1, 0)
    expect("arms with an FPR-cap row", sum(1 for a in COH.values() if a["cap_row"]), 22, 0)
    expect("arms with a zero-FP row", sum(1 for a in COH.values() if a["zero_fp"]), 22, 0)

    # --- the corpus record in the ranking artifact agrees with the stage-0 one
    expect("ranking corpus positives", CORPUS["positives_A_B"], 436, 0)
    expect("ranking corpus negatives", CORPUS["negatives_D"], 3381, 0)
    expect("ranking corpus scorable", CORPUS["scorable_cases_A_B_D"], 3817, 0)
    expect("ranking corpus prevalence",
           CORPUS["positives_A_B"] / CORPUS["scorable_cases_A_B_D"], CORPUS["prevalence"], 5e-15)
    if CORPUS["cases_sha256"] != SCORES["corpus"]["cases_sha256"]:
        BAD.append("the ranking artifact scored a different corpus than the stage-0 scorecards")
    expect("trivial floor in the ranking artifact",
           f1_of(FLOOR["tp"], FLOOR["fp"], FLOOR["fn"]), FLOOR["f1"], 5e-15)
    expect("the two artifacts agree on the floor", FLOOR["f1"],
           TRIVIAL["block_every_case"]["f1"], 0)

    # --- the ranking artifact's own provenance: the shared arithmetic and the scope rule
    rp = RANK["provenance"]
    if rp["remine_sha256"] != SCORER["shared_arithmetic"]["sha256"]:
        BAD.append(f"the ranking artifact used arithmetic at {rp['remine_sha256']} against the "
                   f"pinned {SCORER['shared_arithmetic']['sha256']}")
    if "no Jev-family" not in rp["scope_rule"]:
        BAD.append("the ranking artifact does not record the cohort scope rule")
    if rp["gpu_used"] is not False:
        BAD.append("the ranking artifact records GPU use, which the scoring path should not need")
    # the stage-0 artifact's remaining held-out keys stay closed; the settled pair carries them
    for k in _S3_KEYS_STILL_CLOSED:
        if k in RANK and k in _READ_KEYS:
            BAD.append(f"an s3 key ({k}) was read out of the stage-0 artifact; the settled pair "
                       f"is the only source for a held-out number")

    # --- the shared scoring arithmetic. This is the load-bearing claim for comparability
    # between a cohort number and a board number, so the module's identity is checked here
    # rather than asserted in prose. Editing it fails this build.
    sa = SCORER["shared_arithmetic"]
    path = os.path.join(REPO_ROOT, sa["repo_path"])
    if not os.path.exists(path):
        BAD.append(f'the shared arithmetic is not vendored at {sa["repo_path"]}, so the '
                   f'comparability claim rests on nothing in this repository')
    else:
        _TOUCHED.add(path)
        got = sha256_file(path)
        if got != sa["sha256"]:
            BAD.append(f'shared arithmetic digest {got} against the pinned {sa["sha256"]}; the '
                       f'module changed and comparability must be re-established')
        expect("shared arithmetic size", os.path.getsize(path), sa["bytes"], 0)
        if sa["dev_host_copy_sha256"] != sa["sha256"]:
            BAD.append("the pinned dev-host digest differs from the vendored digest, so the "
                       "scoring run did not import the module in this repository")
        if sa["dev_host_copy_is_byte_identical"] is not True:
            BAD.append("the provenance record does not assert the two copies are identical")

    # --- the dropped family's download, summed from the manifest
    drop = ROSTER["dropped"][0]
    dropped_bytes = sum(MANIFEST[r]["bytes"] for r in drop["repos"])
    expect("dropped Qwen3 download in GiB", round(dropped_bytes / GIB, 2), 12.72, 0)
    DROPPED["bytes"] = dropped_bytes
    DROPPED["gib"] = dropped_bytes / GIB

    # --- throughput coverage
    tp_rows = (LAPTOP["decoder_throughput_rows_per_min"]
               + LAPTOP["encoder_throughput_rows_per_min"])
    expect("published rows/min figures", len(tp_rows),
           LAPTOP["throughput_coverage"]["arms_with_a_published_rows_per_min"], 0)
    expect("decoder conversions", len(LAPTOP["decoder_throughput_rows_per_min"]),
           LAPTOP["provenance"]["measurement_conditions"]["conversions_succeeded"]["decoders"],
           0)
    for r in tp_rows:
        if r["arm"] not in by_key:
            BAD.append(f'throughput row names {r["arm"]!r}, which is not a registry arm')
    for k in ("q4_k_m_gib_min", "q4_k_m_gib_max", "peak_rss_hungriest"):
        if LAPTOP["memory"][k]["arm"] not in by_key:
            BAD.append(f'memory.{k} names {LAPTOP["memory"][k]["arm"]!r}, which is not a '
                       f'registry arm')
    expect("the laptop artifact records that its measurement step was not preserved",
           1 if "never saved" in LAPTOP["provenance"]["reproducibility"] else 0, 1, 0)

    # --- each scored arm's run metadata agrees with the registry
    for arm_key, roster_key in SCORED_TO_ROSTER.items():
        if roster_key not in by_key:
            continue          # out of scope on this Space; the registry omits it
        m = ARMS[arm_key].get("arm_meta") or {}
        if not m:
            continue
        r = by_key[roster_key]
        expect(f"{arm_key} params agree with the registry", m["params_counted"], r["params"], 0)
        if m["repo"] != r["repo"]:
            BAD.append(f'{arm_key}: run meta repo {m["repo"]!r} against registry {r["repo"]!r}')
        if m["licence"] != r["licence"]:
            BAD.append(f'{arm_key}: run meta licence {m["licence"]!r} against registry '
                       f'{r["licence"]!r}')
        if m["revision"] != r["revision"]:
            BAD.append(f'{arm_key}: run meta revision {m["revision"]!r} against registry '
                       f'{r["revision"]!r}')
        expect(f"{arm_key} rows", m["rows"], ARMS[arm_key]["prediction_rows"], 0)
        expect(f"{arm_key} errors", m["errors"], 0, 0)
    # --- the common operating point. Every arm is reported at one shared false-positive budget,
    # so each row's confusion matrix is recomputed from its own counts and checked against the
    # rates the artifact records, and the budget itself is checked to hold on every row.
    scorable = CORPUS["scorable_cases_A_B_D"]
    pos, neg = CORPUS["positives_A_B"], CORPUS["negatives_D"]
    max_fp = int(FPR_CAP * neg)
    for key, a in COH.items():
        x = a["cap_row"]
        expect(f"{key} at the cap, positives", x["tp"] + x["fn"], pos, 0)
        expect(f"{key} at the cap, negatives", x["fp"] + x["tn"], neg, 0)
        expect(f"{key} at the cap, F1", f1_of(x["tp"], x["fp"], x["fn"]), x["f1"], 5e-15)
        expect(f"{key} at the cap, recall", x["tp"] / pos, x["recall"], 5e-15)
        expect(f"{key} at the cap, FPR", x["fp"] / neg, x["fpr"], 5e-15)
        expect(f"{key} at the cap, false-positive allowance",
               x["max_false_positives_allowed"], max_fp, 0)
        if x["tp"] + x["fp"]:
            expect(f"{key} at the cap, precision",
                   x["tp"] / (x["tp"] + x["fp"]), x["precision"], 5e-15)
        if x["fpr"] > FPR_CAP:
            BAD.append(f"{key}: FPR {x['fpr']} at the cap row exceeds the cap {FPR_CAP}, so the "
                       f"row is not at the common operating point")
        if x["fp"] > max_fp:
            BAD.append(f"{key}: {x['fp']} false positives against an allowance of {max_fp}")
        z = a["zero_fp"]
        expect(f"{key} at a zero-FP gate, false positives", z["fp"], 0, 0)
        expect(f"{key} at a zero-FP gate, negatives", z["fp"] + z["tn"], neg, 0)
        expect(f"{key} at a zero-FP gate, positives", z["tp"] + z["fn"], pos, 0)
        expect(f"{key} at a zero-FP gate, F1", f1_of(z["tp"], z["fp"], z["fn"]), z["f1"], 5e-15)
        expect(f"{key} at a zero-FP gate, recall", z["tp"] / pos, z["recall"], 5e-15)
        expect(f"{key} at a zero-FP gate, rule-of-three bound", 3 / neg,
               z["rule_of_three_upper_bound"], 5e-15)
    expect("the cap is the incumbent block false-positive rate", FPR_CAP,
           float(next(k.rsplit("_", 1)[1]
                      for k in AUTH if k.startswith("deployability_at_fpr_cap_"))), 0)
    expect("candidates retaining zero recall at a zero-FP gate",
           sum(1 for a in CANDS.values() if a["zero_fp"]["recall"] == 0), 13, 0)
    expect("candidates with any recall at a zero-FP gate",
           sum(1 for a in CANDS.values() if a["zero_fp"]["recall"] > 0), 7, 0)
    best_cap = max(CANDS.values(), key=lambda a: a["cap_row"]["f1"])
    expect("the best F1 at the common operating point", best_cap["cap_row"]["f1"],
           0.10548523206751055, 5e-17)
    expect("its true blocks", best_cap["cap_row"]["tp"], 25, 0)

    # --- accuracy is only meaningful against the all-allow baseline at these prevalences
    allow = TRIVIAL["allow_every_case"]
    expect("all-allow accuracy on s2", accuracy(allow, scorable), neg / scorable, 5e-16)
    expect("all-allow accuracy on s2 equals 1 minus prevalence",
           1 - CORPUS["prevalence"], neg / scorable, 5e-15)
    # an arm's accuracy exceeds the all-allow baseline exactly when it gains more true blocks
    # than it spends on false ones, so the two counts are the same count
    expect("arms whose accuracy at the cap beats the all-allow baseline",
           sum(1 for a in COH.values()
               if accuracy(a["cap_row"], scorable) > neg / scorable),
           sum(1 for a in COH.values()
               if a["cap_row"]["tp"] > a["cap_row"]["fp"]), 0)
    expect("the widest accuracy gain over the all-allow baseline, in cases",
           max(a["cap_row"]["tp"] - a["cap_row"]["fp"] for a in COH.values()), 12, 0)
    expect("all-allow accuracy on the held-out corpus",
           S3CORP["negatives_D"] / S3CORP["cases"], 1 - S3CORP["prevalence"], 5e-15)

    # --- each arm's own argmax, which is an in-sample oracle upper bound and never a result
    for key, a in COH.items():
        if a["oracle"] is None:
            continue
        o = a["oracle"]
        expect(f"{key} oracle positives", o["tp"] + o["fn"], pos, 0)
        expect(f"{key} oracle negatives", o["fp"] + o["tn"], neg, 0)
        expect(f"{key} oracle F1", f1_of(o["tp"], o["fp"], o["fn"]), o["f1"], 5e-15)
        expect(f"{key} oracle recall", o["tp"] / pos, o["recall"], 5e-15)
        expect(f"{key} oracle precision", o["tp"] / (o["tp"] + o["fp"]), o["precision"], 5e-15)
        expect(f"{key} oracle block FPR", o["fp"] / neg, o["block_fpr"], 5e-15)
        expect(f"{key} oracle F1 matches the ranking artifact", o["f1"], a["oracle_f1"], 0)
        if o["f1"] < a["cap_row"]["f1"]:
            BAD.append(f"{key}: its own argmax scores below the common operating point, which "
                       f"an unconstrained in-sample sweep cannot do")
    expect("arms whose own argmax clears the trivial floor",
           sum(1 for a in COH.values() if a["oracle_f1"] > FLOOR["f1"]), 22, 0)
    expect("candidates below the floor at their shipped decision",
           sum(1 for a in CANDS.values()
               if a["shipped"] and a["shipped"]["f1"] < FLOOR["f1"]), 9, 0)
    expect("candidates scoring exactly zero at their shipped decision",
           sum(1 for a in CANDS.values()
               if a["shipped"] and a["shipped"]["f1"] == 0.0), 5, 0)

    # --- size bands, from counted parameters in each arm's own run metadata
    for a in COH.values():
        r = by_key[a["key"]]
        expect(f"{a['key']} counted parameters agree with the registry", a["params"],
               r["params"], 0)
        if a["repo"] != r["repo"]:
            BAD.append(f'{a["key"]}: ranking meta repo {a["repo"]!r} against registry '
                       f'{r["repo"]!r}')
        if a["revision"] != r["revision"]:
            BAD.append(f'{a["key"]}: ranking meta revision {a["revision"]!r} against registry '
                       f'{r["revision"]!r}')
    expect("arms in the under-3B band", len(in_band("under 3B")), 14, 0)
    expect("arms in the 3B-to-6B band", len(in_band("3B to 6B")), 8, 0)
    expect("arms in the 6B-and-up band", len(in_band("6B and up")), 0, 0)
    expect("every arm lands in exactly one band",
           sum(len(in_band(b)) for b, _lo, _hi in SIZE_BANDS), len(COH), 0)

    # --- the two corpora, and the grade composition that keeps a transfer claim off this Space
    expect("s2 scorable agrees across artifacts", S2CORP["scorable_cases_A_B_D"], scorable, 0)
    expect("s2 digest agrees across artifacts",
           1 if S2CORP["cases_sha256"] == CORPUS["cases_sha256"] else 0, 1, 0)
    expect("held-out scorable", S3CORP["positives_A_B"] + S3CORP["negatives_D"],
           S3CORP["scorable_cases_A_B_D"], 0)
    expect("held-out cases", S3CORP["scorable_cases_A_B_D"] + S3CORP["grade_C_excluded"],
           S3CORP["cases"], 0)
    expect("held-out prevalence", S3CORP["positives_A_B"] / S3CORP["cases"],
           S3CORP["prevalence"], 5e-16)
    expect("held-out positives by grade",
           S3CORP["grade_counts_all"]["A"] + S3CORP["grade_counts_all"]["B"],
           S3CORP["positives_A_B"], 0)
    expect("held-out trivial floor",
           f1_of(S3FLOOR["tp"], S3FLOOR["fp"], S3FLOOR["fn"]), S3FLOOR["f1"], 5e-16)
    expect("held-out chance band is verified in the artifact",
           1 if S3BANDC["verified"] else 0, 1, 0)
    _z = 1.959963984540054
    expect("held-out chance band lower", 0.5 - _z * S3BANDC["se_at_auc_0.5"],
           S3BANDC["band_95pct"][0], 5e-15)
    expect("held-out chance band upper", 0.5 + _z * S3BANDC["se_at_auc_0.5"],
           S3BANDC["band_95pct"][1], 5e-15)
    expect("case-id overlap between the two corpora", S3C["corpora"]["case_id_overlap_s2_s3"],
           0, 0)
    _gc = S3["grade_composition_confound"]
    expect("s2 grade A share of positives", CORPUS["grade_counts_all"]["A"] / pos,
           _gc["s2_positive_composition"]["grade_A_share_of_positives"], 5e-16)
    expect("held-out grade A share of positives",
           S3CORP["grade_counts_all"]["A"] / S3CORP["positives_A_B"],
           _gc["s3_positive_composition"]["grade_A_share_of_positives"], 5e-16)
    expect("s2 positives by grade agree across artifacts",
           _gc["s2_positive_composition"]["A"] + _gc["s2_positive_composition"]["B"], pos, 0)

    # --- the label scheme and the source lock, both first-party files in this repository
    expect("the grade function is defined where the overlay says",
           1 if LABELS["defines"] else 0, 1, 0)
    expect("grades the function can assign", len(CORPORA["label_scheme"]["conditions"]), 5, 0)
    for g in ("A", "B", "C", "D"):
        if g not in CORPUS["grade_counts_all"]:
            BAD.append(f"s2 carries no grade {g} count, so the grade table would print a blank")
    expect("grades absent from the held-out corpus",
           len({"C", "E"} & set(S3CORP["grade_counts_all"])), 0, 0)
    expect("source-lock entries",
           sum(LOCK["redistribution"].values()), LOCK["entries"], 0)
    expect("source-lock entries by licence status",
           sum(LOCK["licence_status"].values()), LOCK["entries"], 0)
    if "aggregate-only" not in LOCK["redistribution"]:
        BAD.append("the source lock records no aggregate-only entry, so the restricted-source "
                   "disclosure has nothing behind it")
    expect("rows either restricted source contributes to these corpora", CENSUS["rows"], 0, 0)
    expect("restricted sources the census covers", CENSUS["sources"], 2, 0)
    for _n in (str(CORPUS["cases"]), str(S3CORP["cases"])):
        if _n not in (CENSUS["method"] or ""):
            BAD.append(f"the restricted-source census does not record a case count of {_n}, so it "
                       f"may not have been taken over the corpora this Space reports")
    if CENSUS["payload_field_absent"] is not False:
        BAD.append("the census record does not assert that no uploaded file carries the payload "
                   "field")

    # --- the held-out bodies, settled
    expect("arms scored on the held-out corpus", len(S3ARMS), 6, 0)
    expect("arms in the stage-0 artifact's partial held-out block", len(S3_STAGE0_NAMES), 3, 0)
    if not set(S3_STAGE0_NAMES) <= set(S3ARMS):
        BAD.append(f"the stage-0 held-out block names arms the settled artifact does not cover: "
                   f"{sorted(set(S3_STAGE0_NAMES) - set(S3ARMS))}")
    # The two artifacts have to agree on every arm they share, or the page cannot say which one
    # governs on the strength of coverage alone.
    for key in S3_STAGE0_NAMES:
        old, new = RANK["arms_s3"][key], S3ARMS[key]
        if old["primary_block_variable"] != new["primary_block_variable"]:
            BAD.append(f"{key}: the two held-out artifacts rank it on different variables")
            continue
        ov = old["by_variable"][old["primary_block_variable"]]
        nv = new["by_variable"][new["primary_block_variable"]]
        expect(f"{key} held-out raw AUC agrees across both artifacts",
               ov["auc_raw_mann_whitney_tie_corrected"],
               nv["s3_auc_raw_mann_whitney_tie_corrected"], 0)
        expect(f"{key} held-out rows agree across both artifacts", old["prediction_rows"],
               new["s3_prediction_rows"], 0)
        if old["prediction_sha256_disk"] != new["s3_prediction_sha256_disk"]:
            BAD.append(f"{key}: the two held-out artifacts scored different bytes")
        if (old["shipped_argmax_from_rows"]["block_only"]
                != new["s3_shipped_argmax_from_rows"]["block_only"]):
            BAD.append(f"{key}: the two held-out artifacts disagree on its shipped confusion "
                       f"matrix, so neither can be preferred on coverage alone")
    for key, a in S3ARMS.items():
        m = a["s3_meta"]
        expect(f"{key} held-out rows", m["rows"], a["s3_prediction_rows"], 0)
        expect(f"{key} held-out errors", m["errors"], 0, 0)
        expect(f"{key} held-out cases covered", a["s3_cases_in_prediction"], S3CORP["cases"], 0)
        expect(f"{key} held-out cases missing", a["s3_scorable_missing"], 0, 0)
        expect(f"{key} held-out params agree with the registry", m["params_counted"],
               by_key[key]["params"], 0)
        if m["prediction_sha256_meta"] != a["s3_prediction_sha256_disk"]:
            BAD.append(f"{key}: the held-out metadata digest differs from the body on disk")
        if not (m["complete_value"] and m["settled"] and m["sha256_meta_matches_disk"]):
            BAD.append(f"{key}: the held-out body is not settled complete with a matching digest")
        v = s3_primary(key)
        x = v["s3_at_fpr_cap"][f"{FPR_CAP}"]
        expect(f"{key} held-out positives at the cap", x["tp"] + x["fn"],
               S3CORP["positives_A_B"], 0)
        expect(f"{key} held-out negatives at the cap", x["fp"] + x["tn"],
               S3CORP["negatives_D"], 0)
        expect(f"{key} held-out F1 at the cap", f1_of(x["tp"], x["fp"], x["fn"]), x["f1"], 5e-15)
        expect(f"{key} held-out FPR at the cap", x["fp"] / S3CORP["negatives_D"],
               x["fpr"], 5e-15)
        if x["fpr"] > FPR_CAP:
            BAD.append(f"{key}: held-out FPR {x['fpr']} exceeds the cap")
    expect("held-out row counts that are all equal",
           len({a["s3_prediction_rows"] for a in S3ARMS.values()}), 1, 0)
    expect("held-out prediction rows per arm",
           next(iter({a["s3_prediction_rows"] for a in S3ARMS.values()})), 100001, 0)
    for pos_i in (1, 2, 3):
        nm = AUTH["AUTHORITATIVE_RANKING"][f"rank_{pos_i}"]
        if nm not in S3ARMS:
            BAD.append(f"rank {pos_i} under the authoritative estimator, {nm}, has no settled "
                       f"held-out body, so the settlement claim does not cover it")
    # --- the ranking is never read off the retracted difference variable
    expect("rank 1 is not stable across every scheme",
           0 if AUTH["rank_stability"]["rank_1_stable"] else 1, 1, 0)
    expect("rank 2 is not stable across every scheme",
           0 if AUTH["rank_stability"]["rank_2_stable"] else 1, 1, 0)
    expect("rank 3 is contested across schemes",
           1 if AUTH["rank_stability"]["rank_3_is_contested_across_estimators"] else 0, 1, 0)

    # --- what more corpus would buy, on the held-out corpus's own arithmetic
    expect("pairwise comparisons tested", S3RES["pairs_tested"], 15, 0)
    expect("pairwise comparisons that separate", S3RES["pairs_significant_at_0.05"],
           S3RES["pairs_tested"], 0)
    expect("positives the held-out corpus holds", S3RES["positives"],
           S3CORP["positives_A_B"], 0)
    expect("benign cases the held-out corpus holds", S3RES["benign"],
           S3CORP["negatives_D"], 0)
    _t = tightest_pair()
    expect("positives that would have settled the narrowest pair", _t["proportional"], 32, 0)
    expect("the same under positive-only growth", _t["positives_only"], 31, 0)
    if _t["proportional"] >= S3RES["positives"]:
        BAD.append("the narrowest pair now needs at least as many positives as the corpus holds, "
                   "so the statement that more positives are unnecessary needs rewriting")
    _ceils = [v["sample_size_to_significance"]["proportional_growth"]["positives_needed_ceiling"]
              for v in S3["pairwise_delong_all_pairs"].values()]
    expect("pairs with a sample-size ceiling", len(_ceils), S3RES["pairs_tested"], 0)
    if max(_ceils) > S3RES["positives"]:
        BAD.append("some pair needs more positives than the corpus holds, which contradicts all "
                   "15 comparisons separating")
    _best = max(CANDS.values(), key=lambda a: a["cap_row"]["f1"])
    expect("Wilson upper bound on the best recall at the common budget",
           wilson(_best["cap_row"]["tp"], pos)[1], 0.08327404239553826, 5e-16)
    expect("Wilson lower bound on the same recall",
           wilson(_best["cap_row"]["tp"], pos)[0], 0.039137016728024596, 5e-16)

    # --- the held-out corpus carries no length cue, so raw AUC is its honest primary
    _lo3, _hi3 = S3BANDC["band_95pct"]
    for name, rec in S3C["s3_length_cue_no_model"].items():
        if not isinstance(rec, dict) or "auc_raw" not in rec:
            continue
        if rec["auc_raw"] > _hi3:
            BAD.append(f"the held-out corpus's {name} now reaches AUC {rec['auc_raw']}, above its "
                       f"chance band, so the no-length-cue statement needs rewriting")
    expect("held-out length proxies measured", sum(
        1 for rec in S3C["s3_length_cue_no_model"].values()
        if isinstance(rec, dict) and "auc_raw" in rec), 2, 0)
    expect("the held-out length fields are identical across every arm", sum(
        1 for v in S3C["s3_length_cue_no_model"]["corpus_field_identity_across_all_six_arms"]
        .values() if v["context_bytes_identical_to_reference"]
        and v["context_events_identical_to_reference"]), 6, 0)
    expect("s2's own length cue is larger than either held-out proxy",
           1 if LEAK["structural_cue_auc"]["natural_prompt_tokens (max over events)"]["auc"]
           > _hi3 else 0, 1, 0)

    # every ranked arm is a registry arm, and every registry arm is ranked or deployment-only
    reg_keys = {a["key"] for a in ROWS}
    for k in COH:
        if k not in reg_keys:
            BAD.append(f"{k}: ranked but absent from the arm registry")
    missing = sorted(reg_keys - set(COH))
    if missing:
        BAD.append(f"registry arms with neither a ranking nor a deployment row: {missing}")


# a scored arm's key in cohort-scores.json -> the registry key, or a reference key
SCORED_TO_ROSTER = {
    "deberta-v3-prompt-injection-v2": "deberta-v3-prompt-injection-v2",
    "control-modernbert-base": "control-modernbert-base",
    "control-modernbert-large": "control-modernbert-large",
}

MM: dict[str, dict[str, float]] = {}
DROPPED: dict[str, float] = {}


def settlement() -> dict:
    """What each ranked arm's metadata actually carries. The cohort runner writes neither
    `complete` nor `prediction_sha256`; `harness/settle.py` retrofits both and re-verifies. This
    reports the state of the artifacts on hand rather than assuming either."""
    out = {"arms": {}, "settled": 0, "unsettled": 0, "digest_mismatch": 0}
    for key, a in COH.items():
        rec = {"rows": a["rows"], "errors": a["errors"], "settled": a["settled"],
               "digest_matches_disk": a["digest_matches_disk"], "digest": a["digest"]}
        if a["settled"] and not a["digest_matches_disk"]:
            out["digest_mismatch"] += 1
            BAD.append(f"{key}: settled but its metadata digest does not match the bytes on disk")
        out["arms"][key] = rec
        out["settled" if a["settled"] else "unsettled"] += 1
    return out


SETTLE = None   # built after check_figures, which validates the row counts first

check_figures()
SETTLE = settlement()


# ------------------------------------------------------------- derived quantities

def pass_time(rows_per_min: float, rows: int = 3000) -> str:
    """Wall time for a pass of `rows` rows, rendered as hours and minutes."""
    total = int(round(rows / rows_per_min))
    return f"{total // 60}h{total % 60:02d}m"


DEC = LAPTOP["decoder_throughput_rows_per_min"]
FASTEST, SLOWEST = DEC[0], DEC[-1]
for _i in range(1, len(DEC)):
    if DEC[_i]["rows_per_min"] > DEC[_i - 1]["rows_per_min"]:
        BAD.append("the decoder throughput table is not in descending order")


# ------------------------------------------------------------- svg primitives

def esc(s) -> str:
    return html.escape(str(s), quote=True)


def fmt(v, nd=5) -> str:
    if v is None:
        return "n/a"
    return f"{v:.{nd}f}"


def pct(v, nd=2) -> str:
    return f"{v * 100:.{nd}f}%"


def num(v) -> str:
    return f"{v:,}"


def exact(v) -> str:
    """The shortest decimal string that round-trips to the same float, so a table cell carries
    the artifact's value and not a rounding of it."""
    if v is None:
        return "n/a"
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, int) or float(v) == int(v):
        return f"{int(v):,}"
    return repr(float(v))


MINUS = "&#8722;"
TIMES = "&#215;"
APPROX = "&#8776;"
MDASH = "&#8212;"


def signed(v, nd=5) -> str:
    return (MINUS if v < 0 else "+") + f"{abs(v):.{nd}f}"


# ---------------------------------------------------------------- chart palette
# Identical to the System One generator's table, and the same stylesheet, so the palette
# check below compares the two the same way.

SERIES: dict[str, str] = {
    "s1": "#2a78d6", "s2": "#eb6834", "s3": "#1baf7a", "s4": "#eda100",
    "s5": "#e87ba4", "s6": "#008300", "s7": "#4a3aa7", "s8": "#e34948",
    "seq1": "#86b6ef", "seq2": "#3987e5", "seq3": "#256abf", "seq4": "#104281",
    "pos1": "#86b6ef", "pos2": "#2a78d6", "neg1": "#f2a2a1", "neg2": "#d03b3b",
    "good": "#0ca30c", "warning": "#fab219", "serious": "#ec835a",
    "critical": "#d03b3b",
    "mid": "#f0efec",
    "surface": "#fcfcfb", "surface2": "#f2f1ed", "axis": "#c3c2b7",
    "ink": "#0b0b0b",
}
SERIES_VAR = {
    "s1": "series-1", "s2": "series-2", "s3": "series-3", "s4": "series-4",
    "s5": "series-5", "s6": "series-6", "s7": "series-7", "s8": "series-8",
    "seq1": "seq-1", "seq2": "seq-2", "seq3": "seq-3", "seq4": "seq-4",
    "pos1": "pos-1", "pos2": "pos-2", "neg1": "neg-1", "neg2": "neg-2",
    "good": "good", "warning": "warning", "serious": "serious",
    "critical": "critical", "mid": "mid", "surface": "surface", "surface2": "surface-2",
    "axis": "axis", "ink": "ink",
}
TEXT_ROLE = {
    "ax": ("#898781", "11"),
    "axl": ("#52514e", "11.5"),
    "vl": ("#0b0b0b", "11.5"),
    "hd": ("#0b0b0b", "11.5"),
}
LINE_ROLE = {
    "gl": ("#e1e0d9", "1"),
    "bl": ("#c3c2b7", "1"),
    "eb": ("#52514e", "1.5"),
}
ROLE_VAR = {"ax": "muted", "axl": "ink-2", "vl": "ink", "hd": "ink",
            "gl": "grid", "bl": "axis", "eb": "ink-2", "ref": "ink-2"}


def fa(slot: str) -> str:
    return f'class="f-{slot}" fill="{SERIES[slot]}"'


def sa(slot: str, w: str = "1.5") -> str:
    return f'class="k-{slot}" fill="none" stroke="{SERIES[slot]}" stroke-width="{w}"'


def _text_attrs(role: str) -> str:
    colour, size = TEXT_ROLE[role]
    return f'class="{role}" fill="{colour}" font-size="{size}"'


def _line_attrs(role: str) -> str:
    colour, w = LINE_ROLE[role]
    return f'class="{role}" fill="none" stroke="{colour}" stroke-width="{w}"'


AX = _text_attrs("ax")
AXL = _text_attrs("axl")
VL = _text_attrs("vl")
HD = _text_attrs("hd") + ' font-weight="640"'
GL = _line_attrs("gl")
BL = _line_attrs("bl")
REF = 'class="ref" fill="none" stroke="#52514e" stroke-width="1.5" stroke-dasharray="4 3"'


def check_css(css: str) -> list[str]:
    head = css.split(":root{", 1)[-1].split("}", 1)[0]
    light = dict(re.findall(r"--([a-z0-9-]+):(#[0-9a-fA-F]{6})", head))
    bad = []
    for slot, hexv in SERIES.items():
        if light.get(SERIES_VAR[slot]) != hexv:
            bad.append(f"slot {slot}: build.py {hexv} against --{SERIES_VAR[slot]} "
                       f"{light.get(SERIES_VAR[slot])!r}")
    for role, (hexv, _sz) in TEXT_ROLE.items():
        if light.get(ROLE_VAR[role]) != hexv:
            bad.append(f"text role {role}: build.py {hexv} against --{ROLE_VAR[role]}")
    for role, (hexv, _w) in LINE_ROLE.items():
        if light.get(ROLE_VAR[role]) != hexv:
            bad.append(f"line role {role}: build.py {hexv} against --{ROLE_VAR[role]}")
    for cls in list(TEXT_ROLE) + list(LINE_ROLE) + ["ref"] + [f"f-{s}" for s in SERIES]:
        if f".{cls}{{" not in css:
            bad.append(f"stylesheet has no .{cls} rule, so dark mode would not swap it")
    return bad


def swatch(slot: str) -> str:
    return (f'<svg class="sw" viewBox="0 0 11 11" width="11" height="11" aria-hidden="true">'
            f'<rect x="0" y="0" width="11" height="11" rx="3" {fa(slot)}/></svg>')


_FIT: list[str] = []
_ADV = 0.545


def textw(s: str, size: float = 11.5) -> float:
    plain = re.sub(r"&#\d+;", "-", s)
    wide = sum(1 for ch in plain if ch in "MWmw@%0123456789")
    return (len(plain) + 0.22 * wide) * _ADV * size


def fit(label: str, budget: float, size: float = 11.5, where: str = "") -> str:
    w = textw(label, size)
    if w > budget:
        _FIT.append(f"{where}: {label!r} needs {APPROX}{w:.0f}px in a {budget:.0f}px gutter")
    return label


# ------------------------------------------------ the markup / escaping gate
# Ported from the System One generator: a figure assertion cannot see a string that was
# escaped twice, because the double-escaped form carries the same digits.

_SKIP_BLOCK = re.compile(r"<(script|style)\b[^>]*>.*?</\1>", re.S | re.I)
_ENTITY = re.compile(r"&(#[0-9]{1,7}|#[xX][0-9a-fA-F]{1,6}|[A-Za-z][A-Za-z0-9]{1,31});")
_BAD_LT = re.compile(r"<(?!/?[A-Za-z][A-Za-z0-9]*[\s/>]|!--|!\[|!DOCTYPE|\?)", re.I)
_ESCAPED_TAG = re.compile(
    r"&lt;/?(code|em|strong|a|span|br|p|li|ul|ol|sup|sub|abbr|table|thead|tbody|tr|td|th|div|"
    r"h[1-6]|figure|figcaption|details|summary|svg|text|g|rect|path)\b", re.I)


def check_scope(name: str, body: str) -> list[str]:
    """No page may name a Jev-family model or a System One board arm. The scope rule is the
    user's, and it is enforced over the generated bytes rather than trusted to the templates."""
    low = body.lower()
    return [f"{name}: names the out-of-scope model or arm {tok!r}, which belongs on the "
            f"System One Space"
            for tok in SCOPE["forbidden_tokens"] if tok in low]


def check_markup(name: str, body: str) -> list[str]:
    text = _SKIP_BLOCK.sub(lambda m: " " * len(m.group(0)), body)

    def where(off: int) -> str:
        return f"line {text.count(chr(10), 0, off) + 1}: ...{body[max(0, off - 70):off + 70]!r}..."

    bad: list[str] = []
    once = html.unescape(text)
    for m in _ENTITY.finditer(once):
        bad.append(f"{name}: double-escaped {m.group(0)!r}: "
                   f"...{once[max(0, m.start() - 70):m.end() + 70]!r}...")
    for m in re.finditer(r"&", text):
        if not _ENTITY.match(text, m.start()):
            bad.append(f"{name}: raw '&' that starts no entity reference, {where(m.start())}")
    for m in _BAD_LT.finditer(text):
        bad.append(f"{name}: raw '<' that opens no tag, {where(m.start())}")
    for m in _ESCAPED_TAG.finditer(text):
        bad.append(f"{name}: escaped markup {m.group(0)!r} renders as literal text, "
                   f"{where(m.start())}")
    return bad



# ------------------------------------------------------------- layout collisions
# fit() measures a label against the canvas, so it passes while two labels sit on top of each
# other. This re-reads the finished SVG and reports overlapping text boxes, which is the failure
# that put three end-of-line labels inside one line height on the quintile chart.
_PAD = 1.0
_ATTR = re.compile(r'\b([a-z-]+)="([^"]*)"')
_TEXT = re.compile(r"<text\b([^>]*)>(.*?)</text>", re.S)


def _boxes(svg: str):
    for m in _TEXT.finditer(svg):
        attrs = dict(_ATTR.findall(m.group(1)))
        inner = re.sub(r"<[^>]+>", "", m.group(2)).strip()
        if not inner or "transform" in m.group(1):
            continue
        try:
            x = float(attrs["x"])
            y = float(attrs["y"])
            size = float(attrs.get("font-size", "11.5"))
        except (KeyError, ValueError):
            continue
        w = textw(inner, size)
        anchor = attrs.get("text-anchor", "start")
        left = x if anchor == "start" else (x - w if anchor == "end" else x - w / 2)
        yield (left, y - size * 0.80, left + w, y + size * 0.26, inner)


def audit_layout(name: str, svg: str) -> list[str]:
    out = []
    boxes = list(_boxes(svg))
    for i in range(len(boxes)):
        ax0, ay0, ax1, ay1, at = boxes[i]
        for j in range(i + 1, len(boxes)):
            bx0, by0, bx1, by1, bt = boxes[j]
            if (ax0 < bx1 - _PAD and bx0 < ax1 - _PAD
                    and ay0 < by1 - _PAD and by0 < ay1 - _PAD):
                out.append(f"{name}: text {at[:34]!r} overlaps {bt[:34]!r}")
    return out


_LAYOUT: list[str] = []


# --------------------------------------------------------------------- figures

def figure(fid, title, sub, svg, source, legend=None, table=None, note=None) -> str:
    _LAYOUT.extend(audit_layout(fid, svg))
    parts = [f'<figure class="chart" id="{esc(fid)}">',
             f'<p class="ftitle">{title}</p>']
    if sub:
        parts.append(f'<p class="fsub">{sub}</p>')
    if legend:
        parts.append('<div class="legend">'
                     + "".join(f"<span>{swatch(c)}{esc(l)}</span>" for l, c in legend)
                     + "</div>")
    parts.append(svg)
    if table:
        parts.append('<details class="tv"><summary>Table view (every plotted value)</summary>'
                     f'<div class="tbl-scroll">{table}</div></details>')
    prov = (f"Every value plotted here is read at build time from <code>{esc(source)}</code>. "
            f"The table view lists them all.")
    parts.append(f"<figcaption>{note + ' ' if note else ''}{prov}</figcaption></figure>")
    return "\n".join(parts)


def table_html(headers, rows, numeric_from=1) -> str:
    th = "".join(f'<th class="{"n" if i >= numeric_from else ""}">{h}</th>'
                 for i, h in enumerate(headers))
    trs = "".join("<tr>" + "".join(f'<td class="{"n" if i >= numeric_from else ""}">{c}</td>'
                                   for i, c in enumerate(r)) + "</tr>" for r in rows)
    return f'<table><thead><tr>{th}</tr></thead><tbody>{trs}</tbody></table>'


# ------------------------------------------------------------- chart scaffolding

def hbars(rows, vmax, *, width=880, gutter=250, rowh=24, pad_right=78, vticks=None,
          refs=(), bands=(), where="") -> str:
    """Horizontal bars. `rows` is a list of (label, value, slot) or
    (label, [(value, slot), ...]) for grouped bars sharing one label."""
    x0 = gutter
    plot = width - gutter - pad_right
    groups = []
    for r in rows:
        label, payload = r[0], r[1]
        groups.append((label, payload if isinstance(payload, list) else [(payload, r[2])]))
    per = max(len(g[1]) for g in groups)
    gh = rowh * per + (10 if per > 1 else 6)
    top = 30
    height = top + gh * len(groups) + 34

    def sx(v):
        return x0 + plot * (v / vmax)

    out = [f'<svg viewBox="0 0 {width} {height}" role="img">']
    for lo, hi, slot, _lbl in bands:
        out.append(f'<rect x="{sx(lo):.1f}" y="{top - 8:.1f}" width="{sx(hi) - sx(lo):.1f}" '
                   f'height="{gh * len(groups) + 8:.1f}" {fa(slot)}/>')
    ticks = vticks if vticks is not None else [i * vmax / 5 for i in range(6)]
    for t in ticks:
        out.append(f'<line x1="{sx(t):.1f}" y1="{top - 8:.1f}" x2="{sx(t):.1f}" '
                   f'y2="{top + gh * len(groups):.1f}" {GL}/>')
        lab = f"{t:g}"
        out.append(f'<text x="{sx(t):.1f}" y="{top + gh * len(groups) + 16:.1f}" '
                   f'text-anchor="middle" {AX}>{lab}</text>')
    for v, slot, lab in refs:
        out.append(f'<line x1="{sx(v):.1f}" y1="{top - 14:.1f}" x2="{sx(v):.1f}" '
                   f'y2="{top + gh * len(groups) + 2:.1f}" {REF}/>')
        out.append(f'<text x="{sx(v):.1f}" y="{top - 18:.1f}" text-anchor="middle" '
                   f'{AX}>{fit(lab, 260, 11, where)}</text>')
    for gi, (label, payload) in enumerate(groups):
        gy = top + gh * gi
        out.append(f'<text x="{x0 - 10:.1f}" y="{gy + gh / 2 + 4:.1f}" text-anchor="end" '
                   f'{AXL}>{fit(label, gutter - 16, 11.5, where)}</text>')
        for bi, (v, slot) in enumerate(payload):
            by = gy + (gh - rowh * per) / 2 + rowh * bi + 3
            w = max(0.6, sx(v) - x0)
            out.append(f'<rect x="{x0:.1f}" y="{by:.1f}" width="{w:.1f}" '
                       f'height="{rowh - 6:.1f}" rx="2" {fa(slot)}/>')
            if vmax <= 1.2:
                vlabel = f"{v:.4f}"
            elif v == int(v):
                vlabel = f"{int(v):,}"
            else:
                vlabel = f"{v:,.2f}"
            out.append(f'<text x="{x0 + w + 6:.1f}" y="{by + rowh - 11:.1f}" '
                       f'{VL}>{vlabel}</text>')
    out.append(f'<line x1="{x0:.1f}" y1="{top - 8:.1f}" x2="{x0:.1f}" '
               f'y2="{top + gh * len(groups):.1f}" {BL}/>')
    out.append("</svg>")
    return "\n".join(out)


def lines(series, *, width=880, height=320, xlabels, ymin=0.0, ymax=1.0, ylabel="",
          where="") -> str:
    """One polyline per series over an evenly spaced categorical x axis."""
    left, right, top, bottom = 58, 210, 26, 46
    plot_w = width - left - right
    plot_h = height - top - bottom
    n = len(xlabels)
    step = plot_w / max(1, n - 1)

    def px(i):
        return left + step * i

    def py(v):
        return top + plot_h * (1 - (v - ymin) / (ymax - ymin))

    out = [f'<svg viewBox="0 0 {width} {height}" role="img">']
    for k in range(6):
        v = ymin + (ymax - ymin) * k / 5
        out.append(f'<line x1="{left}" y1="{py(v):.1f}" x2="{left + plot_w:.1f}" '
                   f'y2="{py(v):.1f}" {GL}/>')
        out.append(f'<text x="{left - 8}" y="{py(v) + 4:.1f}" text-anchor="end" '
                   f'{AX}>{v:.1f}</text>')
    out.append(f'<line x1="{left}" y1="{py(0.5):.1f}" x2="{left + plot_w:.1f}" '
               f'y2="{py(0.5):.1f}" {REF}/>')
    for i, lab in enumerate(xlabels):
        out.append(f'<text x="{px(i):.1f}" y="{top + plot_h + 18:.1f}" text-anchor="middle" '
                   f'{AX}>{fit(lab, step - 4, 11, where)}</text>')
    for label, slot, vals in series:
        pts = " ".join(f"{px(i):.1f},{py(v):.1f}" for i, v in enumerate(vals))
        out.append(f'<polyline points="{pts}" {sa(slot, "2")}/>')
        for i, v in enumerate(vals):
            out.append(f'<circle cx="{px(i):.1f}" cy="{py(v):.1f}" r="3" {fa(slot)}/>')
    # End-of-line labels, spread vertically. Three series can finish within 0.04 AUC of each
    # other, which puts their labels inside one line height; a leader line keeps each label tied
    # to its own point once it has been moved off it.
    ends = sorted(((py(vals[-1]), label, slot) for label, slot, vals in series),
                  key=lambda t: t[0])
    gap = 15.0
    placed: list[float] = []
    for y0, _lab, _slot in ends:
        y = y0 if not placed else max(y0, placed[-1] + gap)
        placed.append(y)
    # keep the whole stack on canvas
    overflow = placed[-1] - (top + plot_h)
    if overflow > 0:
        placed = [y - overflow for y in placed]
    for (y0, label, slot), y in zip(ends, placed):
        x = px(n - 1)
        if abs(y - y0) > 1.5:
            out.append(f'<line x1="{x + 3:.1f}" y1="{y0:.1f}" x2="{x + 7:.1f}" '
                       f'y2="{y:.1f}" {sa(slot, "1")}/>')
        out.append(f'<text x="{x + 10:.1f}" y="{y + 4:.1f}" '
                   f'{AXL}>{fit(label, right - 16, 11.5, where)}</text>')
    if ylabel:
        out.append(f'<text x="{left}" y="{top - 10}" {AX}>{ylabel}</text>')
    out.append(f'<line x1="{left}" y1="{top}" x2="{left}" y2="{top + plot_h:.1f}" {BL}/>')
    out.append(f'<line x1="{left}" y1="{top + plot_h:.1f}" x2="{left + plot_w:.1f}" '
               f'y2="{top + plot_h:.1f}" {BL}/>')
    out.append("</svg>")
    return "\n".join(out)


def stacked(rows, vmax, *, width=880, gutter=210, rowh=34, pad_right=96, unit="GiB",
            refs=(), where="") -> str:
    """One horizontal stacked bar per row. `rows` is (label, [(seg_value, slot), ...])."""
    x0 = gutter
    plot = width - gutter - pad_right
    top = 34
    height = top + rowh * len(rows) + 34

    def sx(v):
        return x0 + plot * (v / vmax)

    out = [f'<svg viewBox="0 0 {width} {height}" role="img">']
    for k in range(6):
        v = vmax * k / 5
        out.append(f'<line x1="{sx(v):.1f}" y1="{top - 8:.1f}" x2="{sx(v):.1f}" '
                   f'y2="{top + rowh * len(rows):.1f}" {GL}/>')
        out.append(f'<text x="{sx(v):.1f}" y="{top + rowh * len(rows) + 16:.1f}" '
                   f'text-anchor="middle" {AX}>{v:.1f}</text>')
    for v, lab in refs:
        out.append(f'<line x1="{sx(v):.1f}" y1="{top - 16:.1f}" x2="{sx(v):.1f}" '
                   f'y2="{top + rowh * len(rows) + 2:.1f}" {REF}/>')
        out.append(f'<text x="{sx(v):.1f}" y="{top - 20:.1f}" text-anchor="middle" '
                   f'{AX}>{fit(lab, 200, 11, where)}</text>')
    for ri, (label, segs) in enumerate(rows):
        y = top + rowh * ri + 4
        out.append(f'<text x="{x0 - 10:.1f}" y="{y + rowh / 2 + 1:.1f}" text-anchor="end" '
                   f'{AXL}>{fit(label, gutter - 16, 11.5, where)}</text>')
        acc = 0.0
        for val, slot in segs:
            w = max(0.6, sx(acc + val) - sx(acc))
            out.append(f'<rect x="{sx(acc):.1f}" y="{y:.1f}" width="{w:.1f}" '
                       f'height="{rowh - 12:.1f}" rx="2" {fa(slot)}/>')
            acc += val
        out.append(f'<text x="{sx(acc) + 7:.1f}" y="{y + rowh - 15:.1f}" '
                   f'{VL}>{acc:.3f} {unit}</text>')
    out.append(f'<line x1="{x0:.1f}" y1="{top - 8:.1f}" x2="{x0:.1f}" '
               f'y2="{top + rowh * len(rows):.1f}" {BL}/>')
    out.append("</svg>")
    return "\n".join(out)


# ============================================================ chart definitions

VAR_LABELS = {
    "deberta P(injection.true) [single scalar, A==B]":
        ("deberta-v3-prompt-injection-v2", "s1"),
    "pure length counter (natural prompt tokens)":
        ("prompt tokens, no model", "s4"),
}


def chart_ranking() -> str:
    """The ranking. Raw AUC beside length-controlled AUC, with the chance band drawn."""
    lo, hi = BAND["chance_95pct_interval"]
    rows, trows = [], []
    for i, a in enumerate(by_lc(), 1):
        rows.append((alabel(a["key"]),
                     [(a["auc_lc"], "seq3" if not a["is_control"] else "s5"),
                      (a["auc_raw"], "seq1")]))
        trows.append([("&#8212;" if a["is_control"] else str(i)), alabel(a["key"]),
                      "negative control" if a["is_control"] else a["class_structure"],
                      fmt(a["auc_lc"], 12), fmt(a["auc_raw"], 12),
                      fmt(a["shipped"]["f1"], 12) if a["shipped"] else "n/a",
                      fmt(a["flag_rate"], 8) if a["flag_rate"] is not None else "n/a",
                      num(a["cap_tokens"]), num(a["shrunk"]),
                      fmt(a["cap_row"]["recall"], 10)])
    svg = hbars(rows, 1.0, gutter=252, rowh=17, pad_right=84,
                vticks=[0, 0.2, 0.4, 0.5, 0.6, 0.8, 1.0],
                bands=[(lo, hi, "mid", "null band")],
                refs=[(0.5, "ink", "chance 0.5")], where="ranking")
    beat = [a for a in CANDS.values() if a["auc_lc"] > BASE["auc_lc"]]
    under = [a for a in CANDS.values() if a["auc_lc"] < lo]
    return figure(
        "ranking",
        "Length-controlled AUC beside raw AUC, every ranked arm",
        f'Each arm is ranked on one fixed variable chosen by its class structure, never selected '
        f'per arm. Length-controlled AUC is the unweighted mean of the five within-quintile AUCs. '
        f'The grey band is the 95% chance interval for {num(BAND["npos"])} positives and '
        f'{num(BAND["nneg"])} negatives, [{fmt(lo, 15)}, {fmt(hi, 15)}]. '
        f'{len(beat)} of the {len(CANDS)} candidates score above the untrained '
        f'<code>control-modernbert-base</code>, and {len(under)} fall below the band.',
        svg, "cohort-rank.json",
        legend=[("Length-controlled AUC, candidate", "seq3"),
                ("Length-controlled AUC, control", "s5"), ("Raw AUC", "seq1")],
        table=table_html(["#", "Arm", "Class", "Length-controlled AUC", "Raw AUC",
                          "Shipped F1", "Flag rate", "Cap tokens", "Rows shrunk",
                          "Recall at the FPR cap"], trows, numeric_from=3),
        note="The two controls carry no rank. Rank 1 ran at a 510-token cap and lost context on "
             "some rows; the arms at ranks 2 and 3 ran at cap 6,144 with zero rows shrunk.")


def chart_quintiles() -> str:
    xl = ["Q1 71&#8211;89", "Q2 90&#8211;236", "Q3 237&#8211;673",
          "Q4 674&#8211;1077", "Q5 1078&#8211;3379"]
    ser = []
    for key in ("deberta P(injection.true) [single scalar, A==B]",
                "pure length counter (natural prompt tokens)"):
        rec = LCA[key]
        label, slot = VAR_LABELS[key]
        ser.append((label, slot, [rec["per_quintile"][str(i)]["auc"] for i in range(5)]))
    for key, slot in (("control-modernbert-base", "s3"), ("control-modernbert-large", "s5")):
        q = LEAK["controls"][key]["auc_within_length_quintile"]
        ser.append((key.replace("control-", ""), slot,
                    [q[f"length_quintile_{i}"]["auc"] for i in range(5)]))
    svg = lines(ser, xlabels=xl, ylabel="AUC within the quintile", where="quintiles")
    trows = []
    q0 = LCA["pure length counter (natural prompt tokens)"]["per_quintile"]
    for i in range(5):
        trows.append([f"Q{i + 1}", num(q0[str(i)]["cases"]), num(q0[str(i)]["positives"])]
                     + [fmt(s[2][i], 10) for s in ser])
    return figure(
        "quintiles",
        "AUC inside each prompt-length quintile",
        "Stratifying on prompt length removes the length component from every arm's score. "
        "The length counter falls to "
        f"{fmt(LCA['pure length counter (natural prompt tokens)']['mean_within_length_quintile_auc'], 10)} "
        "under its own control, and both MLM controls land inside the chance band.",
        svg, "cohort-scoring/final-comparisons.json, leakage-diagnostic.json",
        table=table_html(["Quintile", "Cases", "Positives"] + [s[0] for s in ser], trows),
        note="Quintile 1 carries 2 positives, so its AUC rests on two cases and is the "
             "noisiest column in the chart.")


def chart_floor() -> str:
    rows, trows = [], []
    for a in by_shipped():
        sh = a["shipped"]
        rows.append((alabel(a["key"]), sh["f1"], arm_slot(a)))
        trows.append([alabel(a["key"]), "negative control" if a["is_control"] else "candidate",
                      fmt(sh["f1"], 12), num(sh["tp"]), num(sh["fp"]), num(sh["fn"]),
                      num(sh["tn"]), fmt(sh["precision"], 10) if sh["tp"] + sh["fp"] else "n/a",
                      fmt(sh["recall"], 10), fmt(sh["block_fpr"], 10)])
    rows.append(("block every case", FLOOR["f1"], "axis"))
    trows.append(["block every case", "trivial baseline", fmt(FLOOR["f1"], 12),
                  num(FLOOR["tp"]), num(FLOOR["fp"]), num(FLOOR["fn"]), num(FLOOR["tn"]),
                  fmt(FLOOR["precision"], 10), fmt(FLOOR["recall"], 1),
                  fmt(FLOOR["block_fpr"], 1)])
    below = [a for a in CANDS.values() if a["shipped"] and a["shipped"]["f1"] < FLOOR["f1"]]
    zeros = [a for a in CANDS.values() if a["shipped"] and a["shipped"]["f1"] == 0.0]
    svg = hbars(rows, 0.4, gutter=252, rowh=21, pad_right=84,
                vticks=[0, 0.1, 0.2, 0.3, 0.4],
                refs=[(FLOOR["f1"], "ink", f'block everything {fmt(FLOOR["f1"], 5)}')],
                where="floor")
    return figure(
        "floor",
        "Block-only F1 at each arm's shipped operating point",
        f'Blocking every case scores {fmt(FLOOR["f1"], 17)} at '
        f'{pct(CORPUS["prevalence"])} prevalence, at a block false-positive rate of '
        f'{fmt(FLOOR["block_fpr"], 1)}. {len(below)} of the '
        f'{sum(1 for a in CANDS.values() if a["shipped"])} candidates with a shipped decision '
        f'score below that line, and {len(zeros)} score exactly zero at it. Each arm\'s own '
        f'argmax is a separate figure and is an in-sample upper bound.',
        svg, "cohort-rank.json",
        legend=[("Candidate", "seq3"), ("MLM negative control", "s5"),
                ("Trivial baseline, no model", "axis")],
        table=table_html(["Arm", "Role", "Block-only F1", "tp", "fp", "fn", "tn", "Precision",
                          "Recall", "Block FPR"], trows, numeric_from=2),
        note="Argmax F1 is a calibration diagnostic. Every cell is counted from rows.")


def chart_cues() -> str:
    cues = SCORES and LEAK["structural_cue_auc"]
    order = sorted(cues.items(), key=lambda kv: -kv[1]["auc"])
    rows = [(k.replace(" (max over events)", ", max").replace(" (sum over events)", ", sum")
             .replace("event_count_in_prediction", "event count")
             .replace("context_events", "context events")
             .replace("context_bytes", "context bytes")
             .replace("natural_prompt_tokens", "prompt tokens"), v["auc"], "s4")
            for k, v in order]
    lo, hi = BAND["chance_95pct_interval"]
    svg = hbars(rows, 1.0, gutter=210, rowh=25, pad_right=84,
                vticks=[0, 0.2, 0.4, 0.5, 0.6, 0.8, 1.0],
                bands=[(lo, hi, "mid", "null band")],
                refs=[(0.5, "ink", "chance 0.5")], where="cues")
    trows = [[k, fmt(v["auc"], 10), num(v["at_threshold"]), fmt(v["best_f1_ORACLE"], 10)]
             for k, v in order]
    return figure(
        "cues",
        "AUC of five counting variables that contain no model",
        "Each row is a scalar read off the request: how long the prompt is, how many events "
        "the context carries, how many bytes. Destructive multi-step trajectories in this "
        "corpus are longer than benign ones, which is a property of the data-generating "
        "process.",
        svg, "cohort-scoring/leakage-diagnostic.json",
        table=table_html(["Counting variable", "AUC", "Oracle threshold",
                          "Oracle best F1"], trows),
        note="The oracle best-F1 column is an in-sample upper bound.")


def chart_deberta_points() -> str:
    blk = DEB["shipped_argmax_recomputed_from_rows"]["block_only"]
    orc = DEB["by_variable"]["P(injection.true)  [the arm's ONLY scalar]"][
        "best_f1_ORACLE_IN_SAMPLE_UPPER_BOUND_NOT_A_RESULT"]
    rows = [
        ("Recall, argmax at 0.5", blk["recall"], "seq3"),
        ("Recall, oracle threshold", orc["recall"], "seq1"),
        ("Block FPR, argmax at 0.5", blk["fpr"], "neg2"),
        ("Block FPR, oracle threshold", orc["fpr"], "neg1"),
        ("Block-only F1, argmax at 0.5", blk["f1"], "s7"),
        ("Block-only F1, oracle threshold", orc["f1"], "s5"),
    ]
    svg = hbars(rows, 1.0, gutter=252, rowh=25, pad_right=84,
                vticks=[0, 0.2, 0.4, 0.6, 0.8, 1.0],
                refs=[(TRIVIAL["block_every_case"]["f1"], "ink",
                       f"trivial floor {fmt(TRIVIAL['block_every_case']['f1'], 5)}")],
                where="deberta_points")
    trows = [["argmax at 0.5", fmt(blk["f1"], 12), fmt(blk["precision"], 10),
              fmt(blk["recall"], 10), fmt(blk["fpr"], 10), num(blk["tp"]), num(blk["fp"]),
              num(blk["fn"]), num(blk["tn"])],
             [f'oracle threshold {fmt(orc["threshold"], 16)}', fmt(orc["f1"], 12),
              fmt(orc["precision"], 10), fmt(orc["recall"], 10), fmt(orc["fpr"], 10),
              num(orc["tp"]), num(orc["fp"]), num(orc["fn"]), num(orc["tn"])]]
    return figure(
        "deberta-points",
        "deberta-v3-prompt-injection-v2 at two operating points",
        f"The arm emits <code>block</code> on {num(DEB['row_level_action_histogram']['block'])} "
        f"of {num(DEB['prediction_rows'])} rows and "
        f"{num(DEB['shipped_action_histogram_case_level']['block'])} of "
        f"{num(CORPUS['scorable_cases_A_B_D'])} scored cases "
        f"({pct(DEB['shipped_action_histogram_case_level']['block'] / CORPUS['scorable_cases_A_B_D'], 1)}). "
        f"Its oracle threshold sits at {fmt(orc['threshold'], 16)}.",
        svg, "cohort-scoring/cohort-scores.json",
        legend=[("Argmax at 0.5, the shipped point", "seq3"), ("Oracle threshold", "seq1"),
                ("Block FPR at argmax", "neg2"), ("Block FPR at the oracle threshold", "neg1")],
        table=table_html(["Operating point", "Block-only F1", "Precision", "Recall",
                          "Block FPR", "tp", "fp", "fn", "tn"], trows),
        note="The oracle threshold was fitted on the rows it is scored on, so every figure "
             "in its column is an in-sample upper bound.")


def chart_trunc() -> str:
    ec = TRUNC["error_correlation"]
    st = ec["auc_within_stratum"]
    rows = [
        (f'truncated, {num(st["truncated_cases"]["cases"])} cases',
         [(st["truncated_cases"]["auc"], "seq3"),
          (ec["at_oracle_best_f1_threshold"]["truncated_cases"]["f1"], "seq1"),
          (ec["prevalence_confound"]["positive_rate_truncated_cases"], "s4")]),
        (f'untruncated, {num(st["untruncated_cases"]["cases"])} cases',
         [(st["untruncated_cases"]["auc"], "seq3"),
          (ec["at_oracle_best_f1_threshold"]["untruncated_cases"]["f1"], "seq1"),
          (ec["prevalence_confound"]["positive_rate_untruncated_cases"], "s4")]),
    ]
    svg = hbars(rows, 1.0, gutter=228, rowh=24, pad_right=84,
                vticks=[0, 0.2, 0.4, 0.5, 0.6, 0.8, 1.0],
                refs=[(0.5, "ink", "chance 0.5")], where="trunc")
    sc = TRUNC["scored_corpus"]
    trows = [
        ["Rows over 510 tokens in the full pass",
         f'{num(TRUNC["runner_reported_rows_shrunk"])} of '
         f'{num(TRUNC["runner_total_rows"])}', pct(TRUNC["runner_fraction_rows_shrunk"])],
        ["Rows over 510 tokens inside the scored set",
         f'{num(sc["rows_over_512_in_scored_cases"])} of '
         f'{num(sc["rows_belonging_to_scored_cases"])}', pct(sc["rows_over_512_fraction"])],
        ["Cases with at least one truncated event",
         f'{num(sc["cases_with_at_least_one_event_over_512"])} of '
         f'{num(sc["scored_cases"])}',
         pct(sc["cases_with_at_least_one_event_over_512_fraction"])],
        ["Cases with every event truncated",
         num(sc["cases_with_every_event_over_512"]),
         pct(sc["cases_with_every_event_over_512"] / sc["scored_cases"])],
    ]
    return figure(
        "trunc",
        "DeBERTa's 512-token window, and whether it tracks the errors",
        f"The cap is <code>{esc(TRUNC['cap_derivation'])}</code>. A row counted shrunk lost "
        f"context the model never saw. AUC inside the truncated stratum is "
        f"{fmt(st['truncated_cases']['auc'], 10)} against "
        f"{fmt(st['untruncated_cases']['auc'], 10)} untruncated.",
        svg, "cohort-scoring/cohort-scores.json",
        legend=[("AUC within the stratum", "seq3"),
                ("F1 at the oracle threshold", "seq1"),
                ("Positive prevalence in the stratum", "s4")],
        table=table_html(["Extent of truncation", "Count", "Share"], trows, numeric_from=1),
        note=f"Prevalence differs "
             f"{ec['prevalence_confound']['positive_rate_truncated_cases'] / ec['prevalence_confound']['positive_rate_untruncated_cases']:.1f}"
             f"{TIMES} between the strata, so raw error rates are not comparable across them. "
             f"The F1 column is an in-sample upper bound.")


def chart_control_dist() -> str:
    rows, trows = [], []
    for key, slot in (("control-modernbert-base", "s3"),
                      ("control-modernbert-large", "s5")):
        d = LEAK["controls"][key]["score_distribution"]
        rows.append((key.replace("control-", ""),
                     [(d["p95"] - d["p05"], slot),
                      (d["interquartile_width"], "seq1")]))
        trows.append([key, num(d["distinct_values"]), fmt(d["min"], 6), fmt(d["p05"], 6),
                      fmt(d["median"], 3), fmt(d["p95"], 6), fmt(d["max"], 6),
                      fmt(d["interquartile_width"], 10),
                      fmt(LEAK["controls"][key]["spearman_score_vs_natural_prompt_length"], 10)])
    svg = hbars(rows, 0.3, gutter=170, rowh=24, pad_right=90,
                vticks=[0, 0.05, 0.1, 0.15, 0.2, 0.25, 0.3], where="ctl_dist")
    return figure(
        "control-dist",
        "How wide the two MLM controls' readouts are",
        "Both controls are untrained <code>ModernBertForMaskedLM</code> backbones with no "
        "trained head, read by a zero-shot masked-token yes/no probe. Each has a median of "
        "exactly 0.5 and a few dozen distinct values across "
        f"{num(CORPUS['scorable_cases_A_B_D'])} cases.",
        svg, "cohort-scoring/leakage-diagnostic.json",
        legend=[("5th to 95th percentile width, base", "s3"),
                ("5th to 95th percentile width, large", "s5"),
                ("Interquartile width", "seq1")],
        table=table_html(["Control", "Distinct values", "Min", "p05", "Median", "p95", "Max",
                          "IQR width", "Spearman against prompt length"], trows))


def chart_throughput() -> str:
    rows, trows = [], []
    for r in DEC:
        rows.append((r["label"], r["rows_per_min"], "seq3"))
        trows.append([r["label"], "decoder, Q4_K_M", fmt(r["rows_per_min"], 2), "1,200",
                      pass_time(r["rows_per_min"])])
    for r in LAPTOP["encoder_throughput_rows_per_min"]:
        rows.append((r["label"], r["rows_per_min"], "s3"))
        trows.append([r["label"], "encoder, dynamic int8", fmt(r["rows_per_min"], 2),
                      num(r["context_tokens"]), pass_time(r["rows_per_min"])])
    svg = hbars(rows, 200, gutter=250, rowh=23, pad_right=84,
                vticks=[0, 40, 80, 120, 160, 200], where="throughput")
    return figure(
        "throughput",
        "Rows per minute on 8 pinned CPU threads",
        f"Latency model <code>{esc(LAPTOP['provenance']['measurement_conditions']['latency_model'])}</code>, "
        f"from <code>{esc(LAPTOP['provenance']['measurement_conditions']['bench_command'])}</code>. "
        f"A 3,000-row pass takes {pass_time(FASTEST['rows_per_min'])} on "
        f"{esc(FASTEST['label'])} and {pass_time(SLOWEST['rows_per_min'])} on "
        f"{esc(SLOWEST['label'])}. DeBERTa-v3-base reaches its figure only at 512 tokens, "
        f"its architectural maximum.",
        svg, "pinned/laptop-feasibility.json",
        legend=[("Decoder, GGUF Q4_K_M under llama.cpp", "seq3"),
                ("Encoder, dynamic int8", "s3")],
        table=table_html(["Arm", "Serving", "Rows/min", "Context tokens",
                          "3,000-row pass"], trows),
        note="The host carried foreign load throughout and a real laptop also thermally "
             "throttles, so every figure here is an optimistic ceiling.")


def chart_envelope() -> str:
    m = LAPTOP["memory"]
    rows = [
        (f'Q4_K_M, {esc(m["q4_k_m_gib_min"]["label"])} (smallest)',
         m["q4_k_m_gib_min"]["gib"], "seq1"),
        (f'Q4_K_M, {esc(m["q4_k_m_gib_max"]["label"])} (largest)',
         m["q4_k_m_gib_max"]["gib"], "seq3"),
        (f'Peak RSS, {esc(m["peak_rss_hungriest"]["label"])} (irreducible)',
         m["peak_rss_hungriest"]["irreducible_gib"], "s2"),
        (f'Peak RSS, {esc(m["peak_rss_hungriest"]["label"])} (worst observed)',
         m["peak_rss_hungriest"]["worst_observed_under_mmap_gib"], "s4"),
    ]
    headroom = 8 - m["peak_rss_hungriest"]["irreducible_gib"]
    svg = hbars(rows, 24, gutter=282, rowh=27, pad_right=90,
                vticks=[0, 4, 8, 12, 16, 20, 24],
                refs=[(8, "ink", "8 GiB"), (24, "ink", "24 GiB")], where="envelope")
    trows = [
        ["Q4_K_M file, smallest", m["q4_k_m_gib_min"]["label"],
         fmt(m["q4_k_m_gib_min"]["gib"], 3)],
        ["Q4_K_M file, largest", m["q4_k_m_gib_max"]["label"],
         fmt(m["q4_k_m_gib_max"]["gib"], 3)],
        ["Peak RSS, irreducible", m["peak_rss_hungriest"]["label"],
         fmt(m["peak_rss_hungriest"]["irreducible_gib"], 3)],
        ["Peak RSS, worst observed under mmap", m["peak_rss_hungriest"]["label"],
         fmt(m["peak_rss_hungriest"]["worst_observed_under_mmap_gib"], 3)],
    ]
    return figure(
        "envelope",
        "The cohort's memory envelope against an 8 GiB and a 24 GiB machine",
        f"Nothing in the cohort reaches 8 GiB. The hungriest arm leaves "
        f"{fmt(headroom, 3)} GiB spare on an 8 GiB machine.",
        svg, "pinned/laptop-feasibility.json",
        table=table_html(["Quantity", "Arm", "GiB"], trows, numeric_from=2),
        note="Peak RSS came from the kernel's <code>VmHWM</code> high-water mark polled every "
             "5 ms and cross-checked against <code>getrusage</code>. It already includes the "
             "weights, so it is not additive with the Q4_K_M file size.")


def chart_multimodal() -> str:
    rows, trows = [], []
    for m in LAPTOP["multimodal_splits"]:
        d = MM[m["arm"]]
        rows.append((m["label"], [(m["text_tower_params"] / 1e9, "seq3"),
                                  (m["vision_params"] / 1e9, "s2"),
                                  (m["projector_params"] / 1e9, "s4")]))
        trows.append([m["label"], esc(m["architecture"]), num(m["text_tower_params"]),
                      num(m["vision_params"]), num(m["projector_params"]),
                      num(d["total"]), pct(d["share"])])
    svg = stacked(rows, 5.0, gutter=178, rowh=40, unit="B params",
                  refs=[], where="multimodal")
    sh = LAPTOP["multimodal_splits"][0]
    gm = LAPTOP["multimodal_splits"][1]
    trows2 = [
        ["Shieldstral, text-only Q4_K_M on disk", num(sh["text_only_q4_k_m_bytes"]),
         fmt(sh["text_only_q4_k_m_bytes"] / GIB, 4)],
        ["Shieldstral, mmproj that is never built", num(sh["mmproj_bytes"]),
         fmt(sh["mmproj_bytes"] / GIB, 4)],
        ["gemma-3-4b-it, full checkpoint", num(gm["full_checkpoint_bytes"]),
         fmt(gm["full_checkpoint_bytes"] / GIB, 4)],
    ]
    return figure(
        "multimodal",
        "Where the parameters sit in the two multimodal arms",
        f"Shieldstral is <code>{esc(sh['architecture'])}</code>. llama.cpp's converter emits "
        f"the text tower only for <code>mistral3</code>: {num(sh['text_tower_tensors'])} "
        f"tensors, exactly {num(sh['text_tower_params'])} elements, zero vision tensors. "
        f"The vision side exports separately as an mmproj. "
        f"gemma-3-4b-it's full checkpoint is "
        f"{fmt(gm['full_checkpoint_bytes'] / GIB, 4)} GiB, so the split is what makes it "
        f"loadable on an 8 GiB machine.",
        svg, "pinned/laptop-feasibility.json",
        legend=[("Text tower", "seq3"), ("Vision tower", "s2"), ("Projector", "s4")],
        table=table_html(["Arm", "Architecture", "Text tower", "Vision", "Projector",
                          "Total", "Vision plus projector share"], trows)
        + table_html(["Artifact", "Bytes", "GiB"], trows2, numeric_from=1))


CLS_SLOT = {"general": "seq3", "safety": "s2", "encoder": "s3", "control": "s5"}
CLS_LABEL = {"general": "General decoder", "safety": "Purpose-built safety classifier",
             "encoder": "Trained encoder classifier", "control": "MLM negative control"}


def chart_roster() -> str:
    arms = sorted(ROWS, key=lambda a: -a["params"])
    rows = [(a["display"] + (" (gated)" if a["gated"] else ""),
             a["params"] / 1e9, CLS_SLOT[a["cls"]]) for a in arms]
    svg = hbars(rows, 5.0, gutter=292, rowh=22, pad_right=80,
                vticks=[0, 1, 2, 3, 4, 5], where="roster")
    trows = [[a["display"], CLS_LABEL[a["cls"]], num(a["params"]),
              num(a["snapshot_bytes"]), a["licence"], a["origin"],
              a["gated"] or "ungated", a["readout"], a["status"]] for a in arms]
    n_g = sum(1 for a in ROWS if a["gated"])
    return figure(
        "roster",
        f"Parameter count across the {len(ROWS)} arms",
        f"{n_g} of {len(ROWS)} need a licence-accepted token to fetch, across "
        f"{len({a['gated'] for a in ROWS if a['gated']})} separate acceptance groups. The "
        f"snapshot column is the size the download wrote to disk.",
        svg, "harness/arms.py and harness/weights_manifest{,2,3,4}.json",
        legend=[(CLS_LABEL[c], CLS_SLOT[c]) for c in
                ("general", "safety", "encoder", "control")],
        table=table_html(["Arm", "Class", "Parameters", "Snapshot bytes", "Licence", "Origin",
                          "Gating", "Readout", "Status"], trows, numeric_from=2),
        note="Prompt Guard 2's repo names understate its size: the headline 22M and 86M "
             "exclude embeddings.")


def chart_gating() -> str:
    groups = {}
    for a in ROWS:
        groups.setdefault(a["gated"] or "ungated", []).append(a)
    order = ["ungated", "gemma", "llama3.2", "promptguard2"]
    rows = [(k if k != "promptguard2" else "prompt guard 2 (licence other)",
             len(groups.get(k, [])), "seq1" if k == "ungated" else "neg2") for k in order]
    svg = hbars(rows, 16, gutter=238, rowh=26, pad_right=76,
                vticks=[0, 4, 8, 12, 16], where="gating")
    trows = [[k if k != "promptguard2" else "prompt guard 2 (licence other)",
              num(len(groups.get(k, []))),
              ROSTER["gating_groups"].get(k, "no acceptance needed"),
              ", ".join(a["display"] for a in groups.get(k, []))] for k in order]
    return figure(
        "gating",
        "Arms per HuggingFace acceptance group",
        "A 403 rather than a 401 is the signal that the token is valid and that repo's group "
        "is unaccepted. Community re-uploads of the gated weights were refused, because a "
        "mirror launders the provenance the licence column exists to record.",
        svg, "pinned/roster.json",
        legend=[("Fetchable with no acceptance", "seq1"),
                ("Needs a licence-accepted token", "neg2")],
        table=table_html(["Group", "Arms", "Acceptance", "Members"], trows, numeric_from=1),
        note="Eight arms behind three groups is a reproducibility cost for anyone repeating "
             "this.")


def chart_backbones() -> str:
    fam = {}
    for a in ROWS:
        if a["cls"] in ("encoder", "control"):
            fam.setdefault(a["backbone"], []).append(a)
    rows = [("DebertaV2, trained classifiers", len(fam["DebertaV2"]), "s3"),
            ("ModernBERT, untrained controls", len(fam["ModernBERT"]), "s5")]
    svg = hbars(rows, 4, gutter=244, rowh=28, pad_right=70,
                vticks=[0, 1, 2, 3, 4], where="backbones")
    trows = [[a["display"], a["backbone"], CLS_LABEL[a["cls"]], num(a["params"]),
              a["architectures"][0] if a["architectures"] else
              ROSTER["backbone_evidence"][a["key"]], a["status"]]
             for a in ROWS if a["cls"] in ("encoder", "control")]
    return figure(
        "backbones",
        "Backbone family across the five encoder arms",
        "Prompt Guard 2 is <code>DebertaV2ForSequenceClassification</code> at both sizes, so "
        "all three trained encoders share the DeBERTa-v2 backbone family. That is three "
        "checkpoints inside one family. The only independent encoder backbone in the cohort "
        "is ModernBERT, and both ModernBERT arms are controls.",
        svg, "pinned/roster.json",
        legend=[("Trained classifier", "s3"), ("Untrained MLM control", "s5")],
        table=table_html(["Arm", "Backbone", "Class", "Parameters",
                          "How the backbone is known", "Status"], trows, numeric_from=3),
        note="A trained-encoder result here can be shown to be non-checkpoint-specific "
             "within the DeBERTa-v2 family. It cannot be separated from a DeBERTa-family "
             "result.")



def alabel(key: str) -> str:
    return key


def arm_slot(a: dict) -> str:
    return "s5" if a["is_control"] else "seq3"


def by_lc():
    """Every ranked arm, best length-controlled AUC first. Controls are kept in the ordering so a
    reader can see where an untrained backbone falls."""
    return sorted(COH.values(), key=lambda a: -a["auc_lc"])


def by_shipped():
    return sorted(SHIP.values(), key=lambda a: -a["shipped"]["f1"])


def chart_corpus() -> str:
    g = CORPUS["grade_counts_all"]
    rows = [
        ("A, confirmed destructive", g["A"], "neg2"),
        ("B, destructive", g["B"], "neg1"),
        ("D, benign", g["D"], "seq2"),
        ("C, excluded from scoring", g["C"], "axis"),
    ]
    svg = hbars(rows, 3600, gutter=230, rowh=27, pad_right=88,
                vticks=[0, 600, 1200, 1800, 2400, 3000, 3600], where="corpus")
    trows = [["A", num(g["A"]), "scorable positive", ROSTER["corpus_grades"]["A"]],
             ["B", num(g["B"]), "scorable positive", ROSTER["corpus_grades"]["B"]],
             ["D", num(g["D"]), "scorable negative", ROSTER["corpus_grades"]["D"]],
             ["C", num(g["C"]), "excluded", ROSTER["corpus_grades"]["C"]]]
    return figure(
        "corpus",
        "How the corpus splits",
        f'{num(CORPUS["cases"])} cases. {num(CORPUS["scorable_cases_A_B_D"])} are scorable once '
        f'the {num(g["C"])} grade-C cases are excluded: {num(CORPUS["positives_A_B"])} positives '
        f'(A {g["A"]} plus B {g["B"]}) against {num(CORPUS["negatives_D"])} benign. Positive '
        f'prevalence is {pct(TRIVIAL["prevalence_positives_over_scorable"])}, which is what sets '
        f'the trivial floor.',
        svg, "cohort-scoring/cohort-scores.json",
        legend=[("Grade A", "neg2"), ("Grade B", "neg1"), ("Grade D", "seq2"),
                ("Grade C, excluded", "axis")],
        table=table_html(["Grade", "Cases", "Role in scoring", "What the grade records"], trows,
                         numeric_from=1),
        note=f'Grade C is excluded because '
             f'{ROSTER["corpus_grades"]["C"].split("because ", 1)[1].rstrip(".")}. The condition '
             f'the grade function tests for it is '
             f'{CORPORA["label_scheme"]["conditions"]["C"]}.')


def chart_fpr() -> str:
    rows, trows = [], []
    for a in sorted(SHIP.values(), key=lambda a: -a["shipped"]["block_fpr"]):
        sh = a["shipped"]
        rows.append((alabel(a["key"]), sh["block_fpr"], arm_slot(a)))
        trows.append([alabel(a["key"]), fmt(sh["block_fpr"], 12), num(sh["fp"]), num(sh["tn"]),
                      fmt(sh["recall"], 10), fmt(a["flag_rate"], 8)])
    rows.append(("block every case", FLOOR["block_fpr"], "axis"))
    trows.append(["block every case", fmt(FLOOR["block_fpr"], 1), num(FLOOR["fp"]),
                  num(FLOOR["tn"]), fmt(FLOOR["recall"], 1), fmt(1.0, 8)])
    svg = hbars(rows, 1.0, gutter=252, rowh=21, pad_right=84,
                vticks=[0, 0.2, 0.4, 0.6, 0.8, 1.0],
                refs=[(FLOOR["block_fpr"], "ink", "block everything 1.0")], where="fpr")
    return figure(
        "fpr",
        "Block false-positive rate at each arm's shipped operating point",
        f'Share of the {num(CORPUS["negatives_D"])} benign cases each arm blocks. The spread runs '
        f'from {fmt(min(a["shipped"]["block_fpr"] for a in SHIP.values()), 6)} to '
        f'{fmt(max(a["shipped"]["block_fpr"] for a in SHIP.values()), 6)}, which separates these '
        f'arms far more sharply than F1 does.',
        svg, "cohort-rank.json",
        legend=[("Candidate", "seq3"), ("MLM negative control", "s5"),
                ("Trivial baseline, no model", "axis")],
        table=table_html(["Arm", "Block FPR", "False blocks", "Correct allows", "Recall",
                          "Flag rate"], trows),
        note="Counted from rows at each arm's argmax decision.")


def chart_deploy() -> str:
    """Recall at the incumbent cascade's own block false-positive rate."""
    rows, trows = [], []
    ordered = sorted(COH.values(), key=lambda a: -a["cap_row"]["recall"])
    for a in ordered:
        x = a["cap_row"]
        slot = "s5" if a["is_control"] else ("s3" if x["recall"] > 0 else "axis")
        rows.append((alabel(a["key"]), x["recall"], slot))
        trows.append([alabel(a["key"]),
                      "negative control" if a["is_control"] else "candidate",
                      fmt(x["recall"], 12), num(x["tp"]), num(x["fp"]), fmt(x["f1"], 12),
                      fmt(x["fpr"], 12), fmt(x["threshold"], 16)])
    best = {"arm": ordered[0]["key"], **ordered[0]["cap_row"]}
    svg = hbars(rows, 0.08, gutter=252, rowh=20, pad_right=88,
                vticks=[0, 0.02, 0.04, 0.06, 0.08], where="deploy")
    return figure(
        "deploy",
        f"Recall at a block false-positive rate of {FPR_CAP}",
        f'Every arm re-thresholded to the same false-positive budget, which is the operating '
        f'false-positive rate of the incumbent cascade. The best arm in the cohort is '
        f'<code>{esc(best["arm"])}</code> at recall {fmt(best["recall"], 12)}, '
        f'{best["tp"]} of {num(CORPUS["positives_A_B"])} positives, F1 {fmt(best["f1"], 12)}.',
        svg, "reconcile.json",
        legend=[("Candidate with non-zero recall", "s3"), ("MLM negative control", "s5"),
                ("Candidate at zero recall", "axis")],
        table=table_html(["Arm", "Role", "Recall", "tp", "fp", "F1", "Achieved block FPR",
                          "Threshold"], trows, numeric_from=2),
        note="Every threshold here is re-fitted, so no figure in this chart is any arm's shipped "
             "behaviour.")


def chart_zerofp() -> str:
    rows, trows = [], []
    for a in sorted(COH.values(), key=lambda a: -a["zero_fp"]["recall"]):
        v = a["zero_fp"]
        rows.append((alabel(a["key"]), v["recall"], "s3" if v["recall"] > 0 else "axis"))
        trows.append([alabel(a["key"]),
                      "negative control" if a["is_control"] else "candidate",
                      fmt(v["recall"], 12), num(v["tp"]), num(v["fp"]),
                      fmt(v["rule_of_three_upper_bound"], 16)])
    svg = hbars(rows, 0.014, gutter=252, rowh=20, pad_right=90,
                vticks=[0, 0.005, 0.01], where="zerofp")
    zero = [a for a in CANDS.values() if a["zero_fp"]["recall"] == 0]
    nz = [a for a in CANDS.values() if a["zero_fp"]["recall"] > 0]
    return figure(
        "zerofp",
        "Recall at a zero-false-positive gate",
        f'The strictest gate: the highest threshold at which an arm blocks no benign case at all. '
        f'{len(zero)} of the {len(CANDS)} candidates retain zero recall under it, so they catch '
        f'nothing without blocking something benign. {len(nz)} retain any recall.',
        svg, "reconcile.json",
        legend=[("Non-zero recall", "s3"), ("Zero recall", "axis")],
        table=table_html(["Arm", "Role", "Recall", "True blocks", "False blocks",
                          "Rule-of-three upper bound"], trows, numeric_from=2),
        note="Zero-false-positive gates did not transfer across corpora when the System One "
             "programme measured them, so this is reported to answer the deployability question "
             "and not as a durable property.")


def estimator_table() -> str:
    head = (["Arm", "Role"] + [EST_LABEL[e] for e in EST_ORDER]
            + ["Rank under the published estimator", "Worst rank across the four"])
    r = STABILITY["ranks"]
    rows = []
    for a in by_lc():
        pos = []
        for e in EST_ORDER:
            pos.append(r[e].index(a["key"]) + 1 if a["key"] in r[e] else None)
        cells = [fmt(a["est"][e], 10) if a["est"][e] is not None else "n/a" for e in EST_ORDER]
        rows.append([f'<code>{esc(a["key"])}</code>',
                     "negative control" if a["is_control"] else "candidate"] + cells
                    + ([str(pos[0]), str(max(p for p in pos if p))] if not a["is_control"]
                       else ["&#8212;", "&#8212;"]))
    return f'<div class="tbl-scroll">{table_html(head, rows, numeric_from=2)}</div>'


def chart_estimators() -> str:
    """The leading arms under each estimator, so an estimator-dependent position is visible."""
    r = STABILITY["ranks"]
    shown = [k for k in r[PUB_EST][:6]]
    for e in EST_ORDER:
        for k in r[e][:3]:
            if k not in shown:
                shown.append(k)
    rows = []
    slots = ("seq3", "seq1", "s3", "s4")
    for k in shown:
        a = COH[k]
        rows.append((k, [(a["est"][e], slots[i]) for i, e in enumerate(EST_ORDER)
                         if a["est"][e] is not None]))
    lo, hi = BAND["chance_95pct_interval"]
    svg = hbars(rows, 1.0, gutter=252, rowh=15, pad_right=84,
                vticks=[0, 0.2, 0.4, 0.5, 0.6, 0.8, 1.0],
                bands=[(lo, hi, "mid", "null band")],
                refs=[(0.5, "ink", "chance 0.5")], where="estimators")
    trows = []
    for e in EST_ORDER:
        trows.append([EST_LABEL[e]] + [f'{i}. {r[e][i - 1]}' for i in (1, 2, 3)])
    return figure(
        "estimators",
        "The same arms under four length-control estimators",
        f'The published figure is the {EST_LABEL[PUB_EST].lower()} figure, which weights each bin '
        f'by the positive-benign comparisons it actually holds. The retracted unweighted mean gave '
        f'a quintile holding 2 positives the same 20% of the weight as one holding 230. Positions '
        f'1 and 2 are contradicted only by one of the {STABILITY["schemes"]} schemes the artifact '
        f'evaluates, and position 3 by {len(STABILITY["disagreeing_schemes"][3])}.',
        svg, "cohort-rank.json per-bin counts, reconcile.json pooled figures",
        legend=[(EST_LABEL[e], slots[i]) for i, e in enumerate(EST_ORDER)],
        table=table_html(["Estimator", "1st", "2nd", "3rd"], trows, numeric_from=1),
        note="Every value is computed at build time from the per-quintile positive counts, so the "
             "four columns are the same bins re-weighted.")


def sparse_bin_note() -> str:
    """The worked case for why the unweighted mean is fragile, taken from the arm it affects."""
    r = STABILITY["ranks"]
    pub = r[PUB_EST]
    # the leading arm whose position moves most across the four estimators
    worst = max(((k, max(r[e].index(k) + 1 for e in EST_ORDER) - (pub.index(k) + 1))
                 for k in pub[:5]), key=lambda kv: kv[1])
    key, drop = worst
    a = COH[key]
    bins = a["est"]["bins"]
    sparse = [(b, v) for b, v in bins.items() if v["positives"] < 10]
    dense = [(b, v) for b, v in bins.items() if v["positives"] >= 25]
    sp_pos = sum(v["positives"] for _b, v in sparse)
    dn_pos = sum(v["positives"] for _b, v in dense)
    rows = [[b, num(v["cases"]), num(v["positives"]), fmt(v["auc"], 16)]
            for b, v in sorted(bins.items())]
    n_sparse, n_bins = len(sparse), len(bins)
    sp_auc = ", ".join(fmt(v["auc"], 4) for _b, v in sparse)
    dn_auc = ", ".join(fmt(v["auc"], 4) for _b, v in dense)
    word = {1: "sparsest bin holds", 2: "two sparsest bins hold"}.get(
        n_sparse, f"{n_sparse} sparsest bins hold")
    return (
        f'<p>\n  <code>{esc(key)}</code> moves furthest. It sits at position '
        f'{pub.index(key) + 1} under the published estimator and as low as '
        f'{max(r[e].index(key) + 1 for e in EST_ORDER)} under the others, a move of {drop} '
        f'places.\n</p>\n'
        f'<div class="tbl-scroll">{table_html(["Quintile", "Cases", "Positives", "AUC in the bin"], rows, numeric_from=1)}</div>\n'
        f'<p>\n  Its {word} {sp_pos} of the {num(CORPUS["positives_A_B"])} positives, at AUC '
        f'{sp_auc}, and carries {pct(n_sparse / n_bins, 0)} of the unweighted mean. In the '
        f'{len(dense)} bins holding {dn_pos} positives it scores {dn_auc}. Weighting the bins by '
        f'the evidence they hold moves it down the table; an arm whose bins agree with each other '
        f'does not move.\n</p>')



# ------------------------------------------------------- the held-out corpus, as a design finding
# The held-out corpus is NOT used as a generalisation test and no transfer penalty is published.
# Its positive-grade composition is nearly the inverse of s2's, so a transfer figure would conflate
# threshold miscalibration with a changed definition of a positive. What is published is the
# composition itself, the per-grade separation it explains, and the two results that follow.

S3CUE = {k: v for k, v in S3C["s3_length_cue_no_model"].items()
         if isinstance(v, dict) and "auc_raw" in v}


def grade_rows():
    """Per-arm grade-A and grade-B separation, for the arms scored on the held-out corpus."""
    out = []
    for key, v in sorted(GRADE["per_arm"].items()):
        o = v["at_s3_oracle_threshold_ORACLE_IN_SAMPLE_UPPER_BOUND_NOT_A_RESULT"]
        out.append({
            "key": key,
            "auc_a": v["auc_grade_A_positives_vs_all_benign"],
            "auc_b": v["auc_grade_B_positives_vs_all_benign"],
            "rec_a": o["grade_A_recall"], "tp_a": o["grade_A_tp"],
            "rec_b": o["grade_B_recall"], "tp_b": o["grade_B_tp"],
            "n_a": v["grade_A_positive_count"], "n_b": v["grade_B_positive_count"],
            "s2_rank": (STABILITY["ranks"][PUB_EST].index(key) + 1
                        if key in STABILITY["ranks"][PUB_EST] else None),
        })
    return out


def chart_grades() -> str:
    rows, trows = [], []
    for g in sorted(grade_rows(), key=lambda g: -g["auc_a"]):
        rows.append((g["key"], [(g["auc_a"], "neg2"), (g["auc_b"], "seq2")]))
        trows.append([g["key"], str(g["s2_rank"]) if g["s2_rank"] else "n/a",
                      fmt(g["auc_a"], 12), fmt(g["auc_b"], 12),
                      fmt(g["auc_a"] - g["auc_b"], 12),
                      f'{g["tp_a"]} of {g["n_a"]}', f'{g["tp_b"]} of {g["n_b"]}'])
    lo, hi = S3DESIGN["chance_band_95pct"]
    svg = hbars(rows, 1.0, gutter=252, rowh=18, pad_right=84,
                vticks=[0, 0.2, 0.4, 0.5, 0.6, 0.8, 1.0],
                bands=[(lo, hi, "mid", "null band")],
                refs=[(0.5, "ink", "chance 0.5")], where="grades")
    a2, b2 = GRADE["s2_positive_composition"], GRADE["s3_positive_composition"]
    return figure(
        "grades",
        "How well each arm separates grade-A and grade-B positives from benign",
        f'On the held-out corpus. Grade A is an unambiguous destructive call and grade B is a '
        f'judgement call. The two corpora are built from almost opposite mixes: s2 positives are '
        f'{pct(a2["grade_A_share_of_positives"])} grade A and the held-out corpus\'s are '
        f'{pct(b2["grade_A_share_of_positives"])}. An arm\'s position therefore moves with the '
        f'grade mix.',
        svg, "s3-stats.json",
        legend=[("Grade A positives against all benign", "neg2"),
                ("Grade B positives against all benign", "seq2")],
        table=table_html(["Arm", "s2 rank", "Grade A AUC", "Grade B AUC", "A minus B",
                          "Grade A caught", "Grade B caught"], trows, numeric_from=1),
        note="The caught columns are at an in-sample oracle threshold and are an upper bound. "
             "The two AUC columns are not.")


def chart_s3cue() -> str:
    rows, trows = [], []
    for name, v in sorted(S3CUE.items(), key=lambda kv: -kv[1]["auc_raw"]):
        short = name.replace(" (max over events)", ", max")
        rows.append((short, v["auc_raw"], "s4"))
        trows.append([short, fmt(v["auc_raw"], 16)])
    for name, v in sorted(LEAK["structural_cue_auc"].items(), key=lambda kv: -kv[1]["auc"])[:2]:
        short = (name.replace(" (max over events)", ", max")
                 .replace("natural_prompt_tokens", "prompt tokens")
                 .replace("event_count_in_prediction", "event count") + " (s2)")
        rows.append((short, v["auc"], "axis"))
        trows.append([short, fmt(v["auc"], 16)])
    lo, hi = S3DESIGN["chance_band_95pct"]
    svg = hbars(rows, 1.0, gutter=252, rowh=23, pad_right=84,
                vticks=[0, 0.2, 0.4, 0.5, 0.6, 0.8, 1.0],
                bands=[(lo, hi, "mid", "null band")],
                refs=[(0.5, "ink", "chance 0.5")], where="s3cue")
    return figure(
        "s3cue",
        "Counting variables on the held-out corpus, against the same variables on s2",
        f'Both are corpus fields, byte-identical across every arm. On the held-out corpus they sit '
        f'at or below chance, so that corpus carries no length cue to control for and raw AUC is '
        f'the honest primary there. On s2 the same kind of variable reaches '
        f'{fmt(LEAK["structural_cue_auc"]["natural_prompt_tokens (max over events)"]["auc"], 6)}, '
        f'which is why s2 figures are length-controlled and held-out figures are not.',
        svg, "s3-scores-in-scope.json, leakage-diagnostic.json",
        legend=[("Held-out corpus", "s4"), ("s2, for comparison", "axis")],
        table=table_html(["Counting variable", "Raw AUC"], trows),
        note="A length-controlled figure on the held-out corpus would add estimator noise and "
             "nothing else.")


def corpus_design_note() -> str:
    a2, b2 = GRADE["s2_positive_composition"], GRADE["s3_positive_composition"]
    head = ["Corpus", "Cases", "Scorable", "Positives", "Grade A", "Grade B", "Benign",
            "Prevalence", "Grade A share of positives"]
    rows = [
        ["s2", num(CORPUS["cases"]), num(CORPUS["scorable_cases_A_B_D"]),
         num(CORPUS["positives_A_B"]), num(a2["A"]), num(a2["B"]),
         num(CORPUS["negatives_D"]), pct(CORPUS["prevalence"]),
         pct(a2["grade_A_share_of_positives"])],
        ["held out", num(S3DESIGN["cases"]), num(S3DESIGN["cases"]),
         num(S3DESIGN["positives_A_B"]), num(b2["A"]), num(b2["B"]),
         num(S3DESIGN["negatives_D"]), pct(S3DESIGN["prevalence"]),
         pct(b2["grade_A_share_of_positives"])],
    ]
    return f'<div class="tbl-scroll">{table_html(head, rows, numeric_from=1)}</div>'


def resolution_note() -> str:
    best = max(CANDS.values(), key=lambda a: a["cap_row"]["f1"])
    lo, hi = wilson(best["cap_row"]["tp"], CORPUS["positives_A_B"])
    t = tightest_pair()
    ceilings = [v["sample_size_to_significance"]["proportional_growth"]["positives_needed_ceiling"]
                for v in S3["pairwise_delong_all_pairs"].values()]
    return (
        f'<p>\n  More data does not change the s2 answer. All '
        f'{S3RES["pairs_significant_at_0.05"]} of the {S3RES["pairs_tested"]} pairwise comparisons '
        f'on the held-out corpus already separate at p &lt; 0.05, and the median detectable AUC '
        f'difference is {exact(S3RES["median_minimum_detectable_auc_difference"])}. The narrowest '
        f'pair is '
        f'{" against ".join(f"<code>{esc(x)}</code>" for x in t["pair"].split("  vs  "))} at '
        f'{exact(t["mdd"])} AUC, and it would have been significant on '
        f'{num(t["proportional"])} positives under proportional growth or '
        f'{num(t["positives_only"])} under positive-only growth, against the '
        f'{num(S3RES["positives"])} the corpus holds. The widest needs '
        f'{num(max(ceilings))}, which the corpus also holds.\n</p>\n'
        f'<p>\n  A false-positive cap is a rate, so a larger benign pool grows the allowance in '
        f'step with itself and the operating point stays at the same place on an arm\'s ROC curve. '
        f'On s2 the best arm at the cap catches {best["cap_row"]["tp"]} of '
        f'{num(CORPUS["positives_A_B"])} positives, and the Wilson 95% interval on that recall is '
        f'[{exact(lo)}, {exact(hi)}]. More traces buy a tighter interval around the same '
        f'number.\n</p>\n'
        f'<p class="small">\n  That is a statement about ranking precision. '
        f'{pct(S3BIND["mean_share_of_variance_from_the_221_positives"])} of the AUC variance on '
        f'the held-out corpus comes from its {num(S3DESIGN["positives_A_B"])} positives, so the '
        f'positive count remains the binding constraint on every per-positive quantity, and grade '
        f'B has only {num(GRADE["s3_positive_composition"]["B"])} of them there. The binding '
        f'constraint this cohort measures is the grade composition of the positives, and it is a '
        f'property of the corpora.\n</p>')



def control_finding() -> str:
    """The untrained-backbone comparison, with every count derived from the artifacts on hand."""
    ref_s, ref_o = BASE["shipped"]["f1"], BASE["oracle"]["f1"]
    below_s = sorted(a["key"] for a in CANDS.values()
                     if a["shipped"] and a["shipped"]["f1"] <= ref_s)
    below_o = sorted(a["key"] for a in CANDS.values()
                     if a["oracle"] and a["oracle"]["f1"] <= ref_o)
    below_lc = sorted(a["key"] for a in CANDS.values() if a["auc_lc"] <= BASE["auc_lc"])
    n = sum(1 for a in CANDS.values() if a["shipped"])
    fp_ctrl, fp_deb = BASE["shipped"]["fp"], COH["deberta-v3-prompt-injection-v2"]["shipped"]["fp"]
    fewer = (fp_deb - fp_ctrl) / fp_deb
    rows = []
    for a in by_lc():
        if a["shipped"] is None:
            continue
        rows.append([f'<code>{esc(a["key"])}</code>',
                     "negative control" if a["is_control"] else "candidate",
                     fmt(a["shipped"]["f1"], 12), fmt(a["oracle"]["f1"], 12),
                     fmt(a["auc_lc"], 12), fmt(a["shipped"]["block_fpr"], 10),
                     num(a["shipped"]["fp"])])
    # the trivial floor belongs beside every block-only F1 column on this Space
    rows.append(["<code>block every case</code>", "trivial floor",
                 fmt(FLOOR["f1"], 12), MDASH, MDASH, fmt(FLOOR["block_fpr"], 1),
                 num(FLOOR["fp"])])
    return (
        f'<p>\n  <code>control-modernbert-base</code> is an untrained '
        f'<code>ModernBertForMaskedLM</code> backbone with no trained head and no safety '
        f'training. Its best F1 on its own scalar is {fmt(ref_o, 14)}, its shipped F1 is '
        f'{fmt(ref_s, 16)}, and it blocks {num(fp_ctrl)} benign cases.\n</p>\n'
        f'<p><strong>{len(below_o)} of the {n} ranked candidates score at or below it on best F1, '
        f'and {len(below_s)} at or below it on shipped F1.</strong> On this corpus those arms '
        f'cannot be separated from an untrained backbone by F1.</p>\n'
        f'<p>\n  This is not leakage. The leakage gate established that both controls sit at '
        f'chance once prompt length is controlled for, and this one lands at '
        f'{fmt(BASE["auc_lc"], 16)} inside the band '
        f'[{fmt(BAND["chance_95pct_interval"][0], 15)}, '
        f'{fmt(BAND["chance_95pct_interval"][1], 15)}]. The mechanism is the threshold sweep: an '
        f'unconstrained best-F1 search on a corpus carrying a length cue worth AUC '
        f'{fmt(LEAK["structural_cue_auc"]["natural_prompt_tokens (max over events)"]["auc"], 16)} '
        f'flatters anything correlated with length, and this readout is correlated with length at '
        f'Spearman '
        f'{fmt(LEAK["controls"]["control-modernbert-base"]["spearman_score_vs_natural_prompt_length"], 15)}.\n</p>\n'
        f'<p>\n  On length-controlled AUC the picture separates: {len(below_lc)} of the {n} '
        f'candidates sit at or below the control. The candidate ranking is therefore read on '
        f'length-controlled AUC, and best F1 is a diagnostic.\n</p>\n'
        f'<p>\n  The control also blocks fewer benign cases than the highest-ranked candidate: '
        f'{num(fp_ctrl)} against {num(fp_deb)}, which is {pct(fewer, 1)} fewer.\n</p>\n'
        f'<div class="tbl-scroll">{table_html(["Arm", "Role", "Shipped block-only F1", "Its own argmax F1 (in-sample upper bound)", "Length-controlled AUC", "Block FPR", "False blocks"], rows, numeric_from=2)}</div>')


# ================================================ one common operating point, and the bands
# Every arm below is reported at the same block false-positive budget. No arm appears at a
# threshold chosen for it alone, so the columns are comparable down the table. Each arm's own
# argmax is a separate table, labelled an in-sample oracle upper bound.

ROLE = {True: "negative control", False: "candidate"}


def _band_slot(label: str) -> str:
    return {"under 3B": "seq2", "3B to 6B": "s4", "6B and up": "axis"}[label]


def by_cap():
    """Every arm, best F1 at the common operating point first."""
    return sorted(COH.values(), key=lambda a: (-a["cap_row"]["f1"], a["params"]))


def _confusion_cells(m: dict, scorable: int, neg: int, fpr_key: str = "fpr") -> list[str]:
    return [num(m["tp"]), num(m["fp"]), num(m["fn"]), num(m["tn"]),
            exact(m["precision"]) if m["tp"] + m["fp"] else "n/a",
            exact(m["recall"]), exact(m["f1"]),
            exact(accuracy(m, scorable)), exact(m[fpr_key])]


CONF_HEAD = ["tp", "fp", "fn", "tn", "Precision", "Recall", "F1", "Accuracy", "Block FPR"]


def common_point_table() -> str:
    scorable, neg = CORPUS["scorable_cases_A_B_D"], CORPUS["negatives_D"]
    head = (["Arm", "Role", "Size band", "Counted parameters", "Threshold"] + CONF_HEAD)
    rows = []
    for a in by_cap():
        x = a["cap_row"]
        rows.append([f'<code>{esc(a["key"])}</code>', ROLE[a["is_control"]],
                     band_of(a["params"]), num(a["params"]), exact(x["threshold"])]
                    + _confusion_cells(x, scorable, neg))
    allow = TRIVIAL["allow_every_case"]
    for label, t, fk in (("block every case", dict(FLOOR, fpr=FLOOR["block_fpr"]), "fpr"),
                         ("allow every case",
                          dict(allow, precision=0.0, recall=0.0, f1=allow["f1"], fpr=0.0), "fpr")):
        rows.append([f"<code>{label}</code>", "trivial baseline", MDASH, MDASH,
                     "by construction"]
                    + [num(t["tp"]), num(t["fp"]), num(t["fn"]), num(t["tn"]),
                       exact(t["precision"]) if t["tp"] + t["fp"] else "n/a",
                       exact(t["recall"]), exact(t["f1"]),
                       exact(accuracy(t, scorable)), exact(t[fk])])
    return f'<div class="tbl-scroll">{table_html(head, rows, numeric_from=3)}</div>'


def chart_prf() -> str:
    """Precision, recall and F1 for every arm at the one shared false-positive budget."""
    rows, trows = [], []
    scorable, neg = CORPUS["scorable_cases_A_B_D"], CORPUS["negatives_D"]
    for a in by_cap():
        x = a["cap_row"]
        rows.append((alabel(a["key"]), [(x["precision"], "s1"), (x["recall"], "s2"),
                                        (x["f1"], "s3")]))
        trows.append([alabel(a["key"]), ROLE[a["is_control"]], band_of(a["params"]),
                      exact(x["threshold"])] + _confusion_cells(x, scorable, neg))
    svg = hbars(rows, 1.0, gutter=252, rowh=13, pad_right=80,
                vticks=[0, 0.2, 0.4, 0.6, 0.8, 1.0], where="prf")
    best = max(CANDS.values(), key=lambda a: a["cap_row"]["f1"])
    return figure(
        "prf",
        f'Precision, recall and F1 at block FPR &#8804; {exact(FPR_CAP)}',
        f'One budget for every arm, so the three columns are read down the table as well as '
        f'across it. The threshold each arm needs to reach that budget differs; the budget does '
        f'not. The highest F1 among the {len(CANDS)} candidates is '
        f'<code>{esc(best["key"])}</code> at {exact(best["cap_row"]["f1"])}, on '
        f'{num(best["cap_row"]["tp"])} of {num(CORPUS["positives_A_B"])} positives.',
        svg, "cohort-length-controlled-ranking.json",
        legend=[("Precision", "s1"), ("Recall", "s2"), ("F1", "s3")],
        table=table_html(["Arm", "Role", "Size band", "Threshold"] + CONF_HEAD, trows,
                         numeric_from=3),
        note=f'The false-positive allowance at this budget is '
             f'{num(int(FPR_CAP * CORPUS["negatives_D"]))} of the '
             f'{num(CORPUS["negatives_D"])} benign cases.')


def chart_bands() -> str:
    """F1 at the common operating point, with each arm's bar coloured by its size band."""
    rows, trows = [], []
    for a in by_cap():
        b = band_of(a["params"])
        rows.append((f'{alabel(a["key"])} ({a["params"] / 1e9:.2f}B)', a["cap_row"]["f1"],
                     _band_slot(b)))
        trows.append([alabel(a["key"]), b, num(a["params"]), ROLE[a["is_control"]],
                      exact(a["cap_row"]["f1"]), exact(a["cap_row"]["recall"]),
                      num(a["cap_row"]["tp"])])
    svg = hbars(rows, 0.12, gutter=300, rowh=19, pad_right=92,
                vticks=[0, 0.03, 0.06, 0.09, 0.12], where="bands")
    counts = ", ".join(f'{b} {len(in_band(b))}' for b, _lo, _hi in SIZE_BANDS)
    return figure(
        "bands",
        "F1 at the common operating point, by size band",
        f'Counted parameters set the band: {counts}. Within a band the order is F1 at the '
        f'shared budget.',
        svg, "cohort-length-controlled-ranking.json",
        legend=[(b, _band_slot(b)) for b, _lo, _hi in SIZE_BANDS],
        table=table_html(["Arm", "Size band", "Counted parameters", "Role", "F1", "Recall",
                          "True blocks"], trows, numeric_from=2),
        note="Parameter counts come from each arm's own run metadata and are checked against the "
             "arm registry at build time.")


def oracle_table() -> str:
    """Each arm at its own argmax. This is an in-sample upper bound, never an operating point."""
    scorable, neg = CORPUS["scorable_cases_A_B_D"], CORPUS["negatives_D"]
    head = ["Arm", "Role", "Its own threshold"] + CONF_HEAD + ["F1 at the common budget"]
    rows = []
    for a in sorted(COH.values(), key=lambda a: -a["oracle_f1"]):
        if a["oracle"] is None:
            rows.append([f'<code>{esc(a["key"])}</code>', ROLE[a["is_control"]], "n/a"]
                        + ["n/a"] * 6 + [exact(a["oracle_f1"])] + ["n/a", "n/a"]
                        + [exact(a["cap_row"]["f1"])])
            continue
        o = a["oracle"]
        rows.append([f'<code>{esc(a["key"])}</code>', ROLE[a["is_control"]],
                     exact(o["threshold"])]
                    + _confusion_cells(o, scorable, neg, "block_fpr")
                    + [exact(a["cap_row"]["f1"])])
    rows.append([f"<code>block every case</code>", "trivial baseline", "by construction",
                 num(FLOOR["tp"]), num(FLOOR["fp"]), num(FLOOR["fn"]), num(FLOOR["tn"]),
                 exact(FLOOR["precision"]), exact(FLOOR["recall"]), exact(FLOOR["f1"]),
                 exact(accuracy(FLOOR, scorable)), exact(FLOOR["block_fpr"]), MDASH])
    return f'<div class="tbl-scroll">{table_html(head, rows, numeric_from=3)}</div>'


def accuracy_table() -> str:
    """Accuracy beside the accuracy of doing nothing, on both corpora."""
    s2s, s2n = CORPUS["scorable_cases_A_B_D"], CORPUS["negatives_D"]
    s3s, s3n = S3CORP["scorable_cases_A_B_D"], S3CORP["negatives_D"]
    head = ["Corpus", "Arm", "Accuracy at the common budget", "All-allow accuracy",
            "Difference, in cases", "Prevalence"]
    rows = []
    for a in by_cap():
        x = a["cap_row"]
        rows.append(["s2", f'<code>{esc(a["key"])}</code>', exact(accuracy(x, s2s)),
                     exact(s2n / s2s), num(x["tp"] - x["fp"]), exact(CORPUS["prevalence"])])
    for key in sorted(S3ARMS):
        x = s3_primary(key)["s3_at_fpr_cap"][f"{FPR_CAP}"]
        rows.append([S3LABEL, f"<code>{esc(key)}</code>", exact(accuracy(x, s3s)),
                     exact(s3n / s3s), num(x["tp"] - x["fp"]), exact(S3CORP["prevalence"])])
    return f'<div class="tbl-scroll">{table_html(head, rows, numeric_from=2)}</div>'


def size_band_tables() -> str:
    """One table per band, plus the band the cohort leaves empty."""
    scorable, neg = CORPUS["scorable_cases_A_B_D"], CORPUS["negatives_D"]
    out = []
    for label, lo, hi in SIZE_BANDS:
        arms = in_band(label)
        rng = (f"{lo / 1e9:g}B or more" if hi is None
               else (f"under {hi / 1e9:g}B" if lo == 0
                     else f"{lo / 1e9:g}B to under {hi / 1e9:g}B"))
        out.append(f'<h3 id="band-{label.replace(" ", "-").lower()}">{esc(label)} '
                   f'&#8212; {len(arms)} arms</h3>')
        out.append(f'<p class="small">Counted parameters {esc(rng)}.</p>')
        if not arms:
            out.append('<p>Nothing in this cohort lands here. The largest arm carries '
                       f'{num(max(a["params"] for a in COH.values()))} counted parameters.</p>')
            continue
        head = (["Rank in band", "Arm", "Role", "Counted parameters", "Threshold"] + CONF_HEAD)
        rows = []
        for i, a in enumerate(arms, 1):
            x = a["cap_row"]
            rows.append([num(i), f'<code>{esc(a["key"])}</code>', ROLE[a["is_control"]],
                         num(a["params"]), exact(x["threshold"])]
                        + _confusion_cells(x, scorable, neg))
        out.append(f'<div class="tbl-scroll">{table_html(head, rows, numeric_from=3)}</div>')
    return "\n".join(out)


def moe_note() -> str:
    key = "granite-guardian-3.2-3b-a800m"
    a, r = COH[key], next(x for x in ROWS if x["key"] == key)
    return (f'<p>\n  <code>{esc(key)}</code> is a mixture-of-experts arm, so its counted total '
            f'and the parameters active on a forward pass are different numbers. The counted '
            f'total is {num(a["params"])}, recorded in its run metadata and matched against the '
            f'arm registry. The artifacts carry no counted active-parameter figure for it; the '
            f'registry note records {esc(r["note"])}, and the band above places it on the '
            f'counted total. Every other arm in the cohort is dense, so for them the counted '
            f'total and the active count coincide.\n</p>')


def auc_table() -> str:
    """Threshold-free discrimination, one row per arm, each AUC labelled with its definition."""
    lo, hi = BAND["chance_95pct_interval"]
    head = ["Arm", "Role", "Class structure", "Ranking variable", "AUC definition", "Raw AUC",
            "Length-controlled AUC", "Against the chance band"]
    rows = []
    for a in by_lc():
        var, _, dfn = a["primary_var"].partition("||")
        where = ("below" if a["auc_raw"] < lo else
                 "inside" if a["auc_raw"] <= hi else "above")
        rows.append([f'<code>{esc(a["key"])}</code>', ROLE[a["is_control"]],
                     esc(a["class_structure"]), f'<code>{esc(var.strip())}</code>',
                     esc(dfn.strip().replace("defA==defB", "A and B coincide")),
                     exact(a["auc_raw"]), exact(a["auc_lc"]), where])
    return f'<div class="tbl-scroll">{table_html(head, rows, numeric_from=5)}</div>'


def definition_table() -> str:
    """Where definitions A and B differ, they are reported apart and never compared."""
    key = "falcon3-1b-instruct"
    src = RANK["arms_s2"][key]
    head = ["Variable", "Definition A", "Definition B", "Ranked on"]
    seen: dict[str, dict[str, float]] = {}
    for vk, vv in src["by_variable"].items():
        var, _, dfn = vk.partition("||")
        seen.setdefault(var.strip(), {})[dfn.strip()] = (
            vv["auc_raw_mann_whitney_tie_corrected"])
    rows = []
    for var, by_def in sorted(seen.items()):
        both = by_def.get("defA==defB")
        flagged = "P(block) - P(confirm)" in var
        var_html = esc(var).replace(" - ", f" {MINUS} ")
        if both is not None:
            rows.append([f"<code>{var_html}</code>", exact(both), exact(both),
                         "yes, when the class structure selects it"])
        else:
            rows.append([f"<code>{var_html}</code>", exact(by_def.get("defA")),
                         exact(by_def.get("defB")),
                         "no; it inverted below chance on the disjoint corpus and is excluded "
                         "by rule" if flagged
                         else "no; the two definitions give different orderings and the "
                              "programme ranks on one fixed variable"])
    return (f'<p class="small">\n  One arm, <code>{esc(key)}</code>, shown because it emits all '
            f'three classes and therefore carries every variable. Definition A takes the maximum '
            f'block probability and the maximum confirm probability over a case\'s events and '
            f'then subtracts. Definition B takes the maximum over events of the per-event '
            f'difference. For a variable that is already a single monotone scalar the two reduce '
            f'to the same maximum, which is what <code>A and B coincide</code> records. '
            f'<code>P(block) {MINUS} P(confirm)</code> is the variable that inverted below '
            f'chance on a disjoint corpus, and it is never ranked on.\n</p>\n'
            f'<div class="tbl-scroll">{table_html(head, rows, numeric_from=1)}</div>')


def floor_table() -> str:
    """Shipped block-only F1 for every arm, with the trivial floor in the same table."""
    scorable, neg = CORPUS["scorable_cases_A_B_D"], CORPUS["negatives_D"]
    head = ["Arm", "Role"] + CONF_HEAD + ["Against the floor"]
    rows = []
    for a in by_shipped():
        s = a["shipped"]
        rows.append([f'<code>{esc(a["key"])}</code>', ROLE[a["is_control"]]]
                    + _confusion_cells(s, scorable, neg, "block_fpr")
                    + ["above" if s["f1"] > FLOOR["f1"] else "below"])
    rows.append(["<code>block every case</code>", "trivial floor",
                 num(FLOOR["tp"]), num(FLOOR["fp"]), num(FLOOR["fn"]), num(FLOOR["tn"]),
                 exact(FLOOR["precision"]), exact(FLOOR["recall"]), exact(FLOOR["f1"]),
                 exact(accuracy(FLOOR, scorable)), exact(FLOOR["block_fpr"]), MDASH])
    return f'<div class="tbl-scroll">{table_html(head, rows, numeric_from=2)}</div>'


def corpus_table() -> str:
    """Both corpora, documented field by field."""
    head = ["Property", "s2", S3LABEL[0].upper() + S3LABEL[1:]]
    g2, g3 = CORPUS["grade_counts_all"], S3CORP["grade_counts_all"]
    rows = [
        ["Cases", num(CORPUS["cases"]), num(S3CORP["cases"])],
        ["Scorable cases", num(CORPUS["scorable_cases_A_B_D"]),
         num(S3CORP["scorable_cases_A_B_D"])],
        ["Positives, grade A and grade B", num(CORPUS["positives_A_B"]),
         num(S3CORP["positives_A_B"])],
        ["Grade A positives", num(g2["A"]), num(g3["A"])],
        ["Grade B positives", num(g2["B"]), num(g3["B"])],
        ["Grade A share of positives",
         exact(CORPUS["grade_counts_all"]["A"] / CORPUS["positives_A_B"]),
         exact(g3["A"] / S3CORP["positives_A_B"])],
        ["Benign, grade D", num(CORPUS["negatives_D"]), num(S3CORP["negatives_D"])],
        ["Grade C, excluded from scoring", num(CORPUS["grade_C_excluded"]),
         num(S3CORP["grade_C_excluded"])],
        ["Prevalence of positives over scorable cases", exact(CORPUS["prevalence"]),
         exact(S3CORP["prevalence"])],
        ["All-allow accuracy",
         exact(CORPUS["negatives_D"] / CORPUS["scorable_cases_A_B_D"]),
         exact(S3CORP["negatives_D"] / S3CORP["scorable_cases_A_B_D"])],
        ["Block-everything F1", exact(FLOOR["f1"]), exact(S3FLOOR["f1"])],
        ["Chance band at AUC 0.5, 95%",
         f'[{exact(BAND["chance_95pct_interval"][0])}, '
         f'{exact(BAND["chance_95pct_interval"][1])}]',
         f'[{exact(S3BANDC["band_95pct"][0])}, {exact(S3BANDC["band_95pct"][1])}]'],
        ["Hanley&#8211;McNeil standard error at AUC 0.5",
         exact(BAND["hanley_mcneil_se_at_auc_0.5"]), exact(S3BANDC["se_at_auc_0.5"])],
        ["Prediction rows per arm", num(DEB["prediction_rows"]),
         num(next(iter({a["s3_prediction_rows"] for a in S3ARMS.values()})))],
        ["Arms scored on it", num(len(COH)), num(len(S3ARMS))],
        ["<code>cases_sha256</code>", f'<code>{esc(CORPUS["cases_sha256"])}</code>',
         f'<code>{esc(S3CORP["cases_sha256"])}</code>'],
        ["Case-id overlap with the other corpus",
         num(S3C["corpora"]["case_id_overlap_s2_s3"]),
         num(S3C["corpora"]["case_id_overlap_s2_s3"])],
        ["Redistribution", "evaluation-only; rows stay in a private data repository",
         "evaluation-only; rows stay in a private data repository"],
        ["Published here", "aggregates over the corpus or a stratum of it",
         "aggregates over the corpus or a stratum of it"],
    ]
    return f'<div class="tbl-scroll">{table_html(head, rows, numeric_from=1)}</div>'


def grade_scheme_table() -> str:
    g = ROSTER["corpus_grades"]
    cond = CORPORA["label_scheme"]["conditions"]
    head = ["Grade", "Condition the function tests", "What it records", "Scored as",
            "Cases in s2", "Cases in the second corpus"]
    g2, g3 = CORPUS["grade_counts_all"], S3CORP["grade_counts_all"]
    scored = {"A": "positive", "B": "positive", "C": "excluded", "D": "negative",
              "E": "not present in either corpus"}
    rows = [[f"<code>{k}</code>", esc(cond[k]),
             esc(g[k]) if k in g else "no case of this grade is in either corpus", scored[k],
             num(g2.get(k, 0)), num(g3.get(k, 0))]
            for k in ("A", "B", "C", "D", "E")]
    return f'<div class="tbl-scroll">{table_html(head, rows, numeric_from=4)}</div>'


def label_provenance_block() -> str:
    ls = CORPORA["label_scheme"]
    imp = "".join(f'<li><code>{esc(p)}</code></li>' for p in ls["importers"])
    return (f'<p>\n  {esc(ls["how"])}\n</p>\n'
            f'<p>\n  The function is <code>{esc(ls["function"])}()</code> in '
            f'<a href="{GH}/{esc(ls["source"])}"><code>{esc(ls["source"])}</code></a>, '
            f'{num(LABELS["bytes"])} bytes at sha256 <code>{esc(LABELS["sha256"])}</code>, '
            f're-hashed at build time. The scoring paths import it:\n</p>\n<ul>{imp}</ul>\n'
            f'<p>\n  {esc(ls["limits"])}\n</p>')


def licence_table() -> str:
    r = CORPORA["redistribution"]
    head = ["Property", "Value"]
    rows = [
        ["Disposition of the case rows", esc(r["corpora"])],
        ["What leaves the host", esc(r["published_here"])],
        ["Source-dataset licences", f'recorded per source in '
                                   f'<a href="{GH}/{esc(r["source_lock"])}">'
                                   f'<code>{esc(r["source_lock"])}</code></a>, schema version '
                                   f'{esc(LOCK["schema"])}, frozen '
                                   f'{esc(LOCK["frozen_at"])}, at sha256 '
                                   f'<code>{esc(LOCK["sha256"])}</code>'],
        ["Entries in that lock", num(LOCK["entries"])],
        ["Redistribution markers across them",
         ", ".join(f"{esc(k)} {num(v)}" for k, v in LOCK["redistribution"].items())],
        ["Licence-review status across them",
         ", ".join(f"{esc(k)} {num(v)}" for k, v in LOCK["licence_status"].items())],
        ["Distinct licences named", num(len(LOCK["licences"]))],
        ["Most common licence",
         f'{esc(next(iter(LOCK["licences"])))} on '
         f'{num(next(iter(LOCK["licences"].values())))} entries'],
        ["Restricted sources", esc(r["restricted_sources"])],
        ["The local-evaluation-only source",
         f'<code>{esc(r["local_evaluation_only_source"])}</code>'],
        ["Rows either restricted source contributes to these corpora",
         f'{num(CENSUS["rows"])}, counted over {num(CENSUS["sources"])} sources by a census '
         f'recorded in <a href="{GH}/{esc(CENSUS["path"])}">'
         f'<code>{esc(CENSUS["path"])}</code></a> at sha256 '
         f'<code>{esc(CENSUS["sha256"])}</code>'],
        ["Why the lock is cited by digest", esc(r["source_lock_caveat"])],
    ]
    return f'<div class="tbl-scroll">{table_html(head, rows, numeric_from=1)}</div>'


def heldout_table() -> str:
    """The six settled held-out bodies, with the digest each metadata records."""
    head = ["Arm", "Counted parameters", "Rows", "Cases covered", "Cases missing", "Errors",
            "complete", "Digest matches the body on disk", "Prediction sha256"]
    rows = []
    for key in sorted(S3ARMS):
        a = S3ARMS[key]
        m = a["s3_meta"]
        rows.append([f"<code>{esc(key)}</code>", num(m["params_counted"]),
                     num(a["s3_prediction_rows"]), num(a["s3_cases_in_prediction"]),
                     num(a["s3_scorable_missing"]), num(m["errors"]),
                     exact(m["complete_value"]), exact(m["sha256_meta_matches_disk"]),
                     f'<code>{esc(a["s3_prediction_sha256_disk"])}</code>'])
    return f'<div class="tbl-scroll">{table_html(head, rows, numeric_from=1)}</div>'


def heldout_reconciliation() -> str:
    """Two artifacts cover different arm counts on the held-out corpus. Which one governs."""
    stage0 = ", ".join(f"<code>{esc(k)}</code>" for k in S3_STAGE0_NAMES)
    return (
        f'<p>\n  Two artifacts carry held-out records and they cover different arms. '
        f'<code>cohort-rank.json</code> holds {len(S3_STAGE0_NAMES)}: {stage0}. '
        f'<code>s3-stats.json</code> and <code>s3-scores-in-scope.json</code> hold '
        f'{len(S3ARMS)}, and the {len(S3_STAGE0_NAMES)} are a subset of the {len(S3ARMS)}.\n</p>\n'
        f'<p class="small">\n  This section is about which bodies exist and which artifact '
        f'governs. The corpus they cover has positives that are '
        f'{pct(S3CORP["grade_counts_all"]["A"] / S3CORP["positives_A_B"])} grade A against s2\'s '
        f'{pct(CORPUS["grade_counts_all"]["A"] / CORPUS["positives_A_B"])}, so no figure here or '
        f'anywhere on this Space compares a score across the two.\n</p>\n'
        f'<p>\n  The two agree on every arm they share: the same ranking variable, the same raw '
        f'AUC to the last digit, the same {num(next(iter({a["s3_prediction_rows"] for a in S3ARMS.values()})))} '
        f'rows, the same prediction digest and the same argmax confusion matrix. The build '
        f'asserts each of those, so the coverage difference is the only difference.\n</p>\n'
        f'<p>\n  The {len(S3ARMS)}-arm pair governs. <code>cohort-rank.json</code> was written '
        f'when {len(S3_STAGE0_NAMES)} held-out bodies had landed and its block was never '
        f'extended; the later pair was written over the settled archive, where all '
        f'{len(S3ARMS)} bodies carry <code>complete: true</code> and a digest matching the bytes '
        f'on disk. Every held-out number on this Space is read from the later pair.\n</p>')


CHARTS = {
    "prf": chart_prf,
    "bands": chart_bands,
    "corpus": chart_corpus,
    "deploy": chart_deploy,
    "zerofp": chart_zerofp,
    "ranking": chart_ranking,
    "estimators": chart_estimators,
    "grades": chart_grades,
    "s3cue": chart_s3cue,
    "fpr": chart_fpr,
    "quintiles": chart_quintiles,
    "floor": chart_floor,
    "cues": chart_cues,
    "deberta_points": chart_deberta_points,
    "trunc": chart_trunc,
    "control_dist": chart_control_dist,
    "throughput": chart_throughput,
    "envelope": chart_envelope,
    "multimodal": chart_multimodal,
    "roster": chart_roster,
    "gating": chart_gating,
    "backbones": chart_backbones,
}


# ================================================================ figure values

def build_figs() -> dict[str, str]:
    be = TRIVIAL["block_every_case"]
    lo, hi = BAND["chance_95pct_interval"]
    orc = DEB["by_variable"]["P(injection.true)  [the arm's ONLY scalar]"][
        "best_f1_ORACLE_IN_SAMPLE_UPPER_BOUND_NOT_A_RESULT"]
    blk = DEB["shipped_argmax_recomputed_from_rows"]["block_only"]
    sc = TRUNC["scored_corpus"]
    ec = TRUNC["error_correlation"]
    sh, gm = LAPTOP["multimodal_splits"]
    mem = LAPTOP["memory"]
    f: dict[str, str] = {
        # corpus
        "corpus.cases": num(CORPUS["cases"]),
        "corpus.scorable": num(CORPUS["scorable_cases_A_B_D"]),
        "corpus.positives": num(CORPUS["positives_A_B"]),
        "corpus.negatives": num(CORPUS["negatives_D"]),
        "corpus.gradeC": num(CORPUS["grade_C_excluded"]),
        "corpus.gradeA": num(CORPUS["grade_counts_all"]["A"]),
        "corpus.gradeB": num(CORPUS["grade_counts_all"]["B"]),
        "corpus.prevalence": pct(TRIVIAL["prevalence_positives_over_scorable"]),
        "corpus.sha": CORPUS["cases_sha256"],
        "corpus.rows": num(DEB["prediction_rows"]),
        # the floor
        "floor.f1": fmt(be["f1"], 17),
        "floor.f1s": fmt(be["f1"], 5),
        "floor.tp": num(be["tp"]), "floor.fp": num(be["fp"]),
        "floor.fn": num(be["fn"]), "floor.tn": num(be["tn"]),
        "floor.precision": fmt(be["precision"], 10),
        "floor.recall": fmt(be["recall"], 1),
        "floor.fpr": fmt(be["fpr"], 1),
        "floor.allow.f1": fmt(TRIVIAL["allow_every_case"]["f1"], 1),
        # the length cue
        "cue.tokens": fmt(LEAK["structural_cue_auc"]
                          ["natural_prompt_tokens (max over events)"]["auc"], 16),
        "cue.events": fmt(LEAK["structural_cue_auc"]["event_count_in_prediction"]["auc"], 16),
        "cue.ctxevents": fmt(LEAK["structural_cue_auc"]["context_events"]["auc"], 16),
        "cue.ctxbytes": fmt(LEAK["structural_cue_auc"]
                            ["context_bytes (max over events)"]["auc"], 16),
        "cue.tokens.controlled":
            fmt(LCA["pure length counter (natural prompt tokens)"]
                ["mean_within_length_quintile_auc"], 16),
        # the null band
        "band.lo": exact(lo), "band.hi": exact(hi),
        "band.se": exact(BAND["hanley_mcneil_se_at_auc_0.5"]),
        # controls
        "cb.auc": fmt(CB["headline"]["auc_of_best_variable"], 16),
        "cl.auc": fmt(CL["headline"]["auc_of_best_variable"], 17),
        "cb.controlled": fmt(LEAK["controls"]["control-modernbert-base"]
                             ["mean_within_stratum_auc"], 16),
        "cl.controlled": fmt(LEAK["controls"]["control-modernbert-large"]
                             ["mean_within_stratum_auc"], 17),
        "cb.spearman": fmt(LEAK["controls"]["control-modernbert-base"]
                           ["spearman_score_vs_natural_prompt_length"], 15),
        "controls.pearson": fmt(LEAK["controls_agree_with_each_other"]
                                ["pearson_base_vs_large"], 16),
        "cb.distinct": num(LEAK["controls"]["control-modernbert-base"]
                           ["score_distribution"]["distinct_values"]),
        "cl.distinct": num(LEAK["controls"]["control-modernbert-large"]
                           ["score_distribution"]["distinct_values"]),
        # DeBERTa
        "deb.auc": fmt(DEB["headline"]["auc_of_best_variable"], 16),
        "deb.controlled": fmt(LCA["deberta P(injection.true) [single scalar, A==B]"]
                              ["mean_within_length_quintile_auc"], 14),
        "deb.shipped": fmt(blk["f1"], 17),
        "deb.tp": num(blk["tp"]), "deb.fp": num(blk["fp"]),
        "deb.fn": num(blk["fn"]), "deb.tn": num(blk["tn"]),
        "deb.fpr": fmt(blk["fpr"], 16),
        "deb.recall": fmt(blk["recall"], 15),
        "deb.oracle": fmt(orc["f1"], 2),
        "deb.oracle.threshold": fmt(orc["threshold"], 16),
        "deb.blockshare": pct(DEB["shipped_action_histogram_case_level"]["block"]
                              / CORPUS["scorable_cases_A_B_D"], 1),
        "deb.blockrows": num(DEB["row_level_action_histogram"]["block"]),
        "deb.blockcases": num(DEB["shipped_action_histogram_case_level"]["block"]),
        "deb.distinct": num(DEB["by_variable"]["P(injection.true)  [the arm's ONLY scalar]"]
                            ["distinct_thresholds"]),
        "deb.params": num(DEB["arm_meta"]["params_counted"]),
        "deb.revision": DEB["arm_meta"]["revision"],
        "deb.sha": DEB["prediction_sha256"],
        # truncation
        "trunc.cap": num(TRUNC["deberta_cap_tokens"]),
        "trunc.rows": num(TRUNC["runner_reported_rows_shrunk"]),
        "trunc.rowstotal": num(TRUNC["runner_total_rows"]),
        "trunc.rowspct": pct(TRUNC["runner_fraction_rows_shrunk"]),
        "trunc.scoredrows": num(sc["rows_over_512_in_scored_cases"]),
        "trunc.scoredrowstotal": num(sc["rows_belonging_to_scored_cases"]),
        "trunc.scoredrowspct": pct(sc["rows_over_512_fraction"]),
        "trunc.cases": num(sc["cases_with_at_least_one_event_over_512"]),
        "trunc.casespct": pct(sc["cases_with_at_least_one_event_over_512_fraction"]),
        "trunc.allcases": num(sc["cases_with_every_event_over_512"]),
        "trunc.auc": fmt(ec["auc_within_stratum"]["truncated_cases"]["auc"], 16),
        "trunc.aucun": fmt(ec["auc_within_stratum"]["untruncated_cases"]["auc"], 16),
        "trunc.f1": fmt(ec["at_oracle_best_f1_threshold"]["truncated_cases"]["f1"], 4),
        "trunc.f1un": fmt(ec["at_oracle_best_f1_threshold"]["untruncated_cases"]["f1"], 4),
        "trunc.prevratio": f"{ec['prevalence_confound']['positive_rate_truncated_cases'] / ec['prevalence_confound']['positive_rate_untruncated_cases']:.1f}",
        "trunc.flagrows": num(TRUNC["row_truncated_flag_is_not_the_512_limit"]
                              ["rows_with_truncated_true"]),
        "trunc.flagpct": pct(TRUNC["row_truncated_flag_is_not_the_512_limit"]
                             ["rows_with_truncated_true"] / TRUNC["runner_total_rows"]),
        "ctrl.oracle": fmt(BASE["oracle"]["f1"], 14),
        "deb.over.floor": fmt(HEAD["deberta_shipped_minus_block_everything"], 18),
        # the scorer-equivalence gate, as a property of the check rather than of any arm
        "parity.n": num(len(PARITY)),
        "parity.maxdelta": f"{max(v['abs_delta_f1'] for v in PARITY.values()):.2e}",
        "parity.confmatch": num(sum(1 for v in PARITY.values()
                                    if v.get("confusion_matches_published"))),
        "parity.aucdelta": fmt(next(v["auc_abs_delta"] for v in PARITY.values()
                                    if v.get("auc_abs_delta") is not None), 1),
        "other.space": SCOPE["other_space"],
        # the two corpora
        "s2.gradeA.share": pct(GRADE["s2_positive_composition"]["grade_A_share_of_positives"]),
        "s3.gradeA.share": pct(GRADE["s3_positive_composition"]["grade_A_share_of_positives"]),
        "s3.cases": num(S3DESIGN["cases"]),
        "s3.positives": num(S3DESIGN["positives_A_B"]),
        "s3.gradeA": num(GRADE["s3_positive_composition"]["A"]),
        "s3.gradeB": num(GRADE["s3_positive_composition"]["B"]),
        "s3.negatives": num(S3DESIGN["negatives_D"]),
        "s3.prevalence": pct(S3DESIGN["prevalence"]),
        "s3.arms": num(len(GRADE["per_arm"])),
        "s3.cue.bytes": fmt(S3CUE["context_bytes (max over events)"]["auc_raw"], 15),
        "s3.cue.events": fmt(S3CUE["context_events (max over events)"]["auc_raw"], 17),
        "s3.band.lo": exact(S3DESIGN["chance_band_95pct"][0]),
        "s3.band.hi": exact(S3DESIGN["chance_band_95pct"][1]),
        "s3.band.se": exact(S3DESIGN["chance_se_at_auc_0.5"]),
        "s3.varshare": pct(S3BIND["mean_share_of_variance_from_the_221_positives"]),
        "s3.mdauc": fmt(S3RES["median_minimum_detectable_auc_difference"], 14),
        "s3.pairs": num(len(S3["pairwise_delong_all_pairs"])),
        # the two mirror arms, as evidence about the corpora
        "mirror.a.arm": max(grade_rows(), key=lambda g: g["auc_a"])["key"],
        "mirror.a.aucA": fmt(max(grade_rows(), key=lambda g: g["auc_a"])["auc_a"], 15),
        "mirror.a.aucB": fmt(max(grade_rows(), key=lambda g: g["auc_a"])["auc_b"], 16),
        "mirror.a.rank": str(max(grade_rows(), key=lambda g: g["auc_a"])["s2_rank"]),
        "mirror.b.arm": min(grade_rows(), key=lambda g: g["auc_a"])["key"],
        "mirror.b.aucA": fmt(min(grade_rows(), key=lambda g: g["auc_a"])["auc_a"], 15),
        "mirror.b.aucB": fmt(min(grade_rows(), key=lambda g: g["auc_a"])["auc_b"], 16),
        "mirror.b.rank": str(min(grade_rows(), key=lambda g: g["auc_a"])["s2_rank"]),
        # the estimator reasoning
        "est.overweight": fmt([t for t in AUTH["estimator"]["evidence"]
                               ["weight_versus_evidence_mismatch"]["table"]
                               if t["bin"] == "q0"][0]["over_weighting_factor_unweighted"], 1),
        "est.q0.share": pct([t for t in AUTH["estimator"]["evidence"]
                             ["weight_versus_evidence_mismatch"]["table"]
                             if t["bin"] == "q0"][0]["share_of_positives"], 3),
        "est.q0.wunw": pct([t for t in AUTH["estimator"]["evidence"]
                            ["weight_versus_evidence_mismatch"]["table"]
                            if t["bin"] == "q0"][0]["weight_under_unweighted_mean"], 0),
        "est.q0.wpool": pct([t for t in AUTH["estimator"]["evidence"]
                             ["weight_versus_evidence_mismatch"]["table"]
                             if t["bin"] == "q0"][0]["weight_under_pair_weighting"], 3),
        "est.seratio": fmt(AUTH["estimator"]["evidence"]
                           ["primary_analytic_se_ratio_unweighted_over_pooled"]["mean"], 16),
        "est.seworse": num(len(AUTH["estimator"]["evidence"]
                               ["primary_analytic_se_ratio_unweighted_over_pooled"]
                               ["arms_where_unweighted_is_not_worse"])),
        "est.q0.pos": num([t for t in AUTH["estimator"]["evidence"]
                           ["weight_versus_evidence_mismatch"]["table"]
                           if t["bin"] == "q0"][0]["positives"]),
        # the length-control estimator
        "est.published": EST_LABEL[PUB_EST].lower(),
        "est.source": PUB_EST_SOURCE,
        "est.n": num(len(EST_ORDER)),
        "est.schemes": num(STABILITY["schemes"]),
        "est.unwfam": num(STABILITY["families"]["unweighted_mean_family"]),
        "est.rank1": STABILITY["rank1"],
        "est.rank2": STABILITY["rank2"],
        "est.rank3": STABILITY["rank3"],
        "est.rank3.plurality": AUTH["rank_stability"]["rank_3_plurality_among_estimators"],
        "est.disagree1": STABILITY["disagreeing_schemes"][1][0],
        "est.disagree3": num(len(STABILITY["disagreeing_schemes"][3])),
        "est.rank3.pooled": STABILITY["ranks"]["A_pair_weighted_pooled"][2],
        "est.rank3.unw": STABILITY["ranks"]["A_unweighted_mean_within_quintile"][2],
        "est.rank3.ge10": STABILITY["ranks"]["A_unweighted_mean_bins_ge_10_positives"][2],
        "est.rank3.ge25": STABILITY["ranks"]["A_unweighted_mean_bins_ge_25_positives"][2],
        # the shared arithmetic
        "arith.path": esc(SCORER["shared_arithmetic"]["repo_path"]),
        "arith.sha": SCORER["shared_arithmetic"]["sha256"],
        "arith.bytes": num(SCORER["shared_arithmetic"]["bytes"]),
        "arith.importers": num(len(SCORER["shared_arithmetic"]["imported_verbatim_by"])),
        "arith.verified": SCORER["shared_arithmetic"]["dev_host_copy_verified_on"],
        "arith.driver": esc(SCORER["request_construction"]["reference_driver"]),
        # roster
        "roster.n": num(len(ROWS)),
        "roster.candidates": num(sum(1 for a in ROWS if a["cls"] != "control")),
        "roster.general": num(sum(1 for a in ROWS if a["cls"] == "general")),
        "roster.safety": num(sum(1 for a in ROWS if a["cls"] == "safety")),
        "roster.encoder": num(sum(1 for a in ROWS if a["cls"] == "encoder")),
        "roster.control": num(sum(1 for a in ROWS if a["cls"] == "control")),
        "roster.gated": num(sum(1 for a in ROWS if a["gated"])),
        "roster.ungated": num(sum(1 for a in ROWS if not a["gated"])),
        "roster.groups": num(len({a["gated"] for a in ROWS if a["gated"]})),
        "roster.scored": num(sum(1 for a in ROWS if a["status"] == "scored")),
        "roster.ranked": num(sum(1 for a in ROWS if a["status"] == "ranked")),
        "roster.snapshot": num(sum(a["snapshot_bytes"] for a in ROWS)),
        "roster.snapshot.gib": fmt(sum(a["snapshot_bytes"] for a in ROWS) / GIB, 1),
        "qwen.gib": fmt(DROPPED["gib"], 2),
        "qwen.bytes": num(int(DROPPED["bytes"])),
        "qwen.n": num(len(ROSTER["dropped"][0]["repos"])),
        "pg2.86": num(next(a["params"] for a in ROWS if a["key"] == "prompt-guard-2-86m")),
        "pg2.22": num(next(a["params"] for a in ROWS if a["key"] == "prompt-guard-2-22m")),
        "pg2.arch": next(a["architectures"][0] for a in ROWS
                         if a["key"] == "prompt-guard-2-86m"),
        "pg2.maxpos": num(next(a["max_pos"] for a in ROWS if a["key"] == "prompt-guard-2-86m")),
        "gate.cleared": ROSTER["gating_cleared"],
        "lg.categories": num(len(ROSTER["taxonomy"]
                                 ["llama_guard_3_1b_default_categories"])),
        # laptop
        "lap.arms": num(LAPTOP["throughput_coverage"]["arms_converted_or_quantized"]),
        "lap.published": num(LAPTOP["throughput_coverage"]
                             ["arms_with_a_published_rows_per_min"]),
        "lap.fastest": esc(FASTEST["label"]),
        "lap.fastest.rpm": fmt(FASTEST["rows_per_min"], 2),
        "lap.fastest.pass": pass_time(FASTEST["rows_per_min"]),
        "lap.slowest": esc(SLOWEST["label"]),
        "lap.slowest.rpm": fmt(SLOWEST["rows_per_min"], 2),
        "lap.slowest.pass": pass_time(SLOWEST["rows_per_min"]),
        "lap.deberta.rpm": fmt(LAPTOP["encoder_throughput_rows_per_min"][0]
                               ["rows_per_min"], 1),
        "lap.modernbert.rpm": fmt(LAPTOP["encoder_throughput_rows_per_min"][1]
                                  ["rows_per_min"], 1),
        "lap.q4min": fmt(mem["q4_k_m_gib_min"]["gib"], 3),
        "lap.q4min.arm": esc(mem["q4_k_m_gib_min"]["label"]),
        "lap.q4max": fmt(mem["q4_k_m_gib_max"]["gib"], 3),
        "lap.q4max.arm": esc(mem["q4_k_m_gib_max"]["label"]),
        "lap.rss": fmt(mem["peak_rss_hungriest"]["irreducible_gib"], 3),
        "lap.rss.arm": esc(mem["peak_rss_hungriest"]["label"]),
        "lap.rss.mmap": fmt(mem["peak_rss_hungriest"]["worst_observed_under_mmap_gib"], 3),
        "lap.headroom": fmt(8 - mem["peak_rss_hungriest"]["irreducible_gib"], 3),
        # multimodal
        "sh.vision": num(sh["vision_params"]),
        "sh.projector": num(sh["projector_params"]),
        "sh.dead": num(MM[sh["arm"]]["dead"]),
        "sh.share": pct(MM[sh["arm"]]["share"]),
        "sh.text": num(sh["text_tower_params"]),
        "sh.tensors": num(sh["text_tower_tensors"]),
        "sh.q4bytes": num(sh["text_only_q4_k_m_bytes"]),
        "sh.q4gib": fmt(sh["text_only_q4_k_m_bytes"] / GIB, 4),
        "sh.mmproj": num(sh["mmproj_bytes"]),
        "gm.vision": num(gm["vision_params"]),
        "gm.projector": num(gm["projector_params"]),
        "gm.dead": num(MM[gm["arm"]]["dead"]),
        "gm.share": pct(MM[gm["arm"]]["share"]),
        "gm.text": num(gm["text_tower_params"]),
        "gm.bytes": num(gm["full_checkpoint_bytes"]),
        "gm.gib": fmt(gm["full_checkpoint_bytes"] / GIB, 4),
        # the confusion picture, from rows
        "cb.f1": fmt(CB["headline"]["shipped_block_only_f1"], 16),
        "cl.f1": fmt(CL["headline"]["shipped_block_only_f1"], 17),
        "cb.fpr": fmt(CB["shipped_argmax_recomputed_from_rows"]["block_only"]["fpr"], 16),
        "cl.fpr": fmt(CL["shipped_argmax_recomputed_from_rows"]["block_only"]["fpr"], 16),
        "cb.precision": fmt(CB["shipped_argmax_recomputed_from_rows"]
                            ["block_only"]["precision"], 16),
        "cb.recall": fmt(CB["shipped_argmax_recomputed_from_rows"]["block_only"]["recall"], 16),
        "deb.precision": fmt(blk["precision"], 16),
        "top.f1.arm": by_shipped()[0]["key"],
        "top.f1": fmt(by_shipped()[0]["shipped"]["f1"], 16),
        "arms.over.floor": num(sum(1 for a in CANDS.values()
                                   if a["shipped"] and a["shipped"]["f1"] > FLOOR["f1"])),
        "arms.under.floor": num(sum(1 for a in CANDS.values()
                                    if a["shipped"] and a["shipped"]["f1"] < FLOOR["f1"])),
        "arms.zero.f1": num(sum(1 for a in CANDS.values()
                                if a["shipped"] and a["shipped"]["f1"] == 0.0)),
        "arms.shipped.cands": num(sum(1 for a in CANDS.values() if a["shipped"])),
        "arms.scored": num(len(COH)),
        "arms.candidates": num(len(CANDS)),
        "arms.deploy": num(sum(1 for a in COH.values() if a["cap_row"])),
        "arms.noshipped": ", ".join(SHIPPED_MISSING),
        "arms.shipped": num(len(SHIP)),
        # the ranking
        "rank1.arm": by_lc()[0]["key"],
        "rank1.lc": fmt(by_lc()[0]["auc_lc"], 14),
        "rank1.raw": fmt(by_lc()[0]["auc_raw"], 16),
        "rank1.cap": num(by_lc()[0]["cap_tokens"]),
        "rank1.shrunk": num(by_lc()[0]["shrunk"]),
        "rank2.arm": by_lc()[1]["key"],
        "rank2.lc": fmt(by_lc()[1]["auc_lc"], 14),
        "rank2.cap": num(by_lc()[1]["cap_tokens"]),
        "rank3.arm": by_lc()[2]["key"],
        "rank3.lc": fmt(by_lc()[2]["auc_lc"], 14),
        "rank3.cap": num(by_lc()[2]["cap_tokens"]),
        "beat.control": num(sum(1 for a in CANDS.values()
                                if a["auc_lc"] > BASE["auc_lc"])),
        "under.band": num(sum(1 for a in CANDS.values()
                              if a["auc_lc"] < BAND["chance_95pct_interval"][0])),
        # deployment
        "cap.value": f"{FPR_CAP}",
        "cap.deberta.tp": num(COH["deberta-v3-prompt-injection-v2"]["cap_row"]["tp"]),
        # --- the common operating point, reported the same way for every arm
        "cap.exact": exact(FPR_CAP),
        "cap.maxfp": num(int(FPR_CAP * CORPUS["negatives_D"])),
        "cap.f1.arm": max(CANDS.values(), key=lambda a: a["cap_row"]["f1"])["key"],
        "cap.f1": exact(max(CANDS.values(), key=lambda a: a["cap_row"]["f1"])["cap_row"]["f1"]),
        "cap.f1.tp": num(max(CANDS.values(),
                             key=lambda a: a["cap_row"]["f1"])["cap_row"]["tp"]),
        "cap.f1.fp": num(max(CANDS.values(),
                             key=lambda a: a["cap_row"]["f1"])["cap_row"]["fp"]),
        "cap.f1.recall": exact(max(CANDS.values(),
                                   key=lambda a: a["cap_row"]["f1"])["cap_row"]["recall"]),
        "cap.f1.precision": exact(max(CANDS.values(),
                                      key=lambda a: a["cap_row"]["f1"])["cap_row"]["precision"]),
        "cap.f1.threshold": exact(max(CANDS.values(),
                                      key=lambda a: a["cap_row"]["f1"])["cap_row"]["threshold"]),
        "cap.f1.accuracy": exact(accuracy(max(CANDS.values(),
                                              key=lambda a: a["cap_row"]["f1"])["cap_row"],
                                          CORPUS["scorable_cases_A_B_D"])),
        "cap.thresholds": num(len({a["cap_row"]["threshold"] for a in COH.values()})),
        "cap.f1.params": num(max(CANDS.values(), key=lambda a: a["cap_row"]["f1"])["params"]),
        "cap.f1.band": band_of(max(CANDS.values(), key=lambda a: a["cap_row"]["f1"])["params"]),
        # --- size bands
        "band.under": num(len(in_band("under 3B"))),
        "band.mid": num(len(in_band("3B to 6B"))),
        "band.upper": num(len(in_band("6B and up"))),
        "band.max.params": num(max(a["params"] for a in COH.values())),
        "band.max.arm": max(COH.values(), key=lambda a: a["params"])["key"],
        "band.min.params": num(min(a["params"] for a in COH.values())),
        "band.min.arm": min(COH.values(), key=lambda a: a["params"])["key"],
        "band.spread": f'{max(a["params"] for a in COH.values()) / min(a["params"] for a in COH.values()):.0f}',
        "band.best.under": in_band("under 3B")[0]["key"],
        "band.best.mid": in_band("3B to 6B")[0]["key"],
        # --- accuracy against the accuracy of doing nothing
        "acc.s2.allow": exact(CORPUS["negatives_D"] / CORPUS["scorable_cases_A_B_D"]),
        "acc.s3.allow": exact(S3CORP["negatives_D"] / S3CORP["scorable_cases_A_B_D"]),
        "acc.beat": num(sum(1 for a in COH.values()
                            if a["cap_row"]["tp"] > a["cap_row"]["fp"])),
        "acc.gain": num(max(a["cap_row"]["tp"] - a["cap_row"]["fp"] for a in COH.values())),
        # --- each arm's own argmax, an in-sample upper bound
        "oracle.best.arm": max(COH.values(), key=lambda a: a["oracle_f1"])["key"],
        "oracle.best.f1": exact(max(a["oracle_f1"] for a in COH.values())),
        "oracle.min.arm": min(COH.values(), key=lambda a: a["oracle_f1"])["key"],
        "oracle.min.f1": exact(min(a["oracle_f1"] for a in COH.values())),
        "oracle.clear.floor": num(sum(1 for a in COH.values()
                                      if a["oracle_f1"] > FLOOR["f1"])),
        # --- threshold-free
        "auc.above": num(sum(1 for a in COH.values()
                             if a["auc_raw"] > BAND["chance_95pct_interval"][1])),
        "auc.inside": num(sum(1 for a in COH.values()
                              if BAND["chance_95pct_interval"][0] <= a["auc_raw"]
                              <= BAND["chance_95pct_interval"][1])),
        "auc.below": num(sum(1 for a in COH.values()
                             if a["auc_raw"] < BAND["chance_95pct_interval"][0])),
        "auc.coincide": num(sum(1 for a in COH.values()
                                if "defA==defB" in a["primary_var"])),
        # --- the held-out corpus, as settled
        "heldout.arms": num(len(S3ARMS)),
        "heldout.rows": num(next(iter({a["s3_prediction_rows"] for a in S3ARMS.values()}))),
        "heldout.stage0": num(len(S3_STAGE0_NAMES)),
        "heldout.floor.f1": exact(S3FLOOR["f1"]),
        "heldout.sha": S3CORP["cases_sha256"],
        "heldout.overlap": num(S3C["corpora"]["case_id_overlap_s2_s3"]),
        "corpus.prev.ratio": f'{CORPUS["prevalence"] / S3CORP["prevalence"]:.2f}&#215;',
        "rank1.stable": "no" if not AUTH["rank_stability"]["rank_1_stable"] else "yes",
        "rank2.stable": "no" if not AUTH["rank_stability"]["rank_2_stable"] else "yes",
        # --- the Wilson interval on the best recall at the common budget
        "res.wilson.lo": exact(wilson(max(CANDS.values(),
                                          key=lambda a: a["cap_row"]["f1"])["cap_row"]["tp"],
                                      CORPUS["positives_A_B"])[0]),
        "res.wilson.hi": exact(wilson(max(CANDS.values(),
                                          key=lambda a: a["cap_row"]["f1"])["cap_row"]["tp"],
                                      CORPUS["positives_A_B"])[1]),
        # --- the untrained backbone, at both operating points
        "cb.shipped": exact(BASE["shipped"]["f1"]),
        "cb.oracle": exact(BASE["oracle"]["f1"]),
        "beat.control.shipped": num(sum(1 for a in CANDS.values()
                                        if a["shipped"]
                                        and a["shipped"]["f1"] <= BASE["shipped"]["f1"])),
        "beat.control.oracle": num(sum(1 for a in CANDS.values()
                                       if a["oracle"]
                                       and a["oracle"]["f1"] <= BASE["oracle"]["f1"])),
        # --- where the grades and the licences come from
        "labels.path": LABELS["path"],
        "labels.fn": CORPORA["label_scheme"]["function"],
        "labels.sha": LABELS["sha256"],
        "labels.bytes": num(LABELS["bytes"]),
        "lock.path": LOCK["path"],
        "lock.sha": LOCK["sha256"],
        "lock.entries": num(LOCK["entries"]),
        "lock.frozen": LOCK["frozen_at"],
        "lock.aggregate": num(LOCK["redistribution"].get("aggregate-only", 0)),
        "lock.download": num(LOCK["redistribution"].get("download-only", 0)),
        "lock.vendored": num(LOCK["redistribution"].get("vendored", 0)),
        "lock.licences": num(len(LOCK["licences"])),
        "zfp.zero": num(sum(1 for a in CANDS.values() if a["zero_fp"]["recall"] == 0)),
        "zfp.nonzero": num(sum(1 for a in CANDS.values() if a["zero_fp"]["recall"] > 0)),
        "zfp.candidates": num(len(CANDS)),
        "zfp.best.arm": max(CANDS.values(), key=lambda a: a["zero_fp"]["recall"])["key"],
        "zfp.best.recall": exact(max(CANDS.values(),
                                     key=lambda a: a["zero_fp"]["recall"])["zero_fp"]["recall"]),
        "zfp.best.tp": num(max(CANDS.values(),
                               key=lambda a: a["zero_fp"]["recall"])["zero_fp"]["tp"]),
        # settlement
        "settle.settled": num(SETTLE["settled"]),
        "settle.unsettled": num(SETTLE["unsettled"]),
        "settle.rows": num(30310),
        "settle.unsettled.rowsok": num(sum(1 for a in COH.values()
                                           if not a["settled"] and a["rows"] == 30310)),
        "settle.mismatch": num(SETTLE["digest_mismatch"]),
        # gates
        "gate.asserts": num(len(ASSERTS)),
        "gate.artifacts": num(len(_TOUCHED)),
        "gate.charts": num(len(CHARTS)),
    }
    # per-arm confusion and rate keys, from rows. Short aliases for the three current arms keep
    # the templates readable; the full set is keyed by arm so a new arm needs no new code.
    alias = {"deberta-v3-prompt-injection-v2": "deb",
             "control-modernbert-base": "cb",
             "control-modernbert-large": "cl"}
    for key, a in SHIP.items():
        b = dict(a["shipped"]); b["fpr"] = b["block_fpr"]
        for pre in {key, alias.get(key, key)}:
            f[f"{pre}.tp"] = num(b["tp"])
            f[f"{pre}.fp"] = num(b["fp"])
            f[f"{pre}.fn"] = num(b["fn"])
            f[f"{pre}.tn"] = num(b["tn"])
            f[f"{pre}.precision"] = fmt(b["precision"], 16)
            f[f"{pre}.recall"] = fmt(b["recall"], 16)
            f[f"{pre}.f1"] = fmt(b["f1"], 17)
            f[f"{pre}.fpr"] = fmt(b["fpr"], 16)
    return f


# =============================================================== generated tables

def roster_table() -> str:
    head = ["Repository", "Pinned revision", "Class", "Parameters", "Licence", "Origin",
            "Gating group", "Readout", "Status"]
    rows = []
    for a in sorted(ROWS, key=lambda a: (a["cls"], -a["params"])):
        lic = a["licence"]
        if a["licence_name"]:
            lic = f'{lic} ({a["licence_name"]})'
        rows.append([f'<code>{esc(a["repo"])}</code>',
                     f'<code>{esc(a["revision"][:12])}</code>',
                     esc(CLS_LABEL[a["cls"]]), num(a["params"]), esc(lic), esc(a["origin"]),
                     esc(a["gated"]) if a["gated"] else "ungated",
                     f'<code>{esc(a["readout"])}</code>', esc(a["status"])])
    return f'<div class="tbl-scroll">{table_html(head, rows, numeric_from=3)}</div>'


def parity_table() -> str:
    """The equivalence gate, stated as a property of the check. The reference arms belong to the
    System One programme and are not named or scored here."""
    head = ["What the gate checks", "Result"]
    rows = [
        ["Published board scorecards re-derived from their settled prediction bodies before any "
         "cohort arm is reported", f"{len(PARITY)}"],
        ["Confusion matrices reproduced exactly, cell for cell",
         f'{sum(1 for v in PARITY.values() if v.get("confusion_matches_published"))} of '
         f'{len(PARITY)} (the third reference publishes no confusion matrix to check)'],
        ["Largest absolute block-only F1 difference across the references",
         f'{max(v["abs_delta_f1"] for v in PARITY.values()):.2e}'],
        ["Ranking AUC reproduced on the reference that publishes one, absolute difference",
         fmt(next(v["auc_abs_delta"] for v in PARITY.values()
                  if v.get("auc_abs_delta") is not None), 1)],
        ["Arithmetic imported verbatim from the vendored shared module",
         f'sha256 {SCORER["shared_arithmetic"]["sha256"][:16]}'],
    ]
    return f'<div class="tbl-scroll">{table_html(head, rows, numeric_from=1)}</div>'


def scored_table() -> str:
    head = ["Arm", "Role", "Rows", "Errors", "Prediction sha256"]
    rows = []
    for key, arm in sorted(ARMS.items()):
        m = arm.get("arm_meta") or {}
        rows.append([f"<code>{esc(key)}</code>", esc(arm.get("note", "")),
                     num(arm["prediction_rows"]), num(m.get("errors", 0)),
                     f'<code>{esc(arm["prediction_sha256"])}</code>'])
    return f'<div class="tbl-scroll">{table_html(head, rows, numeric_from=2)}</div>'


def taxonomy_table() -> str:
    t = ROSTER["taxonomy"]
    head = ["Arm", "Policy mechanism", "Covers destructive tool calls"]
    rows = [
        ["<code>meta-llama/Llama-Guard-3-1B</code>",
         f'the shipped template hardcodes {len(t["llama_guard_3_1b_default_categories"])} '
         f'categories, S1 to S13',
         "no; <code>llamaguard_default_taxonomy_covers_task: false</code> is recorded in the "
         "run metadata"],
        ["<code>google/shieldgemma-2b</code>",
         "the chat template takes a <code>guideline</code> argument",
         "yes, once the I3 policy is passed as the guideline"],
        ["<code>mistralai/Shieldstral-1.0-3B</code>",
         "policy argument",
         "yes, once the I3 policy is passed as the policy"],
    ]
    return f'<div class="tbl-scroll">{table_html(head, rows, numeric_from=3)}</div>'


def lg_categories() -> str:
    t = ROSTER["taxonomy"]
    items = "".join(f"<li>{esc(c)}</li>"
                    for c in t["llama_guard_3_1b_default_categories"])
    return (f"<ul class=\"slots\">{items}</ul>"
            f"<p>The 8B model in the same family carries an "
            f"{esc(t['llama_guard_3_8b_has_code_interpreter_abuse'])} Code Interpreter Abuse "
            f"category. The 1B's default list does not. S2 Non-Violent Crimes is the nearest "
            f"fit and mapping onto it would have been a manufactured mapping, so "
            f"{esc(t['substitute'])}. Readout is "
            f"{esc(t['readout'])}.</p>")


def artifacts_read() -> str:
    """Every file this build read, deep-linked, with its digest. Derived from the read log, so a
    new input cannot be published without appearing here."""
    rows = []
    for path in sorted(_TOUCHED):
        rel = os.path.relpath(path, REPO_ROOT)
        rows.append([f'<a href="{GH}/{esc(rel)}"><code>{esc(rel)}</code></a>',
                     num(os.path.getsize(path)),
                     f'<code>{esc(sha256_file(path)[:16])}</code>'])
    return (f'<p>\n  {len(rows)} files, listed from the build\'s own read log. A file the build '
            f'opens and this table omits is impossible: the table is generated from that log.\n'
            f'</p>\n<div class="tbl-scroll">'
            f'{table_html(["File", "Bytes", "sha256, first 16"], rows, numeric_from=1)}</div>')


def caveat_list() -> str:
    items = "".join(f'<li>{esc(c["text"])}</li>'
                    for c in LAPTOP["provenance"]["caveats"])
    return f"<ul>{items}</ul>"


UIS = {
    "common_point_table": common_point_table,
    "oracle_table": oracle_table,
    "accuracy_table": accuracy_table,
    "size_band_tables": size_band_tables,
    "moe_note": moe_note,
    "auc_table": auc_table,
    "definition_table": definition_table,
    "floor_table": floor_table,
    "corpus_table": corpus_table,
    "grade_scheme_table": grade_scheme_table,
    "label_provenance": label_provenance_block,
    "licence_table": licence_table,
    "heldout_table": heldout_table,
    "heldout_reconciliation": heldout_reconciliation,
    "control_finding": control_finding,
    "estimator_table": estimator_table,
    "sparse_bin_note": sparse_bin_note,
    "corpus_design_note": corpus_design_note,
    "resolution_note": resolution_note,
    "roster_table": roster_table,
    "parity_table": parity_table,
    "scored_table": scored_table,
    "taxonomy_table": taxonomy_table,
    "lg_categories": lg_categories,
    "artifacts_read": artifacts_read,
    "caveat_list": caveat_list,
}



# ----------------------------------------------------- the Space card's front matter
# The Hugging Face API validates this on upload and rejects the whole commit, so it is checked
# here. The limits below are the ones the API enforces.
CARD_REQUIRED = ("title", "sdk", "app_file", "license", "short_description",
                 "emoji", "colorFrom", "colorTo", "pinned")
CARD_LIMITS = {"short_description": 60, "title": 100}


def check_card(body: str) -> list[str]:
    out = []
    if not body.startswith("---\n"):
        return ["README.md: no YAML front matter, so the Space has no SDK declaration"]
    fm = body.split("---\n", 2)[1]
    keys = dict(re.findall(r"^([A-Za-z_]+):[ \t]*(.*)$", fm, re.M))
    for k in CARD_REQUIRED:
        if k not in keys:
            out.append(f"README.md: front matter is missing {k!r}")
    for k, limit in CARD_LIMITS.items():
        v = keys.get(k, "")
        if len(v) > limit:
            out.append(f"README.md: front matter {k!r} is {len(v)} characters, over the "
                       f"{limit}-character limit the API enforces")
    if keys.get("sdk") != "static":
        out.append(f"README.md: sdk is {keys.get('sdk')!r}, expected 'static'")
    if keys.get("app_file") != "index.html":
        out.append(f"README.md: app_file is {keys.get('app_file')!r}, expected 'index.html'")
    return out


# ======================================================================= shell

NAV_ITEMS = [
    ("index.html", "Overview"),
    ("operating-point.html", "Operating point"),
    ("sizes.html", "Size bands"),
    ("datasets.html", "Datasets"),
    ("baselines.html", "Baselines"),
    ("results.html", "Results"),
    ("roster.html", "Roster"),
    ("footprint.html", "Footprint"),
    ("methodology.html", "Methodology"),
    ("reproduce.html", "Reproduce"),
]


def nav(current: str) -> str:
    links = "".join(
        f'<a href="{href}"{" aria-current=" + chr(34) + "page" + chr(34) if href == current else ""}>{label}</a>'
        for href, label in NAV_ITEMS)
    return ('<nav class="nav"><div class="nav-in">'
            '<span class="nav-brand">SLM tool-call security</span>'
            + links
            + '<span class="tag">evaluation-only &middot; never-train</span>'
              '</div></nav>')


TOKEN = re.compile(r"\{\{(chart|fig|ui):([A-Za-z0-9_.]+)\}\}")




def main() -> int:
    if BAD:
        print("=" * 78)
        print("ABORT: an artifact disagreed with an asserted figure. Nothing was written.")
        for line in BAD:
            print("  " + line)
        print("=" * 78)
        return 2
    print(f"figure assertions: {len(ASSERTS)} checked, 0 mismatches")

    charts = {k: v() for k, v in CHARTS.items()}
    print(f"charts generated: {len(charts)}")
    figs = build_figs()
    print(f"figure keys: {len(figs)}")
    uis = {k: v() for k, v in UIS.items()}
    print(f"ui blocks generated: {len(uis)}")

    if _FIT:
        print("ABORT: label(s) would overflow their gutter:")
        for w in _FIT:
            print("  " + w)
        return 4
    print("label-fit check: every axis and row label fits its gutter")
    if _LAYOUT:
        print(f"ABORT: {len(_LAYOUT)} overlapping label pair(s):")
        for w in _LAYOUT[:40]:
            print("  " + w)
        return 8
    print(f"layout check: 0 overlapping labels across {len(charts)} charts")

    with open(os.path.join(ASSETS, "style.css"), "r", encoding="utf-8") as fh:
        css = fh.read()
    css_bad = check_css(css)
    if css_bad:
        print("ABORT: stylesheet and chart palette disagree:")
        for line in css_bad:
            print("  " + line)
        return 5
    print("palette check: chart presentation attributes match the stylesheet's light values")
    os.makedirs(os.path.join(OUT, "assets"), exist_ok=True)
    with open(os.path.join(OUT, "assets", "style.css"), "w", encoding="utf-8") as fh:
        fh.write(css)
    style_block = "<style>\n" + css.strip() + "\n</style>"

    missing: list[str] = []
    markup_bad: list[str] = []
    card_bad: list[str] = []
    scope_bad: list[str] = []
    written: list[str] = []
    for name in sorted(os.listdir(PAGES)):
        if not name.endswith((".html", ".md")):
            continue
        with open(os.path.join(PAGES, name), "r", encoding="utf-8") as fh:
            body = fh.read()

        def sub(m, _name=name):
            kind, key = m.group(1), m.group(2)
            table = {"chart": charts, "fig": figs, "ui": uis}[kind]
            if key not in table:
                missing.append(f"{_name}: {{{{{kind}:{key}}}}}")
                return m.group(0)
            return table[key]

        body = TOKEN.sub(sub, body)
        body = body.replace("{{NAV}}", nav(name))
        if name == "README.md":
            card_bad.extend(check_card(body))
        if name.endswith(".html"):
            if "{{STYLE}}" not in body:
                missing.append(f"{name}: no {{{{STYLE}}}} in <head>, so the page would be "
                               f"unstyled")
            body = body.replace("{{STYLE}}", style_block)
        with open(os.path.join(OUT, name), "w", encoding="utf-8") as fh:
            fh.write(body)
        written.append(name)
        scope_bad.extend(check_scope(name, body))
        if name.endswith(".html"):
            markup_bad.extend(check_markup(name, body))

    if missing:
        print("ABORT: unresolved template tokens:")
        for m in missing:
            print("  " + m)
        return 3
    if scope_bad:
        print("ABORT: an out-of-scope model or arm is named in the output:")
        for line in scope_bad:
            print("  " + line)
        return 10
    print(f"scope check: 0 of {len(SCOPE['forbidden_tokens'])} out-of-scope names present")
    if card_bad:
        print("ABORT: the Space card's front matter would be rejected on upload:")
        for line in card_bad:
            print("  " + line)
        return 9
    print("card check: front matter carries every required key and is within every limit")
    if markup_bad:
        print("ABORT: escaping defect in generated output:")
        for line in markup_bad[:40]:
            print("  " + line)
        return 7
    print(f"markup check: {len(written)} pages, 0 double-escaped entities, 0 raw '&' or '<', "
          f"0 escaped tags rendering as text")

    allsrc = "".join(open(os.path.join(PAGES, n), encoding="utf-8").read() for n in written)
    unplaced = sorted(c for c in charts if f"chart:{c}" not in allsrc)
    if unplaced:
        print(f"ABORT: charts built but never placed on a page: {unplaced}")
        return 6
    unplaced_ui = sorted(u for u in uis if f"ui:{u}" not in allsrc)
    if unplaced_ui:
        print(f"ABORT: ui blocks built but never placed: {unplaced_ui}")
        return 6
    # the arm-keyed confusion aliases exist so a new arm needs no template edit; they are not
    # expected to be placed, so they are excluded from this note.
    aliases = tuple(f"{k}." for k in list(COH) + ["deb", "cb", "cl"])
    unused_fig = sorted(k for k in figs if f"fig:{k}" not in allsrc
                        and not k.startswith(aliases))
    if unused_fig:
        print(f"note: {len(unused_fig)} figure key(s) defined but not placed: "
              f"{', '.join(unused_fig)}")

    print("pages written:")
    for n in written:
        print(f"  {n:24s} {os.path.getsize(os.path.join(OUT, n)):>8,} bytes")
    print(f"  {'assets/style.css':24s} "
          f"{os.path.getsize(os.path.join(OUT, 'assets', 'style.css')):>8,} bytes")
    print(f"artifacts read: {len(_TOUCHED)}")
    for t in sorted(_TOUCHED):
        print("  " + t)
    with open(os.path.join(OUT, "_build-figures.json"), "w", encoding="utf-8") as fh:
        json.dump({"figures": figs,
                   # repo-rooted, so the record identifies files in the repository and carries no
                   # part of whatever machine ran the build
                   "artifacts_read": sorted(os.path.relpath(p, REPO_ROOT) for p in _TOUCHED),
                   "artifacts_read_sha256": {
                       os.path.relpath(p, REPO_ROOT): sha256_file(p) for p in sorted(_TOUCHED)},
                   "assertions_checked": len(ASSERTS),
                   "charts": sorted(charts),
                   "cases_sha256": CORPUS["cases_sha256"]}, fh, indent=1, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
