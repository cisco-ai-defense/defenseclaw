#!/usr/bin/env python3
"""Conform the cohort's scored arms to this Space build's contract.

Same discipline as benchmarks/system_one/reproduce/08-site-build/conform_to_space_contract.py:
the runs are finished and are not touched. The prediction files, their metas and the scorecards
are read, never rewritten. What this does is put each artifact at the path `build.py :: load()`
resolves, and derive every field from an artifact instead of declaring it:

  artifacts/cohort-scores.json       the per-arm scorecards, by-variable AUC sweep,
  artifacts/leakage-diagnostic.json  leakage gate and truncation analysis, republished byte for
  artifacts/final-comparisons.json   byte from the scoring run's own outputs

  site-build/pinned/roster.json      the overlay: the class label where the readout family does
                                     not determine it, the gating-group descriptions, each arm's
                                     status, the two board references, the taxonomy record and
                                     the dropped family. Everything else about an arm is read
                                     from harness/arms.py and the weight manifests.
  site-build/pinned/laptop-*.json    the CPU primitives, whose parameter splits are re-checked
                                     against the registry's totals

Checks that abort:
  * the corpus digest in each artifact differs from the pinned cases_sha256
  * a prediction file's on-disk sha256 differs from the digest the scorecard records
  * an arm's row count, error count or scorable-case coverage differs from the corpus
  * the registry and a scored arm's run metadata disagree on params, licence, repo or revision
  * a multimodal parameter split does not sum to the registry's total for that arm
  * a throughput or memory row names an arm the registry does not hold
  * the overlay covers an arm the registry does not hold, or misses one it does
  * a scored arm is missing from the registry, or the overlay claims a status the artifacts
    contradict
  * a manifest's recorded architecture class contradicts the overlay's backbone claim

Run with --check to verify without writing.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
ARTIFACTS = os.path.join(REPO_ROOT, "slm_toolcall", "artifacts")
PINNED = os.path.join(HERE, "pinned")
HARNESS = os.path.abspath(os.path.join(HERE, "..", "harness"))

# where the scoring run wrote its own outputs, and where the predictions live
SRC = os.environ.get("SLM_COHORT_SRC", "/home/ubuntu/cohort-scoring")
PREDS = os.path.join(SRC, "preds")

CASES_SHA = "39f2c1df2369952a0525cc4c5575f4bdb590fb3ca8c1bc6805cf4f376c1adbf7"
ARTIFACT_FILES = ["cohort-scores.json", "leakage-diagnostic.json", "final-comparisons.json"]

# a scored arm's key in cohort-scores.json -> its key in the arm registry. Arms the overlay's
# scope block excludes are not mapped: they belong to the other programme's Space.
SCORED_TO_ROSTER = {
    "deberta-v3-prompt-injection-v2": "deberta-v3-prompt-injection-v2",
    "control-modernbert-base": "control-modernbert-base",
    "control-modernbert-large": "control-modernbert-large",
}

CHANGED: list[str] = []
NOTES: list[str] = []


def must(cond: bool, msg: str) -> None:
    if not cond:
        raise SystemExit(f"ABORT: {msg}")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load(path: str):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def write_bytes(path: str, body: bytes, check: bool) -> None:
    if os.path.exists(path) and open(path, "rb").read() == body:
        return
    CHANGED.append(path)
    if check:
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(body)


# ------------------------------------------------------------------ the artifacts

def stage_artifacts(check: bool) -> None:
    """Republish the scoring run's three outputs byte for byte, after checking each one's own
    record of the corpus it scored."""
    for name in ARTIFACT_FILES:
        src = os.path.join(SRC, name)
        if not os.path.exists(src):
            NOTES.append(f"{name}: not present at {SRC}; the copy already in the repository is "
                         f"left as it is")
            must(os.path.exists(os.path.join(ARTIFACTS, name)),
                 f"{name} is in neither {SRC} nor {ARTIFACTS}")
            continue
        write_bytes(os.path.join(ARTIFACTS, name), open(src, "rb").read(), check)

    scores = load(os.path.join(ARTIFACTS, "cohort-scores.json"))
    must(scores["corpus"]["cases_sha256"] == CASES_SHA,
         "cohort-scores.json records a different corpus than the pinned cases_sha256")
    c = scores["corpus"]
    must(c["positives_A_B"] + c["negatives_D"] == c["scorable_cases_A_B_D"],
         "the corpus label counts do not sum to the scorable-case count")
    must(c["scorable_cases_A_B_D"] + c["grade_C_excluded"] == c["cases"],
         "the scorable and excluded counts do not sum to the case count")
    return scores


def check_predictions(scores: dict, excluded: set) -> None:
    """Each in-scope arm's prediction file must match the digest its scorecard records, and must
    cover every scorable case with no errors."""
    for key, arm in scores["arms"].items():
        if key in excluded:
            NOTES.append(f"{key}: out of scope on this Space, so it is not checked or published")
            continue
        must(arm["scoreable"] is True, f"{key}: the scorecard does not mark it scoreable")
        must(arm["scorable_cases_missing_from_prediction"] == 0,
             f"{key}: {arm['scorable_cases_missing_from_prediction']} scorable cases are "
             f"missing from the prediction file")
        must(arm["cases_in_prediction"] == scores["corpus"]["cases"],
             f"{key}: the prediction covers {arm['cases_in_prediction']} cases against the "
             f"corpus's {scores['corpus']['cases']}")
        meta = arm.get("arm_meta") or {}
        if meta:
            must(meta.get("errors") == 0, f"{key}: the run recorded errors")
            must(meta.get("rows") == arm["prediction_rows"],
                 f"{key}: run meta rows {meta.get('rows')!r} against scorecard "
                 f"{arm['prediction_rows']!r}")
        path = arm["prediction"]
        if not os.path.exists(path):
            alt = os.path.join(PREDS, os.path.basename(path))
            path = alt if os.path.exists(alt) else None
        if path is None:
            NOTES.append(f"{key}: the prediction body is not on this host, so its digest could "
                         f"not be re-checked. The scorecard records "
                         f"{arm['prediction_sha256'][:12]}.")
            continue
        got = sha256_file(path)
        must(got == arm["prediction_sha256"],
             f"{key}: prediction sha256 on disk {got} against the scorecard's "
             f"{arm['prediction_sha256']}")
        NOTES.append(f"{key}: prediction digest re-checked against the bytes on disk")


# -------------------------------------------------------------------- the roster


def load_registry() -> dict:
    import importlib.util
    path = os.path.join(HARNESS, "arms.py")
    spec = importlib.util.spec_from_file_location("slm_arms", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.ARMS


def load_manifests() -> dict:
    out: dict[str, dict] = {}
    for n in ("weights_manifest.json", "weights_manifest2.json", "weights_manifest3.json",
              "weights_manifest4.json"):
        for e in load(os.path.join(HARNESS, n)):
            e = dict(e)
            e["manifest"] = n
            out[e["repo"]] = e
    return out


def check_roster(scores: dict) -> dict:
    overlay = load(os.path.join(PINNED, "roster.json"))
    reg = load_registry()
    man = load_manifests()

    must(len(reg) == 22, f"the arm registry holds {len(reg)} arms, expected 22")
    must(sum(1 for a in reg.values() if a.get("control")) == 2,
         "the registry does not flag exactly two negative controls")
    must(sum(1 for a in reg.values() if a.get("gated")) == 8,
         "the registry does not flag exactly eight gated arms")

    # the overlay must cover the registry exactly, in both directions
    for field in ("class_override", "backbone", "backbone_evidence"):
        for k in overlay[field]:
            must(k in reg, f"overlay {field} names {k!r}, which the registry does not hold")
    for k, a in reg.items():
        must(a["readout"] in overlay["class_from_readout"],
             f"{k}: readout {a['readout']!r} has no class mapping in the overlay")
        must(a["repo"] in man, f"{k}: no weight-manifest record for {a['repo']!r}")
        must(man[a["repo"]]["status"] == "ok",
             f"{k}: the download record for {a['repo']!r} is not ok")
        must(isinstance(man[a["repo"]].get("bytes"), int) and man[a["repo"]]["bytes"] > 0,
             f"{k}: the download record carries no byte size")
        if man[a["repo"]].get("params") is not None:
            must(man[a["repo"]]["params"] == a["params"],
                 f"{k}: manifest params {man[a['repo']]['params']} against registry "
                 f"{a['params']}")

    # the manifest's architecture class must support the overlay's backbone claim
    for k, want in overlay["backbone"].items():
        arch = man[reg[k]["repo"]].get("architectures")
        if arch:
            must(any(want.lower() in x.lower() for x in arch),
                 f"{k}: manifest architectures {arch!r} do not support backbone {want!r}")
            NOTES.append(f"{k}: backbone {want} confirmed by the download record's "
                         f"architectures field")
        else:
            must(k in overlay["backbone_evidence"],
                 f"{k}: the overlay claims backbone {want!r} and records no evidence, and the "
                 f"download predates the architecture field")

    # the scope block must name exactly the scorecard arms this Space does not publish
    # The vendored artifacts are scope-filtered by vendor_artifacts.py, so an excluded arm is
    # normally already absent from them. Both states are accepted; what must hold is that the arm
    # is never published and never mapped onto the registry.
    excluded = set(overlay["scope"]["excluded_scorecard_arms"])
    for k in excluded:
        must(k not in SCORED_TO_ROSTER, f"{k!r} is both excluded and mapped onto the registry")
        if k in scores["arms"]:
            NOTES.append(f"{k}: present in the vendored artifact and excluded at build time")
        else:
            NOTES.append(f"{k}: already removed from the vendored artifact by vendor_artifacts.py")
    must(set(scores["arms"]) - excluded == set(SCORED_TO_ROSTER),
         f"the stage-0 scorecards hold {sorted(set(scores['arms']) - excluded)} in scope and this "
         f"script maps {sorted(SCORED_TO_ROSTER)}")
    NOTES.append(f"scope: {len(excluded)} scorecard arm(s) excluded, "
                 f"{len(SCORED_TO_ROSTER)} published")

    for scored, rkey in SCORED_TO_ROSTER.items():
        must(scored in scores["arms"], f"{scored}: scored arm is absent from the scorecards")
        must(rkey in reg,
             f"{rkey}: scored arm is absent from the arm registry")
        meta = scores["arms"][scored].get("arm_meta") or {}
        if not meta:
            NOTES.append(f"{rkey}: the scorecard carries no arm_meta, so params, licence, repo "
                         f"and revision were not cross-checked")
            continue
        a = reg[rkey]
        must(meta["params_counted"] == a["params"],
             f"{rkey}: run meta params {meta['params_counted']} against registry {a['params']}")
        must(a["licence"].startswith(meta["licence"]),
             f"{rkey}: run meta licence {meta['licence']!r} against registry {a['licence']!r}")
        must(meta["repo"] == a["repo"],
             f"{rkey}: run meta repo {meta['repo']!r} against registry {a['repo']!r}")
        must(meta["revision"] == a["revision"],
             f"{rkey}: run meta revision {meta['revision']!r} against registry "
             f"{a['revision']!r}")
        must(meta["readout"] == a["readout"],
             f"{rkey}: run meta readout {meta['readout']!r} against registry {a['readout']!r}")
        NOTES.append(f"{rkey}: params, licence, repo, revision and readout all agree with the "
                     f"registry at {a['revision'][:12]}")

    for scored in scores["arms"]:
        must(scored in SCORED_TO_ROSTER or scored in excluded,
             f"{scored}: a scored arm this script neither maps nor excludes")

    # status is derived from the artifacts, so the overlay must no longer declare it
    must("status" not in overlay,
         "the overlay still declares a per-arm status; it is derived from the artifacts now")

    # the dropped family's download record
    drop = overlay["dropped"][0]
    for r in drop["repos"]:
        must(r in man, f"{r}: the dropped family's download record is missing")
        must(r not in {a['repo'] for a in reg.values()},
             f"{r}: a dropped repo is still in the arm registry")
    total = sum(man[r]["bytes"] for r in drop["repos"])
    NOTES.append(f"dropped {drop['family']}: {len(drop['repos'])} repositories, {total:,} bytes "
                 f"on disk, {total / 1024 ** 3:.2f} GiB")
    return {"registry": reg, "manifest": man, "overlay": overlay}


# ------------------------------------------------------------- the CPU primitives

def check_laptop(ctx: dict) -> None:
    lap = load(os.path.join(PINNED, "laptop-feasibility.json"))
    reg = ctx["registry"]
    must(lap["provenance"]["raw_artifacts_read_for_this_build"] is False,
         "the laptop artifact claims its raw measurements were re-read; they are on the studio "
         "and the provenance block must say so")
    must("never saved" in lap["provenance"]["reproducibility"],
         "the laptop artifact does not record that its measurement step was never saved")
    for m in lap["multimodal_splits"]:
        must(m["arm"] in reg, f'{m["arm"]}: a multimodal split names a non-registry arm')
        total = m["vision_params"] + m["projector_params"] + m["text_tower_params"]
        must(total == reg[m["arm"]]["params"],
             f'{m["arm"]}: the split sums to {total} against the registry\'s '
             f'{reg[m["arm"]]["params"]}')
        NOTES.append(f'{m["arm"]}: parameter split sums to the registry total exactly')
    rows = lap["decoder_throughput_rows_per_min"] + lap["encoder_throughput_rows_per_min"]
    for r in rows:
        must(r["arm"] in reg, f'{r["arm"]}: a throughput row names a non-registry arm')
    for k in ("q4_k_m_gib_min", "q4_k_m_gib_max", "peak_rss_hungriest"):
        must(lap["memory"][k]["arm"] in reg,
             f'memory.{k} names {lap["memory"][k]["arm"]!r}, which is not a registry arm')
    must(len(rows) == lap["throughput_coverage"]["arms_with_a_published_rows_per_min"],
         "the throughput coverage count disagrees with the number of rows present")
    must(lap["throughput_coverage"]["arms_with_a_published_rows_per_min"]
         <= lap["throughput_coverage"]["arms_converted_or_quantized"],
         "more rows/min figures are published than arms were converted")
    vals = [r["rows_per_min"] for r in lap["decoder_throughput_rows_per_min"]]
    must(vals == sorted(vals, reverse=True),
         "the decoder throughput table is not in descending order, which the chart relies on")
    NOTES.append(f"laptop primitives: {len(rows)} rows/min figures over "
                 f"{lap['throughput_coverage']['arms_converted_or_quantized']} converted arms")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    scores = stage_artifacts(args.check)
    overlay_scope = load(os.path.join(PINNED, "roster.json"))["scope"]
    check_predictions(scores, set(overlay_scope["excluded_scorecard_arms"]))
    ctx = check_roster(scores)
    check_laptop(ctx)
    for n in NOTES:
        print("note:", n)
    verb = "would write" if args.check else "wrote"
    if CHANGED:
        print(f"{verb} {len(CHANGED)} file(s):")
        for p in CHANGED:
            print("  " + p)
    else:
        print("nothing to do: every staged artifact is already on disk and identical")
    return 0


if __name__ == "__main__":
    sys.exit(main())
