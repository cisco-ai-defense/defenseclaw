"""Cache per-case aggregates for the s3 escalation analysis.  ZERO GPU, read-only.

Every piece of arithmetic is imported, not reimplemented:
  * sweep / best_point / mann_whitney_auc / f1_of / wilson / at_fpr_cap /
    zero_fp_point / truth_grade / ACTION_RANK / Z / sha256_file
        <- /home/ubuntu/rescoring-remine/remine.py
           sha256 97df17a30891446d94a9df923ec343a6c7bd29adea3435b0303e4604440d5a6f
  * load_corpus / read_arm / classify / projections_for / confusion /
    quintile_bucketer / length_controlled / variable_entry / score
        <- /home/ubuntu/cohort-rank/rank_cohort.py  (the settled cohort ranking code)

This step only reads prediction bodies once and writes a compact per-case cache so the
later analyses never re-parse 1.4M JSON lines.

s3 bodies come from the ARCHIVED SETTLED copies under
/home/ubuntu/archive-stage-2026-09-24/, which carry `complete: true` plus a
`prediction_sha256` that matches the body.  The /home/ubuntu/cohort-rank/preds-s3 copies
of the same three arms do NOT carry those keys, so they are not used here.
"""
from __future__ import annotations

import json, sys
from pathlib import Path

sys.path.insert(0, "/home/ubuntu/rescoring-remine")
sys.path.insert(0, "/home/ubuntu/cohort-rank")
import remine as H          # noqa: E402  house arithmetic
import rank_cohort as RC     # noqa: E402  settled cohort ranking machinery

ROOT = Path("/home/ubuntu/s3-escalation-2026-09-24")
CACHE = ROOT / "cache"
CACHE.mkdir(parents=True, exist_ok=True)

S2P = Path("/home/ubuntu/cohort-rank/preds-s2")
S3P = Path("/home/ubuntu/archive-stage-2026-09-24/laptopguard/preds-s3")
NIMBLE = {
    "s2": Path("/home/ubuntu/.system-one-data/outputs/nimble/s2/bespoke-nimble-9b.jsonl"),
    "s3": Path("/home/ubuntu/archive-stage-2026-09-24/sysone/runs/nimble-s3/settled/bespoke-nimble-9b.jsonl"),
}

# the six cohort arms that have a settled s3 counterpart, with their published s2 rank
COHORT6 = {
    "deberta-v3-prompt-injection-v2": 1,
    "shieldgemma-2b": 2,
    "granite-guardian-3.2-3b-a800m": 3,
    "shieldstral-1.0-3b": 8,
    "prompt-guard-2-22m": 11,
    "prompt-guard-2-86m": 14,
}


def dump(name: str, obj) -> None:
    (CACHE / name).write_text(json.dumps(obj, sort_keys=True) + "\n")
    print("  cached", name, flush=True)


def extract(arm: str, path: Path, corp, tag: str) -> dict:
    """Read one prediction body and cache the per-case vectors, in corpus order."""
    scorable = corp["scorable"]
    d = RC.read_arm(path)
    shape = d["shape"]
    proj, inap, primary = RC.projections_for(shape)
    agg = d["agg"]
    missing = [c for c in scorable if c not in agg]
    ship = {}
    for cid in scorable:
        acts = d["actions"].get(cid) or []
        ship[cid] = max(acts, key=lambda v: H.ACTION_RANK.get(v, -1)) if acts else "error"
    rec = {
        "arm": arm, "split": corp["split"], "prediction": str(path),
        "prediction_rows": d["rows"], "cases_in_prediction": len(agg),
        "prediction_sha256_disk": d["prediction_sha256_disk"],
        "output_shape": shape,
        "two_class_positive_key": d["two_class_positive_key"],
        "row_action_histogram": d["row_action_histogram"],
        "rows_without_probabilities": d["rows_without_probabilities"],
        "scorable_cases_missing_from_prediction": len(missing),
        "primary_block_variable": primary,
        "inapplicable_variables": inap,
        "ship_action": [ship[c] for c in scorable],
        "vars": {v: [fn(agg[c]) for c in scorable] for v, (fn, _dl) in proj.items()},
        "var_definition_label": {v: dl for v, (_fn, dl) in proj.items()},
        "cbytes": [agg[c]["cbytes"] for c in scorable],
        "cevents": [agg[c]["cevents"] for c in scorable],
        "tok": [agg[c]["tok"] for c in scorable],
        "events": [agg[c]["events"] for c in scorable],
    }
    mp = Path(str(path) + ".meta.json")
    if mp.exists():
        m = json.loads(mp.read_text())
        sha_ok = (m.get("prediction_sha256") == d["prediction_sha256_disk"]) if "prediction_sha256" in m else None
        rec["metadata"] = {
            "meta_path": str(mp),
            "carries_complete_key": "complete" in m, "complete_value": m.get("complete"),
            "carries_prediction_sha256_key": "prediction_sha256" in m,
            "prediction_sha256_meta": m.get("prediction_sha256"),
            "sha256_meta_matches_disk": sha_ok,
            "settled": bool(m.get("complete") is True and sha_ok is True),
            "rows": m.get("rows"), "errors": m.get("errors"), "shrunk": m.get("shrunk"),
            "cap_tokens": m.get("cap_tokens"), "token_budget": m.get("token_budget"),
            "repo": m.get("repo"), "revision": m.get("revision"),
            "params_counted": m.get("params_counted"), "readout": m.get("readout"),
            "rows_per_min_cuda": m.get("rows_per_min"),
            "cases": m.get("cases"), "cases_sha256": m.get("cases_sha256"),
            "run_id": m.get("run_id"),
        }
    else:
        rec["metadata"] = {"meta_path": str(mp), "present": False, "settled": False}
    dump(f"{tag}.json", rec)
    return rec


def main() -> None:
    manifest = {"corpora": {}, "arms": {}}
    for split in ("s2", "s3"):
        c = RC.load_corpus(split)
        dump(f"corpus-{split}.json", {
            "split": split, "scorable": c["scorable"], "labels": c["labels"],
            **{k: v for k, v in c.items()
               if k not in ("scorable", "labels", "label_by_case", "grades")},
        })
        manifest["corpora"][split] = {
            k: v for k, v in c.items()
            if k not in ("scorable", "labels", "label_by_case", "grades")}
        globals()["CORP_" + split] = c

    s2, s3 = globals()["CORP_s2"], globals()["CORP_s3"]
    manifest["corpus_overlap"] = {
        "s2_cases": len(s2["grades"]), "s3_cases": len(s3["grades"]),
        "case_id_intersection": len(set(s2["grades"]) & set(s3["grades"])),
        "scorable_intersection": len(set(s2["scorable"]) & set(s3["scorable"])),
        "note": "0 means s3 is genuinely held out from s2",
    }

    # ---- all 22 s2 cohort arms (needed for the s2 side of the transfer, for the
    #      error-correlation study and for the cascade)
    print("=== s2 cohort (22 arms)", flush=True)
    for p in sorted(S2P.glob("*.jsonl")):
        arm = p.stem
        r = extract(arm, p, s2, f"s2--{arm}")
        manifest["arms"][f"s2/{arm}"] = {
            k: r[k] for k in ("prediction", "prediction_rows", "prediction_sha256_disk",
                              "output_shape", "scorable_cases_missing_from_prediction",
                              "primary_block_variable")}
        manifest["arms"][f"s2/{arm}"]["settled"] = r["metadata"].get("settled")

    # ---- the six settled s3 cohort arms
    print("=== s3 cohort (6 settled arms)", flush=True)
    for arm in sorted(COHORT6):
        p = S3P / f"{arm}.jsonl"
        r = extract(arm, p, s3, f"s3--{arm}")
        manifest["arms"][f"s3/{arm}"] = {
            k: r[k] for k in ("prediction", "prediction_rows", "prediction_sha256_disk",
                              "output_shape", "scorable_cases_missing_from_prediction",
                              "primary_block_variable")}
        manifest["arms"][f"s3/{arm}"]["settled"] = r["metadata"].get("settled")
        manifest["arms"][f"s3/{arm}"]["published_s2_rank"] = COHORT6[arm]

    # ---- bespoke-nimble-9b, both splits (Task 2, System One work, kept separate)
    print("=== bespoke-nimble-9b (System One, separate from the cohort ranking)", flush=True)
    for split, p in NIMBLE.items():
        corp = s2 if split == "s2" else s3
        r = extract("bespoke-nimble-9b", p, corp, f"{split}--bespoke-nimble-9b")
        manifest["arms"][f"{split}/bespoke-nimble-9b"] = {
            k: r[k] for k in ("prediction", "prediction_rows", "prediction_sha256_disk",
                              "output_shape", "scorable_cases_missing_from_prediction",
                              "primary_block_variable")}
        manifest["arms"][f"{split}/bespoke-nimble-9b"]["settled"] = r["metadata"].get("settled")

    manifest["provenance"] = {
        "gpu_used": False,
        "remine_path": "/home/ubuntu/rescoring-remine/remine.py",
        "remine_sha256": H.sha256_file(Path("/home/ubuntu/rescoring-remine/remine.py")),
        "rank_cohort_path": "/home/ubuntu/cohort-rank/rank_cohort.py",
        "rank_cohort_sha256": H.sha256_file(Path("/home/ubuntu/cohort-rank/rank_cohort.py")),
        "s3_bodies": str(S3P),
        "s3_body_note": ("archived SETTLED copies: meta carries complete=true and a "
                         "prediction_sha256 that matches the body on disk"),
        "scope_rule": ("no Jev-family or System One board model in the cohort ranking; "
                       "bespoke-nimble-9b is cached here for Task 2 only and is excluded "
                       "from every cohort ranking statement"),
    }
    (ROOT / "extract-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print("wrote", ROOT / "extract-manifest.json")


if __name__ == "__main__":
    main()
