#!/usr/bin/env python3
"""Write realdet-<stage>-jev.json scorecards from predictions already on disk.

NO new inference: s2/jev-C7.jsonl (30,310 requests) and s3/jev-C7.jsonl (100,001 requests)
are already complete and settled. This only re-scores them.

Correctness requirement handled explicitly:
  * the deterministic tier passed to the scorer is the real Go rule-engine output at
    outputs/deterministic-real/<stage>-run/predictions.jsonl, referenced by that path
    directly (not via the outputs/<stage>/deterministic.jsonl alias),
  * its sha256 is recorded, and asserted DIFFERENT from the all-allow stand-in
    outputs/<stage>/deterministic-approx.jsonl,
  * the invocation is first validated by reproducing the existing realdet-<stage>-openjev.json
    lenses that the scorer change does not touch; any mismatch aborts.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

DATA = Path("$WORK/.system-one-data/outputs")
REPO = Path("$WORK/defenseclaw-system-one")
PY = "$WORK/.system-one-venv/bin/python"
SCORER = REPO / "benchmarks/scripts/benchmark_score_system_one.py"
REALDET = DATA / "deterministic-real"

STAGES = {
    "s2": {
        "cases": DATA / "s2/cases.jsonl",
        "det": REALDET / "s2-run/predictions.jsonl",
        "approx": DATA / "s2/deterministic-approx.jsonl",
        "llm": DATA / "s2/gemma4-c7.jsonl",
        "jev": DATA / "s2/jev-C7.jsonl",
        "extra_jev": [("q0", DATA / "s2/jev-q0-C7.jsonl"),
                      ("q1", DATA / "s2/jev-q1-C7.jsonl"),
                      ("q3", DATA / "s2/jev-q3-C7.jsonl"),
                      ("q4", DATA / "s2/jev-q4-C7.jsonl")],
        "openjev": DATA / "s2/openjev-final.jsonl",
        "reference": REALDET / "realdet-s2-openjev.json",
    },
    "s3": {
        "cases": DATA / "s3/cases.jsonl",
        "det": REALDET / "s3-run/predictions.jsonl",
        "approx": DATA / "s3/deterministic-approx.jsonl",
        "llm": DATA / "s3/gemma4-c7.jsonl",
        "jev": DATA / "s3/jev-C7.jsonl",
        "extra_jev": [("q3", DATA / "s3/jev-q3-C7.jsonl")],
        "openjev": DATA / "s3/openjev-full.jsonl",
        "reference": REALDET / "realdet-s3-openjev.json",
    },
}

# The seven cascade policy rows the Space consumes.
POLICY_ROWS = [
    "deterministic_then_llm",
    "deterministic_then_system_one",
    "deterministic_then_system_one_then_llm",
    "deterministic_then_system_one_then_llm_two_sided_0.05",
    "deterministic_then_system_one_then_llm_two_sided_0.10",
    "deterministic_then_system_one_then_llm_two_sided_0.20",
    "deterministic_then_system_one_then_llm_two_sided_0.30",
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def settled(pred: Path) -> dict:
    meta_path = Path(str(pred) + ".meta.json")
    if not meta_path.exists():
        raise RuntimeError(f"{pred}: no meta")
    meta = json.loads(meta_path.read_text())
    if meta.get("complete") is not True:
        raise RuntimeError(f"{pred}: meta complete is not true")
    digest = sha256_file(pred)
    if digest != meta.get("prediction_sha256"):
        raise RuntimeError(f"{pred}: on-disk sha256 {digest} != meta {meta.get('prediction_sha256')}")
    return meta


SCHEMA_Q4 = DATA / "jev-parity/schema/system-one-prediction-v1-plus-q4.schema.json"


def score(cases: Path, preds: Path, det: Path, llm: Path, out: Path) -> None:
    cmd = [PY, str(SCORER), "--cases", str(cases),
           "--system-one-predictions", str(preds),
           "--deterministic-predictions", str(det),
           "--llm-predictions", str(llm),
           "--prediction-schema", str(SCHEMA_Q4),
           "--output", str(out),
           "--input-usd-per-million", "0.042"]
    proc = subprocess.run(cmd, cwd=str(REPO), capture_output=True, text=True,
                          env={"PYTHONPATH": str(REPO / "benchmarks/scripts"),
                               "PATH": "/usr/bin:/bin"})
    if proc.returncode != 0:
        raise RuntimeError(f"scorer failed for {preds.name}: "
                           f"{proc.stderr.strip().splitlines()[-3:]}")


def main() -> int:
    provenance = {"kind": "defenseclaw-system-one-realdet-jev-provenance", "schema_version": "1",
                  "new_inference_required": False,
                  "note": "produced by re-scoring predictions already on disk; no provider calls",
                  "stages": {}}
    for stage, spec in STAGES.items():
        print(f"===== {stage} =====")
        if not spec["jev"].exists():
            print(f"  SKIP: {spec['jev']} does not exist yet")
            continue
        jev_meta = settled(spec["jev"])
        print(f"  jev predictions settled: {spec['jev'].name} "
              f"requests={jev_meta['requests']} sha={jev_meta['prediction_sha256'][:16]}")

        det_sha = sha256_file(spec["det"])
        approx_sha = sha256_file(spec["approx"]) if spec["approx"].exists() else None
        alias = DATA / stage / "deterministic.jsonl"
        alias_sha = sha256_file(alias) if alias.exists() else None
        if approx_sha is not None and det_sha == approx_sha:
            raise RuntimeError(f"{stage}: real tier digest equals the all-allow stand-in; aborting")
        print(f"  real deterministic tier : {spec['det']}")
        print(f"    sha256               : {det_sha}")
        print(f"    all-allow stand-in   : {approx_sha} (DIFFERENT -> not used)")
        print(f"    outputs/{stage}/deterministic.jsonl sha256: {alias_sha} "
              f"({'same file' if alias_sha == det_sha else 'DIFFERENT'})")

        # validate the invocation against the published OpenJev realdet scorecard
        ref = json.loads(spec["reference"].read_text())
        repro = REALDET / f"repro-check-{stage}-openjev.json"
        score(spec["cases"], spec["openjev"], spec["det"], spec["llm"], repro)
        mine = json.loads(repro.read_text())
        ref_cand, my_cand = ref["candidates"][0], mine["candidates"][0]
        checks = {}
        for lens in ("system_one", "deterministic_then_llm", "deterministic_then_system_one"):
            checks[lens] = ref_cand.get(lens) == my_cand.get(lens)
        changed = {lens: (ref_cand.get(lens, {}).get("binary_block_only", {}).get("f1"),
                          my_cand.get(lens, {}).get("binary_block_only", {}).get("f1"))
                   for lens in POLICY_ROWS if not ref_cand.get(lens) == my_cand.get(lens)}
        print(f"  invocation validation vs {spec['reference'].name}:")
        for lens, ok in checks.items():
            print(f"    {lens:<38} {'MATCH' if ok else 'DIFFERS'}")
        if not all(checks.values()):
            raise RuntimeError(f"{stage}: invocation does not reproduce the published OpenJev "
                               f"realdet scorecard on the lenses the scorer change does not touch; "
                               f"aborting rather than writing a mislabelled file")
        print(f"    lenses changed by today's scorer fix (expected): {sorted(changed)}")

        out = REALDET / f"realdet-{stage}-jev.json"
        score(spec["cases"], spec["jev"], spec["det"], spec["llm"], out)
        card = json.loads(out.read_text())
        cand = card["candidates"][0]
        present = [row for row in POLICY_ROWS if row in cand]
        print(f"  wrote {out.name}: candidate {cand['candidate']}, "
              f"{len(present)}/{len(POLICY_ROWS)} policy rows present")
        missing = [row for row in POLICY_ROWS if row not in cand]
        if missing:
            raise RuntimeError(f"{stage}: missing policy rows {missing}")
        for row in POLICY_ROWS:
            lens = cand[row]
            block = lens["binary_block_only"]
            print(f"    {row:<52} blockF1={block['f1']:.5f} "
                  f"blockFPR={block['false_positive_rate']:.5f} "
                  f"confirm={lens.get('review_rate')} llm={lens.get('llm_invocation_rate')}")

        # additional large-stage Jev arms: same free re-scoring, same verified real tier
        for variant, pred in spec.get("extra_jev", []):
            if not pred.exists():
                print(f"  extra arm {variant}: {pred.name} not present, skipping")
                continue
            try:
                extra_meta = settled(pred)
            except RuntimeError as exc:
                print(f"  extra arm {variant}: NOT SETTLED ({exc}); skipping")
                continue
            extra_out = REALDET / f"realdet-{stage}-jev-{variant}.json"
            score(spec["cases"], pred, spec["det"], spec["llm"], extra_out)
            extra_card = json.loads(extra_out.read_text())
            extra_cand = extra_card["candidates"][0]
            extra_missing = [row for row in POLICY_ROWS if row not in extra_cand]
            if extra_missing:
                raise RuntimeError(f"{stage}/{variant}: missing policy rows {extra_missing}")
            print(f"  wrote {extra_out.name}: candidate {extra_cand['candidate']}, "
                  f"7/7 policy rows")
            provenance["stages"].setdefault(f"{stage}-{variant}", {}).update({
                "scorecard": str(extra_out),
                "scorecard_sha256": sha256_file(extra_out),
                "predictions": str(pred),
                "predictions_sha256": extra_meta["prediction_sha256"],
                "predictions_requests": extra_meta["requests"],
                "predictions_meta_complete": True,
                "grid": (f"{extra_meta['contexts'][0]}/{extra_meta['instructions'][0]}"
                         f"/{extra_meta['questions'][0]}"),
                "cases": str(spec["cases"]),
                "cases_sha256": extra_card["cases_sha256"],
                "deterministic_tier": str(spec["det"]),
                "deterministic_tier_sha256": det_sha,
                "deterministic_tier_is_real": True,
                "all_allow_standin_used": False,
                "all_allow_standin_sha256": approx_sha,
                "llm_tier": str(spec["llm"]),
                "invocation_validated_against": str(spec["reference"]),
                "validated_lenses_match": checks,
                "policy_rows": POLICY_ROWS,
                "new_inference_required": False,
            })

        provenance["stages"][stage] = {
            "scorecard": str(out),
            "scorecard_sha256": sha256_file(out),
            "predictions": str(spec["jev"]),
            "predictions_sha256": jev_meta["prediction_sha256"],
            "predictions_requests": jev_meta["requests"],
            "predictions_meta_complete": True,
            "cases": str(spec["cases"]),
            "cases_sha256": card["cases_sha256"],
            "deterministic_tier": str(spec["det"]),
            "deterministic_tier_sha256": det_sha,
            "deterministic_tier_is_real": True,
            "all_allow_standin": str(spec["approx"]),
            "all_allow_standin_sha256": approx_sha,
            "all_allow_standin_used": False,
            "stage_alias_path": str(alias),
            "stage_alias_sha256": alias_sha,
            "stage_alias_identical_to_real_tier": alias_sha == det_sha,
            "llm_tier": str(spec["llm"]),
            "llm_tier_sha256": sha256_file(spec["llm"]),
            "invocation_validated_against": str(spec["reference"]),
            "validated_lenses_match": checks,
            "lenses_changed_by_scorer_fix": sorted(changed),
            "policy_rows": POLICY_ROWS,
            "new_inference_required": False,
        }
        repro.unlink()

    out = REALDET / "realdet-jev-provenance.json"
    out.write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
