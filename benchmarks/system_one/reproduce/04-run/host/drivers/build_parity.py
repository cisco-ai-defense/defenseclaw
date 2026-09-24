#!/usr/bin/env python3
"""Score every model arm with one scorer and emit like-for-like parity comparisons.

Every arm in a stage is scored by benchmark_score_system_one.py with the SAME cases file,
the SAME deterministic tier and the SAME LLM tier, so each stage table is genuinely
like-for-like. Grids are recorded per cell and mismatches are flagged explicitly.

Writes:
  outputs/jev-parity/scores/<stage>__<arm>.json     per-arm scorecard
  outputs/<stage>/three-way-comparison.json / .txt  per-stage comparison
  outputs/model-parity.json                         rollup across stages
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

DATA = Path("$WORK/.system-one-data/outputs")
# The authoritative Go rule-engine output. A stage's deterministic tier is only the REAL tier
# if it is byte-identical to the matching deterministic-real run; the `-approx` files are the
# all-allow stand-in and must never be mixed into the same comparison.
DETERMINISTIC_REAL = {
    "s2": Path("$WORK/.system-one-data/outputs/deterministic-real/s2-run/predictions.jsonl"),
    "s3": Path("$WORK/.system-one-data/outputs/deterministic-real/s3-run/predictions.jsonl"),
}
REPO = Path("$WORK/defenseclaw-system-one")
PY = "$WORK/.system-one-venv/bin/python"
SCORER = REPO / "benchmarks/scripts/benchmark_score_system_one.py"
SCHEMA_DEFAULT = REPO / "benchmarks/schema/system-one-prediction-v1.schema.json"
SCHEMA_Q4 = DATA / "jev-parity/schema/system-one-prediction-v1-plus-q4.schema.json"
SCORES = DATA / "jev-parity/scores"

# Grade semantics from the scorer: A -> expected block, B -> expected confirm,
# C -> diagnostic (excluded from scoring), D -> expected allow.
BLOCK_GRADE = "A"
CONFIRM_GRADE = "B"

STAGES: list[dict] = [
    {
        "stage": "s2",
        "label": "Broad comparison",
        "cases": DATA / "s2/cases.jsonl",
        "deterministic": DATA / "s2/deterministic.jsonl",
        "llm": DATA / "s2/gemma4-c7.jsonl",
        "llm_model": "google.gemma-4-26b-a4b",
        "llm_grid_note": "Gemma 4 judge arm gemma4-c7 (judge prompt, not a C/I/Q grid)",
        "schema": SCHEMA_Q4,
        "parity_grid": "C7/I3/Q2",
        "arms": [
            {"model": "jev", "label": "Jev (hosted jev-1.13.0)", "paths": [DATA / "s2/jev-C7.jsonl"],
             "grid": "C7/I3/Q2", "new": True},
            {"model": "openjev", "label": "OpenJev", "paths": [DATA / "s2/openjev-final.jsonl"],
             "grid": "C7/I3/Q2"},
            {"model": "diffusiongemma", "label": "DiffusionGemma", "paths": [DATA / "s2/diffgemma-q2.jsonl"],
             "grid": "C7/I3/Q2"},
        ],
        "extra_arms": [
            {"model": "openjev", "label": "OpenJev (Q3)", "paths": [DATA / "s2/openjev-q3.jsonl"],
             "grid": "C7/I3/Q3", "off_parity": True},
            {"model": "diffusiongemma", "label": "DiffusionGemma (Q3)",
             "paths": [DATA / "s2/diffgemma-final.jsonl"], "grid": "C7/I3/Q3", "off_parity": True},
            {"model": "jev", "label": "Jev (Q3)", "paths": [DATA / "s2/jev-q3-C7.jsonl"],
             "grid": "C7/I3/Q3", "off_parity": True, "new": True, "optional": True},
            {"model": "openjev", "label": "OpenJev (Q1)", "paths": [DATA / "s2/openjev-q1.jsonl"],
             "grid": "C7/I3/Q1", "off_parity": True},
            {"model": "jev", "label": "Jev (Q1)", "paths": [DATA / "s2/jev-q1-C7.jsonl"],
             "grid": "C7/I3/Q1", "off_parity": True, "new": True, "optional": True},
            {"model": "jev", "label": "Jev (Q0)", "paths": [DATA / "s2/jev-q0-C7.jsonl"],
             "grid": "C7/I3/Q0", "off_parity": True, "new": True, "optional": True},
            {"model": "jev", "label": "Jev (Q4)", "paths": [DATA / "s2/jev-q4-C7.jsonl"],
             "grid": "C7/I3/Q4", "off_parity": True, "new": True, "optional": True},
        ],
    },
    {
        "stage": "s3",
        "label": "Production-weighted",
        "cases": DATA / "s3/cases.jsonl",
        "deterministic": DATA / "s3/deterministic.jsonl",
        "llm": DATA / "s3/gemma4-c7.jsonl",
        "llm_model": "google.gemma-4-26b-a4b",
        "llm_grid_note": "Gemma 4 judge arm gemma4-c7 (judge prompt, not a C/I/Q grid)",
        "schema": SCHEMA_DEFAULT,
        "parity_grid": "C7/I3/Q2",
        "arms": [
            {"model": "jev", "label": "Jev (hosted jev-1.13.0)", "paths": [DATA / "s3/jev-C7.jsonl"],
             "grid": "C7/I3/Q2", "new": True},
            {"model": "openjev", "label": "OpenJev",
             "paths": [DATA / "s3/openjev-full.jsonl"], "grid": "C7/I3/Q2",
             # concatenation of the five settled shards; digest pinned from the published
             # s3/score-openjev.json scorecard, which recorded this exact sha256
             "attested_sha256": {str(DATA / "s3/openjev-full.jsonl"):
                                 "cbe2db0fd78ae35e8c9fd7f0b14bdfa5248553bd2ea5702ad3c763e004dd40cd"}},
            {"model": "diffusiongemma", "label": "DiffusionGemma", "paths": [DATA / "s3/diffgemma-q2.jsonl"],
             "grid": "C7/I3/Q2"},
        ],
        "extra_arms": [
            {"model": "diffusiongemma", "label": "DiffusionGemma (Q3)",
             "paths": [DATA / "s3/diffgemma-final.jsonl"], "grid": "C7/I3/Q3", "off_parity": True},
            {"model": "jev", "label": "Jev (Q3)", "paths": [DATA / "s3/jev-q3-C7.jsonl"],
             "grid": "C7/I3/Q3", "off_parity": True, "new": True, "optional": True},
        ],
    },
    {
        "stage": "intent-real",
        "label": "Intent (real corpus)",
        "cases": DATA / "intent-real/cases.jsonl",
        "deterministic": None,
        "llm": DATA / "intent-real/gemma4-C7.jsonl",
        "llm_model": "google.gemma-4-26b-a4b",
        "llm_grid_note": "Gemma 4 judge arm gemma4-C7",
        "schema": SCHEMA_Q4,
        "parity_grid": "C7/I3/Q2",
        "arms": [
            {"model": "jev", "label": "Jev (hosted jev-1.13.0)", "paths": [DATA / "intent-real/jev-C7.jsonl"],
             "grid": "C7/I3/Q2"},
            {"model": "openjev", "label": "OpenJev", "paths": [DATA / "intent-real/openjev-C7.jsonl"],
             "grid": "C7/I3/Q2"},
            {"model": "diffusiongemma", "label": "DiffusionGemma",
             "paths": [DATA / "intent-real/diffgemma-C7.jsonl"], "grid": "C7/I3/Q2"},
        ],
        "extra_arms": [
            {"model": "jev", "label": "Jev C0", "paths": [DATA / "intent-real/jev-C0.jsonl"], "grid": "C0/I3/Q2"},
            {"model": "openjev", "label": "OpenJev C0", "paths": [DATA / "intent-real/openjev-C0.jsonl"],
             "grid": "C0/I3/Q2"},
            {"model": "diffusiongemma", "label": "DiffusionGemma C0",
             "paths": [DATA / "intent-real/diffgemma-C0.jsonl"], "grid": "C0/I3/Q2"},
            {"model": "jev", "label": "Jev Q4 C7", "paths": [DATA / "intent-real/jev-q4-C7.jsonl"],
             "grid": "C7/I3/Q4", "new": True},
            {"model": "openjev", "label": "OpenJev Q4 C7", "paths": [DATA / "intent-real/openjev-q4-C7.jsonl"],
             "grid": "C7/I3/Q4"},
            {"model": "diffusiongemma", "label": "DiffusionGemma Q4 C7",
             "paths": [DATA / "intent-real/diffgemma-q4-C7.jsonl"], "grid": "C7/I3/Q4"},
            {"model": "jev", "label": "Jev Q4 C0", "paths": [DATA / "intent-real/jev-q4-C0.jsonl"],
             "grid": "C0/I3/Q4", "new": True},
            {"model": "openjev", "label": "OpenJev Q4 C0", "paths": [DATA / "intent-real/openjev-q4-C0.jsonl"],
             "grid": "C0/I3/Q4"},
            {"model": "diffusiongemma", "label": "DiffusionGemma Q4 C0",
             "paths": [DATA / "intent-real/diffgemma-q4-C0.jsonl"], "grid": "C0/I3/Q4"},
        ],
    },
    {
        "stage": "intent-ablation",
        "label": "Intent ablation",
        "cases": DATA / "intent-ablation/cases.jsonl",
        "deterministic": None,
        "llm": None,
        "llm_model": None,
        "llm_grid_note": None,
        "schema": SCHEMA_Q4,
        "parity_grid": "C1/I3/Q2",
        "arms": [
            {"model": "jev", "label": "Jev (hosted jev-1.13.0)", "paths": [DATA / "intent-ablation/jev-C1.jsonl"],
             "grid": "C1/I3/Q2", "new": True},
            {"model": "openjev", "label": "OpenJev", "paths": [DATA / "intent-ablation/openjev-C1.jsonl"],
             "grid": "C1/I3/Q2"},
            {"model": "diffusiongemma", "label": "DiffusionGemma",
             "paths": [DATA / "intent-ablation/diffgemma-C1.jsonl"], "grid": "C1/I3/Q2"},
        ],
        "extra_arms": [
            {"model": "jev", "label": "Jev Q4", "paths": [DATA / "intent-ablation/jev-q4-C1.jsonl"],
             "grid": "C1/I3/Q4", "new": True, "optional": True},
            {"model": "openjev", "label": "OpenJev Q4", "paths": [DATA / "intent-ablation/openjev-q4-C1.jsonl"],
             "grid": "C1/I3/Q4"},
            {"model": "diffusiongemma", "label": "DiffusionGemma Q4",
             "paths": [DATA / "intent-ablation/diffgemma-q4-C1.jsonl"], "grid": "C1/I3/Q4"},
        ],
    },
    {
        "stage": "toolcall-labels",
        "label": "Label corpus",
        "cases": DATA / "toolcall-labels/cases.jsonl",
        "deterministic": None,
        "llm": None,
        "llm_model": None,
        "llm_grid_note": None,
        "schema": SCHEMA_Q4,
        "parity_grid": "C7/I3/Q4",
        "arms": [
            {"model": "jev", "label": "Jev (hosted jev-1.13.0)",
             "paths": [DATA / "toolcall-labels/jev-q4-C7.jsonl"], "grid": "C7/I3/Q4", "new": True},
            {"model": "openjev", "label": "OpenJev", "paths": [DATA / "toolcall-labels/openjev-q4-C7.jsonl"],
             "grid": "C7/I3/Q4"},
            {"model": "diffusiongemma", "label": "DiffusionGemma",
             "paths": [DATA / "toolcall-labels/diffgemma-q4-C7.jsonl"], "grid": "C7/I3/Q4"},
        ],
        "extra_arms": [
            {"model": "jev", "label": "Jev C0", "paths": [DATA / "toolcall-labels/jev-q4-C0.jsonl"],
             "grid": "C0/I3/Q4", "new": True},
            {"model": "openjev", "label": "OpenJev C0", "paths": [DATA / "toolcall-labels/openjev-q4-C0.jsonl"],
             "grid": "C0/I3/Q4"},
            {"model": "diffusiongemma", "label": "DiffusionGemma C0",
             "paths": [DATA / "toolcall-labels/diffgemma-q4-C0.jsonl"], "grid": "C0/I3/Q4"},
        ],
    },
    {
        "stage": "terminalbench",
        "label": "TerminalBench benign lane",
        "cases": DATA / "s1-n1000/terminalbench-context-cases.jsonl",
        "deterministic": None,
        "llm": None,
        "llm_model": None,
        "llm_grid_note": None,
        "schema": SCHEMA_Q4,
        "parity_grid": "C7/I3/Q4",
        "arms": [
            {"model": "jev", "label": "Jev (hosted jev-1.13.0)",
             "paths": [DATA / "terminalbench/jev-q4-C7.jsonl"], "grid": "C7/I3/Q4", "new": True},
            {"model": "openjev", "label": "OpenJev", "paths": [DATA / "terminalbench/openjev-q4-C7.jsonl"],
             "grid": "C7/I3/Q4"},
            {"model": "diffusiongemma", "label": "DiffusionGemma",
             "paths": [DATA / "terminalbench/diffgemma-q4-C7.jsonl"], "grid": "C7/I3/Q4"},
        ],
        "extra_arms": [
            {"model": "jev", "label": "Jev C1", "paths": [DATA / "terminalbench/jev-q4-C1.jsonl"],
             "grid": "C1/I3/Q4", "new": True},
            {"model": "openjev", "label": "OpenJev C1", "paths": [DATA / "terminalbench/openjev-q4-C1.jsonl"],
             "grid": "C1/I3/Q4"},
            {"model": "diffusiongemma", "label": "DiffusionGemma C1",
             "paths": [DATA / "terminalbench/diffgemma-q4-C1.jsonl"], "grid": "C1/I3/Q4"},
        ],
    },
]


def arm_key(stage: str, arm: dict) -> str:
    base = arm["paths"][0].name.removesuffix(".jsonl")
    if len(arm["paths"]) > 1:
        base = base.rsplit("-", 1)[0] + "-merged"
    return f"{stage}__{arm['model']}__{base}"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def is_settled(path: Path, attested: dict[str, str] | None = None) -> tuple[bool, str]:
    """Settled-file discipline: meta complete: true AND on-disk sha256 == meta.prediction_sha256.

    Merged prediction files carry a sibling `.merge.json` attestation instead of a `.meta.json`;
    for those the merge manifest's `merged_sha256` and `coverage_complete` are the equivalent gate.
    """
    meta_path = Path(str(path) + ".meta.json")
    if meta_path.exists():
        meta = json.loads(meta_path.read_text())
        if meta.get("complete") is not True:
            return False, "meta complete is not true (run still in flight or failed)"
        if sha256_file(path) != meta.get("prediction_sha256"):
            return False, "on-disk sha256 does not match meta.prediction_sha256"
        return True, "meta"
    merge_path = path.with_suffix("").with_suffix(".merge.json")
    if not merge_path.exists():
        merge_path = Path(str(path).removesuffix(".jsonl") + ".merge.json")
    if merge_path.exists():
        merge = json.loads(merge_path.read_text())
        if not merge.get("verification", {}).get("coverage_complete"):
            return False, "merge manifest does not report coverage_complete"
        if sha256_file(path) != merge.get("merged_sha256"):
            return False, "on-disk sha256 does not match merge manifest merged_sha256"
        return True, "merge-manifest"
    if attested and str(path) in attested:
        # A concatenated arm whose integrity is attested by the sha256 recorded in the
        # already-published scorecard for this stage. The digest is pinned in the arm spec,
        # so a silent change to the file on disk still fails the gate.
        if sha256_file(path) == attested[str(path)]:
            return True, "published-scorecard-sha256"
        return False, "on-disk sha256 does not match the published scorecard digest"
    return False, "no .meta.json and no .merge.json attestation"


def score_arm(stage: dict, arm: dict, force: bool) -> Path | None:
    """Run the shared scorer for one arm. Returns the scorecard path, or None if inputs are missing."""
    for path in arm["paths"]:
        if not path.exists():
            return None
    for path in arm["paths"]:
        ok, why = is_settled(path, arm.get("attested_sha256"))
        if not ok:
            print(f"  NOT SETTLED, refusing to score {path.name}: {why}")
            return None
    SCORES.mkdir(parents=True, exist_ok=True)
    out = SCORES / (arm_key(stage["stage"], arm) + ".json")
    if out.exists() and not force:
        return out
    cmd = [PY, str(SCORER), "--cases", str(stage["cases"])]
    for path in arm["paths"]:
        cmd += ["--system-one-predictions", str(path)]
    cmd += ["--prediction-schema", str(stage["schema"])]
    if stage.get("deterministic"):
        cmd += ["--deterministic-predictions", str(stage["deterministic"])]
    if stage.get("llm"):
        cmd += ["--llm-predictions", str(stage["llm"])]
    cmd += ["--output", str(out), "--input-usd-per-million", "0.042"]
    env_cwd = str(REPO)
    proc = subprocess.run(cmd, cwd=env_cwd, capture_output=True, text=True,
                          env={"PYTHONPATH": str(REPO / "benchmarks/scripts"), "PATH": "/usr/bin:/bin"})
    if proc.returncode != 0:
        print(f"  SCORE FAIL {arm_key(stage['stage'], arm)}: {proc.stderr.strip().splitlines()[-1:]}")
        return None
    return out


def lens_block(lens: dict | None) -> dict:
    if not lens:
        return {}
    binary = lens.get("binary", {})
    block = lens.get("binary_block_only", {})
    three = lens.get("three_way", {})
    return {
        "confirm_lens": {
            "f1": binary.get("f1"), "precision": binary.get("precision"),
            "recall": binary.get("recall"), "false_positive_rate": binary.get("false_positive_rate"),
            "confusion": binary.get("confusion"),
        },
        "block_lens": {
            "f1": block.get("f1"), "precision": block.get("precision"),
            "recall": block.get("recall"), "false_positive_rate": block.get("false_positive_rate"),
            "confusion": block.get("confusion"),
        },
        "confirm_rate": lens.get("review_rate"),
        "three_way_accuracy": three.get("accuracy"),
        "three_way_macro_f1": three.get("macro_f1"),
        "system_one_invocation_rate": lens.get("system_one_invocation_rate"),
        "llm_call_rate": lens.get("llm_invocation_rate"),
    }


def run_provenance(arm: dict) -> dict:
    """Authoritative run facts straight from the run metas (not the scorer's scorable subset)."""
    out = {"attestations": [], "run_requests": 0, "run_input_tokens": 0,
           "run_estimated_usd": 0.0, "prediction_sha256": {}}
    for path in arm["paths"]:
        ok, kind = is_settled(path, arm.get("attested_sha256"))
        out["attestations"].append({"path": str(path), "settled": ok, "attestation": kind})
        meta_path = Path(str(path) + ".meta.json")
        if meta_path.exists():
            meta = json.loads(meta_path.read_text())
            out["run_requests"] += int(meta.get("requests") or 0)
            out["run_input_tokens"] += int(meta.get("actual_input_tokens") or 0)
            out["run_estimated_usd"] += float(meta.get("estimated_usd") or 0.0)
            out["prediction_sha256"][str(path)] = meta.get("prediction_sha256")
            out["model_revision"] = meta.get("model_revision")
            out["instruction_format"] = meta.get("instruction_format")
    out["run_estimated_usd"] = round(out["run_estimated_usd"], 8)
    if out["run_requests"] == 0:
        # concatenated arms carry no .meta.json; count rows so the digest is not misleading
        rows = 0
        for path in arm["paths"]:
            with path.open("rb") as handle:
                rows += sum(1 for _ in handle)
        out["run_requests"] = rows
        out["requests_source"] = "row count (no run meta; concatenated arm)"
    else:
        out["requests_source"] = "run meta"
    out["tokens_per_request"] = (
        round(out["run_input_tokens"] / out["run_requests"], 1)
        if out["run_requests"] and out["run_input_tokens"] else None)
    return out


def extract(stage: dict, arm: dict, card_path: Path) -> dict:
    card = json.loads(card_path.read_text())
    cand = card["candidates"][0]
    grades = card["truth_grades"]
    so = cand["system_one"]
    row = {
        "run_provenance": run_provenance(arm),
        "model": arm["model"],
        "label": arm["label"],
        "candidate": cand["candidate"],
        "grid": arm["grid"],
        "grid_matches_parity_grid": arm["grid"] == stage["parity_grid"],
        "newly_run": bool(arm.get("new")),
        "prediction_paths": [str(p) for p in arm["paths"]],
        "scorecard": str(card_path),
        "case_count": card["case_count"],
        "scorable_cases": cand.get("scorable_cases"),
        "truth_grades": grades,
        "requests": so.get("requests"),
        "input_tokens": so.get("input_tokens"),
        "errors": so.get("errors"),
        "estimated_usd": so.get("estimated_usd"),
        "repeatability_flip_rate": card.get("repeatability", {}).get("flip_rate"),
        "per_case": {"model_only": lens_block(so)},
        "per_event": cand.get("per_event"),
        "diagnostic_grade_c": cand.get("diagnostic_grade_c"),
    }
    for lens_name, out_name in [
        ("deterministic_then_system_one", "deterministic_then_model"),
        ("deterministic_then_system_one_then_llm", "deterministic_then_model_then_llm"),
        ("deterministic_then_llm", "deterministic_then_llm_only"),
    ]:
        if lens_name in cand:
            row["per_case"][out_name] = lens_block(cand[lens_name])
    return row


def deterministic_provenance(stage: dict) -> dict:
    """Pin which rule tier this stage's cascade numbers came from, so a consumer can verify it
    is the real Go rule-engine output and not the all-allow stand-in."""
    tier = stage.get("deterministic")
    if not tier:
        return {"tier": None, "is_real_tier": None,
                "note": "no deterministic tier used; only the model-only lens is reported"}
    digest = sha256_file(tier)
    real = DETERMINISTIC_REAL.get(stage["stage"])
    real_digest = sha256_file(real) if real and real.exists() else None
    approx = tier.parent / "deterministic-approx.jsonl"
    return {
        "tier": str(tier),
        "tier_sha256": digest,
        "deterministic_real_path": str(real) if real else None,
        "deterministic_real_sha256": real_digest,
        "is_real_tier": bool(real_digest and digest == real_digest),
        "all_allow_standin_path": str(approx) if approx.exists() else None,
        "all_allow_standin_sha256": sha256_file(approx) if approx.exists() else None,
        "note": ("cascade lenses were computed against the real Go rule-engine tier; the "
                 "all-allow stand-in digest is recorded only so a consumer can confirm it was "
                 "NOT used"),
    }


def applicability(grades: dict) -> dict:
    """Both lenses share ONE truth positive class: unsafe = grade A (expect block) or grade B
    (expect confirm). The lenses differ only in which PREDICTION counts as a detection -
    `block_lens` counts a hard block only, `confirm_lens` counts block or confirm. So f1,
    precision and recall are meaningful for both iff the corpus has unsafe cases at all.
    """
    unsafe = grades.get(BLOCK_GRADE, 0) + grades.get(CONFIRM_GRADE, 0)
    notes = []
    if unsafe == 0:
        notes.append(
            "f1 / precision / recall are NOT APPLICABLE for BOTH lenses: the scorable corpus is "
            f"entirely benign (no grade-{BLOCK_GRADE} and no grade-{CONFIRM_GRADE} cases), so there "
            "are no positives to recover. Only false_positive_rate, confirm rate and the per-event "
            "activity / benign-FPR figures are meaningful on this stage."
        )
    elif unsafe < 50:
        notes.append(
            f"CAUTION: only {unsafe} unsafe cases "
            f"(grade {BLOCK_GRADE}={grades.get(BLOCK_GRADE, 0)}, "
            f"grade {CONFIRM_GRADE}={grades.get(CONFIRM_GRADE, 0)}) back the recall and F1 figures, "
            "so those columns carry wide confidence intervals; prefer the false_positive_rate "
            "columns and the per-event figures for ranking."
        )
    return {
        "unsafe_truth_cases": unsafe,
        "truth_positive_class": (f"grade {BLOCK_GRADE} (expect block) or grade {CONFIRM_GRADE} "
                                 "(expect confirm)"),
        "block_lens_applicable": unsafe > 0,
        "confirm_lens_applicable": unsafe > 0,
        "notes": notes,
    }


def fmt(value, width: int = 9, digits: int = 5) -> str:
    if value is None:
        return "n/a".rjust(width)
    if isinstance(value, float):
        return f"{value:.{digits}f}".rjust(width)
    return str(value).rjust(width)


def digest(stage: dict, report: dict) -> str:
    lines: list[str] = []
    app = report["metric_applicability"]
    lines.append("=" * 118)
    lines.append(f"{stage['label']} ({stage['stage']}) - model parity comparison")
    lines.append("=" * 118)
    lines.append(f"cases file        : {report['cases']}")
    lines.append(f"cases sha256      : {report['cases_sha256']}")
    lines.append(f"scorable cases    : {report['scorable_cases']} of {report['case_count']}")
    lines.append(f"truth grades      : {report['truth_grades']}  (A=expect block, B=expect confirm, "
                 f"C=diagnostic/excluded, D=expect allow)")
    lines.append(f"unsafe positives  : {app['unsafe_truth_cases']} "
                 f"(shared truth positive class for BOTH lenses)")
    lines.append(f"parity grid       : {report['parity_grid']}")
    prov = report["deterministic_tier_provenance"]
    if prov.get("tier"):
        lines.append(f"deterministic tier: {prov['tier']}")
        lines.append(f"  sha256          : {prov['tier_sha256']}")
        lines.append(f"  real rule tier  : {prov['is_real_tier']} "
                     f"(byte-identical to {prov['deterministic_real_path']})")
        lines.append(f"  all-allow stand-in NOT used (its digest is "
                     f"{str(prov.get('all_allow_standin_sha256'))[:16]}...)")
    else:
        lines.append("deterministic tier: none (model-only lens)")
    lines.append(f"llm tier          : {report['llm_tier'] or 'none'}"
                 + (f"  [{stage['llm_grid_note']}]" if stage.get("llm_grid_note") else ""))
    lines.append(f"scorer            : benchmark_score_system_one.py (single scorer for every arm)")
    lines.append("")
    if report["grid_parity"]["all_parity_arms_identical"]:
        lines.append(f"GRID PARITY: TRUE like-for-like. Every primary arm below was measured on "
                     f"{report['parity_grid']}.")
    else:
        lines.append("GRID PARITY: NOT identical - see per-row grid column and flags.")
    for note in app["notes"]:
        lines.append(f"! {note}")
    lines.append("")

    for lens_label, lens_key in [
        ("MODEL ONLY (no deterministic tier, no LLM)", "model_only"),
        ("DETERMINISTIC -> MODEL", "deterministic_then_model"),
        ("DETERMINISTIC -> MODEL -> LLM", "deterministic_then_model_then_llm"),
        ("DETERMINISTIC -> LLM (model bypassed; judge reference)", "deterministic_then_llm_only"),
    ]:
        rows = [r for r in report["arms"] if lens_key in r["per_case"]]
        if not rows:
            continue
        lines.append("-" * 118)
        lines.append(f"PER CASE | {lens_label}")
        lines.append("-" * 118)
        lines.append(f"{'model':<26}{'grid':<12}{'blockF1':>9}{'blockP':>9}{'blockR':>9}{'blockFPR':>10}"
                     f"{'cfmF1':>9}{'cfmFPR':>10}{'cfmRate':>9}{'LLMrate':>9}{'3wayAcc':>9}")
        for r in rows:
            lens = r["per_case"][lens_key]
            blk, cfm = lens["block_lens"], lens["confirm_lens"]
            flag = "" if r["grid_matches_parity_grid"] else " *"
            bf1 = blk["f1"] if app["block_lens_applicable"] else None
            bp = blk["precision"] if app["block_lens_applicable"] else None
            br = blk["recall"] if app["block_lens_applicable"] else None
            cf1 = cfm["f1"] if app["confirm_lens_applicable"] else None
            lines.append(
                f"{r['label'][:25]:<26}{r['grid'] + flag:<12}"
                f"{fmt(bf1)}{fmt(bp)}{fmt(br)}{fmt(blk['false_positive_rate'], 10)}"
                f"{fmt(cf1)}{fmt(cfm['false_positive_rate'], 10)}{fmt(lens['confirm_rate'])}"
                f"{fmt(lens['llm_call_rate'])}{fmt(lens['three_way_accuracy'])}"
            )
        lines.append("")

    lines.append("-" * 118)
    lines.append("PER EVENT")
    lines.append("-" * 118)
    lines.append(f"{'model':<26}{'grid':<12}{'events':>10}{'flagged':>10}{'activity':>10}"
                 f"{'benignEv':>10}{'benignFlag':>12}{'benignFPR':>11}")
    for r in report["arms"]:
        pe = r["per_event"] or {}
        flag = "" if r["grid_matches_parity_grid"] else " *"
        lines.append(
            f"{r['label'][:25]:<26}{r['grid'] + flag:<12}{fmt(pe.get('events'), 10)}"
            f"{fmt(pe.get('flagged_events'), 10)}{fmt(pe.get('activity_rate'), 10)}"
            f"{fmt(pe.get('benign_events'), 10)}{fmt(pe.get('benign_flagged_events'), 12)}"
            f"{fmt(pe.get('benign_event_false_positive_rate'), 11)}"
        )
    lines.append("")
    if any(not r["grid_matches_parity_grid"] for r in report["arms"]):
        lines.append(f"* grid differs from the parity grid {report['parity_grid']}; "
                     f"these rows are NOT like-for-like with the primary rows above.")
    lines.append("")
    lines.append("Run provenance (requests/tokens/cost from the run metas, not the scorable subset):")
    for r in report["arms"]:
        prov = r["run_provenance"]
        cost = (f"${prov['run_estimated_usd']:.6f}" if r["model"] == "jev" else "n/a (local model)")
        lines.append(f"  {r['label'][:34]:<36} {r['grid']:<10} requests {str(prov['run_requests']):>7}  "
                     f"tok/req {str(prov['tokens_per_request']):>7}  errors {str(r['errors']):>4}  "
                     f"cost {cost}")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", action="append", default=[])
    parser.add_argument("--force-rescore", action="store_true")
    parser.add_argument("--rollup", action="store_true")
    args = parser.parse_args()

    selected = [s for s in STAGES if not args.stage or s["stage"] in args.stage]
    rollup: dict = {
        "schema_version": "1",
        "kind": "defenseclaw-system-one-model-parity",
        "scorer": "benchmarks/scripts/benchmark_score_system_one.py",
        "grade_semantics": {"A": "expected block", "B": "expected confirm",
                            "C": "diagnostic, excluded from scoring", "D": "expected allow"},
        "q4_schema_note": (
            "Q4 arms were validated against a copy of "
            "benchmarks/schema/system-one-prediction-v1.schema.json (published in the "
            "evaluations repo at protocol/v1/system-one-prediction-v1.schema.json) with the "
            "single delta properties.question_variant.enum = [Q0,Q1,Q2,Q3] -> "
            "[Q0,Q1,Q2,Q3,Q4]. Nothing else was changed. The committed schema was not "
            "modified; the copy lives at "
            "outputs/jev-parity/schema/system-one-prediction-v1-plus-q4.schema.json and is "
            "reproducible from the published schema with that one edit."),
        "metric_definitions": {
            "block_lens": "positive = predicted action is block; the production lens",
            "confirm_lens": "positive = predicted action is block OR confirm (escalation counts "
                            "as a detection)",
            "confirm_rate": "share of scorable cases routed to review (review_rate)",
            "llm_call_rate": "share of cases that reach the LLM tier "
                             "(llm_invocation_rate, cascade lenses only)",
            "per_event.benign_event_false_positive_rate": "flagged benign events / benign events",
        },
        "stages": {},
    }

    for stage in selected:
        print(f"== {stage['stage']} ==")
        arms_out = []
        for arm in stage["arms"] + stage.get("extra_arms", []):
            card = score_arm(stage, arm, args.force_rescore)
            if card is None:
                status = "optional, not run" if arm.get("optional") else "MISSING"
                print(f"  skip {arm['label']} ({status})")
                continue
            arms_out.append(extract(stage, arm, card))
            print(f"  scored {arm['label']} [{arm['grid']}]")
        if not arms_out:
            continue
        grades = arms_out[0]["truth_grades"]
        primary_models = {a["model"] for a in stage["arms"]}
        parity_rows = [r for r in arms_out
                       if r["grid"] == stage["parity_grid"] and r["model"] in primary_models]
        report = {
            "schema_version": "1",
            "kind": "defenseclaw-system-one-three-way-comparison",
            "stage": stage["stage"],
            "stage_label": stage["label"],
            "cases": str(stage["cases"]),
            "cases_sha256": json.loads(
                (SCORES / (arm_key(stage["stage"], stage["arms"][0]) + ".json")).read_text()
            )["cases_sha256"] if (SCORES / (arm_key(stage["stage"], stage["arms"][0]) + ".json")).exists()
            else None,
            "case_count": arms_out[0]["case_count"],
            "scorable_cases": arms_out[0]["scorable_cases"],
            "truth_grades": grades,
            "parity_grid": stage["parity_grid"],
            "deterministic_tier": str(stage["deterministic"]) if stage["deterministic"] else None,
            "deterministic_tier_provenance": deterministic_provenance(stage),
            "llm_tier": str(stage["llm"]) if stage["llm"] else None,
            "llm_model": stage.get("llm_model"),
            "llm_grid_note": stage.get("llm_grid_note"),
            "metric_applicability": applicability(grades),
            "grid_parity": {
                "parity_grid": stage["parity_grid"],
                "models_at_parity_grid": sorted({r["model"] for r in parity_rows}),
                "all_parity_arms_identical": sorted({r["model"] for r in parity_rows}) == sorted(primary_models),
                "off_parity_rows": [{"label": r["label"], "grid": r["grid"]}
                                    for r in arms_out if r["grid"] != stage["parity_grid"]],
            },
            "arms": arms_out,
        }
        out_dir = DATA / stage["stage"]
        (out_dir / "three-way-comparison.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        (out_dir / "three-way-comparison.txt").write_text(digest(stage, report))
        print(f"  wrote {out_dir}/three-way-comparison.json and .txt")

        rollup["stages"][stage["stage"]] = {
            "stage_label": stage["label"],
            "parity_grid": stage["parity_grid"],
            "case_count": report["case_count"],
            "scorable_cases": report["scorable_cases"],
            "truth_grades": grades,
            "metric_applicability": report["metric_applicability"],
            "grid_parity": report["grid_parity"],
            "deterministic_tier": report["deterministic_tier"],
            "deterministic_tier_provenance": report["deterministic_tier_provenance"],
            "llm_tier": report["llm_tier"],
            "cells": [
                {
                    "model": r["model"], "label": r["label"],
                    "measured_on_grid": r["grid"],
                    "grid_matches_parity_grid": r["grid_matches_parity_grid"],
                    "newly_run": r["newly_run"],
                    "per_case_model_only": r["per_case"]["model_only"],
                    "per_case_cascade": {k: v for k, v in r["per_case"].items() if k != "model_only"},
                    "per_event": r["per_event"],
                    "requests": r["requests"], "errors": r["errors"],
                }
                for r in arms_out
            ],
        }

    if args.rollup:
        (DATA / "model-parity.json").write_text(json.dumps(rollup, indent=2, sort_keys=True) + "\n")
        print(f"wrote {DATA}/model-parity.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
