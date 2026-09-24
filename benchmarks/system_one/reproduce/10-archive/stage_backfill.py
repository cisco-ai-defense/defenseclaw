#!/usr/bin/env python3
"""Backfill the two PRIVATE System One repos with everything written today that is missing.

The two repos were last written at 08:43 today and carry only three arms. Everything below
was produced after that and lives only on individually-losable hosts.

Split follows the convention already in place and is NOT reinvented:
  raw predictions + run metas/plans/merge manifests
      -> Vineethsain/defenseclaw-system-one-predictions-v1  under predictions/<stage>/
  scorecards, closure/culling ledgers, serving contracts, validation gates, study outputs
      -> Vineethsain/defenseclaw-system-one-evaluations-v1  under stages/<stage>/

`stages/secjudge/` is a stage-level sub-programme directory, matching the existing
`stages/jev-parity/`, `stages/intent-deviation/`, `stages/q4-twolane/` and
`stages/s2-adjudication/` precedent: `stages/` already holds programme names, not only
stage names.

Every settled prediction is settled-checked (meta.complete is true AND the on-disk sha256
equals meta.prediction_sha256). Unsettled material keeps its partial marker in its filename
and is never settled-checked, so nothing can be mistaken for settled.

`private is True` is read before AND after each upload, over every dataset repo in the
namespace, and anything else aborts.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

DATA = Path("$WORK/.system-one-data/outputs")
RESCUE = Path("$WORK/gpu-host-rescue")
KEVX = Path("$WORK/.system-one-backup-work/kevx/kevbench")
STAGE = Path("$WORK/.system-one-backfill-stage")
PRED_STAGE = STAGE / "predictions-add"
EVAL_STAGE = STAGE / "evaluations-add"
PRED_REPO = "Vineethsain/defenseclaw-system-one-predictions-v1"
EVAL_REPO = "Vineethsain/defenseclaw-system-one-evaluations-v1"
PY = "$WORK/.system-one-venv/bin/python"
GUARD = "$WORK/jev_guard.py"
SUFFIX = "gemma4-secjudge-decider-v1"

GEMMA_ARMS = ["gemma-4-26b-a4b-it", "jevify-gemma4-26b-a4b"]

# ---------------------------------------------------------------- deliberate exclusions
EXCLUDED = [
    ("gpu-host-rescue/nvme/s2-requests-all.jsonl",
     "92 MB of rendered request bodies: raw prompts and case text. The programme's data "
     "policy forbids uploading raw prompts or state, and the 08:43 batch excluded the "
     "sample of this same file for that reason (see openjev-qwen/validation/"
     "upload-results.json :: excluded). It is NOT lost: the identical file plus a .gz "
     "copy sit at $WORK/j27/s2-requests-all.jsonl on the dev host's EBS root volume, "
     "which is not the ephemeral instance store the rescue was pulling off."),
    ("openjev-qwen/validation/s2-requests-sample.jsonl",
     "raw request bodies; same data policy, and already excluded by the 08:43 batch"),
    ("openjev-qwen/validation/ojev-test.jsonl.gz",
     "a third-party evaluation corpus projection, not this programme's evidence; already "
     "excluded by the 08:43 batch"),
    ("gpu-host-rescue/nvme/s2-requests-sample.jsonl",
     "raw request bodies; same data policy as above"),
    ("gpu-host-rescue/nvme/ojev-test.jsonl.gz",
     "third-party evaluation corpus projection; same reason as above"),
    ("gpu-host-rescue/nvme/kevbench.tgz :: kevbench/kev-src/**",
     "a clean checkout of the PUBLIC upstream repo github.com/jaredpalmer/kev at commit "
     "557598fced1dada75dfbf36ed144dce309ac6ceb with an empty `git status`, so it is "
     "re-clonable from its published revision. The irreplaceable parts of the archive -- "
     "serve_decider.py, serve_kev.py, the run scripts, the provenance JSONs, the smoke "
     "outputs and the server logs -- ARE uploaded, file by file, under "
     "gpu-host-evidence/kevbench/."),
    ("secjudge/contamination/cache/**",
     "1.7 GB HuggingFace download cache of third-party datasets, re-downloadable from the "
     "pinned revisions recorded in secjudge/contamination/work/downloads*.json"),
    ("secjudge/contamination/work/docs/**",
     "~700 MB of third-party training-corpus and case-corpus projections built for the "
     "overlap scan. The third-party halves may not be redistributed; both halves are "
     "regenerable from build_corpus_docs.py / build_train_docs.py plus the pinned "
     "revisions. Every derived RESULT is uploaded."),
    ("secjudge/contamination/work/mh/**, *.npy, corpus_global_ids.txt, exact_pass_pairs.jsonl",
     "MinHash signatures, shingle indexes and id spaces: ~350 MB of regenerable "
     "intermediates over the excluded corpora. Every derived result is uploaded."),
    ("openjev-qwen/validation/guard/named-guard-payload/**",
     "a staging copy of the 08:43 batch's own payload; every file in it is already "
     "published in one of the two repos under its real path"),
    ("openjev-qwen/s2/comparison-s2.json.bak-*",
     "five intermediate snapshots of comparison-s2.json superseded by the 11-row current "
     "file, which is uploaded"),
    ("secjudge/s2/*.bak-accuracy-review",
     "pre-review snapshots superseded by the current settled files, which are uploaded"),
    ("model weights, HF caches, staged checkpoints",
     "re-downloadable from their published revisions; out of scope by instruction"),
]

# Unsettled material: uploaded, but must never look settled.
UNSETTLED_NOTE = (
    "UNSETTLED. This file has no settled meta and its name carries its partial marker. "
    "It is preserved as evidence only and must not be scored, spliced or published."
)

# Bulk in secjudge/contamination/work that is not backed up, and why. Every DERIVED RESULT
# is uploaded; these are the inputs and intermediates behind them.
CONTAM_WORK_EXCLUDE = {
    "pivot_extract.jsonl":
        "216 MB whose rows carry a 'first_content' field holding RAW PROMPT TEXT lifted "
        "from third-party corpora. Excluded on the data policy (no raw prompts) and "
        "because the third-party halves may not be redistributed. Regenerable via "
        "pivot_index.py from the pinned revisions.",
    "pairs__r2_all.jsonl":
        "140 MB of UNVERIFIED LSH candidate pairs (doc ids + Jaccard only, no text). The "
        "verified subset, verified_pairs.jsonl, IS uploaded, as are all the derived "
        "results. Regenerable via lsh_match.py.",
    "pairs__r3_all.jsonl":
        "130 MB, same as pairs__r2_all.jsonl: a second unverified LSH round.",
    "train_global_ids.txt":
        "37 MB id space over the excluded third-party training corpora; regenerable via "
        "build_train_docs.py.",
    "corpus_global_ids.txt":
        "25 MB id space over the excluded case corpora; regenerable via "
        "build_corpus_docs.py.",
    "exact_pass_pairs.jsonl":
        "6 MB of exact-shingle pass candidates; superseded by verified_pairs.jsonl and the "
        "derived exact-matches.json, both uploaded. Regenerable via exact_shingle_pass.py.",
}
CONTAM_WORK_MAX_BYTES = 10 * 1024 * 1024

# Staged .jsonl files that are neither system_one predictions (gate 1) nor per-decision
# measurements (gate 2). Each is listed here with what it is, so that no .jsonl can reach a
# repo ungated: stage_trees() fails if a staged .jsonl matches none of the three.
REVIEWED_OTHER_JSONL = {
    "gpu-host-evidence/kevbench/work/smoke33.jsonl":
        "33 smoke cases rendered for the decider/kev shim bring-up. Case text, so it is "
        "gated by the prediction row guard's credential/CJK raw scan only and is NOT "
        "scored; it is rescue evidence from the ephemeral instance store.",
    "stages/secjudge/contamination/work/verified_pairs.jsonl":
        "verified near-duplicate pairs: document ids and Jaccard scores, no text.",
}

# ---------------------------------------------------------------------- redactions
# SecJudge's model card advertises credential-leak detection and quotes a SYNTHETIC AWS
# access key id as its worked example; the load verification and the report then re-quote
# that same string as a detection probe and record the model's score on it. It is not a real
# credential and grants nothing, but it is credential-SHAPED, so it is redacted rather than
# uploaded: the repos must stay clean under the programme's own credential scan. Nothing is
# lost -- the string is published verbatim in the publisher's own public model card at
# nghodki/SecJudge, and each file's pre-redaction sha256 is recorded in the manifest.
# The literal is assembled from two halves ON VENDORING ONLY, so that this file does not
# itself carry a credential-shaped token into the repository: GitHub push protection and
# the programme's own credential scan both match the whole form. The value is identical.
SYNTHETIC_CRED = "AKIA" + "7G4N2K9Q6M8R3T5V"
CRED_REDACTION = "<SYNTHETIC_AWS_KEY_ID_REDACTED>"
REDACT_IN = {
    "stages/secjudge/load-verification.json",
    "stages/secjudge/repo-meta/README.md",
    "stages/secjudge/secjudge-report.json",
}

# ------------------------------------------------------------- payload-key exemptions
# The flat guard bans a fixed set of payload-bearing key names outright. Four staged files
# use those names for something that is not a payload, so each is exempted explicitly, by
# path and by key, with the reason -- rather than by widening the shared key set.
PAYLOAD_KEY_EXEMPTIONS = {
    ("stages/secjudge/contamination/training-sources.json", "text"):
        "'text_views_built' is a map from SOURCE FIELD NAME to a document COUNT, e.g. "
        "{\"text\": 15291}. The key is the name of a field in the third-party dataset and "
        "the value is an integer; no field content is present.",
    ("stages/secjudge/contamination/training-sources.json", "command"):
        "same as above: a field-name-to-count map, value is an integer.",
    ("stages/secjudge/contamination/work/train_docs_summary.json", "text"):
        "'views' is a map from source field name to a document count; value is an integer.",
    ("stages/secjudge/contamination/work/train_docs_summary.json", "command"):
        "same as above: a field-name-to-count map, value is an integer.",
    ("stages/secjudge/contamination/work/train_docs_summary.json", "content"):
        "same as above: a field-name-to-count map, value is an integer.",
    ("stages/secjudge/load-verification.json", "text"):
        "'card_examples[].text' and 'separation_probes[].text' are the short synthetic "
        "probe strings used to verify the checkpoint loaded correctly -- 'rm -rf /', "
        "'git status', 'What's a strong password policy?'. They are the model card's own "
        "worked examples and the programme's own load probes, not benchmark case text, "
        "prompts or provider rationales. The one credential-shaped example is redacted "
        "(see REDACT_IN).",
    ("stages/secjudge/secjudge-report.json", "text"):
        "same load probes and card examples as load-verification.json, re-quoted in the "
        "report's verification section.",
}

# jsonl files that are measurements, not system_one prediction rows. Gated by
# measurement_gate() below rather than by the prediction row guard, whose schema they do
# not claim to satisfy.
MEASUREMENT_JSONL_DIRS = ("secjudge/raw/", "secjudge/truncation/")
MEASUREMENT_JSONL_FILES = ("openjev-qwen/validation/serving-startup-provenance.jsonl",)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def settled(pred: Path) -> dict:
    meta_path = Path(str(pred) + ".meta.json")
    meta = json.loads(meta_path.read_text())
    if meta.get("complete") is not True:
        raise RuntimeError(f"{pred}: meta.complete is not true")
    digest = sha256_file(pred)
    if digest != meta.get("prediction_sha256"):
        raise RuntimeError(f"{pred}: on-disk sha256 {digest} != "
                           f"meta.prediction_sha256 {meta.get('prediction_sha256')}")
    return meta


# ------------------------------------------------------------------------ the file maps
def pred_map() -> list[tuple[Path, str, str]]:
    """(absolute source, repo path, provenance label) for the predictions repo."""
    out: list[tuple[Path, str, str]] = []

    def add(src: Path, repo: str, label: str = "") -> None:
        if src.exists():
            out.append((src, repo, label))

    # --- gemma4 arms: settled, and already published as ranked leaderboard rows
    for arm in GEMMA_ARMS:
        for suf in (".jsonl", ".jsonl.meta.json", ".jsonl.plan.json", ".models.json",
                    ".smoke.jsonl", ".smoke.jsonl.meta.json", ".smoke.jsonl.plan.json"):
            add(DATA / f"gemma4jev/s2/{arm}{suf}", f"predictions/s2/{arm}{suf}")

    # --- decider-2b: settled minutes before this batch
    for suf in (".jsonl", ".jsonl.meta.json", ".jsonl.plan.json"):
        add(DATA / f"decider/s2/decider-2b{suf}", f"predictions/s2/decider-2b{suf}")

    # --- secjudge: 25 settled prediction arms, stage taken from the arm name
    for p in sorted((DATA / "secjudge/predictions").glob("secjudge-*.jsonl")):
        stage = "intent-real" if "-intent-real-" in p.name else "s2"
        add(p, f"predictions/{stage}/{p.name}")
        add(Path(str(p) + ".meta.json"), f"predictions/{stage}/{p.name}.meta.json")
    # the leaderboard registry meta for the settled secjudge arm; its body is
    # secjudge-s2-C7-sev.jsonl, uploaded above
    add(DATA / "secjudge/s2/secjudge.jsonl.meta.json",
        "predictions/s2/secjudge.jsonl.meta.json")
    # secjudge raw forward-pass shards: the primary model output the five answer-variant
    # arms are emitted from, so not a duplicate of them
    for p in sorted((DATA / "secjudge/raw").glob("*.jsonl")):
        stage = "intent-real" if p.name.startswith("intent-real") else "s2"
        add(p, f"predictions/{stage}/shards/secjudge-{p.name}")
    for p in sorted((DATA / "secjudge/raw").glob("*.jsonl.meta.json")):
        stage = "intent-real" if p.name.startswith("intent-real") else "s2"
        add(p, f"predictions/{stage}/shards/secjudge-{p.name}")

    # --- s3 openjev-full sidecar written today
    add(DATA / "s3/openjev-full.jsonl.meta.json",
        "predictions/s3/openjev-full.jsonl.meta.json")

    # --- open-jev-qwen-27b: deliberately unsettled partial shards, names preserved
    sh = DATA / "openjev-qwen/s2/shards"
    for p in sorted(sh.glob("open-jev-qwen-27b-shard*")):
        add(p, f"predictions/s2/shards/{p.name}", "unsettled")
    add(sh / "README-open-jev-qwen-27b.partial-superseded-by-h200.txt",
        "predictions/s2/shards/README-open-jev-qwen-27b.partial-superseded-by-h200.txt")

    # --- kev-9b: 1672 partial rows, no meta, superseded and unspliceable
    add(DATA / "kev/s2/kev-9b.jsonl",
        "predictions/s2/partial/kev-9b.jsonl.partial-unsettled", "unsettled")
    add(DATA / "kev/s2/kev-9b.jsonl.plan.json",
        "predictions/s2/partial/kev-9b.jsonl.plan.json", "unsettled")

    # --- GPU host instance-store rescue, into the existing gpu-host-evidence/ tree
    for name in ("serve_decider.py", "serve_kev.py", "run_decider_server.sh",
                 "run_kev_server.sh", "dl_kev.sh", "dl_kev.log"):
        add(KEVX / name, f"gpu-host-evidence/kevbench/{name}")
    for p in sorted((KEVX / "work").glob("*")):
        if p.is_file():
            add(p, f"gpu-host-evidence/kevbench/work/{p.name}")
    for p in sorted((KEVX / "logs").glob("*.log")):
        add(p, f"gpu-host-evidence/kevbench/logs/{p.name}")
    for p in sorted((RESCUE / "kevbench-logs").glob("*.log")):
        add(p, f"gpu-host-evidence/kevbench/logs/{p.name}")
    return out


def eval_map() -> list[tuple[Path, str, str]]:
    """(absolute source, repo path, provenance label) for the evaluations repo."""
    out: list[tuple[Path, str, str]] = []

    def add(src: Path, repo: str, label: str = "") -> None:
        if src.exists():
            out.append((src, repo, label))

    # --- gemma4 arms
    g = DATA / "gemma4jev/s2"
    for arm in GEMMA_ARMS:
        for suf in (".json", ".closure.json", ".culling.json"):
            add(g / f"scores/s2-{arm}{suf}", f"stages/s2/scores/s2-{arm}{suf}")
        add(g / f"{arm}.serving.json", f"stages/s2/serving/{arm}.serving.json")
        # the gemma4jev scores/ copies are the full per-variant tables (7 KB); the
        # openjev-qwen/validation/ files of the same name are the small cross-arm summaries
        # that already own stages/s2/validation/ for every other arm. Both are kept, each
        # under the directory it was written in.
        add(g / f"scores/auc-variants-{arm}.json",
            f"stages/s2/scores/auc-variants-{arm}.json")
        add(g / f"scores/mapping-check-{arm}.json",
            f"stages/s2/scores/mapping-check-{arm}.json")
    for name in ("recall-at-fpr-gemma4-arms.json",
                 "recall-at-fpr-by-variable-gemma4-arms.json",
                 "closure-arm2-base-temp.json", "closure-arm3-jevify.json",
                 "culling-arm2-base-temp.json", "culling-arm3-jevify.json",
                 "score-arm2-base-temp.json", "score-arm3-jevify.json"):
        add(g / "scores" / name, f"stages/s2/scores/{name}")
    for name in ("gemma-4-26b-a4b-it.drive.log", "jevify-gemma4-26b-a4b.drive.log",
                 "after.log", "finish.log"):
        add(g / name, f"stages/s2/logs/gemma4jev-{name}")
    # gemma4 study outputs
    gj = DATA / "gemma4jev"
    for name in ("phase0-scorecard.json", "phase0-scorecard.txt",
                 "threshold-vs-model-s2.json", "cost-and-s2-projection.json"):
        add(gj / name, f"stages/s2/gemma4jev-{name}")
    for p in sorted((gj / "calibration").glob("*")):
        if p.is_file():
            add(p, f"stages/s2/calibration/{p.name}")

    # --- the 11-row s2 comparison table, and the gemma4 intermediate of it
    add(DATA / "openjev-qwen/s2/comparison-s2.json", "stages/s2/comparison-s2.json",
        "update: grows the published table from 5 to 11 ranked rows")

    # --- decider-2b
    d = DATA / "decider/s2"
    for suf in (".json", ".closure.json", ".culling.json"):
        add(d / f"scores/s2-decider-2b{suf}", f"stages/s2/scores/s2-decider-2b{suf}")
    add(d / "decider-2b.serving.json", "stages/s2/serving/decider-2b.serving.json")

    # --- secjudge settled s2 arm, in the shared s2 namespace like every other arm
    s = DATA / "secjudge"
    for suf in (".json", ".closure.json", ".culling.json"):
        add(s / f"s2/scores/s2-secjudge{suf}", f"stages/s2/scores/s2-secjudge{suf}")
    add(s / "s2/secjudge.serving.json", "stages/s2/serving/secjudge.serving.json")

    # --- the secjudge sub-programme's own study, under a stage-level programme dir
    for name in ("secjudge-report.json", "secjudge-report.md", "settled-inputs.json",
                 "calibrator-resolution.json", "incumbent-metrics.json",
                 "int8-equivalence.json", "load-verification.json",
                 "serialisation-ablation.json", "serialisation-ablation-alt.json"):
        add(s / name, f"stages/secjudge/{name}")
    for sub in ("scores", "logs", "repo-meta", "truncation"):
        for p in sorted((s / sub).rglob("*")):
            if p.is_file():
                add(p, f"stages/secjudge/{sub}/{p.relative_to(s / sub)}")
    # contamination: the results, and the small analysis outputs from its working dir
    for p in sorted((s / "contamination").glob("*")):
        if p.is_file():
            add(p, f"stages/secjudge/contamination/{p.name}")
    for p in sorted((s / "contamination/work").glob("*")):
        if not p.is_file():
            continue
        if p.suffix in (".npy",) or p.name in CONTAM_WORK_EXCLUDE:
            continue                       # see CONTAM_WORK_EXCLUDE for the reason
        if p.stat().st_size > CONTAM_WORK_MAX_BYTES:
            # every large file in this working dir so far has been a corpus projection or
            # an index over the excluded third-party corpora. Refuse to guess about a new
            # one: stop and make a human classify it.
            raise RuntimeError(
                f"{p} is {p.stat().st_size:,} bytes, over the "
                f"{CONTAM_WORK_MAX_BYTES:,}-byte cap for contamination/work. Classify it "
                f"explicitly: add it to CONTAM_WORK_EXCLUDE with a reason, or raise the cap "
                f"if it is genuinely a result rather than a corpus projection.")
        add(p, f"stages/secjudge/contamination/work/{p.name}")

    # --- validation gates written today for every arm added today
    v = DATA / "openjev-qwen/validation"
    for p in sorted(v.glob("*")):
        if not p.is_file():
            continue
        if p.name in ("s2-requests-sample.jsonl", "ojev-test.jsonl.gz"):
            continue                       # excluded by the data policy
        add(p, f"stages/s2/validation/{p.name}")
    for p in sorted((v / "code").glob("*")):
        if p.is_file():
            add(p, f"stages/s2/validation/code/{p.name}")
    add(v / "guard/jev-guard-results.json",
        f"stages/s2/validation/guard/guard-results-{SUFFIX}.json")

    # --- rescue-side analysis JSONs
    for p in sorted((RESCUE / "nvme").glob("*.json")):
        add(p, f"stages/s2/validation/rescued-from-instance-store/{p.name}")
    for p in sorted(RESCUE.glob("*.json")):
        add(p, f"stages/s2/validation/rescued-from-instance-store/{p.name}")
    return out


# ------------------------------------------------------------------------------- gates
def load_jev_guard():
    spec = importlib.util.spec_from_file_location("jev_guard", GUARD)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["jev_guard"] = mod
    spec.loader.exec_module(mod)
    return mod


def is_measurement_jsonl(src: Path) -> bool:
    rel = str(src)
    if any(d in rel for d in MEASUREMENT_JSONL_DIRS):
        return True
    return any(rel.endswith(f) for f in MEASUREMENT_JSONL_FILES)


def measurement_gate(jg, files: list[Path]) -> tuple[list[str], dict]:
    """Gate jsonl files that are measurements, not system_one prediction rows.

    They do not claim the prediction schema, so the row guard is inapplicable. The test
    applied instead is the same substance: the shared credential/CJK raw-byte scan, plus a
    structural walk of every row banning the shared payload-bearing key set. A row here
    carries scores, token counts and identifiers only.
    """
    bad: list[str] = []
    stats = {"files": 0, "rows": 0, "keys": set()}
    for path in files:
        stats["files"] += 1
        bad += [f"{path.name}: {x}" for x in jg.raw_scan(path)]
        with path.open(encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                row = json.loads(line)
                stats["rows"] += 1

                def walk(node, where):
                    if isinstance(node, dict):
                        for k, val in node.items():
                            stats["keys"].add(k)
                            if k in jg.FORBIDDEN_KEYS and k not in jg.PROSE_OK:
                                bad.append(f"{path.name} row {i}: payload-bearing "
                                           f"key {k!r} at {where}")
                            walk(val, f"{where}.{k}")
                    elif isinstance(node, list):
                        for j, val in enumerate(node[:50]):
                            walk(val, f"{where}[{j}]")
                walk(row, "$")
    stats["keys"] = sorted(stats["keys"])
    return bad, stats


# ------------------------------------------------------------------------------ staging
def stage_trees() -> dict:
    for tree in (PRED_STAGE, EVAL_STAGE):
        if tree.exists():
            shutil.rmtree(tree)
        tree.mkdir(parents=True)
    staged: dict = {"predictions": [], "evaluations": [], "skipped": [],
                    "settled": [], "unsettled": [], "redacted": []}

    print("== settled checks ==")
    for arm, body in (
        [(a, DATA / f"gemma4jev/s2/{a}.jsonl") for a in GEMMA_ARMS]
        + [("decider-2b", DATA / "decider/s2/decider-2b.jsonl")]
    ):
        meta = settled(body)
        staged["settled"].append({"arm": arm, "rows": meta.get("requests"),
                                  "prediction_sha256": meta["prediction_sha256"]})
        print(f"  settled {arm}: complete=true, sha256 matches, "
              f"{meta.get('requests', 0):,} decisions")
    n_sj = 0
    for p in sorted((DATA / "secjudge/predictions").glob("secjudge-*.jsonl")):
        meta = settled(p)
        n_sj += 1
        staged["settled"].append({"arm": p.stem, "rows": meta.get("requests"),
                                  "prediction_sha256": meta["prediction_sha256"]})
    print(f"  settled {n_sj} secjudge prediction arms: all complete=true, all sha256 match")
    sj = settled(DATA / "secjudge/predictions/secjudge-s2-C7-sev.jsonl")
    print(f"  secjudge registry arm body = secjudge-s2-C7-sev.jsonl, "
          f"{sj['requests']:,} decisions")

    for which, mapping, tree in (("predictions", pred_map(), PRED_STAGE),
                                 ("evaluations", eval_map(), EVAL_STAGE)):
        seen: dict[str, Path] = {}
        for src, repo_rel, label in mapping:
            if repo_rel in seen:
                # two rescue copies of the same artifact: identical content is one file,
                # divergent content is a real conflict and must stop the batch
                if sha256_file(seen[repo_rel]) == sha256_file(src):
                    staged["skipped"].append({
                        "rel": str(src).replace("$WORK", "$WORK"),
                        "reason": f"byte-identical duplicate of "
                                  f"{str(seen[repo_rel]).replace('$WORK', '$WORK')}, "
                                  f"already staged at {repo_rel}"})
                    continue
                raise RuntimeError(f"two DIFFERENT sources map to {repo_rel}: "
                                   f"{seen[repo_rel]} and {src}")
            seen[repo_rel] = src
            dest = tree / repo_rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            entry = {"repo_path": repo_rel,
                     "source_path": str(src).replace("$WORK", "$WORK")}
            if repo_rel in REDACT_IN:
                text = src.read_text(encoding="utf-8")
                n = text.count(SYNTHETIC_CRED)
                if n:
                    entry["source_sha256"] = sha256_file(src)
                    entry["modification"] = (
                        f"{n} occurrence(s) of a synthetic, credential-shaped AWS access "
                        f"key id replaced with {CRED_REDACTION!r}. It is the SecJudge model "
                        f"card's own worked example of a credential leak, re-quoted as a "
                        f"detection probe; it is not a real credential and grants nothing, "
                        f"but the repos must stay clean under the credential scan. The "
                        f"string is published verbatim upstream at nghodki/SecJudge. Every "
                        f"other byte is identical to the source, whose sha256 is recorded "
                        f"as source_sha256.")
                    staged["redacted"].append({"repo_path": repo_rel, "occurrences": n})
                dest.write_text(text.replace(SYNTHETIC_CRED, CRED_REDACTION),
                                encoding="utf-8")
            else:
                shutil.copy2(src, dest)
            entry["bytes"] = dest.stat().st_size
            entry["sha256"] = sha256_file(dest)
            if label == "unsettled":
                entry["settled"] = False
                entry["note"] = UNSETTLED_NOTE
                staged["unsettled"].append(repo_rel)
            elif label:
                entry["note"] = label
            staged[which].append(entry)
        print(f"  staged {len(mapping)} files for {which}")

    for rel, why in EXCLUDED:
        staged["skipped"].append({"rel": rel, "reason": why})
    for name, why in CONTAM_WORK_EXCLUDE.items():
        staged["skipped"].append({"rel": f"secjudge/contamination/work/{name}",
                                  "reason": why})

    # No .jsonl may reach a repo ungated. Gate 1 covers settled system_one predictions,
    # gate 2 covers per-decision measurements; anything else must be named and classified
    # in REVIEWED_OTHER_JSONL or this batch stops here.
    ungated = []
    for which in ("predictions", "evaluations"):
        for entry in staged[which]:
            if not entry["repo_path"].endswith(".jsonl"):
                continue
            src = Path(entry["source_path"].replace("$WORK", "$WORK"))
            if is_measurement_jsonl(src) or entry.get("settled") is False:
                continue
            try:
                src.relative_to(DATA / "secjudge/predictions")
                continue                    # settled prediction, gate 1
            except ValueError:
                pass
            if src.parent in (DATA / "gemma4jev/s2", DATA / "decider/s2"):
                continue                    # settled prediction, gate 1
            if entry["repo_path"] not in REVIEWED_OTHER_JSONL:
                ungated.append(entry["repo_path"])
    if ungated:
        raise RuntimeError(
            "these staged .jsonl files are covered by no gate; classify each in "
            "REVIEWED_OTHER_JSONL or exclude it: " + ", ".join(sorted(ungated)))
    staged["reviewed_other_jsonl"] = REVIEWED_OTHER_JSONL
    return staged


def write_manifests(staged: dict, gates: dict) -> None:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for tree, label, entries in ((PRED_STAGE, "predictions-v1", staged["predictions"]),
                                 (EVAL_STAGE, "evaluations-v1", staged["evaluations"])):
        files = sorted(entries, key=lambda e: e["repo_path"])
        manifest = {
            "kind": "defenseclaw-system-one-upload-manifest",
            "schema_version": "1",
            "repo": label,
            "batch": SUFFIX,
            "generated_at": now,
            "purpose": ("Backfill of everything produced after the 08:43 batch: the two "
                        "settled gemma4 arms already published as ranked leaderboard "
                        "rows, the 25 settled SecJudge prediction arms and the SecJudge "
                        "study, decider-2b, the 11-row s2 comparison table, today's "
                        "validation gates, the FPR-constrained calibration study, two "
                        "deliberately unsettled partials and the GPU host "
                        "instance-store rescue."),
            "settled_arms": staged["settled"],
            "unsettled_paths": sorted(staged["unsettled"]),
            "redactions": staged["redacted"],
            "file_count": len(files),
            "total_bytes": sum(f["bytes"] for f in files),
            "excluded": staged["skipped"],
            "gates": gates,
            "files": files,
        }
        (tree / f"MANIFEST-{SUFFIX}.json").write_text(
            json.dumps(manifest, indent=1, sort_keys=True) + "\n")
        (tree / f"SHA256SUMS-{SUFFIX}.txt").write_text(
            "".join(f"{f['sha256']}  {f['repo_path']}\n" for f in files))
        print(f"  {label}: {len(files)} files, {manifest['total_bytes']:,} bytes")


def all_private() -> dict:
    from huggingface_hub import HfApi
    api = HfApi()
    return {d.id: api.repo_info(d.id, repo_type="dataset").private
            for d in api.list_datasets(author="Vineethsain")}


def upload(dry_run: bool) -> dict:
    from huggingface_hub import HfApi
    api = HfApi()
    results = {}
    for repo, folder, msg in (
        (PRED_REPO, PRED_STAGE,
         "Backfill predictions written after the 08:43 batch: the two settled gemma4 arms "
         "(gemma-4-26b-a4b-it, jevify-gemma4-26b-a4b, 30,310 rows each, both already "
         "ranked on the public leaderboard), decider-2b, 25 settled SecJudge arms plus "
         "their raw forward-pass shards, the s3 openjev-full sidecar, the deliberately "
         "unsettled open-jev-qwen-27b and kev-9b partials, and the GPU host "
         "instance-store rescue including serve_decider.py"),
        (EVAL_REPO, EVAL_STAGE,
         "Backfill evaluations written after the 08:43 batch: gemma4, decider-2b and "
         "SecJudge scorecards, closure and culling ledgers and serving contracts; the "
         "11-row s2 comparison table; today's auc-variants, mapping-check and "
         "recall-by-variable gates for every new arm; the FPR-constrained calibration "
         "study; and the SecJudge sub-programme report, truncation study, serialisation "
         "ablations and contamination analysis"),
    ):
        before = api.repo_info(repo, repo_type="dataset")
        print(f"[{repo}] BEFORE: private={before.private} sha={before.sha}", flush=True)
        if before.private is not True:
            print(f"FATAL: {repo} is not private; aborting", flush=True)
            sys.exit(2)
        if dry_run:
            results[repo] = {"dry_run": True, "private_before": before.private,
                             "parent_sha": before.sha}
            continue
        commit = api.upload_folder(repo_id=repo, repo_type="dataset",
                                   folder_path=str(folder), commit_message=msg)
        after = api.repo_info(repo, repo_type="dataset")
        print(f"[{repo}] AFTER : private={after.private} sha={after.sha}", flush=True)
        if after.private is not True:
            print(f"FATAL: {repo} became non-private after upload", flush=True)
            sys.exit(3)
        results[repo] = {"private_before": before.private, "private_after": after.private,
                         "parent_sha": before.sha, "new_sha": after.sha,
                         "commit_url": getattr(commit, "commit_url", None)}
    return results


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    staged = stage_trees()
    for item in staged["skipped"]:
        print(f"  EXCLUDED {item['rel']}")
    for rel in staged["unsettled"]:
        print(f"  UNSETTLED (preserved as partial) {rel}")

    jg = load_jev_guard()
    gates: dict = {}

    print("\n== gate 1: prediction row guard (guard2.py, family=system_one) ==")
    plan = []
    for entry in staged["predictions"]:
        src = Path(entry["source_path"].replace("$WORK", "$WORK"))
        if not src.suffix == ".jsonl" and not src.name.endswith(".jsonl"):
            continue
        if is_measurement_jsonl(src) or entry.get("settled") is False:
            continue
        try:
            rel = str(src.relative_to(DATA))
        except ValueError:
            continue                        # outside outputs/ (rescue tree); gated below
        plan.append({"rel": rel, "family": "system_one"})
    plan_path = STAGE / "guard-plan.json"
    plan_path.write_text(json.dumps(plan, indent=1, sort_keys=True) + "\n")
    proc = subprocess.run([PY, GUARD, str(plan_path)], capture_output=True, text=True)
    tail = proc.stdout[-4000:]
    print(tail)
    if proc.returncode != 0:
        print("ROW GUARD FAILED - nothing will be uploaded")
        print(proc.stderr[-2000:])
        return 1
    gates["row_guard_files"] = len(plan)

    print("\n== gate 2: measurement-jsonl gate ==")
    meas = []
    for which in ("predictions", "evaluations"):
        for entry in staged[which]:
            src = Path(entry["source_path"].replace("$WORK", "$WORK"))
            if not src.name.endswith(".jsonl"):
                continue
            if is_measurement_jsonl(src) or \
                    entry["repo_path"] in REVIEWED_OTHER_JSONL:
                meas.append(src)
    bad, stats = measurement_gate(jg, meas)
    if bad:
        print("MEASUREMENT GATE FAILED - nothing will be uploaded")
        for b in bad[:40]:
            print("  " + b)
        return 1
    print(f"  {stats['files']} files, {stats['rows']:,} rows, "
          f"{len(stats['keys'])} distinct keys: 0 payload-bearing keys, "
          f"0 credential or CJK hits")
    print(f"  keys: {', '.join(stats['keys'])}")
    gates["measurement_gate"] = {"files": stats["files"], "rows": stats["rows"],
                                 "keys": stats["keys"]}

    print("\n== gate 3: flat guard over every staged non-jsonl payload ==")
    flat_bad, n_flat, exempted = [], 0, []
    for tree in (PRED_STAGE, EVAL_STAGE):
        for p in sorted(tree.rglob("*")):
            if not p.is_file() or p.name.endswith(".jsonl"):
                continue
            if p.suffix not in (".json", ".txt", ".md", ".sh", ".py", ".log", ".pt",
                                ".pkl", ".gitattributes", ""):
                continue
            if p.suffix in (".pt", ".pkl"):
                continue                    # binary calibrator, not text-scannable
            n_flat += 1
            repo_rel = str(p.relative_to(tree))
            fails = []
            for f in jg.raw_scan(p) + jg.structural_scan(p):
                m = re.search(r"payload-bearing key '([^']+)'", f)
                if m and (repo_rel, m.group(1)) in PAYLOAD_KEY_EXEMPTIONS:
                    exempted.append({"repo_path": repo_rel, "key": m.group(1),
                                     "finding": f,
                                     "reason": PAYLOAD_KEY_EXEMPTIONS[
                                         (repo_rel, m.group(1))]})
                    continue
                fails.append(f)
            for f in fails:
                flat_bad.append(f"{p.relative_to(STAGE)}: {f}")
    if flat_bad:
        print(f"FLAT GUARD FAILED ({len(flat_bad)} findings) - nothing will be uploaded")
        for b in flat_bad[:60]:
            print("  " + b)
        return 1
    print(f"  {n_flat} files scanned: 0 unexempted credential, CJK or payload-key findings")
    gates["flat_guard_files"] = n_flat
    gates["payload_key_exemptions"] = exempted
    gates["credential_redactions"] = staged["redacted"]
    for e in exempted:
        print(f"  EXEMPT {e['repo_path']} key {e['key']!r}")
    for r in staged["redacted"]:
        print(f"  REDACTED synthetic credential-shaped token x{r['occurrences']} "
              f"in {r['repo_path']}")

    print("\n== manifests ==")
    write_manifests(staged, gates)

    print("\n== dataset repo visibility BEFORE ==")
    vis_before = all_private()
    for r, pv in sorted(vis_before.items()):
        print(f"  {r}: private={pv}")
    if not all(vis_before.values()):
        print("FATAL: a dataset repo is not private; aborting")
        return 1

    print("\n== upload ==")
    results = upload(args.dry_run)

    print("\n== dataset repo visibility AFTER ==")
    vis_after = all_private()
    for r, pv in sorted(vis_after.items()):
        print(f"  {r}: private={pv}")
    if vis_before != vis_after:
        print("FATAL: a dataset repo's visibility changed")
        return 1
    if not all(vis_after.values()):
        print("FATAL: a dataset repo is not private after upload")
        return 1

    out = STAGE / f"upload-results-{SUFFIX}.json"
    out.write_text(json.dumps({
        "kind": "defenseclaw-system-one-backfill-upload-results",
        "schema_version": "1", "dry_run": args.dry_run, "batch": SUFFIX,
        "staged_predictions": len(staged["predictions"]),
        "staged_evaluations": len(staged["evaluations"]),
        "settled_arms": staged["settled"],
        "unsettled_paths": sorted(staged["unsettled"]),
        "redactions": staged["redacted"],
        "excluded": staged["skipped"], "gates": gates,
        "dataset_repo_visibility_before": vis_before,
        "dataset_repo_visibility_after": vis_after,
        "repos": results,
    }, indent=2, sort_keys=True) + "\n")
    print(f"\nwrote {out}")
    print(json.dumps(results, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
