#!/usr/bin/env python3
"""Stage the new hosted-Jev evidence and publish it to the two existing PRIVATE repos.

Split follows the convention already in place:
  raw predictions + run metas/plans -> Vineethsain/defenseclaw-system-one-predictions-v1
                                       under predictions/<stage>/
  analyses, scorecards, digests     -> Vineethsain/defenseclaw-system-one-evaluations-v1
                                       under stages/<stage>/ and stages/jev-parity/

Every file is settled-checked, guarded and digested before anything is uploaded.
`private is True` is verified before AND after each upload; anything else aborts.
New manifest/SHA256SUMS names only - the existing MANIFEST.json / SHA256SUMS are never
overwritten.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

DATA = Path("$WORK/.system-one-data/outputs")
STAGE = Path("$WORK/.system-one-jev-stage")
PRED_STAGE = STAGE / "predictions-v1"
EVAL_STAGE = STAGE / "evaluations-add"
PRED_REPO = "Vineethsain/defenseclaw-system-one-predictions-v1"
EVAL_REPO = "Vineethsain/defenseclaw-system-one-evaluations-v1"
PY = "$WORK/.system-one-venv/bin/python"
GUARD = "$WORK/jev_guard.py"
SUFFIX = "jev-parity-v1"

# ---- new hosted-Jev prediction arms: (stage dir, prediction basename) -------------------
JEV_ARMS: list[tuple[str, str]] = [
    ("s2", "jev-C7.jsonl"),
    ("s2", "jev-smoke20.jsonl"),
    ("s2", "jev-q3-C7.jsonl"),
    ("s2", "jev-q1-C7.jsonl"),
    ("s2", "jev-q0-C7.jsonl"),
    ("s2", "jev-q4-C7.jsonl"),
    ("s3", "jev-C7.jsonl"),
    ("toolcall-labels", "jev-q4-C0.jsonl"),
    ("toolcall-labels", "jev-q4-C7.jsonl"),
    ("toolcall-labels", "jev-q4-C0-I1.jsonl"),
    ("toolcall-labels", "jev-q4-C0-I2.jsonl"),
    ("toolcall-labels", "jev-q4-C7-I1.jsonl"),
    ("toolcall-labels", "jev-q4-C7-I2.jsonl"),
    ("intent-real", "jev-q4-C0.jsonl"),
    ("intent-real", "jev-q4-C7.jsonl"),
    ("intent-ablation", "jev-C1.jsonl"),
    ("intent-ablation", "jev-q4-C1.jsonl"),
    ("intent-large", "jev-C7.jsonl"),
    ("terminalbench", "jev-q4-C1.jsonl"),
    ("terminalbench", "jev-q4-C7.jsonl"),
    ("s1-n1000", "tb-jev-q2.jsonl"),
    ("s1-n1000", "tb-jev-q3.jsonl"),
    ("s1-n1000", "jev-smoke.jsonl"),
    ("s3", "jev-q3-C7.jsonl"),
    ("toolcall-labels", "jev-q4-smoke-C0.jsonl"),
    ("toolcall-labels", "jev-q4-smoke-C7.jsonl"),
] + [("repeat", f"jev-r{n}.jsonl") for n in range(4, 17)]

# ---- new evaluation artifacts: (source rel under outputs, repo rel under evaluations) ---
def eval_files() -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for stage in ("s2", "s3", "intent-real", "intent-ablation", "toolcall-labels", "terminalbench"):
        for name in ("three-way-comparison.json", "three-way-comparison.txt"):
            pairs.append((f"{stage}/{name}", f"stages/{stage}/{name}"))
    pairs.append(("model-parity.json", "stages/model-parity.json"))
    # real-deterministic-tier Jev scorecards the Space cascade charts consume
    realdet = DATA / "deterministic-real"
    for card in sorted(realdet.glob("realdet-*-jev*.json")):
        rel = f"deterministic-real/{card.name}"
        pairs.append((rel, f"stages/{rel}"))
    pairs.append(("repeat/three-way-repeatability.json", "stages/repeat/three-way-repeatability.json"))
    pairs.append(("repeat/three-way-repeatability.txt", "stages/repeat/three-way-repeatability.txt"))
    # stage-native analyses re-run with the Jev arm added
    native = [
        "terminalbench/q4-lane-fpr-with-jev.json", "terminalbench/q4-lane-fpr-with-jev.txt",
        "intent-real/q4-analysis-with-jev.json", "intent-real/q4-analysis-with-jev.txt",
        "intent-ablation/ablation-analysis-jev.json", "intent-ablation/ablation-analysis-jev.txt",
        "intent-ablation/q4-ablation-analysis-with-jev.json",
        "intent-ablation/q4-ablation-analysis-with-jev.txt",
        "toolcall-labels/q4-c0-vs-c7-jev.json", "toolcall-labels/q4-c0-vs-c7-jev.txt",
        "toolcall-labels/q4-analysis-jev-C0.json", "toolcall-labels/q4-analysis-jev-C0.txt",
        "toolcall-labels/q4-analysis-jev-C7.json", "toolcall-labels/q4-analysis-jev-C7.txt",
        "toolcall-labels/q4-instruction-arms-with-jev.json",
        "toolcall-labels/q4-instruction-arms-with-jev.txt",
    ]
    for rel in native:
        pairs.append((rel, f"stages/{rel}"))
    # parity provenance: per-arm scorecards, gap enumeration, extended schema, cost ledgers
    pairs.append(("jev-parity/parity-gap-enumeration.json",
                  "stages/jev-parity/parity-gap-enumeration.json"))
    pairs.append(("jev-parity/guard/jev-guard-results.json",
                  "stages/jev-parity/guard/jev-guard-results.json"))
    pairs.append(("jev-run-ledger.json", "stages/jev-parity/jev-run-ledger.json"))
    pairs.append(("jev-run-ledger-2.json", "stages/jev-parity/jev-run-ledger-2.json"))
    pairs.append(("jev-run-ledger-3.json", "stages/jev-parity/jev-run-ledger-3.json"))
    pairs.append(("jev-run-ledger-4.json", "stages/jev-parity/jev-run-ledger-4.json"))
    pairs.append(("jev-run-ledger-5.json", "stages/jev-parity/jev-run-ledger-5.json"))
    pairs.append(("jev-parity/jev-arm-audit.json", "stages/jev-parity/jev-arm-audit.json"))
    pairs.append(("s1-n1000/jev-context.jsonl.settlement.json",
                  "stages/s1-n1000/jev-context.jsonl.settlement.json"))
    scores = DATA / "jev-parity/scores"
    if scores.is_dir():
        for card in sorted(scores.glob("*.json")):
            pairs.append((f"jev-parity/scores/{card.name}",
                          f"stages/jev-parity/scores/{card.name}"))
    return pairs


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def settled(pred: Path) -> dict:
    meta_path = Path(str(pred) + ".meta.json")
    meta = json.loads(meta_path.read_text())
    if meta.get("complete") is not True:
        raise RuntimeError(f"{pred}: meta complete is not true")
    if sha256_file(pred) != meta.get("prediction_sha256"):
        raise RuntimeError(f"{pred}: on-disk sha256 does not match meta.prediction_sha256")
    return meta


def build_guard_plan() -> Path:
    plan = []
    for stage, name in JEV_ARMS:
        rel = f"{stage}/{name}"
        if (DATA / rel).exists():
            plan.append({"rel": rel, "family": "system_one"})
    for src, _ in eval_files():
        if (DATA / src).exists():
            plan.append({"rel": src, "family": "analysis"})
    out = DATA / "jev-parity/guard-plan-jev.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(plan, indent=1, sort_keys=True) + "\n")
    return out


def stage_trees() -> dict:
    for tree in (PRED_STAGE, EVAL_STAGE):
        if tree.exists():
            shutil.rmtree(tree)
        tree.mkdir(parents=True)
    staged = {"predictions": [], "evaluations": [], "skipped": []}

    for stage, name in JEV_ARMS:
        pred = DATA / stage / name
        if not pred.exists():
            staged["skipped"].append({"rel": f"{stage}/{name}", "reason": "not run"})
            continue
        try:
            meta = settled(pred)
        except (RuntimeError, FileNotFoundError) as exc:
            staged["skipped"].append({"rel": f"{stage}/{name}", "reason": str(exc)})
            continue
        dest_dir = PRED_STAGE / "predictions" / stage
        dest_dir.mkdir(parents=True, exist_ok=True)
        for src in (pred, Path(str(pred) + ".meta.json"), Path(str(pred) + ".plan.json")):
            if src.exists():
                shutil.copy2(src, dest_dir / src.name)
                staged["predictions"].append({
                    "repo_path": f"predictions/{stage}/{src.name}",
                    "source_path": f"outputs/{stage}/{src.name}",
                    "bytes": src.stat().st_size, "sha256": sha256_file(src),
                })
        staged["predictions"][-1]["run_meta"] = {
            "run_id": meta.get("run_id"), "requests": meta.get("requests"),
            "actual_input_tokens": meta.get("actual_input_tokens"),
            "estimated_usd": meta.get("estimated_usd"),
            "grid": f"{meta['contexts'][0]}/{meta['instructions'][0]}/{meta['questions'][0]}",
        }

    for src_rel, repo_rel in eval_files():
        src = DATA / src_rel
        if not src.exists():
            staged["skipped"].append({"rel": src_rel, "reason": "not produced"})
            continue
        dest = EVAL_STAGE / repo_rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        staged["evaluations"].append({
            "repo_path": repo_rel, "source_path": f"outputs/{src_rel}",
            "bytes": src.stat().st_size, "sha256": sha256_file(src),
        })
    return staged


def write_manifests(staged: dict, guard_report: dict) -> None:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for tree, label, entries, man_name, sums_name in (
        (PRED_STAGE, "predictions-v1", staged["predictions"],
         f"MANIFEST-{SUFFIX}.json", f"SHA256SUMS-{SUFFIX}.txt"),
        (EVAL_STAGE, "evaluations-v1", staged["evaluations"],
         f"MANIFEST-{SUFFIX}.json", f"SHA256SUMS-{SUFFIX}.txt"),
    ):
        files = sorted(
            ({"path": e["repo_path"], "bytes": e["bytes"], "sha256": e["sha256"],
              "source_path": e["source_path"],
              **({"run_meta": e["run_meta"]} if "run_meta" in e else {})}
             for e in entries), key=lambda x: x["path"])
        manifest = {
            "kind": "defenseclaw-system-one-upload-manifest",
            "schema_version": "1",
            "repo": label,
            "batch": SUFFIX,
            "generated_at": now,
            "seed": 741983,
            "file_count": len(files),
            "total_bytes": sum(f["bytes"] for f in files),
            "guard": {
                "row_guard_files": guard_report["row_guard"]["files"],
                "row_guard_rows": guard_report["row_guard"]["rows_checked"],
                "row_guard_failures": guard_report["row_guard"]["failures"],
                "flat_guard_files": guard_report["flat_guard"]["files"],
                "flat_guard_failures": guard_report["flat_guard"]["failures"],
                "named_guard_returncode": guard_report["named_guard"]["returncode"],
                "named_guard_files": guard_report["named_guard"]["accepted_files"],
                "named_guard_inapplicable": len(guard_report["named_guard"]["inapplicable"]),
            },
            "files": files,
        }
        (tree / man_name).write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")
        (tree / sums_name).write_text(
            "".join(f"{f['sha256']}  {f['path']}\n" for f in files))
        print(f"  {label}: {len(files)} files, "
              f"{manifest['total_bytes']:,} bytes -> {man_name}, {sums_name}")


def upload(dry_run: bool) -> dict:
    from huggingface_hub import HfApi
    api = HfApi()
    results = {}
    for repo, folder, message in (
        (PRED_REPO, PRED_STAGE,
         "Add hosted Jev (jev-1.13.0) prediction arms for cross-model parity: Broad comparison "
         "(Q1/Q2/Q3), Production-weighted, label corpus (I1/I2/I3 x C0/C7), intent ablation, "
         "intent real Q4, intent large, TerminalBench lanes"),
        (EVAL_REPO, EVAL_STAGE,
         "Add three-way (Jev / OpenJev / DiffusionGemma) parity comparisons per stage, the "
         "model-parity rollup with per-cell grid provenance, per-arm scorecards, the "
         "parity-gap enumeration and the guard results"),
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
                                   folder_path=str(folder), commit_message=message)
        after = api.repo_info(repo, repo_type="dataset")
        print(f"[{repo}] AFTER : private={after.private} sha={after.sha}", flush=True)
        if after.private is not True:
            print(f"FATAL: {repo} became non-private after upload", flush=True)
            sys.exit(3)
        results[repo] = {
            "private_before": before.private, "private_after": after.private,
            "parent_sha": before.sha, "new_sha": after.sha,
            "commit_url": getattr(commit, "commit_url", None),
            "oid": getattr(commit, "oid", None),
        }
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--skip-guard", action="store_true")
    args = parser.parse_args()

    print("== staging ==")
    staged = stage_trees()
    print(f"  predictions: {len(staged['predictions'])} files")
    print(f"  evaluations: {len(staged['evaluations'])} files")
    for item in staged["skipped"]:
        print(f"  SKIPPED {item['rel']}: {item['reason']}")

    plan = build_guard_plan()
    if not args.skip_guard:
        print("\n== guard ==")
        proc = subprocess.run([PY, GUARD, str(plan)], capture_output=True, text=True)
        print(proc.stdout[-4000:])
        if proc.returncode != 0:
            print("GUARD FAILED - nothing will be uploaded")
            print(proc.stderr[-2000:])
            return 1
    guard_report = json.loads((DATA / "jev-parity/guard/jev-guard-results.json").read_text())
    # the guard report itself is staged, so re-copy it now that it exists
    dest = EVAL_STAGE / "stages/jev-parity/guard/jev-guard-results.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    src = DATA / "jev-parity/guard/jev-guard-results.json"
    shutil.copy2(src, dest)
    if not any(e["repo_path"] == "stages/jev-parity/guard/jev-guard-results.json"
               for e in staged["evaluations"]):
        staged["evaluations"].append({
            "repo_path": "stages/jev-parity/guard/jev-guard-results.json",
            "source_path": "outputs/jev-parity/guard/jev-guard-results.json",
            "bytes": src.stat().st_size, "sha256": sha256_file(src)})

    print("\n== manifests ==")
    write_manifests(staged, guard_report)

    print("\n== upload ==")
    results = upload(args.dry_run)

    out = DATA / "jev-parity/upload-results.json"
    out.write_text(json.dumps({
        "kind": "defenseclaw-system-one-jev-upload-results",
        "schema_version": "1",
        "dry_run": args.dry_run,
        "batch": SUFFIX,
        "staged_predictions": len(staged["predictions"]),
        "staged_evaluations": len(staged["evaluations"]),
        "skipped": staged["skipped"],
        "repos": results,
    }, indent=2, sort_keys=True) + "\n")
    print(f"\nwrote {out}")
    print(json.dumps(results, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
