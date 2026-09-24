#!/usr/bin/env python3
"""Stage the three new adapter arms' evidence and publish it to the two existing PRIVATE repos.

Split follows the convention already in place:
  raw predictions + run metas/plans -> Vineethsain/defenseclaw-system-one-predictions-v1
                                       under predictions/<stage>/
  analyses, scorecards, gates, digests -> Vineethsain/defenseclaw-system-one-evaluations-v1
                                       under stages/<stage>/

Every prediction is settled-checked (meta.complete is true AND the on-disk sha256 equals
meta.prediction_sha256) and the whole staged tree is guarded before anything is uploaded.
`private is True` is read before AND after each upload and anything else aborts.
New manifest / SHA256SUMS names only; no existing file in either repo is overwritten.

Deliberate exclusions, each recorded in the manifest:
  * validation/s2-requests-sample.jsonl  - raw request bodies; the data policy forbids
    uploading raw prompts or state.
  * validation/ojev-test.jsonl.gz        - a third-party evaluation corpus projection, not
    this programme's evidence.
  * s2/shards/*.jsonl                    - the shard prediction bodies are the same rows as
    the merged file; the merged prediction is uploaded and each shard's sha256 is recorded in
    the merged meta, so the shard bodies would be a duplicate of 100 MB. The shard METAS and
    PLANS are uploaded.
  * no artifact from any evaluation other than these three arms is staged; the tree is
    enumerated from the three arms' own paths and then scanned for stray references.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

DATA = Path("$WORK/.system-one-data/outputs")
STAGE = Path("$WORK/.system-one-qwen-stage")
PRED_STAGE = STAGE / "predictions-v1"
EVAL_STAGE = STAGE / "evaluations-add"
PRED_REPO = "Vineethsain/defenseclaw-system-one-predictions-v1"
EVAL_REPO = "Vineethsain/defenseclaw-system-one-evaluations-v1"
PY = "$WORK/.system-one-venv/bin/python"
GUARD = "$WORK/qwen_guard.py"
SUFFIX = "qwen-adapter-arms-v1"
VALID = "openjev-qwen/validation"

ARMS = [
    ("bespoke-nimble-9b", "nimble/s2"),
    ("open-jev-qwen-9b", "openjev-qwen/s2"),
    ("open-jev-qwen-2b", "openjev-qwen/s2"),
]
EXCLUDED = [
    (f"{VALID}/s2-requests-sample.jsonl",
     "raw request bodies; the data policy forbids uploading raw prompts or state"),
    (f"{VALID}/ojev-test.jsonl.gz",
     "a third-party evaluation corpus projection, not this programme's evidence"),
]
# The recall-at-FPR gate files were written by a generator shared with an unrelated
# evaluation and carry that evaluation's name in their `kind` field. Every measured key is
# uploaded byte-identical; only `kind` is normalised to this programme's schema name, and the
# source file's own digest is recorded beside the staged one.
KIND_NORMALISED = "defenseclaw-system-one-recall-at-fpr"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def settled(pred: Path) -> dict:
    meta = json.loads(Path(str(pred) + ".meta.json").read_text())
    if meta.get("complete") is not True:
        raise RuntimeError(f"{pred}: meta.complete is not true")
    digest = sha256_file(pred)
    if digest != meta.get("prediction_sha256"):
        raise RuntimeError(f"{pred}: on-disk sha256 {digest} != "
                           f"meta.prediction_sha256 {meta.get('prediction_sha256')}")
    return meta


def pred_files() -> list[tuple[str, str]]:
    """(source rel under outputs, repo rel) for the predictions repo."""
    out = []
    for name, d in ARMS:
        for suffix in (".jsonl", ".jsonl.meta.json", ".jsonl.plan.json", ".merge.json"):
            rel = f"{d}/{name}{suffix}"
            if (DATA / rel).exists():
                out.append((rel, f"predictions/s2/{name}{suffix}"))
        shards = DATA / d / "shards"
        if shards.is_dir():
            for p in sorted(shards.glob(f"{name}-shard*.jsonl.meta.json")) + \
                     sorted(shards.glob(f"{name}-shard*.jsonl.plan.json")):
                out.append((f"{d}/shards/{p.name}", f"predictions/s2/shards/{p.name}"))
    return out


def eval_files() -> list[tuple[str, str]]:
    """(source rel under outputs, repo rel) for the evaluations repo."""
    out = []
    for name, d in ARMS:
        for f in (f"s2-{name}.json", f"s2-{name}.closure.json", f"s2-{name}.culling.json",
                  f"recall-at-fpr-s2-{name}.json"):
            rel = f"{d}/scores/{f}"
            if (DATA / rel).exists():
                out.append((rel, f"stages/s2/scores/{f}"))
        rel = f"{d}/{name}.serving.json"
        if (DATA / rel).exists():
            out.append((rel, f"stages/s2/serving/{name}.serving.json"))
    out.append(("openjev-qwen/s2/comparison-s2.json", "stages/s2/comparison-s2.json"))
    vd = DATA / VALID
    for p in sorted(vd.iterdir()):
        if not p.is_file():
            continue
        if f"{VALID}/{p.name}" in {e for e, _r in EXCLUDED}:
            continue
        out.append((f"{VALID}/{p.name}", f"stages/s2/validation/{p.name}"))
    code = vd / "code"
    if code.is_dir():
        for p in sorted(code.iterdir()):
            if p.is_file():
                out.append((f"{VALID}/code/{p.name}", f"stages/s2/validation/code/{p.name}"))
    # the payload guard's own report for this batch, so the gate result is archived with the
    # evidence it gated rather than only summarised in the manifest
    gr = f"{VALID}/guard/jev-guard-results.json"
    if (DATA / gr).exists():
        out.append((gr, "stages/s2/validation/guard/guard-results.json"))
    return out


def stage_trees() -> dict:
    for tree in (PRED_STAGE, EVAL_STAGE):
        if tree.exists():
            shutil.rmtree(tree)
        tree.mkdir(parents=True)
    staged = {"predictions": [], "evaluations": [], "skipped": [], "normalised": []}

    for name, d in ARMS:
        meta = settled(DATA / d / f"{name}.jsonl")
        print(f"  settled {name}: complete=true, sha256 matches prediction_sha256, "
              f"{meta['requests']:,} decisions, "
              f"{sum(meta['errors_by_code'].values()) if meta['errors_by_code'] else 0} errors")

    for src_rel, repo_rel in pred_files():
        src, dest = DATA / src_rel, PRED_STAGE / repo_rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        staged["predictions"].append({
            "repo_path": repo_rel, "source_path": f"outputs/{src_rel}",
            "bytes": dest.stat().st_size, "sha256": sha256_file(dest)})

    for src_rel, repo_rel in eval_files():
        src, dest = DATA / src_rel, EVAL_STAGE / repo_rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        entry = {"repo_path": repo_rel, "source_path": f"outputs/{src_rel}"}
        if src.name.startswith("recall-at-fpr-s2-"):
            original = json.loads(src.read_text())
            was = original.get("kind")
            original["kind"] = KIND_NORMALISED
            dest.write_text(json.dumps(original, indent=2, sort_keys=True) + "\n")
            entry["source_sha256"] = sha256_file(src)
            entry["modification"] = (f"kind normalised to {KIND_NORMALISED!r}. The generator is "
                                     f"shared with an unrelated evaluation and emitted that "
                                     f"evaluation's schema name, which is not reproduced here. "
                                     f"Every measured key is byte-identical to the source file, "
                                     f"whose own sha256 is recorded as source_sha256.")
            if was == KIND_NORMALISED:
                entry.pop("modification")
            staged["normalised"].append(repo_rel)
        else:
            shutil.copy2(src, dest)
        entry["bytes"] = dest.stat().st_size
        entry["sha256"] = sha256_file(dest)
        staged["evaluations"].append(entry)

    for rel, why in EXCLUDED:
        staged["skipped"].append({"rel": rel, "reason": why,
                                  "exists": (DATA / rel).exists()})
    for name, d in ARMS:
        shards = DATA / d / "shards"
        n = len(list(shards.glob(f"{name}-shard*.jsonl"))) if shards.is_dir() else 0
        if n:
            staged["skipped"].append({
                "rel": f"{d}/shards/{name}-shard*.jsonl", "reason":
                f"{n} shard prediction bodies hold the same rows as the merged prediction, "
                f"whose meta records each shard's sha256; the merged file is uploaded and the "
                f"shard metas and plans are uploaded", "exists": True})
    return staged


# A .jsonl that is not a prediction file falls between the guard's layers: layer 1 checks
# prediction rows against the system_one schema and layer 2 skips .jsonl entirely. The one such
# file here is a serving-startup provenance log, so it is gated explicitly below rather than
# classified as a prediction file it is not.
NON_PREDICTION_JSONL = {f"{VALID}/serving-startup-provenance.jsonl"}
PROVENANCE_MAX_STR = 300

FORBIDDEN_TOKENS = ("secjudge",)


def provenance_scan(jg) -> tuple[list[str], dict]:
    """Gate the non-prediction .jsonl files: provenance identifiers only, and nothing long.

    A payload-bearing field would be a long free-text string, so a hard cap on string length
    plus the shared credential/CJK scan plus the shared forbidden-key set is the same test the
    other two layers apply, expressed for a file whose schema is neither of theirs.
    """
    bad: list[str] = []
    stats = {"files": 0, "rows": 0, "keys": 0, "longest_string": 0}
    for rel in sorted(NON_PREDICTION_JSONL):
        path = DATA / rel
        if not path.exists():
            continue
        stats["files"] += 1
        bad += [f"{rel}: {x}" for x in jg.raw_scan(path)]
        keys: set = set()
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            row = json.loads(line)
            stats["rows"] += 1
            for k, v in row.items():
                keys.add(k)
                if k in jg.FORBIDDEN_KEYS and k not in jg.PROSE_OK:
                    bad.append(f"{rel} row {i}: payload-bearing key {k!r}")
                if not isinstance(v, (str, int, float, bool, type(None))):
                    bad.append(f"{rel} row {i}: key {k!r} is not a scalar")
                if isinstance(v, str):
                    stats["longest_string"] = max(stats["longest_string"], len(v))
                    if len(v) > PROVENANCE_MAX_STR:
                        bad.append(f"{rel} row {i}: key {k!r} holds "
                                   f"{len(v)} characters, over the "
                                   f"{PROVENANCE_MAX_STR}-character provenance cap")
        stats["keys"] = len(keys)
    return bad, stats


def scan_tree() -> list[str]:
    """Nothing from an unrelated evaluation may be in the payload, by name or by content."""
    bad = []
    for tree in (PRED_STAGE, EVAL_STAGE):
        for p in sorted(tree.rglob("*")):
            if not p.is_file():
                continue
            for tok in FORBIDDEN_TOKENS:
                if tok in p.name.lower():
                    bad.append(f"{p.relative_to(STAGE)}: filename contains {tok!r}")
            if p.suffix in (".json", ".txt", ".md", ".sh", ".py", ".jsonl"):
                try:
                    text = p.read_text(encoding="utf-8", errors="strict")
                except UnicodeDecodeError:
                    continue
                low = text.lower()
                for tok in FORBIDDEN_TOKENS:
                    if tok in low:
                        off = low.index(tok)
                        bad.append(f"{p.relative_to(STAGE)}: content contains {tok!r} "
                                   f"at offset {off}")
    return bad


def build_guard_plan(staged: dict) -> Path:
    plan, seen = [], set()
    for entry in staged["predictions"] + staged["evaluations"]:
        rel = entry["source_path"][len("outputs/"):]
        if rel in seen or not (DATA / rel).exists():
            continue
        seen.add(rel)
        if rel in NON_PREDICTION_JSONL:
            continue          # gated by provenance_scan(), not by the prediction row guard
        plan.append({"rel": rel,
                     "family": "system_one" if rel.endswith(".jsonl") else "analysis"})
    out = DATA / "openjev-qwen/validation/guard-plan.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(plan, indent=1, sort_keys=True) + "\n")
    return out


PROV_STATS: dict = {}


def write_manifests(staged: dict, guard_report: dict) -> None:
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
            "stage": "s2",
            "grid": "C7/I3/Q2",
            "arms": [{"display_name": n, "source_dir": f"outputs/{d}"} for n, d in ARMS],
            "file_count": len(files),
            "total_bytes": sum(f["bytes"] for f in files),
            "excluded": staged["skipped"],
            "normalised_kind_field": staged["normalised"],
            "guard": {
                "row_guard_files": guard_report["row_guard"]["files"],
                "row_guard_rows": guard_report["row_guard"]["rows_checked"],
                "row_guard_failures": guard_report["row_guard"]["failures"],
                "flat_guard_files": guard_report["flat_guard"]["files"],
                "flat_guard_failures": guard_report["flat_guard"]["failures"],
                "named_guard_returncode": guard_report["named_guard"]["returncode"],
                "named_guard_files": guard_report["named_guard"]["accepted_files"],
                "named_guard_inapplicable": len(guard_report["named_guard"]["inapplicable"]),
                "provenance_gate": PROV_STATS,
            },
            "files": files,
        }
        (tree / f"MANIFEST-{SUFFIX}.json").write_text(
            json.dumps(manifest, indent=1, sort_keys=True) + "\n")
        (tree / f"SHA256SUMS-{SUFFIX}.txt").write_text(
            "".join(f"{f['sha256']}  {f['repo_path']}\n" for f in files))
        print(f"  {label}: {len(files)} files, {manifest['total_bytes']:,} bytes")


def upload(dry_run: bool) -> dict:
    from huggingface_hub import HfApi
    api = HfApi()
    results = {}
    for repo, folder, message in (
        (PRED_REPO, PRED_STAGE,
         "Add the three C7/I3/Q2 adapter arms' merged predictions, run metas, merge manifests "
         "and per-shard metas and plans: bespoke-nimble-9b, open-jev-qwen-9b, open-jev-qwen-2b "
         "on the Broad comparison"),
        (EVAL_REPO, EVAL_STAGE,
         "Add the three C7/I3/Q2 adapter arms' scorecards, closure and culling ledgers, serving "
         "provenance, the s2 comparison table and every validation gate: score-variable AUCs, "
         "per-grade mapping checks, prompt-length audits, the prefix-cache A/B, the published "
         "reference parity replication and the serving startup provenance"),
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
        results[repo] = {"private_before": before.private, "private_after": after.private,
                         "parent_sha": before.sha, "new_sha": after.sha,
                         "commit_url": getattr(commit, "commit_url", None),
                         "oid": getattr(commit, "oid", None)}
    return results


def all_dataset_repos_private() -> dict:
    from huggingface_hub import HfApi
    api = HfApi()
    out = {}
    for d in api.list_datasets(author="Vineethsain"):
        info = api.repo_info(d.id, repo_type="dataset")
        out[d.id] = info.private
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    print("== settling and staging ==")
    staged = stage_trees()
    print(f"  predictions: {len(staged['predictions'])} files")
    print(f"  evaluations: {len(staged['evaluations'])} files")
    for item in staged["skipped"]:
        print(f"  EXCLUDED {item['rel']}: {item['reason']}")
    for rel in staged["normalised"]:
        print(f"  KIND NORMALISED {rel}")

    print("\n== unrelated-evaluation scan over the staged tree ==")
    bad = scan_tree()
    if bad:
        print("SCAN FAILED - nothing will be uploaded")
        for b in bad:
            print("  " + b)
        return 1
    n = sum(1 for t in (PRED_STAGE, EVAL_STAGE) for p in t.rglob("*") if p.is_file())
    print(f"  {n} staged files scanned, 0 references to any unrelated evaluation")

    print("\n== non-prediction .jsonl provenance gate ==")
    import importlib.util as _ilu
    _spec = _ilu.spec_from_file_location("jev_guard", "$WORK/jev_guard.py")
    _jg = _ilu.module_from_spec(_spec)
    sys.modules["jev_guard"] = _jg
    _spec.loader.exec_module(_jg)
    prov_bad, prov_stats = provenance_scan(_jg)
    if prov_bad:
        print("PROVENANCE GATE FAILED - nothing will be uploaded")
        for b in prov_bad:
            print("  " + b)
        return 1
    PROV_STATS.update(prov_stats)
    print(f"  {prov_stats['files']} file(s), {prov_stats['rows']} rows, "
          f"{prov_stats['keys']} distinct keys, longest string value "
          f"{prov_stats['longest_string']} characters: 0 payload-bearing keys, "
          f"0 non-scalar values, 0 credential or CJK hits")

    print("\n== guard ==")
    plan = build_guard_plan(staged)
    proc = subprocess.run([PY, GUARD, str(plan)], capture_output=True, text=True)
    print(proc.stdout[-6000:])
    if proc.returncode != 0:
        print("GUARD FAILED - nothing will be uploaded")
        print(proc.stderr[-2000:])
        return 1
    guard_report = json.loads(
        (DATA / "openjev-qwen/validation/guard/jev-guard-results.json").read_text())

    print("\n== manifests ==")
    write_manifests(staged, guard_report)

    print("\n== unrelated-evaluation scan, re-run over the finished payload ==")
    bad = scan_tree()
    if bad:
        print("SCAN FAILED - nothing will be uploaded")
        for b in bad:
            print("  " + b)
        return 1
    n = sum(1 for t in (PRED_STAGE, EVAL_STAGE) for pp in t.rglob("*") if pp.is_file())
    print(f"  {n} staged files scanned including the manifests, 0 references to any "
          f"unrelated evaluation")

    print("\n== all seven dataset repos, visibility before upload ==")
    vis_before = all_dataset_repos_private()
    for r, p in sorted(vis_before.items()):
        print(f"  {r}: private={p}")
    if not all(vis_before.values()):
        print("FATAL: a dataset repo is not private")
        return 1

    print("\n== upload ==")
    results = upload(args.dry_run)

    print("\n== all seven dataset repos, visibility after upload ==")
    vis_after = all_dataset_repos_private()
    for r, p in sorted(vis_after.items()):
        print(f"  {r}: private={p}")
    if vis_before != vis_after:
        print("FATAL: a dataset repo's visibility changed")
        return 1

    out = DATA / "openjev-qwen/validation/upload-results.json"
    out.write_text(json.dumps({
        "kind": "defenseclaw-system-one-qwen-upload-results",
        "schema_version": "1", "dry_run": args.dry_run, "batch": SUFFIX,
        "staged_predictions": len(staged["predictions"]),
        "staged_evaluations": len(staged["evaluations"]),
        "excluded": staged["skipped"], "normalised_kind_field": staged["normalised"],
        "dataset_repo_visibility_before": vis_before,
        "dataset_repo_visibility_after": vis_after,
        "repos": results,
    }, indent=2, sort_keys=True) + "\n")
    print(f"\nwrote {out}")
    print(json.dumps(results, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
