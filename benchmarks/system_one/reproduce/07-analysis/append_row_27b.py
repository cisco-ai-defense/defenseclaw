"""Append the open-jev-qwen-27b row to comparison-s2.json, preserving every existing row.

Row construction is imported from `compare_s2.py` rather than duplicated, so this row is
1:1 with the published `kind: "new"` rows for the 2B, 9B and nimble arms -- same key paths
into the same scorecard tier (`deterministic_then_system_one`).

Another agent is appending Gemma rows to this same file concurrently, so the document is
re-read at append time (never from a cached copy), deduped by `row["model"]`, written to a
temp file and swapped atomically. Afterwards it re-reads the result and asserts that every
row that was present beforehand is still byte-for-byte identical.
"""

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, "$WORK")
sys.path.insert(0, "$WORK/defenseclaw-system-one/benchmarks/scripts")

spec_path = Path("$WORK/sysone-compare_s2.py")
import importlib.util  # noqa: E402

spec = importlib.util.spec_from_file_location("compare_s2", spec_path)
compare_s2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compare_s2)

COMPARISON = Path("$WORK/.system-one-data/outputs/openjev-qwen/s2/comparison-s2.json")


def canonical(row):
    return json.dumps(row, indent=2, sort_keys=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", default="open-jev-qwen-27b")
    parser.add_argument("--scoredir",
                        default="$WORK/.system-one-data/outputs/openjev-qwen/s2/scores")
    parser.add_argument("--predictions",
                        default="$WORK/.system-one-data/outputs/openjev-qwen/s2/"
                                "open-jev-qwen-27b.jsonl")
    parser.add_argument("--by-variable")
    parser.add_argument("--deployment",
                        default="Qwen3.8-27B + LoRA r8 + scalar head, 2 cards per replica")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    scoredir = Path(args.scoredir)
    card = scoredir / f"s2-{args.name}.json"
    closure = scoredir / f"s2-{args.name}.closure.json"
    recall = scoredir / f"recall-at-fpr-s2-{args.name}.json"
    for required in (card, closure, recall):
        if not required.exists():
            raise SystemExit(f"ABORT: missing {required}")

    settled = json.loads(closure.read_text()).get("complete") is True
    if not settled:
        raise SystemExit(f"ABORT: {closure} is not complete:true; refusing to publish a row")

    row = compare_s2.metrics_from(card)
    row.pop("_raw")
    row.update(model=args.name, deployment=args.deployment, kind="new", settled=settled,
               recall=compare_s2.recall_rows(recall, args.name))

    digest = hashlib.sha256()
    with open(args.predictions, "rb") as stream:
        for block in iter(lambda: stream.read(8 << 20), b""):
            digest.update(block)
    row["prediction_sha256"] = digest.hexdigest()

    # The leaderboard ranks on `risk`, which for this family can sit below chance while the
    # block channel is informative, so carry the alternative variables on the row too.
    if args.by_variable:
        by_variable = json.loads(Path(args.by_variable).read_text())
        arm = by_variable["arms"][args.name]
        row["recall"].update(
            roc_auc_p_block=arm["p_block"]["roc_auc"],
            roc_auc_p_block_minus_p_confirm=arm["p_block_minus_p_confirm"]["roc_auc"],
            best_variable=arm["verdict"]["best_variable"],
            matched_fpr={
                "openjev_operating_fpr": by_variable["openjev_reference_fpr"],
                "openjev_recall_at_that_fpr":
                    arm["verdict"]["openjev_recall_at_its_own_fpr"],
                "this_arm_recall_at_that_fpr_by_variable":
                    arm["verdict"]["recall_at_openjev_fpr_by_variable"],
            })

    before = json.loads(COMPARISON.read_text())
    before_rows = {r["model"]: canonical(r) for r in before["rows"]}
    print(f"existing rows ({len(before['rows'])}): {[r['model'] for r in before['rows']]}")

    if args.dry_run:
        print(canonical(row))
        return

    backup = COMPARISON.with_name(COMPARISON.name + ".bak-before-" + args.name)
    if not backup.exists():
        shutil.copy2(COMPARISON, backup)
        print("backup ->", backup)

    doc = json.loads(COMPARISON.read_text())  # re-read, not the copy above
    doc["rows"] = [r for r in doc["rows"] if r.get("model") != args.name]
    doc["rows"].append(row)
    tmp = COMPARISON.with_suffix(".json.tmp-27b")
    tmp.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(COMPARISON)

    after = json.loads(COMPARISON.read_text())
    after_rows = {r["model"]: canonical(r) for r in after["rows"]}
    lost = [name for name in before_rows if name not in after_rows]
    changed = [name for name in before_rows
               if name in after_rows and after_rows[name] != before_rows[name]]
    if lost or changed:
        raise SystemExit(f"ABORT: rows lost={lost} changed={changed}")
    print(json.dumps({
        "appended": args.name, "rows_before": len(before["rows"]), "rows_after": len(after["rows"]),
        "preexisting_rows_unchanged": True,
        "models": [r["model"] for r in after["rows"]],
        "block_f1": row["block_f1"], "block_fpr": row["block_fpr"],
        "roc_auc_risk": row["recall"].get("roc_auc"),
    }, indent=2))


if __name__ == "__main__":
    main()
