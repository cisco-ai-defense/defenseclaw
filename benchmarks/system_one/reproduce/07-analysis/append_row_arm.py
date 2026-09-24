#!/usr/bin/env python3
"""Append one settled arm's row to comparison-s2.json, preserving every existing row.

A generalisation of `j27/append_row_27b.py`. Row construction is still imported from
`sysone-compare_s2.py`, so the row is 1:1 with every published `kind: "new"` row and reads
the same scorecard tier (`deterministic_then_system_one`). The only change is that the
`recall-by-variable` reader accepts both shapes that script has emitted: the older one
keyed `p_block` / `p_block_minus_p_confirm`, and the current one keyed by the variable's
own name. A row is refused if its closure ledger is not `complete: true`.
"""
import argparse
import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, "$WORK")
sys.path.insert(0, "$WORK/defenseclaw-system-one/benchmarks/scripts")

_spec = importlib.util.spec_from_file_location(
    "compare_s2", Path("$WORK/sysone-compare_s2.py"))
compare_s2 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(compare_s2)

COMPARISON = Path("$WORK/.system-one-data/outputs/openjev-qwen/s2/comparison-s2.json")
LEAD = "risk = 1 - P(allow)  [leaderboard variable]"


def canonical(row):
    return json.dumps(row, indent=2, sort_keys=True)


def auc_of(arm: dict, variable: str, legacy_key: str) -> float:
    """One variable's AUC, from whichever shape the by-variable file used."""
    if variable in arm:
        return arm[variable]["roc_auc"]
    if legacy_key in arm:
        return arm[legacy_key]["roc_auc"]
    raise SystemExit(f"ABORT: the by-variable file carries neither {variable!r} nor "
                     f"{legacy_key!r}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--name", required=True)
    p.add_argument("--scoredir", required=True)
    p.add_argument("--predictions", required=True)
    p.add_argument("--by-variable", required=True)
    p.add_argument("--deployment", required=True)
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

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

    bv = json.loads(Path(args.by_variable).read_text())
    arm = bv["arms"][args.name]
    row["recall"].update(
        roc_auc_p_block=auc_of(arm, "P(block)", "p_block"),
        roc_auc_p_block_minus_p_confirm=auc_of(arm, "P(block) - P(confirm)",
                                               "p_block_minus_p_confirm"),
        best_variable=arm["verdict"]["best_variable"],
        matched_fpr={
            "openjev_operating_fpr": bv["openjev_reference_fpr"],
            "openjev_recall_at_that_fpr": arm["verdict"]["openjev_recall_at_its_own_fpr"],
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

    doc = json.loads(COMPARISON.read_text())          # re-read, not the copy above
    doc["rows"] = [r for r in doc["rows"] if r.get("model") != args.name]
    doc["rows"].append(row)
    tmp = COMPARISON.with_suffix(f".json.tmp-{args.name}")
    tmp.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(COMPARISON)

    after = json.loads(COMPARISON.read_text())
    after_rows = {r["model"]: canonical(r) for r in after["rows"]}
    lost = [n for n in before_rows if n not in after_rows]
    changed = [n for n in before_rows
               if n in after_rows and after_rows[n] != before_rows[n]]
    if lost or changed:
        raise SystemExit(f"ABORT: rows lost={lost} changed={changed}")
    print(json.dumps({
        "appended": args.name, "rows_before": len(before["rows"]),
        "rows_after": len(after["rows"]), "preexisting_rows_unchanged": True,
        "models": [r["model"] for r in after["rows"]],
        "block_f1": row["block_f1"], "block_fpr": row["block_fpr"],
        "any_f1": row["any_f1"], "three_way": row["three_way"],
        "review_rate": row["review_rate"],
        "roc_auc_risk": row["recall"].get("roc_auc"),
    }, indent=2))


if __name__ == "__main__":
    main()
