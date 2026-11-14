#!/usr/bin/env python3
"""Append one trend row (kind "compare") per tool x config x pack x set, holdout side, plus the pooled rows, to the S7 trend file.

  python3 trend_rows.py --results results.json --trend ~/dc-eh/evidence/rel-1-0-10/s7/trend/trend.jsonl --code "<DefenseClaw head>" [--dry-run]

Same fields as the s7-gate rows (benign_block, block_recall, *_ci, F1, labels_sha, split_sha ...) plus tool and config.
"""
import argparse, json, time


def row(r, sets, code, t):
    b, al = r["block"], r["alert"]
    return dict(t=t, kind="compare", run=r["run"], tool=r["tool"], config=r["config"], pack=r["pack"], corpus=("cmp-" + r["set"]) if r["set"] != "POOLED" else "cmp-pooled",
                surface=r["surface"], split="holdout", split_sha=sets.get("split_sha256"), labels_sha=(sets.get("labels_sha256") or "")[:16], code=code,
                layers="competitor" if r.get("kind") == "competitor" else "defenseclaw", benign_n=r["benign"], attack_n=r["attack"], cases=r["benign"] + r["attack"],
                benign_block=b["fp"], benign_block_rate=b["fpr"], benign_block_ci=b["fpr_ci"], benign_alert=al["fp"], benign_alert_rate=al["fpr"], benign_alert_ci=al["fpr_ci"],
                block_recall=b["recall"], block_recall_ci=b["recall_ci"], alert_recall=al["recall"], alert_recall_ci=al["recall_ci"], block_f1=b["f1"], alert_f1=al["f1"],
                block_precision=b["precision"], alert_precision=al["precision"], na=r.get("na", False), sampled=r["set"] == "nemotron-terminal")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True); ap.add_argument("--sets", required=True); ap.add_argument("--trend", required=True)
    ap.add_argument("--code", required=True); ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    R = json.load(open(a.results)); S = json.load(open(a.sets)); t = time.strftime("%Y-%m-%dT%H:%MZ", time.gmtime())
    rows = [row(r, S, a.code, t) for r in R["results"] if r["side"] == "holdout"] + [row(dict(p, na=False), S, a.code, t) for p in R["pooled"] if p["side"] == "holdout"]
    if a.dry_run:
        print(len(rows), "rows (dry run)"); return
    with open(a.trend, "a") as f:
        for x in rows:
            f.write(json.dumps(x, sort_keys=True) + "\n")
    print("appended", len(rows), "compare rows to", a.trend)


if __name__ == "__main__":
    main()
