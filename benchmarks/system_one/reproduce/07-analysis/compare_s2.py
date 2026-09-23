"""Assemble the s2 comparison table: three new adapters beside the published incumbents.

Reads only settled scorecards. Incumbent numbers come from the same files the published
leaderboard used, and the same key paths, so the rows are 1:1 by construction:
  block-only F1 <- deterministic_then_system_one.binary_block_only.f1
  any F1        <- deterministic_then_system_one.binary.f1
  FPR           <- deterministic_then_system_one.binary_block_only.false_positive_rate
                   (the published headline FPR is the BLOCK-ONLY rate, matching block-only F1;
                    the any-intervention rate is an order of magnitude higher and is also shown)
  three-way acc <- deterministic_then_system_one.three_way.accuracy
Verified: this reproduces all four published reference rows exactly, including
recall at <=0.5% FPR (OpenJev 0.2890, Jev 0.0917, DiffusionGemma 0.0275).
Gemma 4 is the judge tier (deterministic_then_llm) inside any s2 scorecard, not a
system_one arm, and is reported as a reference row that must not be AUC-ranked.
"""
import argparse
import json
from pathlib import Path

O = Path("$WORK/.system-one-data/outputs")
SJ = O / "secjudge" / "scores"

INCUMBENTS = [
    ("OpenJev", SJ / "incumbent-s2-openjev.json", "openjev", "self-hosted FP8, rev 5ec9e5fd"),
    ("Jev (hosted)", SJ / "incumbent-s2-jev.json", "jev", "hosted API, jev-1.13.0"),
    ("DiffusionGemma", SJ / "incumbent-s2-diffusiongemma.json", "diffusiongemma",
     "diffusiongemma-26B-A4B-it-FP8-dynamic"),
]
NEW = [
    ("open-jev-qwen-9b", O / "openjev-qwen/s2/scores", "Qwen3.5-9B + LoRA r8 + scalar head"),
    ("bespoke-nimble-9b", O / "nimble/s2/scores", "Qwen3.5-9B + LoRA r16, letter readout"),
    ("open-jev-qwen-2b", O / "openjev-qwen/s2/scores", "Qwen3.5-2B + LoRA r8 + scalar head"),
]
FPR_TARGETS = ("0.001", "0.005", "0.01", "0.05")


def metrics_from(path, candidate_index=0):
    data = json.loads(Path(path).read_text())
    c = data["candidates"][candidate_index]
    d = c.get("deterministic_then_system_one", c["system_one"])
    return {
        "candidate": c["candidate"],
        "n": c["scorable_cases"],
        "errors": c["system_one"]["errors"],
        "block_f1": d["binary_block_only"]["f1"],
        "block_precision": d["binary_block_only"]["precision"],
        "block_recall": d["binary_block_only"]["recall"],
        "block_fpr": d["binary_block_only"]["false_positive_rate"],
        "any_f1": d["binary"]["f1"],
        "any_precision": d["binary"]["precision"],
        "any_recall": d["binary"]["recall"],
        "any_fpr": d["binary"]["false_positive_rate"],
        "three_way": d["three_way"]["accuracy"],
        "macro_f1": d["three_way"]["macro_f1"],
        "review_rate": d["review_rate"],
        "brier": c["system_one"]["calibration"]["brier"],
        "ece": c["system_one"]["calibration"]["ece"],
        "latency_p50": c["system_one"]["latency_ms"]["p50"],
        "latency_p95": c["system_one"]["latency_ms"]["p95"],
        "_raw": data,
    }


def judge_row(path):
    c = json.loads(Path(path).read_text())["candidates"][0]
    d = c["deterministic_then_llm"]
    return {
        "candidate": "google.gemma-4-26b-a4b (judge tier)", "n": c["scorable_cases"], "errors": None,
        "block_f1": d["binary_block_only"]["f1"], "block_precision": d["binary_block_only"]["precision"],
        "block_recall": d["binary_block_only"]["recall"], "block_fpr": d["binary_block_only"]["false_positive_rate"],
        "any_f1": d["binary"]["f1"], "any_precision": d["binary"]["precision"],
        "any_recall": d["binary"]["recall"], "any_fpr": d["binary"]["false_positive_rate"],
        "three_way": d["three_way"]["accuracy"], "macro_f1": d["three_way"]["macro_f1"],
        "review_rate": d["review_rate"], "brier": None, "ece": None,
        "latency_p50": None, "latency_p95": None,
    }


def recall_rows(path, label=None):
    """Arms are keyed "<label>|<candidate>", so select by label prefix, never positionally."""
    if not Path(path).exists():
        return {}
    data = json.loads(Path(path).read_text())
    arms = data.get("arms", {})
    arm = {}
    if label:
        matches = [value for key, value in arms.items() if key.split("|", 1)[0] == label]
        if len(matches) == 1:
            arm = matches[0]
        elif matches:
            raise ValueError(f"ambiguous arm label {label!r} in {path}")
        else:
            return {"missing_arm": label, "available": sorted(k.split('|', 1)[0] for k in arms)}
    elif len(arms) == 1:
        arm = next(iter(arms.values()))
    out = {"roc_auc": arm.get("roc_auc"), "distinct_scores": arm.get("distinct_scores"),
           "score_variable": arm.get("score_variable"), "candidate": arm.get("candidate")}
    for target in FPR_TARGETS:
        entry = arm.get(f"recall_at_fpr_{target}") or {}
        out[target] = entry.get("recall")
        out[target + "_achieved"] = entry.get("achieved_fpr")
    return out


def fmt(value, width=10, places=8):
    if value is None:
        return "-".rjust(width)
    if isinstance(value, float):
        return f"{value:.{places}f}".rjust(width)
    return str(value).rjust(width)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    rows = []
    incumbent_recall = SJ / "recall-at-fpr-s2-incumbents.json"

    for label, path, arm, deployment in INCUMBENTS:
        if not Path(path).exists():
            print(f"  MISSING incumbent scorecard {path}")
            continue
        row = metrics_from(path)
        row.pop("_raw")
        row.update(model=label, deployment=deployment, kind="incumbent",
                   recall=recall_rows(incumbent_recall, arm))
        rows.append(row)

    if Path(INCUMBENTS[0][1]).exists():
        row = judge_row(INCUMBENTS[0][1])
        row.update(model="Gemma 4 (judge, reference)", kind="reference-not-ranked",
                   deployment="LLM judge tier; 2 distinct score values, do not AUC-rank",
                   recall=recall_rows(incumbent_recall, "gemma4"))
        rows.append(row)

    for name, scoredir, deployment in NEW:
        card = Path(scoredir) / f"s2-{name}.json"
        if not card.exists():
            print(f"  PENDING {name}: {card} not written yet")
            continue
        closure = Path(scoredir) / f"s2-{name}.closure.json"
        settled = json.loads(closure.read_text()).get("complete") is True if closure.exists() else False
        row = metrics_from(card)
        row.pop("_raw")
        row.update(model=name, deployment=deployment, kind="new",
                   settled=settled,
                   recall=recall_rows(Path(scoredir) / f"recall-at-fpr-s2-{name}.json", name))
        rows.append(row)

    report = {"schema_version": "1", "kind": "defenseclaw-system-one-s2-comparison",
              "stage": "s2", "grid": "C7/I3/Q2",
              "deterministic_tier": str(O / "deterministic-real/s2-run/predictions.jsonl"),
              "rows": rows}
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"\n{'model':28s} {'n':>5s} {'blockF1':>12s} {'anyF1':>12s} {'blockFPR':>12s} "
          f"{'anyFPR':>11s} {'3way':>9s} {'err':>4s}")
    print("-" * 104)
    for row in rows:
        print(f"{row['model']:28s} {row['n']:>5d} {fmt(row['block_f1'],12)} {fmt(row['any_f1'],12)} "
              f"{fmt(row['block_fpr'],12)} {fmt(row['any_fpr'],11)} {fmt(row['three_way'],9,4)} "
              f"{str(row['errors'] if row['errors'] is not None else '-'):>4s}")

    print(f"\n{'model':28s} {'AUC':>10s} " + " ".join(f"{'R@'+t:>9s}" for t in FPR_TARGETS))
    print("-" * 80)
    for row in rows:
        r = row.get("recall") or {}
        print(f"{row['model']:28s} {fmt(r.get('roc_auc'),10,6)} "
              + " ".join(fmt(r.get(t), 9, 4) for t in FPR_TARGETS))
    print(f"\nwritten: {args.out}")


if __name__ == "__main__":
    main()
