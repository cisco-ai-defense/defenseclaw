#!/usr/bin/env python3
"""Task 2: Gemma 4 flex vs default service tier comparison."""
import json
from collections import Counter
from pathlib import Path

OUT = Path("$WORK/.system-one-data/outputs/flex")


def read_rows(path):
    rows = []
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def case_map(rows):
    m, errs = {}, 0
    for r in rows:
        if r.get("error_code"):
            errs += 1
        m[str(r.get("case_id", ""))] = str(r.get("action", ""))
    return m, errs


def event_map(rows):
    m, errs = {}, 0
    for r in rows:
        if r.get("error_code"):
            errs += 1
            continue
        m[(str(r.get("case_id", "")), int(r.get("event_index", -1)))] = str(r.get("action", ""))
    return m, errs


def main():
    report = {}
    paths = {t: OUT / f"gemma4-{t}.jsonl" for t in ("default", "flex")}
    missing = {t: str(p) for t, p in paths.items() if not p.exists()}
    if missing:
        print(json.dumps({"status": "MISSING", "missing": missing}, indent=2))
        return

    cases, cerrs, evs, eerrs, metas = {}, {}, {}, {}, {}
    for tier, p in paths.items():
        rows = read_rows(p)
        cases[tier], cerrs[tier] = case_map(rows)
        report[f"{tier}_case_rows"] = len(rows)
        report[f"{tier}_case_errors"] = cerrs[tier]
        ep = p.with_suffix(p.suffix + ".events.jsonl")
        if ep.exists():
            erows = read_rows(ep)
            evs[tier], eerrs[tier] = event_map(erows)
            report[f"{tier}_event_rows"] = len(erows)
            report[f"{tier}_event_errors"] = eerrs[tier]
        mp = p.with_suffix(p.suffix + ".meta.json")
        if mp.exists():
            metas[tier] = json.loads(mp.read_text())

    # --- per-case agreement ---
    common = set(cases["default"]) & set(cases["flex"])
    agree = sum(1 for c in common if cases["default"][c] == cases["flex"][c])
    disagree = [
        {"case_id": c, "default": cases["default"][c], "flex": cases["flex"][c]}
        for c in sorted(common)
        if cases["default"][c] != cases["flex"][c]
    ]
    report["case_identities_common"] = len(common)
    report["case_agreements"] = agree
    report["case_agreement_rate"] = agree / len(common) if common else None
    report["case_disagreements"] = len(disagree)
    report["case_disagreement_examples"] = disagree[:20]
    report["case_transition_counts"] = dict(
        Counter(f"{d['default']}->{d['flex']}" for d in disagree).most_common()
    )
    report["case_action_dist_default"] = dict(Counter(cases["default"].values()).most_common())
    report["case_action_dist_flex"] = dict(Counter(cases["flex"].values()).most_common())

    # --- per-event agreement ---
    if "default" in evs and "flex" in evs:
        ec = set(evs["default"]) & set(evs["flex"])
        eagree = sum(1 for k in ec if evs["default"][k] == evs["flex"][k])
        edis = [
            {"case_id": k[0], "event_index": k[1], "default": evs["default"][k], "flex": evs["flex"][k]}
            for k in sorted(ec)
            if evs["default"][k] != evs["flex"][k]
        ]
        report["event_identities_common"] = len(ec)
        report["event_agreements"] = eagree
        report["event_agreement_rate"] = eagree / len(ec) if ec else None
        report["event_disagreements"] = len(edis)
        report["event_transition_counts"] = dict(
            Counter(f"{d['default']}->{d['flex']}" for d in edis).most_common()
        )
        report["event_disagreement_examples"] = edis[:15]

    # --- tokens / cost from meta ---
    report["meta"] = metas
    if "default" in metas and "flex" in metas:
        for f in ("prompt_tokens", "completion_tokens", "provider_calls", "errors", "cases_written"):
            d, x = metas["default"].get(f), metas["flex"].get(f)
            report[f"delta_{f}"] = {
                "default": d,
                "flex": x,
                "abs_delta": (x - d) if isinstance(d, (int, float)) and isinstance(x, (int, float)) else None,
                "pct_delta": (round(100.0 * (x - d) / d, 4) if isinstance(d, (int, float)) and d else None),
            }
        # Bedrock pricing: in $0.0002/1K? Task states output flex 0.0002/1K vs 0.0004/1K std.
        for tier in ("default", "flex"):
            pt = metas[tier].get("prompt_tokens", 0)
            ct = metas[tier].get("completion_tokens", 0)
            out_rate = 0.0002 if tier == "flex" else 0.0004
            report[f"cost_est_{tier}_usd_output_only"] = round(ct / 1000.0 * out_rate, 6)
            report[f"tokens_{tier}"] = {"prompt": pt, "completion": ct}

    # --- duration ---
    tf = OUT / "timing.txt"
    if tf.exists():
        report["wall_clock_timing_txt"] = tf.read_text().strip().splitlines()
    for tier, p in paths.items():
        rows = read_rows(p)
        durs = [r.get("duration_ms", 0) for r in rows if isinstance(r.get("duration_ms"), (int, float))]
        if durs:
            durs_sorted = sorted(durs)
            report[f"per_case_duration_ms_{tier}"] = {
                "n": len(durs),
                "sum_s": round(sum(durs) / 1000.0, 2),
                "mean": round(sum(durs) / len(durs), 1),
                "median": round(durs_sorted[len(durs_sorted) // 2], 1),
                "p95": round(durs_sorted[int(len(durs_sorted) * 0.95) - 1], 1),
                "max": round(max(durs), 1),
            }

    print(json.dumps(report, indent=2, sort_keys=False))


if __name__ == "__main__":
    main()
