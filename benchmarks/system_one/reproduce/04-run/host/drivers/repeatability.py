#!/usr/bin/env python3
"""Three-way run-to-run stability (flip rate) for Jev / OpenJev / DiffusionGemma.

All three models have three repeat runs on the identical 200-case corpus at C7/I3/Q2
(1,519 decisions each), so this needs no new inference. Reports the corpus-wide flip rate
and the flagged-only flip rate, which is the figure that matters operationally: instability
on traffic the model already wants to escalate.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

DATA = Path("$WORK/.system-one-data/outputs")
REPEAT = DATA / "repeat"
MODELS = {
    "jev": ("Jev (hosted jev-1.13.0)", ["jev-r1.jsonl", "jev-r2.jsonl", "jev-r3.jsonl"]),
    "openjev": ("OpenJev", ["openjev-r1.jsonl", "openjev-r2.jsonl", "openjev-r3.jsonl"]),
    "diffusiongemma": ("DiffusionGemma",
                       ["diffgemma-r1.jsonl", "diffgemma-r2.jsonl", "diffgemma-r3.jsonl"]),
}
FLAGGED = {"confirm", "block"}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def settled(pred: Path) -> dict:
    meta = json.loads(Path(str(pred) + ".meta.json").read_text())
    if meta.get("complete") is not True:
        raise RuntimeError(f"{pred.name}: meta complete is not true")
    if sha256_file(pred) != meta.get("prediction_sha256"):
        raise RuntimeError(f"{pred.name}: on-disk sha256 != meta.prediction_sha256")
    return meta


def load(pred: Path) -> dict[tuple[str, int], str]:
    out: dict[tuple[str, int], str] = {}
    with pred.open() as handle:
        for line in handle:
            row = json.loads(line)
            out[(row["case_id"], int(row.get("event_index", -1)))] = str(row.get("action", "error"))
    return out


def main() -> int:
    report = {
        "schema_version": "1",
        "kind": "defenseclaw-system-one-three-way-repeatability",
        "corpus": str(REPEAT),
        "grid": "C7/I3/Q2",
        "runs_per_model": 3,
        "definitions": {
            "corpus_wide_flip_rate":
                "share of (case_id, event_index) decisions whose action is not identical across "
                "all three repeat runs",
            "flagged_only_flip_rate":
                "same, restricted to decisions that at least one run flagged (confirm or block); "
                "this is the operational figure - instability on traffic the model wants to act on",
            "unanimous_rate": "share of decisions where all three runs agree",
        },
        "models": {},
        "within_run_repeatability": {},
        "two_measures_are_different": (
            "benchmark_score_system_one.repeatability() is a WITHIN-run measure: it groups rows by "
            "request_sha256 and only sees request bodies that happen to recur inside a single run "
            "(e.g. C0 and C1 render identically when intent is absent). It answers 'same bytes, same "
            "run, different action?'. The per-model table above is the ACROSS-run measure: the same "
            "corpus submitted three separate times, which is what a repeat-run flip-rate chart needs. "
            "They are not interchangeable and the within-run figure must not be plotted as a "
            "repeat-run flip rate."),
    }
    lines: list[str] = []
    lines.append("=" * 104)
    lines.append("Run-to-run stability, three repeat runs per model, identical corpus and grid "
                 "(C7/I3/Q2)")
    lines.append("=" * 104)

    for key, (label, names) in MODELS.items():
        paths = [REPEAT / n for n in names]
        metas = []
        try:
            metas = [settled(p) for p in paths]
        except (RuntimeError, FileNotFoundError) as exc:
            report["models"][key] = {"label": label, "available": False, "reason": str(exc)}
            continue
        maps = [load(p) for p in paths]
        keys = set(maps[0])
        for m in maps[1:]:
            keys &= set(m)
        total = len(keys)
        flips = 0
        flagged_keys = 0
        flagged_flips = 0
        transition = Counter()
        per_run_actions = [Counter(m[k] for k in keys) for m in maps]
        for decision in keys:
            actions = [m[decision] for m in maps]
            unanimous = len(set(actions)) == 1
            if not unanimous:
                flips += 1
                transition["|".join(sorted(set(actions)))] += 1
            if any(a in FLAGGED for a in actions):
                flagged_keys += 1
                if not unanimous:
                    flagged_flips += 1
        report["models"][key] = {
            "label": label,
            "available": True,
            "model_revision": metas[0].get("model_revision"),
            "runs": [{"path": str(p), "requests": m.get("requests"),
                      "prediction_sha256": m.get("prediction_sha256"),
                      "estimated_usd": m.get("estimated_usd")}
                     for p, m in zip(paths, metas)],
            "decisions_compared": total,
            "corpus_wide_flips": flips,
            "corpus_wide_flip_rate": round(flips / total, 8) if total else None,
            "unanimous_rate": round((total - flips) / total, 8) if total else None,
            "flagged_decisions": flagged_keys,
            "flagged_only_flips": flagged_flips,
            "flagged_only_flip_rate": round(flagged_flips / flagged_keys, 8) if flagged_keys else None,
            "flip_action_sets": dict(sorted(transition.items())),
            "per_run_action_counts": [dict(sorted(c.items())) for c in per_run_actions],
        }

    lines.append("")
    lines.append(f"{'model':<28}{'decisions':>10}{'flips':>8}{'corpusFlipRate':>16}"
                 f"{'flaggedDec':>12}{'flaggedFlips':>14}{'flaggedFlipRate':>17}")
    for key, entry in report["models"].items():
        if not entry.get("available"):
            lines.append(f"{entry['label'][:27]:<28}  UNAVAILABLE: {entry['reason']}")
            continue
        lines.append(
            f"{entry['label'][:27]:<28}{entry['decisions_compared']:>10}"
            f"{entry['corpus_wide_flips']:>8}{entry['corpus_wide_flip_rate']:>16.6f}"
            f"{entry['flagged_decisions']:>12}{entry['flagged_only_flips']:>14}"
            f"{(entry['flagged_only_flip_rate'] if entry['flagged_only_flip_rate'] is not None else 0):>17.6f}")
    lines.append("")
    lines.append("Per-run action counts (run1 / run2 / run3):")
    for key, entry in report["models"].items():
        if not entry.get("available"):
            continue
        lines.append(f"  {entry['label']}")
        for index, counts in enumerate(entry["per_run_action_counts"], start=1):
            lines.append(f"    r{index}: {counts}")
        if entry["flip_action_sets"]:
            lines.append(f"    flip action sets: {entry['flip_action_sets']}")
    # Jev-only deep estimate over every replicate that exists (r1..rN). Not like-for-like with
    # the 3-run table above, which is why it is reported separately.
    deep_paths = []
    index = 1
    while (REPEAT / f"jev-r{index}.jsonl").exists():
        candidate = REPEAT / f"jev-r{index}.jsonl"
        try:
            settled(candidate)
            deep_paths.append(candidate)
        except (RuntimeError, FileNotFoundError):
            pass
        index += 1
    if len(deep_paths) > 3:
        maps = [load(p) for p in deep_paths]
        keys = set(maps[0])
        for m in maps[1:]:
            keys &= set(m)
        total = len(keys)
        flips = flagged_keys = flagged_flips = 0
        for decision in keys:
            actions = [m[decision] for m in maps]
            unanimous = len(set(actions)) == 1
            if not unanimous:
                flips += 1
            if any(a in FLAGGED for a in actions):
                flagged_keys += 1
                if not unanimous:
                    flagged_flips += 1
        report["jev_deep_repeatability"] = {
            "replicates": len(deep_paths),
            "runs": [p.name for p in deep_paths],
            "decisions_compared": total,
            "corpus_wide_flips": flips,
            "corpus_wide_flip_rate": round(flips / total, 8) if total else None,
            "flagged_decisions": flagged_keys,
            "flagged_only_flips": flagged_flips,
            "flagged_only_flip_rate": (round(flagged_flips / flagged_keys, 8)
                                       if flagged_keys else None),
            "note": ("Jev-only, more replicates than the other two models have, so NOT "
                     "like-for-like with the three-way table; reported to tighten the estimate "
                     "for the only non-deterministic model of the three"),
        }
        d = report["jev_deep_repeatability"]
        lines.append("")
        lines.append("-" * 104)
        lines.append(f"JEV-ONLY DEEP ESTIMATE over {d['replicates']} replicates "
                     f"(not like-for-like: the other models have 3)")
        lines.append("-" * 104)
        lines.append(f"  decisions {d['decisions_compared']}  corpus-wide flips "
                     f"{d['corpus_wide_flips']} ({d['corpus_wide_flip_rate']:.6f})")
        lines.append(f"  flagged decisions {d['flagged_decisions']}  flagged flips "
                     f"{d['flagged_only_flips']} ({d['flagged_only_flip_rate']:.6f})")

    # within-run figure, for contrast, straight out of the large-stage scorecards
    scores = DATA / "jev-parity/scores"
    for stage, arms in (("s2", {"jev": "s2__jev__jev-C7.json",
                                "openjev": "s2__openjev__openjev-final.json",
                                "diffusiongemma": "s2__diffusiongemma__diffgemma-q2.json"}),
                        ("s3", {"jev": "s3__jev__jev-C7.json",
                                "openjev": "s3__openjev__openjev-full.json",
                                "diffusiongemma": "s3__diffusiongemma__diffgemma-q2.json"})):
        report["within_run_repeatability"][stage] = {}
        for model, name in arms.items():
            card_path = scores / name
            if not card_path.exists():
                continue
            rep = json.loads(card_path.read_text()).get("repeatability", {})
            report["within_run_repeatability"][stage][model] = rep
    lines.append("")
    lines.append("-" * 104)
    lines.append("WITHIN-RUN duplicate-request flip rate (a DIFFERENT measure - see note below)")
    lines.append("-" * 104)
    lines.append(f"{'stage':<8}{'model':<20}{'distinctReq':>12}{'repeatedReq':>13}"
                 f"{'flippedReq':>12}{'withinRunFlipRate':>19}")
    for stage, models in report["within_run_repeatability"].items():
        for model, rep in models.items():
            rate = rep.get("flip_rate")
            lines.append(f"{stage:<8}{model:<20}{rep.get('distinct_requests', 0):>12}"
                         f"{rep.get('repeated_requests', 0):>13}{rep.get('flipped_requests', 0):>12}"
                         f"{(rate if rate is not None else 0):>19.8f}")
    lines.append("")
    lines.append("NOTE: the within-run figure only sees request bodies that happen to recur inside a")
    lines.append("single run, so it is NOT a repeat-run flip rate and must not be plotted as one.")
    lines.append("The across-run table at the top is the repeat-run measure.")
    lines.append("")
    lines.append("All three models are compared on the same decisions, same corpus and the same "
                 "C7/I3/Q2 grid, so this table is like-for-like.")

    (REPEAT / "three-way-repeatability.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n")
    (REPEAT / "three-way-repeatability.txt").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    print(f"\nwrote {REPEAT / 'three-way-repeatability.json'} and .txt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
