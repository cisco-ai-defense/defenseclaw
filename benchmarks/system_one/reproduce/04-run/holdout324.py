"""Evaluate a Gemma 4 checkpoint on the 324-item Nimble/Jev holdout, with G3 built in.

Reuses the published accounting so the numbers are directly comparable with the
existing evidence artifact (Qwen3.5-9B 215/324, Bespoke-Nimble-9B 292/324,
Jev 1.13.0 302/324): nimble.evaluation.evaluate_pilot.assess decides correctness,
NLL and Brier from a normalized distribution over the declared candidates.

Prompt and readout are jevify's own (prompting.render + label-token mass), matching
how the adapter under test was trained. attn_implementation defaults to eager per G2
and enable_thinking is pinned False with a tail-token assertion per G1.

G3 (position bias): --permute reverse reverses the presented order of every Choice's
options, so option content keeps its key while its letter code changes. Accuracy that
tracks the letter rather than the content is a broken readout. Score levels are left
alone because their prompt asserts a low-to-high ordering, so reordering them would
change the question rather than just the label.
"""

import argparse
import gc
import hashlib
import json
import math
import sys
import time
from collections import Counter
from pathlib import Path

import torch

sys.path.insert(0, "$WORK/sysone/nimble")
sys.path.insert(0, "$WORK/g4j/jevify/src")
sys.path.insert(0, "$WORK/g4j")

from gemma4_jev_shim import Gemma4JevPredictor, normalize_questions, serialize  # noqa: E402
from jevify.prompting import render  # noqa: E402
from jevify.questions import Choice, Noul, Score  # noqa: E402
from nimble.evaluation.evaluate_pilot import assess  # noqa: E402

HUB = Path("/opt/dlami/nvme/hf/hub")
PINS = json.loads(Path("$WORK/g4j/pins.json").read_text())
DATA = Path("$WORK/sysone/nimble/data/eval.jsonl")


def snapshot(repo_id):
    return HUB / ("models--" + repo_id.replace("/", "--")) / "snapshots" / PINS[repo_id]


def permute_question(question, mode):
    if mode == "none" or not isinstance(question, Choice):
        return question, None
    keys = list(question.criteria)
    order = list(reversed(range(len(keys))))
    criteria = {keys[i]: question.criteria[keys[i]] for i in order}
    return Choice(instructions=question.instructions, criteria=criteria), order


def ece_from(records, bins=15):
    edges = [i / bins for i in range(bins + 1)]
    total = len(records)
    if not total:
        return None
    value = 0.0
    for low, high in zip(edges[:-1], edges[1:]):
        chosen = [r for r in records if low < r["top_probability"] <= high]
        if not chosen:
            continue
        weight = len(chosen) / total
        accuracy = sum(r["correct"] for r in chosen) / len(chosen)
        confidence = sum(r["top_probability"] for r in chosen) / len(chosen)
        value += weight * abs(accuracy - confidence)
    return value


def summarize(rows):
    out = {}
    for kind in ("all", "choice", "noul", "score"):
        chosen = [r for r in rows if kind == "all" or r["kind"] == kind]
        if not chosen:
            continue
        group = {"count": len(chosen), "correct": sum(r["correct"] for r in chosen)}
        group["accuracy"] = group["correct"] / group["count"]
        group["mean_nll"] = sum(r["nll"] for r in chosen) / len(chosen)
        group["mean_brier"] = sum(r["brier"] for r in chosen) / len(chosen)
        group["mean_top_probability"] = sum(r["top_probability"] for r in chosen) / len(chosen)
        group["mean_reference_probability"] = sum(r["reference_probability"] for r in chosen) / len(chosen)
        group["ece_15bin"] = ece_from(chosen)
        group["mean_label_mass"] = sum(r["label_mass"] for r in chosen) / len(chosen)
        group["min_label_mass"] = min(r["label_mass"] for r in chosen)
        out[kind] = group
    out["by_family"] = {}
    for family in sorted({r["family"] for r in rows}):
        chosen = [r for r in rows if r["family"] == family]
        out["by_family"][family] = {"count": len(chosen), "correct": sum(r["correct"] for r in chosen),
                                    "accuracy": sum(r["correct"] for r in chosen) / len(chosen)}
    out["selected_letter_counts"] = dict(sorted(Counter(r["selected_letter"] for r in rows).items()))
    out["selected_letter_counts_choice"] = dict(
        sorted(Counter(r["selected_letter"] for r in rows if r["kind"] == "choice").items()))
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--attention", default="eager", choices=["eager", "sdpa"])
    parser.add_argument("--device-map")
    parser.add_argument("--max-gpu-memory")
    parser.add_argument("--temperature", type=float, default=1.0)
    parser.add_argument("--permute", default="none", choices=["none", "reverse"])
    parser.add_argument("--prefix-cache", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()

    raw = DATA.read_bytes()
    rows = [json.loads(line) for line in raw.decode().splitlines() if line.strip()]
    if len(rows) != 324 or len({r["id"] for r in rows}) != 324:
        raise ValueError("expected the 324-row holdout with unique ids")

    output = Path(args.out_dir)
    output.mkdir(parents=True, exist_ok=True)
    settings = {
        "repo": args.repo, "revision": PINS[args.repo], "name": args.name,
        "dataset": str(DATA), "dataset_sha256": hashlib.sha256(raw).hexdigest(), "count": len(rows),
        "attention": args.attention, "device_map": args.device_map, "max_gpu_memory": args.max_gpu_memory,
        "temperature": args.temperature, "permute": args.permute,
        "prefix_cache": args.prefix_cache,
        "prompt": "jevify.prompting.render, enable_thinking=False",
        "readout": "full-vocabulary softmax, label-token mass, renormalized over candidates",
        "accounting": "nimble.evaluation.evaluate_pilot.assess",
    }
    settings_path, progress_path = output / "settings.json", output / "rows.jsonl"
    if settings_path.exists() and json.loads(settings_path.read_text()) != settings:
        raise ValueError("existing settings differ; use a new output directory")
    settings_path.write_text(json.dumps(settings, indent=2) + "\n")
    saved = [json.loads(l) for l in progress_path.read_text().splitlines() if l.strip()] if progress_path.exists() else []
    if [r["id"] for r in saved] != [r["id"] for r in rows[:len(saved)]]:
        raise ValueError("saved progress does not match dataset order")

    predictor = None
    if len(saved) < len(rows):
        predictor = Gemma4JevPredictor(
            snapshot(args.repo), args.repo, PINS[args.repo], args.name, attention=args.attention,
            device_map=args.device_map, max_gpu_memory=args.max_gpu_memory,
            temperature=args.temperature, weight_digests=True, prefix_cache=args.prefix_cache)

    started = time.perf_counter()
    try:
        with progress_path.open("a") as stream:
            for row in rows[len(saved):]:
                if list(row["input"]["questions"]) != ["decision"]:
                    raise ValueError("expected one decision question per row")
                question = normalize_questions(row["input"]["questions"])["decision"]
                kind = row["input"]["questions"]["decision"]["type"]
                question, order = permute_question(question, args.permute)
                state = row["input"]["state"]
                rendered = render(state, question)
                ids = predictor._encode(rendered.messages)
                tick = time.perf_counter()
                logprobs, shared = predictor._next_token_logprobs(ids)
                probabilities, mass = predictor._label_probabilities(logprobs, rendered.labels)
                elapsed = time.perf_counter() - tick
                # map back to the dataset's own candidate keys, whatever order was presented
                if isinstance(question, Noul):
                    keyed = {"false": probabilities[rendered.keys.index("no")],
                             "true": probabilities[rendered.keys.index("yes")]}
                else:
                    keyed = dict(zip(rendered.keys, probabilities))
                result = assess(keyed, row["reference"]["target"], kind)
                letter = rendered.labels[max(range(len(probabilities)), key=probabilities.__getitem__)]
                record = {
                    "id": row["id"], "kind": kind, "family": row["source_family"], "domain": row["domain"],
                    "target": row["reference"]["target"], "prediction": result["prediction"],
                    "correct": result["correct"], "probabilities": keyed,
                    "reference_probability": result["reference_probability"],
                    "top_probability": result["top_probability"],
                    "nll": result["negative_log_likelihood"], "brier": result["multiclass_brier"],
                    "selected_letter": letter, "presented_order": order,
                    "label_mass": mass, "prompt_tokens": len(ids), "cached_prefix_tokens": shared,
                    "elapsed_seconds": elapsed,
                }
                if kind == "score":
                    record["expected_score"] = result["expected_score"]
                    record["score_absolute_error"] = result["absolute_score_error"]
                stream.write(json.dumps(record, ensure_ascii=False, allow_nan=False) + "\n")
                stream.flush()
                saved.append(record)
                if len(saved) % 25 == 0 or len(saved) == len(rows):
                    print(f"{args.name}: {len(saved)}/{len(rows)} ({time.perf_counter() - started:.0f}s)", flush=True)
    finally:
        if predictor is not None:
            provenance = predictor.provenance
            del predictor
            gc.collect()
            torch.cuda.empty_cache()
        else:
            provenance = None

    report = {"settings": settings, "provenance": provenance,
              "wall_seconds": time.perf_counter() - started,
              "median_seconds_per_item": sorted(r["elapsed_seconds"] for r in saved)[len(saved) // 2],
              "total_prompt_tokens": sum(r["prompt_tokens"] for r in saved),
              "summary": summarize(saved)}
    (output / "results.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps(report["summary"], indent=2))


if __name__ == "__main__":
    main()
