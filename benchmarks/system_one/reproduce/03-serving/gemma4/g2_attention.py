"""G2 (BLOCKING): eager vs SDPA vs math-only SDPA logit agreement across the sliding window.

Nimble's own scorer forces attn_implementation="eager" for Gemma because Torch's
optimized CUDA SDPA produced incorrect Gemma outputs once prompts crossed the
512-token sliding window (nimble/scoring/cuda_scorer.py:84). Gemma 4 E2B keeps a
512-token window and 26B-A4B a 1024-token window, and the measured C7/I3/Q2
prompts straddle both. This runs the same prompt under all three attention paths
and compares the answer-position logits. Nothing else may be reported until the
comparison is inside the tolerance, or the eager-only conclusion is recorded.
"""

import argparse
import gc
import json
import sys
from pathlib import Path

import torch
from torch.nn.attention import SDPBackend, sdpa_kernel
from transformers import AutoConfig, AutoModelForCausalLM, AutoTokenizer

sys.path.insert(0, "$WORK/g4j/jevify/src")
from jevify.prompting import render  # noqa: E402
from jevify.questions import question_from_dict  # noqa: E402

HUB = Path("/opt/dlami/nvme/hf/hub")
PINS = json.loads(Path("$WORK/g4j/pins.json").read_text())
REQUESTS = Path("/opt/dlami/nvme/s2-requests-all.jsonl")
TOLERANCE = 1e-3


def snapshot(repo_id):
    return HUB / ("models--" + repo_id.replace("/", "--")) / "snapshots" / PINS[repo_id]


def serialize(value):
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)


def normalize_question(definition):
    definition = dict(definition)
    definition["instructions"] = serialize(definition.get("instructions"))
    criteria = definition.get("criteria")
    if isinstance(criteria, dict):
        definition["criteria"] = {k: (serialize(v) if v is not None else None) for k, v in criteria.items()}
    elif isinstance(criteria, list):
        definition["criteria"] = [serialize(v) for v in criteria]
    return question_from_dict(definition)


def pick_prompts(tokenizer, bands, per_band=2):
    """Real C7/I3/Q2 disposition prompts whose token length lands in each band."""
    found = {band: [] for band in bands}
    with REQUESTS.open() as stream:
        for line in stream:
            if all(len(v) >= per_band for v in found.values()):
                break
            row = json.loads(line)
            question = normalize_question(row["questions"]["disposition"])
            rendered = render(row["state"], question)
            text = tokenizer.apply_chat_template(
                rendered.messages, tokenize=False, add_generation_prompt=True, enable_thinking=False)
            ids = tokenizer(text, add_special_tokens=False)["input_ids"]
            n = len(ids)
            for band in bands:
                low, high = band
                if low <= n < high and len(found[band]) < per_band:
                    found[band].append({"case_id": row["case_id"], "event_index": row["event_index"],
                                        "tokens": n, "band": f"{low}-{high}", "ids": ids,
                                        "labels": rendered.labels})
                    break
    return [p for band in bands for p in found[band]]


def label_token_ids(tokenizer, labels):
    out = {}
    for label in labels:
        ids = tokenizer(label, add_special_tokens=False)["input_ids"]
        out[label] = ids[0] if len(ids) == 1 else None
    return out


def run(repo_id, prompts, device_map, max_gpu_memory, dtype=torch.bfloat16):
    path = snapshot(repo_id)
    results = {}
    for mode in ("eager", "sdpa", "sdpa_math"):
        implementation = "eager" if mode == "eager" else "sdpa"
        options = dict(local_files_only=True, dtype=dtype, attn_implementation=implementation)
        if device_map:
            options["device_map"] = device_map
            if max_gpu_memory:
                options["max_memory"] = {index: max_gpu_memory for index in range(torch.cuda.device_count())}
                options["max_memory"]["cpu"] = "300GiB"
        model = AutoModelForCausalLM.from_pretrained(path, **options)
        model = model.eval()
        if not device_map:
            model = model.to("cuda")
        rows = []
        for prompt in prompts:
            ids = torch.tensor([prompt["ids"]], device=next(p.device for p in model.parameters() if p.device.type == "cuda"))
            with torch.inference_mode():
                if mode == "sdpa_math":
                    with sdpa_kernel(SDPBackend.MATH):
                        logits = model(input_ids=ids, use_cache=False, logits_to_keep=1).logits[0, -1].float()
                else:
                    logits = model(input_ids=ids, use_cache=False, logits_to_keep=1).logits[0, -1].float()
            rows.append(logits.cpu())
        results[mode] = rows
        del model
        gc.collect()
        torch.cuda.empty_cache()
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--device-map")
    parser.add_argument("--max-gpu-memory")
    parser.add_argument("--out", required=True)
    parser.add_argument("--stress", action="store_true",
                        help="weight prompt selection above the sliding window, 4 per band")
    args = parser.parse_args()

    path = snapshot(args.repo)
    tokenizer = AutoTokenizer.from_pretrained(path, local_files_only=True)
    config = AutoConfig.from_pretrained(path, local_files_only=True)
    text_config = config.get_text_config() if hasattr(config, "get_text_config") else config
    window = getattr(text_config, "sliding_window", None)
    if args.stress:
        bands = [(1024, 1200), (1200, 1500), (1500, 2100), (2100, 3000), (3000, 4096)]
        prompts = pick_prompts(tokenizer, bands, per_band=4)
    else:
        bands = [(200, 480), (480, 560), (900, 1100), (1500, 2100), (2100, 4096)]
        prompts = pick_prompts(tokenizer, bands)
    ids_by_label = label_token_ids(tokenizer, prompts[0]["labels"])
    candidates = [v for v in ids_by_label.values() if v is not None]

    results = run(args.repo, prompts, args.device_map, args.max_gpu_memory)

    report = {"repo": args.repo, "revision": PINS[args.repo], "sliding_window": window,
              "tolerance": TOLERANCE, "torch": torch.__version__,
              "gpu": torch.cuda.get_device_name(0), "dtype": "bfloat16",
              "label_token_ids": ids_by_label, "device_map": args.device_map,
              "max_gpu_memory": args.max_gpu_memory, "prompts": [], "worst": {}}
    worst = {}
    for index, prompt in enumerate(prompts):
        entry = {k: prompt[k] for k in ("case_id", "event_index", "tokens", "band")}
        entry["crosses_window"] = bool(window and prompt["tokens"] > window)
        for pair in (("eager", "sdpa"), ("eager", "sdpa_math"), ("sdpa", "sdpa_math")):
            a, b = results[pair[0]][index], results[pair[1]][index]
            full = float((a - b).abs().max())
            cand_a, cand_b = a[candidates], b[candidates]
            cand = float((cand_a - cand_b).abs().max())
            pa = torch.softmax(cand_a, dim=-1)
            pb = torch.softmax(cand_b, dim=-1)
            key = f"{pair[0]}_vs_{pair[1]}"
            entry[key] = {
                "max_abs_logit_diff_full_vocab": full,
                "max_abs_logit_diff_candidates": cand,
                "max_abs_label_probability_diff": float((pa - pb).abs().max()),
                "argmax_full_vocab_agrees": int(a.argmax()) == int(b.argmax()),
                "argmax_candidate_agrees": int(cand_a.argmax()) == int(cand_b.argmax()),
            }
            slot = worst.setdefault(key, {"max_abs_logit_diff_full_vocab": 0.0,
                                         "max_abs_logit_diff_candidates": 0.0,
                                         "max_abs_label_probability_diff": 0.0,
                                         "argmax_candidate_disagreements": 0,
                                         "argmax_full_vocab_disagreements": 0})
            for metric in ("max_abs_logit_diff_full_vocab", "max_abs_logit_diff_candidates",
                           "max_abs_label_probability_diff"):
                slot[metric] = max(slot[metric], entry[key][metric])
            slot["argmax_candidate_disagreements"] += not entry[key]["argmax_candidate_agrees"]
            slot["argmax_full_vocab_disagreements"] += not entry[key]["argmax_full_vocab_agrees"]
        report["prompts"].append(entry)
    report["worst"] = worst
    report["prompt_token_counts"] = [p["tokens"] for p in prompts]
    report["prompts_crossing_window"] = sum(bool(window and p["tokens"] > window) for p in prompts)
    report["verdict"] = {
        key: {"within_tolerance": slot["max_abs_label_probability_diff"] < TOLERANCE
              and slot["argmax_candidate_disagreements"] == 0}
        for key, slot in worst.items()
    }
    report["eager_required"] = not report["verdict"]["eager_vs_sdpa"]["within_tolerance"]
    print(json.dumps(report, indent=2))
    Path(args.out).write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
