"""G2b: same weights, same placement, only the attention kernel changes.

The first G2 pass reloaded the checkpoint once per attention implementation. For the
26B that means reloading under accelerate's device map, and the CPU/GPU split (hence
the bf16 reduction order) is free to differ between loads -- which showed up as a
~1e-3 floor on *every* pair, including eager vs math-only SDPA, two paths that compute
the same thing. That floor is a placement artifact, not an attention finding.

This variant loads the checkpoint once and switches `attn_implementation` in place, so
weights, device placement and prompt tokens are byte-identical across the three paths
and the only difference is the kernel. It also re-runs each mode twice to measure the
run-to-run floor of the configuration itself, which is the yardstick any cross-kernel
difference has to beat.
"""

import argparse
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


def pick_prompts(tokenizer, bands, per_band):
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
            for band in bands:
                low, high = band
                if low <= len(ids) < high and len(found[band]) < per_band:
                    found[band].append({"case_id": row["case_id"], "event_index": row["event_index"],
                                        "tokens": len(ids), "band": f"{low}-{high}", "ids": ids,
                                        "labels": rendered.labels})
                    break
    return [p for band in bands for p in found[band]]


def forward_all(model, prompts, mode, device):
    rows = []
    for prompt in prompts:
        ids = torch.tensor([prompt["ids"]], device=device)
        with torch.inference_mode():
            if mode == "sdpa_math":
                with sdpa_kernel(SDPBackend.MATH):
                    logits = model(input_ids=ids, use_cache=False, logits_to_keep=1).logits[0, -1].float()
            else:
                logits = model(input_ids=ids, use_cache=False, logits_to_keep=1).logits[0, -1].float()
        rows.append(logits.cpu())
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--device-map")
    parser.add_argument("--max-gpu-memory")
    parser.add_argument("--stress", action="store_true")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    path = snapshot(args.repo)
    tokenizer = AutoTokenizer.from_pretrained(path, local_files_only=True)
    config = AutoConfig.from_pretrained(path, local_files_only=True)
    text_config = config.get_text_config() if hasattr(config, "get_text_config") else config
    window = getattr(text_config, "sliding_window", None)
    bands = ([(1024, 1200), (1200, 1500), (1500, 2100), (2100, 3000), (3000, 4096)] if args.stress
             else [(200, 480), (480, 560), (560, 900), (900, 1100), (1500, 2100), (2100, 4096)])
    prompts = pick_prompts(tokenizer, bands, 4 if args.stress else 2)

    torch.backends.cuda.matmul.allow_tf32 = False
    options = dict(local_files_only=True, dtype=torch.bfloat16, attn_implementation="eager")
    if args.device_map:
        options["device_map"] = args.device_map
        if args.max_gpu_memory:
            options["max_memory"] = {i: args.max_gpu_memory for i in range(torch.cuda.device_count())}
            options["max_memory"]["cpu"] = "300GiB"
    model = AutoModelForCausalLM.from_pretrained(path, **options).eval()
    if not args.device_map:
        model = model.to("cuda")
    device = next(p.device for p in model.parameters() if p.device.type == "cuda")
    placement = None
    if getattr(model, "hf_device_map", None):
        from collections import Counter
        placement = dict(Counter(str(v) for v in model.hf_device_map.values()))

    label_ids = {}
    for label in prompts[0]["labels"]:
        ids = tokenizer(label, add_special_tokens=False)["input_ids"]
        label_ids[label] = ids[0] if len(ids) == 1 else None
    candidates = [v for v in label_ids.values() if v is not None]

    runs = {}
    for mode in ("eager", "sdpa", "sdpa_math", "eager_repeat", "sdpa_repeat"):
        implementation = "eager" if mode.startswith("eager") else "sdpa"
        model.set_attn_implementation(implementation)
        assert model.config._attn_implementation == implementation, model.config._attn_implementation
        runs[mode] = forward_all(model, prompts, "sdpa_math" if mode == "sdpa_math" else implementation, device)

    pairs = [("eager", "eager_repeat"), ("sdpa", "sdpa_repeat"), ("eager", "sdpa"),
             ("eager", "sdpa_math"), ("sdpa", "sdpa_math")]
    report = {"repo": args.repo, "revision": PINS[args.repo], "sliding_window": window,
              "tolerance": TOLERANCE, "torch": torch.__version__, "gpu": torch.cuda.get_device_name(0),
              "dtype": "bfloat16", "device_map": args.device_map, "max_gpu_memory": args.max_gpu_memory,
              "placement": placement, "single_load_attention_switch": True,
              "prompt_token_counts": [p["tokens"] for p in prompts],
              "prompts_crossing_window": sum(bool(window and p["tokens"] > window) for p in prompts),
              "label_token_ids": label_ids, "prompts": [], "worst": {}}
    worst = {}
    for index, prompt in enumerate(prompts):
        entry = {k: prompt[k] for k in ("case_id", "event_index", "tokens", "band")}
        entry["crosses_window"] = bool(window and prompt["tokens"] > window)
        for left, right in pairs:
            a, b = runs[left][index], runs[right][index]
            cand_a, cand_b = a[candidates], b[candidates]
            key = f"{left}_vs_{right}"
            entry[key] = {
                "max_abs_logit_diff_full_vocab": float((a - b).abs().max()),
                "max_abs_logit_diff_candidates": float((cand_a - cand_b).abs().max()),
                "max_abs_label_probability_diff": float(
                    (torch.softmax(cand_a, -1) - torch.softmax(cand_b, -1)).abs().max()),
                "argmax_candidate_agrees": int(cand_a.argmax()) == int(cand_b.argmax()),
                "argmax_full_vocab_agrees": int(a.argmax()) == int(b.argmax()),
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
    floor = max(worst["eager_vs_eager_repeat"]["max_abs_label_probability_diff"],
                worst["sdpa_vs_sdpa_repeat"]["max_abs_label_probability_diff"])
    report["same_config_repeat_floor"] = floor
    report["verdict"] = {
        key: {"within_tolerance": slot["max_abs_label_probability_diff"] < TOLERANCE
              and slot["argmax_candidate_disagreements"] == 0,
              "above_repeat_floor": slot["max_abs_label_probability_diff"] > floor}
        for key, slot in worst.items()}
    report["eager_required"] = not report["verdict"]["eager_vs_sdpa"]["within_tolerance"]
    print(json.dumps(report, indent=2))
    Path(args.out).write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
