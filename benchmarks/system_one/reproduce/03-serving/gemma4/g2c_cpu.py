"""G2c: adjudicate eager vs SDPA on Gemma 4 26B-A4B against a CPU reference.

On E2B, eager and math-only SDPA agree and the optimized CUDA SDPA is the outlier, so
eager is clearly the correct path there. On 26B-A4B every SDPA variant disagrees with
eager on window-crossing prompts while same-config repeats are bit-identical, so the
difference is structural and one of the two paths is wrong. A CPU forward settles it:
CPU has no fused attention kernel, so the CPU eager result is the reference.

CPU only -- it takes no GPU and cannot disturb the neighbouring servers.
"""

import argparse
import json
import sys
import time
from pathlib import Path

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

sys.path.insert(0, "$WORK/g4j/jevify/src")
from jevify.prompting import render  # noqa: E402
from jevify.questions import question_from_dict  # noqa: E402

HUB = Path("/opt/dlami/nvme/hf/hub")
PINS = json.loads(Path("$WORK/g4j/pins.json").read_text())
REQUESTS = Path("/opt/dlami/nvme/s2-requests-all.jsonl")


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--low", type=int, default=1024)
    parser.add_argument("--high", type=int, default=1120)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    path = snapshot(args.repo)
    tokenizer = AutoTokenizer.from_pretrained(path, local_files_only=True)
    prompts = []
    with REQUESTS.open() as stream:
        for line in stream:
            if len(prompts) >= args.count:
                break
            row = json.loads(line)
            rendered = render(row["state"], normalize_question(row["questions"]["disposition"]))
            text = tokenizer.apply_chat_template(
                rendered.messages, tokenize=False, add_generation_prompt=True, enable_thinking=False)
            ids = tokenizer(text, add_special_tokens=False)["input_ids"]
            if args.low <= len(ids) < args.high:
                prompts.append({"case_id": row["case_id"], "tokens": len(ids), "ids": ids,
                                "labels": rendered.labels})
    if not prompts:
        raise SystemExit("no prompt in the requested band")

    candidates = [tokenizer(l, add_special_tokens=False)["input_ids"][0] for l in prompts[0]["labels"]]
    torch.set_num_threads(torch.get_num_threads())
    results = {}
    for mode in ("eager", "sdpa"):
        started = time.perf_counter()
        model = AutoModelForCausalLM.from_pretrained(
            path, local_files_only=True, dtype=torch.float32, attn_implementation=mode,
            device_map={"": "cpu"}).eval()
        rows = []
        for prompt in prompts:
            ids = torch.tensor([prompt["ids"]])
            with torch.inference_mode():
                logits = model(input_ids=ids, use_cache=False, logits_to_keep=1).logits[0, -1].float()
            rows.append(logits)
            print(f"{mode}: {prompt['tokens']} tokens done at {time.perf_counter() - started:.0f}s", flush=True)
        results[mode] = rows
        del model
    report = {"repo": args.repo, "revision": PINS[args.repo], "device": "cpu", "dtype": "float32",
              "torch": torch.__version__, "threads": torch.get_num_threads(),
              "prompt_token_counts": [p["tokens"] for p in prompts], "prompts": []}
    for index, prompt in enumerate(prompts):
        a, b = results["eager"][index], results["sdpa"][index]
        ca, cb = a[candidates], b[candidates]
        report["prompts"].append({
            "case_id": prompt["case_id"], "tokens": prompt["tokens"],
            "cpu_eager_vs_cpu_sdpa": {
                "max_abs_logit_diff_full_vocab": float((a - b).abs().max()),
                "max_abs_logit_diff_candidates": float((ca - cb).abs().max()),
                "max_abs_label_probability_diff": float(
                    (torch.softmax(ca, -1) - torch.softmax(cb, -1)).abs().max()),
                "argmax_candidate_agrees": int(ca.argmax()) == int(cb.argmax()),
            },
            "cpu_eager_candidate_logits": ca.tolist(),
            "cpu_sdpa_candidate_logits": cb.tolist(),
            "cpu_eager_label_probabilities": torch.softmax(ca, -1).tolist(),
            "cpu_sdpa_label_probabilities": torch.softmax(cb, -1).tolist(),
        })
    print(json.dumps(report, indent=2))
    Path(args.out).write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
