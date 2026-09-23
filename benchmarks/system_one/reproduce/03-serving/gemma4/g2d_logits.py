"""Dump answer-position candidate logits for a fixed prompt set, one device/kernel at a time.

Used to adjudicate G2 on 26B-A4B, where GPU eager and GPU SDPA disagree by up to ~1e-2
in label probability on every window-crossing prompt while same-config repeats are
bit-identical. A CPU float32 eager pass has no fused attention kernel at all, so it is
the reference the two GPU paths are compared against.

The prompt set is the same deterministic selection g2b uses with --stress, so the runs
line up prompt for prompt.
"""

import argparse
import json
import sys
from pathlib import Path

import torch
from torch.nn.attention import SDPBackend, sdpa_kernel
from transformers import AutoModelForCausalLM, AutoTokenizer

sys.path.insert(0, "$WORK/g4j/jevify/src")
from jevify.prompting import render  # noqa: E402
from jevify.questions import question_from_dict  # noqa: E402

HUB = Path("/opt/dlami/nvme/hf/hub")
PINS = json.loads(Path("$WORK/g4j/pins.json").read_text())
REQUESTS = Path("/opt/dlami/nvme/s2-requests-all.jsonl")
BANDS = [(1024, 1200), (1200, 1500), (1500, 2100), (2100, 3000), (3000, 4096)]
PER_BAND = 4


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


def pick_prompts(tokenizer):
    found = {band: [] for band in BANDS}
    with REQUESTS.open() as stream:
        for line in stream:
            if all(len(v) >= PER_BAND for v in found.values()):
                break
            row = json.loads(line)
            rendered = render(row["state"], normalize_question(row["questions"]["disposition"]))
            text = tokenizer.apply_chat_template(
                rendered.messages, tokenize=False, add_generation_prompt=True, enable_thinking=False)
            ids = tokenizer(text, add_special_tokens=False)["input_ids"]
            for band in BANDS:
                if band[0] <= len(ids) < band[1] and len(found[band]) < PER_BAND:
                    found[band].append({"case_id": row["case_id"], "event_index": row["event_index"],
                                        "tokens": len(ids), "ids": ids, "labels": rendered.labels})
                    break
    return [p for band in BANDS for p in found[band]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--device", required=True, choices=["cpu", "cuda"])
    parser.add_argument("--attn", required=True, choices=["eager", "sdpa", "sdpa_math"])
    parser.add_argument("--dtype", default="float32", choices=["float32", "bfloat16"])
    parser.add_argument("--device-map")
    parser.add_argument("--max-gpu-memory")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    path = snapshot(args.repo)
    tokenizer = AutoTokenizer.from_pretrained(path, local_files_only=True)
    prompts = pick_prompts(tokenizer)
    candidates = [tokenizer(l, add_special_tokens=False)["input_ids"][0] for l in prompts[0]["labels"]]

    torch.backends.cuda.matmul.allow_tf32 = False
    options = dict(local_files_only=True, dtype=getattr(torch, args.dtype),
                   attn_implementation="eager" if args.attn == "eager" else "sdpa")
    if args.device == "cpu":
        options["device_map"] = {"": "cpu"}
    elif args.device_map:
        options["device_map"] = args.device_map
        if args.max_gpu_memory:
            options["max_memory"] = {i: args.max_gpu_memory for i in range(torch.cuda.device_count())}
            options["max_memory"]["cpu"] = "300GiB"
    model = AutoModelForCausalLM.from_pretrained(path, **options).eval()
    if args.device == "cuda" and not args.device_map:
        model = model.to("cuda")
    target = torch.device("cpu") if args.device == "cpu" else next(
        p.device for p in model.parameters() if p.device.type == "cuda")

    rows = []
    for prompt in prompts:
        ids = torch.tensor([prompt["ids"]], device=target)
        with torch.inference_mode():
            if args.attn == "sdpa_math":
                with sdpa_kernel(SDPBackend.MATH):
                    logits = model(input_ids=ids, use_cache=False, logits_to_keep=1).logits[0, -1].float()
            else:
                logits = model(input_ids=ids, use_cache=False, logits_to_keep=1).logits[0, -1].float()
        picked = logits.cpu()[candidates]
        rows.append({"case_id": prompt["case_id"], "event_index": prompt["event_index"],
                     "tokens": prompt["tokens"], "candidate_logits": picked.tolist(),
                     "label_probabilities": torch.softmax(picked, -1).tolist()})
        print(f"{len(rows)}/{len(prompts)} {prompt['tokens']} tokens", flush=True)
    Path(args.out).write_text(json.dumps(
        {"repo": args.repo, "revision": PINS[args.repo], "device": args.device, "attn": args.attn,
         "dtype": args.dtype, "device_map": args.device_map, "torch": torch.__version__,
         "labels": prompts[0]["labels"], "candidate_token_ids": candidates, "rows": rows}, indent=2) + "\n")


if __name__ == "__main__":
    main()
