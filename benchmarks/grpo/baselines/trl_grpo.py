#!/usr/bin/env python3
"""benchmarks/grpo/baselines/trl_grpo.py
Run GRPO training with TRL GRPOTrainer on Qwen3-1.7B.
Outputs results JSON with metrics.
"""
import json
import time
import resource
import argparse
from pathlib import Path

import torch
from datasets import load_dataset
from transformers import AutoModelForCausalLM, AutoTokenizer
from trl import GRPOConfig, GRPOTrainer
from peft import LoraConfig

def gsm8k_reward(completions: list[str], ground_truths: list[str], **kwargs) -> list[float]:
    """Check if completion contains the correct boxed answer."""
    import re
    rewards = []
    for completion, gt in zip(completions, ground_truths):
        match = re.search(r"\\boxed\{(.+?)\}", completion)
        if match and match.group(1).strip() == gt.strip():
            rewards.append(1.0)
        elif gt.strip() in completion:
            rewards.append(0.5)
        else:
            rewards.append(0.0)
    return rewards

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="Qwen/Qwen3-1.7B")
    parser.add_argument("--dataset", default="datasets/gsm8k_grpo.jsonl")
    parser.add_argument("--output", default="results/trl_gsm8k.json")
    parser.add_argument("--steps", type=int, default=200)
    args = parser.parse_args()

    start_time = time.time()

    # Load model with LoRA
    model = AutoModelForCausalLM.from_pretrained(args.model, torch_dtype=torch.bfloat16)
    tokenizer = AutoTokenizer.from_pretrained(args.model)

    lora_config = LoraConfig(
        r=16, lora_alpha=16,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        lora_dropout=0.0, bias="none", task_type="CAUSAL_LM",
    )

    # Load dataset
    dataset = load_dataset("json", data_files=args.dataset, split="train")

    # Configure GRPO
    training_args = GRPOConfig(
        output_dir="/tmp/trl_grpo_bench",
        max_steps=args.steps,
        per_device_train_batch_size=1,
        gradient_accumulation_steps=4,
        learning_rate=1e-4,
        num_generations=4,  # group size
        max_completion_length=256,
        beta=0.0,  # no KL
        logging_steps=5,
        report_to="none",
    )

    trainer = GRPOTrainer(
        model=model,
        args=training_args,
        train_dataset=dataset,
        reward_funcs=[gsm8k_reward],
        peft_config=lora_config,
    )

    # Train
    trainer.train()
    elapsed = time.time() - start_time

    # Collect metrics
    peak_mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024  # MB
    vram_mb = torch.cuda.max_memory_allocated() // (1024 * 1024) if torch.cuda.is_available() else None

    results = {
        "system": "trl",
        "model": args.model,
        "dataset": "gsm8k",
        "steps": args.steps,
        "wall_clock_seconds": elapsed,
        "peak_rss_mb": peak_mem,
        "peak_vram_mb": vram_mb,
        "reward_curve": [log["loss"] for log in trainer.state.log_history if "loss" in log],
    }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)

    print(f"TRL GRPO complete: {elapsed:.1f}s, RSS={peak_mem}MB, VRAM={vram_mb}MB")

if __name__ == "__main__":
    main()
