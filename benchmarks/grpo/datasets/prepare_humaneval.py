#!/usr/bin/env python3
"""benchmarks/grpo/datasets/prepare_humaneval.py
Downloads HumanEval and formats it for GRPO training (prompt + test function).
"""
import json
from pathlib import Path
from datasets import load_dataset

def main():
    ds = load_dataset("openai/openai_humaneval")
    out_dir = Path(__file__).parent

    # Training set: first 100 problems
    train_data = []
    for item in list(ds["test"])[:100]:
        train_data.append({
            "prompt": item["prompt"],
            "ground_truth": item["canonical_solution"],
            "test": item["test"],
            "entry_point": item["entry_point"],
            "metadata": {"source": "humaneval", "task_id": item["task_id"]}
        })

    with open(out_dir / "humaneval_grpo.jsonl", "w") as f:
        for item in train_data:
            f.write(json.dumps(item) + "\n")

    # Eval set: remaining problems (64)
    eval_data = []
    for item in list(ds["test"])[100:]:
        eval_data.append({
            "prompt": item["prompt"],
            "ground_truth": item["canonical_solution"],
            "test": item["test"],
            "entry_point": item["entry_point"],
            "task_id": item["task_id"],
        })

    with open(out_dir / "humaneval_eval.jsonl", "w") as f:
        for item in eval_data:
            f.write(json.dumps(item) + "\n")

    print(f"Wrote {len(train_data)} train, {len(eval_data)} eval examples")

if __name__ == "__main__":
    main()
