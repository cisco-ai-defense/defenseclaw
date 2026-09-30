#!/usr/bin/env python3
"""benchmarks/grpo/datasets/prepare_gsm8k.py
Downloads GSM8K and formats it for GRPO training (prompt + ground_truth).
"""
import json
import re
from pathlib import Path
from datasets import load_dataset

def extract_answer(solution: str) -> str:
    """Extract the final numerical answer from GSM8K solution text."""
    match = re.search(r"####\s*(.+)", solution)
    return match.group(1).strip() if match else ""

def main():
    ds = load_dataset("openai/gsm8k", "main")
    out_dir = Path(__file__).parent

    # Training set: first 500 problems
    train_data = []
    for item in list(ds["train"])[:500]:
        answer = extract_answer(item["answer"])
        train_data.append({
            "prompt": f"Solve this math problem step by step. Put your final answer in \\boxed{{}}.\n\nProblem: {item['question']}\n\nSolution:",
            "ground_truth": answer,
            "metadata": {"source": "gsm8k", "split": "train"}
        })

    with open(out_dir / "gsm8k_grpo.jsonl", "w") as f:
        for item in train_data:
            f.write(json.dumps(item) + "\n")

    # Eval set: first 200 from test split
    eval_data = []
    for item in list(ds["test"])[:200]:
        answer = extract_answer(item["answer"])
        eval_data.append({
            "prompt": f"Solve this math problem step by step. Put your final answer in \\boxed{{}}.\n\nProblem: {item['question']}\n\nSolution:",
            "ground_truth": answer,
        })

    with open(out_dir / "gsm8k_eval.jsonl", "w") as f:
        for item in eval_data:
            f.write(json.dumps(item) + "\n")

    print(f"Wrote {len(train_data)} train, {len(eval_data)} eval examples")

if __name__ == "__main__":
    main()
