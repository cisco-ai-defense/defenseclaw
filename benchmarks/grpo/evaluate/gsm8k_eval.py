#!/usr/bin/env python3
"""benchmarks/grpo/evaluate/gsm8k_eval.py
Evaluate a trained model on GSM8K test set (200 problems).
Reports pass@1 accuracy.
"""
import json
import re
import argparse
from pathlib import Path

def extract_boxed(text: str) -> str:
    match = re.search(r"\\boxed\{(.+?)\}", text)
    return match.group(1).strip() if match else ""

def evaluate(predictions_path: str, eval_data_path: str) -> dict:
    preds = [json.loads(l) for l in open(predictions_path)]
    evals = [json.loads(l) for l in open(eval_data_path)]

    correct = 0
    total = min(len(preds), len(evals))

    for pred, ev in zip(preds[:total], evals[:total]):
        predicted = extract_boxed(pred.get("completion", ""))
        expected = ev["ground_truth"]
        if predicted == expected:
            correct += 1

    return {
        "accuracy": correct / total if total > 0 else 0.0,
        "correct": correct,
        "total": total,
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--eval-data", default="datasets/gsm8k_eval.jsonl")
    args = parser.parse_args()

    result = evaluate(args.predictions, args.eval_data)
    print(f"GSM8K Accuracy: {result['accuracy']:.3f} ({result['correct']}/{result['total']})")
    print(json.dumps(result, indent=2))
