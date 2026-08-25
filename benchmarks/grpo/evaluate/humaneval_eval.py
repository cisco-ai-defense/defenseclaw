#!/usr/bin/env python3
"""benchmarks/grpo/evaluate/humaneval_eval.py
Evaluate a trained model on HumanEval test set (64 problems).
Reports pass@1 accuracy using code execution.
"""
import json
import argparse
import tempfile
import subprocess
from pathlib import Path

def extract_code(completion: str, entry_point: str) -> str:
    """Extract function definition from completion."""
    # Simple heuristic: take everything up to the next def or end
    lines = completion.split('\n')
    code_lines = []
    in_function = False
    for line in lines:
        if line.strip().startswith(f"def {entry_point}"):
            in_function = True
        if in_function:
            code_lines.append(line)
            # Stop at next function definition or class
            if line.strip().startswith("def ") and not line.strip().startswith(f"def {entry_point}"):
                break
            if line.strip().startswith("class "):
                break
    return '\n'.join(code_lines)

def test_code(code: str, test: str) -> bool:
    """Execute code + test in isolated environment."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code + '\n' + test)
        f.flush()
        try:
            result = subprocess.run(
                ['python3', f.name],
                capture_output=True,
                timeout=5,
                text=True
            )
            Path(f.name).unlink()
            return result.returncode == 0
        except (subprocess.TimeoutExpired, Exception):
            Path(f.name).unlink()
            return False

def evaluate(predictions_path: str, eval_data_path: str) -> dict:
    preds = [json.loads(l) for l in open(predictions_path)]
    evals = [json.loads(l) for l in open(eval_data_path)]

    correct = 0
    total = min(len(preds), len(evals))

    for pred, ev in zip(preds[:total], evals[:total]):
        completion = pred.get("completion", "")
        code = extract_code(completion, ev["entry_point"])
        if test_code(code, ev["test"]):
            correct += 1

    return {
        "accuracy": correct / total if total > 0 else 0.0,
        "correct": correct,
        "total": total,
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--eval-data", default="datasets/humaneval_eval.jsonl")
    args = parser.parse_args()

    result = evaluate(args.predictions, args.eval_data)
    print(f"HumanEval Accuracy: {result['accuracy']:.3f} ({result['correct']}/{result['total']})")
    print(json.dumps(result, indent=2))
