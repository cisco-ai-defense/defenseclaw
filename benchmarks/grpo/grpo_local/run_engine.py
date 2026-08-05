#!/usr/bin/env python3
"""benchmarks/grpo/grpo_local/run_engine.py
Run GRPO training with the C engine (via Go binary).
Collects metrics and outputs results JSON.
"""
import json
import subprocess
import time
import resource
import argparse
from pathlib import Path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-gguf", required=True, help="Path to GGUF model")
    parser.add_argument("--tokenizer", required=True, help="Path to tokenizer.json")
    parser.add_argument("--dataset", default="datasets/gsm8k_grpo.jsonl")
    parser.add_argument("--output", default="results/grpo_local_gsm8k.json")
    parser.add_argument("--steps", type=int, default=200)
    args = parser.parse_args()

    start_time = time.time()

    # Build the Go binary if needed
    build_cmd = ["go", "build", "-tags", "cgo,grpo_engine", "-o", "/tmp/grpo_bench",
                 "./cmd/grpo-bench"]
    subprocess.run(build_cmd, check=True, cwd=str(Path(__file__).parents[2]))

    # Run the engine
    run_cmd = [
        "/tmp/grpo_bench",
        "--policy-gguf", args.model_gguf,
        "--tokenizer", args.tokenizer,
        "--dataset", args.dataset,
        "--max-steps", str(args.steps),
        "--group-size", "4",
        "--lora-rank", "16",
        "--lora-alpha", "16",
        "--learning-rate", "1e-4",
        "--clip-epsilon", "0.2",
        "--kl-coef", "0.0",
        "--reward-funcs", "ground_truth:field=ground_truth",
        "--output-json", "/tmp/grpo_bench_metrics.json",
    ]

    proc = subprocess.run(run_cmd, capture_output=True, text=True)
    elapsed = time.time() - start_time

    peak_mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024

    # Read engine metrics
    metrics = {}
    metrics_path = Path("/tmp/grpo_bench_metrics.json")
    if metrics_path.exists():
        metrics = json.loads(metrics_path.read_text())

    results = {
        "system": "grpo-local",
        "model": args.model_gguf,
        "dataset": "gsm8k",
        "steps": args.steps,
        "wall_clock_seconds": elapsed,
        "peak_rss_mb": peak_mem,
        "peak_vram_mb": None,
        "reward_curve": metrics.get("reward_curve", []),
        "tokens_per_second": metrics.get("tokens_per_second", 0),
    }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)

    print(f"GRPO-Local complete: {elapsed:.1f}s, RSS={peak_mem}MB")
    if proc.returncode != 0:
        print(f"Engine stderr:\n{proc.stderr[-2000:]}")

if __name__ == "__main__":
    main()
