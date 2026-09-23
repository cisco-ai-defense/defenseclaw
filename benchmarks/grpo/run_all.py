#!/usr/bin/env python3
"""benchmarks/grpo/run_all.py
Master orchestrator: runs all benchmarks and generates comparison.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

def run_trl(args):
    print("=" * 60)
    print("Running TRL baseline...")
    subprocess.run([
        sys.executable, "baselines/trl_grpo.py",
        "--model", args.model_hf,
        "--dataset", "datasets/gsm8k_grpo.jsonl",
        "--output", "results/trl_gsm8k.json",
        "--steps", str(args.steps),
    ], check=True)

def run_grpo_local(args):
    print("=" * 60)
    print("Running GRPO-Local C engine...")
    subprocess.run([
        sys.executable, "grpo_local/run_engine.py",
        "--model-gguf", args.model_gguf,
        "--tokenizer", args.tokenizer,
        "--dataset", "datasets/gsm8k_grpo.jsonl",
        "--output", "results/grpo_local_gsm8k.json",
        "--steps", str(args.steps),
    ], check=True)

def compare(args):
    print("\n" + "=" * 60)
    print("COMPARISON RESULTS")
    print("=" * 60)

    results = []
    for p in Path("results").glob("*.json"):
        results.append(json.loads(p.read_text()))

    fmt = "{:<15} {:>12} {:>12} {:>12}"
    print(fmt.format("System", "Time (s)", "RSS (MB)", "VRAM (MB)"))
    print("-" * 55)
    for r in results:
        print(fmt.format(
            r["system"],
            f"{r['wall_clock_seconds']:.1f}",
            str(r["peak_rss_mb"]),
            str(r.get("peak_vram_mb", "N/A")),
        ))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-hf", default="Qwen/Qwen3-1.7B")
    parser.add_argument("--model-gguf", required=True)
    parser.add_argument("--tokenizer", required=True)
    parser.add_argument("--steps", type=int, default=200)
    parser.add_argument("--plot", action="store_true")
    parser.add_argument("--skip-trl", action="store_true")
    args = parser.parse_args()

    if not args.skip_trl:
        run_trl(args)
    run_grpo_local(args)
    compare(args)

    if args.plot:
        subprocess.run([sys.executable, "plot_results.py"], check=True)

if __name__ == "__main__":
    main()
