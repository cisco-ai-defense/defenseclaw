#!/usr/bin/env python3
"""benchmarks/grpo/plot_results.py — Generate comparison charts."""
import json
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

def main():
    results_dir = Path("results")
    results = {p.stem: json.loads(p.read_text()) for p in results_dir.glob("*.json")}

    fig, axes = plt.subplots(1, 3, figsize=(15, 5))

    # Chart 1: Memory comparison
    systems = list(results.keys())
    rss = [results[s]["peak_rss_mb"] for s in systems]
    axes[0].bar(systems, rss, color=["#2196F3", "#4CAF50"])
    axes[0].set_title("Peak RSS (MB)")
    axes[0].set_ylabel("MB")

    # Chart 2: Training time
    times = [results[s]["wall_clock_seconds"] for s in systems]
    axes[1].bar(systems, times, color=["#2196F3", "#4CAF50"])
    axes[1].set_title("Training Time (seconds)")
    axes[1].set_ylabel("Seconds")

    # Chart 3: Reward curves
    for name, r in results.items():
        if "reward_curve" in r and r["reward_curve"]:
            axes[2].plot(r["reward_curve"], label=name)
    axes[2].set_title("Reward Curve")
    axes[2].set_xlabel("Step")
    axes[2].set_ylabel("Mean Reward")
    axes[2].legend()

    plt.tight_layout()
    plt.savefig("results/comparison.png", dpi=150)
    print("Saved results/comparison.png")

if __name__ == "__main__":
    main()
