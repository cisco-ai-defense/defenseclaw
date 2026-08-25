# GRPO Benchmark Harness

This benchmark suite compares the GRPO-Local C engine against TRL+Unsloth on GSM8K and HumanEval datasets.

## Overview

**Purpose**: Measure performance (speed, memory, accuracy) of:
- **TRL baseline**: HuggingFace TRL GRPOTrainer with Unsloth optimizations (GPU)
- **GRPO-Local**: Custom C engine with CPU-only training

**Datasets**:
- **GSM8K**: 500 training problems, 200 test problems (mathematical reasoning)
- **HumanEval**: 100 training problems, 64 test problems (code generation)

## Directory Structure

```
benchmarks/grpo/
├── README.md              # This file
├── requirements.txt       # Python dependencies
├── run_all.py            # Master orchestrator script
├── plot_results.py       # Generate comparison charts
├── datasets/             # Dataset preparation
│   ├── prepare_gsm8k.py
│   └── prepare_humaneval.py
├── baselines/            # TRL baseline implementation
│   └── trl_grpo.py
├── grpo_local/          # C engine wrapper
│   └── run_engine.py
├── evaluate/            # Evaluation scripts
│   ├── gsm8k_eval.py
│   └── humaneval_eval.py
└── results/             # Output JSON files and charts
    └── .gitkeep
```

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Prepare Datasets

```bash
cd datasets/
python3 prepare_gsm8k.py      # Creates gsm8k_grpo.jsonl and gsm8k_eval.jsonl
python3 prepare_humaneval.py  # Creates humaneval_grpo.jsonl and humaneval_eval.jsonl
```

### 3. Run Full Benchmark Suite

```bash
# Requires:
# - model_gguf: Path to quantized GGUF model (e.g., Qwen3-1.7B-Q8_0.gguf)
# - tokenizer: Path to tokenizer.json

python3 run_all.py \
  --model-hf Qwen/Qwen3-1.7B \
  --model-gguf /path/to/model.gguf \
  --tokenizer /path/to/tokenizer.json \
  --steps 200 \
  --plot
```

### 4. Run Individual Components

**TRL Baseline Only** (requires GPU):
```bash
python3 baselines/trl_grpo.py \
  --model Qwen/Qwen3-1.7B \
  --dataset datasets/gsm8k_grpo.jsonl \
  --output results/trl_gsm8k.json \
  --steps 200
```

**GRPO-Local Only** (CPU):
```bash
python3 grpo_local/run_engine.py \
  --model-gguf /path/to/model.gguf \
  --tokenizer /path/to/tokenizer.json \
  --dataset datasets/gsm8k_grpo.jsonl \
  --output results/grpo_local_gsm8k.json \
  --steps 200
```

**Evaluate Trained Model**:
```bash
# Generate predictions first, then evaluate
python3 evaluate/gsm8k_eval.py \
  --predictions results/predictions.jsonl \
  --eval-data datasets/gsm8k_eval.jsonl
```

### 5. Generate Comparison Charts

```bash
python3 plot_results.py  # Creates results/comparison.png
```

## Output Format

Each run produces a JSON file in `results/` with this structure:

```json
{
  "system": "trl" | "grpo-local",
  "model": "model_name_or_path",
  "dataset": "gsm8k" | "humaneval",
  "steps": 200,
  "wall_clock_seconds": 1234.5,
  "peak_rss_mb": 8192,
  "peak_vram_mb": 16384 | null,
  "reward_curve": [0.1, 0.15, 0.2, ...],
  "tokens_per_second": 45.2
}
```

## Metrics

**Performance**:
- `wall_clock_seconds`: Total training time
- `peak_rss_mb`: Peak RAM usage
- `peak_vram_mb`: Peak GPU memory (null for CPU-only)
- `tokens_per_second`: Throughput

**Accuracy**:
- GSM8K: Pass@1 accuracy (exact match on boxed answer)
- HumanEval: Pass@1 accuracy (functional correctness via test execution)

**Learning Dynamics**:
- `reward_curve`: Mean reward per training step

## Configuration

Training uses identical hyperparameters for both systems:
- Model: Qwen3-1.7B (1.7B parameters)
- LoRA: rank=16, alpha=16, target=all linear layers
- Learning rate: 1e-4
- Group size: 4 (4 completions per prompt)
- Max completion length: 256 tokens
- Clip epsilon: 0.2 (PPO clipping)
- KL coefficient: 0.0 (no KL penalty)

## Requirements

**Hardware**:
- TRL baseline: NVIDIA GPU with 16GB+ VRAM
- GRPO-Local: CPU with 16GB+ RAM (no GPU required)

**Software**:
- Python 3.12+
- PyTorch 2.5+
- TRL 0.15+
- Transformers 4.50+
- Go 1.23+ (for building C engine)

## Notes

- These are **benchmark scripts** designed for reproducible comparisons
- They don't need to run immediately (require GPU + model downloads)
- All scripts are syntactically correct Python 3.12
- The C engine is built via `go build -tags cgo,grpo_engine`
- Results are used in the research paper (Task 5)
