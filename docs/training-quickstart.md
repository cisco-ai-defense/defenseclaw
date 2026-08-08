# Model Training Quickstart

Train language models on your local machine — no GPU, no cloud, no data leaving your device.

## Overview

DefenseClaw supports two training methods:

| Method | When to Use | Data Needed |
|--------|-------------|-------------|
| **GRPO** (Reinforcement Learning) | Model should explore and improve via rewards | Prompts only (no answers) |
| **SFT** (Supervised Fine-Tuning) | Model should mimic specific behavior | Prompt + answer pairs |

Both run entirely on-device using quantized GGUF models and LoRA adapters.

---

## 1. Quick Start (5 minutes)

### Install

```bash
# DefenseClaw with training support
brew install defenseclaw
# or build from source:
CGO_ENABLED=1 go install -tags "cgo grpo_engine" ./cmd/defenseclaw/
```

### Train (one command)

```bash
# GRPO: teach model to write working Python code
defenseclaw train \
  --model qwen3:8b \
  --dataset my_prompts.jsonl \
  --reward exec

# SFT: teach model from labeled examples
defenseclaw train \
  --method sft \
  --model qwen3:8b \
  --dataset my_sft_data.jsonl
```

Everything auto-downloads and auto-configures on first run.

---

## 2. Prepare Your Data

### For GRPO (prompts only)

Create `prompts.txt` — one task per line:

```text
Write a Python function to reverse a linked list
Implement binary search that returns the index
Write a function to check if a number is prime
Implement merge sort for a list of integers
Write a Python class for a stack with push/pop/peek
```

Tokenize it:

```bash
defenseclaw dataset create \
  --model qwen3:8b \
  --input prompts.txt \
  --output training_data.jsonl
```

### For SFT (prompt + answer pairs)

Create `sft_data.txt` — pairs separated by `---`:

```text
Write hello world in Python
---
print("Hello, World!")
===
Write a function to add two numbers
---
def add(a, b):
    return a + b
```

Or provide JSONL directly:

```jsonl
{"prompt": "Write hello world", "completion": "print('Hello, World!')", "prompt_tokens": [...], "completion_tokens": [...]}
```

### Validate

```bash
defenseclaw dataset validate --model qwen3:8b --dataset training_data.jsonl
# ✓ Dataset: 100 valid prompts
# ✓ Avg tokens: 18, Max: 45
# ✓ All token IDs valid for qwen3:8b
```

---

## 3. Choose a Model

```bash
defenseclaw models
```

| Model | Size | RAM Needed | Best For |
|-------|------|-----------|----------|
| **qwen3:8b** ★ | 4.9 GB | 16 GB | Code GRPO, reasoning |
| qwen3:4b | 2.6 GB | 8 GB | Fast iteration |
| qwen3:1.7b | 1.1 GB | 4 GB | Low-memory devices |
| deepseek-r1:8b | 4.9 GB | 16 GB | Reasoning + code |
| deepseek-coder-v2:16b | 9.4 GB | 24 GB | Code-focused |
| llama3.2:3b | 2.0 GB | 8 GB | General baseline |
| llama3.1:8b | 4.7 GB | 16 GB | General purpose |
| phi4:14b | 8.4 GB | 24 GB | Strong reasoning |
| gemma2:9b | 5.4 GB | 16 GB | Google's model |
| mistral:7b | 4.1 GB | 12 GB | Efficient general |
| codellama:7b | 3.8 GB | 12 GB | Code generation |

**Any GGUF model works** — these are just tested recommendations.

---

## 4. Train with GRPO

GRPO learns from reward signals — the model generates completions, they get scored, and the model improves toward higher-scoring outputs.

### Basic

```bash
defenseclaw train \
  --model qwen3:8b \
  --dataset training_data.jsonl \
  --reward exec
```

### Full Options

```bash
defenseclaw train \
  --method grpo \
  --model qwen3:8b \
  --dataset training_data.jsonl \
  --reward exec \
  --steps 100 \
  --group-size 4 \
  --gen-length 64 \
  --lr 1e-4 \
  --lora-rank 8 \
  --temperature 0.8 \
  --output ./my-grpo-lora/
```

### Reward Types

| Reward | What It Does | Use Case |
|--------|-------------|----------|
| `exec` | Runs generated code, scores 1.0 if no error | Code generation |
| `diversity` | Scores token variety (default) | General exploration |
| `regex` | Matches against a pattern | Structured output |
| `format` | Checks JSON/YAML validity | Data extraction |
| `length` | Rewards appropriate length | Conciseness training |

### What Happens During Training

```
Step 1/100:
  → Generate 4 completions for "Write a sort function"
  → Run each as Python code
  → Score: [0, 0, 1, 0] (only 3rd one ran without error)
  → Compute advantages: [-0.5, -0.5, 1.5, -0.5]
  → Update LoRA weights toward completion #3's style
  → Repeat with next prompt
```

---

## 5. Train with SFT

SFT learns from labeled examples — the model sees correct answers and learns to reproduce them.

### Basic

```bash
defenseclaw train \
  --method sft \
  --model qwen3:8b \
  --dataset sft_data.jsonl
```

### Full Options

```bash
defenseclaw train \
  --method sft \
  --model qwen3:8b \
  --dataset sft_data.jsonl \
  --epochs 3 \
  --batch-size 4 \
  --lr 2e-5 \
  --lora-rank 16 \
  --output ./my-sft-lora/
```

### SFT Dataset Format

```jsonl
{"prompt_tokens": [151644, 872, 198, ...], "completion_tokens": [755, 1182, ...]}
{"full_tokens": [151644, 872, 198, ..., 755, 1182, ...], "prompt_tokens": [151644, 872, 198, ...]}
```

---

## 6. Test Your Trained Model

```bash
# Generate with base model
defenseclaw generate \
  --model qwen3:8b \
  --prompt "Write a function to find prime numbers"

# Generate with trained LoRA applied
defenseclaw generate \
  --model qwen3:8b \
  --lora ./my-grpo-lora/checkpoint.gguf \
  --prompt "Write a function to find prime numbers"
```

---

## 7. Monitor Training

A live dashboard starts automatically at **http://localhost:8077**

It shows:
- Real-time reward/loss charts
- Current step and ETA
- Training log
- Status indicator (active/idle)

You can also start it independently:

```bash
defenseclaw dashboard
```

Or watch the raw metrics:

```bash
tail -f /tmp/grpo-metrics.log
```

---

## 8. Performance Guide

| Config | Time per Step | 100 Steps | Hardware |
|--------|--------------|-----------|----------|
| G=2, len=32 | 7 sec | 12 min | Apple M2, 16 GB |
| G=4, len=64 | 30 sec | 50 min | Apple M2, 32 GB |
| G=4, len=128 | 60 sec | 100 min | Apple M2, 32 GB |
| SFT, batch=4 | 3 sec | 5 min | Apple M2, 16 GB |

### Tips for Speed

- Use `--group-size 2` for fast iteration, `4` for quality
- Use `--gen-length 32` for quick experiments, `64-128` for production
- SFT is 2-3x faster than GRPO (no generation step)
- Larger models are proportionally slower (8B ≈ 2× of 4B)

### Tips for Quality

- GRPO: use `--reward exec` for code, `--group-size 4` for richer gradients
- SFT: use `--epochs 3`, more data > more epochs
- Start with `qwen3:8b` (best reasoning), drop to `4b` if too slow
- For code: DeepSeek-R1 or Qwen3 (both are reasoning models)

---

## 9. Troubleshooting

### "model not found"

```bash
# Model auto-downloads via ollama. If ollama isn't installed:
brew install ollama
ollama pull qwen3:8b
```

### "dataset error: no valid entries"

```bash
# Your dataset needs tokenized prompt_tokens. Create with:
defenseclaw dataset create --model qwen3:8b --input prompts.txt
```

### "training engine not available"

```bash
# Rebuild with CGO support:
CGO_ENABLED=1 go build -tags "cgo grpo_engine" ./cmd/defenseclaw/

# Or run auto-setup:
defenseclaw setup training
```

### "llama.cpp not found"

```bash
# macOS:
brew install llama.cpp

# Linux:
git clone https://github.com/ggerganov/llama.cpp && cd llama.cpp
cmake -B build && cmake --build build && sudo cmake --install build
```

### Training reward stays flat

- For GRPO: increase `--group-size` (4+) and `--gen-length` (64+)
- Check if reward function matches your task (`exec` for code, `format` for JSON)
- Try a reasoning model (qwen3, deepseek-r1) for code tasks

---

## 10. Architecture

```
defenseclaw train
       │
       ▼
┌──────────────────────────────────────────────┐
│              Go Orchestrator                  │
│  (config, dataset, rewards, checkpoints)     │
└──────────────────┬───────────────────────────┘
                   │ CGO
                   ▼
┌──────────────────────────────────────────────┐
│              C Engine                         │
│  ┌─────────────┐  ┌────────────────────┐    │
│  │ llama.cpp   │  │ LoRA Engine        │    │
│  │ (inference) │  │ (backward + adam)   │    │
│  └─────────────┘  └────────────────────┘    │
│  ┌─────────────┐  ┌────────────────────┐    │
│  │ Tokenizer   │  │ GRPO/SFT Loss      │    │
│  │ (GGUF BPE)  │  │ (advantages, clip) │    │
│  └─────────────┘  └────────────────────┘    │
└──────────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────┐
│  GGUF Model File (quantized, 1-20 GB)       │
│  + LoRA Checkpoint (< 100 MB)               │
└──────────────────────────────────────────────┘
```

---

## 11. What's Next

After training, you can:

1. **Deploy the LoRA** alongside the base model in production
2. **Merge LoRA into base** for a single-file model (coming soon)
3. **Continue training** from a checkpoint (`--resume`)
4. **Export to HuggingFace** format for use with other tools

---

## Quick Reference

```bash
# Setup
defenseclaw setup training
defenseclaw models

# Data
defenseclaw dataset create --model MODEL --input FILE --output JSONL
defenseclaw dataset validate --model MODEL --dataset JSONL

# Train
defenseclaw train --method grpo --model MODEL --dataset JSONL --reward REWARD
defenseclaw train --method sft --model MODEL --dataset JSONL --epochs N

# Test & Monitor
defenseclaw generate --model MODEL --prompt "..."
defenseclaw dashboard
```
