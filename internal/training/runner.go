package training

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// RunConfig defines the parameters for a training run
type RunConfig struct {
	Backend     string // "unsloth" or "mlx-lm-lora"
	Algorithm   string // "sft", "dpo", "grpo", "orpo"
	BaseModel   string // HF repo or MLX repo
	DatasetPath string // path to training JSONL
	OutputDir   string // where to write model output
	ScriptsDir  string // where to write generated script
	TimeoutSec  int    // kill after this many seconds (default 43200 = 12h)
}

// RunResult contains the results of a training run
type RunResult struct {
	GGUFPath string
	Duration time.Duration
	ExitCode int
}

// Run generates a training script and executes it as subprocess
func Run(ctx context.Context, cfg RunConfig) (*RunResult, error) {
	// Set default timeout if not specified
	if cfg.TimeoutSec == 0 {
		cfg.TimeoutSec = 43200 // 12 hours
	}

	// Validate config
	if cfg.Backend == "" {
		return nil, fmt.Errorf("backend is required")
	}
	if cfg.Algorithm == "" {
		return nil, fmt.Errorf("algorithm is required")
	}
	if cfg.BaseModel == "" {
		return nil, fmt.Errorf("base model is required")
	}
	if cfg.DatasetPath == "" {
		return nil, fmt.Errorf("dataset path is required")
	}
	if cfg.OutputDir == "" {
		return nil, fmt.Errorf("output directory is required")
	}

	// Create output directory
	if err := os.MkdirAll(cfg.OutputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	// Create scripts directory
	if cfg.ScriptsDir == "" {
		cfg.ScriptsDir = filepath.Join(cfg.OutputDir, "scripts")
	}
	if err := os.MkdirAll(cfg.ScriptsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create scripts directory: %w", err)
	}

	// Generate training script
	scriptContent, err := scriptGenerator(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate training script: %w", err)
	}

	// Determine script extension and interpreter
	var scriptPath, interpreter string
	if cfg.Backend == "unsloth" {
		scriptPath = filepath.Join(cfg.ScriptsDir, "train.py")
		interpreter = "python3"
	} else {
		scriptPath = filepath.Join(cfg.ScriptsDir, "train.sh")
		interpreter = "bash"
	}

	// Write script to file
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
		return nil, fmt.Errorf("failed to write script: %w", err)
	}

	// Create context with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(cfg.TimeoutSec)*time.Second)
	defer cancel()

	// Execute script
	start := time.Now()
	cmd := exec.CommandContext(timeoutCtx, interpreter, scriptPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Dir = cfg.OutputDir

	err = cmd.Run()
	duration := time.Since(start)

	result := &RunResult{
		Duration: duration,
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			// Context timeout or other error
			result.ExitCode = -1
		}
		return result, fmt.Errorf("training script failed: %w", err)
	}

	result.ExitCode = 0

	// Find generated GGUF file
	ggufPath, err := findGGUF(cfg.OutputDir)
	if err != nil {
		return result, fmt.Errorf("training completed but GGUF not found: %w", err)
	}
	result.GGUFPath = ggufPath

	return result, nil
}

// scriptGenerator is a variable function pointer to allow test overrides
var scriptGenerator = generateTrainingScript

// generateTrainingScript creates the Python/Bash script for the selected backend
func generateTrainingScript(cfg RunConfig) (string, error) {
	switch cfg.Backend {
	case "unsloth":
		return generateUnslothScript(cfg)
	case "mlx-lm-lora":
		return generateMLXScript(cfg)
	default:
		return "", fmt.Errorf("unknown backend: %s", cfg.Backend)
	}
}

func generateUnslothScript(cfg RunConfig) (string, error) {
	// Determine trainer class based on algorithm
	var trainerClass, configClass, importExtra string
	switch strings.ToLower(cfg.Algorithm) {
	case "sft":
		trainerClass = "SFTTrainer"
		configClass = "SFTConfig"
		importExtra = "SFTTrainer, SFTConfig"
	case "dpo":
		trainerClass = "DPOTrainer"
		configClass = "DPOConfig"
		importExtra = "DPOTrainer, DPOConfig"
	case "grpo":
		trainerClass = "GRPOTrainer"
		configClass = "GRPOConfig"
		importExtra = "GRPOTrainer, GRPOConfig"
	case "orpo":
		trainerClass = "ORPOTrainer"
		configClass = "ORPOConfig"
		importExtra = "ORPOTrainer, ORPOConfig"
	default:
		return "", fmt.Errorf("unknown algorithm for unsloth: %s", cfg.Algorithm)
	}

	script := fmt.Sprintf(`#!/usr/bin/env python3
"""
Auto-generated training script for Unsloth
Backend: unsloth
Algorithm: %s
Base Model: %s
"""

from unsloth import FastLanguageModel
from trl import %s
from datasets import load_dataset

# Load model
print("Loading model: %s")
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name="%s",
    load_in_4bit=True,
    max_seq_length=4096
)

# Apply LoRA
print("Applying LoRA adapters")
model = FastLanguageModel.get_peft_model(
    model,
    r=64,
    lora_alpha=16,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    lora_dropout=0.05,
    bias="none",
    use_gradient_checkpointing=True
)

# Load dataset
print("Loading dataset: %s")
dataset = load_dataset("json", data_files="%s")

# Configure trainer
print("Initializing trainer")
trainer = %s(
    model=model,
    tokenizer=tokenizer,
    train_dataset=dataset["train"],
    args=%s(
        output_dir="%s",
        num_train_epochs=3,
        per_device_train_batch_size=2,
        gradient_accumulation_steps=4,
        learning_rate=2e-4,
        logging_steps=10,
        save_strategy="epoch",
        fp16=True
    )
)

# Train
print("Starting training")
trainer.train()

# Save GGUF
print("Exporting to GGUF format")
model.save_pretrained_gguf(
    "%s",
    tokenizer,
    quantization_method="q4_k_m"
)

print("Training complete!")
`, cfg.Algorithm, cfg.BaseModel, importExtra, cfg.BaseModel, cfg.BaseModel, cfg.DatasetPath, cfg.DatasetPath, trainerClass, configClass, cfg.OutputDir, cfg.OutputDir)

	return script, nil
}

func generateMLXScript(cfg RunConfig) (string, error) {
	// Validate algorithm for MLX
	validAlgorithms := map[string]bool{"sft": true, "dpo": true, "grpo": true, "orpo": true}
	if !validAlgorithms[strings.ToLower(cfg.Algorithm)] {
		return "", fmt.Errorf("unknown algorithm for mlx-lm-lora: %s", cfg.Algorithm)
	}

	script := fmt.Sprintf(`#!/usr/bin/env bash
# Auto-generated training script for MLX
# Backend: mlx-lm-lora
# Algorithm: %s
# Base Model: %s

set -e

echo "Starting MLX training"
echo "Algorithm: %s"
echo "Model: %s"
echo "Dataset: %s"
echo "Output: %s"

# Train
mlx-lm-lora \
  --train-mode %s \
  --model %s \
  --data %s \
  --output %s \
  --batch-size 2 \
  --epochs 3 \
  --learning-rate 2e-4

# Export to GGUF
echo "Exporting to GGUF format"
mlx-lm-lora \
  --export-gguf \
  --model %s \
  --output %s/model.gguf \
  --quantize q4_k_m

echo "Training complete!"
`, cfg.Algorithm, cfg.BaseModel, cfg.Algorithm, cfg.BaseModel, cfg.DatasetPath, cfg.OutputDir,
		cfg.Algorithm, cfg.BaseModel, cfg.DatasetPath, cfg.OutputDir,
		cfg.OutputDir, cfg.OutputDir)

	return script, nil
}

// findGGUF searches for a .gguf file in the output directory
func findGGUF(dir string) (string, error) {
	var ggufPath string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(strings.ToLower(path), ".gguf") {
			ggufPath = path
			return filepath.SkipDir // Stop after finding first GGUF
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if ggufPath == "" {
		return "", fmt.Errorf("no .gguf file found in %s", dir)
	}
	return ggufPath, nil
}
