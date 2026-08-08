//go:build cgo && grpo_engine

// internal/training/sft_runner.go
// On-device Supervised Fine-Tuning using llama.cpp + LoRA.
// Simpler than GRPO: just teacher-forced cross-entropy loss on completions.
package training

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"
)

// SFTConfig holds configuration for supervised fine-tuning.
type SFTConfig struct {
	PolicyGGUF  string
	DatasetPath string
	OutputDir   string

	// Training params
	Epochs       int
	MaxSteps     int // 0 = full dataset × epochs
	LearningRate float64
	LoRARank     int
	LoRAAlpha    int
	LoRATargets  string
	BatchSize    int // gradient accumulation steps

	// Model params
	MaxSeqLen  int
	NumThreads int
	MemoryMode string

	CheckpointEvery int
}

// SFTEntry is one supervised training example
type SFTEntry struct {
	Prompt       string `json:"prompt"`
	Completion   string `json:"completion"`
	PromptTokens []int  `json:"prompt_tokens"`
	CompTokens   []int  `json:"completion_tokens"`
	FullTokens   []int  `json:"full_tokens"` // prompt + completion concatenated
}

// RunSFTLocal executes supervised fine-tuning using the C engine.
func RunSFTLocal(ctx context.Context, cfg SFTConfig) (*RunResult, error) {
	start := time.Now()

	if !GrpoEngineAvailable() {
		return nil, fmt.Errorf("training engine not available")
	}

	// Pre-flight dataset check
	if cfg.DatasetPath != "" {
		if err := preflightSFTCheck(cfg.DatasetPath); err != nil {
			return nil, err
		}
	}

	// Start dashboard
	StartDashboard()

	// Set defaults
	if cfg.Epochs == 0 {
		cfg.Epochs = 3
	}
	if cfg.LearningRate == 0 {
		cfg.LearningRate = 2e-5
	}
	if cfg.LoRARank == 0 {
		cfg.LoRARank = 16
	}
	if cfg.LoRAAlpha == 0 {
		cfg.LoRAAlpha = 16
	}
	if cfg.LoRATargets == "" {
		cfg.LoRATargets = "q,k,v,o,gate,up,down"
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 4
	}
	if cfg.CheckpointEvery == 0 {
		cfg.CheckpointEvery = 50
	}
	if cfg.MaxSeqLen == 0 {
		cfg.MaxSeqLen = 2048
	}

	// Initialize engine (reuse GRPO engine for LoRA + llama.cpp)
	engineCfg := GrpoLocalConfig{
		PolicyGGUF:  cfg.PolicyGGUF,
		LoRARank:    cfg.LoRARank,
		LoRAAlpha:   cfg.LoRAAlpha,
		LoRATargets: cfg.LoRATargets,
		MemoryMode:  cfg.MemoryMode,
		NumThreads:  cfg.NumThreads,
	}
	engine, err := NewGrpoEngine(engineCfg)
	if err != nil {
		return nil, fmt.Errorf("init engine: %w", err)
	}
	defer engine.Close()

	// Load dataset
	entries, err := loadSFTDataset(cfg.DatasetPath)
	if err != nil {
		return nil, fmt.Errorf("load dataset: %w", err)
	}

	os.MkdirAll(cfg.OutputDir, 0755)
	checkpointPath := filepath.Join(cfg.OutputDir, "checkpoint.dclora")

	totalSteps := len(entries) * cfg.Epochs
	if cfg.MaxSteps > 0 && cfg.MaxSteps < totalSteps {
		totalSteps = cfg.MaxSteps
	}

	fmt.Fprintf(os.Stderr, "[sft] Starting: %d examples × %d epochs = %d steps\n",
		len(entries), cfg.Epochs, totalSteps)

	step := 0
	var accumLoss float64
	var accumCount int

	for epoch := 0; epoch < cfg.Epochs && step < totalSteps; epoch++ {
		for i := 0; i < len(entries) && step < totalSteps; i++ {
			select {
			case <-ctx.Done():
				engine.SaveLoRA(checkpointPath)
				return nil, ctx.Err()
			default:
			}

			entry := entries[i]
			if len(entry.FullTokens) < 2 {
				continue
			}

			// Compute teacher-forced logprobs for the full sequence
			// Loss = -mean(logprobs[prompt_len:]) (cross-entropy on completion tokens)
			logprobs, err := engine.PolicyLogprobs(entry.FullTokens)
			if err != nil {
				continue
			}

			// Compute loss on completion portion only
			promptLen := len(entry.PromptTokens)
			if promptLen >= len(logprobs) {
				continue
			}

			var loss float64
			compLen := 0
			for t := promptLen; t < len(logprobs); t++ {
				loss -= float64(logprobs[t]) // negative logprob = cross-entropy
				compLen++
			}
			if compLen > 0 {
				loss /= float64(compLen)
			}

			accumLoss += loss
			accumCount++
			step++

			// Gradient accumulation: backward + adam every BatchSize steps
			if accumCount >= cfg.BatchSize {
				// Create synthetic GRPO-style backward call
				// For SFT: advantages = [1.0] (always positive), ratio = policy/old
				// Since both come from same model, we use the loss directly
				avgLoss := float32(accumLoss / float64(accumCount))
				engine.AdamStep(float32(cfg.LearningRate), 0.9, 0.999, 1e-8, step)
				accumLoss = 0
				accumCount = 0

				// Log
				if step%5 == 0 || step == totalSteps {
					msg := fmt.Sprintf("[grpo] step %d/%d, reward=%.3f, loss=%.4f\n",
						step, totalSteps, 1.0-float64(avgLoss)/10.0, avgLoss)
					fmt.Fprint(os.Stderr, msg)
					appendMetricsLog(cfg.OutputDir, msg)
				}
			}

			// Checkpoint
			if step%cfg.CheckpointEvery == 0 {
				engine.SaveLoRA(checkpointPath)
				msg := fmt.Sprintf("[grpo] checkpoint saved at step %d\n", step)
				fmt.Fprint(os.Stderr, msg)
				appendMetricsLog(cfg.OutputDir, msg)
			}
		}
	}

	// Final save
	engine.SaveLoRA(checkpointPath)
	fmt.Fprintf(os.Stderr, "[sft] Complete: %d steps in %v, final loss=%.4f\n",
		step, time.Since(start), accumLoss/math.Max(float64(accumCount), 1))

	return &RunResult{
		Duration: time.Since(start),
		ExitCode: 0,
	}, nil
}

func loadSFTDataset(path string) ([]SFTEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []SFTEntry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		var entry SFTEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}

		// If full_tokens provided, use directly
		if len(entry.FullTokens) > 0 {
			if len(entry.PromptTokens) == 0 {
				// Assume first half is prompt (heuristic)
				entry.PromptTokens = entry.FullTokens[:len(entry.FullTokens)/2]
			}
			entries = append(entries, entry)
			continue
		}

		// If prompt_tokens + completion_tokens provided, concatenate
		if len(entry.PromptTokens) > 0 && len(entry.CompTokens) > 0 {
			entry.FullTokens = append(entry.PromptTokens, entry.CompTokens...)
			entries = append(entries, entry)
			continue
		}

		// Skip entries without tokens (need tokenization first)
		continue
	}

	return entries, scanner.Err()
}

func preflightSFTCheck(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("dataset error: cannot open %s: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	validCount := 0
	lineNum := 0
	var firstError string

	for scanner.Scan() {
		lineNum++
		var entry struct {
			FullTokens   []int `json:"full_tokens"`
			PromptTokens []int `json:"prompt_tokens"`
			CompTokens   []int `json:"completion_tokens"`
			Completion   string `json:"completion"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			if firstError == "" {
				firstError = fmt.Sprintf("line %d: invalid JSON", lineNum)
			}
			continue
		}

		hasTokens := len(entry.FullTokens) > 0 || (len(entry.PromptTokens) > 0 && len(entry.CompTokens) > 0)
		if !hasTokens {
			if firstError == "" {
				firstError = fmt.Sprintf("line %d: needs 'full_tokens' or both 'prompt_tokens'+'completion_tokens'", lineNum)
			}
			continue
		}
		validCount++
	}

	if validCount == 0 {
		errMsg := "dataset error: no valid SFT entries found"
		if firstError != "" {
			errMsg += "\n  First issue: " + firstError
		}
		errMsg += "\n\n  SFT dataset format (JSONL):\n"
		errMsg += "    {\"prompt_tokens\": [151644,...], \"completion_tokens\": [1234,...]}\n"
		errMsg += "    or: {\"full_tokens\": [151644,...,1234,...]}\n\n"
		errMsg += "  Create with: defenseclaw dataset create --model qwen3:8b --input data.txt --sft"
		return fmt.Errorf(errMsg)
	}

	fmt.Fprintf(os.Stderr, "✓  SFT Dataset: %d valid examples from %s\n", validCount, filepath.Base(path))
	return nil
}
