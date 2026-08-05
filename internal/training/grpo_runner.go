//go:build cgo && grpo_engine

// internal/training/grpo_runner.go
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

// RunGrpoLocal executes the full GRPO training loop using the C engine.
func RunGrpoLocal(ctx context.Context, cfg GrpoLocalConfig) (*RunResult, error) {
	start := time.Now()

	if !GrpoEngineAvailable() {
		return nil, fmt.Errorf("grpo-local engine not available")
	}

	// Set defaults
	if cfg.GroupSize == 0 {
		cfg.GroupSize = 4
	}
	if cfg.MaxGenLength == 0 {
		cfg.MaxGenLength = 256
	}
	if cfg.ClipEpsilon == 0 {
		cfg.ClipEpsilon = 0.2
	}
	if cfg.Temperature == 0 {
		cfg.Temperature = 0.7
	}
	if cfg.TopP == 0 {
		cfg.TopP = 0.9
	}
	if cfg.LearningRate == 0 {
		cfg.LearningRate = 1e-4
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
	if cfg.CheckpointEvery == 0 {
		cfg.CheckpointEvery = 100
	}
	if cfg.GradAccumSteps == 0 {
		cfg.GradAccumSteps = 1
	}

	// Initialize engine
	engine, err := NewGrpoEngine(cfg)
	if err != nil {
		return nil, fmt.Errorf("init engine: %w", err)
	}
	defer engine.Close()

	// Check for existing checkpoint (resume support)
	checkpointPath := filepath.Join(cfg.OutputDir, "checkpoint.dclora")
	startStep := 0
	if _, err := os.Stat(checkpointPath); err == nil {
		if err := engine.LoadLoRA(checkpointPath); err == nil {
			stats := engine.Stats()
			startStep = int(stats.Steps)
			fmt.Fprintf(os.Stderr, "[grpo] Resuming from step %d\n", startStep)
		}
	}

	// Load dataset (JSONL: one prompt per line)
	prompts, metadata, err := loadGRPODataset(cfg.DatasetPath)
	if err != nil {
		return nil, fmt.Errorf("load dataset: %w", err)
	}

	totalSteps := len(prompts)
	if cfg.MaxSteps > 0 && cfg.MaxSteps < totalSteps {
		totalSteps = cfg.MaxSteps
	}

	rewardSpecs := cfg.RewardFuncs

	// Training loop
	step := startStep
	for ; step < totalSteps; step++ {
		select {
		case <-ctx.Done():
			engine.SaveLoRA(checkpointPath)
			return nil, ctx.Err()
		default:
		}

		prompt := prompts[step%len(prompts)]
		meta := metadata[step%len(prompts)]

		// Step 1: Prefill once, then generate G completions from same starting point
		if err := engine.Prefill(prompt); err != nil {
			continue
		}
		engine.SaveKVSnapshot()

		var completionTokens [][]int
		var oldLogprobs [][]float32
		for g := 0; g < cfg.GroupSize; g++ {
			if g > 0 {
				engine.RestoreKVSnapshot()
			}
			tokens, lp, err := engine.GenerateContinue(cfg.MaxGenLength,
				float32(cfg.Temperature), float32(cfg.TopP))
			if err != nil {
				continue
			}
			completionTokens = append(completionTokens, tokens)
			oldLogprobs = append(oldLogprobs, lp)
		}
		engine.FreeKVSnapshot()

		if len(completionTokens) == 0 {
			continue
		}
		G := len(completionTokens)

		// Step 2: Score completions
		rewards := make([]float64, G)
		for g := 0; g < G; g++ {
			completionStr := tokensToString(completionTokens[g]) // placeholder: needs tokenizer
			rewards[g] = DispatchReward(completionStr, meta, rewardSpecs)
		}

		// Step 3: Compute group-relative advantages
		advantages := groupAdvantages(rewards)

		// Step 4: Reference logprobs (skip if kl_coef=0)
		var refLPs [][]float32
		if cfg.KLCoef > 0 {
			for g := 0; g < G; g++ {
				fullSeq := append(prompt, completionTokens[g]...)
				rlp, err := engine.RefLogprobs(fullSeq)
				if err != nil {
					refLPs = append(refLPs, make([]float32, len(completionTokens[g])))
					continue
				}
				refLPs = append(refLPs, rlp[len(prompt):])
			}
		} else {
			for g := 0; g < G; g++ {
				refLPs = append(refLPs, make([]float32, len(completionTokens[g])))
			}
		}

		// Step 5: Policy logprobs
		var policyLPs [][]float32
		for g := 0; g < G; g++ {
			fullSeq := append(prompt, completionTokens[g]...)
			plp, err := engine.PolicyLogprobs(fullSeq)
			if err != nil {
				policyLPs = append(policyLPs, make([]float32, len(completionTokens[g])))
				continue
			}
			policyLPs = append(policyLPs, plp[len(prompt):])
		}

		// Step 6: Backward + Adam
		// Flatten for C call
		maxSeqLen := 0
		for g := 0; g < G; g++ {
			if len(completionTokens[g]) > maxSeqLen {
				maxSeqLen = len(completionTokens[g])
			}
		}

		flatAdv := make([]float32, G)
		flatPolicy := make([]float32, G*maxSeqLen)
		flatOld := make([]float32, G*maxSeqLen)
		flatRef := make([]float32, G*maxSeqLen)

		for g := 0; g < G; g++ {
			flatAdv[g] = float32(advantages[g])
			for t := 0; t < len(policyLPs[g]) && t < maxSeqLen; t++ {
				flatPolicy[g*maxSeqLen+t] = policyLPs[g][t]
				flatOld[g*maxSeqLen+t] = oldLogprobs[g][t]
				flatRef[g*maxSeqLen+t] = refLPs[g][t]
			}
		}

		engine.Backward(flatAdv, flatPolicy, flatOld, flatRef,
			G, maxSeqLen, float32(cfg.ClipEpsilon), float32(cfg.KLCoef))

		if (step+1)%cfg.GradAccumSteps == 0 {
			engine.AdamStep(float32(cfg.LearningRate), 0.9, 0.999, 1e-8, step+1)
		}

		// Step 7: Logging
		if (step+1)%10 == 0 {
			stats := engine.Stats()
			meanReward := mean(rewards)
			fmt.Fprintf(os.Stderr, "[grpo] step %d/%d, reward=%.3f, loss=%.4f\n",
				step+1, totalSteps, meanReward, stats.LastLoss)
		}

		// Checkpoint
		if (step+1)%cfg.CheckpointEvery == 0 {
			engine.SaveLoRA(checkpointPath)
			fmt.Fprintf(os.Stderr, "[grpo] checkpoint saved at step %d\n", step+1)
		}
	}

	// Export merged GGUF
	os.MkdirAll(cfg.OutputDir, 0755)
	mergedPath := filepath.Join(cfg.OutputDir, "merged.gguf")
	if err := engine.ExportMergedGGUF(mergedPath); err != nil {
		return nil, fmt.Errorf("export merged gguf: %w", err)
	}

	return &RunResult{
		GGUFPath: mergedPath,
		Duration: time.Since(start),
		ExitCode: 0,
	}, nil
}

func loadGRPODataset(path string) ([][]int, []map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	var prompts [][]int
	var metadata []map[string]string

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		var entry struct {
			Prompt       string            `json:"prompt"`
			PromptTokens []int             `json:"prompt_tokens"`
			GroundTruth  string            `json:"ground_truth"`
			Metadata     map[string]string `json:"metadata"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		if entry.PromptTokens != nil {
			prompts = append(prompts, entry.PromptTokens)
		} else {
			// Placeholder: real impl needs tokenizer
			prompts = append(prompts, []int{1}) // BOS token
		}
		meta := entry.Metadata
		if meta == nil {
			meta = make(map[string]string)
		}
		if entry.GroundTruth != "" {
			meta["ground_truth"] = entry.GroundTruth
		}
		metadata = append(metadata, meta)
	}
	return prompts, metadata, scanner.Err()
}

func groupAdvantages(rewards []float64) []float64 {
	n := len(rewards)
	if n == 0 {
		return nil
	}
	m := mean(rewards)
	s := stddev(rewards)
	if s < 1e-8 {
		s = 1e-8
	}
	adv := make([]float64, n)
	for i := range rewards {
		adv[i] = (rewards[i] - m) / s
	}
	return adv
}

func mean(x []float64) float64 {
	if len(x) == 0 {
		return 0
	}
	s := 0.0
	for _, v := range x {
		s += v
	}
	return s / float64(len(x))
}

func stddev(x []float64) float64 {
	if len(x) == 0 {
		return 0
	}
	m := mean(x)
	s := 0.0
	for _, v := range x {
		s += (v - m) * (v - m)
	}
	return math.Sqrt(s / float64(len(x)))
}

func tokensToString(tokens []int) string {
	// Placeholder: real implementation needs the model's tokenizer
	// For now, return token IDs as string (tests will use pre-tokenized prompts)
	parts := make([]string, len(tokens))
	for i, t := range tokens {
		parts[i] = fmt.Sprintf("%d", t)
	}
	return fmt.Sprintf("[%s]", joinStrings(parts, ","))
}

func joinStrings(parts []string, sep string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += sep
		}
		result += p
	}
	return result
}
