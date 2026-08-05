// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package training

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// PipelineState represents the current stage of a training run.
type PipelineState string

const (
	StateIdle            PipelineState = "idle"
	StateExtracting      PipelineState = "extracting"
	StateBuildingDataset PipelineState = "building_dataset"
	StateTraining        PipelineState = "training"
	StateExporting       PipelineState = "exporting"
	StateDeploying       PipelineState = "deploying"
	StateEvaluating      PipelineState = "evaluating"
	StatePromoted        PipelineState = "promoted"
	StateFailed          PipelineState = "failed"
)

// PipelineConfig holds all settings for a pipeline run.
type PipelineConfig struct {
	Category      string
	Backend       string // "unsloth", "mlx-lm-lora", or "grpo-local"
	Algorithm     string
	BaseModel     string // HF or MLX repo
	MinTraces     int
	EvalThreshold float64
	EvalPrompts   int
	DataDir       string // ~/.defenseclaw
	ModelsDir     string // ~/.defenseclaw/models
	LlamaPort     int
	JudgeEndpoint string
	JudgeModel    string
	JudgeAPIKey   string
	TimeoutSec    int

	// GRPO-specific (only used when Backend="grpo-local")
	GroupSize      int
	MaxGenLength   int
	ClipEpsilon    float64
	KLCoef         float64
	Temperature    float64
	LoRARank       int
	LoRATargets    string
	MemoryMode     string
	RewardFuncs    []string
	ReferenceModel string
	RewardModel    string
	PolicyGGUF     string
}

// PipelineResult holds the outcome of a pipeline run.
type PipelineResult struct {
	Category   string
	State      PipelineState
	VersionID  string
	GGUFPath   string
	EvalResult *EvalResult
	Duration   time.Duration
	Error      error
}

// Pipeline orchestrates the full training cycle.
type Pipeline struct {
	store    *Store
	registry *Registry
}

func NewPipeline(store *Store, registry *Registry) *Pipeline {
	return &Pipeline{store: store, registry: registry}
}

// Run executes the full pipeline for a category.
func (p *Pipeline) Run(ctx context.Context, cfg PipelineConfig) *PipelineResult {
	start := time.Now()
	result := &PipelineResult{Category: cfg.Category, State: StateIdle}

	// Validate
	count, err := p.store.CountByCategory(cfg.Category)
	if err != nil {
		result.State = StateFailed
		result.Error = fmt.Errorf("pipeline: count traces: %w", err)
		return result
	}
	if count < cfg.MinTraces {
		result.State = StateFailed
		result.Error = fmt.Errorf("pipeline: need %d traces for %q, have %d", cfg.MinTraces, cfg.Category, count)
		return result
	}

	// Stage 1: Extract
	result.State = StateExtracting
	fmt.Fprintf(os.Stderr, "[pipeline] %s: extracting traces (%d available)...\n", cfg.Category, count)

	datasetsDir := filepath.Join(cfg.DataDir, "training", "datasets")
	dataset, err := Extract(p.store, cfg.Category, cfg.MinTraces, 0.1, datasetsDir)
	if err != nil {
		result.State = StateFailed
		result.Error = fmt.Errorf("pipeline: extract: %w", err)
		return result
	}

	// Stage 2: Train
	result.State = StateTraining
	fmt.Fprintf(os.Stderr, "[pipeline] %s: training %s with %s (%d examples)...\n",
		cfg.Category, cfg.BaseModel, cfg.Algorithm, dataset.TrainCount)

	outputDir := filepath.Join(cfg.DataDir, "training", "output", cfg.Category)
	scriptsDir := filepath.Join(cfg.DataDir, "training", "scripts")

	var runResult *RunResult
	if cfg.Backend == "grpo-local" {
		// GRPO-local uses the C engine directly instead of generating a script
		policyGGUF := cfg.PolicyGGUF
		if policyGGUF == "" {
			policyGGUF = filepath.Join(cfg.ModelsDir, cfg.BaseModel+".gguf")
		}

		grpoResult, err := RunGrpoLocal(ctx, GrpoLocalConfig{
			PolicyGGUF:      policyGGUF,
			ReferenceGGUF:   cfg.ReferenceModel,
			RewardGGUF:      cfg.RewardModel,
			GroupSize:       cfg.GroupSize,
			MaxGenLength:    cfg.MaxGenLength,
			ClipEpsilon:     cfg.ClipEpsilon,
			KLCoef:          cfg.KLCoef,
			Temperature:     cfg.Temperature,
			LearningRate:    2e-4,
			LoRARank:        cfg.LoRARank,
			LoRATargets:     cfg.LoRATargets,
			MemoryMode:      cfg.MemoryMode,
			RewardFuncs:     ParseRewardFuncs(cfg.RewardFuncs),
			DatasetPath:     dataset.TrainFile,
			OutputDir:       outputDir,
			CheckpointEvery: 100,
		})
		if err != nil {
			result.State = StateFailed
			result.Error = fmt.Errorf("pipeline: grpo-local: %w", err)
			return result
		}
		runResult = grpoResult
	} else {
		// Standard SFT/DPO/ORPO path using script generation
		runResult, err = Run(ctx, RunConfig{
			Backend:     cfg.Backend,
			Algorithm:   cfg.Algorithm,
			BaseModel:   cfg.BaseModel,
			DatasetPath: dataset.TrainFile,
			OutputDir:   outputDir,
			ScriptsDir:  scriptsDir,
			TimeoutSec:  cfg.TimeoutSec,
		})
		if err != nil {
			result.State = StateFailed
			result.Error = fmt.Errorf("pipeline: train: %w", err)
			return result
		}
	}

	// Stage 3: Deploy (copy GGUF to models dir)
	result.State = StateDeploying
	if runResult.GGUFPath == "" {
		result.State = StateFailed
		result.Error = fmt.Errorf("pipeline: no GGUF file found in output")
		return result
	}

	versionID := fmt.Sprintf("%s-v%d", cfg.Category, time.Now().Unix())
	ggufDest := filepath.Join(cfg.ModelsDir, versionID+".gguf")

	if err := copyFile(runResult.GGUFPath, ggufDest); err != nil {
		result.State = StateFailed
		result.Error = fmt.Errorf("pipeline: deploy copy: %w", err)
		return result
	}
	result.GGUFPath = ggufDest
	result.VersionID = versionID
	fmt.Fprintf(os.Stderr, "[pipeline] %s: deployed %s\n", cfg.Category, ggufDest)

	// Stage 4: Evaluate
	result.State = StateEvaluating
	fmt.Fprintf(os.Stderr, "[pipeline] %s: evaluating (%d prompts)...\n", cfg.Category, cfg.EvalPrompts)

	evalResult, err := Evaluate(ctx, EvalConfig{
		EvalFilePath:  dataset.EvalFile,
		LocalEndpoint: fmt.Sprintf("http://127.0.0.1:%d", cfg.LlamaPort),
		LocalModel:    versionID,
		JudgeEndpoint: cfg.JudgeEndpoint,
		JudgeModel:    cfg.JudgeModel,
		JudgeAPIKey:   cfg.JudgeAPIKey,
		EvalPrompts:   cfg.EvalPrompts,
		Threshold:     cfg.EvalThreshold,
	})
	if err != nil {
		result.State = StateFailed
		result.Error = fmt.Errorf("pipeline: eval: %w", err)
		return result
	}
	result.EvalResult = evalResult

	// Stage 5: Register version
	if err := p.registry.RegisterVersion(cfg.Category, ModelVersion{
		ID:                versionID,
		File:              filepath.Base(ggufDest),
		BaseModel:         cfg.BaseModel,
		Algorithm:         cfg.Algorithm,
		Created:           time.Now(),
		TracesUsed:        dataset.TrainCount,
		EvalScoreLocal:    evalResult.ScoreLocal,
		EvalScoreFrontier: evalResult.ScoreFrontier,
		EvalRatio:         evalResult.Ratio,
	}); err != nil {
		result.State = StateFailed
		result.Error = fmt.Errorf("pipeline: register version: %w", err)
		return result
	}

	// Stage 6: Promote or fail
	if evalResult.Passed {
		result.State = StatePromoted
		if err := p.registry.Promote(cfg.Category, versionID); err != nil {
			result.State = StateFailed
			result.Error = fmt.Errorf("pipeline: promote: %w", err)
			return result
		}
		fmt.Fprintf(os.Stderr, "[pipeline] %s: PROMOTED (ratio=%.3f >= %.3f)\n",
			cfg.Category, evalResult.Ratio, cfg.EvalThreshold)
	} else {
		result.State = StateFailed
		fmt.Fprintf(os.Stderr, "[pipeline] %s: NOT PROMOTED (ratio=%.3f < %.3f)\n",
			cfg.Category, evalResult.Ratio, cfg.EvalThreshold)
	}

	result.Duration = time.Since(start)
	return result
}

// copyFile copies src to dst atomically.
func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}
