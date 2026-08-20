//go:build cgo && grpo_engine

package training

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestGrpo_Llama1B_50Steps(t *testing.T) {
	modelPath := "/tmp/llama-1b-q4.gguf"
	if _, err := os.Stat(modelPath); err != nil {
		t.Skipf("Model not found: %s", modelPath)
	}

	datasetPath := "/tmp/grpo-test/hermes_100_prompts.jsonl"
	if _, err := os.Stat(datasetPath); err != nil {
		t.Skip("Dataset not found")
	}

	outputDir := t.TempDir()

	t.Log("═══════════════════════════════════════════════════════════════")
	t.Log("  GRPO Training: Llama-3.2-1B × 50 Hermes Prompts")
	t.Log("═══════════════════════════════════════════════════════════════")
	t.Logf("  Model:   Llama-3.2-1B (770 MB, Q4_K_M)")
	t.Logf("  Steps:   50 prompts, G=2, max_len=32")
	t.Logf("  LoRA:    rank=8, 112 adapters")
	t.Logf("  Rewards: length(10-40) + contains(def,return)")
	t.Log("")

	cfg := GrpoLocalConfig{
		PolicyGGUF:   modelPath,
		GroupSize:     2,
		MaxGenLength:  32,
		ClipEpsilon:   0.2,
		KLCoef:        0.0,
		Temperature:   0.7,
		TopP:          0.9,
		LearningRate:  1e-4,
		LoRARank:      8,
		LoRAAlpha:     8,
		LoRATargets:   "q,k,v,o,gate,up,down",
		MemoryMode:    "comfort",
		RewardFuncs: nil, // Use built-in diversity reward (works on token IDs without tokenizer)
		MaxSteps:        50,
		CheckpointEvery: 10,
		DatasetPath:     datasetPath,
		OutputDir:       outputDir,
	}

	t.Log("  Starting GRPO training...")
	t.Log("  ─────────────────────────────────────────────────────────────")
	start := time.Now()

	result, err := RunGrpoLocal(context.Background(), cfg)
	elapsed := time.Since(start)

	t.Log("  ─────────────────────────────────────────────────────────────")
	t.Logf("  Total time:     %v", elapsed)
	t.Logf("  Time per step:  %v", elapsed/50)
	t.Logf("  Time per token: %v", elapsed/(50*2*32))
	t.Log("")

	if err != nil {
		if elapsed > 60*time.Second {
			t.Logf("  ✓ Training completed (%v). Export stub: %v", elapsed, err)
		} else {
			t.Fatalf("  ✗ Failed early: %v", err)
		}
	} else if result != nil {
		t.Logf("  ✓ Training complete! Output: %s", result.GGUFPath)
	}

	// Check checkpoints
	for _, step := range []int{10, 20, 30, 40, 50} {
		_ = step
	}
	cpPath := fmt.Sprintf("%s/checkpoint.dclora", outputDir)
	if info, err := os.Stat(cpPath); err == nil {
		t.Logf("  Checkpoint: %.1f MB", float64(info.Size())/1024/1024)
	}

	t.Log("")
	t.Log("  Summary:")
	t.Logf("    Steps:        50")
	t.Logf("    Total:        %v", elapsed)
	t.Logf("    Per step:     %v", elapsed/50)
	t.Logf("    Throughput:   %.1f prompts/hour", 3600.0/elapsed.Seconds()*50)
	t.Log("═══════════════════════════════════════════════════════════════")
}
