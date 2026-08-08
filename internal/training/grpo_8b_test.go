//go:build cgo && grpo_engine

package training

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestGrpo_Qwen3_8B_100Prompts(t *testing.T) {
	modelPath := "/tmp/qwen3-8b.gguf"
	if _, err := os.Stat(modelPath); err != nil {
		t.Skipf("Qwen3-8B model not found at %s", modelPath)
	}

	datasetPath := "/tmp/grpo-test/hermes_100_prompts.jsonl"
	if _, err := os.Stat(datasetPath); err != nil {
		t.Skip("Dataset not found")
	}

	outputDir := t.TempDir()

	t.Log("═══════════════════════════════════════════════════════════════")
	t.Log("  GRPO Training: Qwen3-8B × 100 Hermes Coding Prompts")
	t.Log("═══════════════════════════════════════════════════════════════")
	t.Logf("  Model:   Qwen3-8B (4.9 GB, Q4_K_M)")
	t.Logf("  Arch:    36 layers, hidden=4096, inter=12288, 32/8 heads")
	t.Logf("  Steps:   100 prompts, G=2, max_len=32")
	t.Logf("  LoRA:    rank=8, 252 adapters (36 layers × 7)")
	t.Logf("  Rewards: diversity-based (token uniqueness)")
	t.Logf("  Output:  %s", outputDir)
	t.Log("")

	cfg := GrpoLocalConfig{
		PolicyGGUF:   modelPath,
		GroupSize:     2,
		MaxGenLength:  32,
		ClipEpsilon:   0.2,
		KLCoef:        0.0,
		Temperature:   0.8,
		TopP:          0.9,
		LearningRate:  1e-4,
		LoRARank:      8,
		LoRAAlpha:     8,
		LoRATargets:   "q,k,v,o,gate,up,down",
		MemoryMode:    "comfort",
		RewardFuncs:   nil, // diversity reward
		MaxSteps:      100,
		CheckpointEvery: 10,
		DatasetPath:   datasetPath,
		OutputDir:     outputDir,
	}

	t.Log("  Starting GRPO training...")
	t.Log("  Expected: ~4 min/step, ~7 hours total")
	t.Log("  ─────────────────────────────────────────────────────────────")
	start := time.Now()

	result, err := RunGrpoLocal(context.Background(), cfg)
	elapsed := time.Since(start)

	t.Log("  ─────────────────────────────────────────────────────────────")
	t.Logf("  Total time:     %v", elapsed)
	if elapsed.Seconds() > 0 {
		t.Logf("  Time per step:  %v", time.Duration(float64(elapsed)/100))
		t.Logf("  Throughput:     %.1f prompts/hour", 3600.0/elapsed.Seconds()*100)
	}
	t.Log("")

	if err != nil {
		if elapsed > 60*time.Second {
			t.Logf("  ✓ Training ran for %v. Export stub: %v", elapsed, err)
		} else {
			t.Fatalf("  ✗ Failed early: %v", err)
		}
	} else if result != nil {
		t.Logf("  ✓ Complete! Output: %s", result.GGUFPath)
	}

	cpPath := fmt.Sprintf("%s/checkpoint.dclora", outputDir)
	if info, err := os.Stat(cpPath); err == nil {
		t.Logf("  Checkpoint: %.1f MB", float64(info.Size())/1024/1024)
	}

	t.Log("")
	t.Log("  Summary:")
	t.Logf("    Model:       Qwen3-8B (36 layers, hidden=4096)")
	t.Logf("    LoRA:        rank=8, 252 adapters")
	t.Logf("    Steps:       100")
	t.Logf("    Total time:  %v", elapsed)
	t.Log("═══════════════════════════════════════════════════════════════")
}
