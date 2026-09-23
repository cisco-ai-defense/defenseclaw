//go:build cgo && grpo_engine

package training

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestGrpo_Qwen3_8B_TokenizerReward_20Steps(t *testing.T) {
	modelPath := "/tmp/qwen3-8b.gguf"
	if _, err := os.Stat(modelPath); err != nil {
		t.Skipf("Qwen3-8B model not found at %s", modelPath)
	}

	datasetPath := "/tmp/grpo-test/hermes_100_prompts.jsonl"
	if _, err := os.Stat(datasetPath); err != nil {
		t.Skip("Dataset not found")
	}

	t.Log("═══════════════════════════════════════════════════════════════")
	t.Log("  A/B Test: Tokenizer+Exec Reward vs Diversity-Only (20 steps)")
	t.Log("═══════════════════════════════════════════════════════════════")

	baseCfg := GrpoLocalConfig{
		PolicyGGUF:      modelPath,
		GroupSize:       2,
		MaxGenLength:    32,
		ClipEpsilon:     0.2,
		KLCoef:          0.0,
		Temperature:     0.8,
		TopP:            0.9,
		LearningRate:    1e-4,
		LoRARank:        8,
		LoRAAlpha:       8,
		LoRATargets:     "q,k,v,o,gate,up,down",
		MemoryMode:      "comfort",
		MaxSteps:        20,
		CheckpointEvery: 100,
		DatasetPath:     datasetPath,
	}

	// --- Run A: Diversity reward only (no tokenizer needed) ---
	t.Log("")
	t.Log("  [A] DIVERSITY REWARD (token uniqueness, no text decode)")
	t.Log("  ─────────────────────────────────────────────────────────")
	cfgA := baseCfg
	cfgA.OutputDir = t.TempDir()
	cfgA.RewardFuncs = nil // diversity only

	startA := time.Now()
	resultA, errA := RunGrpoLocal(context.Background(), cfgA)
	elapsedA := time.Since(startA)
	_ = resultA
	if errA != nil {
		t.Logf("  [A] Ended: %v (elapsed: %v)", errA, elapsedA)
	} else {
		t.Logf("  [A] Complete in %v", elapsedA)
	}

	// --- Run B: Exec reward (tokenizer decodes text, runs as Python) ---
	t.Log("")
	t.Log("  [B] EXEC REWARD (tokenizer→text→python exec, timeout=5s)")
	t.Log("  ─────────────────────────────────────────────────────────")
	cfgB := baseCfg
	cfgB.OutputDir = t.TempDir()
	cfgB.RewardFuncs = []RewardSpec{
		{Type: "exec", Weight: 1.0, Params: map[string]string{"timeout": "5", "lang": "python"}},
	}

	startB := time.Now()
	resultB, errB := RunGrpoLocal(context.Background(), cfgB)
	elapsedB := time.Since(startB)
	_ = resultB
	if errB != nil {
		t.Logf("  [B] Ended: %v (elapsed: %v)", errB, elapsedB)
	} else {
		t.Logf("  [B] Complete in %v", elapsedB)
	}

	t.Log("")
	t.Log("═══════════════════════════════════════════════════════════════")
	t.Logf("  Run A (diversity):  %v", elapsedA)
	t.Logf("  Run B (exec):       %v", elapsedB)
	t.Log("  Check [grpo] log lines above for reward progression")
	t.Log("═══════════════════════════════════════════════════════════════")
	fmt.Fprintf(os.Stderr, "\n[RESULT] A=%v B=%v\n", elapsedA, elapsedB)
}
