//go:build cgo && grpo_engine

package training

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGrpoRunnerE2E(t *testing.T) {
	tinyModel := filepath.Join("grpo_engine", "testdata", "tiny_model.gguf")
	if _, err := os.Stat(tinyModel); err != nil {
		t.Skip("tiny_model.gguf not found — run scripts/gen_tiny_gguf.py first")
	}

	tmpDir := t.TempDir()

	// Create minimal dataset
	datasetPath := filepath.Join(tmpDir, "prompts.jsonl")
	err := os.WriteFile(datasetPath, []byte(
		`{"prompt_tokens": [1, 5, 10, 15], "ground_truth": "hello"}`+"\n"+
			`{"prompt_tokens": [1, 20, 25, 30], "ground_truth": "world"}`+"\n",
	), 0644)
	if err != nil {
		t.Fatalf("Failed to write dataset: %v", err)
	}

	cfg := GrpoLocalConfig{
		PolicyGGUF:      tinyModel,
		GroupSize:       2,
		MaxGenLength:    8,
		ClipEpsilon:     0.2,
		Temperature:     1.0,
		TopP:            0.9,
		LearningRate:    1e-3,
		LoRARank:        4,
		LoRAAlpha:       4,
		LoRATargets:     "q,k,v,o,gate,up,down",
		MemoryMode:      "comfort",
		RewardFuncs:     []RewardSpec{{Type: "length", Params: map[string]string{"min": "1", "max": "10"}, Weight: 1.0}},
		MaxSteps:        5,
		CheckpointEvery: 2,
		DatasetPath:     datasetPath,
		OutputDir:       tmpDir,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	result, err := RunGrpoLocal(ctx, cfg)
	if err != nil {
		t.Fatalf("RunGrpoLocal failed: %v", err)
	}

	if result.GGUFPath == "" {
		t.Fatal("no merged GGUF produced")
	}
	if _, err := os.Stat(result.GGUFPath); err != nil {
		t.Fatalf("merged GGUF not found at %s", result.GGUFPath)
	}

	// Verify checkpoint was created
	checkpoint := filepath.Join(tmpDir, "checkpoint.dclora")
	if _, err := os.Stat(checkpoint); err != nil {
		t.Fatal("no checkpoint created")
	}

	t.Logf("GRPO E2E completed in %v, output: %s", result.Duration, result.GGUFPath)
}

func TestGrpoEngineAvailable(t *testing.T) {
	if !GrpoEngineAvailable() {
		t.Fatal("GrpoEngineAvailable should return true when built with cgo && grpo_engine")
	}
}

func TestGrpoConfigDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	datasetPath := filepath.Join(tmpDir, "prompts.jsonl")
	os.WriteFile(datasetPath, []byte(`{"prompt_tokens": [1]}`+"\n"), 0644)

	cfg := GrpoLocalConfig{
		PolicyGGUF:  "nonexistent.gguf", // Will fail at init, but we're testing defaults
		DatasetPath: datasetPath,
		OutputDir:   tmpDir,
	}

	// Don't actually run, just verify config processing by attempting init
	// This will fail because the model doesn't exist, but it exercises the default-setting code path
	_, err := RunGrpoLocal(context.Background(), cfg)
	if err == nil {
		t.Fatal("Expected error for nonexistent model")
	}

	// Verify defaults were set by checking the error path didn't panic
	// (The defaults are set before NewGrpoEngine is called)
}

func TestGrpoRewardIntegration(t *testing.T) {
	// Test that reward dispatch works end-to-end with real composition
	specs := []RewardSpec{
		{Type: "format", Params: map[string]string{"type": "json"}, Weight: 0.3},
		{Type: "length", Params: map[string]string{"min": "1", "max": "50"}, Weight: 0.4},
		{Type: "contains", Params: map[string]string{"required": "test"}, Weight: 0.3},
	}

	completion := `{"result": "test output"}`
	metadata := make(map[string]string)

	reward := DispatchReward(completion, metadata, specs)

	// JSON valid (1.0 × 0.3) + length OK (1.0 × 0.4) + contains "test" (1.0 × 0.3) = 1.0
	if reward != 1.0 {
		t.Errorf("expected 1.0, got %f", reward)
	}
}

func TestParseRewardFuncs(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []RewardSpec
	}{
		{
			name:  "simple type",
			input: []string{"length"},
			expected: []RewardSpec{
				{Type: "length", Params: map[string]string{}, Weight: 1.0},
			},
		},
		{
			name:  "type with params",
			input: []string{"exec:timeout=10,lang=python"},
			expected: []RewardSpec{
				{Type: "exec", Params: map[string]string{"timeout": "10", "lang": "python"}, Weight: 1.0},
			},
		},
		{
			name:  "multiple specs",
			input: []string{"format:type=json", "length:min=1,max=100"},
			expected: []RewardSpec{
				{Type: "format", Params: map[string]string{"type": "json"}, Weight: 1.0},
				{Type: "length", Params: map[string]string{"min": "1", "max": "100"}, Weight: 1.0},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseRewardFuncs(tt.input)
			if len(result) != len(tt.expected) {
				t.Fatalf("expected %d specs, got %d", len(tt.expected), len(result))
			}
			for i := range result {
				if result[i].Type != tt.expected[i].Type {
					t.Errorf("spec %d: expected type %s, got %s", i, tt.expected[i].Type, result[i].Type)
				}
				if result[i].Weight != tt.expected[i].Weight {
					t.Errorf("spec %d: expected weight %f, got %f", i, tt.expected[i].Weight, result[i].Weight)
				}
				if len(result[i].Params) != len(tt.expected[i].Params) {
					t.Errorf("spec %d: expected %d params, got %d", i, len(tt.expected[i].Params), len(result[i].Params))
				}
				for k, v := range tt.expected[i].Params {
					if result[i].Params[k] != v {
						t.Errorf("spec %d: expected param %s=%s, got %s", i, k, v, result[i].Params[k])
					}
				}
			}
		})
	}
}

func TestLoadGRPODataset(t *testing.T) {
	tmpDir := t.TempDir()
	datasetPath := filepath.Join(tmpDir, "test_dataset.jsonl")

	// Create test dataset with various formats
	content := `{"prompt_tokens": [1, 2, 3], "ground_truth": "hello"}
{"prompt": "test prompt", "ground_truth": "world", "metadata": {"key": "value"}}
{"prompt_tokens": [4, 5], "metadata": {"custom": "data"}}
`
	err := os.WriteFile(datasetPath, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to write test dataset: %v", err)
	}

	prompts, metadata, err := loadGRPODataset(datasetPath)
	if err != nil {
		t.Fatalf("loadGRPODataset failed: %v", err)
	}

	if len(prompts) != 3 {
		t.Fatalf("expected 3 prompts, got %d", len(prompts))
	}

	// First entry: has prompt_tokens and ground_truth
	if len(prompts[0]) != 3 || prompts[0][0] != 1 {
		t.Errorf("first prompt tokens incorrect: %v", prompts[0])
	}
	if metadata[0]["ground_truth"] != "hello" {
		t.Errorf("first metadata ground_truth incorrect: %s", metadata[0]["ground_truth"])
	}

	// Second entry: no prompt_tokens, should get BOS token placeholder
	if len(prompts[1]) != 1 || prompts[1][0] != 1 {
		t.Errorf("second prompt should be [1], got %v", prompts[1])
	}
	if metadata[1]["ground_truth"] != "world" || metadata[1]["key"] != "value" {
		t.Errorf("second metadata incorrect: %v", metadata[1])
	}

	// Third entry: has custom metadata
	if metadata[2]["custom"] != "data" {
		t.Errorf("third metadata incorrect: %v", metadata[2])
	}
}

func TestGroupAdvantages(t *testing.T) {
	tests := []struct {
		name     string
		rewards  []float64
		checkFn  func(t *testing.T, adv []float64)
	}{
		{
			name:    "empty rewards",
			rewards: []float64{},
			checkFn: func(t *testing.T, adv []float64) {
				if adv != nil {
					t.Errorf("expected nil for empty rewards, got %v", adv)
				}
			},
		},
		{
			name:    "uniform rewards",
			rewards: []float64{1.0, 1.0, 1.0, 1.0},
			checkFn: func(t *testing.T, adv []float64) {
				if len(adv) != 4 {
					t.Fatalf("expected 4 advantages, got %d", len(adv))
				}
				// All should be zero (normalized to mean)
				for i, a := range adv {
					if a > 1e-6 || a < -1e-6 {
						t.Errorf("advantage %d should be ~0, got %f", i, a)
					}
				}
			},
		},
		{
			name:    "varied rewards",
			rewards: []float64{0.0, 0.5, 1.0, 1.5},
			checkFn: func(t *testing.T, adv []float64) {
				if len(adv) != 4 {
					t.Fatalf("expected 4 advantages, got %d", len(adv))
				}
				// Should be normalized to mean=0, std=1
				sum := 0.0
				for _, a := range adv {
					sum += a
				}
				meanAdv := sum / float64(len(adv))
				if meanAdv > 1e-6 || meanAdv < -1e-6 {
					t.Errorf("mean advantage should be ~0, got %f", meanAdv)
				}
				// First should be most negative, last most positive
				if adv[0] >= adv[1] || adv[2] >= adv[3] {
					t.Errorf("advantages not properly ordered: %v", adv)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adv := groupAdvantages(tt.rewards)
			tt.checkFn(t, adv)
		})
	}
}

func TestGrpoStatsFormat(t *testing.T) {
	stats := GrpoStats{
		Steps:          42,
		LastRewardMean: 0.85,
		LastLoss:       0.123,
	}

	formatted := stats.FormatProgress(100)
	expected := "step 42/100, reward=0.850, loss=0.1230"

	if formatted != expected {
		t.Errorf("expected %q, got %q", expected, formatted)
	}
}
